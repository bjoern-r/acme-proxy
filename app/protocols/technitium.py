"""Impersonates the HTTP API of Technitium DNS Server (https://technitium.com/dns/) --
specifically the `/api/zones/records/add` and `/api/zones/records/delete` calls, which
is the subset ACME DNS-01 hooks actually use. Point a client that already knows how to
drive a *real* Technitium server directly at this proxy instead, and it works
unmodified, gaining this proxy's multi-tenant permission layer and pluggable backend in
front of whatever DNS provider you actually use.

Reference implementation this was modeled against: acme.sh's `dns_technitium` provider
(github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_technitium), which does e.g.:

    GET {Technitium_Server}/api/zones/records/add
        ?token={Technitium_Token}&domain={fulldomain}&type=TXT&text={txtvalue}

and treats the call as successful if the response body contains `"status":"ok"`.
Full API spec: github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md. Only the
TXT-record subset needed for DNS-01 is implemented here -- the real API supports every
RR type and a long tail of record-specific parameters, none of which this proxy's
`DNSBackend.present()`/`cleanup()` (TXT-only) has any use for.

Auth: the real API takes a single opaque bearer token -- an `Authorization: Bearer
<token>` header, or (kept for backward compatibility, per the real server's own docs) a
`token` query/form parameter. Both are accepted here. This proxy has no
single-opaque-token owner identity, so the token value an admin hands to the ACME
client for this protocol is `"<owner-username>:<owner-api-key>"` (the same api-key
`create-owner` prints, just concatenated with the username) -- paste that whole string
in as the "Technitium API token" config value.

Response shape matches the real server: always HTTP 200, with a JSON `status` field of
`ok` / `error` / `invalid-token` -- the real server never uses HTTP status codes to
signal API-level failure, and the reference client above only ever inspects the body.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import crud
from app.backends.registry import UnroutableHostname, get_registry
from app.database import get_db
from app.hostmatch import is_authorized_for_challenge
from app.models import Owner
from app.protocols.base import FrontendProtocolBase
from app.security import verify_secret

logger = logging.getLogger("acme_proxy.protocols.technitium")

# Documentation-only: the real params are (re-)parsed from the raw `Request` in
# `_request_params`/`_extract_token` so both GET query-string and POST form-encoded
# submissions work identically -- FastAPI can't infer that dual shape from a plain
# `Request` argument, so these declarations exist purely to populate the OpenAPI
# schema/Swagger UI and are otherwise unused by the handler.
_bearer_scheme = HTTPBearer(
    auto_error=False,
    description="Owner credential, formatted as \"<owner-username>:<owner-api-key>\" "
    "(the api-key printed by `create-owner`, concatenated with the username).",
)
_TOKEN_DESCRIPTION = (
    'Owner credential as "<owner-username>:<owner-api-key>". Accepted as a query '
    "parameter (GET) or form field (POST) for compatibility with the real "
    "Technitium API; the Authorization: Bearer header above is equivalent and takes "
    "precedence if both are supplied."
)
_DOMAIN_DESCRIPTION = "Fully-qualified domain name to add/remove the TXT record for, e.g. _acme-challenge.example.com."
_TYPE_DESCRIPTION = 'Record type. Must be the literal string "TXT" -- no other record type is supported.'
_TEXT_DESCRIPTION = "TXT record value, i.e. the ACME DNS-01 challenge token."

_RESPONSE_SCHEMA = {
    "description": "Always HTTP 200 -- clients must inspect the `status` field, per the real Technitium API.",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["ok", "error", "invalid-token"],
                    },
                    "response": {
                        "type": "object",
                        "description": "Present when status is 'ok'.",
                    },
                    "errorMessage": {
                        "type": "string",
                        "description": "Present when status is 'error'.",
                    },
                },
                "required": ["status"],
            }
        }
    },
}

_ADD_RESPONSES = {
    200: {
        **_RESPONSE_SCHEMA,
        "content": {
            "application/json": {
                **_RESPONSE_SCHEMA["content"]["application/json"],
                "examples": {
                    "ok": {
                        "summary": "Record added",
                        "value": {
                            "status": "ok",
                            "response": {
                                "addedRecord": {
                                    "name": "_acme-challenge.example.com",
                                    "type": "TXT",
                                    "rData": {"text": "<challenge-token>"},
                                }
                            },
                        },
                    },
                    "invalid-token": {"summary": "Authentication failed", "value": {"status": "invalid-token"}},
                    "error": {
                        "summary": "Request rejected",
                        "value": {"status": "error", "errorMessage": "<reason>"},
                    },
                },
            }
        },
    }
}

_DELETE_RESPONSES = {
    200: {
        **_RESPONSE_SCHEMA,
        "content": {
            "application/json": {
                **_RESPONSE_SCHEMA["content"]["application/json"],
                "examples": {
                    "ok": {"summary": "Record deleted", "value": {"status": "ok", "response": {}}},
                    "invalid-token": {"summary": "Authentication failed", "value": {"status": "invalid-token"}},
                    "error": {
                        "summary": "Request rejected",
                        "value": {"status": "error", "errorMessage": "<reason>"},
                    },
                },
            }
        },
    }
}


async def _request_params(request: Request) -> dict[str, str]:
    params = dict(request.query_params)
    content_type = request.headers.get("content-type", "")
    if request.method == "POST" and (
        "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type
    ):
        form = await request.form()
        params.update({k: str(v) for k, v in form.items()})
    return params


def _extract_token(request: Request, params: dict[str, str]) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[len("bearer "):].strip()
    return params.get("token")


def _authenticate(token: str | None, db: Session) -> Owner | None:
    if not token or ":" not in token:
        return None
    username, _, api_key = token.partition(":")
    owner = crud.get_owner_by_username(db, username)
    if owner is None or not verify_secret(api_key, owner.api_key_hash):
        return None
    return owner


class TechnitiumProtocol(FrontendProtocolBase):
    name = "technitium"

    def build_router(self) -> APIRouter:
        router = APIRouter(tags=["technitium"])

        async def handle(request: Request, db: Session, action: str) -> dict:
            params = await _request_params(request)

            owner = _authenticate(_extract_token(request, params), db)
            if owner is None:
                return {"status": "invalid-token"}

            domain = params.get("domain")
            record_type = params.get("type")
            text = params.get("text")
            if not domain or record_type != "TXT" or not text:
                return {
                    "status": "error",
                    "errorMessage": "domain, type=TXT and text parameters are required",
                }

            perms = crud.list_permissions(db, owner)
            if not is_authorized_for_challenge(domain, perms):
                return {
                    "status": "error",
                    "errorMessage": f"{owner.username!r} is not permitted to request records for {domain!r}",
                }

            try:
                backend = get_registry().resolve(domain)
            except UnroutableHostname:
                return {"status": "error", "errorMessage": "no backend configured for this domain"}

            try:
                if action == "add":
                    backend.present(domain, text)
                    return {
                        "status": "ok",
                        "response": {"addedRecord": {"name": domain, "type": "TXT", "rData": {"text": text}}},
                    }
                else:
                    backend.cleanup(domain, text)
                    return {"status": "ok", "response": {}}
            except Exception as exc:  # noqa: BLE001
                logger.exception("backend %s() failed for %s", action, domain)
                return {"status": "error", "errorMessage": f"upstream DNS update failed: {exc}"}

        @router.api_route(
            "/api/zones/records/add",
            methods=["GET", "POST"],
            summary="Add a TXT record (Technitium API impersonation)",
            description=__doc__,
            responses=_ADD_RESPONSES,
        )
        async def add_record(
            request: Request,
            db: Session = Depends(get_db),
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
            token: str | None = Query(None, description=_TOKEN_DESCRIPTION),
            domain: str | None = Query(None, description=_DOMAIN_DESCRIPTION),
            type: str | None = Query(None, alias="type", description=_TYPE_DESCRIPTION),  # noqa: A002
            text: str | None = Query(None, description=_TEXT_DESCRIPTION),
        ) -> dict:
            return await handle(request, db, "add")

        @router.api_route(
            "/api/zones/records/delete",
            methods=["GET", "POST"],
            summary="Delete a TXT record (Technitium API impersonation)",
            description=__doc__,
            responses=_DELETE_RESPONSES,
        )
        async def delete_record(
            request: Request,
            db: Session = Depends(get_db),
            _credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
            token: str | None = Query(None, description=_TOKEN_DESCRIPTION),
            domain: str | None = Query(None, description=_DOMAIN_DESCRIPTION),
            type: str | None = Query(None, alias="type", description=_TYPE_DESCRIPTION),  # noqa: A002
            text: str | None = Query(None, description=_TEXT_DESCRIPTION),
        ) -> dict:
            return await handle(request, db, "delete")

        return router
