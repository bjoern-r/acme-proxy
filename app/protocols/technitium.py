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

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import crud
from app.backends.registry import UnroutableHostname, get_registry
from app.database import get_db
from app.hostmatch import is_authorized_for_challenge
from app.models import Owner
from app.protocols.base import FrontendProtocolBase
from app.security import verify_secret

logger = logging.getLogger("acme_proxy.protocols.technitium")


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

        @router.api_route("/api/zones/records/add", methods=["GET", "POST"])
        async def add_record(request: Request, db: Session = Depends(get_db)) -> dict:
            return await handle(request, db, "add")

        @router.api_route("/api/zones/records/delete", methods=["GET", "POST"])
        async def delete_record(request: Request, db: Session = Depends(get_db)) -> dict:
            return await handle(request, db, "delete")

        return router
