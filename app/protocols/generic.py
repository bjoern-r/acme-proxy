"""A second, independent frontend protocol -- included mainly to demonstrate the
extensibility point, but genuinely useful: it mirrors the convention lego's `httpreq`
provider and acme.sh's custom-API pattern already use (a plain REST present/cleanup
call carrying the real FQDN on every request), and it exercises full per-request
regex/exact hostname authorization instead of the acme-dns protocol's
"authorize once at binding-creation time" model.

Any ACME client whose native DNS provider is a generic HTTP hook (lego/traefik `httpreq`,
or acme.sh `dns_acmeproxy.sh` or caddy `acmeproxy`) can talk to
this without acme-dns's one-time-registration step at all.
The protocol is taken from https://github.com/madcamel/acmeproxy.pl

Auth accepts either credential shape (see `app.auth.get_current_owner_or_binding`):
an Owner's own API key, checked against that owner's HostnamePermission patterns as
usual; or an acme-dns Binding's scoped username/password (see
`app/protocols/acmedns.py`), checked instead against that binding's own single fqdn
(plus its `allowfrom`/revocation state, same as the acme-dns protocol enforces). This
lets an operator hand out a Binding's narrow, one-hostname credential to a client that
speaks the generic protocol instead of acme-dns, without exposing the wider
owner-level key.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app import crud
from app.auth import OwnerOrBinding, get_current_owner_or_binding
from app.backends.registry import UnroutableHostname, get_registry
from app.hostmatch import is_authorized_for_challenge, is_ip_allowed, matches_fqdn_or_challenge
from app.protocols.base import FrontendProtocolBase
from app.database import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger("acme_proxy.protocols.generic")


class ChallengeRequest(BaseModel):
    fqdn: str
    value: str


class CleanupRequest(BaseModel):
    fqdn: str
    value: str | None = None


class ChallengeResponse(BaseModel):
    """Echoes the request back, matching the real acmeproxy.pl/lego `httpreq`
    convention this protocol mirrors -- callers don't inspect this body, they just
    expect HTTP 200 on success, but the shape still needs to match."""

    fqdn: str
    value: str | None = None


class GenericProtocol(FrontendProtocolBase):
    name = "generic"

    def build_router(self) -> APIRouter:
        router = APIRouter(tags=["generic"])

        def _authorize_and_resolve(fqdn: str, identity: OwnerOrBinding, request: Request, db: Session):
            if identity.owner is not None:
                perms = crud.list_permissions(db, identity.owner)
                if not is_authorized_for_challenge(fqdn, perms):
                    raise HTTPException(
                        status.HTTP_403_FORBIDDEN,
                        f"{identity.owner.username!r} is not permitted to request records for {fqdn!r}",
                    )
            else:
                binding = identity.binding
                if binding.revoked_at is not None:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "credentials have been revoked")
                client_ip = request.client.host if request.client else ""
                if not is_ip_allowed(client_ip, binding.allowfrom):
                    logger.warning(
                        "rejected request for %s from disallowed IP %s (allowfrom=%r)",
                        fqdn, client_ip, binding.allowfrom,
                    )
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "source IP not permitted for these credentials")
                if not matches_fqdn_or_challenge(fqdn, binding.fqdn):
                    raise HTTPException(
                        status.HTTP_403_FORBIDDEN,
                        f"credentials are scoped to {binding.fqdn!r}, not {fqdn!r}",
                    )

            try:
                return get_registry().resolve(fqdn)
            except UnroutableHostname as exc:
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, "no backend configured for this domain") from exc

        @router.post("/present", response_model=ChallengeResponse)
        def present(
            req: ChallengeRequest,
            request: Request,
            identity: OwnerOrBinding = Depends(get_current_owner_or_binding),
            db: Session = Depends(get_db),
        ) -> ChallengeResponse:
            backend = _authorize_and_resolve(req.fqdn, identity, request, db)
            try:
                backend.present(req.fqdn, req.value)
            except Exception as exc:  # noqa: BLE001
                logger.exception("backend present() failed for %s", req.fqdn)
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"upstream DNS update failed: {exc}") from exc
            return ChallengeResponse(fqdn=req.fqdn, value=req.value)

        @router.post("/cleanup", response_model=ChallengeResponse)
        def cleanup(
            req: CleanupRequest,
            request: Request,
            identity: OwnerOrBinding = Depends(get_current_owner_or_binding),
            db: Session = Depends(get_db),
        ) -> ChallengeResponse:
            backend = _authorize_and_resolve(req.fqdn, identity, request, db)
            try:
                backend.cleanup(req.fqdn, req.value or "")
            except Exception as exc:  # noqa: BLE001 -- cleanup failures shouldn't block issuance
                logger.warning("backend cleanup() failed for %s: %s", req.fqdn, exc)
            return ChallengeResponse(fqdn=req.fqdn, value=req.value)

        return router
