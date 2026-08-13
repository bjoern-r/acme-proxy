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
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app import crud
from app.auth import get_current_owner
from app.backends.registry import UnroutableHostname, get_registry
from app.hostmatch import is_authorized_for_challenge
from app.models import Owner
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
    ok: bool = True


class GenericProtocol(FrontendProtocolBase):
    name = "generic"

    def build_router(self) -> APIRouter:
        router = APIRouter(tags=["generic"])

        def _authorize_and_resolve(fqdn: str, owner: Owner, db: Session):
            perms = crud.list_permissions(db, owner)
            if not is_authorized_for_challenge(fqdn, perms):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    f"{owner.username!r} is not permitted to request records for {fqdn!r}",
                )
            try:
                return get_registry().resolve(fqdn)
            except UnroutableHostname as exc:
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, "no backend configured for this domain") from exc

        @router.post("/present", response_model=ChallengeResponse)
        def present(
            req: ChallengeRequest,
            owner: Owner = Depends(get_current_owner),
            db: Session = Depends(get_db),
        ) -> ChallengeResponse:
            backend = _authorize_and_resolve(req.fqdn, owner, db)
            try:
                backend.present(req.fqdn, req.value)
            except Exception as exc:  # noqa: BLE001
                logger.exception("backend present() failed for %s", req.fqdn)
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"upstream DNS update failed: {exc}") from exc
            return ChallengeResponse()

        @router.post("/cleanup", response_model=ChallengeResponse)
        def cleanup(
            req: CleanupRequest,
            owner: Owner = Depends(get_current_owner),
            db: Session = Depends(get_db),
        ) -> ChallengeResponse:
            backend = _authorize_and_resolve(req.fqdn, owner, db)
            try:
                backend.cleanup(req.fqdn, req.value or "")
            except Exception as exc:  # noqa: BLE001 -- cleanup failures shouldn't block issuance
                logger.warning("backend cleanup() failed for %s: %s", req.fqdn, exc)
            return ChallengeResponse()

        return router
