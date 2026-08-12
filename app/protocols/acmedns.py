"""acme-dns protocol (https://github.com/joohoi/acme-dns).

`/update` is byte-for-byte spec compliant -- this is what Traefik (`--dns acmedns`
in lego), acme.sh (`dns_acmedns`), and any other acme-dns-aware client call on every
certificate issuance/renewal, so those clients need zero code changes or plugins.

`/register` deviates from the public spec on purpose: the real spec's /register is
unauthenticated (anyone can mint a fresh subdomain, then you're expected to eyeball an
`allowfrom` IP allowlist for protection). That's a poor fit for a governed multi-tenant
proxy, so here /register is an admin-only, fqdn-aware operation that checks the
requested fqdn against the owning tenant's HostnamePermission rules before minting
credentials. In practice this step is a one-time, out-of-band action (see
scripts/admin_cli.py `create-binding`) -- it does not run on every renewal, so gating it
doesn't affect ongoing ACME client compatibility at all.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import crud
from app.auth import get_current_binding, require_admin_key
from app.backends.registry import UnroutableHostname, get_registry
from app.config import get_settings
from app.database import get_db
from app.hostmatch import is_ip_allowed
from app.models import Binding
from app.protocols.base import FrontendProtocolBase

logger = logging.getLogger("acme_proxy.protocols.acmedns")


class RegisterRequest(BaseModel):
    owner_username: str
    fqdn: str
    allowfrom: list[str] = []


class RegisterResponse(BaseModel):
    username: str
    password: str
    fulldomain: str
    subdomain: str
    allowfrom: list[str] = []


class UpdateRequest(BaseModel):
    subdomain: str
    txt: str


class UpdateResponse(BaseModel):
    txt: str


class AcmeDnsProtocol(FrontendProtocolBase):
    name = "acmedns"

    def build_router(self) -> APIRouter:
        router = APIRouter(tags=["acme-dns"])

        @router.post("/register", response_model=RegisterResponse, dependencies=[Depends(require_admin_key)])
        def register(req: RegisterRequest, db: Session = Depends(get_db)) -> RegisterResponse:
            owner = crud.get_owner_by_username(db, req.owner_username)
            if owner is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown owner")
            try:
                created = crud.create_binding(db, owner, req.fqdn, allowfrom=",".join(req.allowfrom) or None)
            except crud.NotAuthorized as exc:
                raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

            settings = get_settings()
            fulldomain = f"{created.binding.subdomain}.{settings.delegation_zone}"
            return RegisterResponse(
                username=created.binding.username,
                password=created.plaintext_password,
                fulldomain=fulldomain,
                subdomain=created.binding.subdomain,
                allowfrom=req.allowfrom,
            )

        @router.post("/update", response_model=UpdateResponse)
        def update(
            req: UpdateRequest,
            request: Request,
            binding: Binding = Depends(get_current_binding),
            db: Session = Depends(get_db),
        ) -> UpdateResponse:
            if binding.revoked_at is not None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "credentials have been revoked")

            client_ip = request.client.host if request.client else ""
            if not is_ip_allowed(client_ip, binding.allowfrom):
                logger.warning(
                    "rejected /update for subdomain=%s from disallowed IP %s (allowfrom=%r)",
                    binding.subdomain, client_ip, binding.allowfrom,
                )
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "source IP not permitted for these credentials")

            if req.subdomain != binding.subdomain:
                # Matches real acme-dns behaviour: credentials are scoped to exactly
                # one subdomain; requesting a different one is a hard auth failure.
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "subdomain does not match credentials")

            settings = get_settings()
            fulldomain = f"{binding.subdomain}.{settings.delegation_zone}"
            try:
                backend = get_registry().resolve(fulldomain)
            except UnroutableHostname as exc:
                logger.error("no backend route for %s: %s", fulldomain, exc)
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, "no backend configured for this domain") from exc

            try:
                # No "_acme-challenge." prefix here: the client's real domain already
                # has "_acme-challenge.<realdomain> CNAME <fulldomain>", so this proxy
                # only needs to be authoritative for TXT at <fulldomain> itself.
                backend.present(fulldomain, req.txt)
            except Exception as exc:  # noqa: BLE001 -- surface upstream failure to the client
                logger.exception("backend present() failed for %s", fulldomain)
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"upstream DNS update failed: {exc}") from exc

            crud.update_last_txt_value(db, binding, req.txt)
            return UpdateResponse(txt=req.txt)

        return router
