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

`/update` normally writes the TXT record to "<subdomain>.<delegation_zone>", relying on
the operator having set up "_acme-challenge.<realdomain> CNAME <subdomain>.
<delegation_zone>" once out-of-band -- that's the whole point of the acme-dns spec.
If the `acmedns` protocol config sets `direct_update: true`, /update instead writes
straight to "_acme-challenge.<binding.fqdn>" (the real domain), skipping the
delegation_zone/CNAME indirection entirely. This only works if the backend resolved
for that fqdn is authoritative for the real domain directly (e.g. rfc2136 pointed at
the customer's own zone) -- it's for operators who want acme-dns-speaking ACME clients
without asking every tenant to create a CNAME first.

If the `acmedns` protocol config additionally sets `accept_fqdn_as_subdomain: true`,
/update's "subdomain" field may also be the binding's real fqdn (bare, or already
"_acme-challenge."-prefixed) instead of the random subdomain -- for clients/hooks that
were only ever told the real domain and never learned the random subdomain from
/register. A request that matches this way always writes to
"_acme-challenge.<binding.fqdn>" directly, independent of `direct_update` (the client
explicitly named the real domain, so that's what gets updated).
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
from app.hostmatch import is_ip_allowed, matches_fqdn_or_challenge
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

            settings = get_settings()
            protocol_cfg = settings.protocols.get("acmedns")
            accept_fqdn_as_subdomain = bool(protocol_cfg and protocol_cfg.accept_fqdn_as_subdomain)

            matched_fqdn = accept_fqdn_as_subdomain and matches_fqdn_or_challenge(req.subdomain, binding.fqdn)
            if req.subdomain != binding.subdomain and not matched_fqdn:
                # Matches real acme-dns behaviour: credentials are scoped to exactly
                # one subdomain; requesting a different one is a hard auth failure.
                # (accept_fqdn_as_subdomain widens "one subdomain" to also accept the
                # binding's own real fqdn as an alternative spelling of that same
                # target, not to a different target.)
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "subdomain does not match credentials")

            if matched_fqdn or (protocol_cfg is not None and protocol_cfg.direct_update):
                # No CNAME delegation involved: write straight to the real domain's
                # own "_acme-challenge." name, so the backend for binding.fqdn must be
                # authoritative for that domain directly.
                target_fqdn = f"_acme-challenge.{binding.fqdn}"
            else:
                target_fqdn = f"{binding.subdomain}.{settings.delegation_zone}"

            try:
                backend = get_registry().resolve(target_fqdn)
            except UnroutableHostname as exc:
                logger.error("no backend route for %s: %s", target_fqdn, exc)
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, "no backend configured for this domain") from exc

            try:
                backend.present(target_fqdn, req.txt)
            except Exception as exc:  # noqa: BLE001 -- surface upstream failure to the client
                logger.exception("backend present() failed for %s", target_fqdn)
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"upstream DNS update failed: {exc}") from exc

            crud.update_last_txt_value(db, binding, req.txt)
            return UpdateResponse(txt=req.txt)

        return router
