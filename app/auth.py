from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app import crud
from app.config import get_settings
from app.database import get_db
from app.models import Binding, Owner
from app.security import verify_secret


def require_admin_key(x_admin_key: str = Header(...)) -> None:
    settings = get_settings()
    if not secrets.compare_digest(x_admin_key, settings.admin_master_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid admin key")


def get_current_owner(
    x_api_user: str = Header(...),
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
) -> Owner:
    """Auth dependency for the generic (owner-level) protocol."""
    owner = crud.get_owner_by_username(db, x_api_user)
    if owner is None or not verify_secret(x_api_key, owner.api_key_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    return owner


def get_current_binding(
    x_api_user: str = Header(...),
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
) -> Binding:
    """Auth dependency for the acme-dns protocol's /update call. Field names match the
    acme-dns spec's headers exactly (X-Api-User / X-Api-Key) so real ACME clients need
    no configuration beyond the credentials themselves.
    """
    binding = crud.get_binding_by_username(db, x_api_user)
    if binding is None or not verify_secret(x_api_key, binding.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    return binding


@dataclass
class OwnerOrBinding:
    """Exactly one of `owner`/`binding` is set. Lets a protocol accept either an
    Owner's own (wide, permission-checked) API key or a narrower per-hostname acme-dns
    Binding credential, and decide per-request which authorization rule applies."""

    owner: Owner | None = None
    binding: Binding | None = None


def get_current_owner_or_binding(
    x_api_user: str = Header(...),
    x_api_key: str = Header(...),
    db: Session = Depends(get_db),
) -> OwnerOrBinding:
    """Auth dependency for protocols willing to accept a Binding's scoped credentials
    as an alternative to the owning Owner's API key -- e.g. so a Binding created for
    the acme-dns protocol can also drive the generic protocol for that same one fqdn,
    without exposing the wider owner-level key to whoever holds it. The caller is
    responsible for checking the requested fqdn against `binding.fqdn` (this
    dependency only verifies the credential itself, not its scope, since scope
    checking needs the request body).
    """
    owner = crud.get_owner_by_username(db, x_api_user)
    if owner is not None and verify_secret(x_api_key, owner.api_key_hash):
        return OwnerOrBinding(owner=owner)

    binding = crud.get_binding_by_username(db, x_api_user)
    if binding is not None and verify_secret(x_api_key, binding.password_hash):
        return OwnerOrBinding(binding=binding)

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
