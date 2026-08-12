from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.hostmatch import is_authorized
from app.models import Binding, HostnamePermission, Owner
from app.security import generate_api_key, hash_secret


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)



class NotAuthorized(Exception):
    pass


class NotFound(Exception):
    pass


@dataclass
class CreatedOwner:
    owner: Owner
    plaintext_api_key: str


@dataclass
class CreatedBinding:
    binding: Binding
    plaintext_password: str


def create_owner(db: Session, username: str, description: str | None = None) -> CreatedOwner:
    api_key = generate_api_key()
    owner = Owner(username=username, api_key_hash=hash_secret(api_key), description=description)
    db.add(owner)
    db.commit()
    db.refresh(owner)
    return CreatedOwner(owner=owner, plaintext_api_key=api_key)


def get_owner_by_username(db: Session, username: str) -> Owner | None:
    return db.scalar(select(Owner).where(Owner.username == username))


def add_permission(db: Session, owner: Owner, pattern: str, is_regex: bool) -> HostnamePermission:
    perm = HostnamePermission(owner_id=owner.id, pattern=pattern, is_regex=is_regex)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm


def list_permissions(db: Session, owner: Owner) -> list[HostnamePermission]:
    return list(db.scalars(select(HostnamePermission).where(HostnamePermission.owner_id == owner.id)))


def create_binding(
    db: Session, owner: Owner, fqdn: str, allowfrom: str | None = None
) -> CreatedBinding:
    """Authorize `fqdn` against `owner`'s permissions, then create a fresh acme-dns
    style (subdomain, username, password) triple bound to it. Raises NotAuthorized if
    the fqdn doesn't match any of the owner's HostnamePermission patterns.

    `allowfrom` is an optional comma-separated list of CIDR blocks restricting which
    source IPs may call /update with these credentials (mirrors real acme-dns).
    """
    perms = list_permissions(db, owner)
    if not is_authorized(fqdn, perms):
        raise NotAuthorized(f"{owner.username!r} is not permitted to bind {fqdn!r}")

    password = generate_api_key()
    binding = Binding(
        owner_id=owner.id, fqdn=fqdn, password_hash=hash_secret(password), allowfrom=allowfrom
    )
    db.add(binding)
    db.commit()
    db.refresh(binding)
    return CreatedBinding(binding=binding, plaintext_password=password)


def revoke_binding(db: Session, binding: Binding) -> None:
    binding.revoked_at = _now()
    db.add(binding)
    db.commit()


def delete_permission(db: Session, owner: Owner, permission_id: int) -> None:
    perm = db.get(HostnamePermission, permission_id)
    if perm is None or perm.owner_id != owner.id:
        raise NotFound(f"no permission {permission_id} for owner {owner.username!r}")
    db.delete(perm)
    db.commit()


def get_binding_by_username(db: Session, username: str) -> Binding | None:
    return db.scalar(select(Binding).where(Binding.username == username))


def get_binding_by_subdomain(db: Session, subdomain: str) -> Binding | None:
    return db.scalar(select(Binding).where(Binding.subdomain == subdomain))


def update_last_txt_value(db: Session, binding: Binding, value: str) -> None:
    binding.last_txt_value = value
    db.add(binding)
    db.commit()
