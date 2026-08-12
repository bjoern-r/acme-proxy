from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Owner(Base):
    """A management-level tenant: a team, CI pipeline, or individual ACME client
    operator. Owns one or more HostnamePermission patterns and, for the acme-dns
    protocol, one or more Bindings (one per real hostname it's allowed to serve).
    """

    __tablename__ = "owners"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    permissions: Mapped[list["HostnamePermission"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    bindings: Mapped[list["Binding"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class HostnamePermission(Base):
    """One authorization rule for an Owner: either an exact FQDN, or (if is_regex) a
    regular expression matched with re.fullmatch against the requested FQDN.
    """

    __tablename__ = "hostname_permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("owners.id"))
    pattern: Mapped[str] = mapped_column(String(512))
    is_regex: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)

    owner: Mapped[Owner] = relationship(back_populates="permissions")


class Binding(Base):
    """One acme-dns 'account': a (subdomain, username, password) triple tied to a
    single real-world FQDN, owned by an Owner. Created once (admin_cli.py /
    create-binding), then used by the ACME client's acme-dns provider for every
    subsequent /update call, forever (or until revoked).
    """

    __tablename__ = "bindings"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("owners.id"))

    fqdn: Mapped[str] = mapped_column(String(255), index=True)
    subdomain: Mapped[str] = mapped_column(String(36), unique=True, default=_uuid, index=True)
    username: Mapped[str] = mapped_column(String(36), unique=True, default=_uuid, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))

    # Comma-separated list of CIDR blocks (e.g. "10.0.0.0/8,192.168.1.5/32"). Empty
    # string/None means "no IP restriction" -- matches real acme-dns's `allowfrom`
    # semantics, which is also opt-in.
    allowfrom: Mapped[str | None] = mapped_column(String(512), nullable=True)

    last_txt_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)

    owner: Mapped[Owner] = relationship(back_populates="bindings")
