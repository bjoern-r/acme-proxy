#!/usr/bin/env python3
"""Admin CLI for acme-proxy.

This is deliberately a direct-DB-access tool (not an HTTP client) -- it's meant to be
run on the box hosting the proxy, by whoever operates it, as the one and only way to
create tenants/permissions/bindings in this reference implementation.

Examples:
    python scripts/admin_cli.py init-db
    python scripts/admin_cli.py create-owner --username team-a --description "5G testbed"
    python scripts/admin_cli.py add-permission --owner team-a --pattern 'www.example.com'
    python scripts/admin_cli.py add-permission --owner team-a \\
        --pattern '.*\\.lab\\.foo\\.example\\.biz$' --regex
    python scripts/admin_cli.py create-binding --owner team-a --fqdn n104.lab.foo.example.biz
    python scripts/admin_cli.py list-owner --username team-a
"""
from __future__ import annotations

import sys
from pathlib import Path

import typer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import crud  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402

cli = typer.Typer(add_completion=False)


@cli.command(name="init-db")
def init_db_cmd() -> None:
    """Create database tables if they don't exist yet."""
    init_db()
    typer.echo("database initialized")


@cli.command(name="create-owner")
def create_owner(
    username: str = typer.Option(...), description: str = typer.Option(None)
) -> None:
    db = SessionLocal()
    try:
        existing = crud.get_owner_by_username(db, username)
        if existing is not None:
            typer.echo(f"owner {username!r} already exists", err=True)
            raise typer.Exit(1)
        created = crud.create_owner(db, username, description)
        typer.echo(f"owner created: {username}")
        typer.echo(f"  X-Api-User: {created.owner.username}")
        typer.echo(f"  X-Api-Key : {created.plaintext_api_key}   (shown once -- store it now)")
    finally:
        db.close()


@cli.command(name="add-permission")
def add_permission(
    owner: str = typer.Option(...),
    pattern: str = typer.Option(...),
    regex: bool = typer.Option(False, "--regex"),
) -> None:
    db = SessionLocal()
    try:
        owner_obj = crud.get_owner_by_username(db, owner)
        if owner_obj is None:
            typer.echo(f"no such owner: {owner}", err=True)
            raise typer.Exit(1)
        perm = crud.add_permission(db, owner_obj, pattern, regex)
        kind = "regex" if regex else "exact"
        typer.echo(f"permission added ({kind}): {perm.pattern!r} for owner {owner!r}")
    finally:
        db.close()


@cli.command(name="create-binding")
def create_binding(
    owner: str = typer.Option(...),
    fqdn: str = typer.Option(...),
    allowfrom: str = typer.Option(None, help="Comma-separated CIDR blocks, e.g. '10.0.0.0/8,203.0.113.5/32'"),
) -> None:
    db = SessionLocal()
    try:
        owner_obj = crud.get_owner_by_username(db, owner)
        if owner_obj is None:
            typer.echo(f"no such owner: {owner}", err=True)
            raise typer.Exit(1)
        try:
            created = crud.create_binding(db, owner_obj, fqdn, allowfrom=allowfrom)
        except crud.NotAuthorized as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1)

        from app.config import get_settings

        settings = get_settings()
        fulldomain = f"{created.binding.subdomain}.{settings.delegation_zone}"
        typer.echo("binding created:")
        typer.echo(f"  fqdn      : {fqdn}")
        typer.echo(f"  username  : {created.binding.username}")
        typer.echo(f"  password  : {created.plaintext_password}   (shown once -- store it now)")
        typer.echo(f"  subdomain : {created.binding.subdomain}")
        typer.echo(f"  fulldomain: {fulldomain}")
        typer.echo()
        typer.echo(f"Create this CNAME once, then configure your ACME client with the")
        typer.echo(f"username/password above:")
        typer.echo(f"  _acme-challenge.{fqdn}.  CNAME  {fulldomain}.")
    finally:
        db.close()


@cli.command(name="revoke-binding")
def revoke_binding(subdomain: str = typer.Option(...)) -> None:
    """Immediately invalidate a binding's credentials (e.g. a leaked API key)."""
    db = SessionLocal()
    try:
        binding = crud.get_binding_by_subdomain(db, subdomain)
        if binding is None:
            typer.echo(f"no such binding: {subdomain}", err=True)
            raise typer.Exit(1)
        crud.revoke_binding(db, binding)
        typer.echo(f"revoked binding for {binding.fqdn} (subdomain={subdomain})")
    finally:
        db.close()


@cli.command(name="delete-permission")
def delete_permission(owner: str = typer.Option(...), permission_id: int = typer.Option(...)) -> None:
    db = SessionLocal()
    try:
        owner_obj = crud.get_owner_by_username(db, owner)
        if owner_obj is None:
            typer.echo(f"no such owner: {owner}", err=True)
            raise typer.Exit(1)
        try:
            crud.delete_permission(db, owner_obj, permission_id)
        except crud.NotFound as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(1)
        typer.echo(f"deleted permission {permission_id} from owner {owner!r}")
    finally:
        db.close()


@cli.command(name="list-owner")
def list_owner(username: str = typer.Option(...)) -> None:
    db = SessionLocal()
    try:
        owner_obj = crud.get_owner_by_username(db, username)
        if owner_obj is None:
            typer.echo(f"no such owner: {username}", err=True)
            raise typer.Exit(1)
        typer.echo(f"owner: {owner_obj.username} ({owner_obj.description or ''})")
        typer.echo("permissions:")
        for p in crud.list_permissions(db, owner_obj):
            typer.echo(f"  - [id={p.id}] {'regex' if p.is_regex else 'exact'}: {p.pattern}")
        typer.echo("bindings:")
        for b in owner_obj.bindings:
            status_str = "REVOKED" if b.revoked_at else "active"
            typer.echo(
                f"  - [{status_str}] {b.fqdn} -> subdomain={b.subdomain} username={b.username}"
                f" allowfrom={b.allowfrom or '(any)'}"
            )
    finally:
        db.close()


if __name__ == "__main__":
    cli()
