"""Minimal smoke tests. Run with: pytest tests/

Uses an isolated sqlite file and a config with only the `noop` backend, so this needs
no network access and no real acme.sh checkout.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient


def _make_app_client(tmp_path: Path, monkeypatch, acmedns_overrides: dict | None = None):
    db_path = tmp_path / "test.db"
    config = {
        "delegation_zone": "acme.test.example",
        "admin_master_key": "test-admin-key",
        "database_url": f"sqlite:///{db_path}",
        "protocols": {
            "acmedns": {"enabled": True, "prefix": "", **(acmedns_overrides or {})},
            "generic": {"enabled": True, "prefix": "/generic"},
            "technitium": {"enabled": True, "prefix": ""},
        },
        "backend_routes": [{"match": ".*", "regex": True, "backend": "noop"}],
        "backends": {"noop": {"driver": "noop"}},
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.dump(config))
    monkeypatch.setenv("ACME_PROXY_CONFIG", str(config_path))

    # config.get_settings() and backends.registry.get_registry() are lru_cache'd
    # module-level singletons; clear them so each test gets a fresh Settings load.
    from app.config import get_settings
    from app.backends.registry import get_registry

    get_settings.cache_clear()
    get_registry.cache_clear()

    from app.main import create_app

    return create_app()


@pytest.fixture()
def app_client(tmp_path: Path, monkeypatch):
    app = _make_app_client(tmp_path, monkeypatch)
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def direct_update_client(tmp_path: Path, monkeypatch):
    app = _make_app_client(tmp_path, monkeypatch, acmedns_overrides={"direct_update": True})
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def fqdn_subdomain_client(tmp_path: Path, monkeypatch):
    app = _make_app_client(tmp_path, monkeypatch, acmedns_overrides={"accept_fqdn_as_subdomain": True})
    with TestClient(app) as client:
        yield client


def test_healthz(app_client):
    r = app_client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_register_and_update_flow(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-a")
    crud.add_permission(db, created.owner, r".*\.lab\.example\.com$", is_regex=True)
    db.close()

    resp = app_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-a", "fqdn": "gnb1.lab.example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["fulldomain"].endswith(".acme.test.example")

    update = app_client.post(
        "/update",
        headers={"X-Api-User": body["username"], "X-Api-Key": body["password"]},
        json={"subdomain": body["subdomain"], "txt": "some-challenge-value"},
    )
    assert update.status_code == 200, update.text
    assert update.json() == {"txt": "some-challenge-value"}


def test_update_direct_mode_writes_to_real_domain(direct_update_client, caplog):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-direct")
    crud.add_permission(db, created.owner, r".*\.lab\.example\.com$", is_regex=True)
    db.close()

    resp = direct_update_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-direct", "fqdn": "gnb1.lab.example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    with caplog.at_level("INFO", logger="acme_proxy.backends.noop"):
        update = direct_update_client.post(
            "/update",
            headers={"X-Api-User": body["username"], "X-Api-Key": body["password"]},
            json={"subdomain": body["subdomain"], "txt": "some-challenge-value"},
        )
    assert update.status_code == 200, update.text
    assert update.json() == {"txt": "some-challenge-value"}

    assert any(
        "NOOP present: _acme-challenge.gnb1.lab.example.com" in record.message for record in caplog.records
    )
    assert not any(".acme.test.example" in record.message for record in caplog.records)


def test_update_accepts_fqdn_as_subdomain(fqdn_subdomain_client, caplog):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-fqdn")
    crud.add_permission(db, created.owner, r".*\.lab\.example\.com$", is_regex=True)
    db.close()

    resp = fqdn_subdomain_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-fqdn", "fqdn": "gnb2.lab.example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    headers = {"X-Api-User": body["username"], "X-Api-Key": body["password"]}

    # bare real fqdn instead of the random subdomain
    with caplog.at_level("INFO", logger="acme_proxy.backends.noop"):
        update = fqdn_subdomain_client.post(
            "/update", headers=headers, json={"subdomain": "gnb2.lab.example.com", "txt": "value-1"}
        )
    assert update.status_code == 200, update.text
    assert any(
        "NOOP present: _acme-challenge.gnb2.lab.example.com" in record.message for record in caplog.records
    )

    # "_acme-challenge."-prefixed real fqdn also accepted
    caplog.clear()
    with caplog.at_level("INFO", logger="acme_proxy.backends.noop"):
        update = fqdn_subdomain_client.post(
            "/update",
            headers=headers,
            json={"subdomain": "_acme-challenge.gnb2.lab.example.com", "txt": "value-2"},
        )
    assert update.status_code == 200, update.text
    assert any(
        "NOOP present: _acme-challenge.gnb2.lab.example.com" in record.message for record in caplog.records
    )

    # the classic random subdomain still works too
    update = fqdn_subdomain_client.post(
        "/update", headers=headers, json={"subdomain": body["subdomain"], "txt": "value-3"}
    )
    assert update.status_code == 200, update.text


def test_update_rejects_fqdn_as_subdomain_when_disabled(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-fqdn-disabled")
    crud.add_permission(db, created.owner, r".*\.lab\.example\.com$", is_regex=True)
    db.close()

    resp = app_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-fqdn-disabled", "fqdn": "gnb3.lab.example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    update = app_client.post(
        "/update",
        headers={"X-Api-User": body["username"], "X-Api-Key": body["password"]},
        json={"subdomain": "gnb3.lab.example.com", "txt": "value"},
    )
    assert update.status_code == 401


def test_update_rejects_unrelated_fqdn_even_when_enabled(fqdn_subdomain_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-fqdn-scope")
    crud.add_permission(db, created.owner, r".*\.lab\.example\.com$", is_regex=True)
    db.close()

    first = fqdn_subdomain_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-fqdn-scope", "fqdn": "gnb4.lab.example.com"},
    ).json()
    fqdn_subdomain_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-fqdn-scope", "fqdn": "gnb5.lab.example.com"},
    )

    update = fqdn_subdomain_client.post(
        "/update",
        headers={"X-Api-User": first["username"], "X-Api-Key": first["password"]},
        json={"subdomain": "gnb5.lab.example.com", "txt": "value"},
    )
    assert update.status_code == 401


def test_register_rejects_unauthorized_hostname(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-b")
    crud.add_permission(db, created.owner, "only-this.example.com", is_regex=False)
    db.close()

    resp = app_client.post(
        "/register",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"owner_username": "team-b", "fqdn": "not-this.example.com"},
    )
    assert resp.status_code == 403


def test_generic_protocol_present_and_cleanup(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-c")
    crud.add_permission(db, created.owner, r".*\.example\.org$", is_regex=True)
    db.close()

    headers = {"X-Api-User": "team-c", "X-Api-Key": created.plaintext_api_key}

    present = app_client.post(
        "/generic/present",
        headers=headers,
        json={"fqdn": "_acme-challenge.foo.example.org", "value": "abc123"},
    )
    assert present.status_code == 200, present.text

    cleanup = app_client.post(
        "/generic/cleanup",
        headers=headers,
        json={"fqdn": "_acme-challenge.foo.example.org", "value": "abc123"},
    )
    assert cleanup.status_code == 200, cleanup.text

    cleanup_no_value = app_client.post(
        "/generic/cleanup",
        headers=headers,
        json={"fqdn": "_acme-challenge.foo.example.org"},
    )
    assert cleanup_no_value.status_code == 200, cleanup_no_value.text


def test_generic_protocol_exact_permission_covers_acme_challenge_prefix(app_client):
    """A HostnamePermission is granted against the real-world domain (see README's
    "Authorization model"), but real DNS-01 clients always request the TXT record at
    `_acme-challenge.<realdomain>` -- an exact-match permission on the real domain must
    still authorize that prefixed request."""
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-j")
    crud.add_permission(db, created.owner, "exact.example.org", is_regex=False)
    db.close()

    headers = {"X-Api-User": "team-j", "X-Api-Key": created.plaintext_api_key}
    present = app_client.post(
        "/generic/present",
        headers=headers,
        json={"fqdn": "_acme-challenge.exact.example.org", "value": "abc123"},
    )
    assert present.status_code == 200, present.text


def test_generic_protocol_rejects_unauthorized_fqdn(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-d")
    crud.add_permission(db, created.owner, "allowed.example.org", is_regex=False)
    db.close()

    headers = {"X-Api-User": "team-d", "X-Api-Key": created.plaintext_api_key}
    resp = app_client.post(
        "/generic/present",
        headers=headers,
        json={"fqdn": "_acme-challenge.not-allowed.example.org", "value": "abc123"},
    )
    assert resp.status_code == 403


def test_generic_protocol_accepts_binding_credentials_for_matching_fqdn(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created_owner = crud.create_owner(db, "team-generic-binding")
    crud.add_permission(db, created_owner.owner, "gnb-binding.lab.example.com", is_regex=False)
    created_binding = crud.create_binding(db, created_owner.owner, "gnb-binding.lab.example.com")
    username = created_binding.binding.username
    password = created_binding.plaintext_password
    db.close()

    headers = {"X-Api-User": username, "X-Api-Key": password}

    present = app_client.post(
        "/generic/present",
        headers=headers,
        json={"fqdn": "_acme-challenge.gnb-binding.lab.example.com", "value": "abc123"},
    )
    assert present.status_code == 200, present.text

    # bare fqdn (no "_acme-challenge." prefix) is also accepted
    present_bare = app_client.post(
        "/generic/present",
        headers=headers,
        json={"fqdn": "gnb-binding.lab.example.com", "value": "abc123"},
    )
    assert present_bare.status_code == 200, present_bare.text

    cleanup = app_client.post(
        "/generic/cleanup",
        headers=headers,
        json={"fqdn": "_acme-challenge.gnb-binding.lab.example.com", "value": "abc123"},
    )
    assert cleanup.status_code == 200, cleanup.text


def test_generic_protocol_rejects_binding_credentials_for_other_fqdn(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created_owner = crud.create_owner(db, "team-generic-scope")
    crud.add_permission(db, created_owner.owner, r".*\.lab\.example\.com$", is_regex=True)
    created_binding = crud.create_binding(db, created_owner.owner, "scoped.lab.example.com")
    username = created_binding.binding.username
    password = created_binding.plaintext_password
    db.close()

    resp = app_client.post(
        "/generic/present",
        headers={"X-Api-User": username, "X-Api-Key": password},
        json={"fqdn": "_acme-challenge.other.lab.example.com", "value": "abc123"},
    )
    assert resp.status_code == 403


def test_generic_protocol_rejects_revoked_binding_credentials(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created_owner = crud.create_owner(db, "team-generic-revoked")
    crud.add_permission(db, created_owner.owner, "revoked-generic.example.com", is_regex=False)
    created_binding = crud.create_binding(db, created_owner.owner, "revoked-generic.example.com")
    crud.revoke_binding(db, created_binding.binding)
    username = created_binding.binding.username
    password = created_binding.plaintext_password
    db.close()

    resp = app_client.post(
        "/generic/present",
        headers={"X-Api-User": username, "X-Api-Key": password},
        json={"fqdn": "_acme-challenge.revoked-generic.example.com", "value": "abc123"},
    )
    assert resp.status_code == 401


def test_generic_protocol_binding_credentials_respect_allowfrom(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created_owner = crud.create_owner(db, "team-allowfrom-generic")
    crud.add_permission(db, created_owner.owner, "restricted-generic.example.com", is_regex=False)
    created_binding = crud.create_binding(
        db, created_owner.owner, "restricted-generic.example.com", allowfrom="203.0.113.0/24"
    )
    username = created_binding.binding.username
    password = created_binding.plaintext_password
    db.close()

    # TestClient's default client IP is 127.0.0.1 (testserver), which is outside the
    # allowed 203.0.113.0/24 block, so this must be rejected.
    resp = app_client.post(
        "/generic/present",
        headers={"X-Api-User": username, "X-Api-Key": password},
        json={"fqdn": "_acme-challenge.restricted-generic.example.com", "value": "abc123"},
    )
    assert resp.status_code == 401


def test_revoked_binding_rejected(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created_owner = crud.create_owner(db, "team-e")
    crud.add_permission(db, created_owner.owner, "revoke-me.example.com", is_regex=False)
    created_binding = crud.create_binding(db, created_owner.owner, "revoke-me.example.com")
    crud.revoke_binding(db, created_binding.binding)
    subdomain = created_binding.binding.subdomain
    username = created_binding.binding.username
    password = created_binding.plaintext_password
    db.close()

    resp = app_client.post(
        "/update",
        headers={"X-Api-User": username, "X-Api-Key": password},
        json={"subdomain": subdomain, "txt": "value"},
    )
    assert resp.status_code == 401


def test_allowfrom_restricts_update(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created_owner = crud.create_owner(db, "team-f")
    crud.add_permission(db, created_owner.owner, "restricted.example.com", is_regex=False)
    created_binding = crud.create_binding(
        db, created_owner.owner, "restricted.example.com", allowfrom="203.0.113.0/24"
    )
    subdomain = created_binding.binding.subdomain
    username = created_binding.binding.username
    password = created_binding.plaintext_password
    db.close()

    # TestClient's default client IP is 127.0.0.1 (testserver), which is outside the
    # allowed 203.0.113.0/24 block, so this must be rejected.
    resp = app_client.post(
        "/update",
        headers={"X-Api-User": username, "X-Api-Key": password},
        json={"subdomain": subdomain, "txt": "value"},
    )
    assert resp.status_code == 401


def test_technitium_protocol_add_and_delete(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-g")
    crud.add_permission(db, created.owner, r".*\.example\.net$", is_regex=True)
    db.close()

    token = f"team-g:{created.plaintext_api_key}"

    add = app_client.get(
        "/api/zones/records/add",
        params={"domain": "_acme-challenge.foo.example.net", "type": "TXT", "text": "abc123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert add.status_code == 200, add.text
    assert add.json()["status"] == "ok"

    delete = app_client.get(
        "/api/zones/records/delete",
        params={"domain": "_acme-challenge.foo.example.net", "type": "TXT", "text": "abc123", "token": token},
    )
    assert delete.status_code == 200, delete.text
    assert delete.json()["status"] == "ok"


def test_technitium_protocol_accepts_form_encoded_post(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-i")
    crud.add_permission(db, created.owner, r".*\.example\.net$", is_regex=True)
    db.close()

    token = f"team-i:{created.plaintext_api_key}"

    add = app_client.post(
        "/api/zones/records/add",
        data={"token": token, "domain": "_acme-challenge.foo.example.net", "type": "TXT", "text": "abc123"},
    )
    assert add.status_code == 200, add.text
    assert add.json()["status"] == "ok"


def test_technitium_protocol_exact_permission_covers_acme_challenge_prefix(app_client):
    """Same real-domain-vs-challenge-prefix gap as the generic protocol test above --
    an exact-match permission on the real domain (no `_acme-challenge.` prefix) must
    still authorize a `domain` param that has it, since real Technitium clients (e.g.
    acme.sh's dns_technitium) always send the prefixed name."""
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-k")
    crud.add_permission(db, created.owner, "exact.example.net", is_regex=False)
    db.close()

    token = f"team-k:{created.plaintext_api_key}"
    add = app_client.get(
        "/api/zones/records/add",
        params={"domain": "_acme-challenge.exact.example.net", "type": "TXT", "text": "abc123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert add.status_code == 200, add.text
    assert add.json()["status"] == "ok"


def test_technitium_protocol_rejects_bad_token(app_client):
    resp = app_client.get(
        "/api/zones/records/add",
        params={"domain": "foo.example.net", "type": "TXT", "text": "abc123"},
        headers={"Authorization": "Bearer team-g:wrong-key"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "invalid-token"


def test_technitium_protocol_rejects_unauthorized_domain(app_client):
    from app import crud
    from app.database import SessionLocal

    db = SessionLocal()
    created = crud.create_owner(db, "team-h")
    crud.add_permission(db, created.owner, "allowed.example.net", is_regex=False)
    db.close()

    token = f"team-h:{created.plaintext_api_key}"

    resp = app_client.get(
        "/api/zones/records/add",
        params={"domain": "not-allowed.example.net", "type": "TXT", "text": "abc123"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"
