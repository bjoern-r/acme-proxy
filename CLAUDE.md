# CLAUDE.md

Guidance for Claude Code (or any coding agent) picking up development on this project.
Read this before making changes — several of the gotchas below were discovered the
hard way and re-breaking them is easy to do by accident.

## What this is

A multi-tenant DNS-01 challenge proxy for ACME clients (Traefik, Caddy, acme.sh, lego,
certbot). See `README.md` for the full architecture writeup and setup instructions —
this file is about *how to work on the code*, not what it does.

Two independent plugin axes:
- **Frontend protocols** (`app/protocols/`) — how ACME clients talk to us (acme-dns
  spec, a generic REST protocol, extend with more).
- **Backends** (`app/backends/`) — how we talk to upstream DNS (RFC2136, acme.sh
  dnsapi shim, noop, extend with more).

They never talk to each other directly; protocols call `app.backends.registry.get_registry().resolve(fqdn)`
to get a `DNSBackend` instance, and never touch the DB except through `app.crud`.
Keep new code following that separation.

## Running things

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml   # edit as needed; noop backend needs no editing
python scripts/admin_cli.py init-db
python -m pytest tests/ -v            # run this after every change, see below
uvicorn app.main:app --reload         # must be run from the repo root (see gotcha #1)
```

Interactive API docs at `/docs` once running (FastAPI default).

## Gotchas (read before touching these files)

1. **`app/config.py` reads `config.yaml` via a relative path** (`os.environ.get("ACME_PROXY_CONFIG", "config.yaml")`).
   `uvicorn`/`pytest`/the admin CLI must all be run from the repo root, or with
   `ACME_PROXY_CONFIG` set to an absolute path. If you see
   `FileNotFoundError: config.yaml`, this is why — it's not a bug, just check your cwd.
   Tests don't hit this because `tests/test_service.py`'s fixture sets
   `ACME_PROXY_CONFIG` to an absolute tmp path per test.

2. **`get_settings()` and `get_registry()` are `@lru_cache`'d module-level singletons.**
   If you change config in a test or REPL session, you must call `.cache_clear()` on
   both before the change takes effect — see the `app_client` fixture in
   `tests/test_service.py` for the pattern. Forgetting this is the #1 cause of "I
   edited config.yaml but nothing changed" confusion during interactive debugging.

3. **`acmesh_runner.sh` deliberately does NOT use `set -euo pipefail`.** Real acme.sh
   doesn't run its dnsapi scripts under nounset/errexit, and the scripts rely on that
   (references to possibly-unset optional vars, non-zero exits from grep treated as
   normal control flow). Adding strict mode back will break real dnsapi scripts that
   work fine under real acme.sh — this was tested and reverted once already, don't
   redo it without re-running `tests/test_acmesh_shim.py` against a couple of
   different real dnsapi scripts to confirm.

4. **Don't try to source the real `acme.sh` main script to get its helpers "for
   free."** It was considered and rejected: acme.sh's main script may call `exit`
   internally on argument-parsing paths, which would kill the sourcing shell before
   the target dnsapi script's add/rm function ever runs. `acmesh_runner.sh`
   reimplements the helper surface from scratch instead. If you're tempted to revisit
   this, prototype it in isolation first (`bash -c '. acme.sh --help; echo survived'`)
   before wiring it into the runner.

5. **The acme.sh shim covers a subset of acme.sh's helper functions**, enough for
   most curl-based REST providers (see the list at the top of `acmesh_runner.sh`). It
   does not implement AWS SigV4, OAuth flows, or other provider-specific auth helpers.
   When adding support for a new provider script, first try it directly:
   ```bash
   CF_Token=... bash app/backends/acmesh_runner.sh /path/to/dnsapi/dns_XXX.sh dns_XXX add _acme-challenge.example.com testvalue
   ```
   If it fails with `command not found: _something`, that's a missing helper — add it
   to `acmesh_runner.sh`, not to `acmesh.py`. If it fails after making a real HTTP call
   to the provider's API (auth/permission error), the shim is working correctly and
   the failure is credentials-related.

6. **`Owner.username` is the acme-dns/generic-protocol login identity; `Binding.username`
   is a separate, unrelated per-binding UUID.** Don't conflate them — an Owner can have
   many Bindings, each with its own independent username/password pair, precisely so a
   leaked Binding credential (used by one ACME client, for one hostname) doesn't expose
   the Owner's admin-level credential (used to create new bindings).

7. **The acme-dns protocol's `/update` never calls `backend.cleanup()`.** This matches
   real acme-dns semantics: the CNAME is permanent, the TXT record just gets
   overwritten on each renewal, and real ACME clients' acme-dns providers implement
   `CleanUp()` as a no-op. Don't "fix" this by adding a cleanup call — it would be
   spec-incorrect and no real client would ever trigger it anyway.

8. **`DeprecationWarning` about `datetime.datetime.utcnow()`** in the test output is
   known and currently harmless (SQLAlchemy's default-column-value warning fires
   during table creation regardless). Fine to fix opportunistically if you're already
   editing `app/models.py` or `app/crud.py`, but it's not worth a standalone change.

## Adding a new frontend protocol

1. Create `app/protocols/your_protocol.py`, subclass `FrontendProtocolBase`
   (`app/protocols/base.py`), implement `build_router() -> APIRouter`.
2. Auth: reuse `app.auth.get_current_owner` (owner-level, permission-checked per
   request) or `app.auth.get_current_binding` (binding-level, acme-dns style) as
   dependencies — don't write new auth logic unless the protocol genuinely needs a
   third auth shape.
3. Resolve backends via `app.backends.registry.get_registry().resolve(fqdn)`, never
   instantiate a `DNSBackend` subclass directly.
4. Register it in `AVAILABLE_PROTOCOLS` in `app/main.py`.
5. Add it to `config.example.yaml`'s `protocols:` section (disabled by default unless
   you're confident it's ready).
6. Add tests in `tests/` following the `app_client` fixture pattern in
   `tests/test_service.py` — every protocol should have at least one success-path
   test and one authorization-rejection test.

## Adding a new backend driver

1. Create `app/backends/your_driver.py`, subclass `DNSBackend` (`app/backends/base.py`),
   implement `present(fqdn, value)` and `cleanup(fqdn, value)`. Constructor kwargs come
   straight from that backend's `config.yaml` entry (minus `driver`), so keep kwarg
   names matching what you'll document in `config.example.yaml`.
2. Register the driver name in `DRIVERS` in `app/backends/registry.py`.
3. Document its config shape in `config.example.yaml` with a commented example.
4. If it shells out or hits real network services, write a test that at minimum
   confirms the command/request is constructed correctly with a fake target (see
   `tests/test_acmesh_shim.py` for the "run it against something real, assert it fails
   for the *right* reason" pattern — this catches missing-helper/wrong-argument bugs
   that a pure-mock unit test won't).

## Testing conventions

- `tests/test_service.py` — full-stack API tests via `TestClient`, isolated sqlite DB
  and `noop` backend per test (no real network/DNS needed). This is the pattern to
  copy for new protocol/permission/auth behavior.
- `tests/test_acmesh_shim.py` — validates the acme.sh shim against a real dnsapi
  script fetched from GitHub at test time; skips gracefully if there's no network
  access. This is the pattern to copy when validating shim changes or adding support
  for a new provider script.
- Run `python -m pytest tests/ -v` before considering any change done. All tests
  should pass; a skipped `test_acmesh_shim` (no network) is acceptable, a failing one
  is not.
- There is currently no test for `app/backends/rfc2136.py` against a real nameserver —
  if you're working in that file, consider adding one (e.g. spin up a throwaway BIND
  or `dnspython`-based test server) rather than trusting the manual smoke test alone.

## Things intentionally NOT implemented (don't be surprised, ask before adding)

- No self-service `/register` for the acme-dns protocol (admin-gated by design — see
  README "Security notes"). If a task asks for open self-registration, that's a
  deliberate policy change, not a bug fix — confirm before doing it.
- No HTTP-based admin API, only `scripts/admin_cli.py` (direct DB access). Fine to add
  one if asked, but it doesn't exist yet — don't assume there's an `/admin/*` router
  hiding somewhere.
- No rate limiting on any endpoint.
- No structured/JSON logging — just Python's stdlib `logging` with plain formatting.
