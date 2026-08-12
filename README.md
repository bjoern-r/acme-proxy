# acme-proxy

A multi-tenant DNS-01 challenge proxy for ACME clients (Traefik, Caddy, acme.sh, lego,
certbot, ...), built with FastAPI.

It solves one problem: you want several ACME clients (on different hosts, run by
different teams) to be able to publish `_acme-challenge` TXT records for **their own**
hostnames, without handing each of them credentials for your real DNS provider(s), and
without running your own authoritative nameserver.

## Architecture

```
ACME client (Traefik/acme.sh/lego/...)
        │  speaks one of several *frontend protocols*
        ▼
┌─────────────────────────────────────────────────┐
│  FastAPI app  (app/main.py)                     │
│                                                 │
│  protocols/  (pluggable, mounted routers)       │
│    - acmedns.py   -> acme-dns protocol          │
│    - generic.py   -> lego-httpreq-style REST    │
│    - ...add your own...                         │
│                                                 │
│  auth.py + hostmatch.py                         │
│    - authenticate the caller                    │
│    - authorize requested hostname               │
│      (exact match OR regex, per user)           │
│                                                 │
│  backends/  (pluggable upstream drivers)        │
│    - acmesh.py   -> reuses acme.sh dnsapi/*.sh  │
│    - rfc2136.py  -> native RFC2136 DNS UPDATE   │
│    - noop.py     -> logs only, for testing      │
│    - ...add your own...                         │
└─────────────────────────────────────────────────┘
        │
        ▼
   real upstream DNS (Cloudflare, PowerDNS, BIND, ...)
```

Two independent extensibility axes, matching the two things you asked for:

1. **Multiple ACME-client-facing protocols** ("frontend protocols"). Each protocol is a
   self-contained `APIRouter` factory implementing `app/protocols/base.py`. Ship as many
   as you like side by side; each ACME client only ever talks to the one it natively
   understands.
2. **Multiple upstream DNS backends**, selected per-hostname via config, each
   implementing the 2-method `DNSBackend` interface in `app/backends/base.py`.
   `AcmeShDNSApiBackend` lets you reuse any of the ~150 shell scripts in acme.sh's
   `dnsapi/` folder instead of reimplementing every provider's API in Python.

## Authorization model

- An **Owner** is a management-level account (e.g. "team-a", "ci-pipeline-5g-testbed").
- Each Owner has one or more **HostnamePermission** rows: a pattern (exact string or
  regex) describing which real-world FQDNs that owner may request TXT records for.
- The **generic** protocol checks the permission list on *every* present/cleanup call
  (the FQDN is part of every request, so this is straightforward).
- The **acme-dns** protocol only ever receives an opaque `subdomain` on `/update` (that's
  the real acme-dns spec — it doesn't send the real hostname on every renewal). So the
  hostname<->owner<->permission check happens once, at **binding creation time** (an
  admin-only step, see below), and the resulting `subdomain`/`username`/`password`
  triple is what you paste into Traefik/acme.sh/lego's config. This matches how acme-dns
  is used in practice: register once, store credentials, renew forever after.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml   # edit backend routing + admin key
python scripts/admin_cli.py init-db
```

### 1. Create an owner and a hostname permission

```bash
python scripts/admin_cli.py create-owner --username team-a --description "5G testbed"
# -> prints the owner's admin API key, save it

python scripts/admin_cli.py add-permission --owner team-a \
    --pattern '.*\.lab\.foo\.example\.biz$' --regex

python scripts/admin_cli.py add-permission --owner team-a \
    --pattern 'www.example.com'
```

### 2a. acme-dns protocol: create a binding (once per real hostname)

```bash
python scripts/admin_cli.py create-binding --owner team-a --fqdn n104.lab.foo.example.biz
```

This checks `n104.lab.foo.example.biz` against team-a's permissions, and if allowed,
prints something like:

```json
{
  "username": "d1c1c1e4-...",
  "password": "REDACTED-plaintext-shown-once",
  "fulldomain": "8f2b....acme.example.org",
  "subdomain": "8f2b....",
  "allowfrom": []
}
```

Create the CNAME once:

```
_acme-challenge.n104.lab.foo.example.biz. CNAME 8f2b....acme.example.org.
```

Then configure your ACME client (this is 100% standard acme-dns, so Traefik/acme.sh/lego
need zero plugins — see their docs for `ACME_DNS_*` / `ACMEDNS_*` env vars).

### 2b. generic protocol: no pre-registration needed

The generic protocol checks the owner's permissions on every call, so there's no
binding step. Just give the ACME client the owner's own API key and point it at
`/generic/present` and `/generic/cleanup` (see `app/protocols/generic.py` for the exact
request/response shape — it mirrors lego's `httpreq` provider).

## Backend routing (`config.yaml`)

```yaml
backend_routes:
  - match: '.*\.lab\.foo\.example\.biz$'
    regex: true
    backend: rfc2136_lab
  - match: 'example.com'
    regex: false
    backend: acmesh_cloudflare

backends:
  rfc2136_lab:
    driver: rfc2136
    nameserver: "10.0.0.53"
    zone: "lab.foo.example.biz"
    tsig_key_name: "acme-proxy."
    tsig_key_secret: "base64secret=="
    tsig_algorithm: "hmac-sha256"

  acmesh_cloudflare:
    driver: acmesh
    dnsapi_script: dns_cf          # acme.sh/dnsapi/dns_cf.sh
    acme_sh_home: /opt/acme.sh
    env:
      CF_Token: "xxxxx"
      CF_Account_ID: "xxxxx"
```

The first matching route wins; routes are tried top to bottom. Add as many backends and
routes as you need — this is exactly how you plug in "multiple upstream DNS services."

## The acme.sh shim (`app/backends/acmesh.py` + `app/backends/acmesh_runner.sh`)

acme.sh's `dnsapi/*.sh` scripts are **not** standalone — they call shared helper
functions (`_post`, `_get`, `_base64`, `_get_root`, `_err`, `_info`, ...) that normally
live in the main `acme.sh` script and are only defined when acme.sh itself runs. Sourcing
the real `acme.sh` file is risky (it may call `exit` internally and kill the wrapper), so
`acmesh_runner.sh` ships a **from-scratch reimplementation of the common helper
surface** (HTTP GET/POST via curl with custom headers, base64/URL encoding, HMAC, a
`_get_root` zone-walker, account-config persistence no-ops, plus logging stubs).

This has been validated against a real, unmodified `dns_cf.sh` (Cloudflare) pulled
straight from the acme.sh repo (`tests/test_acmesh_shim.py`): with fake credentials, it
runs the provider's *actual* zone-detection logic and makes genuine HTTP calls to
Cloudflare's API, only failing at the point a real invalid token would fail. That's the
right failure mode — it proves no shim helper was missing, as opposed to dying early
with a shell "command not found."

This covers most simple REST-based providers (Cloudflare, DNSPod, most "dns_XXX" scripts
that just do curl calls). It does **not** cover providers needing more exotic helpers
(AWS SigV4, OAuth token flows, etc.) out of the box — those need their specific missing
helper(s) added to the runner. Treat it as "most providers work unmodified, the rest
need a small helper added," not "every acme.sh dnsapi script works with zero changes."
If a script fails with a shell error naming an undefined `_xxx` function, add it to
`acmesh_runner.sh` — `tests/test_acmesh_shim.py` is a good template for smoke-testing
any additional provider script the same way before trusting it in production.

Also note: this is deliberately a *stateless* shim. acme.sh normally persists
credentials to `~/.acme.sh/account.conf` between runs; here every credential the
provider needs must be supplied via config.yaml's backend `env` block on every call,
and the `_*accountconf*` family of helpers are safe no-ops.

## Access control details

- **Hostname authorization**: `HostnamePermission` rows per Owner, exact or regex
  (`re.fullmatch`), enforced on every `/generic/present|cleanup` call and once at
  `create-binding` time for the acme-dns protocol.
- **allowfrom (source-IP restriction)**: optional, comma-separated CIDR list stored per
  Binding, enforced on every acme-dns `/update` call — mirrors real acme-dns's
  `allowfrom` field. Omit it (leave `None`) for no IP restriction.
- **Revocation**: `admin_cli.py revoke-binding --subdomain <uuid>` immediately
  invalidates a binding's credentials without deleting its history.

## Extending

- **New frontend protocol**: subclass `FrontendProtocolBase` in `app/protocols/base.py`,
  implement `build_router()`, register it in `app/main.py`.
- **New backend**: subclass `DNSBackend` in `app/backends/base.py`, implement
  `present()`/`cleanup()`, register the driver name in `app/backends/registry.py`.

## Security notes

- API keys are stored bcrypt-hashed; plaintext is only ever shown once, at creation time.
- The admin CLI is the only way to create owners/permissions/bindings in this reference
  implementation — there's no open self-registration endpoint, unlike vanilla acme-dns.
  This is a deliberate choice for multi-tenant governance; see `app/protocols/acmedns.py`
  if you want to add a gated self-service `/register` later.
- Run this behind TLS. Credentials for both protocols travel as headers/body fields.
