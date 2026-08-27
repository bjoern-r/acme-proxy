# OpenRC service for acme-proxy (Alpine Linux)

Runs acme-proxy as a non-root OpenRC service on Alpine (or any OpenRC-based
system).

Files:

- `acme-proxy`       -> `/etc/init.d/acme-proxy`   (the service script)
- `acme-proxy.confd` -> `/etc/conf.d/acme-proxy`   (tunables, all optional)

## Install (run as root)

1. Packages + code + venv:

   ```sh
   apk add python3 py3-pip openrc
   install -d -m 0755 /srv
   cp -a /path/to/acme-proxy /srv/acme-proxy
   python3 -m venv /srv/acme-proxy/.venv
   /srv/acme-proxy/.venv/bin/pip install -r /srv/acme-proxy/requirements.txt
   ```

   Only needed if you use the acme.sh shim backend (`app/backends/acmesh_runner.sh`,
   whose shebang is `#!/usr/bin/env bash`):

   ```sh
   apk add bash curl
   ```

2. Config (default location: `/etc/acme-proxy/config.yaml`):

   ```sh
   install -d -m 0755 /etc/acme-proxy
   cp /srv/acme-proxy/config.example.yaml /etc/acme-proxy/config.yaml
   $EDITOR /etc/acme-proxy/config.yaml   # admin_master_key, backends, routes...
   ```

   The default `database_url: sqlite:///./data/acme_proxy.db` is relative to the
   service working dir (`/srv/acme-proxy`), so the DB lands at
   `/srv/acme-proxy/data/`. To store it elsewhere, use an absolute path, e.g.
   `database_url: "sqlite:////var/lib/acme-proxy/acme_proxy.db"`.

3. Unprivileged service user + ownership of state:

   ```sh
   addgroup -S acme-proxy
   adduser -S -D -H -h /srv/acme-proxy -s /sbin/nologin -G acme-proxy acme-proxy
   chown -R acme-proxy:acme-proxy /srv/acme-proxy/data
   ```

4. Install the service files:

   ```sh
   cp /srv/acme-proxy/contrib/openrc/acme-proxy        /etc/init.d/acme-proxy
   chmod +x /etc/init.d/acme-proxy
   cp /srv/acme-proxy/contrib/openrc/acme-proxy.confd   /etc/conf.d/acme-proxy
   ```

5. Initialize the DB (idempotent; runs as the service user so file ownership is
   correct), then enable and start:

   ```sh
   rc-service acme-proxy initdb
   rc-update add acme-proxy default
   rc-service acme-proxy start
   rc-service acme-proxy status
   ```

Logs go to `/var/log/acme-proxy/acme-proxy.log` by default. Health check:

```sh
curl -s http://127.0.0.1:8000/healthz
```

## Notes / design choices

- **Non-root by default.** Runs as `acme-proxy:acme-proxy`; OpenRC drops
  privileges via `command_user`.
- **Gotcha #1 neutralized.** `ACME_PROXY_CONFIG` is exported and the working
  dir is pinned (`directory=`), so config is found regardless of cwd, and a
  relative `database_url` (the example default) resolves under
  `/srv/acme-proxy`.
- **`initdb` runs as the service user**, not root. Running `init-db` as root
  would create the sqlite file root-owned, and the unprivileged service
  couldn't write it — so the script drops to `${ACME_PROXY_USER}` via
  `su -s /bin/sh` (the `-s` matters because the account uses `/sbin/nologin`).
  It's exposed as `rc-service acme-proxy initdb` and is idempotent.
- **Graceful shutdown.** uvicorn stays in the foreground; OpenRC backgrounds it
  and tracks the PID. `retry="TERM/30/KILL/5"` gives uvicorn up to 30s to drain
  in-flight requests before SIGKILL.
- **uvicorn resolution.** Prefers `${ACME_PROXY_VENV}/bin/uvicorn`, else system
  `uvicorn` (e.g. `apk add py3-uvicorn`). A venv is more reliable since not all
  deps (e.g. `py3-pydantic-settings`) are packaged on Alpine.
- **sqlite + workers.** Default `ACME_PROXY_WORKERS=1` because the example
  `database_url` is sqlite; multiple workers writing one sqlite file cause
  "database is locked" errors. Bump it only with a server DB.
- **Auto-restart on crash** is *not* enabled (`command_background=true` doesn't
  respawn). If you want that, switch to the supervise-daemon supervisor —
  replace `command_background=true` with `supervisor="supervise-daemon"` and add
  `respawn_delay=5` / `respawn_max=0` in `/etc/conf.d/acme-proxy`
  (see `man openrc-run`).
- **`ACME_PROXY_EXTRA_ARGS`** is appended verbatim and whitespace-split (no
  shell quoting), so keep individual flags space-free (e.g.
  `--proxy-headers --forwarded-allow-ips=127.0.0.1`).
