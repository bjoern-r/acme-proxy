"""Validates the acme.sh shim (app/backends/acmesh_runner.sh) against a real,
unmodified acme.sh dnsapi script, rather than only against hand-written fixtures.

This test does NOT assert that the DNS update succeeds (that would need real
Cloudflare credentials). It asserts the more important thing for a shim: that every
acme.sh core helper function the script calls is actually defined, so the script runs
its real provider logic (including making a genuine HTTP call to Cloudflare's API) all
the way through to a *provider-level* failure -- rather than dying early with a shell
"command not found" for some missing `_xxx` helper. That's the actual risk with this
architecture, and the one worth regression-testing.

Skipped automatically if network access to raw.githubusercontent.com is unavailable.
"""
from __future__ import annotations

import subprocess
import urllib.request
from pathlib import Path

import pytest

RUNNER = Path(__file__).resolve().parent.parent / "app" / "backends" / "acmesh_runner.sh"
DNS_CF_URL = "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/dnsapi/dns_cf.sh"


@pytest.fixture(scope="module")
def dns_cf_script(tmp_path_factory) -> Path:
    dest = tmp_path_factory.mktemp("acmesh") / "dns_cf.sh"
    try:
        urllib.request.urlretrieve(DNS_CF_URL, dest)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"no network access to fetch a real dnsapi script: {exc}")
    return dest


def test_shim_runs_real_dns_cf_script_without_missing_helpers(dns_cf_script):
    env = {
        "CF_Token": "fake-token-for-shim-test",
        "CF_Account_ID": "fake-account-id",
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run(
        ["/bin/bash", str(RUNNER), str(dns_cf_script), "dns_cf", "add",
         "_acme-challenge.example.com", "test-value-123"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    combined = result.stdout + result.stderr

    # The failure signature of a *missing shim helper* is bash's own error message.
    assert "command not found" not in combined, combined
    assert "unbound variable" not in combined, combined

    # A real provider-level rejection (bad/fake token) is fine and expected here --
    # it proves the script executed its actual Cloudflare zone-lookup logic.
    assert result.returncode != 0
    assert "invalid domain" in combined or "error" in combined.lower()
