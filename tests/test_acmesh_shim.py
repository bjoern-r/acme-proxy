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

import http.server
import subprocess
import threading
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


def test_post_helper_forwards_fifth_arg_as_content_type(tmp_path):
    """Regression test for a real bug: real acme.sh's `_post` takes the request
    Content-Type as its 5th positional argument (e.g. current dns_acmedns.sh calls
    `_post "$data" "$url" "" "POST" "application/json"`). The shim's `_post` used to
    silently drop that argument, so curl fell back to its own default of
    "application/x-www-form-urlencoded" for -d/--data -- breaking any JSON API
    (including this proxy's own /update) that validates Content-Type strictly."""
    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            received["content_type"] = self.headers.get("Content-Type")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args) -> None:  # noqa: D401 -- silence test output
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        fake_script = tmp_path / "dns_fake.sh"
        fake_script.write_text(
            "dns_fake_add() {\n"
            f'  _post \'{{"fake": "body"}}\' "http://127.0.0.1:{port}/" "" "POST" "application/json"\n'
            "}\n"
        )
        result = subprocess.run(
            ["/bin/bash", str(RUNNER), str(fake_script), "dns_fake", "add",
             "_acme-challenge.example.com", "test-value-123"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert received.get("content_type") == "application/json"


def test_hmac_helper_matches_real_acme_sh_semantics(tmp_path):
    """Regression test for a real bug: real acme.sh's `_hmac` signature is
    `_hmac <alg> <secret_hex> [outputhex]` (secret as HEX, alg first) -- widely relied
    on by real dnsapi scripts (dns_aws.sh, dns_aurora.sh, dns_active24.sh, and many
    more all call it this way). The shim's `_hmac` used to take `<key> <alg>` (swapped)
    and treated the key as a literal passphrase instead of hex, so any real script
    calling it the normal way got either a wrong signature or an outright
    "Unknown option or message digest" openssl crash."""
    # HMAC-SHA256("The quick brown fox jumps over the lazy dog", key=hex"6b6579")
    # cross-checked against Python's hmac module.
    expected = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    fake_script = tmp_path / "dns_fake_hmac.sh"
    fake_script.write_text(
        "dns_fake_hmac_add() {\n"
        '  printf "%s" "The quick brown fox jumps over the lazy dog" | _hmac sha256 "6b6579" hex\n'
        "}\n"
    )
    result = subprocess.run(
        ["/bin/bash", str(RUNNER), str(fake_script), "dns_fake_hmac", "add",
         "_acme-challenge.example.com", "test-value-123"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == expected
