from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from app.backends.base import DNSBackend

logger = logging.getLogger("acme_proxy.backends.acmesh")

_RUNNER = Path(__file__).parent / "acmesh_runner.sh"


class AcmeShDNSApiBackend(DNSBackend):
    """Reuses an existing acme.sh dnsapi/dns_XXX.sh script as the upstream driver,
    instead of reimplementing that provider's API in Python.

    acme.sh's dnsapi scripts are not standalone -- they call helper functions
    (_post, _get, _base64, _get_root, ...) that normally get defined by acme.sh itself
    before it sources the dnsapi script. `acmesh_runner.sh` reimplements the common
    subset of that helper surface and then sources the real dns_XXX.sh unmodified, so
    upgrades to acme.sh's dnsapi/ directory can just be dropped in.

    Config keys (see config.example.yaml):
      dnsapi_script:  e.g. "dns_cf"  (must match acme_sh_home/dnsapi/<name>.sh)
      acme_sh_home:   path to a checkout of https://github.com/acmesh-official/acme.sh
      env:            dict of provider-specific env vars (CF_Token, CF_Account_ID, ...)
                       -- exactly the same variables you'd export before running
                       `acme.sh --issue --dns dns_cf ...` by hand.
    """

    def __init__(
        self,
        dnsapi_script: str,
        acme_sh_home: str,
        env: dict[str, str] | None = None,
        timeout: int = 30,
        **_kwargs,
    ) -> None:
        self.func_prefix = dnsapi_script
        self.script_path = Path(acme_sh_home) / "dnsapi" / f"{dnsapi_script}.sh"
        if not self.script_path.is_file():
            raise FileNotFoundError(f"dnsapi script not found: {self.script_path}")
        self.env = env or {}
        self.timeout = timeout

    def _run(self, action: str, fqdn: str, value: str) -> None:
        cmd = ["/bin/bash", str(_RUNNER), str(self.script_path), self.func_prefix, action, fqdn, value]
        proc_env = {**os.environ, **self.env}
        result = subprocess.run(
            cmd, env=proc_env, capture_output=True, text=True, timeout=self.timeout
        )
        logger.debug("acme.sh shim stdout: %s", result.stdout)
        if result.returncode != 0:
            raise RuntimeError(
                f"acme.sh dnsapi {self.func_prefix}_{action} failed "
                f"(exit {result.returncode}):\n{result.stdout}\n{result.stderr}"
            )

    def present(self, fqdn: str, value: str) -> None:
        # Real acme.sh dnsapi scripts assume an fqdn with no trailing dot (that's what
        # acme.sh's own core always passes them) -- some ACME clients/protocols here
        # hand us one with a trailing dot instead, which then breaks provider zone
        # lookups/API calls downstream. Strip it before it ever reaches the script.
        fqdn = fqdn.rstrip(".")
        logger.debug("before acme.sh(%s) present: %s TXT %r", self.func_prefix, fqdn, value)
        self._run("add", fqdn, value)
        logger.info("acme.sh(%s) present: %s TXT %r", self.func_prefix, fqdn, value)

    def cleanup(self, fqdn: str, value: str) -> None:
        fqdn = fqdn.rstrip(".")
        self._run("rm", fqdn, value)
        logger.info("acme.sh(%s) cleanup: %s TXT %r", self.func_prefix, fqdn, value)
