from __future__ import annotations

import logging

from app.backends.base import DNSBackend

logger = logging.getLogger("acme_proxy.backends.noop")


class NoopBackend(DNSBackend):
    """Logs what it would have done and does nothing else. Useful as a safe fallback
    route while wiring up real backends, and in tests."""

    def __init__(self, **_kwargs) -> None:
        pass

    def present(self, fqdn: str, value: str) -> None:
        logger.info("NOOP present: %s TXT %r", fqdn, value)

    def cleanup(self, fqdn: str, value: str) -> None:
        logger.info("NOOP cleanup: %s TXT %r", fqdn, value)
