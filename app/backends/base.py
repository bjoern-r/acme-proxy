from __future__ import annotations

from abc import ABC, abstractmethod


class DNSBackend(ABC):
    """Interface every upstream DNS driver implements. Two methods, mirroring the ACME
    DNS-01 lifecycle exactly (present the challenge record, then clean it up once
    validation is done) -- this is deliberately the same shape as lego's
    challenge.Provider interface and acme.sh's dns_xxx_add/dns_xxx_rm pair, so wrapping
    either kind of existing implementation is mechanical.
    """

    @abstractmethod
    def present(self, fqdn: str, value: str) -> None:
        """Create/update the TXT record at `fqdn` (e.g. `_acme-challenge.example.com`)
        with content `value`. Must be idempotent."""

    @abstractmethod
    def cleanup(self, fqdn: str, value: str) -> None:
        """Remove the TXT record created by present(). Must not raise if it's already
        gone -- cleanup is best-effort."""
