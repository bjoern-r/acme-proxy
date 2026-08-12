from __future__ import annotations

import logging

import dns.query
import dns.tsig
import dns.tsigkeyring
import dns.update

from app.backends.base import DNSBackend

logger = logging.getLogger("acme_proxy.backends.rfc2136")

_ALGORITHMS = {
    "hmac-md5": dns.tsig.HMAC_MD5,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha224": dns.tsig.HMAC_SHA224,
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


class RFC2136Backend(DNSBackend):
    """Native RFC 2136 DNS UPDATE backend, TSIG-authenticated. Talks directly to an
    authoritative nameserver -- no acme.sh involved. This is the natively-supported
    DNS-01 mechanism in Traefik/lego (`--dns rfc2136`) and acme.sh (`dns_nsupdate`), so
    it's worth having as a first-class Python driver too, e.g. if you want this proxy
    to *be* the RFC2136 target for a small internal zone rather than shelling out.
    """

    def __init__(
        self,
        nameserver: str,
        zone: str,
        tsig_key_name: str,
        tsig_key_secret: str,
        tsig_algorithm: str = "hmac-sha256",
        port: int = 53,
        ttl: int = 60,
        use_tcp: bool = True,
        **_kwargs,
    ) -> None:
        self.nameserver = nameserver
        self.port = port
        self.zone = zone.rstrip(".") + "."
        self.ttl = ttl
        self.use_tcp = use_tcp
        algo = _ALGORITHMS.get(tsig_algorithm.lower())
        if algo is None:
            raise ValueError(f"unsupported TSIG algorithm: {tsig_algorithm}")
        self.keyring = dns.tsigkeyring.from_text({tsig_key_name: tsig_key_secret})
        self.keyalgorithm = algo

    def _send(self, update: "dns.update.Update") -> None:
        if self.use_tcp:
            response = dns.query.tcp(update, self.nameserver, port=self.port, timeout=10)
        else:
            response = dns.query.udp(update, self.nameserver, port=self.port, timeout=10)
        rcode = response.rcode()
        if rcode != 0:
            raise RuntimeError(f"RFC2136 update to {self.nameserver} failed: rcode={rcode}")

    def present(self, fqdn: str, value: str) -> None:
        update = dns.update.Update(
            self.zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm
        )
        update.add(fqdn.rstrip(".") + ".", self.ttl, "TXT", f'"{value}"')
        self._send(update)
        logger.info("RFC2136 present: %s TXT %r via %s", fqdn, value, self.nameserver)

    def cleanup(self, fqdn: str, value: str) -> None:
        update = dns.update.Update(
            self.zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm
        )
        update.delete(fqdn.rstrip(".") + ".", "TXT", f'"{value}"')
        self._send(update)
        logger.info("RFC2136 cleanup: %s TXT %r via %s", fqdn, value, self.nameserver)
