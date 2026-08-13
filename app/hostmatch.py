from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

from app.models import HostnamePermission


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


def matches(fqdn: str, permission: HostnamePermission) -> bool:
    fqdn = fqdn.rstrip(".").lower()
    pattern = permission.pattern.rstrip(".")
    if permission.is_regex:
        return _compiled(pattern).fullmatch(fqdn) is not None
    return fqdn == pattern.lower()


def is_authorized(fqdn: str, permissions: list[HostnamePermission]) -> bool:
    return any(matches(fqdn, p) for p in permissions)


_ACME_CHALLENGE_PREFIX = "_acme-challenge."


def is_authorized_for_challenge(fqdn: str, permissions: list[HostnamePermission]) -> bool:
    """DNS-01 clients always request the TXT record at `_acme-challenge.<realdomain>`,
    but HostnamePermission patterns are meant to describe the real-world domain an
    owner may request certs for (see README's "Authorization model"), so an exact-match
    permission for `<realdomain>` must also authorize the `_acme-challenge.`-prefixed
    name. Checks both forms so admins can grant permissions against either style."""
    if is_authorized(fqdn, permissions):
        return True
    stripped = fqdn.rstrip(".")
    if stripped.lower().startswith(_ACME_CHALLENGE_PREFIX):
        stripped = stripped[len(_ACME_CHALLENGE_PREFIX):]
        return is_authorized(stripped, permissions)
    return False


def matches_fqdn_or_challenge(candidate: str, fqdn: str) -> bool:
    """True if `candidate` is exactly `fqdn`, or `_acme-challenge.<fqdn>` -- i.e.
    whether a DNS-01 request for `candidate` is a request for the challenge record of
    `fqdn`. Same "match either spelling" rule as `is_authorized_for_challenge`, but
    for a single known fqdn (e.g. a Binding's own scope) rather than a permission
    pattern list."""
    candidate = candidate.rstrip(".").lower()
    fqdn = fqdn.rstrip(".").lower()
    return candidate == fqdn or candidate == f"{_ACME_CHALLENGE_PREFIX}{fqdn}"


def is_ip_allowed(client_ip: str, allowfrom: str | None) -> bool:
    """`allowfrom` is a comma-separated list of CIDR blocks, mirroring acme-dns's own
    `allowfrom` field. Empty/None means unrestricted (matches acme-dns default)."""
    if not allowfrom or not allowfrom.strip():
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in allowfrom.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
