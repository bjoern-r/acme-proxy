from __future__ import annotations

import re
from functools import lru_cache

from app.backends.acmesh import AcmeShDNSApiBackend
from app.backends.base import DNSBackend
from app.backends.noop import NoopBackend
from app.backends.rfc2136 import RFC2136Backend
from app.config import BackendRouteConfig, Settings, get_settings

# Adding a new backend driver is a one-line addition here plus one new module in
# app/backends/. No other file needs to change.
DRIVERS: dict[str, type[DNSBackend]] = {
    "noop": NoopBackend,
    "rfc2136": RFC2136Backend,
    "acmesh": AcmeShDNSApiBackend,
}


class UnroutableHostname(Exception):
    pass


class BackendRegistry:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._instances: dict[str, DNSBackend] = {}

    def _get_instance(self, name: str) -> DNSBackend:
        if name not in self._instances:
            cfg = self._settings.backends[name]
            driver_cls = DRIVERS.get(cfg.driver)
            if driver_cls is None:
                raise ValueError(f"unknown backend driver: {cfg.driver}")
            kwargs = cfg.model_dump(exclude={"driver"})
            self._instances[name] = driver_cls(**kwargs)
        return self._instances[name]

    def resolve(self, fqdn: str) -> DNSBackend:
        fqdn_norm = fqdn.rstrip(".").lower()
        for route in self._settings.backend_routes:
            if _route_matches(route, fqdn_norm):
                return self._get_instance(route.backend)
        raise UnroutableHostname(f"no backend_routes entry matches {fqdn!r}")


def _route_matches(route: BackendRouteConfig, fqdn: str) -> bool:
    pattern = route.match.rstrip(".").lower()
    if route.regex:
        return re.fullmatch(pattern, fqdn) is not None
    return fqdn == pattern


@lru_cache
def get_registry() -> BackendRegistry:
    return BackendRegistry(get_settings())
