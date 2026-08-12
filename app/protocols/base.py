from __future__ import annotations

from abc import ABC, abstractmethod

from fastapi import APIRouter


class FrontendProtocolBase(ABC):
    """Every ACME-client-facing protocol (acme-dns, the generic REST protocol, or
    anything you add later -- e.g. an RFC2136-over-HTTP bridge, a certbot
    manual-hook webhook receiver, etc.) implements this and is mounted independently
    in app/main.py. Protocols never talk to DNSBackend implementations directly except
    through app.backends.registry.get_registry(), and never touch the DB except
    through app.crud, so the two extensibility axes (protocols x backends) stay fully
    decoupled.
    """

    name: str

    @abstractmethod
    def build_router(self) -> APIRouter: ...
