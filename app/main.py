from __future__ import annotations

import logging

from fastapi import FastAPI

from app.config import get_settings
from app.database import init_db
from app.protocols.acmedns import AcmeDnsProtocol
from app.protocols.base import FrontendProtocolBase
from app.protocols.generic import GenericProtocol

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Registry of available protocol implementations, keyed by the name used in
# config.yaml's `protocols:` section. Add new protocols here.
AVAILABLE_PROTOCOLS: dict[str, type[FrontendProtocolBase]] = {
    "acmedns": AcmeDnsProtocol,
    "generic": GenericProtocol,
}


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="acme-proxy",
        description="Multi-tenant DNS-01 challenge proxy for ACME clients",
        version="0.1.0",
    )

    init_db()

    for name, protocol_cfg in settings.protocols.items():
        if not protocol_cfg.enabled:
            continue
        protocol_cls = AVAILABLE_PROTOCOLS.get(name)
        if protocol_cls is None:
            raise ValueError(f"unknown protocol in config: {name}")
        router = protocol_cls().build_router()
        app.include_router(router, prefix=protocol_cfg.prefix)
        logging.info("mounted protocol %r at prefix %r", name, protocol_cfg.prefix or "/")

    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
