"""Loads config.yaml into typed settings objects.

Kept deliberately separate from pydantic-settings' env-var machinery: the backend
routing table and per-backend parameters are naturally a nested structure that's much
more pleasant to hand-edit as YAML than as flat environment variables.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ProtocolConfig(BaseModel):
    enabled: bool = True
    prefix: str = ""


class BackendRouteConfig(BaseModel):
    match: str
    regex: bool = False
    backend: str


class BackendConfig(BaseModel):
    driver: str
    # Driver-specific parameters are passed through as-is; each backend driver
    # validates/consumes the keys it needs. Keeping this as a free-form dict is what
    # makes adding a new backend driver a one-file change (no changes to this schema).
    model_config = {"extra": "allow"}


class Settings(BaseModel):
    delegation_zone: str
    admin_master_key: str
    database_url: str = "sqlite:///./acme_proxy.db"
    protocols: dict[str, ProtocolConfig] = Field(default_factory=dict)
    backend_routes: list[BackendRouteConfig] = Field(default_factory=list)
    backends: dict[str, BackendConfig] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Settings":
        with open(path, "r") as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
        return cls.model_validate(raw)


@lru_cache
def get_settings() -> Settings:
    config_path = os.environ.get("ACME_PROXY_CONFIG", "config.yaml")
    return Settings.load(config_path)
