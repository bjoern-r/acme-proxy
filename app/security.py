from __future__ import annotations

import secrets

import bcrypt


def generate_api_key(length: int = 32) -> str:
    """URL-safe random secret suitable for use as either an Owner admin key or a
    per-Binding acme-dns password."""
    return secrets.token_urlsafe(length)


def hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_secret(secret: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(secret.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # malformed hash in DB -- fail closed
        return False
