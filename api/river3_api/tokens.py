"""Token helpers with no side effects (safe to import from the CLI before config is valid)."""
from __future__ import annotations

import hashlib
import secrets


def sha256_hex(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return "r3_" + secrets.token_urlsafe(32)
