"""Two kinds of callers, two kinds of token.

* ingest   : machines (sensor, policy layer, containment layer) posting data
* operator : humans using the console; every action is tied to their name
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Query

from .config import settings


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def require_ingest(authorization: str | None = Header(default=None)) -> str:
    token = _bearer(authorization)
    if not token or not hmac.compare_digest(token, settings.ingest_token):
        raise HTTPException(status_code=401, detail="ingest token required")
    return "ingest"


def _operator_for(token: str | None) -> str | None:
    if not token:
        return None
    for known, name in settings.operators.items():
        if hmac.compare_digest(token, known):
            return name
    return None


def require_operator(authorization: str | None = Header(default=None)) -> str:
    name = _operator_for(_bearer(authorization))
    if not name:
        raise HTTPException(status_code=401, detail="operator token required")
    return name


def require_operator_query(token: str | None = Query(default=None)) -> str:
    """For the live stream: browsers' EventSource cannot send headers."""
    name = _operator_for(token)
    if not name:
        raise HTTPException(status_code=401, detail="operator token required")
    return name
