import json
import os
import tempfile

_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ.setdefault("RIVER3_DATABASE_URL", f"sqlite:///{_db.name}")
os.environ["RIVER3_SECRET_KEY"] = "test-secret-key-that-is-long-enough-123456"
os.environ["RIVER3_LLM_BASE_URL"] = "http://127.0.0.1:9/v1"  # nothing listens: forces fallback
os.environ["RIVER3_LLM_TIMEOUT"] = "1"
os.environ["RIVER3_AUTH_FAIL_LIMIT"] = "5"
os.environ["RIVER3_ROLES"] = json.dumps({"night-shift": ["read", "act"]})
os.environ["RIVER3_PRINCIPALS"] = json.dumps([
    {"name": "alice", "kind": "operator", "role": "admin", "token": "op-admin"},
    {"name": "bob", "kind": "operator", "role": "viewer", "token": "op-viewer"},
    {"name": "nina", "kind": "operator", "role": "night-shift", "token": "op-night"},
    {"name": "ray", "kind": "operator", "role": "responder", "token": "op-resp"},
    # scoped operator (CONTRACTS §6): sees and acts on the "payments" team only
    {"name": "tina", "kind": "operator", "role": "responder", "teams": ["payments"], "token": "op-team"},
    {"name": "sensor-1", "kind": "machine", "role": "sensor", "token": "m-sensor"},
    {"name": "policy-1", "kind": "machine", "role": "policy", "token": "m-policy"},
    {"name": "contain-1", "kind": "machine", "role": "containment", "token": "m-contain"},
    {"name": "gw-1", "kind": "machine", "role": "gateway", "token": "m-gateway"},
    {"name": "rev-1", "kind": "machine", "role": "revoker", "token": "m-revoker"},
])

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def H(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


ADMIN, VIEWER, NIGHT, RESPONDER, TEAM = H("op-admin"), H("op-viewer"), H("op-night"), H("op-resp"), H("op-team")
SENSOR, POLICY, CONTAIN, GATEWAY, REVOKER = H("m-sensor"), H("m-policy"), H("m-contain"), H("m-gateway"), H("m-revoker")


@pytest.fixture(scope="session")
def c():
    from river3_api.main import app
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _reset_limiter():
    from river3_api.security import limiter
    limiter.reset()
    yield
