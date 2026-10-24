"""Tests for every security control. If one of these fails, don't ship."""
import hashlib
import hmac
import time
import json

import pytest

from conftest import ADMIN, CONTAIN, H, NIGHT, POLICY, SENSOR, VIEWER

from river3_api.config import Settings, validate
from river3_api.security import ConfigError, load_principals, load_roles, sign_webhook


# ---------------------------------------------------------------- authentication
def test_no_token_and_wrong_token(c):
    assert c.get("/api/v1/incidents").status_code == 401
    assert c.get("/api/v1/incidents", headers=H("nope")).status_code == 401


def test_failed_auth_is_throttled(c):
    for _ in range(5):
        assert c.get("/api/v1/me", headers=H("wrong")).status_code == 401
    # further bad tokens from that client are refused until the window passes ...
    assert c.get("/api/v1/me", headers=H("wrong")).status_code == 429
    # ... but a valid token is never locked out by someone else's failures (shared proxy IP)
    assert c.get("/api/v1/me", headers=ADMIN).status_code == 200


# ---------------------------------------------------------------- authorization
@pytest.mark.parametrize("hdr,path,method,expect", [
    (VIEWER, "/api/v1/incidents", "get", 200),
    (VIEWER, "/api/v1/audit", "get", 403),            # viewers can't read the audit log
    (ADMIN, "/api/v1/audit", "get", 200),
    (SENSOR, "/api/v1/incidents", "get", 403),         # machines can't read the console
    (CONTAIN, "/api/v1/actions", "get", 200),
    (POLICY, "/api/v1/actions", "get", 403),           # only containment picks up actions
    (VIEWER, "/api/v1/actions", "get", 403),
])
def test_permission_matrix(c, hdr, path, method, expect):
    assert getattr(c, method)(path, headers=hdr).status_code == expect


def test_operators_cannot_ingest_and_sensor_cannot_open_incidents(c):
    wl = {"id": "x-1", "name": "x", "profile": "p"}
    assert c.post("/api/v1/workloads", headers=ADMIN, json=wl).status_code == 403
    assert c.post("/api/v1/workloads", headers=SENSOR, json=wl).status_code == 201
    inc = {"workload_id": "x-1", "title": "t", "severity": "high", "verdict": "prohibited", "rule": "r"}
    assert c.post("/api/v1/incidents", headers=SENSOR, json=inc).status_code == 403
    assert c.post("/api/v1/incidents", headers=POLICY, json=inc).status_code == 201


def test_viewer_cannot_act_but_custom_role_can(c):
    c.post("/api/v1/workloads", headers=POLICY, json={"id": "x-2", "name": "x", "profile": "p", "kind": "ai_worker"})
    iid = c.post("/api/v1/incidents", headers=POLICY, json={
        "workload_id": "x-2", "title": "t", "severity": "high", "verdict": "prohibited", "rule": "r"}).json()["id"]
    body = {"action": "resolve", "reason": "reviewed and resolved"}
    assert c.post(f"/api/v1/incidents/{iid}/actions", headers=VIEWER, json=body).status_code == 403
    r = c.post(f"/api/v1/incidents/{iid}/actions", headers=NIGHT, json=body)  # business-defined role
    assert r.status_code == 201 and r.json()["operator"] == "nina"
    # night-shift has no "summarize"
    assert c.post(f"/api/v1/incidents/{iid}/summary", headers=NIGHT).status_code == 403


def test_me_reports_role(c):
    me = c.get("/api/v1/me", headers=NIGHT).json()
    assert me == {"operator": "nina", "role": "night-shift", "permissions": ["act", "read"], "teams": []}


# ---------------------------------------------------------------- config validation
def _settings(**kw):
    s = Settings()
    return Settings(**{**s.__dict__, **kw})


def test_production_refuses_unsafe_config():
    s = _settings(env="production", secret_key="short", secret_key_set=True, principals_raw=None,
                  database_url="sqlite:///x.db", action_webhook="http://hook", webhook_secret=None)
    problems = " ".join(validate(s))
    for needle in ("RIVER3_SECRET_KEY", "PRINCIPALS", "PostgreSQL", "https://", "WEBHOOK_SECRET"):
        assert needle in problems


def test_production_requires_https_or_loopback_model_endpoint():
    base = dict(env="production", secret_key="k" * 40, secret_key_set=True, principals_raw=[],
                database_url="postgresql+psycopg://u:p@h/db")
    ok = _settings(**base, llm_base_url="http://127.0.0.1:11434/v1")
    assert validate(ok) == []
    assert validate(_settings(**base, llm_base_url="https://models.internal/v1")) == []
    assert validate(_settings(**base, llm_base_url="http://localhost:11434/v1")) == []
    remote = _settings(**base, llm_base_url="http://host.docker.internal:11434/v1")
    assert any("RIVER3_LLM_BASE_URL" in p and "RIVER3_LLM_ALLOW_PLAIN_HTTP" in p for p in validate(remote))
    assert validate(_settings(**base, llm_base_url="http://host.docker.internal:11434/v1", llm_allow_plain_http=True)) == []
    # development only warns
    assert validate(_settings(llm_base_url="http://ollama.lan:11434/v1")) == []


def test_readiness_requires_migration_head():
    """Production readiness compares alembic_version with the bundled head; a stale or missing row is a problem."""
    from sqlalchemy import create_engine, text
    from river3_api.main import migration_heads, schema_problem
    heads = migration_heads()
    assert len(heads) == 1
    eng = create_engine("sqlite://")
    with eng.connect() as c:
        assert "missing" in schema_problem(c)
        c.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        c.execute(text("INSERT INTO alembic_version VALUES ('000000000000')"))
        assert "alembic upgrade head" in schema_problem(c)
        c.execute(text("UPDATE alembic_version SET version_num = :h"), {"h": next(iter(heads))})
        assert schema_problem(c) is None


def test_production_refuses_short_or_dev_tokens():
    roles = load_roles(None)
    s = _settings(env="production", principals_raw=[{"name": "a", "kind": "operator", "role": "admin", "token": "short"}])
    with pytest.raises(ConfigError, match=">= 32"):
        load_principals(s, roles)
    dev_hash = hashlib.sha256(b"dev-operator-token").hexdigest()
    s = _settings(env="production", principals_raw=[{"name": "a", "kind": "operator", "role": "admin",
                                                     "token_sha256": dev_hash}])
    with pytest.raises(ConfigError, match="development token"):
        load_principals(s, roles)


def test_roles_file_rejects_unknown_permissions_and_mixed_kinds():
    with pytest.raises(ConfigError, match="unknown permissions"):
        load_roles({"oops": ["read", "god-mode"]})
    roles = load_roles({"mixed": ["read", "events.write"]})
    s = _settings(principals_raw=[{"name": "m", "kind": "operator", "role": "mixed", "token": "x" * 40}])
    with pytest.raises(ConfigError, match="machine permissions"):
        load_principals(s, roles)


def test_duplicate_tokens_rejected():
    s = _settings(principals_raw=[{"name": "a", "kind": "operator", "role": "viewer", "token": "same"},
                                  {"name": "b", "kind": "operator", "role": "admin", "token": "same"}])
    with pytest.raises(ConfigError, match="shares a token"):
        load_principals(s, load_roles(None))


# ---------------------------------------------------------------- live stream tickets
def test_stream_requires_ticket_not_token(c):
    assert c.get("/api/v1/stream?token=op-admin").status_code == 401
    assert c.get("/api/v1/stream?ticket=garbage").status_code == 401
    t = c.post("/api/v1/stream/ticket", headers=VIEWER).json()["ticket"]
    b, s = t.split(".")
    assert c.get(f"/api/v1/stream?ticket={b}.{s[:-2]}AA").status_code == 401  # tampered signature


def test_ticket_is_single_use():
    from river3_api.security import PRINCIPALS, issue_ticket, redeem_ticket
    from fastapi import HTTPException
    pr = next(p for p in PRINCIPALS.values() if p.name == "bob")
    t = issue_ticket(pr)
    assert redeem_ticket(t).name == "bob"
    with pytest.raises(HTTPException):
        redeem_ticket(t)


def test_machine_cannot_get_stream_ticket(c):
    assert c.post("/api/v1/stream/ticket", headers=SENSOR).status_code == 403


# ---------------------------------------------------------------- webhook signing
def test_webhook_signature_verifies(monkeypatch):
    from river3_api import security
    object.__setattr__(security.settings, "webhook_secret", "w" * 40)
    body = b'{"id":"act_1"}'
    hdr = sign_webhook(body, ts=1_800_000_000, delivery="dl-1")
    expect = hmac.new(b"w" * 40, b"1800000000.dl-1." + body, hashlib.sha256).hexdigest()
    assert hdr["X-River3-Signature"] == f"sha256={expect}"
    assert hdr["X-River3-Timestamp"] == "1800000000" and hdr["X-River3-Delivery"] == "dl-1"
    assert len(sign_webhook(body)["X-River3-Delivery"]) == 32  # always present, fresh uuid4 hex
    object.__setattr__(security.settings, "webhook_secret", None)
    # the inbound verifier accepts exactly what the signer produced, and only once
    from river3_api.security import ReplayCache, verify_signature
    from fastapi import HTTPException
    now = int(time.time())
    hdr = {k.lower(): v for k, v in sign_webhook(body, ts=now, secret="s" * 40, delivery="dl-2").items()}
    cache = ReplayCache()
    assert verify_signature(hdr, body, "s" * 40, seen=cache) == "dl-2"
    with pytest.raises(HTTPException) as e:
        verify_signature(hdr, body, "s" * 40, seen=cache)
    assert e.value.status_code == 409


def test_webhook_carries_no_river3_credentials(c, monkeypatch):
    from river3_api import main
    sent = {}

    def fake_post(url, content, headers, timeout, follow_redirects):
        sent.update(headers=headers, body=content, redirects=follow_redirects)
        class R:
            status_code = 204
        return R()

    object.__setattr__(main.settings, "action_webhook", "https://containment.example/hook")
    object.__setattr__(main.settings, "webhook_secret", "w" * 40)
    monkeypatch.setattr(main.httpx, "post", fake_post)
    try:
        main._deliver({"id": "act_missing", "action": "resume"})
    finally:
        object.__setattr__(main.settings, "action_webhook", None)
        object.__setattr__(main.settings, "webhook_secret", None)
    assert "Authorization" not in sent["headers"]
    assert sent["headers"]["X-River3-Signature"].startswith("sha256=")
    assert sent["redirects"] is False
    delivery = sent["headers"]["X-River3-Delivery"]
    assert len(delivery) == 32
    base = f"{sent['headers']['X-River3-Timestamp']}.{delivery}.".encode() + sent["body"]
    assert sent["headers"]["X-River3-Signature"] == "sha256=" + hmac.new(b"w" * 40, base, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- audit chain
def test_audit_chain_detects_tampering(c):
    from river3_api.db import AuditLog, SessionLocal
    from sqlalchemy import select
    c.post("/api/v1/workloads", headers=SENSOR, json={"id": "x-3", "name": "x", "profile": "p"})
    assert c.get("/api/v1/audit/verify", headers=ADMIN).json()["ok"] is True
    with SessionLocal() as db:
        row = db.scalars(select(AuditLog).order_by(AuditLog.seq.desc())).first()
        original = dict(row.detail)
        row.detail = {**original, "profile": "edited"}
        db.commit()
        seq = row.seq
    res = c.get("/api/v1/audit/verify", headers=ADMIN).json()
    assert res["ok"] is False and res["broken_at"] == seq and res["problem"] == "row contents changed"
    with SessionLocal() as db:  # restore so later tests see a clean chain
        row = db.scalars(select(AuditLog).where(AuditLog.seq == seq)).one()
        row.detail = original
        db.commit()
    assert c.get("/api/v1/audit/verify", headers=ADMIN).json()["ok"] is True


def test_audit_detects_deleted_tail(c):
    from river3_api.db import AuditLog, SessionLocal
    from sqlalchemy import select
    c.post("/api/v1/workloads", headers=SENSOR, json={"id": "x-4", "name": "x", "profile": "p"})
    with SessionLocal() as db:
        row = db.scalars(select(AuditLog).order_by(AuditLog.seq.desc())).first()
        saved = {k: getattr(row, k) for k in ("seq", "id", "ts", "actor", "action", "target", "detail",
                                              "prev_hash", "hash")}
        db.delete(row)
        db.commit()
    assert c.get("/api/v1/audit/verify", headers=ADMIN).json()["problem"] == "rows deleted from the end"
    with SessionLocal() as db:
        db.add(AuditLog(**saved))
        db.commit()
    assert c.get("/api/v1/audit/verify", headers=ADMIN).json()["ok"] is True


# ---------------------------------------------------------------- HTTP hardening
def test_security_headers(c):
    r = c.get("/api/health")
    for h in ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy",
              "x-request-id", "cache-control"):
        assert h in r.headers, h
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_body_size_limit(c):
    big = "x" * (1 << 20)
    r = c.post("/api/v1/workloads", headers=SENSOR, content=json.dumps({"id": "big", "name": big, "profile": "p"}),
               )
    assert r.status_code == 413


def test_input_bounds(c):
    bad_id = {"id": "../etc/passwd", "name": "x", "profile": "p"}
    assert c.post("/api/v1/workloads", headers=SENSOR, json=bad_id).status_code == 422
    huge_facts = {"id": "ev-huge", "workload_id": "x-1", "kind": "file_open", "outcome": "success",
                  "facts": {"blob": "y" * 20_000}}
    assert c.post("/api/v1/events", headers=SENSOR, json=[huge_facts]).status_code == 422


def test_errors_do_not_leak_internals(c):
    r = c.get("/api/v1/incidents/does-not-exist", headers=VIEWER)
    assert r.status_code == 404 and r.json() == {"detail": "incident not found"}


def test_static_path_traversal_blocked(c, tmp_path, monkeypatch):
    from river3_api import main
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<html>console</html>")
    (tmp_path / "secret.txt").write_text("TOP SECRET")
    monkeypatch.setattr(main, "STATIC_DIR", static.resolve())
    assert c.get("/").text == "<html>console</html>"
    assert c.get("/incidents/123").text == "<html>console</html>"  # SPA fallback
    for probe in ("/%2e%2e/secret.txt", "/..%2fsecret.txt", "/%2e%2e%2fsecret.txt"):
        r = c.get(probe)
        assert "TOP SECRET" not in r.text, probe
    assert c.get("/api/v1/nope").status_code == 404


def test_spa_guard_direct(tmp_path, monkeypatch):
    import pytest as _p
    from fastapi import HTTPException
    from river3_api import main
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("ok")
    (tmp_path / "secret.txt").write_text("TOP SECRET")
    monkeypatch.setattr(main, "STATIC_DIR", static.resolve())
    with _p.raises(HTTPException):
        main.spa("../secret.txt")
