"""Alert notifier and canary-credential webhook."""
import dataclasses
import hashlib
import hmac
import json
import time
from concurrent.futures import Executor

import httpx

from conftest import ADMIN, CONTAIN, POLICY

from river3_api import main as main_mod
from river3_api import notify
from river3_api.config import settings


class _Inline(Executor):
    """Runs submitted work immediately so tests see the result without sleeping."""
    def submit(self, fn, *a, **kw):
        fn(*a, **kw)


def _workload(c, wid="cw-1", kind="ai_worker"):
    r = c.post("/api/v1/workloads", headers=POLICY, json={"id": wid, "name": "Canary worker", "profile": "diag", "kind": kind})
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------- notifier

def test_alert_sent_for_high_and_above_only(c, monkeypatch):
    sent = []

    def fake_post(url, content, headers, timeout, follow_redirects):
        sent.append((url, json.loads(content), headers))
        return httpx.Response(200)

    monkeypatch.setattr(notify, "settings", dataclasses.replace(
        settings, alert_webhook="https://alerts.example/hook", alert_min_severity="high",
        alert_secret="x" * 40, webhook_secret="y" * 40))
    monkeypatch.setattr(notify.httpx, "post", fake_post)
    monkeypatch.setattr(notify, "_pool", _Inline())

    _workload(c, "al-1")
    body = {"workload_id": "al-1", "title": "Decoy file opened", "threat": "agent_drift", "severity": "critical",
            "verdict": "prohibited", "rule": "DECOY_OPEN", "mode": "shadow"}
    r = c.post("/api/v1/incidents", headers=POLICY, json=body)
    assert r.status_code == 201
    assert len(sent) == 1
    url, payload, headers = sent[0]
    assert url == "https://alerts.example/hook"
    assert payload["type"] == "incident.created" and payload["incident"]["id"] == r.json()["id"]
    assert payload["text"].startswith("[River3 CRITICAL] Decoy file opened — Canary worker") and "shadow" in payload["text"]
    assert "Authorization" not in headers and headers["X-River3-Signature"].startswith("sha256=")
    # signed over "<ts>.<delivery>.<body>" with the ALERT secret, never the action-webhook secret
    raw = json.dumps(payload, default=str, separators=(",", ":")).encode()
    base = f"{headers['X-River3-Timestamp']}.{headers['X-River3-Delivery']}.".encode() + raw
    assert headers["X-River3-Signature"] == "sha256=" + hmac.new(b"x" * 40, base, hashlib.sha256).hexdigest()
    assert headers["X-River3-Signature"] != "sha256=" + hmac.new(b"y" * 40, base, hashlib.sha256).hexdigest()

    body.update(severity="info", title="Program type not in scope started")
    assert c.post("/api/v1/incidents", headers=POLICY, json=body).status_code == 201
    assert len(sent) == 1, "info is below the threshold"


def test_alert_failure_never_fails_the_request(c, monkeypatch):
    def boom(*a, **kw):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(notify, "settings", dataclasses.replace(settings, alert_webhook="https://alerts.example/hook"))
    monkeypatch.setattr(notify.httpx, "post", boom)
    monkeypatch.setattr(notify, "_pool", _Inline())
    _workload(c, "al-2")
    r = c.post("/api/v1/incidents", headers=POLICY, json={
        "workload_id": "al-2", "title": "t", "severity": "high", "verdict": "prohibited", "rule": "r"})
    assert r.status_code == 201


def test_no_webhook_means_nothing_sent(monkeypatch):
    monkeypatch.setattr(notify, "settings", dataclasses.replace(settings, alert_webhook=None))
    assert notify.incident_created({"severity": "critical"}) is False


def test_alert_without_secret_is_unsigned_in_development_only(c, monkeypatch, caplog):
    """Development falls back to unsigned (with a warning); production refuses the configuration outright."""
    import logging
    from river3_api.config import validate
    sent = []

    def fake_post(url, content, headers, timeout, follow_redirects):
        sent.append(headers)
        return httpx.Response(200)

    monkeypatch.setattr(notify, "settings", dataclasses.replace(settings, alert_webhook="https://alerts.example/hook",
                                                                alert_secret=None, webhook_secret="y" * 40))
    monkeypatch.setattr(notify.httpx, "post", fake_post)
    monkeypatch.setattr(notify, "_pool", _Inline())
    monkeypatch.setattr(notify, "_warned_unsigned", False)
    _workload(c, "al-3")
    with caplog.at_level(logging.WARNING, logger="river3.notify"):
        r = c.post("/api/v1/incidents", headers=POLICY, json={
            "workload_id": "al-3", "title": "t", "severity": "high", "verdict": "prohibited", "rule": "r"})
    assert r.status_code == 201 and len(sent) == 1
    assert "X-River3-Signature" not in sent[0], "the action-webhook secret must never sign an alert"
    assert any(rec.msg == "alert.unsigned" for rec in caplog.records)

    prod = dataclasses.replace(settings, env="production", secret_key="k" * 40, secret_key_set=True,
                               database_url="postgresql+psycopg://u:p@h/db", principals_raw=[],
                               alert_webhook="https://alerts.example/hook", alert_secret=None, webhook_secret="y" * 40)
    assert any("RIVER3_ALERT_SECRET" in p for p in validate(prod))
    assert any("must differ" in p for p in validate(dataclasses.replace(prod, alert_secret="y" * 40)))
    assert not [p for p in validate(dataclasses.replace(prod, alert_secret="z" * 40)) if "ALERT" in p]


# --------------------------------------------------------------------- canary

def test_canary_hit_creates_critical_incident(c):
    _workload(c, "cw-1")
    r = c.post("/api/v1/canary", headers=POLICY, json={
        "workload_id": "cw-1", "credential": "db_recovery_creds", "service": "postgres", "source_ip": "203.0.113.9",
        "detail": {"user": "recovery"}})
    assert r.status_code == 201, r.text
    inc = r.json()
    assert inc["severity"] == "critical" and inc["verdict"] == "prohibited" and inc["rule"] == "CANARY_CREDENTIAL_USED"
    assert inc["threat"] == "agent_drift" and inc["status"] == "open" and inc["response"] == {}
    assert "db_recovery_creds" in inc["title"] and "postgres" in inc["title"]
    assert inc["policy"]["findings"][0]["code"] == "CANARY_CREDENTIAL_USED"
    assert inc["policy"]["canary"]["source_ip"] == "203.0.113.9"
    # visible to operators, in the audit log, and the workload is untouched
    assert c.get(f"/api/v1/incidents/{inc['id']}", headers=ADMIN).status_code == 200
    assert any(a["action"] == "canary.hit" and a["target"] == inc["id"] for a in c.get("/api/v1/audit", headers=ADMIN).json())
    assert inc["workload"]["state"] == "running"


def test_canary_requires_incidents_write_or_signature(c, monkeypatch):
    _workload(c, "cw-2", kind="shared_service")
    body = {"workload_id": "cw-2", "credential": "aws_backup_key"}
    assert c.post("/api/v1/canary", headers=CONTAIN, json=body).status_code == 403
    assert c.post("/api/v1/canary", json=body).status_code == 401  # no secret configured, no bearer
    assert c.post("/api/v1/canary", headers=POLICY, json={"workload_id": "nope", "credential": "x"}).status_code == 422

    secret = "canary-secret-that-is-long-enough-0123456789"
    monkeypatch.setattr(main_mod, "settings", dataclasses.replace(settings, canary_secret=secret))
    raw = json.dumps(body).encode()

    def signed(ts, delivery="d-1"):
        # exactly the controller's base string: "<ts>.<delivery>.<body>"
        mac = hmac.new(secret.encode(), f"{ts}.{delivery}.".encode() + raw, hashlib.sha256).hexdigest()
        return {"Content-Type": "application/json", "X-River3-Timestamp": str(ts),
                "X-River3-Signature": "sha256=" + mac, "X-River3-Delivery": delivery}

    now = int(time.time())
    assert c.post("/api/v1/canary", content=raw, headers=signed(now - 600)).status_code == 401  # stale
    bad = signed(now)
    bad["X-River3-Signature"] = "sha256=" + "0" * 64
    assert c.post("/api/v1/canary", content=raw, headers=bad).status_code == 401
    no_delivery = signed(now)
    del no_delivery["X-River3-Delivery"]
    assert c.post("/api/v1/canary", content=raw, headers=no_delivery).status_code == 401
    swapped = signed(now)
    swapped["X-River3-Delivery"] = "d-other"  # id is inside the MAC: changing it breaks the signature
    assert c.post("/api/v1/canary", content=raw, headers=swapped).status_code == 401
    r = c.post("/api/v1/canary", content=raw, headers=signed(now))
    assert r.status_code == 201, r.text
    assert r.json()["threat"] == "external_exploit"
    audit = c.get("/api/v1/audit", headers=ADMIN).json()
    assert any(a["action"] == "canary.hit" and a["actor"] == "canary-service" for a in audit)
    # replay of the very same signed request is refused; a fresh delivery id is a new hit
    assert c.post("/api/v1/canary", content=raw, headers=signed(now)).status_code == 409
    assert c.post("/api/v1/canary", content=raw, headers=signed(now, "d-2")).status_code == 201
    # the failed replay must not have poisoned the cache for unauthenticated callers
    bad2 = signed(now, "d-3")
    bad2["X-River3-Signature"] = "sha256=" + "0" * 64
    assert c.post("/api/v1/canary", content=raw, headers=bad2).status_code == 401
    assert c.post("/api/v1/canary", content=raw, headers=signed(now, "d-3")).status_code == 201


def test_replay_cache_is_bounded():
    from river3_api.security import ReplayCache
    rc = ReplayCache(max_entries=3)
    assert all(rc.first_time(f"id-{i}") for i in range(3))
    assert rc.first_time("id-0") is False
    assert rc.first_time("id-3") is True  # evicts id-0, the oldest
    assert rc.first_time("id-0") is True and rc.first_time("id-3") is False
