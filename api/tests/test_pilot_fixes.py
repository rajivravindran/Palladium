"""Regression tests for the pilot blockers found in the 20 Oct audit (STATUS.md bugs 1, 2, 3, 15)."""
from datetime import datetime, timezone

from conftest import ADMIN, CONTAIN, H, POLICY, SENSOR


def _workload(c, wid, kind="ai_worker", profile="diagnostic-worker"):
    r = c.post("/api/v1/workloads", json={"id": wid, "name": wid, "profile": profile, "kind": kind}, headers=SENSOR)
    assert r.status_code == 201, r.text
    return r.json()


def _event(wid, eid, **facts):
    base = {"workload": {"id": wid}, "process": {"pid": 1, "ppid": 0, "uid": 1000, "comm": "python3"},
            "target": {"path": "/var/log/app/x.log", "path_resolved": True, "access": "read"}}
    base.update(facts)
    return {"id": eid, "workload_id": wid, "kind": "file_open", "outcome": "success", "facts": base}


# ---------------------------------------------------------------- bug 1: canary observed_at
def test_canary_with_observed_at_is_stored(c):
    _workload(c, "canary-w1")
    r = c.post("/api/v1/canary", headers=POLICY, json={
        "workload_id": "canary-w1", "credential": "db_recovery_creds", "service": "postgres",
        "source_ip": "10.0.4.7", "observed_at": datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc).isoformat()})
    assert r.status_code == 201, r.text
    assert r.json()["policy"]["canary"]["observed_at"].startswith("2026-10-20T08:00")


# ---------------------------------------------------------------- bug 2: throttle must not lock out valid tokens
def test_valid_token_survives_a_spray_of_bad_ones(c):
    for _ in range(5):
        assert c.get("/api/v1/me", headers=H("not-a-token")).status_code == 401
    assert c.get("/api/v1/me", headers=H("not-a-token")).status_code == 429
    assert c.get("/api/v1/me", headers=ADMIN).status_code == 200
    assert c.get("/api/v1/stats", headers=CONTAIN).status_code == 403  # authenticated, just not allowed


# ---------------------------------------------------------------- bug 3: re-registration cannot relabel or reset state
def test_reregistration_cannot_change_kind(c):
    _workload(c, "pay-1", kind="shared_service", profile="payment-service")
    r = c.post("/api/v1/workloads", json={"id": "pay-1", "name": "pay-1", "profile": "payment-service",
                                          "kind": "ai_worker"}, headers=SENSOR)
    assert r.status_code == 409
    assert c.get("/api/v1/workloads", headers=ADMIN).json()[-1]["kind"] in ("shared_service", "ai_worker")
    w = next(w for w in c.get("/api/v1/workloads", headers=ADMIN).json() if w["id"] == "pay-1")
    assert w["kind"] == "shared_service"


def test_unknown_kind_can_be_settled_once(c):
    _workload(c, "u-1", kind="unknown")
    assert c.post("/api/v1/workloads", json={"id": "u-1", "name": "u-1", "profile": "p", "kind": "ai_worker"},
                  headers=SENSOR).status_code == 201
    assert c.post("/api/v1/workloads", json={"id": "u-1", "name": "u-1", "profile": "p", "kind": "shared_service"},
                  headers=SENSOR).status_code == 409


def test_reregistration_does_not_reset_frozen_state(c):
    _workload(c, "frz-1")
    inc = c.post("/api/v1/incidents", headers=POLICY, json={
        "workload_id": "frz-1", "title": "Decoy file opened", "threat": "agent_drift", "severity": "critical",
        "verdict": "prohibited", "rule": "DECOY_OPEN", "reason": "decoy", "mode": "active"}).json()
    r = c.patch(f"/api/v1/incidents/{inc['id']}/response", headers=CONTAIN,
                json={"response": {"state": "verified", "action": "PAUSE_CONTAINER"}, "status": "contained",
                      "workload_state": "frozen"})
    assert r.status_code == 200, r.text
    # the sensor restarts and registers again with its defaults (state=running)
    assert c.post("/api/v1/workloads", json={"id": "frz-1", "name": "renamed", "profile": "diagnostic-worker",
                                             "kind": "ai_worker"}, headers=SENSOR).status_code == 201
    w = next(w for w in c.get("/api/v1/workloads", headers=ADMIN).json() if w["id"] == "frz-1")
    assert w["state"] == "frozen" and w["name"] == "renamed"


# ---------------------------------------------------------------- bug 15: a malformed event must not poison a workload
def test_malformed_facts_are_refused_not_stored(c):
    _workload(c, "poison-1")
    bad = _event("poison-1", "poison-ev-1", target="not-an-object")
    assert c.post("/api/v1/events", json=[bad], headers=SENSOR).status_code == 422
    bad = _event("poison-1", "poison-ev-2", errno="EACCES")
    assert c.post("/api/v1/events", json=[bad], headers=SENSOR).status_code == 422
    good = _event("poison-1", "poison-ev-3")
    assert c.post("/api/v1/events", json=[good], headers=SENSOR).status_code == 201
    assert c.get("/api/v1/drift/poison-1", headers=ADMIN).status_code == 200


def test_drift_failure_never_fails_the_request(c, monkeypatch):
    from river3_api import drift as drift_mod
    _workload(c, "poison-2")

    def boom(*a, **k):
        raise RuntimeError("drift exploded")

    monkeypatch.setattr(drift_mod, "assess", boom)
    assert c.post("/api/v1/events", json=[_event("poison-2", "poison-ev-4")], headers=SENSOR).status_code == 201
    r = c.post("/api/v1/incidents", headers=POLICY, json={
        "workload_id": "poison-2", "title": "Read outside scope", "threat": "agent_drift", "severity": "high",
        "verdict": "prohibited", "rule": "READ_OUTSIDE_SCOPE", "reason": "x", "mode": "shadow"})
    assert r.status_code == 201, r.text
    assert c.post("/api/v1/agents/poison-2/log", headers=POLICY,
                  json=[{"id": "l-1", "ts": datetime.now(timezone.utc).isoformat(), "kind": "message",
                         "text": "hello"}]).status_code == 201
    monkeypatch.undo()
    # and the workload recovers as soon as drift works again
    assert c.post("/api/v1/drift/poison-2/recompute", headers=ADMIN).status_code == 200
