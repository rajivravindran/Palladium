"""Stage B contract (docs/CONTRACTS.md): sessions, revoke, approval gate, teams, export, `blocked`, domains.

Every endpoint and rule in the API column of §10 has a test here, including the permission matrix for the
seven roles the conftest configures (viewer, responder, admin, night-shift custom; sensor, policy,
containment, gateway) and the scoped operator `tina` (team "payments").
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import ADMIN, CONTAIN, GATEWAY, POLICY, RESPONDER, SENSOR, TEAM, VIEWER

from river3_api import drift, profiles, replay
from river3_api.config import Settings
from river3_api.db import Approval, SessionLocal
from river3_api.security import ConfigError, load_principals, load_roles

NOW = datetime.now(timezone.utc)


# ----------------------------------------------------------------- helpers
def _workload(c, wid, kind="ai_worker", team="", **extra):
    r = c.post("/api/v1/workloads", headers=SENSOR, json={"id": wid, "name": wid, "profile": "diag", "kind": kind,
                                                          "team": team, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def _session(c, sid, wid, principal="svc-deployer@prod", **extra):
    r = c.post("/api/v1/sessions", headers=GATEWAY, json={"session_id": sid, "workload_id": wid,
                                                          "principal": principal, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def _event(eid, wid, outcome="success", session_id=None, errno=None, minutes_ago=0, **target):
    facts = {"process": {"comm": "agent", "pid": 7}, "target": target or {"path": "/data/x", "access": "read"}}
    if errno is not None:
        facts["errno"] = errno
    e = {"id": eid, "workload_id": wid, "kind": "file_open", "outcome": outcome, "facts": facts,
         "ts": (NOW - timedelta(minutes=minutes_ago)).isoformat()}
    if session_id:
        e["session_id"] = session_id
    return e


def _incident(c, wid, events=(), event_ids=(), policy=None, verdict="prohibited", title="Out-of-scope read"):
    body = {"workload_id": wid, "title": title, "threat": "agent_drift", "severity": "critical", "verdict": verdict,
            "rule": "READ_OUTSIDE_SCOPE", "mode": "active", "events": list(events), "event_ids": list(event_ids)}
    if policy:
        body["policy"] = policy
    r = c.post("/api/v1/incidents", headers=POLICY, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _audit(c, action):
    return [a for a in c.get("/api/v1/audit?limit=500", headers=ADMIN).json() if a["action"] == action]


# ================================================================= §1 sessions
def test_session_upsert_patch_get(c):
    _workload(c, "sb-w1")
    s = _session(c, "sb-s1", "sb-w1", labels={"run": "nightly"})
    assert s["state"] == "active" and s["principal"] == "svc-deployer@prod" and s["labels"] == {"run": "nightly"}
    assert s["revoked_at"] is None and s["ended_at"] is None and s["last_seen_at"]
    # upsert keeps the id, updates the binding
    s2 = _session(c, "sb-s1", "sb-w1", principal="svc-deployer@staging")
    assert s2["id"] == "sb-s1" and s2["principal"] == "svc-deployer@staging"
    # strict machine input: an unknown field is a mis-versioned gateway, not something to drop silently
    assert c.post("/api/v1/sessions", headers=GATEWAY, json={"session_id": "sb-s9", "workload_id": "sb-w1",
                                                             "principal": "p", "bogus": 1}).status_code == 422
    assert c.post("/api/v1/sessions", headers=GATEWAY, json={"session_id": "sb-s9", "workload_id": "nope",
                                                             "principal": "p"}).status_code == 422
    # keep-alive and end
    seen = (NOW + timedelta(minutes=1)).isoformat()
    r = c.patch("/api/v1/sessions/sb-s1", headers=GATEWAY, json={"last_seen_at": seen})
    assert r.status_code == 200 and r.json()["last_seen_at"].startswith(seen[:19])
    assert c.patch("/api/v1/sessions/sb-s1", headers=GATEWAY, json={}).status_code == 422
    assert c.patch("/api/v1/sessions/sb-s1", headers=GATEWAY, json={"state": "revoked"}).status_code == 422
    assert c.patch("/api/v1/sessions/sb-nope", headers=GATEWAY, json={"state": "ended"}).status_code == 404
    r = c.patch("/api/v1/sessions/sb-s1", headers=GATEWAY, json={"state": "ended"})
    assert r.json()["state"] == "ended" and r.json()["ended_at"]
    # an ended session can be re-posted (the agent came back), a revoked one cannot (tested below)
    assert _session(c, "sb-s1", "sb-w1")["state"] == "active"
    # list and get
    _session(c, "sb-s2", "sb-w1")
    ids = [s["id"] for s in c.get("/api/v1/sessions?workload_id=sb-w1", headers=ADMIN).json()]
    assert set(ids) == {"sb-s1", "sb-s2"}
    assert c.get("/api/v1/sessions?state=bogus", headers=ADMIN).status_code == 422
    assert "sb-s1" in [s["id"] for s in c.get("/api/v1/sessions?state=active", headers=CONTAIN).json()]
    got = c.get("/api/v1/sessions/sb-s1", headers=VIEWER).json()
    assert got["incident_ids"] == [] and got["workload_id"] == "sb-w1"
    assert c.get("/api/v1/sessions/sb-nope", headers=VIEWER).status_code == 404


@pytest.mark.parametrize("hdr,method,path,expect", [
    (GATEWAY, "post", "/api/v1/sessions", 422),       # allowed; 422 because the body is empty
    (CONTAIN, "post", "/api/v1/sessions", 403),       # containment reads sessions, never writes them
    (SENSOR, "post", "/api/v1/sessions", 403),
    (POLICY, "post", "/api/v1/sessions", 403),
    (ADMIN, "post", "/api/v1/sessions", 403),         # people never bind sessions
    (GATEWAY, "get", "/api/v1/sessions", 200),
    (CONTAIN, "get", "/api/v1/sessions", 200),        # sessions-from-api
    (SENSOR, "get", "/api/v1/sessions", 403),
    (POLICY, "get", "/api/v1/sessions", 403),
    (VIEWER, "get", "/api/v1/sessions", 200),
    (RESPONDER, "get", "/api/v1/sessions", 200),
    (ADMIN, "get", "/api/v1/sessions", 200),
    (GATEWAY, "get", "/api/v1/incidents", 403),       # the gateway sees no incidents
    (GATEWAY, "post", "/api/v1/agents/sb-w1/log", 422),  # agentlog.write: allowed, empty body
    (GATEWAY, "post", "/api/v1/events", 403),
    (GATEWAY, "post", "/api/v1/tools/check", 422),    # allowed, empty body
    (CONTAIN, "post", "/api/v1/tools/check", 403),
    (SENSOR, "post", "/api/v1/tools/check", 403),
    (ADMIN, "post", "/api/v1/tools/check", 403),
])
def test_session_permission_matrix(c, hdr, method, path, expect):
    kw = {"json": {}} if method == "post" else {}
    assert getattr(c, method)(path, headers=hdr, **kw).status_code == expect, path


def test_gateway_role_and_permissions_are_exact():
    roles = load_roles(None)
    # 22 Oct CONTRACTS §2 adds approvals.request; the Stage B permissions stay for the reference gateway
    assert roles["gateway"] == {"sessions.write", "sessions.read", "agentlog.write", "tools.check", "approvals.request"}
    assert roles["revoker"] == {"actions.read", "actions.write"}
    assert roles["containment"] == {"response.write", "actions.read", "actions.write", "sessions.read"}


# ================================================================= §1.3 session on events and incidents
def test_event_and_incident_carry_session_id(c):
    _workload(c, "sb-w2")
    _session(c, "sb-s20", "sb-w2")
    r = c.post("/api/v1/events", headers=SENSOR, json=[_event("sb-e20", "sb-w2", session_id="sb-s20"),
                                                       _event("sb-e21", "sb-w2")])
    assert r.status_code == 201
    assert c.post("/api/v1/events", headers=SENSOR, json=[_event("sb-e22", "sb-w2", session_id="bad id!")]).status_code == 422
    # from an attached (pre-existing) event
    inc = _incident(c, "sb-w2", event_ids=["sb-e21", "sb-e20"])
    assert inc["session_id"] == "sb-s20"
    assert inc["events"][0]["session_id"] in (None, "sb-s20")
    # from an embedded event: the first one that has a session wins
    inc2 = _incident(c, "sb-w2", events=[_event("sb-e23", "sb-w2"), _event("sb-e24", "sb-w2", session_id="sb-s21"),
                                         _event("sb-e25", "sb-w2", session_id="sb-s22")])
    assert inc2["session_id"] == "sb-s21"
    # from the policy engine's identity when no event names one
    decision = {"profile_name": "diag", "profile_version": 1, "status": "VIOLATION", "findings": [],
                "recommended_action": "REVOKE_SESSION", "action": "REVOKE_SESSION", "blockers": [],
                "candidate": {"action": "REVOKE_SESSION", "target": {"asset_id": "sb-w2", "session_id": "sb-s23"}}}
    inc3 = _incident(c, "sb-w2", policy=decision)
    assert inc3["session_id"] == "sb-s23"
    # nothing names a session: none is guessed
    assert _incident(c, "sb-w2", events=[_event("sb-e26", "sb-w2")])["session_id"] is None
    # serialized on the list and on the session
    listed = {i["id"]: i for i in c.get("/api/v1/incidents?limit=500", headers=ADMIN).json()}
    assert listed[inc["id"]]["session_id"] == "sb-s20"
    assert c.get("/api/v1/sessions/sb-s20", headers=ADMIN).json()["incident_ids"] == [inc["id"]]


# ================================================================= §2 revoke
def test_operator_revoke_session_flow(c):
    _workload(c, "sb-w3")
    _session(c, "sb-s30", "sb-w3")
    plain = _incident(c, "sb-w3", events=[_event("sb-e30", "sb-w3")])
    r = c.post(f"/api/v1/incidents/{plain['id']}/actions", headers=ADMIN,
               json={"action": "revoke_session", "reason": "agent is exfiltrating"})
    assert r.status_code == 409 and "not bound to a session" in r.json()["detail"]

    inc = _incident(c, "sb-w3", events=[_event("sb-e31", "sb-w3", session_id="sb-s30")])
    r = c.post(f"/api/v1/incidents/{inc['id']}/actions", headers=RESPONDER,
               json={"action": "revoke_session", "reason": "agent is exfiltrating"})
    assert r.status_code == 201, r.text
    act = r.json()
    assert act["action"] == "revoke_session" and act["status"] == "requested" and act["session_id"] == "sb-s30"
    # one pending action per incident, as for resume/terminate
    assert c.post(f"/api/v1/incidents/{inc['id']}/actions", headers=ADMIN,
                  json={"action": "revoke_session", "reason": "agent is exfiltrating"}).status_code == 409
    # the controller picks it up (same queue as resume/terminate) with the session id on it
    queued = {a["id"]: a for a in c.get("/api/v1/actions", headers=CONTAIN).json()}
    assert queued[act["id"]]["session_id"] == "sb-s30"
    # the API session is still active until the controller verified the gateway cut it
    assert c.get("/api/v1/sessions/sb-s30", headers=ADMIN).json()["state"] == "active"
    r = c.post(f"/api/v1/actions/{act['id']}/result", headers=CONTAIN,
               json={"status": "completed", "detail": {"gateway_state": "revoked"}})
    assert r.status_code == 200
    s = c.get("/api/v1/sessions/sb-s30", headers=ADMIN).json()
    assert s["state"] == "revoked" and s["revoked_by"] == "ray" and s["revoke_reason"] == "agent is exfiltrating"
    assert s["revoked_at"]
    rows = [a for a in _audit(c, "session.revoke") if a["target"] == "sb-s30"]
    assert rows and rows[0]["detail"]["via"] == "operator_action" and rows[0]["actor"] == "ray"
    # terminal: no re-bind, no end, no second revoke request
    assert c.post("/api/v1/sessions", headers=GATEWAY, json={"session_id": "sb-s30", "workload_id": "sb-w3",
                                                             "principal": "p"}).status_code == 409
    assert c.patch("/api/v1/sessions/sb-s30", headers=GATEWAY, json={"state": "ended"}).status_code == 409
    r = c.post(f"/api/v1/incidents/{inc['id']}/actions", headers=ADMIN,
               json={"action": "revoke_session", "reason": "agent is exfiltrating"})
    assert r.status_code == 409 and "already revoked" in r.json()["detail"]


def test_failed_revoke_result_leaves_session_active(c):
    _workload(c, "sb-w4")
    _session(c, "sb-s40", "sb-w4")
    inc = _incident(c, "sb-w4", events=[_event("sb-e40", "sb-w4", session_id="sb-s40")])
    act = c.post(f"/api/v1/incidents/{inc['id']}/actions", headers=ADMIN,
                 json={"action": "revoke_session", "reason": "agent is exfiltrating"}).json()
    c.post(f"/api/v1/actions/{act['id']}/result", headers=CONTAIN, json={"status": "failed", "detail": {"why": "gateway 503"}})
    assert c.get("/api/v1/sessions/sb-s40", headers=ADMIN).json()["state"] == "active"


def test_automatic_revoke_via_response(c):
    _workload(c, "sb-w5")
    _session(c, "sb-s50", "sb-w5")
    inc = _incident(c, "sb-w5", events=[_event("sb-e50", "sb-w5", session_id="sb-s50")])
    # failed / unknown never flip the record
    for state in ("failed", "unknown"):
        c.patch(f"/api/v1/incidents/{inc['id']}/response", headers=CONTAIN,
                json={"response": {"action": "REVOKE_SESSION", "state": state, "session_id": "sb-s50"}})
        assert c.get("/api/v1/sessions/sb-s50", headers=ADMIN).json()["state"] == "active"
    r = c.patch(f"/api/v1/incidents/{inc['id']}/response", headers=CONTAIN,
                json={"response": {"action": "REVOKE_SESSION", "state": "verified", "session_id": "sb-s50"},
                      "status": "contained"})
    assert r.status_code == 200 and r.json()["status"] == "contained"
    s = c.get("/api/v1/sessions/sb-s50", headers=ADMIN).json()
    assert s["state"] == "revoked" and s["revoked_by"] == "contain-1" and "READ_OUTSIDE_SCOPE" in s["revoke_reason"]
    assert any(a["detail"]["via"] == "response" for a in _audit(c, "session.revoke") if a["target"] == "sb-s50")


def test_revoke_of_session_the_gateway_never_registered(c):
    """The sensor saw a session id the gateway never POSTed. The revocation is still recorded so
    tools/check denies it from now on."""
    _workload(c, "sb-w6")
    inc = _incident(c, "sb-w6", events=[_event("sb-e60", "sb-w6", session_id="sb-s60")])
    # 22 Oct CONTRACTS §1: the id is known from evidence, so the session view exists (state unknown, unregistered)
    view = c.get("/api/v1/sessions/sb-s60", headers=ADMIN).json()
    assert view["state"] == "unknown" and view["registered"] is False and [e["id"] for e in view["events"]] == ["sb-e60"]
    assert c.get("/api/v1/sessions/sb-never-anywhere", headers=ADMIN).status_code == 404
    c.patch(f"/api/v1/incidents/{inc['id']}/response", headers=CONTAIN,
            json={"response": {"action": "REVOKE_SESSION", "state": "verified"}})
    s = c.get("/api/v1/sessions/sb-s60", headers=ADMIN).json()
    assert s["state"] == "revoked" and s["principal"] == "" and s["workload_id"] == "sb-w6"
    r = c.post("/api/v1/tools/check", headers=GATEWAY, json={"workload_id": "sb-w6", "session_id": "sb-s60", "tool": "ls"})
    assert r.json()["decision"] == "deny"


# ================================================================= §3 gate, tools/check, approvals
GATE = {"risky_tools": ["shell", "kube*", "terraform"], "hold_at": "rising", "ttl_s": 600}


def test_gate_put_get_and_validation(c):
    _workload(c, "sb-w7")
    d = c.get("/api/v1/workloads/sb-w7/gate", headers=VIEWER).json()
    assert d == {"workload_id": "sb-w7", "risky_tools": [], "hold_at": "never", "ttl_s": 600, "configured": False,
                 "updated_by": None, "updated_at": None}
    assert c.put("/api/v1/workloads/sb-w7/gate", headers=RESPONDER, json=GATE).status_code == 403
    assert c.put("/api/v1/workloads/sb-w7/gate", headers=VIEWER, json=GATE).status_code == 403
    assert c.put("/api/v1/workloads/sb-w7/gate", headers=POLICY, json=GATE).status_code == 403
    assert c.put("/api/v1/workloads/sb-nope/gate", headers=ADMIN, json=GATE).status_code == 404
    for bad in ({**GATE, "hold_at": "always"}, {**GATE, "ttl_s": 0}, {**GATE, "risky_tools": ["x" * 65]},
                {**GATE, "risky_tools": ["t"] * 65}, {**GATE, "extra": 1}):
        assert c.put("/api/v1/workloads/sb-w7/gate", headers=ADMIN, json=bad).status_code == 422, bad
    r = c.put("/api/v1/workloads/sb-w7/gate", headers=ADMIN, json=GATE)
    assert r.status_code == 200 and r.json()["configured"] and r.json()["updated_by"] == "alice"
    g = c.get("/api/v1/workloads/sb-w7/gate", headers=VIEWER).json()
    assert g["risky_tools"] == GATE["risky_tools"] and g["hold_at"] == "rising" and g["ttl_s"] == 600
    assert _audit(c, "gate.update")[0]["target"] == "sb-w7"
    assert c.get("/api/v1/workloads/sb-w7/gate", headers=GATEWAY).status_code == 403


def _raise_tier(c, wid, n=12):
    """12 refused reads in the window -> rising (fails_rising=10); 45 -> high."""
    evs = [_event(f"{wid}-f{i}", wid, outcome="failed", errno=13, path=f"/root/.aws/c{i}", access="read") for i in range(n)]
    assert c.post("/api/v1/events", headers=SENSOR, json=evs).status_code == 201
    return c.get(f"/api/v1/drift/{wid}", headers=ADMIN).json()["state"]["tier"]


def test_tools_check_allow_hold_deny(c):
    _workload(c, "sb-w8")
    _session(c, "sb-s80", "sb-w8")
    chk = lambda **kw: c.post("/api/v1/tools/check", headers=GATEWAY,  # noqa: E731
                              json={"workload_id": "sb-w8", "session_id": "sb-s80", "tool": "shell", **kw})
    assert chk(bogus=1).status_code == 422
    assert c.post("/api/v1/tools/check", headers=GATEWAY,
                  json={"workload_id": "sb-nope", "session_id": "sb-s80", "tool": "shell"}).status_code == 422
    # no gate: allow, no audit row
    before = len(_audit(c, "tool.check"))
    r = chk()
    assert r.status_code == 200 and r.json() == {"decision": "allow", "approval_id": None, "tier": "steady",
                                                 "reason": "no gate rule holds this tool at this tier"}
    assert len(_audit(c, "tool.check")) == before
    # gate at rising, tier still steady: allow
    c.put("/api/v1/workloads/sb-w8/gate", headers=ADMIN, json=GATE)
    assert chk().json()["decision"] == "allow"
    assert _raise_tier(c, "sb-w8") == "rising"
    # risky tool at rising: hold with a pending approval
    r = chk(args_summary="rm -rf /data").json()
    assert r["decision"] == "hold" and r["tier"] == "rising" and r["approval_id"].startswith("apr_")
    assert "waiting for an operator" in r["reason"]
    # glob matches, non-risky tool does not
    assert chk(tool="kubectl").json()["decision"] == "hold"
    assert chk(tool="Shell").json()["decision"] == "allow"   # case-sensitive, as the gateway sent it
    assert chk(tool="read_file").json()["decision"] == "allow"
    held = _audit(c, "tool.check")
    assert len(held) == before + 2 and all(a["detail"]["decision"] == "hold" for a in held[:2])
    # gate at high does not hold at rising
    c.put("/api/v1/workloads/sb-w8/gate", headers=ADMIN, json={**GATE, "hold_at": "high"})
    assert chk().json()["decision"] == "allow"
    c.put("/api/v1/workloads/sb-w8/gate", headers=ADMIN, json={**GATE, "hold_at": "never"})
    assert chk().json()["decision"] == "allow"
    # the approval is visible to operators and pollable by the gateway
    a = c.get(f"/api/v1/approvals/{r['approval_id']}", headers=GATEWAY).json()
    assert a["status"] == "pending" and a["tool"] == "shell" and a["summary"] == "rm -rf /data" and a["tier"] == "rising"
    assert a["tier_at_request"] == "rising" and a["risk"] == "risky" and a["requested_by"] == "gw-1" and a["summary_trust"] == "untrusted"
    assert a["session_id"] == "sb-s80" and a["workload_id"] == "sb-w8" and a["expires_at"] > a["requested_at"]
    assert c.get("/api/v1/approvals", headers=GATEWAY).status_code == 403   # polling one is not listing all
    assert c.get("/api/v1/approvals", headers=SENSOR).status_code == 403
    pend = c.get("/api/v1/approvals?status=pending", headers=VIEWER).json()
    assert [x["id"] for x in pend][:2] == [held[0]["detail"]["approval_id"], r["approval_id"]]  # newest first
    assert c.get("/api/v1/stats", headers=ADMIN).json()["pending_approvals"] >= 2
    # a check is proof of life
    assert c.get("/api/v1/sessions/sb-s80", headers=ADMIN).json()["last_seen_at"] >= a["requested_at"][:19]

    # deny: frozen workload
    c.patch(f"/api/v1/incidents/{_incident(c, 'sb-w8')['id']}/response", headers=CONTAIN,
            json={"response": {"action": "PAUSE_CONTAINER", "state": "verified"}, "workload_state": "frozen"})
    r = chk().json()
    assert r["decision"] == "deny" and r["approval_id"] is None and "frozen" in r["reason"]
    assert _audit(c, "tool.check")[0]["detail"]["decision"] == "deny"
    # deny: revoked session (checked before the workload state, which goes back to running here)
    inc = _incident(c, "sb-w8", events=[_event("sb-e80", "sb-w8", session_id="sb-s80")])
    c.patch(f"/api/v1/incidents/{inc['id']}/response", headers=CONTAIN,
            json={"response": {"action": "REVOKE_SESSION", "state": "verified"}, "workload_state": "running"})
    r = chk().json()
    assert r["decision"] == "deny" and "revoked" in r["reason"]


def test_approval_decide_rules(c):
    _workload(c, "sb-w9")
    _session(c, "sb-s90", "sb-w9")
    c.put("/api/v1/workloads/sb-w9/gate", headers=ADMIN, json=GATE)
    _raise_tier(c, "sb-w9")
    hold = lambda: c.post("/api/v1/tools/check", headers=GATEWAY,  # noqa: E731
                          json={"workload_id": "sb-w9", "session_id": "sb-s90", "tool": "terraform"}).json()
    a1, a2, a3 = hold(), hold(), hold()
    assert all(x["decision"] == "hold" for x in (a1, a2, a3))
    dec = lambda aid, hdr, **body: c.post(f"/api/v1/approvals/{aid}/decide", headers=hdr,  # noqa: E731
                                          json={"decision": "allow", "reason": "reviewed the plan, fine", **body})
    assert dec(a1["approval_id"], VIEWER).status_code == 403
    assert dec(a1["approval_id"], GATEWAY).status_code == 403
    assert dec(a1["approval_id"], RESPONDER, reason="short").status_code == 422
    assert dec(a1["approval_id"], RESPONDER, decision="maybe").status_code == 422
    assert dec("apr_nope", RESPONDER).status_code == 404
    r = dec(a1["approval_id"], RESPONDER)
    assert r.status_code == 200 and r.json()["status"] == "allowed" and r.json()["decided_by"] == "ray"
    assert r.json()["decided_at"] and r.json()["decision_reason"] == "reviewed the plan, fine"
    assert c.get(f"/api/v1/approvals/{a1['approval_id']}", headers=GATEWAY).json()["status"] == "allowed"
    r = dec(a1["approval_id"], ADMIN)
    assert r.status_code == 409 and "already allowed by ray" in r.json()["detail"]
    r = dec(a2["approval_id"], ADMIN, decision="deny", reason="not during an incident")
    assert r.json()["status"] == "denied"
    decided = _audit(c, "approval.decide")
    assert decided[0]["target"] == a2["approval_id"] and decided[0]["detail"]["decision"] == "deny"
    assert decided[1]["target"] == a1["approval_id"] and decided[1]["detail"]["decision"] == "allow"
    # the Stage B word is still accepted
    assert dec(hold()["approval_id"], ADMIN, decision="approve").json()["status"] == "allowed"
    # expiry is computed on read and refuses a late decision
    with SessionLocal() as db:
        row = db.get(Approval, a3["approval_id"])
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    assert c.get(f"/api/v1/approvals/{a3['approval_id']}", headers=GATEWAY).json()["status"] == "expired"
    r = dec(a3["approval_id"], ADMIN)
    assert r.status_code == 409 and "expired" in r.json()["detail"]
    ids = lambda q: [x["id"] for x in c.get(f"/api/v1/approvals?workload_id=sb-w9&{q}", headers=ADMIN).json()]  # noqa: E731
    assert a3["approval_id"] not in ids("status=pending")
    assert a3["approval_id"] in ids("status=expired") and a1["approval_id"] in ids("status=allowed")
    assert {a1["approval_id"], a2["approval_id"]} <= set(ids("status=allowed,denied"))
    # the lazy sweep persisted the expiry with an audit row
    assert _audit(c, "approval.expire")[0]["target"] == a3["approval_id"]
    assert c.get("/api/v1/approvals?status=bogus", headers=ADMIN).status_code == 422
    # only still-decidable holds count
    stats_before = c.get("/api/v1/stats", headers=ADMIN).json()["pending_approvals"]
    hold()
    assert c.get("/api/v1/stats", headers=ADMIN).json()["pending_approvals"] == stats_before + 1


# ================================================================= §6 teams
def test_team_scoping(c):
    _workload(c, "sb-pay-1", team="payments")
    _workload(c, "sb-ml-1", team="ml")
    _workload(c, "sb-none-1")
    pay = _incident(c, "sb-pay-1", events=[_event("sb-ep1", "sb-pay-1", session_id="sb-sp1")])
    ml = _incident(c, "sb-ml-1", events=[_event("sb-em1", "sb-ml-1", session_id="sb-sm1")])
    _session(c, "sb-sp1", "sb-pay-1")
    _session(c, "sb-sm1", "sb-ml-1")
    c.put("/api/v1/workloads/sb-pay-1/gate", headers=ADMIN, json=GATE)
    c.put("/api/v1/workloads/sb-ml-1/gate", headers=ADMIN, json=GATE)
    _raise_tier(c, "sb-pay-1")
    _raise_tier(c, "sb-ml-1")
    hp = c.post("/api/v1/tools/check", headers=GATEWAY, json={"workload_id": "sb-pay-1", "session_id": "sb-sp1", "tool": "shell"}).json()
    hm = c.post("/api/v1/tools/check", headers=GATEWAY, json={"workload_id": "sb-ml-1", "session_id": "sb-sm1", "tool": "shell"}).json()
    assert hp["decision"] == hm["decision"] == "hold"

    me = c.get("/api/v1/me", headers=TEAM).json()
    assert me["teams"] == ["payments"] and me["operator"] == "tina"
    # reads: only payments; unassigned ("" team) is not hers either
    ws = {w["id"] for w in c.get("/api/v1/workloads?limit=500", headers=TEAM).json()}
    assert "sb-pay-1" in ws and "sb-ml-1" not in ws and "sb-none-1" not in ws
    incs = {i["id"] for i in c.get("/api/v1/incidents?limit=500", headers=TEAM).json()}
    assert pay["id"] in incs and ml["id"] not in incs
    assert c.get(f"/api/v1/incidents/{pay['id']}", headers=TEAM).status_code == 200
    assert c.get(f"/api/v1/incidents/{ml['id']}", headers=TEAM).status_code == 404
    dr = {d["workload_id"] for d in c.get("/api/v1/drift", headers=TEAM).json()}
    assert "sb-pay-1" in dr and "sb-ml-1" not in dr
    assert c.get("/api/v1/drift/sb-ml-1", headers=TEAM).status_code == 404
    assert c.get("/api/v1/drift/sb-pay-1", headers=TEAM).status_code == 200
    assert c.get("/api/v1/agents/sb-ml-1/log", headers=TEAM).status_code == 404
    ss = {s["id"] for s in c.get("/api/v1/sessions?limit=500", headers=TEAM).json()}
    assert "sb-sp1" in ss and "sb-sm1" not in ss
    assert c.get("/api/v1/sessions/sb-sm1", headers=TEAM).status_code == 404
    aps = {a["id"] for a in c.get("/api/v1/approvals?limit=500", headers=TEAM).json()}
    assert hp["approval_id"] in aps and hm["approval_id"] not in aps
    assert c.get(f"/api/v1/approvals/{hm['approval_id']}", headers=TEAM).status_code == 404
    assert c.get("/api/v1/workloads/sb-ml-1/gate", headers=TEAM).status_code == 404
    assert c.get("/api/v1/workloads/sb-ml-1/export", headers=TEAM).status_code == 404
    st = c.get("/api/v1/stats", headers=TEAM).json()
    all_st = c.get("/api/v1/stats", headers=ADMIN).json()
    assert st["workloads"] == 1 and st["workloads"] < all_st["workloads"]
    # her workload is `crossed` (open prohibited incident), so heading_out (rising|high) is 0 for her
    assert st["pending_approvals"] == 1 and st["heading_out"] == 0 and st["open"] == 1 and st["critical_open"] == 1
    assert c.get("/api/v1/drift/sb-pay-1", headers=TEAM).json()["state"]["tier"] == "crossed"
    # actions outside her teams: 403; inside: fine
    body = {"action": "resolve", "reason": "reviewed, benign"}
    assert c.post(f"/api/v1/incidents/{ml['id']}/actions", headers=TEAM, json=body).status_code == 403
    assert c.post(f"/api/v1/incidents/{ml['id']}/summary", headers=TEAM).status_code == 403
    assert c.post("/api/v1/drift/sb-ml-1/recompute", headers=TEAM).status_code == 403
    assert c.post(f"/api/v1/approvals/{hm['approval_id']}/decide", headers=TEAM,
                  json={"decision": "deny", "reason": "not my team anyway"}).status_code == 403
    assert c.post(f"/api/v1/approvals/{hp['approval_id']}/decide", headers=TEAM,
                  json={"decision": "approve", "reason": "payments on-call approves"}).status_code == 200
    assert c.post("/api/v1/drift/sb-pay-1/recompute", headers=TEAM).status_code == 200
    assert c.post(f"/api/v1/incidents/{pay['id']}/actions", headers=TEAM, json=body).status_code == 201
    # admin and unscoped operators see everything; machines are never scoped
    assert {"sb-pay-1", "sb-ml-1", "sb-none-1"} <= {w["id"] for w in c.get("/api/v1/workloads?limit=500", headers=ADMIN).json()}
    assert {"sb-pay-1", "sb-ml-1"} <= {w["id"] for w in c.get("/api/v1/workloads?limit=500", headers=VIEWER).json()}
    assert {"sb-sp1", "sb-sm1"} <= {s["id"] for s in c.get("/api/v1/sessions?limit=500", headers=CONTAIN).json()}


def test_team_on_registration(c):
    w = _workload(c, "sb-t1")
    assert w["team"] == ""
    # fill once
    assert _workload(c, "sb-t1", team="payments")["team"] == "payments"
    # sensor restart without the label leaves it alone
    assert _workload(c, "sb-t1")["team"] == "payments"
    # a different label cannot move it
    r = c.post("/api/v1/workloads", headers=SENSOR, json={"id": "sb-t1", "name": "x", "profile": "p", "kind": "ai_worker", "team": "ml"})
    assert r.status_code == 409 and "cannot move" in r.json()["detail"]
    assert c.post("/api/v1/workloads", headers=SENSOR, json={"id": "sb-t2", "name": "x", "profile": "p", "team": "x" * 65}).status_code == 422


def test_principal_teams_validation():
    roles = load_roles(None)

    def load(**p):
        base = {"name": "p", "kind": "operator", "role": "viewer", "token": "t" * 40}
        return load_principals(Settings(principals_raw=[{**base, **p}]), roles)

    pr = next(iter(load(teams=["payments", "ml"]).values()))
    assert pr.teams == frozenset({"payments", "ml"}) and pr.team_scope == pr.teams and pr.sees_team("ml")
    assert not pr.sees_team("") and not pr.sees_team("ops")
    assert next(iter(load().values())).team_scope is None
    admin = next(iter(load(role="admin", teams=["payments"]).values()))
    assert admin.teams == frozenset({"payments"}) and admin.team_scope is None  # admin bypasses
    for bad in ({"kind": "machine", "role": "sensor", "teams": ["a"]}, {"teams": "payments"}, {"teams": [1]},
                {"teams": [""]}, {"teams": ["x" * 65]}, {"teams": [" a"]}, {"teams": ["a"] * 65}):
        with pytest.raises(ConfigError):
            load(**bad)


# ================================================================= §7 export
def test_export_matches_replay_format(c, tmp_path):
    _workload(c, "sb-x1")
    prof = {"name": "diag", "kind": "ai_worker", "read_allowed": ["/data/**"], "write_allowed": ["/out/**"]}
    c.put("/api/v1/policies/diag", headers=ADMIN, json={"profile": prof, "base_version": 0, "comment": "for the export test"})
    evs = [_event(f"sb-x1-e{i}", "sb-x1", minutes_ago=30 - i, path=f"/data/in-{i}.csv", access="read") for i in range(10)]
    evs += [_event(f"sb-x1-f{i}", "sb-x1", outcome="failed", errno=13, minutes_ago=5, path="/root/.aws/c", access="read")
            for i in range(3)]
    assert c.post("/api/v1/events", headers=SENSOR, json=evs).status_code == 201
    log = [{"id": f"l{i}", "ts": (NOW - timedelta(minutes=30 - i)).isoformat(), "kind": "tool_call", "tool": "read_file",
            "status": "ok", "target": f"/data/in-{i}.csv", "text": f"read input {i}"} for i in range(10)]
    assert c.post("/api/v1/agents/sb-x1/log", headers=GATEWAY, json=log).status_code == 201
    inc = _incident(c, "sb-x1", events=[_event("sb-x1-v", "sb-x1", minutes_ago=1, session_id="sb-sx1",
                                               path="/etc/shadow", access="read")])
    normal = _incident(c, "sb-x1", verdict="unresolved", title="Program not in scope")

    assert c.get("/api/v1/workloads/sb-nope/export", headers=ADMIN).status_code == 404
    assert c.get("/api/v1/workloads/sb-x1/export", headers=SENSOR).status_code == 403
    assert c.get("/api/v1/workloads/sb-x1/export?since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z",
                 headers=ADMIN).status_code == 422
    r = c.get("/api/v1/workloads/sb-x1/export", headers=VIEWER)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["id"] == "sb-x1" and s["kind"] == "ai_worker" and s["synthetic"] is False and s["label"] == "violation"
    assert s["violation_at"] == inc["created_at"].replace("Z", "+00:00") or s["violation_at"].startswith(inc["created_at"][:19])
    assert s["profile"]["name"] == "diag" and s["truncated"] is False
    assert len(s["events"]) == 14 and len(s["agent_log"]) == 10 and {i["id"] for i in s["incidents"]} == {inc["id"], normal["id"]}
    assert set(s["events"][0]) == {"id", "ts", "kind", "outcome", "facts", "session_id"}
    assert set(s["agent_log"][0]) == {"id", "ts", "kind", "tool", "status", "target", "text", "session"}
    assert all("payload" not in e for e in s["events"])  # events carry kernel facts only
    # agent_log[].text is Channel B and is exported (the benchmark needs it) but labelled as untrusted
    assert s["trust"] == {"events.facts": "channel A", "agent_log": "channel B, untrusted"}
    assert [e["ts"] for e in s["events"]] == sorted(e["ts"] for e in s["events"])
    # feed it to the replay unchanged
    p = tmp_path / "sb-x1.json"
    p.write_text(json.dumps(s))
    loaded = replay.load(str(p))
    assert loaded["label"] == "violation" and loaded["synthetic"] is False and loaded["violation_at"].tzinfo
    res = replay.replay(loaded, step_s=60)
    assert res["id"] == "sb-x1" and res["kind"] == "ai_worker" and res["label"] == "violation"
    assert res["final"] in drift.TIERS and res["hours"] > 0 and res["injection"] is False and res["synthetic"] is False
    assert replay.summarize([res])["ai_worker"] == {
        "sessions": 1, "violations": 1, "normal_hours": 0.0, "false_alarms": 0, "missed": 1,  # 3 fails: no early warning
        "injection_sessions": 0, "injection_lowered": 0, "false_alarms_per_agent_hour": None,
        "lead_rising_median_min": None, "lead_high_median_min": None}
    assert "sb-x1" in replay.render([res], replay.summarize([res]))
    # a window with only the early, clean events is a normal session
    until = (NOW - timedelta(minutes=10)).isoformat()
    s2 = c.get("/api/v1/workloads/sb-x1/export", params={"until": until}, headers=ADMIN).json()
    assert s2["label"] == "normal" and s2["violation_at"] is None and len(s2["incidents"]) == 0
    assert all(e["ts"] <= s2["until"] for e in s2["events"]) and len(s2["events"]) < 14
    assert replay.replay(replay.load(str(p)), step_s=600)["label"] == "violation"


# ================================================================= §9 outcome blocked
def test_blocked_outcome_is_accepted_and_counts_as_failed(c):
    _workload(c, "sb-b1")
    evs = [_event(f"sb-b1-e{i}", "sb-b1", outcome="blocked", path="/opt/decoys/creds", access="read") for i in range(12)]
    assert c.post("/api/v1/events", headers=SENSOR, json=evs).status_code == 201
    d = c.get("/api/v1/drift/sb-b1", headers=ADMIN).json()["state"]
    assert d["tier"] == "rising" and d["features"]["kernel"]["failed"] == 12
    assert d["features"]["kernel"]["refused"] == 12, "blocked is refused by definition, errno or not"
    assert c.post("/api/v1/events", headers=SENSOR, json=[_event("sb-b1-bad", "sb-b1", outcome="exploded")]).status_code == 422
    inc = _incident(c, "sb-b1", event_ids=["sb-b1-e0"])
    s = c.post(f"/api/v1/incidents/{inc['id']}/summary", headers=ADMIN).json()
    assert s["source"] == "fallback" and s["content"]["timeline"][0]["what"].endswith("(blocked)")


def test_drift_blocked_equals_failed_in_pure_assess():
    def snap(outcome):
        evs = [{"ts": NOW - timedelta(minutes=1), "kind": "file_open", "outcome": outcome,
                "facts": {"target": {"path": f"/etc/x{i}", "access": "read"}}} for i in range(45)]
        return drift.Snapshot(workload_id="w", now=NOW, events=evs)
    blocked, failed = drift.assess(snap("blocked")), drift.assess(snap("failed"))
    assert blocked["tier"] == failed["tier"] == "high"
    assert blocked["features"]["kernel"]["failed"] == 45 and blocked["features"]["kernel"]["refused"] == 45
    assert failed["features"]["kernel"]["refused"] == 0  # plain failed without errno is not "refused"


# ================================================================= §5 egress_allowed_domains
def test_profile_accepts_valid_domains_and_keeps_them(c):
    body = {"name": "sb-dom", "kind": "ai_worker", "egress_allowed_domains": ["api.example.com", "*.internal.example.org", "a-b.io"]}
    clean, errors = profiles.validate(body)
    assert errors == [] and clean["egress_allowed_domains"] == body["egress_allowed_domains"]
    r = c.put("/api/v1/policies/sb-dom", headers=ADMIN, json={"profile": body, "base_version": 0, "comment": "domain egress"})
    assert r.status_code == 200, r.text
    assert r.json()["body"]["egress_allowed_domains"] == body["egress_allowed_domains"]
    bundle = c.get("/api/v1/policy/bundle", headers=POLICY).json()
    assert next(p for p in bundle["profiles"] if p["name"] == "sb-dom")["egress_allowed_domains"] == body["egress_allowed_domains"]
    assert profiles.validate({"name": "d", "kind": "ai_worker"})[0]["egress_allowed_domains"] == []


@pytest.mark.parametrize("bad", [
    "Example.com", "example", "*.com", "-bad.example.com", "bad-.example.com", "ex ample.com", "example.com.",
    "**.example.com", "a.*.example.com", "10.0.0.1", "a" * 64 + ".com", "x." + "a" * 250, "", "http://example.com",
])
def test_profile_rejects_invalid_domains(bad):
    _, errors = profiles.validate({"name": "d", "kind": "ai_worker", "egress_allowed_domains": [bad]})
    assert errors and errors[0]["field"].startswith("egress_allowed_domains"), bad


def test_profile_domain_list_is_bounded():
    many = [f"h{i}.example.com" for i in range(129)]
    _, errors = profiles.validate({"name": "d", "kind": "ai_worker", "egress_allowed_domains": many})
    assert errors and errors[0]["field"] == "egress_allowed_domains"
