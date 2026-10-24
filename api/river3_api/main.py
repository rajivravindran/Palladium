"""River3 API: the hub between the runtime layers and the operator console.

  sensor ─┐
  policy ─┼─(machine tokens, scoped by role)──►  API  ◄──(operator tokens, scoped by role and team)── console
  gateway ┤   sessions · tools/check · approvals
  containment ◄── signed webhook / action queue ─┘

The API never freezes, resumes, terminates or revokes anything itself. Operator requests are queued
for the containment layer, and their status only changes when that layer reports back; a session reads
as revoked only after the controller verified the gateway cut it off. A `hold` from tools/check is a
question for a human, not an action (docs/CONTRACTS.md).
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from . import audit as audit_mod
from . import drift as drift_mod
from . import notify
from . import profiles as profiles_mod
from . import summary as summary_mod
from .bus import bus
from .config import ConfigError, settings, validate
from .db import (AgentLogEntry, AgentSession, Approval, AuditLog, DriftHistory, DriftState, Event, Incident,
                 OperatorAction, PolicyProfile, PolicyProfileVersion, PolicySync, SessionLocal, Summary, Workload,
                 WorkloadGate, engine, init_db, now)
from .schemas import (CORRELATED, IDENT_PATTERN, MAX_EVENTS_PER_POST, MAX_LOG_ENTRIES_PER_POST, ActionIn,
                      ActionResult, AgentLogEntryIn, ApprovalDecision, ApprovalIn, CanaryHit, EventIn, GateIn,
                      IncidentIn, PolicyDelete, PolicySave, PolicySyncIn, ResponseUpdate, SessionIn, SessionPatch,
                      ToolCheckIn, WorkloadIn)
from .security import (Principal, SecurityMiddleware, authenticate, canary_replays, configure_logging, issue_ticket,
                       redeem_ticket, require, require_any, sign_webhook, verify_signature)

configure_logging()
log = logging.getLogger("river3.api")

STATIC_DIR = (Path(__file__).resolve().parent.parent / "static").resolve()
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
VERSION = "0.2.0"
MAX_STREAMS = 50
SUMMARY_COOLDOWN_S = 15


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = validate(settings)
    if problems:
        for p in problems:
            log.error("config.invalid", extra={"problem": p})
        if settings.production:
            raise ConfigError("refusing to start: " + "; ".join(problems))
    if settings.production:
        with engine.connect() as c:  # schema comes from `alembic upgrade head`, never create_all
            if (behind := schema_problem(c)):
                raise ConfigError("refusing to start: " + behind)
    else:
        init_db()
    bus.bind(asyncio.get_running_loop())
    log.info("startup", extra={"env": settings.env, "version": VERSION})
    yield
    _webhook_pool.shutdown(wait=False, cancel_futures=True)
    drift_mod.model_worker.shutdown()
    notify.shutdown()


app = FastAPI(
    title="River3 API", version=VERSION, lifespan=lifespan,
    docs_url=None if settings.production else "/api/docs",
    redoc_url=None, openapi_url=None if settings.production else "/api/openapi.json",
)
app.add_middleware(SecurityMiddleware, max_body=settings.max_body_bytes, hsts=settings.hsts)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    rid = request.scope.get("state", {}).get("request_id")
    log.exception("unhandled", extra={"request_id": rid, "path": request.url.path})
    return JSONResponse({"detail": "internal error", "request_id": rid}, status_code=500)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def page(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000)) -> tuple[int, int]:
    return limit, offset


# ----------------------------------------------------------------- serializers
def ser_workload(w: Workload) -> dict:
    return {"id": w.id, "name": w.name, "profile": w.profile, "kind": w.kind, "sensor": w.sensor,
            "state": w.state, "labels": w.labels, "team": w.team, "demo": w.demo,
            "enrolled_at": w.enrolled_at, "updated_at": w.updated_at}


def ser_event(e: Event) -> dict:
    return {"id": e.id, "workload_id": e.workload_id, "session_id": e.session_id, "kind": e.kind,
            "outcome": e.outcome, "ts": e.ts, "facts": e.facts, "payload": e.payload}


def ser_action(a: OperatorAction) -> dict:
    # session_id rides along so the controller can run the gateway adapter for revoke_session without
    # fetching the incident first. For `revoke` it is the session resolved when the operator asked (stored
    # on the action); otherwise the incident's binding. Never something the operator typed.
    return {"id": a.id, "incident_id": a.incident_id, "workload_id": a.workload_id, "action": a.action,
            "session_id": a.session_id or (a.incident.session_id if a.incident else None),
            "operator": a.operator, "reason": a.reason, "status": a.status, "result": a.result,
            "requested_at": a.requested_at, "completed_at": a.completed_at}


def ser_session(s: AgentSession) -> dict:
    return {"id": s.id, "workload_id": s.workload_id, "principal": s.principal, "state": s.state,
            "started_at": s.started_at, "ended_at": s.ended_at, "revoked_at": s.revoked_at,
            "revoked_by": s.revoked_by, "revoke_reason": s.revoke_reason, "labels": s.labels,
            "last_seen_at": s.last_seen_at}


def _aware(dt: datetime) -> datetime:
    """SQLite hands back naive datetimes for timezone=True columns; every value we store is UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def approval_status(a: Approval, at: datetime | None = None) -> str:
    """Expiry is computed on read: no timer has to run for a stale hold to read as expired, and a decision on
    one is refused by the same rule, never applied after the gateway gave up. `expire_stale` persists it."""
    if a.status == "pending" and _aware(a.expires_at) <= (at or now()):
        return "expired"
    return a.status


def ser_approval(a: Approval) -> dict:
    # `tier` duplicates `tier_at_request` for readers of the Stage B shape (the console's tier badge).
    return {"id": a.id, "workload_id": a.workload_id, "session_id": a.session_id, "tool": a.tool,
            "tool_call_id": a.tool_call_id, "risk": a.risk, "summary": a.summary, "summary_trust": "untrusted",
            "tier_at_request": a.tier_at_request, "tier": a.tier_at_request, "status": approval_status(a),
            "decision_reason": a.decision_reason, "requested_by": a.requested_by,
            "requested_at": a.requested_at, "expires_at": a.expires_at, "decided_by": a.decided_by,
            "decided_at": a.decided_at}


def expire_stale(db: Session, rows: list[Approval]) -> None:
    """Lazy sweep (22 Oct CONTRACTS §2, fail closed): every pending row past its expiry is persisted as
    `expired` with an audit row and a stream message, so the console, the audit log and the gateway's poll
    all say the same thing without a timer job. Runs on every read and list of approvals. Commits."""
    t = now()
    stale = [a for a in rows if a.status == "pending" and _aware(a.expires_at) <= t]
    if not stale:
        return
    for a in stale:
        a.status = "expired"
        a.decision_reason = a.decision_reason or "nobody decided before the hold expired; refused (fail closed)"
        audit_mod.append(db, "system", "approval.expire", a.id, workload=a.workload_id, session_id=a.session_id,
                         tool=a.tool, tool_call_id=a.tool_call_id, expires_at=a.expires_at)
    db.commit()
    for a in stale:
        bus.publish("approval", ser_approval(a))


def ser_gate(g: WorkloadGate | None, workload_id: str) -> dict:
    """No row = no gate: the default shape says so explicitly so the console and the gateway need no
    special case for 404."""
    if g is None:
        return {"workload_id": workload_id, "risky_tools": [], "hold_at": "never", "ttl_s": 600,
                "configured": False, "updated_by": None, "updated_at": None}
    return {"workload_id": g.workload_id, "risky_tools": g.risky_tools, "hold_at": g.hold_at, "ttl_s": g.ttl_s,
            "configured": True, "updated_by": g.updated_by, "updated_at": g.updated_at}


# ----------------------------------------------------------------- team scoping (CONTRACTS §6)
# Operators may carry a team list; reads are filtered to it and actions outside it are refused. Reads
# of a single hidden object are 404, not 403: a scoped operator learns nothing about other teams'
# workloads, not even that an id exists. Actions are 403: the caller already knows the id (it came
# from an incident they can see, or they are probing) and the honest answer is "not yours".
def scoped(q, pr: Principal, workload_col=None):
    """Adds the team filter to a select over Workload (or over a table joined to it via `workload_col`)."""
    scope = pr.team_scope
    if scope is None:
        return q
    if workload_col is not None:
        q = q.join(Workload, Workload.id == workload_col)
    return q.where(Workload.team.in_(sorted(scope)))


def visible_workload(db: Session, pr: Principal, workload_id: str) -> Workload:
    w = db.get(Workload, workload_id)
    if not w or not pr.sees_team(w.team):
        raise HTTPException(404, "workload not found")
    return w


def own_workload(pr: Principal, w: Workload) -> None:
    if not pr.sees_team(w.team):
        raise HTTPException(403, f"workload {w.id} belongs to team '{w.team or '(none)'}', outside your teams")


def ser_summary(s: Summary) -> dict:
    return {"id": s.id, "source": s.source, "model": s.model, "content": s.content, "grounded": s.grounded,
            "invalid_citations": s.invalid_citations, "latency_ms": round(s.latency_ms, 1),
            "created_at": s.created_at}


def session_facts_of(e: Event) -> dict | None:
    s = (e.facts or {}).get("session") if isinstance(e.facts, dict) else None
    if isinstance(s, dict) and isinstance(s.get("id"), str):
        return {"id": s["id"], "tool_call_id": s.get("tool_call_id") if isinstance(s.get("tool_call_id"), str) else None,
                "source": s.get("source") if isinstance(s.get("source"), str) else None}
    return None


def incident_session(i: Incident) -> dict | None:
    """Who was acting, for the console (22 Oct CONTRACTS §1): the first event (by time) that carries
    facts.session wins, including a `correlated` one, which the console marks as advisory. With no such event,
    the incident's own evidence-bound session_id (from an event's session_id or the policy identity)."""
    for e in i.events:
        s = session_facts_of(e)
        if s:
            return s
    if i.session_id:
        return {"id": i.session_id, "tool_call_id": None, "source": "incident"}
    return None


def ser_incident(i: Incident, full: bool = False) -> dict:
    out = {"id": i.id, "workload": ser_workload(i.workload), "title": i.title, "threat": i.threat,
           "severity": i.severity, "verdict": i.verdict, "rule": i.rule, "reason": i.reason,
           "mode": i.mode, "status": i.status, "response": i.response, "policy": i.policy or {}, "demo": i.demo,
           "session_id": i.session_id, "session": incident_session(i),
           "created_at": i.created_at, "updated_at": i.updated_at, "event_count": len(i.events)}
    if full:
        out["events"] = [ser_event(e) for e in i.events]
        out["actions"] = [ser_action(a) for a in i.actions]
        out["summaries"] = [ser_summary(s) for s in i.summaries]
    return out


def _incident(db: Session, incident_id: str) -> Incident:
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(404, "incident not found")
    return inc


# ----------------------------------------------------------------- health
@app.get("/api/health")
def health():
    """Liveness: no auth, no internals."""
    return {"ok": True}


@lru_cache(maxsize=1)
def migration_heads() -> frozenset[str]:
    """Head revision(s) of the bundled migrations. Read once: the script directory is part of the
    image and never changes while the process runs."""
    from alembic.script import ScriptDirectory
    return frozenset(ScriptDirectory(str(MIGRATIONS_DIR)).get_heads())


def schema_problem(conn) -> str | None:
    """A sentence when the database is not at the migration head, else None. A table that merely
    exists is not enough: an API started against an older schema fails on the first query that
    touches a new column, usually inside a request, long after it reported healthy."""
    try:
        applied = frozenset(conn.execute(text("SELECT version_num FROM alembic_version")).scalars())
    except Exception:  # noqa: BLE001 - no table, no permission: either way the schema is not ready
        return "alembic_version table is missing: run `alembic upgrade head` first"
    heads = migration_heads()
    if applied != heads:
        return f"database schema is at {sorted(applied) or 'nothing'}, code expects {sorted(heads)}: run `alembic upgrade head`"
    return None


@app.get("/api/ready")
def ready():
    """Readiness: database reachable and, in production, migrated to the head this build ships.
    Development uses create_all (no alembic_version row), so the head check applies only in production."""
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
            behind = schema_problem(c) if settings.production else None
    except Exception:
        raise HTTPException(503, "database unavailable") from None
    if behind:
        raise HTTPException(503, behind)
    return {"ok": True}


@app.get("/api/v1/me")
def me(pr: Principal = Depends(require("read"))):
    return {"operator": pr.name, "role": pr.role, "permissions": sorted(pr.permissions), "teams": sorted(pr.teams)}


# ----------------------------------------------------------------- machines
@app.post("/api/v1/workloads", status_code=201)
def upsert_workload(body: WorkloadIn, db: Session = Depends(get_db),
                    pr: Principal = Depends(require("workloads.write"))):
    w = db.get(Workload, body.id)
    if w:
        # Re-registration may rename, re-profile or relabel, but it may not change what the workload IS
        # (a shared service relabelled as an AI worker would unlock terminate) and it never resets the
        # runtime state the containment layer reported (a sensor restart must not turn frozen into running).
        if w.kind != "unknown" and body.kind != w.kind:
            raise HTTPException(409, f"workload {w.id} is a {w.kind}; its kind cannot be changed by re-registration")
        # Team follows the same rule as kind: it can be filled in once, never moved. A team decides who
        # SEES the workload, so a relabelled container must not slide out of its team's view; an empty
        # team on re-registration (sensor without the label) leaves the current one alone.
        if body.team and w.team and body.team != w.team:
            raise HTTPException(409, f"workload {w.id} belongs to team '{w.team}'; re-registration cannot move it")
        if body.team and not w.team:
            w.team = body.team
        for k in ("name", "profile", "kind", "sensor", "labels"):
            setattr(w, k, getattr(body, k))
    else:
        w = Workload(**body.model_dump())
        db.add(w)
    audit_mod.append(db, pr.name, "workload.upsert", body.id, profile=body.profile, kind=body.kind, team=w.team)
    db.commit()
    bus.publish("workload", ser_workload(w))
    return ser_workload(w)


def correlate_session(db: Session, workload_id: str, ts: datetime) -> dict | None:
    """22 Oct CONTRACTS §1: an event with no facts.session is attributed to the most recent agent-log
    `tool_call` entry for the same workload whose ts falls in the RIVER3_SESSION_WINDOW_S seconds before the
    event. ADVISORY: the agent log is Channel B (the gateway wrote it, timing is the only link), so the result
    is stamped with source "correlated", never copied into events.session_id or incidents.session_id, which
    stay evidence-bound. The console shows it as "correlated" and revoke asks the operator to confirm it."""
    window = settings.session_window_s
    if window <= 0:
        return None
    ts = _aware(ts)
    entry = db.scalars(select(AgentLogEntry)
                       .where(AgentLogEntry.workload_id == workload_id, AgentLogEntry.kind == "tool_call",
                              AgentLogEntry.session != "", AgentLogEntry.ts <= ts,
                              AgentLogEntry.ts >= ts - timedelta(seconds=window))
                       .order_by(AgentLogEntry.ts.desc()).limit(1)).first()
    if entry is None:
        return None
    return {"id": entry.session, "tool_call_id": entry.tool_call_id or None, "source": CORRELATED}


def _add_event(db: Session, e: EventIn, incident_id: str | None = None) -> Event:
    if db.get(Event, e.id):
        raise HTTPException(409, f"duplicate event id {e.id}")
    ts = e.ts or now()
    facts, session_id, explicit = e.facts, e.session_id, e.session_facts
    if explicit is not None:
        # A session the sender vouches for (gateway / harness / sensor) also binds the evidence column.
        session_id = session_id or explicit.get("id")
    elif (corr := correlate_session(db, e.workload_id, ts)):
        facts = {**facts, "session": corr}
    ev = Event(id=e.id, incident_id=incident_id, workload_id=e.workload_id, session_id=session_id, kind=e.kind,
               outcome=e.outcome, ts=ts, facts=facts, payload=e.payload)
    db.add(ev)
    return ev


_IDENT = re.compile(IDENT_PATTERN)


def _candidate_session(policy) -> str | None:
    """The policy engine's identity for the event it decided on: candidate.target.session_id (policy.Identity).
    Checked against Ident because `candidate` is an opaque blob to the schema."""
    if not policy or not isinstance(policy.candidate, dict):
        return None
    sid = (policy.candidate.get("target") or {}).get("session_id") if isinstance(policy.candidate.get("target"), dict) else None
    return sid if isinstance(sid, str) and _IDENT.match(sid) else None


@app.post("/api/v1/events", status_code=201)
def ingest_events(body: list[EventIn], db: Session = Depends(get_db),
                  _: Principal = Depends(require("events.write"))):
    if len(body) > MAX_EVENTS_PER_POST:
        raise HTTPException(413, f"at most {MAX_EVENTS_PER_POST} events per request")
    if len({e.id for e in body}) != len(body):
        raise HTTPException(409, "duplicate event ids in request")
    for e in body:
        _add_event(db, e)
    db.commit()
    for wid in {e.workload_id for e in body}:
        recompute_drift(db, wid)
    return {"accepted": len(body)}


@app.post("/api/v1/incidents", status_code=201)
def create_incident(body: IncidentIn, db: Session = Depends(get_db),
                    pr: Principal = Depends(require("incidents.write"))):
    if not db.get(Workload, body.workload_id):
        raise HTTPException(422, "unknown workload; enroll it first")
    data = body.model_dump(exclude={"event_ids", "events", "policy"})
    inc = Incident(**data, policy=body.policy.model_dump() if body.policy else {})
    db.add(inc)
    db.flush()
    # Who was acting (CONTRACTS §1.3): the first attached event that carries a session wins, then the
    # policy engine's identity. Never inferred from "the session active at the time": an incident must
    # name the session its EVIDENCE names, or no session at all (revoke is then refused, not guessed).
    session_id: str | None = None
    for e in body.events:
        ev = _add_event(db, e, inc.id)
        session_id = session_id or ev.session_id  # top-level session_id or a vouched-for facts.session.id
    for eid in body.event_ids:
        ev = db.get(Event, eid)
        if not ev:
            raise HTTPException(422, f"unknown event id {eid}")
        if ev.incident_id and ev.incident_id != inc.id:
            raise HTTPException(409, f"event {eid} already belongs to {ev.incident_id}")
        ev.incident_id = inc.id
        session_id = session_id or ev.session_id
    inc.session_id = session_id or _candidate_session(body.policy)
    audit_mod.append(db, pr.name, "incident.create", inc.id, rule=inc.rule, severity=inc.severity, mode=inc.mode,
                     session_id=inc.session_id)
    db.commit()
    db.refresh(inc)
    out = ser_incident(inc)
    bus.publish("incident", out)
    notify.incident_created(out)
    recompute_drift(db, inc.workload_id)
    return ser_incident(inc, full=True)


def revoke_session(db: Session, session_id: str, workload_id: str, *, by: str, reason: str, incident_id: str,
                   via: str) -> AgentSession | None:
    """Marks a session revoked. The API records; the gateway, driven by the controller, is what actually
    cut the session off, and this is only called once that layer reported success (CONTRACTS §2).
    Returns the session when its state changed (the caller publishes after commit), None when it was
    already revoked. A session known only from events (the gateway never registered it) gets a row so
    tools/check denies it from now on and the console shows who was acting."""
    s = db.get(AgentSession, session_id, with_for_update=True)
    if s is None:
        s = AgentSession(id=session_id, workload_id=workload_id, principal="", state="active")
        db.add(s)
    if s.state == "revoked":
        return None
    s.state, s.revoked_at, s.revoked_by, s.revoke_reason = "revoked", now(), by, reason[:2000]
    audit_mod.append(db, by, "session.revoke", session_id, incident=incident_id, via=via, reason=reason[:500],
                     workload=workload_id)
    return s


@app.patch("/api/v1/incidents/{incident_id}/response")
def update_response(incident_id: str, body: ResponseUpdate, db: Session = Depends(get_db),
                    pr: Principal = Depends(require("response.write"))):
    inc = _incident(db, incident_id)
    inc.response = {**(inc.response or {}), **body.response}
    if body.status:
        inc.status = body.status
    if body.workload_state:
        inc.workload.state = body.workload_state
    # Automatic revoke (CONTRACTS §2.3): the controller ran the gateway adapter and VERIFIED the session is
    # gone. Only `verified` flips our record; failed/unknown leave it active so the operator can retry.
    revoked = None
    if body.response.get("action") == "REVOKE_SESSION" and body.response.get("state") == "verified":
        sid = body.response.get("session_id") or inc.session_id
        if isinstance(sid, str) and _IDENT.match(sid):
            inc.session_id = inc.session_id or sid
            revoked = revoke_session(db, sid, inc.workload_id, by=pr.name, incident_id=inc.id, via="response",
                                     reason=str(body.response.get("reason") or f"automatic response to {inc.rule}"))
    audit_mod.append(db, pr.name, "incident.response", inc.id, **body.model_dump())
    db.commit()
    bus.publish("incident", ser_incident(inc))
    if revoked is not None:
        bus.publish("session", ser_session(revoked))
    return ser_incident(inc, full=True)


def canary_caller(request: Request, body: bytes = None) -> str:
    """Who is allowed to report a canary hit: a machine principal with incidents.write
    (bearer), or — for services that can only send signed webhooks — a request carrying
    X-River3-Timestamp / X-River3-Signature computed with RIVER3_CANARY_SECRET."""
    if request.headers.get("authorization"):
        pr = authenticate(request)
        if not pr.can("incidents.write"):
            raise HTTPException(403, f"role '{pr.role}' does not allow 'incidents.write'")
        return pr.name
    if settings.canary_secret:
        # Same base string and replay rule the controller applies to our outbound webhooks.
        verify_signature(request.headers, body or b"", settings.canary_secret, seen=canary_replays)
        request.state.principal = "canary-service"
        return "canary-service"
    raise HTTPException(401, "bearer token with incidents.write, or a signed request, required",
                        headers={"WWW-Authenticate": "Bearer"})


@app.post("/api/v1/canary", status_code=201)
async def canary_hit(request: Request, db: Session = Depends(get_db)):
    """A seeded decoy credential was used. Opens a critical incident the same way the
    policy layer does; nothing is contained automatically from here."""
    raw = await request.body()
    actor = canary_caller(request, raw)
    try:
        hit = CanaryHit.model_validate_json(raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)[:500]) from None
    w = db.get(Workload, hit.workload_id)
    if not w:
        raise HTTPException(422, "unknown workload; enroll it first")
    threat = {"ai_worker": "agent_drift", "shared_service": "external_exploit"}.get(w.kind, "unknown")
    where = f" at {hit.service}" if hit.service else ""
    src = f" from {hit.source_ip}" if hit.source_ip else ""
    inc = Incident(
        workload_id=w.id, title=f"Decoy credential '{hit.credential}' was used{where}", threat=threat,
        severity="critical", verdict="prohibited", rule="CANARY_CREDENTIAL_USED", mode="active",
        reason=(f"The decoy credential '{hit.credential}' seeded into {w.name} was presented{where}{src}. "
                "Decoys have no legitimate use: something read it and tried it. Check this workload's recent "
                "file reads and egress; containment, if any, is the operator's call or the controller's on a matching event."),
        response={}, policy={"profile_name": w.profile, "profile_version": 0, "status": "VIOLATION",
                             "findings": [{"code": "CANARY_CREDENTIAL_USED", "rule": hit.credential}],
                             "recommended_action": "ALERT", "action": "ALERT", "blockers": [], "candidate": None,
                             "canary": {"service": hit.service, "source_ip": hit.source_ip,
                                        "observed_at": hit.observed_at.isoformat() if hit.observed_at else None,
                                        "detail": hit.detail}},
    )
    db.add(inc)
    db.flush()
    audit_mod.append(db, actor, "canary.hit", inc.id, workload=w.id, credential=hit.credential, service=hit.service,
                     source_ip=hit.source_ip)
    db.commit()
    db.refresh(inc)
    out = ser_incident(inc)
    bus.publish("incident", out)
    notify.incident_created(out, kind="canary.hit")
    return ser_incident(inc, full=True)


@app.get("/api/v1/actions")
def queued_actions(status: Literal["requested", "delivered"] = "requested",
                   action: Literal["resume", "terminate", "revoke_session", "revoke"] | None = None,
                   pg: tuple[int, int] = Depends(page), db: Session = Depends(get_db),
                   _: Principal = Depends(require("actions.read"))):
    """The containment layer polls this (or receives the webhook) to pick up operator requests. `revoke`
    requests are for the session revoker (role `revoker`, RIVER3_REVOKE_WEBHOOK), not the controller, so they
    are listed only when asked for with `action=revoke`; without a filter the list is what it always was."""
    limit, offset = pg
    q = select(OperatorAction).where(OperatorAction.status == status)
    q = q.where(OperatorAction.action == action) if action else q.where(OperatorAction.action != "revoke")
    rows = db.scalars(q.order_by(OperatorAction.requested_at).limit(limit).offset(offset)).all()
    return [ser_action(a) for a in rows]


@app.post("/api/v1/actions/{action_id}/result")
def action_result(action_id: str, body: ActionResult, db: Session = Depends(get_db),
                  pr: Principal = Depends(require("actions.write"))):
    a = db.get(OperatorAction, action_id, with_for_update=True)
    if not a:
        raise HTTPException(404, "action not found")
    if a.status not in ("requested", "delivered"):
        raise HTTPException(409, f"action already {a.status}")
    a.status = body.status
    a.result = body.detail
    a.completed_at = now()
    inc = a.incident
    if body.workload_state:
        inc.workload.state = body.workload_state
    if body.status == "completed" and a.action == "terminate":
        inc.status = "resolved"
    revoked = None
    if body.status == "completed" and a.action == "revoke_session" and inc.session_id:
        # CONTRACTS §2.2: revoked_by is the operator who asked, not the controller that reported.
        revoked = revoke_session(db, inc.session_id, inc.workload_id, by=a.operator, reason=a.reason,
                                 incident_id=inc.id, via="operator_action")
    if body.status == "completed" and a.action == "revoke" and a.session_id:
        # 22 Oct CONTRACTS §3: the receiver (gateway / IdP / cloud-role revoker) says the identity is cut.
        # The incident stays as it is (a revoked session is not a resolved incident); the response records
        # the fact, and the session row follows so tools/check denies it from now on.
        inc.response = {**(inc.response or {}), "session_revoked": True, "revoked_session_id": a.session_id,
                        "revoked_by": a.operator, "revoked_at": now().isoformat()}
        audit_mod.append(db, pr.name, "incident.session_revoked", inc.id, session_id=a.session_id, action_id=a.id,
                         operator=a.operator, workload=inc.workload_id)
        revoked = revoke_session(db, a.session_id, inc.workload_id, by=a.operator, reason=a.reason,
                                 incident_id=inc.id, via="revoke")
    audit_mod.append(db, pr.name, f"action.{body.status}", a.id, requested_action=a.action, detail=body.detail)
    db.commit()
    bus.publish("incident", ser_incident(inc))
    if revoked is not None:
        bus.publish("session", ser_session(revoked))
    return ser_action(a)


# ----------------------------------------------------------------- operators
@app.get("/api/v1/stats")
def stats(db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    def count(*where):
        return db.scalar(scoped(select(func.count(Incident.id)).where(*where), pr, Incident.workload_id)) or 0
    return {
        "open": count(Incident.status == "open"),
        "contained": count(Incident.status == "contained"),
        "critical_open": count(Incident.status.in_(["open", "contained"]), Incident.severity == "critical"),
        "workloads": db.scalar(scoped(select(func.count(Workload.id)), pr)) or 0,
        "frozen": db.scalar(scoped(select(func.count(Workload.id)).where(Workload.state == "frozen"), pr)) or 0,
        "pending_actions": db.scalar(scoped(select(func.count(OperatorAction.id))
                                            .where(OperatorAction.status.in_(["requested", "delivered"])),
                                            pr, OperatorAction.workload_id)) or 0,
        "heading_out": db.scalar(scoped(select(func.count(DriftState.workload_id))
                                        .where(DriftState.tier.in_(["rising", "high"])), pr, DriftState.workload_id)) or 0,
        "pending_approvals": db.scalar(scoped(select(func.count(Approval.id))
                                              .where(Approval.status == "pending", Approval.expires_at > now()),
                                              pr, Approval.workload_id)) or 0,
    }


@app.get("/api/v1/workloads")
def list_workloads(pg: tuple[int, int] = Depends(page), db: Session = Depends(get_db),
                   pr: Principal = Depends(require("read"))):
    limit, offset = pg
    q = scoped(select(Workload), pr).order_by(Workload.name).limit(limit).offset(offset)
    return [ser_workload(w) for w in db.scalars(q)]


_STATUSES = {"open", "contained", "resolved", "false_positive"}
_SEVERITIES = {"info", "high", "critical"}


def _csv(value: str | None, allowed: set[str], name: str) -> list[str] | None:
    if not value:
        return None
    items = [v for v in value.split(",") if v]
    bad = set(items) - allowed
    if bad:
        raise HTTPException(422, f"unknown {name}: {sorted(bad)}")
    return items


@app.get("/api/v1/incidents")
def list_incidents(status: str | None = None, severity: str | None = None,
                   threat: Literal["agent_drift", "external_exploit", "unknown"] | None = None,
                   pg: tuple[int, int] = Depends(page), db: Session = Depends(get_db),
                   pr: Principal = Depends(require("read"))):
    limit, offset = pg
    q = scoped(select(Incident), pr, Incident.workload_id).order_by(Incident.created_at.desc())
    if (s := _csv(status, _STATUSES, "status")):
        q = q.where(Incident.status.in_(s))
    if (v := _csv(severity, _SEVERITIES, "severity")):
        q = q.where(Incident.severity.in_(v))
    if threat:
        q = q.where(Incident.threat == threat)
    return [ser_incident(i) for i in db.scalars(q.limit(limit).offset(offset)).all()]


def _visible_incident(db: Session, pr: Principal, incident_id: str) -> Incident:
    inc = _incident(db, incident_id)
    if not pr.sees_team(inc.workload.team):
        raise HTTPException(404, "incident not found")
    return inc


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    return ser_incident(_visible_incident(db, pr, incident_id), full=True)


_webhook_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="webhook")


def _post_signed(url: str, secret: str | None, action_id: str, body_obj: dict, what: str) -> bool:
    """One HMAC-signed POST; True when the receiver answered 2xx. No River3 credentials are sent."""
    body = json.dumps(body_obj, default=str, separators=(",", ":")).encode()
    # One fresh delivery id per attempt; it is part of the signed string, and the receiver
    # refuses an id it has already accepted, so a captured request cannot be replayed.
    delivery = uuid.uuid4().hex
    headers = {"Content-Type": "application/json", **sign_webhook(body, secret=secret, delivery=delivery)}
    try:
        r = httpx.post(url, content=body, headers=headers, timeout=5, follow_redirects=False)
        if r.status_code >= 300:
            log.warning(f"{what}.rejected", extra={"action_id": action_id, "delivery": delivery, "status": r.status_code})
            return False
        return True
    except httpx.HTTPError as exc:
        log.warning(f"{what}.failed", extra={"action_id": action_id, "delivery": delivery, "error": type(exc).__name__})
        return False


def _mark_delivered(action_id: str) -> None:
    with SessionLocal() as db:
        a = db.get(OperatorAction, action_id)
        if a and a.status == "requested":
            a.status = "delivered"
            db.commit()
            bus.publish("incident", ser_incident(a.incident))


def _deliver(action: dict) -> None:
    """Best-effort, HMAC-signed delivery to the containment layer (RIVER3_ACTION_WEBHOOK / RIVER3_WEBHOOK_SECRET).
    If delivery fails the action stays 'requested' and the containment layer can still poll for it."""
    if not settings.action_webhook:
        return
    if _post_signed(settings.action_webhook, settings.webhook_secret, action["id"], action, "webhook"):
        _mark_delivered(action["id"])


def revoke_body(action: dict) -> dict:
    """The exact body of 22 Oct CONTRACTS §3, nothing else (no incident text, no agent log)."""
    return {"action_id": action["id"], "incident_id": action["incident_id"], "workload_id": action["workload_id"],
            "session_id": action["session_id"], "reason": action["reason"], "requested_by": action["operator"],
            "requested_at": action["requested_at"]}


def _deliver_revoke(action: dict) -> None:
    """`revoke` goes to the session revoker (gateway / identity provider / cloud-role revoker) at
    RIVER3_REVOKE_WEBHOOK, signed with RIVER3_REVOKE_SECRET: its own key, so this receiver can neither forge
    containment actions nor alerts. With no webhook configured the request is still recorded and stays
    `requested`; a revoker holding the `revoker` role picks it up from GET /api/v1/actions?action=revoke and
    the console shows it waiting until it reports through POST /api/v1/actions/{id}/result."""
    if not settings.revoke_webhook:
        return
    if _post_signed(settings.revoke_webhook, settings.revoke_secret, action["id"], revoke_body(action), "revoke_webhook"):
        _mark_delivered(action["id"])


def revoke_target(db: Session, inc: Incident) -> str | None:
    """The session a `revoke` on this incident would cut: the incident's evidence-bound session, else the
    first facts.session on its events (explicit or correlated), else the workload's newest active session the
    gateway registered. None when nothing is known: the API never guesses from timing alone here."""
    if inc.session_id:
        return inc.session_id
    s = incident_session(inc)
    if s:
        return s["id"]
    return db.scalar(select(AgentSession.id).where(AgentSession.workload_id == inc.workload_id,
                                                   AgentSession.state == "active")
                     .order_by(AgentSession.last_seen_at.desc()).limit(1))


@app.post("/api/v1/incidents/{incident_id}/actions", status_code=201)
def request_action(incident_id: str, body: ActionIn, db: Session = Depends(get_db),
                   pr: Principal = Depends(require("act"))):
    inc = db.get(Incident, incident_id, with_for_update=True)
    if not inc:
        raise HTTPException(404, "incident not found")
    w = inc.workload
    own_workload(pr, w)
    # A closed incident is a decision already taken; reopening it is not something a button should
    # do by accident. The containment layer may still report on it (PATCH /response), operators may not act.
    if inc.status in ("resolved", "false_positive"):
        raise HTTPException(409, f"incident is {inc.status}; no further actions can be requested on it")
    # Only one request in flight per incident, whatever it is: a resume and a terminate racing to the
    # controller would leave the workload in whichever state the slower one produced.
    pending = [a for a in inc.actions if a.status in ("requested", "delivered")]
    if pending:
        raise HTTPException(409, f"a {pending[0].action} request is already pending ({pending[0].id}); "
                                 "wait for the containment layer to report on it")
    if body.action == "resume" and w.state != "frozen":
        raise HTTPException(409, f"workload is {w.state}, not frozen; nothing to resume")
    if body.action == "terminate" and w.state == "terminated":
        raise HTTPException(409, "workload already terminated")
    if body.action == "terminate" and w.kind == "shared_service":
        raise HTTPException(409, "shared services are never terminated from the console")
    if body.action == "revoke_session":
        if not inc.session_id:
            raise HTTPException(409, "this incident is not bound to a session; nothing to revoke")
        s = db.get(AgentSession, inc.session_id)
        if s and s.state == "revoked":
            raise HTTPException(409, f"session {inc.session_id} is already revoked")
    target: str | None = None
    if body.action == "revoke":  # 22 Oct CONTRACTS §3: both workload kinds; needs a known session
        target = revoke_target(db, inc)
        if not target:
            raise HTTPException(409, "no session to revoke: neither this incident nor its workload has a known session id")
        s = db.get(AgentSession, target)
        if s and s.state == "revoked":
            raise HTTPException(409, f"session {target} is already revoked")

    record_only = body.action in ("resolve", "false_positive")
    a = OperatorAction(incident_id=inc.id, workload_id=w.id, action=body.action, operator=pr.name,
                       reason=body.reason, status="recorded" if record_only else "requested", session_id=target)
    if record_only:
        a.completed_at = now()
        inc.status = "false_positive" if body.action == "false_positive" else "resolved"
    db.add(a)
    db.flush()
    audit_mod.append(db, pr.name, f"operator.{body.action}", inc.id, reason=body.reason, workload=w.id,
                     action_id=a.id, **({"session_id": target} if target else {}))
    db.commit()
    db.refresh(inc)
    payload = ser_action(a)
    bus.publish("incident", ser_incident(inc))
    if body.action == "revoke":
        _webhook_pool.submit(_deliver_revoke, payload)
    elif not record_only:
        _webhook_pool.submit(_deliver, payload)
    return payload


_last_summary: dict[str, float] = {}


@app.post("/api/v1/incidents/{incident_id}/summary", status_code=201)
def make_summary(incident_id: str, db: Session = Depends(get_db), pr: Principal = Depends(require("summarize"))):
    inc = _incident(db, incident_id)
    own_workload(pr, inc.workload)
    t = time.monotonic()
    if t - _last_summary.get(inc.id, -1e9) < SUMMARY_COOLDOWN_S:
        raise HTTPException(429, f"a summary was just generated; wait {SUMMARY_COOLDOWN_S} s")
    if len(_last_summary) > 10_000:
        _last_summary.clear()
    _last_summary[inc.id] = t
    result = summary_mod.summarize(inc)
    s = Summary(incident_id=inc.id, **result)
    db.add(s)
    audit_mod.append(db, pr.name, "summary.generate", inc.id, source=s.source, grounded=s.grounded)
    db.commit()
    return ser_summary(s)


# Deliberately not team-scoped: the audit log is the record of what every principal did across the
# tenant, and `audit` is granted only to admins and auditors (see README, roles). Team viewers never
# reach this route.
@app.get("/api/v1/audit")
def audit_log(pg: tuple[int, int] = Depends(page), db: Session = Depends(get_db),
              _: Principal = Depends(require("audit"))):
    limit, offset = pg
    rows = db.scalars(select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit).offset(offset)).all()
    return [{"seq": r.seq, "id": r.id, "ts": r.ts, "actor": r.actor, "action": r.action, "target": r.target,
             "detail": r.detail, "hash": r.hash} for r in rows]


# Same scope as /api/v1/audit: the hash chain is tenant-wide, so verifying it is too.
@app.get("/api/v1/audit/verify")
def audit_verify(db: Session = Depends(get_db), _: Principal = Depends(require("audit"))):
    return audit_mod.verify_chain(db)


# ----------------------------------------------------------------- policy profiles
# Admins edit profiles here; controllers started with -profiles-from-api fetch the whole set,
# check it with the policy engine and swap it in only if every profile compiles. The API
# never enforces a profile itself.
def ser_profile(p: PolicyProfile) -> dict:
    return {"name": p.name, "kind": p.kind, "version": p.version, "body": p.body, "updated_by": p.updated_by,
            "created_at": p.created_at, "updated_at": p.updated_at}


def ser_profile_version(v: PolicyProfileVersion) -> dict:
    return {"id": v.id, "name": v.name, "version": v.version, "body": v.body, "deleted": v.deleted,
            "author": v.author, "comment": v.comment, "created_at": v.created_at}


def ser_sync(s: PolicySync, current: str) -> dict:
    return {"controller": s.controller, "seen_revision": s.seen_revision, "active_revision": s.active_revision,
            "profiles": s.profiles, "error": s.error, "reported_at": s.reported_at,
            "current": s.active_revision == current}


def _current_revision(db: Session) -> tuple[str, list[dict]]:
    bodies = [p.body for p in db.scalars(select(PolicyProfile).order_by(PolicyProfile.name))]
    return profiles_mod.revision(bodies), bodies


def _invalid(errors: list[dict]) -> HTTPException:
    return HTTPException(422, {"message": "the profile is not valid", "errors": errors})


@app.get("/api/v1/policies")
def list_policies(db: Session = Depends(get_db), _: Principal = Depends(require("read"))):
    rev, _bodies = _current_revision(db)
    used: dict[str, int] = {}
    for name, n in db.execute(select(Workload.profile, func.count(Workload.id)).group_by(Workload.profile)):
        used[name] = n
    rows = db.scalars(select(PolicyProfile).order_by(PolicyProfile.name)).all()
    return {"revision": rev,
            "profiles": [{**ser_profile(p), "workloads": used.get(p.name, 0)} for p in rows],
            "controllers": [ser_sync(s, rev) for s in db.scalars(select(PolicySync).order_by(PolicySync.controller))],
            "unbound": sorted(n for n in used if not any(p.name == n for p in rows))}


@app.get("/api/v1/policies/{name}")
def get_policy(name: str, db: Session = Depends(get_db), _: Principal = Depends(require("read"))):
    p = db.get(PolicyProfile, name)
    history = db.scalars(select(PolicyProfileVersion).where(PolicyProfileVersion.name == name)
                         .order_by(PolicyProfileVersion.created_at.desc()).limit(100)).all()
    if not p and not history:
        raise HTTPException(404, "policy not found")
    workloads = db.scalars(select(Workload).where(Workload.profile == name).order_by(Workload.name)).all()
    return {"profile": ser_profile(p) if p else None, "history": [ser_profile_version(v) for v in history],
            "workloads": [ser_workload(w) for w in workloads]}


@app.post("/api/v1/policies/validate")
def validate_policy(body: dict, _: Principal = Depends(require("policies"))):
    """Checks a profile without saving it, so the editor can show problems as you type."""
    clean, errors = profiles_mod.validate(body)
    return {"ok": not errors, "errors": errors, "profile": clean}


@app.put("/api/v1/policies/{name}")
def save_policy(name: str, body: PolicySave, db: Session = Depends(get_db),
                pr: Principal = Depends(require("policies"))):
    """Creates (base_version 0) or replaces a profile. base_version must be the version the
    editor started from, so two admins can't silently overwrite each other."""
    clean, errors = profiles_mod.validate(body.profile)
    if errors:
        raise _invalid(errors)
    if clean["name"] != name:
        raise _invalid([{"field": "name", "message": "a profile can't be renamed; create a new one instead"}])
    p = db.get(PolicyProfile, name, with_for_update=True)
    current = p.version if p else 0
    if body.base_version != current:
        what = "already exists" if p and body.base_version == 0 else f"is now at version {current}"
        raise HTTPException(409, f"policy {name} {what}; reload it and apply your change again")
    if p is None and db.scalar(select(func.count(PolicyProfile.name))) >= profiles_mod.MAX_PROFILES:
        raise HTTPException(409, f"at most {profiles_mod.MAX_PROFILES} policies")
    # The version only grows, even across a delete and re-create, so a controller never sees one reused
    last = db.scalar(select(func.max(PolicyProfileVersion.version)).where(PolicyProfileVersion.name == name)) or 0
    clean["version"] = max(current, last) + 1
    old = p.body if p else None
    if p and profiles_mod.changed_fields(old, clean) == []:
        raise HTTPException(409, "nothing changed")
    if p:
        p.body, p.kind, p.version, p.updated_by = clean, clean["kind"], clean["version"], pr.name
    else:
        p = PolicyProfile(name=name, kind=clean["kind"], version=clean["version"], body=clean, updated_by=pr.name)
        db.add(p)
    db.add(PolicyProfileVersion(name=name, version=clean["version"], body=clean, author=pr.name, comment=body.comment))
    audit_mod.append(db, pr.name, "policy.create" if old is None else "policy.update", name,
                     version=clean["version"], mode=clean["mode"], on_violation=clean["response"]["on_violation"],
                     changed=profiles_mod.changed_fields(old, clean), comment=body.comment)
    db.commit()
    db.refresh(p)
    bus.publish("policy", {"name": name, "version": p.version})
    return ser_profile(p)


@app.delete("/api/v1/policies/{name}")
def delete_policy(name: str, body: PolicyDelete, db: Session = Depends(get_db),
                  pr: Principal = Depends(require("policies"))):
    p = db.get(PolicyProfile, name, with_for_update=True)
    if not p:
        raise HTTPException(404, "policy not found")
    in_use = db.scalars(select(Workload.id).where(Workload.profile == name).limit(5)).all()
    if in_use:
        raise HTTPException(409, f"policy {name} is assigned to workloads ({', '.join(in_use)}); "
                                 "assign them another policy in the controller's registry first")
    if body.base_version != p.version:
        raise HTTPException(409, f"policy {name} is now at version {p.version}; reload it first")
    db.add(PolicyProfileVersion(name=name, version=p.version, body=p.body, deleted=True, author=pr.name,
                                comment=body.comment))
    audit_mod.append(db, pr.name, "policy.delete", name, version=p.version, comment=body.comment)
    db.delete(p)
    db.commit()
    bus.publish("policy", {"name": name, "deleted": True})
    return {"deleted": name}


@app.get("/api/v1/policy/bundle")
def policy_bundle(db: Session = Depends(get_db), _: Principal = Depends(require("profiles.read"))):
    """The complete set a controller should enforce. `revision` changes whenever any profile does."""
    rev, bodies = _current_revision(db)
    return {"revision": rev, "profiles": bodies}


@app.post("/api/v1/policy/sync")
def policy_sync(body: PolicySyncIn, db: Session = Depends(get_db),
                pr: Principal = Depends(require("profiles.status"))):
    s = db.get(PolicySync, pr.name)
    if s is None:
        s = PolicySync(controller=pr.name, seen_revision=body.seen_revision, active_revision=body.active_revision)
        db.add(s)
    changed = (s.active_revision, s.error) != (body.active_revision, body.error)
    s.seen_revision, s.active_revision = body.seen_revision, body.active_revision
    s.profiles, s.error, s.reported_at = body.profiles, body.error, now()
    if changed:
        audit_mod.append(db, pr.name, "policy.applied" if not body.error else "policy.rejected",
                         body.seen_revision[:12], active=body.active_revision[:12], profiles=body.profiles,
                         error=body.error[:500])
    db.commit()
    if changed:
        bus.publish("policy", {"controller": pr.name, "active_revision": body.active_revision})
    return {"ok": True}


# ----------------------------------------------------------------- early warning (drift tiers)
# Kernel events are high trust; the agent's own log is low trust and lives in its own table.
# Both feed drift.assess(), which only ever lets the log RAISE a tier. Nothing here acts.
MAX_LOG_PER_WORKLOAD = 5000


def log_entry_key(workload_id: str, client_id: str) -> str:
    """Storage key for a client-supplied log id. Ids are only unique per sender, so two workloads may
    both send "l1"; keying on (workload, id) keeps one from silently swallowing the other's entry."""
    return f"{workload_id}:{client_id}"


def client_log_id(e: AgentLogEntry) -> str:
    prefix = e.workload_id + ":"
    return e.id[len(prefix):] if e.id.startswith(prefix) else e.id  # server-generated ids carry no prefix


def ser_log_entry(e: AgentLogEntry) -> dict:
    return {"id": client_log_id(e), "workload_id": e.workload_id, "session": e.session, "tool_call_id": e.tool_call_id or None,
            "ts": e.ts, "kind": e.kind, "tool": e.tool, "status": e.status, "target": e.target, "text": e.text,
            "received_at": e.received_at, "trust": "untrusted"}


def ser_drift(d: DriftState) -> dict:
    return {"workload_id": d.workload_id, "tier": d.tier, "previous_tier": d.previous_tier, "trend": d.trend,
            "reasons": d.reasons, "features": d.features, "model": d.model, "computed_at": d.computed_at,
            "changed_at": d.changed_at}


def _snapshot(db: Session, w: Workload) -> drift_mod.Snapshot:
    events = db.scalars(select(Event).where(Event.workload_id == w.id).order_by(Event.ts.desc())
                        .limit(drift_mod.MAX_EVENTS)).all()
    entries = db.scalars(select(AgentLogEntry).where(AgentLogEntry.workload_id == w.id)
                         .order_by(AgentLogEntry.ts.desc()).limit(drift_mod.MAX_ENTRIES)).all()
    prof = db.get(PolicyProfile, w.profile)
    violation = db.scalar(select(Incident.id).where(Incident.workload_id == w.id, Incident.verdict == "prohibited",
                                                    Incident.status.in_(["open", "contained"]))
                          .order_by(Incident.created_at.desc()).limit(1))
    has_history = bool(entries) or db.scalar(select(func.count(AgentLogEntry.id))
                                             .where(AgentLogEntry.workload_id == w.id)) > 0
    return drift_mod.Snapshot(
        workload_id=w.id, now=now(),
        events=[{"ts": e.ts, "kind": e.kind, "outcome": e.outcome, "facts": e.facts} for e in reversed(events)],
        entries=[{"id": client_log_id(e), "ts": e.ts, "kind": e.kind, "tool": e.tool, "status": e.status,
                  "target": e.target, "text": e.text} for e in reversed(entries)],
        profile=prof.body if prof else None, violation=violation, has_log_history=has_history)


MAX_DRIFT_HISTORY = 500


def recompute_drift(db: Session, workload_id: str, *, ask_model_now: bool = False) -> dict | None:
    """Reassess one workload and store the result. Publishes and alerts only when the tier changes.
    Early warning is advisory: a failure here is logged and must never fail the ingest, incident or
    log request that triggered it (the caller has already committed its own change).

    Model calls stay off the request path. The assessment here is code-only plus the last cached
    model answer for this workload when the log window's input hash is unchanged; a changed window
    schedules the question on drift.model_worker, whose completion stores the answer and calls
    `_apply_model_answer`, which runs this again so the stored tier reflects it. Only the operator's
    manual POST /drift/{id}/recompute passes `ask_model_now=True` and waits for the model (it asked,
    and it holds `act`); the answer it gets is cached the same way."""
    try:
        return _recompute_drift(db, workload_id, ask_model_now=ask_model_now)
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 - advisory path; never propagate into the caller's response
        log.exception("drift.recompute_failed", extra={"workload": workload_id})
        db.rollback()
        return None


def _apply_model_answer(workload_id: str) -> None:
    """ModelWorker callback (worker thread): rerun the code-path recompute so the cached answer lands
    in DriftState, the stream and, if the tier rose, the alert webhook."""
    db = SessionLocal()
    try:
        recompute_drift(db, workload_id)
    finally:
        db.close()


def _model_input(snap: drift_mod.Snapshot, w: Workload, *, ask_model_now: bool) -> tuple[dict | None, dict | None]:
    """(model answer to apply now: cached, or fresh when the operator asked; a `pending` marker when
    the question was handed to the background worker instead)."""
    model = drift_mod.configured_asker()
    if model is None:
        return None, None
    window = drift_mod.model_window(snap)
    if not window:
        return None, None
    name, asker = model
    h = drift_mod.input_hash(window)
    cached = drift_mod.model_worker.cached(w.id, h)
    if cached is not None:
        return cached, None
    if ask_model_now:
        return drift_mod.model_worker.store(w.id, h, name, drift_mod.ask_model(window, asker)), None
    queued = drift_mod.model_worker.schedule(w.id, h, window, model, _apply_model_answer)
    return None, {"name": name, "answer": None, "hash": h, "pending": queued}


def _recompute_drift(db: Session, workload_id: str, *, ask_model_now: bool = False) -> dict | None:
    w = db.get(Workload, workload_id)
    if not w:
        return None
    snap = _snapshot(db, w)
    answer, pending = _model_input(snap, w, ask_model_now=ask_model_now)
    result = drift_mod.assess(snap, model_answer=answer)
    if pending is not None:
        result["model"] = pending  # the stored tier is code-only until the worker's callback reruns this
    d = db.get(DriftState, w.id)
    prev = d.tier if d else None
    if not d:
        d = DriftState(workload_id=w.id)
        db.add(d)
    d.tier, d.reasons, d.features, d.model = result["tier"], result["reasons"], result["features"], result["model"]
    d.computed_at = result["computed_at"]
    changed = prev != d.tier
    if changed:
        d.previous_tier, d.trend, d.changed_at = prev, drift_mod.trend(prev, d.tier), d.computed_at
        db.add(DriftHistory(workload_id=w.id, tier=d.tier, at=d.computed_at,
                            summary="; ".join(r["text"] for r in d.reasons[:3])[:512]))
        db.flush()
        stale = db.scalars(select(DriftHistory.id).where(DriftHistory.workload_id == w.id)
                           .order_by(DriftHistory.at.desc()).offset(MAX_DRIFT_HISTORY)).all()
        if stale:
            db.execute(DriftHistory.__table__.delete().where(DriftHistory.id.in_(stale)))
    db.commit()
    out = ser_drift(d)
    if changed:
        bus.publish("drift", out)
        notify.drift_changed(out, ser_workload(w))
    return out


@app.post("/api/v1/agents/{workload_id}/log", status_code=201)
def post_agent_log(workload_id: str, body: list[AgentLogEntryIn], db: Session = Depends(get_db),
                   _: Principal = Depends(require("agentlog.write"))):
    """Intake for an agent's own log. Ship it from a tool gateway or LLM proxy the agent cannot write to,
    not from a file inside the agent's container. Entries are stored verbatim but never trusted."""
    if len(body) > MAX_LOG_ENTRIES_PER_POST:
        raise HTTPException(413, f"at most {MAX_LOG_ENTRIES_PER_POST} entries per request")
    w = db.get(Workload, workload_id)
    if not w:
        raise HTTPException(422, "unknown workload; enroll it first")
    accepted = 0
    seen: set[str] = set()
    for e in body:
        key = log_entry_key(w.id, e.id) if e.id else None
        if key and (key in seen or db.get(AgentLogEntry, key)):
            continue  # idempotent re-send (per workload: another workload's "l1" is a different entry)
        row = AgentLogEntry(workload_id=w.id, session=e.session, tool_call_id=e.tool_call_id or "", ts=e.ts or now(),
                            kind=e.kind, tool=e.tool, status=e.status, target=e.target, text=e.text)
        if key:
            row.id = key
            seen.add(key)
        db.add(row)
        accepted += 1
    db.flush()
    total = db.scalar(select(func.count(AgentLogEntry.id)).where(AgentLogEntry.workload_id == w.id)) or 0
    if total > MAX_LOG_PER_WORKLOAD:
        oldest = db.scalars(select(AgentLogEntry.id).where(AgentLogEntry.workload_id == w.id)
                            .order_by(AgentLogEntry.ts.asc()).limit(total - MAX_LOG_PER_WORKLOAD)).all()
        for eid in oldest:
            db.delete(db.get(AgentLogEntry, eid))
    db.commit()
    state = recompute_drift(db, w.id)
    return {"accepted": accepted, "tier": state["tier"] if state else None}


@app.get("/api/v1/agents/{workload_id}/log")
def get_agent_log(workload_id: str, pg: tuple[int, int] = Depends(page), db: Session = Depends(get_db),
                  pr: Principal = Depends(require("read"))):
    limit, offset = pg
    if pr.team_scope is not None:
        visible_workload(db, pr, workload_id)
    rows = db.scalars(select(AgentLogEntry).where(AgentLogEntry.workload_id == workload_id)
                      .order_by(AgentLogEntry.ts.desc()).limit(limit).offset(offset)).all()
    return [ser_log_entry(e) for e in rows]


@app.get("/api/v1/drift")
def list_drift(db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    q = scoped(select(DriftState), pr, DriftState.workload_id).order_by(DriftState.workload_id)
    return [ser_drift(d) for d in db.scalars(q)]


@app.get("/api/v1/drift/{workload_id}")
def get_drift(workload_id: str, db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    visible_workload(db, pr, workload_id)
    d = db.get(DriftState, workload_id)
    hist = db.scalars(select(DriftHistory).where(DriftHistory.workload_id == workload_id)
                      .order_by(DriftHistory.at.desc()).limit(200)).all()
    return {"state": ser_drift(d) if d else None,
            "history": [{"tier": h.tier, "at": h.at, "summary": h.summary} for h in reversed(hist)],
            "log_entries": db.scalar(select(func.count(AgentLogEntry.id))
                                     .where(AgentLogEntry.workload_id == workload_id)) or 0}


@app.post("/api/v1/drift/{workload_id}/recompute")
def recompute(workload_id: str, db: Session = Depends(get_db), pr: Principal = Depends(require("act"))):
    """Reassess now (the window moves with the clock, so an operator may want a fresh read). This is the
    one path that waits for the configured model: the operator asked for it and holds `act`."""
    w = db.get(Workload, workload_id)
    if not w:
        raise HTTPException(404, "workload not found")
    own_workload(pr, w)
    out = recompute_drift(db, workload_id, ask_model_now=True)
    if out is None:
        raise HTTPException(404, "workload not found")
    audit_mod.append(db, pr.name, "drift.recompute", workload_id, tier=out["tier"])
    db.commit()
    return out


# ----------------------------------------------------------------- sessions (CONTRACTS §1)
# The gateway tells us who is acting in which container. The API stores and serves the binding;
# revoking is recorded here only after the controller has verified the gateway cut the session off.
_SESSION_STATES = {"active", "ended", "revoked"}


@app.post("/api/v1/sessions", status_code=201)
def upsert_session(body: SessionIn, db: Session = Depends(get_db), pr: Principal = Depends(require("sessions.write"))):
    if not db.get(Workload, body.workload_id):
        raise HTTPException(422, "unknown workload; enroll it first")
    s = db.get(AgentSession, body.session_id, with_for_update=True)
    if s is None:
        s = AgentSession(id=body.session_id, started_at=body.started_at or now())
        db.add(s)
    elif s.state == "revoked":
        # Terminal by design: a revoked agent re-posting its own session id must not come back to life.
        raise HTTPException(409, f"session {s.id} is revoked and cannot be reactivated")
    elif body.started_at:
        s.started_at = body.started_at
    s.workload_id, s.principal, s.labels = body.workload_id, body.principal, body.labels
    s.state, s.ended_at, s.last_seen_at = "active", None, now()
    db.commit()
    out = ser_session(s)
    bus.publish("session", out)
    return out


@app.patch("/api/v1/sessions/{session_id}")
def patch_session(session_id: str, body: SessionPatch, db: Session = Depends(get_db),
                  pr: Principal = Depends(require("sessions.write"))):
    if body.state is None and body.last_seen_at is None:
        raise HTTPException(422, "send state or last_seen_at")
    s = db.get(AgentSession, session_id, with_for_update=True)
    if not s:
        raise HTTPException(404, "session not found")
    if s.state == "revoked":
        raise HTTPException(409, f"session {s.id} is revoked; its state is final")
    if body.last_seen_at:
        s.last_seen_at = body.last_seen_at
    if body.state == "ended" and s.state != "ended":
        s.state, s.ended_at = "ended", now()
    db.commit()
    out = ser_session(s)
    bus.publish("session", out)
    return out


@app.get("/api/v1/sessions")
def list_sessions(workload_id: str | None = None, state: str | None = None, pg: tuple[int, int] = Depends(page),
                  db: Session = Depends(get_db), pr: Principal = Depends(require_any("read", "sessions.read"))):
    limit, offset = pg
    q = scoped(select(AgentSession), pr, AgentSession.workload_id).order_by(AgentSession.started_at.desc())
    if workload_id:
        q = q.where(AgentSession.workload_id == workload_id)
    if (st := _csv(state, _SESSION_STATES, "state")):
        q = q.where(AgentSession.state.in_(st))
    return [ser_session(s) for s in db.scalars(q.limit(limit).offset(offset)).all()]


def _event_names_session(session_id: str):
    """Events that name this session: the evidence column, or facts.session.id (explicit or correlated)."""
    return or_(Event.session_id == session_id, Event.facts["session"]["id"].as_string() == session_id)


@app.get("/api/v1/sessions/{session_id}")
def get_session(session_id: str, pg: tuple[int, int] = Depends(page), db: Session = Depends(get_db),
                pr: Principal = Depends(require_any("read", "sessions.read"))):
    """Everything known about one session id across workloads (22 Oct CONTRACTS §1): the gateway's
    registration if there is one (top-level fields, as before), then the events, agent-log entries, incidents
    and approvals that name it. Each list is paged with the same limit/offset and team-scoped for operators.
    404 only when nothing at all names the id. `state` is "unknown" when the gateway never registered it."""
    if not _IDENT.match(session_id):
        raise HTTPException(404, "session not found")
    limit, offset = pg
    s = db.get(AgentSession, session_id)
    if s is not None and not pr.sees_team(s.workload.team):
        raise HTTPException(404, "session not found")

    def pick(q):
        return db.scalars(q.limit(limit).offset(offset)).all()

    events = pick(scoped(select(Event).where(_event_names_session(session_id)), pr, Event.workload_id).order_by(Event.ts))
    entries = pick(scoped(select(AgentLogEntry).where(AgentLogEntry.session == session_id), pr, AgentLogEntry.workload_id)
                   .order_by(AgentLogEntry.ts))
    named_by_event = select(Event.incident_id).where(_event_names_session(session_id), Event.incident_id.is_not(None))
    incidents = pick(scoped(select(Incident).where(or_(Incident.session_id == session_id, Incident.id.in_(named_by_event))),
                            pr, Incident.workload_id).order_by(Incident.created_at))
    approvals = pick(scoped(select(Approval).where(Approval.session_id == session_id), pr, Approval.workload_id)
                     .order_by(Approval.requested_at.desc()))
    expire_stale(db, approvals)
    if s is None and not (events or entries or incidents or approvals):
        raise HTTPException(404, "session not found")
    head = ser_session(s) if s else {
        "id": session_id, "state": "unknown", "principal": "",
        "workload_id": next((x.workload_id for x in (*events, *entries, *incidents, *approvals)), None),
        "started_at": None, "ended_at": None, "revoked_at": None, "revoked_by": None, "revoke_reason": "",
        "labels": {}, "last_seen_at": None}
    return {**head, "registered": s is not None,
            "incident_ids": [i.id for i in incidents],
            "events": [ser_event(e) for e in events],
            "log_entries": [ser_log_entry(e) for e in entries],
            "incidents": [ser_incident(i) for i in incidents],
            "approvals": [ser_approval(a) for a in approvals],
            "page": {"limit": limit, "offset": offset}}


# ----------------------------------------------------------------- approval gate (CONTRACTS §3)
# A drift tier alone never freezes anything (principle 0). What it CAN do is make the gateway pause
# before a risky tool and ask a human. The gate says which tools and from which tier; tools/check is
# the question; approvals are the answers. The API decides nothing about the tool itself.
_HOLD_RANK = {"never": None, "rising": drift_mod.RANK["rising"], "high": drift_mod.RANK["high"]}


@app.get("/api/v1/workloads/{workload_id}/gate")
def get_gate(workload_id: str, db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    visible_workload(db, pr, workload_id)
    return ser_gate(db.get(WorkloadGate, workload_id), workload_id)


@app.put("/api/v1/workloads/{workload_id}/gate")
def put_gate(workload_id: str, body: GateIn, db: Session = Depends(get_db), pr: Principal = Depends(require("policies"))):
    w = db.get(Workload, workload_id)
    if not w:
        raise HTTPException(404, "workload not found")
    own_workload(pr, w)
    g = db.get(WorkloadGate, workload_id, with_for_update=True)
    if g is None:
        g = WorkloadGate(workload_id=workload_id)
        db.add(g)
    g.risky_tools, g.hold_at, g.ttl_s, g.updated_by = body.risky_tools, body.hold_at, body.ttl_s, pr.name
    audit_mod.append(db, pr.name, "gate.update", workload_id, risky_tools=body.risky_tools, hold_at=body.hold_at,
                     ttl_s=body.ttl_s)
    db.commit()
    out = ser_gate(g, workload_id)
    bus.publish("gate", out)
    return out


def _tool_is_risky(tool: str, patterns: list) -> bool:
    """fnmatchcase: `*` and `?` globs, case-sensitive, so `kube*` matches kubectl and nothing sneaks past by
    changing case (the gateway sends the tool name as the agent asked for it)."""
    return any(fnmatch.fnmatchcase(tool, str(p)) for p in patterns)


@app.post("/api/v1/tools/check")
def tools_check(body: ToolCheckIn, db: Session = Depends(get_db), pr: Principal = Depends(require("tools.check"))):
    """Asked by the gateway before it runs a tool. Order matters: a revoked session or a contained workload
    is denied whatever the tool is; only then does the gate decide whether to hold. Nothing here acts on the
    agent: `hold` is a request for a human, and the gateway polls the approval until someone answers."""
    w = db.get(Workload, body.workload_id)
    if not w:
        raise HTTPException(422, "unknown workload; enroll it first")
    s = db.get(AgentSession, body.session_id)
    if s is not None:
        s.last_seen_at = now()  # a check is proof of life; cheaper than a separate PATCH from the gateway
    d = db.get(DriftState, w.id)
    tier = d.tier if d else "steady"
    deny = None
    if s is not None and s.state == "revoked":
        deny = f"session {s.id} is revoked"
    elif w.state in ("frozen", "terminated"):
        deny = f"workload is {w.state}"
    if deny:
        audit_mod.append(db, pr.name, "tool.check", w.id, decision="deny", session_id=body.session_id, tool=body.tool,
                         tier=tier, reason=deny)
        db.commit()
        return {"decision": "deny", "approval_id": None, "tier": tier, "reason": deny}
    g = db.get(WorkloadGate, w.id)
    threshold = _HOLD_RANK.get(g.hold_at) if g else None
    if threshold is not None and drift_mod.RANK.get(tier, 0) >= threshold and _tool_is_risky(body.tool, g.risky_tools):
        t = now()
        a = Approval(workload_id=w.id, session_id=body.session_id, tool=body.tool, summary=body.args_summary, risk="risky",
                     tier_at_request=tier, status="pending", requested_by=pr.name, requested_at=t,
                     expires_at=t + timedelta(seconds=g.ttl_s))
        db.add(a)
        db.flush()
        reason = f"drift tier is {tier} (gate holds at {g.hold_at}) and '{body.tool}' is a risky tool; waiting for an operator"
        audit_mod.append(db, pr.name, "tool.check", w.id, decision="hold", session_id=body.session_id, tool=body.tool,
                         tier=tier, approval_id=a.id)
        db.commit()
        out = ser_approval(a)
        bus.publish("approval", out)
        notify.approval_held({**out, "ttl_s": g.ttl_s}, ser_workload(w))
        return {"decision": "hold", "approval_id": a.id, "tier": tier, "reason": reason}
    db.commit()
    return {"decision": "allow", "approval_id": None, "tier": tier, "reason": "no gate rule holds this tool at this tier"}


_APPROVAL_STATUSES = {"pending", "allowed", "denied", "expired"}
APPROVAL_POLL_AFTER_S = 2


def approval_decision(tier: str, risk: str) -> tuple[str, str]:
    """22 Oct CONTRACTS §2. Crossed denies whatever the risk (a kernel-confirmed violation is open); High holds
    only risky tools for a human; anything lower allows and is merely recorded. `normal` risk never holds."""
    if tier == "crossed":
        return "deny", f"drift tier is {tier}: a kernel-confirmed scope violation is open, no tool runs until it is handled"
    if tier == "high" and risk == "risky":
        return "hold", f"drift tier is {tier} and the call is risky; an operator must decide"
    return "allow", f"drift tier is {tier}" + ("; normal-risk calls are never held" if risk == "normal" else "")


@app.post("/api/v1/approvals")
def request_approval(body: ApprovalIn, db: Session = Depends(get_db), pr: Principal = Depends(require("approvals.request"))):
    """The gateway asks before running a tool (22 Oct CONTRACTS §2). Every answer is a recorded approval row
    and an audit row, including the allows nobody had to look at. The decision follows the workload's CURRENT
    drift tier (no DriftState yet = steady). Two fail-closed checks come before the tier: a session already
    revoked, or a workload frozen / terminated, is denied whatever the tier says. A `hold` waits
    RIVER3_APPROVAL_TTL_S seconds for an operator; past that the gateway's poll reads `expired`, which it must
    treat as deny."""
    w = db.get(Workload, body.workload_id)
    if not w:
        raise HTTPException(422, "unknown workload; enroll it first")
    s = db.get(AgentSession, body.session_id)
    if s is not None:
        s.last_seen_at = now()
    d = db.get(DriftState, w.id)
    tier = d.tier if d else "steady"
    if s is not None and s.state == "revoked":
        decision, reason = "deny", f"session {s.id} is revoked"
    elif w.state in ("frozen", "terminated"):
        decision, reason = "deny", f"workload is {w.state}"
    else:
        decision, reason = approval_decision(tier, body.risk)
    t = now()
    ttl = settings.approval_ttl_s if decision == "hold" else 0
    a = Approval(workload_id=w.id, session_id=body.session_id, tool=body.tool, tool_call_id=body.tool_call_id,
                 risk=body.risk, summary=body.summary, tier_at_request=tier, requested_by=pr.name, requested_at=t,
                 status="pending" if decision == "hold" else ("allowed" if decision == "allow" else "denied"),
                 decision_reason=reason, expires_at=t + timedelta(seconds=ttl))
    if decision != "hold":
        a.decided_by, a.decided_at = "policy", t
    db.add(a)
    db.flush()
    audit_mod.append(db, pr.name, "approval.request", a.id, workload=w.id, session_id=body.session_id, tool=body.tool,
                     tool_call_id=body.tool_call_id, risk=body.risk, tier=tier, decision=decision, ttl_s=ttl)
    db.commit()
    out = ser_approval(a)
    bus.publish("approval", out)
    if decision == "hold":
        notify.approval_held({**out, "ttl_s": ttl}, ser_workload(w))
    return {"approval_id": a.id, "decision": decision, "reason": reason, "ttl_s": ttl,
            "poll_after_s": APPROVAL_POLL_AFTER_S if decision == "hold" else 0}


@app.get("/api/v1/approvals")
def list_approvals(status: str | None = None, workload_id: str | None = None, pg: tuple[int, int] = Depends(page),
                   db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    """Newest first. `status` is matched on the COMPUTED status: `pending` excludes holds past their
    expiry and `expired` includes them, so the console's queue never shows a hold nobody can still act on.
    Listing also runs the lazy expiry sweep over the rows it returns."""
    limit, offset = pg
    q = scoped(select(Approval), pr, Approval.workload_id).order_by(Approval.requested_at.desc())
    if workload_id:
        q = q.where(Approval.workload_id == workload_id)
    wanted = set(_csv(status, _APPROVAL_STATUSES, "status") or [])
    if wanted:
        t = now()
        conds = []
        if "pending" in wanted:
            conds.append((Approval.status == "pending") & (Approval.expires_at > t))
        if "expired" in wanted:
            conds.append((Approval.status == "expired") | ((Approval.status == "pending") & (Approval.expires_at <= t)))
        stored = [x for x in wanted if x in ("allowed", "denied")]
        if stored:
            conds.append(Approval.status.in_(stored))
        q = q.where(or_(*conds))
    rows = db.scalars(q.limit(limit).offset(offset)).all()
    expire_stale(db, rows)
    return [ser_approval(a) for a in rows]


@app.get("/api/v1/approvals/{approval_id}")
def get_approval(approval_id: str, db: Session = Depends(get_db),
                 pr: Principal = Depends(require_any("read", "tools.check", "approvals.request"))):
    """The gateway polls this until status != pending (and treats `expired` as deny); operators read it in the
    console. A stale hold is persisted as expired here, so the poll that notices it is also what records it."""
    a = db.get(Approval, approval_id)
    if not a or (pr.team_scope is not None and not pr.sees_team(db.get(Workload, a.workload_id).team)):
        raise HTTPException(404, "approval not found")
    expire_stale(db, [a])
    return ser_approval(a)


@app.post("/api/v1/approvals/{approval_id}/decide")
def decide_approval(approval_id: str, body: ApprovalDecision, db: Session = Depends(get_db),
                    pr: Principal = Depends(require("act"))):
    a = db.get(Approval, approval_id, with_for_update=True)
    if not a:
        raise HTTPException(404, "approval not found")
    own_workload(pr, db.get(Workload, a.workload_id))
    current = approval_status(a)
    if current == "expired":
        expire_stale(db, [a])  # persist what the read already says, so later readers and the audit trail agree
        raise HTTPException(409, "approval expired before a decision was made; the gateway has treated it as denied")
    if current != "pending":
        raise HTTPException(409, f"approval already {current} by {a.decided_by}")
    decision = "deny" if body.decision == "deny" else "allow"
    a.status = "allowed" if decision == "allow" else "denied"
    a.decided_by, a.decided_at, a.decision_reason = pr.name, now(), body.reason
    audit_mod.append(db, pr.name, "approval.decide", a.id, decision=decision, workload=a.workload_id,
                     session_id=a.session_id, tool=a.tool, tool_call_id=a.tool_call_id, tier=a.tier_at_request,
                     reason=body.reason)
    db.commit()
    out = ser_approval(a)
    bus.publish("approval", out)
    return out


# ----------------------------------------------------------------- export for the replay benchmark (CONTRACTS §7)
MAX_EXPORT_ROWS = 20_000  # per list; the replay walks everything in memory, and one session is one agent run


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@app.get("/api/v1/workloads/{workload_id}/export")
def export_workload(workload_id: str, since: datetime | None = None, until: datetime | None = None,
                    db: Session = Depends(get_db), pr: Principal = Depends(require("read"))):
    """One recorded session in the replay format (river3_api.replay.load reads it unchanged). The point is
    to measure the early-warning tiers on real runs instead of fixtures, so `synthetic` is false and the
    label comes from what actually happened: a prohibited incident in the window makes it a violation,
    with `violation_at` the moment the first one was opened. `agent_log[].text` (Channel B payload) is
    exported because the drift benchmark needs it; the top-level `trust` block marks it as untrusted so a
    reader of a pasted export does not mistake agent text for a kernel fact."""
    w = visible_workload(db, pr, workload_id)
    since, until = _utc(since), _utc(until)
    if since and until and since > until:
        raise HTTPException(422, "since must be before until")

    def window(q, col):
        if since:
            q = q.where(col >= since)
        if until:
            q = q.where(col <= until)
        return q.limit(MAX_EXPORT_ROWS + 1)

    events = db.scalars(window(select(Event).where(Event.workload_id == w.id).order_by(Event.ts), Event.ts)).all()
    entries = db.scalars(window(select(AgentLogEntry).where(AgentLogEntry.workload_id == w.id)
                                .order_by(AgentLogEntry.ts), AgentLogEntry.ts)).all()
    incidents = db.scalars(window(select(Incident).where(Incident.workload_id == w.id).order_by(Incident.created_at),
                                  Incident.created_at)).all()
    truncated = any(len(x) > MAX_EXPORT_ROWS for x in (events, entries, incidents))
    events, entries, incidents = events[:MAX_EXPORT_ROWS], entries[:MAX_EXPORT_ROWS], incidents[:MAX_EXPORT_ROWS]
    prof = db.get(PolicyProfile, w.profile)
    prohibited = [i for i in incidents if i.verdict == "prohibited"]
    violation_at = min((_utc(i.created_at) for i in prohibited), default=None)
    iso = lambda dt: _utc(dt).isoformat()  # noqa: E731
    return {
        "id": w.id, "kind": w.kind, "label": "violation" if prohibited else "normal", "synthetic": False,
        "violation_at": violation_at.isoformat() if violation_at else None,
        "profile": prof.body if prof else None,
        "workload": {"id": w.id, "name": w.name, "profile": w.profile, "kind": w.kind, "team": w.team},
        "exported_at": iso(now()), "since": since.isoformat() if since else None,
        "until": until.isoformat() if until else None, "truncated": truncated,
        # Provenance of each section: events.facts come from the authenticated sensor (Channel A);
        # agent_log is what the agent/gateway said about itself (Channel B) and proves nothing.
        "trust": {"events.facts": "channel A", "agent_log": "channel B, untrusted"},
        "events": [{"id": e.id, "ts": iso(e.ts), "kind": e.kind, "outcome": e.outcome, "facts": e.facts,
                    "session_id": e.session_id} for e in events],
        "agent_log": [{"id": client_log_id(e), "ts": iso(e.ts), "kind": e.kind, "tool": e.tool, "status": e.status,
                       "target": e.target, "text": e.text, "session": e.session} for e in entries],
        "incidents": [{"id": i.id, "created_at": iso(i.created_at), "title": i.title, "rule": i.rule,
                       "severity": i.severity, "verdict": i.verdict, "status": i.status, "mode": i.mode,
                       "session_id": i.session_id, "event_ids": [e.id for e in i.events]} for i in incidents],
    }


# ----------------------------------------------------------------- live stream
@app.post("/api/v1/stream/ticket")
def stream_ticket(pr: Principal = Depends(require("read"))):
    return {"ticket": issue_ticket(pr), "expires_in": 60}


_streams = 0


@app.get("/api/v1/stream")
async def stream(request: Request, ticket: str | None = None):
    global _streams
    pr = redeem_ticket(ticket)
    if _streams >= MAX_STREAMS:
        raise HTTPException(503, "too many live connections")
    request.scope.setdefault("state", {})["principal"] = pr.name
    q = bus.subscribe()
    _streams += 1

    async def gen():
        global _streams
        try:
            yield "event: hello\ndata: {}\n\n"
            while not await request.is_disconnected():
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            bus.unsubscribe(q)
            _streams -= 1

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ----------------------------------------------------------------- console static files
if (STATIC_DIR / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    """Serves the built console (ui/ -> api/static). Anything outside STATIC_DIR is refused."""
    root = STATIC_DIR
    index = root / "index.html"
    if path.startswith("api/") or not index.is_file():
        raise HTTPException(404, "not found")
    f = (root / path).resolve()
    if not f.is_relative_to(root):  # blocks ../ traversal
        raise HTTPException(404, "not found")
    if path and f.is_file():
        return FileResponse(f)
    return FileResponse(index)
