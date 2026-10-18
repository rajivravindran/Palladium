"""Sentinel API: the hub between the runtime layers and the operator console.

  sensor / policy / containment  --(ingest token)-->  API  <--(operator token)--  console
                                  <-- action queue / webhook --

The API never contains or resumes anything itself. Operator requests are queued
for the containment layer, and their status only changes when that layer reports back.
"""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import summary as summary_mod
from .auth import require_ingest, require_operator, require_operator_query
from .bus import bus
from .config import settings
from .db import AuditLog, Event, Incident, OperatorAction, SessionLocal, Summary, Workload, init_db, now
from .schemas import ActionIn, ActionResult, EventIn, IncidentIn, ResponseUpdate, WorkloadIn

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bus.bind(asyncio.get_running_loop())
    yield


app = FastAPI(title="Sentinel API", version="0.1.0", lifespan=lifespan)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def audit(db: Session, actor: str, action: str, target: str, **detail: Any) -> None:
    db.add(AuditLog(actor=actor, action=action, target=target, detail=detail))


# ----------------------------------------------------------------- serializers
def ser_workload(w: Workload) -> dict:
    return {"id": w.id, "name": w.name, "profile": w.profile, "kind": w.kind, "sensor": w.sensor,
            "state": w.state, "labels": w.labels, "demo": w.demo,
            "enrolled_at": w.enrolled_at, "updated_at": w.updated_at}


def ser_event(e: Event) -> dict:
    return {"id": e.id, "workload_id": e.workload_id, "kind": e.kind, "outcome": e.outcome,
            "ts": e.ts, "facts": e.facts, "payload": e.payload}


def ser_action(a: OperatorAction) -> dict:
    return {"id": a.id, "incident_id": a.incident_id, "workload_id": a.workload_id, "action": a.action,
            "operator": a.operator, "reason": a.reason, "status": a.status, "result": a.result,
            "requested_at": a.requested_at, "completed_at": a.completed_at}


def ser_summary(s: Summary) -> dict:
    return {"id": s.id, "source": s.source, "model": s.model, "content": s.content, "grounded": s.grounded,
            "invalid_citations": s.invalid_citations, "latency_ms": round(s.latency_ms, 1),
            "created_at": s.created_at}


def ser_incident(i: Incident, full: bool = False) -> dict:
    out = {"id": i.id, "workload": ser_workload(i.workload), "title": i.title, "threat": i.threat,
           "severity": i.severity, "verdict": i.verdict, "rule": i.rule, "reason": i.reason,
           "mode": i.mode, "status": i.status, "response": i.response, "demo": i.demo,
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
    return {"ok": True, "version": app.version}


@app.get("/api/v1/me")
def me(operator: str = Depends(require_operator)):
    return {"operator": operator}


# ----------------------------------------------------------------- ingest (machines)
@app.post("/api/v1/workloads", status_code=201)
def upsert_workload(body: WorkloadIn, db: Session = Depends(get_db), _: str = Depends(require_ingest)):
    w = db.get(Workload, body.id)
    if w:
        for k, v in body.model_dump().items():
            setattr(w, k, v)
    else:
        w = Workload(**body.model_dump())
        db.add(w)
    audit(db, "ingest", "workload.upsert", body.id, profile=body.profile, kind=body.kind)
    db.commit()
    bus.publish("workload", ser_workload(w))
    return ser_workload(w)


def _add_event(db: Session, e: EventIn, incident_id: str | None = None) -> Event:
    if db.get(Event, e.id):
        raise HTTPException(409, f"duplicate event id {e.id}")
    ev = Event(id=e.id, incident_id=incident_id, workload_id=e.workload_id, kind=e.kind,
               outcome=e.outcome, ts=e.ts or now(), facts=e.facts, payload=e.payload)
    db.add(ev)
    return ev


@app.post("/api/v1/events", status_code=201)
def ingest_events(body: list[EventIn], db: Session = Depends(get_db), _: str = Depends(require_ingest)):
    for e in body:
        _add_event(db, e)
    db.commit()
    return {"accepted": len(body)}


@app.post("/api/v1/incidents", status_code=201)
def create_incident(body: IncidentIn, db: Session = Depends(get_db), _: str = Depends(require_ingest)):
    if not db.get(Workload, body.workload_id):
        raise HTTPException(422, "unknown workload; enroll it first")
    data = body.model_dump(exclude={"event_ids", "events"})
    inc = Incident(**data)
    db.add(inc)
    db.flush()
    for e in body.events:
        _add_event(db, e, inc.id)
    for eid in body.event_ids:
        ev = db.get(Event, eid)
        if not ev:
            raise HTTPException(422, f"unknown event id {eid}")
        ev.incident_id = inc.id
    audit(db, "ingest", "incident.create", inc.id, rule=inc.rule, severity=inc.severity, mode=inc.mode)
    db.commit()
    db.refresh(inc)
    bus.publish("incident", ser_incident(inc))
    return ser_incident(inc, full=True)


@app.patch("/api/v1/incidents/{incident_id}/response")
def update_response(incident_id: str, body: ResponseUpdate, db: Session = Depends(get_db),
                    _: str = Depends(require_ingest)):
    inc = _incident(db, incident_id)
    inc.response = {**(inc.response or {}), **body.response}
    if body.status:
        inc.status = body.status
    if body.workload_state:
        inc.workload.state = body.workload_state
    audit(db, "containment", "incident.response", inc.id, **body.model_dump())
    db.commit()
    bus.publish("incident", ser_incident(inc))
    return ser_incident(inc, full=True)


@app.get("/api/v1/actions")
def pending_actions(status: str = "requested", db: Session = Depends(get_db), _: str = Depends(require_ingest)):
    """The containment layer polls this (or receives the webhook) to pick up operator requests."""
    rows = db.scalars(select(OperatorAction).where(OperatorAction.status == status)
                      .order_by(OperatorAction.requested_at)).all()
    return [ser_action(a) for a in rows]


@app.post("/api/v1/actions/{action_id}/result")
def action_result(action_id: str, body: ActionResult, db: Session = Depends(get_db),
                  _: str = Depends(require_ingest)):
    a = db.get(OperatorAction, action_id)
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
    audit(db, "containment", f"action.{body.status}", a.id, requested_action=a.action, detail=body.detail)
    db.commit()
    bus.publish("incident", ser_incident(inc))
    return ser_action(a)


# ----------------------------------------------------------------- console (operators)
@app.get("/api/v1/stats")
def stats(db: Session = Depends(get_db), _: str = Depends(require_operator)):
    def count(*where):
        return db.scalar(select(func.count(Incident.id)).where(*where)) or 0
    return {
        "open": count(Incident.status == "open"),
        "contained": count(Incident.status == "contained"),
        "critical_open": count(Incident.status.in_(["open", "contained"]), Incident.severity == "critical"),
        "workloads": db.scalar(select(func.count(Workload.id))) or 0,
        "frozen": db.scalar(select(func.count(Workload.id)).where(Workload.state == "frozen")) or 0,
        "pending_actions": db.scalar(select(func.count(OperatorAction.id))
                                     .where(OperatorAction.status.in_(["requested", "delivered"]))) or 0,
    }


@app.get("/api/v1/workloads")
def list_workloads(db: Session = Depends(get_db), _: str = Depends(require_operator)):
    return [ser_workload(w) for w in db.scalars(select(Workload).order_by(Workload.name)).all()]


@app.get("/api/v1/incidents")
def list_incidents(status: str | None = None, severity: str | None = None, threat: str | None = None,
                   db: Session = Depends(get_db), _: str = Depends(require_operator)):
    q = select(Incident).order_by(Incident.created_at.desc())
    if status:
        q = q.where(Incident.status.in_(status.split(",")))
    if severity:
        q = q.where(Incident.severity.in_(severity.split(",")))
    if threat:
        q = q.where(Incident.threat == threat)
    return [ser_incident(i) for i in db.scalars(q.limit(500)).all()]


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db), _: str = Depends(require_operator)):
    return ser_incident(_incident(db, incident_id), full=True)


def _deliver(action: dict) -> None:
    """Best-effort webhook delivery to the containment layer (runs in a thread)."""
    if not settings.action_webhook:
        return
    try:
        r = httpx.post(settings.action_webhook, json=action, timeout=5,
                       headers={"Authorization": f"Bearer {settings.ingest_token}"})
        delivered = r.status_code < 300
    except httpx.HTTPError:
        delivered = False
    if delivered:
        with SessionLocal() as db:
            a = db.get(OperatorAction, action["id"])
            if a and a.status == "requested":
                a.status = "delivered"
                db.commit()
                bus.publish("incident", ser_incident(a.incident))


@app.post("/api/v1/incidents/{incident_id}/actions", status_code=201)
def request_action(incident_id: str, body: ActionIn, db: Session = Depends(get_db),
                   operator: str = Depends(require_operator)):
    inc = _incident(db, incident_id)
    w = inc.workload
    open_same = [a for a in inc.actions if a.action == body.action and a.status in ("requested", "delivered")]
    if open_same:
        raise HTTPException(409, f"a {body.action} request is already pending ({open_same[0].id})")

    if body.action == "resume" and w.state != "frozen":
        raise HTTPException(409, f"workload is {w.state}, not frozen; nothing to resume")
    if body.action == "terminate" and w.state == "terminated":
        raise HTTPException(409, "workload already terminated")

    record_only = body.action in ("resolve", "false_positive")
    a = OperatorAction(incident_id=inc.id, workload_id=w.id, action=body.action, operator=operator,
                       reason=body.reason, status="recorded" if record_only else "requested")
    if record_only:
        a.completed_at = now()
        inc.status = "false_positive" if body.action == "false_positive" else "resolved"
    db.add(a)
    audit(db, operator, f"operator.{body.action}", inc.id, reason=body.reason, workload=w.id)
    db.commit()
    db.refresh(inc)
    payload = ser_action(a)
    bus.publish("incident", ser_incident(inc))
    if not record_only:
        threading.Thread(target=_deliver, args=(payload,), daemon=True).start()
    return payload


@app.post("/api/v1/incidents/{incident_id}/summary", status_code=201)
def make_summary(incident_id: str, db: Session = Depends(get_db), operator: str = Depends(require_operator)):
    inc = _incident(db, incident_id)
    result = summary_mod.summarize(inc)
    s = Summary(incident_id=inc.id, **result)
    db.add(s)
    audit(db, operator, "summary.generate", inc.id, source=s.source, grounded=s.grounded)
    db.commit()
    return ser_summary(s)


@app.get("/api/v1/audit")
def audit_log(limit: int = 200, db: Session = Depends(get_db), _: str = Depends(require_operator)):
    rows = db.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(min(limit, 1000))).all()
    return [{"id": r.id, "ts": r.ts, "actor": r.actor, "action": r.action, "target": r.target,
             "detail": r.detail} for r in rows]


@app.get("/api/v1/stream")
async def stream(request: Request, _: str = Depends(require_operator_query)):
    q = bus.subscribe()

    async def gen():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ----------------------------------------------------------------- console static files
if (STATIC_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        f = STATIC_DIR / path
        if path and f.is_file():
            return FileResponse(f)
        return FileResponse(STATIC_DIR / "index.html")
