"""Database models. Works on SQLite (dev) and PostgreSQL (pilot)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Base(DeclarativeBase):
    pass


class Workload(Base):
    __tablename__ = "workloads"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    profile: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32))  # ai_worker | shared_service | unknown
    sensor: Mapped[str] = mapped_column(String(32), default="ebpf")
    state: Mapped[str] = mapped_column(String(32), default="running")  # running|frozen|terminated|unknown
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("inc"))
    workload_id: Mapped[str] = mapped_column(ForeignKey("workloads.id"))
    title: Mapped[str] = mapped_column(String(512))
    threat: Mapped[str] = mapped_column(String(32))  # agent_drift | external_exploit | unknown
    severity: Mapped[str] = mapped_column(String(16))  # info | high | critical
    verdict: Mapped[str] = mapped_column(String(16))  # prohibited | unresolved
    rule: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text, default="")
    mode: Mapped[str] = mapped_column(String(16), default="shadow")  # shadow | active
    status: Mapped[str] = mapped_column(String(32), default="open")  # open|contained|resolved|false_positive
    # Reported by the containment layer, e.g. {"action": "freeze", "state": "verified", "latency_ms": 12.4}
    response: Mapped[dict] = mapped_column(JSON, default=dict)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

    workload: Mapped[Workload] = relationship()
    events: Mapped[list["Event"]] = relationship(back_populates="incident", order_by="Event.ts")
    actions: Mapped[list["OperatorAction"]] = relationship(back_populates="incident", order_by="OperatorAction.requested_at")
    summaries: Mapped[list["Summary"]] = relationship(back_populates="incident", order_by="Summary.created_at")


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    workload_id: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(16))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    facts: Mapped[dict] = mapped_column(JSON)        # Channel A
    payload: Mapped[dict] = mapped_column(JSON, default=dict)  # Channel B: untrusted, display-only
    incident: Mapped[Incident | None] = relationship(back_populates="events")


class OperatorAction(Base):
    __tablename__ = "operator_actions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("act"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    workload_id: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(32))  # resume | terminate | resolve | false_positive
    operator: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    # requested -> delivered -> completed | failed ; record-only actions go straight to "recorded"
    status: Mapped[str] = mapped_column(String(16), default="requested")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    incident: Mapped[Incident] = relationship(back_populates="actions")


class Summary(Base):
    __tablename__ = "summaries"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("sum"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    source: Mapped[str] = mapped_column(String(16))  # model | fallback
    model: Mapped[str] = mapped_column(String(128))
    content: Mapped[dict] = mapped_column(JSON)
    grounded: Mapped[bool] = mapped_column(Boolean)
    invalid_citations: Mapped[list] = mapped_column(JSON, default=list)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    incident: Mapped[Incident] = relationship(back_populates="summaries")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("aud"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)
