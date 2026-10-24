"""Database models. Works on SQLite (dev) and PostgreSQL (pilot)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, create_engine
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
    # Which team owns it (CONTRACTS §6). "" = unassigned, visible to every operator. Set by the sensor
    # from the river3.team label; operators with a team list only see workloads in their teams.
    team: Mapped[str] = mapped_column(String(64), default="", server_default="")
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AgentSession(Base):
    """One agent run as the gateway identifies it, bound to a workload (CONTRACTS §1). Named
    AgentSession in code because `Session` is SQLAlchemy's; the table is `sessions`.

    The id is the GATEWAY's session id, not ours: the gateway is the one that has to recognise it
    when the controller says "revoke this". `revoked` is terminal: a revoked session never becomes
    active again through re-registration (a compromised agent must not be able to re-bind itself)."""
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workload_id: Mapped[str] = mapped_column(ForeignKey("workloads.id"), index=True)
    principal: Mapped[str] = mapped_column(String(128))  # the agent identity, e.g. svc-deployer@prod
    state: Mapped[str] = mapped_column(String(16), default="active", index=True)  # active | ended | revoked
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    revoke_reason: Mapped[str] = mapped_column(Text, default="")
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    workload: Mapped[Workload] = relationship()


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
    # Policy engine decision (status, findings, blockers, candidate) kept as evidence
    policy: Mapped[dict] = mapped_column(JSON, default=dict, server_default="{}")
    # Who was acting (CONTRACTS §1.3): the gateway session the evidence belongs to, if any. Required
    # for revoke_session; the API never guesses it from timing, only from events or the policy identity.
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
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
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(16))  # success | failed | pending | blocked | unknown
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    facts: Mapped[dict] = mapped_column(JSON)        # Channel A
    payload: Mapped[dict] = mapped_column(JSON, default=dict)  # Channel B: untrusted, display-only
    incident: Mapped[Incident | None] = relationship(back_populates="events")


class OperatorAction(Base):
    __tablename__ = "operator_actions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("act"))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"))
    workload_id: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(32))  # resume | terminate | revoke_session | revoke | resolve | false_positive
    operator: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    # `revoke` (22 Oct CONTRACTS §3): the session this request targets, resolved when the operator asked
    # (incident binding, then facts.session on its events, then the workload's newest active session).
    # Stored on the action so the webhook body and the receiver's report agree on what was revoked.
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
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


class PolicyProfile(Base):
    """The current version of a policy profile. `body` is the exact JSON the policy engine loads."""
    __tablename__ = "policy_profiles"
    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))  # ai_worker | shared_service
    version: Mapped[int] = mapped_column(Integer)
    body: Mapped[dict] = mapped_column(JSON)
    updated_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class PolicyProfileVersion(Base):
    """Every saved version, and deletions, kept forever so a change can be reviewed or rolled back."""
    __tablename__ = "policy_profile_versions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("pv"))
    name: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[int] = mapped_column(Integer)
    body: Mapped[dict] = mapped_column(JSON)  # the profile as saved; the last body for a deletion
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    author: Mapped[str] = mapped_column(String(128))
    comment: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class PolicySync(Base):
    """What each controller last reported: the newest set it saw and the set it is enforcing."""
    __tablename__ = "policy_sync"
    controller: Mapped[str] = mapped_column(String(128), primary_key=True)  # machine principal name
    seen_revision: Mapped[str] = mapped_column(String(64))
    active_revision: Mapped[str] = mapped_column(String(64))
    profiles: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")  # why seen_revision was refused, if it was
    reported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AgentLogEntry(Base):
    """The agent's OWN account of what it did: tool calls, plans, reasoning. Untrusted (the agent wrote
    it), bounded, and kept apart from kernel-observed events. drift.py reads it; nothing else does."""
    __tablename__ = "agent_log"
    # A client-supplied id is stored as "<workload_id>:<id>" so re-sends dedupe per workload (two
    # agents may both number their lines l1, l2...). Width: Ident(128) + ":" + Ident(128).
    id: Mapped[str] = mapped_column(String(257), primary_key=True, default=lambda: new_id("al"))
    workload_id: Mapped[str] = mapped_column(String(128), index=True)
    session: Mapped[str] = mapped_column(String(128), default="")
    # The gateway's id for one tool call (22 Oct CONTRACTS §1). Events without facts.session are correlated
    # to the latest tool_call entry in the window and carry this id as facts.session.tool_call_id.
    tool_call_id: Mapped[str] = mapped_column(String(128), default="", server_default="")
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    kind: Mapped[str] = mapped_column(String(16))  # tool_call | tool_result | plan | reasoning | message | text
    tool: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="")  # ok | error | ""
    target: Mapped[str] = mapped_column(String(512), default="")  # path or host the tool acted on, as the agent reports it
    text: Mapped[str] = mapped_column(Text, default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class DriftState(Base):
    """The current early-warning tier of a workload, with the reasons behind it."""
    __tablename__ = "drift_state"
    workload_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tier: Mapped[str] = mapped_column(String(16), default="steady")  # steady | rising | high | crossed
    previous_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)
    trend: Mapped[str] = mapped_column(String(8), default="flat")  # up | down | flat
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    model: Mapped[dict] = mapped_column(JSON, default=dict)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class DriftHistory(Base):
    """One row per tier change, for the trend line and for measuring lead time later."""
    __tablename__ = "drift_history"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("dh"))
    workload_id: Mapped[str] = mapped_column(String(128), index=True)
    tier: Mapped[str] = mapped_column(String(16))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    summary: Mapped[str] = mapped_column(String(512), default="")


class WorkloadGate(Base):
    """Approval gate for one workload (CONTRACTS §3.1): which tools are risky and from which drift tier
    the gateway must hold them for a human. Kept outside the policy profile on purpose: a profile says
    what the kernel may see the workload do; the gate is about what the GATEWAY lets the agent try,
    and it is tuned per workload, not per profile. No row = no gate."""
    __tablename__ = "workload_gates"
    workload_id: Mapped[str] = mapped_column(ForeignKey("workloads.id"), primary_key=True)
    risky_tools: Mapped[list] = mapped_column(JSON, default=list)  # glob patterns, fnmatch
    hold_at: Mapped[str] = mapped_column(String(8), default="never")  # high | rising | never
    ttl_s: Mapped[int] = mapped_column(Integer, default=600)  # how long a hold waits for a decision
    updated_by: Mapped[str] = mapped_column(String(128), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class Approval(Base):
    """One tool call the gateway asked about (22 Oct CONTRACTS §2; also the holds raised by tools/check).
    `allow` and `deny` answers are recorded with the decision already taken (decided_by "policy"); a `hold`
    is stored `pending` until an operator decides. A pending row past `expires_at` READS as expired (see
    main.approval_status) and is persisted as such on the next read (lazy sweep), so no timer job is needed,
    a decision on a stale hold is refused, never applied late, and the gateway polling GET sees `expired`,
    which it must treat as deny (fail closed)."""
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: new_id("apr"))
    workload_id: Mapped[str] = mapped_column(ForeignKey("workloads.id"), index=True)
    session_id: Mapped[str] = mapped_column(String(128), index=True)
    tool: Mapped[str] = mapped_column(String(64))
    tool_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    risk: Mapped[str] = mapped_column(String(8), default="risky", server_default="risky")  # normal | risky
    summary: Mapped[str] = mapped_column(String(512), default="")  # Channel B: what the agent says it wants; untrusted
    tier_at_request: Mapped[str] = mapped_column(String(16))  # drift tier when the gateway asked
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|allowed|denied|expired
    decision_reason: Mapped[str] = mapped_column(Text, default="")  # the rule that decided, or the operator's reason
    requested_by: Mapped[str] = mapped_column(String(128), default="", server_default="")  # the gateway principal
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Append-only and hash-chained: each row stores the hash of the previous row,
    so editing or deleting any row breaks the chain (see audit.verify_chain)."""
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    id: Mapped[str] = mapped_column(String(64), unique=True, default=lambda: new_id("aud"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditHead(Base):
    """Single row holding the chain tip; locked FOR UPDATE while appending."""
    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    hash: Mapped[str] = mapped_column(String(64), default="0" * 64)


_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    """Development convenience. Production uses Alembic migrations (`alembic upgrade head`)."""
    Base.metadata.create_all(engine)
