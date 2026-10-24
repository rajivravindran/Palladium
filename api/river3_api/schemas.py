"""Request shapes. Channel A (facts) and Channel B (payload) stay separate here too.

Every field is bounded: string lengths, list sizes and JSON blob sizes, so one bad or
hostile client can't fill the database or exhaust memory.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

IDENT_PATTERN = r"^[A-Za-z0-9._:\-]{1,128}$"
Ident = Annotated[str, StringConstraints(pattern=IDENT_PATTERN)]
Short = Annotated[str, StringConstraints(min_length=1, max_length=256)]
Kind = Literal["file_open", "process_exec", "net_connect"]
# pending = attempted / in progress; blocked = refused inline by the sensor (-EPERM), a failed-class outcome (CONTRACTS §9)
Outcome = Literal["success", "failed", "pending", "blocked", "unknown"]
FAILED_OUTCOMES = frozenset({"failed", "blocked"})
WorkloadState = Literal["running", "frozen", "terminated", "unknown"]
IncidentStatus = Literal["open", "contained", "resolved", "false_positive"]
Team = Annotated[str, StringConstraints(max_length=64)]

MAX_BLOB = 16 * 1024  # bytes of JSON per facts / payload / response / detail object

# facts.session.source as a client may send it (22 Oct CONTRACTS §1). "correlated" is reserved: only the
# API writes it, when it attributes an event to a recent tool_call log entry itself.
SESSION_SOURCES = ("gateway", "harness", "sensor")
CORRELATED = "correlated"


def _bounded(v: dict[str, Any], name: str) -> dict[str, Any]:
    if len(json.dumps(v, default=str)) > MAX_BLOB:
        raise ValueError(f"{name} is larger than {MAX_BLOB} bytes")
    return v


def _check_session_facts(s: Any) -> None:
    """facts.session = {id?, tool_call_id?, source?}: idents up to 128 chars, source from the enum."""
    if not isinstance(s, dict):
        raise ValueError("facts.session must be an object")
    for key in ("id", "tool_call_id"):
        if key in s and (not isinstance(s[key], str) or not re.match(IDENT_PATTERN, s[key])):
            raise ValueError(f"facts.session.{key} must be an identifier of 1-128 chars [A-Za-z0-9._:-]")
    if "source" in s and s["source"] not in SESSION_SOURCES:
        raise ValueError(f"facts.session.source must be one of {list(SESSION_SOURCES)}")
    unknown = set(s) - {"id", "tool_call_id", "source"}
    if unknown:
        raise ValueError(f"facts.session has unknown fields {sorted(unknown)}")


class WorkloadIn(BaseModel):
    id: Ident
    name: Short
    profile: Short
    kind: Literal["ai_worker", "shared_service", "unknown"] = "unknown"
    sensor: Annotated[str, StringConstraints(max_length=32)] = "ebpf"
    state: WorkloadState = "running"
    labels: dict[Annotated[str, StringConstraints(max_length=64)], Annotated[str, StringConstraints(max_length=256)]] = Field(
        default_factory=dict, max_length=32)
    # From the river3.team label (CONTRACTS §4.1/§6). Set on create; on re-registration it may only fill
    # an empty team (see main.upsert_workload), so a stale label can't move a workload between teams.
    team: Team = ""
    demo: bool = False


class EventIn(BaseModel):
    id: Ident
    workload_id: Ident
    session_id: Ident | None = None  # the gateway session acting at the time, when the sensor knows it
    kind: Kind
    outcome: Outcome
    ts: datetime | None = None
    facts: dict[str, Any]
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("facts", "payload")
    @classmethod
    def _size(cls, v, info):
        return _bounded(v, info.field_name)

    @field_validator("facts")
    @classmethod
    def _facts_shape(cls, v):
        # Channel A is typed. Anything that reads facts later (drift, console, summaries) relies on these
        # shapes, so a malformed event is refused here instead of failing every later request.
        for key in ("target", "process", "workload"):
            if key in v and not isinstance(v[key], dict):
                raise ValueError(f"facts.{key} must be an object")
        if "errno" in v and (isinstance(v["errno"], bool) or not isinstance(v["errno"], int)):
            raise ValueError("facts.errno must be an integer")
        tgt = v.get("target") or {}
        for key in ("path", "exe", "ip", "access", "binary_class"):
            if key in tgt and not isinstance(tgt[key], str):
                raise ValueError(f"facts.target.{key} must be a string")
        if "session" in v:
            _check_session_facts(v["session"])
        return v

    @property
    def session_facts(self) -> dict[str, Any] | None:
        """facts.session as sent (validated), or None."""
        s = self.facts.get("session")
        return s if isinstance(s, dict) else None


Code = Annotated[str, StringConstraints(pattern=r"^[A-Z0-9_]{1,64}$")]
PolicyAction = Literal["NONE", "ALERT", "PAUSE_CONTAINER", "REVOKE_SESSION"]


class PolicyFinding(BaseModel):
    code: Code
    rule: Annotated[str, StringConstraints(max_length=4096)] = ""


class PolicyDecisionIn(BaseModel):
    """The policy engine's decision, stored as evidence. `action` is an eligible
    candidate at most, never a completed response; results come from the containment layer."""
    profile_name: Short
    profile_version: Annotated[int, Field(ge=1)]
    status: Literal["IN_SCOPE", "VIOLATION", "REVIEW", "UNKNOWN"]
    findings: list[PolicyFinding] = Field(default_factory=list, max_length=64)
    recommended_action: PolicyAction
    action: PolicyAction
    blockers: list[Code] = Field(default_factory=list, max_length=64)
    candidate: dict[str, Any] | None = None

    @field_validator("candidate")
    @classmethod
    def _size(cls, v):
        return None if v is None else _bounded(v, "candidate")


class IncidentIn(BaseModel):
    workload_id: Ident
    title: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    threat: Literal["agent_drift", "external_exploit", "unknown"] = "unknown"
    severity: Literal["info", "high", "critical"]
    verdict: Literal["prohibited", "unresolved"]
    rule: Short
    reason: Annotated[str, StringConstraints(max_length=2000)] = ""
    mode: Literal["shadow", "active"] = "shadow"
    status: IncidentStatus = "open"
    response: dict[str, Any] = Field(default_factory=dict)
    policy: PolicyDecisionIn | None = None
    event_ids: list[Ident] = Field(default_factory=list, max_length=500)
    events: list[EventIn] = Field(default_factory=list, max_length=500)
    demo: bool = False

    @field_validator("response")
    @classmethod
    def _size(cls, v):
        return _bounded(v, "response")


class ResponseUpdate(BaseModel):
    """Posted by the containment layer when it has acted (or failed to)."""
    response: dict[str, Any]
    status: IncidentStatus | None = None
    workload_state: WorkloadState | None = None

    @field_validator("response")
    @classmethod
    def _size(cls, v):
        return _bounded(v, "response")


class ActionIn(BaseModel):
    # revoke_session (docs/CONTRACTS.md §2.2) needs the incident to carry a session_id; the controller runs
    # the gateway session adapter and reports back like any other action.
    # revoke (22 Oct CONTRACTS §3) goes to RIVER3_REVOKE_WEBHOOK instead (gateway / identity provider /
    # cloud-role revoker, role `revoker`) and accepts a session known from the incident OR its workload.
    action: Literal["resume", "terminate", "revoke_session", "revoke", "resolve", "false_positive"]
    reason: Annotated[str, StringConstraints(min_length=8, max_length=2000, strip_whitespace=True)]


class ActionResult(BaseModel):
    status: Literal["completed", "failed"]
    detail: dict[str, Any] = Field(default_factory=dict)
    workload_state: WorkloadState | None = None

    @field_validator("detail")
    @classmethod
    def _size(cls, v):
        return _bounded(v, "detail")


MAX_EVENTS_PER_POST = 1000


class CanaryHit(BaseModel):
    """A decoy credential was USED somewhere. Posted by the canary-token service (or a
    relay in front of it). Creates a critical incident for the workload the credential
    was seeded into; the sensor may or may not have seen the read that leaked it."""
    workload_id: Ident
    credential: Short                      # which decoy, e.g. "db_recovery_creds"
    service: Annotated[str, StringConstraints(max_length=128)] = ""  # where it was used, e.g. "aws-sts", "postgres"
    source_ip: Annotated[str, StringConstraints(max_length=64)] = ""
    observed_at: datetime | None = None
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detail")
    @classmethod
    def _size(cls, v):
        return _bounded(v, "detail")


MAX_LOG_ENTRIES_PER_POST = 500


class AgentLogEntryIn(BaseModel):
    """One line of an agent's own log. Untrusted by design: it is stored apart from kernel facts
    and only ever raises a drift tier. `target` is what the agent SAYS it touched; the kernel
    decides what it actually touched."""
    id: Ident | None = None
    ts: datetime | None = None
    session: Annotated[str, StringConstraints(max_length=128)] = ""
    tool_call_id: Ident | None = None  # the gateway's id for this tool call (22 Oct CONTRACTS §1)
    kind: Literal["tool_call", "tool_result", "plan", "reasoning", "message", "text"] = "text"
    tool: Annotated[str, StringConstraints(max_length=128)] = ""
    status: Literal["ok", "error", ""] = ""
    target: Annotated[str, StringConstraints(max_length=512)] = ""
    text: Annotated[str, StringConstraints(max_length=4000)] = ""


Comment = Annotated[str, StringConstraints(min_length=8, max_length=2000, strip_whitespace=True)]
Revision = Annotated[str, StringConstraints(pattern=r"^([a-f0-9]{64})?$")]


class PolicySave(BaseModel):
    """An admin's edit. `profile` is checked by profiles.validate, which mirrors the policy engine."""
    profile: dict[str, Any]
    base_version: Annotated[int, Field(ge=0)]  # 0 = create
    comment: Comment                          # why; kept in the version history and audit log


class PolicyDelete(BaseModel):
    base_version: Annotated[int, Field(ge=1)]
    comment: Comment


class PolicySyncIn(BaseModel):
    """A controller's report after fetching the bundle."""
    seen_revision: Revision
    active_revision: Revision
    profiles: Annotated[int, Field(ge=0, le=256)]
    error: Annotated[str, StringConstraints(max_length=2000)] = ""


# ----------------------------------------------------------------- sessions, gate, approvals (Stage B)
# Machine-to-machine input is strict (CONTRACTS §0): a gateway that sends a field this API does not
# know is mis-versioned, and silently dropping it would hide that until something is revoked wrongly.
Labels = dict[Annotated[str, StringConstraints(max_length=64)], Annotated[str, StringConstraints(max_length=256)]]
SessionState = Literal["active", "ended", "revoked"]


class SessionIn(BaseModel):
    """POST /sessions: the gateway binds one agent run to a workload. Upsert by session_id."""
    model_config = ConfigDict(extra="forbid")
    session_id: Ident
    workload_id: Ident
    principal: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    started_at: datetime | None = None
    labels: Labels = Field(default_factory=dict, max_length=32)


class SessionPatch(BaseModel):
    """PATCH /sessions/{id}: the gateway ends a session or reports it is still alive. Revoking is
    not something a gateway may do here: that comes from an incident response or an operator."""
    model_config = ConfigDict(extra="forbid")
    state: Literal["ended"] | None = None
    last_seen_at: datetime | None = None


HoldAt = Literal["high", "rising", "never"]
ToolPattern = Annotated[str, StringConstraints(min_length=1, max_length=64)]


class GateIn(BaseModel):
    """PUT /workloads/{id}/gate. `risky_tools` are fnmatch globs against the tool name the gateway sends."""
    model_config = ConfigDict(extra="forbid")
    risky_tools: list[ToolPattern] = Field(default_factory=list, max_length=64)
    hold_at: HoldAt = "never"
    ttl_s: Annotated[int, Field(ge=1, le=86_400)] = 600


class ToolCheckIn(BaseModel):
    """POST /tools/check: asked by the gateway BEFORE it runs a tool."""
    model_config = ConfigDict(extra="forbid")
    workload_id: Ident
    session_id: Ident
    tool: ToolPattern
    args_summary: Annotated[str, StringConstraints(max_length=512)] = ""


class ApprovalIn(BaseModel):
    """POST /approvals (22 Oct CONTRACTS §2): the gateway asks before running a tool. `summary` is what the
    agent says it is about to do: Channel B, stored for display with an untrusted marking, never parsed."""
    model_config = ConfigDict(extra="forbid")
    workload_id: Ident
    session_id: Ident
    tool: ToolPattern
    tool_call_id: Ident
    risk: Literal["normal", "risky"]
    summary: Annotated[str, StringConstraints(max_length=512)] = ""


class ApprovalDecision(BaseModel):
    """`allow` is the contract's word; `approve` is accepted for callers written against the Stage B draft."""
    decision: Literal["allow", "approve", "deny"]
    reason: Comment
