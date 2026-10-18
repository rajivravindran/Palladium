"""Request/response shapes. Channel A (facts) and Channel B (payload) stay separate here too."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Kind = Literal["file_open", "process_exec", "net_connect"]
Outcome = Literal["success", "failed", "pending"]


class WorkloadIn(BaseModel):
    id: str
    name: str
    profile: str
    kind: Literal["ai_worker", "shared_service", "unknown"] = "unknown"
    sensor: str = "ebpf"
    state: Literal["running", "frozen", "terminated", "unknown"] = "running"
    labels: dict[str, str] = Field(default_factory=dict)
    demo: bool = False


class EventIn(BaseModel):
    id: str
    workload_id: str
    kind: Kind
    outcome: Outcome
    ts: datetime | None = None
    facts: dict[str, Any]
    payload: dict[str, Any] = Field(default_factory=dict)


class IncidentIn(BaseModel):
    workload_id: str
    title: str
    threat: Literal["agent_drift", "external_exploit", "unknown"] = "unknown"
    severity: Literal["info", "high", "critical"]
    verdict: Literal["prohibited", "unresolved"]
    rule: str
    reason: str = ""
    mode: Literal["shadow", "active"] = "shadow"
    status: Literal["open", "contained", "resolved", "false_positive"] = "open"
    response: dict[str, Any] = Field(default_factory=dict)
    event_ids: list[str] = Field(default_factory=list)
    events: list[EventIn] = Field(default_factory=list)
    demo: bool = False


class ResponseUpdate(BaseModel):
    """Posted by the containment layer when it has acted (or failed to)."""
    response: dict[str, Any]
    status: Literal["open", "contained", "resolved", "false_positive"] | None = None
    workload_state: Literal["running", "frozen", "terminated", "unknown"] | None = None


class ActionIn(BaseModel):
    action: Literal["resume", "terminate", "resolve", "false_positive"]
    reason: str = Field(min_length=8, max_length=2000)


class ActionResult(BaseModel):
    status: Literal["completed", "failed"]
    detail: dict[str, Any] = Field(default_factory=dict)
    workload_state: Literal["running", "frozen", "terminated", "unknown"] | None = None
