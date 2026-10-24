"""Alert notifications: one HTTP POST per incident that meets the severity threshold.

Configured by RIVER3_ALERT_WEBHOOK (URL) and RIVER3_ALERT_MIN_SEVERITY (info|high|critical,
default high). The body carries a human line ("text", which Slack-style receivers render
as-is) and the incident as structured JSON. The request is HMAC-signed with
RIVER3_ALERT_SECRET using the same scheme as the action webhook ("<ts>.<delivery>.<body>",
see security.sign_webhook), so a receiver you own can verify it. The alert key is deliberately
NOT the action-webhook key: the alert receiver is a different trust domain and must not be
able to forge operator actions. In production config.validate() refuses an alert webhook
without its own secret; in development alerts fall back to unsigned with a warning.
No River3 credentials are ever sent.

Delivery is best-effort and off the request path (thread pool); the incident is already
committed and in the audit log by the time this runs. A failed alert is logged, not
retried: the console and the live stream are the system of record, this is a nudge.

Early-warning tier changes (`drift_changed`) go through the same webhook with a per-workload
cooldown (RIVER3_DRIFT_ALERT_COOLDOWN, default 600 s): inside it only a higher tier is alerted.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from .config import settings
from .security import sign_webhook

log = logging.getLogger("river3.notify")

_SEVERITY_RANK = {"info": 0, "high": 1, "critical": 2}
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")


def wanted(severity: str) -> bool:
    """True when this severity meets the configured threshold and a webhook is set."""
    if not settings.alert_webhook:
        return False
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(settings.alert_min_severity, 1)


def render_text(inc: dict[str, Any]) -> str:
    w = inc.get("workload") or {}
    resp = inc.get("response") or {}
    line = f"[River3 {inc.get('severity', '?').upper()}] {inc.get('title', '')} — {w.get('name') or w.get('id')}"
    if inc.get("mode") == "shadow":
        line += " (shadow: no automatic action)"
    elif resp.get("state"):
        line += f" (response: {resp.get('action')} {resp.get('state')})"
    return line[:500]


def payload_for(inc: dict[str, Any], kind: str = "incident.created") -> dict[str, Any]:
    keep = {k: inc.get(k) for k in ("id", "title", "threat", "severity", "verdict", "rule", "reason", "mode", "status",
                                     "response", "demo", "created_at")}
    keep["workload"] = {k: (inc.get("workload") or {}).get(k) for k in ("id", "name", "profile", "kind", "state")}
    return {"text": render_text(inc), "type": kind, "incident": keep}


_warned_unsigned = False


def _send(body: dict[str, Any]) -> None:
    global _warned_unsigned
    raw = json.dumps(body, default=str, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    if settings.alert_secret:
        headers.update(sign_webhook(raw, secret=settings.alert_secret))
    elif not _warned_unsigned:  # development only: validate() refuses this combination in production
        _warned_unsigned = True
        log.warning("alert.unsigned", extra={"note": "RIVER3_ALERT_SECRET is not set; alerts carry no signature"})
    try:
        r = httpx.post(settings.alert_webhook, content=raw, headers=headers, timeout=5, follow_redirects=False)
        ref = (body["incident"].get("id") or (body.get("drift") or {}).get("workload_id")
               or (body.get("approval") or {}).get("id"))
        if r.status_code >= 300:
            log.warning("alert.rejected", extra={"status": r.status_code, "ref": ref})
        else:
            log.info("alert.sent", extra={"ref": ref, "type": body.get("type"), "severity": body["incident"]["severity"]})
    except httpx.HTTPError as exc:
        log.warning("alert.failed", extra={"type": body.get("type"), "error": type(exc).__name__})


def incident_created(inc: dict[str, Any], kind: str = "incident.created") -> bool:
    """Queue an alert for a serialized incident. Returns whether one was queued."""
    if not wanted(inc.get("severity", "info")):
        return False
    _pool.submit(_send, payload_for(inc, kind))
    return True


_TIER_SEVERITY = {"rising": "high", "high": "critical"}
_TIER_RANK = {"rising": 1, "high": 2}

# Per-workload alert cooldown. A workload sitting on a threshold can flip rising<->steady on every
# request; without this each flip would be a webhook. Inside the cooldown window another alert goes
# out only when the tier is HIGHER than the highest one already alerted in that window. The live
# stream still gets every change (bus.publish in main.py): that is cheap and the console wants it.
_recent_lock = threading.Lock()
_recent: dict[str, dict[str, float]] = {}  # workload_id -> {"at": monotonic seconds, "rank": highest tier alerted}
_RECENT_MAX = 4096


def _cooldown_allows(workload_id: str, rank: int, now_s: float) -> bool:
    cooldown = settings.drift_alert_cooldown_s
    with _recent_lock:
        last = _recent.get(workload_id)
        if last is not None and now_s - last["at"] < cooldown and rank <= last["rank"]:
            return False
        if len(_recent) >= _RECENT_MAX:  # forget expired windows before remembering a new one
            for wid in [w for w, r in _recent.items() if now_s - r["at"] >= cooldown]:
                del _recent[wid]
        _recent[workload_id] = {"at": now_s, "rank": rank}
        return True


def reset_cooldowns() -> None:
    """Forget alert cooldowns (tests)."""
    with _recent_lock:
        _recent.clear()


def drift_changed(state: dict[str, Any], workload: dict[str, Any], now_s: float | None = None) -> bool:
    """Queue an alert when a workload's early-warning tier RISES to rising or high, at most once per
    RIVER3_DRIFT_ALERT_COOLDOWN seconds per workload unless the tier climbed further. `crossed`
    is not alerted here: the incident that caused it already was. `now_s` is a clock override for tests."""
    sev = _TIER_SEVERITY.get(state.get("tier", ""))
    if not sev or state.get("trend") != "up" or not wanted(sev):
        return False
    wid = str(state.get("workload_id") or workload.get("id") or "")
    if not _cooldown_allows(wid, _TIER_RANK[state["tier"]], time.monotonic() if now_s is None else now_s):
        log.info("alert.drift_cooldown", extra={"ref": wid, "tier": state["tier"]})
        return False
    reasons = "; ".join(r.get("text", "") for r in state.get("reasons", [])[:3])
    text = f"[River3 {state['tier'].upper()}] {workload.get('name') or workload.get('id')} is heading out of scope: {reasons}"
    body = {"text": text[:500], "type": "drift.tier_changed",
            "incident": {"id": None, "severity": sev},  # keeps receivers that key on incident.* working
            "drift": {k: state.get(k) for k in ("workload_id", "tier", "previous_tier", "trend", "reasons", "computed_at")},
            "workload": {k: workload.get(k) for k in ("id", "name", "profile", "kind", "state")}}
    _pool.submit(_send, body)
    return True


def approval_held(approval: dict[str, Any], workload: dict[str, Any]) -> bool:
    """Queue an alert when the gateway's approval request is HELD for an operator (22 Oct CONTRACTS §2):
    someone has `ttl_s` seconds to decide or the tool call is refused. Severity high, same webhook and
    signature as incidents. The agent's `summary` is Channel B and is left out on purpose: an alert
    channel (Slack, pager) renders text without the console's "untrusted" marking, and an agent must not
    be able to address the on-call engineer through it. The console shows it, marked."""
    if not wanted("high"):
        return False
    tool, name = approval.get("tool", "?"), workload.get("name") or workload.get("id")
    text = (f"[River3 APPROVAL] {name} wants to run '{tool}' at tier {approval.get('tier_at_request', '?')}: "
            f"decide in the console within {approval.get('ttl_s', '?')} s or it is refused")
    body = {"text": text[:500], "type": "approval.held",
            "incident": {"id": None, "severity": "high"},  # keeps receivers that key on incident.* working
            "approval": {k: approval.get(k) for k in ("id", "workload_id", "session_id", "tool", "tool_call_id", "risk",
                                                       "tier_at_request", "requested_by", "requested_at", "expires_at")},
            "workload": {k: workload.get(k) for k in ("id", "name", "profile", "kind", "state", "team")}}
    _pool.submit(_send, body)
    return True


def shutdown() -> None:
    _pool.shutdown(wait=False, cancel_futures=True)
