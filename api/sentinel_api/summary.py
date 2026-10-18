"""Investigation summaries (Qwen3-8B, local).

Safety rules baked in:
1. The model sees Channel A facts ONLY. Channel B payload (raw commands, file
   text) is untrusted and could carry prompt injection, so it never reaches the model.
2. Every timeline line must cite an event ID. Citations that don't exist in the
   incident are stripped and the summary is marked NOT grounded.
3. If the model is unreachable or returns junk, a deterministic summary is used,
   and the console says so.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from .config import settings
from .db import Incident

SYSTEM_PROMPT = """You are Sentinel's incident investigator. You write short, factual incident summaries for a security operator.
Rules:
- Use ONLY the structured facts provided. Do not guess at intent or content you cannot see.
- Every timeline item MUST cite exactly one event_id from the input.
- If something is unknown, say so in "unknowns".
- Reply with JSON only, no prose outside JSON:
{"headline": str, "timeline": [{"event_id": str, "what": str}], "assessment": str, "unknowns": [str]}
/no_think"""


def _facts_for_model(inc: Incident) -> dict[str, Any]:
    return {
        "incident": {
            "id": inc.id, "title": inc.title, "threat": inc.threat, "severity": inc.severity,
            "verdict": inc.verdict, "rule": inc.rule, "reason": inc.reason, "mode": inc.mode,
            "response": inc.response,
        },
        "workload": {
            "id": inc.workload.id, "name": inc.workload.name, "profile": inc.workload.profile,
            "kind": inc.workload.kind, "state": inc.workload.state,
        },
        # Channel A only. e.payload is deliberately excluded.
        "events": [
            {"event_id": e.id, "ts": e.ts.isoformat(), "kind": e.kind, "outcome": e.outcome, "facts": e.facts}
            for e in inc.events
        ],
    }


def _extract_json(text: str) -> dict[str, Any]:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("no JSON object in model output")
    return json.loads(m.group(0))


def ground(content: dict[str, Any], valid_ids: set[str]) -> tuple[dict[str, Any], list[str]]:
    """Keep only timeline items that cite a real event. Returns (cleaned, invalid_ids)."""
    invalid: list[str] = []
    kept = []
    for item in content.get("timeline") or []:
        if not isinstance(item, dict):
            continue
        eid = str(item.get("event_id", ""))
        if eid in valid_ids:
            kept.append({"event_id": eid, "what": str(item.get("what", ""))[:400]})
        else:
            invalid.append(eid or "<missing>")
    cleaned = {
        "headline": str(content.get("headline", ""))[:300],
        "timeline": kept,
        "assessment": str(content.get("assessment", ""))[:1500],
        "unknowns": [str(u)[:300] for u in (content.get("unknowns") or []) if u][:10],
    }
    return cleaned, invalid


def _describe(e) -> str:
    f = e.facts
    t = f.get("target", {})
    proc = f.get("process", {}).get("comm") or "process"
    if e.kind == "file_open":
        return f"{proc} opened {t.get('path', '?')} for {t.get('access', '?')} ({e.outcome})"
    if e.kind == "process_exec":
        return f"{proc} started {t.get('exe', '?')} [{t.get('binary_class', '?')}] ({e.outcome})"
    if e.kind == "net_connect":
        return f"{proc} connected to {t.get('ip', '?')}:{t.get('port', '?')} ({e.outcome})"
    return f"{e.kind} ({e.outcome})"


def fallback_summary(inc: Incident) -> dict[str, Any]:
    resp = inc.response or {}
    action = resp.get("action")
    state = resp.get("state")
    assessment = f"Rule '{inc.rule}' marked this {inc.verdict}. {inc.reason}".strip()
    if action:
        assessment += f" Response: {action} ({state or 'state not reported'})."
    elif inc.mode == "shadow":
        assessment += " Shadow mode: no automatic action was taken."
    return {
        "headline": f"{inc.workload.name}: {inc.title}",
        "timeline": [{"event_id": e.id, "what": _describe(e)} for e in inc.events],
        "assessment": assessment,
        "unknowns": ["Generated without the language model (deterministic fallback)."],
    }


def summarize(inc: Incident, client: httpx.Client | None = None) -> dict[str, Any]:
    """Returns dict(source, model, content, grounded, invalid_citations, latency_ms)."""
    valid_ids = {e.id for e in inc.events}
    started = time.perf_counter()
    try:
        own = client is None
        client = client or httpx.Client(timeout=settings.llm_timeout_s)
        try:
            r = client.post(
                f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                json={
                    "model": settings.llm_model,
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(_facts_for_model(inc), default=str)},
                    ],
                },
            )
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
        finally:
            if own:
                client.close()
        content, invalid = ground(_extract_json(text), valid_ids)
        if not content["timeline"]:
            raise ValueError("model produced no grounded timeline items")
        return {
            "source": "model", "model": settings.llm_model, "content": content,
            "grounded": not invalid, "invalid_citations": invalid,
            "latency_ms": (time.perf_counter() - started) * 1000,
        }
    except Exception as exc:  # model offline, bad JSON, etc.
        content = fallback_summary(inc)
        content["unknowns"].append(f"Model unavailable: {type(exc).__name__}: {str(exc)[:160]}")
        return {
            "source": "fallback", "model": "deterministic", "content": content,
            "grounded": True, "invalid_citations": [],
            "latency_ms": (time.perf_counter() - started) * 1000,
        }
