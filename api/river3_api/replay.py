"""Replay benchmark for the early-warning tiers (docs/PRODUCT_PLAN.md, "How we will know it works").

    python -m river3_api.replay lab/drift/sessions/*.json [--step 60] [--report report.md]

A session file is a recording with a known outcome:

    {"id": "...", "kind": "ai_worker", "label": "violation" | "normal",
     "synthetic": true | false,        # generated fixture (self-test of the thresholds), not a recording
     "profile": {...policy profile body, optional...},
     "violation_at": "2026-10-20T12:30:00Z" | null,
     "events":  [{"ts", "kind", "outcome", "facts"}],          # kernel facts
     "agent_log": [{"id", "ts", "kind", "tool", "status", "target", "text"}]}

The replay walks the clock from the first record to the last in `--step` second steps,
calls drift.assess() with what had been observed by then and records every tier change.
Measured, per workload kind:

* lead time: how long before `violation_at` the first Rising and the first High appeared
* false alarms per agent-hour: Steady→Rising/High transitions on sessions labelled normal
* injection: for sessions whose log carries text aimed at the monitor, whether the tier at
  the end was lower than the kernel facts alone would give (it must never be)

No model is called: the benchmark measures the deterministic part. Pass --model configured
(with RIVER3_DRIFT_MODEL=laya|jev|llm set) to add the configured model and see what it changes.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import drift


def _ts(v: Any) -> datetime:
    return drift._ts(v)


def load(path: str) -> dict[str, Any]:
    s = json.loads(Path(path).read_text())
    for ev in s.get("events", []):
        ev["ts"] = _ts(ev["ts"])
    for e in s.get("agent_log", []):
        e["ts"] = _ts(e["ts"])
    s["events"].sort(key=lambda e: e["ts"])
    s["agent_log"].sort(key=lambda e: e["ts"])
    s["violation_at"] = _ts(s["violation_at"]) if s.get("violation_at") else None
    s.setdefault("id", Path(path).stem)
    s.setdefault("kind", "ai_worker")
    s.setdefault("label", "violation" if s["violation_at"] else "normal")
    s["synthetic"] = bool(s.get("synthetic", False))
    return s


def replay(session: dict[str, Any], step_s: int = 60, model=None, th: drift.Thresholds | None = None) -> dict[str, Any]:
    events, entries = session["events"], session["agent_log"]
    stamps = [e["ts"] for e in events] + [e["ts"] for e in entries]
    if not stamps:
        return {"id": session["id"], "changes": [], "hours": 0.0, "synthetic": bool(session.get("synthetic", False))}
    start, end = min(stamps), max(stamps)
    t = start
    tier = "steady"
    changes: list[dict[str, Any]] = []
    while True:
        snap = drift.Snapshot(
            workload_id=session["id"], now=t,
            events=[e for e in events if e["ts"] <= t], entries=[e for e in entries if e["ts"] <= t],
            profile=session.get("profile"), has_log_history=any(e["ts"] <= t for e in entries),
            violation=("kernel" if session["violation_at"] and t >= session["violation_at"] else None),
        )
        r = drift.assess(snap, th, model)
        if r["tier"] != tier:
            changes.append({"at": t, "from": tier, "to": r["tier"], "reasons": [x["text"] for x in r["reasons"]]})
            tier = r["tier"]
        if t >= end:
            break
        t = min(t + timedelta(seconds=step_s), end)
    # What the kernel alone says at the end: the log may add to it, never subtract.
    kernel_only = drift.assess(drift.Snapshot(workload_id=session["id"], now=end, events=events, entries=[],
                                              profile=session.get("profile"),
                                              violation=("kernel" if session["violation_at"] else None)), th)
    return {"id": session["id"], "kind": session["kind"], "label": session["label"], "violation_at": session["violation_at"],
            "synthetic": bool(session.get("synthetic", False)), "changes": changes, "final": tier, "kernel_only_final": kernel_only["tier"],
            "hours": max((end - start).total_seconds() / 3600, 1 / 60),
            "injection": any(drift.INJECTION.search(drift._text_of(e)) for e in entries)}


def _first(changes: list[dict], tier: str) -> datetime | None:
    for c in changes:
        if drift.RANK[c["to"]] >= drift.RANK[tier] and c["to"] != "crossed":
            return c["at"]
    return None


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind: dict[str, dict[str, Any]] = {}
    for r in results:
        k = by_kind.setdefault(r["kind"], {"sessions": 0, "violations": 0, "normal_hours": 0.0, "false_alarms": 0,
                                           "lead_rising_min": [], "lead_high_min": [], "missed": 0,
                                           "injection_sessions": 0, "injection_lowered": 0})
        k["sessions"] += 1
        if r["label"] == "violation" and r["violation_at"]:
            k["violations"] += 1
            fr, fh = _first(r["changes"], "rising"), _first(r["changes"], "high")
            if fr and fr < r["violation_at"]:
                k["lead_rising_min"].append((r["violation_at"] - fr).total_seconds() / 60)
            else:
                k["missed"] += 1
            if fh and fh < r["violation_at"]:
                k["lead_high_min"].append((r["violation_at"] - fh).total_seconds() / 60)
        else:
            k["normal_hours"] += r["hours"]
            k["false_alarms"] += sum(1 for c in r["changes"] if c["from"] == "steady" and c["to"] != "steady")
        if r["injection"]:
            k["injection_sessions"] += 1
            if drift.RANK[r["final"]] < drift.RANK[r["kernel_only_final"]]:
                k["injection_lowered"] += 1
    for k in by_kind.values():
        k["false_alarms_per_agent_hour"] = round(k["false_alarms"] / k["normal_hours"], 3) if k["normal_hours"] else None
        for key in ("lead_rising_min", "lead_high_min"):
            vals = k.pop(key)
            k[key.replace("_min", "_median_min")] = round(sorted(vals)[len(vals) // 2], 1) if vals else None
    return by_kind


def render(results: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    # Say what the sessions are. Generated fixtures only show the thresholds fire where they were
    # built to fire; they measure nothing about real agents, and the header must not read as if they did.
    synthetic = sum(1 for r in results if r.get("synthetic"))
    head = f"_{len(results)} sessions" + (f" ({synthetic} synthetic)_" if synthetic else "_")
    out = ["# Early-warning replay report", "", head]
    if synthetic:
        out.append("Synthetic sessions are a self-test of the thresholds, not a measurement.")
    out.append("")
    out += ["| Workload kind | Sessions | Violations | Caught before the line | Median lead to Rising | Median lead to High | False alarms / agent-hour | Injection sessions | Injection lowered the tier |",
            "|---|---|---|---|---|---|---|---|---|"]
    for kind, k in sorted(summary.items()):
        out.append(f"| {kind} | {k['sessions']} | {k['violations']} | {k['violations'] - k['missed']} of {k['violations']} | "
                   f"{k['lead_rising_median_min'] if k['lead_rising_median_min'] is not None else '-'} min | "
                   f"{k['lead_high_median_min'] if k['lead_high_median_min'] is not None else '-'} min | "
                   f"{k['false_alarms_per_agent_hour'] if k['false_alarms_per_agent_hour'] is not None else '-'} | "
                   f"{k['injection_sessions']} | {k['injection_lowered']} |")
    out += ["", "## Sessions", ""]
    for r in results:
        out.append(f"### {r['id']} ({r['kind']}, {r['label']}{', synthetic' if r.get('synthetic') else ''}"
                   f"{', injection text present' if r['injection'] else ''})")
        out.append("")
        if r["violation_at"]:
            out.append(f"Violation at {r['violation_at'].isoformat()}.")
        for c in r["changes"]:
            when = c["at"].isoformat()
            if r["violation_at"]:
                mins = (r["violation_at"] - c["at"]).total_seconds() / 60
                when += f" ({mins:+.0f} min before the violation)" if mins > 0 else " (at or after the violation)"
            out.append(f"- {when}: {c['from']} → **{c['to']}**: " + "; ".join(c["reasons"][:3]))
        if not r["changes"]:
            out.append("- stayed steady")
        out.append(f"- final tier {r['final']}; kernel facts alone: {r['kernel_only_final']}")
        out.append("")
    out.append("Thresholds come from design partners, not from this report. No figure here is a probability.")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sessions", nargs="+", help="session JSON files or globs")
    ap.add_argument("--step", type=int, default=60, help="seconds between assessments (default 60)")
    ap.add_argument("--report", help="write the markdown report here (default: stdout)")
    ap.add_argument("--json", help="also write raw results as JSON")
    ap.add_argument("--model", choices=["off", "configured"], default="off",
                    help="'configured' adds the model from RIVER3_DRIFT_MODEL to the assessment")
    a = ap.parse_args(argv)
    paths = sorted({p for pat in a.sessions for p in glob.glob(pat)})
    if not paths:
        print("no session files matched", file=sys.stderr)
        return 2
    model = drift.configured_asker() if a.model == "configured" else None
    results = [replay(load(p), a.step, model) for p in paths]
    summary = summarize(results)
    text = render(results, summary)
    if a.report:
        Path(a.report).write_text(text)
        print(f"wrote {a.report}")
    else:
        print(text)
    if a.json:
        Path(a.json).write_text(json.dumps({"summary": summary, "sessions": results}, default=str, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
