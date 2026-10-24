#!/usr/bin/env python3
"""Feeds a recorded session into a running API so the console shows its early-warning tier.

    python3 lab/drift/feed.py lab/drift/sessions/injection-attempt.json my-agent-01 \
        [--api http://127.0.0.1:8000] [--token dev-sensor-token] [--end-minutes-ago 2]

Timestamps are shifted so the session's last record lands `--end-minutes-ago` before now, which
puts the run-up inside the assessment window. Event and log ids get a per-run prefix so the same
session can be fed more than once. Standard library only (the host has Python 3.10).
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


def ts(v):
    d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def post(api, token, path, body):
    req = urllib.request.Request(f"{api}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("session")
    ap.add_argument("workload_id")
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--token", default="dev-sensor-token")
    ap.add_argument("--end-minutes-ago", type=float, default=2)
    ap.add_argument("--until", help="only feed records up to this many minutes into the session (to show a mid-run tier)",
                    type=float)
    a = ap.parse_args()

    s = json.load(open(a.session))
    recs = [("ev", e) for e in s["events"]] + [("log", e) for e in s["agent_log"]]
    recs.sort(key=lambda r: ts(r[1]["ts"]))
    t0 = ts(recs[0][1]["ts"])
    if a.until is not None:
        recs = [r for r in recs if ts(r[1]["ts"]) <= t0 + timedelta(minutes=a.until)]
    t_last = ts(recs[-1][1]["ts"])
    shift = datetime.now(timezone.utc) - timedelta(minutes=a.end_minutes_ago) - t_last
    run = hex(int(time.time()))[2:]

    events = [{"id": f"{run}-{e['id']}", "workload_id": a.workload_id, "kind": e["kind"], "outcome": e["outcome"],
               "ts": (ts(e["ts"]) + shift).isoformat(), "facts": e["facts"]} for k, e in recs if k == "ev"]
    logs = [{"id": f"{run}-{e['id']}", "ts": (ts(e["ts"]) + shift).isoformat(), "kind": e["kind"], "tool": e["tool"],
             "status": e["status"], "target": e["target"], "text": e["text"]} for k, e in recs if k == "log"]
    for i in range(0, len(events), 500):
        code, out = post(a.api, a.token, "/api/v1/events", events[i:i + 500])
        print("events", code, out)
    for i in range(0, len(logs), 500):
        code, out = post(a.api, a.token, f"/api/v1/agents/{a.workload_id}/log", logs[i:i + 500])
        print("agent log", code, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
