#!/usr/bin/env bash
# River3 demo for a laptop WITHOUT Docker or root. Same two stories as demo/run.sh (the freeze, the
# drift), same API, console, controller, gateway, profiles and principals -- but the runtime is the
# controller's mock adapter and the kernel events are REPLAYED from demo/events/*.jsonl instead of
# being observed by the eBPF sensor. Nothing here is evidence of anything; demo/run.sh is.
#
#   demo/run-mock.sh            start everything, replay both feeds (~45 s), print a summary
#   demo/run-mock.sh --no-wait  start everything, replay in the background, return immediately
#   DEMO_FAST=1 demo/run-mock.sh   replay at ~6x speed
#   demo/stop.sh                tear everything down (logs stay in demo/.run/)
#
# Needs: bash, curl, python3, Go, the API venv at api/.venv (api/README.md). No docker, no sudo.
#
# What is real and what is not:
#   real   river3-containd (policy engine, journal, verify-after-act, reporting), the API, the console,
#          the drift tiers, the reference gateway, the two profiles, the development principals
#   mock   the container runtime (-adapter mock -mock-containers registry: two "containers" seeded from
#          the registry; a pause flips their state and the controller re-inspects it like any adapter)
#   replay the kernel events: demo/events/<agent>.jsonl is what the eBPF sensor reported for the scripted
#          agents, posted here with the sensor token to the controller (/v1/events) and the API
#          (/api/v1/events), with the agent's own log lines (Channel B) going through the gateway
# Not wired: a session adapter. The controller only knows `-session-adapter gateway` (signed revokes
# against a real gateway); the in-memory mock session adapter exists only in the Go tests. So
# REVOKE_SESSION is blocked with ADAPTER_UNAVAILABLE here, exactly as in demo/run.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
RUN="$HERE/.run"
BIN="$RUN/bin"

API_PORT="${API_PORT:-8000}"
CTL_PORT="${CTL_PORT:-8787}"
GW_PORT="${GW_PORT:-8790}"
API="http://127.0.0.1:$API_PORT"
CTL="http://127.0.0.1:$CTL_PORT"
GW="http://127.0.0.1:$GW_PORT"
WAIT=1
[ "${1:-}" = "--no-wait" ] && WAIT=0

# Development tokens (demo/principals.json). Plain tokens are refused in production mode.
OPERATOR_TOKEN=dev-operator-token
SENSOR_TOKEN=dev-sensor-token
POLICY_TOKEN=dev-policy-token
CONTAINMENT_TOKEN=dev-containment-token
GATEWAY_TOKEN=dev-gateway-token
GATEWAY_SECRET=demo-gateway-secret-0123456789abcdef0123456789abcdef

log()  { printf '\033[1;34m[demo-mock]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[demo-mock] %s\033[0m\n' "$*" >&2; exit 1; }
on_err() { printf '\033[1;31m[demo-mock] failed at line %s; tearing down (logs in %s)\033[0m\n' "$1" "$RUN" >&2; "$HERE/stop.sh" --quiet || true; }
trap 'on_err $LINENO' ERR

wait_http() { # url seconds
  local i; for ((i = 0; i < $2 * 2; i++)); do curl -sf "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done
  return 1
}
start_bg() { # name cwd cmd...  (stdout+stderr -> $RUN/<name>.log; pid -> $RUN/pids, which stop.sh reads)
  local name="$1" cwd="$2"; shift 2
  ( cd "$cwd" && exec "$@" ) >"$RUN/$name.log" 2>&1 &
  echo "$! $name" >>"$RUN/pids"
  log "started $name (pid $!)"
}
api() { # method path [json]   as the operator
  curl -sS -X "$1" -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
       ${3:+--data-binary "$3"} "$API$2"
}

printf '\n\033[1;33m  SIMULATED: mock runtime, replayed events. For the real run use demo/run.sh\033[0m\n\n'

# ---------------------------------------------------------------- preconditions
command -v go >/dev/null || die "go not found"
command -v python3 >/dev/null || die "python3 not found"
command -v curl >/dev/null || die "curl not found"
[ -x "$ROOT/api/.venv/bin/python" ] || die "api/.venv missing (see api/README.md)"

"$HERE/stop.sh" --quiet
mkdir -p "$RUN" "$BIN"
: >"$RUN/pids"
log "run directory: $RUN"

# ---------------------------------------------------------------- enrollment for the mock runtime
# demo/registry.json has an empty workload list because run.sh discovers containers by their Docker
# labels. There is no runtime to discover here, so the two enrollments are written out explicitly,
# keeping the node and sensor from the shared file (same sensor token hash). The 64-hex container ids
# are what the feeds carry in facts.workload.container_id; the mock adapter seeds them as running.
REGISTRY="$RUN/registry-mock.json"
python3 - "$HERE/registry.json" "$REGISTRY" <<'EOF'
import json, sys
src, dst = sys.argv[1:]
reg = json.load(open(src))
reg["sensors"] = [dict(s, name="replay") for s in reg["sensors"]]  # same token, honest name
mk = lambda asset, prof, cid: {"asset_id": asset, "name": asset, "profile": prof, "kind": "ai_worker",
                               "container_id": cid, "generation": "mock-2026-10-22", "dedicated": True,
                               "active": True, "permitted_actions": ["PAUSE_CONTAINER"], "team": "platform"}
reg["workloads"] = [mk("coding-agent-01", "coding-agent", "a1" * 32), mk("devops-agent-01", "devops-agent", "d0" * 32)]
json.dump(reg, open(dst, "w"), indent=2)
EOF

# ---------------------------------------------------------------- API + console
export RIVER3_ENV=development
export RIVER3_DATABASE_URL="sqlite:///$RUN/river3.db"
export RIVER3_PRINCIPALS_FILE="$HERE/principals.json"
rm -f "$RUN/river3.db"
if [ ! -f "$ROOT/api/static/index.html" ]; then
  log "building the console (api/static is missing)"
  command -v npm >/dev/null || die "npm needed to build the console"
  ( cd "$ROOT/ui" && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npm run build ) >"$RUN/ui-build.log" 2>&1 || die "console build failed; see $RUN/ui-build.log"
fi
( cd "$ROOT/api" && .venv/bin/alembic upgrade head ) >"$RUN/alembic.log" 2>&1 || die "alembic failed; see $RUN/alembic.log"
start_bg api "$ROOT/api" .venv/bin/uvicorn river3_api.main:app --host 127.0.0.1 --port "$API_PORT"
wait_http "$API/api/health" 30 || die "API did not come up; see $RUN/api.log"

log "loading the two profiles"
for f in "$HERE"/profiles/*.json; do
  "$ROOT/api/.venv/bin/python" - "$f" "$API" "$OPERATOR_TOKEN" <<'EOF'
import json, sys, urllib.request
path, api, tok = sys.argv[1:]
prof = json.load(open(path))
body = json.dumps({"profile": prof, "base_version": 0, "comment": "loaded by demo/run-mock.sh"}).encode()
req = urllib.request.Request(f"{api}/api/v1/policies/{prof['name']}", data=body, method="PUT",
                             headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
with urllib.request.urlopen(req) as r:
    out = json.load(r)
print(f"  {out['name']} v{out['version']} {out['body']['mode']}")
EOF
done

# ---------------------------------------------------------------- controller (mock adapter)
log "building river3-containd"
( cd "$ROOT/containment" && go build -o "$BIN/river3-containd" ./cmd/river3-containd ) >"$RUN/build.log" 2>&1 \
  || die "containment does not build; see $RUN/build.log"
export RIVER3_CONTAINMENT_TOKEN="$CONTAINMENT_TOKEN" RIVER3_POLICY_TOKEN="$POLICY_TOKEN"
rm -f "$RUN/containd.journal" "$RUN/containd.journal.policy.json"
start_bg containd "$HERE" "$BIN/river3-containd" -adapter mock -mock-containers registry \
  -registry "$REGISTRY" -profiles "$HERE/profiles" -profiles-from-api -api "$API" \
  -journal "$RUN/containd.journal" -listen "127.0.0.1:$CTL_PORT" -profile-sync 5s
wait_http "$CTL/healthz" 30 || die "controller did not come up; see $RUN/containd.log"

# ---------------------------------------------------------------- gateway
export RIVER3_API="$API" RIVER3_GATEWAY_TOKEN="$GATEWAY_TOKEN" RIVER3_GATEWAY_SECRET="$GATEWAY_SECRET" GATEWAY_LISTEN="127.0.0.1:$GW_PORT"
start_bg gateway "$HERE" python3 "$ROOT/lab/gateway/gateway.py"
wait_http "$GW/healthz" 15 || die "gateway did not come up; see $RUN/gateway.log"

# ---------------------------------------------------------------- what the sensor would have done first
# river3d registers every enrollment at the API when it attaches; the replayer does the same with the
# sensor token so the workloads exist before the gateway binds a session or the controller reports.
log "registering the two workloads at the API (as the sensor)"
for w in coding-agent-01:coding-agent devops-agent-01:devops-agent; do
  curl -sSf -X POST -H "Authorization: Bearer $SENSOR_TOKEN" -H 'Content-Type: application/json' \
    --data-binary "{\"id\":\"${w%%:*}\",\"name\":\"${w%%:*}\",\"profile\":\"${w##*:}\",\"kind\":\"ai_worker\",\"sensor\":\"replay\",\"team\":\"platform\",\"labels\":{\"discovered\":\"replay\"}}" \
    "$API/api/v1/workloads" >/dev/null
done

cat <<EOF

  Console:    $API   (operator token: $OPERATOR_TOKEN)
  Gateway:    $GW/healthz        Controller: $CTL/healthz
  Journal:    tail -f $RUN/containd.journal
  Replay log: tail -f $RUN/replay.log
  Stop:       $HERE/stop.sh

EOF

# ---------------------------------------------------------------- the replay
# One thread per agent, both start together. Each feed line is {"t": seconds, "event": {facts, payload}}
# or {"t": seconds, "log": AgentLogEntryIn}. Events go where river3d sends them: the controller (which
# decides and may act) and the API (history + drift), with ts = now. Log lines go through the gateway
# like the real harness does, after binding a session for the run. DEMO_FAST shrinks every gap.
REPLAYER="$RUN/replay.py"
cat >"$REPLAYER" <<'EOF'
import json, os, sys, threading, time, urllib.error, urllib.request, uuid
from datetime import datetime, timezone
API, CTL, GW, SENSOR, OPERATOR = sys.argv[1:6]
FEEDS = sys.argv[6:]
SPEED = 0.15 if os.environ.get("DEMO_FAST", "") not in ("", "0", "false") else 1.0
PRINCIPAL = {"coding-agent-01": "coding-bot@dev", "devops-agent-01": "svc-deployer@staging"}
lock = threading.Lock()

def say(msg):
    with lock:
        sys.stdout.write(time.strftime("%H:%M:%S ") + msg + "\n"); sys.stdout.flush()

def post(url, body, token=None):
    hdr = {"Content-Type": "application/json"}
    if token:
        hdr["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}

def run_feed(path):
    records = [json.loads(l) for l in open(path) if l.strip()]
    wl = next(r["event"]["facts"]["workload"]["id"] for r in records if "event" in r)
    session = f"{wl}-run-{uuid.uuid4().hex[:8]}"
    code, out = post(f"{GW}/v1/sessions", {"session_id": session, "workload_id": wl, "principal": PRINCIPAL.get(wl, "agent@mock")})
    say(f"{wl}: session {session} bound through the gateway ({code})")
    start = time.monotonic(); seq = 0
    for r in records:
        time.sleep(max(0.0, start + r["t"] * SPEED - time.monotonic()))
        if "log" in r:
            seq += 1
            entry = dict(r["log"], id=f"{session}-{seq:04d}")
            code, out = post(f"{GW}/v1/log", {"workload_id": wl, "session_id": session, "entries": [entry]})
            e = r["log"]
            say(f"{wl}: log  [{e['kind']}{' ' + e['tool'] if e.get('tool') else ''}{' ' + e['status'] if e.get('status') else ''}] "
                f"{e.get('target') or ''} {e.get('text') or ''}".rstrip() + ("" if code == 201 else f"  (NOT accepted: {code} {out})"))
        else:
            f = r["event"]["facts"]; t = f["target"]
            what = t.get("path") or t.get("exe") or (f"{t.get('ip')}:{t.get('port')}" if t.get("ip") else "?")
            code, out = post(f"{CTL}/v1/events", r["event"], SENSOR)
            if code == 202:
                verdict = f"{out.get('status', '?')} {out.get('action', '')}".strip()
                if out.get("blockers"):
                    verdict += " (" + ",".join(out["blockers"]) + ")"
                if out.get("response_state"):
                    verdict += f" {out['response_state']}"
            else:
                verdict = f"http {code} {out}"
            api_ev = {"id": f["id"], "workload_id": wl, "kind": f["kind"], "outcome": f["outcome"],
                      "ts": datetime.now(timezone.utc).isoformat(), "facts": f, "payload": r["event"].get("payload", {})}
            acode, aout = post(f"{API}/api/v1/events", [api_ev], SENSOR)
            # 409 = the controller already stored this event with the incident it opened; river3d's
            # API sink counts the same answer as a duplicate, not a failure.
            if acode == 409:
                acode = 201
            tier = "?"
            try:
                req = urllib.request.Request(f"{API}/api/v1/drift/{wl}", headers={"Authorization": f"Bearer {OPERATOR}"})
                with urllib.request.urlopen(req, timeout=10) as rr:
                    st = json.load(rr).get("state") or {}
                    tier = st.get("tier", "?")
            except Exception:  # noqa: BLE001 - the drift read is decoration for the transcript
                pass
            say(f"{wl}: {f['kind']:<12} {f['outcome']:<8} {what:<34} -> {verdict:<42} tier: {tier}"
                + ("" if acode == 201 else f"  (API refused: {acode} {aout})"))
    say(f"{wl}: feed finished ({seq} log lines)")

threads = [threading.Thread(target=run_feed, args=(p,), daemon=True) for p in FEEDS]
for t in threads: t.start()
for t in threads: t.join()
EOF
if [ "$WAIT" = 0 ]; then
  start_bg replay "$HERE" python3 "$REPLAYER" "$API" "$CTL" "$GW" "$SENSOR_TOKEN" "$OPERATOR_TOKEN" "$HERE"/events/*.jsonl
  log "replaying in the background; $RUN/replay.log"; exit 0
fi
log "replaying both feeds ..."
python3 "$REPLAYER" "$API" "$CTL" "$GW" "$SENSOR_TOKEN" "$OPERATOR_TOKEN" "$HERE"/events/*.jsonl 2>&1 | tee "$RUN/replay.log" | sed 's/^/  /'
sleep 1 # let the controller report the last response

printf '\n  %-18s %-10s %s\n' workload mock tier
for w in coding-agent-01 devops-agent-01; do
  state="$(api GET "/api/v1/workloads" | "$ROOT/api/.venv/bin/python" -c 'import json,sys; w=sys.argv[1]; print(next((x["state"] for x in json.load(sys.stdin) if x["id"]==w), "?"))' "$w")"
  tier="$(api GET "/api/v1/drift/$w" | "$ROOT/api/.venv/bin/python" -c 'import json,sys; d=json.load(sys.stdin)["state"]; print(d["tier"] if d else "-")')"
  printf '  %-18s %-10s %s\n' "$w" "$state" "$tier"
done
echo
grep -E '"state":"(VERIFIED|FAILED|UNKNOWN|ABORTED)"' "$RUN/containd.journal" | sed 's/^/  journal: /' || true
echo
printf '\033[1;33m  SIMULATED: mock runtime, replayed events. For the real run use demo/run.sh\033[0m\n'
log "open $API and sign in with $OPERATOR_TOKEN"
