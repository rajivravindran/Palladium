#!/usr/bin/env bash
# River3 live demo: two scripted agents in real containers, the eBPF sensor, the controller with the
# Docker adapter, the API + console, and the reference gateway -- all on one host, in development mode.
#
#   demo/run.sh            start everything, launch both agents, wait until both are frozen, print a summary
#   demo/run.sh --no-wait  start everything and return immediately
#   DEMO_FAST=1 demo/run.sh   agents run their script in ~10 s instead of ~60 s
#   demo/stop.sh           tear everything down (logs stay in demo/.run/)
#
# Needs: root (the eBPF sensor loads kernel programs), Docker on /var/run/docker.sock, the local image
# river3-lab-base:latest (lab/images/build_base_image.sh), Go, Node (only if api/static is missing) and
# the API venv at api/.venv. Nothing here touches a registry or the internet.
#
# Why --network host for the agent containers: the gateway binds to 127.0.0.1:8790 on the host, as a
# real tool gateway would sit next to the harness, not on the internet. Host networking is the one-line
# way for a container to reach a loopback-only service without publishing it. It also means the
# agents' own connects are visible to the kernel sensor as ordinary egress -- which is why both
# profiles allow 127.0.0.1/32 and nothing else (plus 10/8 for the DevOps agent).
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
IMAGE="${IMAGE:-river3-lab-base:latest}"
WAIT=1
[ "${1:-}" = "--no-wait" ] && WAIT=0

# Development tokens (demo/principals.json). Plain tokens are refused in production mode.
OPERATOR_TOKEN=dev-operator-token
SENSOR_TOKEN=dev-sensor-token
POLICY_TOKEN=dev-policy-token
CONTAINMENT_TOKEN=dev-containment-token
GATEWAY_TOKEN=dev-gateway-token
GATEWAY_SECRET=demo-gateway-secret-0123456789abcdef0123456789abcdef

log()  { printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[demo] %s\033[0m\n' "$*" >&2; exit 1; }
on_err() { printf '\033[1;31m[demo] failed at line %s; tearing down (logs in %s)\033[0m\n' "$1" "$RUN" >&2; "$HERE/stop.sh" --quiet || true; }
trap 'on_err $LINENO' ERR

wait_http() { # url seconds
  local i; for ((i = 0; i < $2 * 2; i++)); do curl -sf "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done
  return 1
}
start_bg() { # name cwd cmd...  (stdout+stderr -> $RUN/<name>.log; pid -> $RUN/pids)
  local name="$1" cwd="$2"; shift 2
  ( cd "$cwd" && exec "$@" ) >"$RUN/$name.log" 2>&1 &
  echo "$! $name" >>"$RUN/pids"
  log "started $name (pid $!)"
}
api() { # method path [json]   as the operator
  curl -sS -X "$1" -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
       ${3:+--data-binary "$3"} "$API$2"
}

# ---------------------------------------------------------------- preconditions
command -v docker >/dev/null || die "docker not found"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE missing: run lab/images/build_base_image.sh"
command -v go >/dev/null || die "go not found"
[ -x "$ROOT/api/.venv/bin/python" ] || die "api/.venv missing (see api/README.md)"
SUDO=""
if [ "$(id -u)" != 0 ]; then command -v sudo >/dev/null || die "the eBPF sensor needs root (or sudo)"; SUDO="sudo -E"; fi

"$HERE/stop.sh" --quiet
mkdir -p "$RUN" "$BIN"
: >"$RUN/pids"
log "run directory: $RUN"

# ---------------------------------------------------------------- what the agents see
# Files are prepared on the host and bind-mounted, so no `docker exec` runs inside the watched
# containers (an exec would itself be a kernel event the demo would then have to explain).
FS="$RUN/fs"; rm -rf "$FS"
for a in coding devops; do
  mkdir -p "$FS/$a/workspace" "$FS/$a/home/agent/.aws" "$FS/$a/home/agent/.ssh"
  printf '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' >"$FS/$a/home/agent/.aws/credentials"
  printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY-NOT-A-REAL-KEY\n-----END OPENSSH PRIVATE KEY-----\n' >"$FS/$a/home/agent/.ssh/id_rsa"
  chmod 0644 "$FS/$a/home/agent/.aws/credentials" "$FS/$a/home/agent/.ssh/id_rsa"
  chown -R 1000:1000 "$FS/$a/workspace"
done
cat >"$FS/coding/workspace/README.md" <<'EOF'
# calc
Tiny service. Run the tests with `python3 tests/test_app.py`. Deploy with `make release` (needs AWS).
EOF
printf 'def add(a, b):\n    return a - b  # bug: should be a + b\n' >"$FS/coding/workspace/app.py"
mkdir -p "$FS/coding/workspace/tests"
printf 'import sys; sys.path.insert(0, "..")\nfrom app import add\nassert add(2, 3) == 5\nprint("ok")\n' >"$FS/coding/workspace/tests/test_app.py"
chown -R 1000:1000 "$FS/coding/workspace"
mkdir -p "$FS/devops/etc-app" "$FS/devops/tmp-shared"
printf 'service: billing\nreplicas: 3\nrelease: 2.14\ndb_host: 10.20.0.5\n' >"$FS/devops/etc-app/config.yaml"
printf 'DB_PASSWORD=not-for-the-agent\n' >"$FS/devops/etc-app/secrets"
chmod 0644 "$FS/devops/etc-app/config.yaml"; chmod 0600 "$FS/devops/etc-app/secrets"; chown root:root "$FS/devops/etc-app/secrets"
chmod 1777 "$FS/devops/tmp-shared"

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
body = json.dumps({"profile": prof, "base_version": 0, "comment": "loaded by demo/run.sh"}).encode()
req = urllib.request.Request(f"{api}/api/v1/policies/{prof['name']}", data=body, method="PUT",
                             headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
with urllib.request.urlopen(req) as r:
    out = json.load(r)
print(f"  {out['name']} v{out['version']} {out['body']['mode']}")
EOF
done

# ---------------------------------------------------------------- controller (Docker adapter, discovery by labels)
log "building river3-containd and river3d"
( cd "$ROOT/containment" && go build -o "$BIN/river3-containd" ./cmd/river3-containd ) >"$RUN/build.log" 2>&1 \
  || die "containment does not build; see $RUN/build.log"
if ! ( cd "$ROOT/river3d" && go build -o "$BIN/river3d" . ) >>"$RUN/build.log" 2>&1; then
  [ -x "$ROOT/river3d/river3d" ] || die "river3d does not build and no prebuilt binary; see $RUN/build.log"
  log "river3d source did not build; using the prebuilt river3d/river3d"; cp "$ROOT/river3d/river3d" "$BIN/river3d"
fi

export RIVER3_CONTAINMENT_TOKEN="$CONTAINMENT_TOKEN" RIVER3_POLICY_TOKEN="$POLICY_TOKEN"
rm -f "$RUN/containd.journal" "$RUN/containd.journal.policy.json"
start_bg containd "$HERE" "$BIN/river3-containd" -adapter docker -registry-from-runtime -runtime docker \
  -registry "$HERE/registry.json" -profiles "$HERE/profiles" -profiles-from-api -api "$API" \
  -journal "$RUN/containd.journal" -listen "127.0.0.1:$CTL_PORT" -registry-refresh 2s -profile-sync 5s
wait_http "$CTL/healthz" 30 || die "controller did not come up; see $RUN/containd.log"

# ---------------------------------------------------------------- sensor (eBPF, discovery by labels)
export RIVER3_SENSOR_TOKEN="$SENSOR_TOKEN" RIVER3_INGEST_TOKEN="$SENSOR_TOKEN"
start_bg river3d "$HERE" $SUDO "$BIN/river3d" -source ebpf -enroll "" -enroll-from-labels -runtime docker \
  -refresh 2s -controller "$CTL" -api "$API"
for _ in $(seq 40); do grep -q "sensor attached" "$RUN/river3d.log" 2>/dev/null && break; sleep 0.5; done
grep -q "sensor attached" "$RUN/river3d.log" || die "sensor did not attach; see $RUN/river3d.log"

# ---------------------------------------------------------------- gateway
export RIVER3_API="$API" RIVER3_GATEWAY_TOKEN="$GATEWAY_TOKEN" RIVER3_GATEWAY_SECRET="$GATEWAY_SECRET" GATEWAY_LISTEN="127.0.0.1:$GW_PORT"
start_bg gateway "$HERE" python3 "$ROOT/lab/gateway/gateway.py"
wait_http "$GW/healthz" 15 || die "gateway did not come up; see $RUN/gateway.log"

# ---------------------------------------------------------------- the agents
# LC_ALL/PYTHONCOERCECLOCALE/TZ: the lab image has no locale or tz files; without these Python probes
# for them on every start and each ENOENT is a failed open the kernel sensor faithfully reports.
run_agent() { # name asset profile principal script extra-mounts...
  local name="$1" asset="$2" profile="$3" principal="$4" script="$5"; shift 5
  docker run -d --name "river3-demo-$name" --network host --user 1000:1000 \
    -e GATEWAY_URL="$GW" -e RIVER3_WORKLOAD_ID="$asset" -e RIVER3_PRINCIPAL="$principal" \
    -e DEMO_FAST="${DEMO_FAST:-}" -e DEMO_START_DELAY="${DEMO_START_DELAY:-6}" \
    -e LC_ALL=C -e PYTHONCOERCECLOCALE=0 -e TZ=UTC0 -e PYTHONUNBUFFERED=1 \
    -v "$HERE/agents:/agents:ro" -v "$FS/$name/workspace:/workspace" -v "$FS/$name/home/agent:/home/agent:ro" "$@" \
    --label river3.enroll=true --label "river3.asset_id=$asset" --label "river3.profile=$profile" \
    --label river3.kind=ai_worker --label river3.team=platform --label "river3.name=$asset" \
    "$IMAGE" python3 "/agents/$script" >/dev/null
  log "launched $asset ($(docker inspect -f '{{.Id}}' "river3-demo-$name" | cut -c1-12))"
}
run_agent coding coding-agent-01 coding-agent coding-bot@dev coding_agent.py
run_agent devops devops-agent-01 devops-agent svc-deployer@staging devops_agent.py \
  -v "$FS/devops/etc-app:/etc/app:ro" -v "$FS/devops/tmp-shared:/tmp/shared"

cat <<EOF

  Console:   $API   (operator token: $OPERATOR_TOKEN)
  Gateway:   $GW/healthz        Controller: $CTL/healthz
  Journal:   tail -f $RUN/containd.journal
  Agents:    docker logs -f river3-demo-coding    docker logs -f river3-demo-devops
  Stop:      $HERE/stop.sh

EOF

[ "$WAIT" = 1 ] || exit 0
log "waiting for both containers to be frozen (up to 180 s) ..."
deadline=$((SECONDS + 180))
while :; do
  c="$(docker inspect -f '{{.State.Status}}' river3-demo-coding 2>/dev/null || echo gone)"
  d="$(docker inspect -f '{{.State.Status}}' river3-demo-devops 2>/dev/null || echo gone)"
  if [ "$c" = paused ] && [ "$d" = paused ]; then break; fi
  if [ $SECONDS -ge $deadline ]; then log "timeout: coding=$c devops=$d (see $RUN/*.log)"; break; fi
  sleep 2
done
printf '\n  %-18s %-10s %s\n' workload docker tier
for w in coding-agent-01:coding devops-agent-01:devops; do
  tier="$(api GET "/api/v1/drift/${w%%:*}" | "$ROOT/api/.venv/bin/python" -c 'import json,sys; d=json.load(sys.stdin)["state"]; print(d["tier"] if d else "-")')"
  printf '  %-18s %-10s %s\n' "${w%%:*}" "$(docker inspect -f '{{.State.Status}}' "river3-demo-${w##*:}" 2>/dev/null || echo gone)" "$tier"
done
echo
grep -E '"state":"(VERIFIED|FAILED|UNKNOWN|ABORTED)"' "$RUN/containd.journal" | sed 's/^/  journal: /' || true
echo
log "open $API and sign in with $OPERATOR_TOKEN"
