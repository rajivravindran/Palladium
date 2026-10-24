#!/usr/bin/env bash
# Tears the demo down: the two agent containers, then every process run.sh started (API, controller,
# sensor, gateway). Logs, the journal and the sqlite db stay in demo/.run/ for evidence.
#
#   demo/stop.sh            stop everything, keep demo/.run/
#   demo/stop.sh --purge    also delete demo/.run/
#   demo/stop.sh --quiet    no output (used by run.sh before a fresh start)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$HERE/.run"
QUIET=0; PURGE=0
for a in "$@"; do case "$a" in --quiet) QUIET=1 ;; --purge) PURGE=1 ;; *) echo "usage: stop.sh [--quiet] [--purge]" >&2; exit 2 ;; esac; done
log() { [ "$QUIET" = 1 ] || printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }

# Agent containers (paused containers must be unpaused before they can be removed).
for c in $(docker ps -aq --filter name='^river3-demo-' 2>/dev/null); do
  docker unpause "$c" >/dev/null 2>&1 || true
  docker rm -f "$c" >/dev/null 2>&1 || true
done
log "agent containers removed"

# Processes started by run.sh, newest first (sensor before controller, controller before API).
if [ -f "$RUN/pids" ]; then
  tac "$RUN/pids" | while read -r pid name; do
    [ -n "${pid:-}" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || sudo kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
      kill -0 "$pid" 2>/dev/null && { kill -KILL "$pid" 2>/dev/null || sudo kill -KILL "$pid" 2>/dev/null || true; }
      log "stopped $name ($pid)"
    fi
  done
  rm -f "$RUN/pids"
fi
# A sensor started through sudo leaves a child the pid file does not know about.
pkill -TERM -f "river3d -source ebpf -enroll" 2>/dev/null || true

# Anything still holding the demo ports (e.g. from a run whose pid file was lost).
listeners() { # port -> pids
  if command -v fuser >/dev/null; then fuser -n tcp "$1" 2>/dev/null | tr -s ' ' '\n'
  elif command -v lsof >/dev/null; then lsof -t -iTCP:"$1" -sTCP:LISTEN 2>/dev/null
  elif command -v ss >/dev/null; then ss -ltnpH "sport = :$1" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2
  fi | sort -u
}
for port in "${API_PORT:-8000}" "${CTL_PORT:-8787}" "${GW_PORT:-8790}"; do
  for pid in $(listeners "$port"); do
    [ -n "$pid" ] || continue
    kill -TERM "$pid" 2>/dev/null || true
    log "freed port $port (pid $pid)"
  done
done

if [ "$PURGE" = 1 ]; then rm -rf "$RUN"; log "removed $RUN"; fi
log "done"
