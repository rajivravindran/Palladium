#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p workspace evidence
cp notes.md workspace/notes.md
if [[ ! -x integration/bin/river3d || ! -x integration/bin/river3-containd ]]; then
  ./prepare-integration.sh
fi
docker compose up -d --build --wait api model agent
ready=0
for ((i=0; i<30; i++)); do
  if docker compose exec -T model ollama list >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'Ollama did not become ready' >&2; exit 1; }
if ! docker compose exec -T model ollama show "${MODEL:-qwen2.5-coder:1.5b}" >/dev/null 2>&1; then
  docker compose exec -T model ollama pull "${MODEL:-qwen2.5-coder:1.5b}"
fi
python3 river3ctl.py init
docker compose up -d controller sensor
python3 river3ctl.py ready
echo 'Console: http://127.0.0.1:8001 (dev-operator-token). Run ./run-task.sh to start the coding task.'
