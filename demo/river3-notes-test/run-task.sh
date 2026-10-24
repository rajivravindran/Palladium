#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
cp notes.md workspace/notes.md
docker compose exec -T agent python3 /agents/agent.py "$@"
