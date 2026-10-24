#!/usr/bin/env bash
# Restart river3-containd so it reloads profiles/ and registry.json (it reads them only at startup).
set -euo pipefail
docker restart river3-containd >/dev/null
for _ in $(seq 60); do
  docker exec river3-containd curl -sf http://127.0.0.1:8787/healthz >/dev/null 2>&1 && { docker logs river3-containd 2>&1 | grep '"startup"\|level":"ERROR' | tail -1; exit 0; }
  sleep 2
done
echo "controller did not come up; see: docker logs river3-containd" >&2; exit 1
