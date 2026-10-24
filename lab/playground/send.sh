#!/usr/bin/env bash
# Send sensor events to the local river3-containd: ./send.sh events/samples.jsonl
# Each line is one event; the controller evaluates it against the workload's profile.
# Posts from inside the river3-containd container: under Docker Desktop its port isn't reachable from the host.
set -euo pipefail
while IFS= read -r ev; do
  [ -z "$ev" ] && continue
  docker exec -i river3-containd curl -s -H "Authorization: Bearer dev-sensor-token" \
       -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8787/v1/events <<<"$ev"
  echo
done < "${1:?usage: send.sh events-file.jsonl}"
