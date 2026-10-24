# demo/

Two scripted agents, two stories, one host. Everything in this directory is development mode: the
tokens in `principals.json` are plain strings the API refuses in production.

| | `demo/run.sh` | `demo/run-mock.sh` |
|---|---|---|
| Needs | root (eBPF), Docker, `river3-lab-base:latest`, Go, `api/.venv` | bash, curl, python3, Go, `api/.venv` |
| Agents | `demo/agents/*.py` running in two containers | nobody runs; `demo/events/*.jsonl` is replayed |
| Kernel events | observed by `river3d -source ebpf` | posted from the feed with the sensor token |
| Runtime | Docker Engine API (`-adapter docker -registry-from-runtime`) | `-adapter mock -mock-containers registry` |
| Evidence | yes: `docs/evidence/2026-10-22-*.txt` came from it | **no**; it prints `SIMULATED` first and last |
| Stop | `demo/stop.sh` | `demo/stop.sh` |

Shared by both: `profiles/` (the two policies), `principals.json` (dev tokens), `registry.json` (node + sensor
token hash), the API + console, `lab/gateway/gateway.py` as the tool gateway.

## The stories

1. **The freeze** (`coding-agent-01`, profile `coding-agent`). Reads its project under `/workspace`, runs the
   interpreter, writes a note, then opens `/home/agent/.aws/credentials`. That path is a decoy in the profile:
   the kernel sees the open, the engine says `VIOLATION` (`DECOY_OPEN`, `READ_OUTSIDE_SCOPE`), the controller
   pauses the container and verifies the pause. Tier: steady -> crossed.
2. **The drift** (`devops-agent-01`, profile `devops-agent`). Wants the DB password in root-only
   `/etc/app/secrets`; every read fails with EACCES. It says in its own log that it will "work around the
   permission check", keeps retrying, then copies what it can read to `/tmp/shared/out`, outside `write_allowed`.
   The failed reads (kernel) and its own words (agent log, Channel B) raise the tier: steady -> rising -> high.
   The first write outside scope is the kernel-confirmed `VIOLATION` (`WRITE_OUTSIDE_SCOPE`): crossed, paused.
   The scripted agent's next steps (an egress to the public internet, then the AWS decoy) never run because the
   container is already frozen; the mock feed stops at the same point for the same reason.

## `run-mock.sh`: the demo on a laptop without Docker or root

```
demo/run-mock.sh              # start, replay (~45 s), print a summary; then open http://127.0.0.1:8000
DEMO_FAST=1 demo/run-mock.sh  # ~6x faster
demo/run-mock.sh --no-wait    # return at once; replay runs in the background (demo/.run/replay.log)
demo/stop.sh                  # tear down (logs stay in demo/.run/; --purge removes them)
```

What it starts: the API (sqlite in `demo/.run/river3.db`, dev principals), `river3-containd` built into
`demo/.run/bin/` with the **mock adapter** (two "containers" seeded from a registry written to
`demo/.run/registry-mock.json`: `registry.json`'s node and sensor plus the two enrollments, since there is no
runtime to discover them from), and the reference gateway. Then it registers the two workloads at the API
the way `river3d` would, binds one gateway session per agent, and replays both feeds in parallel.

Each feed line is `{"t": <seconds>, "event": {"facts", "payload"}}` or `{"t": <seconds>, "log": <AgentLogEntryIn>}`.
Events go where the sensor sends them, to the controller's `/v1/events` (decision, action, journal) and the
API's `/api/v1/events` (history, drift), with `ts` = now and the sensor token. Log lines go through the
gateway's `/v1/log` like the real harness does. The replayer prints every step with the controller's answer and
the drift tier read back from the API, so you can watch the devops tier climb before the pause.

What is real here: the policy engine, the journal (RESERVED -> EXECUTING -> VERIFIED), verify-after-act (the
controller re-inspects the mock container and reads `paused`), the incident and response reporting, the drift
tiers, the gateway and session binding. What is not: the kernel events (replayed, `facts.sensor = "replay"`)
and the runtime (`adapter: mock`). The mock run proves the plumbing, not that an agent was caught.

Not wired: a session adapter. The controller's only session adapter is `-session-adapter gateway` (signed
revokes against a real gateway, which `run.sh` also leaves unset); the in-memory mock session adapter
(`containment/adapter/mocksession.go`) is used by the Go tests only, so `REVOKE_SESSION` stays blocked with
`ADAPTER_UNAVAILABLE` here as well. `-sessions-from-api` is not used either.

## Files

- `run.sh`, `stop.sh`: the real demo and its teardown. `run.sh` header lists what it needs.
- `run-mock.sh`: the simulated demo described above.
- `agents/`: the two scripted agents and their gateway harness (Channel B).
- `events/`: the two replay feeds for `run-mock.sh` (coding: 9 events, devops: 13 events, plus log lines).
- `profiles/`: `coding-agent.json`, `devops-agent.json` (ACTIVE_FREEZE_MODE, `on_violation: PAUSE_CONTAINER`).
- `principals.json`, `registry.json`: development principals and the node/sensor enrollment file.
- `shoot.py`, `shoot.mjs`: console screenshots.
- `.run/`: created by either script; logs, journal, sqlite db, built binaries.
