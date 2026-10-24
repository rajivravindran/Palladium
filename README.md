# River3

Runtime scope enforcement for AI agents and business services.
**Every workload has a scope. River3 catches actions outside it, whoever is behind them.**

## Layout
| Folder | What | Status |
|---|---|---|
| `lab/images/` | Builds a small lab container image from host binaries | ✅ works |
| `river3d/` | eBPF sensor daemon (enrolled containers only) + Falco adapter for the Mac; sends to the containment controller and the API | ✅ 32 tests; eBPF path run live on Linux, Falco path with synthetic alerts |
| `api/` | FastAPI hub: workloads, events, incidents, operator actions, policy profiles, early-warning tiers, audit log, live stream, Qwen3 summaries, alert webhook, canary-credential endpoint | ✅ `pytest` green (run it; counts in docs go stale) |
| `policy/` | Go policy engine: decides IN_SCOPE / VIOLATION / REVIEW / UNKNOWN, gates response eligibility | ✅ `go test ./...`, shadow replay CLI |
| `containment/` | Go node controller: trusted normalizer, durable journal, verified pause via adapter, operator resume/terminate, signed webhook, policy sync from the API, Laya model guard | ✅ `go test ./...`; mock runtime only (see `containment/HANDOVER.md`) |
| `ui/` | Operator console (React/Vite): sign-in, incidents, detail + actions, workloads + drift, policies, audit, live stream | ✅ builds; `npm run build` → `api/static`; the Docker image builds it itself |
| `deploy/` | `docker compose` pilot stack: PostgreSQL, migration, API + console | ✅ compose file, `.env.example`, `principals.example.json` |
| `docs/` | [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) | ✅ |

## Run the API
```bash
cd api
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.lock   # exact versions; requirements.lock is the runtime subset the image uses
alembic upgrade head                   # schema (SQLite file in development; production refuses to start if not at head)
pytest -q tests
uvicorn river3_api.main:app --reload
```
Open http://127.0.0.1:8000/api/docs for the interactive API (development only).
Pilot stack with PostgreSQL: `deploy/docker-compose.yml` (read its header; copy `.env.example` and `principals.example.json` first).

## Settings (environment variables)
The authoritative list is the docstring of `api/river3_api/config.py`; this table mirrors it.

| Variable | Default | Meaning |
|---|---|---|
| `RIVER3_ENV` | `development` | `production` refuses dev principals, SQLite and plain-http webhooks, and requires the keys below |
| `RIVER3_DATABASE_URL` | `sqlite:///./river3.db` | `postgresql+psycopg://user:pass@host/db` for a pilot |
| `RIVER3_SECRET_KEY` | random per start | ≥ 32 chars, **required in production**; signs the console's stream tickets |
| `RIVER3_PRINCIPALS_FILE` | dev principals | JSON list of people and machines allowed to call the API — format in `api/principals.example.json`; **required in production** |
| `RIVER3_PRINCIPALS` | – | the same JSON inline (containers, tests) |
| `RIVER3_ROLES_FILE` / `RIVER3_ROLES` | built-in roles | optional JSON `{"role": ["permission", …]}` that redefines roles for this business — see `api/roles.example.json` |
| `RIVER3_ACTION_WEBHOOK` | – | URL where operator resume/terminate requests are POSTed for the containment controller, HMAC-signed; `https://` in production |
| `RIVER3_WEBHOOK_SECRET` | – | ≥ 32 chars; required when `RIVER3_ACTION_WEBHOOK` is set; shared with `river3-containd` and nothing else |
| `RIVER3_ALERT_WEBHOOK` | – | URL that receives new incidents at or above the threshold and early-warning tier rises (`{"text": …, "incident": {…}}`, Slack-compatible) |
| `RIVER3_ALERT_SECRET` | – | ≥ 32 chars; signs alerts. **Required in production when the alert webhook is set** and must differ from `RIVER3_WEBHOOK_SECRET`; development without it sends unsigned alerts and warns |
| `RIVER3_ALERT_MIN_SEVERITY` | `high` | `info` \| `high` \| `critical` |
| `RIVER3_CANARY_SECRET` | – | ≥ 32 chars; lets a canary-credential service call `POST /api/v1/canary` with an HMAC instead of a bearer token |
| `RIVER3_REVOKE_WEBHOOK` | – | URL that receives operator **revoke** requests (gateway / identity provider / cloud-role revoker), HMAC-signed with `RIVER3_REVOKE_SECRET`; `https://` in production. Unset: the request is recorded, stays `requested` and a `revoker` picks it up from `GET /api/v1/actions?action=revoke` |
| `RIVER3_REVOKE_SECRET` | – | ≥ 32 chars; required when `RIVER3_REVOKE_WEBHOOK` is set; must differ from `RIVER3_WEBHOOK_SECRET` and `RIVER3_ALERT_SECRET` (the revoker must not be able to forge containment actions or alerts) |
| `RIVER3_SESSION_WINDOW_S` | `30` | an event with no `facts.session` is attributed to the latest agent-log `tool_call` for the same workload within this many seconds, stamped `facts.session.source: "correlated"` (advisory: it never binds `incidents.session_id`); `0` disables |
| `RIVER3_APPROVAL_TTL_S` | `120` | how long a held approval (`POST /api/v1/approvals` → `hold`) waits for an operator; past it the gateway's poll reads `expired`, which it must treat as deny |
| `RIVER3_LLM_BASE_URL` | `http://localhost:11434/v1` | OpenAI-compatible endpoint for summaries, and for the drift question when `RIVER3_DRIFT_MODEL=llm` (Ollama / MLX). Production: `https://` or loopback only |
| `RIVER3_LLM_ALLOW_PLAIN_HTTP` | `false` | `true` permits plain `http://` to a non-loopback model host in production (docker `host.docker.internal`); logged as a warning |
| `RIVER3_LLM_MODEL` | `qwen3:8b` | summary model |
| `RIVER3_LLM_TIMEOUT` | `60` | seconds |
| `RIVER3_DRIFT_MODEL` | `off` | `off` \| `laya` \| `jev` \| `llm`: who answers the typed drift question; see below |
| `RIVER3_LAYA_URL` / `RIVER3_LAYA_TOKEN` | `http://127.0.0.1:8600` / – | local Laya (`laya-serve`, `/v1/systemone`); `https://` or plain `http://` to loopback only; the token is `LAYA_API_KEY` when set |
| `RIVER3_JEV_URL` / `RIVER3_JEV_TOKEN` / `RIVER3_JEV_OPT_IN` / `RIVER3_JEV_MODEL` | – / – / `false` / – | hosted Jev, same protocol; `https://` and `RIVER3_JEV_OPT_IN=true` are required because agent logs leave the host |
| `RIVER3_DRIFT_MIN_CONFIDENCE` | `0.6` | in `(0, 1]`; a Laya/Jev answer below it is *unknown* (the protocol has no abstain option) |
| `RIVER3_DRIFT_MAX_LEN` | `512` | the protocol's `max_len` (512 English, 1024 multilingual, up to 8192) |
| `RIVER3_DRIFT_MODEL_TIMEOUT`, `RIVER3_DRIFT_*` | `8`, … | seconds per model call; early-warning thresholds, see below |
| `RIVER3_MAX_BODY_BYTES` | `1048576` | request body limit |
| `RIVER3_HSTS` | `false` | `true` when served over HTTPS |
| `RIVER3_TRUSTED_PROXY` | `false` | `true` only behind a reverse proxy that sets `X-Forwarded-For` |
| `RIVER3_AUTH_FAIL_LIMIT` / `RIVER3_AUTH_FAIL_WINDOW` | `20` / `300` | failed sign-ins per client IP per window before 429 |

Principals: `{"name", "kind": "operator"|"machine", "role", "token_sha256", "teams"?: [..]}` — tokens are stored only as SHA-256 (`python -m river3_api.cli new-token`). `teams` is for operators only: a non-empty list limits what they see and act on to workloads in those teams (`admin` bypasses; machines are never scoped). `python -m river3_api.cli check-config` validates all of it.

| Role | Kind | Permissions |
|---|---|---|
| `viewer` | operator | `read` |
| `responder` | operator | `read`, `act`, `summarize` |
| `admin` | operator | `read`, `act`, `summarize`, `audit`, `policies` |
| `sensor` | machine | `workloads.write`, `events.write`, `agentlog.write` |
| `policy` | machine | `workloads.write`, `events.write`, `incidents.write`, `profiles.read`, `profiles.status`, `agentlog.write` |
| `agentlog` | machine | `agentlog.write` |
| `containment` | machine | `response.write`, `actions.read`, `actions.write`, `sessions.read` |
| `gateway` | machine | `sessions.write`, `sessions.read`, `agentlog.write`, `tools.check` |

`GET /api/v1/audit` and `/api/v1/audit/verify` are tenant-wide and not team-scoped: anyone holding `audit` (admins, or a dedicated auditor role you define) sees every principal's actions, because the audit log is the record of the whole tenant and its hash chain only verifies as a whole.

Webhooks (action, alert, inbound canary) are all signed the same way: `X-River3-Signature: sha256=HMAC-SHA256(secret, "<ts>.<delivery>.<body>")` with `X-River3-Timestamp` (±300 s) and `X-River3-Delivery` (unique per attempt; receivers refuse an id they have already accepted). The three use three different secrets.

⚠️ Change every token before any pilot. The development tokens are refused in production.

## Policies
A policy (profile) says what one kind of workload may do (files it may read or write, kinds of programs it may start, IP ranges it may reach, decoy files it must never touch) and what River3 does when it steps outside that: alert, pause the container, or revoke the session, in **shadow** (record only) or **active** mode.

- **Edit them in the console** (Policies tab; needs the `policies` permission, which `admin` has). Every save needs a reason, creates a new version, and is written to the audit log; old versions can be viewed and loaded back. The API checks each profile with the same rules as the policy engine (`api/river3_api/profiles.py` mirrors `policy/profile.go`).
- **Enforce them** by starting the controller with `-profiles-from-api` (and `RIVER3_POLICY_TOKEN`, role `policy`). It fetches the set every `-profile-sync` (10 s), checks it with the engine, and swaps it in only if every profile compiles and every enrolled workload still has its profile; otherwise it keeps the last good set and the console shows why. An action decided under the old set is aborted if the set changes before it runs. The last applied set is cached next to the journal, so a restart while the API is down still enforces it.
- Without `-profiles-from-api` the controller reads `-profiles` (a directory of JSON files) at startup, as before.

## Early warning (drift tiers)
Containment acts when a workload crosses its scope. The early warning tells the owning team that an agent is **heading** there, with evidence, before it does. Each AI worker carries a tier: **Steady → Rising → High → Crossed** (Workloads tab; click a row for the reasons, the trend and the agent's own log).

- **Kernel facts decide.** Trend features (failed or refused attempts, resources never touched before, writes outside the profile's `write_allowed`) are computed in plain code from the events the sensor already posts to `/api/v1/events`. Thresholds are `RIVER3_DRIFT_*` settings (`WINDOW_MIN`, `FAILS_RISING`, `FAILS_HIGH`, `NEW_RESOURCES_RISING`, `SHARED_WRITES_RISING`, `SHARED_WRITES_HIGH`, `UNLOGGED_MIN_EVENTS`, `BASELINE_MIN_EVENTS`); defaults are starting points for design partners.
- **The agent's own log only raises a tier, never lowers one.** Ship tool calls, plans and reasoning to `POST /api/v1/agents/{workload_id}/log` (permission `agentlog.write`; roles `sensor`, `policy` and `agentlog`) from a tool gateway or LLM proxy the agent cannot write to. Entries are stored apart from kernel facts and parsed by code first: text addressed to the monitor ("ignore previous instructions", "Laya", "summariser"…) is itself evidence, as is kernel activity missing from the log (the wallet-incident shape), repeated failing calls, and reasoning about getting around a restriction. A tier never freezes anything; **Crossed** comes only from a kernel-confirmed violation that is already an incident.
- **Optional model question.** `RIVER3_DRIFT_MODEL` picks who answers a typed question over small chunks of structured log lines (`kind|tool|status|text`, ≤ 1200 chars, one call per chunk):
  - `laya` — [Laya](https://github.com/convaiinnovations/laya) (Apache-2.0), a 421M non-autoregressive **decision** model: it never generates text. Per chunk the API POSTs `/v1/systemone` with `state` = the chunk and two typed questions: a *choice* `agent_mode` (`on_task` / `exploring` / `working_around_limit`) and a *noul* `addressed_to_monitor`. A choice counts only when its confidence is ≥ `RIVER3_DRIFT_MIN_CONFIDENCE` (default 0.6), otherwise it is *unknown*; `working_around_limit` raises to Rising, and a noul p(yes) ≥ the threshold adds the raise-only reason *model: text addressed to the monitor*. Run it beside the API with `pip install "laya[serve]"` then `LAYA_PORT=8600 LAYA_PRELOAD=1 LAYA_API_KEY=<key> laya-serve` (its default port 8000 is this API's; set `RIVER3_LAYA_URL=http://127.0.0.1:8600` and `RIVER3_LAYA_TOKEN=<key>`). `python lab/models/laya_smoke.py --url http://127.0.0.1:8600 --token <key>` checks `/health` and six fixed chunks. **The base checkpoint is near chance zero-shot and over-confident** (model card): fine-tune on your own sessions and keep the threshold conservative; the recorded `model` field (e.g. `laya:english`) says which checkpoint and route answered.
  - `jev` — TypeSafe Jev, hosted, same protocol: `RIVER3_JEV_URL` (https only) plus `RIVER3_JEV_OPT_IN=true`, because agent logs leave the host.
  - `llm` — the chat path for Qwen-style models on `RIVER3_LLM_BASE_URL`: the same question as a JSON-only prompt, prose discarded, the chunk id echoed back or the answer is unknown.
  - Whatever the model: a timeout, a refused token, a malformed answer, low confidence or chunks disagreeing is *unknown*, never steady, with the reason recorded; the model can only ever raise a tier. The question runs off the request path: ingest uses the last answer for the same log window and queues a new one when the window changed; only the operator's manual recompute waits for the model.
- **Alerts.** A rise to Rising or High posts to `RIVER3_ALERT_WEBHOOK` (`type: drift.tier_changed`) and the live stream; the stats bar counts workloads heading out of scope. Webhooks are rate-limited per workload (`RIVER3_DRIFT_ALERT_COOLDOWN`, default 600 s: inside it only a higher tier is sent); the stream gets every change.
- **Measure it, don't guess.** `python -m river3_api.replay "lab/drift/sessions/*.json" --report report.md` replays recorded sessions and reports lead time before the violation, false alarms per agent-hour and whether injection text ever lowered a tier. `lab/drift/make_sessions.py` builds the fixture sessions; `lab/drift/feed.py` plays one into a running API.

## Runtimes
`river3-containd -adapter mock | podman | openshell`. The **NVIDIA OpenShell** adapter drives sandboxes through the `openshell` CLI: pause = `sandbox stop` (compute stops, workspace and record stay), resume = `sandbox start`, terminate = `sandbox delete`; state comes from `sandbox list`, never from an exit code. It needs `-openshell-sandboxes`, a JSON map from the registry's 64-hex container id to `{sandbox, generation}` (see `containment/fixtures/openshell-sandboxes.json`). Not yet exercised against a real gateway; the CLI shapes follow the public docs.

## How the layers talk
```
river3d (sensor) ──/v1/events (sensor token)──► river3-containd (controller) ──PATCH /incidents/{id}/response──► API ◄── console
     └──POST /api/v1/events, /agents/{id}/log (sensor role token)──────────────────────────────────────────────►  │
                              GET /policy/bundle · POST /policy/sync (policy role, -profiles-from-api) ──────────►  │
                                                        ▲ GET /actions · signed webhook /river3/actions · POST /actions/{id}/result
```
- **Sensor** (`river3d`) → `river3-containd /v1/events`, and optionally `POST /api/v1/workloads`, `/api/v1/events` for history. Every machine holds a named principal with a role; there is no shared ingest token.
- **Controller** (`river3-containd`, policy engine inside) → `POST /api/v1/incidents` (policy role), `PATCH /api/v1/incidents/{id}/response` after it has acted *and inspected the runtime*; picks up operator requests from `GET /api/v1/actions` or the signed webhook and answers with `POST /api/v1/actions/{id}/result`. With `-profiles-from-api` it also fetches `GET /api/v1/policy/bundle` and reports `POST /api/v1/policy/sync`.
- **Canary service** → `POST /api/v1/canary` when a seeded decoy credential is used anywhere.
- **Console** → operator endpoints (`/api/v1/incidents`, `/actions`, `/summary`, `/policies`, `/drift`, `/audit`, `/stream`). One operator action may be pending per incident, and none on a resolved or false-positive one.
- **Tool gateway / agent harness** (role `gateway`, [docs/CONTRACTS.md](docs/CONTRACTS.md) §1–3) → `POST /api/v1/sessions` and `PATCH /api/v1/sessions/{id}` bind an agent run to a workload; `POST /api/v1/tools/check` before a risky tool (`allow` / `hold` / `deny`), then polls `GET /api/v1/approvals/{id}` while an operator decides (`POST /api/v1/approvals/{id}/decide`, `GET /api/v1/approvals?status=pending`). Admins set the gate per workload with `PUT /api/v1/workloads/{id}/gate`. Revoking a session is an operator action (`revoke_session`) or an automatic `REVOKE_SESSION` response; the API marks the session revoked only after the controller verified it. `GET /api/v1/workloads/{id}/export?since=&until=` writes one workload's events, agent log and incidents in the replay format for the real-session benchmark.
- **Approval gate and session governance** (22 Oct contract, role `gateway` = Stage B permissions + `approvals.request`) → `POST /api/v1/approvals` `{workload_id, session_id, tool, tool_call_id, risk: normal|risky, summary}` answers `allow` / `hold` / `deny` from the workload's current drift tier (below High: allow; High and risky: hold for an operator, `ttl_s` from `RIVER3_APPROVAL_TTL_S`; Crossed: deny; a revoked session or a frozen workload is always denied). Every answer is an approval row and an audit row (`approval.request`, `approval.decide`, `approval.expire`); holds also go to the alert webhook as `approval.held`. The gateway polls `GET /api/v1/approvals/{id}` and must treat `expired` as deny (fail closed: expiry is persisted lazily on read). Operators: `GET /api/v1/approvals?status=pending`, `POST /api/v1/approvals/{id}/decide` `{decision: allow|deny, reason ≥ 8}`. The agent's `summary` is untrusted and is shown as such. Agent-log entries take `tool_call_id`; events may carry `facts.session {id, tool_call_id, source}`; `GET /api/v1/sessions/{id}` returns everything known about a session id across workloads (events, log entries, incidents, approvals; paged). Operator action `revoke` (`POST /api/v1/incidents/{id}/actions`, both workload kinds, 409 without a known session) is delivered to `RIVER3_REVOKE_WEBHOOK` and answered by a `revoker` through `POST /api/v1/actions/{id}/result`; `completed` sets `response.session_revoked` and leaves the incident status alone.

The API never freezes, resumes or terminates anything itself. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Models
Two local models, both advisory:
- **Summaries** (`api/river3_api/summary.py`): Qwen3-8B sees **Channel A facts only**; every cited event id is checked and the summary is marked not grounded if any was invented; a deterministic fallback is used when the model is offline.
- **Laya, the model guard** (`containment/guard`): two separate calls per event — structural facts, then untrusted payload — returning an enum. `Verified` is set by the adapter after schema and event-id checks, never by the model. Channel B alone can never contain; a Channel A containment request only matters if the profile opts in (`response.on_structural_guard`). `river3-containd -guard laya`.

`ollama pull qwen3:8b && ollama serve` on the Mac serves both.
