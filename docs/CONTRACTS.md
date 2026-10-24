# Cross-component contracts (Stage B, 21 Oct 2026)

Every builder reads this before touching code. Names are exact. Code name in the repo stays `river3`.

## 0. Principles (unchanged)
- Channel A (kernel facts) decides. Channel B (agent text, model output, gateway claims) can only raise suspicion.
- Nothing a model says can act. A drift tier alone never freezes. Deterministic engine first, models after.
- The single exception: a profile that explicitly opts in with `response.on_structural_guard: PAUSE_CONTAINER` lets a verified Channel A model verdict lead to a container pause of a dedicated AI worker; it never revokes a session (`REVOKE_SESSION` is rejected there by the engine and the API).
- Every action is verified after it is taken, journaled before and after, and attributable to a principal.
- Strict JSON everywhere: unknown fields are rejected on machine-to-machine input.

## 1. Sessions (who was acting)

A **session** is one agent run as the gateway/harness identifies it. The gateway binds it to a workload (container).

### 1.1 API storage
Table `sessions`: `id` (Ident, PK; the gateway's session id), `workload_id` (FK), `principal` (string ≤128: the agent identity, e.g. `svc-deployer@prod`), `state` ∈ `active|ended|revoked`, `started_at`, `ended_at`, `revoked_at`, `revoked_by`, `revoke_reason`, `labels` JSON (≤32 keys), `last_seen_at`.

### 1.2 API endpoints
| Method/path | Permission | Body / result |
|---|---|---|
| `POST /api/v1/sessions` | `sessions.write` | `{session_id, workload_id, principal, started_at?, labels?}` → 201 session; upsert; a revoked session cannot be reactivated (409) |
| `PATCH /api/v1/sessions/{id}` | `sessions.write` | `{state:"ended"}` or `{last_seen_at}` → session |
| `GET /api/v1/sessions?workload_id=&state=` | `read` (people) or `sessions.read` (machines) | list |
| `GET /api/v1/sessions/{id}` | same | session + incident ids |

New permissions: `sessions.write`, `sessions.read`, `tools.check` (machine). New built-in machine role **`gateway`** = `sessions.write, sessions.read, agentlog.write, tools.check`. The `containment` role gains `sessions.read`.

### 1.3 Session on events and logs
- `EventIn` gains optional top-level `session_id` (Ident). Stored on `events.session_id`.
- `AgentLogEntryIn` already has `session` (string); keep it, treat it as the session id.
- `Incident` gains `session_id`: set on create from the first embedded/attached event that has one, or from the policy decision's identity `session_id`. Serialized on every incident.

### 1.4 Controller knows the session
- `river3-containd -sessions-from-api` polls `GET /api/v1/sessions?state=active` every `-session-sync` (5 s) using the containment token (`sessions.read`) and keeps `workload_id → session_id` (the newest active). The normalizer stamps `Identity.SessionID` from it, which clears the engine's `NO_BOUND_SESSION` blocker.
- No session known → behaviour exactly as today.

## 2. Revoke (the response for shared services and agents)

### 2.1 Session adapter (controller → customer gateway), adapter name `gateway`
Flags: `-session-adapter gateway -gateway-url https://... ` env `RIVER3_GATEWAY_SECRET` (≥32).
Requests are signed exactly like webhooks: headers `X-River3-Timestamp`, `X-River3-Delivery`, `X-River3-Signature: sha256=hex(HMAC-SHA256(secret, "<ts>.<delivery>.<body>"))`.

| Call | Body → reply |
|---|---|
| `POST {gateway}/v1/sessions/{id}/revoke` | `{"reason": str, "incident_id": str, "idempotency_key": str}` → 200/202 `{"state": "revoked"|"active"|"unknown"}` |
| `GET {gateway}/v1/sessions/{id}` | → 200 `{"state": "active"|"revoked"|"ended"|"unknown", "principal": str, "started_at": rfc3339}`; 404 = unknown |

Verify-after-act: the controller GETs after the POST and journals VERIFIED only if `state == "revoked"`; `unknown` → UNKNOWN; `active` → FAILED. `Actions()` advertises `REVOKE_SESSION`. Everything else (Reserve → Revalidate → journal → outbox) is unchanged.

### 2.2 Operator-initiated revoke
`POST /api/v1/incidents/{id}/actions` accepts `action: "revoke_session"` (409 if the incident has no `session_id`). Delivered to the controller like resume/terminate; the controller runs the session adapter; result `completed` marks the API session `revoked` with `revoked_by` = the operator.

### 2.3 Automatic revoke
Engine candidate `REVOKE_SESSION` (profile `response.on_violation`) → controller `act()` → session adapter → `PATCH /incidents/{id}/response` with `response.action = "REVOKE_SESSION"`, `response.state = verified|failed|unknown`, `response.session_id`. The API marks the session `revoked` on `verified`.

## 3. Approval gate (tier High holds risky tools)

### 3.1 Gate config (API, per workload, outside the engine profile)
`PUT /api/v1/workloads/{id}/gate` (permission `policies`): `{"risky_tools": ["shell", "kubectl", "terraform", ...] (≤64, each ≤64 chars, glob `*` allowed), "hold_at": "high"|"rising"|"never", "ttl_s": 600}`; `GET` returns it. Default: no gate.

### 3.2 Check (gateway → API), before the gateway runs a tool
`POST /api/v1/tools/check` (permission `tools.check`): `{workload_id, session_id, tool, args_summary?(≤512)}` →
`{"decision": "allow"|"hold"|"deny", "approval_id": str|null, "tier": str, "reason": str}`.
- `deny` when the session is `revoked` or the workload is `frozen|terminated`.
- `hold` when the drift tier ≥ `hold_at` and `tool` matches `risky_tools`; creates an **approval** (`pending`).
- otherwise `allow`.
Audit row `tool.check` only for hold/deny.

### 3.3 Approvals
Table `approvals`: `id`, `workload_id`, `session_id`, `tool`, `args_summary`, `tier`, `status` ∈ `pending|approved|denied|expired`, `requested_at`, `expires_at`, `decided_by`, `decided_at`, `reason`.
| Method/path | Permission | |
|---|---|---|
| `GET /api/v1/approvals?status=pending` | `read` | list (newest first) |
| `GET /api/v1/approvals/{id}` | `read` or `tools.check` | the gateway polls this until status ≠ pending |
| `POST /api/v1/approvals/{id}/decide` | `act` | `{"decision": "approve"|"deny", "reason" ≥ 8}` → approval; audit `approval.approve|deny`; bus `approval` |
Expiry: a pending approval past `expires_at` reads as `expired` (treated as deny by the gateway). Stats gain `pending_approvals`.

## 4. Runtime discovery (no more static enrol files)

### 4.1 Labels (Docker and Podman)
A container opts in with labels:
`river3.enroll=true`, `river3.asset_id=<Ident>`, `river3.profile=<name>`, `river3.kind=ai_worker|shared_service`, optional `river3.name`, `river3.dedicated=true|false` (default true for ai_worker), `river3.actions=PAUSE_CONTAINER,REVOKE_SESSION` (default: `PAUSE_CONTAINER` for dedicated ai_worker, none otherwise), `river3.team=<string>`.

### 4.2 Controller
- `-adapter docker` (Engine API over `/var/run/docker.sock`, `-docker-socket`): `GET /containers/{id}/json` (generation = `State.StartedAt`), `POST .../pause`, `.../unpause`, `.../stop?t=10`. Same verify rules as podman.
- `-registry-from-runtime` (+ `-registry-refresh`, default 10 s): workloads are built from labelled containers and swapped in atomically with `Holder.Set`; sensors still come from `-registry`. A container that disappears is removed; a restart (new StartedAt) is a new generation. Both podman and docker runtimes.

### 4.3 Sensor
- `-enroll-from-labels` with `-runtime podman|docker` (+ socket flag): enrolments are discovered every `-refresh` from labelled containers; `-enroll` file optional and merged. Registration to the API includes `team` from the label.

## 5. Domain-based egress
- Profile JSON gains `egress_allowed_domains: []string` (≤128, valid hostnames or `*.example.com`). The engine accepts and validates the field but **matches only IPs** (documented).
- The controller resolves the domains (A/AAAA) when it compiles a profile set and again every `-egress-refresh` (60 s), appends the resulting `/32` and `/128` CIDRs to `egress_allowed`, and swaps the engine atomically (same path as policy sync). Wildcards are resolved for the apex only and documented as "forward resolution: an IP the name resolved to in the last refresh".
- The API validator and the console editor accept the field. The caveat text appears in the console ("resolved every 60 s; a CDN may rotate faster").

## 6. Teams (B7 first slice)
- `workloads.team` (string ≤64, default `""`). Operator principals may carry `teams: [..]`; empty = all teams. Read endpoints (workloads, incidents, drift, sessions, approvals, stats) filter by the principal's teams; operator actions on a workload outside the principal's teams → 403. Admin role bypasses. Machines are not scoped.

## 7. Export for the real benchmark (B6)
`GET /api/v1/workloads/{id}/export?since=&until=` (permission `read`) → one session JSON in the replay format used by `lab/drift/make_sessions.py` (events, log entries, incidents, `synthetic: false`, `violation_at` = first prohibited incident). `python -m river3_api.replay` consumes it unchanged.

## 8. Inline blocking (B1, sensor)
- `river3d -source lsm` loads BPF-LSM programs `lsm/file_open`, `lsm/bprm_check_security`, `lsm/socket_connect`; same event record and decoder as the tracepoint source. Falls back to `-source ebpf` behaviour with a logged warning when the kernel has no `bpf` LSM.
- `-block-decoys`: at enrolment the sensor resolves each enrolled workload's profile `decoys` and `protected_read` paths inside the container root to `(dev, ino)` and loads them into a BPF map; `file_open` on a listed inode returns `-EPERM` and emits an event with `outcome: "blocked"` (new Outcome value; the API, controller normalizer and policy engine must accept `blocked` as a failed-class outcome: engine `Failed`). Profiles come from `-shadow-profiles`-style directory or `-profiles-from-api` bundle (the sensor already understands profile JSON).
- Everything else about enrolment and sinks is unchanged.

## 9. Outcome vocabulary (updated)
Sensor: `success | failed | pending | blocked`. API `Outcome` adds `blocked`. Controller maps `blocked → policy.Failed` and adds note `blocked inline by sensor`.

## 10. Who builds what tonight
| Area | Items |
|---|---|
| containment | small bugs (journal torn tail, operator claim lost after crash, double-flush orphan, policy cache on first start), Docker adapter, registry-from-runtime, `blocked` outcome, sessions-from-api, gateway session adapter, domain egress refresh, revoke flow |
| api | sessions, session_id on events/incidents, revoke_session action, gate + tools/check + approvals, teams, export, `blocked` outcome, `egress_allowed_domains` in validator, role `gateway` |
| river3d | LSM source, block-decoys, enroll-from-labels (podman+docker), `blocked` outcome, team label |
| policy | `egress_allowed_domains` field (validate, don't match) |
| ui | JSON-tab crash fix, sessions on incidents, approvals screen, gate editor, domain field in policy editor, team filter |
| lab | reference gateway (python stdlib) that binds sessions, checks tools, holds on approval, revokes; demo compose; demo scripts |
</content>
</invoke>
