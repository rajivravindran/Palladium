# Palladium technical reference

_How every part works under the hood. Checked against the code on 20 Oct 2026 (code name **river3**).
File references are `path:line`._

**Contents**
1. [Big picture](#1-big-picture)
2. [Trust model: two channels](#2-trust-model-two-channels)
3. [Sensor: river3d](#3-sensor-river3d)
4. [Policy engine: policy/](#4-policy-engine-policy)
5. [Containment controller: river3-containd](#5-containment-controller-river3-containd)
6. [API: river3_api](#6-api-river3_api)
7. [Console: ui/](#7-console-ui)
8. [How Qwen3 and Laya are used](#8-how-qwen3-and-laya-are-used)
9. [One event, start to finish](#9-one-event-start-to-finish)
10. [Data formats](#10-data-formats)
11. [Configuration reference](#11-configuration-reference)
12. [Tests](#12-tests)
13. [Known limitations](#13-known-limitations)

---

## 1. Big picture

```
NODE (each Linux server)                                         CONTROL PLANE
┌───────────────────────────────────────────────────────┐       ┌──────────────────────────────┐
│ container(s)                                           │       │ API (FastAPI) + PostgreSQL   │
│    │ syscalls: openat, execve, connect                 │       │  workloads, events,          │
│    ▼                                                   │       │  incidents, actions,         │
│ river3d (eBPF sensor, root)                            │       │  audit chain, policies,      │
│    │ POST /v1/events (sensor token)                    │       │  summaries (Qwen3), alerts   │
│    ▼                                                   │ HTTPS │                              │
│ river3-containd (controller)                           │──────►│                              │
│    normalize → [Laya] → policy engine → journal        │◄──────│ operator actions, policies   │
│    → pause via adapter (mock | podman) → verify        │       └──────────────┬───────────────┘
└───────────────────────────────────────────────────────┘                      │ SSE + REST
                                                                     console (React) in a browser
```

| Part | Language | Binary or package | Runs where |
|---|---|---|---|
| Sensor | Go + eBPF C | `river3d` | each node, as root |
| Policy engine | Go library | `river3.local/policy` | inside the controller and the sensor (shadow) |
| Replay tool | Go | `policy-eval` | anywhere |
| Controller | Go | `river3-containd` | each node |
| API | Python 3.12, FastAPI, SQLAlchemy 2.1, Alembic | `river3_api` | control plane |
| Console | React 18, Vite, TypeScript | built into `api/static` | browser |

**Design rule:** the API **never** freezes, resumes or terminates anything. Only the controller on the node touches containers, and only after checking again.

---

## 2. Trust model: two channels

Every event has two separate halves:

| Channel | What | Example | Trust |
|---|---|---|---|
| **A: facts** | Typed, observed by the kernel | path opened, program path, IP:port, outcome, pid, uid | Used for decisions |
| **B: payload** | Text that came from the workload | command-line arguments (argv) | Can **raise** concern, never **clear** it or freeze on its own |

How the code enforces it:
- **Separate types.** The sensor keeps `Facts` and `Payload` as separate Go structs (`river3d/event.go:64-81`).
- **The engine only sees facts.** It takes a `policy.Event` built from facts only. The payload never reaches it.
- **Channel B can't escalate.** A Channel B guard verdict can only move the action up to **ALERT** (`policy/engine.go:166-206`).
- **The model only sees facts.** The summary model never sees the payload (`api/river3_api/summary.py:35`).

> **Caveat:** some Channel A strings (file paths, program names, `comm`) are still chosen by the workload. "Typed" means the field is structured, not that its contents are trustworthy.

---

## 3. Sensor: river3d

### 3.1 Kernel program (`river3d/bpf/sensor.bpf.c`)
- **Six tracepoints:** `sys_enter_` and `sys_exit_` for `openat`, `execve` and `connect` (lines 124-214).
- **On enter:**
  1. Read the calling process's mount-namespace id: `current->nsproxy->mnt_ns->ns.inum`, using CO-RE (96-112).
  2. Stop unless that id is in the `watched` map.
  3. Save what's needed in `inflight`, keyed by thread id. What's saved depends on the call:

| Call | Recorded |
|---|---|
| openat | path (≤256 bytes), flags |
| execve | filename, first 4 argv entries (64 bytes each) |
| connect | address family, port, IPv4/IPv6 address (only AF_INET and AF_INET6) |

- **On exit:**
  1. Look up the saved entry.
  2. Add the return value, timestamps, pid/tgid/ppid, uid, mount-namespace id and `comm`.
  3. Write a 600-byte record to the `events` ring buffer.

  Recording at **exit** means Palladium knows the real **outcome** (success, failed, still in progress).

| BPF map | Type | Size | Holds |
|---|---|---|---|
| `watched` | hash | 1024 | mount-ns id → 1 |
| `inflight` | LRU hash | 16384 | thread id → pending call |
| `scratch` | per-CPU array | 1 | build buffer |
| `events` | ring buffer | 16 MiB | finished events |

The compiled object `sensor_x86_bpfel.o` is committed. It matches a fresh build of the source.

### 3.2 Loader and decoder (`sensor_linux.go`, `decode.go`)
- **Loading.** The loader removes the memlock limit, loads the objects, attaches the six tracepoints and keeps the `watched` map in sync with the enrolled set.
- **Outcome.** Return value ≥ 0 → `success`. A connect returning `-EINPROGRESS` → `pending` (errno 115). Anything else → `failed` with its errno.
- **Event id.** `"ev-"` + 24 hex characters of sha256(sensor|mntns|pid|exit_ns|type). Retries therefore get the same id.
- **Paths.** Relative paths are joined to `/proc/<pid>/cwd`, then walked component by component inside `/proc/<pid>/root`, following symlinks (up to 40) inside the container's root. Success gives `path_resolved: true`.
- **Programs.** The exec path is resolved the same way, then confirmed by device and inode against `/proc/<pid>/exe`.
- **Program class.** Taken from the file name (`event.go:148-161`). The detail label is one of SHELL, NET_CLIENT, PRIV_ESC, RECON, FILE_UTIL, ENCODER, PKG, INTERPRETER or OTHER. It maps to the engine's five classes: DIAGNOSTIC, INTERPRETER, NET_CLIENT, PRIVILEGED_TOOL and OTHER. A test fails if these drift from the engine's list.

  The sensor's label is **advisory**. The controller recomputes the class from the exe path with its own copy of the table (`containment/normalize/classify.go:49-62`) and adds a note if the two differ.
- **File access.** `flags & 3`: 0 = read, 1 = write, otherwise rw.

### 3.3 Enrollment (`workload.go`)
- **Input.** `enroll.json` lists workloads: `asset_id`, `name`, `profile`, `kind` (`ai_worker` | `shared_service`) and a full 64-hex `container_id`. A `pid` or `mntns` can stand in for labs.
- **Refresh.** Every `-refresh` (5 s) the sensor:
  1. asks Podman's REST API (`/run/podman/podman.sock`) for each container's PID;
  2. reads `/proc/<pid>/ns/mnt` to get its mount namespace;
  3. updates the kernel's `watched` map.
- **Collisions.** Two enrollments in the same namespace are both dropped.
- **Registration.** With `-api`, the sensor registers each workload via `POST /api/v1/workloads`.

### 3.4 Where events go (`sink.go`)

| Sink | Flag | Sends | Auth | Retries |
|---|---|---|---|---|
| stdout | `-stdout` | JSONL | none | none |
| controller | `-controller URL` | `POST /v1/events`, one per request | `Bearer $RIVER3_SENSOR_TOKEN` | 4 tries (200/400/800 ms) on network, 5xx and 429; queue 4096 |
| api | `-api URL` | `POST /api/v1/events`, batches of 200 every 1 s | `Bearer $RIVER3_INGEST_TOKEN` | none (dropped and counted); queue 8192 |

All HTTP clients:
- only use `https`, or `http` to loopback;
- refuse credentials in the URL;
- never follow redirects;
- time out after 10 s.

### 3.5 Shadow mode in the sensor (`shadow.go`)
`-shadow-profiles DIR` loads profiles, forces shadow mode, evaluates each event in-process and prints the decision to **stderr**. It's for looking only; it can never act.

### 3.6 Falco source (`falco.go`, `falco/river3_rules.yaml`)
- **Rules.** The rules file gives Falco three rules (`river3_open`, `river3_exec`, `river3_connect`), each matching on syscall exit inside containers.
- **Mapping.** Falco's JSON alerts become the same `Event`:
  - `evt.type` gives the kind;
  - `evt.rawres` gives the outcome;
  - `fd.name` or `proc.exepath` gives the path;
  - `fd.rip:fd.rport` gives the destination;
  - `proc.cmdline` becomes Channel B argv.
- **Input.** From a file, stdin, or `POST /falco` on `-falco-listen`.

> ⚠️ The `/falco` listener has **no authentication**. Bind it to loopback only.

---

## 4. Policy engine: policy/

A pure, deterministic Go library. **It never acts; it only decides.**

### 4.1 Profile schema (`profile.go:22-36`)
| Field | Rules |
|---|---|
| `name` | identifier `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`, unique |
| `kind` | `ai_worker` \| `shared_service` |
| `description` | ≤ 2048 chars |
| `version` | ≥ 1 (0 → 1) |
| `mode` | `SHADOW_MODE` (default) \| `ACTIVE_FREEZE_MODE` |
| `decoys`, `protected_read`, `read_allowed`, `write_allowed` | ≤ 128 canonical absolute patterns; `*` within a segment, trailing `/**` for a subtree. `read_allowed` absent = denylist only; `[]` = deny all reads |
| `exec_allowed_classes`, `exec_denied_classes` | from the 5 classes |
| `egress_allowed` | ≤ 128 CIDRs, no host bits; empty = deny all (including loopback) |
| `response.on_violation`, `response.on_structural_guard` | `ALERT` (default) \| `PAUSE_CONTAINER` \| `REVOKE_SESSION`; PAUSE refused for `shared_service` |

**Loading** is strict and all-or-nothing:
- 1 to 256 files, each ≤ 256 KiB;
- unknown fields, duplicate keys (case-folded), trailing data and nesting deeper than 32 are refused.

### 4.2 Evaluation (`engine.go:86-280`)
1. **Validate the event.** A malformed id, identity, provenance, outcome or operation is an **error**, not a status.
2. **Check the operation:**

| Operation | Checks, in order | Findings |
|---|---|---|
| FILE_OPEN | path must be canonical, else UNKNOWN | `UNRESOLVED_FILE_OPEN` |
| | decoys (any mode) | `DECOY_OPEN` |
| | read: protected, then allowed list | `PROTECTED_OPEN`, `READ_OUTSIDE_SCOPE` |
| | write: allowed list | `WRITE_OUTSIDE_SCOPE` |
| PROCESS_EXEC | class known? deny list wins, then allow list | `UNKNOWN_EXEC_CLASS`, `EXEC_CLASS_DENIED`, `EXEC_CLASS_NOT_ALLOWED` |
| NET_CONNECT | IP valid, not unspecified; must be in a CIDR | `UNRESOLVED_DESTINATION`, `EGRESS_OUTSIDE_SCOPE` |

   Ports are not part of the model yet.
3. **Recommended action.** VIOLATION → `response.on_violation`. UNKNOWN → ALERT.
4. **Guard assessments** (Laya; at most 2, one per channel). See §8.
5. **Blockers** that are always checked:
   - `IDENTITY_NOT_VERIFIED`
   - `POLICY_VERSION_MISMATCH`
   - `UNAUTHENTICATED_SENSOR`
   - `WORKLOAD_NOT_READY`
   - `RESOURCE_NOT_VERIFIED`
   - `MISSING_CONTROLLER_TIME`
   - `STALE_EVENT` (> 30 s)
   - `FUTURE_EVENT` (> 2 s ahead)

   Any of these turns IN_SCOPE into UNKNOWN.
6. **More blockers** only when the action would be PAUSE or REVOKE:
   - `SHADOW_MODE`
   - `NON_LIVE_EVIDENCE`
   - `OUTCOME_NOT_SUCCESSFUL`
   - `INCOMPLETE_ASSESSMENT`
   - `ACTION_NOT_PERMITTED`
   - `ADAPTER_UNAVAILABLE`
   - `NOT_A_DEDICATED_BOUND_CONTAINER`
   - `NO_BOUND_SESSION`
7. **Decide the action:**
   - any blocker → `action = ALERT`, no candidate;
   - otherwise `action = recommended`, plus a **Candidate**.

   The Candidate contains:
   - action and target identity;
   - policy name and version;
   - evidence id;
   - `issued_at` and `expires_at = issued_at + 5 s`;
   - `idempotency_key = "policy_" + sha256(profile, event, action)`.

**Status precedence:** VIOLATION > UNKNOWN > REVIEW > IN_SCOPE. Findings are never removed.

### 4.3 Revalidate (`engine.go:298-314`)
Just before acting, the controller calls `Revalidate(candidate, freshContext)`.

1. The lease must be valid:
   - issued in the past;
   - not expired;
   - ≤ 5 s long.
2. The engine **re-runs** the evaluation.
3. It requires the same action, target, policy version, evidence and key.

If the policy changed or the container changed in between, the action is **aborted**.

### 4.4 policy-eval and the reporter (`cmd/policy-eval`, `report/`)
- **Input.** JSONL `{"profile": …, "event": {…}}`. Shadow mode is forced; one decision is printed per line.
- **Reporting.** `-report URL` (token from `RIVER3_POLICY_TOKEN`) posts VIOLATION and REVIEW decisions as incidents. Add `-report-unknown` for UNKNOWN too.
- **Retries.** On 429 and 5xx; 409 counts as a duplicate success; redirects are never followed.
- **Replays only.** It has no live context, so the always-checked blockers (identity, sensor, readiness) are present, and benign events come out **UNKNOWN**, not IN_SCOPE.

---

## 5. Containment controller: river3-containd

Runs on each node, next to the sensor.

### 5.1 Endpoints it serves (`controller/server.go`)
| Method + path | Auth | Purpose |
|---|---|---|
| `POST /v1/events` | sensor bearer token (sha256 in registry) | Receive one event (≤ 64 KiB, strict JSON) |
| `POST /river3/actions` | HMAC `sha256(ts + "." + body)` with `RIVER3_WEBHOOK_SECRET`, ±5 min | Operator actions pushed by the API |
| `GET /healthz` | none | Journal stats, adapter name |

Default listen address: `127.0.0.1:8787`. There is no TLS.

### 5.2 Flow for one event (`controller/controller.go:146-294`)
1. **Authenticate** the sensor and **normalize** the event:
   - look the workload up in the **registry**;
   - ask the **adapter** to inspect the live container;
   - check the id and generation (container start time) match;
   - set the trust flags: identity verified, healthy, active, resource verified, sensor authenticated.
2. **(Optional) Laya** gives one or two assessments (§8).
3. **Evaluate** with the policy engine.
4. **Journal** the decision. The event id deduplicates, so a repeat returns the earlier answer.
5. **If there's a candidate, act first:**
   1. reserve its idempotency key in the journal;
   2. normalize again with a fresh clock;
   3. call `Revalidate`;
   4. journal EXECUTING;
   5. `Adapter.Pause` (5 s timeout);
   6. `Adapter.Inspect`, and decide VERIFIED / FAILED / UNKNOWN from the **observed** state, never from the pause call's return value.
6. **Then report** to the API (`controller.go:223-227`, `outbox.go:48-96`):
   1. create the incident with its events;
   2. send `PATCH /incidents/{id}/response` with the action's result.

   If the API is down, the outbox retries both.

Only `PAUSE_CONTAINER` is executed. Any other candidate is aborted with "action not implemented by this controller".

### 5.3 Registry (`registry/registry.go`)
- **One JSON file per node.** It holds:
  - the node's tenant and host;
  - sensors (name, `token_sha256`, `resolves_paths`);
  - workloads (asset_id, name, profile, kind, full `container_id`, `generation`, `dedicated`, `active`, `permitted_actions`, optional `session_id`).
- **Rules:**
  - PAUSE is allowed only on a dedicated `ai_worker`;
  - shared services can't be `dedicated`;
  - no container may be enrolled twice.
- **Loaded once at start**, so changes need a restart.

### 5.4 Journal and outbox (`journal/`, `controller/outbox.go`)
**Journal**
- An append-only JSONL file (mode 0600), **fsync'd on every record** and replayed at start.
- Record kinds: decision, action, report, operator.
- Action states: `RESERVED → ABORTED | EXECUTING → VERIFIED | FAILED | UNKNOWN`.
- **After a crash:**
  - RESERVED → ABORTED (the adapter was never called);
  - EXECUTING → re-inspected to see what really happened.

**Outbox**
- Every 10 s (`-flush`), the outbox retries everything the API hasn't confirmed:
  - workload registration;
  - incidents;
  - response updates;
  - operator results.
- It is driven by the journal, so it survives restarts.

### 5.5 Adapters (`adapter/`)
The interface is `Name, Actions, Inspect, Pause, Resume, Terminate`, with statuses running / paused / exited / missing / unknown.

| Adapter | Does | Status |
|---|---|---|
| `mock` (default) | in-memory containers; `-mock-containers registry` seeds them as running | used in tests and the lab |
| `podman` | libpod REST over the unix socket: `GET …/json`, `POST …/pause`, `…/unpause`, `…/stop?timeout=10`; generation = `State.StartedAt` | **never run on real Podman** |

No adapter offers `REVOKE_SESSION`, so the engine blocks it with `ADAPTER_UNAVAILABLE`.

### 5.6 Operator actions (`controller/operator.go`)
- **Two ways to receive them:**
  - **poll:** `GET /api/v1/actions` every 5 s;
  - **push:** the signed webhook.
- **Steps:**
  1. Claim the action id durably in the journal, so it is never run twice.
  2. Inspect the container. A different generation means `STALE_GENERATION`.
  3. **Resume** only if paused. **Terminate** only `ai_worker`.
  4. Inspect again to verify.
  5. `POST /api/v1/actions/{id}/result`.

### 5.7 Policy sync (`controller/policysync.go`)
- **Turned on by `-profiles-from-api`.** The controller then fetches `GET /api/v1/policy/bundle` every 10 s.
- **Validation before use:**
  1. parse every profile strictly;
  2. check that every enrolled workload's profile is present;
  3. build the engine.

  Only then is the set **swapped in atomically** and cached to `<journal>.policy.json`.
- **A bad bundle** is remembered and skipped; the old set stays in force.
- **Status reports** go to `POST /api/v1/policy/sync` on every change and at least once a minute.
- **At start-up** the controller tries the API first, then the cache, then the `-profiles` folder.

---

## 6. API: river3_api

### 6.1 Endpoints (`main.py`)
| Area | Endpoints | Who |
|---|---|---|
| Health | `GET /api/health`, `GET /api/ready` | anyone |
| Me | `GET /api/v1/me` | any person |
| Ingest | `POST /api/v1/workloads`, `POST /api/v1/events` (≤ 1000) | sensor, policy |
| Incidents in | `POST /api/v1/incidents` | policy |
| Response in | `PATCH /api/v1/incidents/{id}/response` | containment |
| Canary | `POST /api/v1/canary` | policy role, or HMAC with `RIVER3_CANARY_SECRET` |
| Actions out | `GET /api/v1/actions`, `POST /api/v1/actions/{id}/result` | containment |
| Read | `GET /api/v1/stats`, `/workloads`, `/incidents`, `/incidents/{id}` | viewer+ |
| Operator | `POST /api/v1/incidents/{id}/actions` (resume, terminate, resolve, false_positive; reason ≥ 8) | responder+ |
| Summary | `POST /api/v1/incidents/{id}/summary` (15 s cooldown) | responder+ |
| Audit | `GET /api/v1/audit`, `GET /api/v1/audit/verify` | admin |
| Policies | `GET /api/v1/policies`, `GET /policies/{name}` | viewer+ |
| | `POST /policies/validate`, `PUT /policies/{name}`, `DELETE /policies/{name}` | admin |
| Policy bundle | `GET /api/v1/policy/bundle`, `POST /api/v1/policy/sync` | policy |
| Live | `POST /api/v1/stream/ticket`, `GET /api/v1/stream?ticket=` (SSE) | viewer+ |
| Console | `GET /` and assets from `api/static` | anyone |

**Operator rules:**
- resume only when frozen;
- terminate never on a shared service;
- the same action can't be pending twice.

**Delivery:** resume and terminate are queued, and pushed to `RIVER3_ACTION_WEBHOOK` if it is set.

### 6.2 Data model (`db.py`; migrations `909063513ad1 → e0d80e09f882 → cce76aa444fa`)
| Table | Holds |
|---|---|
| `workloads` | id, name, profile, kind, sensor, state (running / frozen / terminated / unknown), demo |
| `incidents` | title, threat, severity, verdict, rule, reason, mode, status (open / contained / resolved / false_positive), `response` JSON, `policy` JSON (the engine's decision) |
| `events` | id, incident, workload, kind, outcome, ts, `facts` (A), `payload` (B) |
| `operator_actions` | action, operator, reason, status (requested → delivered → completed / failed, or recorded), result |
| `summaries` | source (model / fallback), model, content, grounded, invalid_citations, latency |
| `policy_profiles` + `policy_profile_versions` | current body + full history (with tombstones) |
| `policy_sync` | per controller: seen and active revision, profile count, error |
| `audit_log` + `audit_head` | hash chain + its head |

### 6.3 Auth (`security.py`)
- **Principals** come from `RIVER3_PRINCIPALS_FILE`: name, kind (operator / machine), role, `token_sha256`.
- **Token check:** the bearer token is hashed with SHA-256 and compared in constant time.
- **Permissions:**
  - people: `read`, `act`, `summarize`, `audit`, `policies`;
  - machines: `workloads.write`, `events.write`, `incidents.write`, `response.write`, `actions.read`, `actions.write`, `profiles.read`, `profiles.status`.

  A person's role can't hold machine permissions, and the reverse.
- **Custom roles:** `RIVER3_ROLES_FILE`.
- **Throttle:** 20 failed sign-ins per IP per 5 minutes → 429.
- **Headers:**
  - strict CSP, `X-Frame-Options: DENY`, `nosniff`;
  - `no-store` on `/api/`;
  - optional HSTS;
  - a request id;
  - a JSON access log.
- **Body limit:** 1 MiB. There is no CORS: same origin only.
- **Production mode** (`RIVER3_ENV=production`) refuses to start without:
  - a 32+ character secret key;
  - a principals file;
  - a non-SQLite database;
  - HTTPS webhooks.

  It also disables the docs page and requires migrations to have run.

### 6.4 Audit chain (`audit.py`)
- **Each row's hash** = SHA-256 of `prev_hash | seq | ts | actor | action | target | detail-json`. The first row uses `0 × 64`.
- **Appending** locks the head row (`SELECT … FOR UPDATE`), adds the row and moves the head, in the same transaction as the business change.
- **Verify** walks every row (contiguous seq, links, recomputed hashes) and checks the head.

**Limits:**
- The hash isn't keyed and the head isn't exported, so someone with database write access could rebuild the chain.
- Event ingest isn't audited.

### 6.5 Live stream (`bus.py`, `security.py:244`)
1. The console asks for a **ticket**: an HMAC-signed blob with `{token hash, expiry 60 s, nonce}`, usable once.
2. It opens `EventSource('/api/v1/stream?ticket=…')`, so the real token never appears in a URL.
3. The in-process bus fans out `workload`, `incident` and `policy` messages (256 per subscriber, at most 50 streams).

### 6.6 Webhooks and alerts (`main.py:394`, `notify.py`)
- **Action webhook**
  - Headers: `X-River3-Timestamp`, `X-River3-Signature: sha256=HMAC(secret, ts + "." + body)` and `X-River3-Delivery: uuid`.
  - 5 s timeout, no retry, no redirects.
- **Alert webhook**
  - Body: `{"text", "type", "incident"}`, Slack-compatible.
  - Sent for severity ≥ `RIVER3_ALERT_MIN_SEVERITY`.
  - Signed the same way when a secret is set.

### 6.7 CLI (`cli.py`)
`new-token`, `hash-token` (reads stdin), `new-secret`, `check-config`, `verify-audit`.

---

## 7. Console: ui/

- **Views:** Incidents, Workloads, Policies, Audit log, plus a stats strip.
- **Sign-in:** a bearer token, checked with `/api/v1/me`. It's kept in `sessionStorage`, or in memory if storage is blocked.
- **Live updates:** SSE via tickets. If the stream drops, the console polls every 15 s and gets a new ticket after 5 s.
- **Incident detail:** facts, reason, decision with blockers, the action buttons (each needs a reason), summary view and an event timeline with argv shown separately.
- **Policy editor (`Policies.tsx`):**
  - a Rules form, a JSON tab and a History tab;
  - validation as you type through `/policies/validate`;
  - optimistic versioning (`base_version`), with a conflict banner;
  - an "I understand" checkbox before going active;
  - a controller sync panel.
- **Build:** `npm run build` writes to `api/static`, which FastAPI serves.

---

## 8. How Qwen3 and Laya are used

Both are **optional**, and **local with the default settings**. They are different kinds of model:
- **Qwen3-8B** is a chat model, called through an OpenAI-compatible endpoint (Ollama) at `…/chat/completions` with `response_format: json_object`, low temperature, prompts ending in `/no_think`, and `<think>…</think>` stripped from replies. It writes the summaries.
- **Laya** (`convaiinnovations/laya`, 421M, ModernBERT backbone, Apache 2.0) is a **non-generative decision model**: it takes a state plus typed questions and returns an answer per question with a probability, in one forward pass. It is served by `laya-serve` (`pip install "laya[serve]"`), which speaks **TypeSafe Jev's `/v1/systemone` protocol**, so the same client (`api/river3_api/systemone.py`, `containment/guard/guard.go`) talks to Laya locally or to Jev hosted.

`/v1/systemone` in one line: `POST {state, questions: {id: {type: "choice", instructions, criteria: {option: description}}}}` → `{model, answers: {id: {type, choice, probabilities, confidence}}}`. Laya has no abstain option, so "unknown" is derived client-side from `confidence` against a threshold.

### 8.1 Qwen3-8B: incident summaries (API side, `api/river3_api/summary.py`)

**When:** an operator clicks **Generate summary**. It is **not** automatic yet.

**Request**
| | |
|---|---|
| Endpoint | `RIVER3_LLM_BASE_URL` + `/chat/completions` (default `http://localhost:11434/v1`) |
| Model | `RIVER3_LLM_MODEL` (default `qwen3:8b`), temperature 0.1 |
| Timeout | `RIVER3_LLM_TIMEOUT` (60 s) |
| System prompt | "You are River3's incident investigator… Use ONLY the structured facts… Every timeline item MUST cite exactly one event_id… Reply with JSON only: `{headline, timeline[{event_id, what}], assessment, unknowns[]}`" |
| User message | JSON of: the incident (id, title, threat, severity, verdict, rule, reason, mode, response), the workload (id, name, profile, kind, state), and the **newest 200 events** as `{event_id, ts, kind, outcome, facts}` |
| **Not sent** | `payload` (Channel B), and the policy decision JSON |

**Grounding check**
1. Each timeline item must cite an event id that belongs to **this** incident. Others are removed and listed in `invalid_citations`.
2. `grounded = true` only if nothing had to be removed.
3. Text fields are length-capped.
4. If no valid timeline item is left, the deterministic summary is used instead.

> Only the **citations** are checked. The prose (headline, assessment) is not compared with the facts.

**Fallback** (model down, timeout, bad JSON): a deterministic summary.
- **Headline:** `"<workload>: <title>"`.
- **Timeline:** one plain line per event.
- **Assessment:** built from the rule, verdict, reason and response (plus a note if in shadow mode).
- **Stored as:** `source: fallback`, `model: deterministic`.

### 8.2 Laya: the model guard (controller side, `containment/guard/guard.go`)

**When:** after the deterministic engine, and only when it found **no violation**, if the controller runs with `-guard laya` (or `-guard llm` for a chat model). A decoy open is a violation before any model is asked, so a slow or absent model never delays a freeze.

**Two separate calls, one after the other, to `POST /v1/systemone`**
| | Call A: structural | Call B: payload |
|---|---|---|
| State | `{profile, operation, outcome, facts}`; facts are Channel A (no argv), bounded to 4 KiB | `{untrusted_text}`: argv and the like, cut at 4 KiB |
| Question | one `choice` named `verdict`, options CONTINUE / WARN_OPERATOR / REQUEST_CONTAINMENT with criteria worded for kernel facts | the same question with criteria worded for text ("ordinary", "suspicious or obfuscated", "plainly an attack or an attempt to disable monitoring") |
| Runs | always, if channel A is enabled | only if there is a payload |

- **Settings:** `RIVER3_GUARD_URL` (default `http://127.0.0.1:8600`; https or loopback http only, no redirects), `RIVER3_GUARD_TOKEN` (Laya's `LAYA_API_KEY`), `-guard-timeout` (0 = default: 3 s for laya, 8 s for llm), `-guard-min-confidence` (0.6), `-guard-channels` (`A,B`).

**Who decides "Verified"?** The **guard code**, never the model. An assessment is verified only if the reply has exactly the one answer, of type `choice`, whose option is one of the three we sent, with a confidence in [0, 1] at or above the threshold. Anything else (timeout, 401, malformed, low confidence) becomes `UNAVAILABLE`, not verified.

**What the engine does with it** (`policy/engine.go`)
| Laya says | Effect |
|---|---|
| CONTINUE | nothing |
| not verified (timeout, low confidence, garbage) | finding `UNTRUSTED_GUARD_ASSESSMENT` → status becomes UNKNOWN (unless already VIOLATION) → alert |
| WARN_OPERATOR (A or B) | finding `GUARD_A_WARN_OPERATOR` / `GUARD_B_WARN_OPERATOR`; IN_SCOPE → REVIEW; action ≥ ALERT |
| REQUEST_CONTAINMENT on **B** | same as warn: **alert only**. Untrusted text can never freeze. |
| REQUEST_CONTAINMENT on **A**, no rule broken | action = `response.on_structural_guard`, which may be ALERT (default) or PAUSE_CONTAINER, never REVOKE_SESSION. All the normal blockers still apply. |

**Other notes:**
- **This is the one way a model can lead to a freeze:** channel A says REQUEST_CONTAINMENT and the policy opts in with `on_structural_guard: PAUSE_CONTAINER`.
- Laya's verdicts are stored in the event's `facts.guard` and reused unchanged when the controller revalidates before acting. The lease starts **after** the guard answers.
- Laya **cannot clear** a rule violation.
- **Accuracy:** Laya's model card says the base checkpoint is near chance zero-shot and over-confident until fine-tuned. Keep the threshold conservative and plan to fine-tune on exported sessions.
- Call A gets the profile **name**, not its rules. Passing the compiled rules into the state is a planned improvement.

### 8.3 Laya and Jev in the drift tiers (API side, `api/river3_api/drift.py`)

Off by default (`RIVER3_DRIFT_MODEL=off`). With `laya` or `jev`, each chunk of the agent's log window (up to 8 chunks of ~1,200 characters) is sent as the state with two questions: a `choice` `agent_mode` (on_task / exploring / working_around_limit) and a `noul` `addressed_to_monitor`. Only `working_around_limit` at or above `RIVER3_DRIFT_MIN_CONFIDENCE` can raise the tier (to Rising); a confident yes on `addressed_to_monitor` adds the raise-only reason "text addressed to the monitor". Everything else, including every failure, is `unknown`: a reason line, no tier change. Calls run on a background worker with a per-workload cache, never inside a request. `llm` keeps the chat-model path for Qwen-style models.

---

## 9. One event, start to finish

Example: an AI worker in **active** mode connects to an address outside its policy.

| # | Where | What happens |
|---|---|---|
| 1 | kernel | `connect()` enters. The mount namespace is watched, so the address is saved. |
| 2 | kernel | `connect()` exits with 0. A 600-byte record goes to the ring buffer. |
| 3 | river3d | Decode: `net_connect`, `success`, `203.0.113.50:443`, id `ev-…`. Sent to the controller. |
| 4 | controller | Sensor token ok → registry: `my-agent-01` → Inspect: running, same id and generation → trust flags set. |
| 5 | controller | (Laya, if on) → engine: `EGRESS_OUTSIDE_SCOPE` → VIOLATION → recommended PAUSE → no blockers → Candidate (5 s lease). |
| 6 | controller | Journal decision → reserve key → re-normalize → Revalidate ok → EXECUTING → Pause → Inspect = paused → **VERIFIED**. |
| 7 | controller | Create the incident in the API, then `PATCH` the response. |
| 8 | API | Incident `contained`, workload `frozen` → audit rows → SSE → the console updates instantly. |
| 9 | console | Operator clicks **Resume** with a reason → action `requested` → audit. |
| 10 | controller | Poll picks it up → claim → Inspect → unpause → Inspect = running → result `completed`. |
| 11 | API | Workload `running` → audit row → SSE. |

All of this was run on 20 Oct with the mock adapter (USER_GUIDE.md §2).

---

## 10. Data formats

**Sensor event** (`river3d/examples/events.golden.jsonl`):
```json
{"facts":{"id":"ev-848687875e442b3d5909be97","sensor":"ebpf","kind":"net_connect","outcome":"pending","errno":115,
  "workload":{"id":"worker-01","name":"W","profile":"diagnostic-worker","kind":"ai_worker","enrolled":true,"container_id":"aaaa…"},
  "process":{"pid":4242,"tgid":4242,"ppid":1,"uid":1000,"comm":"python3"},
  "target":{"ip":"203.0.113.9","port":80},
  "t_kernel_enter_ns":1000000000,"t_kernel_exit_ns":1000050000,"t_received_ns":1792368001000050000},
 "payload":{}}
```

**Enrollment** (`river3d/examples/enroll.json`):
```json
[{"asset_id":"worker-01","name":"Diagnostic worker 01","profile":"diagnostic-worker","kind":"ai_worker","container_id":"<64 hex>"}]
```

**Controller registry** (`containment/fixtures/registry.json`, shortened):
```json
{"node":{"tenant_id":"lab","host_id":"podman-vm"},
 "sensors":[{"name":"lab-sensor","token_sha256":"75d4…db18","resolves_paths":true}],
 "workloads":[{"asset_id":"worker-01","name":"Diagnostic worker 01","profile":"diagnostic-worker","kind":"ai_worker",
   "container_id":"<64 hex>","generation":"generation-1","dedicated":true,"active":true,"permitted_actions":["PAUSE_CONTAINER"]}]}
```

**Policy** (`lab/playground/profiles/my-agent.json`):
```json
{"name":"my-agent","kind":"ai_worker","version":1,"mode":"ACTIVE_FREEZE_MODE",
 "decoys":["/home/agent/.ssh/id_rsa_backup"],"protected_read":["/root/**","/etc/shadow"],
 "read_allowed":["/data/**","/etc/app/**"],"write_allowed":["/out/**"],
 "exec_allowed_classes":["INTERPRETER"],"exec_denied_classes":["NET_CLIENT","PRIVILEGED_TOOL"],
 "egress_allowed":["10.0.0.0/8"],"response":{"on_violation":"PAUSE_CONTAINER","on_structural_guard":"ALERT"}}
```

**Journal lines** (controller):
```json
{"seq":3,"kind":"action","event_id":"fx-decoy-open","key":"policy_7b6f…","state":"RESERVED","action":"PAUSE_CONTAINER","asset":"worker-01"}
{"seq":5,"kind":"action","state":"VERIFIED","detail":{"adapter":"mock","observed":{"status":"paused"}},"latency_ms":0.022}
```

---

## 11. Configuration reference

### API environment
| Variable | Default | Notes |
|---|---|---|
| `RIVER3_ENV` | `development` | `production` turns on all the checks in §6.3 |
| `RIVER3_DATABASE_URL` | `sqlite:///./river3.db` | `postgresql+psycopg://…` for a pilot |
| `RIVER3_SECRET_KEY` | random per start | ≥ 32 chars; signs stream tickets |
| `RIVER3_PRINCIPALS_FILE` / `RIVER3_PRINCIPALS` | dev principals | required in production |
| `RIVER3_ROLES_FILE` / `RIVER3_ROLES` | built-in roles | |
| `RIVER3_ACTION_WEBHOOK` / `RIVER3_WEBHOOK_SECRET` | none | push operator actions to the controller |
| `RIVER3_ALERT_WEBHOOK` / `RIVER3_ALERT_MIN_SEVERITY` | none / `high` | |
| `RIVER3_CANARY_SECRET` | none | HMAC for canary callers |
| `RIVER3_LLM_BASE_URL` / `_MODEL` / `_TIMEOUT` | `http://localhost:11434/v1` / `qwen3:8b` / `60` | summaries |
| `RIVER3_MAX_BODY_BYTES` | `1048576` | |
| `RIVER3_HSTS` / `RIVER3_TRUSTED_PROXY` | `false` / `false` | |
| `RIVER3_AUTH_FAIL_LIMIT` / `_WINDOW` | `20` / `300` | |

### Controller flags (`containment/cmd/river3-containd/main.go:44-60`)
| Flag | Default |
|---|---|
| `-profiles` | `../policy/examples/profiles` |
| `-profiles-from-api` / `-profile-sync` | off / `10s` |
| `-registry` | `fixtures/registry.json` |
| `-journal` | `river3-containd.journal` |
| `-listen` | `127.0.0.1:8787` |
| `-api` | none (offline) |
| `-adapter` / `-podman-socket` | `mock` / `/run/podman/podman.sock` |
| `-mock-containers` | none (`registry` to seed) |
| `-report-unknown` | off |
| `-poll` / `-flush` | `5s` / `10s` |
| `-sensor-heartbeat` | off |
| `-guard` / `-guard-channels` / `-guard-timeout` | `off` / `A,B` / `8s` |

**Controller environment:**
- `RIVER3_CONTAINMENT_TOKEN` (required with `-api`);
- `RIVER3_POLICY_TOKEN` (falls back to the containment token);
- `RIVER3_WEBHOOK_SECRET`;
- `RIVER3_GUARD_URL`, `RIVER3_GUARD_MODEL`.

### Sensor flags (`river3d/main.go:39-49`)
| Flag | Default |
|---|---|
| `-source` | `ebpf` (or `falco`) |
| `-enroll` | `enroll.json` |
| `-podman-socket` | `/run/podman/podman.sock` |
| `-refresh` | `5s` |
| `-name` | `ebpf` (set `falco` for Falco) |
| `-controller`, `-api` | none |
| `-stdout` | off |
| `-shadow-profiles` | none |
| `-falco-input` / `-falco-listen` | `-` (stdin) / none |

**Sensor environment:** `RIVER3_SENSOR_TOKEN`, `RIVER3_INGEST_TOKEN`.

---

## 12. Tests

All run on 20 Oct 2026 (Go 1.24.7, Python 3.13, Node 22). Every suite passes.

| Module | Test functions | Result | Coverage |
|---|---|---|---|
| `river3d` | 26 | pass (also loaded live on kernel 6.18) | 48.5% |
| `policy` | 20 + 2 fuzz | pass | 88.2% |
| `policy/cmd/policy-eval` | 5 | pass | 67.2% |
| `policy/report` | 9 | pass | 82.2% |
| `containment` | 80 (1 skipped when run alone) | pass | 59-86% per package |
| `api` | 47 (74 cases with parametrize) | pass; `alembic check` clean | — |
| `ui` | — | `tsc` + `vite build` clean; `npm ci`: 0 vulnerabilities | — |

Run them:
```bash
(cd policy && go test ./...)
(cd river3d && go test ./...)
(cd containment && go test ./...)
(cd api && pytest -q tests)
(cd ui && npm run build)
```

---

## 13. Known limitations

**Sensor coverage**
- **Missing system calls.** Only `openat`, `execve` and `connect` are hooked. Not seen:
  - `open` and `creat`, `openat2`, `execveat`, io_uring opens;
  - UDP sent without `connect`;
  - bind / listen / accept;
  - rename / unlink / chmod;
  - ptrace, mount / setns / unshare.
- **Paths:**
  - relative paths are joined to the working directory, not the directory handle passed to `openat`;
  - paths longer than 255 bytes are cut without a flag.
- **Program class comes from the file name.** A copied and renamed program is judged by its new name.
- **Lost connect events.** A connect whose address can't be read is dropped silently.
- **Child mount namespaces** (e.g. `unshare -m`) leave the watched set.
- **Non-blocking connects** come out as `pending`, so they can alert but never freeze (`OUTCOME_NOT_SUCCESSFUL`).
- **Platform.** Linux x86-64 only for eBPF, and Podman only for container lookup.

**Response**
- **No session revoke**, and the sensor doesn't track sessions.
- **The Podman adapter has never run on real Podman.**
- There are no Docker, containerd or Kubernetes adapters.
- Registry and enrollment changes need a restart.

**Control plane**
- Single process. The stream, tickets and throttle are all in memory, so there's no high availability.
- No team or tenant scoping.
- The audit chain isn't anchored outside the database.
- The Docker image doesn't include the console.

**Bugs:** see STATUS.md, which lists 14 with their impact.
</content>
</invoke>
