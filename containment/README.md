# River3 containment layer (Go)

`river3-containd` is the node-local controller that sits between the policy engine
and the runtime. It answers: **"Given an eligible candidate, did River3 actually
contain the workload, and can we prove it?"** — and it executes authenticated
operator resume / terminate requests the same way.

It is a standard-library-only Go module next to `../policy`, which it imports via a
`replace` directive. Nothing in it shells out.

## The loop

```
authenticated sensor event (POST /v1/events, sensor token)
  │
  ▼
normalize/      trusted normalizer + context provider
                identity ← registry + live Inspect, never the event
                resource ← sensor capability + canonical path / controller class table
  │
  ▼
policy.Engine.Evaluate   deterministic rules only, no model input
  │
  ├─ VIOLATION ──────────────────────────────► final: the guard is never asked
  │
  └─ IN_SCOPE / REVIEW / UNKNOWN, -guard laya|llm ─► guard.Assess (Channel A, Channel B)
                                                    Context.Now re-stamped, Evaluate again
  │
  ▼
journal: decision (durable, deduplicated by event id)
  │
  ├─ no candidate ──► report incident (VIOLATION / REVIEW; UNKNOWN only with -report-unknown)
  │
  └─ candidate ──► journal: RESERVED (idempotency key)
                   refresh context ──► Engine.Revalidate ──✗──► ABORTED
                   journal: EXECUTING
                   adapter.Pause(container id)        ← structured call, never a shell
                   adapter.Inspect(container id)      ← the real state decides
                   journal: VERIFIED | FAILED | UNKNOWN
                   PATCH /api/v1/incidents/{id}/response   (status contained only when VERIFIED)
```

Operator requests (`GET /api/v1/actions` poll, or the HMAC-signed webhook on
`POST /river3/actions`) are claimed once in the journal, checked against the
enrolled container id + generation, executed, inspected, and reported with
`POST /api/v1/actions/{id}/result`.

Every API report goes through an **outbox**: it is retried until the API
acknowledges it, and survives restarts. A restart first reconciles any action left
`EXECUTING` by inspecting the runtime; a `RESERVED` key whose adapter call never
went out is `ABORTED`.

## Run it

```sh
cd containment
go test -race ./...

# Offline: evaluate and act against the mock runtime, journal locally, report nothing.
go run ./cmd/river3-containd -profiles fixtures/profiles -registry fixtures/registry.json \
    -adapter mock -mock-containers registry -journal /tmp/r3.journal

# Against a real Docker daemon, enrolling whatever is labelled river3.enroll=true
# (no workloads in the registry file; sensors still come from it):
go run ./cmd/river3-containd -profiles fixtures/profiles -registry fixtures/registry.json \
    -adapter docker -registry-from-runtime -journal /tmp/r3.journal
docker run -d --label river3.enroll=true --label river3.asset_id=worker-01 \
    --label river3.profile=diagnostic-worker --label river3.kind=ai_worker river3-lab-base:latest sleep 300

# With the API (dev tokens from api/river3_api/config.py):
export RIVER3_CONTAINMENT_TOKEN=dev-containment-token RIVER3_POLICY_TOKEN=dev-policy-token
go run ./cmd/river3-containd -profiles fixtures/profiles -registry fixtures/registry.json \
    -adapter mock -mock-containers registry -api http://127.0.0.1:8000

# Feed the fixtures (the sensor token hashes to the entry in fixtures/registry.json):
while read -r ev; do
  curl -s -H "Authorization: Bearer dev-sensor-token" -H 'Content-Type: application/json' \
       --data-binary "$ev" http://127.0.0.1:8787/v1/events; echo
done < fixtures/events.jsonl
```

`fixtures/profiles/diagnostic.json` is the example profile in `ACTIVE_FREEZE_MODE`;
`../policy/examples/profiles` are all shadow and will only ever alert.

To receive operator actions by push instead of polling, set on the API
`RIVER3_ACTION_WEBHOOK=http://127.0.0.1:8787/river3/actions` (https off-host) and the
same `RIVER3_WEBHOOK_SECRET` on both sides. The controller verifies the three headers
exactly as `api/river3_api/security.py` `sign_webhook` produces them:

```
X-River3-Timestamp:  unix seconds, plain decimal
X-River3-Delivery:   unique id per delivery (required)
X-River3-Signature:  "sha256=" + hex( HMAC-SHA256( secret, "<ts>.<delivery>.<body>" ) )
```

The signed base string is **`"<X-River3-Timestamp>.<X-River3-Delivery>.<body>"`**
(`controller.WebhookBase`). A timestamp outside ±5 minutes, a missing delivery id, or
a delivery id already seen within that window is rejected with 401; the seen set is
bounded (10 000 ids, oldest evicted). Polling keeps working alongside, and a request
delivered both ways is executed once.

### Flags worth knowing

| Flag | Meaning |
|---|---|
| `-profiles DIR` | profile JSON files to enforce (default `../policy/examples/profiles`, all shadow). |
| `-profiles-from-api` | enforce the policy set admins edit in the console (needs `-api`). `-profiles` is used only until the API has a valid set; the last applied set is cached next to the journal (`<journal>.policy.json`) the moment it is accepted, startup included, and used if the API is unreachable at start. |
| `-profile-sync 10s` | with `-profiles-from-api`: how often to fetch and apply policy changes. A set the engine rejects is reported back and never applied. |
| `-guard off\|laya\|llm` | the model guard, off by default. `laya` talks to the real Laya decision model through `laya-serve` (`RIVER3_GUARD_URL`, default `http://127.0.0.1:8600`; `RIVER3_GUARD_TOKEN` optional bearer). `llm` talks to an OpenAI-compatible chat-completions endpoint (`RIVER3_GUARD_URL`, default `http://127.0.0.1:11434/v1`; `RIVER3_GUARD_MODEL`, default `qwen3:8b`). Plain `http` only on loopback, `https` otherwise, no redirects. See **Model guard** below. |
| `-guard-channels A,B` | which channels the guard assesses: `A` structural facts, `B` untrusted payload. |
| `-guard-timeout 0` | per model call; `0` = the mode's default, **3 s for `laya`** (one forward pass is ~0.2–0.5 s on CPU) and **8 s for `llm`**. A timeout yields an unverified `UNAVAILABLE` assessment, which the engine records as `UNTRUSTED_GUARD_ASSESSMENT`; a benign event then becomes `UNKNOWN`, never `IN_SCOPE`. The guard is consulted only when the deterministic rules did not already find a `VIOLATION`, so it never delays a pause. |
| `-guard-min-confidence 0.6` | `laya` only: an answer whose `confidence` is below this is an unverified `UNAVAILABLE` (so `UNKNOWN`), however clear the chosen option. Must be in `(0, 1]`. |
| `-sensor-heartbeat 0` | treat a workload as unhealthy (`WORKLOAD_NOT_READY`) if its sensor has been silent this long, judged against the sensor's *previous* message; a sensor never heard from is measured from controller start. |
| `-report-unknown` | also post `UNKNOWN` decisions as incidents. |
| `-adapter mock\|podman\|docker\|openshell` | the runtime. `docker` speaks the Engine API (`/v1.43`) over `-docker-socket` (default `/var/run/docker.sock`): `GET /containers/{id}/json` (generation = `State.StartedAt`), `POST .../pause`, `.../unpause`, `.../stop?t=10`. `podman` speaks libpod over `-podman-socket`. Both send only the full 64-hex id, one request per connection, no redirects, 10 s per call (stop: 10 s + the 10 s grace period, because the daemon answers only once the container is down). |
| `-registry-from-runtime` | enrol workloads from containers labelled `river3.enroll=true` (CONTRACTS.md §4.1: `river3.asset_id`, `river3.profile`, `river3.kind`, optional `river3.name`, `river3.dedicated`, `river3.actions`, `river3.team`) instead of the registry file's `workloads`; the file still supplies `node` and `sensors`. The container id and generation (`StartedAt`) come from the runtime's inspect, never from a label. Re-listed every `-registry-refresh` (10 s) and swapped in atomically; a container that disappears is un-enrolled, a restarted one gets its new generation, a container whose labels fail the registry rules or name a profile the engine does not have is skipped and logged. One `registry.discovered` line per change. |
| `-runtime podman\|docker` | which runtime `-registry-from-runtime` lists; default: the adapter's own. Listing a different runtime than the adapter acts on only makes sense for dry runs (`-adapter mock`). |
| `-registry-reload 5s` | hot reload of the `-registry` file (CONTRACTS.md §5): the file's mtime/size is checked this often and re-read when it changed; `0` turns the poll off. `SIGHUP` reloads it at any time regardless. The file is validated whole with the start-up loader (plus: every workload's profile must be in the enforced set) and swapped in atomically; an invalid file is logged (`registry.rejected`), shown as `registry_error` on `/healthz`, and the previous snapshot stays in force. Each applied reload logs `registry.reloaded` with the added / removed / changed asset ids and added / removed sensor names. With `-registry-from-runtime` only the file's node and sensors reload; workloads keep coming from the runtime. `-mock-containers registry` seeds the mock runtime at start only. |
| `-poll 5s`, `-flush 10s` | operator-action poll and outbox retry intervals. Every loop interval must be `> 0` (the ones documented "0 = off" accept zero); the command line is refused otherwise instead of the daemon crashing after start-up. |

## Model guard

The guard is a *second opinion* the engine may use to raise an `IN_SCOPE` event to
`REVIEW`, never to clear a deterministic finding. It is off by default, and it is only
consulted when the deterministic rules did **not** find a `VIOLATION`; a decoy read or a
denied exec is paused without a single model call. Two implementations sit behind the
same `guard.Guard` interface:

### `-guard laya` — the Laya decision model

[Laya](https://github.com/convaiinnovations/laya) (convaiinnovations/laya) is a 421M
**non-autoregressive decision model**. It never generates text: you send a `state`
(string or JSON object) plus typed `questions`, and get typed answers with per-option
probabilities and a confidence in one forward pass (~0.2–0.5 s on CPU, 512-token
context on the english checkpoint). It is served by `laya-serve`, whose wire protocol
is TypeSafe Jev's `POST /v1/systemone`:

```sh
# 8000 is the River3 API, so run Laya on 8600 (the controller's default).
LAYA_PORT=8600 LAYA_API_KEY=change-me laya-serve
curl -s http://127.0.0.1:8600/health

RIVER3_GUARD_URL=http://127.0.0.1:8600 RIVER3_GUARD_TOKEN=change-me \
  go run ./cmd/river3-containd -guard laya -guard-min-confidence 0.6 ...
```

Per event the controller makes **two separate calls**, each with one `choice` question
named `verdict` whose options *are* the engine's enum:

- **Channel A** (structural): `state = {"profile", "operation", "outcome", "facts"}`,
  the kernel-observed facts and the profile they are judged against. Never the payload,
  never the event id. Criteria: `CONTINUE` "consistent with the stated profile and
  ordinary for this kind of workload", `WARN_OPERATOR` "unusual for this profile; a
  person should look", `REQUEST_CONTAINMENT` "clear sign of credential access, lateral
  movement, data leaving, or privilege escalation". The serialised state is kept
  ≤ 4096 bytes (normalizer notes are clipped first, then whole fact keys dropped
  largest-first and listed under `facts.truncated`).
- **Channel B** (payload): `state = {"untrusted_text": <payload JSON, ≤ 4096 bytes>}`
  and nothing else. Criteria: "ordinary command or message", "suspicious or
  obfuscated", "plainly an attack or an attempt to disable monitoring".

The reply is accepted only if `answers.verdict` is a `choice` naming one of the three
options we offered **and** its `confidence` (or, failing that, the chosen option's
probability) is ≥ `-guard-min-confidence`. Then — and only then — the adapter sets
`Verified` and the verdict reaches the engine. Everything else (HTTP 4xx/5xx, a 401
from a wrong key, malformed JSON, a wrong question id, an option we did not offer,
low confidence, timeout) is `UNAVAILABLE` + unverified → `UNTRUSTED_GUARD_ASSESSMENT`
→ the event is `UNKNOWN`, not `IN_SCOPE`. Laya has no abstain option; the threshold
is where "unknown" comes from. The server's `model` field is recorded as the guard's
name (`laya:<model>`) on the incident's `facts.guard`.

**The base checkpoint is near chance zero-shot and over-confident.** Until it is
fine-tuned on River3 events, expect verified-but-wrong verdicts at any threshold; keep
`-guard-min-confidence` conservative, run with `on_structural_guard: ALERT` (the
default) so the worst case is a `REVIEW` a person looks at, and treat the guard as
telemetry to collect training data from, not as a decision maker.

### `-guard llm` — any OpenAI-compatible text model

The previous implementation, kept for hosts without Laya: Ollama or any
`/v1/chat/completions` endpoint, a system prompt per channel, `temperature 0`, and a
JSON reply `{"event_id", "verdict"}` that must echo the event id and name one of the
three verdicts. Slower (8 s default timeout) and a text model can be argued with, which
is why Channel B is a separate call that never sees the facts.

### What the guard can and cannot do

- Channel B alone **cannot** contain (engine rule): a payload verdict of
  `REQUEST_CONTAINMENT` is an `ALERT`.
- A Channel A `REQUEST_CONTAINMENT` becomes a containment candidate **only** if the
  profile explicitly opts in with `response.on_structural_guard: PAUSE_CONTAINER`;
  the default is `ALERT`. Nothing here can act without a deterministic violation
  except that opt-in.
- `Verified` is decided in `guard/guard.go` and nowhere else; the model's output
  cannot set it, and a `"verified": true` in the reply is ignored.
- A deterministic `VIOLATION` never waits on the model.

## Files

| Path | Role |
|---|---|
| `registry/` | Trusted enrollment: node tenant/host, sensors (token hashes + capabilities), workloads (profile, full container id, generation, permitted actions, team). From a strict-JSON file, or (`discover.go`) built from labelled containers plus the file's node and sensors. Atomic swap via `Holder`. |
| `normalize/` | river3d facts → `policy.Event`; `policy.Context` from registry + `Inspect`. Controller-side executable classification table. |
| `journal/` | Append-only, fsync'd JSONL: decisions, action states, outbox steps, operator claims. Replayed on start. |
| `adapter/` | `Adapter` interface (+ `Lister` for discovery); `Mock` with failure switches; `Docker` over the Engine API socket (exercised live, see HANDOVER); `Podman` over the libpod socket (fake-socket tests only); `OpenShell` via its CLI. **OpenShell has no generation check**: `sandbox list` exposes only NAME / STATUS / AGE (relative), so the generation is echoed from the mapping file and every `Inspect` carries `adapter.GenerationEchoNote`, which the controller journals under `observed.note`; a sandbox recreated under the same name is not detected by this adapter. |
| `apiclient/` | River3 API client: https/loopback rule, no redirects, bounded retries, two tokens. |
| `controller/` | The loop, operator handling, outbox, registry reload (`reload.go`), HTTP server (`/v1/events`, `/river3/actions`, `/healthz`). `/healthz` reports `journal` stats, `adapter`, `sessions`, `registry` (workloads, sensors, path, reloads, loaded_at) and `registry_error` (`""` = the file on disk is the one in force; otherwise why the last reload was refused — `ok` stays `true` because the previous snapshot is still enforced). |
| `guard/` | The model guard behind one `Guard` interface: `Laya` (laya-serve `POST /v1/systemone`, one choice question per channel, confidence threshold), `LLM` (OpenAI-compatible chat completions, JSON enum reply) and `Mock`. `Verified` is set here only. |
| `cmd/river3-containd/` | Daemon. Secrets from env only. |
| `fixtures/` | Inert synthetic registry, events and an active profile. Fake identities only. |

## Trust decisions (what sets each Context flag)

| Flag | Set only when |
|---|---|
| `SensorAuthenticated` | the event arrived on `/v1/events` with a bearer token whose SHA-256 is in the registry **file** (never a label) |
| `IdentityVerified` | the asset is enrolled, the sensor's container id (if given) equals the enrolled full id, and `Inspect` returns that exact id in the enrolled generation. With `-registry-from-runtime` the enrolled id and generation were themselves read from the runtime's inspect (not from labels), so a restarted container fails this until the next refresh re-enrols it with the new generation |
| `Healthy` / `Active` | identity verified, the container is `running`, enrollment is active, and (if enabled) the sensor's heartbeat is fresh |
| `ResourceVerified` (file) | the sensor is enrolled with `resolves_paths`, marked this path kernel-resolved, and the path is canonical |
| `ResourceVerified` (exec) | the executable path is canonical and comes from a path-resolving sensor; the class is the controller's name table unless the sensor supplied a content hash (see below) |
| `ResourceVerified` (net) | the destination parses as a concrete IP |
| `PermittedActions` | copied from the workload's enrollment: the file, or the `river3.actions` label (default `PAUSE_CONTAINER` for a dedicated `ai_worker`, none otherwise); a label is an administrator statement, with the same validation as the file |
| `AdapterActions` | what the configured adapter advertises |

Anything unresolved stays `false` and is written into the incident reason
("Normalizer: …") so the operator sees why River3 held back.

**Sensor outcomes** (`CONTRACTS.md` §9): `success → SUCCEEDED`, `failed → FAILED`,
`pending → ATTEMPTED`, `blocked → FAILED` with the note `blocked inline by sensor`
(river3d's BPF-LSM hook refused the operation before it happened; the incident still
records the VIOLATION, but `OUTCOME_NOT_SUCCESSFUL` means nothing is paused for an
operation that never took place). Anything else is `UNKNOWN`.

**Executable class and binary identity.** `normalize/classify.go` classifies by the
basename of the kernel-reported path, which a copied binary defeats. A river3d sensor
that hashes `/proc/<pid>/exe` and looks it up in the workload's image sends
`exe_sha256` (plus `exe_dev`, `exe_ino`, `exe_size`, `renamed`, `foreign_binary`) and
a class derived from the file's *content*. When that hash is present, well-formed, the
sensor is authenticated and enrolled with `resolves_paths`, and the class is in the
engine vocabulary, the sensor's class reaches the engine and a disagreement with the
name is recorded as `class from exe hash (sensor): NET_CLIENT; name would be
INTERPRETER`. When `exe_sha256` is absent (older sensors, Falco) the name-based class
is used and overrides the sensor's label exactly as before. The sensor's
`binary_detail` is copied into the incident only when it is a plain label such as
`RENAMED:curl` or `NET_CLIENT:NAME_ONLY`.

## Outcome states

`RESERVED → ABORTED | EXECUTING → VERIFIED | FAILED | UNKNOWN`

- **ABORTED** — `Revalidate` refused (identity, generation, policy version, lease,
  permissions changed). The adapter was never called.
- **VERIFIED** — the runtime, inspected after the call, shows the intended state for
  the same container id and generation. Only this marks the incident `contained`.
- **FAILED** — the runtime does not show it (including "adapter returned OK but
  nothing changed", and the container being gone after a pause).
- **UNKNOWN** — the runtime could not be inspected after the call, or it reported a
  transitional / unrecognised state (podman `pausing`, `stopping`; docker
  `restarting`, `created`) that is neither proof of success nor of failure. Reported
  with `workload_state: unknown`; never as success.

Operator requests have their own durable claim. One left `handling` by a crash is
settled at the next start, and reported either way:

- **resume** is re-executed through the same flow as a fresh request (inspect first:
  already running → `completed`; stale generation → `failed`; paused → unpause and
  verify). It is idempotent, it restores service rather than removing it, and failing it
  would leave frozen a workload an authenticated operator explicitly asked to run.
- **terminate** and **revoke_session** are never re-run after a restart: a kill or a
  revoke happens only when an operator asked for it in the state they were looking at.
  They are settled by inspection only — `completed` if the runtime already shows the
  asked-for state (the call went out before the crash), otherwise `failed` with reason
  `controller restarted mid-action` so the operator can ask again.
