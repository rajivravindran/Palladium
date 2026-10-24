# River3 architecture

River3 answers one question continuously: *is this workload still doing what it was
enrolled to do?* — and when the answer is no, it can stop a dedicated AI worker,
verifiably, and tell a human exactly what happened.

## Components

```
 ┌─────────────── node (Linux host or podman machine VM) ───────────────┐
 │                                                                       │
 │  enrolled container ──syscalls──► kernel ──eBPF──► river3d (sensor)   │
 │                                   ▲                    │              │
 │                     Falco (Mac) ──┘ alerts             │ /v1/events   │
 │                                                        ▼              │
 │                                        river3-containd (controller)   │
 │                                        ├─ normalize: trusted context  │
 │                                        ├─ policy engine (Go library)  │
 │                                        ├─ Laya model guard (optional) │
 │                                        ├─ journal (durable)           │
 │                                        └─ adapter ──► runtime (podman)│
 └──────────────────────────────┬────────────────────────────────────────┘
                                │ machine tokens, HMAC webhooks
                                ▼
                     River3 API (FastAPI + PostgreSQL)          ◄── canary service
                     incidents · actions · audit chain · stream · summaries
                                ▲ operator tokens
                                │
                         operator console (React)
```

| Component | Language | Owns | Never does |
|---|---|---|---|
| `river3d` | Go | observing enrolled namespaces, resolving paths/executables, enrollment → BPF map | decide, contain |
| `policy/` | Go library | deterministic scope rules, response eligibility gates, revalidation | network, subprocesses, state |
| `river3-containd` | Go | trusted context, durable decisions, the only runtime calls, outcome verification, reporting | trust an event's own claims, act without revalidating |
| `api/` | Python | storage, operator workflows, audit chain, alerts, summaries, early-warning tiers (kernel trend + untrusted agent log) | freeze/resume/terminate anything; let the agent's log lower a tier |
| `ui/` | TypeScript | showing and requesting | anything else |
| Laya (`containment/guard`) | Go | two-channel model assessments | set `Verified`, contain on its own |

## The two threats, one engine

A **dedicated AI worker** (`kind: ai_worker`) runs in its own container with a scope
profile: which files it may read/write, which classes of program it may start, which
networks it may reach, and inert **decoy** files it must never touch. Leaving scope is
*agent drift*, and the profile may permit `PAUSE_CONTAINER`.

A **shared business service** (`kind: shared_service`) has the same kind of profile,
but its violations are *external exploit* and the only automatic response the engine
can ever select is `REVOKE_SESSION` of a verified request session — which needs an
application adapter that does not exist yet. Shared services are never paused or
terminated from the console either.

## Event path

1. **Kernel → sensor.** The BPF program records `openat`/`execve`/`connect` on syscall
   *exit* (so every event has an outcome) for mount namespaces in the `watched` map.
   `river3d` resolves the opened path inside the process's own root and confirms the
   executed binary by inode, then emits `Event{facts, payload}`. `facts` is Channel A
   (typed, structural); `payload` (argv) is Channel B and is never read by policy.
2. **Sensor → controller.** `POST /v1/events` with a sensor bearer token whose hash is
   in the controller's registry. That authenticated transport is the only thing that
   sets `SensorAuthenticated`.
3. **Normalize.** The controller builds `policy.Context` from its registry (tenant,
   host, asset, generation, full container id, permitted actions) and a live
   `Inspect` of the runtime. Nothing in the event can set a trust flag. Anything
   unresolved stays unverified and is written into the incident reason.
4. **Laya (optional).** Two model calls, one per channel, return enum verdicts bound
   to the event id. The adapter sets `Verified`; failures become `UNAVAILABLE`.
5. **Evaluate.** The engine returns a `Decision`: status, findings, recommended
   action, blockers, and — only when every gate passes — a `Candidate` with an
   idempotency key and a 5 s lease. Shadow-mode profiles never produce candidates.
6. **Act.** Reserve the key in the journal → refresh the context → `Revalidate` →
   `adapter.Pause(containerID)` → `adapter.Inspect` → record `VERIFIED | FAILED |
   UNKNOWN` (or `ABORTED` if revalidation refused). The adapter's return value is
   never the result; the inspected state is.
7. **Report.** `POST /api/v1/incidents` (attaching to an existing event by id if the
   sensor's history sink stored it first), then `PATCH /api/v1/incidents/{id}/response`.
   Only `VERIFIED` marks the incident `contained`. Reports sit in a journaled outbox
   until the API acknowledges them.

## Human path

An operator with the `act` permission requests `resume`, `terminate`, `resolve` or
`false_positive` with a reason. The first two are queued (`requested`), pushed to the
controller over an HMAC-signed webhook and also pollable; the controller re-checks
ownership and container generation, executes through the same adapter, inspects, and
posts `completed` or `failed`. Every step lands in the hash-chained audit log under the
operator's own name.

## Durability and restart

The controller's journal is an append-only, fsync'd JSONL file replayed at start:
decisions (deduplicated by event id), action states, outbox steps, operator claims.
After a crash, anything left `EXECUTING` is re-inspected and settled; a reserved key
whose adapter call never went out is `ABORTED`; unreported results are flushed. It is a
single-node, single-writer store — not a lease between controllers.

## Scaling

One API worker per container today: the live stream fan-out, the ticket replay cache
and the failed-auth throttle are in-process. To run several API containers behind a
proxy, move those three to a shared store (Redis or PostgreSQL) first; the audit chain
already serializes through a locked head row and is safe across instances. One
`river3-containd` per node; one `river3d` per node (or per Falco instance).

## What is not built

- A real Podman pause has not been run; the adapter is tested against a fake libpod socket.
- `REVOKE_SESSION` has no application adapter.
- Registry reload needs a restart.
- No TLS of its own anywhere: terminate TLS in front of the API and the controller.
