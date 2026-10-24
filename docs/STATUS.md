# Palladium: what's built, what it does, what's pending

_Checked against the code on 20 Oct 2026, updated 21 Oct. Code name in the repo: **river3**._

> ## Update, 22 Oct
> **Evening:** Laya (`convaiinnovations/laya`) is a 421M **decision model**, not a chat model. The controller guard (`-guard laya`) and the drift question (`RIVER3_DRIFT_MODEL=laya|jev`) now use its real protocol (`/v1/systemone`, served by `laya-serve` on port 8600; Jev speaks the same). Unknown is derived from a confidence threshold (0.6). The old chat path survives as `llm`. Tests: API 224, controller 163. **Still not run against the real model**; first step on your machine: `pip install "laya[serve]"`, start it on 8600, run `lab/models/laya_smoke.py`.
>
> **The freeze is proven on real containers.** On the night of 21 Oct the demo ran on a host with Docker: two containers from `river3-lab-base`, the real eBPF sensor, `river3-containd -adapter docker`, two `PAUSE_CONTAINER` actions executed through the Docker Engine API and **VERIFIED** by re-inspecting the containers. Evidence: `docs/evidence/`. Podman itself is still unproven; Docker is now the proven runtime.
>
> **Built since 21 Oct (all tested, all in the folder):**
> - **Session governance (B2, first slice):** sessions on events and logs (gateway, harness or correlated by timing), `POST /api/v1/approvals` with the tier rule (steady → allow, High + risky → hold for a person, Crossed → deny, fail-closed on expiry), operator **Revoke session** with a signed webhook to your gateway or identity provider, a gateway session adapter in the controller, and a reference tool gateway in `lab/gateway/`. Console: Approvals view, session on incidents, Revoke button.
> - **Runtime discovery (B3):** sensor and controller enrol containers by labels (`river3.workload`, `river3.profile`, `river3.kind`) on Docker and Podman; registry hot reload; Docker adapter.
> - **Egress by host and port (B4):** rules like `api.openai.com:443`, `10.0.0.0/8:8000-8100`; the sensor resolves names.
> - **BPF-LSM sensor (B1):** `-source lsm` and `-block-decoys` (inline `-EPERM` on decoy inodes) are built and the compiled object matches the source; **not yet run on a kernel with the bpf LSM**. Without the LSM it falls back to tracepoints and logs it; with `-block-decoys` it refuses to start rather than silently not enforce.
> - **Binary identity (A3):** programs are classified by hash against the container image; renamed and foreign binaries are flagged.
> - **Teams (B7 slice):** team-scoped operators see only their workloads; audit routes stay tenant-wide by design.
> - **Export (B6):** bounded per-workload export of events and agent log for the real benchmark.
> - **Demos (A9):** `demo/run.sh` (real containers, needs Docker + root) and `demo/run-mock.sh` (laptop, mock runtime, replayed events; ran here end to end).
> - **Controller fixes:** engine before Laya, lease after Laya, unknown ≠ failed, heartbeat, torn journal tail, operator action after a crash, double-flush race, policy cache on first start, OpenShell generation note.
> - **Rule tightened:** a model verdict can at most *pause* a dedicated AI worker (explicit profile opt-in); it can never revoke.
>
> **Tests now:** policy 155 cases, sensor 76 (+6 skipped without a live kernel), controller 150, API 216; console builds clean.
>
> **Still open:** A11 console redesign and A12 clickable stat tiles (added 22 Oct after the first hands-on look); A13 enrol from the console (added 24 Oct); A14 sensor reports TCP connection completion (decided 24 Oct; until then out-of-scope egress alerts but is never contained); bugs 19–24 from the 24 Oct lab (egress port rules never match; terminated state survives re-enrolment; unresolved paths only alert; 4–5 s event-to-decision latency; events judged against the policy at processing time; connects carry no protocol, so DNS probes pass for connections); A17 event-to-decision latency and no-drop requirements (R1, R2) and B8 network default-deny (R4), from the 24 Oct requirements "stop out-of-scope actions in time"; B9 language-independent coverage (R6) and B10 deletion, renaming and log tampering (R7), from the 24 Oct code review; L1–L7 (misuse through allowed channels: effects not tools, generated profiles, controlled DNS, shared surfaces, sequence rules, intent, covert channels) recorded 24 Oct and deferred past the YC application; A7 rename; A9 rehearsal; A10 freeze; `-source lsm` live run; Kubernetes; OpenShell event source; HA and SSO; the console still offers REVOKE_SESSION in the structural-guard dropdown (the API rejects it).

> ## Update, 21 Oct
> Two pieces landed on the evening of 20 Oct, after the audit below. Both were reviewed and tested on 21 Oct.
>
> **✅ Early-warning drift tiers (API + console)**
> - `POST /api/v1/agents/{id}/log` takes an agent's own tool-call log (untrusted, capped at 5000 entries per workload). `GET /api/v1/drift[/{id}]` and `POST …/recompute` expose the tier. The Workloads screen shows a tier badge, a trend chart and the reasons.
> - Tier = max of kernel features (failed calls, new resources, writes outside the policy) and log features (injection text, workaround talk, retry streaks, kernel writes missing from the log). Kernel + log agreeing → High. An open prohibited incident → Crossed.
> - **The design rules hold:** logs can only raise a tier; no tier triggers a freeze; no probability is shown; model scoring is **off by default** (`RIVER3_DRIFT_MODEL=off|laya|jev`).
> - **Not built:** the approval gate for risky tools at High. **Synthetic:** the replay report (`lab/drift/report.md`) is a self-test on generated sessions, not a measurement.
> - Tests: `api` now 89 pass; migrations match.
>
> **✅ NVIDIA OpenShell containment adapter**
> - `river3-containd -adapter openshell` stops, starts or deletes an OpenShell sandbox through the `openshell` CLI and reads state back with `sandbox list`. Mock-tested only; the CLI flags are unverified on a real install. "Pause" is a stop, so in-memory state is lost.
> - It's a *containment* adapter. The *event-source* adapter (OpenShell denials feeding the tiers) is still planned.
>
> **🐞 New bugs (added to the lists below)**
> - **15 (high):** one malformed event (`facts.target` not an object) makes every later event, log post and incident for that workload return 500 **after** committing. The controller retries, so incidents and alert webhooks duplicate without end.
> - **16:** drift model calls run inside request handlers (up to 8 calls × 8 s per workload per request).
> - **17:** the `--no-verify` pattern can never match; the words `palladium`, `river3`, `system prompt` raise the tier on ordinary text.
> - **18:** OpenShell's generation check is a no-op (echoed from the mapping file), and a transitional sandbox status is reported FAILED, not UNKNOWN.
> - Yesterday's bugs 1-4 are all still open.
>
> **Plan:** see [PRODUCT_PLAN.md](PRODUCT_PLAN.md) → "Road to 12 Nov: Plan C".

> **How this was checked:** every source file was read, every test suite was run, and the local
> demo (API → controller → console) was run end to end. Nothing here comes from memory.

---

## 30-second version

- ✅ **The core loop works.** An event comes in → the policy engine judges it → an AI worker is frozen (on the mock runtime) → an incident appears in the console → a person resumes or terminates it → everything is in a tamper-evident log.
- ✅ **Everything builds and all tests pass:** 189 test functions (216 test cases) across the four code modules (sensor, policy, containment, API); the console builds clean.
- ⚠️ **Freezing has only ever run against a fake container runtime.** The real Podman adapter exists but has never paused a real container.
- ❌ **"Revoke one session" on a shared service is not built.** For the outside-attacker case, Palladium today can only **alert**.
- ✅ **Early-warning tiers and an OpenShell containment adapter landed on 20 Oct** (see the Update above for caveats).
- ❌ **Kubernetes, SSO, the approval gate and the Palladium name are not in the code yet.**
- 🐞 **18 bugs found; 13 fixed on 21 Oct.** Still open: 5 (journal torn tail), 6 (operator action lost after crash), 7 (double flush orphans), 9 (policy cache on first start), 14 (console JSON tab), and the OpenShell generation echo.

---

## The product in one picture

```
 your container                 your node                                   your control plane
┌──────────────┐   kernel   ┌──────────────┐  events  ┌────────────────────┐  incidents  ┌───────────────┐
│ AI agent  or │ ─────────► │   river3d    │ ───────► │  river3-containd   │ ──────────► │      API      │ ◄── console
│ shared svc   │  openat    │  (sensor)    │          │  normalize         │             │  store, audit │     (browser)
└──────────────┘  execve    └──────────────┘          │  policy engine     │ ◄────────── │  summaries    │
        ▲         connect                             │  pause + verify    │  operator   │  alerts       │
        └──────────────── pause / resume ──────────── │  journal           │  actions    │  policies     │
                                                      └────────────────────┘             └───────────────┘
```

---

## Scorecard: each part

| Part | Folder | Built? | Runs for real? | Tests |
|---|---|---|---|---|
| **Sensor** (eBPF) | `river3d/` | ✅ | ✅ Loaded on a real Linux kernel; sees file opens, program starts, network connects | 26 pass |
| **Sensor via Falco** | `river3d/falco.go` | ✅ | ⚠️ Only tested with saved Falco alerts; real Falco never run | (in the 26) |
| **Policy engine** | `policy/` | ✅ | ✅ Fully working; decides in-scope / violation / review / unknown | 20 + 2 fuzz pass |
| **Replay tool** (`policy-eval`) + reporter | `policy/cmd/`, `policy/report/` | ✅ | ✅ Replays events and can post incidents | 14 pass |
| **Containment controller** | `containment/` | ✅ | ⚠️ Works end to end on the **mock** runtime only | 80 pass |
| **Podman adapter** (real freeze) | `containment/adapter/podman.go` | ✅ | ❌ Never run against real Podman | 2 pass (fake socket) |
| **Laya model guard** | `containment/guard/` | ✅ | ❌ Never run against a real model | 6 pass |
| **API** | `api/` | ✅ | ✅ All endpoints work; migrations match | 47 (74 cases) pass |
| **Qwen3 summaries** | `api/river3_api/summary.py` | ✅ | ⚠️ Fallback path tested; real Qwen not run in tests | (in the 74) |
| **Console** | `ui/` | ✅ | ✅ Builds clean, 0 npm vulnerabilities | — |
| **Policy editor in console** | `ui/src/Policies.tsx` | ✅ | ✅ Edit → save → controller picks it up within 10 s (checked) | (API tests) |
| **Docker deploy** | `deploy/` | ⚠️ | ⚠️ Image has **no console** in it; a few config traps | — |
| **Lab playground** | `lab/playground/` | ✅ | ✅ Sample events produce the expected freeze | — |

---

## What actually happens today, for each threat

### Threat 1: an internal AI agent goes outside its task ✅ mostly works

1. The sensor sees the agent's container open a file, start a program or connect somewhere.
2. The controller checks it against the agent's profile.
3. Out of scope, and the profile is in **active** mode → the container is **paused**, then checked to be really paused.
4. An incident appears in the console with the reason and the facts.
5. An operator resumes or terminates it, with a written reason.

**Proven in the demo today:** an agent connecting to an unknown address was frozen and verified, then resumed from the console.

**Not yet proven:** step 3 on a real Podman container.

### Threat 2: an outsider takes over a shared service ⚠️ detect only

1. Same detection as above: the service does something it never does.
2. The profile says **revoke that one session**, but:
   - no adapter can revoke a session;
   - the sensor doesn't know which session made a request;
   - so the engine downgrades it to **ALERT**.
3. The incident appears in the console. **Nothing is cut off.**

> This is the biggest gap against the website. "Payments keep flowing while the attacker's session is cut" is not true yet. Only the "payments keep flowing" half is.

---

## What's missing

### 🔴 Big gaps (product features)

| # | Missing | Why it matters |
|---|---|---|
| 1 | **Revoke one session** (shared services) | It's the whole response for threat 2. Needs session tracking in the sensor *and* an adapter (e.g. at the proxy or the app's session store). |
| 2 | **Real container freeze** | The Podman adapter has never touched a real container. There's no Docker, containerd or Kubernetes adapter. |
| 3 | **Approval gate at tier High** | Tiers themselves were built on 20 Oct (see Update). Holding risky tool calls for approval is not. |
| 4 | **Agent-log analysis by a model** | Code-only log features exist (20 Oct). Model scoring (`RIVER3_DRIFT_MODEL`) is off by default and untested on a real model. |
| 5 | **Canary credential planting** | Only the *receiving* endpoint exists. Nothing plants decoy keys or watches for their use. |
| 6 | **Approval for risky tools** | The website mentions it. Nothing in the code. |
| 7 | **Teams / per-team views** | Roles are global; there's no "each team sees its own workloads". |
| 8 | **Kubernetes, SSO, HA, VMs/bare metal** | Roadmap on the website. Not started. |
| 9 | **NVIDIA OpenShell event source** | The containment adapter exists (20 Oct). Feeding OpenShell denials into the tiers does not. |
| 10 | **Palladium name** | Every binary, module, env var and screen still says River3. |

### 🐞 Bugs to fix before any pilot

(Plus bug 15 in the next table.)

| # | Where | What goes wrong |
|---|---|---|
| 1 | API canary endpoint | ~~A canary report with `observed_at` crashes with a 500.~~ **Fixed 21 Oct.** |
| 2 | API sign-in throttle | ~~Behind a proxy, 20 bad logins from anyone lock everybody out.~~ **Fixed 21 Oct:** a valid token is never refused; only bad tokens get 429. (The trusted-proxy bypass remains: don't set `RIVER3_TRUSTED_PROXY=true` unless the proxy overwrites `X-Forwarded-For`.) |
| 3 | API workloads | ~~Any sensor token can relabel any workload.~~ **Fixed 21 Oct:** a workload's kind can't change once known (409), and re-registration no longer resets `frozen` to `running`. |
| 4 | Controller + Laya | ~~A slow Laya cancelled every automatic freeze.~~ **Fixed 21 Oct:** the engine runs first, Laya is consulted only when no rule was broken, and the lease starts after Laya answers. |

### 🐞 Other bugs

| # | Where | What goes wrong |
|---|---|---|
| 5 | Controller journal | A half-written last line (power cut) means the controller **can't start** after the next write. |
| 6 | Controller | Operator action lost if the controller crashes mid-action: it's never run or reported. |
| 7 | Controller | Two report flushes at once can mark an incident "orphaned", so its result never reaches the console. |
| 8 | Controller | ~~Heartbeat check could never fail.~~ **Fixed 21 Oct.** |
| 9 | Controller | Policy cache isn't saved on first start from the API, so a restart while the API is down falls back to files. |
| 10 | Controller | Terminate waits up to 10 s for Podman but gives up at 5 s, so it may report "failed" wrongly. (Transitional status now reports UNKNOWN, not FAILED, since 21 Oct.) |
| 11 | API + controller | ~~Delivery id unsigned; canary replayable.~~ **Fixed 21 Oct:** both sides sign `ts.delivery.body`, the delivery id is required, replays are refused. |
| 12 | API | ~~One secret for alerts and actions.~~ **Fixed 21 Oct:** `RIVER3_ALERT_SECRET`, required in production. |
| 13 | API | ~~Conflicting pending actions.~~ **Fixed 21 Oct:** one pending action per incident; none on closed incidents. |
| 14 | Console | Pasting non-profile JSON (like `{}`) in the JSON tab crashes the editor. |
| 15 | API drift (high) | ~~A malformed event poisons its workload.~~ **Fixed 21 Oct:** `facts` shapes are validated (422), drift failures are logged and never fail the request, `drift_history` is capped at 500 per workload. |
| 16 | API drift | ~~Model calls run inside request handlers.~~ **Fixed 21 Oct:** model calls run in the background with a per-workload cache; alerts have a 10-minute cooldown. |
| 17 | API drift | ~~Regex bugs and false positives.~~ **Fixed 21 Oct.** |
| 18 | OpenShell adapter | Generation is echoed from the mapping file, not the runtime. (Transitional status → UNKNOWN since 21 Oct.) |
| 19 | Normalizer (high) | **Egress port rules never match** (found 24 Oct, fix not decided). `containment/normalize/normalize.go` copies the port only into display facts, never into `ev.Port`, and `policy/egress.go` rejects port 0 whenever a rule names a port, so any `cidr:port` or `host:port` rule fails. Fix: set `ev.Port = f.Target.Port` and add a port case to `TestNetConnect`. Until then B4 is hostname-only. |
| 20 | API | **A terminated workload stays "terminated" after it comes back** (found 24 Oct, fix not decided). `upsert_workload` never resets the stored state on re-enrolment: intended so a sensor restart cannot turn frozen into running, but it also applies to a brand-new container with the same asset id. Evidence: notes-agent lab, 24 Oct: after a console Terminate the agent was recreated (`a9414aadf190`), the sensor re-enrolled it, the API still showed `terminated`; manual Terminate ("already terminated") and Resume ("not frozen") are both refused, so an operator cannot stop it by hand. Automatic pause still works (the controller uses its own runtime view) and a pause report corrects the state. Fix idea: reset to `running` when the container generation differs from the one recorded; keep the rule for the same generation. Note: the `workloads` table has no generation column yet, so registration must carry it first. |
| 21 | Sensor / engine (low) | **Unresolved file paths only alert** (found 24 Oct). 38% of lab file events came back `UNKNOWN` / `RESOURCE_NOT_VERIFIED`, almost all failed opens of missing files; they never reach the console. Worth one test: a successful protected read through `/proc/self/root/...`. |
| 22 | Controller (high) | **About 4–5 s from event to decision** (found 24 Oct, notes-agent lab). The controller judges events one at a time, ~22 ms each; a process start produces a couple of hundred file events, so a connect made right after start waits in the queue. Evidence: a Python download connected at 17:54:35.38 IST, the pause decision came at 17:54:39.5, the pause itself took 74 ms; a small page had almost certainly finished downloading before the pause. The 74 ms figure is measured *after* the queue: end-to-end containment is seconds, and data can leave first. To investigate: where the 22 ms goes (API round trip per event, journal sync, normalizer); batching or parallel evaluation; network and exec events ahead of file events. |
| 23 | Controller | **Events judged against the policy at processing time, not event time** (found 24 Oct). A download at 17:49:07 IST happened under active mode; the policy switched to shadow at 17:49:10; the connects were judged at 17:49:12–14 under shadow and not paused. With the lag in 22, a mode or rule change applies to events that happened before it. Mostly a lab hazard today; it matters for audit ("which rule judged this?"). Fix idea: tag each event with the policy revision current when it reaches the controller and judge it against that revision (the bundle `Revision` already exists in `policysync.go`; it is not recorded per decision). |
| 24 | Sensor (high) | **Connect events carry no protocol, so lookup probes look like real connections** (found 24 Oct). One urllib download produced three connects to the same IP and port 443: two instant `success`, one `pending` (errno 115). The pending one is the HTTPS connection; the two successes are most likely glibc `getaddrinfo` address-sorting probes (UDP connect, no packets sent). Unconfirmed: the event has no protocol field. Effect: the 17:54 pause was triggered by a probe, not by the download; a client that connects straight to an IP, or resolves without that probe, would not be paused. Fix idea: `river3d` records protocol (TCP/UDP) and socket type on `net_connect`; the policy treats a UDP connect with no data sent as non-egress and relies on A14 (connection completion) for TCP. |

### 🕳️ Sensor blind spots

The sensor only hooks three system calls (`openat`, `execve`, `connect`), so it misses:
- other ways to open files or start programs (older `open`, `openat2`, `execveat`);
- UDP traffic sent without `connect`, and listening for incoming connections;
- renames, deletes and permission changes;
- **the completion of a non-blocking TCP connect** (24 Oct): `connect()` returns EINPROGRESS, the event stays *pending*, the engine only alerts. Most real clients connect this way, so out-of-scope egress is **not contained** today. Fix planned: PRODUCT_PLAN A14 (sensor watches `sock:inet_sock_set_state`).

It had judged what a program is by its file name; since 21 Oct the class comes from the binary's **hash** against the container image (a renamed `curl` stays NET_CLIENT, an unknown binary is OTHER). Not yet run live. It still has a few path edge cases (very long paths, paths relative to an open folder), and loses sight of a process that creates its own mount namespace.

Details and file references are in `TECHNICAL.md` → "Known limitations".

### 📦 Deploy and docs

- ~~The Docker image doesn't include the console.~~ Fixed 21 Oct (two-stage build); not yet built on a machine with Docker.
- ~~compose principals path.~~ Fixed 21 Oct.
- ~~`host.docker.internal` on Linux.~~ Fixed 21 Oct.
- ~~README pins.~~ Fixed 21 Oct.
- `api/river3_api/auth.py` deleted 21 Oct (run `git rm api/river3_api/auth.py` if git still shows it).
- `PRODUCT_PLAN.md` said "revoke one session: Built". That was wrong and is now fixed.

---

## Website promises vs the code

| Website says | Reality |
|---|---|
| Watches containers from the kernel | ✅ Yes |
| Decoy files trip an alert | ✅ Yes |
| Shadow mode, then active | ✅ Yes |
| Freezes an AI worker and checks it froze | ⚠️ Yes on the mock runtime; never on real Podman |
| Cuts one session on a shared service | ❌ Not built: alert only |
| Early-warning tiers, reads agent logs | ✅ Built 20 Oct (code-only features by default; model off) |
| Risky tools need approval | ❌ Not built |
| Each team sees its own workloads | ❌ Not built |
| Qwen3 summaries, made-up events stripped | ✅ Yes, but only when someone clicks "Generate summary" |
| Laya model guard | ⚠️ Built; never run on a real model |
| Tamper-evident audit log, one-command check | ✅ Yes |
| Your own roles | ✅ Yes |
| Alerts to Slack, Teams, SIEM | ⚠️ One Slack-style webhook only |
| Setup commands `palladium-sensor`, `palladium-controller`, `PALLADIUM_*` | ❌ Don't exist yet. Real names are `river3d`, `river3-containd`, `RIVER3_*`. **Copy-pasting the website's setup won't work.** |

---

## Questions for you (is this what you intended?)

1. **Shared services:** should "revoke a session" happen at a proxy in front of the service, in the app's session store, or by blocking the source IP? This decides what to build.
2. **Runtimes:** Podman first, or Docker / Kubernetes first?
3. **Laya:** in the code it's a *role* (the model guard), and by default it calls the **same** `qwen3:8b` as summaries. Did you want a separate small model for Laya? If so, which one?
4. **Summaries:** should every new incident get a summary automatically, or only when an operator clicks?
5. **Rename:** shall I rename the code to Palladium (binaries, env vars, console) so the website setup works as written?
</content>
</invoke>
