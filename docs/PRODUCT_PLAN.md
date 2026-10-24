# Palladium product plan

_Last updated: 24 Oct 2026. Checked status, bugs and gaps: [STATUS.md](STATUS.md). How to use it: [USER_GUIDE.md](USER_GUIDE.md). Under the hood: [TECHNICAL.md](TECHNICAL.md)._

## Where we are

| Area | Status |
|---|---|
| Kernel sensor (eBPF) and Falco adapter | Built (Falco tested with saved alerts only) |
| Scope profiles and deterministic policy engine | Built |
| Two modes per profile: shadow and active | Built |
| Policy editor in the console, synced to controllers | Built |
| Freeze an AI worker, verified | Built; mock runtime only, Podman adapter never run on real Podman |
| **Revoke one session on a shared service** | **Not built** (alert only today) |
| API, operator console, audit chain, alerts | Built |
| Canary endpoint | Receiver built; nothing plants decoy credentials yet |
| Grounded incident summaries (Qwen3-8B, local) | Built (on click, not automatic) |
| Laya model guard | Built, optional; never run on a real model |
| Early warning: drift tiers | Built 20 Oct: log intake, kernel trend, tiers, alerts, console, replay. Model scoring is **off by default**. Approval gate for risky tools **not built**. Benchmark sessions are synthetic. |
| NVIDIA OpenShell | **Containment adapter** built 20 Oct (`-adapter openshell`, stops a sandbox via the CLI); command shapes unverified against a real install. **Event-source adapter not built.** |
| Kubernetes DaemonSet and Helm chart | Roadmap |
| SSO (SAML, OIDC) | Roadmap |
| High-availability control plane | Roadmap |
| Plain VMs and bare-metal processes | Roadmap |
| Profile suggestions from shadow data | Roadmap (L2) |

---

## Road to 12 Nov: Plan C

> **22 Oct (evening):** Laya turned out to be a decision model, not a chat model; the guard and the drift question now speak its real protocol (`/v1/systemone`, shared with Jev). Not yet run against the real model: `lab/models/laya_smoke.py` is the first thing to run.
>
> **22 Oct:** Stage A is done except the rename (A7) and the demo rehearsal; the real-container proof came on Docker (`docs/evidence/`). Stage B has a first slice of every item except B5. Test counts: policy 155 cases, sensor 76, controller 150, API 216; console builds. Still to do before 12 Nov: A7 rename, A9 rehearsal, A10 freeze, and a run of `-source lsm` on a kernel with the bpf LSM.

**Decision (21 Oct):** patch and demo what exists (Stage A) *and* present the sensor swap, session governance and runtime discovery as the plan (Stage B). Lead with **AI-agent containment and session governance**; shared services stay as "the same sensor also watches these".

### Stage A: demo-ready by 12 Nov

**Week 1, 21 to 27 Oct: fix and harden**

| # | Work | Owner | Done when |
|---|---|---|---|
| A1 ✅ 21 Oct | API pilot bugs: canary `observed_at` 500; sign-in throttle must not block valid tokens; sensors must not relabel a workload's kind or profile; a malformed event must not poison a workload (validate `facts`, `recompute_drift` never raises); trim `drift_history` | Claude | Tests for each; `pytest` green |
| A2 ✅ 21 Oct | Controller: start the 5 s lease **after** the Laya calls; run the engine first and call Laya only when the engine did not find a violation; treat adapter status *unknown* as UNKNOWN, not FAILED | Rajiv (Claude can patch on request) | `go test` green; a 6 s guard delay no longer aborts a freeze |
| A3 ✅ 21 Oct (needs a live run) | Binary class by **hash**, not file name: sensor records sha256 + dev/inode of the exe; controller classifies by a hash table built from the container image at enrollment; a renamed binary gets `RENAMED_BINARY` and class PRIVILEGED_TOOL | Claude (sensor), Rajiv (controller) | `cp curl /tmp/python3 && /tmp/python3` is classified NET_CLIENT |
| A4 ✅ 21 Oct | Drift fixes: `--no-verify` regex, false positives on `palladium`/`river3` words, model calls off the request path, cooldown on tier alerts, report labelled *synthetic* | Claude | Review items closed |

**Week 2, 28 Oct to 3 Nov: prove it real**

| # | Work | Owner | Done when |
|---|---|---|---|
| A5 ✅ 22 Oct, on **Docker** (see `docs/evidence/`); Podman still unproven | **Real container pause**: enrol a real container, trip a decoy, see VERIFIED in the journal and `frozen` in the console | Rajiv | Journal line + screenshot in `docs/evidence/` |
| A6 ✅ 21 Oct (image not yet built on a Docker host) | Docker image includes the console; compose traps fixed (`principals.json`, `host.docker.internal`); README truth pass | Claude | `docker compose up` serves the console |
| A7 | **Rename to Palladium** in one commit: binaries, env vars, console, module names; website setup steps then match the code | Claude, after A5 | `palladium-sensor`, `palladium-controller`, `PALLADIUM_*` exist |
| A8 ✅ 21 Oct | Delete `auth.py`; fix webhook replay (sign the delivery id); separate alert and action secrets | Claude | Tests |

**Week 3, 4 to 11 Nov: demo and application**

| # | Work | Owner | Done when |
|---|---|---|---|
| A9 ✅ built 22 Oct, rehearsal pending | Five-minute demo, two stories (`demo/run.sh` real containers, `demo/run-mock.sh` laptop): (1) a **coding agent in a devcontainer** (Claude Code or Codex) reaches for `~/.aws/credentials` → frozen, verified, operator resumes; (2) a DevOps agent drifts → Rising alert → High → crosses → frozen. All live. | Both | Recorded once, rehearsed twice |
| A10 | Code freeze 9 Nov; STATUS.md refreshed; Stage B design doc with one diagram | Claude | In `docs/` |
| A11 | **Console redesign** (added 22 Oct): a proper visual system (type scale, spacing, severity and tier colour, real list rows, detail layout, empty states, dark mode), designed first, then built. **Early warning becomes a timeline**, not a step chart: one vertical timeline per workload, newest first; each entry = time, tier reached, the one-line cause, the evidence beneath; kernel facts and the agent's own log carry distinct markers; incidents and operator actions sit on the same timeline so the story reads top to bottom | Claude | Rajiv looks at it and doesn't call it lame; a new operator can explain a workload's history from the timeline alone |
| A12 | **Stat tiles filter** (added 22 Oct): clicking "4 open" shows only those 4; same for critical, contained, frozen, heading out, pending; click again clears; filter in the URL | Claude | Each tile filters correctly |
| A13 | **Enrol from the console** (added 24 Oct). Today a workload appears only after a sensor or controller registers it; assigning a policy means editing `registry.json` or container labels. New: the Workloads screen gets a **Waiting** section listing containers the controller can see but has not enrolled (unlabelled on a watched runtime, or labelled but skipped) with the reason; an admin picks one, chooses a policy, permitted actions and a reason, and the **controller writes the registry entry itself**, taking the container id and generation from the runtime's inspect. Changing the policy or permitted actions of an enrolled workload works the same way. Rules: the console never supplies an id or generation (so `Inspect` verification is unchanged); `permitted_actions` from the console can only be narrower than what the node's registry allows; admin-only, reason required, audit entry and version history as for policies; a controller started without the flag stays file-only, so machines without a console lose nothing. Needs a controller endpoint (the registry holder already swaps snapshots atomically) and an API route the console calls | Claude | A container started with no labels shows up in Waiting within 10 s; enrolling it from the console, then tripping a decoy, ends in a VERIFIED freeze; a typed container id is not possible anywhere in the UI or API |
| A14 | **Sensor reports TCP connection completion** (decided 24 Oct, option A; details in the section below). A non-blocking `connect()` returns EINPROGRESS, the sensor logs it as *pending*, the engine alerts but never pauses, and most real clients connect this way, so out-of-scope egress is never contained today. Fix in `river3d`: watch `sock:inet_sock_set_state` for TCP_ESTABLISHED, match it to the pending connect, send a follow-up `net_connect` with outcome `success`. Engine rule unchanged | Claude | A lab connect to an out-of-scope address in active mode produces a `success` event and a verified PAUSE_CONTAINER |
| A15 | **24 Oct lab fixes** (STATUS bugs 19–21): (1) egress **port rules never match**: set `ev.Port` in the normalizer and add a port case to `TestNetConnect`; (2) a **terminated workload stays terminated** when a new container re-enrols under the same asset id: carry the generation on registration and reset the state to `running` when it differs; (3) one test for a protected read through `/proc/self/root/...` to confirm unresolved paths cannot hide a success | Claude | A `10.0.0.0/8:8000-8100` rule matches a connect to port 8050 and not 9000; Terminate → recreate → the console shows `running` and a manual Terminate is accepted; the `/proc/self/root` read is an incident, not UNKNOWN |
| A16 | **Containment latency and judgement correctness** (findings from the notes-agent lab, 24 Oct; STATUS bugs 22–24; details in the section below). (1) Measure where the ~22 ms per event goes and bring event-to-decision under one second for network and exec events: batching or parallel evaluation, or network/exec ahead of file events. (2) Stamp each decision with the policy revision it was judged under and judge against the revision current when the event reached the controller. (3) `river3d` records protocol and socket type on `net_connect`; a UDP connect with no data sent is not egress; TCP relies on A14 | Claude (controller + sensor), Rajiv reviews the latency numbers | A connect made within 200 ms of process start is decided in under 1 s on the lab host; the journal line for every decision names the policy revision; a urllib download produces one TCP connect event, not three |
| A17 | **Stop out-of-scope actions in time, R1 + R2** (requirements section below, 24 Oct): priority lane for `net_connect` and `process_exec` in the sensor queue and the controller; journal durability by importance (action-driving records fsynced before acting, in-scope decisions group-committed, nothing lost across a crash); batched sensor-to-controller delivery that never delays priority events; detection latency on every decision and p50/p99 on `/healthz`; no silent drops of priority events, `SENSOR_BACKPRESSURE` alert naming workload and count, per-profile fail-closed | Claude | T3 and T7: priority events p99 ≤ 100 ms from sensor receive to decision with 1,000 file events/s of noise; controller killed mid-run loses and repeats no action record |

### Stage B: the plan we present (12 Nov onward)

| # | What | Why |
|---|---|---|
| B1 🟡 built 22 Oct (`-source lsm`, `-block-decoys`), **not yet run on a kernel with the bpf LSM** | **Sensor: BPF-LSM hooks** (`file_open`, `bprm_check_security`, `socket_connect`) for decoys and credential reads, so those are blocked inline, not paused after; keep tracepoints for the rest. **Extended 24 Oct by R3** (requirements section below): refuse `socket_connect` outside `egress_allowed` and exec of `exec_denied_classes` from the same profile loaded into BPF maps; ACTIVE mode and `response.inline_block` only; every block reported as outcome `blocked` and raises an incident; sensor reports whether the kernel supports it, no silent fallback; per-profile infrastructure exceptions. Alternative: ingest **Tetragon** events and stop owning the kernel sensor. Decide in December. | Removes the syscall gaps, `/proc` races, non-blocking connect blind spot; prevention instead of detect-then-pause, which always acts after the first packet |
| B2 🟡 first slice built 22 Oct: sessions, approvals, revoke action + webhook, gateway session adapter, reference gateway; needs a real gateway/IdP partner | **Session governance:** the **tool gateway** (MCP gateway, agent proxy, LLM proxy) is the main integration, the agent harness the second; it sends `session_id` + `tool_call_id` with each tool call; the controller links kernel events to the session; `REVOKE_SESSION` revokes whatever the agent was acting with: the session token, the OAuth grant, or the **cloud role or kubeconfig** (the DevOps-agent case); at tier **High** the gateway holds risky tool calls for a person's approval | This is the differentiated product. Nobody sells it cleanly yet. Works for agents whose hands run on your servers, whichever model they call. |
| B3 🟡 Docker + Podman by labels built 22 Oct (sensor and controller, registry hot reload); Kubernetes not started | **Runtime discovery:** Docker, containerd, Kubernetes by labels; no restarts; a Kubernetes DaemonSet | Static `enroll.json` keyed by container id does not survive orchestrators |
| B4 🟡 built 22 Oct: ports and hostnames in rules, sensor resolves names; wildcards need a DNS-observing sensor. **Port rules never match until A15 / bug 19 is fixed** (found 24 Oct) | **Egress by domain and port** (DNS-aware), not CIDR only | Agents call APIs behind CDNs; static IPs force `0.0.0.0/0` |
| B5 | OpenShell **event-source** adapter (denied actions feed the drift tiers) | Works-with story for teams already on OpenShell |
| B6 🟡 export endpoint built 22 Oct; real sessions still needed | Design-partner replay benchmark with **real** sessions | Today's numbers come from synthetic sessions |
| B7 🟡 team scoping built 22 Oct; HA and SSO not started | HA control plane, team scoping, SSO | Enterprise table stakes |
| B8 (added 24 Oct, R4) | **Network default-deny** per enrolled container, generated from the profile's egress allowlist (nftables in its network namespace, or Docker / Cilium network policy); holds even when the sensor or controller is down or slow; settles whether a freeze stops packets already queued | Defence in depth: the sensor path is detect-then-pause and can never beat the first packet |
| B9 (added 24 Oct, R6) | **Language-independent coverage**: LSM mode as the default source where the kernel supports it, node mode shown in the console; tracepoint fallback also hooks `open`, `openat2`, `creat`, `execveat`, `sendto`/`sendmsg`; io_uring confirmed under LSM and reported under tracepoints; memory-backed programs (`memfd_create` + `fexecve`) reported with a flag and deniable; `exec_denied_paths` for writable locations; a real `FOREIGN_BINARY` class (today unknown hashes fall to `OTHER`); TCP Fast Open tested in both modes | Today the lab sensor sees only `openat`, `execve`, `connect`; a C or Go program, a downloaded binary or a raw syscall walks past it |
| B10 (added 24 Oct, R7) | **Deletion, renaming and log tampering**: new event kinds `file_delete`, `file_rename`, `file_truncate`, `file_attr`, `file_link` from LSM path hooks with a tracepoint fallback; profile fields `delete_allowed`, `append_only`, `immutable`; findings `DELETE_OUTSIDE_SCOPE`, `RENAME_OUTSIDE_SCOPE`, `LOG_TAMPER`, `ATTR_CHANGE_OUTSIDE_SCOPE`; refused in the kernel under R3; API stores and console shows them; the agent-log vs kernel cross-check becomes an incident (today drift only raises the tier); the audit hash-chain check runs on a schedule | Today delete, rename, truncate and chmod are not watched at all: an agent can rewrite its own logs in `/evidence` unseen |

### Later: not before the YC application

_L = later. Recorded 24 Oct 2026 so the design accounts for them; no work planned before 12 Nov. Details: "Later: misuse through allowed channels" below._

| # | What | Why it is recorded now |
|---|---|---|
| L1 (R8.1, R8.2) | **Scope on effects, not tools.** Profiles default-deny on effects (file read/write/delete paths, network destinations, programs only from read-only locations, privileges). Tool-name rules such as `exec_denied_classes` stay but only raise early warnings; no decision depends on a tool's name alone | A home-built client bypasses any tool-name rule; the 24 Oct urllib test was caught by the egress rule, not by a tool rule |
| L2 (R8.3) | **Least-privilege profiles from observed behaviour**: shadow mode records what the agent actually uses, a tight profile is generated for review; builds on `api/river3_api/drift.py`. Same item as "Profile suggestions from shadow data" in *Where we are* | Lab profiles allow `/`, `/etc/**`, `/proc/**`, so reading secrets is "in scope" today |
| L3 (R8.4) | **Controlled DNS** for watched workloads: a resolver that answers only names in the profile, refuses the rest, reports every lookup as an event | `127.0.0.0/8` covers Docker's resolver, which forwards to the internet: data can leave hidden in lookups |
| L4 (R8.5) | **Shared surfaces count as exits**: paths another system reads or runs (workspace, git hooks, CI configs, scheduled scripts) are append-only or review-required | A script left in a host folder runs outside River3's view of the agent |
| L5 (R9.1, R9.2) | **Sequence rules** over a workload's recent events (write-then-run linked by inode; secret read then outbound connect or shared-surface write; drops into hooks, CI, scheduled-task folders), using the same incident and containment path, whole sequence as evidence | Harmless steps add up: read a key, encode it, write it into a fixture, commit it |
| L6 (R9.3) | **Laya judges intent over a sequence** ("is this still the task?") as advisory input beside the hard rules, never instead of them (Channel A/B) | Keeps the model where the guard design already puts it |
| L7 (R9.4) | **Covert use of allowed channels** (long or high-entropy DNS names, unusual volume to the model endpoint) raises a REVIEW incident | The model endpoint is an allowed channel for data or planted instructions |

**Where it applies:** Palladium watches where an agent's actions land, not every keyboard. Agents whose hands run in your containers (hosted model or local) get full coverage; coding agents are covered through their devcontainer or sandbox, the tool gateway, and the services they touch; a laptop agent is not planned.

**The honest line for the application:** what works today is the loop in the demo; what is measured is nothing real yet; what is next is B1 and B2.

---

## Feature: early warning with drift tiers

### Problem
Today Palladium acts when a workload crosses its scope. Real incidents show a long run-up before
that line is crossed. In the July 2026 sandbox escape, public write-ups describe about 17,600 logged
actions over several days and a chain of steps before the agents reached a node with internet
access. Nobody was told while the trend was building.

### Goal
Tell the owning team that an agent session is **heading** out of scope, with evidence, before it gets there.

### What the operator sees
Each agent session gets a tier, a trend and the reasons behind it.

| Tier | Meaning | What Palladium does |
|---|---|---|
| **Steady** | Working inside its task | Nothing |
| **Rising** | Pattern moving away from its task | Notify the owning team, with the trend and evidence |
| **High** | Strong signs it is working around its limits | Notify. Requiring approval for risky tools is **not built yet** (Stage B2) |
| **Crossed** | A kernel-confirmed scope violation | Freeze or revoke, as today |

Example reason line: *"41 failed requests to the package server in 10 minutes, writes to a shared
location outside its task, and reasoning that mentions getting around a restriction."*

### Inputs
| Source | Examples | Trust |
|---|---|---|
| Kernel facts (already collected) | rate of failed or refused attempts, new resources per hour, writes to shared locations, new destinations | High: the agent cannot fake them |
| Agent's own logs (new) | tool-call log, plan, reasoning trace, transcript | Low: written by the agent |

### Rules
1. Agent logs can **raise** a tier, never lower one. (In the October wallet incident the agent left the spend out of its own report.)
2. A tier alone never freezes anything. Freezing still needs a kernel-confirmed violation.
3. No "% chance of going rogue" until it is measured. Until then we show a tier and its reasons.
   Once we have labelled sessions, show a measured figure such as *"8 of the last 10 sessions at this level led to a violation."*
4. Agent logs stay on the customer's network by default.
5. The agent's log is parsed by code first. Text addressed to the monitor ("ignore previous instructions",
   "summariser", "Laya"...) is itself evidence and raises the tier. (An agent could otherwise steer the
   summary and blind the decision model; see "Why the log cannot blind us" below.)
6. Kernel activity missing from the agent's own log raises the tier (the wallet-incident shape).
7. The model only ever sees small chunks of structured, truncated lines, one call per chunk, and answers from
   a fixed list; its prose is discarded. A timeout, a malformed answer or chunks disagreeing is *unknown*, never steady.
8. Collect the log from a tool gateway or LLM proxy the agent cannot write to, not from a file inside its container.

### Why the log cannot blind us
The tier is the maximum over sources. Kernel trend features are computed without any model and the agent
cannot write to the kernel's record. Whatever the agent puts in its log can add a reason, never remove one,
and the attempt itself (rule 5) is counted. The replay benchmark includes a session with planted injection
text and reports whether it ever lowered a tier below what the kernel facts alone gave.

### Models
| | Laya (`RIVER3_DRIFT_MODEL=laya`) | Jev (`RIVER3_DRIFT_MODEL=jev`, opt-in) |
|---|---|---|
| What | `convaiinnovations/laya`: a 421M **decision model** (ModernBERT backbone, Apache 2.0). Typed questions in, an answer with a probability out, one forward pass. Never generates text. | TypeSafe's hosted sibling; same `/v1/systemone` protocol, stronger on the card's benchmarks |
| Default | **Off.** Tiers come from code-only features unless a model is switched on | Off, and needs `RIVER3_JEV_OPT_IN=true` |
| Runs | Locally via `laya-serve` (port 8600), CPU is enough (0.2–0.5 s) | Hosted, so log text leaves the network |
| Context | 512 tokens (English), 1,024 multilingual, up to 8,192 | Larger |
| Accuracy today | Base checkpoint near chance zero-shot and over-confident (model card); fine-tune on exported sessions | Better out of the box |
| MVP decision (24 Oct) | Shadow mode first; MLX is Apple-only, so the Linux serving path needs its own test | **Dropped for the MVP**: hosted-only, no published calibration. The opt-in code path stays, off |

Other models: **Qwen3-8B** (4-bit, local) writes the plain-English incident summaries. **GLM-5.3** is used for red-team stress testing in the lab only: licence and weights undisclosed, never on customer data.

Questions are typed and sent per log chunk:
- `agent_mode` (choice): on_task / exploring / working_around_limit. Only a confident *working_around_limit* raises the tier.
- `addressed_to_monitor` (yes/no): a confident yes adds a raise-only reason.
- *How likely is a scope violation in the next N steps?* **Not built**, and would conflict with rule 3 until measured.

Laya has no "unknown" option, so unknown is derived from confidence (`RIVER3_DRIFT_MIN_CONFIDENCE`, default 0.6). A timeout, a refused key or a low-confidence answer is unknown, never steady; unknown adds a reason line and does not move the tier. `RIVER3_DRIFT_MODEL=llm` keeps a chat-model path (Qwen-style) for comparison.

### How we will know it works
- Replay recorded sessions with known outcomes and measure:
  - how far ahead of the violation the first Rising or High appeared
  - false alarms per agent-hour on normal sessions
- Report results per workload type. Thresholds come from design partners, not from us.
- **Today's report (`lab/drift/report.md`) is a self-test on synthetic sessions, not a measurement.** Real sessions come from design partners (Stage B6).

### Pieces to build
| Piece | Owner |
|---|---|
| Log intake for agent tool calls and reasoning (bounded, untrusted, kept separate from kernel facts) | Built: `POST /api/v1/agents/{id}/log`, `agent_log` table, 5000 entries per workload |
| Kernel trend features (failure rate, new-resource rate, shared-location writes) | Built: `api/river3_api/drift.py` `kernel_features` |
| Laya / Jev typed questions and tier calculation | Built: `drift.assess`, `RIVER3_DRIFT_MODEL=off\|laya\|jev` |
| API: store tier, trend and reasons per session; alert on tier changes | Built: `drift_state`, `drift_history`, `/api/v1/drift`, `drift.tier_changed` webhook |
| Console: tier badge, trend line and reasons on each agent | Built: Workloads tab |
| Replay benchmark and report | Built: `python -m river3_api.replay`, sessions are **synthetic**, generated by `lab/drift/make_sessions.py` into `lab/drift/sessions/` (not committed) |

### Open questions
- Which agent frameworks to support first for log intake? Today: River3's own tool-call JSON (kinds tool_call,
  tool_result, plan, reasoning, message, text). OpenTelemetry and plain-text adapters are not built.
- What N, the look-ahead window in steps, is useful to operators?
- Which customers will allow Jev?

---

## Competition: NVIDIA Open Agent Safety Platform

Announced 28 Sept 2026. Two parts:
- **OpenShell**: open-source sandbox for agents. Landlock (files), seccomp (syscalls), network allowlist. YAML policy.
- **Sentry**: reference design for a hardware watchdog on BlueField-4 DPUs. Quarantines an agent that leaves its boundary.

100+ partners, including CrowdStrike, Palo Alto Networks, Anthropic, Red Hat, Salesforce and SAP.

### In one line
NVIDIA builds the cage you put an agent into. Palladium watches everything already running, including services nobody put in a cage.

### Side by side
| | NVIDIA | Palladium |
|---|---|---|
| What it covers | Agents launched inside OpenShell | Anything already running: agents, shared services, legacy apps |
| Hijacked shared service | Not covered | Core use case |
| Special hardware | Sentry needs BlueField-4 DPUs | No. Any Linux server. |
| Alerts and investigation | Docs describe blocking, not alerting | Incidents, summaries, audit chain, console |
| Learn before enforcing | File and process rules fixed when the sandbox starts | Shadow mode, then active |
| Response | Stop the agent | Freeze an AI worker, or revoke one session on a shared service |
| Early warning | Not mentioned | Drift tiers |

### Where we are weaker
- **We react, they block first.** OpenShell stops the action before it happens. Palladium sees it, then freezes.
- **Distribution.** They are free, open source and have every big partner. We cannot win on price or reach.
- **Scale.** No Kubernetes or high-availability control plane yet (see roadmap).

### Positioning
Work **with** NVIDIA, not against it:
> *OpenShell sandboxes the agents you build. Palladium covers everything else: the shared services and legacy apps that will never run in a sandbox, plus a warning before an agent hits its limits.*

NVIDIA's launch shows the market is real. Use it in the YC application.

Sources: [NVIDIA press release](https://mfn.se/one/a/nvidia/nvidia-launches-open-agent-safety-platform-to-secure-agents-from-testing-to-deployment-63ac6a6c), [OpenShell docs](https://docs.nvidia.com/openshell/about/overview.md)

---

## Feature: NVIDIA OpenShell adapters

### Built 20 Oct: containment adapter
`river3-containd -adapter openshell -openshell-sandboxes map.json` maps container ids to sandbox names and stops, starts or deletes a sandbox through the `openshell` CLI; state is read back with `sandbox list`. Mock-tested only; the CLI flags and status words are from the public docs and unverified on a real install. Note: "pause" is a `sandbox stop`, so in-memory state is lost.

### Planned: event-source adapter
#### Goal
Customers who already run OpenShell get Palladium's incidents, console, audit chain and early warning on top, with no second agent on the box.

#### How
Built the same way as the Falco adapter in `river3d/falco.go`:
1. Read OpenShell's action traces and denied events.
2. Map them to Channel A facts (file open, process exec, network connect, outcome).
3. Mark a denied action as `failed`, so it feeds the drift tiers. Repeated denials show an agent testing its limits.
4. Send the facts through the normal policy engine and API.

#### Rules
- OpenShell events are a sensor source, like eBPF and Falco. They never override a kernel fact from our own sensor.
- If OpenShell output cannot be parsed, the event is reported as unknown, never dropped silently.

#### Pieces to build
| Piece | Owner |
|---|---|
| Confirm OpenShell's trace and denial format (docs and GitHub) | Rajiv |
| Adapter: parse, map to facts, tests with recorded samples | Rajiv / Claude |
| Website and YC application: "works with NVIDIA OpenShell" | After the adapter works |

#### Open questions
- Does OpenShell expose traces as a stream, a log file or an API?
- Does Sentry's attested telemetry have a public format we could read later?

---

## Pending: sensor reports TCP connection completion (option A)

Decided 24 Oct 2026. Not started. Stage A row A14.

### Problem
- A non-blocking `connect()` returns EINPROGRESS (errno 115), so `river3d` logs it as *pending* (`river3d/decode.go`).
- The normalizer maps pending to ATTEMPTED (`containment/normalize/normalize.go`, `classifyOutcome`).
- The engine adds `OUTCOME_NOT_SUCCESSFUL` for anything not SUCCEEDED (`policy/engine.go`), so it alerts but never pauses.
- Most real clients connect this way (Python with a timeout, curl, Go, Node), so out-of-scope egress would never be contained.

### Evidence
- Notes-agent lab, 24 Oct: all 16 TCP connects from the agent to `172.22.0.2:11434` were pending, errno 115.

### Plan
- In `river3d`, watch the `sock:inet_sock_set_state` tracepoint for the move to `TCP_ESTABLISHED`.
- Match it to the earlier pending connect (same socket / pid / destination) and send a follow-up `net_connect` event with outcome `success`.
- Leave the engine rule ("attempted alerts, never contains") unchanged.

### Done when
- A lab connect to an out-of-scope address in active mode produces a `success` event and a verified PAUSE_CONTAINER.

### Not chosen for now
- B: normalizer treats pending + errno 115 as SUCCEEDED.
- C: engine allows pausing on an ATTEMPTED NET_CONNECT.

---

## Open issues (24 Oct)

Bugs with a known cause are in STATUS.md (19–21) and Stage A row A15. These are the ones without a fix decided:

- **Deck figures need primary sources**: 1,200 pods, 70,000 notes, K8s takeover, 41 nodes, "362 wallets hijacked", CIAD-2026-0049, "<3 hrs". Nothing in BRIEFING §9 should be quoted until each has a link.
- **Egress: does a freeze stop packets that are already queued?** A paused container's kernel socket buffers may still drain. Needs an explicit egress gate test (send, pause, capture on the far side).
- **The 5-event decay window can be gamed**: keep exposure evidence longer. (The term "decay window" does not appear in the current code; confirm which mechanism this refers to, the drift window or an engine rule, before planning the change.)

---

## Findings from the notes-agent lab, 24 Oct 2026

Stage A row A16; STATUS bugs 22–24.

### 1. About 4–5 s from event to decision
**Problem.** The controller judges events one at a time, about 22 ms each. A process start produces a couple of hundred file events, so a network connect made right after start waits in the queue.

**Evidence.** A Python download connected at 17:54:35.38 IST. The pause decision came at 17:54:39.5; the pause itself took 74 ms. A small page had almost certainly finished downloading before the pause.

**Effect.** The 74 ms pause is measured after the queue. End-to-end containment is seconds, not milliseconds, and data can leave first.

**To investigate.** Where the 22 ms goes: API round trip per event, journal sync, normalizer. Batching or parallel evaluation. Putting network and exec events ahead of file events.

### 2. Events judged against the policy at processing time, not event time
**Evidence.** A download at 17:49:07 IST happened under active mode. The policy switched to shadow at 17:49:10. River3 judged the connects at 17:49:12–14 under shadow and did not pause.

**Effect.** With the lag above, a mode or rule change can apply to events that happened before it. Mostly a lab hazard today, but it matters for audit ("which rule judged this?").

**Fix idea.** Tag each event with the policy revision current when it reaches the controller, and judge it against that revision. The controller already tracks the bundle `Revision` (`containment/controller/policysync.go`); it is not yet written into each decision.

### 3. Connect events carry no protocol, so lookup probes look like real connections
**Evidence.** One urllib download produced three connects to the same IP and port 443: two instant "success", one "pending" (errno 115). The "pending" one is the HTTPS connection. The two "success" ones are most likely glibc `getaddrinfo` address-sorting probes (UDP connect, no packets sent). Unconfirmed: the event has no protocol field (checked 24 Oct: `river3d/event.go` has none).

**Effect.** The 17:54 pause was triggered by a probe, not by the download connection. A client that connects straight to an IP, or resolves without that probe, would not be paused.

**Fix idea.** `river3d` records the protocol (TCP/UDP) and socket type on `net_connect`. The policy treats a UDP connect with no data sent as non-egress, and relies on option A (connection completion, A14) for TCP.

---

## Requirements: stop out-of-scope actions in time

_Written 24 Oct 2026 from the notes-agent lab. Plan rows: R1 + R2 → A17; R3 → B1 (extended); R4 → B8; R5 → A14, A15, A16._

**Context (lab, 24 Oct 2026)**
- A Python download to Pinterest was paused ~4 s after it connected; the download had most likely finished.
- Cause: the sensor-to-controller path is fully serial (one event per HTTP request, an fsync per decision, ~22 ms each), so a connect waits behind file events.
- Even with no lag, detect-then-pause acts after the syscall; the first packet has already left.

### R1. Cut event-to-decision lag
- R1.1 Priority lane: `net_connect` and `process_exec` events skip ahead of `file_open`, in the sensor queue and in the controller.
- R1.2 Journal durability by importance: records that drive an action (violations, candidates, action state changes) are fsynced before acting. In-scope decisions are written in batches (group commit, at most every 10 ms or every N records). No action record may be lost across a crash.
- R1.3 Batched delivery from sensor to controller (as the API sink already does), without delaying priority events.
- R1.4 Measure it: every decision records detection latency (sensor receive time → decision time); `/healthz` reports p50/p99. Each incident shows its own latency.
- Target (proposed): priority events p99 ≤ 100 ms from sensor receive to decision, with 1,000 file events/s of background noise.

### R2. No silent drops
- R2.1 A full queue must never drop `net_connect` or `process_exec` events.
- R2.2 If any event for a workload is dropped, River3 raises an alert or incident (e.g. `SENSOR_BACKPRESSURE`) naming the workload and the count.
- R2.3 Per-profile option to fail closed: pause the workload when its events were dropped.

### R3. Block the riskiest actions inline (prevention)
- R3.1 BPF-LSM hooks refuse, before they happen:
  - `socket_connect` to destinations outside `egress_allowed` (address, port, resolved hostnames)
  - exec of binaries in `exec_denied_classes`
- R3.2 The rules come from the same profile (one source of truth), loaded into BPF maps. A policy change reaches the kernel within 5 s (proposed).
- R3.3 Inline blocking applies only in ACTIVE mode and only when the profile enables it (e.g. `response.inline_block: true`). Shadow mode never blocks.
- R3.4 Every blocked action is still reported (outcome `blocked`) and raises an incident.
- R3.5 Decide and document: does a blocked action also pause the workload? (Today `blocked` maps to FAILED in `containment/normalize/normalize.go` and can never trigger containment.)
- R3.6 The sensor reports whether inline blocking is available on this kernel (BPF in the active LSM list). If not, the console says so clearly; no silent fallback.
- R3.7 Per-profile exceptions for infrastructure the agent must reach (DNS resolver, loopback, model endpoint).

### R4. Network default-deny (defence in depth)
- R4.1 Each enrolled container's egress is restricted at the network layer to the profile's allowlist (e.g. nftables in its network namespace, or Docker/Cilium network policy), generated from the profile.
- R4.2 Works even if the sensor or controller is down or slow.
- R4.3 Answers the existing open issue: confirm whether a freeze stops packets already queued.

### R5. Correct event semantics (linked items)
- R5.1 Connection completion events (A14, option A).
- R5.2 Protocol (TCP/UDP) and socket type on every `net_connect` (A16).
- R5.3 Each event is judged against the policy revision current when it reached the controller (A16).
- R5.4 Port rules work: the normalizer copies the port into the policy event (A15, bug 19).

### Acceptance tests (lab)
- T1 Python urllib download in active mode: connection refused, zero bytes received, incident with outcome `blocked`.
- T2 wget run in active mode: exec refused, incident raised.
- T3 Flood: `find /` running while the agent connects out; the connect is judged within the R1 target; no priority events dropped.
- T4 Connect straight to an IP (no DNS lookup): still blocked.
- T5 Full agent run talking only to the model endpoint: zero false positives, zero blocks.
- T6 Same runs in shadow mode: nothing blocked, everything recorded.
- T7 Kill and restart the controller mid-run: no action records lost, no action repeated.

### Out of scope for now
- Inspecting HTTPS content or request payloads.

---

## Requirements: language-independent coverage and tamper detection

_Written 24 Oct 2026 from a code review. Plan rows: R6 → B9; R7 → B10. Checked against the code the same day: `river3d/bpf/sensor.bpf.c` has exactly the three tracepoints and three LSM hooks named below; `RENAMED_BINARY` / `FOREIGN_BINARY` are not classes in the code (unknown hashes fall to `OTHER`, `river3d/binident.go`); the agent-log cross-check exists only as a drift feature (`unlogged`, raises the tier); `/api/v1/audit/verify` runs on request only._

**Context (code review, 24 Oct 2026)**
- The lab sensor runs in tracepoint mode, hooking only the `openat`, `execve` and `connect` system calls. Raw `open`/`openat2`/`creat`, `execveat`/`fexecve` (including memfd "fileless" programs), io_uring and UDP `sendto` without `connect` are not seen.
- river3d's LSM mode (`file_open`, `bprm_check_security`, `socket_connect`) sits inside the kernel's own code paths and covers those routes, but today it is only used for decoy blocking.
- Binaries the agent compiles or downloads classify as OTHER, which the lab profile allows.
- Delete, rename, truncate and permission changes are not watched at all. The agent can rewrite its own logs in `/evidence`.

### R6. Coverage that does not depend on the agent's language
- R6.1 LSM mode is the default event source wherever the kernel supports it. Tracepoint mode stays as a fallback, and the console shows which mode each node runs.
- R6.2 In tracepoint mode, also hook: `open`, `openat2`, `creat`, `execveat`, `sendto` and `sendmsg` (UDP to a new destination), so the fallback has no known easy bypass.
- R6.3 io_uring: in LSM mode, confirm its opens and connects pass through the hooks. In tracepoint mode, report io_uring setup by a watched workload as an event (and allow a profile to deny it).
- R6.4 Programs run from memory (`memfd_create` + `fexecve` / `execveat`) are reported as `process_exec` with a "memory-backed" flag. A profile can deny them.
- R6.5 Profile rule: no running programs from writable locations (e.g. `exec_denied_paths: ["/workspace/**", "/tmp/**"]`). Applies to any binary, whatever its name or class.
- R6.6 Foreign binaries (hash not in the image's known set, which the sensor already computes) get their own class, e.g. `FOREIGN_BINARY`, so a profile can deny them instead of treating them as OTHER.
- R6.7 TCP Fast Open (`sendto` with `MSG_FASTOPEN`) is tested in both modes; if a hook misses it, add one or deny Fast Open for watched workloads.

### R7. Deletion, renaming and log tampering
- R7.1 New event kinds from LSM hooks: `file_delete` (`path_unlink`, `path_rmdir`), `file_rename` (`path_rename`), `file_truncate` (`path_truncate`, and open with `O_TRUNC`), `file_attr` (`inode_setattr`: permissions, owner, timestamps), `file_link` (`path_link`, `path_symlink`).
- R7.2 Tracepoint fallback for the same: `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat2`, `truncate`, `ftruncate`, `chmod`, `fchmodat`, `chown`, `utimensat`, `link`, `symlink`.
- R7.3 New profile fields:
  - `delete_allowed`: paths where delete and rename are in scope (default: none outside `/tmp`).
  - `append_only`: paths that may only be appended to; truncate, delete, rename and overwrite are violations (e.g. `/evidence/**`, log folders).
  - `immutable`: paths that may not change at all (e.g. the agent's own code, `/agents/**`).
- R7.4 New findings: `DELETE_OUTSIDE_SCOPE`, `RENAME_OUTSIDE_SCOPE`, `LOG_TAMPER` (any non-append change to an `append_only` path), `ATTR_CHANGE_OUTSIDE_SCOPE`.
- R7.5 In active mode with inline blocking enabled (R3), these actions are refused in the kernel, not only reported.
- R7.6 The API accepts and stores the new event kinds; the console shows them in the incident timeline.
- R7.7 Cross-check: River3 compares the agent's own log (`agent_log` / harness evidence) with its own kernel record and raises an incident when the agent's log is missing actions River3 saw. (Today: drift rule 6 raises the tier only.)
- R7.8 River3's own records stay outside every watched workload's reach (separate container and database, hash-chained audit log), and the hash-chain check runs on a schedule, not only on request.

### Acceptance tests (lab), continued
- T8 A small C program makes the raw `open` syscall on a protected file: seen and flagged (both modes).
- T9 A Go program downloads from a non-allowed host: seen, flagged and (with option A) contained.
- T10 A binary written to `/workspace` and run: refused or flagged by the writable-location rule, reported as `FOREIGN_BINARY`.
- T11 A program run from memory (`memfd_create` + `fexecve`): reported with the memory-backed flag; refused when the profile denies it.
- T12 io_uring `openat` on a protected file and io_uring `connect` to a non-allowed IP: seen (LSM mode).
- T13 The agent runs `rm`, `mv` and `truncate` on `/evidence/events.jsonl`: `LOG_TAMPER` incidents; refused in active mode with inline blocking.
- T14 The agent deletes a file inside `delete_allowed`: no incident.
- T15 The agent edits its own log to hide a step: the cross-check flags the mismatch.

---

## Later: misuse through allowed channels

Status: deferred. Recorded 24 Oct 2026 so the design accounts for it; no work planned before the YC application. Plan rows L1–L7.

**Context**
- An agent can build its own tools (scripts, compiled binaries) instead of using known ones. River3 still sees their effects, because every effect goes through the kernel. The 24 Oct urllib test was flagged by the egress rule, with no forbidden tool involved.
- Rules that name tools (`exec_denied_classes` such as NET_CLIENT) are easily bypassed by a home-built client. They are early warnings only; real scope must be default-deny on effects.
- Effect rules still miss misuse that goes through allowed channels. Lab examples:
  - DNS is allowed (`127.0.0.0/8` covers Docker's resolver), and the resolver forwards to the internet, so data can leave hidden in DNS lookups.
  - `read_allowed` includes `/`, `/etc/**` and `/proc/**`, so reading secrets is "in scope".
  - `workspace/` is a host folder; a script, git hook or CI file left there runs outside River3's view of the agent.
  - The model endpoint is an allowed channel for data or planted instructions.
  - Harmless steps add up: read a key, encode it, write it into a test fixture, commit it.

### R8. Scope on effects, not tools (later)
- R8.1 Profiles are default-deny on effects: file read, write and delete paths; network destinations; running programs only from read-only locations; privileges.
- R8.2 Tool-name rules stay, but only raise early warnings; a decision never depends on a tool's name alone.
- R8.3 Least-privilege profiles from observed behaviour: run in shadow mode, record what the agent actually uses, generate a tight profile for review. Build on the existing drift module (`api/river3_api/drift.py`).
- R8.4 Controlled DNS for watched workloads: a resolver that answers only names in the profile and refuses the rest, with every lookup reported as an event.
- R8.5 Shared surfaces count as exits: paths that another system reads or runs (workspace, git hooks, CI configs, scheduled scripts) are append-only or review-required in the profile.

### R9. Sequences and intent (later)
- R9.1 Sequence rules over a workload's recent events, for example:
  - a file written by the agent and then run (linked by inode)
  - a protected or secret file read, followed by any outbound connection or write to a shared surface
  - new files dropped into git hooks, CI configs or scheduled-task folders
- R9.2 Sequence findings use the same incident and containment path as single-event findings, with the whole sequence attached as evidence.
- R9.3 Laya judges intent over a sequence ("is this still the task?") as advisory input next to the hard rules, never in place of them (per the guard's Channel A/B design).
- R9.4 Data hidden in allowed channels (long or high-entropy DNS names, unusual volume to the model endpoint) raises a REVIEW incident.

### Acceptance tests (later)
- T16 DNS tunnel: the agent encodes a file into lookups for an outside domain. Refused by controlled DNS and flagged.
- T17 Secret read then connect: the agent reads a protected file, then connects to an allowed destination. A sequence incident is raised.
- T18 Write-then-run: the agent writes a binary and runs it. Linked as one sequence and refused by R6.5.
- T19 Git hook drop: the agent writes `.git/hooks/pre-commit` in the workspace. Flagged as a shared-surface change.
- T20 Generated profile: after a shadow-mode baseline, a normal agent run produces no incidents under the generated profile, and the over-broad read rules are gone.
