# Palladium user guide

_How to try it, set it up and use it day to day. Matches the code as of 20 Oct 2026._

> **Names:** the product is **Palladium**. The code still uses the code name **river3**, so every
> command, file and setting below says `river3`. That is correct for now.

**Contents**
1. [The idea in 1 minute](#1-the-idea-in-1-minute)
2. [Try it on your laptop (15 minutes)](#2-try-it-on-your-laptop-15-minutes)
3. [The console, screen by screen](#3-the-console-screen-by-screen)
4. [Handling an incident](#4-handling-an-incident)
5. [Writing a policy (scope profile)](#5-writing-a-policy-scope-profile)
6. [People, machines and roles](#6-people-machines-and-roles)
7. [Alerts, canaries and the audit log](#7-alerts-canaries-and-the-audit-log)
8. [The local models: Qwen3 and Laya](#8-the-local-models-qwen3-and-laya)
9. [Setting up on real servers](#9-setting-up-on-real-servers)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. The idea in 1 minute

- **Every workload has a job.** You write that job down as a **policy**: which files it may read and write, which kinds of programs it may run, which networks it may talk to.
- **Palladium watches from the kernel**, outside the workload, so the workload can't hide or lie.
- **Something outside the job** → an **incident**. What happens next depends on the policy's **mode**:

| Mode | What happens |
|---|---|
| **Shadow** (default) | Record and alert. Nothing is stopped. Use this first. |
| **Active** | An **AI worker** is **frozen** (paused), then checked. A **shared service** is never frozen; today it gets an alert. |

- **A person decides.** Resume or terminate, always with a written reason. Everything goes in a log nobody can quietly edit.

### Words you'll see

| Word | Means |
|---|---|
| **Workload** | One container being watched: an AI worker or a shared service |
| **Policy** / profile | The workload's job description (scope) |
| **Incident** | Something out of scope, or something Palladium couldn't judge |
| **Decoy** | A file that should never be opened. Opening one is always critical. |
| **Blocker** | A reason Palladium *didn't* act automatically, e.g. shadow mode |
| **Controller** | The piece on each server that decides and freezes (`river3-containd`) |
| **Sensor** | The piece on each server that watches the kernel (`river3d`) |

---

## 2. Try it on your laptop (15 minutes)

This runs the real API, controller and console with a **pretend container runtime** (mock), so nothing needs root or real containers. It's the quickest way to see the whole loop.

**You need:** Python 3.12+, Go 1.22+ (1.24.7+ to build the sensor in §9), Node 20+.

### Step 1: start the API (terminal 1)
```bash
cd ~/Downloads/river3/api
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.lock
alembic upgrade head
uvicorn river3_api.main:app --reload
```
Check: http://127.0.0.1:8000/api/health shows `{"ok":true}`.

### Step 2: build the console (once)
```bash
cd ~/Downloads/river3/ui
npm ci && npm run build
```
Open **http://127.0.0.1:8000/** and sign in with **`dev-operator-token`**.

### Step 3: start the controller (terminal 2)
```bash
cd ~/Downloads/river3/containment
RIVER3_CONTAINMENT_TOKEN=dev-containment-token RIVER3_POLICY_TOKEN=dev-policy-token \
go run ./cmd/river3-containd \
  -registry ../lab/playground/registry.json \
  -profiles ../lab/playground/profiles \
  -adapter mock -mock-containers registry \
  -api http://127.0.0.1:8000
```
You should see `"msg":"startup","profiles":3 … "adapter":"mock"` and `listening 127.0.0.1:8787`.

### Step 4: send five sample events (terminal 3)
These pretend to be the sensor watching an agent called **my-agent-01**.
```bash
cd ~/Downloads/river3
while IFS= read -r line; do
  curl -s -H 'Authorization: Bearer dev-sensor-token' -H 'Content-Type: application/json' \
       --data "$line" http://127.0.0.1:8787/v1/events; echo
done < lab/playground/events/my-agent.jsonl
```

**What you'll get** (checked on 20 Oct):

| Event | Result |
|---|---|
| reads `/data/input.csv` | ✅ in scope |
| writes to `/out/` | ✅ in scope |
| connects to `10.1.2.3` | ✅ in scope |
| connects to `203.0.113.50` | 🔴 **violation → frozen → verified** |
| opens the decoy SSH key | 🔴 **critical**, alert only (the agent is already frozen) |

### Step 5: play with it in the console
- **Incidents:** two incidents. Open the frozen one.
- Click **Resume**, type a reason. Within about 5 seconds the action shows **completed** and the workload is running again.
- Click **Generate summary**. Without Ollama you get the plain fallback summary (that's fine).
- **Policies:** the list starts empty (this controller reads its policies from files). Click **New policy**, paste `lab/playground/profiles/my-agent.json` into the **JSON** tab, add a comment and save. Edit and save again to get version 2. To have the controller use console policies, restart it with `-profiles-from-api` after adding all three lab policies.
- **Audit log:** every step you just took is there.

### Start again from scratch
Stop everything, then delete `api/river3.db` and `containment/river3-containd.journal*`, and run `alembic upgrade head` again. (The controller remembers event ids, so sending the same file twice just returns the earlier result.)

### Other quick demo: replay without a controller
```bash
cd ~/Downloads/river3/policy
RIVER3_POLICY_TOKEN=dev-policy-token go run ./cmd/policy-eval \
  -report http://127.0.0.1:8000 < examples/events.jsonl
```
The decoy event becomes a critical incident. The other event is judged **unknown** (the replay tool has no live context) and isn't posted. Use `-report-unknown` to post those too.

---

## 3. The console, screen by screen

**Top bar:**
- a **Live** dot: updates arrive instantly; it shows "Polling" if the live stream drops;
- your name and role;
- the **stats strip**: open, critical open, contained, workloads, frozen, pending actions.

| Screen | What you can do |
|---|---|
| **Incidents** | List of incidents: "Needs attention" or "All". Click one for the details (next section). |
| **Workloads** | Read-only table: name, kind, policy, state (running / frozen / terminated), sensor, last update. |
| **Policies** | Create, edit, copy and delete policies; see version history; see which controllers have picked up the latest version. |
| **Audit log** | Every action by a person or machine, newest first. Click to see details. |

**Notes:**
- Only admins can edit policies. The Audit tab and the action buttons are shown to everyone, but a viewer or responder gets a "not allowed" banner when using one they don't have.
- Your sign-in token is kept for this browser tab only and is gone when you close it.

---

## 4. Handling an incident

### Reading it
| Field | Tells you |
|---|---|
| **Severity** | `critical` (decoy or canary), `high` (violation), `info` (needs review) |
| **Threat** | "AI agent left its scope" or "Service behaving outside its scope" |
| **Rule** | The main finding, e.g. `EGRESS_OUTSIDE_SCOPE` (codes below) |
| **Why it was flagged** | Plain-English reason |
| **Automatic response** | What Palladium did, and whether it **verified** it |
| **Policy** row | The engine's decision; "· blocked by …" lists why Palladium *didn't* act on its own (codes below) |
| **Events** | The kernel facts, in order. Command-line text is shown separately because it comes from the workload and can't be trusted. |

### Your four buttons
| Button | When | What happens |
|---|---|---|
| **Resume** | The workload is frozen | The controller unpauses it and checks it's running |
| **Terminate** | AI workers only (the button also shows for shared services, but the request is refused) | The controller stops the container and checks it stopped |
| **Mark resolved** | Open or contained | Closes the incident (record only) |
| **Mark not a threat** | Open or contained | Closes it as a false positive (record only) |

Every button asks for a reason of **at least 8 characters** (the form lets you confirm at 3, but the API refuses anything under 8). The reason goes in the audit log.

### Summary
**Generate summary** asks the local Qwen3 model for a headline, a timeline and an assessment. Each timeline line must point to a real event in this incident; anything that doesn't is removed and flagged. If the model is off, you get a plain summary built from the facts.

### Finding codes
| Code | Means |
|---|---|
| `DECOY_OPEN` | A decoy file was opened (always critical) |
| `PROTECTED_OPEN` | A never-read path was read |
| `READ_OUTSIDE_SCOPE` / `WRITE_OUTSIDE_SCOPE` | File read or write outside the allowed paths |
| `EXEC_CLASS_DENIED` / `EXEC_CLASS_NOT_ALLOWED` | Started a kind of program it shouldn't |
| `EGRESS_OUTSIDE_SCOPE` | Connected to a network it shouldn't |
| `UNRESOLVED_FILE_OPEN` / `UNRESOLVED_DESTINATION` / `UNKNOWN_EXEC_CLASS` | Couldn't tell for sure, so marked unknown |
| `GUARD_A_…` / `GUARD_B_…` | The Laya model guard raised a concern (A = facts, B = untrusted text) |
| `CANARY_CREDENTIAL_USED` | A planted decoy credential was used somewhere |

### Blocker codes (why it didn't freeze)
| Code | Plain words |
|---|---|
| `SHADOW_MODE` | The policy is in shadow mode. **This is the usual one.** |
| `NON_LIVE_EVIDENCE` | The event is a replay or simulation |
| `OUTCOME_NOT_SUCCESSFUL` | The action failed or was only attempted (e.g. a connect still in progress) |
| `WORKLOAD_NOT_READY` | The container isn't running (e.g. already frozen) |
| `IDENTITY_NOT_VERIFIED` | The controller couldn't confirm which container this is |
| `ACTION_NOT_PERMITTED` | The registry doesn't allow this action for this workload |
| `ADAPTER_UNAVAILABLE` | No adapter can do this action. **Every REVOKE_SESSION today.** |
| `NOT_A_DEDICATED_BOUND_CONTAINER` | Freezing is only for a dedicated AI-worker container |
| `STALE_EVENT` / `FUTURE_EVENT` | The event time is too old or in the future |
| `POLICY_VERSION_MISMATCH` | The policy changed between deciding and acting |

---

## 5. Writing a policy (scope profile)

Go to **Policies → New policy**, or edit the JSON files in a `profiles/` folder.

### Fields in plain words
| Field | Plain words | Example |
|---|---|---|
| `name` | Unique name | `my-agent` |
| `kind` | `ai_worker` or `shared_service` | `ai_worker` |
| `mode` | `SHADOW_MODE` (watch) or `ACTIVE_FREEZE_MODE` (act) | start with shadow |
| `decoys` | Files nobody should ever open | `/home/agent/.ssh/id_rsa_backup` |
| `protected_read` | Never read these | `/root/**`, `/etc/shadow` |
| `read_allowed` | May read only these. Leave out = anything except protected. `[]` = nothing. | `/data/**` |
| `write_allowed` | May write only these | `/out/**` |
| `exec_allowed_classes` | Kinds of programs it may start | `INTERPRETER` |
| `exec_denied_classes` | Kinds it must never start | `NET_CLIENT`, `PRIVILEGED_TOOL` |
| `egress_allowed` | Networks it may connect to (CIDR). Empty = none, not even localhost. | `10.0.0.0/8` |
| `response.on_violation` | What to do in active mode | `PAUSE_CONTAINER` (AI worker), `ALERT`, `REVOKE_SESSION` (not built yet) |
| `response.on_structural_guard` | What to do when Laya flags the facts | `ALERT` |

**Path patterns:** `*` matches within one folder level; a trailing `/**` means "everything under this folder".

### Program kinds
| Kind | Examples |
|---|---|
| `DIAGNOSTIC` | `cat`, `ls`, `grep`, `find`, `tar`, `base64`, `ps`, `ip`, `ss` |
| `INTERPRETER` | `sh`, `bash`, `python`, `node`, `perl`, `ruby`, `php` |
| `NET_CLIENT` | `curl`, `wget`, `ssh`, `scp`, `nc`, `rsync`, `pip`, `npm`, `openssl`, `nmap` |
| `PRIVILEGED_TOOL` | `sudo`, `su`, `nsenter`, `mount`, `unshare`, `insmod`, `fdisk` |
| `OTHER` | anything else |

> ⚠️ The kind is decided from the program's **file name**, so a renamed program is judged by its new name. See STATUS.md.

### A safe way to roll out
1. Write the policy in **shadow** mode.
2. Run real work for a few days and look at what shows up.
3. Widen the policy where the work is legitimate.
4. Switch to **active**. The console asks you to tick "I understand…".

### Saving and versions
- Every save needs a comment (8+ characters) and creates a **new version**. Versions only go up.
- **History** shows every version. "Load into editor" + save is how you roll back.
- If someone else saved while you were editing, you'll see a conflict banner.
- You can't delete a policy that workloads still use.

### How a saved policy reaches the servers
- Controllers started with **`-profiles-from-api`** fetch the latest set every 10 seconds and use it only if **every** policy compiles and **every** enrolled workload's policy is there.
- The **Policies** screen shows each controller as up to date, behind, or refused (with the error).
- Controllers started with only `-profiles <folder>` **never** see console edits.

> **Assigning a workload to a policy** is done in the controller's `registry.json` (and the sensor's `enroll.json`), not in the console.

---

## 6. People, machines and roles

### Built-in roles
| Role | For | Can |
|---|---|---|
| `viewer` | people | look |
| `responder` | people | look, act on incidents, generate summaries |
| `admin` | people | everything, including the audit log and policies |
| `sensor` | machines | send workloads and events |
| `policy` | machines | send workloads, events and incidents; fetch policies; report sync |
| `containment` | machines | report responses, pick up operator actions |

You can define your own roles in a JSON file (`RIVER3_ROLES_FILE`); see `api/roles.example.json`.

### Making a login
```bash
cd api && . .venv/bin/activate
python -m river3_api.cli new-token      # prints a token and its sha256
```
- Give the **token** to the person or machine.
- Put only the **sha256** in `principals.json`, like `api/principals.example.json`:
  ```json
  {"name": "oncall-1", "kind": "operator", "role": "responder", "token_sha256": "…"}
  ```

> ⚠️ The development tokens (`dev-operator-token` and the like) work only when no principals file is set, and are always refused in production. Never use them on a shared machine.

---

## 7. Alerts, canaries and the audit log

### Alerts (Slack-style webhook)
Set:
- `RIVER3_ALERT_WEBHOOK=https://…`
- `RIVER3_ALERT_MIN_SEVERITY=high` (`info` | `high` | `critical`)

Each new incident at or above that severity is posted as `{"text": "...", "type": "incident.created", "incident": {...}}`. Canary hits use `"type": "canary.hit"`. If `RIVER3_WEBHOOK_SECRET` is set, it's signed with `X-River3-Timestamp` and `X-River3-Signature`.

### Canary credentials
Plant a fake credential (e.g. a fake database password) inside a workload. When it's **used** anywhere, have the service that saw it call:
```bash
curl -X POST https://<api>/api/v1/canary -H "Authorization: Bearer <policy-role token>" \
  -H 'Content-Type: application/json' \
  -d '{"workload_id":"worker-01","credential":"db_recovery_creds","service":"postgres","source_ip":"10.0.4.7"}'
```
→ a **critical** incident.

**Notes:**
- Palladium does **not** plant or detect the credential itself yet; you need a canary service.
- **Leave out `observed_at` for now**: sending it causes an error (bug, see STATUS.md).

### Audit log check
```bash
cd api && python -m river3_api.cli verify-audit     # or GET /api/v1/audit/verify
```
It prints `{"ok": true, "checked": N, "head": "…"}` if no entry was changed, removed or reordered.

---

## 8. The local models: Qwen3 and Laya

Two very different models, both optional, both off your network with the default settings.

| | Qwen3-8B | Laya |
|---|---|---|
| What it is | A chat model (generates text) | A **decision model** (`convaiinnovations/laya`, 421M parameters, Apache 2.0). It never generates text: you give it a state and typed questions, it answers each with a probability. |
| Used for | Incident summaries | 1. A second opinion on each event (controller guard). 2. The drift tiers' question about the agent's log. |
| Runs on | Ollama (`ollama serve`) | `laya-serve` from `pip install "laya[serve]"`, CPU is fine (0.2–0.5 s per answer) |
| On by default | Yes, falls back to a plain summary if unreachable | No: controller `-guard laya`; drift `RIVER3_DRIFT_MODEL=laya` |
| Can it act? | Never | At most **pause** a dedicated AI worker, and only if the policy opts in with `on_structural_guard: PAUSE_CONTAINER`. Never revoke. Untrusted text can never freeze. |

**Set up Laya (once, on the machine that runs the controller and the API)**
```bash
pip install "laya[serve]"
LAYA_PORT=8600 LAYA_PRELOAD=1 LAYA_API_KEY=<a long secret> laya-serve
# port 8600, not the default 8000: that is Palladium's API port
python lab/models/laya_smoke.py --url http://127.0.0.1:8600 --token <the secret>   # 7 fixed states, prints answers and latency
```
Then:
- controller: `river3-containd … -guard laya` with `RIVER3_GUARD_URL=http://127.0.0.1:8600 RIVER3_GUARD_TOKEN=<the secret>`
- API: `RIVER3_DRIFT_MODEL=laya RIVER3_LAYA_URL=http://127.0.0.1:8600 RIVER3_LAYA_TOKEN=<the secret>`

**Set up Qwen3 (Ollama)**
```bash
ollama pull qwen3:8b && ollama serve     # RIVER3_LLM_BASE_URL defaults to http://localhost:11434/v1
```
On a CPU-only machine use `qwen3:1.7b` or `qwen3:4b` and set `RIVER3_LLM_MODEL` accordingly.

**How "unknown" works with Laya.** Laya has no "don't know" option, so Palladium derives it from confidence: an answer below `RIVER3_DRIFT_MIN_CONFIDENCE` / `-guard-min-confidence` (default 0.6) counts as unknown, which adds a reason line and never moves a tier or a verdict.

> ⚠️ **Accuracy warning from Laya's model card:** the base checkpoint is close to chance on new question types until it is fine-tuned, and it is over-confident. Expect noisy answers at first; the rules above make noise harmless (a model can only raise, never clear). The fix is fine-tuning on your own recorded sessions, which is what the export endpoint and the design-partner benchmark are for.

**Jev** (hosted by TypeSafe) speaks the same protocol as `laya-serve`. `RIVER3_DRIFT_MODEL=jev` with `RIVER3_JEV_URL` (https), `RIVER3_JEV_TOKEN` and `RIVER3_JEV_OPT_IN=true`, because log text then leaves your network.

**Other chat models** for the drift question: `RIVER3_DRIFT_MODEL=llm` uses the Ollama-style endpoint (`RIVER3_LLM_BASE_URL`, `RIVER3_LLM_MODEL`); controller `-guard llm` does the same for the guard.

---

## 9. Setting up on real servers

> ⚠️ **Read first:** the real Podman freeze has never been run. Treat this section as a pilot checklist, and keep every policy in **shadow** until you've seen a real pause work.

### What each server (node) needs
- Linux **x86-64**, kernel ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`), and tracefs mounted.
- **Root** for the sensor.
- **Rootful Podman** with its API socket: `sudo systemctl enable --now podman.socket` (socket at `/run/podman/podman.sock`).

### A. Control plane (API + database)
```bash
cp deploy/.env.example deploy/.env           # fill in POSTGRES_PASSWORD, RIVER3_SECRET_KEY
python -m river3_api.cli new-secret          # use for RIVER3_SECRET_KEY
# create deploy/principals.json BEFORE starting (copy api/principals.example.json, fill in hashes)
docker compose -f deploy/docker-compose.yml up -d
```

**Known traps:**
- The Docker image **does not include the console** yet. Serve `ui/` separately or add `static/` to the image.
- If `deploy/principals.json` is missing when compose starts, Docker creates a folder there and the API won't start.
- On Linux, `host.docker.internal` (used for Ollama) needs `extra_hosts: ["host.docker.internal:host-gateway"]` in compose.
- The API listens on `127.0.0.1:8000`. Put HTTPS (Caddy or nginx) in front, and set `RIVER3_HSTS=true`.

### B. Controller on each node
1. Find each container's full id and start time:
   ```bash
   curl -s --unix-socket /run/podman/podman.sock \
     http://d/v4.0.0/libpod/containers/<name>/json | jq -r '.Id, .State.StartedAt'
   ```
2. Write `registry.json` (copy `lab/playground/registry.json`):
   - `container_id` = full id
   - `generation` = StartedAt
   - `dedicated: true` and `permitted_actions: ["PAUSE_CONTAINER"]` for AI workers
   - the sensor's `token_sha256`
3. Run:
   ```bash
   export RIVER3_CONTAINMENT_TOKEN=… RIVER3_POLICY_TOKEN=… RIVER3_WEBHOOK_SECRET=…
   river3-containd -registry registry.json -profiles profiles/ -profiles-from-api \
     -adapter podman -api https://palladium.example.internal
   ```
   Add `-guard laya` for the model guard.

**Restart needed:** after changing `registry.json` (new containers, a container restart that changes StartedAt).

### C. Sensor on each node
1. Write `enroll.json`:
   ```json
   [{"asset_id":"worker-01","name":"Diagnostic worker 01","profile":"diagnostic-worker",
     "kind":"ai_worker","container_id":"<full 64-char id>"}]
   ```
2. Build and run:
   ```bash
   cd river3d && go build -o river3d .
   export RIVER3_SENSOR_TOKEN=… RIVER3_INGEST_TOKEN=…
   sudo -E ./river3d -source ebpf -enroll enroll.json \
     -controller http://127.0.0.1:8787 -api https://palladium.example.internal
   ```
   - `-stdout` prints every event, which is good for a first look.
   - `-shadow-profiles profiles/` prints policy decisions locally.

**Falco instead of eBPF** (e.g. a Mac with a Podman VM): load `river3d/falco/river3_rules.yaml` into Falco with JSON output, then pipe it in:
```bash
falco -o json_output=true … | ./river3d -source falco -name falco -enroll enroll.json -controller …
```

### D. Switch on
1. Watch in shadow mode.
2. Check `verify-audit`.
3. Set the policy's mode to **Active** in the console.

---

## 10. Troubleshooting

| You see | Likely cause | Fix |
|---|---|---|
| Console says "Polling", not "Live" | Stream dropped | It reconnects by itself; check the API is up |
| Everything is **UNKNOWN** in `policy-eval` | Replay has no live context | Expected; use the controller for real decisions |
| Violation but **not frozen** | Blockers | Read the Blockers line; usually `SHADOW_MODE` |
| Shared-service incident never cuts anything | Revoke isn't built | Expected today: alert only |
| Summary says "fallback" | Ollama not reachable | Start Ollama; check `RIVER3_LLM_BASE_URL` |
| Controller "refused" a policy in the Policies screen | A policy failed to compile, or an enrolled workload's policy is missing | Read the error; add the missing policy |
| `401` from controller | Wrong sensor token, or its sha256 isn't in `registry.json` | Recompute with `printf %s '<token>' \| python -m river3_api.cli hash-token` |
| 429 for everyone | Sign-in throttle tripped (20 bad tokens in 5 min from one IP) | Wait 5 minutes; see STATUS.md bug 2 |
| `/api/docs` is blank | Browser security policy blocks the docs page's scripts | Known; use `pytest`/curl, or relax the policy in dev |
</content>
</invoke>
