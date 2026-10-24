# Containment layer handover

Delivered: 19 October 2026. Scope: the "next bounded task" from `policy/HANDOVER.md`
— trusted normalizer and enrollment/context provider on synthetic fixtures, the
engine integrated with durable decisions and a mocked response adapter — plus the
node-local controller loop around the River3 API contract, with the reliability
requirements (explicit outcome states, verification of the real result, restart and
duplicate handling, authenticated human resume).

## Delivered

`containment/`, a Go module (`river3.local/containment`, standard library only,
`replace river3.local/policy => ../policy`). The policy module is **unchanged**: its
tests still pass, and the controller uses only its exported `LoadProfiles`,
`NewEngine`, `Evaluate`, `Revalidate`, `DecodeStrict` and `report.BuildIncident`.

Against the policy obligations (`policy/AGENTS.md`):

| Obligation | Where it is met |
|---|---|
| Never derive trusted Context from external JSON | `normalize`: every flag comes from the registry, the authenticated sensor's enrolled capabilities or `adapter.Inspect`. Tests: `TestEventCannotClaimTrust`, `TestContainerMismatchBreaksIdentity`, `TestPathTrust`, `TestExecClassComesFromController`. |
| Only enrollment and authenticated normalization establish identity | `registry` (full 64-hex container id + generation required) + `/v1/events` bearer check (`TestEventsEndpointRequiresSensorToken`). |
| Scope by tenant, asset, generation, permissions | Identity is built from node tenant/host + enrolled asset/generation; permissions copied from enrollment; generation re-checked at revalidation and before every operator action (`TestContainerReplacedBetweenEvaluateAndActAborts`, `TestOperatorStaleGenerationIsRefused`). |
| Shared-service containment separate from worker pause | Registry refuses `PAUSE_CONTAINER` on shared services; the adapter advertises only pause, so `REVOKE_SESSION` is blocked with `ADAPTER_UNAVAILABLE` (`TestSharedServiceNeverPaused`). No session adapter exists. |
| No automatic resume or termination | Only operator requests authenticated by the API reach `Resume`/`Terminate`; record-only actions are ignored (`TestRecordOnlyActionsAreIgnored`). |
| Candidate ≠ performed action: persist dedup, refresh, revalidate, fixed adapter, verify | `controller.act`: `journal.Reserve` → `Normalize` again → `Engine.Revalidate` → `adapter.Pause` → `adapter.Inspect` → state. Tests: `TestDecoyOpenPausesVerifiesAndReports`, `TestDuplicateEventNeverPausesTwice`, `TestAdapterReturnsOKButRuntimeUnchangedIsFailed`, `TestInspectionFailureAfterPauseIsUnknown`, `TestExpiredCandidateAborts`. |
| Do not turn an action into a shell command | `adapter.Adapter` takes a container id; Podman adapter speaks the libpod REST API over a unix socket and refuses anything but a full id. |
| Inert fixtures | `fixtures/` uses fake identities, `203.0.113.x` test addresses and the engine's own inert decoy path. |
| gofmt / vet / race | run; see Verification. |

Against the reliability requirements:

- **Outcome states** `RESERVED → ABORTED | EXECUTING → VERIFIED | FAILED | UNKNOWN`
  are journaled and reported verbatim (`response.state`). Only VERIFIED sets the
  incident to `contained` and the workload to `frozen`; UNKNOWN reports
  `workload_state: unknown`.
- **Verification of the real result**: `verify()` decides from `Inspect`, never from
  the adapter's return value; an adapter error is recorded as evidence alongside.
- **Restart handling**: the journal is replayed; EXECUTING actions are re-inspected
  and settled, RESERVED-but-never-called are ABORTED, unreported results are flushed
  (`TestRestartReconcilesInterruptedExecution`, `TestRestartAbortsReservedButNeverExecuted`,
  `TestJournalSurvivesRestartAndKeepsDuplicateProtection`).
- **Duplicate handling**: event id dedup (`RecordDecision`), idempotency-key
  reservation before the adapter call, operator action id claim, webhook delivery id
  replay window (`TestOperatorDuplicateDeliveryHandledOnce`, `TestWebhookVerification`).
- **Authenticated human resume**: resume/terminate are only accepted from the API
  (machine-token poll) or a webhook whose HMAC-SHA256 over
  `"<ts>.<delivery>.<body>"` (`controller.WebhookBase`; changed 21 Oct from
  `"<ts>.<body>"`, in step with `api/river3_api/security.py`) verifies with the shared
  secret, within ±5 min, with a required and never-repeated `X-River3-Delivery` id.
  The node then re-checks ownership and generation and verifies by inspection
  (`TestOperatorResumeUnpausesVerifiesAndReports`, `TestWebhookVerification`,
  `TestWebhookBaseStringMatchesAPIContract`, `TestWebhookReplaySetIsBounded`).
- **API unavailability never blocks containment**: the action happens, the report
  waits in the outbox (`TestAPIOutageDoesNotStopContainmentAndIsRetried`).

### Added 19 Oct (afternoon): Laya, the model guard

*(22 Oct: the chat-completions code described here is now `-guard llm`; `-guard laya`
speaks the real Laya model's systemone protocol — see "Added 22 Oct" below.)*

`containment/guard` fills `Context.Assessments`. Two separate OpenAI-compatible calls per
event — Channel A gets structural facts, Channel B gets the untrusted payload — each
answering `{"event_id", "verdict"}` with an enum. The adapter sets `Verified` only after
checking the schema, the enum and that the echoed event id matches; anything else is
`UNAVAILABLE` + unverified. Wired with `river3-containd -guard laya`
(`RIVER3_GUARD_URL`, `RIVER3_GUARD_MODEL`, `-guard-channels`, `-guard-timeout`); off by
default. Verdicts are recorded on the incident's event facts under `guard`.
Tests: payload-only containment alerts (`TestChannelBAloneCannotContain`), structural
containment needs `on_structural_guard` (`TestChannelAContainNeedsProfileOptIn`),
unverified assessments are untrusted, a model outage does not erase a decoy finding but
turns a benign event `UNKNOWN`, injection attempts in the model output cannot set
`Verified`. Not run against a real model here.

Also: `exec_allowed_classes` of the diagnostic profiles now includes `INTERPRETER`
(the worker is a Python agent); `NET_CLIENT` / `PRIVILEGED_TOOL` remain denied.

### Added 22 Oct: model guard re-pointed onto the real Laya

`containment/guard` now has two implementations behind the same `Guard` interface:

- **`Laya`** (`-guard laya`, new): a client for the real Laya model
  (convaiinnovations/laya), a 421M non-autoregressive *decision* model served by
  `laya-serve`, wire protocol TypeSafe Jev's `POST /v1/systemone`. No prompts, no
  text parsing: each channel is one `choice` question `verdict` whose options are the
  engine's enum (`CONTINUE`, `WARN_OPERATOR`, `REQUEST_CONTAINMENT`) with a one-line
  criterion each; the reply is `{"model", "answers": {"verdict": {"type": "choice",
  "choice", "probabilities", "confidence"}}, "usage"}`. Channel A's state is
  `{"profile", "operation", "outcome", "facts"}` (≤ 4096 bytes; normalizer notes
  clipped first, then fact keys dropped largest-first under `facts.truncated`);
  Channel B's state is `{"untrusted_text": <payload JSON ≤ 4096 bytes>}` and nothing
  else, so the payload has no profile, facts or event id to echo or impersonate.
  `Verified` is set only when the answer is a `choice` naming an option we offered
  **and** `confidence` (or the chosen option's probability when the server omits
  it) ≥ `-guard-min-confidence` (default 0.6, must be in (0, 1]). Laya has no
  abstain option, so the threshold is where "unknown" comes from. Everything else —
  4xx/5xx, 401 bad key, malformed answers, wrong question id, an option we did not
  offer, low confidence, timeout — is `UNAVAILABLE` + unverified, exactly the old
  timeout path (engine: `UNTRUSTED_GUARD_ASSESSMENT`, event `UNKNOWN`). The server's
  `model` is recorded as `Name()` = `laya:<model>` and lands on the incident's
  `facts.guard.name` (the controller re-reads `Name()` after the call).
  `RIVER3_GUARD_URL` default `http://127.0.0.1:8600` (https or loopback http only,
  no redirects), `RIVER3_GUARD_TOKEN` optional bearer (= the server's `LAYA_API_KEY`).
- **`LLM`** (`-guard llm`): the previous OpenAI-compatible chat-completions code,
  renamed (`NewLLM`, `LLMConfig`), behaviour and tests unchanged. `RIVER3_GUARD_URL`
  default `http://127.0.0.1:11434/v1`, `RIVER3_GUARD_MODEL` default `qwen3:8b`.
- `-guard-timeout` now defaults to `0` = the mode's default: **3 s for laya**, **8 s
  for llm**; negatives are refused. `validate` also refuses an unknown `-guard` mode,
  a `-guard-min-confidence` outside (0, 1] and a `-guard-channels` that is not A/B
  (`TestValidateGuardFlags`, `TestGuardTimeoutDefaultsPerMode`).

Tests (`guard/laya_test.go`, httptest fake laya-serve): verified verdict on a
confident CONTINUE / WARN / CONTAIN with the model name recorded
(`TestLayaConfidentAnswersAreVerified`); low confidence, exactly-at-threshold and a
raised threshold (`TestLayaLowConfidenceIsUnverifiedUnavailable`); 400/401/422/500
(`TestLayaHTTPErrorsAreUnverified`); fifteen malformed-answer shapes incl. wrong option
name, lowercase option, `UNAVAILABLE` as an option, `"verified": true` in the reply
(`TestLayaMalformedAnswersAreUnverified`); request body shape pinned — profile + facts
in A's state, four keys only, no argv / payload / event id; one `choice` question with
the three criteria in both channels, structural vs text wording; B's state is the
payload alone (`TestLayaRequestBodyShape`); bounded state both channels
(`TestLayaStateIsBounded`); server down, slow server, no payload → no B call, URL /
threshold rules, redirects refused (`TestLayaDownIsUnavailableNotContinue`,
`TestLayaSlowServerTimesOutUnverified`, `TestLayaNoPayloadNoChannelB`,
`TestLayaConfigRules`). Controller: the existing `guard_test.go` flows still pass
with the mock; `TestLayaEndToEnd` runs the controller against the fake laya-serve: a
decoy violation is paused with zero systemone calls, a benign exec gets two confident
CONTINUEs (verified, `IN_SCOPE`, nothing reported), an under-confident answer makes it
`UNKNOWN`, a confident WARN makes it `REVIEW` with `facts.guard.name =
laya:laya-421m-english`.

#### Model guard: what an operator needs to know

- **What Laya is**: a decision model, not a chat model. It cannot be prompted into
  anything; it picks one of the options we offer and tells us how sure it is.
- **Run it**: `LAYA_PORT=8600 LAYA_API_KEY=... laya-serve` (8000 is the River3 API);
  `GET /health` to check; the english checkpoint has a 512-token context, so the
  4096-byte state budget is an upper bound and the server may see less.
- **Flags**: `-guard off|laya|llm`, `-guard-channels A,B`, `-guard-timeout` (0 = 3 s
  laya / 8 s llm), `-guard-min-confidence 0.6`. Env: `RIVER3_GUARD_URL`,
  `RIVER3_GUARD_TOKEN` (laya), `RIVER3_GUARD_MODEL` (llm).
- **The base checkpoint is near chance zero-shot and over-confident.** Until it is
  fine-tuned on River3 events it will produce verified-but-wrong verdicts at any
  threshold. Keep the threshold conservative, keep `on_structural_guard: ALERT`, and
  use the recorded `facts.guard.assessments` as labelled training data.
- **Nothing here can act without a deterministic violation** except the explicit
  per-profile opt-in `response.on_structural_guard: PAUSE_CONTAINER`, which turns a
  *verified* Channel A `REQUEST_CONTAINMENT` on a live, dedicated worker into a
  candidate that still goes through `Revalidate` and verification by inspection.
  Channel B alone never contains. A model failure never becomes `CONTINUE`.

### Added 21 Oct: review fixes (A2a, A2b, A2c, A8, B2)

- **A2b, deterministic first.** `HandleEvent` runs `Engine.Evaluate` with no
  assessments before anything else. Only when the result is not a `VIOLATION` (and
  `-guard laya` is set) is Laya consulted and the engine re-run with its assessments.
  A decoy read is therefore paused without a single model call
  (`TestDeterministicViolationNeverWaitsOnTheGuard`: 300 ms guard, zero calls,
  VERIFIED). `act()` revalidates with the same `Context.Assessments` the decision
  used (nil when the guard was skipped). The incident's `facts.guard` now records
  `consulted: true|false` plus `assessments` or `reason`.
- **A2a, lease clock.** The candidate lease (`Options.ActionTTL`, 5 s) runs from
  `Context.Now`, which used to be stamped before the guard. Two sequential model
  calls at `-guard-timeout 8s` made every post-guard candidate expire before
  `Revalidate`. `Context.Now` is now re-read after the guard answers; the event's
  `ObservedAt` is untouched, so `STALE_EVENT` still measures true event age
  (`TestCandidateLeaseStartsAfterTheGuardAnswers`, both halves).
- **A2c, transitional runtime state.** `verify()` maps an `Inspect` status of
  `Unknown` to journal `UNKNOWN` (reported `workload_state: unknown`) instead of
  `FAILED`; `Missing` is still `FAILED`
  (`TestTransitionalRuntimeStateAfterPauseIsUnknownNotFailed`, `TestContainerGoneAfterPauseIsFailed`).
- **A8, webhook HMAC.** Base string `"<ts>.<delivery>.<body>"`, `X-River3-Delivery`
  required, replay set bounded at 10 000 ids (see above). Coordinated with the API's
  `sign_webhook`; the two sides must be deployed together.
- **B2, heartbeat order.** The sensor's heartbeat is recorded *after* normalization,
  so the liveness check sees the previous message. A sensor never heard from is
  measured from controller start (`Controller.started`), so a fresh controller does
  not block a sensor's first event, while an hour of silence does
  (`TestSilentSensorBlocksAutomaticAction`, `TestSensorNeverHeardIsMeasuredFromControllerStart`).
- Comment fixes: a Laya timeout is an *unverified* `UNAVAILABLE`, which the engine
  records as `UNTRUSTED_GUARD_ASSESSMENT`, not `GUARD_UNAVAILABLE` (`main.go`,
  `guard.go`). Flag reference for `-profiles-from-api`, `-profile-sync`, `-guard*`,
  `-sensor-heartbeat` added to the README.

### Added 21 Oct (wave 1): review bugs, Docker, runtime discovery, `blocked`

Scope: `docs/CONTRACTS.md` §4.2, §9 and the four confirmed review bugs. Only
`containment/` changed; `../policy` is untouched.

**Review bugs.**

- *Journal torn tail* (`journal.replay`). A crash mid-write left the final line
  either a fragment or a complete record without its `\n`; both were tolerated on
  replay but left in place, so the next append shared the line and the *next* restart
  saw "corrupt record in the middle" and refused the journal. Open now repairs the
  tail before anything is appended: a fragment is truncated away (`ftruncate` on the
  same descriptor, fsync'd), a complete unterminated record gets its newline. Garbage
  with complete records after it is still corruption. Tests:
  `TestTornTailIsTruncatedSoTheNextAppendOwnsItsLine` (torn tail → append → reopen →
  every line parses, record present), `TestUnterminatedCompleteRecordIsKeptAndTerminated`,
  `TestEmptyJournalAndNewlineOnlyTail`.
- *Operator claim lost after a crash* (`controller.reconcileOperator`, from `Start`).
  `ClaimOperator` now journals the request (action, workload, operator, source) with
  the claim; a claim still `handling` at start is settled **by inspection only**:
  `completed` when the runtime already shows the asked-for state (resume → running,
  terminate → exited/missing), otherwise `failed` with reason
  `controller restarted mid-action`; reported through the outbox like any result. The
  mutation is never re-run: an operator action happens only when an operator asked for
  it in the state they were looking at. Tests:
  `TestOperatorClaimStuckInHandlingIsFailedOnRestartAndReported` (journal fixture,
  redelivery is still a duplicate, zero adapter calls),
  `TestOperatorClaimSettledCompletedWhenRuntimeAlreadyShowsIt`,
  `TestOperatorClaimForUnknownWorkloadIsFailedNotGuessed`.
- *Double flush orphans incidents* (`controller.acquire/release` in `outbox.go`).
  `HandleEvent` flushes its own event while the periodic `Flush` (and `Start`'s)
  scans the pending list; two passes seeing `IncidentID == ""` both POSTed, the second
  got 409, retried by id, got 409 again and marked the event **orphaned**, never to be
  retried. A per-key in-flight set (`event:<id>`, `operator:<id>`) makes the second
  pass skip the key; the view is re-read after the key is taken.
  `TestConcurrentFlushNeverDoublePostsAnIncident` runs two concurrent `Flush` 30 times
  against a counting fake API (exactly one POST, no orphan, in-flight set empty after);
  it fails at run 0 with the lock removed. `TestConcurrentOperatorReportIsPostedOnce`.
- *Policy cache not written on first start from the API*. The API/cache selection
  moved from `main.initialPolicy` into `controller.StartupPolicy` (testable) and
  writes `<journal>.policy.json` the moment the API's set is accepted, so a controller
  that started from the API and is restarted while the API is down finds the console's
  policy instead of silently falling back to the shadow example files.
  `TestStartupPolicyWritesCacheWhenTheSetComesFromTheAPI` (written on first start,
  used when the API is down, rejected set neither used nor cached).

**Docker adapter** (`adapter/docker.go`, `-adapter docker`, `-docker-socket`).
Engine API over the unix socket under `/v1.43` (the daemon here is API 1.56, min
1.40; the unversioned path works too but a pinned prefix fixes the response shapes):
`GET /containers/{id}/json` (404 → Missing; generation = `State.StartedAt`; status
running/paused → as is, exited/dead → Exited, created/restarting/removing → Unknown),
`POST /containers/{id}/pause`, `/unpause`, `/stop?t=10` (204 and 304 = success; 409
"already paused" is an adapter error that `verify()` then settles by inspection).
Full 64-hex ids only, keep-alives off, no redirects, 10 s per call. Shared plumbing
with Podman is in `adapter/unixhttp.go`.
**Found live:** `stop?t=10` blocks until the container is dead, and a `sleep` as PID 1
ignores SIGTERM, so the daemon answered after the full grace period and the 10 s HTTP
timeout fired first. Stop calls now get `10 s + adapter.StopGrace`, in Docker **and**
Podman (same latent bug), and the controller's operator terminate call gets
`ActionTimeout + StopGrace` for the same reason. Tests: `TestDockerAgainstFakeSocket`,
`TestDockerStatusMapping`, `TestDockerListEnrolledUsesFilterAndInspectGeneration`
(fake socket), and live `TestLiveDockerPauseInspectUnpauseStopMissing` (run → pause →
inspect paused, cross-checked with `docker inspect` → unpause → stop → rm → Missing),
`TestLiveDockerListEnrolledSeesOnlyLabelledRunningContainers`. Live tests skip
without `/var/run/docker.sock` or the local `river3-lab-base:latest` image.

**Runtime discovery** (`registry/discover.go`, `controller/discovery.go`,
`adapter.Lister`; `-registry-from-runtime`, `-registry-refresh 10s`, `-runtime`).
`GET /containers/json?all=false&filters={"label":["river3.enroll=true"]}` (docker) /
`GET /v4.0.0/libpod/containers/json?all=false&filters=…` (podman), then one inspect
per container so the enrolled generation is the exact `StartedAt` string `Inspect`
will later compare against. Labels → `registry.WorkloadFromLabels` with the §4.1
defaults (name = container name, `dedicated` = ai_worker, `actions` =
`PAUSE_CONTAINER` for a dedicated ai_worker), validated by the same `registry.New`
rules as the file; the file keeps `node` and `sensors` and its `workloads` are ignored
(logged once). Skipped, with a `registry.skipped` warning each: invalid labels, a
profile the active engine does not have (otherwise every event from it would error
and `BuildPolicy` would refuse every policy update), and an asset id claimed by two
containers (both dropped: copying another container's labels must not let it inherit
that asset's permissions). The snapshot is swapped whole with `Holder.Set` only when
its fingerprint (asset/container/generation + skips) changed, with one
`registry.discovered` line naming added/removed/restarted. A listing failure keeps the
last snapshot. `Workload`/`apiclient.Workload` gained `team` (§6, omitempty). Tests:
`registry/discover_test.go` (defaults, refusals, dedupe, fingerprint/diff),
`TestDiscoverySwapsRegistryAndFollowsRestarts` and
`TestDiscoverySkipsUnknownProfileAndKeepsSensors` (fake lister; the discovered worker
is paused through the loop; identical set → same pointer), and live
`TestLiveDockerDiscoveryEnrolsPausesRestartsAndRemoves`: two labelled containers
(ai_worker + shared_service) enrolled from labels, decoy read → **real pause
VERIFIED** (daemon confirms `paused`), second violation alerts only, operator resume
→ running, `docker restart` → stale generation aborts until the next discovery, which
enrols the new `StartedAt` and the worker is paused again, `docker rm` → removed.
Also smoke-ran `river3-containd -adapter docker -registry-from-runtime` offline:
one log line each for add, restart and remove, none on quiet ticks.

**`blocked` outcome** (§9). `normalize.classifyOutcome`: `blocked → policy.Failed`,
note `blocked inline by sensor` (`normalize.BlockedNote`) into the incident reason,
facts `sensor_outcome: blocked`, `blocked_inline: true`. A blocked decoy read is a
VIOLATION held by `OUTCOME_NOT_SUCCESSFUL`, so nothing is paused for an operation the
sensor already stopped. `TestBlockedOutcomeIsFailedWithInlineNote`,
`TestBlockedDecoyOpenAlertsAndNamesTheInlineBlock` (reason text checked on the posted
incident).

**OpenShell generation echo.** `Info` gained `Note`; the OpenShell adapter sets
`adapter.GenerationEchoNote` on every `Inspect` because `sandbox list` exposes no
creation time (AGE is relative), and `verify()` copies the note into
`detail.observed`, so the weaker evidence is visible in the journal and the incident.
Documented in the type comment: a sandbox recreated under the same name is **not**
detected by this adapter. No live test possible here.

**Not done in this wave** (contract items for containment still open):
`-sessions-from-api`, the `gateway` session adapter / `REVOKE_SESSION`, domain egress
refresh (`-egress-refresh`), operator `revoke_session`. Known edge with discovery: an
incident for a workload that was un-enrolled before the outbox posted it waits in the
outbox (`ensureWorkload` needs the enrolment for the API record); it posts again if
the container comes back under the same asset id.

### Added 22 Oct: review follow-ups and registry hot reload (§5)

Of the six items on the 22 Oct list, four were already in the tree from wave 1
(torn tail, in-flight flush set, policy cache on first start, OpenShell generation
note); each was re-checked by disabling the fix and watching its test fail, and the
gaps were closed:

- **Journal torn tail**: the review's exact scenario added as
  `TestTwoRecordsPlusTornFragmentThenAppendReopensWithThree` (two records + fragment →
  Open → append → Close → Open = 3 records); fails without `truncateTo`.
- **Operator claim after a crash** (`reconcileOperator`): rule changed from
  "inspection only for everything" to **resume is re-executed, terminate / revoke never
  are**. Resume goes through `runOperator` exactly like a fresh request (already running →
  completed with no call; stale generation → failed, untouched; paused → unpause, verify),
  so it is idempotent and bounded by the same checks; failing it left a workload frozen
  that an authenticated operator had asked to run. Terminate and revoke stay
  inspection-only (completed if the runtime already shows it, else failed
  `controller restarted mid-action`) because a kill or a revoke must only happen in the
  state the operator was looking at. Tests:
  `TestOperatorResumeClaimIsReExecutedOnRestartAndReported` (exactly one resume call,
  redelivery still a duplicate), `TestOperatorResumeClaimOnStaleGenerationIsFailedNotForced`,
  `TestOperatorTerminateClaimIsFailedOnRestartAndNeverReRun` (zero adapter calls, reported),
  `TestOperatorClaimSettledCompletedWhenRuntimeAlreadyShowsIt` (no call when already running).
- **Double flush**: the in-flight set and its 30-iteration test were already there
  (`TestConcurrentFlushNeverDoublePostsAnIncident`, fails at run 0 without the lock).
  Checked the API's 409 body for an incident id: `POST /api/v1/incidents` answers
  `{"detail": "event <id> already belongs to <incident_id>"}` — a human-readable message,
  not a field. Parsing it would couple the controller to message text, so the second
  409 still orphans (loud, final, with the reconciliation hint); with the in-flight set
  the controller itself can no longer cause that race. If the API ever returns the id as
  a field, link to it there instead of orphaning.
- **Policy cache on first start**: already fixed (`StartupPolicy`,
  `TestStartupPolicyWritesCacheWhenTheSetComesFromTheAPI` fails without the save).
- **Registry hot reload** (`controller/reload.go`, `-registry-reload 5s`, SIGHUP; CONTRACTS
  §5). `RegistryReload{Path, Every, Discovery}` attached with `WatchRegistry` (records
  the start-up stat), `ReloadRegistry` (unconditional, SIGHUP), `PollRegistry` (mtime or
  size changed), `RunRegistryReload(ctx, hup)`. The file is read with `registry.LoadFile`
  + `registry.New` (whole-file validation) and additionally refused if a workload names
  a profile the enforced set lacks (mirror of BuildPolicy's rule; otherwise every event
  from it errors and every later policy sync is refused). Swap is `Holder.Set`; one
  `registry.reloaded` line with `registry.Compare` (added / removed / changed asset ids
  by full-field comparison, sensors added / removed by name). A rejected file keeps the
  previous snapshot, logs `registry.rejected`, and `/healthz` carries `registry_error`
  plus a `registry` block (path, reloads, loaded_at, poll). The stat is recorded before
  parsing so a rejected file is not re-parsed every tick. With `-registry-from-runtime`
  the reload installs the file as the discovery base (`Discovery.rebase`, now mutex
  guarded) and runs one discovery pass, so sensors change while workloads keep coming
  from the runtime. Verified that every reader goes through `Holder.Get` per request
  (normalizer, operator path, `/v1/events` authentication, outbox `ensureWorkload`,
  policy sync); the API-registration memo (`enrolled`) is cleared for changed/removed
  assets. Tests: `TestRegistryReloadEnrolsNewWorkloadAndNeverSwapsInAnInvalidFile`
  (v1 unenrolled → v2 reload → new workload paused and resumable → invalid v3 refused,
  pointer-identical registry, `registry_error` set, not re-read while unchanged → unknown
  profile refused → valid v5 applied, error cleared, removed workload alert-only),
  `TestRegistryReloadOnSIGHUP` (signal channel, poll off),
  `TestRegistryReloadPollPicksUpAnEditAndKeepsV2OnABadV3` (ticker, half-written JSON),
  `TestRegistryReloadWithDiscoveryReplacesSensorsOnly`,
  `TestRegistryReloadCompareNamesEveryKindOfChange`. Smoke-ran the daemon: poll picked up
  a bad edit (rejected, `/healthz` error) then a good one (payments-01 removed), SIGHUP
  reloaded on demand.
- **Small**: OpenShell `sandbox list` has no creation time or id column, so the
  generation stays echoed; `TestOpenShellLifecycle` now asserts `GenerationEchoNote`, and
  the README names the limitation. `main.validate` refuses `-poll`, `-flush`,
  `-profile-sync`, `-registry-refresh`, `-session-sync`, `-guard-timeout` ≤ 0 and negative
  "0 = off" intervals before anything is opened (`time.NewTicker` panicked after
  start-up); `cmd/river3-containd/main_test.go`.
- Also fixed in passing: `TestSessionChangedBetweenEvaluateAndActAborts` (wave 2) swapped
  the session on the *second* inspection, but `Normalize` reads the session map before it
  inspects, so act()'s refresh had already bound sess-1; the hook now swaps on the first
  inspection. `harness_test.go` was not gofmt-clean. `TestPolicySyncKeepsLastGoodSet`
  matched the engine's full egress error text, which `../policy` (being edited in
  parallel on 22 Oct) reworded; it now matches only the stable `invalid egress rule "nope"`
  prefix.

**Verification, 22 Oct (Go 1.24.7, `GOFLAGS=-mod=mod`):** `gofmt -l .` clean,
`go vet ./...` clean, `go test -count=1 ./...` every package ok,
`go test -race -count=1 ./journal ./controller ./registry` ok; 150 top-level test
functions. `../policy` untouched by this wave.

## Verification

Environment: Go 1.24.7, Linux amd64, Python 3.13 for the API.

**21 Oct (wave 1), this sandbox (Go 1.24.7, Docker 29 / API 1.56, image
`river3-lab-base:latest`):** `gofmt -l .` clean, `go vet ./...` clean,
`go test -count=1 ./...` all packages ok, `go test -race -count=1 ./controller
./journal ./adapter ./registry` ok. Live tests that ran: `TestLiveDockerPauseInspectUnpauseStopMissing`,
`TestLiveDockerListEnrolledSeesOnlyLabelledRunningContainers` (adapter),
`TestLiveDockerDiscoveryEnrolsPausesRestartsAndRemoves` (controller). Every container
they create is removed in `t.Cleanup`. Earlier verification below is from 19 Oct.

- `gofmt -l .` clean; `go vet ./...` clean.
- `go test -race -count=1 ./...`: all packages pass. **82 test/subtest passes**
  across 63 top-level test functions. Statement coverage: controller 84.0%,
  journal 86.0%, normalize 82.6%, apiclient 82.8%, registry 71.6%, adapter 58.9%;
  **74.3% total** (the daemon `main` has no unit test).
- `../policy`: `go test ./...` still passes; no file in it was modified.
- `api/`: `pytest -q tests` → **37 passed**.
- **Live end-to-end** against the real FastAPI hub (`uvicorn`, SQLite, dev
  principals, `RIVER3_ACTION_WEBHOOK` pointing at the daemon) with the mock runtime:
  - benign read → `IN_SCOPE`, nothing posted;
  - decoy open → `VIOLATION`, candidate, pause **VERIFIED** in 0.011 ms (mock),
    incident `contained`, workload `frozen`, response payload carries the idempotency
    key and the inspected state;
  - the same event replayed → `duplicate=true`, no second adapter call;
  - `curl` exec with the sensor claiming `DIAGNOSTIC` → controller classifies
    `NET_CLIENT`, `VIOLATION`, held at `ALERT` by `WORKLOAD_NOT_READY` (the container
    was already paused) — the reason text names both facts;
  - operator `resume` via the console API → delivered over the signed webhook →
    unpaused → **completed** with `workload_state: running`; audit chain verifies
    (`/api/v1/audit/verify` ok, 6 rows: workload.upsert, incident.create,
    incident.response, incident.create, operator.resume, action.completed);
  - daemon restarted on the same journal → 3 events / 1 verified action replayed,
    the decoy event replayed again → duplicate, zero new actions.

These checks establish bounded behaviour with a **mocked runtime**. No real
container was paused.

## Review decisions

- A sensor's `path_resolved` bit is accepted as evidence only from a sensor whose
  enrollment says `resolves_paths`; the bit alone never verifies a resource.
- The executable class that reaches the engine is the controller's own table applied
  to the kernel-reported path, unless the sensor supplied `exe_sha256` and a class
  derived from the file's content (see README, *Executable class and binary
  identity*); then the content wins and the name-based class is noted alongside. A
  disagreement is always written into the incident.
- Tenant and host are node configuration. An event cannot name a tenant.
- A paused container is not `Active`, so a second violation on an already-paused
  workload alerts instead of producing another candidate. This is the intended
  behaviour, not a gap.
- The journal is a single-node, single-writer file. It is **not** a lease shared
  between controllers. Two controllers on one runtime would race.
- On a `409 duplicate event id` when embedding the event, the controller retries once
  with `event_ids` (the sensor's own history sink usually stores the event first).
  Only if the event already belongs to another incident is it marked **orphaned**
  and never retried: the controller cannot learn that id (machine roles have no read
  permission). Logged at ERROR with a reconciliation hint. Found in the live run with
  `river3d` feeding both the controller and the API: 1897 orphans before, 0 after.
- Operator actions are fanned out by the API to every controller; a controller
  silently ignores workloads it has not enrolled instead of failing them.
- `terminate` is `podman stop` (graceful, 10 s), not `kill` or `rm`. The container
  remains inspectable after the fact.

## Not done / remaining obligations

1. **Real runtime.** ~~Not yet~~ — done 21 Oct for **Docker**: a real container was
   paused, verified, resumed, restarted (stale generation refused, then re-enrolled)
   and removed through the controller loop (`TestLiveDockerDiscoveryEnrolsPausesRestartsAndRemoves`).
   `adapter.Podman` is still tested only against a fake unix-socket server; the stop
   timeout fix found live on Docker was applied to it as well. Enrollment for a real
   container needs `generation` equal to `State.StartedAt`, which
   `-registry-from-runtime` now does automatically.
2. ~~Sensor wiring~~ — done 19 Oct: `river3d -controller URL` posts to `/v1/events`
   with `RIVER3_SENSOR_TOKEN`, carrying `workload.container_id`. Exercised live
   (eBPF on Linux, Falco alerts from a fixture) through this controller.
3. **Shared-service revocation** needs its own application adapter and request→session
   attribution. Nothing here advertises `REVOKE_SESSION`; the engine blocks it.
4. ~~Channel B / model assessments are not attached~~ — done 19 Oct; consulted only
   for non-violations since 21 Oct; re-pointed onto the real Laya model's systemone
   protocol 22 Oct (`-guard laya`; the text-model path is `-guard llm`). Still not run
   against a real `laya-serve`, and the base checkpoint needs fine-tuning before its
   verdicts mean anything (see "Model guard: what an operator needs to know" above).
5. ~~Registry reload~~ — done 22 Oct: `-registry-reload` (mtime poll) and SIGHUP reload
   the file in both modes (workloads from the file, or node + sensors with
   `-registry-from-runtime`). An API-driven enrollment push is still not a thing.
6. **Transport security**: the daemon listens on loopback by default without TLS.
   Off-host sensors or webhooks need a TLS terminator in front, and the API must use
   `https://` for the webhook URL in production (the API enforces this).
7. **Heartbeat liveness** (`-sensor-heartbeat`) is implemented but off by default
   because no sensor is sending yet.
8. The daemon `main` has no automated test beyond the live run above.
