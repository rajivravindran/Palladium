# Policy engine handover

Delivered: 19 October 2026. Assigned scope: implement a policy engine using the
uploaded Go profile schema and River3 response boundaries.

## Delivered

An importable Go library with immutable compiled profiles; deterministic file,
execution and egress checks; structured findings; response eligibility gates;
model recommendation handling; candidate expiry/idempotency/revalidation; strict
JSON profile loading; and a shadow-only JSONL replay command.

The supplied file was `package main` with an unexported loader. This module uses
`package policy`, exports `LoadProfiles`, and adds optional profile fields. It is
not a drop-in single-file replacement for an unseen Go application. Original
profile JSON keys are retained, including read-denylist behaviour when the new
`read_allowed` field is absent. Original uploaded files were not overwritten.

The Python Stage 0 contracts remain unchanged. They do not yet express every Go
field or `REVOKE_SESSION`; integrate through an explicit contract update. Do not
pretend this standalone module is already wired into the full application.

## Verification

Environment: Go 1.27.2, Linux amd64. Downloaded the official Go archive and
checked its SHA-256 against the go.dev download metadata. The development
toolchain, caches and generated binaries are excluded from the deliverable.

- `go test -race -coverprofile=build/coverage.out ./...`: both packages passed.
  Core library statement coverage: **88.3%**. Replay command: **74.4%**.
  Combined coverage: **86.9%**. No race reported in the exercised paths.
- `go test -json ./...`: **99 test/subtest passes**, including 24 top-level test
  functions and seed execution for two fuzz targets. No failed test records.
- `go vet ./...`: passed with no diagnostics.
- `go test -run '^$' -fuzz FuzzGlobBoundary -fuzztime 3s -parallel 2`:
  passed, **40,198** executions in this run.
- `go test -run '^$' -fuzz FuzzDecodeStrict -fuzztime 3s -parallel 2`:
  passed, **75,927** executions in this run.
- Offline replay exercised the supplied two-event fixture. The decoy produced
  a pause recommendation but only an alert action and no candidate, because
  the CLI remains untrusted shadow replay. Ordinary replay also reports its
  missing trusted context explicitly rather than claiming live protection.
- Cross-compilation for macOS ARM64 succeeded with `GOOS=darwin GOARCH=arm64
  CGO_ENABLED=0 go build -buildvcs=false ./cmd/policy-eval`. The generated binary
  was not run on a Mac and is excluded from this source package.

These tests establish bounded implementation behaviour, not production efficacy
or assurance against all bypasses. No Falco/Podman adapter, live pause, model call,
remote session revocation, notification or Mac runtime execution was tested.

## Review decisions

- Unknown resources and ambiguous paths are reviewable gaps, not silently allowed.
- Do not use path.Clean to convert an ambiguous path into a trusted allowed path.
- Decoys override read allows; execution deny overrides allow.
- Model failure does not erase a deterministic decoy finding.
- Channel B alone cannot contain; Channel A containment is explicitly configured.
- Failed/attempted actions alert instead of automatically containing in this version.
- Every automatic candidate requires live successful fresh evidence, verified
  identity and resource attribution, active/healthy enrollment, a matching policy
  version, current permissions and a supported adapter.
- Shared-service revocation requires an actual verified session binding; no
  process-wide guess or source-IP-derived identity is acceptable.
- Revalidation catches changed identity, generation, policy, evidence, expiry and
  permissions. It does not itself make the final runtime call atomic or supply
  authentication, signatures, durable idempotency or a generation lock.

## Next bounded task

> **Status 19 Oct 2026:** the normalizer, context provider, durable decisions, mocked
> adapter and node controller are delivered in `../containment/` (see its HANDOVER.md).
> The remaining item is the first real Podman pause in the Mac's Linux VM.

Implement the trusted normalizer and enrollment/context provider, using synthetic
fixtures first. Map full event identity, path/resource certainty and operation
outcomes explicitly. Treat an unresolved value as UNKNOWN or a blocker. Then
integrate the engine with durable decisions and a mocked response adapter.

Only after that should a separate node-local controller execute one permitted
Podman pause in the Mac's Linux VM, record the real inspected result, and exercise
stale-generation/replay/permission-removal failures. Shared-service session
revocation needs its own application adapter and attribution integration.

## B4 — egress by host and port (22 October 2026)

`egress_allowed` entries now accept `CIDR`, `CIDR:port`, `CIDR:low-high`, `[v6-cidr]:port`,
`host[:port]` and `*.host[:port]` (`ParseEgressRule`, egress.go). `Event` gained `Port`
(uint16, 0 = unknown) and `DestHost` (sensor-resolved hostname); both optional in JSON.
`EGRESS_OUTSIDE_SCOPE` keeps its code and gains a `Rule` detail: `host_unknown` or `ip:port`.
Plain-CIDR profiles with `Port 0` events are unchanged; no existing test was modified.
README "Egress rules" documents the grammar and matching. The API mirror
(`api/river3_api/profiles.py: check_egress_rule`) was cross-checked against the Go parser on
an 84-entry corpus: identical accept/reject and reasons.

Checks run: `gofmt -l .` clean; `go vet ./...` clean; `go test -count=1 ./...` all three
packages pass (root coverage 92.8%, was 89.2%); `go test -race .` pass;
`FuzzEgressRule`, `FuzzGlobBoundary`, `FuzzDecodeStrict` pass; `../containment` and
`../river3d` build and vet against the new package.

Remaining: the controller must copy `facts.target.host` to `Event.DestHost` and `target.port`
to `Event.Port` (CONTRACTS §4 defers this); the sensor's `-resolve-hosts` should take its name
list from `Profile.EgressHosts()`. `containment/controller/policysync_test.go` expects the old
error text `invalid or mapped CIDR` for the entry `"nope"`; the engine now says
`invalid egress rule "nope": a hostname needs at least two labels…` — update that expected
substring to `invalid egress rule` when that package is next touched.
