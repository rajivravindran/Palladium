# River3 policy engine (Go)

This component answers: **“What policy did this observed action violate, and is River3 permitted to request containment?”**

It extends the supplied `profile.go` into a reusable, standard-library-only Go module. It is a standalone node-policy component; it has not been wired into the Python Stage 0 application or a live Falco collector. The existing Stage 0 project and uploaded files are unchanged.

## First step

With Go 1.22 or newer installed, open a terminal in this extracted directory and run:

```sh
go test ./...
```

Then replay the synthetic example:

```sh
go run ./cmd/policy-eval -profiles examples/profiles < examples/events.jsonl
```

The CLI always uses shadow mode and an untrusted replay context. It can display recommendations and blockers, but cannot authorize or execute a pause. It makes no outbound requests, downloads no models and never accesses Podman. The Go toolchain may contact its configured services when installing or updating tools; this module has no third-party dependencies.

## What is implemented

- File-open rules for decoys, protected reads, optional allowed reads and allowed writes. `DECOY_OPEN` names a matched rule; `observed_outcome` preserves whether the open succeeded, failed, was attempted or is unknown. Even success does not prove reading or exfiltration. Provenance is retained in each decision.
- Execution-class deny/allow rules with deny precedence.
- Egress rules by CIDR, CIDR with a port or port range, hostname and `*.` wildcard hostname (each optionally with a port or range), including IPv4-mapped IPv6 handling. Hostname rules match the name the sensor resolved into the event, never DNS performed here. Empty egress allowlist means no outbound IP is allowed, including loopback.
- Explicit `IN_SCOPE`, `VIOLATION`, `REVIEW` and `UNKNOWN` results, with reason codes and action blockers.
- Shadow mode and opt-in active mode. Successful, recent, live evidence is required for automatic containment candidates.
- Separate handling of structural Channel A and payload Channel B recommendations. Neither channel can erase a deterministic violation. Channel B alone alerts in this implementation.
- Dedicated-worker pause eligibility and explicitly bound application-session revocation eligibility. Shared services cannot select pause in their profile.
- Expiring action candidates, deterministic idempotency keys and pre-execution revalidation.
- Strict profile loading: atomic failure, bounded files/lists, unknown fields, duplicate/case-colliding JSON keys, duplicate names, invalid patterns/CIDRs/classes and dangerous response types rejected.

## How to connect it

```text
Authenticated collector / node registry
                |
Trusted normalizer: event + current workload context
                |
policy.Engine.Evaluate(event, context)
                |
Durable incident + notification queue
                |
Candidate? Refresh context -> Revalidate -> scoped adapter
                |
Verify actual outcome -> durable result / operator console
```

1. Load administrator-managed profiles with `LoadProfiles` and build an immutable `NewEngine` snapshot. Bind the selected profile to a tenant/asset in your trusted registry. Never let an incoming event or container label choose its own policy. Validate a complete replacement snapshot before swapping it atomically. Increment versions on policy changes.
2. Authenticate the collector. Resolve full runtime identity against enrollment, including tenant, asset, host, generation and full container ID. A session label is metadata, not authority. For a shared service, establish request-to-session attribution; do not infer it from a process-wide event.
3. Normalize evidence into `Event`. Construct `Context` exclusively from trusted controller state; all its fields have `json:"-"`. Do not decode external JSON into a different struct and copy its trust flags into Context. `IdentityVerified`, `ResourceVerified`, `SensorAuthenticated` and assessment `Verified` are obligations of this integration, not capabilities provided by this library.
4. Use separate upstream calls for Channel A and B. Verify provider response schema, input/evidence binding and tenant scope before attaching assessments. The engine accepts enums, not natural-language commands or arbitrary scores. It does not run a model or authenticate a model endpoint.
5. Call `Evaluate`. Any returned error is a coverage/configuration problem: record and alert it. Never interpret an error as permission to continue automatically. An `IN_SCOPE` result means only that the supplied operation satisfies the configured rules, not that the entire workload is safe.
6. Persist the decision and evidence. Send notifications through your notification worker. A non-nil `Candidate` is an eligible action request, **not a performed or verified action**.
7. Immediately before execution, refresh the runtime binding, permissions, profile snapshot, adapter availability and health, then call `Revalidate`. Use a narrowly privileged adapter with structured arguments. Do not turn an action into a shell command. Use a generation-aware lease or runtime serialization to reduce the check/use race.
8. Atomically reserve the idempotency key in durable storage and reconcile retries with the actual runtime. This library generates keys but does not persist or consume them. Protect the action API with authentication and authorization; the key is not a signature or bearer capability. It deliberately excludes evaluation time so a replay does not create a different key.
9. Verify the actual runtime result and record verification evidence. An adapter error is `FAILED` or `UNKNOWN`, not containment success. Resume and termination belong to separate authenticated operator workflows and are never returned here.

### Minimal library use

```go
engine, err := policy.NewEngine(profiles, policy.Options{})
if err != nil { return err }

// Both are supplied by trusted integration code, not taken on faith from JSON.
decision, err := engine.Evaluate(normalizedEvent, controllerContext)
if err != nil { return err }

if decision.Candidate != nil {
    candidate := *decision.Candidate
    // Refresh the registry, permissions and runtime generation here.
    if err := engine.Revalidate(candidate, normalizedEvent, refreshedContext); err != nil {
        return err
    }
    // Durable deduplication and an authenticated execution adapter come next.
}
```

Module path is `river3.local/policy`, a local development placeholder. Change it to your repository path when publishing or use a Go workspace/replace directive for local integration. Python integration should use a narrow authenticated node service or a deliberate binding; the offline CLI is not an active enforcement transport.

## Profile semantics

The original JSON keys are retained. New fields are `version`, `mode`, `read_allowed`, `response` and `egress_allowed_domains`. The original Go `package main` was changed to importable `package policy`; `loadProfiles` is exported as `LoadProfiles`. Internal CIDRs are compiled into the immutable engine rather than retained on mutable profiles.

| Setting | Behaviour |
|---|---|
| Missing version / mode / responses | Version 1; shadow mode; alert only |
| `decoys` | Seeded inert files configured by the operator; these override allowlists |
| `protected_read` | Read-open denial; actual credentials are sensitive resources, not automatically decoys |
| `read_allowed` absent or null | Backward-compatible read denylist: ordinary reads are not restricted |
| `read_allowed: []` | Every read-open outside decoys/protected paths is out of scope |
| `write_allowed: []` | No write-open is in scope |
| `exec_allowed_classes: []` | No known execution class is in scope |
| Class in both allow/deny | Deny wins |
| `egress_allowed: []` | No outbound IP is allowed |
| `egress_allowed` entries | Up to 128 of: CIDR, `CIDR:port`, `CIDR:low-high`, `[v6-cidr]:port`, `host[:port]`, `*.host[:port]`. See **Egress rules** below |
| `egress_allowed_domains` | Up to 128 lowercase hostnames, optionally `*.example.com`. Validated at load (no IPs, ports, schemes, paths or trailing dots) and exposed through `Profile.EgressDomains()`, but **never matched by the engine**: the controller resolves them and appends the addresses to `egress_allowed` on every refresh |
| `response.on_violation` | Alert, pause a dedicated worker, or revoke a bound session |
| `response.on_structural_guard` | Separate opt-in response for a verified Channel A containment recommendation: `ALERT` (default) or `PAUSE_CONTAINER` only. `REVOKE_SESSION` is rejected at load ("a model verdict may at most pause a dedicated AI worker; session revocation needs a deterministic violation") |

Allowed classes: `DIAGNOSTIC`, `INTERPRETER`, `NET_CLIENT`, `PRIVILEGED_TOOL`, `OTHER`. Unknown classes produce `UNKNOWN`; a trusted normalizer must classify executables from adequate evidence, not a user-controlled process name. This taxonomy is not a permission to trust every command executed by a diagnostic program.

Patterns use Go `path.Match` within segments (`*`, `?`, character classes), plus a literal trailing `/**` subtree. `/app/**` covers `/app` and its descendants, not `/application`. `/**` covers all canonical absolute paths. Wildcards before `/**` are rejected. Linux slash paths are used even when testing on macOS. Non-canonical paths, traversal, control characters, backslashes, relative paths and deleted-file markers produce `UNKNOWN` instead of being silently cleaned into an allowed path. Names are case-sensitive.

Lexical matching is not filesystem authorization. Symlinks, hard links, mount aliases, renames, namespaces and truncation require trusted normalization and resource identity checks. Do not set `ResourceVerified` merely because `path.Clean` or `path.Match` succeeded. There is no DNS in the engine: provide the observed destination IP and port, and the hostname the sensor itself resolved for that IP (see **Egress rules**). Protocols are not implemented. `egress_allowed_domains` is accepted and validated so one profile document serves the API, the console and the controller, but `Evaluate` ignores it. The controller turns each name into `/32` and `/128` prefixes (forward resolution: an address the name resolved to in the last refresh, wildcards resolved for the apex only) and compiles a new engine; until it does, a connection to that name's address is `EGRESS_OUTSIDE_SCOPE`.

## Egress rules

Each `egress_allowed` entry (at most 128) is parsed by `ParseEgressRule` into one `EgressRule`. Nothing is normalised: the string the console stores is the string the engine compiles, and the API (`river3_api/profiles.py`) applies the same grammar with the same error reasons.

| Entry | Meaning |
|---|---|
| `10.0.0.0/8` | Any destination in the range, any port (unchanged from before) |
| `10.0.0.0/8:443` | The range, port 443 only |
| `10.0.0.0/8:8000-8100` | The range, ports 8000 through 8100 inclusive (`low < high`; write `443`, not `443-443`) |
| `2001:db8::/32` | IPv6 range, any port |
| `[2001:db8::/32]:443` | IPv6 range with a port **must** be bracketed; `2001:db8::/32:443` is rejected because the port cannot be told from the address |
| `api.example.com` | Exactly that hostname, any port |
| `api.example.com:443`, `api.example.com:8000-8100` | Hostname with a port or range |
| `*.example.com` | Any name with one **or more** labels below `example.com` (`a.example.com`, `a.b.example.com`), **not** `example.com` itself. Add the apex as a separate entry if it is wanted |
| `*.example.com:443` | Wildcard with a port or range |

Hostnames are lowercase RFC 1123 names: labels of `a-z`, `0-9` and `-` (not at either end), 1–63 characters each, at most 253 in all, at least two labels, and the last label is not all digits. Rejected, each with a precise error: schemes (`https://`), paths, uppercase, trailing dots, whitespace, a single-label name (`localhost`; use its address in CIDR form), `*` anywhere but as the leading `*.` label, `*.` alone, port `0`, ports above `65535`, leading zeros, reversed ranges, CIDRs with host bits (the error suggests the masked form), IPv4-mapped IPv6 prefixes, and an IP address written in the host form (`10.0.0.1:443` → use `10.0.0.1/32:443`; `2001:db8::1` → `2001:db8::1/128`).

**Event input.** `Event.Port` (uint16, `0` = the sensor did not report a port) and `Event.DestHost` (optional, lowercase hostname the sensor resolved for `DestinationIP` from its own cache of the profile's names; `Profile.EgressHosts()` lists those names). Both are rejected on `FILE_OPEN`/`PROCESS_EXEC`; a malformed `DestHost` on `NET_CONNECT` is an evaluation error, not a silent pass. Both are optional in JSON, so existing event producers are unaffected.

**Matching (`NET_CONNECT`).** The address is unmapped first (`::ffff:10.1.2.3` is `10.1.2.3`). Rules are tried in order; the first match puts the connection in scope:

- a rule with a port needs `Port != 0` and `low ≤ Port ≤ high`; a rule without a port ignores `Port`;
- a CIDR rule matches when the prefix contains the address;
- a hostname rule matches only when `DestHost` is set and equals the name (or, for `*.`, ends in `.name`); the address is not consulted.

If no rule matches the finding is `EGRESS_OUTSIDE_SCOPE` (no new code) with `Finding.Rule` set to `host_unknown` when the profile has at least one hostname rule and `DestHost` is empty (the connection may have been to an allowed name the sensor did not resolve; check sensor resolution), otherwise the destination as `ip:port` (`[2001:db8::1]:443` for IPv6, just the address when the port is unknown). A profile of plain CIDRs evaluated against events with `Port 0` behaves exactly as before. Matching allocates nothing: hostnames are compared on slices of the event's own string.

Examples against `examples/profiles/api-agent.json` (`api.openai.com:443`, `*.github.com:443`, `10.0.0.0/8:443`, `10.20.0.0/16:8000-8100`, `[2001:db8::/32]:443`, `192.0.2.53/32`):

| Destination | Port | DestHost | Result |
|---|---|---|---|
| 140.82.112.3 | 443 | `api.github.com` | in scope (wildcard) |
| 140.82.112.3 | 443 | `objects.api.github.com` | in scope (wildcard, two labels) |
| 140.82.112.3 | 443 | `github.com` | `EGRESS_OUTSIDE_SCOPE`, rule `140.82.112.3:443` (apex) |
| 140.82.112.3 | 443 | — | `EGRESS_OUTSIDE_SCOPE`, rule `host_unknown` |
| 10.20.1.1 | 8080 | — | in scope (range) |
| 10.20.1.1 | 0 | — | `EGRESS_OUTSIDE_SCOPE`, rule `host_unknown` (port rules need a known port; host rules exist) |
| 192.0.2.53 | 0 | — | in scope (plain CIDR, port irrelevant) |

Default timing bounds: event age 30 seconds, future clock skew 2 seconds, action lease 5 seconds. They are configurable within constructor limits. A controller timestamp is passed explicitly to make evaluation deterministic and testable. No latency or prevention guarantee follows from these values.

## Scope and limitations

This is an evaluator with a response-eligibility gate, not a full River3 deployment. It does not provide authentication, Falco JSON normalization, process/request attribution, inode resolution, kernel enforcement, storage, stateful trajectory/exposure tracking, model inference, notifications, runtime adapters or operator approval APIs. Those components must fulfill the contracts above. No real pause or session revocation was performed while testing it.

Supported observations are `FILE_OPEN`, `PROCESS_EXEC` and `NET_CONNECT`. The first reports the requested open mode, not completed data transfer. Other filesystem operations, process injection, escape syscalls, ingress/API authorization events, inherited open descriptors, memory access and existing network streams need additional event types and coverage. Unsupported events return errors rather than `IN_SCOPE`.

Failed or attempted policy violations alert; they do not produce automatic containment in this initial policy. A deterministic decoy response does not wait on a model. Model outages do not erase a deterministic finding. Payload-only model containment is deliberately not enabled until corroboration rules are implemented and evaluated. There is no automatic resume/kill action.

Out-of-band containment reduces further harm; an action or transmission may already have completed. Do not claim that a pause prevents every first effect or recalls queued packets. The trusted controller host is part of the security boundary.

## Development

```sh
gofmt -w *.go cmd/policy-eval/*.go
go test -race ./...
go vet ./...
go test -run '^$' -fuzz FuzzGlobBoundary -fuzztime 3s
go test -run '^$' -fuzz FuzzDecodeStrict -fuzztime 3s
go test -run '^$' -fuzz FuzzEgressRule -fuzztime 5s
```

See `HANDOVER.md` for actual executed checks and remaining integration work. Fixtures use fake identities and inert paths only. Do not upload live credentials or logs to the tests.

Implementation references: [Go path matching](https://pkg.go.dev/path#Match) and [netip address normalization](https://pkg.go.dev/net/netip#Addr.Unmap). The former is lexical; the latter handles IPv4-mapped addresses. These are not filesystem or identity guarantees. A hostname match is only as trustworthy as the sensor's IP→name cache that produced `DestHost`; the engine cannot tell a resolved name from a forged one.
