# River3 security notes

What River3 trusts, what it refuses to trust, and what a pilot must still do.

## Trust boundaries

| Boundary | Mechanism | Where |
|---|---|---|
| Who may call the API | Named principals; tokens stored as SHA-256 only; constant-time compare; per-IP failed-auth throttle | `api/river3_api/security.py` |
| What a caller may do | Roles → permissions; operators cannot hold machine permissions and vice versa; unknown permissions refused at startup | `security.py`, `RIVER3_ROLES_FILE` |
| Browser live stream | Single-use 60 s HMAC tickets instead of a token in the URL | `/api/v1/stream/ticket` |
| API → controller | HMAC-SHA256 over `"<ts>.<body>"`, ±5 min window, delivery-id replay cache | `sign_webhook` / `controller.Server.verify` |
| Canary service → API | bearer with `incidents.write`, or the same HMAC scheme with `RIVER3_CANARY_SECRET` | `/api/v1/canary` |
| Sensor → controller | bearer token hashed in the controller's registry, with declared capabilities | `containment/registry` |
| Workload identity | mount-namespace inode resolved by the sensor from an enrolled full container id; re-checked by `Inspect` for id + generation before every action | `river3d/workload.go`, `containment/normalize` |
| Model output | enum only; `Verified` set by the adapter after schema + event-id checks; Channel B never reaches structural decisions | `containment/guard`, `api/.../summary.py` |
| Runtime calls | one adapter interface, structured arguments, full ids only; outcomes decided by inspection | `containment/adapter` |

## Things River3 deliberately does not do

- **Trust the workload about itself.** Labels, hostnames, environment, the process's own
  `comm`, and the sensor's advisory `binary_class` never set a trust flag. Tenant and
  host come from node configuration.
- **Treat an adapter return value as success.** `VERIFIED` requires a post-call
  `Inspect` showing the intended state for the same container id and generation.
- **Act twice.** Idempotency keys are reserved durably before the adapter is called;
  event ids, operator action ids and webhook delivery ids are each deduplicated.
- **Let a model contain anything by itself.** Payload-channel verdicts alert only;
  structural-channel containment requests need the profile's explicit opt-in and
  every other gate (live evidence, successful outcome, verified identity and
  resource, active and healthy workload, permission, adapter, lease).
- **Follow redirects or send tokens anywhere but the configured base URL.**
- **Terminate shared services** from the console or the controller.
- **Pretend lexical path matching is filesystem authorization.** Paths are resolved
  inside the process root after the syscall; it is evidence with a TOCTOU window.

## Known gaps before a pilot

1. **TLS.** Neither the API nor the controller terminates TLS. Put Caddy/nginx in
   front; set `RIVER3_HSTS=true`; use `https://` webhook URLs (enforced in production).
2. **Base image.** `api/Dockerfile` uses `python:3.12-slim` by tag. Pin by digest:
   `docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim`,
   then `FROM python:3.12-slim@sha256:…`.
3. **Secrets.** `RIVER3_SECRET_KEY`, `RIVER3_WEBHOOK_SECRET`, `RIVER3_CANARY_SECRET`
   and every principal token must be generated (`python -m river3_api.cli new-token`,
   `new-secret`) and never committed. `deploy/.env` and `principals.json` are gitignored.
4. **Dead module.** `api/river3_api/auth.py` is the pre-principals authenticator;
   nothing imports it and it reads settings that no longer exist. Delete it.
5. **Controller host is part of the boundary.** The journal, registry and tokens live
   on the node; protect them like the runtime socket.
6. **Model endpoints.** Laya and summaries accept plain `http` only to loopback. A
   remote model needs `https` and should be treated as an untrusted advisor regardless.
7. **Executable classification** is by basename; a copied or renamed binary is `OTHER`.
   Profiles that allow `OTHER` accept that trade-off knowingly.
8. **Multiple API instances** need the stream, ticket cache and throttle moved to a
   shared store first (see ARCHITECTURE.md, Scaling).

## Reporting a problem

Open an issue with the incident id and the relevant audit rows (`GET /api/v1/audit`,
`GET /api/v1/audit/verify`). Do not attach live credentials, journals or model prompts
containing workload payloads.
