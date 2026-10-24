"""Who can call the API, what they may do, and the HTTP-level protections.

Principals
  Every caller is a named principal: a person ("operator") or a component ("machine").
  Tokens are stored only as SHA-256 hashes. Plain tokens are allowed in the file for
  development and are hashed at load; production refuses plain tokens shorter than 32 chars.

Roles -> permissions
  Built-in roles below. A business can replace or extend them with RIVER3_ROLES_FILE,
  e.g. {"night-shift": ["read", "act"], "auditor": ["read", "audit"]}.
  Unknown permissions are rejected at startup, so a typo can't silently grant nothing or everything.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from .config import DEV_PRINCIPALS, ConfigError, Settings, settings
from .tokens import generate_token, sha256_hex  # noqa: F401  (re-exported)

log = logging.getLogger("river3.security")

# ------------------------------------------------------------------ permissions
PERMISSIONS = {
    # people
    "read": "view incidents, workloads, stats and the live stream",
    "act": "request resume / terminate, mark resolved or not a threat",
    "summarize": "generate an AI summary of an incident",
    "audit": "read and verify the audit log",
    "policies": "create, edit and delete policy profiles",
    # machines
    "workloads.write": "enroll or update workloads",
    "events.write": "post sensor events",
    "incidents.write": "open incidents",
    "response.write": "report containment results on an incident",
    "actions.read": "pick up queued operator requests",
    "actions.write": "report the result of an operator request",
    "profiles.read": "fetch the policy profiles to enforce",
    "profiles.status": "report which policy revision is being enforced",
    "agentlog.write": "post an agent's own activity log (untrusted; only ever raises a drift tier)",
    "sessions.write": "bind, end or keep alive gateway sessions",
    "sessions.read": "list sessions (the controller maps workloads to the session acting in them)",
    "tools.check": "ask whether a tool call may run now, and poll the approval it is held on",
    "approvals.request": "ask for an approval before a tool call (allow / hold / deny by drift tier) and poll it",
}

BUILTIN_ROLES: dict[str, set[str]] = {
    "viewer": {"read"},
    "responder": {"read", "act", "summarize"},
    "admin": {"read", "act", "summarize", "audit", "policies"},
    "sensor": {"workloads.write", "events.write", "agentlog.write"},
    "policy": {"workloads.write", "events.write", "incidents.write", "profiles.read", "profiles.status", "agentlog.write"},
    "agentlog": {"agentlog.write"},  # for a tool gateway or log shipper that only forwards agent logs
    "containment": {"response.write", "actions.read", "actions.write", "sessions.read"},
    # the customer's tool gateway / agent harness: binds sessions, ships the agent log (with tool_call_id),
    # asks before tools (POST /approvals, 22 Oct CONTRACTS §2; tools/check from the Stage B draft stays)
    "gateway": {"sessions.write", "sessions.read", "agentlog.write", "tools.check", "approvals.request"},
    # whoever can actually cut a session (gateway, identity provider, cloud-role revoker): picks up
    # `revoke` requests and reports the result. Deliberately not `containment`: cutting an identity and
    # pausing a container are different powers held by different systems.
    "revoker": {"actions.read", "actions.write"},
}

MAX_TEAMS = 64
MAX_TEAM_LEN = 64


@dataclass(frozen=True)
class Principal:
    name: str
    kind: str  # operator | machine
    role: str
    permissions: frozenset[str]
    token_hash: str
    # Operators only (CONTRACTS §6). Empty = every team. Machines are never scoped: a sensor or
    # controller serves the whole host, and filtering what it may report would hide evidence.
    teams: frozenset[str] = frozenset()

    def can(self, perm: str) -> bool:
        return perm in self.permissions

    @property
    def team_scope(self) -> frozenset[str] | None:
        """The teams this principal's reads are limited to, or None for "everything".
        Admins bypass: someone has to see the unassigned and the misassigned."""
        if self.kind != "operator" or not self.teams or self.role == "admin":
            return None
        return self.teams

    def sees_team(self, team: str) -> bool:
        """True when a workload in `team` is inside this principal's scope. Strict: an unassigned
        workload ("" team) is NOT visible to a scoped operator. Admins (unscoped) see it, which is
        who should notice a container that enrolled without a team label."""
        scope = self.team_scope
        return scope is None or team in scope


def load_roles(raw: object) -> dict[str, set[str]]:
    roles = {k: set(v) for k, v in BUILTIN_ROLES.items()}
    if raw is None:
        return roles
    if not isinstance(raw, dict):
        raise ConfigError("roles file must be a JSON object of role -> [permissions]")
    for role, perms in raw.items():
        if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
            raise ConfigError(f"role {role!r}: permissions must be a list of strings")
        unknown = set(perms) - PERMISSIONS.keys()
        if unknown:
            raise ConfigError(f"role {role!r}: unknown permissions {sorted(unknown)}")
        roles[role] = set(perms)
    return roles


def _teams_of(p: dict, name: str, kind: str) -> frozenset[str]:
    """`teams` from a principal entry. Machines must not carry one: scoping a sensor or controller
    would silently drop evidence for the other teams, which is worse than no scoping at all."""
    raw = p.get("teams")
    if raw is None:
        return frozenset()
    if kind != "operator":
        raise ConfigError(f"principal {name!r}: only operators can have teams (machines are not scoped)")
    if not isinstance(raw, list) or not all(isinstance(t, str) for t in raw):
        raise ConfigError(f"principal {name!r}: teams must be a list of strings")
    if len(raw) > MAX_TEAMS:
        raise ConfigError(f"principal {name!r}: at most {MAX_TEAMS} teams")
    for t in raw:
        if not t.strip() or len(t) > MAX_TEAM_LEN or t != t.strip():
            raise ConfigError(f"principal {name!r}: a team is 1-{MAX_TEAM_LEN} characters with no surrounding spaces")
    return frozenset(raw)


def load_principals(s: Settings, roles: dict[str, set[str]]) -> dict[str, Principal]:
    raw = s.principals_raw if s.principals_raw is not None else DEV_PRINCIPALS
    if not isinstance(raw, list):
        raise ConfigError("principals must be a JSON list")
    by_hash: dict[str, Principal] = {}
    names: set[str] = set()
    for i, p in enumerate(raw):
        if not isinstance(p, dict):
            raise ConfigError(f"principal #{i} must be an object")
        name, kind, role = p.get("name"), p.get("kind"), p.get("role")
        if not name or kind not in ("operator", "machine") or role not in roles:
            raise ConfigError(f"principal #{i}: needs name, kind (operator|machine) and a known role")
        if name in names:
            raise ConfigError(f"principal name {name!r} is duplicated")
        names.add(name)
        if "token_sha256" in p:
            h = str(p["token_sha256"]).lower()
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                raise ConfigError(f"principal {name!r}: token_sha256 must be 64 hex chars")
        elif "token" in p:
            tok = str(p["token"])
            if s.production and len(tok) < 32:
                raise ConfigError(f"principal {name!r}: production tokens must be >= 32 chars (use token_sha256)")
            h = sha256_hex(tok)
        else:
            raise ConfigError(f"principal {name!r}: needs token_sha256 (or token in development)")
        perms = roles[role]
        if kind == "operator" and any("." in x for x in perms):
            raise ConfigError(f"principal {name!r}: operator roles can't hold machine permissions")
        if kind == "machine" and any("." not in x for x in perms):
            raise ConfigError(f"principal {name!r}: machine roles can't hold operator permissions")
        if h in by_hash:
            raise ConfigError(f"principal {name!r} shares a token with {by_hash[h].name!r}")
        by_hash[h] = Principal(name, kind, role, frozenset(perms), h, teams=_teams_of(p, name, kind))
    if s.production and any(pr.token_hash in {sha256_hex(d["token"]) for d in DEV_PRINCIPALS}
                            for pr in by_hash.values()):
        raise ConfigError("a development token is configured in production")
    return by_hash


ROLES = load_roles(settings.roles_raw)
PRINCIPALS = load_principals(settings, ROLES)


# ------------------------------------------------------------------ failed-auth throttling
class FailureLimiter:
    """Per-client sliding window of failed authentications. In-memory: one API instance.
    For several instances behind a load balancer, put the limit in the proxy or a shared store."""

    def __init__(self, limit: int, window_s: int) -> None:
        self.limit, self.window = limit, window_s
        self._fails: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _trim(self, q: deque[float], now: float) -> None:
        while q and now - q[0] > self.window:
            q.popleft()

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._fails.get(key)
            if not q:
                return False
            self._trim(q, now)
            return len(q) >= self.limit

    def fail(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._fails.setdefault(key, deque())
            self._trim(q, now)
            q.append(now)
            if len(self._fails) > 50_000:  # bound memory under a spray of addresses
                self._fails.clear()

    def reset(self) -> None:
        with self._lock:
            self._fails.clear()


limiter = FailureLimiter(settings.auth_fail_limit, settings.auth_fail_window_s)


def client_ip(request: Request) -> str:
    if settings.trusted_proxy:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _bearer(request: Request) -> str | None:
    h = request.headers.get("authorization")
    if h and h[:7].lower() == "bearer ":
        return h[7:].strip() or None
    return None


def _lookup(token: str | None) -> Principal | None:
    if not token:
        return None
    h = sha256_hex(token)
    found = None
    for known, pr in PRINCIPALS.items():  # constant-time compare against every entry
        if hmac.compare_digest(h, known):
            found = pr
    return found


def authenticate(request: Request) -> Principal:
    ip = client_ip(request)
    pr = _lookup(_bearer(request))
    if pr:
        # A valid token is never refused because of other people's failures from the same address:
        # behind a proxy every client shares one IP, and locking machines out is a denial of service.
        request.state.principal = pr.name
        return pr
    if limiter.blocked(ip):
        raise HTTPException(429, "too many failed sign-in attempts; try again later")
    limiter.fail(ip)
    log.warning("auth.failed", extra={"client": ip, "path": request.url.path})
    raise HTTPException(401, "valid bearer token required", headers={"WWW-Authenticate": "Bearer"})


def require(perm: str):
    """FastAPI dependency: caller must hold `perm`."""
    if perm not in PERMISSIONS:
        raise ValueError(f"unknown permission {perm}")

    def dep(pr: Principal = Depends(authenticate)) -> Principal:
        if not pr.can(perm):
            raise HTTPException(403, f"role '{pr.role}' does not allow '{perm}'")
        return pr

    return dep


def require_any(*perms: str):
    """FastAPI dependency: caller must hold at least one of `perms`. For endpoints that both a person
    and a machine legitimately read (sessions, approvals) without giving either the other's permission."""
    unknown = set(perms) - PERMISSIONS.keys()
    if unknown or not perms:
        raise ValueError(f"unknown permissions {sorted(unknown)}")

    def dep(pr: Principal = Depends(authenticate)) -> Principal:
        if not any(pr.can(p) for p in perms):
            raise HTTPException(403, f"role '{pr.role}' does not allow any of {sorted(perms)}")
        return pr

    return dep


# ------------------------------------------------------------------ stream tickets
# Browsers' EventSource can't send headers. Instead of putting a long-lived token in the
# URL (where it ends up in logs and history), the console swaps its token for a ticket
# that is single-use, valid for 60 seconds, and bound to the principal.
_TICKET_TTL = 60
_used_nonces: dict[str, float] = {}
_nonce_lock = threading.Lock()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_ticket(pr: Principal) -> str:
    body = json.dumps({"sub": pr.token_hash, "exp": int(time.time()) + _TICKET_TTL,
                       "n": secrets.token_urlsafe(12)}, separators=(",", ":")).encode()
    sig = hmac.new(settings.secret_key.encode(), body, hashlib.sha256).digest()
    return f"{_b64(body)}.{_b64(sig)}"


def redeem_ticket(ticket: str | None) -> Principal:
    try:
        b, s = (ticket or "").split(".", 1)
        body, sig = _unb64(b), _unb64(s)
        good = hmac.new(settings.secret_key.encode(), body, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, good):
            raise ValueError("bad signature")
        data = json.loads(body)
        now = time.time()
        if data["exp"] < now:
            raise ValueError("expired")
        with _nonce_lock:
            for n, exp in list(_used_nonces.items()):
                if exp < now:
                    del _used_nonces[n]
            if data["n"] in _used_nonces:
                raise ValueError("ticket already used")
            _used_nonces[data["n"]] = data["exp"]
        pr = PRINCIPALS.get(data["sub"])
        if not pr or not pr.can("read"):
            raise ValueError("principal no longer allowed")
        return pr
    except (ValueError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise HTTPException(401, f"invalid stream ticket ({exc})") from None


# ------------------------------------------------------------------ webhook signing
# Base string: "<ts>.<delivery>.<body>". The delivery id is INSIDE the MAC so that a receiver's
# replay cache keys on a value the sender committed to; with the id outside the MAC an attacker
# could replay a captured body under a fresh id. The containment controller verifies exactly
# this string and requires the X-River3-Delivery header (containment/controller/server.go).
SIGNATURE_WINDOW_S = 300


def _mac(secret: str, ts: int | str, delivery: str, body: bytes) -> str:
    return hmac.new(secret.encode(), f"{ts}.{delivery}.".encode() + body, hashlib.sha256).hexdigest()


def sign_webhook(body: bytes, ts: int | None = None, secret: str | None = None,
                 delivery: str | None = None) -> dict[str, str]:
    """Headers for an outbound webhook. Receivers must recompute
    HMAC-SHA256(secret, f"{timestamp}.{delivery}.{body}"), reject timestamps outside
    SIGNATURE_WINDOW_S and remember delivery ids for that window."""
    ts = ts or int(time.time())
    delivery = delivery or uuid.uuid4().hex
    key = (secret if secret is not None else settings.webhook_secret) or ""
    return {"X-River3-Timestamp": str(ts), "X-River3-Signature": f"sha256={_mac(key, ts, delivery, body)}",
            "X-River3-Delivery": delivery}


class ReplayCache:
    """Delivery ids already accepted, bounded by count (oldest evicted). Time-based expiry is
    unnecessary: a delivery older than the signature window is refused by the timestamp check
    before the cache is consulted, so the cache only has to hold one window's worth of ids.
    In-memory, one API instance (same caveat as the ticket nonces and the auth limiter)."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self.max_entries = max_entries
        self._seen: dict[str, None] = {}  # insertion-ordered; value unused
        self._lock = threading.Lock()

    def first_time(self, delivery: str) -> bool:
        """Records the id; False when it was already there."""
        with self._lock:
            if delivery in self._seen:
                return False
            self._seen[delivery] = None
            while len(self._seen) > self.max_entries:
                del self._seen[next(iter(self._seen))]
            return True

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


canary_replays = ReplayCache()


def verify_signature(headers, body: bytes, secret: str, max_age_s: int = SIGNATURE_WINDOW_S,
                     seen: ReplayCache | None = None) -> str:
    """Inbound counterpart of sign_webhook: HMAC-SHA256(secret, f"{ts}.{delivery}.{body}") in
    X-River3-Signature, timestamp within max_age_s, X-River3-Delivery required. With `seen`,
    a delivery id presented twice is refused (409). Returns the delivery id.
    Raises HTTPException(401) for anything unverifiable."""
    ts_raw = headers.get("x-river3-timestamp") or ""
    sig = headers.get("x-river3-signature") or ""
    delivery = (headers.get("x-river3-delivery") or "").strip()
    try:
        ts = int(ts_raw)
    except ValueError:
        raise HTTPException(401, "missing or malformed signature timestamp") from None
    if abs(time.time() - ts) > max_age_s:
        raise HTTPException(401, "signature timestamp outside the accepted window")
    if not sig.startswith("sha256="):
        raise HTTPException(401, "missing signature")
    if not delivery or len(delivery) > 128:
        raise HTTPException(401, "missing X-River3-Delivery header")
    if not hmac.compare_digest(sig[len("sha256="):], _mac(secret, ts_raw, delivery, body)):
        raise HTTPException(401, "bad signature")
    # Only after the MAC checks out: an unauthenticated caller must not be able to fill the cache
    # with ids and lock out the genuine sender.
    if seen is not None and not seen.first_time(delivery):
        raise HTTPException(409, "replayed delivery id")
    return delivery


# ------------------------------------------------------------------ ASGI middleware
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}


class SecurityMiddleware:
    """Adds security headers and a request id, enforces the body size limit,
    and writes one structured access-log line per request (no tokens, no query strings)."""

    def __init__(self, app, max_body: int, hsts: bool) -> None:
        self.app, self.max_body, self.hsts = app, max_body, hsts
        self.access = logging.getLogger("river3.access")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers") or [])
        rid = headers.get(b"x-request-id", b"").decode()[:64] or uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = rid
        started = time.perf_counter()
        status_holder = {"status": 0}

        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_body
            except ValueError:
                too_big = True
            if too_big:
                await self._reject(send, 413, "request body too large", rid)
                self._log(scope, 413, started, rid)
                return

        received = 0

        async def limited_receive():
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_body:
                    raise _BodyTooLarge()
            return msg

        async def send_wrapper(msg):
            if msg["type"] == "http.response.start":
                status_holder["status"] = msg["status"]
                hdrs = list(msg.get("headers", []))
                existing = {k.lower() for k, _ in hdrs}
                for k, v in SECURITY_HEADERS.items():
                    if k.lower().encode() not in existing:
                        hdrs.append((k.encode(), v.encode()))
                if self.hsts:
                    hdrs.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                if scope["path"].startswith("/api/"):
                    hdrs.append((b"cache-control", b"no-store"))
                hdrs.append((b"x-request-id", rid.encode()))
                msg["headers"] = hdrs
            await send(msg)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except _BodyTooLarge:
            if not status_holder["status"]:
                await self._reject(send, 413, "request body too large", rid)
            status_holder["status"] = 413
        finally:
            self._log(scope, status_holder["status"], started, rid)

    async def _reject(self, send, status: int, detail: str, rid: str) -> None:
        body = json.dumps({"detail": detail}).encode()
        hdrs = [(b"content-type", b"application/json"), (b"x-request-id", rid.encode())]
        hdrs += [(k.encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
        await send({"type": "http.response.start", "status": status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

    def _log(self, scope, status: int, started: float, rid: str) -> None:
        st = scope.get("state", {})
        self.access.info("request", extra={
            "request_id": rid, "method": scope.get("method"), "path": scope.get("path"),
            "status": status, "ms": round((time.perf_counter() - started) * 1000, 1),
            "principal": st.get("principal") if isinstance(st, dict) else None,
        })


class _BodyTooLarge(Exception):
    pass


class JsonFormatter(logging.Formatter):
    _skip = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname,
               "logger": record.name, "msg": record.getMessage()}
        out.update({k: v for k, v in vars(record).items() if k not in self._skip})
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging() -> None:
    root = logging.getLogger("river3")
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    h = logging.StreamHandler()
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(logging.INFO)
    root.propagate = False
