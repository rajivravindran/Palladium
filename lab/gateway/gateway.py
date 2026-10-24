#!/usr/bin/env python3
"""River3 reference tool gateway (Python 3 standard library only).

A tool gateway is the one place an agent's actions already flow through: the harness or
proxy that runs tools on the agent's behalf. River3 does not require a particular gateway;
it requires that whatever sits there speaks two small contracts (docs/CONTRACTS.md):

Agent-facing (this file's own API; a real harness would call these from its tool loop)
  POST /v1/sessions            {session_id, workload_id, principal}
                               -> binds the run to its container: POST /api/v1/sessions on the API
  POST /v1/sessions/{id}/end   -> PATCH /api/v1/sessions/{id} {state: "ended"}
  POST /v1/log                 {workload_id, session_id, entries: [AgentLogEntryIn...]}
                               -> POST /api/v1/agents/{workload_id}/log (the agent's own words:
                               low trust, can only raise a drift tier)
  POST /v1/tools/run           {workload_id, session_id, tool, args_summary?}
                               -> POST /api/v1/tools/check. allow -> 200 {decision: "allow"};
                               hold -> poll GET /api/v1/approvals/{id} every 2 s until a human
                               decides or the hold expires, then 200 allow or 403 deny;
                               deny -> 403. A revoked session is refused here without asking.

Controller-facing (CONTRACTS.md §2.1, adapter name `gateway`), signed like webhooks:
  headers X-River3-Timestamp (unix s), X-River3-Delivery (unique id),
          X-River3-Signature: sha256=hex(HMAC-SHA256(RIVER3_GATEWAY_SECRET, "<ts>.<delivery>.<body>"))
  A timestamp outside +-300 s or a delivery id seen before is refused (401).
  POST /v1/sessions/{id}/revoke  {reason, incident_id, idempotency_key} -> {state: "revoked"|"unknown"}
  GET  /v1/sessions/{id}         -> {state, principal, started_at}; 404 when unknown

The gateway only marks the session revoked locally and stops running tools for it. It
never PATCHes the API: the controller verifies with GET and reports (verify-after-act).

Configuration (environment):
  RIVER3_API              API base URL (default http://127.0.0.1:8000)
  RIVER3_GATEWAY_TOKEN    machine token with role `gateway`
  RIVER3_GATEWAY_SECRET   HMAC secret shared with river3-containd (>= 32 chars); without it the
                          revoke endpoint answers 503 and nothing can be revoked through here
  GATEWAY_LISTEN          host:port (default 127.0.0.1:8790)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIGNATURE_WINDOW_S = 300
REPLAY_MAX = 10_000
POLL_S = 2.0
MAX_BODY = 1 << 20


class ApiError(Exception):
    def __init__(self, status: int, detail: object):
        super().__init__(f"api {status}: {detail}")
        self.status, self.detail = status, detail


class ApiClient:
    """Bearer-token JSON calls to the River3 API. Errors keep the API's status and body."""

    def __init__(self, base: str, token: str, timeout: float = 10.0):
        self.base, self.token, self.timeout = base.rstrip("/"), token, timeout

    def call(self, method: str, path: str, body: object | None = None) -> object:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                detail = json.loads(raw).get("detail", raw.decode(errors="replace"))
            except (ValueError, AttributeError):
                detail = raw.decode(errors="replace")
            raise ApiError(e.code, detail) from None
        except (urllib.error.URLError, OSError) as e:
            raise ApiError(502, f"API unreachable: {e}") from None
        return json.loads(raw) if raw else None


class Gateway:
    """Local session table plus the API client. One instance per process; thread-safe."""

    def __init__(self, api: ApiClient, secret: str, clock=time.time):
        self.api, self.secret, self.clock = api, secret.encode() if secret else b"", clock
        self.sessions: dict[str, dict] = {}
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.lock = threading.Lock()

    # ----- agent-facing
    def bind(self, body: dict) -> tuple[int, dict]:
        expect(body, {"session_id", "workload_id", "principal"}, {"labels"})
        with self.lock:
            s = self.sessions.get(body["session_id"])
            if s and s["state"] == "revoked":
                return 409, {"detail": "session is revoked and cannot be reactivated"}
        out = self.api.call("POST", "/api/v1/sessions", body)
        with self.lock:
            self.sessions[body["session_id"]] = {"state": "active", "principal": body["principal"],
                                                 "workload_id": body["workload_id"],
                                                 "started_at": out.get("started_at") or rfc3339(self.clock())}
        return 201, out

    def end(self, session_id: str) -> tuple[int, dict]:
        with self.lock:
            s = self.sessions.get(session_id)
            if s and s["state"] == "revoked":
                return 409, {"detail": "session is revoked; its state is final"}
            if s:
                s["state"] = "ended"
        return 200, self.api.call("PATCH", f"/api/v1/sessions/{session_id}", {"state": "ended"})

    def log(self, body: dict) -> tuple[int, dict]:
        expect(body, {"workload_id", "session_id", "entries"})
        if not isinstance(body["entries"], list):
            raise Bad("entries must be a list")
        entries = [{**e, "session": body["session_id"]} for e in body["entries"] if isinstance(e, dict)]
        return 201, self.api.call("POST", f"/api/v1/agents/{body['workload_id']}/log", entries)

    def run_tool(self, body: dict) -> tuple[int, dict]:
        expect(body, {"workload_id", "session_id", "tool"}, {"args_summary"})
        with self.lock:
            s = self.sessions.get(body["session_id"])
            if s and s["state"] == "revoked":
                return 403, {"decision": "deny", "reason": "session is revoked at the gateway"}
        check = self.api.call("POST", "/api/v1/tools/check", body)
        decision = check.get("decision")
        if decision == "allow":
            return 200, {"decision": "allow", "tier": check.get("tier"), "reason": check.get("reason")}
        if decision == "hold":
            final = self.wait_for_approval(check["approval_id"])
            if final["status"] == "approved":
                return 200, {"decision": "allow", "approval_id": final["id"], "decided_by": final.get("decided_by"),
                             "tier": check.get("tier"), "reason": f"approved by {final.get('decided_by')}"}
            return 403, {"decision": "deny", "approval_id": final["id"],
                         "reason": f"approval {final['status']}: {final.get('reason') or check.get('reason')}"}
        return 403, {"decision": "deny", "tier": check.get("tier"), "reason": check.get("reason", "denied")}

    def wait_for_approval(self, approval_id: str) -> dict:
        """Polls until the approval leaves `pending`. The API reports a hold past its expiry as
        `expired`, so the loop ends by itself; the deadline below only guards a clock mismatch."""
        a = self.api.call("GET", f"/api/v1/approvals/{approval_id}")
        deadline = parse_ts(a.get("expires_at")) or (self.clock() + 600)
        while a.get("status") == "pending":
            if self.clock() > deadline + POLL_S:
                return {**a, "status": "expired"}
            time.sleep(POLL_S)
            a = self.api.call("GET", f"/api/v1/approvals/{approval_id}")
        return a

    # ----- controller-facing
    def verify(self, headers, body: bytes) -> str | None:
        """None when the signature is good; else the reason to answer 401."""
        if not self.secret:
            return "gateway has no RIVER3_GATEWAY_SECRET"
        ts, delivery, sig = headers.get("X-River3-Timestamp"), headers.get("X-River3-Delivery"), headers.get("X-River3-Signature", "")
        if not ts or not ts.isdigit() or not delivery or not sig.startswith("sha256="):
            return "missing or malformed signature headers"
        if abs(self.clock() - int(ts)) > SIGNATURE_WINDOW_S:
            return "timestamp outside the signature window"
        want = hmac.new(self.secret, f"{ts}.{delivery}.".encode() + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig[len("sha256="):], want):
            return "bad signature"
        with self.lock:
            if delivery in self.seen:
                return "replayed delivery id"
            self.seen[delivery] = None
            while len(self.seen) > REPLAY_MAX:
                self.seen.popitem(last=False)
        return None

    def revoke(self, session_id: str, body: dict) -> tuple[int, dict]:
        expect(body, {"reason", "incident_id", "idempotency_key"})
        with self.lock:
            s = self.sessions.get(session_id)
            if s is None:
                return 200, {"state": "unknown"}
            s["state"] = "revoked"
            s["revoked"] = {"reason": body["reason"], "incident_id": body["incident_id"], "at": rfc3339(self.clock())}
        return 200, {"state": "revoked"}

    def status(self, session_id: str) -> tuple[int, dict]:
        with self.lock:
            s = self.sessions.get(session_id)
            if s is None:
                return 404, {"state": "unknown"}
            return 200, {"state": s["state"], "principal": s["principal"], "started_at": s["started_at"]}


class Bad(Exception):
    pass


def expect(body: object, required: set[str], optional: set[str] = frozenset()) -> None:
    """Strict JSON: every required key present, no unknown keys (principle 0)."""
    if not isinstance(body, dict):
        raise Bad("body must be a JSON object")
    missing, unknown = required - body.keys(), body.keys() - required - optional
    if missing or unknown:
        raise Bad(f"missing {sorted(missing)}, unknown {sorted(unknown)}")


def rfc3339(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ts(v: object) -> float | None:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()
    except (TypeError, ValueError):
        return None


class Handler(BaseHTTPRequestHandler):
    gw: Gateway  # set by make_server
    server_version, sys_version = "river3-gateway/0.1", ""

    def log_message(self, fmt, *args):  # one line per request, to stderr
        sys.stderr.write("gateway %s %s\n" % (self.address_string(), fmt % args))

    def send(self, status: int, body: object) -> None:
        raw = json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise Bad("body too large")
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        if parts == ["healthz"]:
            return self.send(200, {"ok": True, "sessions": len(self.gw.sessions)})
        if len(parts) == 3 and parts[:2] == ["v1", "sessions"]:
            return self.send(*self.gw.status(parts[2]))
        self.send(404, {"detail": "not found"})

    def do_POST(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        try:
            raw = self.read_body()
            if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "revoke":
                if (why := self.gw.verify(self.headers, raw)):
                    return self.send(401, {"detail": why})
                return self.send(*self.gw.revoke(parts[2], json.loads(raw or b"{}")))
            body = json.loads(raw or b"{}")
            if parts == ["v1", "sessions"]:
                return self.send(*self.gw.bind(body))
            if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "end":
                return self.send(*self.gw.end(parts[2]))
            if parts == ["v1", "log"]:
                return self.send(*self.gw.log(body))
            if parts == ["v1", "tools", "run"]:
                return self.send(*self.gw.run_tool(body))
            self.send(404, {"detail": "not found"})
        except (Bad, ValueError) as e:
            self.send(422, {"detail": str(e)})
        except ApiError as e:
            self.send(e.status if 400 <= e.status < 600 else 502, {"detail": e.detail})


def make_server(listen: str, gw: Gateway) -> ThreadingHTTPServer:
    host, _, port = listen.rpartition(":")
    handler = type("BoundHandler", (Handler,), {"gw": gw})
    srv = ThreadingHTTPServer((host or "127.0.0.1", int(port)), handler)
    srv.daemon_threads = True
    return srv


def main() -> None:
    token = os.environ.get("RIVER3_GATEWAY_TOKEN", "")
    if not token:
        sys.exit("RIVER3_GATEWAY_TOKEN is required (a machine token with role gateway)")
    secret = os.environ.get("RIVER3_GATEWAY_SECRET", "")
    if secret and len(secret) < 32:
        sys.exit("RIVER3_GATEWAY_SECRET must be at least 32 characters")
    gw = Gateway(ApiClient(os.environ.get("RIVER3_API", "http://127.0.0.1:8000"), token), secret)
    srv = make_server(os.environ.get("GATEWAY_LISTEN", "127.0.0.1:8790"), gw)
    sys.stderr.write(f"gateway listening on {srv.server_address[0]}:{srv.server_address[1]} api={gw.api.base} "
                     f"revoke={'on' if secret else 'OFF (no secret)'}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
