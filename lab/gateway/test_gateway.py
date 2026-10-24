"""Unit tests for the reference gateway against a fake River3 API (stdlib only).

    python -m unittest lab/gateway/test_gateway.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gateway  # noqa: E402

SECRET = "0123456789abcdef0123456789abcdef"


class FakeAPI(BaseHTTPRequestHandler):
    """Just enough of the API: sessions, agent log, tools/check, approvals. Shared state on the class."""
    state: dict = {}

    def log_message(self, *a):
        pass

    def reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"null")

    def do_POST(self):
        st = FakeAPI.state
        st["calls"].append((self.command, self.path, self.headers.get("Authorization")))
        b = self.body()
        if self.path == "/api/v1/sessions":
            if b["workload_id"] not in st["workloads"]:
                return self.reply(422, {"detail": "unknown workload; enroll it first"})
            return self.reply(201, {"id": b["session_id"], "state": "active", "principal": b["principal"],
                                    "started_at": "2026-10-22T10:00:00Z"})
        if self.path.startswith("/api/v1/agents/") and self.path.endswith("/log"):
            st["log"].extend(b)
            return self.reply(201, {"accepted": len(b), "tier": "steady"})
        if self.path == "/api/v1/tools/check":
            d = st["decisions"].get(b["tool"], "allow")
            if d == "hold":
                st["approvals"]["ap-1"] = {"id": "ap-1", "status": "pending", "expires_at": "2099-01-01T00:00:00Z"}
                return self.reply(200, {"decision": "hold", "approval_id": "ap-1", "tier": "high", "reason": "risky"})
            return self.reply(200, {"decision": d, "approval_id": None, "tier": "steady", "reason": "r"})
        self.reply(404, {"detail": "nope"})

    def do_PATCH(self):
        FakeAPI.state["calls"].append((self.command, self.path, None))
        self.reply(200, {"id": self.path.rsplit("/", 1)[1], "state": "ended"})

    def do_GET(self):
        st = FakeAPI.state
        st["calls"].append((self.command, self.path, None))
        if self.path.startswith("/api/v1/approvals/"):
            a = st["approvals"].get(self.path.rsplit("/", 1)[1])
            return self.reply(200, a) if a else self.reply(404, {"detail": "approval not found"})
        self.reply(404, {"detail": "nope"})


def http(method, url, body=None, headers=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def signed(body: bytes, ts=None, delivery="d-1", secret=SECRET):
    ts = str(ts or int(time.time()))
    mac = hmac.new(secret.encode(), f"{ts}.{delivery}.".encode() + body, hashlib.sha256).hexdigest()
    return {"X-River3-Timestamp": ts, "X-River3-Delivery": delivery, "X-River3-Signature": f"sha256={mac}",
            "Content-Type": "application/json"}


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api_srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI)
        threading.Thread(target=cls.api_srv.serve_forever, daemon=True).start()
        api = gateway.ApiClient(f"http://127.0.0.1:{cls.api_srv.server_address[1]}", "gw-token")
        cls.gw = gateway.Gateway(api, SECRET)
        cls.srv = gateway.make_server("127.0.0.1:0", cls.gw)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        gateway.POLL_S = 0.05
        gateway.Handler.log_message = lambda *a: None  # keep the test output quiet

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.api_srv.shutdown()

    def setUp(self):
        FakeAPI.state = {"calls": [], "workloads": {"w-1"}, "log": [], "decisions": {}, "approvals": {}}
        self.gw.sessions.clear()
        self.gw.seen.clear()

    def bind(self, sid="s-1"):
        return http("POST", self.url + "/v1/sessions", {"session_id": sid, "workload_id": "w-1", "principal": "dev@x"})

    def test_bind_relays_to_api_with_gateway_token(self):
        code, out = self.bind()
        self.assertEqual(code, 201)
        self.assertEqual(out["state"], "active")
        self.assertIn(("POST", "/api/v1/sessions", "Bearer gw-token"), FakeAPI.state["calls"])
        code, st = http("GET", self.url + "/v1/sessions/s-1")
        self.assertEqual((code, st["state"], st["principal"]), (200, "active", "dev@x"))

    def test_bind_unknown_workload_relays_422(self):
        code, out = http("POST", self.url + "/v1/sessions", {"session_id": "s", "workload_id": "nope", "principal": "p"})
        self.assertEqual(code, 422)
        self.assertIn("unknown workload", out["detail"])

    def test_unknown_fields_rejected(self):
        code, _ = http("POST", self.url + "/v1/sessions", {"session_id": "s", "workload_id": "w-1", "principal": "p", "x": 1})
        self.assertEqual(code, 422)
        code, _ = http("POST", self.url + "/v1/tools/run", {"workload_id": "w-1", "session_id": "s-1"})
        self.assertEqual(code, 422)

    def test_log_relay_stamps_session(self):
        self.bind()
        code, out = http("POST", self.url + "/v1/log", {"workload_id": "w-1", "session_id": "s-1",
                                                        "entries": [{"id": "l1", "kind": "tool_call", "tool": "read_file"}]})
        self.assertEqual((code, out["accepted"]), (201, 1))
        self.assertEqual(FakeAPI.state["log"][0]["session"], "s-1")

    def test_tool_allow(self):
        self.bind()
        code, out = http("POST", self.url + "/v1/tools/run", {"workload_id": "w-1", "session_id": "s-1", "tool": "read_file"})
        self.assertEqual((code, out["decision"]), (200, "allow"))

    def test_tool_deny_is_403(self):
        self.bind()
        FakeAPI.state["decisions"]["shell"] = "deny"
        code, out = http("POST", self.url + "/v1/tools/run", {"workload_id": "w-1", "session_id": "s-1", "tool": "shell"})
        self.assertEqual((code, out["decision"]), (403, "deny"))

    def test_tool_hold_waits_for_approval(self):
        self.bind()
        FakeAPI.state["decisions"]["kubectl"] = "hold"

        def approve():
            time.sleep(0.2)
            FakeAPI.state["approvals"]["ap-1"].update(status="approved", decided_by="oncall")
        threading.Thread(target=approve).start()
        code, out = http("POST", self.url + "/v1/tools/run", {"workload_id": "w-1", "session_id": "s-1", "tool": "kubectl",
                                                              "args_summary": "apply -f prod.yaml"})
        self.assertEqual((code, out["decision"], out["approval_id"]), (200, "allow", "ap-1"))
        self.assertGreaterEqual(sum(1 for c in FakeAPI.state["calls"] if c[1] == "/api/v1/approvals/ap-1"), 2)

    def test_tool_hold_denied_or_expired_is_403(self):
        self.bind()
        FakeAPI.state["decisions"]["kubectl"] = "hold"

        def deny():
            time.sleep(0.15)
            FakeAPI.state["approvals"]["ap-1"].update(status="denied", decided_by="oncall", reason="not now")
        threading.Thread(target=deny).start()
        code, out = http("POST", self.url + "/v1/tools/run", {"workload_id": "w-1", "session_id": "s-1", "tool": "kubectl"})
        self.assertEqual((code, out["decision"]), (403, "deny"))
        self.assertIn("denied", out["reason"])

    def test_revoke_contract(self):
        self.bind()
        body = json.dumps({"reason": "decoy read", "incident_id": "inc-1", "idempotency_key": "k1"}).encode()
        code, out = http("POST", self.url + "/v1/sessions/s-1/revoke", body, signed(body))
        self.assertEqual((code, out["state"]), (200, "revoked"))
        code, st = http("GET", self.url + "/v1/sessions/s-1")
        self.assertEqual((code, st["state"]), (200, "revoked"))
        # a revoked session gets no more tools, and the API is not even asked
        before = len(FakeAPI.state["calls"])
        code, out = http("POST", self.url + "/v1/tools/run", {"workload_id": "w-1", "session_id": "s-1", "tool": "read_file"})
        self.assertEqual((code, out["decision"]), (403, "deny"))
        self.assertEqual(len(FakeAPI.state["calls"]), before)
        # and cannot be re-bound
        self.assertEqual(self.bind()[0], 409)
        # idempotent: a second signed revoke (new delivery id) still says revoked
        code, out = http("POST", self.url + "/v1/sessions/s-1/revoke", body, signed(body, delivery="d-2"))
        self.assertEqual((code, out["state"]), (200, "revoked"))

    def test_revoke_unknown_session_and_status_404(self):
        body = json.dumps({"reason": "r", "incident_id": "i", "idempotency_key": "k"}).encode()
        code, out = http("POST", self.url + "/v1/sessions/ghost/revoke", body, signed(body))
        self.assertEqual((code, out["state"]), (200, "unknown"))
        self.assertEqual(http("GET", self.url + "/v1/sessions/ghost")[0], 404)

    def test_revoke_signature_checks(self):
        self.bind()
        body = json.dumps({"reason": "r", "incident_id": "i", "idempotency_key": "k"}).encode()
        self.assertEqual(http("POST", self.url + "/v1/sessions/s-1/revoke", body, signed(body, secret="wrong" * 8))[0], 401)
        self.assertEqual(http("POST", self.url + "/v1/sessions/s-1/revoke", body, signed(body, ts=int(time.time()) - 400))[0], 401)
        self.assertEqual(http("POST", self.url + "/v1/sessions/s-1/revoke", body, {"Content-Type": "application/json"})[0], 401)
        ok = signed(body, delivery="once")
        self.assertEqual(http("POST", self.url + "/v1/sessions/s-1/revoke", body, ok)[0], 200)
        self.assertEqual(http("POST", self.url + "/v1/sessions/s-1/revoke", body, ok)[0], 401)  # replay
        # tampered body under a valid signature
        self.assertEqual(http("POST", self.url + "/v1/sessions/s-1/revoke", body + b" ", signed(body, delivery="d-9"))[0], 401)
        self.assertEqual(http("GET", self.url + "/v1/sessions/s-1")[1]["state"], "revoked")

    def test_end_session(self):
        self.bind()
        code, out = http("POST", self.url + "/v1/sessions/s-1/end")
        self.assertEqual((code, out["state"]), (200, "ended"))
        self.assertIn(("PATCH", "/api/v1/sessions/s-1", None), FakeAPI.state["calls"])


if __name__ == "__main__":
    unittest.main()
