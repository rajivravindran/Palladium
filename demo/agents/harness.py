"""The scripted agents' tool loop: the part of an agent harness that talks to the River3 gateway.

Everything an agent does goes through `Harness.tool(...)`:
  1. the call is written to the agent log (`/v1/log`, kind tool_call),
  2. the gateway is asked (`/v1/tools/run`): allow / hold (wait for a human) / deny,
  3. the tool runs,
  4. the result is logged (kind tool_result, status ok|error).

The kernel sees step 3 regardless of what the log says: this file is Channel B, the sensor is
Channel A. Without GATEWAY_URL the harness only prints, so the agents also run stand-alone.

Environment: GATEWAY_URL, RIVER3_WORKLOAD_ID, RIVER3_PRINCIPAL, DEMO_FAST (shrink every pause).
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

FAST = os.environ.get("DEMO_FAST", "") not in ("", "0", "false")


def pace(seconds: float) -> None:
    time.sleep(seconds * (0.15 if FAST else 1.0))


def say(msg: str) -> None:
    sys.stdout.write(time.strftime("%H:%M:%S ") + msg + "\n")
    sys.stdout.flush()


class Denied(Exception):
    pass


class Harness:
    def __init__(self, default_workload: str, default_principal: str):
        self.url = os.environ.get("GATEWAY_URL", "").rstrip("/")
        self.workload = os.environ.get("RIVER3_WORKLOAD_ID", default_workload)
        self.principal = os.environ.get("RIVER3_PRINCIPAL", default_principal)
        self.session = f"{self.workload}-run-{uuid.uuid4().hex[:8]}"
        self.seq = 0

    # ----- transport
    def _post(self, path: str, body: object, timeout: float = 30.0) -> tuple[int, dict]:
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError) as e:
            return 0, {"detail": str(e)}

    # ----- session
    def bind(self, wait_s: float = 120.0) -> None:
        """Binds the session. The workload appears at the API when the sensor enrols the container, so a
        fresh container may have to wait a few seconds (422 unknown workload)."""
        say(f"session {self.session} as {self.principal} on {self.workload}")
        if not self.url:
            say("no GATEWAY_URL: printing only")
            return
        deadline = time.time() + wait_s
        while True:
            code, out = self._post("/v1/sessions", {"session_id": self.session, "workload_id": self.workload,
                                                    "principal": self.principal})
            if code == 201:
                say("session bound through the gateway")
                return
            if time.time() > deadline:
                sys.exit(f"could not bind session: {code} {out}")
            say(f"gateway not ready ({code} {out.get('detail', '')}); retrying")
            time.sleep(2)

    def end(self) -> None:
        if self.url:
            self._post(f"/v1/sessions/{self.session}/end", {})
        say("session ended")

    # ----- log (Channel B: the agent's own words)
    def log(self, kind: str, text: str = "", *, tool: str = "", status: str = "", target: str = "") -> None:
        self.seq += 1
        entry = {"id": f"{self.session}-{self.seq:04d}", "kind": kind, "tool": tool, "status": status,
                 "target": target[:512], "text": text[:4000]}
        say(f"[{kind}{' ' + tool if tool else ''}{' ' + status if status else ''}] {target or ''} {text}".rstrip())
        if self.url:
            code, out = self._post("/v1/log", {"workload_id": self.workload, "session_id": self.session, "entries": [entry]})
            if code != 201:
                say(f"  (log not accepted: {code} {out.get('detail', '')})")

    # ----- tools
    def tool(self, name: str, target: str, fn, *, summary: str = ""):
        """Logs, asks the gateway, runs `fn()`, logs the result. Raises Denied when the gateway says no."""
        self.log("tool_call", summary, tool=name, target=target)
        if self.url:
            code, out = self._post("/v1/tools/run", {"workload_id": self.workload, "session_id": self.session,
                                                     "tool": name, "args_summary": (summary or target)[:512]}, timeout=900)
            if code != 200 or out.get("decision") != "allow":
                self.log("tool_result", f"gateway refused: {out.get('reason', code)}", tool=name, status="error", target=target)
                raise Denied(out.get("reason", str(code)))
            if out.get("approval_id"):
                say(f"  held for a human and {out.get('reason')}")
        try:
            result = fn()
        except Exception as e:  # the tool failed; that is a result too
            self.log("tool_result", f"{type(e).__name__}: {e}", tool=name, status="error", target=target)
            return None
        self.log("tool_result", str(result)[:300] if result is not None else "ok", tool=name, status="ok", target=target)
        return result
