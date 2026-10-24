"""Client for the `/v1/systemone` decision protocol (TypeSafe Jev; Laya's `laya-serve` speaks the same).

These are DECISION models, not chat models: you send a `state` (a string or a JSON object) plus typed
`questions`, and one forward pass answers every question. Nothing is generated, so there is no prose
to parse and nothing for an injected instruction to talk into. What the model returns per question:

    choice  {"type": "choice", "choice": <option>, "probabilities": {<option>: p, ...}, "confidence": p}
    noul    {"type": "noul", "noul": p_yes, "confidence": p}
    score   {"type": "score", ...}

There is no abstain option in the protocol. `answer_or_unknown()` derives "unknown" from the
confidence, because the base Laya checkpoint is near chance zero-shot and over-confident until it is
fine-tuned: callers must keep the threshold conservative and configurable (RIVER3_DRIFT_MIN_CONFIDENCE).

Transport rules (same as the other model endpoints in this service): https, or plain http to loopback
only; a bearer token when the server has one; no redirects; request and response bodies bounded;
every failure is a typed `SystemOneError` so the caller can record a reason and treat it as unknown.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import httpx

MAX_REQUEST_BYTES = 64 * 1024     # chunks are ~1.2 KB; anything near this is a bug, not a payload
MAX_RESPONSE_BYTES = 256 * 1024   # answers are a few hundred bytes
MIN_MAX_LEN, MAX_MAX_LEN = 64, 8192  # the server's context window argument

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class SystemOneError(RuntimeError):
    """A failed decision call. `kind` is one of: url, too_large, transport, timeout, auth, http, protocol."""

    def __init__(self, kind: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.kind, self.status = kind, status

    def __str__(self) -> str:
        base = super().__str__()
        return f"{self.kind}: {base}" if base else self.kind


def url_problem(url: str | None, *, require_https: bool = False, name: str = "URL") -> str | None:
    """None when `url` is acceptable for model traffic: https anywhere, or plain http to loopback (which
    cannot be tapped from the network). `require_https` is for hosted models: agent logs leave the host."""
    if not url:
        return f"{name} is not set"
    u = urlsplit(url)
    if u.scheme == "https" and u.hostname:
        return None
    if u.scheme != "http" or not u.hostname:
        return f"{name} must be an http(s) URL, not {url!r}"
    if require_https:
        return f"{name} must use https:// (agent logs leave this host), not {url!r}"
    host = u.hostname.lower()
    if host in _LOOPBACK_HOSTS or host.startswith("127."):
        return None
    return f"{name}={url!r} is plain http to a non-loopback host; use https:// or a loopback address"


class SystemOneClient:
    """One decision endpoint. Stateless: each `decide()` is a single bounded POST."""

    def __init__(self, base_url: str, token: str | None = None, timeout_s: float = 8.0, max_len: int = 512,
                 *, require_https: bool = False, model: str | None = None) -> None:
        problem = url_problem(base_url, require_https=require_https)
        if problem:
            raise ValueError(problem)
        if not MIN_MAX_LEN <= int(max_len) <= MAX_MAX_LEN:
            raise ValueError(f"max_len must be between {MIN_MAX_LEN} and {MAX_MAX_LEN}")
        self.base_url = base_url.rstrip("/")
        self.token = token or None
        self.timeout_s = float(timeout_s)
        self.max_len = int(max_len)
        self.model = model or None

    @property
    def endpoint(self) -> str:
        return self.base_url + "/v1/systemone"

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def request_body(self, state: str | dict[str, Any], questions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """The exact JSON sent; exposed so docs and tests can show it."""
        body: dict[str, Any] = {"state": state, "questions": questions, "max_len": self.max_len}
        if self.model:
            body["model"] = self.model
        return body

    def decide(self, state: str | dict[str, Any], questions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        """POST /v1/systemone. Returns the parsed response, guaranteed to be a dict whose `answers` is a dict
        holding one dict per question id asked. Raises SystemOneError otherwise."""
        if not isinstance(questions, dict) or not questions:
            raise SystemOneError("protocol", "no questions to ask")
        raw = json.dumps(self.request_body(state, questions), ensure_ascii=False, separators=(",", ":")).encode()
        if len(raw) > MAX_REQUEST_BYTES:
            raise SystemOneError("too_large", f"request body {len(raw)} bytes exceeds {MAX_REQUEST_BYTES}")
        buf = bytearray()
        try:
            with httpx.Client(timeout=self.timeout_s, follow_redirects=False) as client, \
                    client.stream("POST", self.endpoint, content=raw, headers=self._headers()) as r:
                status = r.status_code
                for part in r.iter_bytes():
                    buf += part
                    if len(buf) > MAX_RESPONSE_BYTES:
                        raise SystemOneError("protocol", f"response larger than {MAX_RESPONSE_BYTES} bytes", status)
        except SystemOneError:
            raise
        except httpx.TimeoutException as exc:
            raise SystemOneError("timeout", f"no answer within {self.timeout_s:g}s") from exc
        except httpx.HTTPError as exc:
            raise SystemOneError("transport", str(exc) or exc.__class__.__name__) from exc
        if status in (401, 403):
            raise SystemOneError("auth", f"HTTP {status}: bearer token refused", status)
        if status != 200:
            raise SystemOneError("http", f"HTTP {status}", status)
        try:
            data = json.loads(bytes(buf).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SystemOneError("protocol", "response is not JSON", status) from exc
        if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
            raise SystemOneError("protocol", "response has no `answers` object", status)
        answers = data["answers"]
        missing = [q for q in questions if not isinstance(answers.get(q), dict)]
        if missing:
            raise SystemOneError("protocol", f"answers missing for {', '.join(sorted(missing))}", status)
        return data


def prob(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    f = float(v)
    if f != f or f < 0.0 or f > 1.0:  # NaN or out of range
        return None
    return f


def answer_or_unknown(answer: dict[str, Any] | None, min_confidence: float) -> tuple[str | None, float]:
    """Turns one answer into `(option, confidence)`; `option` is None when the model is not confident enough
    or the answer is malformed, which callers must read as UNKNOWN (never as the calmer option).

    choice: `choice` is returned when `confidence` (or, failing that, its probability) >= min_confidence.
    noul:   "yes" when p_yes >= min_confidence, "no" when 1 - p_yes >= min_confidence, else None;
            the returned confidence is max(p_yes, 1 - p_yes)."""
    if not isinstance(answer, dict):
        return None, 0.0
    kind = answer.get("type")
    if kind == "noul":
        p = prob(answer.get("noul"))
        if p is None:
            return None, 0.0
        conf = max(p, 1.0 - p)
        if p >= min_confidence:
            return "yes", conf
        if 1.0 - p >= min_confidence:
            return "no", conf
        return None, conf
    if kind == "choice":
        choice = answer.get("choice")
        if not isinstance(choice, str) or not choice:
            return None, 0.0
        conf = prob(answer.get("confidence"))
        if conf is None:
            probs = answer.get("probabilities")
            conf = prob(probs.get(choice)) if isinstance(probs, dict) else None
        if conf is None:
            return None, 0.0
        return (choice if conf >= min_confidence else None), conf
    return None, 0.0


def reported_model(response: dict[str, Any], prefix: str, limit: int = 64) -> str:
    """`laya:english`-style label from the response's `model` and `routing` fields, for the record."""
    parts: list[str] = []
    m = response.get("model")
    if isinstance(m, str) and m.strip():
        parts.append(m.strip())
    routing = response.get("routing")
    if isinstance(routing, dict):
        for key in ("model", "route", "language", "selected"):
            v = routing.get(key)
            if isinstance(v, str) and v.strip() and v.strip() not in parts:
                parts.append(v.strip())
                break
    label = ":".join([prefix, *parts]) if parts else prefix
    return label[:limit]
