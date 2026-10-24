"""Settings, read once from environment variables.

RIVER3_ENV               "development" (default) or "production"
RIVER3_DATABASE_URL      sqlite:///./river3.db (default) or postgresql+psycopg://user:pass@host/db
RIVER3_SECRET_KEY        >= 32 chars, required in production (signs stream tickets)
RIVER3_PRINCIPALS_FILE   JSON file of people and machines allowed to call the API (see principals.example.json)
RIVER3_PRINCIPALS        same JSON inline (handy for containers / tests)
RIVER3_ROLES_FILE        optional JSON file that redefines roles -> permissions for this business
RIVER3_ACTION_WEBHOOK    optional HTTPS URL; operator actions are POSTed here, HMAC-signed
RIVER3_WEBHOOK_SECRET    >= 32 chars, required when RIVER3_ACTION_WEBHOOK is set; shared with the containment controller only
RIVER3_ALERT_WEBHOOK     optional HTTPS URL; new incidents at or above the threshold are POSTed here (Slack-style "text" + JSON)
RIVER3_ALERT_SECRET      >= 32 chars; signs alert webhooks. Required in production when RIVER3_ALERT_WEBHOOK is set and must
                         differ from RIVER3_WEBHOOK_SECRET (the alert receiver must not be able to forge operator actions).
                         Development without it: alerts go out unsigned, with a warning in the log.
RIVER3_ALERT_MIN_SEVERITY info | high (default) | critical
RIVER3_CANARY_SECRET     >= 32 chars; lets a canary-credential service POST /api/v1/canary with an HMAC instead of a bearer token
RIVER3_REVOKE_WEBHOOK    optional URL; operator `revoke` requests are POSTed here (gateway / identity provider / cloud-role
                         revoker), HMAC-signed like actions but with RIVER3_REVOKE_SECRET; https:// in production
RIVER3_REVOKE_SECRET     >= 32 chars, required when RIVER3_REVOKE_WEBHOOK is set; must differ from the action and alert secrets
RIVER3_SESSION_WINDOW_S  default 30; an event with no facts.session is attributed to the latest agent-log tool_call for the
                         same workload within this many seconds (recorded as source "correlated", advisory only); 0 disables
RIVER3_APPROVAL_TTL_S    default 120; how long a held approval (POST /api/v1/approvals -> hold) waits for an operator before
                         it reads as expired, which the gateway must treat as deny
RIVER3_LLM_BASE_URL      OpenAI-compatible endpoint, default Ollama on localhost. In production it must be https:// or
                         plain http:// to loopback only; RIVER3_LLM_ALLOW_PLAIN_HTTP=true overrides that for a model on the
                         docker host (host.docker.internal) and is logged as a warning
RIVER3_LLM_MODEL         default qwen3:8b
RIVER3_LLM_TIMEOUT       seconds per summary call, default 60
RIVER3_DRIFT_MODEL       off (default) | laya | jev | llm. Who answers the typed drift question over the agent's log:
                           laya  local Laya decision model (`laya-serve`, /v1/systemone protocol) at RIVER3_LAYA_URL
                           jev   TypeSafe Jev, hosted, same protocol; needs RIVER3_JEV_URL (https) and RIVER3_JEV_OPT_IN=true
                           llm   an OpenAI-compatible chat model (Qwen-style, RIVER3_LLM_*) asked for a one-word JSON answer
RIVER3_LAYA_URL          default http://127.0.0.1:8600 (run `LAYA_PORT=8600 laya-serve`: its default 8000 is this API's
                         port). https://, or plain http:// to loopback only
RIVER3_LAYA_TOKEN        optional; sent as a bearer token when laya-serve runs with LAYA_API_KEY
RIVER3_JEV_URL / RIVER3_JEV_TOKEN / RIVER3_JEV_OPT_IN / RIVER3_JEV_MODEL   hosted model; agent logs leave the network, so
                         https:// and the explicit opt-in are required. MODEL is optional (the protocol's `model` field)
RIVER3_DRIFT_MIN_CONFIDENCE  default 0.6, in (0, 1]. A laya/jev answer below it is `unknown` (the protocol has no abstain
                         option and the base Laya checkpoint is over-confident until fine-tuned: keep this conservative)
RIVER3_DRIFT_MAX_LEN     default 512 (Laya's English context; 1024 multilingual; up to 8192) -> the protocol's `max_len`
RIVER3_DRIFT_*           early-warning thresholds (WINDOW_MIN, FAILS_RISING, FAILS_HIGH, NEW_RESOURCES_RISING,
                         SHARED_WRITES_RISING, SHARED_WRITES_HIGH, UNLOGGED_MIN_EVENTS, BASELINE_MIN_EVENTS,
                         MODEL_TIMEOUT) and ALERT_COOLDOWN (seconds between tier alerts per workload, default 600)
RIVER3_MAX_BODY_BYTES    default 1 MiB
RIVER3_HSTS              "true" when served over HTTPS
RIVER3_TRUSTED_PROXY     "true" if behind a reverse proxy that sets X-Forwarded-For
RIVER3_AUTH_FAIL_LIMIT / RIVER3_AUTH_FAIL_WINDOW   failed sign-ins per client IP (default 20) per window (default 300 s) before 429
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import systemone

log = logging.getLogger("river3.config")


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _json_source(inline_var: str, file_var: str) -> object | None:
    inline = os.getenv(inline_var)
    if inline:
        return json.loads(inline)
    path = os.getenv(file_var)
    if path:
        return json.loads(Path(path).read_text())
    return None


# Development-only principals. Refused in production (see validate()).
DEV_PRINCIPALS = [
    {"name": "rajiv", "kind": "operator", "role": "admin", "token": "dev-operator-token"},
    {"name": "lab-sensor", "kind": "machine", "role": "sensor", "token": "dev-sensor-token"},
    {"name": "lab-policy", "kind": "machine", "role": "policy", "token": "dev-policy-token"},
    {"name": "lab-containment", "kind": "machine", "role": "containment", "token": "dev-containment-token"},
]


@dataclass(frozen=True)
class Settings:
    env: str = field(default_factory=lambda: os.getenv("RIVER3_ENV", "development").strip().lower())
    database_url: str = field(default_factory=lambda: os.getenv("RIVER3_DATABASE_URL", "sqlite:///./river3.db"))
    secret_key: str = field(default_factory=lambda: os.getenv("RIVER3_SECRET_KEY") or secrets.token_urlsafe(48))
    secret_key_set: bool = field(default_factory=lambda: bool(os.getenv("RIVER3_SECRET_KEY")))
    principals_raw: object = field(default_factory=lambda: _json_source("RIVER3_PRINCIPALS", "RIVER3_PRINCIPALS_FILE"))
    roles_raw: object = field(default_factory=lambda: _json_source("RIVER3_ROLES", "RIVER3_ROLES_FILE"))
    action_webhook: str | None = field(default_factory=lambda: os.getenv("RIVER3_ACTION_WEBHOOK") or None)
    webhook_secret: str | None = field(default_factory=lambda: os.getenv("RIVER3_WEBHOOK_SECRET") or None)
    alert_webhook: str | None = field(default_factory=lambda: os.getenv("RIVER3_ALERT_WEBHOOK") or None)
    alert_secret: str | None = field(default_factory=lambda: os.getenv("RIVER3_ALERT_SECRET") or None)
    alert_min_severity: str = field(default_factory=lambda: os.getenv("RIVER3_ALERT_MIN_SEVERITY", "high").strip().lower())
    canary_secret: str | None = field(default_factory=lambda: os.getenv("RIVER3_CANARY_SECRET") or None)
    # Session governance (CONTRACTS 22 Oct §1-3). The revoke receiver is its own trust domain: a gateway or
    # identity provider must not be able to forge containment actions or alerts, so it gets its own key.
    revoke_webhook: str | None = field(default_factory=lambda: os.getenv("RIVER3_REVOKE_WEBHOOK") or None)
    revoke_secret: str | None = field(default_factory=lambda: os.getenv("RIVER3_REVOKE_SECRET") or None)
    session_window_s: int = field(default_factory=lambda: int(os.getenv("RIVER3_SESSION_WINDOW_S", "30")))
    approval_ttl_s: int = field(default_factory=lambda: int(os.getenv("RIVER3_APPROVAL_TTL_S", "120")))
    llm_base_url: str = field(default_factory=lambda: os.getenv("RIVER3_LLM_BASE_URL", "http://localhost:11434/v1"))
    llm_model: str = field(default_factory=lambda: os.getenv("RIVER3_LLM_MODEL", "qwen3:8b"))
    llm_timeout_s: float = field(default_factory=lambda: float(os.getenv("RIVER3_LLM_TIMEOUT", "60")))
    llm_allow_plain_http: bool = field(default_factory=lambda: _bool("RIVER3_LLM_ALLOW_PLAIN_HTTP"))
    max_body_bytes: int = field(default_factory=lambda: int(os.getenv("RIVER3_MAX_BODY_BYTES", str(1 << 20))))
    hsts: bool = field(default_factory=lambda: _bool("RIVER3_HSTS"))
    trusted_proxy: bool = field(default_factory=lambda: _bool("RIVER3_TRUSTED_PROXY"))
    # Early warning (drift tiers). Thresholds are starting points for design partners to tune.
    drift_window_min: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_WINDOW_MIN", "10")))
    drift_fails_rising: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_FAILS_RISING", "10")))
    drift_fails_high: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_FAILS_HIGH", "40")))
    drift_new_resources_rising: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_NEW_RESOURCES_RISING", "20")))
    drift_shared_writes_rising: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_SHARED_WRITES_RISING", "1")))
    drift_shared_writes_high: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_SHARED_WRITES_HIGH", "5")))
    drift_unlogged_min_events: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_UNLOGGED_MIN_EVENTS", "10")))
    # Below this many baseline events "a resource it never touched before" means nothing yet.
    drift_baseline_min_events: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_BASELINE_MIN_EVENTS", "20")))
    # Per-workload cooldown between tier alerts; inside it only a HIGHER tier than already alerted is sent.
    drift_alert_cooldown_s: float = field(default_factory=lambda: float(os.getenv("RIVER3_DRIFT_ALERT_COOLDOWN", "600")))
    # off (default) | laya (local decision model, RIVER3_LAYA_*) | jev (hosted; needs RIVER3_JEV_URL https and
    # RIVER3_JEV_OPT_IN=true) | llm (OpenAI-compatible chat model, RIVER3_LLM_*)
    drift_model: str = field(default_factory=lambda: os.getenv("RIVER3_DRIFT_MODEL", "off").strip().lower())
    drift_model_timeout_s: float = field(default_factory=lambda: float(os.getenv("RIVER3_DRIFT_MODEL_TIMEOUT", "8")))
    # Below this confidence a laya/jev answer is `unknown`. The protocol cannot abstain; this is where abstention lives.
    drift_min_confidence: float = field(default_factory=lambda: float(os.getenv("RIVER3_DRIFT_MIN_CONFIDENCE", "0.6")))
    drift_max_len: int = field(default_factory=lambda: int(os.getenv("RIVER3_DRIFT_MAX_LEN", "512")))
    laya_url: str = field(default_factory=lambda: os.getenv("RIVER3_LAYA_URL", "http://127.0.0.1:8600").strip())
    laya_token: str | None = field(default_factory=lambda: os.getenv("RIVER3_LAYA_TOKEN") or None)
    jev_url: str | None = field(default_factory=lambda: os.getenv("RIVER3_JEV_URL") or None)
    jev_model: str | None = field(default_factory=lambda: os.getenv("RIVER3_JEV_MODEL") or None)
    jev_token: str | None = field(default_factory=lambda: os.getenv("RIVER3_JEV_TOKEN") or None)
    jev_opt_in: bool = field(default_factory=lambda: _bool("RIVER3_JEV_OPT_IN"))
    auth_fail_limit: int = field(default_factory=lambda: int(os.getenv("RIVER3_AUTH_FAIL_LIMIT", "20")))
    auth_fail_window_s: int = field(default_factory=lambda: int(os.getenv("RIVER3_AUTH_FAIL_WINDOW", "300")))

    @property
    def production(self) -> bool:
        return self.env == "production"


class ConfigError(RuntimeError):
    pass


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def llm_url_problem(s: Settings) -> str | None:
    """Plain http to a model endpoint lets anyone on the path read incident facts and agent logs
    and rewrite the model's answers. Loopback can't be tapped from the network, so it is allowed;
    anything else needs https, or the explicit override for the docker host-gateway case where
    the traffic stays on one machine but the hostname isn't loopback."""
    u = urlsplit(s.llm_base_url)
    if u.scheme == "https":
        return None
    if u.scheme != "http":
        return f"RIVER3_LLM_BASE_URL must be an http(s) URL, not {s.llm_base_url!r}"
    host = (u.hostname or "").lower()
    if host in _LOOPBACK_HOSTS or host.startswith("127."):
        return None
    if s.llm_allow_plain_http:
        log.warning("config.llm_plain_http", extra={"url": s.llm_base_url,
                    "note": "RIVER3_LLM_ALLOW_PLAIN_HTTP=true: model traffic is unencrypted; keep it on one host"})
        return None
    return (f"RIVER3_LLM_BASE_URL={s.llm_base_url!r} is plain http to a non-loopback host; use https://, "
            "or set RIVER3_LLM_ALLOW_PLAIN_HTTP=true if the model runs on the docker host (host.docker.internal)")


def validate(s: Settings) -> list[str]:
    """Returns a list of problems. In production any problem stops the server from starting."""
    problems: list[str] = []
    if s.env not in ("development", "production"):
        problems.append(f"RIVER3_ENV must be development or production, not {s.env!r}")
    if s.production:
        if not s.secret_key_set or len(s.secret_key) < 32:
            problems.append("RIVER3_SECRET_KEY must be set to at least 32 characters")
        if s.principals_raw is None:
            problems.append("RIVER3_PRINCIPALS_FILE (or RIVER3_PRINCIPALS) is required; dev principals are refused")
        if s.database_url.startswith("sqlite"):
            problems.append("use PostgreSQL in production (RIVER3_DATABASE_URL=postgresql+psycopg://...)")
        if (llm := llm_url_problem(s)):
            problems.append(llm)
    elif (llm := llm_url_problem(s)):
        log.warning("config.llm_plain_http", extra={"note": llm + " (refused in production)"})
    if s.webhook_secret is not None and len(s.webhook_secret) < 32:
        problems.append("RIVER3_WEBHOOK_SECRET must be >= 32 chars")
    if s.action_webhook:
        if s.production and not s.action_webhook.startswith("https://"):
            problems.append("RIVER3_ACTION_WEBHOOK must use https:// in production")
        if not s.webhook_secret:
            problems.append("RIVER3_WEBHOOK_SECRET (>= 32 chars) is required when RIVER3_ACTION_WEBHOOK is configured")
    if s.alert_secret is not None and len(s.alert_secret) < 32:
        problems.append("RIVER3_ALERT_SECRET must be >= 32 chars")
    # The alert receiver (Slack relay, pager) is a different trust domain from the containment
    # controller. One shared key would let whoever holds the alert endpoint forge operator actions.
    if s.alert_secret is not None and s.webhook_secret is not None and s.alert_secret == s.webhook_secret:
        problems.append("RIVER3_ALERT_SECRET must differ from RIVER3_WEBHOOK_SECRET (alerts must not share the action key)")
    if s.alert_webhook:
        if s.production and not s.alert_webhook.startswith("https://"):
            problems.append("RIVER3_ALERT_WEBHOOK must use https:// in production")
        if s.production and not s.alert_secret:
            problems.append("RIVER3_ALERT_SECRET (>= 32 chars) is required when RIVER3_ALERT_WEBHOOK is set in production: "
                            "alerts are never sent unsigned, and they must not be signed with RIVER3_WEBHOOK_SECRET")
    if s.alert_min_severity not in ("info", "high", "critical"):
        problems.append("RIVER3_ALERT_MIN_SEVERITY must be info, high or critical")
    if s.canary_secret is not None and len(s.canary_secret) < 32:
        problems.append("RIVER3_CANARY_SECRET must be >= 32 chars")
    if s.revoke_secret is not None and len(s.revoke_secret) < 32:
        problems.append("RIVER3_REVOKE_SECRET must be >= 32 chars")
    if s.revoke_secret is not None and s.revoke_secret in (s.webhook_secret, s.alert_secret):
        problems.append("RIVER3_REVOKE_SECRET must differ from RIVER3_WEBHOOK_SECRET and RIVER3_ALERT_SECRET "
                        "(the session revoker must not be able to forge containment actions or alerts)")
    if s.revoke_webhook:
        if s.production and not s.revoke_webhook.startswith("https://"):
            problems.append("RIVER3_REVOKE_WEBHOOK must use https:// in production")
        if not s.revoke_secret:
            problems.append("RIVER3_REVOKE_SECRET (>= 32 chars) is required when RIVER3_REVOKE_WEBHOOK is configured")
    if not 0 <= s.session_window_s <= 3600:
        problems.append("RIVER3_SESSION_WINDOW_S must be between 0 (off) and 3600 seconds")
    if not 1 <= s.approval_ttl_s <= 86_400:
        problems.append("RIVER3_APPROVAL_TTL_S must be between 1 and 86400 seconds")
    if s.drift_model not in ("off", "laya", "jev", "llm"):
        problems.append("RIVER3_DRIFT_MODEL must be off, laya, jev or llm")
    if s.drift_model == "laya" and (p := systemone.url_problem(s.laya_url, name="RIVER3_LAYA_URL")):
        problems.append(p)  # in every environment: the client refuses the URL anyway, better to say so at start
    if s.drift_model == "jev":
        if (p := systemone.url_problem(s.jev_url, require_https=True, name="RIVER3_JEV_URL")):
            problems.append(p + " (required for RIVER3_DRIFT_MODEL=jev)")
        if not s.jev_opt_in:
            problems.append("RIVER3_JEV_OPT_IN=true is required: Jev sends agent logs off the network")
    if not 0.0 < s.drift_min_confidence <= 1.0:
        problems.append("RIVER3_DRIFT_MIN_CONFIDENCE must be in (0, 1]")
    if not systemone.MIN_MAX_LEN <= s.drift_max_len <= systemone.MAX_MAX_LEN:
        problems.append(f"RIVER3_DRIFT_MAX_LEN must be between {systemone.MIN_MAX_LEN} and {systemone.MAX_MAX_LEN}")
    if s.max_body_bytes < 1024:
        problems.append("RIVER3_MAX_BODY_BYTES is too small")
    return problems


settings = Settings()
