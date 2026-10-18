"""Settings, read once from environment variables.

SENTINEL_DATABASE_URL   sqlite:///./sentinel.db (default) or postgresql+psycopg://...
SENTINEL_INGEST_TOKEN   token the sensor / policy / containment layers use to post data
SENTINEL_OPERATORS      "name:token,name2:token2"  (operators who can act in the console)
SENTINEL_ACTION_WEBHOOK optional URL; operator actions are POSTed here for the containment layer
SENTINEL_LLM_BASE_URL   OpenAI-compatible endpoint, default Ollama on localhost
SENTINEL_LLM_MODEL      default qwen3:8b
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _operators(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in filter(None, (s.strip() for s in raw.split(","))):
        name, _, token = item.partition(":")
        if name and token:
            out[token] = name
    return out


@dataclass(frozen=True)
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("SENTINEL_DATABASE_URL", "sqlite:///./sentinel.db"))
    ingest_token: str = field(default_factory=lambda: os.getenv("SENTINEL_INGEST_TOKEN", "dev-ingest-token"))
    operators: dict[str, str] = field(default_factory=lambda: _operators(os.getenv("SENTINEL_OPERATORS", "rajiv:dev-operator-token")))
    action_webhook: str | None = field(default_factory=lambda: os.getenv("SENTINEL_ACTION_WEBHOOK") or None)
    llm_base_url: str = field(default_factory=lambda: os.getenv("SENTINEL_LLM_BASE_URL", "http://localhost:11434/v1"))
    llm_model: str = field(default_factory=lambda: os.getenv("SENTINEL_LLM_MODEL", "qwen3:8b"))
    llm_timeout_s: float = field(default_factory=lambda: float(os.getenv("SENTINEL_LLM_TIMEOUT", "60")))


settings = Settings()
