"""Admin helpers.

    python -m river3_api.cli new-token           # prints a new token and its SHA-256 for the principals file
    python -m river3_api.cli hash-token          # reads a token from stdin, prints its SHA-256
    python -m river3_api.cli new-secret          # 48-byte random secret for RIVER3_SECRET_KEY / RIVER3_WEBHOOK_SECRET
    python -m river3_api.cli check-config        # validates settings, roles and principals; exit 1 on problems
    python -m river3_api.cli verify-audit        # checks the audit hash chain; exit 1 if broken
"""
from __future__ import annotations

import json
import secrets
import sys


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "help"
    if cmd == "new-token":
        from .tokens import generate_token, sha256_hex
        tok = generate_token()
        print(json.dumps({"token": tok, "token_sha256": sha256_hex(tok)}, indent=2))
        print("Give the token to its owner once. Store only token_sha256 in the principals file.", file=sys.stderr)
        return 0
    if cmd == "hash-token":
        from .tokens import sha256_hex
        print(sha256_hex(sys.stdin.readline().strip()))
        return 0
    if cmd == "new-secret":
        print(secrets.token_urlsafe(48))
        return 0
    if cmd == "check-config":
        from .config import ConfigError, settings, validate
        try:
            from .security import PRINCIPALS, ROLES, configure_logging
        except ConfigError as exc:
            print(f"principals/roles: {exc}")
            return 1
        configure_logging()  # validate() logs warnings (e.g. the plain-http model override); show them as the server would
        problems = validate(settings)
        for p in problems:
            print(f"problem: {p}")
        print(f"env={settings.env} roles={sorted(ROLES)} principals={len(PRINCIPALS)}")
        return 1 if problems else 0
    if cmd == "verify-audit":
        from .audit import verify_chain
        from .db import SessionLocal
        with SessionLocal() as db:
            res = verify_chain(db)
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    print(__doc__)
    return 0 if cmd == "help" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
