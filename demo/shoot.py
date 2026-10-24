#!/usr/bin/env python3
"""Takes the console screenshots for docs/evidence/ after demo/run.sh has frozen both agents.

    demo/shoot.py [--out docs/evidence] [--date YYYY-MM-DD] [--url http://127.0.0.1:8000] [--token ...]

Writes <out>/<date>-console-incidents.png, -console-incident-coding-agent.png, -console-workloads.png,
-console-workload-devops-agent.png and -console-approvals.png.

The browser work is in demo/shoot.mjs: the Playwright on this host is the Node package (global npm
root, browsers in /opt/pw-browsers); there is no Python binding installed. This file finds it, waits
for the API, and runs the script, so the operator only ever types one command.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def playwright_index() -> str:
    """The Playwright package: $PLAYWRIGHT_INDEX, else <npm root -g>/playwright/index.mjs, else 'playwright'."""
    if (p := os.environ.get("PLAYWRIGHT_INDEX")):
        return p
    try:
        root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, check=True).stdout.strip()
        cand = os.path.join(root, "playwright", "index.mjs")
        if os.path.exists(cand):
            return cand
    except (OSError, subprocess.CalledProcessError):
        pass
    return "playwright"


def wait_api(url: str, seconds: int = 30) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/api/health", timeout=3):
                return
        except OSError:
            time.sleep(1)
    sys.exit(f"console not reachable at {url}; is demo/run.sh running?")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "evidence"))
    ap.add_argument("--date", default=dt.date.today().isoformat())
    ap.add_argument("--url", default=os.environ.get("RIVER3_CONSOLE", "http://127.0.0.1:8000"))
    ap.add_argument("--token", default=os.environ.get("RIVER3_OPERATOR_TOKEN", "dev-operator-token"))
    a = ap.parse_args()
    wait_api(a.url)
    env = {**os.environ}
    env.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers" if os.path.isdir("/opt/pw-browsers") else "")
    cmd = ["node", os.path.join(HERE, "shoot.mjs"), a.url, a.token, a.out, a.date, playwright_index()]
    sys.exit(subprocess.run(cmd, env={k: v for k, v in env.items() if v != ""}).returncode)


if __name__ == "__main__":
    main()
