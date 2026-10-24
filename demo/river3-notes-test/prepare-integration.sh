#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
target="$PWD/integration"
source_root="${RIVER3_SOURCE:-/home/rajivravindran/Downloads/river3}"
go_bin="${GO_BIN:-/usr/local/go/bin/go}"
mkdir -p "$target/bin" "$target/profiles" "$target/state"
python3 - "$source_root" "$target" <<'PY'
from pathlib import Path
import shutil
import sys
src, dst = map(Path, sys.argv[1:])
(dst/'api').mkdir(exist_ok=True)
for name in ['river3_api', 'migrations', 'static']:
    shutil.copytree(src/'api'/name, dst/'api'/name, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
for name in ['requirements.lock', 'alembic.ini']:
    shutil.copy2(src/'api'/name, dst/'api'/name)
shutil.copy2(src/'demo/registry.json', dst/'registry.json')
PY
export GOCACHE="${GOCACHE:-/tmp/river3-notes-go-cache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/river3-notes-go-mod}"
export CGO_ENABLED=0
(cd "$source_root/river3d" && "$go_bin" build -mod=readonly -o "$target/bin/river3d" .)
(cd "$source_root/containment" && "$go_bin" build -mod=readonly -o "$target/bin/river3-containd" ./cmd/river3-containd)
echo 'Prepared the River3 API snapshot and Linux binaries.'
