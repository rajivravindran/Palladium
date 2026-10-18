#!/usr/bin/env bash
# Builds a small lab container image ("sentinel-lab-base") from binaries already
# on this host. Used because public registries are unreachable from the lab.
# On a normal machine you can replace this with `FROM python:3.12-slim`.
set -euo pipefail

IMAGE="${1:-sentinel-lab-base:latest}"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

BINS=(sh bash cat ls grep sleep env curl head tail wc id whoami mkdir rm cp echo
      true false ps base64 dd timeout nc python3.12 capsh)

copy_with_libs() {
  local bin="$1"
  local path
  path="$(type -P "$bin" 2>/dev/null)"; [ -n "$path" ] || { echo "skip: $bin"; return 0; }
  path="$(readlink -f "$path")"
  mkdir -p "$ROOT$(dirname "$path")"
  cp -L "$path" "$ROOT$path"
  # link under /usr/bin/<name> so PATH lookups work
  mkdir -p "$ROOT/usr/bin"
  [ "$ROOT$path" = "$ROOT/usr/bin/$bin" ] || ln -sf "$path" "$ROOT/usr/bin/$bin"
  ldd "$path" 2>/dev/null | grep -oE '/[^ ]+' | while read -r lib; do
    [ -f "$lib" ] || continue
    mkdir -p "$ROOT$(dirname "$lib")"
    cp -Ln "$lib" "$ROOT$lib" 2>/dev/null || true
  done
}

for b in "${BINS[@]}"; do copy_with_libs "$b"; done
ln -sf /usr/bin/python3.12 "$ROOT/usr/bin/python3"
mkdir -p "$ROOT/bin" && ln -sf /usr/bin/sh "$ROOT/bin/sh" && ln -sf /usr/bin/bash "$ROOT/bin/bash"

# Python stdlib (needed by python3 workloads)
mkdir -p "$ROOT/usr/lib"
cp -a /usr/lib/python3.12 "$ROOT/usr/lib/"
rm -rf "$ROOT/usr/lib/python3.12/test" "$ROOT/usr/lib/python3.12/__pycache__"

# CA certs + minimal /etc
mkdir -p "$ROOT/etc/ssl/certs" "$ROOT/tmp" "$ROOT/root" "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/workspace"
cp -L /etc/ssl/certs/ca-certificates.crt "$ROOT/etc/ssl/certs/" 2>/dev/null || true
echo 'root:x:0:0:root:/root:/bin/bash' > "$ROOT/etc/passwd"
echo 'agent:x:1000:1000:agent:/workspace:/bin/bash' >> "$ROOT/etc/passwd"
printf 'root:x:0:\nagent:x:1000:\n' > "$ROOT/etc/group"
echo 'hosts: files dns' > "$ROOT/etc/nsswitch.conf"
chmod 1777 "$ROOT/tmp"

tar -C "$ROOT" -c . | docker import \
  -c 'ENV PATH=/usr/bin:/bin' -c 'WORKDIR /workspace' -c 'CMD ["sleep","infinity"]' \
  - "$IMAGE" >/dev/null
echo "built $IMAGE"
