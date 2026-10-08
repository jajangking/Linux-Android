#!/usr/bin/env sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/rootfs"
mkdir -p "$root/etc"
printf 'from-rootfs\n' > "$root/etc/rootshim-marker"

output=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 \
    LD_PRELOAD="$repo/build/librootshim.so" \
    "$repo/build/rootshim-probe")
printf '%s\n' "$output"
printf '%s\n' "$output" | grep -F 'cwd=/' >/dev/null
printf '%s\n' "$output" | grep -F 'uid=0 gid=0 st_uid=0 marker=from-rootfs' >/dev/null

echo 'rootshim smoke test: PASS'
