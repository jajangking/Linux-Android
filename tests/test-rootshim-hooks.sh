#!/usr/bin/env sh
# Regression test: every hooked path operation must land inside ROOTSHIM_ROOT.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rootshim-hooks.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/rootfs"
mkdir -p "$root/etc"
printf 'from-rootfs\n' > "$root/etc/marker"

set +e
output=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 \
    LD_PRELOAD="$repo/build/librootshim.so" \
    "$repo/build/rootshim-hooks" 2>&1)
status=$?
set -e
printf '%s\n' "$output"

if [ "$status" -ne 0 ]; then
    echo "rootshim hook regression: $status failing check(s)" >&2
    exit 1
fi
if [ ! -f "$root/rsh-d/f" ] || [ ! -L "$root/rsh-d/l" ]; then
    echo 'rootshim hook regression: expected files missing inside rootfs' >&2
    exit 1
fi
if [ -e /rsh-d ]; then
    echo 'rootshim hook regression: operations leaked to host /rsh-d' >&2
    exit 1
fi

echo 'rootshim hook regression test: PASS'
