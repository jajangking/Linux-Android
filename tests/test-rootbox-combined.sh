#!/usr/bin/env sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/rootfs"
mkdir -p "$root/etc"
printf 'from-rootfs\n' > "$root/etc/rootshim-marker"

set +e
output=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 \
    ROOTSHIM_LIB="$repo/build/librootshim.so" \
    "$repo/tools/rootbox-run.sh" -- sh -c \
    'cd /; IFS= read -r marker < /etc/rootshim-marker; printf "cwd=%s uid=%s marker=%s\n" "$(pwd)" "$(id -u)" "$marker"' 2>&1)
status=$?
set -e
printf '%s\n' "$output"

if [ "$status" -eq 125 ]; then
    echo 'seccomp user notification unavailable here; combined test: SKIP'
    exit 0
fi
if [ "$status" -ne 0 ]; then
    echo "combined runner exited with status $status" >&2
    exit "$status"
fi
printf '%s\n' "$output" | grep -F 'cwd=/ uid=0 marker=from-rootfs' >/dev/null
echo 'combined rootbox/shim smoke test: PASS'
