#!/usr/bin/env sh
# Combined rootbox + shim smoke test. Deliberately independent of the host
# PATH: the program under test is a compiled probe, and the shell check uses
# only builtins plus an absolute path to sh, so host PATH entries (which the
# shim hides from inside the rootfs) cannot affect the result.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rootbox-combined.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/rootfs"
mkdir -p "$root/etc"
printf 'from-rootfs\n' > "$root/etc/rootshim-marker"
sh_bin=$(command -v sh)

set +e
output=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 \
    ROOTSHIM_LIB="$repo/build/librootshim.so" \
    "$repo/tools/rootbox-run.sh" -- "$repo/build/rootshim-probe" 2>&1)
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
printf '%s\n' "$output" | grep -F 'cwd=/ uid=0 gid=0 st_uid=0 marker=from-rootfs' >/dev/null

set +e
shell_out=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 \
    ROOTSHIM_LIB="$repo/build/librootshim.so" \
    "$repo/tools/rootbox-run.sh" -- "$sh_bin" -c \
    'cd /; IFS= read -r marker < /etc/rootshim-marker; printf "shell-marker=%s\n" "$marker"' 2>&1)
shell_status=$?
set -e
printf '%s\n' "$shell_out"
if [ "$shell_status" -ne 0 ]; then
    echo "combined shell check exited with status $shell_status" >&2
    exit 1
fi
printf '%s\n' "$shell_out" | grep -F 'shell-marker=from-rootfs' >/dev/null

echo 'combined rootbox/shim smoke test: PASS'
