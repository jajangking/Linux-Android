#!/usr/bin/env sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

set +e
output=$("$repo/build/rootbox" -- id -u 2>&1)
status=$?
set -e
printf '%s\n' "$output"

if [ "$status" -eq 125 ]; then
    echo 'seccomp user notification unavailable here; supervisor test: SKIP'
    exit 0
fi
if [ "$status" -ne 0 ]; then
    echo "rootbox exited with status $status" >&2
    exit "$status"
fi
if [ "$(printf '%s\n' "$output" | tail -n 1)" != '0' ]; then
    echo 'expected child to observe synthetic uid 0' >&2
    exit 1
fi

echo 'seccomp supervisor smoke test: PASS'
