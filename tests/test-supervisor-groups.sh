#!/usr/bin/env sh
# Regression test: under rootbox, getgroups() must list group 0 (the synthetic
# getegid() value), not an empty list.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

set +e
output=$("$repo/build/rootbox" -- "$repo/build/repro-getgroups" 2>&1)
status=$?
set -e
printf '%s\n' "$output"

case "$status" in
    0)
        echo 'rootbox getgroups consistency test: PASS'
        ;;
    125)
        echo 'seccomp user notification unavailable here; getgroups test: SKIP'
        ;;
    *)
        echo "rootbox getgroups consistency test: FAIL (exit $status)" >&2
        exit 1
        ;;
esac
