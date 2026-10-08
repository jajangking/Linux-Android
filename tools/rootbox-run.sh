#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rootbox=${ROOTBOX_BIN:-"$repo_dir/build/rootbox"}

if [ "$#" -gt 0 ] && [ "$1" = "--" ]; then
    shift
fi
if [ "$#" -eq 0 ]; then
    echo "Usage: ROOTSHIM_ROOT=/path/to/rootfs ROOTSHIM_LIB=/path/to/matching/librootshim.so $0 [--] command [args...]" >&2
    exit 2
fi
if [ -z "${ROOTSHIM_ROOT:-}" ] || [ ! -d "$ROOTSHIM_ROOT" ]; then
    echo 'rootbox-run: set ROOTSHIM_ROOT to an existing directory' >&2
    exit 2
fi
shim=${ROOTSHIM_LIB:-"$repo_dir/build/librootshim.so"}
if [ ! -r "$shim" ]; then
    echo "rootbox-run: shim not found: $shim" >&2
    exit 2
fi
if [ ! -x "$rootbox" ]; then
    echo "rootbox-run: supervisor not built: $rootbox (run make first)" >&2
    exit 2
fi

ROOTSHIM_ROOT=$(CDPATH= cd -- "$ROOTSHIM_ROOT" && pwd)
export ROOTSHIM_ROOT
export ROOTSHIM_FAKE_ID=${ROOTSHIM_FAKE_ID:-1}
export ROOTBOX_LD_PRELOAD="$shim"
if [ -n "${ROOTSHIM_LIBRARY_PATH:-}" ]; then
    export ROOTBOX_LD_LIBRARY_PATH="$ROOTSHIM_LIBRARY_PATH"
fi

exec "$rootbox" -- "$@"
