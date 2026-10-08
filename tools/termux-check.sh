#!/usr/bin/env sh
# Termux verification runner. Builds, runs the smoke tests, reproduces the
# known bugs from the 2026-10-08 codebase review, and writes a plain-text
# report to build/termux-report.txt. Does NOT modify tracked source files.
#
# Usage (from the repo root, inside Termux):
#   sh tools/termux-check.sh
set -u

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$repo/build"
report="$build/termux-report.txt"
mkdir -p "$build"
: > "$report"

pass=0; fail=0; known=0; skip=0; error=0

log() { printf '%s\n' "$*" | tee -a "$report"; }
section() { log ""; log "===== $* ====="; }
verdict() { # verdict <STATUS> <label>
    case "$1" in
        PASS) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        KNOWN-BUG) known=$((known + 1)) ;;
        SKIP) skip=$((skip + 1)) ;;
        ERROR) error=$((error + 1)) ;;
    esac
    log "[$1] $2"
}

# Pick a compiler: clang if available (Termux default after `pkg install clang`), else cc.
if command -v clang >/dev/null 2>&1; then CC_BIN=clang; else CC_BIN=cc; fi

section "Environment"
log "date: $(date)"
log "uname: $(uname -a)"
log "arch: $(uname -m)"
log "PREFIX: ${PREFIX:-<unset>}"
log "TERMUX_VERSION: ${TERMUX_VERSION:-<unset>}"
log "uid (real, via id): $(id -u 2>/dev/null || echo '?')"
log "compiler: $CC_BIN -> $($CC_BIN --version 2>/dev/null | head -1)"
log "make: $(make --version 2>/dev/null | head -1)"
log "git HEAD: $(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null) @ $(git -C "$repo" rev-parse --short HEAD 2>/dev/null)"
log "Seccomp/NoNewPrivs of this shell:"
grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status 2>/dev/null | tee -a "$report" >/dev/null || log "  (not readable)"

section "Step 1: build"
if make -C "$repo" -B CC="$CC_BIN" all >"$build/termux-build.log" 2>&1; then
    cat "$build/termux-build.log" >> "$report"
    verdict PASS "make all (CC=$CC_BIN)"
else
    cat "$build/termux-build.log" >> "$report"
    verdict FAIL "make all (CC=$CC_BIN) -- see build/termux-build.log"
    log "Build failed; remaining steps may not be meaningful."
fi

section "Step 2: make test (smoke tests)"
if make -C "$repo" CC="$CC_BIN" test >"$build/termux-test.log" 2>&1; then
    verdict PASS "make test"
else
    verdict FAIL "make test -- see build/termux-test.log"
fi
cat "$build/termux-test.log" >> "$report"
if grep -q 'SKIP' "$build/termux-test.log"; then
    log "note: at least one test reported SKIP (seccomp user notification likely unavailable here)."
fi

section "Step 3: repro chroot() on a regular file (known bug)"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rootshim-check.XXXXXX") || { verdict ERROR "mktemp"; tmp=""; }
if [ -n "$tmp" ]; then
    root="$tmp/rootfs"
    mkdir -p "$root/etc"
    printf 'from-rootfs\n' > "$root/etc/marker"
    printf 'file\n' > "$root/afile"
    if "$CC_BIN" -O2 -std=gnu11 -o "$build/repro-chroot-file" "$repo/tests/repro/chroot_file.c" 2>"$build/repro-chroot-file.err"; then
        out=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 LD_PRELOAD="$build/librootshim.so" \
              "$build/repro-chroot-file" 2>&1)
        rc=$?
        log "$out"
        case $rc in
            0) verdict PASS "chroot() failure leaves virtual root intact (bug fixed)" ;;
            2) verdict KNOWN-BUG "failed chroot() corrupts virtual root (rootshim.c chroot)" ;;
            3) verdict FAIL "chroot() to a regular file unexpectedly succeeded" ;;
            *) verdict ERROR "repro-chroot-file exit=$rc" ;;
        esac
    else
        log "$(cat "$build/repro-chroot-file.err")"
        verdict ERROR "compile tests/repro/chroot_file.c"
    fi
    rm -rf "$tmp"
fi

section "Step 4: repro getgroups() under rootbox (known bug)"
if "$CC_BIN" -O2 -std=gnu11 -o "$build/repro-getgroups" "$repo/tests/repro/getgroups.c" 2>"$build/repro-getgroups.err"; then
    out=$("$build/rootbox" -- "$build/repro-getgroups" 2>&1)
    rc=$?
    log "$out"
    case $rc in
        0) verdict PASS "getgroups() consistent with faked egid (bug fixed)" ;;
        2) verdict KNOWN-BUG "getgroups() returns 0 groups while getegid()==0 (seccomp_supervisor.c)" ;;
        125) verdict SKIP "rootbox: seccomp user notification unavailable here" ;;
        *) verdict ERROR "repro-getgroups exit=$rc" ;;
    esac
else
    log "$(cat "$build/repro-getgroups.err")"
    verdict ERROR "compile tests/repro/getgroups.c"
fi

section "Step 5: Termux probe (tools/probe-termux.sh)"
if sh "$repo/tools/probe-termux.sh" >"$build/termux-probe.log" 2>&1; then
    verdict PASS "probe-termux.sh ran to completion"
else
    verdict ERROR "probe-termux.sh exit=$? (often: clang/make missing; run 'pkg install clang make')"
fi
cat "$build/termux-probe.log" >> "$report"

section "Summary"
log "PASS=$pass FAIL=$fail KNOWN-BUG=$known SKIP=$skip ERROR=$error"
log "Report: $report"
log "Attach this file (build/termux-report.txt) when handing results back."

[ "$fail" -eq 0 ] && [ "$error" -eq 0 ]
