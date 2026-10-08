#!/usr/bin/env sh
# Termux verification runner (round 2). Builds, runs the full test suite,
# re-checks the two reproduced bugs (now expected to be fixed), runs the
# coreutils-under-shim check, and runs probe-termux.sh. Writes a plain-text
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

pass=0; fail=0; skip=0; error=0

log() { printf '%s\n' "$*" | tee -a "$report"; }
section() { log ""; log "===== $* ====="; }
verdict() { # verdict <STATUS> <label>
    case "$1" in
        PASS) pass=$((pass + 1)) ;;
        FAIL) fail=$((fail + 1)) ;;
        SKIP) skip=$((skip + 1)) ;;
        ERROR) error=$((error + 1)) ;;
    esac
    log "[$1] $2"
}

# Prefer clang (Termux default after `pkg install clang`), else cc.
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
grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status 2>/dev/null | while IFS= read -r line; do log "  $line"; done
[ -r /proc/self/status ] || log "  (/proc/self/status not readable)"

section "Step 1: build (make -B all, CC=$CC_BIN)"
if make -C "$repo" -B CC="$CC_BIN" all >"$build/termux-build.log" 2>&1; then
    cat "$build/termux-build.log" >> "$report"
    verdict PASS "make all"
else
    cat "$build/termux-build.log" >> "$report"
    verdict FAIL "make all -- see build/termux-build.log"
    log "Build failed; remaining steps may not be meaningful."
fi

section "Step 2: make test (full suite)"
if make -C "$repo" CC="$CC_BIN" test >"$build/termux-test.log" 2>&1; then
    verdict PASS "make test"
else
    verdict FAIL "make test -- see build/termux-test.log"
fi
cat "$build/termux-test.log" >> "$report"
# Attribute each SKIP to its source so the note never misleads.
if grep -q 'seccomp user notification unavailable' "$build/termux-test.log"; then
    log "note: rootbox/seccomp tests SKIPped (seccomp user notification unavailable here)."
fi
if grep -q 'host denies hard links' "$build/termux-test.log"; then
    log "note: hard-link checks SKIPped (host denies link(2)); this is a platform limit, not a shim failure."
fi

section "Step 3: repro chroot() on a regular file (fixed in round 2)"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rootshim-check.XXXXXX") || { verdict ERROR "mktemp"; tmp=""; }
if [ -n "$tmp" ]; then
    root="$tmp/rootfs"
    mkdir -p "$root/etc"
    printf 'from-rootfs\n' > "$root/etc/marker"
    printf 'file\n' > "$root/afile"
    out=$(ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 LD_PRELOAD="$build/librootshim.so" \
          "$build/repro-chroot-file" 2>&1)
    rc=$?
    log "$out"
    case $rc in
        0) verdict PASS "failed chroot() leaves virtual root intact" ;;
        2) verdict FAIL "REGRESSION: failed chroot() corrupts virtual root" ;;
        3) verdict FAIL "chroot() to a regular file unexpectedly succeeded" ;;
        *) verdict ERROR "repro-chroot-file exit=$rc" ;;
    esac
    rm -rf "$tmp"
fi

section "Step 4: repro getgroups() under rootbox (fixed in round 2)"
out=$("$build/rootbox" -- "$build/repro-getgroups" 2>&1)
rc=$?
log "$out"
case $rc in
    0) verdict PASS "getgroups() lists group 0, consistent with getegid()" ;;
    2) verdict FAIL "REGRESSION: getgroups() empty while getegid()==0" ;;
    4) verdict FAIL "getgroups() failed: supervisor could not write the list (ptrace policy?)" ;;
    5) verdict FAIL "getgroups() list does not contain group 0" ;;
    125) verdict SKIP "rootbox: seccomp user notification unavailable here" ;;
    *) verdict ERROR "repro-getgroups exit=$rc" ;;
esac

section "Step 5: coreutils under shim (tests/test-coreutils-shim.sh)"
out=$(sh "$repo/tests/test-coreutils-shim.sh" 2>&1)
rc=$?
log "$out"
if [ "$rc" -eq 0 ]; then
    verdict PASS "coreutils file operations stay inside rootfs"
else
    verdict FAIL "coreutils leak or failure -- see output above"
fi

section "Step 6: Termux probe (tools/probe-termux.sh)"
sh "$repo/tools/probe-termux.sh" >"$build/termux-probe.log" 2>&1
rc=$?
cat "$build/termux-probe.log" >> "$report"
if [ "$rc" -eq 0 ]; then
    verdict PASS "probe-termux.sh ran to completion"
else
    verdict ERROR "probe-termux.sh exit=$rc (often: clang/make missing; run 'pkg install clang make')"
fi

section "Summary"
log "PASS=$pass FAIL=$fail SKIP=$skip ERROR=$error"
log "Report: $report"
log "Attach this file (build/termux-report.txt) when handing results back."

[ "$fail" -eq 0 ] && [ "$error" -eq 0 ]
