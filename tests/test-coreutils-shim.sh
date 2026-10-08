#!/usr/bin/env sh
# Runs common coreutils under librootshim.so and checks that each file
# operation lands inside the rootfs and never on the host. The tools are
# resolved before the shim is enabled, so PATH lookup is not under test here.
set -u

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
shim="$repo/build/librootshim.so"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rootshim-coreutils.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/rootfs"
mkdir -p "$root/etc"
printf 'from-rootfs\n' > "$root/etc/marker"
guest=/rsh-coreutils # virtual path; must never appear on the host
fails=0

for tool in cat cp mv rm ln readlink ls stat dd head chmod truncate touch mkdir; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "coreutils under shim: missing tool $tool" >&2
        exit 1
    fi
done

# run <tool> args...: execute with the shim enabled, capture output and status.
run() {
    env ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 LD_PRELOAD="$shim" "$@"
}

pass() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; fails=$((fails + 1)); }

check_out() { # check_out <name> <expected> <tool> args...
    name=$1; expected=$2; shift 2
    if out=$(run "$@" 2>&1) && [ "$out" = "$expected" ]; then
        pass "$name"
    else
        bad "$name (got: $out)"
    fi
}

check_ok() { # check_ok <name> <tool> args...
    name=$1; shift
    if out=$(run "$@" 2>&1); then
        pass "$name"
    else
        bad "$name ($out)"
    fi
}

cat_bin=$(command -v cat)
check_out cat from-rootfs "$cat_bin" /etc/marker
check_ok mkdir "$(command -v mkdir)" -p "$guest"
[ -d "$root$guest" ] && pass 'mkdir landed in rootfs' || bad 'mkdir landed in rootfs'
check_ok cp "$(command -v cp)" /etc/marker "$guest/copy"
[ -f "$root$guest/copy" ] && pass 'cp landed in rootfs' || bad 'cp landed in rootfs'
check_ok mv "$(command -v mv)" "$guest/copy" "$guest/moved"
[ -f "$root$guest/moved" ] && [ ! -e "$root$guest/copy" ] && pass 'mv renamed inside rootfs' || bad 'mv renamed inside rootfs'
check_ok ln "$(command -v ln)" -s moved "$guest/link"
[ -L "$root$guest/link" ] && pass 'ln -s created symlink in rootfs' || bad 'ln -s created symlink in rootfs'
check_out readlink moved "$(command -v readlink)" "$guest/link"
check_ok ls "$(command -v ls)" "$guest"
check_out stat-size 12 "$(command -v stat)" -c %s /etc/marker
check_ok dd "$(command -v dd)" if=/etc/marker of="$guest/dd" bs=4 count=1 status=none
[ "$(cat "$root$guest/dd" 2>/dev/null)" = 'from' ] && pass 'dd wrote into rootfs' || bad 'dd wrote into rootfs'
check_out head from-rootfs "$(command -v head)" -n 1 /etc/marker
check_ok chmod "$(command -v chmod)" 600 "$guest/moved"
[ "$(stat -c %a "$root$guest/moved" 2>/dev/null)" = 600 ] && pass 'chmod changed rootfs file' || bad 'chmod changed rootfs file'
check_ok truncate "$(command -v truncate)" -s 0 "$guest/dd"
[ ! -s "$root$guest/dd" ] && pass 'truncate affected rootfs file' || bad 'truncate affected rootfs file'
check_ok touch "$(command -v touch)" "$guest/t"
check_ok rm "$(command -v rm)" "$guest/moved" "$guest/t"
[ ! -e "$root$guest/moved" ] && [ ! -e "$root$guest/t" ] && pass 'rm removed rootfs files' || bad 'rm removed rootfs files'

if [ -e "$guest" ]; then
    bad "operations leaked to host $guest"
    fails=$((fails + 1))
fi

if [ "$fails" -ne 0 ]; then
    echo "coreutils under shim: $fails failing check(s)" >&2
    exit 1
fi
echo 'coreutils under shim test: PASS'
