#!/usr/bin/env sh
# Real-userland test. Builds a Debian bookworm rootfs from the host's own
# installed packages (file lists from dpkg, contents from the local disk, so
# no network), then runs the glibc binaries of that rootfs under
# librootshim.so, which is built against the same glibc.
#
# Covered here and not by the synthetic-rootfs suites:
#   - glibc's own cp/mv/ls/rm/stat/id/getent running from the rootfs,
#   - the renameat2 and statx wrappers of glibc 2.36,
#   - NSS lookups (getent, id -un) resolved from files inside the rootfs,
#   - libc itself opened from the rootfs (checked through /proc/self/maps).
#
# Known limits: none. Each former KNOWN-LIMIT (NSS, the kernel-loaded libc,
# host-only scripts) is now a checked PASS. The limit() helper stays for new
# probes that cannot pass yet.
#
# SKIP (exit 0 with a SKIP line) when the host has no Debian/glibc userland,
# for example on Termux/Bionic.
set -u

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
shim="$repo/build/librootshim.so"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rootshim-debian.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/rootfs"
guest=/rsh-deb # virtual path; must never appear on the host
fails=0
known=0
checks=0

if ! command -v dpkg >/dev/null 2>&1 || [ ! -e /lib64/ld-linux-x86-64.so.2 ] \
    || ! dpkg -s libc6 >/dev/null 2>&1; then
    echo 'debian rootfs: SKIP (host has no dpkg/glibc Debian userland)'
    exit 0
fi
if [ ! -r "$shim" ]; then
    echo "debian rootfs: shim not built: $shim (run make first)" >&2
    exit 1
fi

# ---- build the rootfs -------------------------------------------------------
pkgs='base-files base-passwd libc6 libc-bin coreutils bash dash debianutils sed grep findutils'
mkdir -p "$root/usr/bin" "$root/usr/sbin" "$root/usr/lib" "$root/usr/lib64"
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
ln -s usr/lib64 "$root/lib64"

list="$tmp/files.lst"
for p in $pkgs; do dpkg -L "$p"; done | sort -u | while IFS= read -r f; do
    if [ -L "$f" ] || [ -f "$f" ]; then printf '%s\n' "${f#/}"; fi
done | grep -vxE 'bin|sbin|lib|lib64' > "$list"
while IFS= read -r f; do mkdir -p "$root/$(dirname "$f")" 2>/dev/null; done < "$list"
if ! tar -C / -cf - -T "$list" 2>"$tmp/tar.err" | tar -C "$root" -xf - 2>>"$tmp/tar.err"; then
    echo 'debian rootfs: setup failed while extracting package files' >&2
    cat "$tmp/tar.err" >&2
    exit 1
fi

# Parts normally written by package postinst scripts, not by the package files.
mkdir -p "$root/etc" "$root/root" "$root/tmp"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root/etc/passwd"
printf 'root:x:0:\n' > "$root/etc/group"
# Account that exists only in the rootfs: proves NSS reads the rootfs files.
printf 'rootshimtest:x:4242:4242:rootfs only:/:/bin/sh\n' >> "$root/etc/passwd"
printf 'rootshimtest:x:4242:\n' >> "$root/etc/group"
printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' > "$root/etc/nsswitch.conf"
# Rootfs-only probe for execve: exists only inside the rootfs.
printf '#!/bin/sh\necho from-rootfs\n' > "$root/usr/bin/rsh-probe"
chmod 755 "$root/usr/bin/rsh-probe"

# ---- helpers -----------------------------------------------------------------
# rfs: run a rootfs binary by its host path; the kernel loads the host ELF
# interpreter. rld: run the same binary through the rootfs's own glibc loader,
# so libc and the libraries come from the rootfs.
rfs() { env ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 LD_PRELOAD="$shim" "$@"; }
rld() {
    env ROOTSHIM_ROOT="$root" ROOTSHIM_FAKE_ID=1 LD_PRELOAD="$shim" \
        "$root/lib64/ld-linux-x86-64.so.2" \
        --library-path "$root/usr/lib/x86_64-linux-gnu:$root/lib" "$@"
}
pass() { checks=$((checks + 1)); echo "ok    $1"; }
bad() { checks=$((checks + 1)); echo "FAIL  $1"; fails=$((fails + 1)); }
limit() { checks=$((checks + 1)); known=$((known + 1)); echo "KNOWN-LIMIT $1"; }

# check_out <name> <expected> <cmd...>: stdout must equal expected exactly.
check_out() {
    name=$1; expected=$2; shift 2
    if out=$("$@" 2>&1) && [ "$out" = "$expected" ]; then
        pass "$name"
    else
        bad "$name (got: $out)"
    fi
}

# check_ok <name> <cmd...>: exit status 0.
check_ok() {
    name=$1; shift
    if out=$("$@" 2>&1); then
        pass "$name"
    else
        bad "$name ($out)"
    fi
}

# ---- checks ------------------------------------------------------------------
[ -x "$root/usr/bin/ls" ] && [ -e "$root/lib64/ld-linux-x86-64.so.2" ] \
    && [ -e "$root/lib/x86_64-linux-gnu/libc.so.6" ] \
    && pass "rootfs built from dpkg file lists ($(find "$root" -type f | wc -l) files)" \
    || bad 'rootfs built from dpkg file lists'

if rfs "$root/usr/bin/cat" /etc/os-release | grep -qx 'ID=debian'; then
    pass 'os-release read through virtual path'
else
    bad 'os-release read through virtual path'
fi

check_out 'id -u sees fake uid 0' 0 rfs "$root/usr/bin/id" -u
# Weak check: "root" is also the host name for uid 0. The NSS check below is
# the one that tells rootfs passwd apart from host passwd.
check_out 'id -un resolves fake uid 0 to root' root rfs "$root/usr/bin/id" -un
check_out 'stat -c %u reports fake owner (glibc statx path)' 0 \
    rfs "$root/usr/bin/stat" -c %u /etc/passwd

# NSS: getpw*/getgr* are answered from the rootfs files by the shim. The
# rootfs-only account exists nowhere on the host, so it shows the source.
nss_out=$(rfs "$root/usr/bin/getent" passwd root 2>&1)
if [ "$nss_out" = 'root:x:0:0:root:/root:/bin/sh' ]; then
    pass 'NSS lookup reads rootfs /etc/passwd'
else
    bad "NSS lookup reads rootfs /etc/passwd (got: $nss_out)"
fi
check_out 'NSS lookup finds rootfs-only account' \
    'rootshimtest:x:4242:4242:rootfs only:/:/bin/sh' \
    rfs "$root/usr/bin/getent" passwd rootshimtest
check_out 'id -u resolves rootfs-only account' 4242 \
    rfs "$root/usr/bin/id" -u rootshimtest
check_out 'getent group reads rootfs /etc/group' 'rootshimtest:x:4242:' \
    rfs "$root/usr/bin/getent" group rootshimtest
enum_out=$(rfs "$root/usr/bin/getent" passwd 2>&1)
enum_want=$(printf 'root:x:0:0:root:/root:/bin/sh\nrootshimtest:x:4242:4242:rootfs only:/:/bin/sh')
if [ "$enum_out" = "$enum_want" ]; then
    pass 'NSS enumeration (getent passwd) lists rootfs accounts only'
else
    bad "NSS enumeration (got: $enum_out)"
fi
# Without ROOTSHIM_ROOT the hooks must pass through to the host unchanged.
host_pw=$(getent passwd root 2>&1)
shim_pw=$(env LD_PRELOAD="$shim" getent passwd root 2>&1)
if [ -n "$host_pw" ] && [ "$host_pw" = "$shim_pw" ]; then
    pass 'NSS hooks pass through to host without ROOTSHIM_ROOT'
else
    bad "NSS hooks pass through without ROOTSHIM_ROOT (host: $host_pw, shim: $shim_pw)"
fi

# libc source. Kernel-loaded ELF: the host kernel first loads host libc, then
# the shim re-runs the program once through the rootfs loader. Explicit rootfs
# loader: must map rootfs libc.
if rfs "$root/usr/bin/cat" /proc/self/maps | grep -F "$root/" | grep -q 'libc'; then
    pass 'kernel-loaded binary re-runs through rootfs loader and maps rootfs libc'
else
    bad 'kernel-loaded binary maps libc from rootfs'
fi
if rld "$root/usr/bin/cat" /proc/self/maps | grep -F "$root/" | grep -q 'libc'; then
    pass 'rootfs loader maps libc from rootfs'
else
    bad 'rootfs loader maps libc from rootfs'
fi
check_out 'rootfs loader: id -u sees fake uid 0' 0 rld "$root/usr/bin/id" -u

# File operations with glibc 2.36 coreutils, all on the virtual guest path.
check_ok 'mkdir (rootfs coreutils)' rfs "$root/usr/bin/mkdir" -p "$guest"
check_ok 'cp (rootfs coreutils)' rfs "$root/usr/bin/cp" /etc/passwd "$guest/copy"
[ -f "$root$guest/copy" ] && pass 'cp landed in rootfs' || bad 'cp landed in rootfs'
check_ok 'mv absolute path (renameat2 wrapper)' rfs "$root/usr/bin/mv" "$guest/copy" "$guest/moved"
[ -f "$root$guest/moved" ] && [ ! -e "$root$guest/copy" ] \
    && pass 'mv renamed inside rootfs' || bad 'mv renamed inside rootfs'
check_ok 'mv through rootfs loader' rld "$root/usr/bin/mv" "$guest/moved" "$guest/moved2"
[ -f "$root$guest/moved2" ] && [ ! -e "$root$guest/moved" ] \
    && pass 'rootfs-loader mv renamed inside rootfs' || bad 'rootfs-loader mv renamed inside rootfs'
check_ok 'ln -s (rootfs coreutils)' rfs "$root/usr/bin/ln" -s moved2 "$guest/link"
check_out 'readlink (rootfs coreutils)' moved2 rfs "$root/usr/bin/readlink" "$guest/link"
check_out 'ls lists rootfs directory' 'link
moved2' rfs "$root/usr/bin/ls" "$guest"
check_ok 'rm (rootfs coreutils)' rfs "$root/usr/bin/rm" "$guest/moved2" "$guest/link"
[ ! -e "$root$guest/moved2" ] && [ ! -L "$root$guest/link" ] \
    && pass 'rm removed rootfs files' || bad 'rm removed rootfs files'

# dash builtins only: no PATH lookup, so host binaries cannot be picked up.
check_out 'dash reads rootfs file via builtins' 'root:x:0:0:root:/root:/bin/sh' \
    rfs "$root/usr/bin/dash" -c 'IFS= read -r line < /etc/passwd; printf "%s\n" "$line"'

# execve through the shim: a rootfs shebang script, a rootfs ELF started
# through the rootfs loader (its libc must come from the rootfs), and the
# fake uid seen by a program started that way.
probe_out=$(rfs "$root/usr/bin/dash" -c '/usr/bin/rsh-probe' 2>&1)
if [ "$probe_out" = 'from-rootfs' ]; then
    pass 'execve of rootfs shebang script runs rootfs interpreter'
else
    bad "execve of rootfs shebang script (got: $probe_out)"
fi
check_out 'execve-launched id sees fake uid 0' 0 \
    rfs "$root/usr/bin/dash" -c '/usr/bin/id -u'
if rfs "$root/usr/bin/dash" -c '/usr/bin/cat /proc/self/maps' | grep -F "$root/" | grep -q 'libc'; then
    pass 'execve-launched program maps libc from rootfs'
else
    bad 'execve-launched program maps libc from rootfs'
fi

# Host-only script: not in the rootfs, so the shim runs it with the rootfs shell
# and passes the file as /proc/self/fd/N (/proc is not mapped).
printf '#!/bin/sh\necho from-host\n' > "$tmp/host-probe"
chmod 755 "$tmp/host-probe"
host_out=$(rfs "$root/usr/bin/dash" -c "$tmp/host-probe" 2>&1)
if [ "$host_out" = 'from-host' ]; then
    pass 'host-only script runs through rootfs shell'
else
    bad "host-only script runs through rootfs shell (got: $host_out)"
fi

if [ -e "$guest" ]; then
    bad "operations leaked to host $guest"
    fails=$((fails + 1))
fi

echo "debian rootfs: checks=$checks failures=$fails known-limits=$known"
if [ "$fails" -ne 0 ]; then
    exit 1
fi
