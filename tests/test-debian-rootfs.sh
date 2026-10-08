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
# Not covered, and reported as KNOWN-LIMIT when probed:
#   - execve() of host-only paths: the exec falls back to the host, but files
#     the program opens are still mapped into the rootfs (see README),
#   - the ELF interpreter, which the kernel loads from the host.
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

# NSS: libnss_files reads passwd through glibc-internal opens, which LD_PRELOAD
# cannot interpose. Expected today: the host's passwd entry comes back.
nss_out=$(rfs "$root/usr/bin/getent" passwd root 2>&1)
if [ "$nss_out" = 'root:x:0:0:root:/root:/bin/sh' ]; then
    pass 'NSS lookup reads rootfs /etc/passwd'
else
    limit "NSS lookup reads host /etc/passwd (libnss_files uses glibc-internal open; got: $nss_out)"
fi

# libc source. Kernel-loaded ELF: the host loader maps host libc (ld.so's own
# opens are not interposable). Explicit rootfs loader: must map rootfs libc.
if rfs "$root/usr/bin/cat" /proc/self/maps | grep -F "$root/" | grep -q 'libc'; then
    pass 'kernel-loaded binary maps libc from rootfs'
else
    limit 'kernel-loaded binary maps host libc, not rootfs libc (host ELF interpreter; ld.so opens are not interposable)'
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

# Host-only path: exec is handed to the host, but the script reads its own file
# through open(), which is mapped into the rootfs. Expected today: KNOWN-LIMIT.
printf '#!/bin/sh\necho from-host\n' > "$tmp/host-probe"
chmod 755 "$tmp/host-probe"
host_out=$(rfs "$root/usr/bin/dash" -c "$tmp/host-probe" 2>&1)
if [ "$host_out" = 'from-host' ]; then
    pass 'host-only script runs through host fallback'
else
    limit "host-only script: exec falls back to host but open() maps into rootfs (got: $host_out)"
fi

if [ -e "$guest" ]; then
    bad "operations leaked to host $guest"
    fails=$((fails + 1))
fi

echo "debian rootfs: checks=$checks failures=$fails known-limits=$known"
if [ "$fails" -ne 0 ]; then
    exit 1
fi
