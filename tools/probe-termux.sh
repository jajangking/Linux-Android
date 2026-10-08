#!/data/data/com.termux/files/usr/bin/bash
set -u

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p "$repo_dir/build"

printf '%s\n' '== Termux / Android probe =='
printf 'uname: '
uname -a
printf 'PREFIX: %s\n' "${PREFIX:-<unset>}"
printf 'TERMUX_VERSION: %s\n' "${TERMUX_VERSION:-<unset>}"
printf 'architecture: %s\n' "$(uname -m)"

if [ -r /proc/sys/user/max_user_namespaces ]; then
    printf 'user.max_user_namespaces: '
    cat /proc/sys/user/max_user_namespaces
else
    echo 'user.max_user_namespaces: not readable/available'
fi

if [ -r /proc/self/status ]; then
    awk '/^(Seccomp|NoNewPrivs):/ { print }' /proc/self/status
fi

if command -v unshare >/dev/null 2>&1; then
    echo 'checking unprivileged user namespace...'
    if unshare --user --map-current-user sh -c 'id >/dev/null' 2>"$repo_dir/build/unshare-probe.err"; then
        echo 'unshare: available to this process'
    else
        printf 'unshare: unavailable (exit %s): ' "$?"
        cat "$repo_dir/build/unshare-probe.err"
    fi
else
    echo 'unshare: command not installed'
fi

if ! command -v make >/dev/null 2>&1 || ! command -v clang >/dev/null 2>&1; then
    echo 'Build requirements missing. In Termux run: pkg install clang make'
    exit 2
fi

printf '%s\n' 'building native probes...'
make -C "$repo_dir" CC=clang all

printf '%s\n' 'checking seccomp user-notification supervisor...'
set +e
"$repo_dir/build/rootbox" -- sh -c 'id; echo "seccomp-child-ran"'
status=$?
set -e
if [ "$status" -eq 125 ]; then
    echo 'seccomp supervisor: unavailable in this Termux process'
else
    printf 'seccomp supervisor child exit: %s\n' "$status"
fi

printf '%s\n' 'probe complete'
