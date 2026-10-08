#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/*
 * Experimental, cooperative-process shim. This is NOT a security boundary
 * and does not grant kernel privileges. It redirects a subset of libc path
 * calls into ROOTSHIM_ROOT and can report synthetic uid/gid values.
 *
 * Path-taking calls are hooked in both their plain and *at forms, plus the
 * glibc/Bionic _FORTIFY_SOURCE entry points (__open_2 & co.), which GNU
 * binaries import instead of open()/openat() when built with fortify.
 *
 * execve()/execv() are hooked: a program found inside the rootfs is run
 * through the rootfs's own dynamic loader, and a host script is run by the
 * rootfs shell (see "execve" below). Host ELF binaries outside the rootfs
 * are passed to the kernel unchanged. getpw and getgr read the rootfs's
 * /etc/passwd and /etc/group. A program started from the rootfs by the host
 * kernel re-runs once through the rootfs loader. See README.md
 * "Batas keamanan dan kompatibilitas".
 */

static char root_dir[PATH_MAX];
static size_t root_len;
static int fake_identity;
static int resolving_symbols;

static int exec_rooted(const char *path, char *const argv[],
                       char *const envp[], int depth);
extern char **environ;

#define LOAD_NEXT(var, name) do {                                      \
    if (!(var) && !resolving_symbols) {                                \
        resolving_symbols = 1;                                         \
        *(void **)(&(var)) = dlsym(RTLD_NEXT, (name));                 \
        resolving_symbols = 0;                                         \
    }                                                                   \
} while (0)

typedef long (*syscall_fn_t)(long, ...);

/* The real libc syscall(). Internal shim fallbacks must use this, not the
   interposer defined at the end of this file, or paths would be mapped twice. */
static long real_syscall(long number, ...)
{
    static syscall_fn_t next_syscall;
    long a[6] = { 0, 0, 0, 0, 0, 0 };
    va_list ap;
    va_start(ap, number);
    for (int i = 0; i < 6; ++i)
        a[i] = va_arg(ap, long);
    va_end(ap);
    LOAD_NEXT(next_syscall, "syscall");
    if (!next_syscall) {
        errno = ENOSYS;
        return -1;
    }
    return next_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static bool enabled_env(const char *name)
{
    const char *value = getenv(name);
    return value && (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
}

static bool is_passthrough(const char *path)
{
    /* These Android/kernel interfaces are useful to CLI programs and remain
       subject to the Termux app's ordinary Android permissions. */
    static const char *const prefixes[] = { "/proc", "/dev", "/sys" };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(path, prefixes[i], n) == 0 &&
            (path[n] == '\0' || path[n] == '/'))
            return true;
    }
    return false;
}

static bool already_rooted(const char *path)
{
    if (!root_len || strncmp(path, root_dir, root_len) != 0)
        return false;
    return path[root_len] == '\0' || path[root_len] == '/';
}

/* free() that does not clobber the errno of the wrapped call. */
static void release(char *p)
{
    int saved = errno;
    free(p);
    errno = saved;
}

/* Map an absolute virtual path into ROOTSHIM_ROOT. Dot-dot components are
   clamped at the virtual root. This lexical mapping does not prevent symlink
   escapes; see the security notes in README.md. Returns NULL with errno set
   on failure; the caller must release() the result. */
static char *map_path(const char *path)
{
    if (!path) {
        errno = EFAULT;
        return NULL;
    }
    if (!root_len || path[0] != '/' || is_passthrough(path) ||
        already_rooted(path))
        return strdup(path);

    char result[PATH_MAX];
    size_t len = root_len;
    memcpy(result, root_dir, root_len + 1);

    const char *p = path;
    while (*p == '/')
        ++p;

    while (*p) {
        const char *start = p;
        while (*p && *p != '/')
            ++p;
        size_t seglen = (size_t)(p - start);

        if (seglen == 0 || (seglen == 1 && start[0] == '.')) {
            /* nothing */
        } else if (seglen == 2 && start[0] == '.' && start[1] == '.') {
            if (len > root_len) {
                while (len > root_len && result[len - 1] != '/')
                    --len;
                if (len > root_len)
                    --len;
                result[len] = '\0';
            }
        } else {
            size_t slash = (len > 0 && result[len - 1] != '/') ? 1 : 0;
            if (len + slash + seglen >= sizeof(result)) {
                errno = ENAMETOOLONG;
                return NULL;
            }
            if (slash)
                result[len++] = '/';
            memcpy(result + len, start, seglen);
            len += seglen;
            result[len] = '\0';
        }
        while (*p == '/')
            ++p;
    }
    return strdup(result);
}

/* Read /proc/self/cmdline into argv. The backing buffer is returned in *backing. */
static char **cmdline_argv(char **backing)
{
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (!f)
        return NULL;
    size_t cap = 512, used = 0;
    char *buf = malloc(cap);
    while (buf) {
        size_t n = fread(buf + used, 1, cap - used, f);
        used += n;
        if (used < cap)
            break;
        char *nb = realloc(buf, cap * 2);
        if (!nb) {
            free(buf);
            buf = NULL;
            break;
        }
        buf = nb;
        cap *= 2;
    }
    fclose(f);
    if (!buf || used == 0 || buf[used - 1] != '\0') {
        free(buf);
        return NULL;
    }
    size_t argc = 0;
    for (size_t i = 0; i < used; ++i)
        if (buf[i] == '\0')
            ++argc;
    char **argv = calloc(argc + 1, sizeof *argv);
    if (!argv) {
        free(buf);
        return NULL;
    }
    size_t k = 0, start = 0;
    for (size_t i = 0; i < used; ++i) {
        if (buf[i] == '\0') {
            argv[k++] = buf + start;
            start = i + 1;
        }
    }
    *backing = buf;
    return argv;
}

/* The host kernel loads a rootfs program with the host ELF interpreter, so its
   libc comes from the host. Such a process runs its own loader once more, this
   time through the rootfs loader. ROOTSHIM_REEXEC marks that second run; the
   second run clears it, so children are not affected. */
static void reexec_into_rootfs(void)
{
    if (getenv("ROOTSHIM_REEXEC")) {
        unsetenv("ROOTSHIM_REEXEC");
        return;
    }
    char exe[PATH_MAX];
    ssize_t en = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (en <= 0)
        return;
    exe[en] = '\0';
    if (strncmp(exe, root_dir, root_len) != 0 || exe[root_len] != '/')
        return;

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return;
    char *line = NULL;
    size_t cap = 0;
    bool rootfs_libc = false, host_libc = false;
    while (getline(&line, &cap, maps) > 0) {
        char *path = strchr(line, '/');
        if (!path || !strstr(path, "/libc.so"))
            continue;
        if (strncmp(path, root_dir, root_len) == 0 && path[root_len] == '/')
            rootfs_libc = true;
        else
            host_libc = true;
    }
    free(line);
    fclose(maps);
    if (rootfs_libc || !host_libc)
        return;

    char *backing = NULL;
    char **argv = cmdline_argv(&backing);
    if (!argv || !argv[0]) {
        free(argv);
        free(backing);
        return;
    }
    setenv("ROOTSHIM_REEXEC", "1", 1);
    /* exe is a host path inside the rootfs; the virtual path is the rest. */
    exec_rooted(exe + root_len, argv, environ, 0);
    /* Reached only if the exec failed: keep running with the host libc. */
    unsetenv("ROOTSHIM_REEXEC");
    free(argv);
    free(backing);
}

static void init_rootshim(void) __attribute__((constructor));
static void init_rootshim(void)
{
    const char *root = getenv("ROOTSHIM_ROOT");
    fake_identity = enabled_env("ROOTSHIM_FAKE_ID");
    if (!root || root[0] != '/')
        return;

    char *resolved = realpath(root, NULL);
    const char *selected = resolved ? resolved : root;
    size_t n = strlen(selected);
    while (n > 1 && selected[n - 1] == '/')
        --n;
    if (n >= sizeof(root_dir)) {
        free(resolved);
        return;
    }
    memcpy(root_dir, selected, n);
    root_dir[n] = '\0';
    root_len = n;
    free(resolved);
    reexec_into_rootfs();
}

static void fake_stat_owner(struct stat *st)
{
    if (st && fake_identity) {
        st->st_uid = 0;
        st->st_gid = 0;
    }
}

/* ---- identity ----------------------------------------------------------- */

uid_t getuid(void)  { return fake_identity ? 0 : (uid_t)real_syscall(SYS_getuid); }
uid_t geteuid(void) { return fake_identity ? 0 : (uid_t)real_syscall(SYS_geteuid); }
gid_t getgid(void)  { return fake_identity ? 0 : (gid_t)real_syscall(SYS_getgid); }
gid_t getegid(void) { return fake_identity ? 0 : (gid_t)real_syscall(SYS_getegid); }

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    if (!fake_identity)
        return (int)real_syscall(SYS_getresuid, ruid, euid, suid);
    if (ruid) *ruid = 0;
    if (euid) *euid = 0;
    if (suid) *suid = 0;
    return 0;
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    if (!fake_identity)
        return (int)real_syscall(SYS_getresgid, rgid, egid, sgid);
    if (rgid) *rgid = 0;
    if (egid) *egid = 0;
    if (sgid) *sgid = 0;
    return 0;
}

/* Synthetic supplementary groups: the single group 0, matching getegid(). */
int getgroups(int size, gid_t list[])
{
    if (!fake_identity)
        return (int)real_syscall(SYS_getgroups, size, list);
    if (size < 0) {
        errno = EINVAL;
        return -1;
    }
    if (size == 0)
        return 1;
    if (!list) {
        errno = EFAULT;
        return -1;
    }
    list[0] = 0;
    return 1;
}

/* ---- open family ---------------------------------------------------------- */

typedef int (*openat_fn)(int, const char *, int, ...);

static bool open_needs_mode(int flags)
{
    if (flags & O_CREAT)
        return true;
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE)
        return true;
#endif
    return false;
}

static int do_openat(int dirfd, const char *path, int flags, mode_t mode)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    static openat_fn next_fn;
    LOAD_NEXT(next_fn, "openat");
    int rc;
    if (next_fn)
        rc = open_needs_mode(flags) ? next_fn(dirfd, mapped, flags, mode)
                                    : next_fn(dirfd, mapped, flags);
    else
        rc = (int)real_syscall(SYS_openat, dirfd, mapped, flags, mode);
    release(mapped);
    return rc;
}

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return do_openat(AT_FDCWD, path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return do_openat(AT_FDCWD, path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return do_openat(dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (open_needs_mode(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return do_openat(dirfd, path, flags, mode);
}

/* _FORTIFY_SOURCE entry points: the compiler emits these instead of
   open()/openat() when flags are constant and no mode is needed. They take
   no mode argument, so mode 0 is passed through. */
int __open_2(const char *path, int flags)
{
    return do_openat(AT_FDCWD, path, flags, 0);
}

int __open64_2(const char *path, int flags)
{
    return do_openat(AT_FDCWD, path, flags, 0);
}

int __openat_2(int dirfd, const char *path, int flags)
{
    return do_openat(dirfd, path, flags, 0);
}

int __openat64_2(int dirfd, const char *path, int flags)
{
    return do_openat(dirfd, path, flags, 0);
}

FILE *fopen(const char *path, const char *mode)
{
    char *mapped = map_path(path);
    if (!mapped)
        return NULL;
    typedef FILE *(*fn_t)(const char *, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fopen");
    FILE *rc = next_fn ? next_fn(mapped, mode) : NULL;
    release(mapped);
    return rc;
}

FILE *fopen64(const char *path, const char *mode)
{
    char *mapped = map_path(path);
    if (!mapped)
        return NULL;
    typedef FILE *(*fn_t)(const char *, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fopen64");
    if (!next_fn)
        LOAD_NEXT(next_fn, "fopen");
    FILE *rc = next_fn ? next_fn(mapped, mode) : NULL;
    release(mapped);
    return rc;
}

DIR *opendir(const char *path)
{
    char *mapped = map_path(path);
    if (!mapped)
        return NULL;
    typedef DIR *(*fn_t)(const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "opendir");
    DIR *rc = next_fn ? next_fn(mapped) : NULL;
    release(mapped);
    return rc;
}

/* ---- stat family ---------------------------------------------------------- */

static int do_fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, struct stat *, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fstatat");
    int rc = next_fn ? next_fn(dirfd, mapped, st, flags)
                     : (int)real_syscall(SYS_newfstatat, dirfd, mapped, st, flags);
    if (rc == 0)
        fake_stat_owner(st);
    release(mapped);
    return rc;
}

int stat(const char *path, struct stat *st)
{
    return do_fstatat(AT_FDCWD, path, st, 0);
}

int lstat(const char *path, struct stat *st)
{
    return do_fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    return do_fstatat(dirfd, path, st, flags);
}

/* The *64 variants share the layout of struct stat on LP64 targets (Termux
   arm64, x86_64). Their symbols are not provided on 32-bit builds here. */
#if __SIZEOF_POINTER__ == 8
int stat64(const char *path, struct stat64 *st)
{
    return do_fstatat(AT_FDCWD, path, (struct stat *)st, 0);
}

int lstat64(const char *path, struct stat64 *st)
{
    return do_fstatat(AT_FDCWD, path, (struct stat *)st, AT_SYMLINK_NOFOLLOW);
}

int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags)
{
    return do_fstatat(dirfd, path, (struct stat *)st, flags);
}
#endif

int fstat(int fd, struct stat *st)
{
    typedef int (*fn_t)(int, struct stat *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fstat");
    int rc = next_fn ? next_fn(fd, st) : (int)real_syscall(SYS_fstat, fd, st);
    if (rc == 0)
        fake_stat_owner(st);
    return rc;
}

#if __SIZEOF_POINTER__ == 8
int fstat64(int fd, struct stat64 *st)
{
    return fstat(fd, (struct stat *)st);
}
#endif

/* statx is only declared by glibc and by Bionic at API >= 30. Termux builds
   at a lower API level, so the hook is compiled only where the header
   provides struct statx. */
#if defined(__GLIBC__) || (defined(__ANDROID_API__) && __ANDROID_API__ >= 30)
#define ROOTSHIM_HAVE_STATX 1
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int, unsigned int, struct statx *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "statx");
    int rc = next_fn ? next_fn(dirfd, mapped, flags, mask, buf)
                     : (int)real_syscall(SYS_statx, dirfd, mapped, flags, mask, buf);
    if (rc == 0 && fake_identity) {
        buf->stx_uid = 0;
        buf->stx_gid = 0;
    }
    release(mapped);
    return rc;
}
#endif

/* ---- access / cwd -------------------------------------------------------- */

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "faccessat");
    int rc = next_fn ? next_fn(dirfd, mapped, mode, flags)
                     : (int)real_syscall(SYS_faccessat, dirfd, mapped, mode, flags);
    release(mapped);
    return rc;
}

int faccessat2(int dirfd, const char *path, int mode, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "faccessat2");
    int rc;
    if (next_fn) {
        rc = next_fn(dirfd, mapped, mode, flags);
    } else {
#ifdef SYS_faccessat2
        rc = (int)real_syscall(SYS_faccessat2, dirfd, mapped, mode, flags);
#else
        errno = ENOSYS;
        rc = -1;
#endif
    }
    release(mapped);
    return rc;
}

int access(const char *path, int mode)
{
    return faccessat(AT_FDCWD, path, mode, 0);
}

int chdir(const char *path)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "chdir");
    int rc = next_fn ? next_fn(mapped) : (int)real_syscall(SYS_chdir, mapped);
    release(mapped);
    return rc;
}

char *getcwd(char *buf, size_t size)
{
    typedef char *(*fn_t)(char *, size_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "getcwd");
    char *cwd = next_fn ? next_fn(buf, size) : NULL;
    if (!cwd || !root_len || !already_rooted(cwd))
        return cwd;

    char *virtual_cwd = cwd + root_len;
    if (*virtual_cwd == '\0')
        virtual_cwd = "/";
    else if (*virtual_cwd != '/')
        return cwd;

    size_t n = strlen(virtual_cwd) + 1;
    if (n > size && buf != NULL) {
        errno = ERANGE;
        return NULL;
    }
    memmove(cwd, virtual_cwd, n);
    return cwd;
}

/* ---- create / remove / rename / link ------------------------------------- */

int mkdirat(int dirfd, const char *path, mode_t mode)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, mode_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "mkdirat");
    int rc = next_fn ? next_fn(dirfd, mapped, mode)
                     : (int)real_syscall(SYS_mkdirat, dirfd, mapped, mode);
    release(mapped);
    return rc;
}

int mkdir(const char *path, mode_t mode)
{
    return mkdirat(AT_FDCWD, path, mode);
}

int unlinkat(int dirfd, const char *path, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "unlinkat");
    int rc = next_fn ? next_fn(dirfd, mapped, flags)
                     : (int)real_syscall(SYS_unlinkat, dirfd, mapped, flags);
    release(mapped);
    return rc;
}

int unlink(const char *path)
{
    return unlinkat(AT_FDCWD, path, 0);
}

int rmdir(const char *path)
{
    return unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    char *old_mapped = map_path(oldpath);
    char *new_mapped = old_mapped ? map_path(newpath) : NULL;
    if (!old_mapped || !new_mapped) {
        release(old_mapped);
        release(new_mapped);
        return -1;
    }
    typedef int (*fn_t)(int, const char *, int, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "renameat");
    int rc = next_fn ? next_fn(olddirfd, old_mapped, newdirfd, new_mapped)
                     : (int)real_syscall(SYS_renameat, olddirfd, old_mapped, newdirfd, new_mapped);
    release(old_mapped);
    release(new_mapped);
    return rc;
}

int rename(const char *oldpath, const char *newpath)
{
    return renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
              const char *newpath, unsigned int flags)
{
    char *old_mapped = map_path(oldpath);
    char *new_mapped = old_mapped ? map_path(newpath) : NULL;
    if (!old_mapped || !new_mapped) {
        release(old_mapped);
        release(new_mapped);
        return -1;
    }
    typedef int (*fn_t)(int, const char *, int, const char *, unsigned int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "renameat2");
    int rc;
    if (next_fn) {
        rc = next_fn(olddirfd, old_mapped, newdirfd, new_mapped, flags);
    } else {
#ifdef SYS_renameat2
        rc = (int)real_syscall(SYS_renameat2, olddirfd, old_mapped, newdirfd, new_mapped, flags);
#else
        errno = ENOSYS;
        rc = -1;
#endif
    }
    release(old_mapped);
    release(new_mapped);
    return rc;
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    char *old_mapped = map_path(oldpath);
    char *new_mapped = old_mapped ? map_path(newpath) : NULL;
    if (!old_mapped || !new_mapped) {
        release(old_mapped);
        release(new_mapped);
        return -1;
    }
    typedef int (*fn_t)(int, const char *, int, const char *, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "linkat");
    int rc = next_fn ? next_fn(olddirfd, old_mapped, newdirfd, new_mapped, flags)
                     : (int)real_syscall(SYS_linkat, olddirfd, old_mapped, newdirfd, new_mapped, flags);
    release(old_mapped);
    release(new_mapped);
    return rc;
}

int link(const char *oldpath, const char *newpath)
{
    return linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

/* The symlink *target* is stored verbatim (it is interpreted later, inside
   the virtual root, as written); only the link location is mapped. */
int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    char *mapped = map_path(linkpath);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, int, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "symlinkat");
    int rc = next_fn ? next_fn(target, newdirfd, mapped)
                     : (int)real_syscall(SYS_symlinkat, target, newdirfd, mapped);
    release(mapped);
    return rc;
}

int symlink(const char *target, const char *linkpath)
{
    return symlinkat(target, AT_FDCWD, linkpath);
}

ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef ssize_t (*fn_t)(int, const char *, char *, size_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "readlinkat");
    ssize_t rc = next_fn ? next_fn(dirfd, mapped, buf, bufsiz)
                         : (ssize_t)real_syscall(SYS_readlinkat, dirfd, mapped, buf, bufsiz);
    release(mapped);
    return rc;
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
    return readlinkat(AT_FDCWD, path, buf, bufsiz);
}

/* ---- mode, size, times, xattrs ------------------------------------------- */

int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, mode_t, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fchmodat");
    int rc = next_fn ? next_fn(dirfd, mapped, mode, flags)
                     : (int)real_syscall(SYS_fchmodat, dirfd, mapped, mode, flags);
    release(mapped);
    return rc;
}

int chmod(const char *path, mode_t mode)
{
    return fchmodat(AT_FDCWD, path, mode, 0);
}

int truncate(const char *path, off_t length)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, off_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "truncate");
    int rc = next_fn ? next_fn(mapped, length)
                     : (int)real_syscall(SYS_truncate, mapped, length);
    release(mapped);
    return rc;
}

/* utimensat(dirfd, NULL, ...) is valid (acts on dirfd itself): pass through. */
int utimensat(int dirfd, const char *path, const struct timespec times[2], int flags)
{
    char *mapped = NULL;
    const char *p = path; /* copy: NULL is a valid argument here */
    if (p) {
        mapped = map_path(p);
        if (!mapped)
            return -1;
    }
    typedef int (*fn_t)(int, const char *, const struct timespec *, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "utimensat");
    const char *target = mapped ? mapped : path;
    int rc = next_fn ? next_fn(dirfd, target, times, flags)
                     : (int)real_syscall(SYS_utimensat, dirfd, target, times, flags);
    release(mapped);
    return rc;
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef ssize_t (*fn_t)(const char *, const char *, void *, size_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "getxattr");
    ssize_t rc = next_fn ? next_fn(mapped, name, value, size)
                         : (ssize_t)real_syscall(SYS_getxattr, mapped, name, value, size);
    release(mapped);
    return rc;
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef ssize_t (*fn_t)(const char *, const char *, void *, size_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "lgetxattr");
    ssize_t rc = next_fn ? next_fn(mapped, name, value, size)
                         : (ssize_t)real_syscall(SYS_lgetxattr, mapped, name, value, size);
    release(mapped);
    return rc;
}

int setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, const char *, const void *, size_t, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "setxattr");
    int rc = next_fn ? next_fn(mapped, name, value, size, flags)
                     : (int)real_syscall(SYS_setxattr, mapped, name, value, size, flags);
    release(mapped);
    return rc;
}

int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, const char *, const void *, size_t, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "lsetxattr");
    int rc = next_fn ? next_fn(mapped, name, value, size, flags)
                     : (int)real_syscall(SYS_lsetxattr, mapped, name, value, size, flags);
    release(mapped);
    return rc;
}

int removexattr(const char *path, const char *name)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "removexattr");
    int rc = next_fn ? next_fn(mapped, name)
                     : (int)real_syscall(SYS_removexattr, mapped, name);
    release(mapped);
    return rc;
}

int lremovexattr(const char *path, const char *name)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "lremovexattr");
    int rc = next_fn ? next_fn(mapped, name)
                     : (int)real_syscall(SYS_lremovexattr, mapped, name);
    release(mapped);
    return rc;
}

ssize_t listxattr(const char *path, char *list, size_t size)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef ssize_t (*fn_t)(const char *, char *, size_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "listxattr");
    ssize_t rc = next_fn ? next_fn(mapped, list, size)
                         : (ssize_t)real_syscall(SYS_listxattr, mapped, list, size);
    release(mapped);
    return rc;
}

ssize_t llistxattr(const char *path, char *list, size_t size)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef ssize_t (*fn_t)(const char *, char *, size_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "llistxattr");
    ssize_t rc = next_fn ? next_fn(mapped, list, size)
                         : (ssize_t)real_syscall(SYS_llistxattr, mapped, list, size);
    release(mapped);
    return rc;
}

/* ---- ownership (virtual) ------------------------------------------------- */

int chown(const char *path, uid_t owner, gid_t group)
{
    if (fake_identity)
        return 0; /* metadata is virtual; the Android-owned file is unchanged */
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, uid_t, gid_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "chown");
    int rc = next_fn ? next_fn(mapped, owner, group)
                     : (int)real_syscall(SYS_fchownat, AT_FDCWD, mapped, owner, group, 0);
    release(mapped);
    return rc;
}

int lchown(const char *path, uid_t owner, gid_t group)
{
    if (fake_identity)
        return 0;
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, uid_t, gid_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "lchown");
    int rc = next_fn ? next_fn(mapped, owner, group)
                     : (int)real_syscall(SYS_fchownat, AT_FDCWD, mapped, owner, group, AT_SYMLINK_NOFOLLOW);
    release(mapped);
    return rc;
}

int fchown(int fd, uid_t owner, gid_t group)
{
    if (fake_identity)
        return 0;
    typedef int (*fn_t)(int, uid_t, gid_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fchown");
    return next_fn ? next_fn(fd, owner, group) : (int)real_syscall(SYS_fchown, fd, owner, group);
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
    if (fake_identity)
        return 0;
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, uid_t, gid_t, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fchownat");
    int rc = next_fn ? next_fn(dirfd, mapped, owner, group, flags)
                     : (int)real_syscall(SYS_fchownat, dirfd, mapped, owner, group, flags);
    release(mapped);
    return rc;
}

/* ---- synthetic chroot ----------------------------------------------------- */

/* Change the virtual root and process cwd, but never invoke the privileged
   kernel chroot syscall. The new root must be an existing directory; the
   virtual root is only replaced after every check and the chdir succeeded,
   so a failed chroot() leaves the previous root fully in effect. */
int chroot(const char *path)
{
    if (!root_len)
        return (int)real_syscall(SYS_chroot, path);

    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    char resolved[PATH_MAX];
    if (!realpath(mapped, resolved)) {
        release(mapped);
        return -1;
    }
    release(mapped);

    /* Raw syscall: the path is already a host path and must not be mapped. */
    struct stat st;
    if (real_syscall(SYS_newfstatat, AT_FDCWD, resolved, &st, 0) != 0)
        return -1;
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    size_t n = strlen(resolved);
    if (n >= sizeof(root_dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    typedef int (*fn_t)(const char *);
    static fn_t next_chdir;
    LOAD_NEXT(next_chdir, "chdir");
    int rc = next_chdir ? next_chdir(resolved) : (int)real_syscall(SYS_chdir, resolved);
    if (rc != 0)
        return -1;

    memcpy(root_dir, resolved, n + 1);
    root_len = n;
    return 0;
}

/* ---- raw syscall() interposition ------------------------------------------
 * Programs that call syscall(SYS_xxx, ...) directly bypass the libc wrappers
 * above. libc's syscall() is an ordinary exported function, so programs that
 * call it through the PLT are caught here. Inline asm and static binaries are
 * not covered. Pointer arguments listed below are mapped the same way as in
 * the wrappers; the symlink target and utimensat's NULL path are left alone.
 */
static long map_syscall_path_arg(long *slot, char **keep)
{
    if (!*slot)
        return 0;
    char *m = map_path((const char *)*slot);
    if (!m)
        return -1;
    *keep = m;
    *slot = (long)m;
    return 0;
}

/* ---- execve: rootfs-first, through the rootfs's own loader ----------------
 *
 * A program found inside ROOTSHIM_ROOT is started through the rootfs's dynamic
 * loader (ld-linux), so libc and the libraries come from the rootfs. This
 * bypasses the kernel's interpreter lookup, which would open the host's
 * /lib64/ld-linux and fails on Android/Termux, where that file does not exist.
 *
 * Symlinks in the final path component are resolved inside the rootfs, since
 * an absolute link target would otherwise be resolved against the host root.
 * Shebang scripts are re-issued as their interpreter, with the same argv the
 * kernel would build. A path missing from the rootfs is handed to the host
 * exec unchanged, but files the program opens are still mapped into the rootfs
 * (open() has no host fallback), so a host script that reads its own file
 * fails. Host ELF binaries that do not read rootfs-mapped files still work.
 *
 * Not covered: execvp(), execl*() and posix_spawn(). glibc calls the internal
 * __execve for these, which an LD_PRELOAD shim cannot intercept.
 */

#define ROOTSHIM_MAX_EXEC_DEPTH 4
#define ROOTSHIM_MAX_PHDRS 64
#define ROOTSHIM_MAX_SYMLINK_HOPS 16

#if defined(__x86_64__)
#define ROOTSHIM_EM_HOST EM_X86_64
#define ROOTSHIM_MULTIARCH "x86_64-linux-gnu"
#elif defined(__aarch64__)
#define ROOTSHIM_EM_HOST EM_AARCH64
#define ROOTSHIM_MULTIARCH "aarch64-linux-gnu"
#else
#define ROOTSHIM_EM_HOST 0
#define ROOTSHIM_MULTIARCH ""
#endif

/* Raw syscalls with all six arguments given explicitly; real_syscall() reads
   six variadic longs, so every call site must pass six. */
static long raw_openat_ro(const char *path)
{
    return real_syscall(SYS_openat, (long)AT_FDCWD, (long)path,
                        (long)(O_RDONLY | O_CLOEXEC), 0L, 0L, 0L);
}

static long raw_pread(long fd, void *buf, size_t n, long off)
{
    return real_syscall(SYS_pread64, fd, (long)buf, (long)n, off, 0L, 0L);
}

static void raw_close(long fd)
{
    real_syscall(SYS_close, fd, 0L, 0L, 0L, 0L, 0L);
}

/* ---- user and group databases ------------------------------------------ */

/* libnss_files reads /etc/passwd and /etc/group through glibc-internal opens,
   which LD_PRELOAD cannot see. The getpw and getgr functions below answer from
   the rootfs copies instead. With no rootfs they call the next implementation. */

#define ROOTSHIM_NSS_BUF 8192

struct nss_cursor {
    char *text;
    size_t len;
    size_t pos;
    bool open;
};
static struct nss_cursor pw_cursor, gr_cursor;
static struct passwd enum_pw;
static struct group enum_gr;
static char enum_pw_buf[ROOTSHIM_NSS_BUF];
static char enum_gr_buf[ROOTSHIM_NSS_BUF];

/* Whole file <root>/etc/<name>, NUL-terminated. NULL if it is missing. */
static char *nss_read(const char *name, size_t *len)
{
    char path[PATH_MAX];
    int pn = snprintf(path, sizeof path, "%s/etc/%s", root_dir, name);
    if (pn < 0 || (size_t)pn >= sizeof path) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    long fd = raw_openat_ro(path);
    if (fd < 0)
        return NULL;
    size_t cap = 4096, used = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        if (used == cap) {
            char *nb = realloc(buf, cap * 2 + 1);
            if (!nb) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = nb;
            cap *= 2;
        }
        long r = raw_pread(fd, buf + used, cap - used, (long)used);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            buf = NULL;
            break;
        }
        if (r == 0)
            break;
        used += (size_t)r;
    }
    raw_close(fd);
    if (!buf) {
        errno = EIO;
        return NULL;
    }
    buf[used] = '\0';
    *len = used;
    return buf;
}

/* Copy the next data line (no comments, no blanks) into buf. *too_big is set
   when the line does not fit; the position still moves past it. */
static bool nss_next_line(const char *text, size_t len, size_t *pos, char *buf,
                          size_t bufsz, size_t *out_len, bool *too_big)
{
    *too_big = false;
    while (*pos < len) {
        size_t start = *pos;
        const char *nl = memchr(text + start, '\n', len - start);
        size_t end = nl ? (size_t)(nl - text) : len;
        *pos = nl ? end + 1 : len;
        size_t n = end - start;
        if (n == 0 || text[start] == '#')
            continue;
        if (n >= bufsz) {
            *too_big = true;
            return false;
        }
        memcpy(buf, text + start, n);
        buf[n] = '\0';
        *out_len = n;
        return true;
    }
    return false;
}

/* Split line in place at ':'. Returns the total field count; only the first
   max fields are stored. */
static int nss_split(char *line, char *fields[], int max)
{
    int n = 0;
    char *p = line;
    for (;;) {
        char *c = strchr(p, ':');
        if (n < max)
            fields[n] = p;
        ++n;
        if (!c)
            break;
        if (n <= max)
            *c = '\0';
        p = c + 1;
    }
    return n;
}

static bool nss_id(const char *s, unsigned long *out)
{
    if (!*s)
        return false;
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (*end != '\0' || errno)
        return false;
    *out = v;
    return true;
}

static bool nss_fill_passwd(char *line, struct passwd *pw)
{
    char *f[7];
    if (nss_split(line, f, 7) != 7)
        return false;
    unsigned long uid, gid;
    if (!nss_id(f[2], &uid) || !nss_id(f[3], &gid))
        return false;
    pw->pw_name = f[0];
    pw->pw_passwd = f[1];
    pw->pw_uid = (uid_t)uid;
    pw->pw_gid = (gid_t)gid;
    pw->pw_gecos = f[4];
    pw->pw_dir = f[5];
    pw->pw_shell = f[6];
    return true;
}

/* 0 = filled, EINVAL = not a group line, ERANGE = buffer too small. The member
   pointer array is placed in buf after the line. */
static int nss_fill_group(char *buf, size_t buflen, size_t linelen,
                          struct group *gr)
{
    char *f[4];
    if (nss_split(buf, f, 4) != 4)
        return EINVAL;
    unsigned long gid;
    if (!nss_id(f[2], &gid))
        return EINVAL;
    size_t members = 0;
    if (*f[3]) {
        members = 1;
        for (const char *c = f[3]; *c; ++c)
            if (*c == ',')
                ++members;
    }
    size_t off = linelen + 1;
    size_t mis = ((uintptr_t)(buf + off)) % sizeof(char *);
    if (mis)
        off += sizeof(char *) - mis;
    if (off > buflen || (members + 1) * sizeof(char *) > buflen - off)
        return ERANGE;
    char **mem = (char **)(void *)(buf + off);
    size_t k = 0;
    if (members) {
        char *p = f[3];
        for (;;) {
            char *c = strchr(p, ',');
            mem[k++] = p;
            if (!c)
                break;
            *c = '\0';
            p = c + 1;
        }
    }
    mem[k] = NULL;
    gr->gr_name = f[0];
    gr->gr_passwd = f[1];
    gr->gr_gid = (gid_t)gid;
    gr->gr_mem = mem;
    return 0;
}

static int nss_passwd_find(const char *name, uid_t uid, bool by_name,
                           struct passwd *pw, char *buf, size_t buflen,
                           struct passwd **result)
{
    *result = NULL;
    size_t len = 0;
    char *text = nss_read("passwd", &len);
    if (!text)
        return 0;
    int rc = 0;
    size_t pos = 0, linelen = 0;
    bool too_big = false;
    while (nss_next_line(text, len, &pos, buf, buflen, &linelen, &too_big)) {
        if (!nss_fill_passwd(buf, pw))
            continue;
        if (by_name ? strcmp(pw->pw_name, name) == 0 : pw->pw_uid == uid) {
            *result = pw;
            break;
        }
    }
    if (!*result && too_big)
        rc = ERANGE;
    free(text);
    return rc;
}

static int nss_group_find(const char *name, gid_t gid, bool by_name,
                          struct group *gr, char *buf, size_t buflen,
                          struct group **result)
{
    *result = NULL;
    size_t len = 0;
    char *text = nss_read("group", &len);
    if (!text)
        return 0;
    int rc = 0;
    size_t pos = 0, linelen = 0;
    bool too_big = false;
    while (nss_next_line(text, len, &pos, buf, buflen, &linelen, &too_big)) {
        int fr = nss_fill_group(buf, buflen, linelen, gr);
        if (fr == ERANGE) {
            rc = ERANGE;
            break;
        }
        if (fr != 0)
            continue;
        if (by_name ? strcmp(gr->gr_name, name) == 0 : gr->gr_gid == gid) {
            *result = gr;
            break;
        }
    }
    if (!*result && too_big)
        rc = ERANGE;
    free(text);
    return rc;
}

static bool nss_cursor_load(struct nss_cursor *c, const char *name)
{
    if (!c->open) {
        c->text = nss_read(name, &c->len);
        c->pos = 0;
        c->open = true;
    }
    return c->text != NULL;
}

static void nss_cursor_close(struct nss_cursor *c)
{
    free(c->text);
    c->text = NULL;
    c->len = 0;
    c->pos = 0;
    c->open = false;
}

static void nss_fail(int rc)
{
    errno = rc;
}

struct passwd *getpwnam(const char *name)
{
    static struct passwd pw;
    static char buf[ROOTSHIM_NSS_BUF];
    struct passwd *res = NULL;
    if (!root_len) {
        static struct passwd *(*next)(const char *);
        LOAD_NEXT(next, "getpwnam");
        return next ? next(name) : NULL;
    }
    int rc = nss_passwd_find(name, 0, true, &pw, buf, sizeof buf, &res);
    if (rc)
        { nss_fail(rc); return NULL; }
    return res;
}

struct passwd *getpwuid(uid_t uid)
{
    static struct passwd pw;
    static char buf[ROOTSHIM_NSS_BUF];
    struct passwd *res = NULL;
    if (!root_len) {
        static struct passwd *(*next)(uid_t);
        LOAD_NEXT(next, "getpwuid");
        return next ? next(uid) : NULL;
    }
    int rc = nss_passwd_find(NULL, uid, false, &pw, buf, sizeof buf, &res);
    if (rc)
        { nss_fail(rc); return NULL; }
    return res;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result)
{
    if (!root_len) {
        static int (*next)(const char *, struct passwd *, char *, size_t,
                           struct passwd **);
        LOAD_NEXT(next, "getpwnam_r");
        return next ? next(name, pwd, buf, buflen, result) : ENOSYS;
    }
    return nss_passwd_find(name, 0, true, pwd, buf, buflen, result);
}

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen,
               struct passwd **result)
{
    if (!root_len) {
        static int (*next)(uid_t, struct passwd *, char *, size_t,
                           struct passwd **);
        LOAD_NEXT(next, "getpwuid_r");
        return next ? next(uid, pwd, buf, buflen, result) : ENOSYS;
    }
    return nss_passwd_find(NULL, uid, false, pwd, buf, buflen, result);
}

struct group *getgrnam(const char *name)
{
    static struct group gr;
    static char buf[ROOTSHIM_NSS_BUF];
    struct group *res = NULL;
    if (!root_len) {
        static struct group *(*next)(const char *);
        LOAD_NEXT(next, "getgrnam");
        return next ? next(name) : NULL;
    }
    int rc = nss_group_find(name, 0, true, &gr, buf, sizeof buf, &res);
    if (rc)
        { nss_fail(rc); return NULL; }
    return res;
}

struct group *getgrgid(gid_t gid)
{
    static struct group gr;
    static char buf[ROOTSHIM_NSS_BUF];
    struct group *res = NULL;
    if (!root_len) {
        static struct group *(*next)(gid_t);
        LOAD_NEXT(next, "getgrgid");
        return next ? next(gid) : NULL;
    }
    int rc = nss_group_find(NULL, gid, false, &gr, buf, sizeof buf, &res);
    if (rc)
        { nss_fail(rc); return NULL; }
    return res;
}

int getgrnam_r(const char *name, struct group *grp, char *buf, size_t buflen,
               struct group **result)
{
    if (!root_len) {
        static int (*next)(const char *, struct group *, char *, size_t,
                           struct group **);
        LOAD_NEXT(next, "getgrnam_r");
        return next ? next(name, grp, buf, buflen, result) : ENOSYS;
    }
    return nss_group_find(name, 0, true, grp, buf, buflen, result);
}

int getgrgid_r(gid_t gid, struct group *grp, char *buf, size_t buflen,
               struct group **result)
{
    if (!root_len) {
        static int (*next)(gid_t, struct group *, char *, size_t,
                           struct group **);
        LOAD_NEXT(next, "getgrgid_r");
        return next ? next(gid, grp, buf, buflen, result) : ENOSYS;
    }
    return nss_group_find(NULL, gid, false, grp, buf, buflen, result);
}

/* Enumeration (getent without a key). */
void setpwent(void)
{
    if (!root_len) {
        static void (*next)(void);
        LOAD_NEXT(next, "setpwent");
        if (next)
            next();
        return;
    }
    nss_cursor_close(&pw_cursor);
    nss_cursor_load(&pw_cursor, "passwd");
}

void endpwent(void)
{
    if (!root_len) {
        static void (*next)(void);
        LOAD_NEXT(next, "endpwent");
        if (next)
            next();
        return;
    }
    nss_cursor_close(&pw_cursor);
}

struct passwd *getpwent(void)
{
    if (!root_len) {
        static struct passwd *(*next)(void);
        LOAD_NEXT(next, "getpwent");
        return next ? next() : NULL;
    }
    if (!nss_cursor_load(&pw_cursor, "passwd"))
        return NULL;
    size_t linelen = 0;
    bool too_big = false;
    for (;;) {
        if (!nss_next_line(pw_cursor.text, pw_cursor.len, &pw_cursor.pos,
                           enum_pw_buf, sizeof enum_pw_buf, &linelen,
                           &too_big)) {
            if (too_big)
                continue;
            return NULL;
        }
        if (nss_fill_passwd(enum_pw_buf, &enum_pw))
            return &enum_pw;
    }
}

void setgrent(void)
{
    if (!root_len) {
        static void (*next)(void);
        LOAD_NEXT(next, "setgrent");
        if (next)
            next();
        return;
    }
    nss_cursor_close(&gr_cursor);
    nss_cursor_load(&gr_cursor, "group");
}

void endgrent(void)
{
    if (!root_len) {
        static void (*next)(void);
        LOAD_NEXT(next, "endgrent");
        if (next)
            next();
        return;
    }
    nss_cursor_close(&gr_cursor);
}

struct group *getgrent(void)
{
    if (!root_len) {
        static struct group *(*next)(void);
        LOAD_NEXT(next, "getgrent");
        return next ? next() : NULL;
    }
    if (!nss_cursor_load(&gr_cursor, "group"))
        return NULL;
    size_t linelen = 0;
    bool too_big = false;
    for (;;) {
        if (!nss_next_line(gr_cursor.text, gr_cursor.len, &gr_cursor.pos,
                           enum_gr_buf, sizeof enum_gr_buf, &linelen,
                           &too_big)) {
            if (too_big)
                continue;
            return NULL;
        }
        if (nss_fill_group(enum_gr_buf, sizeof enum_gr_buf, linelen,
                           &enum_gr) == 0)
            return &enum_gr;
    }
}

/* Follow symlinks in the final component of a virtual path, inside the
   rootfs. Absolute targets stay virtual; relative ones are joined to the
   directory of the link. Intermediate directory links are left to the kernel.
   Returns a new virtual path, or NULL with errno set. */
static char *resolve_final_rooted(const char *virt)
{
    char *cur = strdup(virt);
    if (!cur) {
        errno = ENOMEM;
        return NULL;
    }
    for (int hop = 0; hop < ROOTSHIM_MAX_SYMLINK_HOPS; ++hop) {
        char *mapped = map_path(cur);
        if (!mapped) {
            free(cur);
            return NULL;
        }
        char target[PATH_MAX];
        long n = real_syscall(SYS_readlinkat, (long)AT_FDCWD, (long)mapped,
                              (long)target, (long)sizeof(target), 0L, 0L);
        release(mapped);
        if (n <= 0 || (size_t)n >= sizeof(target))
            return cur; /* not a symlink, or missing: nothing more to do */
        target[n] = '\0';

        char *next = NULL;
        if (target[0] == '/') {
            next = strdup(target);
        } else {
            size_t dirlen = (size_t)(strrchr(cur, '/') - cur);
            next = malloc(dirlen + 1 + (size_t)n + 1);
            if (next) {
                memcpy(next, cur, dirlen);
                next[dirlen] = '/';
                memcpy(next + dirlen + 1, target, (size_t)n + 1);
            }
        }
        free(cur);
        if (!next) {
            errno = ENOMEM;
            return NULL;
        }
        cur = next;
    }
    free(cur);
    errno = ELOOP;
    return NULL;
}

/* PT_INTERP of a 64-bit little-endian ELF for this machine. Returns 1 with
   interp set when dynamic, 0 when static, -1 when this path does not apply. */
static int elf_interp(long fd, char *interp, size_t size)
{
#if ROOTSHIM_EM_HOST == 0
    (void)fd;
    (void)interp;
    (void)size;
    return -1;
#else
    Elf64_Ehdr eh;
    if (raw_pread(fd, &eh, sizeof eh, 0) != (long)sizeof eh)
        return -1;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;
    if (eh.e_machine != ROOTSHIM_EM_HOST)
        return -1;
    if (eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
        eh.e_phnum > ROOTSHIM_MAX_PHDRS)
        return -1;

    Elf64_Phdr ph[ROOTSHIM_MAX_PHDRS];
    size_t bytes = (size_t)eh.e_phnum * sizeof(Elf64_Phdr);
    if (raw_pread(fd, ph, bytes, (long)eh.e_phoff) != (long)bytes)
        return -1;

    for (unsigned i = 0; i < eh.e_phnum; ++i) {
        if (ph[i].p_type != PT_INTERP)
            continue;
        if (ph[i].p_filesz < 2 || ph[i].p_filesz >= size)
            return -1;
        if (raw_pread(fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) !=
            (long)ph[i].p_filesz)
            return -1;
        interp[ph[i].p_filesz] = '\0';
        return interp[0] == '/' ? 1 : -1;
    }
    return 0;
#endif
}

/* Parse "#!interp [optional-arg]" from the first line of a script. The
   kernel passes the whole remainder of the line as one optional argument. */
static bool parse_shebang(const unsigned char *head, size_t n, char *interp,
                          size_t isz, char *opt, size_t osz, bool *has_opt)
{
    size_t i = 2;
    while (i < n && (head[i] == ' ' || head[i] == '\t'))
        ++i;
    size_t start = i;
    while (i < n && head[i] != ' ' && head[i] != '\t' && head[i] != '\n' &&
           head[i] != '\r')
        ++i;
    size_t len = i - start;
    if (len == 0 || len >= isz || head[start] != '/')
        return false;
    memcpy(interp, head + start, len);
    interp[len] = '\0';

    while (i < n && (head[i] == ' ' || head[i] == '\t'))
        ++i;
    size_t optstart = i;
    while (i < n && head[i] != '\n' && head[i] != '\r')
        ++i;
    if (i >= n)
        return false; /* line longer than the buffer: refuse */
    size_t optlen = i - optstart;
    while (optlen > 0 && (head[optstart + optlen - 1] == ' ' ||
                          head[optstart + optlen - 1] == '\t'))
        --optlen;
    *has_opt = optlen > 0;
    if (*has_opt) {
        if (optlen >= osz)
            return false;
        memcpy(opt, head + optstart, optlen);
        opt[optlen] = '\0';
    }
    return true;
}

static int passthrough_exec(const char *path, char *const argv[],
                            char *const envp[])
{
    return (int)real_syscall(SYS_execve, (long)path, (long)argv, (long)envp,
                             0L, 0L, 0L);
}

/* Library search path for the rootfs loader. ROOTSHIM_LOADER_LIBPATH replaces
   the default for other layouts. Caller frees. */
static char *loader_library_path(void)
{
    const char *override = getenv("ROOTSHIM_LOADER_LIBPATH");
    if (override)
        return strdup(override);
    size_t cap = 4 * (root_len + 1) + 128;
    char *lp = malloc(cap);
    if (!lp)
        return NULL;
    snprintf(lp, cap,
             "%s/usr/lib/" ROOTSHIM_MULTIARCH ":%s/lib/" ROOTSHIM_MULTIARCH
             ":%s/usr/lib:%s/lib",
             root_dir, root_dir, root_dir, root_dir);
    return lp;
}

/* Start a dynamic program through the rootfs loader: ld-linux with
   --library-path, then the program, with argv[0] restored via --argv0. */
static int exec_via_loader(const char *mapped_prog, const char *interp,
                           char *const argv[], char *const envp[])
{
    char *virt_interp = resolve_final_rooted(interp);
    if (!virt_interp)
        return -1;
    char *ld = map_path(virt_interp);
    free(virt_interp);
    if (!ld)
        return -1;

    long lfd = raw_openat_ro(ld);
    if (lfd < 0) {
        /* The rootfs has no loader for this program: let the kernel try. */
        release(ld);
        return passthrough_exec(mapped_prog, argv, envp);
    }
    raw_close(lfd);

    char *lp = loader_library_path();
    size_t argc = 0;
    while (argv && argv[argc])
        ++argc;
    char **nargv = calloc(argc + 8, sizeof *nargv);
    if (!lp || !nargv) {
        free(lp);
        free(nargv);
        release(ld);
        errno = ENOMEM;
        return -1;
    }
    size_t k = 0;
    nargv[k++] = ld;
    nargv[k++] = (char *)"--library-path";
    nargv[k++] = lp;
    if (argc > 0) {
        nargv[k++] = (char *)"--argv0";
        nargv[k++] = argv[0];
    }
    nargv[k++] = (char *)mapped_prog;
    for (size_t i = 1; i < argc; ++i)
        nargv[k++] = argv[i];
    nargv[k] = NULL;

    int rc = (int)real_syscall(SYS_execve, (long)ld, (long)nargv, (long)envp,
                               0L, 0L, 0L);
    int saved = errno;
    free(nargv);
    free(lp);
    release(ld);
    errno = saved;
    return rc;
}

/* A path that is not in the rootfs. A host shell script is run by the rootfs
   shell, with the script passed as /proc/self/fd/N: /proc is not mapped, so the
   interpreter reads the host file through the inherited descriptor. Anything
   that is not a script goes to the host exec unchanged. $0 in such a script is
   the /proc/self/fd/N path. */
static int exec_host_script(const char *path, char *const argv[],
                            char *const envp[], int depth)
{
    long hfd = raw_openat_ro(path);
    if (hfd < 0)
        return passthrough_exec(path, argv, envp);
    unsigned char head[256];
    long n = raw_pread(hfd, head, sizeof head, 0);
    char sinterp[PATH_MAX];
    char sopt[256];
    bool has_opt = false;
    if (n < 2 || head[0] != '#' || head[1] != '!' ||
        !parse_shebang(head, (size_t)n, sinterp, sizeof sinterp, sopt,
                       sizeof sopt, &has_opt)) {
        raw_close(hfd);
        return passthrough_exec(path, argv, envp);
    }
    /* Keep the descriptor across exec (raw_openat_ro sets O_CLOEXEC). */
    real_syscall(SYS_fcntl, hfd, (long)F_SETFD, 0L, 0L, 0L, 0L);
    char script[64];
    snprintf(script, sizeof script, "/proc/self/fd/%ld", hfd);

    size_t argc = 0;
    while (argv && argv[argc])
        ++argc;
    char **nargv = calloc(argc + 4, sizeof *nargv);
    if (!nargv) {
        raw_close(hfd);
        errno = ENOMEM;
        return -1;
    }
    size_t k = 0;
    nargv[k++] = sinterp;
    if (has_opt)
        nargv[k++] = sopt;
    nargv[k++] = script;
    for (size_t i = 1; i < argc; ++i)
        nargv[k++] = argv[i];
    nargv[k] = NULL;
    int rc = exec_rooted(sinterp, nargv, envp, depth + 1);
    int saved = errno;
    free(nargv);
    raw_close(hfd);
    errno = saved;
    return rc;
}

static int exec_rooted(const char *path, char *const argv[],
                       char *const envp[], int depth)
{
    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (depth > ROOTSHIM_MAX_EXEC_DEPTH) {
        errno = ELOOP;
        return -1;
    }
    if (!root_len || path[0] != '/' || is_passthrough(path))
        return passthrough_exec(path, argv, envp);

    char *virt = resolve_final_rooted(path);
    if (!virt)
        return -1;
    char *mapped = map_path(virt);
    if (!mapped) {
        int saved = errno;
        free(virt);
        errno = saved;
        return -1;
    }

    long fd = raw_openat_ro(mapped);
    if (fd < 0) {
        /* Not in the rootfs: host scripts and host binaries (see exec_host_script). */
        release(mapped);
        free(virt);
        return exec_host_script(path, argv, envp, depth);
    }

    unsigned char head[256];
    long n = raw_pread(fd, head, sizeof head, 0);
    int rc;
    if (n >= 4 && memcmp(head, ELFMAG, SELFMAG) == 0) {
        char interp[PATH_MAX];
        int dyn = elf_interp(fd, interp, sizeof interp);
        raw_close(fd);
        if (dyn == 1)
            rc = exec_via_loader(mapped, interp, argv, envp);
        else
            rc = passthrough_exec(mapped, argv, envp);
    } else if (n >= 2 && head[0] == '#' && head[1] == '!') {
        raw_close(fd);
        char sinterp[PATH_MAX];
        char sopt[256];
        bool has_opt = false;
        if (parse_shebang(head, (size_t)n, sinterp, sizeof sinterp, sopt,
                          sizeof sopt, &has_opt)) {
            size_t argc = 0;
            while (argv && argv[argc])
                ++argc;
            char **nargv = calloc(argc + 4, sizeof *nargv);
            if (!nargv) {
                errno = ENOMEM;
                rc = -1;
            } else {
                size_t k = 0;
                nargv[k++] = sinterp;
                if (has_opt)
                    nargv[k++] = sopt;
                nargv[k++] = (char *)path; /* kernel passes the script path */
                for (size_t i = 1; i < argc; ++i)
                    nargv[k++] = argv[i];
                nargv[k] = NULL;
                rc = exec_rooted(sinterp, nargv, envp, depth + 1);
                free(nargv);
            }
        } else {
            errno = ENOEXEC;
            rc = -1;
        }
    } else {
        raw_close(fd);
        rc = passthrough_exec(mapped, argv, envp);
    }

    int saved = errno;
    release(mapped);
    free(virt);
    errno = saved;
    return rc;
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    return exec_rooted(path, argv, envp, 0);
}

extern char **environ;

int execv(const char *path, char *const argv[])
{
    return exec_rooted(path, argv, environ, 0);
}

/* Raw stat results need the same synthetic owner as the wrappers. struct
   statx is addressed by its stable kernel uapi offsets (stx_uid at 20,
   stx_gid at 24) so this works even where the libc headers lack statx. */
static void fake_raw_stat(long number, const long *a)
{
    if (!fake_identity)
        return;
    switch (number) {
#ifdef SYS_newfstatat
    case SYS_newfstatat:
        fake_stat_owner((struct stat *)(intptr_t)a[2]);
        break;
#endif
#ifdef SYS_fstatat
    case SYS_fstatat:
        fake_stat_owner((struct stat *)(intptr_t)a[2]);
        break;
#endif
#ifdef SYS_fstat
    case SYS_fstat:
        fake_stat_owner((struct stat *)(intptr_t)a[1]);
        break;
#endif
#ifdef SYS_statx
    case SYS_statx:
        if (a[4]) {
            uint32_t zero = 0;
            memcpy((char *)(intptr_t)a[4] + 20, &zero, sizeof(zero));
            memcpy((char *)(intptr_t)a[4] + 24, &zero, sizeof(zero));
        }
        break;
#endif
    default:
        break;
    }
}

long syscall(long number, ...)
{
    long a[6] = { 0, 0, 0, 0, 0, 0 };
    va_list ap;
    va_start(ap, number);
    for (int i = 0; i < 6; ++i)
        a[i] = va_arg(ap, long);
    va_end(ap);

#ifdef SYS_execve
    if (number == SYS_execve)
        return exec_rooted((const char *)a[0], (char *const *)a[1],
                           (char *const *)a[2], 0);
#endif

    if (fake_identity) {
        switch (number) {
#ifdef SYS_getuid
        case SYS_getuid:
#endif
#ifdef SYS_geteuid
        case SYS_geteuid:
#endif
#ifdef SYS_getgid
        case SYS_getgid:
#endif
#ifdef SYS_getegid
        case SYS_getegid:
#endif
            return 0;
#ifdef SYS_getgroups
        case SYS_getgroups:
            return getgroups((int)a[0], (gid_t *)a[1]);
#endif
        default:
            break;
        }
    }

    long *slot1 = NULL;
    long *slot2 = NULL;
    switch (number) {
        /* path in arg 1 (dirfd first) */
#ifdef SYS_openat
    case SYS_openat:
#endif
#ifdef SYS_mkdirat
    case SYS_mkdirat:
#endif
#ifdef SYS_unlinkat
    case SYS_unlinkat:
#endif
#ifdef SYS_readlinkat
    case SYS_readlinkat:
#endif
#ifdef SYS_newfstatat
    case SYS_newfstatat:
#endif
#ifdef SYS_fstatat
    case SYS_fstatat:
#endif
#ifdef SYS_faccessat
    case SYS_faccessat:
#endif
#ifdef SYS_faccessat2
    case SYS_faccessat2:
#endif
#ifdef SYS_fchmodat
    case SYS_fchmodat:
#endif
#ifdef SYS_fchownat
    case SYS_fchownat:
#endif
#ifdef SYS_utimensat
    case SYS_utimensat:
#endif
#ifdef SYS_statx
    case SYS_statx:
#endif
        slot1 = &a[1];
        break;
        /* two paths: arg 1 and arg 3 */
#ifdef SYS_renameat
    case SYS_renameat:
#endif
#ifdef SYS_renameat2
    case SYS_renameat2:
#endif
#ifdef SYS_linkat
    case SYS_linkat:
#endif
        slot1 = &a[1];
        slot2 = &a[3];
        break;
        /* symlinkat(target, newdirfd, linkpath): only linkpath is mapped */
#ifdef SYS_symlinkat
    case SYS_symlinkat:
        slot1 = &a[2];
        break;
#endif
        /* path in arg 0 */
#ifdef SYS_chdir
    case SYS_chdir:
#endif
#ifdef SYS_truncate
    case SYS_truncate:
#endif
#ifdef SYS_getxattr
    case SYS_getxattr:
#endif
#ifdef SYS_lgetxattr
    case SYS_lgetxattr:
#endif
#ifdef SYS_setxattr
    case SYS_setxattr:
#endif
#ifdef SYS_lsetxattr
    case SYS_lsetxattr:
#endif
#ifdef SYS_listxattr
    case SYS_listxattr:
#endif
#ifdef SYS_llistxattr
    case SYS_llistxattr:
#endif
#ifdef SYS_removexattr
    case SYS_removexattr:
#endif
#ifdef SYS_lremovexattr
    case SYS_lremovexattr:
#endif
        slot1 = &a[0];
        break;
    default:
        break;
    }

    char *keep1 = NULL;
    char *keep2 = NULL;
    if (slot1 && map_syscall_path_arg(slot1, &keep1) != 0)
        return -1;
    if (slot2 && map_syscall_path_arg(slot2, &keep2) != 0) {
        release(keep1);
        return -1;
    }

    long rc = real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (rc == 0)
        fake_raw_stat(number, a);
    release(keep1);
    release(keep2);
    return rc;
}
