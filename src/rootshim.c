#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

/*
 * Experimental, cooperative-process shim. This is NOT a security boundary
 * and does not grant kernel privileges. It redirects a subset of libc path
 * calls into ROOTSHIM_ROOT and can report synthetic uid/gid values.
 */

static char root_dir[PATH_MAX];
static size_t root_len;
static int fake_identity;
static int resolving_symbols;

#define LOAD_NEXT(var, name) do {                                      \
    if (!(var) && !resolving_symbols) {                                \
        resolving_symbols = 1;                                         \
        *(void **)(&(var)) = dlsym(RTLD_NEXT, (name));                 \
        resolving_symbols = 0;                                         \
    }                                                                   \
} while (0)

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

/* Map an absolute virtual path into ROOTSHIM_ROOT. Dot-dot components are
   clamped at the virtual root. This lexical mapping does not prevent symlink
   escapes; see the security notes in README.md. */
static char *map_path(const char *path)
{
    if (!path)
        return NULL;
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
}

static void fake_stat_owner(struct stat *st)
{
    if (st && fake_identity) {
        st->st_uid = 0;
        st->st_gid = 0;
    }
}

uid_t getuid(void)  { return fake_identity ? 0 : (uid_t)syscall(SYS_getuid); }
uid_t geteuid(void) { return fake_identity ? 0 : (uid_t)syscall(SYS_geteuid); }
gid_t getgid(void)  { return fake_identity ? 0 : (gid_t)syscall(SYS_getgid); }
gid_t getegid(void) { return fake_identity ? 0 : (gid_t)syscall(SYS_getegid); }

int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    if (!fake_identity)
        return (int)syscall(SYS_getresuid, ruid, euid, suid);
    if (ruid) *ruid = 0;
    if (euid) *euid = 0;
    if (suid) *suid = 0;
    return 0;
}

int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    if (!fake_identity)
        return (int)syscall(SYS_getresgid, rgid, egid, sgid);
    if (rgid) *rgid = 0;
    if (egid) *egid = 0;
    if (sgid) *sgid = 0;
    return 0;
}

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, int, ...);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "open");
    int rc;
    if (next_fn)
        rc = (flags & O_CREAT) ? next_fn(mapped, flags, mode) : next_fn(mapped, flags);
    else
        rc = (int)syscall(SYS_openat, AT_FDCWD, mapped, flags, mode);
    free(mapped);
    return rc;
}

int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, int, ...);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "open64");
    int rc;
    if (next_fn)
        rc = (flags & O_CREAT) ? next_fn(mapped, flags, mode) : next_fn(mapped, flags);
    else
        rc = (int)syscall(SYS_openat, AT_FDCWD, mapped, flags, mode);
    free(mapped);
    return rc;
}

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int, ...);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "openat");
    int rc;
    if (next_fn)
        rc = (flags & O_CREAT) ? next_fn(dirfd, mapped, flags, mode) : next_fn(dirfd, mapped, flags);
    else
        rc = (int)syscall(SYS_openat, dirfd, mapped, flags, mode);
    free(mapped);
    return rc;
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int, ...);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "openat64");
    int rc;
    if (next_fn)
        rc = (flags & O_CREAT) ? next_fn(dirfd, mapped, flags, mode) : next_fn(dirfd, mapped, flags);
    else
        rc = (int)syscall(SYS_openat, dirfd, mapped, flags, mode);
    free(mapped);
    return rc;
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
    free(mapped);
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
    if (!next_fn) {
        next_fn = dlsym(RTLD_NEXT, "fopen");
    }
    FILE *rc = next_fn ? next_fn(mapped, mode) : NULL;
    free(mapped);
    return rc;
}

int stat(const char *path, struct stat *st)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, struct stat *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "stat");
    int rc = next_fn ? next_fn(mapped, st) : (int)syscall(SYS_newfstatat, AT_FDCWD, mapped, st, 0);
    if (rc == 0) fake_stat_owner(st);
    free(mapped);
    return rc;
}

int lstat(const char *path, struct stat *st)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, struct stat *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "lstat");
    int rc = next_fn ? next_fn(mapped, st) : (int)syscall(SYS_newfstatat, AT_FDCWD, mapped, st, AT_SYMLINK_NOFOLLOW);
    if (rc == 0) fake_stat_owner(st);
    free(mapped);
    return rc;
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, struct stat *, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fstatat");
    int rc = next_fn ? next_fn(dirfd, mapped, st, flags) : (int)syscall(SYS_newfstatat, dirfd, mapped, st, flags);
    if (rc == 0) fake_stat_owner(st);
    free(mapped);
    return rc;
}

int fstat(int fd, struct stat *st)
{
    typedef int (*fn_t)(int, struct stat *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fstat");
    int rc = next_fn ? next_fn(fd, st) : (int)syscall(SYS_fstat, fd, st);
    if (rc == 0) fake_stat_owner(st);
    return rc;
}

int access(const char *path, int mode)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "access");
    int rc = next_fn ? next_fn(mapped, mode) : (int)syscall(SYS_faccessat, AT_FDCWD, mapped, mode, 0);
    free(mapped);
    return rc;
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(int, const char *, int, int);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "faccessat");
    int rc = next_fn ? next_fn(dirfd, mapped, mode, flags) : (int)syscall(SYS_faccessat, dirfd, mapped, mode, flags);
    free(mapped);
    return rc;
}

int chdir(const char *path)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "chdir");
    int rc = next_fn ? next_fn(mapped) : (int)syscall(SYS_chdir, mapped);
    free(mapped);
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

int mkdir(const char *path, mode_t mode)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *, mode_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "mkdir");
    int rc = next_fn ? next_fn(mapped, mode) : (int)syscall(SYS_mkdirat, AT_FDCWD, mapped, mode);
    free(mapped);
    return rc;
}

int unlink(const char *path)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "unlink");
    int rc = next_fn ? next_fn(mapped) : (int)syscall(SYS_unlinkat, AT_FDCWD, mapped, 0);
    free(mapped);
    return rc;
}

int rmdir(const char *path)
{
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    typedef int (*fn_t)(const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "rmdir");
    int rc = next_fn ? next_fn(mapped) : (int)syscall(SYS_unlinkat, AT_FDCWD, mapped, AT_REMOVEDIR);
    free(mapped);
    return rc;
}

int rename(const char *oldpath, const char *newpath)
{
    char *old_mapped = map_path(oldpath);
    char *new_mapped = map_path(newpath);
    if (!old_mapped || !new_mapped) {
        free(old_mapped);
        free(new_mapped);
        return -1;
    }
    typedef int (*fn_t)(const char *, const char *);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "rename");
    int rc = next_fn ? next_fn(old_mapped, new_mapped) : (int)syscall(SYS_renameat, AT_FDCWD, old_mapped, AT_FDCWD, new_mapped);
    free(old_mapped);
    free(new_mapped);
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
    free(mapped);
    return rc;
}

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
    int rc = next_fn ? next_fn(mapped, owner, group) : (int)syscall(SYS_fchownat, AT_FDCWD, mapped, owner, group, 0);
    free(mapped);
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
    int rc = next_fn ? next_fn(mapped, owner, group) : (int)syscall(SYS_fchownat, AT_FDCWD, mapped, owner, group, AT_SYMLINK_NOFOLLOW);
    free(mapped);
    return rc;
}

int fchown(int fd, uid_t owner, gid_t group)
{
    if (fake_identity)
        return 0;
    typedef int (*fn_t)(int, uid_t, gid_t);
    static fn_t next_fn;
    LOAD_NEXT(next_fn, "fchown");
    return next_fn ? next_fn(fd, owner, group) : (int)syscall(SYS_fchown, fd, owner, group);
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
    int rc = next_fn ? next_fn(dirfd, mapped, owner, group, flags) : (int)syscall(SYS_fchownat, dirfd, mapped, owner, group, flags);
    free(mapped);
    return rc;
}

/* Synthetic chroot: change the virtual root and process cwd, but never invoke
   the privileged kernel chroot syscall. */
int chroot(const char *path)
{
    if (!root_len)
        return (int)syscall(SYS_chroot, path);
    char *mapped = map_path(path);
    if (!mapped)
        return -1;
    char resolved[PATH_MAX];
    if (!realpath(mapped, resolved)) {
        free(mapped);
        return -1;
    }
    free(mapped);
    size_t n = strlen(resolved);
    if (n >= sizeof(root_dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(root_dir, resolved, n + 1);
    root_len = n;
    typedef int (*fn_t)(const char *);
    static fn_t next_chdir;
    LOAD_NEXT(next_chdir, "chdir");
    return next_chdir ? next_chdir(root_dir) : (int)syscall(SYS_chdir, root_dir);
}
