#define _GNU_SOURCE
#include <dirent.h>
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
 * Deliberately NOT hooked: execve()/exec*(). Host binaries are found through
 * the host PATH and must stay executable from inside the virtual root; see
 * README.md "Batas keamanan dan kompatibilitas".
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

/* ---- identity ----------------------------------------------------------- */

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

/* Synthetic supplementary groups: the single group 0, matching getegid(). */
int getgroups(int size, gid_t list[])
{
    if (!fake_identity)
        return (int)syscall(SYS_getgroups, size, list);
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
        rc = (int)syscall(SYS_openat, dirfd, mapped, flags, mode);
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
                     : (int)syscall(SYS_newfstatat, dirfd, mapped, st, flags);
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
    int rc = next_fn ? next_fn(fd, st) : (int)syscall(SYS_fstat, fd, st);
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
                     : (int)syscall(SYS_statx, dirfd, mapped, flags, mask, buf);
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
                     : (int)syscall(SYS_faccessat, dirfd, mapped, mode, flags);
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
        rc = (int)syscall(SYS_faccessat2, dirfd, mapped, mode, flags);
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
    int rc = next_fn ? next_fn(mapped) : (int)syscall(SYS_chdir, mapped);
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
                     : (int)syscall(SYS_mkdirat, dirfd, mapped, mode);
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
                     : (int)syscall(SYS_unlinkat, dirfd, mapped, flags);
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
                     : (int)syscall(SYS_renameat, olddirfd, old_mapped, newdirfd, new_mapped);
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
        rc = (int)syscall(SYS_renameat2, olddirfd, old_mapped, newdirfd, new_mapped, flags);
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
                     : (int)syscall(SYS_linkat, olddirfd, old_mapped, newdirfd, new_mapped, flags);
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
                     : (int)syscall(SYS_symlinkat, target, newdirfd, mapped);
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
                         : (ssize_t)syscall(SYS_readlinkat, dirfd, mapped, buf, bufsiz);
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
                     : (int)syscall(SYS_fchmodat, dirfd, mapped, mode, flags);
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
                     : (int)syscall(SYS_truncate, mapped, length);
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
                     : (int)syscall(SYS_utimensat, dirfd, target, times, flags);
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
                         : (ssize_t)syscall(SYS_getxattr, mapped, name, value, size);
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
                         : (ssize_t)syscall(SYS_lgetxattr, mapped, name, value, size);
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
                     : (int)syscall(SYS_setxattr, mapped, name, value, size, flags);
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
                     : (int)syscall(SYS_lsetxattr, mapped, name, value, size, flags);
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
                     : (int)syscall(SYS_removexattr, mapped, name);
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
                     : (int)syscall(SYS_lremovexattr, mapped, name);
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
                         : (ssize_t)syscall(SYS_listxattr, mapped, list, size);
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
                         : (ssize_t)syscall(SYS_llistxattr, mapped, list, size);
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
                     : (int)syscall(SYS_fchownat, AT_FDCWD, mapped, owner, group, 0);
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
                     : (int)syscall(SYS_fchownat, AT_FDCWD, mapped, owner, group, AT_SYMLINK_NOFOLLOW);
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
    int rc = next_fn ? next_fn(dirfd, mapped, owner, group, flags)
                     : (int)syscall(SYS_fchownat, dirfd, mapped, owner, group, flags);
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
        return (int)syscall(SYS_chroot, path);

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
    if (syscall(SYS_newfstatat, AT_FDCWD, resolved, &st, 0) != 0)
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
    int rc = next_chdir ? next_chdir(resolved) : (int)syscall(SYS_chdir, resolved);
    if (rc != 0)
        return -1;

    memcpy(root_dir, resolved, n + 1);
    root_len = n;
    return 0;
}
