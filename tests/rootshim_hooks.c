/*
 * Regression probe for librootshim.so hooks. Build with _FORTIFY_SOURCE=2 so
 * the compiler emits __open_2/__openat_2 for constant-flag open() calls, as
 * GNU coreutils and other fortified binaries do.
 *
 * Run with ROOTSHIM_ROOT=<rootfs containing etc/marker>, ROOTSHIM_FAKE_ID=1
 * and LD_PRELOAD=librootshim.so. Every operation must land inside the rootfs.
 * Prints one line per check; exit status is the number of failed checks.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, name)                                              \
    do {                                                               \
        if (cond) {                                                    \
            printf("ok    %s\n", name);                                \
        } else {                                                       \
            printf("FAIL  %s (errno=%s)\n", name, strerror(errno));    \
            failures++;                                                \
        }                                                              \
    } while (0)

#define DIR_V "/rsh-d"

int main(void)
{
    char buf[256];
    struct stat st;
    int fake = getenv("ROOTSHIM_FAKE_ID") != NULL;
    int fd;

    /* Fortify paths: fortified open()/openat() only fall back to the
       __open_2/__openat_2 entry points when the flags are NOT compile-time
       constants. The volatile flag forces that path. */
    volatile int rdonly = O_RDONLY;
    fd = open("/etc/marker", rdonly);
    CHECK(fd >= 0, "open(flags runtime) via __open_2");
    if (fd >= 0)
        close(fd);
    fd = openat(AT_FDCWD, "/etc/marker", rdonly);
    CHECK(fd >= 0, "openat(flags runtime) via __openat_2");
    if (fd >= 0)
        close(fd);

    CHECK(mkdirat(AT_FDCWD, DIR_V, 0755) == 0, "mkdirat");
    CHECK(mkdir(DIR_V "/sub", 0755) == 0, "mkdir");
    CHECK(rmdir(DIR_V "/sub") == 0, "rmdir");

    fd = openat(AT_FDCWD, DIR_V "/f", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK(fd >= 0, "openat(O_CREAT, mode)");
    if (fd >= 0) {
        CHECK(write(fd, "x\n", 2) == 2, "write to created file");
        close(fd);
    }

    CHECK(symlinkat("f", AT_FDCWD, DIR_V "/l") == 0, "symlinkat");
    CHECK(symlink("f", DIR_V "/l2") == 0, "symlink");
    CHECK(readlinkat(AT_FDCWD, DIR_V "/l", buf, sizeof buf - 1) == 1 && buf[0] == 'f',
          "readlinkat");
    CHECK(readlink(DIR_V "/l2", buf, sizeof buf - 1) == 1, "readlink");
    CHECK(unlink(DIR_V "/l2") == 0, "unlink");

    CHECK(linkat(AT_FDCWD, DIR_V "/f", AT_FDCWD, DIR_V "/h", 0) == 0, "linkat");
    CHECK(link(DIR_V "/h", DIR_V "/h1") == 0, "link");
    CHECK(renameat(AT_FDCWD, DIR_V "/h", AT_FDCWD, DIR_V "/h2") == 0, "renameat");
    CHECK(rename(DIR_V "/h2", DIR_V "/h3") == 0, "rename");
    CHECK(unlinkat(AT_FDCWD, DIR_V "/h3", 0) == 0, "unlinkat");
    CHECK(unlink(DIR_V "/h1") == 0, "unlink (hard link)");

#if defined(__GLIBC__)
    CHECK(renameat2(AT_FDCWD, DIR_V "/f", AT_FDCWD, DIR_V "/f", 0) == 0, "renameat2");
#endif

    CHECK(faccessat(AT_FDCWD, DIR_V "/f", F_OK, 0) == 0, "faccessat");
    CHECK(access(DIR_V "/f", R_OK) == 0, "access");

    CHECK(fchmodat(AT_FDCWD, DIR_V "/f", 0600, 0) == 0, "fchmodat");
    CHECK(chmod(DIR_V "/f", 0640) == 0, "chmod");
    CHECK(truncate(DIR_V "/f", 0) == 0, "truncate");
    CHECK(utimensat(AT_FDCWD, DIR_V "/f", NULL, 0) == 0, "utimensat(path)");

    CHECK(stat(DIR_V "/f", &st) == 0, "stat");
    CHECK(lstat(DIR_V "/l", &st) == 0 && S_ISLNK(st.st_mode), "lstat (symlink itself)");
    CHECK(fstatat(AT_FDCWD, DIR_V "/f", &st, 0) == 0, "fstatat");
    if (fake)
        CHECK(st.st_uid == 0 && st.st_gid == 0, "stat reports synthetic owner");

#if defined(__GLIBC__)
    {
        struct statx sx;
        CHECK(statx(AT_FDCWD, DIR_V "/f", 0, STATX_BASIC_STATS, &sx) == 0, "statx");
        if (fake)
            CHECK(sx.stx_uid == 0 && sx.stx_gid == 0, "statx reports synthetic owner");
    }
#endif

    if (setxattr(DIR_V "/f", "user.rsh", "v", 1, 0) == 0) {
        CHECK(getxattr(DIR_V "/f", "user.rsh", buf, sizeof buf) == 1, "getxattr");
        CHECK(listxattr(DIR_V "/f", buf, sizeof buf) > 0, "listxattr");
        CHECK(removexattr(DIR_V "/f", "user.rsh") == 0, "removexattr");
    } else if (errno == ENOTSUP) {
        printf("skip  xattr checks (filesystem without user xattrs)\n");
    } else {
        CHECK(0, "setxattr");
    }

    if (fake) {
        gid_t groups[8];
        int n = getgroups(8, groups);
        CHECK(getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0,
              "synthetic uid/gid are 0");
        CHECK(n == 1 && groups[0] == 0, "getgroups lists synthetic group 0");
    }

    /* '..' is clamped at the virtual root. */
    fd = open("/../../etc/marker", O_RDONLY);
    CHECK(fd >= 0, "'..' clamped at virtual root");
    if (fd >= 0)
        close(fd);

    /* Failed chroot() to a regular file must leave the virtual root intact. */
    errno = 0;
    CHECK(chroot(DIR_V "/f") == -1 && errno == ENOTDIR, "chroot(file) fails ENOTDIR");
    fd = open("/etc/marker", O_RDONLY);
    CHECK(fd >= 0, "virtual root intact after failed chroot");
    if (fd >= 0)
        close(fd);

    /* Successful chroot() to a directory narrows the virtual root. */
    CHECK(chroot(DIR_V) == 0, "chroot(dir)");
    CHECK(access("/f", F_OK) == 0, "virtual path visible after chroot(dir)");
    fd = open("/etc/marker", O_RDONLY);
    CHECK(fd < 0 && errno == ENOENT, "outer rootfs path hidden after chroot(dir)");
    if (fd >= 0)
        close(fd);

    printf("summary failures=%d\n", failures);
    return failures > 255 ? 255 : failures;
}
