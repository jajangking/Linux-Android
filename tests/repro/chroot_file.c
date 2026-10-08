/*
 * Repro: a failed synthetic chroot() must not change the virtual root.
 * Run with ROOTSHIM_ROOT=<dir containing afile and etc/marker>, LD_PRELOAD=librootshim.so.
 * Exit codes:
 *   0 = fixed (chroot failed AND /etc/marker still readable)
 *   2 = known bug reproduced (chroot failed AND /etc/marker no longer readable)
 *   3 = unexpected (chroot to a regular file succeeded)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    int rc = chroot("/afile");
    int saved = errno;
    printf("chroot(/afile) rc=%d errno=%s\n", rc, rc ? strerror(saved) : "ok");
    if (rc == 0)
        return 3;

    int fd = open("/etc/marker", O_RDONLY);
    printf("open(/etc/marker) after failed chroot: fd=%d errno=%s\n",
           fd, fd < 0 ? strerror(errno) : "ok");
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return 2;
}
