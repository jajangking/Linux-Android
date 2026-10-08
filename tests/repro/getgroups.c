/*
 * Repro/regression: under rootbox, getegid() is faked to 0, so getgroups()
 * must list group 0 as well.
 * Exit codes:
 *   0 = consistent (group 0 listed, or identity not faked)
 *   2 = regression: egid == 0 but getgroups() count == 0 (old bug)
 *   4 = getgroups() failed (e.g. seccomp supervisor could not write the list)
 *   5 = egid == 0 but group 0 missing from the list
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    gid_t groups[64];
    int n = getgroups(64, groups);
    gid_t egid = getegid();
    if (n < 0) {
        printf("getgroups failed: %s\n", strerror(errno));
        return 4;
    }
    printf("getgroups n=%d", n);
    for (int i = 0; i < n; i++)
        printf(" %u", (unsigned)groups[i]);
    printf("\negid=%u\n", (unsigned)egid);

    if (egid != 0)
        return 0;
    if (n == 0)
        return 2;
    for (int i = 0; i < n; i++)
        if (groups[i] == 0)
            return 0;
    return 5;
}
