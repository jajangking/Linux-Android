/*
 * Repro: under rootbox, getegid() is faked to 0, so getgroups() should list
 * group 0 as well. Known bug: getgroups() reports 0 groups.
 * Exit codes:
 *   0 = consistent (or not faked: egid != 0)
 *   2 = known bug reproduced (egid == 0 but getgroups() count == 0)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    gid_t groups[64];
    int n = getgroups(64, groups);
    gid_t egid = getegid();
    printf("getgroups n=%d", n);
    for (int i = 0; i < n; i++)
        printf(" %u", (unsigned)groups[i]);
    printf("\negid=%u\n", (unsigned)egid);
    return (egid == 0 && n == 0) ? 2 : 0;
}
