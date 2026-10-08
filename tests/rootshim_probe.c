#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    char cwd[4096];
    if (chdir("/") != 0) {
        perror("chdir(/)");
        return 1;
    }
    if (!getcwd(cwd, sizeof(cwd))) {
        perror("getcwd");
        return 1;
    }

    FILE *file = fopen("/etc/rootshim-marker", "r");
    if (!file) {
        perror("fopen(/etc/rootshim-marker)");
        return 1;
    }
    char marker[128] = {0};
    if (!fgets(marker, sizeof(marker), file)) {
        perror("fgets");
        fclose(file);
        return 1;
    }
    fclose(file);

    struct stat st;
    if (stat("/etc/rootshim-marker", &st) != 0) {
        perror("stat(/etc/rootshim-marker)");
        return 1;
    }

    printf("cwd=%s uid=%lu gid=%lu st_uid=%lu marker=%s",
           cwd,
           (unsigned long)getuid(),
           (unsigned long)getgid(),
           (unsigned long)st.st_uid,
           marker);
    return 0;
}
