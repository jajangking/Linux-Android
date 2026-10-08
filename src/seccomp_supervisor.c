#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID _IOW('!', 2, uint64_t)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR('!', 0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR('!', 1, struct seccomp_notif_resp)
#endif

#if defined(__aarch64__)
#define ROOTBOX_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define ROOTBOX_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__arm__)
#define ROOTBOX_AUDIT_ARCH AUDIT_ARCH_ARM
#else
#error "rootbox currently supports AArch64, ARM32, and x86_64"
#endif

typedef struct {
    int status;
    int error;
} child_status_t;

static int send_listener(int sock, int listener, int error)
{
    child_status_t status = { .status = listener >= 0 ? 0 : -1, .error = error };
    struct iovec iov = { .iov_base = &status, .iov_len = sizeof(status) };
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (listener >= 0) {
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &listener, sizeof(listener));
        msg.msg_controllen = CMSG_SPACE(sizeof(int));
    }
    return sendmsg(sock, &msg, 0) == (ssize_t)sizeof(status) ? 0 : -1;
}

static int receive_listener(int sock, child_status_t *status)
{
    struct iovec iov = { .iov_base = status, .iov_len = sizeof(*status) };
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t n = recvmsg(sock, &msg, 0);
    if (n != (ssize_t)sizeof(*status)) {
        if (n >= 0)
            errno = EPROTO;
        return -1;
    }
    if (status->status != 0)
        return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        errno = EPROTO;
        return -1;
    }
    int listener;
    memcpy(&listener, CMSG_DATA(cmsg), sizeof(listener));
    return listener;
}

static int install_identity_filter(void)
{
    struct sock_filter filter[32];
    size_t n = 0;
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                offsetof(struct seccomp_data, arch));
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                ROOTBOX_AUDIT_ARCH, 1, 0);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                offsetof(struct seccomp_data, nr));

#define WATCH_SYSCALL(nr) do { \
    filter[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1); \
    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF); \
} while (0)
#ifdef SYS_getuid
    WATCH_SYSCALL(SYS_getuid);
#endif
#ifdef SYS_geteuid
    WATCH_SYSCALL(SYS_geteuid);
#endif
#ifdef SYS_getgid
    WATCH_SYSCALL(SYS_getgid);
#endif
#ifdef SYS_getegid
    WATCH_SYSCALL(SYS_getegid);
#endif
#ifdef SYS_getgroups
    WATCH_SYSCALL(SYS_getgroups);
#endif
#undef WATCH_SYSCALL

    filter[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog prog = { .len = (unsigned short)n, .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
#ifdef SYS_seccomp
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int is_identity_query(int syscall_nr)
{
#ifdef SYS_getuid
    if (syscall_nr == SYS_getuid) return 1;
#endif
#ifdef SYS_geteuid
    if (syscall_nr == SYS_geteuid) return 1;
#endif
#ifdef SYS_getgid
    if (syscall_nr == SYS_getgid) return 1;
#endif
#ifdef SYS_getegid
    if (syscall_nr == SYS_getegid) return 1;
#endif
#ifdef SYS_getgroups
    if (syscall_nr == SYS_getgroups) return 1;
#endif
    return 0;
}

/* Is the notification still for a live, unchanged request? Guards against
   the tracee having exited and its pid having been reused. */
static int notification_still_valid(int listener, uint64_t id)
{
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}

/* Write one gid_t (0) into the tracee's memory at addr. */
static int write_gid_zero(pid_t pid, unsigned long addr)
{
    gid_t gid = 0;
    struct iovec local = { .iov_base = &gid, .iov_len = sizeof(gid) };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = sizeof(gid) };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return n == (ssize_t)sizeof(gid) ? 0 : -1;
}

static void answer_getgroups(int listener, const struct seccomp_notif *request,
                             struct seccomp_notif_resp *response)
{
    /* getgroups(int size, gid_t *list): size==0 queries the count only.
       The synthetic set is exactly {0}, matching the faked getegid(). */
    int size = (int)request->data.args[0];
    unsigned long list = (unsigned long)request->data.args[1];
    if (size < 0) {
        response->error = -EINVAL;
    } else if (size == 0) {
        response->val = 1;
    } else if (!list) {
        response->error = -EFAULT;
    } else if (!notification_still_valid(listener, request->id)) {
        response->error = -ENOENT;
    } else if (write_gid_zero(request->pid, list) != 0) {
        /* process_vm_writev denied (ptrace policy). Report an error rather
           than leave an uninitialised list behind. */
        response->error = -EPERM;
    } else if (!notification_still_valid(listener, request->id)) {
        response->error = -ENOENT;
    } else {
        response->val = 1;
    }
}

static int respond_to_notification(int listener)
{
    struct seccomp_notif request;
    struct seccomp_notif_resp response;
    memset(&request, 0, sizeof(request));
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) != 0)
        return -1;
    memset(&response, 0, sizeof(response));
    response.id = request.id;
    if (request.data.nr == SYS_getgroups) {
        answer_getgroups(listener, &request, &response);
    } else if (is_identity_query(request.data.nr)) {
        /* This changes only the return value observed by the child. The child
           retains its real Android UID and receives no kernel capabilities. */
        response.val = 0;
        response.error = 0;
    } else {
        response.error = -ENOSYS;
    }
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response);
}

static int supervise(int listener, pid_t child)
{
    struct pollfd pfd = { .fd = listener, .events = POLLIN };
    int child_status = 0;
    for (;;) {
        int ready = poll(&pfd, 1, 250);
        if (ready < 0 && errno != EINTR) {
            perror("rootbox: poll");
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
            return 125;
        }
        if (ready > 0 && (pfd.revents & (POLLHUP | POLLERR)) && !(pfd.revents & POLLIN)) {
            /* No task still holds the filter: the child has exited. Reap it
               instead of spinning on the hung-up listener. */
            if (waitpid(child, &child_status, 0) < 0) {
                perror("rootbox: waitpid");
                return 125;
            }
            break;
        }
        if (ready > 0 && (pfd.revents & POLLIN)) {
            if (respond_to_notification(listener) != 0 && errno != ENOENT && errno != EINTR) {
                perror("rootbox: seccomp notification");
                kill(child, SIGKILL);
                waitpid(child, NULL, 0);
                return 125;
            }
        }
        pid_t result = waitpid(child, &child_status, WNOHANG);
        if (result == child)
            break;
        if (result < 0 && errno != EINTR) {
            perror("rootbox: waitpid");
            return 125;
        }
    }
    if (WIFEXITED(child_status))
        return WEXITSTATUS(child_status);
    if (WIFSIGNALED(child_status))
        return 128 + WTERMSIG(child_status);
    return 125;
}

static void usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s -- command [args...]\n", argv0);
    fprintf(stderr, "Runs a child with a seccomp user-notification supervisor that\n");
    fprintf(stderr, "fakes getuid/geteuid/getgid/getegid/getgroups return values only.\n");
}

int main(int argc, char **argv)
{
    int command_index = 1;
    if (command_index < argc && strcmp(argv[command_index], "--") == 0)
        ++command_index;
    if (command_index >= argc) {
        usage(argv[0]);
        return 2;
    }

    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel) != 0) {
        perror("rootbox: socketpair");
        return 125;
    }
    pid_t child = fork();
    if (child < 0) {
        perror("rootbox: fork");
        close(channel[0]);
        close(channel[1]);
        return 125;
    }
    if (child == 0) {
        close(channel[0]);
        const char *child_preload = getenv("ROOTBOX_LD_PRELOAD");
        const char *child_library_path = getenv("ROOTBOX_LD_LIBRARY_PATH");
        if (child_preload && setenv("LD_PRELOAD", child_preload, 1) != 0) {
            dprintf(STDERR_FILENO, "rootbox: set LD_PRELOAD: %s\n", strerror(errno));
            _exit(125);
        }
        if (child_library_path && setenv("LD_LIBRARY_PATH", child_library_path, 1) != 0) {
            dprintf(STDERR_FILENO, "rootbox: set LD_LIBRARY_PATH: %s\n", strerror(errno));
            _exit(125);
        }
        int listener = install_identity_filter();
        if (listener < 0) {
            int saved = errno;
            (void)send_listener(channel[1], -1, saved);
            dprintf(STDERR_FILENO, "rootbox: seccomp user notification unavailable: %s\n", strerror(saved));
            _exit(125);
        }
        if (send_listener(channel[1], listener, 0) != 0) {
            dprintf(STDERR_FILENO, "rootbox: could not pass seccomp listener: %s\n", strerror(errno));
            _exit(125);
        }
        close(listener);
        close(channel[1]);
        execvp(argv[command_index], &argv[command_index]);
        dprintf(STDERR_FILENO, "rootbox: exec %s: %s\n", argv[command_index], strerror(errno));
        _exit(errno == ENOENT ? 127 : 126);
    }

    close(channel[1]);
    child_status_t status = {0};
    int listener = receive_listener(channel[0], &status);
    close(channel[0]);
    if (listener < 0) {
        int saved = status.error ? status.error : errno;
        int ignored;
        (void)waitpid(child, &ignored, 0);
        if (saved)
            fprintf(stderr, "rootbox: cannot start seccomp supervisor: %s\n", strerror(saved));
        return 125;
    }
    int rc = supervise(listener, child);
    close(listener);
    return rc;
}
