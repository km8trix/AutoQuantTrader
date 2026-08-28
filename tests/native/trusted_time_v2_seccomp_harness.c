#define _GNU_SOURCE

#include "trusted_time_v2_seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int
aqt_expect_eperm(long result)
{
    return result == -1L && errno == EPERM ? 0 : (errno == 0 ? 20 : 20 + errno);
}

static int
aqt_expect_not_eperm(long result)
{
    return result == -1L && errno == EPERM ? 1 : 0;
}

static int
aqt_raw_eperm(long number, long a0, long a1, long a2, long a3, long a4)
{
    long result;

    errno = 0;
    result = syscall(number, a0, a1, a2, a3, a4);
    return aqt_expect_eperm(result);
}

static int
aqt_probe_dangerous_surface(void)
{
    int failed = 0;

#ifdef __NR_io_uring_setup
    failed |= aqt_raw_eperm(__NR_io_uring_setup, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_io_uring_register
    failed |= aqt_raw_eperm(__NR_io_uring_register, -1L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_io_uring_enter
    failed |= aqt_raw_eperm(__NR_io_uring_enter, -1L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_bpf
    failed |= aqt_raw_eperm(__NR_bpf, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_ptrace
    failed |= aqt_raw_eperm(__NR_ptrace, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_process_vm_readv
    failed |= aqt_raw_eperm(__NR_process_vm_readv, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_process_vm_writev
    failed |= aqt_raw_eperm(__NR_process_vm_writev, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_userfaultfd
    failed |= aqt_raw_eperm(__NR_userfaultfd, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_perf_event_open
    failed |= aqt_raw_eperm(__NR_perf_event_open, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_keyctl
    failed |= aqt_raw_eperm(__NR_keyctl, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_add_key
    failed |= aqt_raw_eperm(__NR_add_key, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_request_key
    failed |= aqt_raw_eperm(__NR_request_key, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_mount
    failed |= aqt_raw_eperm(__NR_mount, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_umount2
    failed |= aqt_raw_eperm(__NR_umount2, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_pivot_root
    failed |= aqt_raw_eperm(__NR_pivot_root, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_chroot
    failed |= aqt_raw_eperm(__NR_chroot, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_open_by_handle_at
    failed |= aqt_raw_eperm(__NR_open_by_handle_at, -1L, 0L, 0L, 0L, 0L);
#endif
    return failed;
}

static int
aqt_probe_process_surface(void)
{
    char *arguments[] = {(char *)"missing", NULL};
    char *environment[] = {NULL};
    int failed = 0;

#ifdef __NR_fork
    failed |= aqt_raw_eperm(__NR_fork, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_vfork
    failed |= aqt_raw_eperm(__NR_vfork, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_clone
    failed |= aqt_raw_eperm(__NR_clone, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_clone3
    failed |= aqt_raw_eperm(__NR_clone3, 0L, 0L, 0L, 0L, 0L);
#endif
    errno = 0;
    failed |= aqt_expect_eperm(
        syscall(__NR_execve, "/definitely-absent", arguments, environment)
    );
#ifdef __NR_execveat
    failed |= aqt_raw_eperm(__NR_execveat, -1L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_unshare
    failed |= aqt_raw_eperm(__NR_unshare, 0L, 0L, 0L, 0L, 0L);
#endif
#ifdef __NR_setns
    failed |= aqt_raw_eperm(__NR_setns, -1L, 0L, 0L, 0L, 0L);
#endif
    return failed;
}

static int
aqt_probe_socket_surface(void)
{
    struct msghdr message;
    int descriptor;
    int pair[2];
    int failed = 0;
    int value = 0;
    socklen_t value_size = (socklen_t)sizeof(value);

    memset(&message, 0, sizeof(message));
    errno = 0;
    descriptor = socket(
        AF_UNIX,
        SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
        0
    );
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
    if (descriptor < 0 || close(descriptor) != 0) {
        failed = 1;
    }
#else
    failed |= aqt_expect_eperm((long)descriptor);
#endif
    errno = 0;
    failed |= aqt_expect_eperm(
        (long)socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0)
    );
    errno = 0;
    failed |= aqt_expect_eperm((long)socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    errno = 0;
    failed |= aqt_expect_eperm((long)socketpair(AF_UNIX, SOCK_STREAM, 0, pair));

    errno = 0;
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
    failed |= aqt_expect_not_eperm((long)connect(-1, NULL, 0));
#else
    failed |= aqt_expect_eperm((long)connect(-1, NULL, 0));
#endif
    errno = 0;
#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
    failed |= aqt_expect_not_eperm((long)bind(-1, NULL, 0));
    errno = 0;
    failed |= aqt_expect_not_eperm((long)listen(-1, 1));
    errno = 0;
    failed |= aqt_expect_not_eperm(
        (long)accept4(-1, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK)
    );
    errno = 0;
    failed |= aqt_expect_eperm((long)listen(-1, 2));
    errno = 0;
    failed |= aqt_expect_eperm((long)accept4(-1, NULL, NULL, SOCK_CLOEXEC));
#else
    failed |= aqt_expect_eperm((long)bind(-1, NULL, 0));
    errno = 0;
    failed |= aqt_expect_eperm((long)listen(-1, 1));
    errno = 0;
    failed |= aqt_expect_eperm(
        (long)accept4(-1, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK)
    );
#endif

    errno = 0;
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
    failed |= aqt_expect_not_eperm(
        (long)sendmsg(-1, &message, MSG_DONTWAIT | MSG_NOSIGNAL)
    );
    errno = 0;
    failed |= aqt_expect_not_eperm(
        (long)recvmsg(-1, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
    );
    errno = 0;
    failed |= aqt_expect_not_eperm(
        (long)getsockopt(-1, SOL_SOCKET, SO_TYPE, &value, &value_size)
    );
    errno = 0;
    failed |= aqt_expect_not_eperm((long)getsockname(-1, NULL, NULL));
    errno = 0;
    failed |= aqt_expect_not_eperm((long)shutdown(-1, SHUT_RDWR));
#else
    failed |= aqt_expect_eperm(
        (long)sendmsg(-1, &message, MSG_DONTWAIT | MSG_NOSIGNAL)
    );
    errno = 0;
    failed |= aqt_expect_eperm(
        (long)recvmsg(-1, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
    );
    errno = 0;
    failed |= aqt_expect_eperm(
        (long)getsockopt(-1, SOL_SOCKET, SO_TYPE, &value, &value_size)
    );
    errno = 0;
    failed |= aqt_expect_eperm((long)getsockname(-1, NULL, NULL));
    errno = 0;
    failed |= aqt_expect_eperm((long)shutdown(-1, SHUT_RDWR));
#endif
    errno = 0;
    failed |= aqt_expect_eperm((long)sendmsg(-1, &message, 0));
    errno = 0;
    failed |= aqt_expect_eperm((long)recvmsg(-1, &message, 0));
    errno = 0;
    failed |= aqt_expect_eperm(
        (long)getsockopt(-1, SOL_SOCKET, SO_BROADCAST, &value, &value_size)
    );
    return failed;
}

static int
aqt_probe_argument_filters(void)
{
    int failed = 0;

    errno = 0;
    failed |= aqt_expect_eperm(
        (long)openat(AT_FDCWD, "/tmp/aqt-seccomp-forbidden", O_WRONLY | O_CREAT, 0600)
    );
    errno = 0;
    failed |= aqt_expect_eperm((long)fcntl(STDIN_FILENO, F_DUPFD, 80));
    errno = 0;
    failed |= aqt_expect_eperm((long)ioctl(STDIN_FILENO, TIOCGWINSZ, NULL));
    errno = 0;
    failed |= aqt_expect_eperm((long)write(99, "x", 1U));
#if !defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
    errno = 0;
    failed |= aqt_expect_eperm(
        (long)(intptr_t)mmap(
            NULL,
            4096U,
            PROT_READ | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        )
    );
#endif
    return failed;
}

static _Atomic int aqt_tsync_ready = 0;
static _Atomic int aqt_tsync_go = 0;
static _Atomic int aqt_tsync_result = 1;

static void *
aqt_tsync_thread(void *unused)
{
    (void)unused;
    atomic_store_explicit(&aqt_tsync_ready, 1, memory_order_release);
    while (atomic_load_explicit(&aqt_tsync_go, memory_order_acquire) == 0) {
    }
    errno = 0;
    atomic_store_explicit(
        &aqt_tsync_result,
        aqt_expect_eperm(syscall(0x1fffffffL)),
        memory_order_release
    );
    return NULL;
}

static int
aqt_run_tsync_probe(void)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, aqt_tsync_thread, NULL) != 0) {
        return 1;
    }
    while (atomic_load_explicit(&aqt_tsync_ready, memory_order_acquire) == 0) {
    }
    if (aqt_trusted_time_v2_seccomp_install_initial()
        != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
        return 1;
    }
    atomic_store_explicit(&aqt_tsync_go, 1, memory_order_release);
    if (pthread_join(thread, NULL) != 0) {
        return 1;
    }
    return atomic_load_explicit(&aqt_tsync_result, memory_order_acquire);
}

int
main(int argument_count, char **argument_values)
{
    const char *mode;
    long result;

    (void)aqt_expect_not_eperm;

    if (argument_count != 2 || argument_values == NULL
        || argument_values[1] == NULL) {
        return 2;
    }
    mode = argument_values[1];
    if (strcmp(mode, "tsync") == 0) {
        return aqt_run_tsync_probe();
    }
    if (aqt_trusted_time_v2_seccomp_install_initial()
        != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
        return 3;
    }
    if (strcmp(mode, "post-child") == 0) {
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
        if (aqt_trusted_time_v2_seccomp_install_post_child()
            != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
            return 4;
        }
        errno = 0;
        if (aqt_expect_eperm(syscall(__NR_clone, 0L, 0L, 0L, 0L, 0L)) != 0) {
            return 5;
        }
        errno = 0;
        return aqt_expect_eperm(
            (long)openat(AT_FDCWD, "/etc/passwd", O_RDONLY | O_CLOEXEC)
        );
#else
        return 6;
#endif
    }
    if (strcmp(mode, "child-filter") == 0) {
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
        if (aqt_trusted_time_v2_seccomp_install_child_exec()
            != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
            return 7;
        }
        return aqt_probe_process_surface();
#else
        return 8;
#endif
    }
    if (strcmp(mode, "allowed") == 0) {
        result = syscall(__NR_getpid);
        return result == (long)getpid() ? 0 : 9;
    }
    if (strcmp(mode, "unknown") == 0) {
        errno = 0;
        return aqt_expect_eperm(syscall(0x1fffffffL));
    }
    if (strcmp(mode, "dangerous") == 0) {
        return aqt_probe_dangerous_surface();
    }
    if (strcmp(mode, "process") == 0) {
        return aqt_probe_process_surface();
    }
    if (strcmp(mode, "socket") == 0) {
        return aqt_probe_socket_surface();
    }
    if (strcmp(mode, "arguments") == 0) {
        return aqt_probe_argument_filters();
    }
    if (strcmp(mode, "x32") == 0) {
#if defined(__x86_64__)
        (void)syscall(__NR_getpid | 0x40000000U);
        return 10;
#else
        return 77;
#endif
    }
    return 11;
}
