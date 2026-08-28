#define _GNU_SOURCE

#include "trusted_time_v2_seccomp.h"

#include <stddef.h>

#if (defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)) != 1
#error "Exactly one trusted-time lifecycle-v2 seccomp profile must be selected."
#endif

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)
#define AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE 1
#endif

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
#define AQT_SECCOMP_PROFILE_NAME "host"
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
#define AQT_SECCOMP_PROFILE_NAME "supervisor"
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
#define AQT_SECCOMP_PROFILE_NAME "recovery"
#else
#define AQT_SECCOMP_PROFILE_NAME "provisioner"
#endif

const char *
aqt_trusted_time_v2_seccomp_profile_name(void)
{
    return AQT_SECCOMP_PROFILE_NAME;
}

const char *
aqt_trusted_time_v2_seccomp_policy_model(void)
{
    return "ordered-default-deny-allowlist-v1";
}

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define AQT_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AQT_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "The trusted-time lifecycle-v2 seccomp profile supports only x86_64 and aarch64."
#endif

#ifndef SECCOMP_FILTER_FLAG_TSYNC
#error "The trusted-time lifecycle-v2 seccomp profile requires TSYNC support."
#endif
#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000U
#endif
#ifndef SO_PEERCRED
#define SO_PEERCRED 17
#endif
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

#if defined(__x86_64__)
#define AQT_CLONE_TLS_ARGUMENT args[4]
#else
#define AQT_CLONE_TLS_ARGUMENT args[3]
#endif

#define AQT_SYSTEMD_CREDS_FD ((unsigned int)AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_FD)
#define AQT_NULL_INPUT_FD ((unsigned int)AQT_TRUSTED_TIME_V2_NULL_INPUT_FD)
#define AQT_SECRET_OUTPUT_FD ((unsigned int)AQT_TRUSTED_TIME_V2_SECRET_OUTPUT_FD)
#define AQT_FORK_CLONE_FLAGS \
    ((unsigned int)(CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD))
#define AQT_OPENAT_WRITE_BITS \
    ((unsigned int)(O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND | 020000000))
#define AQT_TARGET_CREATE_FLAGS \
    ((unsigned int)(O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL))

#define AQT_ALLOW_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define AQT_ERRNO_RESULT \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

#if defined(__x86_64__)
#define AQT_X32_REJECTION \
    , BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, __X32_SYSCALL_BIT, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
#else
#define AQT_X32_REJECTION
#endif

#define AQT_FILTER_PREFIX \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_AUDIT_ARCH, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)) \
    AQT_X32_REJECTION

#define AQT_FILTER_SUFFIX AQT_ERRNO_RESULT

#define AQT_STDIO_WRITE_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDOUT_FILENO, 1, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDERR_FILENO, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_READ_ONLY_OPENAT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, AQT_OPENAT_WRITE_BITS, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_PROVISIONER_OPENAT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 8), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, AQT_OPENAT_WRITE_BITS, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_TARGET_CREATE_FLAGS, 0, 3), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0600U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_NONEXECUTABLE_MMAP_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_NONEXECUTABLE_MPROTECT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_FCNTL_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fcntl, 0, 9), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_GETFD, 5, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_GETFL, 4, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, F_SETFD, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FD_CLOEXEC, 1, 0), \
    AQT_ERRNO_RESULT, \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_TCGETS_IOCTL_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCGETS, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_ENDPOINT_IOCTL_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCGETS, 1, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONREAD, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_MESSAGE_FLAGS_RULE(number, required_flags) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (required_flags), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_UNIX_SEQPACKET_SOCKET_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 8), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 6), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP( \
        BPF_JMP | BPF_JEQ | BPF_K, \
        SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, \
        0, \
        3 \
    ), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_HOST_GETSOCKOPT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockopt, 0, 11), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOL_SOCKET, 0, 8), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_TYPE, 5, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_PEERCRED, 4, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_ERROR, 3, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_COOKIE, 2, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_SNDBUF, 1, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_RCVBUF, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_SUPERVISOR_GETSOCKOPT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getsockopt, 0, 10), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOL_SOCKET, 0, 7), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_TYPE, 4, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_PEERCRED, 3, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_COOKIE, 2, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_SNDBUF, 1, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_RCVBUF, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_ENDPOINT_SETSOCKOPT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setsockopt, 0, 11), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOL_SOCKET, 0, 8), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_SNDBUF, 1, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SO_RCVBUF, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sizeof(int), 0, 3), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_ACCEPT4_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_accept4, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])), \
    BPF_JUMP( \
        BPF_JMP | BPF_JEQ | BPF_K, \
        SOCK_CLOEXEC | SOCK_NONBLOCK, \
        0, \
        1 \
    ), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_LISTEN_ONE_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_EXACT_UMASK_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umask, 0, 6), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0177U, 0, 3), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_UNLINKAT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlinkat, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_PRCTL_NO_NEW_PRIVS_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 18), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_NO_NEW_PRIVS, 0, 15), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1U, 0, 13), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 11), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 9), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 7), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[3]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 3), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_SECCOMP_TSYNC_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_seccomp, 0, 10), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_SET_MODE_FILTER, 0, 7), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_FILTER_FLAG_TSYNC, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 2), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_EXACT_FORK_CLONE_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 16), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_FORK_CLONE_FLAGS, 0, 13), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 11), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 9), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 7), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2]) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, AQT_CLONE_TLS_ARGUMENT)), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 3), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, AQT_CLONE_TLS_ARGUMENT) + 4U), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_SIGKILL_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_kill, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGKILL, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_EXACT_EXECVEAT_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 6), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_SYSTEMD_CREDS_FD, 0, 3), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[4])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AT_EMPTY_PATH, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_DUP3_NORMALIZE_RULE \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_dup3, 0, 21), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, O_CLOEXEC, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_SYSTEMD_CREDS_FD, 15, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_NULL_INPUT_FD, 14, 0), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_SECRET_OUTPUT_FD, 13, 0), \
    AQT_ERRNO_RESULT, \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 0, 12), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_NULL_INPUT_FD, 0, 4), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDIN_FILENO, 7, 0), \
    AQT_ERRNO_RESULT, \
    AQT_ERRNO_RESULT, \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_SECRET_OUTPUT_FD, 0, 5), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, STDOUT_FILENO, 2, 0), \
    AQT_ERRNO_RESULT, \
    AQT_ERRNO_RESULT, \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), \
    AQT_ERRNO_RESULT

#define AQT_BASE_RUNTIME_ALLOWANCES \
    AQT_ALLOW_SYSCALL(__NR_read), \
    AQT_ALLOW_SYSCALL(__NR_close), \
    AQT_ALLOW_SYSCALL(__NR_lseek), \
    AQT_ALLOW_SYSCALL(__NR_munmap), \
    AQT_ALLOW_SYSCALL(__NR_brk), \
    AQT_ALLOW_SYSCALL(__NR_rt_sigaction), \
    AQT_ALLOW_SYSCALL(__NR_rt_sigprocmask), \
    AQT_ALLOW_SYSCALL(__NR_rt_sigreturn), \
    AQT_ALLOW_SYSCALL(__NR_pread64), \
    AQT_ALLOW_SYSCALL(__NR_madvise), \
    AQT_ALLOW_SYSCALL(__NR_geteuid), \
    AQT_ALLOW_SYSCALL(__NR_getpid), \
    AQT_ALLOW_SYSCALL(__NR_futex), \
    AQT_ALLOW_SYSCALL(__NR_clock_gettime), \
    AQT_ALLOW_SYSCALL(__NR_exit), \
    AQT_ALLOW_SYSCALL(__NR_exit_group), \
    AQT_ALLOW_SYSCALL(__NR_newfstatat), \
    AQT_ALLOW_SYSCALL(__NR_fstat), \
    AQT_ALLOW_SYSCALL(__NR_getdents64), \
    AQT_ALLOW_SYSCALL(__NR_getrandom), \
    AQT_ALLOW_SYSCALL(__NR_mlock), \
    AQT_ALLOW_SYSCALL(__NR_munlock), \
    AQT_ALLOW_SYSCALL(__NR_readlinkat), \
    AQT_ALLOW_SYSCALL(__NR_sysinfo)

_Static_assert(
    sizeof(struct sock_filter) == 8U,
    "manifest-bound classic BPF instructions must be exactly eight bytes"
);

static const struct sock_filter aqt_initial_filter[] = {
    AQT_FILTER_PREFIX,
    AQT_STDIO_WRITE_RULE,
#if defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    AQT_PROVISIONER_OPENAT_RULE,
#else
    AQT_READ_ONLY_OPENAT_RULE,
#endif
    AQT_FCNTL_RULE,
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
    AQT_ENDPOINT_IOCTL_RULE,
#else
    AQT_TCGETS_IOCTL_RULE,
#endif
#if !defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    AQT_NONEXECUTABLE_MMAP_RULE,
    AQT_NONEXECUTABLE_MPROTECT_RULE,
#else
    AQT_ALLOW_SYSCALL(__NR_mmap),
    AQT_ALLOW_SYSCALL(__NR_mprotect),
#endif
    AQT_BASE_RUNTIME_ALLOWANCES,
#ifdef __NR_faccessat2
    AQT_ALLOW_SYSCALL(__NR_faccessat2),
#endif
#ifdef __NR_gettid
    AQT_ALLOW_SYSCALL(__NR_gettid),
#endif
#ifdef __NR_prlimit64
    AQT_ALLOW_SYSCALL(__NR_prlimit64),
#endif
#ifdef __NR_rseq
    AQT_ALLOW_SYSCALL(__NR_rseq),
#endif
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
    AQT_UNIX_SEQPACKET_SOCKET_RULE,
    AQT_ENDPOINT_SETSOCKOPT_RULE,
    AQT_ALLOW_SYSCALL(__NR_ppoll),
    AQT_MESSAGE_FLAGS_RULE(__NR_sendmsg, MSG_DONTWAIT | MSG_NOSIGNAL),
    AQT_MESSAGE_FLAGS_RULE(__NR_recvmsg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC),
    AQT_UNLINKAT_RULE,
    AQT_ALLOW_SYSCALL(__NR_statfs),
    AQT_ALLOW_SYSCALL(__NR_fstatfs),
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
    AQT_HOST_GETSOCKOPT_RULE,
    AQT_ALLOW_SYSCALL(__NR_connect),
    AQT_ALLOW_SYSCALL(__NR_getsockname),
#else
    AQT_SUPERVISOR_GETSOCKOPT_RULE,
    AQT_ACCEPT4_RULE,
    AQT_LISTEN_ONE_RULE,
    AQT_ALLOW_SYSCALL(__NR_bind),
    AQT_ALLOW_SYSCALL(__NR_getsockname),
    AQT_EXACT_UMASK_RULE,
#endif
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
    AQT_UNLINKAT_RULE,
#else
    AQT_DUP3_NORMALIZE_RULE,
    AQT_EXACT_FORK_CLONE_RULE,
    AQT_SIGKILL_RULE,
    AQT_EXACT_EXECVEAT_RULE,
    AQT_PRCTL_NO_NEW_PRIVS_RULE,
    AQT_SECCOMP_TSYNC_RULE,
    AQT_ALLOW_SYSCALL(__NR_wait4),
    AQT_ALLOW_SYSCALL(__NR_nanosleep),
    AQT_UNLINKAT_RULE,
    AQT_ALLOW_SYSCALL(__NR_fchmod),
    AQT_ALLOW_SYSCALL(__NR_fchown),
    AQT_ALLOW_SYSCALL(__NR_statfs),
    AQT_ALLOW_SYSCALL(__NR_fstatfs),
    AQT_ALLOW_SYSCALL(__NR_getuid),
    AQT_ALLOW_SYSCALL(__NR_getgid),
    AQT_ALLOW_SYSCALL(__NR_getegid),
#endif
    AQT_FILTER_SUFFIX,
};

#if defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
static const struct sock_filter aqt_child_exec_filter[] = {
    AQT_FILTER_PREFIX,
    AQT_STDIO_WRITE_RULE,
    AQT_READ_ONLY_OPENAT_RULE,
    AQT_FCNTL_RULE,
    AQT_TCGETS_IOCTL_RULE,
    AQT_ALLOW_SYSCALL(__NR_mmap),
    AQT_ALLOW_SYSCALL(__NR_mprotect),
    AQT_BASE_RUNTIME_ALLOWANCES,
    AQT_EXACT_EXECVEAT_RULE,
#ifdef __NR_access
    AQT_ALLOW_SYSCALL(__NR_access),
#endif
#ifdef __NR_arch_prctl
    AQT_ALLOW_SYSCALL(__NR_arch_prctl),
#endif
#ifdef __NR_faccessat2
    AQT_ALLOW_SYSCALL(__NR_faccessat2),
#endif
#ifdef __NR_getegid
    AQT_ALLOW_SYSCALL(__NR_getegid),
#endif
#ifdef __NR_getgid
    AQT_ALLOW_SYSCALL(__NR_getgid),
#endif
#ifdef __NR_gettid
    AQT_ALLOW_SYSCALL(__NR_gettid),
#endif
#ifdef __NR_getuid
    AQT_ALLOW_SYSCALL(__NR_getuid),
#endif
#ifdef __NR_prlimit64
    AQT_ALLOW_SYSCALL(__NR_prlimit64),
#endif
#ifdef __NR_readlink
    AQT_ALLOW_SYSCALL(__NR_readlink),
#endif
#ifdef __NR_rseq
    AQT_ALLOW_SYSCALL(__NR_rseq),
#endif
#ifdef __NR_set_robust_list
    AQT_ALLOW_SYSCALL(__NR_set_robust_list),
#endif
#ifdef __NR_set_tid_address
    AQT_ALLOW_SYSCALL(__NR_set_tid_address),
#endif
#ifdef __NR_statx
    AQT_ALLOW_SYSCALL(__NR_statx),
#endif
#ifdef __NR_uname
    AQT_ALLOW_SYSCALL(__NR_uname),
#endif
    AQT_FILTER_SUFFIX,
};

static const struct sock_filter aqt_post_child_filter[] = {
    AQT_FILTER_PREFIX,
    AQT_STDIO_WRITE_RULE,
    AQT_NONEXECUTABLE_MMAP_RULE,
    AQT_ALLOW_SYSCALL(__NR_read),
    AQT_ALLOW_SYSCALL(__NR_close),
    AQT_ALLOW_SYSCALL(__NR_lseek),
    AQT_ALLOW_SYSCALL(__NR_munmap),
    AQT_ALLOW_SYSCALL(__NR_rt_sigaction),
    AQT_ALLOW_SYSCALL(__NR_rt_sigreturn),
    AQT_ALLOW_SYSCALL(__NR_madvise),
    AQT_ALLOW_SYSCALL(__NR_getpid),
    AQT_ALLOW_SYSCALL(__NR_exit),
    AQT_ALLOW_SYSCALL(__NR_exit_group),
    AQT_ALLOW_SYSCALL(__NR_newfstatat),
    AQT_ALLOW_SYSCALL(__NR_fstat),
    AQT_ALLOW_SYSCALL(__NR_mlock),
    AQT_ALLOW_SYSCALL(__NR_munlock),
#ifdef __NR_gettid
    AQT_ALLOW_SYSCALL(__NR_gettid),
#endif
    AQT_UNLINKAT_RULE,
    AQT_FILTER_SUFFIX,
};
#endif

static int
aqt_install_filter(const struct sock_filter *instructions, size_t count)
{
    struct sock_fprog program;

    if (instructions == NULL || count == 0U || count > UINT16_MAX) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_FILTER_FAILED;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_NO_NEW_PRIVS_FAILED;
    }
    program.len = (unsigned short)count;
    program.filter = (struct sock_filter *)(uintptr_t)instructions;
    if (syscall(
            SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &program
        ) != 0) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_FILTER_FAILED;
    }
    return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
}

static int
aqt_filter_view(
    int phase,
    size_t filter_index,
    const struct sock_filter **instructions,
    size_t *count
)
{
    if (instructions == NULL || count == NULL || filter_index != 0U) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
    }
#if defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_CHILD_EXEC_PHASE) {
        *instructions = aqt_child_exec_filter;
        *count = sizeof(aqt_child_exec_filter) / sizeof(aqt_child_exec_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_POST_CHILD_PHASE) {
        *instructions = aqt_post_child_filter;
        *count = sizeof(aqt_post_child_filter) / sizeof(aqt_post_child_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#endif
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE) {
        *instructions = aqt_initial_filter;
        *count = sizeof(aqt_initial_filter) / sizeof(aqt_initial_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
}

int
aqt_trusted_time_v2_seccomp_filter_count(int phase, size_t *count)
{
    const struct sock_filter *instructions;
    size_t instruction_count;
    int result;

    if (count == NULL) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
    }
    result = aqt_filter_view(phase, 0U, &instructions, &instruction_count);
    if (result != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
        return result;
    }
    (void)instructions;
    (void)instruction_count;
    *count = 1U;
    return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
}

int
aqt_trusted_time_v2_seccomp_filter_bytes(
    int phase,
    size_t filter_index,
    const unsigned char **bytes,
    size_t *size
)
{
    const struct sock_filter *instructions;
    size_t count;
    int result;

    if (bytes == NULL || size == NULL) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
    }
    result = aqt_filter_view(phase, filter_index, &instructions, &count);
    if (result != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
        return result;
    }
    *bytes = (const unsigned char *)(const void *)instructions;
    *size = count * sizeof(instructions[0]);
    return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
}

int
aqt_trusted_time_v2_seccomp_install_initial(void)
{
    return aqt_install_filter(
        aqt_initial_filter,
        sizeof(aqt_initial_filter) / sizeof(aqt_initial_filter[0])
    );
}

int
aqt_trusted_time_v2_seccomp_install_child_exec(void)
{
#if defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    return aqt_install_filter(
        aqt_child_exec_filter,
        sizeof(aqt_child_exec_filter) / sizeof(aqt_child_exec_filter[0])
    );
#else
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
#endif
}

int
aqt_trusted_time_v2_seccomp_install_post_child(void)
{
#if defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    return aqt_install_filter(
        aqt_post_child_filter,
        sizeof(aqt_post_child_filter) / sizeof(aqt_post_child_filter[0])
    );
#else
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
#endif
}

#else

int
aqt_trusted_time_v2_seccomp_filter_count(int phase, size_t *count)
{
    (void)phase;
    (void)count;
    return AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED;
}

int
aqt_trusted_time_v2_seccomp_filter_bytes(
    int phase,
    size_t filter_index,
    const unsigned char **bytes,
    size_t *size
)
{
    (void)phase;
    (void)filter_index;
    (void)bytes;
    (void)size;
    return AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED;
}

int
aqt_trusted_time_v2_seccomp_install_initial(void)
{
    return AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED;
}

int
aqt_trusted_time_v2_seccomp_install_child_exec(void)
{
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE
    return AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED;
#else
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
#endif
}

int
aqt_trusted_time_v2_seccomp_install_post_child(void)
{
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE
    return AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED;
#else
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
#endif
}

#endif
