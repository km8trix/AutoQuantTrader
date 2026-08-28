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
    return "ordered-default-allow-denylist-v1";
}

#ifdef __linux__

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <sys/prctl.h>
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

#define AQT_DENY_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

#define AQT_FILTER_PREFIX \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AQT_AUDIT_ARCH, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))

#define AQT_FILTER_SUFFIX \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

_Static_assert(
    sizeof(struct sock_filter) == 8U,
    "manifest-bound classic BPF instructions must be exactly eight bytes"
);

/*
 * Process creation is intentionally denied more strictly than a Python
 * subprocess boundary: Linux clone-based thread creation is denied too.  The
 * fixed owner processes enter this profile single-threaded before Python.
 */
#define AQT_PROCESS_DENIALS \
    AQT_DENY_SYSCALL(__NR_clone), \
    AQT_DENY_SYSCALL(__NR_execve), \
    AQT_DENY_SYSCALL(__NR_unshare), \
    AQT_DENY_SYSCALL(__NR_setns)

static const struct sock_filter aqt_process_filter[] = {
    AQT_FILTER_PREFIX,
#ifdef __NR_fork
    AQT_DENY_SYSCALL(__NR_fork),
#endif
#ifdef __NR_vfork
    AQT_DENY_SYSCALL(__NR_vfork),
#endif
    AQT_PROCESS_DENIALS,
#ifdef __NR_clone3
    AQT_DENY_SYSCALL(__NR_clone3),
#endif
#ifdef __NR_execveat
    AQT_DENY_SYSCALL(__NR_execveat),
#endif
    AQT_FILTER_SUFFIX,
};

#if defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
static const struct sock_filter aqt_network_filter[] = {
    AQT_FILTER_PREFIX,
#ifdef __NR_socket
    AQT_DENY_SYSCALL(__NR_socket),
#endif
#ifdef __NR_socketpair
    AQT_DENY_SYSCALL(__NR_socketpair),
#endif
#ifdef __NR_connect
    AQT_DENY_SYSCALL(__NR_connect),
#endif
#ifdef __NR_bind
    AQT_DENY_SYSCALL(__NR_bind),
#endif
#ifdef __NR_listen
    AQT_DENY_SYSCALL(__NR_listen),
#endif
#ifdef __NR_accept
    AQT_DENY_SYSCALL(__NR_accept),
#endif
#ifdef __NR_accept4
    AQT_DENY_SYSCALL(__NR_accept4),
#endif
#ifdef __NR_sendto
    AQT_DENY_SYSCALL(__NR_sendto),
#endif
#ifdef __NR_sendmsg
    AQT_DENY_SYSCALL(__NR_sendmsg),
#endif
#ifdef __NR_sendmmsg
    AQT_DENY_SYSCALL(__NR_sendmmsg),
#endif
#ifdef __NR_recvfrom
    AQT_DENY_SYSCALL(__NR_recvfrom),
#endif
#ifdef __NR_recvmsg
    AQT_DENY_SYSCALL(__NR_recvmsg),
#endif
#ifdef __NR_recvmmsg
    AQT_DENY_SYSCALL(__NR_recvmmsg),
#endif
#ifdef __NR_shutdown
    AQT_DENY_SYSCALL(__NR_shutdown),
#endif
#ifdef __NR_getsockname
    AQT_DENY_SYSCALL(__NR_getsockname),
#endif
#ifdef __NR_getpeername
    AQT_DENY_SYSCALL(__NR_getpeername),
#endif
#ifdef __NR_setsockopt
    AQT_DENY_SYSCALL(__NR_setsockopt),
#endif
#ifdef __NR_getsockopt
    AQT_DENY_SYSCALL(__NR_getsockopt),
#endif
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
    if (instructions == NULL || count == NULL) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
    }
#if defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE
        && filter_index == 0U) {
        *instructions = aqt_network_filter;
        *count = sizeof(aqt_network_filter) / sizeof(aqt_network_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE
        && filter_index == 1U) {
        *instructions = aqt_process_filter;
        *count = sizeof(aqt_process_filter) / sizeof(aqt_process_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#elif defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE
        && filter_index == 0U) {
        *instructions = aqt_network_filter;
        *count = sizeof(aqt_network_filter) / sizeof(aqt_network_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_POST_CHILD_PHASE
        && filter_index == 0U) {
        *instructions = aqt_process_filter;
        *count = sizeof(aqt_process_filter) / sizeof(aqt_process_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#else
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE
        && filter_index == 0U) {
        *instructions = aqt_process_filter;
        *count = sizeof(aqt_process_filter) / sizeof(aqt_process_filter[0]);
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#endif
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
}

int
aqt_trusted_time_v2_seccomp_filter_count(int phase, size_t *count)
{
    if (count == NULL) {
        return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
    }
#if defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE) {
        *count = 2U;
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#elif defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE
        || phase == AQT_TRUSTED_TIME_V2_SECCOMP_POST_CHILD_PHASE) {
        *count = 1U;
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#else
    if (phase == AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE) {
        *count = 1U;
        return AQT_TRUSTED_TIME_V2_SECCOMP_OK;
    }
#endif
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
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
#if defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
    int result = aqt_install_filter(
        aqt_network_filter,
        sizeof(aqt_network_filter) / sizeof(aqt_network_filter[0])
    );
    if (result != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
        return result;
    }
    return aqt_install_filter(
        aqt_process_filter,
        sizeof(aqt_process_filter) / sizeof(aqt_process_filter[0])
    );
#elif defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    return aqt_install_filter(
        aqt_network_filter,
        sizeof(aqt_network_filter) / sizeof(aqt_network_filter[0])
    );
#else
    return aqt_install_filter(
        aqt_process_filter,
        sizeof(aqt_process_filter) / sizeof(aqt_process_filter[0])
    );
#endif
}

int
aqt_trusted_time_v2_seccomp_install_post_child(void)
{
#if defined(AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE)
    return aqt_install_filter(
        aqt_process_filter,
        sizeof(aqt_process_filter) / sizeof(aqt_process_filter[0])
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
aqt_trusted_time_v2_seccomp_install_post_child(void)
{
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_PROFILE
    return AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED;
#else
    return AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE;
#endif
}

#endif
