#ifndef AQT_TRUSTED_TIME_V2_SECCOMP_H
#define AQT_TRUSTED_TIME_V2_SECCOMP_H

#include <stddef.h>

/*
 * Linux-only, compile-time-selected lifecycle-v2 syscall isolation.
 *
 * The implementation never parses a policy document at runtime.  A build
 * selects exactly one role macro and the resulting BPF instruction stream is
 * part of the executable's immutable bytes.  macOS keeps the portable build
 * seam but reports the operational filter as unsupported.
 */

#define AQT_TRUSTED_TIME_V2_SECCOMP_OK 0
#define AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED 1
#define AQT_TRUSTED_TIME_V2_SECCOMP_INVALID_PHASE 2
#define AQT_TRUSTED_TIME_V2_SECCOMP_NO_NEW_PRIVS_FAILED 3
#define AQT_TRUSTED_TIME_V2_SECCOMP_FILTER_FAILED 4
#define AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE 0
#define AQT_TRUSTED_TIME_V2_SECCOMP_POST_CHILD_PHASE 1
#define AQT_TRUSTED_TIME_V2_SECCOMP_CHILD_EXEC_PHASE 2

int aqt_trusted_time_v2_seccomp_install_initial(void);
int aqt_trusted_time_v2_seccomp_install_child_exec(void);
int aqt_trusted_time_v2_seccomp_install_post_child(void);
const char *aqt_trusted_time_v2_seccomp_profile_name(void);
const char *aqt_trusted_time_v2_seccomp_policy_model(void);

/*
 * Linux build tooling hashes these exact compiled sock_filter bytes into the
 * architecture-specific manifest.  A stacked phase has one indexed stream
 * per filter, in installation order.  The view is read-only and static.
 */
int aqt_trusted_time_v2_seccomp_filter_count(int phase, size_t *count);
int aqt_trusted_time_v2_seccomp_filter_bytes(
    int phase,
    size_t filter_index,
    const unsigned char **bytes,
    size_t *size
);

#endif
