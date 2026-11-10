#ifndef AQT_TRUSTED_TIME_V2_FORK_GUARD_H
#define AQT_TRUSTED_TIME_V2_FORK_GUARD_H

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT 128U
#define AQT_TRUSTED_TIME_V2_FORK_GUARD_EMPTY_FD (-1)

/*
 * The guard returns zero on success and a positive errno value on rejection.
 * Initialization must complete before Py_InitializeFromConfig.  The guard has
 * no Python dependency and permanently poisons every fork child.
 */
typedef struct {
    pid_t origin_pid;
    pthread_t origin_thread;
    uint64_t fork_epoch;
} aqt_trusted_time_v2_fork_identity;

int aqt_trusted_time_v2_fork_guard_initialize_before_python(void);

int aqt_trusted_time_v2_fork_guard_capture_identity(
    aqt_trusted_time_v2_fork_identity *identity_out
);

int aqt_trusted_time_v2_fork_guard_require_identity(
    const aqt_trusted_time_v2_fork_identity *identity
);

int aqt_trusted_time_v2_fork_guard_register_fd(
    int descriptor,
    uint32_t *slot_out
);

/* Closes under the mutation seqcount before publishing the slot as empty. */
int aqt_trusted_time_v2_fork_guard_close_fd(
    uint32_t slot,
    int expected_descriptor
);

int aqt_trusted_time_v2_fork_guard_require_owner_table_empty(void);

uint64_t aqt_trusted_time_v2_fork_guard_current_epoch(void);

int aqt_trusted_time_v2_fork_guard_is_poisoned(void);

#ifdef AQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING
void aqt_trusted_time_v2_fork_guard_test_pause_after_slot_mutation(void);
int aqt_trusted_time_v2_fork_guard_test_slot_mutation_is_paused(void);
void aqt_trusted_time_v2_fork_guard_test_resume_slot_mutation(void);
void aqt_trusted_time_v2_fork_guard_test_pause_after_fd_close(void);
int aqt_trusted_time_v2_fork_guard_test_fd_close_is_paused(void);
void aqt_trusted_time_v2_fork_guard_test_resume_fd_close(void);
void aqt_trusted_time_v2_fork_guard_test_pause_next_prepare(void);
int aqt_trusted_time_v2_fork_guard_test_prepare_is_paused(void);
void aqt_trusted_time_v2_fork_guard_test_resume_prepare(void);
void aqt_trusted_time_v2_fork_guard_test_invoke_prepare(void);
void aqt_trusted_time_v2_fork_guard_test_invoke_parent(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
