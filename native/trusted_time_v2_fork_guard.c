#define _POSIX_C_SOURCE 200809L

#include "trusted_time_v2_fork_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

enum {
    AQT_FORK_GUARD_UNINITIALIZED = 0,
    AQT_FORK_GUARD_INITIALIZING = 1,
    AQT_FORK_GUARD_INITIALIZED = 2,
};

static _Atomic int aqt_guard_state = ATOMIC_VAR_INIT(AQT_FORK_GUARD_UNINITIALIZED);
static _Atomic int aqt_guard_poisoned = ATOMIC_VAR_INIT(1);
static _Atomic uint64_t aqt_guard_epoch = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t aqt_guard_table_generation = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t aqt_guard_prepare_generation = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t aqt_guard_prepare_epoch = ATOMIC_VAR_INIT(0);
static _Atomic uint32_t aqt_guard_active_prepares = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_slots[AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT];
static atomic_flag aqt_guard_mutation = ATOMIC_FLAG_INIT;

#ifdef AQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING
static _Atomic int aqt_guard_test_pause_mutation = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_test_mutation_paused = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_test_pause_fd_close = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_test_fd_close_paused = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_test_pause_prepare = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_test_prepare_paused = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_guard_test_resume_prepare = ATOMIC_VAR_INIT(0);
#endif

static void
aqt_guard_lock_mutation(void)
{
    while (atomic_flag_test_and_set_explicit(&aqt_guard_mutation, memory_order_acquire)) {
    }
}

static void
aqt_guard_unlock_mutation(void)
{
    atomic_flag_clear_explicit(&aqt_guard_mutation, memory_order_release);
}

static void
aqt_guard_begin_table_mutation(void)
{
    /* Even values are quiescent.  Odd values expose an in-flight mutation. */
    (void)atomic_fetch_add_explicit(
        &aqt_guard_table_generation,
        1,
        memory_order_seq_cst
    );
}

static void
aqt_guard_end_table_mutation(void)
{
#ifdef AQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING
    if (atomic_load_explicit(&aqt_guard_test_pause_mutation, memory_order_acquire)
        != 0) {
        atomic_store_explicit(
            &aqt_guard_test_mutation_paused,
            1,
            memory_order_release
        );
        while (atomic_load_explicit(
                   &aqt_guard_test_pause_mutation,
                   memory_order_acquire) != 0) {
        }
        atomic_store_explicit(
            &aqt_guard_test_mutation_paused,
            0,
            memory_order_release
        );
    }
#endif
    (void)atomic_fetch_add_explicit(
        &aqt_guard_table_generation,
        1,
        memory_order_seq_cst
    );
}

static void
aqt_guard_atfork_prepare(void)
{
    const uint32_t prior_prepares = atomic_fetch_add_explicit(
        &aqt_guard_active_prepares,
        1,
        memory_order_seq_cst
    );

    if (prior_prepares != 0U) {
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_seq_cst);
    }
    atomic_store_explicit(
        &aqt_guard_prepare_generation,
        atomic_load_explicit(&aqt_guard_table_generation, memory_order_seq_cst),
        memory_order_seq_cst
    );
    atomic_store_explicit(
        &aqt_guard_prepare_epoch,
        atomic_load_explicit(&aqt_guard_epoch, memory_order_seq_cst),
        memory_order_seq_cst
    );
#ifdef AQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING
    if (atomic_exchange_explicit(
            &aqt_guard_test_pause_prepare,
            0,
            memory_order_acq_rel) != 0) {
        atomic_store_explicit(&aqt_guard_test_prepare_paused, 1, memory_order_release);
        while (atomic_load_explicit(
                   &aqt_guard_test_resume_prepare,
                   memory_order_acquire) == 0) {
        }
        atomic_store_explicit(&aqt_guard_test_prepare_paused, 0, memory_order_release);
    }
#endif
}

static void
aqt_guard_atfork_parent(void)
{
    const uint64_t before_generation = atomic_load_explicit(
        &aqt_guard_prepare_generation,
        memory_order_seq_cst
    );
    const uint64_t after_generation = atomic_load_explicit(
        &aqt_guard_table_generation,
        memory_order_seq_cst
    );
    const uint64_t before_epoch = atomic_load_explicit(
        &aqt_guard_prepare_epoch,
        memory_order_seq_cst
    );
    const uint64_t after_epoch = atomic_load_explicit(
        &aqt_guard_epoch,
        memory_order_seq_cst
    );
    const uint32_t active_prepares = atomic_load_explicit(
        &aqt_guard_active_prepares,
        memory_order_seq_cst
    );

    if ((before_generation & UINT64_C(1)) != 0
        || (after_generation & UINT64_C(1)) != 0
        || before_generation != after_generation
        || before_epoch != after_epoch
        || active_prepares != 1U) {
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_seq_cst);
    }
    if (atomic_fetch_sub_explicit(
            &aqt_guard_active_prepares,
            1,
            memory_order_seq_cst) == 0U) {
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_seq_cst);
        atomic_store_explicit(&aqt_guard_active_prepares, 0, memory_order_seq_cst);
    }
}

static void
aqt_guard_atfork_child(void)
{
    uint32_t slot;

    (void)atomic_fetch_add_explicit(&aqt_guard_epoch, 1, memory_order_seq_cst);
    atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_seq_cst);
    atomic_store_explicit(&aqt_guard_active_prepares, 0, memory_order_seq_cst);
    for (slot = 0; slot < AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT; ++slot) {
        const int descriptor = atomic_exchange_explicit(
            &aqt_guard_slots[slot],
            AQT_TRUSTED_TIME_V2_FORK_GUARD_EMPTY_FD,
            memory_order_seq_cst
        );
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
    }
}

int
aqt_trusted_time_v2_fork_guard_initialize_before_python(void)
{
    int expected = AQT_FORK_GUARD_UNINITIALIZED;
    uint32_t slot;

    if (atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
        == AQT_FORK_GUARD_INITIALIZED) {
        return atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) == 0
            ? 0
            : EPERM;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &aqt_guard_state,
            &expected,
            AQT_FORK_GUARD_INITIALIZING,
            memory_order_acq_rel,
            memory_order_acquire)) {
        return EBUSY;
    }
    if (!atomic_is_lock_free(&aqt_guard_state)
        || !atomic_is_lock_free(&aqt_guard_poisoned)
        || !atomic_is_lock_free(&aqt_guard_epoch)
        || !atomic_is_lock_free(&aqt_guard_table_generation)
        || !atomic_is_lock_free(&aqt_guard_prepare_generation)
        || !atomic_is_lock_free(&aqt_guard_prepare_epoch)
        || !atomic_is_lock_free(&aqt_guard_active_prepares)) {
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_release);
        atomic_store_explicit(
            &aqt_guard_state,
            AQT_FORK_GUARD_UNINITIALIZED,
            memory_order_release
        );
        return ENOTSUP;
    }
    for (slot = 0; slot < AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT; ++slot) {
        if (!atomic_is_lock_free(&aqt_guard_slots[slot])) {
            atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_release);
            atomic_store_explicit(
                &aqt_guard_state,
                AQT_FORK_GUARD_UNINITIALIZED,
                memory_order_release
            );
            return ENOTSUP;
        }
        atomic_store_explicit(
            &aqt_guard_slots[slot],
            AQT_TRUSTED_TIME_V2_FORK_GUARD_EMPTY_FD,
            memory_order_relaxed
        );
    }
    atomic_store_explicit(&aqt_guard_epoch, 1, memory_order_release);
    atomic_store_explicit(&aqt_guard_table_generation, 2, memory_order_release);
    atomic_store_explicit(&aqt_guard_active_prepares, 0, memory_order_release);
    if (pthread_atfork(
            aqt_guard_atfork_prepare,
            aqt_guard_atfork_parent,
            aqt_guard_atfork_child) != 0) {
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_release);
        atomic_store_explicit(
            &aqt_guard_state,
            AQT_FORK_GUARD_UNINITIALIZED,
            memory_order_release
        );
        return ENOTSUP;
    }
    atomic_store_explicit(&aqt_guard_poisoned, 0, memory_order_release);
    atomic_store_explicit(
        &aqt_guard_state,
        AQT_FORK_GUARD_INITIALIZED,
        memory_order_release
    );
    return 0;
}

int
aqt_trusted_time_v2_fork_guard_capture_identity(
    aqt_trusted_time_v2_fork_identity *identity_out)
{
    if (identity_out == NULL) {
        return EINVAL;
    }
    if (atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
            != AQT_FORK_GUARD_INITIALIZED
        || atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) != 0) {
        return EPERM;
    }
    identity_out->origin_pid = getpid();
    identity_out->origin_thread = pthread_self();
    identity_out->fork_epoch = atomic_load_explicit(&aqt_guard_epoch, memory_order_acquire);
    return 0;
}

int
aqt_trusted_time_v2_fork_guard_require_identity(
    const aqt_trusted_time_v2_fork_identity *identity)
{
    if (identity == NULL) {
        return EINVAL;
    }
    if (atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
            != AQT_FORK_GUARD_INITIALIZED
        || atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) != 0
        || identity->origin_pid != getpid()
        || identity->fork_epoch
            != atomic_load_explicit(&aqt_guard_epoch, memory_order_acquire)
        || pthread_equal(identity->origin_thread, pthread_self()) == 0) {
        return EPERM;
    }
    return 0;
}

int
aqt_trusted_time_v2_fork_guard_register_fd(int descriptor, uint32_t *slot_out)
{
    uint32_t slot;
    uint32_t empty_slot = AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT;
    int descriptor_flags;

    if (descriptor < 0 || slot_out == NULL) {
        return EINVAL;
    }
    if (atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
            != AQT_FORK_GUARD_INITIALIZED
        || atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) != 0) {
        return EPERM;
    }
    descriptor_flags = fcntl(descriptor, F_GETFD);
    if (descriptor_flags < 0) {
        return EBADF;
    }
    if ((descriptor_flags & FD_CLOEXEC) == 0
        && fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
        return errno == 0 ? EIO : errno;
    }

    aqt_guard_lock_mutation();
    if (atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) != 0) {
        aqt_guard_unlock_mutation();
        return EPERM;
    }
    for (slot = 0; slot < AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT; ++slot) {
        const int present = atomic_load_explicit(
            &aqt_guard_slots[slot],
            memory_order_relaxed
        );
        if (present == descriptor) {
            aqt_guard_unlock_mutation();
            return EALREADY;
        }
        if (present == AQT_TRUSTED_TIME_V2_FORK_GUARD_EMPTY_FD
            && empty_slot == AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT) {
            empty_slot = slot;
        }
    }
    if (empty_slot == AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT) {
        aqt_guard_unlock_mutation();
        return EMFILE;
    }
    aqt_guard_begin_table_mutation();
    atomic_store_explicit(
        &aqt_guard_slots[empty_slot],
        descriptor,
        memory_order_release
    );
    aqt_guard_end_table_mutation();
    *slot_out = empty_slot;
    aqt_guard_unlock_mutation();
    return 0;
}

int
aqt_trusted_time_v2_fork_guard_close_fd(uint32_t slot, int expected_descriptor)
{
    int present;
    int close_result = 0;

    if (slot >= AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT || expected_descriptor < 0) {
        return EINVAL;
    }
    if (atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
        != AQT_FORK_GUARD_INITIALIZED) {
        return EPERM;
    }
    aqt_guard_lock_mutation();
    present = atomic_load_explicit(&aqt_guard_slots[slot], memory_order_acquire);
    if (present != expected_descriptor) {
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_seq_cst);
        aqt_guard_unlock_mutation();
        return EINVAL;
    }
    aqt_guard_begin_table_mutation();
    if (close(expected_descriptor) != 0) {
        close_result = errno == 0 ? EIO : errno;
        atomic_store_explicit(&aqt_guard_poisoned, 1, memory_order_seq_cst);
    }
#ifdef AQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING
    if (close_result == 0
        && atomic_load_explicit(&aqt_guard_test_pause_fd_close, memory_order_acquire)
            != 0) {
        atomic_store_explicit(&aqt_guard_test_fd_close_paused, 1, memory_order_release);
        while (atomic_load_explicit(
                   &aqt_guard_test_pause_fd_close,
                   memory_order_acquire) != 0) {
        }
        atomic_store_explicit(&aqt_guard_test_fd_close_paused, 0, memory_order_release);
    }
#endif
    if (close_result == 0) {
        atomic_store_explicit(
            &aqt_guard_slots[slot],
            AQT_TRUSTED_TIME_V2_FORK_GUARD_EMPTY_FD,
            memory_order_release
        );
    }
    aqt_guard_end_table_mutation();
    aqt_guard_unlock_mutation();
    return close_result;
}

int
aqt_trusted_time_v2_fork_guard_require_owner_table_empty(void)
{
    uint32_t slot;

    if (atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
            != AQT_FORK_GUARD_INITIALIZED
        || atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) != 0) {
        return EPERM;
    }
    aqt_guard_lock_mutation();
    for (slot = 0; slot < AQT_TRUSTED_TIME_V2_FORK_GUARD_SLOT_COUNT; ++slot) {
        if (atomic_load_explicit(&aqt_guard_slots[slot], memory_order_acquire)
            != AQT_TRUSTED_TIME_V2_FORK_GUARD_EMPTY_FD) {
            aqt_guard_unlock_mutation();
            return EBUSY;
        }
    }
    aqt_guard_unlock_mutation();
    return 0;
}

uint64_t
aqt_trusted_time_v2_fork_guard_current_epoch(void)
{
    return atomic_load_explicit(&aqt_guard_epoch, memory_order_acquire);
}

int
aqt_trusted_time_v2_fork_guard_is_poisoned(void)
{
    return atomic_load_explicit(&aqt_guard_state, memory_order_acquire)
                != AQT_FORK_GUARD_INITIALIZED
            || atomic_load_explicit(&aqt_guard_poisoned, memory_order_acquire) != 0;
}

#ifdef AQT_TRUSTED_TIME_V2_FORK_GUARD_TESTING
void
aqt_trusted_time_v2_fork_guard_test_pause_after_slot_mutation(void)
{
    atomic_store_explicit(&aqt_guard_test_pause_mutation, 1, memory_order_release);
}

int
aqt_trusted_time_v2_fork_guard_test_slot_mutation_is_paused(void)
{
    return atomic_load_explicit(
        &aqt_guard_test_mutation_paused,
        memory_order_acquire
    );
}

void
aqt_trusted_time_v2_fork_guard_test_resume_slot_mutation(void)
{
    atomic_store_explicit(&aqt_guard_test_pause_mutation, 0, memory_order_release);
}

void
aqt_trusted_time_v2_fork_guard_test_pause_after_fd_close(void)
{
    atomic_store_explicit(&aqt_guard_test_pause_fd_close, 1, memory_order_release);
}

int
aqt_trusted_time_v2_fork_guard_test_fd_close_is_paused(void)
{
    return atomic_load_explicit(&aqt_guard_test_fd_close_paused, memory_order_acquire);
}

void
aqt_trusted_time_v2_fork_guard_test_resume_fd_close(void)
{
    atomic_store_explicit(&aqt_guard_test_pause_fd_close, 0, memory_order_release);
}

void
aqt_trusted_time_v2_fork_guard_test_pause_next_prepare(void)
{
    atomic_store_explicit(&aqt_guard_test_resume_prepare, 0, memory_order_release);
    atomic_store_explicit(&aqt_guard_test_pause_prepare, 1, memory_order_release);
}

int
aqt_trusted_time_v2_fork_guard_test_prepare_is_paused(void)
{
    return atomic_load_explicit(&aqt_guard_test_prepare_paused, memory_order_acquire);
}

void
aqt_trusted_time_v2_fork_guard_test_resume_prepare(void)
{
    atomic_store_explicit(&aqt_guard_test_resume_prepare, 1, memory_order_release);
}

void
aqt_trusted_time_v2_fork_guard_test_invoke_prepare(void)
{
    aqt_guard_atfork_prepare();
}

void
aqt_trusted_time_v2_fork_guard_test_invoke_parent(void)
{
    aqt_guard_atfork_parent();
}
#endif
