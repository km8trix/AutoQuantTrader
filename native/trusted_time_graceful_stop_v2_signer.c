#if defined(__linux__)
#define _GNU_SOURCE
#else
#define _DARWIN_C_SOURCE
#endif

#include "trusted_time_graceful_stop_v2_signer.h"

#include "trusted_time_v2_secret_mount_admission.h"
#include "trusted_time_v2_fork_guard.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define AQT_SIGNER_SEED_BYTES 32U
#define AQT_SIGNER_SECRET_KEY_BYTES 64U
#define AQT_SIGNER_INVALID_SLOT UINT32_MAX
#define AQT_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

enum {
    AQT_SIGNER_UNINITIALIZED = 0,
    AQT_SIGNER_INITIALIZING = 1,
    AQT_SIGNER_INITIALIZED = 2,
    AQT_SIGNER_FAILED = 3,
};

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
#define AQT_SIGNER_PRODUCTION_CREDENTIAL_DIRECTORY \
    "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets"
#define AQT_SIGNER_PRODUCTION_CREDENTIAL_BASENAME "host-ed25519.raw"
#define AQT_SIGNER_DIRECTORY_UID ((uid_t)0)
#define AQT_SIGNER_DIRECTORY_GID ((gid_t)0)
#define AQT_SIGNER_DIRECTORY_MODE ((mode_t)0700)
#define AQT_SIGNER_CREDENTIAL_UID ((uid_t)0)
#define AQT_SIGNER_CREDENTIAL_GID ((gid_t)0)
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE)
#define AQT_SIGNER_PRODUCTION_CREDENTIAL_DIRECTORY \
    "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets"
#define AQT_SIGNER_PRODUCTION_CREDENTIAL_BASENAME "supervisor-ed25519.raw"
#define AQT_SIGNER_DIRECTORY_UID ((uid_t)0)
#define AQT_SIGNER_DIRECTORY_GID ((gid_t)10001)
#define AQT_SIGNER_DIRECTORY_MODE ((mode_t)0730)
#define AQT_SIGNER_CREDENTIAL_UID ((uid_t)10001)
#define AQT_SIGNER_CREDENTIAL_GID ((gid_t)10001)
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE)
#define AQT_SIGNER_PRODUCTION_CREDENTIAL_DIRECTORY \
    "/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets"
#define AQT_SIGNER_PRODUCTION_CREDENTIAL_BASENAME "recovery-ed25519.raw"
#define AQT_SIGNER_DIRECTORY_UID ((uid_t)0)
#define AQT_SIGNER_DIRECTORY_GID ((gid_t)0)
#define AQT_SIGNER_DIRECTORY_MODE ((mode_t)0700)
#define AQT_SIGNER_CREDENTIAL_UID ((uid_t)0)
#define AQT_SIGNER_CREDENTIAL_GID ((gid_t)0)
#endif

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_TEST_PROFILE)
#define AQT_SIGNER_CREDENTIAL_BASENAME "credential.raw"
#undef AQT_SIGNER_DIRECTORY_MODE
#define AQT_SIGNER_DIRECTORY_MODE ((mode_t)0700)
#else
#define AQT_SIGNER_CREDENTIAL_BASENAME AQT_SIGNER_PRODUCTION_CREDENTIAL_BASENAME
#endif

#if defined(__GNUC__) || defined(__clang__)
#define AQT_SIGNER_USED __attribute__((used))
#define AQT_SIGNER_MAYBE_UNUSED __attribute__((unused))
#else
#define AQT_SIGNER_USED
#define AQT_SIGNER_MAYBE_UNUSED
#endif

static const char aqt_signer_production_credential_directory[] AQT_SIGNER_USED =
    AQT_SIGNER_PRODUCTION_CREDENTIAL_DIRECTORY;
static const char aqt_signer_production_credential_basename[] AQT_SIGNER_USED =
    AQT_SIGNER_PRODUCTION_CREDENTIAL_BASENAME;

typedef struct {
    uint64_t device;
    uint64_t inode;
    uint32_t file_type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t link_count;
    int64_t size;
    int64_t modification_seconds;
    int64_t modification_nanoseconds;
    int64_t change_seconds;
    int64_t change_nanoseconds;
} aqt_signer_stat9;

typedef struct {
    int descriptor;
    uint32_t slot;
} aqt_signer_guarded_fd;

typedef struct {
    uint8_t seed[AQT_SIGNER_SEED_BYTES];
    uint8_t verification_seed[AQT_SIGNER_SEED_BYTES];
    uint8_t secret_key[AQT_SIGNER_SECRET_KEY_BYTES];
} aqt_signer_secret_mapping;

struct aqt_trusted_time_v2_signer_owner {
    aqt_trusted_time_v2_fork_identity fork_identity;
    uintptr_t interpreter_identity;
    uint8_t public_key[AQT_TRUSTED_TIME_V2_ED25519_PUBLIC_KEY_BYTES];
    aqt_signer_secret_mapping *secret;
    size_t secret_mapping_size;
    int credential_directory_fd;
    uint32_t credential_directory_slot;
    aqt_signer_stat9 credential_directory_identity;
    aqt_trusted_time_v2_secret_mount_admission *mount_admission;
};

typedef struct {
    const char *key;
    const char *encoded_value;
} aqt_signer_message_rule;

static _Atomic int aqt_signer_state = ATOMIC_VAR_INIT(AQT_SIGNER_UNINITIALIZED);

#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TESTING
static _Atomic int aqt_signer_test_zeroized = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_signer_test_close_fault = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_signer_test_pause_seed_read = ATOMIC_VAR_INIT(0);
static _Atomic int aqt_signer_test_seed_read_paused = ATOMIC_VAR_INIT(0);
#endif

static int
aqt_signer_bytes_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t index;

    for (index = 0; index < size; ++index) {
        difference = (uint8_t)(difference | (uint8_t)(left[index] ^ right[index]));
    }
    return difference == 0;
}

static int
aqt_signer_metadata_matches(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev
        && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode
        && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid
        && left->st_nlink == right->st_nlink
        && left->st_size == right->st_size;
}

static int
aqt_signer_errno_or_io(void)
{
    return errno == 0 ? EIO : errno;
}

static void
aqt_signer_stat9_from_stat(
    const struct stat *metadata,
    aqt_signer_stat9 *identity)
{
    identity->device = (uint64_t)metadata->st_dev;
    identity->inode = (uint64_t)metadata->st_ino;
    identity->file_type = (uint32_t)(metadata->st_mode & S_IFMT);
    identity->mode = (uint32_t)(metadata->st_mode & (mode_t)07777);
    identity->uid = (uint32_t)metadata->st_uid;
    identity->gid = (uint32_t)metadata->st_gid;
    identity->link_count = (uint64_t)metadata->st_nlink;
    identity->size = (int64_t)metadata->st_size;
#if defined(__APPLE__)
    identity->modification_seconds = (int64_t)metadata->st_mtimespec.tv_sec;
    identity->modification_nanoseconds = (int64_t)metadata->st_mtimespec.tv_nsec;
    identity->change_seconds = (int64_t)metadata->st_ctimespec.tv_sec;
    identity->change_nanoseconds = (int64_t)metadata->st_ctimespec.tv_nsec;
#else
    identity->modification_seconds = (int64_t)metadata->st_mtim.tv_sec;
    identity->modification_nanoseconds = (int64_t)metadata->st_mtim.tv_nsec;
    identity->change_seconds = (int64_t)metadata->st_ctim.tv_sec;
    identity->change_nanoseconds = (int64_t)metadata->st_ctim.tv_nsec;
#endif
}

static int
aqt_signer_stat9_equal(
    const aqt_signer_stat9 *left,
    const aqt_signer_stat9 *right)
{
    return left != NULL && right != NULL
        && left->device == right->device
        && left->inode == right->inode
        && left->file_type == right->file_type
        && left->mode == right->mode
        && left->uid == right->uid
        && left->gid == right->gid
        && left->link_count == right->link_count
        && left->size == right->size
        && left->modification_seconds == right->modification_seconds
        && left->modification_nanoseconds == right->modification_nanoseconds
        && left->change_seconds == right->change_seconds
        && left->change_nanoseconds == right->change_nanoseconds;
}

static int
aqt_signer_fstat9(int descriptor, aqt_signer_stat9 *identity_out)
{
    struct stat first;
    struct stat second;
    aqt_signer_stat9 first_identity;
    aqt_signer_stat9 second_identity;

    if (descriptor < 0 || identity_out == NULL) {
        return EINVAL;
    }
    if (fstat(descriptor, &first) != 0 || fstat(descriptor, &second) != 0) {
        return aqt_signer_errno_or_io();
    }
    aqt_signer_stat9_from_stat(&first, &first_identity);
    aqt_signer_stat9_from_stat(&second, &second_identity);
    if (!aqt_signer_stat9_equal(&first_identity, &second_identity)) {
        return ESTALE;
    }
    *identity_out = first_identity;
    return 0;
}

static int
aqt_signer_fstatat9(
    int directory_fd,
    const char *name,
    aqt_signer_stat9 *identity_out)
{
    struct stat first;
    struct stat second;
    aqt_signer_stat9 first_identity;
    aqt_signer_stat9 second_identity;

    if (directory_fd < 0 || name == NULL || identity_out == NULL) {
        return EINVAL;
    }
    if (fstatat(directory_fd, name, &first, AT_SYMLINK_NOFOLLOW) != 0
        || fstatat(directory_fd, name, &second, AT_SYMLINK_NOFOLLOW) != 0) {
        return aqt_signer_errno_or_io();
    }
    aqt_signer_stat9_from_stat(&first, &first_identity);
    aqt_signer_stat9_from_stat(&second, &second_identity);
    if (!aqt_signer_stat9_equal(&first_identity, &second_identity)) {
        return ESTALE;
    }
    *identity_out = first_identity;
    return 0;
}

static void
aqt_signer_guarded_fd_initialize(aqt_signer_guarded_fd *owner)
{
    owner->descriptor = -1;
    owner->slot = AQT_SIGNER_INVALID_SLOT;
}

static int AQT_SIGNER_MAYBE_UNUSED
aqt_signer_guarded_fd_adopt(int descriptor, aqt_signer_guarded_fd *owner)
{
    int result;

    if (owner == NULL) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return EINVAL;
    }
    aqt_signer_guarded_fd_initialize(owner);
    if (descriptor < 0) {
        return aqt_signer_errno_or_io();
    }
    result = aqt_trusted_time_v2_fork_guard_register_fd(descriptor, &owner->slot);
    if (result != 0) {
        (void)close(descriptor);
        return result;
    }
    owner->descriptor = descriptor;
    return 0;
}

static int
aqt_signer_guarded_fd_close(
    aqt_signer_guarded_fd *owner,
    int test_fault_stage)
{
    int result;

    if (owner == NULL || owner->descriptor < 0) {
        return 0;
    }
#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TESTING
    if (test_fault_stage != 0) {
        int expected = test_fault_stage;

        if (atomic_compare_exchange_strong_explicit(
                &aqt_signer_test_close_fault,
                &expected,
                0,
                memory_order_acq_rel,
                memory_order_acquire)) {
            (void)close(owner->descriptor);
        }
    }
#else
    (void)test_fault_stage;
#endif
    result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->slot,
        owner->descriptor
    );
    owner->descriptor = -1;
    owner->slot = AQT_SIGNER_INVALID_SLOT;
    return result;
}

static int
aqt_signer_validate_credential_metadata(const struct stat *metadata)
{
#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TEST_PROFILE
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = AQT_SIGNER_CREDENTIAL_UID;
    const gid_t expected_gid = AQT_SIGNER_CREDENTIAL_GID;
#endif

    return S_ISREG(metadata->st_mode)
        && (metadata->st_mode & (mode_t)07777) == (mode_t)0400
        && metadata->st_uid == expected_uid
        && metadata->st_gid == expected_gid
        && metadata->st_nlink == (nlink_t)1
        && metadata->st_size == (off_t)AQT_SIGNER_SEED_BYTES;
}

static int
aqt_signer_validate_directory_metadata(const struct stat *metadata)
{
#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TEST_PROFILE
    const uid_t expected_uid = geteuid();
    const gid_t expected_gid = getegid();
#else
    const uid_t expected_uid = AQT_SIGNER_DIRECTORY_UID;
    const gid_t expected_gid = AQT_SIGNER_DIRECTORY_GID;
#endif

    return S_ISDIR(metadata->st_mode)
        && (metadata->st_mode & (mode_t)07777) == AQT_SIGNER_DIRECTORY_MODE
        && metadata->st_uid == expected_uid
        && metadata->st_gid == expected_gid
        && metadata->st_nlink >= (nlink_t)2;
}

#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TESTING
static void
aqt_signer_maybe_pause_after_first_seed_read(void)
{
    if (atomic_load_explicit(
            &aqt_signer_test_pause_seed_read,
            memory_order_acquire) == 0) {
        return;
    }
    atomic_store_explicit(
        &aqt_signer_test_seed_read_paused,
        1,
        memory_order_release
    );
    while (atomic_load_explicit(
               &aqt_signer_test_pause_seed_read,
               memory_order_acquire) != 0) {
        (void)sched_yield();
    }
    atomic_store_explicit(
        &aqt_signer_test_seed_read_paused,
        0,
        memory_order_release
    );
}
#else
static void
aqt_signer_maybe_pause_after_first_seed_read(void)
{
}
#endif

#if defined(__linux__)
static int
aqt_signer_validate_secure_ancestor(
    const aqt_signer_stat9 *identity,
    uint64_t minimum_link_count)
{
    return identity != NULL
        && identity->file_type == (uint32_t)S_IFDIR
        && identity->uid == 0U
        && identity->gid == 0U
        && (identity->mode & UINT32_C(0022)) == 0U
        && identity->link_count >= minimum_link_count;
}

static int
aqt_signer_validate_role_directory_identity(
    const aqt_signer_stat9 *identity)
{
    return identity != NULL
        && identity->file_type == (uint32_t)S_IFDIR
        && identity->uid == (uint32_t)AQT_SIGNER_DIRECTORY_UID
        && identity->gid == (uint32_t)AQT_SIGNER_DIRECTORY_GID
        && identity->mode == (uint32_t)AQT_SIGNER_DIRECTORY_MODE
        && identity->link_count >= UINT64_C(2);
}

static int
aqt_signer_open_correlated_child(
    const aqt_signer_guarded_fd *parent,
    const char *name,
    int flags,
    aqt_signer_guarded_fd *child_out,
    aqt_signer_stat9 *identity_out)
{
    aqt_signer_stat9 path_before;
    aqt_signer_stat9 descriptor_identity;
    aqt_signer_stat9 path_after;
    int result;

    if (parent == NULL || parent->descriptor < 0 || name == NULL
        || child_out == NULL || identity_out == NULL) {
        return EINVAL;
    }
    aqt_signer_guarded_fd_initialize(child_out);
    result = aqt_signer_fstatat9(parent->descriptor, name, &path_before);
    if (result != 0) {
        return result;
    }
    result = aqt_signer_guarded_fd_adopt(
        openat(parent->descriptor, name, flags | O_CLOEXEC | O_NOFOLLOW),
        child_out
    );
    if (result != 0) {
        return result;
    }
    result = aqt_signer_fstat9(child_out->descriptor, &descriptor_identity);
    if (result == 0) {
        result = aqt_signer_fstatat9(parent->descriptor, name, &path_after);
    }
    if (result == 0
        && (!aqt_signer_stat9_equal(&path_before, &descriptor_identity)
            || !aqt_signer_stat9_equal(&descriptor_identity, &path_after))) {
        result = ESTALE;
    }
    if (result != 0) {
        (void)aqt_signer_guarded_fd_close(child_out, 0);
        return result;
    }
    *identity_out = descriptor_identity;
    return 0;
}
static int
aqt_signer_open_literal_credential_directory(
    aqt_signer_guarded_fd *directory_out,
    aqt_signer_stat9 *identity_out)
{
    static const char *const components[] = {
        "run", "autoquant", "trusted-time", "graceful-stop-v2",
#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
        "host-secrets",
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE)
        "supervisor-secrets",
#else
        "recovery-secrets",
#endif
    };
    aqt_signer_guarded_fd current;
    aqt_signer_stat9 current_identity;
    int result;

    if (directory_out == NULL || identity_out == NULL) {
        return EINVAL;
    }
    aqt_signer_guarded_fd_initialize(directory_out);
    aqt_signer_guarded_fd_initialize(&current);
    result = aqt_signer_guarded_fd_adopt(
        open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
        &current
    );
    if (result != 0) {
        return result;
    }
    result = aqt_signer_fstat9(current.descriptor, &current_identity);
    if (result != 0
        || !aqt_signer_validate_secure_ancestor(
            &current_identity,
            UINT64_C(1))) {
        result = result == 0 ? EPERM : result;
        (void)aqt_signer_guarded_fd_close(&current, 0);
        return result;
    }
    for (size_t index = 0U; index < AQT_ARRAY_LENGTH(components); ++index) {
        aqt_signer_guarded_fd next;
        aqt_signer_stat9 next_identity;
        int cleanup_result;

        aqt_signer_guarded_fd_initialize(&next);
        result = aqt_signer_open_correlated_child(
            &current,
            components[index],
            O_RDONLY | O_DIRECTORY,
            &next,
            &next_identity
        );
        if (result == 0) {
            if (index + 1U == AQT_ARRAY_LENGTH(components)) {
                if (!aqt_signer_validate_role_directory_identity(&next_identity)) {
                    result = EPERM;
                }
            } else if (!aqt_signer_validate_secure_ancestor(
                           &next_identity,
                           index == 0U ? UINT64_C(1) : UINT64_C(2))) {
                result = EPERM;
            }
        }
        cleanup_result = aqt_signer_guarded_fd_close(&current, 0);
        if (cleanup_result != 0 && result == 0) {
            result = cleanup_result;
        }
        if (result != 0) {
            (void)aqt_signer_guarded_fd_close(&next, 0);
            return result;
        }
        current = next;
    }
    *directory_out = current;
    result = aqt_signer_fstat9(directory_out->descriptor, identity_out);
    if (result != 0) {
        (void)aqt_signer_guarded_fd_close(directory_out, 0);
    }
    return result;
}
#endif

static int
aqt_signer_allocate_secret(aqt_signer_secret_mapping **secret_out)
{
    aqt_signer_secret_mapping *secret;
    int result;

    if (secret_out == NULL || *secret_out != NULL) {
        return EINVAL;
    }
    secret = (aqt_signer_secret_mapping *)mmap(
        NULL,
        sizeof(*secret),
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE |
#if defined(__linux__)
            MAP_ANONYMOUS,
#else
            MAP_ANON,
#endif
        -1,
        0
    );
    if (secret == MAP_FAILED) {
        return errno == 0 ? ENOMEM : errno;
    }
    if (mlock(secret, sizeof(*secret)) != 0) {
        result = errno == 0 ? EPERM : errno;
        crypto_wipe(secret, sizeof(*secret));
        (void)munmap(secret, sizeof(*secret));
        return result;
    }
#if defined(__linux__)
    if (madvise(secret, sizeof(*secret), MADV_DONTDUMP) != 0
        || madvise(secret, sizeof(*secret), MADV_WIPEONFORK) != 0) {
        result = errno == 0 ? ENOTSUP : errno;
        crypto_wipe(secret, sizeof(*secret));
        (void)munlock(secret, sizeof(*secret));
        (void)munmap(secret, sizeof(*secret));
        return result;
    }
#endif
    *secret_out = secret;
    return 0;
}

static int
aqt_signer_bootstrap_self_test(void)
{
    static const uint8_t expected_seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };
    static const uint8_t expected_public_key[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    };
    static const uint8_t expected_signature[64] = {
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    };
    static const uint8_t empty_message = 0;
    aqt_signer_secret_mapping *secret = NULL;
    uint8_t public_key[32];
    uint8_t signature[64];
    int valid;
    int result;

    result = aqt_signer_allocate_secret(&secret);
    if (result != 0) {
        return result;
    }
    (void)memcpy(secret->seed, expected_seed, sizeof(secret->seed));
    crypto_ed25519_key_pair(secret->secret_key, public_key, secret->seed);
    crypto_wipe(secret->seed, sizeof(secret->seed));
    crypto_ed25519_sign(signature, secret->secret_key, &empty_message, 0);
    valid = aqt_signer_bytes_equal(public_key, expected_public_key, sizeof(public_key))
        && aqt_signer_bytes_equal(signature, expected_signature, sizeof(signature))
        && crypto_ed25519_check(signature, public_key, &empty_message, 0) == 0;
    crypto_wipe(secret, sizeof(*secret));
    (void)munlock(secret, sizeof(*secret));
    (void)munmap(secret, sizeof(*secret));
    crypto_wipe(signature, sizeof(signature));
    return valid ? 0 : EIO;
}

int
aqt_trusted_time_v2_signer_initialize_before_python(void)
{
    aqt_trusted_time_v2_fork_identity identity;
    int expected = AQT_SIGNER_UNINITIALIZED;
    int result;

    if (atomic_load_explicit(&aqt_signer_state, memory_order_acquire)
        == AQT_SIGNER_INITIALIZED) {
        return aqt_trusted_time_v2_fork_guard_capture_identity(&identity);
    }
    if (!atomic_compare_exchange_strong_explicit(
            &aqt_signer_state,
            &expected,
            AQT_SIGNER_INITIALIZING,
            memory_order_acq_rel,
            memory_order_acquire)) {
        return expected == AQT_SIGNER_FAILED ? EPERM : EBUSY;
    }
    if (!atomic_is_lock_free(&aqt_signer_state)) {
        result = ENOTSUP;
        goto fail;
    }
    result = aqt_trusted_time_v2_fork_guard_capture_identity(&identity);
    if (result != 0) {
        goto fail;
    }
    result = aqt_signer_bootstrap_self_test();
    if (result != 0) {
        goto fail;
    }
    atomic_store_explicit(&aqt_signer_state, AQT_SIGNER_INITIALIZED, memory_order_release);
    return 0;

fail:
    atomic_store_explicit(&aqt_signer_state, AQT_SIGNER_FAILED, memory_order_release);
    return result;
}

static void
aqt_signer_burn_secret(aqt_signer_secret_mapping **secret_io, size_t mapping_size)
{
    size_t index;
    int zeroized = 1;

    if (secret_io == NULL || *secret_io == NULL) {
        return;
    }
    crypto_wipe(*secret_io, mapping_size);
#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TESTING
    for (index = 0; index < mapping_size; ++index) {
        if (((const volatile uint8_t *)(*secret_io))[index] != 0) {
            zeroized = 0;
        }
    }
    atomic_store_explicit(&aqt_signer_test_zeroized, zeroized, memory_order_release);
#else
    (void)index;
    (void)zeroized;
#endif
    (void)munlock(*secret_io, mapping_size);
    (void)munmap(*secret_io, mapping_size);
    *secret_io = NULL;
}

static int
aqt_signer_require_owner(
    const aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity)
{
    int result;

    if (owner == NULL || interpreter_identity == (uintptr_t)0) {
        return EINVAL;
    }
    result = aqt_trusted_time_v2_fork_guard_require_identity(&owner->fork_identity);
    if (result != 0) {
        return result;
    }
    if (owner->interpreter_identity != interpreter_identity || owner->secret == NULL) {
        return EPERM;
    }
    return 0;
}

static int
aqt_signer_json_hex_digit(uint8_t value)
{
    return (value >= (uint8_t)'0' && value <= (uint8_t)'9')
        || (value >= (uint8_t)'a' && value <= (uint8_t)'f')
        || (value >= (uint8_t)'A' && value <= (uint8_t)'F');
}

static int
aqt_signer_json_skip_string(
    const uint8_t *message,
    size_t message_size,
    size_t *offset_io)
{
    size_t offset = *offset_io;

    if (offset >= message_size || message[offset] != (uint8_t)'"') {
        return 0;
    }
    ++offset;
    while (offset < message_size) {
        const uint8_t value = message[offset++];
        if (value == (uint8_t)'"') {
            *offset_io = offset;
            return 1;
        }
        if (value < UINT8_C(0x20)) {
            return 0;
        }
        if (value == (uint8_t)'\\') {
            uint8_t escape;
            size_t digit;
            if (offset >= message_size) {
                return 0;
            }
            escape = message[offset++];
            if (escape == (uint8_t)'u') {
                if (message_size - offset < 4U) {
                    return 0;
                }
                for (digit = 0; digit < 4U; ++digit) {
                    if (!aqt_signer_json_hex_digit(message[offset + digit])) {
                        return 0;
                    }
                }
                offset += 4U;
            } else if (escape != (uint8_t)'"' && escape != (uint8_t)'\\'
                       && escape != (uint8_t)'/' && escape != (uint8_t)'b'
                       && escape != (uint8_t)'f' && escape != (uint8_t)'n'
                       && escape != (uint8_t)'r' && escape != (uint8_t)'t') {
                return 0;
            }
        }
    }
    return 0;
}

static int
aqt_signer_json_skip_value(
    const uint8_t *message,
    size_t message_size,
    size_t *offset_io)
{
    size_t offset = *offset_io;

    if (offset >= message_size) {
        return 0;
    }
    if (message[offset] == (uint8_t)'"') {
        if (!aqt_signer_json_skip_string(message, message_size, &offset)) {
            return 0;
        }
    } else if (message[offset] == (uint8_t)'{' || message[offset] == (uint8_t)'[') {
        uint8_t closing[64];
        size_t depth = 0;
        closing[depth++] = message[offset++] == (uint8_t)'{'
            ? (uint8_t)'}'
            : (uint8_t)']';
        while (offset < message_size && depth != 0U) {
            const uint8_t value = message[offset];
            if (value == (uint8_t)'"') {
                if (!aqt_signer_json_skip_string(message, message_size, &offset)) {
                    return 0;
                }
            } else if (value == (uint8_t)'{' || value == (uint8_t)'[') {
                if (depth == AQT_ARRAY_LENGTH(closing)) {
                    return 0;
                }
                closing[depth++] = value == (uint8_t)'{' ? (uint8_t)'}' : (uint8_t)']';
                ++offset;
            } else if (value == (uint8_t)'}' || value == (uint8_t)']') {
                if (value != closing[depth - 1U]) {
                    return 0;
                }
                --depth;
                ++offset;
            } else {
                if (value == (uint8_t)' ' || value == (uint8_t)'\t'
                    || value == (uint8_t)'\r' || value == (uint8_t)'\n'
                    || value < UINT8_C(0x20)) {
                    return 0;
                }
                ++offset;
            }
        }
        if (depth != 0U) {
            return 0;
        }
    } else {
        const size_t primitive_start = offset;
        while (offset < message_size && message[offset] != (uint8_t)','
               && message[offset] != (uint8_t)'}') {
            const uint8_t value = message[offset];
            if (!((value >= (uint8_t)'0' && value <= (uint8_t)'9')
                  || (value >= (uint8_t)'a' && value <= (uint8_t)'z')
                  || value == (uint8_t)'-' || value == (uint8_t)'+'
                  || value == (uint8_t)'.')) {
                return 0;
            }
            ++offset;
        }
        if (offset == primitive_start) {
            return 0;
        }
    }
    *offset_io = offset;
    return 1;
}

static int
aqt_signer_json_has_exact_unique_top_level_field(
    const uint8_t *message,
    size_t message_size,
    const aqt_signer_message_rule *rule)
{
    const size_t required_key_size = strlen(rule->key);
    const size_t required_value_size = strlen(rule->encoded_value);
    size_t object_size;
    size_t offset = 1;
    unsigned int matching_key_count = 0;
    int exact_value = 0;

    if (message_size < 3U || message[message_size - 1U] != (uint8_t)'\n') {
        return 0;
    }
    object_size = message_size - 1U;
    if (message[0] != (uint8_t)'{' || message[object_size - 1U] != (uint8_t)'}') {
        return 0;
    }
    if (offset == object_size - 1U) {
        return 0;
    }
    while (offset < object_size - 1U) {
        size_t key_start;
        size_t key_end;
        size_t value_start;
        size_t value_end;
        int key_has_escape = 0;
        size_t scan;

        if (message[offset] != (uint8_t)'"') {
            return 0;
        }
        key_start = offset + 1U;
        if (!aqt_signer_json_skip_string(message, object_size, &offset)) {
            return 0;
        }
        key_end = offset - 1U;
        for (scan = key_start; scan < key_end; ++scan) {
            if (message[scan] == (uint8_t)'\\') {
                key_has_escape = 1;
            }
        }
        if (offset >= object_size || message[offset++] != (uint8_t)':') {
            return 0;
        }
        value_start = offset;
        if (!aqt_signer_json_skip_value(message, object_size, &offset)) {
            return 0;
        }
        value_end = offset;
        if (!key_has_escape && key_end - key_start == required_key_size
            && memcmp(message + key_start, rule->key, required_key_size) == 0) {
            ++matching_key_count;
            if (value_end - value_start == required_value_size
                && memcmp(
                    message + value_start,
                    rule->encoded_value,
                    required_value_size) == 0) {
                exact_value = 1;
            }
        }
        if (offset == object_size - 1U) {
            break;
        }
        if (offset >= object_size - 1U || message[offset++] != (uint8_t)',') {
            return 0;
        }
        if (offset >= object_size - 1U) {
            return 0;
        }
    }
    return offset == object_size - 1U
        && matching_key_count == 1U
        && exact_value != 0;
}

static int
aqt_signer_sign_domain(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const char *domain,
    const aqt_signer_message_rule *rules,
    size_t rule_count,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature_out[64])
{
    size_t domain_size;
    size_t signature_input_size;
    uint8_t *signature_input;
    int result;
    size_t rule_index;

    result = aqt_signer_require_owner(owner, interpreter_identity);
    if (result != 0) {
        return result;
    }
    if (message == NULL || signature_out == NULL || message_size == 0
        || message_size > AQT_TRUSTED_TIME_V2_SIGNER_MAXIMUM_MESSAGE_BYTES) {
        return EINVAL;
    }
    for (rule_index = 0; rule_index < rule_count; ++rule_index) {
        if (!aqt_signer_json_has_exact_unique_top_level_field(
                message,
                message_size,
                &rules[rule_index])) {
            return EINVAL;
        }
    }
    domain_size = strlen(domain);
    if (message_size > SIZE_MAX - domain_size - 1U) {
        return EOVERFLOW;
    }
    signature_input_size = domain_size + 1U + message_size;
    signature_input = (uint8_t *)malloc(signature_input_size);
    if (signature_input == NULL) {
        return ENOMEM;
    }
    (void)memcpy(signature_input, domain, domain_size);
    signature_input[domain_size] = 0;
    (void)memcpy(signature_input + domain_size + 1U, message, message_size);
    crypto_ed25519_sign(
        signature_out,
        owner->secret->secret_key,
        signature_input,
        signature_input_size
    );
    free(signature_input);
    return 0;
}

static int
aqt_signer_close_owner_directory(
    aqt_trusted_time_v2_signer_owner *owner,
    int test_fault_stage)
{
    aqt_signer_guarded_fd directory;
    int result;

    if (owner == NULL || owner->credential_directory_fd < 0) {
        return 0;
    }
    directory.descriptor = owner->credential_directory_fd;
    directory.slot = owner->credential_directory_slot;
    result = aqt_signer_guarded_fd_close(&directory, test_fault_stage);
    owner->credential_directory_fd = -1;
    owner->credential_directory_slot = AQT_SIGNER_INVALID_SLOT;
    return result;
}

static int
aqt_signer_revalidate_owner_resources(
    const aqt_trusted_time_v2_signer_owner *owner)
{
    aqt_signer_stat9 retained_identity;
    struct stat path_metadata;
    int result;

    if (owner == NULL || owner->credential_directory_fd < 0) {
        return EINVAL;
    }
    result = aqt_signer_fstat9(
        owner->credential_directory_fd,
        &retained_identity
    );
    if (result != 0) {
        return result;
    }
    if (!aqt_signer_stat9_equal(
            &owner->credential_directory_identity,
            &retained_identity)) {
        return ESTALE;
    }
    errno = 0;
    if (fstatat(
            owner->credential_directory_fd,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW) == 0) {
        return EPERM;
    }
    if (errno != ENOENT) {
        return aqt_signer_errno_or_io();
    }
    if (owner->mount_admission == NULL) {
        return 0;
    }
#if defined(__linux__)
    {
        aqt_signer_guarded_fd reopened_directory;
        aqt_signer_stat9 reopened_identity;
        int cleanup_result;

        aqt_signer_guarded_fd_initialize(&reopened_directory);
        result = aqt_trusted_time_v2_secret_mount_admission_revalidate(
            owner->mount_admission,
            owner->credential_directory_fd,
            owner->interpreter_identity
        );
        if (result != 0) {
            return result;
        }
        result = aqt_signer_open_literal_credential_directory(
            &reopened_directory,
            &reopened_identity
        );
        if (result == 0) {
            result = aqt_trusted_time_v2_secret_mount_admission_revalidate(
                owner->mount_admission,
                reopened_directory.descriptor,
                owner->interpreter_identity
            );
        }
        if (result == 0
            && !aqt_signer_stat9_equal(
                &owner->credential_directory_identity,
                &reopened_identity)) {
            result = ESTALE;
        }
        cleanup_result = aqt_signer_guarded_fd_close(&reopened_directory, 0);
        if (cleanup_result != 0) {
            return cleanup_result;
        }
        return result;
    }
#else
    return ENOTSUP;
#endif
}

static int
aqt_signer_dispose_owner(
    aqt_trusted_time_v2_signer_owner *owner,
    int test_fault_stage)
{
    int cleanup_result;
    int admission_result;

    if (owner == NULL) {
        return 0;
    }
    aqt_signer_burn_secret(&owner->secret, owner->secret_mapping_size);
    cleanup_result = aqt_signer_close_owner_directory(owner, test_fault_stage);
    admission_result = aqt_trusted_time_v2_secret_mount_admission_close(
        &owner->mount_admission,
        owner->interpreter_identity
    );
    crypto_wipe(owner, sizeof(*owner));
    free(owner);
    return cleanup_result != 0 ? cleanup_result : admission_result;
}

static int AQT_SIGNER_MAYBE_UNUSED
aqt_signer_owner_open_guarded_internal(
    aqt_trusted_time_v2_signer_owner **owner_out,
    aqt_signer_guarded_fd *credential_directory,
    aqt_signer_guarded_fd *credential,
    const uint8_t expected_public_key[32],
    uintptr_t interpreter_identity,
    aqt_trusted_time_v2_secret_mount_admission **mount_admission_io)
{
    aqt_trusted_time_v2_signer_owner *owner = NULL;
    aqt_signer_secret_mapping *secret = NULL;
    struct stat directory_metadata;
    struct stat descriptor_metadata_before;
    struct stat path_metadata;
    struct stat descriptor_metadata_after;
    struct stat unlinked_metadata;
    aqt_signer_stat9 credential_identity;
    aqt_signer_stat9 current_credential_identity;
    aqt_signer_stat9 current_path_identity;
    aqt_signer_stat9 post_unlink_directory_identity;
    uint8_t extra_byte = 0;
    int result = 0;
    int cleanup_result;
    ssize_t read_size;

    if (credential_directory == NULL || credential == NULL
        || mount_admission_io == NULL) {
        return EINVAL;
    }
    if (owner_out == NULL || *owner_out != NULL || expected_public_key == NULL
        || interpreter_identity == (uintptr_t)0
        || credential_directory->descriptor < 0 || credential->descriptor < 0
        || credential_directory->descriptor == credential->descriptor) {
        result = EINVAL;
        goto fail;
    }
    if (atomic_load_explicit(&aqt_signer_state, memory_order_acquire)
        != AQT_SIGNER_INITIALIZED) {
        result = EPERM;
        goto fail;
    }
    if (fstat(credential_directory->descriptor, &directory_metadata) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    if (!aqt_signer_validate_directory_metadata(&directory_metadata)) {
        result = EPERM;
        goto fail;
    }
    if (fstat(credential->descriptor, &descriptor_metadata_before) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    if (!aqt_signer_validate_credential_metadata(&descriptor_metadata_before)) {
        result = EPERM;
        goto fail;
    }
    if (descriptor_metadata_before.st_dev != directory_metadata.st_dev) {
        result = EXDEV;
        goto fail;
    }
    if (fstatat(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    if (!aqt_signer_metadata_matches(&descriptor_metadata_before, &path_metadata)) {
        result = ESTALE;
        goto fail;
    }
    result = aqt_signer_fstat9(credential->descriptor, &credential_identity);
    if (result == 0) {
        result = aqt_signer_fstatat9(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &current_path_identity
        );
    }
    if (result != 0
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_path_identity)) {
        result = result == 0 ? ESTALE : result;
        goto fail;
    }
    result = aqt_signer_allocate_secret(&secret);
    if (result != 0) {
        goto fail;
    }
    read_size = pread(
        credential->descriptor,
        secret->seed,
        sizeof(secret->seed),
        (off_t)0
    );
    if (read_size != (ssize_t)sizeof(secret->seed)) {
        result = read_size < 0 ? aqt_signer_errno_or_io() : EIO;
        goto fail;
    }
    read_size = pread(
        credential->descriptor,
        &extra_byte,
        1U,
        (off_t)sizeof(secret->seed)
    );
    if (read_size != 0) {
        result = read_size < 0 ? aqt_signer_errno_or_io() : EIO;
        goto fail;
    }
    crypto_wipe(&extra_byte, sizeof(extra_byte));
    aqt_signer_maybe_pause_after_first_seed_read();
    result = aqt_signer_fstat9(
        credential->descriptor,
        &current_credential_identity
    );
    if (result == 0) {
        result = aqt_signer_fstatat9(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &current_path_identity
        );
    }
    if (result != 0
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_credential_identity)
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_path_identity)) {
        result = result == 0 ? ESTALE : result;
        goto fail;
    }
    read_size = pread(
        credential->descriptor,
        secret->verification_seed,
        sizeof(secret->verification_seed),
        (off_t)0
    );
    if (read_size != (ssize_t)sizeof(secret->verification_seed)) {
        result = read_size < 0 ? aqt_signer_errno_or_io() : EIO;
        goto fail;
    }
    read_size = pread(
        credential->descriptor,
        &extra_byte,
        1U,
        (off_t)sizeof(secret->verification_seed)
    );
    if (read_size != 0) {
        result = read_size < 0 ? aqt_signer_errno_or_io() : EIO;
        goto fail;
    }
    crypto_wipe(&extra_byte, sizeof(extra_byte));
    result = aqt_signer_fstat9(
        credential->descriptor,
        &current_credential_identity
    );
    if (result == 0) {
        result = aqt_signer_fstatat9(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &current_path_identity
        );
    }
    if (result != 0
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_credential_identity)
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_path_identity)
        || !aqt_signer_bytes_equal(
            secret->seed,
            secret->verification_seed,
            sizeof(secret->seed))) {
        result = result == 0 ? ESTALE : result;
        goto fail;
    }
    owner = (aqt_trusted_time_v2_signer_owner *)calloc(1, sizeof(*owner));
    if (owner == NULL) {
        result = ENOMEM;
        goto fail;
    }
    owner->credential_directory_fd = -1;
    owner->credential_directory_slot = AQT_SIGNER_INVALID_SLOT;
    crypto_ed25519_key_pair(secret->secret_key, owner->public_key, secret->seed);
    crypto_wipe(secret->seed, sizeof(secret->seed));
    crypto_wipe(secret->verification_seed, sizeof(secret->verification_seed));
    if (!aqt_signer_bytes_equal(owner->public_key, expected_public_key, 32U)) {
        result = EACCES;
        goto fail;
    }
    if (fstat(credential->descriptor, &descriptor_metadata_after) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    if (!aqt_signer_metadata_matches(
            &descriptor_metadata_before,
            &descriptor_metadata_after)) {
        result = ESTALE;
        goto fail;
    }
    if (*mount_admission_io != NULL) {
        result = aqt_trusted_time_v2_secret_mount_admission_revalidate(
            *mount_admission_io,
            credential_directory->descriptor,
            interpreter_identity
        );
        if (result != 0) {
            goto fail;
        }
    }
    result = aqt_signer_fstat9(
        credential->descriptor,
        &current_credential_identity
    );
    if (result == 0) {
        result = aqt_signer_fstatat9(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &current_path_identity
        );
    }
    if (result != 0
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_credential_identity)
        || !aqt_signer_stat9_equal(
            &credential_identity,
            &current_path_identity)) {
        result = result == 0 ? ESTALE : result;
        goto fail;
    }
    if (fstatat(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    if (!aqt_signer_metadata_matches(&descriptor_metadata_after, &path_metadata)) {
        result = ESTALE;
        goto fail;
    }
    if (unlinkat(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            0) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    errno = 0;
    if (fstatat(
            credential_directory->descriptor,
            AQT_SIGNER_CREDENTIAL_BASENAME,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW) == 0
        || errno != ENOENT) {
        result = errno == 0 ? EPERM : aqt_signer_errno_or_io();
        goto fail;
    }
    if (fstat(credential->descriptor, &unlinked_metadata) != 0) {
        result = aqt_signer_errno_or_io();
        goto fail;
    }
    if (unlinked_metadata.st_dev != descriptor_metadata_before.st_dev
        || unlinked_metadata.st_ino != descriptor_metadata_before.st_ino
        || unlinked_metadata.st_nlink != (nlink_t)0) {
        result = ESTALE;
        goto fail;
    }
    result = aqt_signer_fstat9(
        credential_directory->descriptor,
        &post_unlink_directory_identity
    );
    if (result != 0) {
        goto fail;
    }
    if (*mount_admission_io != NULL) {
        result = aqt_trusted_time_v2_secret_mount_admission_close(
            mount_admission_io,
            interpreter_identity
        );
        if (result == 0) {
            result = aqt_trusted_time_v2_secret_mount_admission_capture(
                mount_admission_io,
                credential_directory->descriptor,
                interpreter_identity
            );
        }
        if (result != 0) {
            goto fail;
        }
    }
    result = aqt_trusted_time_v2_fork_guard_capture_identity(&owner->fork_identity);
    if (result != 0) {
        goto fail;
    }
    owner->interpreter_identity = interpreter_identity;
    owner->secret = secret;
    owner->secret_mapping_size = sizeof(*secret);
    owner->credential_directory_fd = credential_directory->descriptor;
    owner->credential_directory_slot = credential_directory->slot;
    owner->credential_directory_identity = post_unlink_directory_identity;
    owner->mount_admission = *mount_admission_io;
    *mount_admission_io = NULL;
    secret = NULL;
    aqt_signer_guarded_fd_initialize(credential_directory);
    cleanup_result = aqt_signer_guarded_fd_close(
        credential,
        AQT_TRUSTED_TIME_V2_SIGNER_TEST_CLOSE_CREDENTIAL
    );
    if (cleanup_result != 0) {
        result = cleanup_result;
        goto fail;
    }
    result = aqt_signer_revalidate_owner_resources(owner);
    if (result != 0) {
        goto fail;
    }
    *owner_out = owner;
    return 0;

fail:
    crypto_wipe(&extra_byte, sizeof(extra_byte));
    aqt_signer_burn_secret(&secret, sizeof(*secret));
    cleanup_result = aqt_signer_guarded_fd_close(
        credential,
        AQT_TRUSTED_TIME_V2_SIGNER_TEST_CLOSE_CREDENTIAL
    );
    if (cleanup_result != 0) {
        result = cleanup_result;
    }
    cleanup_result = aqt_signer_guarded_fd_close(credential_directory, 0);
    if (cleanup_result != 0) {
        result = cleanup_result;
    }
    cleanup_result = aqt_trusted_time_v2_secret_mount_admission_close(
        mount_admission_io,
        interpreter_identity
    );
    if (cleanup_result != 0) {
        result = cleanup_result;
    }
    cleanup_result = aqt_signer_dispose_owner(owner, 0);
    if (cleanup_result != 0) {
        result = cleanup_result;
    }
    return result == 0 ? EIO : result;
}

#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TEST_PROFILE
int
aqt_trusted_time_v2_signer_owner_open_preopened(
    aqt_trusted_time_v2_signer_owner **owner_out,
    int credential_directory_fd,
    int credential_fd,
    const uint8_t expected_public_key[32],
    uintptr_t interpreter_identity)
{
    aqt_signer_guarded_fd directory;
    aqt_signer_guarded_fd credential;
    aqt_trusted_time_v2_secret_mount_admission *mount_admission = NULL;
    int result;

    aqt_signer_guarded_fd_initialize(&directory);
    aqt_signer_guarded_fd_initialize(&credential);
    if (credential_directory_fd < 0 || credential_fd < 0
        || credential_directory_fd == credential_fd) {
        if (credential_directory_fd >= 0) {
            (void)close(credential_directory_fd);
        }
        if (credential_fd >= 0 && credential_fd != credential_directory_fd) {
            (void)close(credential_fd);
        }
        return EINVAL;
    }
    result = aqt_signer_guarded_fd_adopt(credential_directory_fd, &directory);
    if (result != 0) {
        (void)close(credential_fd);
        return result;
    }
    result = aqt_signer_guarded_fd_adopt(credential_fd, &credential);
    if (result != 0) {
        (void)aqt_signer_guarded_fd_close(&directory, 0);
        return result;
    }
    return aqt_signer_owner_open_guarded_internal(
        owner_out,
        &directory,
        &credential,
        expected_public_key,
        interpreter_identity,
        &mount_admission
    );
}
#else
int
aqt_trusted_time_v2_signer_owner_open(
    aqt_trusted_time_v2_signer_owner **owner_out,
    const uint8_t expected_public_key[32],
    uintptr_t interpreter_identity)
{
    if (owner_out == NULL || *owner_out != NULL || expected_public_key == NULL
        || interpreter_identity == (uintptr_t)0) {
        return EINVAL;
    }
#if defined(__linux__)
    {
        aqt_signer_guarded_fd directory;
        aqt_signer_guarded_fd credential;
        aqt_signer_stat9 directory_identity;
        aqt_signer_stat9 credential_identity;
        aqt_trusted_time_v2_secret_mount_admission *mount_admission = NULL;
        int result;

        aqt_signer_guarded_fd_initialize(&directory);
        aqt_signer_guarded_fd_initialize(&credential);
        result = aqt_signer_open_literal_credential_directory(
            &directory,
            &directory_identity
        );
        if (result == 0) {
            result = aqt_trusted_time_v2_secret_mount_admission_capture(
                &mount_admission,
                directory.descriptor,
                interpreter_identity
            );
        }
        if (result == 0) {
            result = aqt_signer_open_correlated_child(
                &directory,
                aqt_signer_production_credential_basename,
                O_RDONLY | O_NONBLOCK,
                &credential,
                &credential_identity
            );
        }
        if (result != 0) {
            (void)aqt_trusted_time_v2_secret_mount_admission_close(
                &mount_admission,
                interpreter_identity
            );
            (void)aqt_signer_guarded_fd_close(&credential, 0);
            (void)aqt_signer_guarded_fd_close(&directory, 0);
            return result;
        }
        (void)credential_identity;
        return aqt_signer_owner_open_guarded_internal(
            owner_out,
            &directory,
            &credential,
            expected_public_key,
            interpreter_identity,
            &mount_admission
        );
    }
#else
    return ENOTSUP;
#endif
}
#endif

int
aqt_trusted_time_v2_signer_owner_read_public_key(
    const aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    uint8_t public_key_out[32])
{
    int result = aqt_signer_require_owner(owner, interpreter_identity);

    if (result != 0) {
        return result;
    }
    if (public_key_out == NULL) {
        return EINVAL;
    }
    (void)memcpy(public_key_out, owner->public_key, 32);
    return 0;
}

int
aqt_trusted_time_v2_signer_owner_close(
    aqt_trusted_time_v2_signer_owner **owner_io,
    uintptr_t interpreter_identity)
{
    aqt_trusted_time_v2_signer_owner *owner;
    int result;
    int cleanup_result;

    if (owner_io == NULL) {
        return EINVAL;
    }
    owner = *owner_io;
    if (owner == NULL) {
        return 0;
    }
    result = aqt_signer_require_owner(owner, interpreter_identity);
    if (result != 0) {
        if (owner->fork_identity.origin_pid != getpid()
            || owner->fork_identity.fork_epoch
                != aqt_trusted_time_v2_fork_guard_current_epoch()
            || pthread_equal(owner->fork_identity.origin_thread, pthread_self()) == 0
            || owner->interpreter_identity != interpreter_identity) {
            return result;
        }
    }
    if (result == 0) {
        result = aqt_signer_revalidate_owner_resources(owner);
    }
    cleanup_result = aqt_signer_dispose_owner(
        owner,
        AQT_TRUSTED_TIME_V2_SIGNER_TEST_CLOSE_DIRECTORY
    );
    *owner_io = NULL;
    return cleanup_result != 0 ? cleanup_result : result;
}

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
int
aqt_trusted_time_v2_signer_sign_host_hello(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-host-hello-v2\""},
        {"direction", "\"host_to_supervisor\""},
        {"status", "\"host_hello_offered\""},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/host-hello/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}

int
aqt_trusted_time_v2_signer_sign_host_channel_confirmation(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-host-channel-confirmation-v2\""},
        {"direction", "\"host_to_supervisor\""},
        {"status", "\"host_channel_confirmed\""},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/host-channel-confirmation/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}

int
aqt_trusted_time_v2_signer_sign_clean_stop_request(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\""},
        {"direction", "\"host_to_supervisor\""},
        {"frame_type", "\"clean_stop_request\""},
        {"message_counter", "2"},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE)
int
aqt_trusted_time_v2_signer_sign_supervisor_hello(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-supervisor-hello-v2\""},
        {"direction", "\"supervisor_to_host\""},
        {"status", "\"supervisor_hello_accepted\""},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/supervisor-hello/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}

int
aqt_trusted_time_v2_signer_sign_clean_stop_result(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\""},
        {"direction", "\"supervisor_to_host\""},
        {"frame_type", "\"clean_stop_result\""},
        {"message_counter", "1"},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}

int
aqt_trusted_time_v2_signer_sign_clean_stop_error(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\""},
        {"direction", "\"supervisor_to_host\""},
        {"frame_type", "\"clean_stop_error\""},
        {"message_counter", "1"},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}

int
aqt_trusted_time_v2_signer_sign_supervisor_cleanup_commitment(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-supervisor-transport-cleanup-commitment-v2\""},
        {"service", "\"trusted-time-graceful-stop-transport-v2\""},
        {"status", "\"supervisor_transport_cleanup_committed\""},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/supervisor-transport-cleanup-commitment/v2",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE)
int
aqt_trusted_time_v2_signer_sign_recovery_classification(
    aqt_trusted_time_v2_signer_owner *owner, uintptr_t interpreter_identity,
    const uint8_t *message, size_t message_size, uint8_t signature_out[64])
{
    static const aqt_signer_message_rule rules[] = {
        {"contract_version", "\"phase6d-trusted-time-graceful-stop-recovery-classification-envelope-v1\""},
        {"service", "\"trusted-time-post-enrollment-graceful-stop-lifecycle-v2\""},
        {"status", "\"recovery_classification_requested\""},
    };
    return aqt_signer_sign_domain(
        owner, interpreter_identity,
        "AutoQuantTrader/trusted-time/graceful-stop/recovery-classification/v1",
        rules, AQT_ARRAY_LENGTH(rules),
        message, message_size, signature_out
    );
}
#endif

#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TESTING
int
aqt_trusted_time_v2_signer_test_last_close_zeroized(void)
{
    return atomic_load_explicit(&aqt_signer_test_zeroized, memory_order_acquire);
}

int
aqt_trusted_time_v2_signer_test_fork_secret_is_zero(
    const aqt_trusted_time_v2_signer_owner *owner)
{
    size_t index;

    if (owner == NULL || owner->secret == NULL) {
        return 0;
    }
    for (index = 0; index < owner->secret_mapping_size; ++index) {
        if (((const volatile uint8_t *)owner->secret)[index] != 0) {
            return 0;
        }
    }
    return 1;
}

int
aqt_trusted_time_v2_signer_test_directory_is_closed_after_fork(
    const aqt_trusted_time_v2_signer_owner *owner)
{
    if (owner == NULL || owner->credential_directory_fd < 0) {
        return 0;
    }
    errno = 0;
    return fcntl(owner->credential_directory_fd, F_GETFD) == -1
        && errno == EBADF;
}

void
aqt_trusted_time_v2_signer_test_fail_next_guarded_close(int stage)
{
    if (stage != AQT_TRUSTED_TIME_V2_SIGNER_TEST_CLOSE_CREDENTIAL
        && stage != AQT_TRUSTED_TIME_V2_SIGNER_TEST_CLOSE_DIRECTORY) {
        stage = 0;
    }
    atomic_store_explicit(
        &aqt_signer_test_close_fault,
        stage,
        memory_order_release
    );
}

void
aqt_trusted_time_v2_signer_test_pause_after_first_seed_read(void)
{
    atomic_store_explicit(
        &aqt_signer_test_pause_seed_read,
        1,
        memory_order_release
    );
}

int
aqt_trusted_time_v2_signer_test_first_seed_read_is_paused(void)
{
    return atomic_load_explicit(
        &aqt_signer_test_seed_read_paused,
        memory_order_acquire
    );
}

void
aqt_trusted_time_v2_signer_test_resume_after_first_seed_read(void)
{
    atomic_store_explicit(
        &aqt_signer_test_pause_seed_read,
        0,
        memory_order_release
    );
}
#endif
