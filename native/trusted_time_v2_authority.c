#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "trusted_time_v2_authority.h"

#include "trusted_time_v2_fork_guard.h"

#include "monocypher-ed25519.h"
#include "monocypher.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/syscall.h>
#endif

#ifndef EKEYREJECTED
#define EKEYREJECTED EACCES
#endif
#ifndef ENOKEY
#define ENOKEY EACCES
#endif

#if (defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)) > 1
#error "compile at most one trusted-time v2 authority provisioner role"
#endif

#define AQT_AUTHORITY_DIRECTORY \
    "/opt/autoquant/trusted-time/authorities/graceful-stop-v2"
#define AQT_ROOT_KEY_BASENAME "root-ed25519.pub"
#define AQT_SELECTION_HEAD_BASENAME "selection.json"
#define AQT_AUTHORITY_MAXIMUM_BYTES (64U * 1024U)
#define AQT_GENERATION_MAXIMUM 99999999U
#define AQT_IDENTIFIER_MAXIMUM_BYTES 128U
#define AQT_AUTHORITY_NAME_MAXIMUM_BYTES 192U
#define AQT_AUTHORITY_MAXIMUM_CHAIN_FILES 256U
#define AQT_AUTHORITY_MAXIMUM_AGGREGATE_BYTES \
    (((uint64_t)AQT_AUTHORITY_MAXIMUM_CHAIN_FILES + 1U) \
     * (uint64_t)AQT_AUTHORITY_MAXIMUM_BYTES + AQT_PUBLIC_KEY_BYTES)
#define AQT_SIGNATURE_BYTES 64U
#define AQT_PUBLIC_KEY_BYTES 32U
#define AQT_SHA256_BYTES 32U
#define AQT_MANIFEST_DOMAIN \
    "AutoQuantTrader/trusted-time/graceful-stop/transport-authority/v1"
#define AQT_SELECTION_DOMAIN \
    "AutoQuantTrader/trusted-time/graceful-stop/transport-authority-selection/v1"
#define AQT_MANIFEST_CONTRACT \
    "phase6d-trusted-time-graceful-stop-transport-authority-v1"
#define AQT_SELECTION_CONTRACT \
    "phase6d-trusted-time-graceful-stop-transport-authority-selection-v1"
#define AQT_TRANSPORT_SERVICE "trusted-time-graceful-stop-transport-v2"

#if defined(__GNUC__) || defined(__clang__)
#define AQT_AUTHORITY_MAYBE_UNUSED __attribute__((unused))
#else
#define AQT_AUTHORITY_MAYBE_UNUSED
#endif

static const char aqt_authority_directory_literal[] AQT_AUTHORITY_MAYBE_UNUSED =
    AQT_AUTHORITY_DIRECTORY;

/*
 * ADR 0121 fixes the path and key identity relationship but does not contain a
 * reviewed release public key value.  A candidate therefore has no production
 * root pin and fails closed before opening the authority directory.  The test
 * pin is the public key for the repository's deterministic contract fixture;
 * it is never compiled unless the explicit test-only macro is present.
 */
#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_ROOT_PIN
#define AQT_AUTHORITY_ROOT_PIN_AVAILABLE 1
static const char aqt_reviewed_root_key_id[] =
    "trusted-time-transport-root-ed25519-v1";
static const unsigned char aqt_reviewed_root_public_key[AQT_PUBLIC_KEY_BYTES] = {
    0x03U, 0xa1U, 0x07U, 0xbfU, 0xf3U, 0xceU, 0x10U, 0xbeU,
    0x1dU, 0x70U, 0xddU, 0x18U, 0xe7U, 0x4bU, 0xc0U, 0x99U,
    0x67U, 0xe4U, 0xd6U, 0x30U, 0x9bU, 0xa5U, 0x0dU, 0x5fU,
    0x1dU, 0xdcU, 0x86U, 0x64U, 0x12U, 0x55U, 0x31U, 0xb8U,
};
static const unsigned char aqt_reviewed_root_public_key_sha256[AQT_SHA256_BYTES] = {
    0x56U, 0x47U, 0x5aU, 0xa7U, 0x54U, 0x63U, 0x47U, 0x4cU,
    0x02U, 0x85U, 0xdfU, 0x5dU, 0xbfU, 0x2bU, 0xcaU, 0xb7U,
    0x3dU, 0xa6U, 0x51U, 0x35U, 0x88U, 0x39U, 0xe9U, 0xb7U,
    0x74U, 0x81U, 0xb2U, 0xeaU, 0xb1U, 0x07U, 0x70U, 0x8cU,
};
static const char aqt_reviewed_environment[] = "test";
#else
#define AQT_AUTHORITY_ROOT_PIN_AVAILABLE 0
/* Unreachable parser sentinels, deliberately not an operational root pin. */
static const char aqt_reviewed_root_key_id[] = "release-root-pin-absent";
static const unsigned char aqt_reviewed_root_public_key[AQT_PUBLIC_KEY_BYTES] = {0U};
static const unsigned char aqt_reviewed_root_public_key_sha256[AQT_SHA256_BYTES] = {0U};
static const char aqt_reviewed_environment[] = "release-environment-pin-absent";
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char buffer[64];
    size_t buffer_used;
} AqtAuthoritySha256Context;

typedef struct {
    struct stat metadata;
    unsigned char *bytes;
    size_t size;
    unsigned char sha256[AQT_SHA256_BYTES];
} AqtAuthorityLoadedFile;

typedef struct {
    uint32_t generation;
    int predecessor_present;
    unsigned char predecessor_sha256[AQT_SHA256_BYTES];
    char environment[AQT_IDENTIFIER_MAXIMUM_BYTES + 1U];
    char root_key_id[AQT_IDENTIFIER_MAXIMUM_BYTES + 1U];
    char host_key_id[AQT_IDENTIFIER_MAXIMUM_BYTES + 1U];
    char supervisor_key_id[AQT_IDENTIFIER_MAXIMUM_BYTES + 1U];
    char recovery_key_id[AQT_IDENTIFIER_MAXIMUM_BYTES + 1U];
    unsigned char host_public_key[AQT_PUBLIC_KEY_BYTES];
    unsigned char supervisor_public_key[AQT_PUBLIC_KEY_BYTES];
    unsigned char recovery_public_key[AQT_PUBLIC_KEY_BYTES];
    unsigned char signature[AQT_SIGNATURE_BYTES];
    unsigned char sha256[AQT_SHA256_BYTES];
    size_t signature_field_start;
    size_t signature_field_end;
} AqtAuthorityManifest;

typedef struct {
    uint32_t sequence;
    int disposition_selected;
    int selected_present;
    uint32_t selected_generation;
    unsigned char selected_manifest_sha256[AQT_SHA256_BYTES];
    int recovery_present;
    unsigned char recovery_manifest_sha256[AQT_SHA256_BYTES];
    int predecessor_present;
    unsigned char predecessor_sha256[AQT_SHA256_BYTES];
    char environment[AQT_IDENTIFIER_MAXIMUM_BYTES + 1U];
    char reason_code[32];
    unsigned char signature[AQT_SIGNATURE_BYTES];
    unsigned char sha256[AQT_SHA256_BYTES];
    size_t signature_field_start;
    size_t signature_field_end;
} AqtAuthoritySelection;

typedef struct {
    const unsigned char *bytes;
    size_t size;
    size_t offset;
} AqtAuthorityJsonCursor;

typedef struct {
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration generation;
    aqt_trusted_time_v2_fork_identity identity;
    uint64_t guard_epoch;
    uintptr_t interpreter_identity;
    _Atomic int consumed;
} AqtAuthorityGenerationSeal;

static _Atomic int aqt_authority_consumption_state = 0;
static const unsigned char aqt_native_interpreter_instance_capability = 0x5aU;

#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING
static _Atomic int aqt_test_pause_requested = 0;
static _Atomic int aqt_test_read_paused = 0;
static _Atomic int aqt_test_read_resume = 0;
static _Atomic int aqt_test_identity_fault = 0;
#endif

static uint32_t
aqt_rotate_right(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32U - count));
}

static uint32_t
aqt_load_be32(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24U)
        | ((uint32_t)value[1] << 16U)
        | ((uint32_t)value[2] << 8U)
        | (uint32_t)value[3];
}

static void
aqt_store_be32(unsigned char *destination, uint32_t value)
{
    destination[0] = (unsigned char)(value >> 24U);
    destination[1] = (unsigned char)(value >> 16U);
    destination[2] = (unsigned char)(value >> 8U);
    destination[3] = (unsigned char)value;
}

static void
aqt_sha256_transform(AqtAuthoritySha256Context *context, const unsigned char block[64])
{
    static const uint32_t constants[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    };
    uint32_t words[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    size_t index;

    for (index = 0U; index < 16U; index++) {
        words[index] = aqt_load_be32(block + (index * 4U));
    }
    for (index = 16U; index < 64U; index++) {
        uint32_t left = words[index - 15U];
        uint32_t right = words[index - 2U];
        uint32_t sigma0 = aqt_rotate_right(left, 7U)
            ^ aqt_rotate_right(left, 18U) ^ (left >> 3U);
        uint32_t sigma1 = aqt_rotate_right(right, 17U)
            ^ aqt_rotate_right(right, 19U) ^ (right >> 10U);
        words[index] = words[index - 16U] + sigma0
            + words[index - 7U] + sigma1;
    }
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];
    for (index = 0U; index < 64U; index++) {
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t big0 = aqt_rotate_right(a, 2U)
            ^ aqt_rotate_right(a, 13U) ^ aqt_rotate_right(a, 22U);
        uint32_t big1 = aqt_rotate_right(e, 6U)
            ^ aqt_rotate_right(e, 11U) ^ aqt_rotate_right(e, 25U);
        uint32_t temporary1 = h + big1 + choice + constants[index] + words[index];
        uint32_t temporary2 = big0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void
aqt_sha256_initialize(AqtAuthoritySha256Context *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };

    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0U;
    context->buffer_used = 0U;
    memset(context->buffer, 0, sizeof(context->buffer));
}

static int
aqt_sha256_update(
    AqtAuthoritySha256Context *context,
    const unsigned char *payload,
    size_t size
)
{
    size_t offset = 0U;

    if (context == NULL || (payload == NULL && size != 0U)
        || size > (UINT64_MAX - context->bit_count) / 8U) {
        return EINVAL;
    }
    context->bit_count += (uint64_t)size * 8U;
    while (offset < size) {
        size_t available = sizeof(context->buffer) - context->buffer_used;
        size_t amount = size - offset < available ? size - offset : available;
        memcpy(context->buffer + context->buffer_used, payload + offset, amount);
        context->buffer_used += amount;
        offset += amount;
        if (context->buffer_used == sizeof(context->buffer)) {
            aqt_sha256_transform(context, context->buffer);
            context->buffer_used = 0U;
        }
    }
    return 0;
}

static void
aqt_sha256_finish(
    AqtAuthoritySha256Context *context,
    unsigned char digest[AQT_SHA256_BYTES]
)
{
    uint64_t bits = context->bit_count;
    size_t index;

    context->buffer[context->buffer_used++] = 0x80U;
    if (context->buffer_used > 56U) {
        memset(context->buffer + context->buffer_used, 0, 64U - context->buffer_used);
        aqt_sha256_transform(context, context->buffer);
        context->buffer_used = 0U;
    }
    memset(context->buffer + context->buffer_used, 0, 56U - context->buffer_used);
    for (index = 0U; index < 8U; index++) {
        context->buffer[63U - index] = (unsigned char)(bits >> (index * 8U));
    }
    aqt_sha256_transform(context, context->buffer);
    for (index = 0U; index < 8U; index++) {
        aqt_store_be32(digest + (index * 4U), context->state[index]);
    }
    crypto_wipe(context, sizeof(*context));
}

static int
aqt_sha256(
    const unsigned char *payload,
    size_t size,
    unsigned char digest[AQT_SHA256_BYTES]
)
{
    AqtAuthoritySha256Context context;

    aqt_sha256_initialize(&context);
    if (aqt_sha256_update(&context, payload, size) != 0) {
        crypto_wipe(&context, sizeof(context));
        return EINVAL;
    }
    aqt_sha256_finish(&context, digest);
    return 0;
}

static int
aqt_stat_equal(const struct stat *left, const struct stat *right)
{
    int timestamps_equal;

#ifdef __APPLE__
    timestamps_equal = left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
        && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
        && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
        && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#else
    timestamps_equal = left->st_mtim.tv_sec == right->st_mtim.tv_sec
        && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec
        && left->st_ctim.tv_sec == right->st_ctim.tv_sec
        && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#endif
    return timestamps_equal
        && left->st_dev == right->st_dev
        && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode
        && left->st_nlink == right->st_nlink
        && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid
        && left->st_size == right->st_size;
}

static int
aqt_expected_owner(const struct stat *metadata)
{
#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING
    return metadata->st_uid == geteuid();
#else
    return metadata->st_uid == 0 && metadata->st_gid == 0;
#endif
}

static int
aqt_directory_metadata_valid(const struct stat *metadata)
{
    return S_ISDIR(metadata->st_mode)
        && aqt_expected_owner(metadata)
        && (metadata->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0;
}

static int
aqt_file_metadata_valid(const struct stat *metadata, size_t maximum_size)
{
    return S_ISREG(metadata->st_mode)
        && metadata->st_nlink == 1
        && aqt_expected_owner(metadata)
        && (metadata->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) == 0
        && metadata->st_size > 0
        && (uintmax_t)metadata->st_size <= (uintmax_t)maximum_size;
}

static int
aqt_close_tracked(int descriptor, uint32_t slot)
{
    int result;

    if (descriptor < 0) {
        return 0;
    }
    result = aqt_trusted_time_v2_fork_guard_close_fd(slot, descriptor);
    return result == 0 ? 0 : result;
}

static int
aqt_open_tracked_at(
    int directory_descriptor,
    const char *basename,
    int flags,
    int *descriptor_out,
    uint32_t *slot_out
)
{
    int descriptor;
    int result;

    if (basename == NULL || descriptor_out == NULL || slot_out == NULL) {
        return EINVAL;
    }
    descriptor = openat(directory_descriptor, basename, flags | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 3) {
        int open_result = descriptor < 0 && errno != 0 ? errno : EBADF;
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return open_result;
    }
    result = aqt_trusted_time_v2_fork_guard_register_fd(descriptor, slot_out);
    if (result != 0) {
        (void)close(descriptor);
        return result;
    }
    *descriptor_out = descriptor;
    return 0;
}

#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING
static void
aqt_maybe_pause_after_read(void)
{
    if (atomic_load(&aqt_test_pause_requested) == 0) {
        return;
    }
    atomic_store(&aqt_test_read_paused, 1);
    while (atomic_load(&aqt_test_read_resume) == 0) {
        (void)sched_yield();
    }
    atomic_store(&aqt_test_read_paused, 0);
}
#else
static void
aqt_maybe_pause_after_read(void)
{
}
#endif

static void
aqt_loaded_file_dispose(AqtAuthorityLoadedFile *loaded)
{
    if (loaded == NULL) {
        return;
    }
    if (loaded->bytes != NULL) {
        crypto_wipe(loaded->bytes, loaded->size);
        free(loaded->bytes);
    }
    crypto_wipe(loaded, sizeof(*loaded));
}

static int
aqt_load_file(
    int directory_descriptor,
    const char *basename,
    size_t maximum_size,
    AqtAuthorityLoadedFile *destination
)
{
    int descriptor = -1;
    uint32_t slot = 0U;
    struct stat initial;
    struct stat path_metadata;
    struct stat final;
    unsigned char *bytes = NULL;
    size_t offset = 0U;
    int result;

    if (destination == NULL) {
        return EINVAL;
    }
    memset(destination, 0, sizeof(*destination));
    result = aqt_open_tracked_at(
        directory_descriptor,
        basename,
        O_RDONLY,
        &descriptor,
        &slot
    );
    if (result != 0) {
        return result;
    }
    if (fstat(descriptor, &initial) != 0
        || fstatat(
            directory_descriptor,
            basename,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW
        ) != 0
        || !aqt_stat_equal(&initial, &path_metadata)
        || !aqt_file_metadata_valid(&initial, maximum_size)) {
        result = EACCES;
        goto cleanup;
    }
    bytes = (unsigned char *)calloc((size_t)initial.st_size + 1U, 1U);
    if (bytes == NULL) {
        result = ENOMEM;
        goto cleanup;
    }
    while (offset < (size_t)initial.st_size) {
        ssize_t amount = read(descriptor, bytes + offset, (size_t)initial.st_size - offset);
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            result = EIO;
            goto cleanup;
        }
        offset += (size_t)amount;
    }
    {
        unsigned char detection;
        ssize_t amount = read(descriptor, &detection, 1U);
        if (amount != 0) {
            result = EFBIG;
            goto cleanup;
        }
    }
    aqt_maybe_pause_after_read();
    if (fstat(descriptor, &final) != 0
        || fstatat(
            directory_descriptor,
            basename,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW
        ) != 0
        || !aqt_stat_equal(&initial, &final)
        || !aqt_stat_equal(&initial, &path_metadata)) {
        result = ESTALE;
        goto cleanup;
    }
    if (aqt_sha256(bytes, offset, destination->sha256) != 0) {
        result = EINVAL;
        goto cleanup;
    }
    destination->metadata = initial;
    destination->bytes = bytes;
    destination->size = offset;
    bytes = NULL;
    result = 0;
cleanup:
    if (bytes != NULL) {
        crypto_wipe(bytes, offset);
        free(bytes);
    }
    if (aqt_close_tracked(descriptor, slot) != 0 && result == 0) {
        result = EIO;
    }
    if (result != 0) {
        aqt_loaded_file_dispose(destination);
    }
    return result;
}

static int
aqt_cursor_expect(AqtAuthorityJsonCursor *cursor, const char *literal)
{
    size_t length = strlen(literal);

    if (cursor == NULL || cursor->offset > cursor->size
        || length > cursor->size - cursor->offset
        || memcmp(cursor->bytes + cursor->offset, literal, length) != 0) {
        return EINVAL;
    }
    cursor->offset += length;
    return 0;
}

static int
aqt_identifier_character(unsigned char value, size_t index)
{
    if ((value >= (unsigned char)'A' && value <= (unsigned char)'Z')
        || (value >= (unsigned char)'a' && value <= (unsigned char)'z')
        || (value >= (unsigned char)'0' && value <= (unsigned char)'9')) {
        return 1;
    }
    return index > 0U
        && (value == (unsigned char)'.' || value == (unsigned char)'_'
            || value == (unsigned char)':' || value == (unsigned char)'/'
            || value == (unsigned char)'-');
}

static int
aqt_parse_identifier(
    AqtAuthorityJsonCursor *cursor,
    char *destination,
    size_t destination_size
)
{
    size_t used = 0U;

    if (aqt_cursor_expect(cursor, "\"") != 0) {
        return EINVAL;
    }
    while (cursor->offset < cursor->size
           && cursor->bytes[cursor->offset] != (unsigned char)'\"') {
        unsigned char value = cursor->bytes[cursor->offset];
        if (destination == NULL || destination_size == 0U
            || used >= AQT_IDENTIFIER_MAXIMUM_BYTES
            || used + 1U >= destination_size
            || !aqt_identifier_character(value, used)) {
            return EINVAL;
        }
        destination[used++] = (char)value;
        cursor->offset++;
    }
    if (used == 0U || aqt_cursor_expect(cursor, "\"") != 0) {
        return EINVAL;
    }
    destination[used] = '\0';
    return 0;
}

static int
aqt_parse_exact_string(AqtAuthorityJsonCursor *cursor, const char *expected)
{
    if (aqt_cursor_expect(cursor, "\"") != 0
        || aqt_cursor_expect(cursor, expected) != 0
        || aqt_cursor_expect(cursor, "\"") != 0) {
        return EINVAL;
    }
    return 0;
}

static int
aqt_hex_value(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') {
        return (int)(value - (unsigned char)'a') + 10;
    }
    return -1;
}

static int
aqt_parse_sha256(
    AqtAuthorityJsonCursor *cursor,
    int optional,
    int *present_out,
    unsigned char digest[AQT_SHA256_BYTES]
)
{
    size_t index;

    if (optional && cursor->offset + 4U <= cursor->size
        && memcmp(cursor->bytes + cursor->offset, "null", 4U) == 0) {
        cursor->offset += 4U;
        *present_out = 0;
        memset(digest, 0, AQT_SHA256_BYTES);
        return 0;
    }
    if (aqt_cursor_expect(cursor, "\"") != 0) {
        return EINVAL;
    }
    for (index = 0U; index < AQT_SHA256_BYTES; index++) {
        int high;
        int low;
        if (cursor->offset + 2U > cursor->size) {
            return EINVAL;
        }
        high = aqt_hex_value(cursor->bytes[cursor->offset++]);
        low = aqt_hex_value(cursor->bytes[cursor->offset++]);
        if (high < 0 || low < 0) {
            return EINVAL;
        }
        digest[index] = (unsigned char)((high << 4) | low);
    }
    if (aqt_cursor_expect(cursor, "\"") != 0) {
        return EINVAL;
    }
    *present_out = 1;
    return 0;
}

static int
aqt_base64_value(unsigned char value)
{
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
        return (int)(value - (unsigned char)'A');
    }
    if (value >= (unsigned char)'a' && value <= (unsigned char)'z') {
        return (int)(value - (unsigned char)'a') + 26;
    }
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') {
        return (int)(value - (unsigned char)'0') + 52;
    }
    if (value == (unsigned char)'+') {
        return 62;
    }
    if (value == (unsigned char)'/') {
        return 63;
    }
    return -1;
}

static int
aqt_parse_base64(
    AqtAuthorityJsonCursor *cursor,
    unsigned char *destination,
    size_t decoded_size
)
{
    size_t encoded_size = 4U * ((decoded_size + 2U) / 3U);
    size_t groups = encoded_size / 4U;
    size_t output = 0U;
    size_t group;

    if (aqt_cursor_expect(cursor, "\"") != 0
        || encoded_size > cursor->size - cursor->offset) {
        return EINVAL;
    }
    for (group = 0U; group < groups; group++) {
        unsigned char c0 = cursor->bytes[cursor->offset++];
        unsigned char c1 = cursor->bytes[cursor->offset++];
        unsigned char c2 = cursor->bytes[cursor->offset++];
        unsigned char c3 = cursor->bytes[cursor->offset++];
        int v0 = aqt_base64_value(c0);
        int v1 = aqt_base64_value(c1);
        int v2 = c2 == (unsigned char)'=' ? 0 : aqt_base64_value(c2);
        int v3 = c3 == (unsigned char)'=' ? 0 : aqt_base64_value(c3);
        size_t remaining = decoded_size - output;

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0
            || (group + 1U < groups
                && (c2 == (unsigned char)'=' || c3 == (unsigned char)'='))
            || (remaining >= 3U
                && (c2 == (unsigned char)'=' || c3 == (unsigned char)'='))
            || (remaining == 2U
                && (c2 == (unsigned char)'=' || c3 != (unsigned char)'='))
            || (remaining == 1U
                && (c2 != (unsigned char)'=' || c3 != (unsigned char)'='))) {
            return EINVAL;
        }
        destination[output++] = (unsigned char)((v0 << 2) | (v1 >> 4));
        if (remaining >= 2U) {
            destination[output++] = (unsigned char)((v1 << 4) | (v2 >> 2));
        } else if ((v1 & 0x0f) != 0) {
            return EINVAL;
        }
        if (remaining >= 3U) {
            destination[output++] = (unsigned char)((v2 << 6) | v3);
        } else if (remaining == 2U && (v2 & 0x03) != 0) {
            return EINVAL;
        }
    }
    if (output != decoded_size || aqt_cursor_expect(cursor, "\"") != 0) {
        return EINVAL;
    }
    return 0;
}

static int
aqt_parse_uint32(
    AqtAuthorityJsonCursor *cursor,
    int optional,
    int *present_out,
    uint32_t *value_out
)
{
    uint64_t value = 0U;
    size_t digits = 0U;

    if (optional && cursor->offset + 4U <= cursor->size
        && memcmp(cursor->bytes + cursor->offset, "null", 4U) == 0) {
        cursor->offset += 4U;
        *present_out = 0;
        *value_out = 0U;
        return 0;
    }
    while (cursor->offset < cursor->size
           && cursor->bytes[cursor->offset] >= (unsigned char)'0'
           && cursor->bytes[cursor->offset] <= (unsigned char)'9') {
        unsigned int digit =
            (unsigned int)(cursor->bytes[cursor->offset] - (unsigned char)'0');
        if (digits == 0U && digit == 0U) {
            return EINVAL;
        }
        value = value * 10U + digit;
        if (value > AQT_GENERATION_MAXIMUM) {
            return ERANGE;
        }
        cursor->offset++;
        digits++;
    }
    if (digits == 0U) {
        return EINVAL;
    }
    *present_out = 1;
    *value_out = (uint32_t)value;
    return 0;
}

static int
aqt_verify_signature(
    const char *domain,
    const AqtAuthorityLoadedFile *loaded,
    size_t signature_field_start,
    size_t signature_field_end,
    const unsigned char signature[AQT_SIGNATURE_BYTES]
)
{
    size_t domain_size = strlen(domain);
    size_t unsigned_size;
    size_t total;
    unsigned char *input;
    int result;

    if (signature_field_start > signature_field_end
        || signature_field_end > loaded->size) {
        return EINVAL;
    }
    unsigned_size = signature_field_start + loaded->size - signature_field_end;
    if (domain_size > SIZE_MAX - 1U
        || unsigned_size > SIZE_MAX - domain_size - 1U) {
        return EOVERFLOW;
    }
    total = domain_size + 1U + unsigned_size;
    input = (unsigned char *)malloc(total);
    if (input == NULL) {
        return ENOMEM;
    }
    memcpy(input, domain, domain_size);
    input[domain_size] = 0U;
    memcpy(input + domain_size + 1U, loaded->bytes, signature_field_start);
    memcpy(
        input + domain_size + 1U + signature_field_start,
        loaded->bytes + signature_field_end,
        loaded->size - signature_field_end
    );
    result = crypto_ed25519_check(
        signature,
        aqt_reviewed_root_public_key,
        input,
        total
    ) == 0 ? 0 : EKEYREJECTED;
    crypto_wipe(input, total);
    free(input);
    return result;
}

static int
aqt_parse_manifest(
    const AqtAuthorityLoadedFile *loaded,
    AqtAuthorityManifest *destination
)
{
    AqtAuthorityJsonCursor cursor;
    int present;

    memset(destination, 0, sizeof(*destination));
    cursor.bytes = loaded->bytes;
    cursor.size = loaded->size;
    cursor.offset = 0U;
    if (aqt_cursor_expect(&cursor, "{\"contract_version\":") != 0
        || aqt_parse_exact_string(&cursor, AQT_MANIFEST_CONTRACT) != 0
        || aqt_cursor_expect(&cursor, ",\"environment\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->environment,
            sizeof(destination->environment)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"generation\":") != 0
        || aqt_parse_uint32(
            &cursor,
            0,
            &present,
            &destination->generation
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"host_key_id\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->host_key_id,
            sizeof(destination->host_key_id)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"host_public_key_base64\":") != 0
        || aqt_parse_base64(
            &cursor,
            destination->host_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"predecessor_manifest_sha256\":") != 0
        || aqt_parse_sha256(
            &cursor,
            1,
            &destination->predecessor_present,
            destination->predecessor_sha256
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"recovery_key_id\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->recovery_key_id,
            sizeof(destination->recovery_key_id)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"recovery_public_key_base64\":") != 0
        || aqt_parse_base64(
            &cursor,
            destination->recovery_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"root_key_id\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->root_key_id,
            sizeof(destination->root_key_id)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"service\":") != 0
        || aqt_parse_exact_string(&cursor, AQT_TRANSPORT_SERVICE) != 0
        || aqt_cursor_expect(&cursor, ",") != 0) {
        return EINVAL;
    }
    destination->signature_field_start = cursor.offset;
    if (aqt_cursor_expect(&cursor, "\"signature_ed25519_base64\":") != 0
        || aqt_parse_base64(&cursor, destination->signature, AQT_SIGNATURE_BYTES) != 0
        || aqt_cursor_expect(&cursor, ",") != 0) {
        return EINVAL;
    }
    destination->signature_field_end = cursor.offset;
    if (aqt_cursor_expect(&cursor, "\"status\":") != 0
        || aqt_parse_exact_string(&cursor, "transport_authority_manifest_issued") != 0
        || aqt_cursor_expect(&cursor, ",\"supervisor_key_id\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->supervisor_key_id,
            sizeof(destination->supervisor_key_id)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"supervisor_public_key_base64\":") != 0
        || aqt_parse_base64(
            &cursor,
            destination->supervisor_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) != 0
        || aqt_cursor_expect(&cursor, "}\n") != 0
        || cursor.offset != cursor.size
        || strcmp(destination->environment, aqt_reviewed_environment) != 0
        || destination->generation == 0U
        || (destination->generation == 1U) == destination->predecessor_present
        || strcmp(destination->root_key_id, aqt_reviewed_root_key_id) != 0
        || strcmp(destination->host_key_id, destination->supervisor_key_id) == 0
        || strcmp(destination->host_key_id, destination->recovery_key_id) == 0
        || strcmp(destination->supervisor_key_id, destination->recovery_key_id) == 0
        || memcmp(
            destination->host_public_key,
            destination->supervisor_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) == 0
        || memcmp(
            destination->host_public_key,
            destination->recovery_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) == 0
        || memcmp(
            destination->supervisor_public_key,
            destination->recovery_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) == 0
        || strcmp(destination->host_key_id, aqt_reviewed_root_key_id) == 0
        || strcmp(destination->supervisor_key_id, aqt_reviewed_root_key_id) == 0
        || strcmp(destination->recovery_key_id, aqt_reviewed_root_key_id) == 0
        || memcmp(
            destination->host_public_key,
            aqt_reviewed_root_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) == 0
        || memcmp(
            destination->supervisor_public_key,
            aqt_reviewed_root_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) == 0
        || memcmp(
            destination->recovery_public_key,
            aqt_reviewed_root_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) == 0) {
        return EINVAL;
    }
    memcpy(destination->sha256, loaded->sha256, AQT_SHA256_BYTES);
    return aqt_verify_signature(
        AQT_MANIFEST_DOMAIN,
        loaded,
        destination->signature_field_start,
        destination->signature_field_end,
        destination->signature
    );
}

static int
aqt_reason_valid(const char *reason, uint32_t sequence)
{
    if (sequence == 1U) {
        return strcmp(reason, "initial") == 0;
    }
    return strcmp(reason, "rotation") == 0
        || strcmp(reason, "suspected_compromise") == 0
        || strcmp(reason, "administrative_hold") == 0;
}

static int
aqt_parse_selection(
    const AqtAuthorityLoadedFile *loaded,
    AqtAuthoritySelection *destination
)
{
    AqtAuthorityJsonCursor cursor;
    char disposition[32];
    int sequence_present;

    memset(destination, 0, sizeof(*destination));
    memset(disposition, 0, sizeof(disposition));
    cursor.bytes = loaded->bytes;
    cursor.size = loaded->size;
    cursor.offset = 0U;
    if (aqt_cursor_expect(&cursor, "{\"contract_version\":") != 0
        || aqt_parse_exact_string(&cursor, AQT_SELECTION_CONTRACT) != 0
        || aqt_cursor_expect(&cursor, ",\"disposition\":") != 0
        || aqt_parse_identifier(&cursor, disposition, sizeof(disposition)) != 0
        || aqt_cursor_expect(&cursor, ",\"environment\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->environment,
            sizeof(destination->environment)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"predecessor_selection_sha256\":") != 0
        || aqt_parse_sha256(
            &cursor,
            1,
            &destination->predecessor_present,
            destination->predecessor_sha256
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"reason_code\":") != 0
        || aqt_parse_identifier(
            &cursor,
            destination->reason_code,
            sizeof(destination->reason_code)
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"recovery_manifest_sha256\":") != 0
        || aqt_parse_sha256(
            &cursor,
            1,
            &destination->recovery_present,
            destination->recovery_manifest_sha256
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"selected_generation\":") != 0
        || aqt_parse_uint32(
            &cursor,
            1,
            &destination->selected_present,
            &destination->selected_generation
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"selected_manifest_sha256\":") != 0) {
        return EINVAL;
    }
    {
        int selected_digest_present;
        if (aqt_parse_sha256(
                &cursor,
                1,
                &selected_digest_present,
                destination->selected_manifest_sha256
            ) != 0
            || selected_digest_present != destination->selected_present) {
            return EINVAL;
        }
    }
    if (aqt_cursor_expect(&cursor, ",\"selection_sequence\":") != 0
        || aqt_parse_uint32(
            &cursor,
            0,
            &sequence_present,
            &destination->sequence
        ) != 0
        || aqt_cursor_expect(&cursor, ",\"service\":") != 0
        || aqt_parse_exact_string(&cursor, AQT_TRANSPORT_SERVICE) != 0
        || aqt_cursor_expect(&cursor, ",") != 0) {
        return EINVAL;
    }
    destination->signature_field_start = cursor.offset;
    if (aqt_cursor_expect(&cursor, "\"signature_ed25519_base64\":") != 0
        || aqt_parse_base64(&cursor, destination->signature, AQT_SIGNATURE_BYTES) != 0
        || aqt_cursor_expect(&cursor, ",") != 0) {
        return EINVAL;
    }
    destination->signature_field_end = cursor.offset;
    if (aqt_cursor_expect(&cursor, "\"status\":") != 0
        || aqt_parse_exact_string(&cursor, "transport_authority_selection_recorded") != 0
        || aqt_cursor_expect(&cursor, "}\n") != 0
        || cursor.offset != cursor.size
        || strcmp(destination->environment, aqt_reviewed_environment) != 0
        || destination->sequence == 0U
        || (destination->sequence == 1U) == destination->predecessor_present
        || !aqt_reason_valid(destination->reason_code, destination->sequence)) {
        return EINVAL;
    }
    if (strcmp(disposition, "generation_selected") == 0) {
        if (!destination->selected_present || destination->selected_generation == 0U) {
            return EINVAL;
        }
        destination->disposition_selected = 1;
    } else if (strcmp(disposition, "new_roots_denied") == 0) {
        if (destination->selected_present) {
            return EINVAL;
        }
        destination->disposition_selected = 0;
    } else {
        return EINVAL;
    }
    memcpy(destination->sha256, loaded->sha256, AQT_SHA256_BYTES);
    return aqt_verify_signature(
        AQT_SELECTION_DOMAIN,
        loaded,
        destination->signature_field_start,
        destination->signature_field_end,
        destination->signature
    );
}

static void
aqt_sha256_hex(
    const unsigned char digest[AQT_SHA256_BYTES],
    char destination[65]
)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t index;

    for (index = 0U; index < AQT_SHA256_BYTES; index++) {
        destination[index * 2U] = alphabet[digest[index] >> 4U];
        destination[index * 2U + 1U] = alphabet[digest[index] & 0x0fU];
    }
    destination[64] = '\0';
}

static int
aqt_load_and_parse_selection(
    int directory_descriptor,
    uint32_t sequence,
    const unsigned char expected_sha256[AQT_SHA256_BYTES],
    AqtAuthoritySelection *destination,
    const AqtAuthorityLoadedFile *expected_head
)
{
    char digest_text[65];
    char basename[AQT_AUTHORITY_NAME_MAXIMUM_BYTES];
    AqtAuthorityLoadedFile loaded;
    int length;
    int result;

    aqt_sha256_hex(expected_sha256, digest_text);
    length = snprintf(
        basename,
        sizeof(basename),
        "transport-authority-selection-s%08u-%s.json",
        sequence,
        digest_text
    );
    if (length <= 0 || (size_t)length >= sizeof(basename)) {
        return EOVERFLOW;
    }
    result = aqt_load_file(
        directory_descriptor,
        basename,
        AQT_AUTHORITY_MAXIMUM_BYTES,
        &loaded
    );
    if (result == 0
        && (memcmp(loaded.sha256, expected_sha256, AQT_SHA256_BYTES) != 0
            || (expected_head != NULL
                && (loaded.size != expected_head->size
                    || memcmp(loaded.bytes, expected_head->bytes, loaded.size) != 0)))) {
        result = EKEYREJECTED;
    }
    if (result == 0) {
        result = aqt_parse_selection(&loaded, destination);
    }
    if (result == 0 && destination->sequence != sequence) {
        result = EINVAL;
    }
    aqt_loaded_file_dispose(&loaded);
    return result;
}

static int
aqt_load_and_parse_manifest(
    int directory_descriptor,
    uint32_t generation,
    const unsigned char expected_sha256[AQT_SHA256_BYTES],
    AqtAuthorityManifest *destination
)
{
    char digest_text[65];
    char basename[AQT_AUTHORITY_NAME_MAXIMUM_BYTES];
    AqtAuthorityLoadedFile loaded;
    int length;
    int result;

    aqt_sha256_hex(expected_sha256, digest_text);
    length = snprintf(
        basename,
        sizeof(basename),
        "transport-authority-manifest-g%08u-%s.json",
        generation,
        digest_text
    );
    if (length <= 0 || (size_t)length >= sizeof(basename)) {
        return EOVERFLOW;
    }
    result = aqt_load_file(
        directory_descriptor,
        basename,
        AQT_AUTHORITY_MAXIMUM_BYTES,
        &loaded
    );
    if (result == 0
        && memcmp(loaded.sha256, expected_sha256, AQT_SHA256_BYTES) != 0) {
        result = EKEYREJECTED;
    }
    if (result == 0) {
        result = aqt_parse_manifest(&loaded, destination);
    }
    if (result == 0 && destination->generation != generation) {
        result = EINVAL;
    }
    aqt_loaded_file_dispose(&loaded);
    return result;
}

static int
aqt_load_root_public_key(int directory_descriptor)
{
    AqtAuthorityLoadedFile loaded;
    int result = aqt_load_file(
        directory_descriptor,
        AQT_ROOT_KEY_BASENAME,
        AQT_PUBLIC_KEY_BYTES,
        &loaded
    );

    if (result == 0
        && (loaded.size != AQT_PUBLIC_KEY_BYTES
            || memcmp(
                loaded.bytes,
                aqt_reviewed_root_public_key,
                AQT_PUBLIC_KEY_BYTES
            ) != 0
            || memcmp(
                loaded.sha256,
                aqt_reviewed_root_public_key_sha256,
                AQT_SHA256_BYTES
            ) != 0)) {
        result = EKEYREJECTED;
    }
    aqt_loaded_file_dispose(&loaded);
    return result;
}

static int
aqt_digest_was_selected(
    unsigned char (*selected_digests)[AQT_SHA256_BYTES],
    uint32_t selected_count,
    const unsigned char digest[AQT_SHA256_BYTES]
)
{
    uint32_t index;

    for (index = 1U; index <= selected_count; index++) {
        if (memcmp(selected_digests[index], digest, AQT_SHA256_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
aqt_array_allocation_size(
    uint32_t count,
    size_t additional_count,
    size_t item_size,
    size_t *bytes_out
)
{
    uint64_t total_count = (uint64_t)count + (uint64_t)additional_count;

    if (bytes_out == NULL || item_size == 0U
        || total_count > (uint64_t)(SIZE_MAX / item_size)) {
        return EOVERFLOW;
    }
    *bytes_out = (size_t)total_count * item_size;
    return 0;
}

static int
aqt_validate_selection_chain(
    const AqtAuthoritySelection *selections,
    uint32_t selection_count,
    unsigned char (**selected_digests_out)[AQT_SHA256_BYTES],
    uint32_t *selected_count_out
)
{
    unsigned char (*selected_digests)[AQT_SHA256_BYTES] = NULL;
    uint32_t selected_count = 0U;
    uint32_t index;
    size_t allocation_size;

    if (aqt_array_allocation_size(
            selection_count,
            1U,
            sizeof(*selected_digests),
            &allocation_size
        ) != 0) {
        return EOVERFLOW;
    }
    selected_digests = calloc(1U, allocation_size);
    if (selected_digests == NULL) {
        return ENOMEM;
    }
    for (index = 0U; index < selection_count; index++) {
        const AqtAuthoritySelection *selection = &selections[index];
        if (selection->sequence != index + 1U
            || (index == 0U) != !selection->predecessor_present
            || (index > 0U
                && memcmp(
                    selection->predecessor_sha256,
                    selections[index - 1U].sha256,
                    AQT_SHA256_BYTES
                ) != 0)
            || (index > 0U
                && strcmp(selection->environment, selections[0].environment) != 0)) {
            free(selected_digests);
            return EINVAL;
        }
        if (selection->disposition_selected) {
            if (selection->selected_generation != selected_count + 1U) {
                free(selected_digests);
                return EINVAL;
            }
            selected_count++;
            memcpy(
                selected_digests[selected_count],
                selection->selected_manifest_sha256,
                AQT_SHA256_BYTES
            );
        }
        if (selection->recovery_present
            && !aqt_digest_was_selected(
                selected_digests,
                selected_count,
                selection->recovery_manifest_sha256
            )) {
            free(selected_digests);
            return EINVAL;
        }
    }
    *selected_digests_out = selected_digests;
    *selected_count_out = selected_count;
    return 0;
}

static int
aqt_chain_resources_valid(uint32_t selection_count, uint32_t manifest_count)
{
    uint64_t file_count = (uint64_t)selection_count + (uint64_t)manifest_count + 2U;
    uint64_t maximum_read_bytes =
        (file_count + 1U) * (uint64_t)AQT_AUTHORITY_MAXIMUM_BYTES
        + AQT_PUBLIC_KEY_BYTES;

    return file_count <= AQT_AUTHORITY_MAXIMUM_CHAIN_FILES
        && maximum_read_bytes <= AQT_AUTHORITY_MAXIMUM_AGGREGATE_BYTES;
}

static int
aqt_manifest_reused_key(
    const AqtAuthorityManifest *manifests,
    uint32_t manifest_count,
    const AqtAuthorityManifest *candidate
)
{
    uint32_t index;
    const char *candidate_ids[3] = {
        candidate->host_key_id,
        candidate->supervisor_key_id,
        candidate->recovery_key_id,
    };
    const unsigned char *candidate_keys[3] = {
        candidate->host_public_key,
        candidate->supervisor_public_key,
        candidate->recovery_public_key,
    };

    for (index = 0U; index < manifest_count; index++) {
        const char *prior_ids[3] = {
            manifests[index].host_key_id,
            manifests[index].supervisor_key_id,
            manifests[index].recovery_key_id,
        };
        const unsigned char *prior_keys[3] = {
            manifests[index].host_public_key,
            manifests[index].supervisor_public_key,
            manifests[index].recovery_public_key,
        };
        size_t left;
        size_t right;
        for (left = 0U; left < 3U; left++) {
            for (right = 0U; right < 3U; right++) {
                if (strcmp(candidate_ids[left], prior_ids[right]) == 0
                    || memcmp(
                        candidate_keys[left],
                        prior_keys[right],
                        AQT_PUBLIC_KEY_BYTES
                    ) == 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

static int
aqt_load_manifest_chain(
    int directory_descriptor,
    unsigned char (*selected_digests)[AQT_SHA256_BYTES],
    uint32_t manifest_count,
    AqtAuthorityManifest **manifests_out
)
{
    AqtAuthorityManifest *manifests;
    uint32_t generation;
    int result = 0;
    size_t allocation_size;

    if (manifest_count == 0U
        || aqt_array_allocation_size(
            manifest_count,
            0U,
            sizeof(*manifests),
            &allocation_size
        ) != 0) {
        return EOVERFLOW;
    }
    manifests = calloc(1U, allocation_size);
    if (manifests == NULL) {
        return ENOMEM;
    }
    for (generation = 1U; generation <= manifest_count; generation++) {
        AqtAuthorityManifest *manifest = &manifests[generation - 1U];
        result = aqt_load_and_parse_manifest(
            directory_descriptor,
            generation,
            selected_digests[generation],
            manifest
        );
        if (result != 0
            || strcmp(manifest->environment, manifests[0].environment) != 0
            || (generation == 1U) != !manifest->predecessor_present
            || (generation > 1U
                && memcmp(
                    manifest->predecessor_sha256,
                    manifests[generation - 2U].sha256,
                    AQT_SHA256_BYTES
                ) != 0)
            || aqt_manifest_reused_key(manifests, generation - 1U, manifest)) {
            result = result != 0 ? result : EINVAL;
            break;
        }
    }
    if (result != 0) {
        crypto_wipe(manifests, (size_t)manifest_count * sizeof(*manifests));
        free(manifests);
        return result;
    }
    *manifests_out = manifests;
    return 0;
}

static int
aqt_role_key(
    const AqtAuthorityManifest *manifest,
    int role,
    unsigned char destination[AQT_PUBLIC_KEY_BYTES]
)
{
    if (role == 1) {
        memcpy(destination, manifest->host_public_key, AQT_PUBLIC_KEY_BYTES);
    } else if (role == 2) {
        memcpy(destination, manifest->supervisor_public_key, AQT_PUBLIC_KEY_BYTES);
    } else if (role == 3) {
        memcpy(destination, manifest->recovery_public_key, AQT_PUBLIC_KEY_BYTES);
    } else {
        return EINVAL;
    }
    return 0;
}

static int
aqt_expected_authority_name(
    const char *name,
    const AqtAuthoritySelection *selections,
    uint32_t selection_count,
    const AqtAuthorityManifest *manifests,
    uint32_t manifest_count
)
{
    char digest[65];
    char expected[AQT_AUTHORITY_NAME_MAXIMUM_BYTES];
    uint32_t index;

    if (strcmp(name, AQT_ROOT_KEY_BASENAME) == 0
        || strcmp(name, AQT_SELECTION_HEAD_BASENAME) == 0) {
        return 1;
    }
    for (index = 0U; index < selection_count; index++) {
        int length;
        aqt_sha256_hex(selections[index].sha256, digest);
        length = snprintf(
            expected,
            sizeof(expected),
            "transport-authority-selection-s%08u-%s.json",
            index + 1U,
            digest
        );
        if (length > 0 && (size_t)length < sizeof(expected)
            && strcmp(name, expected) == 0) {
            return 1;
        }
    }
    for (index = 0U; index < manifest_count; index++) {
        int length;
        aqt_sha256_hex(manifests[index].sha256, digest);
        length = snprintf(
            expected,
            sizeof(expected),
            "transport-authority-manifest-g%08u-%s.json",
            index + 1U,
            digest
        );
        if (length > 0 && (size_t)length < sizeof(expected)
            && strcmp(name, expected) == 0) {
            return 1;
        }
    }
    return 0;
}

static int
aqt_scan_authority_directory(
    int directory_descriptor,
    const AqtAuthoritySelection *selections,
    uint32_t selection_count,
    const AqtAuthorityManifest *manifests,
    uint32_t manifest_count
)
{
    int scan_descriptor = -1;
    uint32_t scan_slot = 0U;
    uint64_t entry_count = 0U;
    int result;

    result = aqt_open_tracked_at(
        directory_descriptor,
        ".",
        O_RDONLY | O_DIRECTORY,
        &scan_descriptor,
        &scan_slot
    );
    if (result != 0) {
        return result;
    }
#ifdef __linux__
    for (;;) {
        struct AqtLinuxDirectoryEntry {
            uint64_t inode;
            int64_t offset;
            unsigned short record_size;
            unsigned char type;
            char name[];
        };
        unsigned char buffer[8192];
        long amount = syscall(SYS_getdents64, scan_descriptor, buffer, sizeof(buffer));
        size_t offset = 0U;
        if (amount < 0) {
            result = errno;
            break;
        }
        if (amount == 0) {
            result = 0;
            break;
        }
        while (offset < (size_t)amount) {
            struct AqtLinuxDirectoryEntry *entry =
                (struct AqtLinuxDirectoryEntry *)(void *)(buffer + offset);
            size_t fixed = offsetof(struct AqtLinuxDirectoryEntry, name);
            size_t name_capacity;
            size_t name_size;
            if (entry->record_size <= fixed
                || entry->record_size > (size_t)amount - offset) {
                result = EIO;
                goto cleanup;
            }
            name_capacity = (size_t)entry->record_size - fixed;
            name_size = strnlen(entry->name, name_capacity);
            if (name_size == name_capacity) {
                result = EIO;
                goto cleanup;
            }
            if (strcmp(entry->name, ".") != 0 && strcmp(entry->name, "..") != 0) {
                if (!aqt_expected_authority_name(
                        entry->name,
                        selections,
                        selection_count,
                        manifests,
                        manifest_count
                    )) {
                    result = EINVAL;
                    goto cleanup;
                }
                entry_count++;
            }
            offset += (size_t)entry->record_size;
        }
    }
#elif defined(__APPLE__)
    {
        unsigned char buffer[8192];
        long base = 0L;
        for (;;) {
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
            long amount = syscall(
                SYS_getdirentries64,
                scan_descriptor,
                (char *)(void *)buffer,
                sizeof(buffer),
                &base
            );
#ifdef __clang__
#pragma clang diagnostic pop
#endif
            size_t offset = 0U;
            if (amount < 0) {
                result = errno;
                break;
            }
            if (amount == 0) {
                result = 0;
                break;
            }
            while (offset < (size_t)amount) {
                struct dirent *entry = (struct dirent *)(void *)(buffer + offset);
                if (entry->d_reclen == 0U || entry->d_reclen > (size_t)amount - offset) {
                    result = EIO;
                    goto cleanup;
                }
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                    if (!aqt_expected_authority_name(
                            entry->d_name,
                            selections,
                            selection_count,
                            manifests,
                            manifest_count
                        )) {
                        result = EINVAL;
                        goto cleanup;
                    }
                    entry_count++;
                }
                offset += entry->d_reclen;
            }
        }
    }
#else
    result = ENOTSUP;
#endif
    if (result == 0
        && entry_count != (uint64_t)selection_count + (uint64_t)manifest_count + 2U) {
        result = EINVAL;
    }
cleanup:
    if (aqt_close_tracked(scan_descriptor, scan_slot) != 0 && result == 0) {
        result = EIO;
    }
    return result;
}

static int
aqt_authenticate_directory(
    int directory_descriptor,
    int directory_already_tracked,
    uint32_t tracked_directory_slot,
    int role,
    uint32_t injected_root_generation,
    const unsigned char *injected_root_manifest_sha256,
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    uint32_t directory_slot = tracked_directory_slot;
    struct stat directory_initial;
    struct stat directory_final;
    AqtAuthorityLoadedFile head_loaded;
    AqtAuthoritySelection head;
    AqtAuthoritySelection *selections = NULL;
    unsigned char (*selected_digests)[AQT_SHA256_BYTES] = NULL;
    AqtAuthorityManifest *manifests = NULL;
    uint32_t selected_count = 0U;
    unsigned char expected_selection_sha256[AQT_SHA256_BYTES];
    uint32_t sequence;
    size_t selection_allocation_size = 0U;
    int result = EINVAL;

    memset(destination, 0, sizeof(*destination));
    memset(&head_loaded, 0, sizeof(head_loaded));
    memset(&head, 0, sizeof(head));
    if (directory_descriptor < 3
        || (!directory_already_tracked
            && aqt_trusted_time_v2_fork_guard_register_fd(
                directory_descriptor,
                &directory_slot
            ) != 0)) {
        if (directory_descriptor >= 0) {
            (void)close(directory_descriptor);
        }
        return EBADF;
    }
    if (fstat(directory_descriptor, &directory_initial) != 0
        || !aqt_directory_metadata_valid(&directory_initial)
        || aqt_load_root_public_key(directory_descriptor) != 0
        || aqt_load_file(
            directory_descriptor,
            AQT_SELECTION_HEAD_BASENAME,
            AQT_AUTHORITY_MAXIMUM_BYTES,
            &head_loaded
        ) != 0
        || aqt_parse_selection(&head_loaded, &head) != 0
        || (uint64_t)head.sequence + 3U > AQT_AUTHORITY_MAXIMUM_CHAIN_FILES
        || aqt_array_allocation_size(
            head.sequence,
            0U,
            sizeof(*selections),
            &selection_allocation_size
        ) != 0) {
        goto cleanup;
    }
    selections = calloc(1U, selection_allocation_size);
    if (selections == NULL) {
        result = ENOMEM;
        goto cleanup;
    }
    memcpy(expected_selection_sha256, head.sha256, AQT_SHA256_BYTES);
    for (sequence = head.sequence; sequence > 0U; sequence--) {
        const AqtAuthorityLoadedFile *expected_head =
            sequence == head.sequence ? &head_loaded : NULL;
        result = aqt_load_and_parse_selection(
            directory_descriptor,
            sequence,
            expected_selection_sha256,
            &selections[sequence - 1U],
            expected_head
        );
        if (result != 0) {
            goto cleanup;
        }
        if (sequence > 1U) {
            if (!selections[sequence - 1U].predecessor_present) {
                result = EINVAL;
                goto cleanup;
            }
            memcpy(
                expected_selection_sha256,
                selections[sequence - 1U].predecessor_sha256,
                AQT_SHA256_BYTES
            );
        }
    }
    result = aqt_validate_selection_chain(
        selections,
        head.sequence,
        &selected_digests,
        &selected_count
    );
    if (result != 0 || selected_count == 0U
        || !aqt_chain_resources_valid(head.sequence, selected_count)) {
        result = result != 0 ? result : EINVAL;
        goto cleanup;
    }
    result = aqt_load_manifest_chain(
        directory_descriptor,
        selected_digests,
        selected_count,
        &manifests
    );
    if (result != 0) {
        goto cleanup;
    }
    if (role == 1 || role == 2) {
        if (!selections[head.sequence - 1U].disposition_selected
            || selections[head.sequence - 1U].selected_generation != selected_count
            || memcmp(
                selections[head.sequence - 1U].selected_manifest_sha256,
                manifests[selected_count - 1U].sha256,
                AQT_SHA256_BYTES
            ) != 0) {
            result = EACCES;
            goto cleanup;
        }
        destination->generation = selected_count;
    } else if (role == 3) {
        if (injected_root_generation == 0U
            || injected_root_generation > selected_count
            || injected_root_manifest_sha256 == NULL
            || !selections[head.sequence - 1U].recovery_present
            || memcmp(
                selections[head.sequence - 1U].recovery_manifest_sha256,
                injected_root_manifest_sha256,
                AQT_SHA256_BYTES
            ) != 0
            || memcmp(
                manifests[injected_root_generation - 1U].sha256,
                injected_root_manifest_sha256,
                AQT_SHA256_BYTES
            ) != 0) {
            result = EACCES;
            goto cleanup;
        }
        destination->generation = injected_root_generation;
    } else {
        result = EINVAL;
        goto cleanup;
    }
    result = aqt_role_key(
        &manifests[destination->generation - 1U],
        role,
        destination->expected_public_key
    );
    if (result == 0) {
        result = aqt_scan_authority_directory(
            directory_descriptor,
            selections,
            head.sequence,
            manifests,
            selected_count
        );
    }
    if (result != 0
        || fstat(directory_descriptor, &directory_final) != 0
        || !aqt_stat_equal(&directory_initial, &directory_final)) {
        result = result != 0 ? result : ESTALE;
        goto cleanup;
    }
    result = 0;
cleanup:
    aqt_loaded_file_dispose(&head_loaded);
    if (selections != NULL) {
        crypto_wipe(selections, (size_t)head.sequence * sizeof(*selections));
        free(selections);
    }
    if (selected_digests != NULL) {
        crypto_wipe(
            selected_digests,
            ((size_t)head.sequence + 1U) * sizeof(*selected_digests)
        );
        free(selected_digests);
    }
    if (manifests != NULL) {
        crypto_wipe(manifests, (size_t)selected_count * sizeof(*manifests));
        free(manifests);
    }
    crypto_wipe(&head, sizeof(head));
    if (aqt_close_tracked(directory_descriptor, directory_slot) != 0 && result == 0) {
        result = EIO;
    }
    if (aqt_trusted_time_v2_fork_guard_require_owner_table_empty() != 0 && result == 0) {
        result = EBUSY;
    }
    if (result != 0) {
        crypto_wipe(destination, sizeof(*destination));
    }
    return result;
}

static int
aqt_production_ancestor_valid(const struct stat *metadata)
{
    return S_ISDIR(metadata->st_mode)
        && metadata->st_uid == 0 && metadata->st_gid == 0
        && (metadata->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static int AQT_AUTHORITY_MAYBE_UNUSED
aqt_open_production_authority_directory(
    int *descriptor_out,
    uint32_t *slot_out
)
{
    static const char *components[] = {
        "opt", "autoquant", "trusted-time", "authorities",
    };
    int descriptor = -1;
    uint32_t slot = 0U;
    size_t index;
    struct stat metadata;
    struct stat path_metadata;

    if (descriptor_out == NULL || slot_out == NULL
        || aqt_open_tracked_at(
            AT_FDCWD,
            "/",
            O_RDONLY | O_DIRECTORY,
            &descriptor,
            &slot
        ) != 0) {
        return EINVAL;
    }
    for (index = 0U; index < sizeof(components) / sizeof(components[0]); index++) {
        int child = -1;
        uint32_t child_slot = 0U;
        int step_result = 0;

        if (fstat(descriptor, &metadata) != 0
            || !aqt_production_ancestor_valid(&metadata)) {
            step_result = EACCES;
        } else {
            step_result = aqt_open_tracked_at(
                descriptor,
                components[index],
                O_RDONLY | O_DIRECTORY,
                &child,
                &child_slot
            );
        }
        if (step_result != 0) {
            (void)aqt_close_tracked(descriptor, slot);
            if (child >= 0) {
                (void)aqt_close_tracked(child, child_slot);
            }
            return step_result;
        }
        if (fstat(child, &metadata) != 0
            || fstatat(
                descriptor,
                components[index],
                &path_metadata,
                AT_SYMLINK_NOFOLLOW
            ) != 0
            || !aqt_stat_equal(&metadata, &path_metadata)
            || !aqt_production_ancestor_valid(&metadata)) {
            (void)aqt_close_tracked(child, child_slot);
            (void)aqt_close_tracked(descriptor, slot);
            return EACCES;
        }
        if (aqt_close_tracked(descriptor, slot) != 0) {
            (void)aqt_close_tracked(child, child_slot);
            return EIO;
        }
        descriptor = child;
        slot = child_slot;
    }
    {
        int authority_descriptor = -1;
        uint32_t authority_slot = 0U;
        int open_result;

        if (fstat(descriptor, &metadata) != 0
            || !aqt_production_ancestor_valid(&metadata)) {
            (void)aqt_close_tracked(descriptor, slot);
            return EACCES;
        }
        open_result = aqt_open_tracked_at(
            descriptor,
            "graceful-stop-v2",
            O_RDONLY | O_DIRECTORY,
            &authority_descriptor,
            &authority_slot
        );
        if (open_result != 0) {
            (void)aqt_close_tracked(descriptor, slot);
            return open_result;
        }
        if (fstat(authority_descriptor, &metadata) != 0
            || fstatat(
                descriptor,
                "graceful-stop-v2",
                &path_metadata,
                AT_SYMLINK_NOFOLLOW
            ) != 0
            || !aqt_stat_equal(&metadata, &path_metadata)
            || !aqt_directory_metadata_valid(&metadata)) {
            (void)aqt_close_tracked(authority_descriptor, authority_slot);
            (void)aqt_close_tracked(descriptor, slot);
            return EACCES;
        }
        if (aqt_close_tracked(descriptor, slot) != 0) {
            (void)aqt_close_tracked(authority_descriptor, authority_slot);
            return EIO;
        }
        descriptor = authority_descriptor;
        slot = authority_slot;
    }
    *descriptor_out = descriptor;
    *slot_out = slot;
    return 0;
}

static int AQT_AUTHORITY_MAYBE_UNUSED
aqt_mint_and_consume(
    int directory_descriptor,
    int directory_already_tracked,
    uint32_t tracked_directory_slot,
    int role,
    uint32_t injected_root_generation,
    const unsigned char *injected_root_manifest_sha256,
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    AqtAuthorityGenerationSeal seal;
    int result;
    int consumed = 0;

    memset(&seal, 0, sizeof(seal));
    if (destination == NULL) {
        if (directory_descriptor >= 0) {
            if (directory_already_tracked) {
                (void)aqt_close_tracked(
                    directory_descriptor,
                    tracked_directory_slot
                );
            } else {
                (void)close(directory_descriptor);
            }
        }
        return EINVAL;
    }
    memset(destination, 0, sizeof(*destination));
    if (aqt_trusted_time_v2_fork_guard_is_poisoned() != 0
        || aqt_trusted_time_v2_fork_guard_capture_identity(&seal.identity) != 0) {
        if (directory_descriptor >= 0) {
            if (directory_already_tracked) {
                (void)aqt_close_tracked(
                    directory_descriptor,
                    tracked_directory_slot
                );
            } else {
                (void)close(directory_descriptor);
            }
        }
        return ECHILD;
    }
    result = aqt_authenticate_directory(
        directory_descriptor,
        directory_already_tracked,
        tracked_directory_slot,
        role,
        injected_root_generation,
        injected_root_manifest_sha256,
        &seal.generation
    );
    if (result != 0) {
        crypto_wipe(&seal, sizeof(seal));
        return result;
    }
    seal.guard_epoch = aqt_trusted_time_v2_fork_guard_current_epoch();
    seal.interpreter_identity = (uintptr_t)(const void *)
        &aqt_native_interpreter_instance_capability;
    atomic_init(&seal.consumed, 0);
#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING
    switch ((AqtTrustedTimeV2AuthorityTestIdentityFault)atomic_load(
        &aqt_test_identity_fault
    )) {
        case AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_PID:
            seal.identity.origin_pid++;
            break;
        case AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_THREAD:
            memset(&seal.identity.origin_thread, 0, sizeof(seal.identity.origin_thread));
            break;
        case AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_INTERPRETER:
            seal.interpreter_identity ^= (uintptr_t)1U;
            break;
        case AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_FORK_EPOCH:
            seal.identity.fork_epoch++;
            break;
        case AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_NONE:
        default:
            break;
    }
#endif
    if (seal.guard_epoch != seal.identity.fork_epoch
        || seal.interpreter_identity != (uintptr_t)(const void *)
            &aqt_native_interpreter_instance_capability
        || aqt_trusted_time_v2_fork_guard_require_identity(&seal.identity) != 0
        || !atomic_compare_exchange_strong(&seal.consumed, &consumed, 1)
        || aqt_trusted_time_v2_fork_guard_require_owner_table_empty() != 0) {
        crypto_wipe(&seal, sizeof(seal));
        return EACCES;
    }
    *destination = seal.generation;
    crypto_wipe(&seal, sizeof(seal));
    return 0;
}

static int
aqt_consume_production_role(
    int role,
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    int expected_state = 0;

    if (destination == NULL) {
        return EINVAL;
    }
    memset(destination, 0, sizeof(*destination));
    if (!atomic_compare_exchange_strong(
            &aqt_authority_consumption_state,
            &expected_state,
            1
        )) {
        return EALREADY;
    }
#if !AQT_AUTHORITY_ROOT_PIN_AVAILABLE
    (void)role;
    atomic_store(&aqt_authority_consumption_state, 2);
    return ENOKEY;
#else
    int directory_descriptor = -1;
    uint32_t directory_slot = 0U;
    int result;

    result = aqt_open_production_authority_directory(
        &directory_descriptor,
        &directory_slot
    );
    if (result != 0) {
        atomic_store(&aqt_authority_consumption_state, 2);
        return result;
    }
    result = aqt_mint_and_consume(
        directory_descriptor,
        1,
        directory_slot,
        role,
        0U,
        NULL,
        destination
    );
    atomic_store(&aqt_authority_consumption_state, 2);
    return result;
#endif
}

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    return aqt_consume_production_role(1, destination);
}
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_consume_authenticated_supervisor_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    return aqt_consume_production_role(2, destination);
}
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_consume_authenticated_recovery_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    /* Wave 7 deliberately has no production lifecycle-root reader or route. */
    return aqt_consume_production_role(3, destination);
}
#endif

#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING
int
aqt_trusted_time_v2_authority_test_consume_preopened(
    int authority_directory_fd,
    AqtTrustedTimeV2AuthorityTestRole role,
    uint32_t injected_root_generation,
    const unsigned char *injected_root_manifest_sha256,
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    int expected_state = 0;
    int result;

    if (destination == NULL) {
        if (authority_directory_fd >= 0) {
            (void)close(authority_directory_fd);
        }
        return EINVAL;
    }
    memset(destination, 0, sizeof(*destination));
    if (!atomic_compare_exchange_strong(
            &aqt_authority_consumption_state,
            &expected_state,
            1
        )) {
        if (authority_directory_fd >= 0) {
            (void)close(authority_directory_fd);
        }
        return EALREADY;
    }
    result = aqt_mint_and_consume(
        authority_directory_fd,
        0,
        0U,
        (int)role,
        injected_root_generation,
        injected_root_manifest_sha256,
        destination
    );
    atomic_store(&aqt_authority_consumption_state, 2);
    return result;
}

void
aqt_trusted_time_v2_authority_test_pause_after_read(int enabled)
{
    atomic_store(&aqt_test_read_resume, 0);
    atomic_store(&aqt_test_read_paused, 0);
    atomic_store(&aqt_test_pause_requested, enabled != 0 ? 1 : 0);
}

int
aqt_trusted_time_v2_authority_test_read_is_paused(void)
{
    return atomic_load(&aqt_test_read_paused);
}

void
aqt_trusted_time_v2_authority_test_resume_read(void)
{
    atomic_store(&aqt_test_read_resume, 1);
}

void
aqt_trusted_time_v2_authority_test_set_identity_fault(
    AqtTrustedTimeV2AuthorityTestIdentityFault fault
)
{
    atomic_store(&aqt_test_identity_fault, (int)fault);
}
#endif
