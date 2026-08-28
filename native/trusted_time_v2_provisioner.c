#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "trusted_time_v2_provisioner.h"

#include "trusted_time_v2_descriptor_baseline.h"
#include "trusted_time_v2_fork_guard.h"
#include "trusted_time_v2_seccomp.h"
#include "trusted_time_v2_secret_mount_admission.h"

#include "monocypher-ed25519.h"
#include "monocypher.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/magic.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#endif

#if (defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)) != 1
#error "Exactly one trusted-time lifecycle-v2 provisioner role must be selected."
#endif

#ifndef AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256
#error "The exact /usr/bin/systemd-creds SHA-256 must be compiled into the provisioner."
#endif

#define AQT_PROVISION_FAILURE_STATUS 191
#define AQT_SEED_BYTES 32U
#define AQT_PUBLIC_KEY_BYTES 32U
#define AQT_GENERATION_TEXT_BYTES 8U
#define AQT_SHA256_BYTES 32U
#define AQT_READ_DETECTION_BYTES 33U
#define AQT_MAX_PATH_BYTES 512U
#define AQT_CHILD_TIMEOUT_SECONDS 30L
#define AQT_CHILD_POLL_NANOSECONDS 10000000L

#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
#ifndef AQT_TRUSTED_TIME_V2_TEST_SYSTEMD_CREDS_PATH
#error "The test provisioner must compile an exact child executable path."
#endif
#define AQT_SYSTEMD_CREDS_PATH AQT_TRUSTED_TIME_V2_TEST_SYSTEMD_CREDS_PATH
#else
#define AQT_SYSTEMD_CREDS_PATH "/usr/bin/systemd-creds"
#endif

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
#define AQT_ROLE_NAME "host"
#define AQT_EXECUTABLE_PATH \
    "/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/" \
    "autoquant-trusted-time-graceful-stop-v2-host-provision"
#define AQT_EXECUTABLE_BASENAME \
    "autoquant-trusted-time-graceful-stop-v2-host-provision"
#define AQT_CREDENTIAL_NAME "autoquant-trusted-time-graceful-stop-v2-host"
#define AQT_BLOB_PREFIX \
    "/etc/credstore.encrypted/" \
    "autoquant-trusted-time-graceful-stop-v2-host-g"
#define AQT_TARGET_DIRECTORY \
    "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets"
#define AQT_TARGET_BASENAME "host-ed25519.raw"
#define AQT_TARGET_PATH AQT_TARGET_DIRECTORY "/" AQT_TARGET_BASENAME
#define AQT_TARGET_UID ((uid_t)0)
#define AQT_TARGET_GID ((gid_t)0)
#define AQT_TARGET_MODE ((mode_t)0400)
#define AQT_DIRECTORY_UID ((uid_t)0)
#define AQT_DIRECTORY_GID ((gid_t)0)
#define AQT_DIRECTORY_MODE ((mode_t)0700)
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
#define AQT_ROLE_NAME "supervisor"
#define AQT_EXECUTABLE_PATH \
    "/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/" \
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision"
#define AQT_EXECUTABLE_BASENAME \
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision"
#define AQT_CREDENTIAL_NAME "autoquant-trusted-time-graceful-stop-v2-supervisor"
#define AQT_BLOB_PREFIX \
    "/etc/credstore.encrypted/" \
    "autoquant-trusted-time-graceful-stop-v2-supervisor-g"
#define AQT_TARGET_DIRECTORY \
    "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets"
#define AQT_TARGET_BASENAME "supervisor-ed25519.raw"
#define AQT_TARGET_PATH AQT_TARGET_DIRECTORY "/" AQT_TARGET_BASENAME
#define AQT_TARGET_UID ((uid_t)10001)
#define AQT_TARGET_GID ((gid_t)10001)
#define AQT_TARGET_MODE ((mode_t)0400)
#define AQT_DIRECTORY_UID ((uid_t)0)
#define AQT_DIRECTORY_GID ((gid_t)10001)
#define AQT_DIRECTORY_MODE ((mode_t)0730)
#else
#define AQT_ROLE_NAME "recovery"
#define AQT_EXECUTABLE_PATH \
    "/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/" \
    "autoquant-trusted-time-graceful-stop-v2-recovery-provision"
#define AQT_EXECUTABLE_BASENAME \
    "autoquant-trusted-time-graceful-stop-v2-recovery-provision"
#define AQT_CREDENTIAL_NAME "autoquant-trusted-time-graceful-stop-v2-recovery"
#define AQT_BLOB_PREFIX \
    "/etc/credstore.encrypted/" \
    "autoquant-trusted-time-graceful-stop-v2-recovery-g"
#define AQT_TARGET_DIRECTORY \
    "/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets"
#define AQT_TARGET_BASENAME "recovery-ed25519.raw"
#define AQT_TARGET_PATH AQT_TARGET_DIRECTORY "/" AQT_TARGET_BASENAME
#define AQT_TARGET_UID ((uid_t)0)
#define AQT_TARGET_GID ((gid_t)0)
#define AQT_TARGET_MODE ((mode_t)0400)
#define AQT_DIRECTORY_UID ((uid_t)0)
#define AQT_DIRECTORY_GID ((gid_t)0)
#define AQT_DIRECTORY_MODE ((mode_t)0700)
#endif

#ifdef AQT_TRUSTED_TIME_V2_TEST_BLOB_PREFIX
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
#error "The blob-prefix override is test-only."
#endif
#undef AQT_BLOB_PREFIX
#define AQT_BLOB_PREFIX AQT_TRUSTED_TIME_V2_TEST_BLOB_PREFIX
#endif

#ifdef AQT_TRUSTED_TIME_V2_TEST_TARGET_DIRECTORY
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
#error "The target-directory override is test-only."
#endif
#undef AQT_TARGET_DIRECTORY
#undef AQT_TARGET_PATH
#define AQT_TARGET_DIRECTORY AQT_TRUSTED_TIME_V2_TEST_TARGET_DIRECTORY
#define AQT_TARGET_PATH AQT_TARGET_DIRECTORY "/" AQT_TARGET_BASENAME
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char buffer[64];
    size_t buffer_used;
} AqtSha256Context;

static _Atomic int aqt_child_state = 0;
static _Atomic int aqt_generation_state = 0;
static volatile sig_atomic_t aqt_interrupted_signal = 0;
static struct sigaction aqt_saved_signal_actions[4];
static int aqt_signal_actions_installed = 0;

#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
static uintptr_t
aqt_secret_mount_admission_identity(void)
{
    return (uintptr_t)(const void *)&aqt_child_state;
}
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
aqt_sha256_transform(AqtSha256Context *context, const unsigned char block[64])
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
aqt_sha256_initialize(AqtSha256Context *context)
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
aqt_sha256_update(AqtSha256Context *context, const unsigned char *payload, size_t size)
{
    size_t offset = 0U;

    if (size > (UINT64_MAX - context->bit_count) / 8U) {
        return -1;
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
aqt_sha256_finish(AqtSha256Context *context, unsigned char digest[AQT_SHA256_BYTES])
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
}

static void
aqt_wipe(void *payload, size_t size)
{
    crypto_wipe(payload, size);
}

static void
aqt_fail(const char *message)
{
    (void)fprintf(
        stderr,
        "trusted-time lifecycle-v2 %s provisioner: %s\n",
        AQT_ROLE_NAME,
        message
    );
    _exit(AQT_PROVISION_FAILURE_STATUS);
}

static int
aqt_metadata_equal(const struct stat *left, const struct stat *right)
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
aqt_inode_equal(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev
        && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode
        && left->st_nlink == right->st_nlink
        && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid;
}

static int
aqt_hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

static int
aqt_decode_expected_sha256(unsigned char destination[AQT_SHA256_BYTES])
{
    static const char expected[] = AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256;
    size_t index;

    if (sizeof(expected) != 65U) {
        return -1;
    }
    for (index = 0U; index < AQT_SHA256_BYTES; index++) {
        int high = aqt_hex_nibble(expected[index * 2U]);
        int low = aqt_hex_nibble(expected[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return -1;
        }
        destination[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int
aqt_hash_descriptor(int descriptor, unsigned char digest[AQT_SHA256_BYTES])
{
    AqtSha256Context context;
    unsigned char buffer[65536];
    struct stat before;
    struct stat after;
    ssize_t received;
    int result = -1;

    memset(&context, 0, sizeof(context));
    memset(buffer, 0, sizeof(buffer));
    if (fstat(descriptor, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_size < 0 || before.st_size > (off_t)(256U * 1024U * 1024U)
        || lseek(descriptor, 0, SEEK_SET) != 0) {
        goto cleanup;
    }
    aqt_sha256_initialize(&context);
    for (;;) {
        received = read(descriptor, buffer, sizeof(buffer));
        if (received == 0) {
            break;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto cleanup;
        }
        if (aqt_sha256_update(&context, buffer, (size_t)received) != 0) {
            goto cleanup;
        }
    }
    if (fstat(descriptor, &after) != 0 || !aqt_metadata_equal(&before, &after)) {
        goto cleanup;
    }
    aqt_sha256_finish(&context, digest);
    result = 0;
cleanup:
    aqt_wipe(buffer, sizeof(buffer));
    aqt_wipe(&context, sizeof(context));
    return result;
}

static int
aqt_format_generation(uint32_t generation, char destination[9])
{
    int length;

    if (generation < 1U || generation > 99999999U || destination == NULL) {
        return -1;
    }
    length = snprintf(destination, 9U, "%08" PRIu32, generation);
    if (length != (int)AQT_GENERATION_TEXT_BYTES || destination[8] != '\0') {
        return -1;
    }
    return 0;
}

static int
aqt_build_blob_path(uint32_t generation, char destination[AQT_MAX_PATH_BYTES])
{
    char generation_text[9];
    int length;

    memset(generation_text, 0, sizeof(generation_text));
    if (aqt_format_generation(generation, generation_text) != 0) {
        return -1;
    }
    length = snprintf(
        destination,
        AQT_MAX_PATH_BYTES,
        "%s%s.cred",
        AQT_BLOB_PREFIX,
        generation_text
    );
    aqt_wipe(generation_text, sizeof(generation_text));
    if (length <= 0 || length >= (int)AQT_MAX_PATH_BYTES) {
        return -1;
    }
    return 0;
}

static uid_t
aqt_expected_owner_uid(void)
{
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    return geteuid();
#else
    return AQT_TARGET_UID;
#endif
}

static gid_t
aqt_expected_owner_gid(void)
{
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    return getegid();
#else
    return AQT_TARGET_GID;
#endif
}

static int
aqt_open_directory_chain(const char *path, int role_owned_final)
{
    char bounded[AQT_MAX_PATH_BYTES];
    char *component;
    char *separator;
    int current_descriptor = -1;
    struct stat root_metadata;

#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    (void)role_owned_final;
#endif
    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(bounded)) {
        return -1;
    }
    memcpy(bounded, path, strlen(path) + 1U);
    current_descriptor = open("/", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    if (current_descriptor < 0
        || fstat(current_descriptor, &root_metadata) != 0
        || !S_ISDIR(root_metadata.st_mode)
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        || root_metadata.st_uid != 0 || root_metadata.st_gid != 0
        || (root_metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0
#endif
    ) {
        if (current_descriptor >= 0) {
            (void)close(current_descriptor);
        }
        return -1;
    }
    component = bounded + 1;
    while (*component != '\0') {
        int next_descriptor;
        struct stat metadata;

        separator = strchr(component, '/');
        if (separator != NULL) {
            *separator = '\0';
        }
        if (component[0] == '\0' || strcmp(component, ".") == 0
            || strcmp(component, "..") == 0) {
            (void)close(current_descriptor);
            return -1;
        }
        next_descriptor = openat(
            current_descriptor,
            component,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY
        );
        (void)close(current_descriptor);
        current_descriptor = next_descriptor;
        if (current_descriptor < 0
            || fstat(current_descriptor, &metadata) != 0
            || !S_ISDIR(metadata.st_mode)) {
            if (current_descriptor >= 0) {
                (void)close(current_descriptor);
            }
            return -1;
        }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        if ((separator != NULL || role_owned_final == 0)
            && (metadata.st_uid != 0 || metadata.st_gid != 0
            || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)) {
            (void)close(current_descriptor);
            return -1;
        }
#endif
        if (separator == NULL) {
            break;
        }
        component = separator + 1;
    }
    return current_descriptor;
}

static int
aqt_open_parent_directory(
    const char *path,
    char basename[AQT_MAX_PATH_BYTES]
)
{
    char parent[AQT_MAX_PATH_BYTES];
    const char *separator;
    size_t parent_length;

    if (path == NULL || path[0] != '/' || strlen(path) >= sizeof(parent)) {
        return -1;
    }
    separator = strrchr(path, '/');
    if (separator == NULL || separator == path || separator[1] == '\0') {
        return -1;
    }
    parent_length = (size_t)(separator - path);
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    if (strlen(separator + 1) >= AQT_MAX_PATH_BYTES) {
        return -1;
    }
    memcpy(basename, separator + 1, strlen(separator + 1) + 1U);
    return aqt_open_directory_chain(parent, 0);
}

static int
aqt_capture_blob_identity(const char *path, struct stat *identity)
{
    char basename[AQT_MAX_PATH_BYTES];
    char canonical[AQT_MAX_PATH_BYTES];
    int directory_descriptor = -1;
    int result = -1;

    memset(basename, 0, sizeof(basename));
    memset(canonical, 0, sizeof(canonical));
    if (realpath(path, canonical) == NULL || strcmp(canonical, path) != 0) {
        goto cleanup;
    }
    directory_descriptor = aqt_open_parent_directory(path, basename);
    if (directory_descriptor < 0
        || fstatat(
            directory_descriptor,
            basename,
            identity,
            AT_SYMLINK_NOFOLLOW
        ) != 0
        || !S_ISREG(identity->st_mode)
        || identity->st_nlink != 1
        || identity->st_uid != 0
        || identity->st_gid != 0
        || (identity->st_mode & 07777) != 0600
        || identity->st_size <= 0
        || identity->st_size > (off_t)(16U * 1024U * 1024U)) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (directory_descriptor >= 0) {
        (void)close(directory_descriptor);
    }
    return result;
}

static int
aqt_revalidate_blob_identity(const char *path, const struct stat *identity)
{
    char basename[AQT_MAX_PATH_BYTES];
    struct stat current;
    int directory_descriptor = -1;
    int result = -1;

    memset(basename, 0, sizeof(basename));
    memset(&current, 0, sizeof(current));
    directory_descriptor = aqt_open_parent_directory(path, basename);
    if (directory_descriptor >= 0
        && fstatat(
            directory_descriptor,
            basename,
            &current,
            AT_SYMLINK_NOFOLLOW
        ) == 0
        && aqt_metadata_equal(identity, &current)) {
        result = 0;
    }
    if (directory_descriptor >= 0) {
        (void)close(directory_descriptor);
    }
    return result;
}

static int
aqt_open_target_directory(void)
{
    int descriptor;
    struct stat metadata;

    descriptor = aqt_open_directory_chain(AQT_TARGET_DIRECTORY, 1);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0
        || !S_ISDIR(metadata.st_mode)
        || metadata.st_uid !=
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
            geteuid()
#else
            AQT_DIRECTORY_UID
#endif
        || metadata.st_gid !=
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
            getegid()
#else
            AQT_DIRECTORY_GID
#endif
        || (metadata.st_mode & 07777) != AQT_DIRECTORY_MODE) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
#ifdef __linux__
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    {
        struct statfs filesystem;
        if (fstatfs(descriptor, &filesystem) != 0
            || (unsigned long)filesystem.f_type != (unsigned long)TMPFS_MAGIC) {
            (void)close(descriptor);
            return -1;
        }
    }
#endif
#endif
    return descriptor;
}

static int
aqt_unlink_open_target_by_identity(int directory_descriptor, int target_descriptor)
{
    struct stat descriptor_now;
    struct stat path_now;

    if (directory_descriptor < 0 || target_descriptor < 0
        || fstat(target_descriptor, &descriptor_now) != 0
        || fstatat(
            directory_descriptor,
            AQT_TARGET_BASENAME,
            &path_now,
            AT_SYMLINK_NOFOLLOW
        ) != 0
        || descriptor_now.st_dev != path_now.st_dev
        || descriptor_now.st_ino != path_now.st_ino
        || unlinkat(directory_descriptor, AQT_TARGET_BASENAME, 0) != 0) {
        return -1;
    }
    if (fstatat(
            directory_descriptor,
            AQT_TARGET_BASENAME,
            &path_now,
            AT_SYMLINK_NOFOLLOW
        ) == 0 || errno != ENOENT) {
        return -1;
    }
    return 0;
}

static int
aqt_create_target(int directory_descriptor, struct stat *identity)
{
    int descriptor = openat(
        directory_descriptor,
        AQT_TARGET_BASENAME,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
        0600
    );
    uid_t expected_uid = aqt_expected_owner_uid();
    gid_t expected_gid = aqt_expected_owner_gid();

    if (descriptor < 0
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        || fchown(descriptor, expected_uid, expected_gid) != 0
#endif
        || fchmod(descriptor, AQT_TARGET_MODE) != 0
        || fstat(descriptor, identity) != 0
        || !S_ISREG(identity->st_mode)
        || identity->st_nlink != 1
        || identity->st_uid != expected_uid
        || identity->st_gid != expected_gid
        || (identity->st_mode & 07777) != AQT_TARGET_MODE
        || identity->st_size != 0) {
        if (descriptor >= 0) {
            int removal_result = aqt_unlink_open_target_by_identity(
                directory_descriptor,
                descriptor
            );
            (void)close(descriptor);
            if (removal_result != 0) {
                return -2;
            }
        }
        return -1;
    }
    return descriptor;
}

static int
aqt_unlink_exact_target(
    int directory_descriptor,
    int target_descriptor,
    const struct stat *identity
)
{
    struct stat descriptor_now;
    struct stat path_now;

    if (target_descriptor >= 0
        && fstat(target_descriptor, &descriptor_now) == 0
        && fstatat(
            directory_descriptor,
            AQT_TARGET_BASENAME,
            &path_now,
            AT_SYMLINK_NOFOLLOW
        ) == 0
        && aqt_inode_equal(identity, &descriptor_now)
        && aqt_inode_equal(identity, &path_now)
        && unlinkat(directory_descriptor, AQT_TARGET_BASENAME, 0) == 0
        && fstatat(
            directory_descriptor,
            AQT_TARGET_BASENAME,
            &path_now,
            AT_SYMLINK_NOFOLLOW
        ) != 0
        && errno == ENOENT) {
        return 0;
    }
    return -1;
}

static int
aqt_open_systemd_creds(void)
{
    char basename[AQT_MAX_PATH_BYTES];
    char canonical[AQT_MAX_PATH_BYTES];
    unsigned char actual[AQT_SHA256_BYTES];
    unsigned char expected[AQT_SHA256_BYTES];
    struct stat metadata;
    struct stat path_metadata;
    int directory_descriptor = -1;
    int descriptor = -1;
    int valid = 0;

    memset(basename, 0, sizeof(basename));
    memset(canonical, 0, sizeof(canonical));
    memset(actual, 0, sizeof(actual));
    memset(expected, 0, sizeof(expected));
    if (realpath(AQT_SYSTEMD_CREDS_PATH, canonical) == NULL
        || strcmp(canonical, AQT_SYSTEMD_CREDS_PATH) != 0) {
        goto cleanup;
    }
    directory_descriptor = aqt_open_parent_directory(
        AQT_SYSTEMD_CREDS_PATH,
        basename
    );
    if (directory_descriptor < 0) {
        goto cleanup;
    }
    descriptor = openat(
        directory_descriptor,
        basename,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );
    if (descriptor >= 3
        && fstat(descriptor, &metadata) == 0
        && fstatat(
            directory_descriptor,
            basename,
            &path_metadata,
            AT_SYMLINK_NOFOLLOW
        ) == 0
        && aqt_metadata_equal(&metadata, &path_metadata)
        && S_ISREG(metadata.st_mode)
        && metadata.st_nlink == 1
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        && metadata.st_uid == 0 && metadata.st_gid == 0
#endif
        && (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0
        && aqt_decode_expected_sha256(expected) == 0
        && aqt_hash_descriptor(descriptor, actual) == 0
        && memcmp(actual, expected, sizeof(actual)) == 0) {
        valid = 1;
    }
cleanup:
    aqt_wipe(actual, sizeof(actual));
    aqt_wipe(expected, sizeof(expected));
    if (directory_descriptor >= 0) {
        (void)close(directory_descriptor);
    }
    if (!valid) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
    return descriptor;
}

static int
aqt_consume_authenticated_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    int state = 0;
    int result;

    if (destination == NULL
        || !atomic_compare_exchange_strong(&aqt_generation_state, &state, 1)) {
        return -1;
    }
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
    result = aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
        destination
    );
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
    result = aqt_trusted_time_graceful_stop_v2_consume_authenticated_supervisor_provisioning_generation(
        destination
    );
#else
    result = aqt_trusted_time_graceful_stop_v2_consume_authenticated_recovery_provisioning_generation(
        destination
    );
#endif
    atomic_store(&aqt_generation_state, 2);
    return result;
}

#ifdef __linux__
static int
aqt_normalize_descriptor(int *descriptor_io, int fixed_descriptor)
{
    struct stat before;
    struct stat after;
    int original;

    if (descriptor_io == NULL || *descriptor_io < 3 || fixed_descriptor < 3) {
        return -1;
    }
    original = *descriptor_io;
    if (fstat(original, &before) != 0) {
        return -1;
    }
    if (original != fixed_descriptor) {
        if (dup3(original, fixed_descriptor, O_CLOEXEC) != fixed_descriptor
            || fstat(fixed_descriptor, &after) != 0
            || !aqt_metadata_equal(&before, &after)
            || close(original) != 0) {
            (void)close(fixed_descriptor);
            return -1;
        }
        *descriptor_io = fixed_descriptor;
    }
    return 0;
}
static int
aqt_close_child_descriptors(int executable_descriptor, rlim_t maximum_descriptor)
{
    int descriptor;
    int maximum;

    maximum = maximum_descriptor > (rlim_t)INT_MAX
        ? INT_MAX : (int)maximum_descriptor;
    for (descriptor = 2; descriptor < maximum; descriptor++) {
        if (descriptor != executable_descriptor) {
            (void)close(descriptor);
        }
    }
    return 0;
}
#else
static int
aqt_normalize_descriptor(int *descriptor_io, int fixed_descriptor)
{
    (void)descriptor_io;
    (void)fixed_descriptor;
    return 0;
}
#endif

static void
aqt_defer_signal(int signal_number)
{
    aqt_interrupted_signal = signal_number;
}

static int
aqt_install_signal_deferral(void)
{
    static const int signals[4] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    struct sigaction action;
    size_t index;

    if (aqt_signal_actions_installed != 0) {
        return -1;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = aqt_defer_signal;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    for (index = 0U; index < 4U; index++) {
        if (sigaction(signals[index], &action, &aqt_saved_signal_actions[index]) != 0) {
            while (index > 0U) {
                index--;
                (void)sigaction(
                    signals[index],
                    &aqt_saved_signal_actions[index],
                    NULL
                );
            }
            return -1;
        }
    }
    aqt_signal_actions_installed = 1;
    return 0;
}

static void
aqt_restore_signal_dispositions(void)
{
    static const int signals[4] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    size_t index;

    if (aqt_signal_actions_installed == 0) {
        return;
    }
    for (index = 0U; index < 4U; index++) {
        (void)sigaction(signals[index], &aqt_saved_signal_actions[index], NULL);
    }
    aqt_signal_actions_installed = 0;
}

#ifdef __linux__
static int
aqt_run_child(
    int executable_descriptor,
    int null_descriptor,
    int target_descriptor,
    const char *blob_path
)
{
    static char argument_zero[] = "systemd-creds";
    static char argument_one[] = "decrypt";
    static char argument_two[] = "--name=" AQT_CREDENTIAL_NAME;
    static char argument_four[] = "-";
    char *arguments[6];
    char *environment[1] = {NULL};
    struct rlimit descriptor_limit;
    struct sigaction default_action;
    struct timespec deadline;
    struct timespec now;
    struct timespec poll_interval;
    pid_t child;
    pid_t waited;
    int state;
    int status = 0;
    int must_terminate = 0;
    int reaped = 0;

    state = 0;
    if (!atomic_compare_exchange_strong(&aqt_child_state, &state, 1)
        || getrlimit(RLIMIT_NOFILE, &descriptor_limit) != 0
        || clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        return -1;
    }
    deadline.tv_sec += AQT_CHILD_TIMEOUT_SECONDS;
    poll_interval.tv_sec = 0;
    poll_interval.tv_nsec = AQT_CHILD_POLL_NANOSECONDS;
    arguments[0] = argument_zero;
    arguments[1] = argument_one;
    arguments[2] = argument_two;
    arguments[3] = (char *)(uintptr_t)blob_path;
    arguments[4] = argument_four;
    arguments[5] = NULL;
    child = fork();
    if (child < 0) {
        atomic_store(&aqt_child_state, 2);
        return -1;
    }
    if (child == 0) {
        static const int signals[4] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM};
        size_t index;

        memset(&default_action, 0, sizeof(default_action));
        default_action.sa_handler = SIG_DFL;
        (void)sigemptyset(&default_action.sa_mask);
        for (index = 0U; index < 4U; index++) {
            (void)sigaction(signals[index], &default_action, NULL);
        }
        if (dup3(null_descriptor, STDIN_FILENO, 0) != STDIN_FILENO
            || dup3(target_descriptor, STDOUT_FILENO, 0) != STDOUT_FILENO) {
            _exit(126);
        }
        (void)aqt_close_child_descriptors(
            executable_descriptor,
            descriptor_limit.rlim_cur
        );
        if (aqt_trusted_time_v2_seccomp_install_child_exec()
            != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
            _exit(126);
        }
        (void)syscall(
            SYS_execveat,
            executable_descriptor,
            "",
            arguments,
            environment,
            AT_EMPTY_PATH
        );
        _exit(127);
    }
    for (;;) {
        waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            reaped = 1;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            must_terminate = 1;
            break;
        }
        if (aqt_interrupted_signal != 0
            || clock_gettime(CLOCK_MONOTONIC, &now) != 0
            || now.tv_sec > deadline.tv_sec
            || (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            must_terminate = 1;
            break;
        }
        while (nanosleep(&poll_interval, &poll_interval) != 0 && errno == EINTR) {
            if (aqt_interrupted_signal != 0) {
                must_terminate = 1;
                break;
            }
        }
        poll_interval.tv_sec = 0;
        poll_interval.tv_nsec = AQT_CHILD_POLL_NANOSECONDS;
        if (must_terminate != 0) {
            break;
        }
    }
    if (reaped == 0 && must_terminate != 0) {
        if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
            atomic_store(&aqt_child_state, 3);
            return -1;
        }
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        reaped = waited == child;
    }
    atomic_store(&aqt_child_state, reaped != 0 ? 2 : 3);
    if (reaped == 0 || must_terminate != 0
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    return 0;
}
#else
static int
aqt_run_child(
    int executable_descriptor,
    int null_descriptor,
    int target_descriptor,
    const char *blob_path
)
{
    (void)executable_descriptor;
    (void)null_descriptor;
    (void)target_descriptor;
    (void)blob_path;
    return -1;
}
#endif

static int
aqt_read_and_verify_seed(
    int directory_descriptor,
    int target_descriptor,
    const struct stat *created_identity,
    const unsigned char expected_public_key[AQT_PUBLIC_KEY_BYTES]
)
{
    typedef struct {
        unsigned char detected[AQT_READ_DETECTION_BYTES];
        unsigned char derived_secret_key[64];
        unsigned char derived_public_key[AQT_PUBLIC_KEY_BYTES];
    } AqtProvisioningSecretBuffer;
    AqtProvisioningSecretBuffer *secret = NULL;
    void *mapping = MAP_FAILED;
    long configured_page_size;
    size_t mapping_size = 0U;
    struct stat before;
    struct stat after;
    struct stat path_now;
    ssize_t received;
    size_t total = 0U;
    int locked = 0;
    int result = -1;

    configured_page_size = sysconf(_SC_PAGESIZE);
    if (configured_page_size <= 0
        || (uintmax_t)configured_page_size > (uintmax_t)SIZE_MAX) {
        goto cleanup;
    }
    mapping_size = (size_t)configured_page_size;
    if (mapping_size < sizeof(*secret)) {
        goto cleanup;
    }
    mapping = mmap(
        NULL,
        mapping_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    if (mapping == MAP_FAILED || mlock(mapping, mapping_size) != 0) {
        goto cleanup;
    }
    locked = 1;
#ifdef __linux__
#ifndef MADV_DONTDUMP
#error "The Linux provisioner requires MADV_DONTDUMP."
#endif
#ifndef MADV_WIPEONFORK
#error "The Linux provisioner requires MADV_WIPEONFORK."
#endif
    if (madvise(mapping, mapping_size, MADV_DONTDUMP) != 0
        || madvise(mapping, mapping_size, MADV_WIPEONFORK) != 0) {
        goto cleanup;
    }
#endif
    secret = (AqtProvisioningSecretBuffer *)mapping;
    memset(secret, 0, sizeof(*secret));
    if (lseek(target_descriptor, 0, SEEK_SET) != 0
        || fstat(target_descriptor, &before) != 0
        || !aqt_inode_equal(created_identity, &before)) {
        goto cleanup;
    }
    while (total < sizeof(secret->detected)) {
        received = read(
            target_descriptor,
            secret->detected + total,
            sizeof(secret->detected) - total
        );
        if (received == 0) {
            break;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto cleanup;
        }
        total += (size_t)received;
    }
    if (total != AQT_SEED_BYTES
        || fstat(target_descriptor, &after) != 0
        || fstatat(
            directory_descriptor,
            AQT_TARGET_BASENAME,
            &path_now,
            AT_SYMLINK_NOFOLLOW
        ) != 0
        || !aqt_metadata_equal(&before, &after)
        || !aqt_metadata_equal(&before, &path_now)
        || after.st_size != (off_t)AQT_SEED_BYTES) {
        goto cleanup;
    }
    crypto_ed25519_key_pair(
        secret->derived_secret_key,
        secret->derived_public_key,
        secret->detected
    );
    if (memcmp(
            secret->derived_public_key,
            expected_public_key,
            AQT_PUBLIC_KEY_BYTES
        ) != 0) {
        goto cleanup;
    }
    result = 0;
cleanup:
    if (mapping != MAP_FAILED) {
        aqt_wipe(mapping, mapping_size);
        if (locked != 0) {
            (void)munlock(mapping, mapping_size);
        }
        (void)munmap(mapping, mapping_size);
    }
    return result;
}

static void
aqt_validate_invocation(int argument_count, char **argument_values)
{
    char canonical[PATH_MAX];
    struct stat metadata;

    if (argument_count != 1 || argument_values == NULL
        || argument_values[0] == NULL || argument_values[0][0] != '/') {
        aqt_fail("exactly one absolute argv[0] and no arguments are required");
    }
    if (realpath(argument_values[0], canonical) == NULL
        || strcmp(canonical, argument_values[0]) != 0
        || lstat(canonical, &metadata) != 0
        || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1) {
        aqt_fail("the provisioner executable identity is invalid");
    }
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    {
        const char *separator = strrchr(canonical, '/');
        const char *basename = separator == NULL ? canonical : separator + 1;
        if (strcmp(basename, AQT_EXECUTABLE_BASENAME) != 0
            || metadata.st_uid != geteuid() || metadata.st_gid != getegid()
            || ((metadata.st_mode & 07777) != 0555
                && (metadata.st_mode & 07777) != 0755)) {
            aqt_fail("the test provisioner executable identity is invalid");
        }
    }
#else
    if (strcmp(canonical, AQT_EXECUTABLE_PATH) != 0
        || metadata.st_uid != 0 || metadata.st_gid != 0
        || (metadata.st_mode & 07777) != 0555) {
        aqt_fail("the fixed provisioner executable identity is invalid");
    }
#endif
}

int
aqt_trusted_time_v2_provisioner_main(int argument_count, char **argument_values)
{
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration generation;
    char blob_path[AQT_MAX_PATH_BYTES];
    struct stat blob_identity;
    struct stat null_identity;
    struct stat normalized_target_identity;
    struct stat target_identity;
    int directory_descriptor = -1;
    int target_descriptor = -1;
    int executable_descriptor = -1;
    int null_descriptor = -1;
    int child_attempted = 0;
    int child_result = -1;
    int blob_revalidation_result = -1;
    int unlink_result = 0;
    int success = 0;
    int seccomp_result;
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    aqt_trusted_time_v2_secret_mount_admission *pre_create_mount_admission = NULL;
    aqt_trusted_time_v2_secret_mount_admission *post_create_mount_admission = NULL;
    const uintptr_t mount_admission_identity =
        aqt_secret_mount_admission_identity();
    int mount_revalidation_result = -1;
    int mount_cleanup_result = 0;
#endif

    memset(&generation, 0, sizeof(generation));
    memset(blob_path, 0, sizeof(blob_path));
    memset(&blob_identity, 0, sizeof(blob_identity));
    memset(&null_identity, 0, sizeof(null_identity));
    memset(&normalized_target_identity, 0, sizeof(normalized_target_identity));
    memset(&target_identity, 0, sizeof(target_identity));
    aqt_validate_invocation(argument_count, argument_values);
    if (aqt_trusted_time_v2_close_ambient_descriptors() != 0
        || aqt_trusted_time_v2_validate_standard_descriptors() != 0
        || aqt_install_signal_deferral() != 0) {
        aqt_fail("the fixed descriptor and signal baseline is unavailable");
    }
    if (aqt_trusted_time_v2_fork_guard_initialize_before_python() != 0
        || aqt_trusted_time_v2_fork_guard_is_poisoned() != 0) {
        aqt_fail("the native pre-fork guard could not be installed");
    }
    seccomp_result = aqt_trusted_time_v2_seccomp_install_initial();
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        && seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED) {
#else
    if (seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
#endif
        aqt_fail("the pre-child seccomp profile could not be installed");
    }
    if (aqt_consume_authenticated_generation(&generation) != 0
        || aqt_build_blob_path(generation.generation, blob_path) != 0
        || aqt_capture_blob_identity(blob_path, &blob_identity) != 0
        || aqt_trusted_time_v2_fork_guard_require_owner_table_empty() != 0) {
        goto cleanup;
    }
    directory_descriptor = aqt_open_target_directory();
    if (directory_descriptor < 0) {
        goto cleanup;
    }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (aqt_trusted_time_v2_secret_mount_admission_capture(
            &pre_create_mount_admission,
            directory_descriptor,
            mount_admission_identity
        ) != 0
        || aqt_trusted_time_v2_secret_mount_admission_revalidate(
            pre_create_mount_admission,
            directory_descriptor,
            mount_admission_identity
        ) != 0) {
        goto cleanup;
    }
#endif
    target_descriptor = aqt_create_target(directory_descriptor, &target_identity);
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (aqt_trusted_time_v2_secret_mount_admission_close(
            &pre_create_mount_admission,
            mount_admission_identity
        ) != 0) {
        goto cleanup;
    }
#endif
    if (target_descriptor == -2) {
        unlink_result = -1;
        goto cleanup;
    }
    if (target_descriptor < 0) {
        goto cleanup;
    }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (aqt_trusted_time_v2_secret_mount_admission_capture(
            &post_create_mount_admission,
            directory_descriptor,
            mount_admission_identity
        ) != 0) {
        goto cleanup;
    }
#endif
    executable_descriptor = aqt_open_systemd_creds();
    null_descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (target_descriptor < 3 || executable_descriptor < 3 || null_descriptor < 3
        || target_descriptor == executable_descriptor
        || target_descriptor == null_descriptor
        || executable_descriptor == null_descriptor
        || aqt_normalize_descriptor(
            &executable_descriptor,
            AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_FD
        ) != 0
        || aqt_normalize_descriptor(
            &null_descriptor,
            AQT_TRUSTED_TIME_V2_NULL_INPUT_FD
        ) != 0
        || aqt_normalize_descriptor(
            &target_descriptor,
            AQT_TRUSTED_TIME_V2_SECRET_OUTPUT_FD
        ) != 0
        || fstat(target_descriptor, &normalized_target_identity) != 0
        || !aqt_metadata_equal(&target_identity, &normalized_target_identity)
        || fstat(null_descriptor, &null_identity) != 0
        || !S_ISCHR(null_identity.st_mode)
#ifdef __linux__
        || major(null_identity.st_rdev) != 1U
        || minor(null_identity.st_rdev) != 3U
#endif
        || (fcntl(null_descriptor, F_GETFL) & O_ACCMODE) != O_RDONLY
        || aqt_interrupted_signal != 0
        || aqt_trusted_time_v2_fork_guard_require_owner_table_empty() != 0) {
        goto cleanup;
    }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (aqt_trusted_time_v2_secret_mount_admission_revalidate(
            post_create_mount_admission,
            directory_descriptor,
            mount_admission_identity
        ) != 0) {
        goto cleanup;
    }
#endif
    child_attempted = 1;
    child_result = aqt_run_child(
        executable_descriptor,
        null_descriptor,
        target_descriptor,
        blob_path
    );
    seccomp_result = aqt_trusted_time_v2_seccomp_install_post_child();
#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        && seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED) {
#else
    if (seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
#endif
        goto cleanup;
    }
    blob_revalidation_result = aqt_revalidate_blob_identity(
        blob_path,
        &blob_identity
    );
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    mount_revalidation_result =
        aqt_trusted_time_v2_secret_mount_admission_revalidate(
            post_create_mount_admission,
            directory_descriptor,
            mount_admission_identity
        );
#endif
    if (child_result != 0
        || blob_revalidation_result != 0
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        || mount_revalidation_result != 0
#endif
        || aqt_interrupted_signal != 0
        || aqt_trusted_time_v2_fork_guard_is_poisoned() != 0
        || aqt_read_and_verify_seed(
            directory_descriptor,
            target_descriptor,
            &target_identity,
            generation.expected_public_key
        ) != 0) {
        goto cleanup;
    }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (aqt_trusted_time_v2_secret_mount_admission_revalidate(
            post_create_mount_admission,
            directory_descriptor,
            mount_admission_identity
        ) != 0
        || aqt_trusted_time_v2_secret_mount_admission_close(
            &post_create_mount_admission,
            mount_admission_identity
        ) != 0) {
        goto cleanup;
    }
#endif
    success = 1;
cleanup:
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    if (!success && target_descriptor >= 0
        && post_create_mount_admission != NULL) {
        mount_cleanup_result =
            aqt_trusted_time_v2_secret_mount_admission_revalidate(
                post_create_mount_admission,
                directory_descriptor,
                mount_admission_identity
            );
    }
#endif
    if (!success && target_descriptor >= 0) {
        unlink_result = aqt_unlink_exact_target(
            directory_descriptor,
            target_descriptor,
            &target_identity
        );
    }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
    {
        int admission_close_result =
            aqt_trusted_time_v2_secret_mount_admission_close(
                &post_create_mount_admission,
                mount_admission_identity
            );

        if (admission_close_result != 0 && mount_cleanup_result == 0) {
            mount_cleanup_result = admission_close_result;
        }
        admission_close_result =
            aqt_trusted_time_v2_secret_mount_admission_close(
                &pre_create_mount_admission,
                mount_admission_identity
            );
        if (admission_close_result != 0 && mount_cleanup_result == 0) {
            mount_cleanup_result = admission_close_result;
        }
    }
#endif
    if (null_descriptor >= 0) {
        (void)close(null_descriptor);
    }
    if (executable_descriptor >= 0) {
        (void)close(executable_descriptor);
    }
    if (target_descriptor >= 0) {
        (void)close(target_descriptor);
    }
    if (directory_descriptor >= 0) {
        (void)close(directory_descriptor);
    }
    aqt_wipe(blob_path, sizeof(blob_path));
    aqt_wipe(&blob_identity, sizeof(blob_identity));
    aqt_wipe(&null_identity, sizeof(null_identity));
    aqt_wipe(&normalized_target_identity, sizeof(normalized_target_identity));
    aqt_wipe(&generation, sizeof(generation));
    aqt_restore_signal_dispositions();
    if (!success) {
        if (child_attempted && atomic_load(&aqt_child_state) != 2) {
            aqt_fail("the sole decrypt child was not conclusively reaped");
        }
        if (unlink_result != 0) {
            aqt_fail("the failed target exact-inode unlink was not proven");
        }
#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        if (mount_cleanup_result != 0) {
            aqt_fail("the secret-mount custody cleanup was not proven");
        }
#endif
        aqt_fail("credential provisioning failed closed");
    }
    return 0;
}

#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_API
int
aqt_trusted_time_v2_provisioner_format_generation_for_test(
    uint32_t generation,
    char destination[9]
)
{
    return aqt_format_generation(generation, destination);
}

const char *
aqt_trusted_time_v2_provisioner_role_name_for_test(void)
{
    return AQT_ROLE_NAME;
}

const char *
aqt_trusted_time_v2_provisioner_credential_name_for_test(void)
{
    return AQT_CREDENTIAL_NAME;
}

const char *
aqt_trusted_time_v2_provisioner_target_path_for_test(void)
{
    return AQT_TARGET_PATH;
}
#endif

#ifndef AQT_TRUSTED_TIME_V2_NO_MAIN
int
main(int argument_count, char **argument_values)
{
    return aqt_trusted_time_v2_provisioner_main(argument_count, argument_values);
}
#endif
