#if defined(__linux__)
#define _GNU_SOURCE
#else
#define _DARWIN_C_SOURCE
#endif

#include "trusted_time_v2_fork_guard.h"
#include "trusted_time_graceful_stop_v2_signer.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define AQT_CHECK(expression)                                                     \
    do {                                                                          \
        if (!(expression)) {                                                       \
            (void)fprintf(stderr, "check failed at %s:%d: %s\n",                 \
                          __FILE__, __LINE__, #expression);                        \
            return 1;                                                             \
        }                                                                         \
    } while (0)

typedef struct {
    aqt_trusted_time_v2_signer_owner *owner;
    uintptr_t interpreter_identity;
    int result;
} aqt_wrong_thread_context;

typedef struct {
    int descriptor;
    uint32_t slot;
    int result;
} aqt_guard_race_context;

typedef struct {
    int descriptor;
    int expect_closed;
    int result;
} aqt_concurrent_fork_context;

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
aqt_decode_hex(const char *encoded, uint8_t *decoded, size_t decoded_size)
{
    size_t index;

    if (strlen(encoded) != decoded_size * 2U) {
        return EINVAL;
    }
    for (index = 0; index < decoded_size; ++index) {
        const int high = aqt_hex_nibble(encoded[index * 2U]);
        const int low = aqt_hex_nibble(encoded[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return EINVAL;
        }
        decoded[index] = (uint8_t)((unsigned int)high * 16U + (unsigned int)low);
    }
    return 0;
}

static int
aqt_rfc8032_vector(
    const char *seed_hex,
    const char *public_key_hex,
    const char *message_hex,
    const char *signature_hex)
{
    const size_t message_size = strlen(message_hex) / 2U;
    uint8_t seed[32];
    uint8_t public_key[32];
    uint8_t expected_public_key[32];
    uint8_t secret_key[64];
    uint8_t message[2];
    uint8_t signature[64];
    uint8_t expected_signature[64];
    int result = 0;

    if (message_size > sizeof(message)
        || aqt_decode_hex(seed_hex, seed, sizeof(seed)) != 0
        || aqt_decode_hex(public_key_hex, expected_public_key, sizeof(expected_public_key)) != 0
        || aqt_decode_hex(message_hex, message, message_size) != 0
        || aqt_decode_hex(signature_hex, expected_signature, sizeof(expected_signature)) != 0) {
        return EINVAL;
    }
    crypto_ed25519_key_pair(secret_key, public_key, seed);
    crypto_ed25519_sign(signature, secret_key, message, message_size);
    if (memcmp(public_key, expected_public_key, sizeof(public_key)) != 0
        || memcmp(signature, expected_signature, sizeof(signature)) != 0
        || crypto_ed25519_check(signature, public_key, message, message_size) != 0) {
        result = EIO;
    }
    crypto_wipe(seed, sizeof(seed));
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(signature, sizeof(signature));
    return result;
}

static int
aqt_test_rfc8032(void)
{
    AQT_CHECK(aqt_rfc8032_vector(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b") == 0);
    AQT_CHECK(aqt_rfc8032_vector(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00") == 0);
    AQT_CHECK(aqt_rfc8032_vector(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a") == 0);
    return 0;
}

static int
aqt_verify_domain_signature(
    const uint8_t signature[64],
    const uint8_t public_key[32],
    const char *domain,
    const char *message)
{
    const size_t domain_size = strlen(domain);
    const size_t message_size = strlen(message);
    uint8_t *input = (uint8_t *)malloc(domain_size + 1U + message_size);
    int result;

    if (input == NULL) {
        return ENOMEM;
    }
    (void)memcpy(input, domain, domain_size);
    input[domain_size] = 0;
    (void)memcpy(input + domain_size + 1U, message, message_size);
    result = crypto_ed25519_check(
        signature,
        public_key,
        input,
        domain_size + 1U + message_size
    );
    free(input);
    return result == 0 ? 0 : EIO;
}

static int
aqt_call_primary_signer(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    uint8_t signature[64])
{
#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
    static const char message[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-host-hello-v2\","
        "\"direction\":\"host_to_supervisor\",\"status\":\"host_hello_offered\"}\n";
    return aqt_trusted_time_v2_signer_sign_host_hello(
        owner, interpreter_identity, (const uint8_t *)message, strlen(message), signature
    );
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE)
    static const char message[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-supervisor-hello-v2\","
        "\"direction\":\"supervisor_to_host\",\"status\":\"supervisor_hello_accepted\"}\n";
    return aqt_trusted_time_v2_signer_sign_supervisor_hello(
        owner, interpreter_identity, (const uint8_t *)message, strlen(message), signature
    );
#else
    static const char message[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-recovery-classification-envelope-v1\","
        "\"service\":\"trusted-time-post-enrollment-graceful-stop-lifecycle-v2\","
        "\"status\":\"recovery_classification_requested\"}\n";
    return aqt_trusted_time_v2_signer_sign_recovery_classification(
        owner, interpreter_identity, (const uint8_t *)message, strlen(message), signature
    );
#endif
}

static void *
aqt_wrong_thread_main(void *opaque)
{
    aqt_wrong_thread_context *context = (aqt_wrong_thread_context *)opaque;
    uint8_t signature[64];

    context->result = aqt_call_primary_signer(
        context->owner,
        context->interpreter_identity,
        signature
    );
    return NULL;
}

static int
aqt_write_seed_file(const char *directory_path, const uint8_t seed[32])
{
    int directory_fd = -1;
    int credential_fd = -1;
    ssize_t written;

    directory_fd = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        return errno;
    }
    credential_fd = openat(
        directory_fd,
        "credential.raw",
        O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
        (mode_t)0400
    );
    (void)close(directory_fd);
    if (credential_fd < 0) {
        return errno;
    }
    if (fchown(credential_fd, geteuid(), getegid()) != 0
        || fchmod(credential_fd, (mode_t)0400) != 0) {
        const int result = errno == 0 ? EPERM : errno;
        (void)close(credential_fd);
        return result;
    }
    written = write(credential_fd, seed, 32);
    if (written != 32 || fsync(credential_fd) != 0 || close(credential_fd) != 0) {
        return errno == 0 ? EIO : errno;
    }
    return 0;
}

static int
aqt_open_test_owner(
    const char *directory_path,
    const uint8_t expected_public_key[32],
    uintptr_t interpreter_identity,
    aqt_trusted_time_v2_signer_owner **owner_out)
{
    int directory_fd = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int credential_fd;

    if (directory_fd < 0) {
        return errno;
    }
    credential_fd = openat(directory_fd, "credential.raw", O_RDONLY | O_CLOEXEC);
    if (credential_fd < 0) {
        const int result = errno;
        (void)close(directory_fd);
        return result;
    }
    return aqt_trusted_time_v2_signer_owner_open_preopened(
        owner_out,
        directory_fd,
        credential_fd,
        expected_public_key,
        interpreter_identity
    );
}

static int
aqt_test_role_methods(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t public_key[32])
{
    uint8_t signature[64];
    int result;

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
    static const char host_hello[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-host-hello-v2\","
        "\"direction\":\"host_to_supervisor\",\"status\":\"host_hello_offered\"}\n";
    static const char confirmation[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-host-channel-confirmation-v2\","
        "\"direction\":\"host_to_supervisor\",\"status\":\"host_channel_confirmed\"}\n";
    static const char request[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\","
        "\"direction\":\"host_to_supervisor\",\"frame_type\":\"clean_stop_request\","
        "\"message_counter\":2}\n";
    static const char wrong_frame[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\","
        "\"direction\":\"supervisor_to_host\",\"frame_type\":\"clean_stop_result\","
        "\"message_counter\":1}\n";
    static const char nested_substitution[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\","
        "\"direction\":\"host_to_supervisor\",\"frame_type\":\"wrong\","
        "\"message_counter\":2,\"nested\":{\"frame_type\":\"clean_stop_request\"}}\n";
    static const char duplicate_discriminator[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\","
        "\"direction\":\"host_to_supervisor\",\"frame_type\":\"clean_stop_request\","
        "\"frame_type\":\"clean_stop_request\",\"message_counter\":2}\n";

    result = aqt_trusted_time_v2_signer_sign_host_hello(
        owner, interpreter_identity, (const uint8_t *)host_hello, strlen(host_hello), signature
    );
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(
        signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/host-hello/v2", host_hello) == 0);
    result = aqt_trusted_time_v2_signer_sign_host_channel_confirmation(
        owner, interpreter_identity, (const uint8_t *)confirmation, strlen(confirmation), signature
    );
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(
        signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/host-channel-confirmation/v2",
        confirmation) == 0);
    result = aqt_trusted_time_v2_signer_sign_clean_stop_request(
        owner, interpreter_identity, (const uint8_t *)request, strlen(request), signature
    );
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(
        signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2", request) == 0);
    AQT_CHECK(aqt_trusted_time_v2_signer_sign_clean_stop_request(
        owner, interpreter_identity, (const uint8_t *)wrong_frame,
        strlen(wrong_frame), signature) == EINVAL);
    AQT_CHECK(aqt_trusted_time_v2_signer_sign_clean_stop_request(
        owner, interpreter_identity, (const uint8_t *)nested_substitution,
        strlen(nested_substitution), signature) == EINVAL);
    AQT_CHECK(aqt_trusted_time_v2_signer_sign_clean_stop_request(
        owner, interpreter_identity, (const uint8_t *)duplicate_discriminator,
        strlen(duplicate_discriminator), signature) == EINVAL);
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE)
    static const char supervisor_hello[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-supervisor-hello-v2\","
        "\"direction\":\"supervisor_to_host\",\"status\":\"supervisor_hello_accepted\"}\n";
    static const char result_message[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\","
        "\"direction\":\"supervisor_to_host\",\"frame_type\":\"clean_stop_result\","
        "\"message_counter\":1}\n";
    static const char error_message[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-transport-envelope-v2\","
        "\"direction\":\"supervisor_to_host\",\"frame_type\":\"clean_stop_error\","
        "\"message_counter\":1}\n";
    static const char cleanup[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-supervisor-transport-cleanup-commitment-v2\","
        "\"service\":\"trusted-time-graceful-stop-transport-v2\","
        "\"status\":\"supervisor_transport_cleanup_committed\"}\n";

    result = aqt_trusted_time_v2_signer_sign_supervisor_hello(
        owner, interpreter_identity, (const uint8_t *)supervisor_hello,
        strlen(supervisor_hello), signature);
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/supervisor-hello/v2",
        supervisor_hello) == 0);
    result = aqt_trusted_time_v2_signer_sign_clean_stop_result(
        owner, interpreter_identity, (const uint8_t *)result_message,
        strlen(result_message), signature);
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2",
        result_message) == 0);
    result = aqt_trusted_time_v2_signer_sign_clean_stop_error(
        owner, interpreter_identity, (const uint8_t *)error_message,
        strlen(error_message), signature);
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/transport-envelope/v2",
        error_message) == 0);
    result = aqt_trusted_time_v2_signer_sign_supervisor_cleanup_commitment(
        owner, interpreter_identity, (const uint8_t *)cleanup, strlen(cleanup), signature);
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/supervisor-transport-cleanup-commitment/v2",
        cleanup) == 0);
#else
    static const char recovery[] =
        "{\"contract_version\":\"phase6d-trusted-time-graceful-stop-recovery-classification-envelope-v1\","
        "\"service\":\"trusted-time-post-enrollment-graceful-stop-lifecycle-v2\","
        "\"status\":\"recovery_classification_requested\"}\n";

    result = aqt_trusted_time_v2_signer_sign_recovery_classification(
        owner, interpreter_identity, (const uint8_t *)recovery, strlen(recovery), signature);
    AQT_CHECK(result == 0);
    AQT_CHECK(aqt_verify_domain_signature(signature, public_key,
        "AutoQuantTrader/trusted-time/graceful-stop/recovery-classification/v1",
        recovery) == 0);
#endif
    return 0;
}

static int
aqt_test_signer(void)
{
    static const char seed_hex[] =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    static const char public_key_hex[] =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    char directory_template[] = "/tmp/aqt-v2-signer-XXXXXX";
    char *directory_path;
    uint8_t seed[32];
    uint8_t public_key[32];
    uint8_t wrong_public_key[32];
    uint8_t observed_public_key[32];
    uint8_t signature[64];
    aqt_trusted_time_v2_signer_owner *owner = NULL;
    aqt_wrong_thread_context thread_context;
    pthread_t thread;
    struct stat metadata;
    const uintptr_t interpreter_identity = (uintptr_t)0x61717432U;
    const uint64_t parent_epoch = UINT64_C(1);
    pid_t child;
    int child_status;
    int open_result;

    AQT_CHECK(aqt_decode_hex(seed_hex, seed, sizeof(seed)) == 0);
    AQT_CHECK(aqt_decode_hex(public_key_hex, public_key, sizeof(public_key)) == 0);
    (void)memcpy(wrong_public_key, public_key, sizeof(wrong_public_key));
    wrong_public_key[0] ^= UINT8_C(1);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_initialize_before_python() == 0);
    AQT_CHECK(aqt_trusted_time_v2_signer_initialize_before_python() == 0);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_current_epoch() == parent_epoch);
    directory_path = mkdtemp(directory_template);
    AQT_CHECK(directory_path != NULL);
    AQT_CHECK(chown(directory_path, geteuid(), getegid()) == 0);
    AQT_CHECK(chmod(directory_path, (mode_t)0700) == 0);
    AQT_CHECK(aqt_write_seed_file(directory_path, seed) == 0);

    open_result = aqt_open_test_owner(
        directory_path, wrong_public_key, interpreter_identity, &owner);
    if (open_result != EACCES) {
        (void)fprintf(stderr, "wrong-public-key open returned %d (%s)\n",
                      open_result, strerror(open_result));
    }
    AQT_CHECK(open_result == EACCES);
    AQT_CHECK(owner == NULL);
    AQT_CHECK(stat(directory_path, &metadata) == 0);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);

    AQT_CHECK(aqt_open_test_owner(
        directory_path, public_key, interpreter_identity, &owner) == 0);
    AQT_CHECK(owner != NULL);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
    AQT_CHECK(aqt_trusted_time_v2_signer_owner_read_public_key(
        owner, interpreter_identity, observed_public_key) == 0);
    AQT_CHECK(memcmp(observed_public_key, public_key, sizeof(public_key)) == 0);
    AQT_CHECK(aqt_trusted_time_v2_signer_owner_read_public_key(
        owner, interpreter_identity + 1U, observed_public_key) == EPERM);
    AQT_CHECK(aqt_test_role_methods(owner, interpreter_identity, public_key) == 0);

    thread_context.owner = owner;
    thread_context.interpreter_identity = interpreter_identity;
    thread_context.result = 0;
    AQT_CHECK(pthread_create(&thread, NULL, aqt_wrong_thread_main, &thread_context) == 0);
    AQT_CHECK(pthread_join(thread, NULL) == 0);
    AQT_CHECK(thread_context.result == EPERM);

    child = fork();
    AQT_CHECK(child >= 0);
    if (child == 0) {
        if (!aqt_trusted_time_v2_fork_guard_is_poisoned()
            || aqt_trusted_time_v2_fork_guard_current_epoch() != parent_epoch + 1U
            || aqt_call_primary_signer(owner, interpreter_identity, signature) != EPERM) {
            _exit(20);
        }
#if defined(__linux__)
        if (!aqt_trusted_time_v2_signer_test_fork_secret_is_zero(owner)) {
            _exit(21);
        }
#endif
        _exit(0);
    }
    AQT_CHECK(waitpid(child, &child_status, 0) == child);
    AQT_CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    AQT_CHECK(!aqt_trusted_time_v2_fork_guard_is_poisoned());
    aqt_trusted_time_v2_fork_guard_test_invoke_prepare();
    aqt_trusted_time_v2_fork_guard_test_invoke_prepare();
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_is_poisoned());
    aqt_trusted_time_v2_fork_guard_test_invoke_parent();
    aqt_trusted_time_v2_fork_guard_test_invoke_parent();
    AQT_CHECK(aqt_trusted_time_v2_signer_owner_close(
        &owner, interpreter_identity + 1U) == EPERM);
    AQT_CHECK(owner != NULL);
    AQT_CHECK(aqt_trusted_time_v2_signer_owner_close(&owner, interpreter_identity) == 0);
    AQT_CHECK(owner == NULL);
    AQT_CHECK(aqt_trusted_time_v2_signer_test_last_close_zeroized());
    AQT_CHECK(aqt_trusted_time_v2_signer_owner_close(&owner, interpreter_identity) == 0);
    AQT_CHECK(rmdir(directory_path) == 0);
    crypto_wipe(seed, sizeof(seed));
    return 0;
}

static void *
aqt_guard_race_register_main(void *opaque)
{
    aqt_guard_race_context *context = (aqt_guard_race_context *)opaque;
    context->result = aqt_trusted_time_v2_fork_guard_register_fd(
        context->descriptor,
        &context->slot
    );
    return NULL;
}

static void *
aqt_guard_race_close_main(void *opaque)
{
    aqt_guard_race_context *context = (aqt_guard_race_context *)opaque;
    context->result = aqt_trusted_time_v2_fork_guard_close_fd(
        context->slot,
        context->descriptor
    );
    return NULL;
}

static int
aqt_test_guard_race(void)
{
    int descriptors[2];
    pthread_t thread;
    aqt_guard_race_context context;
    pid_t child;
    int status;

    AQT_CHECK(aqt_trusted_time_v2_fork_guard_initialize_before_python() == 0);
    AQT_CHECK(pipe(descriptors) == 0);
    context.descriptor = descriptors[0];
    context.slot = 0;
    context.result = 0;
    aqt_trusted_time_v2_fork_guard_test_pause_after_slot_mutation();
    AQT_CHECK(pthread_create(&thread, NULL, aqt_guard_race_register_main, &context) == 0);
    while (!aqt_trusted_time_v2_fork_guard_test_slot_mutation_is_paused()) {
        (void)sched_yield();
    }
    child = fork();
    AQT_CHECK(child >= 0);
    if (child == 0) {
        errno = 0;
        if (!aqt_trusted_time_v2_fork_guard_is_poisoned()
            || fcntl(descriptors[0], F_GETFD) != -1
            || errno != EBADF) {
            _exit(30);
        }
        _exit(0);
    }
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_is_poisoned());
    aqt_trusted_time_v2_fork_guard_test_resume_slot_mutation();
    AQT_CHECK(pthread_join(thread, NULL) == 0);
    AQT_CHECK(context.result == 0);
    AQT_CHECK(waitpid(child, &status, 0) == child);
    AQT_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    AQT_CHECK(close(descriptors[0]) == 0);
    AQT_CHECK(close(descriptors[1]) == 0);
    return 0;
}

static void *
aqt_concurrent_fork_main(void *opaque)
{
    aqt_concurrent_fork_context *context = (aqt_concurrent_fork_context *)opaque;
    pid_t child = fork();
    int status;

    if (child < 0) {
        context->result = errno == 0 ? EIO : errno;
        return NULL;
    }
    if (child == 0) {
        if (!aqt_trusted_time_v2_fork_guard_is_poisoned()) {
            _exit(40);
        }
        if (context->expect_closed != 0) {
            errno = 0;
            if (fcntl(context->descriptor, F_GETFD) != -1 || errno != EBADF) {
                _exit(41);
            }
        }
        _exit(0);
    }
    if (waitpid(child, &status, 0) != child
        || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        context->result = EIO;
        return NULL;
    }
    context->result = 0;
    return NULL;
}

static int
aqt_test_guard_prepare_close_race(void)
{
    int descriptors[2];
    uint32_t slot;
    pthread_t fork_thread;
    pthread_t close_thread;
    aqt_concurrent_fork_context context;
    aqt_guard_race_context close_context;

    AQT_CHECK(aqt_trusted_time_v2_fork_guard_initialize_before_python() == 0);
    AQT_CHECK(pipe(descriptors) == 0);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_register_fd(descriptors[0], &slot) == 0);
    context.descriptor = descriptors[0];
    context.expect_closed = 1;
    context.result = 0;
    aqt_trusted_time_v2_fork_guard_test_pause_next_prepare();
    AQT_CHECK(pthread_create(&fork_thread, NULL, aqt_concurrent_fork_main, &context) == 0);
    while (!aqt_trusted_time_v2_fork_guard_test_prepare_is_paused()) {
        (void)sched_yield();
    }
    close_context.descriptor = descriptors[0];
    close_context.slot = slot;
    close_context.result = 0;
    aqt_trusted_time_v2_fork_guard_test_pause_after_fd_close();
    AQT_CHECK(pthread_create(
        &close_thread, NULL, aqt_guard_race_close_main, &close_context) == 0);
    while (!aqt_trusted_time_v2_fork_guard_test_fd_close_is_paused()) {
        (void)sched_yield();
    }
    aqt_trusted_time_v2_fork_guard_test_resume_prepare();
    AQT_CHECK(pthread_join(fork_thread, NULL) == 0);
    AQT_CHECK(context.result == 0);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_is_poisoned());
    aqt_trusted_time_v2_fork_guard_test_resume_fd_close();
    AQT_CHECK(pthread_join(close_thread, NULL) == 0);
    AQT_CHECK(close_context.result == 0);
    AQT_CHECK(close(descriptors[1]) == 0);
    return 0;
}

static void *
aqt_prepare_pair_main(void *opaque)
{
    aqt_concurrent_fork_context *context = (aqt_concurrent_fork_context *)opaque;
    aqt_trusted_time_v2_fork_guard_test_invoke_prepare();
    aqt_trusted_time_v2_fork_guard_test_invoke_parent();
    context->result = 0;
    return NULL;
}

static int
aqt_test_concurrent_fork_prepares(void)
{
    pthread_t thread;
    aqt_concurrent_fork_context context;

    AQT_CHECK(aqt_trusted_time_v2_fork_guard_initialize_before_python() == 0);
    context.descriptor = -1;
    context.expect_closed = 0;
    context.result = 0;
    aqt_trusted_time_v2_fork_guard_test_pause_next_prepare();
    AQT_CHECK(pthread_create(&thread, NULL, aqt_prepare_pair_main, &context) == 0);
    while (!aqt_trusted_time_v2_fork_guard_test_prepare_is_paused()) {
        (void)sched_yield();
    }
    aqt_trusted_time_v2_fork_guard_test_invoke_prepare();
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_is_poisoned());
    aqt_trusted_time_v2_fork_guard_test_invoke_parent();
    aqt_trusted_time_v2_fork_guard_test_resume_prepare();
    AQT_CHECK(pthread_join(thread, NULL) == 0);
    AQT_CHECK(context.result == 0);
    return 0;
}

static int
aqt_test_python_cross_signature(const char *operation, const char *message_path)
{
    static const char seed_hex[] =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    static const char public_key_hex[] =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    char directory_template[] = "/tmp/aqt-v2-cross-XXXXXX";
    uint8_t seed[32];
    uint8_t public_key[32];
    uint8_t signature[64];
    uint8_t *message;
    struct stat metadata;
    aqt_trusted_time_v2_signer_owner *owner = NULL;
    const uintptr_t interpreter_identity = (uintptr_t)0x63726f7373U;
    int descriptor;
    size_t offset = 0;
    ssize_t read_size;
    int result;
    size_t index;
    char *directory_path;

    descriptor = open(message_path, O_RDONLY | O_CLOEXEC);
    AQT_CHECK(descriptor >= 0);
    AQT_CHECK(fstat(descriptor, &metadata) == 0);
    AQT_CHECK(metadata.st_size > 0
              && metadata.st_size <= (off_t)AQT_TRUSTED_TIME_V2_SIGNER_MAXIMUM_MESSAGE_BYTES);
    message = (uint8_t *)malloc((size_t)metadata.st_size);
    AQT_CHECK(message != NULL);
    while (offset < (size_t)metadata.st_size) {
        read_size = read(descriptor, message + offset, (size_t)metadata.st_size - offset);
        AQT_CHECK(read_size > 0);
        offset += (size_t)read_size;
    }
    AQT_CHECK(close(descriptor) == 0);
    AQT_CHECK(aqt_decode_hex(seed_hex, seed, sizeof(seed)) == 0);
    AQT_CHECK(aqt_decode_hex(public_key_hex, public_key, sizeof(public_key)) == 0);
    AQT_CHECK(aqt_trusted_time_v2_fork_guard_initialize_before_python() == 0);
    AQT_CHECK(aqt_trusted_time_v2_signer_initialize_before_python() == 0);
    directory_path = mkdtemp(directory_template);
    AQT_CHECK(directory_path != NULL);
    AQT_CHECK(chown(directory_path, geteuid(), getegid()) == 0);
    AQT_CHECK(chmod(directory_path, (mode_t)0700) == 0);
    AQT_CHECK(aqt_write_seed_file(directory_path, seed) == 0);
    AQT_CHECK(aqt_open_test_owner(
        directory_path, public_key, interpreter_identity, &owner) == 0);

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
    if (strcmp(operation, "host-hello") == 0) {
        result = aqt_trusted_time_v2_signer_sign_host_hello(
            owner, interpreter_identity, message, offset, signature);
    } else if (strcmp(operation, "clean-stop-request") == 0) {
        result = aqt_trusted_time_v2_signer_sign_clean_stop_request(
            owner, interpreter_identity, message, offset, signature);
    } else {
        result = ENOTSUP;
    }
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE)
    if (strcmp(operation, "recovery-classification") == 0) {
        result = aqt_trusted_time_v2_signer_sign_recovery_classification(
            owner, interpreter_identity, message, offset, signature);
    } else {
        result = ENOTSUP;
    }
#else
    (void)operation;
    result = ENOTSUP;
#endif
    AQT_CHECK(result == 0);
    for (index = 0; index < sizeof(signature); ++index) {
        (void)printf("%02x", (unsigned int)signature[index]);
    }
    (void)printf("\n");
    AQT_CHECK(aqt_trusted_time_v2_signer_owner_close(&owner, interpreter_identity) == 0);
    AQT_CHECK(rmdir(directory_path) == 0);
    crypto_wipe(seed, sizeof(seed));
    free(message);
    return 0;
}

int
main(int argument_count, char **arguments)
{
    if (argument_count == 4 && strcmp(arguments[1], "python-cross") == 0) {
        return aqt_test_python_cross_signature(arguments[2], arguments[3]);
    }
    if (argument_count != 2) {
        return 2;
    }
    if (strcmp(arguments[1], "rfc8032") == 0) {
        return aqt_test_rfc8032();
    }
    if (strcmp(arguments[1], "signer") == 0) {
        return aqt_test_signer();
    }
    if (strcmp(arguments[1], "guard-race") == 0) {
        return aqt_test_guard_race();
    }
    if (strcmp(arguments[1], "guard-prepare-close-race") == 0) {
        return aqt_test_guard_prepare_close_race();
    }
    if (strcmp(arguments[1], "guard-concurrent-prepares") == 0) {
        return aqt_test_concurrent_fork_prepares();
    }
    return 2;
}
