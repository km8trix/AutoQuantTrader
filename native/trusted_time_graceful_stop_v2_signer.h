#ifndef AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SIGNER_H
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#if (defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE)) != 1
#error "compile exactly one trusted-time v2 signer role profile"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AQT_TRUSTED_TIME_V2_ED25519_PUBLIC_KEY_BYTES 32U
#define AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES 64U
#define AQT_TRUSTED_TIME_V2_SIGNER_MAXIMUM_MESSAGE_BYTES 262144U

typedef struct aqt_trusted_time_v2_signer_owner aqt_trusted_time_v2_signer_owner;

/* All int functions return zero on success and a positive errno on rejection. */

/* Run after the fork guard and before Py_InitializeFromConfig. */
int aqt_trusted_time_v2_signer_initialize_before_python(void);

#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TEST_PROFILE
/*
 * Takes ownership of both descriptors on every return path.  The directory
 * descriptor must name the directory containing literal `credential.raw`.
 */
int aqt_trusted_time_v2_signer_owner_open_preopened(
    aqt_trusted_time_v2_signer_owner **owner_out,
    int credential_directory_fd,
    int credential_fd,
    const uint8_t expected_public_key[AQT_TRUSTED_TIME_V2_ED25519_PUBLIC_KEY_BYTES],
    uintptr_t interpreter_identity
);
#else
/* Opens only the role's compiled literal production directory and basename. */
int aqt_trusted_time_v2_signer_owner_open(
    aqt_trusted_time_v2_signer_owner **owner_out,
    const uint8_t expected_public_key[AQT_TRUSTED_TIME_V2_ED25519_PUBLIC_KEY_BYTES],
    uintptr_t interpreter_identity
);
#endif

int aqt_trusted_time_v2_signer_owner_read_public_key(
    const aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    uint8_t public_key_out[AQT_TRUSTED_TIME_V2_ED25519_PUBLIC_KEY_BYTES]
);

/* A NULL owner value is an idempotent successful close. */
int aqt_trusted_time_v2_signer_owner_close(
    aqt_trusted_time_v2_signer_owner **owner_io,
    uintptr_t interpreter_identity
);

/*
 * Role methods accept only complete canonical_v2_json_bytes unsigned objects,
 * including their single trailing LF.  Callers must first obtain the bytes
 * from the matching exact typed contract; the native discriminator checks are
 * an independent role/domain gate, not a replacement schema decoder.
 */

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE)
int aqt_trusted_time_v2_signer_sign_host_hello(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
int aqt_trusted_time_v2_signer_sign_host_channel_confirmation(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
int aqt_trusted_time_v2_signer_sign_clean_stop_request(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE)
int aqt_trusted_time_v2_signer_sign_supervisor_hello(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
int aqt_trusted_time_v2_signer_sign_clean_stop_result(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
int aqt_trusted_time_v2_signer_sign_clean_stop_error(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
int aqt_trusted_time_v2_signer_sign_supervisor_cleanup_commitment(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE)
int aqt_trusted_time_v2_signer_sign_recovery_classification(
    aqt_trusted_time_v2_signer_owner *owner,
    uintptr_t interpreter_identity,
    const uint8_t *canonical_unsigned_message,
    size_t message_size,
    uint8_t signature_out[AQT_TRUSTED_TIME_V2_ED25519_SIGNATURE_BYTES]
);
#endif

#ifdef AQT_TRUSTED_TIME_V2_SIGNER_TESTING
int aqt_trusted_time_v2_signer_test_last_close_zeroized(void);
int aqt_trusted_time_v2_signer_test_fork_secret_is_zero(
    const aqt_trusted_time_v2_signer_owner *owner
);
#endif

#ifdef __cplusplus
}
#endif

#endif
