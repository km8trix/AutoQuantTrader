#ifndef AQT_TRUSTED_TIME_V2_AUTHORITY_H
#define AQT_TRUSTED_TIME_V2_AUTHORITY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AQT_TRUSTED_TIME_V2_PROVISION_PUBLIC_KEY_BYTES 32U
#define AQT_TRUSTED_TIME_V2_AUTHORITY_SHA256_BYTES 32U

typedef struct {
    uint32_t generation;
    unsigned char expected_public_key[AQT_TRUSTED_TIME_V2_PROVISION_PUBLIC_KEY_BYTES];
} AqtTrustedTimeV2AuthenticatedProvisioningGeneration;

/*
 * Each candidate links exactly one role-specific entry point.  These
 * functions accept no caller path, generation, role, environment, or key.
 */
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
int aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
);
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
int aqt_trusted_time_graceful_stop_v2_consume_authenticated_supervisor_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
);
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)
int aqt_trusted_time_graceful_stop_v2_consume_authenticated_recovery_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
);
#endif

#ifdef AQT_TRUSTED_TIME_V2_AUTHORITY_TESTING
typedef enum {
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_HOST = 1,
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_SUPERVISOR = 2,
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_RECOVERY = 3,
} AqtTrustedTimeV2AuthorityTestRole;

/* Takes ownership of authority_directory_fd on every return path. */
int aqt_trusted_time_v2_authority_test_consume_preopened(
    int authority_directory_fd,
    AqtTrustedTimeV2AuthorityTestRole role,
    uint32_t injected_root_generation,
    const unsigned char *injected_root_manifest_sha256,
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
);

void aqt_trusted_time_v2_authority_test_pause_after_read(int enabled);
int aqt_trusted_time_v2_authority_test_read_is_paused(void);
void aqt_trusted_time_v2_authority_test_resume_read(void);

typedef enum {
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_NONE = 0,
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_PID = 1,
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_THREAD = 2,
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_INTERPRETER = 3,
    AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_FORK_EPOCH = 4,
} AqtTrustedTimeV2AuthorityTestIdentityFault;

void aqt_trusted_time_v2_authority_test_set_identity_fault(
    AqtTrustedTimeV2AuthorityTestIdentityFault fault
);
#endif

#ifdef __cplusplus
}
#endif

#endif
