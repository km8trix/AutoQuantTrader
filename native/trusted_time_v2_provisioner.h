#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_H
#define AQT_TRUSTED_TIME_V2_PROVISIONER_H

#include <stdint.h>

#define AQT_TRUSTED_TIME_V2_PROVISION_PUBLIC_KEY_BYTES 32U

typedef struct {
    uint32_t generation;
    unsigned char expected_public_key[AQT_TRUSTED_TIME_V2_PROVISION_PUBLIC_KEY_BYTES];
} AqtTrustedTimeV2AuthenticatedProvisioningGeneration;

/*
 * The fixed authority adapter supplies one already-authenticated, one-use
 * generation.  Exactly one declaration survives preprocessing in each role.
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

int aqt_trusted_time_v2_provisioner_main(int argument_count, char **argument_values);

#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_API
int aqt_trusted_time_v2_provisioner_format_generation_for_test(
    uint32_t generation,
    char destination[9]
);
const char *aqt_trusted_time_v2_provisioner_role_name_for_test(void);
const char *aqt_trusted_time_v2_provisioner_credential_name_for_test(void);
const char *aqt_trusted_time_v2_provisioner_target_path_for_test(void);
#endif

#endif
