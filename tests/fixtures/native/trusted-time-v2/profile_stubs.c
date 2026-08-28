#include "trusted_time_v2_provisioner.h"

#include <stddef.h>
#include <string.h>

int
aqt_trusted_time_v2_fork_guard_initialize_before_python(void)
{
    return 0;
}

int
aqt_trusted_time_v2_fork_guard_is_poisoned(void)
{
    return 0;
}

int
aqt_trusted_time_v2_fork_guard_require_owner_table_empty(void)
{
    return 0;
}

int
aqt_trusted_time_v2_signer_initialize_before_python(void)
{
    return 0;
}

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python(void)
{
    return 0;
}
#endif

void
aqt_trusted_time_graceful_stop_v2_signer_explicit_wipe(void *payload, size_t size)
{
    volatile unsigned char *cursor = (volatile unsigned char *)payload;
    while (size > 0U) {
        *cursor++ = 0U;
        size--;
    }
}

int
aqt_trusted_time_graceful_stop_v2_signer_derive_public_key_for_provisioning(
    const unsigned char seed[32],
    unsigned char public_key[32]
)
{
    memcpy(public_key, seed, 32U);
    return 0;
}

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    memset(destination, 0, sizeof(*destination));
    return -1;
}
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_consume_authenticated_supervisor_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    memset(destination, 0, sizeof(*destination));
    return -1;
}
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)
int
aqt_trusted_time_graceful_stop_v2_consume_authenticated_recovery_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    memset(destination, 0, sizeof(*destination));
    return -1;
}
#endif
