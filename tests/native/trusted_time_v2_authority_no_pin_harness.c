#include "trusted_time_v2_authority.h"
#include "trusted_time_v2_fork_guard.h"

#include <stddef.h>
#include <string.h>

int
main(void)
{
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration generation;
    unsigned char zero[sizeof(generation)];
    int result;

    memset(&generation, 0xa5, sizeof(generation));
    memset(zero, 0, sizeof(zero));
    if (aqt_trusted_time_v2_fork_guard_initialize_before_python() != 0) {
        return 90;
    }
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
    result =
        aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
            &generation
        );
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
    result =
        aqt_trusted_time_graceful_stop_v2_consume_authenticated_supervisor_provisioning_generation(
            &generation
        );
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)
    result =
        aqt_trusted_time_graceful_stop_v2_consume_authenticated_recovery_provisioning_generation(
            &generation
        );
#else
#error "compile exactly one no-pin harness role"
#endif
    if (result == 0
        || memcmp(&generation, zero, sizeof(generation)) != 0
        || aqt_trusted_time_v2_fork_guard_require_owner_table_empty() != 0) {
        return 91;
    }
    return 0;
}
