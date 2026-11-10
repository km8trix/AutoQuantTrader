#include "trusted_time_v2_provisioner.h"

#include "monocypher-ed25519.h"
#include "monocypher.h"

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
aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration *destination
)
{
    unsigned char seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    unsigned char secret_key[64];

    if (destination == NULL) {
        return -1;
    }
    memset(destination, 0, sizeof(*destination));
    destination->generation = 1U;
    crypto_ed25519_key_pair(
        secret_key,
        destination->expected_public_key,
        seed
    );
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(seed, sizeof(seed));
    return 0;
}
