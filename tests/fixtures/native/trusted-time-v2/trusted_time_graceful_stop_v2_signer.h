#ifndef AQT_TEST_TRUSTED_TIME_GRACEFUL_STOP_V2_SIGNER_H
#define AQT_TEST_TRUSTED_TIME_GRACEFUL_STOP_V2_SIGNER_H

#include <stddef.h>

int aqt_trusted_time_v2_signer_initialize_before_python(void);
void aqt_trusted_time_graceful_stop_v2_signer_explicit_wipe(void *payload, size_t size);
int aqt_trusted_time_graceful_stop_v2_signer_derive_public_key_for_provisioning(
    const unsigned char seed[32],
    unsigned char public_key[32]
);

#endif
