#ifndef AQT_TRUSTED_TIME_V2_PROVISIONER_H
#define AQT_TRUSTED_TIME_V2_PROVISIONER_H

#include <stdint.h>

#include "trusted_time_v2_authority.h"

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
