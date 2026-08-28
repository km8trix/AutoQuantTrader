#include "trusted_time_v2_provisioner.h"
#include "trusted_time_v2_seccomp.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int
main(void)
{
    char generation[9];
    size_t count = 0U;
#ifdef __linux__
    const unsigned char *initial_bytes = NULL;
    const unsigned char *repeated_bytes = NULL;
    const unsigned char *post_child_bytes = NULL;
    size_t initial_size = 0U;
    size_t repeated_size = 0U;
    size_t post_child_size = 0U;
#endif

    memset(generation, 0x7f, sizeof(generation));
    if (aqt_trusted_time_v2_provisioner_format_generation_for_test(0U, generation) == 0
        || aqt_trusted_time_v2_provisioner_format_generation_for_test(
            100000000U,
            generation
        ) == 0
        || aqt_trusted_time_v2_provisioner_format_generation_for_test(1U, generation) != 0
        || strcmp(generation, "00000001") != 0
        || aqt_trusted_time_v2_provisioner_format_generation_for_test(42U, generation) != 0
        || strcmp(generation, "00000042") != 0
        || aqt_trusted_time_v2_provisioner_format_generation_for_test(
            99999999U,
            generation
        ) != 0
        || strcmp(generation, "99999999") != 0) {
        return 1;
    }
    if (aqt_trusted_time_v2_provisioner_role_name_for_test() == NULL
        || aqt_trusted_time_v2_provisioner_credential_name_for_test() == NULL
        || aqt_trusted_time_v2_provisioner_target_path_for_test() == NULL) {
        return 2;
    }
    if (strcmp(
            aqt_trusted_time_v2_seccomp_policy_model(),
            "ordered-default-allow-denylist-v1"
        ) != 0
        || strcmp(aqt_trusted_time_v2_seccomp_profile_name(), "provisioner") != 0) {
        return 3;
    }
#ifdef __linux__
    if (aqt_trusted_time_v2_seccomp_filter_count(
            AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE,
            &count
        ) != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        || count != 1U
        || aqt_trusted_time_v2_seccomp_filter_bytes(
            AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE,
            0U,
            &initial_bytes,
            &initial_size
        ) != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        || aqt_trusted_time_v2_seccomp_filter_bytes(
            AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE,
            0U,
            &repeated_bytes,
            &repeated_size
        ) != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        || aqt_trusted_time_v2_seccomp_filter_bytes(
            AQT_TRUSTED_TIME_V2_SECCOMP_POST_CHILD_PHASE,
            0U,
            &post_child_bytes,
            &post_child_size
        ) != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        || initial_bytes == NULL || post_child_bytes == NULL
        || initial_size == 0U || post_child_size == 0U
        || initial_size % 8U != 0U || post_child_size % 8U != 0U
        || repeated_bytes != initial_bytes || repeated_size != initial_size
        || memcmp(initial_bytes, repeated_bytes, initial_size) != 0) {
        return 4;
    }
#else
    if (aqt_trusted_time_v2_seccomp_filter_count(
            AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE,
            &count
        ) != AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED) {
        return 5;
    }
#endif
    return 0;
}
