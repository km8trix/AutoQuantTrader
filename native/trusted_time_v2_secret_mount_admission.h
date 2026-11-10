#ifndef AQT_TRUSTED_TIME_V2_SECRET_MOUNT_ADMISSION_H
#define AQT_TRUSTED_TIME_V2_SECRET_MOUNT_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

#if ((defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE) \
      || defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)) \
     + (defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE) \
        || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)) \
     + (defined(AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE) \
        || defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE))) != 1
#error "compile exactly one trusted-time v2 secret-mount role profile"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct aqt_trusted_time_v2_secret_mount_admission
    aqt_trusted_time_v2_secret_mount_admission;

/*
 * The caller retains ownership of `directory_fd`.  The selected build role
 * fixes the only admitted absolute mountpoint, ownership, mode, filesystem,
 * and option sets.  No runtime path or option input exists.  Capture also
 * correlates the caller-held descriptor to that literal mountpoint and freezes
 * its complete Stat9 projection.
 *
 * A controlled directory mutation is composed from two admissions: capture
 * and revalidate immediately before the one fixed create/unlink, close that
 * pre-mutation admission, then capture a new post-mutation admission on the
 * same retained descriptor.  This API intentionally exposes no rebaseline.
 */
int aqt_trusted_time_v2_secret_mount_admission_capture(
    aqt_trusted_time_v2_secret_mount_admission **admission_out,
    int directory_fd,
    uintptr_t interpreter_identity
);

int aqt_trusted_time_v2_secret_mount_admission_revalidate(
    const aqt_trusted_time_v2_secret_mount_admission *admission,
    int directory_fd,
    uintptr_t interpreter_identity
);

int aqt_trusted_time_v2_secret_mount_admission_close(
    aqt_trusted_time_v2_secret_mount_admission **admission_io,
    uintptr_t interpreter_identity
);

#ifdef AQT_TRUSTED_TIME_V2_SECRET_MOUNT_ADMISSION_TESTING
int aqt_trusted_time_v2_secret_mount_admission_test_parse_mountinfo(
    const unsigned char *mountinfo,
    size_t mountinfo_length,
    uint32_t expected_major_device,
    uint32_t expected_minor_device
);
int aqt_trusted_time_v2_secret_mount_admission_test_compare_mountinfo(
    const unsigned char *first,
    size_t first_length,
    const unsigned char *second,
    size_t second_length
);
int aqt_trusted_time_v2_secret_mount_admission_test_secure_directory_metadata(
    uint32_t uid,
    uint32_t gid,
    uint32_t mode,
    uint64_t link_count
);
int aqt_trusted_time_v2_secret_mount_admission_test_root_directory_metadata(
    uint32_t uid,
    uint32_t gid,
    uint32_t mode,
    uint64_t link_count
);
int aqt_trusted_time_v2_secret_mount_admission_test_run_directory_metadata(
    uint32_t uid,
    uint32_t gid,
    uint32_t mode,
    uint64_t link_count
);
#endif

#ifdef __cplusplus
}
#endif

#endif
