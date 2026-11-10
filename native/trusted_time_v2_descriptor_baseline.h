#ifndef AQT_TRUSTED_TIME_V2_DESCRIPTOR_BASELINE_H
#define AQT_TRUSTED_TIME_V2_DESCRIPTOR_BASELINE_H

/*
 * Establish the fixed descriptor baseline before the fork guard or seccomp
 * policy is installed.  Descriptors zero through two must exist and must not
 * be sockets or Linux anonymous-inode capabilities.  Every descriptor above
 * two is closed rather than inherited into an owner or provisioner.
 */
int aqt_trusted_time_v2_close_ambient_descriptors(void);
int aqt_trusted_time_v2_validate_standard_descriptors(void);

#endif
