#ifndef AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESOURCES_H
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESOURCES_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TRANSPORT_DIRECTORY                  \
  "/run/autoquant/trusted-time/graceful-stop-v2/transport"
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH                          \
  AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TRANSPORT_DIRECTORY "/supervisor.sock"
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_BASENAME "supervisor.sock"

typedef struct aqt_trusted_time_v2_host_transport_resources
    aqt_trusted_time_v2_host_transport_resources;
typedef struct aqt_trusted_time_v2_supervisor_transport_resources
    aqt_trusted_time_v2_supervisor_transport_resources;

/*
 * These are endpoint-internal role surfaces.  They return zero on success and
 * a positive errno value on rejection.  They never accept a path, role, UID,
 * GID, mount option, or expected peer credential from a caller.  Every method
 * requires the same nonzero interpreter-instance identity captured at prepare.
 */
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
int aqt_trusted_time_v2_host_transport_resources_prepare(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_v2_host_transport_resources **owner_out);
int aqt_trusted_time_v2_host_transport_resources_bind_connected_peer(
    aqt_trusted_time_v2_host_transport_resources *owner,
    uintptr_t interpreter_instance_identity, int connected_socket);
int aqt_trusted_time_v2_host_transport_resources_revalidate(
    aqt_trusted_time_v2_host_transport_resources *owner,
    uintptr_t interpreter_instance_identity);
int aqt_trusted_time_v2_host_transport_resources_close(
    aqt_trusted_time_v2_host_transport_resources **owner_io,
    uintptr_t interpreter_instance_identity);
#endif

#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
int aqt_trusted_time_v2_supervisor_transport_resources_prepare(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_v2_supervisor_transport_resources **owner_out);
int aqt_trusted_time_v2_supervisor_transport_resources_bind_listener(
    aqt_trusted_time_v2_supervisor_transport_resources *owner,
    uintptr_t interpreter_instance_identity, int listener_socket);
int aqt_trusted_time_v2_supervisor_transport_resources_bind_accepted_peer(
    aqt_trusted_time_v2_supervisor_transport_resources *owner,
    uintptr_t interpreter_instance_identity, int accepted_socket);
int aqt_trusted_time_v2_supervisor_transport_resources_revalidate(
    aqt_trusted_time_v2_supervisor_transport_resources *owner,
    uintptr_t interpreter_instance_identity);
int aqt_trusted_time_v2_supervisor_transport_resources_close(
    aqt_trusted_time_v2_supervisor_transport_resources **owner_io,
    uintptr_t interpreter_instance_identity);
#endif

#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
typedef struct {
  uint64_t device;
  uint64_t inode;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t link_count;
  int64_t size;
  int64_t modification_seconds;
  int64_t modification_nanoseconds;
  int64_t change_seconds;
  int64_t change_nanoseconds;
} aqt_trusted_time_v2_test_stat9;

typedef struct {
  uint64_t mount_id;
  uint64_t parent_mount_id;
  uint32_t major_device;
  uint32_t minor_device;
  char mount_root[8];
  char mount_options[128];
} aqt_trusted_time_v2_test_mount_identity;

int aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
    const unsigned char *mountinfo, size_t mountinfo_length,
    aqt_trusted_time_v2_test_mount_identity *identity_out);
int aqt_trusted_time_v2_resources_test_host_peer_values(uint32_t uid,
                                                        uint32_t gid,
                                                        int64_t pid);
int aqt_trusted_time_v2_resources_test_supervisor_peer_values(uint32_t uid,
                                                              uint32_t gid,
                                                              int64_t pid);
int aqt_trusted_time_v2_resources_test_transport_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count);
int aqt_trusted_time_v2_resources_test_socket_metadata(uint32_t uid,
                                                       uint32_t gid,
                                                       uint32_t mode,
                                                       uint64_t link_count);
int aqt_trusted_time_v2_resources_test_stat9_equal(
    const aqt_trusted_time_v2_test_stat9 *left,
    const aqt_trusted_time_v2_test_stat9 *right);
int aqt_trusted_time_v2_resources_test_overlay_link_count(uint64_t link_count);
int aqt_trusted_time_v2_resources_test_strict_directory_link_count(
    uint64_t link_count);
int aqt_trusted_time_v2_resources_test_transport_component_link_count(
    size_t component_index, uint64_t link_count);
int aqt_trusted_time_v2_resources_test_proc_root_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count);
int aqt_trusted_time_v2_resources_test_peer_process_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count);
int aqt_trusted_time_v2_resources_test_peer_namespace_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count);
int aqt_trusted_time_v2_resources_test_executable_metadata(uint32_t uid,
                                                           uint32_t gid,
                                                           uint32_t mode,
                                                           uint64_t link_count,
                                                           int64_t size);
int aqt_trusted_time_v2_resources_test_executable_path_pair(
    const char *first, int64_t first_length, const char *second,
    int64_t second_length);
int aqt_trusted_time_v2_resources_test_current_process_proc_admission(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
