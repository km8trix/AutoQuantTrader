#define _GNU_SOURCE

#include "trusted_time_graceful_stop_v2_endpoint.h"
#include "trusted_time_graceful_stop_v2_resources.h"
#include "trusted_time_v2_fork_guard.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_INTERPRETER_IDENTITY ((uintptr_t)UINT64_C(0x4151545707000001))

#define aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(       \
    descriptor, deadline, owner_out)                                           \
  aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(             \
      descriptor, deadline, TEST_INTERPRETER_IDENTITY, owner_out)
#define aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test( \
    descriptor, deadline, owner_out)                                           \
  aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(       \
      descriptor, deadline, TEST_INTERPRETER_IDENTITY, owner_out)
#define aqt_trusted_time_graceful_stop_v2_host_send_hello(owner, bytes,        \
                                                          length)              \
  aqt_trusted_time_graceful_stop_v2_host_send_hello(                           \
      owner, TEST_INTERPRETER_IDENTITY, bytes, length)
#define aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(       \
    owner, output, capacity, length_out)                                       \
  aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(             \
      owner, TEST_INTERPRETER_IDENTITY, output, capacity, length_out)
#define aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation(      \
    owner, bytes, length)                                                      \
  aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation(            \
      owner, TEST_INTERPRETER_IDENTITY, bytes, length)
#define aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(        \
    owner, bytes, length, deadline)                                            \
  aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(              \
      owner, TEST_INTERPRETER_IDENTITY, bytes, length, deadline)
#define aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error( \
    owner, output, capacity, length_out, deadline)                               \
  aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error(       \
      owner, TEST_INTERPRETER_IDENTITY, output, capacity, length_out,            \
      deadline)
#define aqt_trusted_time_graceful_stop_v2_host_close(owner_io)                 \
  aqt_trusted_time_graceful_stop_v2_host_close(owner_io,                       \
                                               TEST_INTERPRETER_IDENTITY)
#define aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(       \
    owner, output, capacity, length_out)                                       \
  aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(             \
      owner, TEST_INTERPRETER_IDENTITY, output, capacity, length_out)
#define aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(owner, bytes,  \
                                                                length)        \
  aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(                     \
      owner, TEST_INTERPRETER_IDENTITY, bytes, length)
#define aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation( \
    owner, output, capacity, length_out)                                        \
  aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation(       \
      owner, TEST_INTERPRETER_IDENTITY, output, capacity, length_out)
#define aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request( \
    owner, output, capacity, length_out, deadline)                               \
  aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request(       \
      owner, TEST_INTERPRETER_IDENTITY, output, capacity, length_out,            \
      deadline)
#define aqt_trusted_time_graceful_stop_v2_supervisor_send_terminal_result_or_error( \
    owner, kind, bytes, length, deadline)                                           \
  aqt_trusted_time_graceful_stop_v2_supervisor_send_terminal_result_or_error(       \
      owner, TEST_INTERPRETER_IDENTITY, kind, bytes, length, deadline)
#define aqt_trusted_time_graceful_stop_v2_supervisor_close(owner_io)           \
  aqt_trusted_time_graceful_stop_v2_supervisor_close(                          \
      owner_io, TEST_INTERPRETER_IDENTITY)

#define CHECK(expression)                                                      \
  do {                                                                         \
    if (!(expression)) {                                                       \
      (void)fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, \
                    #expression);                                              \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int test_resource_validators(void) {
  static const unsigned char valid_mount[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char missing_noexec[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char wrong_path[] =
      "42 1 0:77 / /run/not-autoquant "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char reordered_mount[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "noexec,nodev,relatime,rw,nosuid - tmpfs tmpfs "
      "gid=10001,size=64k,mode=770,rw\n";
  static const unsigned char duplicate_option[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime,noexec - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char trailing_option_separator[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime, - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char ambiguous_spacing[] =
      "42  1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char read_only[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "ro,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char executable[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,exec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char devices[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,dev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char setuid[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,suid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char wrong_size[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=65k,mode=770,gid=10001,inode64\n";
  static const unsigned char duplicate_size[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char wrong_uid_option[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,uid=1,inode64\n";
  static const unsigned char wrong_gid_option[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=1,inode64\n";
  static const unsigned char wrong_mode_option[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs "
      "rw,size=64k,mode=777,gid=10001,inode64\n";
  static const unsigned char unknown_option[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,noatime - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  static const unsigned char shared_projection[] =
      "42 1 0:77 / "
      "/run/autoquant/trusted-time/graceful-stop-v2/transport "
      "rw,nosuid,nodev,noexec,relatime shared:9 - tmpfs tmpfs "
      "rw,size=64k,mode=770,gid=10001,inode64\n";
  unsigned char duplicate[sizeof(valid_mount) * 2U];
  unsigned char control[sizeof(valid_mount)];
  aqt_trusted_time_v2_test_mount_identity identity;
  aqt_trusted_time_v2_test_stat9 left;
  aqt_trusted_time_v2_test_stat9 right;

  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            valid_mount, sizeof(valid_mount) - 1U, &identity) == 0);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            valid_mount, sizeof(valid_mount) - 2U, &identity) == EINVAL);
  memcpy(control, valid_mount, sizeof(valid_mount));
  control[2] = (unsigned char)'\t';
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            control, sizeof(control) - 1U, &identity) == EINVAL);
  control[2] = 0x7fU;
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            control, sizeof(control) - 1U, &identity) == EINVAL);
  CHECK(identity.mount_id == 42U);
  CHECK(identity.parent_mount_id == 1U);
  CHECK(identity.major_device == 0U);
  CHECK(identity.minor_device == 77U);
  CHECK(strcmp(identity.mount_root, "/") == 0);
  CHECK(strstr(identity.mount_options, "size=64K") != NULL);
  CHECK(strstr(identity.mount_options, "mode=770") != NULL);
  CHECK(strstr(identity.mount_options, "gid=10001") != NULL);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            reordered_mount, sizeof(reordered_mount) - 1U, &identity) == 0);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            missing_noexec, sizeof(missing_noexec) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            wrong_path, sizeof(wrong_path) - 1U, &identity) == ENOENT);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            duplicate_option, sizeof(duplicate_option) - 1U, &identity) ==
        EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            trailing_option_separator, sizeof(trailing_option_separator) - 1U,
            &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            ambiguous_spacing, sizeof(ambiguous_spacing) - 1U, &identity) ==
        EINVAL);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            read_only, sizeof(read_only) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            executable, sizeof(executable) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            devices, sizeof(devices) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            setuid, sizeof(setuid) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            wrong_size, sizeof(wrong_size) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            duplicate_size, sizeof(duplicate_size) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            wrong_uid_option, sizeof(wrong_uid_option) - 1U, &identity) ==
        EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            wrong_gid_option, sizeof(wrong_gid_option) - 1U, &identity) ==
        EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            wrong_mode_option, sizeof(wrong_mode_option) - 1U, &identity) ==
        EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            unknown_option, sizeof(unknown_option) - 1U, &identity) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            shared_projection, sizeof(shared_projection) - 1U, &identity) ==
        EPERM);
  memcpy(duplicate, valid_mount, sizeof(valid_mount) - 1U);
  memcpy(duplicate + sizeof(valid_mount) - 1U, valid_mount,
         sizeof(valid_mount) - 1U);
  CHECK(aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
            duplicate, 2U * (sizeof(valid_mount) - 1U), &identity) == EPERM);

  CHECK(aqt_trusted_time_v2_resources_test_host_peer_values(10001U, 10001U,
                                                            1) == 0);
  CHECK(aqt_trusted_time_v2_resources_test_host_peer_values(10001U, 10001U,
                                                            0) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_host_peer_values(0U, 10001U, 1) ==
        EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_supervisor_peer_values(0U, 0U, 0) ==
        0);
  CHECK(aqt_trusted_time_v2_resources_test_supervisor_peer_values(0U, 0U, 1) ==
        EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_supervisor_peer_values(
            10001U, 10001U, 0) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_transport_directory_metadata(
            0U, 10001U, 0770U, 2U) == 0);
  CHECK(aqt_trusted_time_v2_resources_test_transport_directory_metadata(
            0U, 10001U, 0750U, 2U) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_transport_directory_metadata(
            10001U, 10001U, 0770U, 2U) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_transport_directory_metadata(
            0U, 0U, 0770U, 2U) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_socket_metadata(10001U, 10001U,
                                                           0600U, 1U) == 0);
  CHECK(aqt_trusted_time_v2_resources_test_socket_metadata(10001U, 10001U,
                                                           0660U, 1U) == EPERM);
  CHECK(aqt_trusted_time_v2_resources_test_socket_metadata(10001U, 10001U,
                                                           0600U, 2U) == EPERM);

  memset(&left, 0, sizeof(left));
  left.device = 1U;
  left.inode = 2U;
  left.mode = 0600U;
  left.uid = 10001U;
  left.gid = 10001U;
  left.link_count = 1U;
  right = left;
  CHECK(aqt_trusted_time_v2_resources_test_stat9_equal(&left, &right) == 1);
  right.change_nanoseconds = 1;
  CHECK(aqt_trusted_time_v2_resources_test_stat9_equal(&left, &right) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT - 1U, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT, 0U, 0U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT, 0U, 0U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT + 1U, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT, 0U,
            0U) == EMSGSIZE);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT - 1U, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT, 0U, 0U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT, 0U, 0U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT + 1U, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT, 0U,
            0U) == EMSGSIZE);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT - 1U, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT, 0U,
            0U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT, 0U,
            0U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT + 1U, 0,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT, 0U,
            0U) == EMSGSIZE);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            1U, MSG_TRUNC, 1U, 0U, 0U) == EMSGSIZE);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(
            1U, MSG_CTRUNC, 1U, 0U, 0U) == EMSGSIZE);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(1U, 0, 1U, 1U,
                                                                0U) == EPROTO);
  CHECK(aqt_trusted_time_graceful_stop_v2_test_packet_admission(1U, 0, 1U, 0U,
                                                                1U) == EPROTO);
  return 0;
}

#if defined(__linux__)
static int make_seqpacket_pair(int pair[2]) {
  return socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                    pair);
}

static uint64_t future_deadline(uint64_t delta) {
  uint64_t now = aqt_trusted_time_graceful_stop_v2_test_boottime_now_ns();

  return now > UINT64_MAX - delta ? 0U : now + delta;
}

static int test_complete_state_machine(void) {
  static const unsigned char host_hello[] = "{\"host\":\"hello\"}";
  static const unsigned char supervisor_hello[] = "{\"supervisor\":\"hello\"}";
  static const unsigned char confirmation[] = "{\"host\":\"confirmed\"}";
  static const unsigned char request[] = "{\"clean\":\"request\"}";
  static const unsigned char terminal[] = "{\"clean\":\"result\"}";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *supervisor = NULL;
  unsigned char output[256];
  size_t output_length = 0U;
  uint64_t handshake_deadline = future_deadline(UINT64_C(5000000000));
  uint64_t operation_deadline = future_deadline(UINT64_C(10000000000));
  int pair[2];

  CHECK(handshake_deadline != 0U && operation_deadline != 0U);
  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], handshake_deadline, &host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
            pair[1], handshake_deadline, &supervisor) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, host_hello, sizeof(host_hello) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(
            supervisor, output, sizeof(output), &output_length) == 0);
  CHECK(output_length == sizeof(host_hello) - 1U);
  CHECK(memcmp(output, host_hello, output_length) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(
            supervisor, supervisor_hello, sizeof(supervisor_hello) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(
            host, output, sizeof(output), &output_length) == 0);
  CHECK(output_length == sizeof(supervisor_hello) - 1U);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation(
            host, confirmation, sizeof(confirmation) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation(
            supervisor, output, sizeof(output), &output_length) == 0);
  CHECK(output_length == sizeof(confirmation) - 1U);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(
            host, request, sizeof(request) - 1U, operation_deadline) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request(
            supervisor, output, sizeof(output), &output_length,
            operation_deadline) == 0);
  CHECK(output_length == sizeof(request) - 1U);
  CHECK(
      aqt_trusted_time_graceful_stop_v2_supervisor_send_terminal_result_or_error(
          supervisor, AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TERMINAL_RESULT,
          terminal, sizeof(terminal) - 1U, operation_deadline) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error(
            host, output, sizeof(output), &output_length, operation_deadline) ==
        0);
  CHECK(output_length == sizeof(terminal) - 1U);
  CHECK(memcmp(output, terminal, output_length) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error(
            host, output, sizeof(output), &output_length, operation_deadline) ==
        EPERM);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_close(&supervisor) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}

static int exercise_terminal_receive_boundary(size_t terminal_length,
                                              int expected) {
  static const unsigned char frame[] = "{}";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *supervisor = NULL;
  unsigned char small_output[16];
  unsigned char *terminal = NULL;
  unsigned char *terminal_output = NULL;
  size_t output_length = 0U;
  uint64_t handshake_deadline = future_deadline(UINT64_C(5000000000));
  uint64_t operation_deadline = future_deadline(UINT64_C(10000000000));
  int pair[2];

  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], handshake_deadline, &host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
            pair[1], handshake_deadline, &supervisor) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, frame, sizeof(frame) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(
            supervisor, small_output, sizeof(small_output), &output_length) ==
        0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(
            supervisor, frame, sizeof(frame) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(
            host, small_output, sizeof(small_output), &output_length) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation(
            host, frame, sizeof(frame) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation(
            supervisor, small_output, sizeof(small_output), &output_length) ==
        0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(
            host, frame, sizeof(frame) - 1U, operation_deadline) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request(
            supervisor, small_output, sizeof(small_output), &output_length,
            operation_deadline) == 0);
  terminal = malloc(terminal_length);
  terminal_output = malloc(terminal_length);
  CHECK(terminal != NULL && terminal_output != NULL);
  memset(terminal, 't', terminal_length);
  CHECK(send(pair[1], terminal, terminal_length, MSG_NOSIGNAL) ==
        (ssize_t)terminal_length);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error(
            host, terminal_output, terminal_length, &output_length,
            operation_deadline) == expected);
  if (expected == 0) {
    CHECK(output_length == terminal_length);
    CHECK(memcmp(terminal, terminal_output, terminal_length) == 0);
  }
  free(terminal);
  free(terminal_output);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_close(&supervisor) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}

static int test_terminal_receive_boundaries(void) {
  CHECK(exercise_terminal_receive_boundary(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT - 1U, 0) ==
        0);
  CHECK(exercise_terminal_receive_boundary(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT, 0) == 0);
  CHECK(exercise_terminal_receive_boundary(
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT + 1U,
            EMSGSIZE) == 0);
  return 0;
}

static int test_order_deadline_and_size_rejection(void) {
  static const unsigned char frame[] = "{}";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *supervisor = NULL;
  unsigned char *oversized;
  uint64_t deadline;
  int pair[2];

  deadline = future_deadline(UINT64_C(5000000000));
  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
            pair[1], deadline, &supervisor) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(
            host, frame, sizeof(frame) - 1U, deadline) == EPROTO);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_close(&supervisor) == 0);

  CHECK(make_seqpacket_pair(pair) == 0);
  deadline = aqt_trusted_time_graceful_stop_v2_test_boottime_now_ns();
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, frame, sizeof(frame) - 1U) == ETIMEDOUT);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(close(pair[1]) == 0);

  CHECK(make_seqpacket_pair(pair) == 0);
  deadline = future_deadline(UINT64_C(5000000000));
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  oversized = malloc(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT + 1U);
  CHECK(oversized != NULL);
  memset(oversized, 'x',
         AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT + 1U);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, oversized,
            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT + 1U) ==
        EMSGSIZE);
  free(oversized);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(close(pair[1]) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}

static int test_extra_packet_rejection(void) {
  static const unsigned char host_hello[] = "host";
  static const unsigned char supervisor_hello[] = "supervisor";
  static const unsigned char extra[] = "extra";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *supervisor = NULL;
  unsigned char output[64];
  size_t output_length;
  uint64_t deadline = future_deadline(UINT64_C(5000000000));
  int pair[2];

  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
            pair[1], deadline, &supervisor) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, host_hello, sizeof(host_hello) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(
            supervisor, output, sizeof(output), &output_length) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(
            supervisor, supervisor_hello, sizeof(supervisor_hello) - 1U) == 0);
  CHECK(send(pair[1], extra, sizeof(extra) - 1U, MSG_NOSIGNAL) ==
        (ssize_t)(sizeof(extra) - 1U));
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(
            host, output, sizeof(output), &output_length) == EPROTO);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_close(&supervisor) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}

static size_t open_descriptor_count(void) {
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0U;

  if (directory == NULL) {
    return SIZE_MAX;
  }
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      count++;
    }
  }
  (void)closedir(directory);
  return count;
}

static int test_ancillary_rights_rejection_and_close(void) {
  static const unsigned char host_hello[] = "host";
  static const unsigned char supervisor_hello[] = "supervisor";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *supervisor = NULL;
  unsigned char output[64];
  unsigned char control[CMSG_SPACE(sizeof(int))];
  struct iovec vector;
  struct msghdr message;
  struct cmsghdr *header;
  size_t output_length;
  size_t before;
  size_t after;
  uint64_t deadline = future_deadline(UINT64_C(5000000000));
  int pipe_descriptors[2];
  int pair[2];

  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
            pair[1], deadline, &supervisor) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, host_hello, sizeof(host_hello) - 1U) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(
            supervisor, output, sizeof(output), &output_length) == 0);
  memset(control, 0, sizeof(control));
  memset(&vector, 0, sizeof(vector));
  vector.iov_base = (void *)supervisor_hello;
  vector.iov_len = sizeof(supervisor_hello) - 1U;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &vector;
  message.msg_iovlen = 1U;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  header = CMSG_FIRSTHDR(&message);
  CHECK(header != NULL);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &pipe_descriptors[0], sizeof(int));
  before = open_descriptor_count();
  CHECK(before != SIZE_MAX);
  CHECK(sendmsg(pair[1], &message, MSG_NOSIGNAL) ==
        (ssize_t)(sizeof(supervisor_hello) - 1U));
  CHECK(aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(
            host, output, sizeof(output), &output_length) == EPROTO);
  after = open_descriptor_count();
  /* Rejection closes both the received right and the burned host channel. */
  CHECK(after + 1U == before);
  CHECK(fcntl(pipe_descriptors[0], F_GETFD) >= 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_supervisor_close(&supervisor) == 0);
  CHECK(close(pipe_descriptors[0]) == 0);
  CHECK(close(pipe_descriptors[1]) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}

typedef struct {
  aqt_trusted_time_graceful_stop_v2_host_endpoint *owner;
  int result;
} ThreadAttempt;

static void *wrong_thread_send(void *opaque) {
  static const unsigned char hello[] = "host";
  ThreadAttempt *attempt = (ThreadAttempt *)opaque;

  attempt->result = aqt_trusted_time_graceful_stop_v2_host_send_hello(
      attempt->owner, hello, sizeof(hello) - 1U);
  return NULL;
}

static int test_wrong_thread_and_fork_child(void) {
  static const unsigned char hello[] = "host";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  ThreadAttempt attempt;
  pthread_t thread;
  unsigned char received[16];
  uint64_t deadline = future_deadline(UINT64_C(5000000000));
  pid_t child;
  int child_status;
  int pair[2];

  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  attempt.owner = host;
  attempt.result = 0;
  CHECK(pthread_create(&thread, NULL, wrong_thread_send, &attempt) == 0);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(attempt.result == EPERM);
  CHECK(
      (aqt_trusted_time_graceful_stop_v2_host_send_hello)(host,
                                                          TEST_INTERPRETER_IDENTITY +
                                                              1U,
                                                          hello,
                                                          sizeof(hello) - 1U) ==
      EPERM);
  CHECK(fcntl(pair[0], F_GETFD) >= 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, hello, sizeof(hello) - 1U) == 0);
  CHECK(recv(pair[1], received, sizeof(received), 0) ==
        (ssize_t)(sizeof(hello) - 1U));
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(close(pair[1]) == 0);

  CHECK(make_seqpacket_pair(pair) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            pair[0], deadline, &host) == 0);
  child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    int rejected = aqt_trusted_time_graceful_stop_v2_host_send_hello(
        host, hello, sizeof(hello) - 1U);
    _exit(rejected == EPERM && fcntl(pair[0], F_GETFD) < 0 ? 0 : 71);
  }
  CHECK(waitpid(child, &child_status, 0) == child);
  CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(close(pair[1]) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}

static int test_socket_fd_substitution(void) {
  static const unsigned char hello[] = "host";
  aqt_trusted_time_graceful_stop_v2_host_endpoint *host = NULL;
  uint64_t deadline = future_deadline(UINT64_C(5000000000));
  int replacement[2];
  int replacement_peer;
  int pair[2];
  int owner_descriptor;

  CHECK(make_seqpacket_pair(pair) == 0);
  owner_descriptor = pair[0];
  CHECK(aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
            owner_descriptor, deadline, &host) == 0);
  CHECK(close(owner_descriptor) == 0);
  CHECK(make_seqpacket_pair(replacement) == 0);
  if (replacement[0] == owner_descriptor) {
    replacement_peer = replacement[1];
  } else if (replacement[1] == owner_descriptor) {
    replacement_peer = replacement[0];
  } else {
    CHECK(dup3(replacement[0], owner_descriptor, O_CLOEXEC) ==
          owner_descriptor);
    CHECK(close(replacement[0]) == 0);
    replacement_peer = replacement[1];
  }
  CHECK(aqt_trusted_time_graceful_stop_v2_host_send_hello(
            host, hello, sizeof(hello) - 1U) == ESTALE);
  CHECK(fcntl(owner_descriptor, F_GETFD) < 0 && errno == EBADF);
  CHECK(aqt_trusted_time_graceful_stop_v2_host_close(&host) == 0);
  CHECK(close(pair[1]) == 0);
  CHECK(close(replacement_peer) == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  return 0;
}
#endif

int main(void) {
  CHECK(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT == 262144U);
  CHECK(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_DETECTION_BUFFER_SIZE == 262145U);
  CHECK(test_resource_validators() == 0);
#if !defined(__linux__)
  CHECK(aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python() ==
        ENOTSUP);
  (void)puts("trusted-time-v2 endpoint/resources: portable compile passed");
  return 0;
#else
  CHECK(aqt_trusted_time_v2_fork_guard_initialize_before_python() == 0);
  CHECK(aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python() ==
        0);
  CHECK(aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python() ==
        EALREADY);
  CHECK(test_complete_state_machine() == 0);
  CHECK(test_terminal_receive_boundaries() == 0);
  CHECK(test_order_deadline_and_size_rejection() == 0);
  CHECK(test_extra_packet_rejection() == 0);
  CHECK(test_ancillary_rights_rejection_and_close() == 0);
  CHECK(test_wrong_thread_and_fork_child() == 0);
  CHECK(test_socket_fd_substitution() == 0);
  CHECK(aqt_trusted_time_v2_fork_guard_require_owner_table_empty() == 0);
  (void)puts("trusted-time-v2 endpoint/resources: all checks passed");
  return 0;
#endif
}
