#ifndef AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_ENDPOINT_H
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_ENDPOINT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT 262144U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_DETECTION_BUFFER_SIZE 262145U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT 8192U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SUPERVISOR_HELLO_LIMIT 12288U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_CONFIRMATION_LIMIT 8192U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_REQUEST_ENVELOPE_LIMIT 95576U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT 248492U
#define AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_ERROR_ENVELOPE_LIMIT 51884U

typedef struct aqt_trusted_time_graceful_stop_v2_host_endpoint
    aqt_trusted_time_graceful_stop_v2_host_endpoint;
typedef struct aqt_trusted_time_graceful_stop_v2_supervisor_endpoint
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint;

typedef enum {
  AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TERMINAL_RESULT = 1,
  AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TERMINAL_ERROR = 2,
} aqt_trusted_time_graceful_stop_v2_terminal_kind;

/*
 * Called exactly once by each normal fixed launcher after the fork guard and
 * signer and before Python initialization.  Each later method requires the
 * same caller-supplied, nonzero interpreter-instance identity captured by its
 * opaque owner.
 */
int aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python(void);

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) ||                               \
    defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
int aqt_trusted_time_graceful_stop_v2_host_connector_create(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_out);
int aqt_trusted_time_graceful_stop_v2_host_send_hello(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_hello, size_t encoded_length);
int aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_hello_out, size_t output_capacity,
    size_t *encoded_length_out);
int aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_confirmation, size_t encoded_length);
int aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_request, size_t encoded_length,
    uint64_t request_result_deadline_boottime_ns);
int aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_terminal_out, size_t output_capacity,
    size_t *encoded_length_out, uint64_t request_result_deadline_boottime_ns);
int aqt_trusted_time_graceful_stop_v2_host_close(
    aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_io,
    uintptr_t interpreter_instance_identity);
#endif

#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE) ||                         \
    defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
int aqt_trusted_time_graceful_stop_v2_supervisor_listener_create(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_out);
int aqt_trusted_time_graceful_stop_v2_supervisor_accept_once(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity);
int aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_hello_out, size_t output_capacity,
    size_t *encoded_length_out);
int aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_hello, size_t encoded_length);
int aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_confirmation_out, size_t output_capacity,
    size_t *encoded_length_out);
int aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_request_out, size_t output_capacity,
    size_t *encoded_length_out, uint64_t request_result_deadline_boottime_ns);
int aqt_trusted_time_graceful_stop_v2_supervisor_send_terminal_result_or_error(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_terminal_kind terminal_kind,
    const unsigned char *canonical_signed_terminal, size_t encoded_length,
    uint64_t request_result_deadline_boottime_ns);
int aqt_trusted_time_graceful_stop_v2_supervisor_close(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_io,
    uintptr_t interpreter_instance_identity);
#endif

#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
/* Test-only adoption of an already-connected seqpacket; never in candidates. */
int aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
    int connected_socket, uint64_t handshake_deadline_boottime_ns,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_out);
int aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
    int connected_socket, uint64_t handshake_deadline_boottime_ns,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_out);
uint64_t aqt_trusted_time_graceful_stop_v2_test_boottime_now_ns(void);
int aqt_trusted_time_graceful_stop_v2_test_packet_admission(
    size_t received_length, int message_flags, size_t method_limit,
    size_t control_length, size_t source_name_length);
#endif

#ifdef __cplusplus
}
#endif

#endif
