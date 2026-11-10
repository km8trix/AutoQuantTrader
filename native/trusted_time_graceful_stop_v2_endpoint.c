#define _GNU_SOURCE

#include "trusted_time_graceful_stop_v2_endpoint.h"

#include "trusted_time_graceful_stop_v2_resources.h"
#include "trusted_time_v2_fork_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/un.h>
#endif

#if (defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) +                               \
     defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)) > 1
#error "Only one lifecycle-v2 endpoint role may be compiled."
#endif

#if !defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) &&                              \
    !defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE) &&                        \
    !defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
#error "An endpoint role or the closed test profile is required."
#endif

#define AQT_INVALID_SLOT UINT32_MAX
#define AQT_NANOSECONDS_PER_SECOND UINT64_C(1000000000)
#define AQT_HANDSHAKE_BUDGET_NS UINT64_C(5000000000)
#define AQT_IO_BUDGET_NS UINT64_C(2000000000)
#define AQT_SCM_RIGHTS_LIMIT 253U
#define AQT_UNIX_PACKET_ACCOUNTING_OVERHEAD 32U

enum {
  AQT_ENDPOINT_OPEN = 0,
  AQT_ENDPOINT_BURNED = 1,
  AQT_ENDPOINT_TERMINAL = 2,
};

enum {
  AQT_ENDPOINT_BOOTSTRAP_UNINITIALIZED = 0,
  AQT_ENDPOINT_BOOTSTRAP_INITIALIZING = 1,
  AQT_ENDPOINT_BOOTSTRAP_READY = 2,
  AQT_ENDPOINT_BOOTSTRAP_FAILED = 3,
};

typedef struct {
  uint64_t device;
  uint64_t inode;
  uint32_t file_type;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t link_count;
  uint64_t cookie;
} AqtSocketFdIdentity;

#if defined(__linux__)
static _Atomic int aqt_endpoint_bootstrap_state =
    AQT_ENDPOINT_BOOTSTRAP_UNINITIALIZED;
static aqt_trusted_time_v2_fork_identity aqt_endpoint_bootstrap_identity;
#endif

enum {
  AQT_HOST_CONNECTED = 0,
  AQT_HOST_HELLO_SENT = 1,
  AQT_HOST_SUPERVISOR_HELLO_RECEIVED = 2,
  AQT_HOST_CONFIRMED = 3,
  AQT_HOST_REQUEST_SENT = 4,
  AQT_HOST_TERMINAL_RECEIVED = 5,
};

enum {
  AQT_SUPERVISOR_LISTENING = 0,
  AQT_SUPERVISOR_ACCEPTED = 1,
  AQT_SUPERVISOR_HOST_HELLO_RECEIVED = 2,
  AQT_SUPERVISOR_HELLO_SENT = 3,
  AQT_SUPERVISOR_CONFIRMED = 4,
  AQT_SUPERVISOR_REQUEST_RECEIVED = 5,
  AQT_SUPERVISOR_TERMINAL_SENT = 6,
};

typedef struct {
  aqt_trusted_time_v2_fork_identity fork_identity;
  uintptr_t interpreter_instance_identity;
  int socket_fd;
  uint32_t socket_slot;
  AqtSocketFdIdentity socket_identity;
  uint64_t handshake_deadline_boottime_ns;
  uint64_t request_result_deadline_boottime_ns;
  uint64_t outgoing_counter;
  uint64_t incoming_counter;
  int disposition;
  unsigned char
      detection_buffer[AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_DETECTION_BUFFER_SIZE];
} AqtEndpointCommon;

struct aqt_trusted_time_graceful_stop_v2_host_endpoint {
  AqtEndpointCommon common;
  int state;
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
  aqt_trusted_time_v2_host_transport_resources *resources;
#endif
};

struct aqt_trusted_time_graceful_stop_v2_supervisor_endpoint {
  AqtEndpointCommon common;
  int state;
  int listener_fd;
  uint32_t listener_slot;
  AqtSocketFdIdentity listener_identity;
#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
  aqt_trusted_time_v2_supervisor_transport_resources *resources;
#endif
};

#if defined(__linux__)
static int aqt_errno_or_io(void) { return errno == 0 ? EIO : errno; }
#endif

static int aqt_endpoint_bootstrap_require(void) {
#if !defined(__linux__)
  return ENOTSUP;
#else
  if (atomic_load_explicit(&aqt_endpoint_bootstrap_state,
                           memory_order_acquire) !=
      AQT_ENDPOINT_BOOTSTRAP_READY) {
    return EPERM;
  }
  return aqt_trusted_time_v2_fork_guard_require_identity(
      &aqt_endpoint_bootstrap_identity);
#endif
}

static void aqt_wipe(void *address, size_t length) {
  volatile unsigned char *cursor = (volatile unsigned char *)address;

  while (length > 0U) {
    *cursor++ = 0U;
    length--;
  }
}

#if defined(__linux__) || defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
static int aqt_boottime_now(uint64_t *sample_out) {
#if !defined(__linux__) || !defined(CLOCK_BOOTTIME)
  (void)sample_out;
  return ENOTSUP;
#else
  struct timespec sampled;
  uint64_t seconds;

  if (sample_out == NULL || clock_gettime(CLOCK_BOOTTIME, &sampled) != 0 ||
      sampled.tv_sec < 0 || sampled.tv_nsec < 0 ||
      sampled.tv_nsec >= (long)AQT_NANOSECONDS_PER_SECOND) {
    return errno == 0 ? EIO : errno;
  }
  seconds = (uint64_t)sampled.tv_sec;
  if (seconds >
      (UINT64_MAX - (uint64_t)sampled.tv_nsec) / AQT_NANOSECONDS_PER_SECOND) {
    return EOVERFLOW;
  }
  *sample_out =
      seconds * AQT_NANOSECONDS_PER_SECOND + (uint64_t)sampled.tv_nsec;
  return *sample_out <= (uint64_t)INT64_MAX ? 0 : ERANGE;
#endif
}
#endif

#if defined(__linux__)
static int aqt_checked_deadline(uint64_t start, uint64_t budget,
                                uint64_t *deadline_out) {
  if (deadline_out == NULL || budget > (uint64_t)INT64_MAX ||
      start > (uint64_t)INT64_MAX - budget) {
    return EOVERFLOW;
  }
  *deadline_out = start + budget;
  return 0;
}

static uint64_t aqt_minimum_deadline(uint64_t left, uint64_t right) {
  return left < right ? left : right;
}
#endif

static int aqt_socket_identity_equal(const AqtSocketFdIdentity *left,
                                     const AqtSocketFdIdentity *right) {
  return left != NULL && right != NULL && left->device == right->device &&
         left->inode == right->inode && left->file_type == right->file_type &&
         left->mode == right->mode && left->uid == right->uid &&
         left->gid == right->gid && left->link_count == right->link_count &&
         left->cookie == right->cookie;
}

static int aqt_capture_socket_identity(int descriptor,
                                       AqtSocketFdIdentity *identity_out) {
#if !defined(__linux__) || !defined(SO_COOKIE)
  (void)descriptor;
  (void)identity_out;
  return ENOTSUP;
#else
  struct stat first;
  struct stat second;
  uint64_t first_cookie = 0U;
  uint64_t second_cookie = 0U;
  socklen_t first_cookie_length = (socklen_t)sizeof(first_cookie);
  socklen_t second_cookie_length = (socklen_t)sizeof(second_cookie);

  if (identity_out == NULL || descriptor < 0) {
    return EINVAL;
  }
  if (fstat(descriptor, &first) != 0 ||
      getsockopt(descriptor, SOL_SOCKET, SO_COOKIE, &first_cookie,
                 &first_cookie_length) != 0 ||
      fstat(descriptor, &second) != 0 ||
      getsockopt(descriptor, SOL_SOCKET, SO_COOKIE, &second_cookie,
                 &second_cookie_length) != 0) {
    return aqt_errno_or_io();
  }
  if (first_cookie_length != sizeof(first_cookie) ||
      second_cookie_length != sizeof(second_cookie) ||
      first.st_dev != second.st_dev || first.st_ino != second.st_ino ||
      first.st_mode != second.st_mode || first.st_uid != second.st_uid ||
      first.st_gid != second.st_gid || first.st_nlink != second.st_nlink ||
      first_cookie == 0U || first_cookie != second_cookie ||
      (first.st_mode & S_IFMT) != S_IFSOCK) {
    return ESTALE;
  }
  identity_out->device = (uint64_t)first.st_dev;
  identity_out->inode = (uint64_t)first.st_ino;
  identity_out->file_type = (uint32_t)(first.st_mode & S_IFMT);
  identity_out->mode = (uint32_t)(first.st_mode & 07777);
  identity_out->uid = (uint32_t)first.st_uid;
  identity_out->gid = (uint32_t)first.st_gid;
  identity_out->link_count = (uint64_t)first.st_nlink;
  identity_out->cookie = first_cookie;
  return 0;
#endif
}

static int aqt_require_socket_identity(int descriptor,
                                       const AqtSocketFdIdentity *expected) {
  AqtSocketFdIdentity captured;
  int result = aqt_capture_socket_identity(descriptor, &captured);

  return result == 0 && !aqt_socket_identity_equal(expected, &captured)
             ? ESTALE
             : result;
}

static int aqt_common_owner_require(AqtEndpointCommon *common,
                                    uintptr_t interpreter_instance_identity) {
  int result;

  if (common == NULL || interpreter_instance_identity == 0U) {
    return EINVAL;
  }
  result = aqt_endpoint_bootstrap_require();
  if (result != 0) {
    return result;
  }
  result =
      aqt_trusted_time_v2_fork_guard_require_identity(&common->fork_identity);
  if (result != 0) {
    return result;
  }
  if (common->interpreter_instance_identity != interpreter_instance_identity) {
    return EPERM;
  }
  return 0;
}

static int aqt_common_require(AqtEndpointCommon *common,
                              uintptr_t interpreter_instance_identity) {
  int result = aqt_common_owner_require(common, interpreter_instance_identity);

  if (result != 0) {
    return result;
  }
  if (common->disposition != AQT_ENDPOINT_OPEN || common->socket_fd < 0) {
    return EPERM;
  }
  return aqt_require_socket_identity(common->socket_fd,
                                     &common->socket_identity);
}

static int aqt_common_burn(AqtEndpointCommon *common,
                           uintptr_t interpreter_instance_identity,
                           int rejection) {
  int owner_result;
  int cleanup_result;

  if (common == NULL) {
    return rejection == 0 ? EINVAL : rejection;
  }
  if (interpreter_instance_identity == 0U ||
      common->interpreter_instance_identity != interpreter_instance_identity) {
    return rejection == 0 ? EPERM : rejection;
  }
  owner_result =
      aqt_trusted_time_v2_fork_guard_require_identity(&common->fork_identity);
  if (owner_result != 0) {
    return rejection == 0 ? owner_result : rejection;
  }
  if (common->socket_fd >= 0 && common->socket_slot != AQT_INVALID_SLOT) {
    cleanup_result = aqt_trusted_time_v2_fork_guard_close_fd(
        common->socket_slot, common->socket_fd);
    if (cleanup_result != 0 && rejection == 0) {
      rejection = cleanup_result;
    }
  }
  common->socket_fd = -1;
  common->socket_slot = AQT_INVALID_SLOT;
  common->disposition = AQT_ENDPOINT_BURNED;
  return rejection == 0 ? EIO : rejection;
}

#if defined(__linux__) || defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
static int aqt_validate_preopened_seqpacket(int descriptor) {
#if !defined(__linux__)
  (void)descriptor;
  return ENOTSUP;
#else
  int type;
  socklen_t type_length = (socklen_t)sizeof(type);
  int descriptor_flags;
  int status_flags;
  int requested_buffer =
      (int)AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_DETECTION_BUFFER_SIZE;
  int send_buffer_first = 0;
  int send_buffer_second = 0;
  int receive_buffer_first = 0;
  int receive_buffer_second = 0;
  socklen_t option_length;
  struct sockaddr_un address;
  socklen_t address_length = (socklen_t)sizeof(address);

  memset(&address, 0, sizeof(address));
  if (descriptor < 0 ||
      getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
      type_length != sizeof(type) || type != SOCK_SEQPACKET ||
      getsockname(descriptor, (struct sockaddr *)&address, &address_length) !=
          0 ||
      address.sun_family != AF_UNIX) {
    return errno == 0 ? EPROTOTYPE : errno;
  }
  descriptor_flags = fcntl(descriptor, F_GETFD);
  status_flags = fcntl(descriptor, F_GETFL);
  if (descriptor_flags < 0 || status_flags < 0 ||
      (descriptor_flags & FD_CLOEXEC) == 0 ||
      (status_flags & O_NONBLOCK) == 0) {
    return EPERM;
  }
  if (setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &requested_buffer,
                 (socklen_t)sizeof(requested_buffer)) != 0 ||
      setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &requested_buffer,
                 (socklen_t)sizeof(requested_buffer)) != 0) {
    return aqt_errno_or_io();
  }
  option_length = (socklen_t)sizeof(send_buffer_first);
  if (getsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &send_buffer_first,
                 &option_length) != 0 ||
      option_length != sizeof(send_buffer_first)) {
    return aqt_errno_or_io();
  }
  option_length = (socklen_t)sizeof(send_buffer_second);
  if (getsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &send_buffer_second,
                 &option_length) != 0 ||
      option_length != sizeof(send_buffer_second)) {
    return aqt_errno_or_io();
  }
  option_length = (socklen_t)sizeof(receive_buffer_first);
  if (getsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer_first,
                 &option_length) != 0 ||
      option_length != sizeof(receive_buffer_first)) {
    return aqt_errno_or_io();
  }
  option_length = (socklen_t)sizeof(receive_buffer_second);
  if (getsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer_second,
                 &option_length) != 0 ||
      option_length != sizeof(receive_buffer_second)) {
    return aqt_errno_or_io();
  }
  if (send_buffer_first != send_buffer_second ||
      receive_buffer_first != receive_buffer_second ||
      send_buffer_first < (int)(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT +
                                AQT_UNIX_PACKET_ACCOUNTING_OVERHEAD) ||
      receive_buffer_first <
          (int)AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_DETECTION_BUFFER_SIZE) {
    return ENOBUFS;
  }
  return 0;
#endif
}

static int aqt_common_adopt(AqtEndpointCommon *common, int descriptor,
                            uint64_t handshake_deadline,
                            uintptr_t interpreter_instance_identity) {
  int result;

  if (common == NULL) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return EINVAL;
  }
  memset(common, 0, sizeof(*common));
  common->socket_fd = -1;
  common->socket_slot = AQT_INVALID_SLOT;
  common->interpreter_instance_identity = interpreter_instance_identity;
  if (interpreter_instance_identity == 0U) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return EINVAL;
  }
  if (handshake_deadline == 0U || handshake_deadline > (uint64_t)INT64_MAX) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return ERANGE;
  }
  result = aqt_endpoint_bootstrap_require();
  if (result != 0) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return result;
  }
  result =
      aqt_trusted_time_v2_fork_guard_capture_identity(&common->fork_identity);
  if (result != 0) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return result;
  }
  result = aqt_trusted_time_v2_fork_guard_register_fd(descriptor,
                                                      &common->socket_slot);
  if (result != 0) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return result;
  }
  common->socket_fd = descriptor;
  result = aqt_validate_preopened_seqpacket(descriptor);
  if (result == 0) {
    result = aqt_capture_socket_identity(descriptor, &common->socket_identity);
  }
  if (result != 0) {
    (void)aqt_trusted_time_v2_fork_guard_close_fd(common->socket_slot,
                                                  common->socket_fd);
    common->socket_fd = -1;
    common->socket_slot = AQT_INVALID_SLOT;
    return result;
  }
  common->handshake_deadline_boottime_ns = handshake_deadline;
  common->disposition = AQT_ENDPOINT_OPEN;
  return 0;
}
#endif

#if defined(__linux__)
static int aqt_io_deadline(AqtEndpointCommon *common, uint64_t outer_deadline,
                           int bind_outer_deadline,
                           uint64_t *effective_deadline_out) {
  uint64_t now;
  uint64_t io_deadline;
  int result = aqt_boottime_now(&now);

  if (result != 0) {
    return result;
  }
  result = aqt_checked_deadline(now, AQT_IO_BUDGET_NS, &io_deadline);
  if (result != 0) {
    return result;
  }
  if (bind_outer_deadline) {
    if (outer_deadline == 0U || outer_deadline > (uint64_t)INT64_MAX) {
      return ERANGE;
    }
    if (common->request_result_deadline_boottime_ns == 0U) {
      common->request_result_deadline_boottime_ns = outer_deadline;
    } else if (common->request_result_deadline_boottime_ns != outer_deadline) {
      return EPERM;
    }
    *effective_deadline_out = aqt_minimum_deadline(io_deadline, outer_deadline);
  } else {
    *effective_deadline_out = aqt_minimum_deadline(
        io_deadline, common->handshake_deadline_boottime_ns);
  }
  return now >= *effective_deadline_out ? ETIMEDOUT : 0;
}

static int aqt_wait_ready(int descriptor, short events, uint64_t deadline) {
#if !defined(__linux__)
  (void)descriptor;
  (void)events;
  (void)deadline;
  return ENOTSUP;
#else
  for (;;) {
    uint64_t now;
    uint64_t remaining;
    struct timespec timeout;
    struct pollfd poll_descriptor;
    int result = aqt_boottime_now(&now);
    int ready;

    if (result != 0) {
      return result;
    }
    if (now >= deadline) {
      return ETIMEDOUT;
    }
    remaining = deadline - now;
    timeout.tv_sec = (time_t)(remaining / AQT_NANOSECONDS_PER_SECOND);
    timeout.tv_nsec = (long)(remaining % AQT_NANOSECONDS_PER_SECOND);
    memset(&poll_descriptor, 0, sizeof(poll_descriptor));
    poll_descriptor.fd = descriptor;
    poll_descriptor.events = events;
    ready = ppoll(&poll_descriptor, 1U, &timeout, NULL);
    if (ready < 0 && errno == EINTR) {
      continue;
    }
    if (ready < 0) {
      return aqt_errno_or_io();
    }
    if (ready == 0) {
      return ETIMEDOUT;
    }
    result = aqt_boottime_now(&now);
    if (result != 0 || now >= deadline) {
      return result == 0 ? ETIMEDOUT : result;
    }
    if ((poll_descriptor.revents & events) != 0) {
      return 0;
    }
    return (poll_descriptor.revents & POLLNVAL) != 0 ? EBADF : EPIPE;
  }
#endif
}

static int aqt_reject_queued_packet(int descriptor,
                                    int terminal_allows_disconnect) {
#if !defined(__linux__)
  (void)descriptor;
  (void)terminal_allows_disconnect;
  return ENOTSUP;
#else
  struct pollfd poll_descriptor;
  const struct timespec no_wait = {0, 0};
  int pending = 0;
  int ready;

  memset(&poll_descriptor, 0, sizeof(poll_descriptor));
  poll_descriptor.fd = descriptor;
  poll_descriptor.events = POLLIN;
  ready = ppoll(&poll_descriptor, 1U, &no_wait, NULL);
  if (ready < 0) {
    return aqt_errno_or_io();
  }
  if (ready == 0) {
    return 0;
  }
  if ((poll_descriptor.revents & POLLNVAL) != 0) {
    return EBADF;
  }
  if ((poll_descriptor.revents & POLLIN) != 0) {
    if (ioctl(descriptor, FIONREAD, &pending) != 0) {
      return aqt_errno_or_io();
    }
    if (pending > 0) {
      return EPROTO;
    }
  }
  return terminal_allows_disconnect ? 0 : ECONNRESET;
#endif
}

static void aqt_close_received_rights(struct msghdr *message) {
#if defined(__linux__)
  struct cmsghdr *header;

  if (message == NULL) {
    return;
  }
  for (header = CMSG_FIRSTHDR(message); header != NULL;
       header = CMSG_NXTHDR(message, header)) {
    if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len >= CMSG_LEN(0U)) {
      size_t byte_count = header->cmsg_len - CMSG_LEN(0U);
      size_t descriptor_count = byte_count / sizeof(int);
      int *descriptors = (int *)CMSG_DATA(header);

      for (size_t index = 0U; index < descriptor_count; ++index) {
        if (descriptors[index] >= 0) {
          uint32_t slot = AQT_INVALID_SLOT;

          if (aqt_trusted_time_v2_fork_guard_register_fd(descriptors[index],
                                                         &slot) == 0) {
            (void)aqt_trusted_time_v2_fork_guard_close_fd(slot,
                                                          descriptors[index]);
          } else {
            (void)close(descriptors[index]);
          }
        }
      }
    }
  }
#else
  (void)message;
#endif
}
#endif

#if defined(__linux__) || defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
static int aqt_packet_admission_result(size_t received_length,
                                       int message_flags, size_t method_limit,
                                       size_t control_length,
                                       size_t source_name_length) {
  if (received_length == 0U) {
    return ECONNRESET;
  }
  if ((message_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
      received_length > AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT ||
      received_length > method_limit) {
    return EMSGSIZE;
  }
  if (control_length != 0U || source_name_length != 0U) {
    return EPROTO;
  }
  return 0;
}
#endif

static int aqt_send_packet(AqtEndpointCommon *common,
                           const unsigned char *bytes, size_t length,
                           size_t maximum, uint64_t outer_deadline,
                           int bind_outer_deadline) {
#if !defined(__linux__)
  (void)common;
  (void)bytes;
  (void)length;
  (void)maximum;
  (void)outer_deadline;
  (void)bind_outer_deadline;
  return ENOTSUP;
#else
  struct iovec vector;
  struct msghdr message;
  uint64_t deadline;
  uint64_t completed;
  ssize_t sent;
  int result;

  if (bytes == NULL || length == 0U || length > maximum ||
      length > AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_PACKET_LIMIT) {
    return EMSGSIZE;
  }
  result =
      aqt_io_deadline(common, outer_deadline, bind_outer_deadline, &deadline);
  if (result != 0) {
    return result;
  }
  result = aqt_reject_queued_packet(common->socket_fd, 0);
  if (result != 0) {
    return result;
  }
  result = aqt_wait_ready(common->socket_fd, POLLOUT, deadline);
  if (result != 0) {
    return result;
  }
  memset(&vector, 0, sizeof(vector));
  vector.iov_base = (void *)bytes;
  vector.iov_len = length;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &vector;
  message.msg_iovlen = 1U;
  sent = sendmsg(common->socket_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (sent < 0) {
    return aqt_errno_or_io();
  }
  if ((size_t)sent != length) {
    return EIO;
  }
  result = aqt_boottime_now(&completed);
  return result != 0 ? result : (completed >= deadline ? ETIMEDOUT : 0);
#endif
}

static int aqt_receive_packet(AqtEndpointCommon *common, unsigned char *output,
                              size_t output_capacity, size_t *length_out,
                              size_t maximum, uint64_t outer_deadline,
                              int bind_outer_deadline, int terminal_receive) {
#if !defined(__linux__)
  (void)common;
  (void)output;
  (void)output_capacity;
  (void)length_out;
  (void)maximum;
  (void)outer_deadline;
  (void)bind_outer_deadline;
  (void)terminal_receive;
  return ENOTSUP;
#else
  unsigned char control[CMSG_SPACE(sizeof(int) * AQT_SCM_RIGHTS_LIMIT)];
  struct iovec vector;
  struct msghdr message;
  uint64_t deadline;
  uint64_t completed;
  ssize_t received;
  int result;

  if (output == NULL || length_out == NULL || output_capacity == 0U ||
      maximum == 0U) {
    return EINVAL;
  }
  *length_out = 0U;
  result =
      aqt_io_deadline(common, outer_deadline, bind_outer_deadline, &deadline);
  if (result != 0) {
    return result;
  }
  result = aqt_wait_ready(common->socket_fd, POLLIN, deadline);
  if (result != 0) {
    return result;
  }
  memset(control, 0, sizeof(control));
  memset(&vector, 0, sizeof(vector));
  vector.iov_base = common->detection_buffer;
  vector.iov_len = sizeof(common->detection_buffer);
  memset(&message, 0, sizeof(message));
  message.msg_iov = &vector;
  message.msg_iovlen = 1U;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  received =
      recvmsg(common->socket_fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (received < 0) {
    return aqt_errno_or_io();
  }
  result =
      aqt_packet_admission_result((size_t)received, message.msg_flags, maximum,
                                  message.msg_controllen, message.msg_namelen);
  if (result != 0) {
    aqt_close_received_rights(&message);
    return result;
  }
  result = aqt_boottime_now(&completed);
  if (result != 0 || completed >= deadline) {
    return result == 0 ? ETIMEDOUT : result;
  }
  if ((size_t)received > output_capacity) {
    return EMSGSIZE;
  }
  result = aqt_reject_queued_packet(common->socket_fd, terminal_receive);
  if (result != 0) {
    return result;
  }
  memcpy(output, common->detection_buffer, (size_t)received);
  *length_out = (size_t)received;
  return 0;
#endif
}

int aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python(void) {
#if !defined(__linux__)
  return ENOTSUP;
#else
  int expected = AQT_ENDPOINT_BOOTSTRAP_UNINITIALIZED;
  int result;

  if (!atomic_compare_exchange_strong_explicit(
          &aqt_endpoint_bootstrap_state, &expected,
          AQT_ENDPOINT_BOOTSTRAP_INITIALIZING, memory_order_acq_rel,
          memory_order_acquire)) {
    return EALREADY;
  }
  result = aqt_trusted_time_v2_fork_guard_capture_identity(
      &aqt_endpoint_bootstrap_identity);
  if (result == 0) {
    result = aqt_trusted_time_v2_fork_guard_require_identity(
        &aqt_endpoint_bootstrap_identity);
  }
  if (result != 0) {
    aqt_wipe(&aqt_endpoint_bootstrap_identity,
             sizeof(aqt_endpoint_bootstrap_identity));
    atomic_store_explicit(&aqt_endpoint_bootstrap_state,
                          AQT_ENDPOINT_BOOTSTRAP_FAILED, memory_order_release);
    return result;
  }
  atomic_store_explicit(&aqt_endpoint_bootstrap_state,
                        AQT_ENDPOINT_BOOTSTRAP_READY, memory_order_release);
  return 0;
#endif
}

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) ||                               \
    defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
#if defined(__linux__) || defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
static int
aqt_host_adopt(int descriptor, uint64_t handshake_deadline,
               uintptr_t interpreter_instance_identity,
               aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_out) {
  aqt_trusted_time_graceful_stop_v2_host_endpoint *owner;
  int result;

  if (owner_out == NULL || *owner_out != NULL) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return EINVAL;
  }
  owner = calloc(1U, sizeof(*owner));
  if (owner == NULL) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return ENOMEM;
  }
  result = aqt_common_adopt(&owner->common, descriptor, handshake_deadline,
                            interpreter_instance_identity);
  if (result != 0) {
    free(owner);
    return result;
  }
  owner->state = AQT_HOST_CONNECTED;
  *owner_out = owner;
  return 0;
}
#endif

int aqt_trusted_time_graceful_stop_v2_host_connector_create(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_out) {
#if !defined(__linux__) || !defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
  (void)interpreter_instance_identity;
  (void)owner_out;
  return ENOTSUP;
#else
  aqt_trusted_time_graceful_stop_v2_host_endpoint *owner = NULL;
  aqt_trusted_time_v2_host_transport_resources *resources = NULL;
  struct sockaddr_un address;
  uint64_t now;
  uint64_t handshake_deadline;
  int descriptor = -1;
  int socket_error = 0;
  socklen_t socket_error_length = (socklen_t)sizeof(socket_error);
  int result;

  result = aqt_endpoint_bootstrap_require();
  if (result != 0) {
    return result;
  }
  if (interpreter_instance_identity == 0U || owner_out == NULL ||
      *owner_out != NULL) {
    return EINVAL;
  }
  result = aqt_boottime_now(&now);
  if (result != 0 || aqt_checked_deadline(now, AQT_HANDSHAKE_BUDGET_NS,
                                          &handshake_deadline) != 0) {
    return result == 0 ? EOVERFLOW : result;
  }
  result = aqt_trusted_time_v2_host_transport_resources_prepare(
      interpreter_instance_identity, &resources);
  if (result != 0) {
    return result;
  }
  descriptor =
      socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (descriptor < 0) {
    result = aqt_errno_or_io();
    goto cleanup;
  }
  result = aqt_host_adopt(descriptor, handshake_deadline,
                          interpreter_instance_identity, &owner);
  descriptor = -1;
  if (result != 0) {
    goto cleanup;
  }
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  if (strlen(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH) >=
      sizeof(address.sun_path)) {
    result = ENAMETOOLONG;
    goto cleanup;
  }
  memcpy(address.sun_path, AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH,
         strlen(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH) + 1U);
  result = aqt_trusted_time_v2_host_transport_resources_revalidate(
      resources, interpreter_instance_identity);
  if (result != 0) {
    goto cleanup;
  }
  if (connect(owner->common.socket_fd, (const struct sockaddr *)&address,
              (socklen_t)sizeof(address)) != 0) {
    if (errno != EINPROGRESS) {
      result = aqt_errno_or_io();
      goto cleanup;
    }
    result =
        aqt_wait_ready(owner->common.socket_fd, POLLOUT, handshake_deadline);
    if (result != 0) {
      goto cleanup;
    }
    if (getsockopt(owner->common.socket_fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_length) != 0 ||
        socket_error_length != sizeof(socket_error) || socket_error != 0) {
      result = socket_error == 0 ? aqt_errno_or_io() : socket_error;
      goto cleanup;
    }
  }
  result = aqt_trusted_time_v2_host_transport_resources_bind_connected_peer(
      resources, interpreter_instance_identity, owner->common.socket_fd);
  if (result != 0) {
    goto cleanup;
  }
  owner->resources = resources;
  *owner_out = owner;
  return 0;
cleanup:
  if (descriptor >= 0) {
    (void)close(descriptor);
  }
  if (owner != NULL) {
    (void)aqt_common_burn(&owner->common, interpreter_instance_identity,
                          result);
    aqt_wipe(owner, sizeof(*owner));
    free(owner);
  }
  (void)aqt_trusted_time_v2_host_transport_resources_close(
      &resources, interpreter_instance_identity);
  return result;
#endif
}

int aqt_trusted_time_graceful_stop_v2_host_send_hello(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_hello, size_t encoded_length) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_HOST_CONNECTED ||
                      owner->common.outgoing_counter != 0U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_send_packet(
        &owner->common, canonical_signed_hello, encoded_length,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT, 0U, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.outgoing_counter = 1U;
  owner->state = AQT_HOST_HELLO_SENT;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_host_receive_supervisor_hello(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_hello_out, size_t output_capacity,
    size_t *encoded_length_out) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_HOST_HELLO_SENT ||
                      owner->common.incoming_counter != 0U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_receive_packet(
        &owner->common, canonical_signed_hello_out, output_capacity,
        encoded_length_out,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SUPERVISOR_HELLO_LIMIT, 0U, 0, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.incoming_counter = 1U;
  owner->state = AQT_HOST_SUPERVISOR_HELLO_RECEIVED;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_host_send_channel_confirmation(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_confirmation, size_t encoded_length) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_HOST_SUPERVISOR_HELLO_RECEIVED ||
                      owner->common.outgoing_counter != 1U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_send_packet(
        &owner->common, canonical_signed_confirmation, encoded_length,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_CONFIRMATION_LIMIT, 0U, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.outgoing_counter = 2U;
  owner->state = AQT_HOST_CONFIRMED;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_host_send_clean_stop_request(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_request, size_t encoded_length,
    uint64_t request_result_deadline_boottime_ns) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_HOST_CONFIRMED ||
                      owner->common.outgoing_counter != 2U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_send_packet(
        &owner->common, canonical_signed_request, encoded_length,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_REQUEST_ENVELOPE_LIMIT,
        request_result_deadline_boottime_ns, 1);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.outgoing_counter = 3U;
  owner->state = AQT_HOST_REQUEST_SENT;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_host_receive_terminal_result_or_error(
    aqt_trusted_time_graceful_stop_v2_host_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_terminal_out, size_t output_capacity,
    size_t *encoded_length_out, uint64_t request_result_deadline_boottime_ns) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_HOST_REQUEST_SENT ||
                      owner->common.incoming_counter != 1U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_receive_packet(
        &owner->common, canonical_signed_terminal_out, output_capacity,
        encoded_length_out,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT,
        request_result_deadline_boottime_ns, 1, 1);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.incoming_counter = 2U;
  owner->state = AQT_HOST_TERMINAL_RECEIVED;
  owner->common.disposition = AQT_ENDPOINT_TERMINAL;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_host_close(
    aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_io,
    uintptr_t interpreter_instance_identity) {
  aqt_trusted_time_graceful_stop_v2_host_endpoint *owner;
  int result;
  int cleanup_result;

  if (owner_io == NULL || *owner_io == NULL) {
    return 0;
  }
  owner = *owner_io;
  result =
      aqt_common_owner_require(&owner->common, interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  result = owner->common.socket_fd < 0
               ? 0
               : aqt_require_socket_identity(owner->common.socket_fd,
                                             &owner->common.socket_identity);
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
  {
    int resource_result = aqt_trusted_time_v2_host_transport_resources_close(
        &owner->resources, interpreter_instance_identity);
    if (resource_result != 0 && result == 0) {
      result = resource_result;
    }
  }
#endif
  if (owner->common.socket_fd >= 0) {
    cleanup_result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->common.socket_slot, owner->common.socket_fd);
    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
    owner->common.socket_fd = -1;
    owner->common.socket_slot = AQT_INVALID_SLOT;
  }
  aqt_wipe(owner, sizeof(*owner));
  free(owner);
  *owner_io = NULL;
  return result;
}

#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
int aqt_trusted_time_graceful_stop_v2_host_adopt_preopened_for_test(
    int connected_socket, uint64_t handshake_deadline_boottime_ns,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_host_endpoint **owner_out) {
  return aqt_host_adopt(connected_socket, handshake_deadline_boottime_ns,
                        interpreter_instance_identity, owner_out);
}
#endif
#endif

#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE) ||                         \
    defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
static int aqt_supervisor_adopt(
    int descriptor, uint64_t handshake_deadline,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_out) {
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner;
  int result;

  if (owner_out == NULL || *owner_out != NULL) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return EINVAL;
  }
  owner = calloc(1U, sizeof(*owner));
  if (owner == NULL) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return ENOMEM;
  }
  owner->listener_fd = -1;
  owner->listener_slot = AQT_INVALID_SLOT;
  result = aqt_common_adopt(&owner->common, descriptor, handshake_deadline,
                            interpreter_instance_identity);
  if (result != 0) {
    free(owner);
    return result;
  }
  owner->state = AQT_SUPERVISOR_ACCEPTED;
  *owner_out = owner;
  return 0;
}
#endif

int aqt_trusted_time_graceful_stop_v2_supervisor_listener_create(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_out) {
#if !defined(__linux__) || !defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
  (void)interpreter_instance_identity;
  (void)owner_out;
  return ENOTSUP;
#else
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner = NULL;
  aqt_trusted_time_v2_supervisor_transport_resources *resources = NULL;
  struct sockaddr_un address;
  uint64_t now;
  uint64_t handshake_deadline;
  int descriptor = -1;
  int result;

  result = aqt_endpoint_bootstrap_require();
  if (result != 0) {
    return result;
  }
  if (interpreter_instance_identity == 0U || owner_out == NULL ||
      *owner_out != NULL) {
    return EINVAL;
  }
  result = aqt_boottime_now(&now);
  if (result != 0 || aqt_checked_deadline(now, AQT_HANDSHAKE_BUDGET_NS,
                                          &handshake_deadline) != 0) {
    return result == 0 ? EOVERFLOW : result;
  }
  result = aqt_trusted_time_v2_supervisor_transport_resources_prepare(
      interpreter_instance_identity, &resources);
  if (result != 0) {
    return result;
  }
  owner = calloc(1U, sizeof(*owner));
  if (owner == NULL) {
    result = ENOMEM;
    goto cleanup;
  }
  owner->common.socket_fd = -1;
  owner->common.socket_slot = AQT_INVALID_SLOT;
  owner->common.interpreter_instance_identity = interpreter_instance_identity;
  owner->listener_fd = -1;
  owner->listener_slot = AQT_INVALID_SLOT;
  result = aqt_trusted_time_v2_fork_guard_capture_identity(
      &owner->common.fork_identity);
  if (result != 0) {
    goto cleanup;
  }
  descriptor =
      socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (descriptor < 0) {
    result = aqt_errno_or_io();
    goto cleanup;
  }
  result = aqt_trusted_time_v2_fork_guard_register_fd(descriptor,
                                                      &owner->listener_slot);
  if (result != 0) {
    goto cleanup;
  }
  owner->listener_fd = descriptor;
  descriptor = -1;
  result = aqt_validate_preopened_seqpacket(owner->listener_fd);
  if (result == 0) {
    result = aqt_capture_socket_identity(owner->listener_fd,
                                         &owner->listener_identity);
  }
  if (result != 0) {
    goto cleanup;
  }
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  if (strlen(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH) >=
      sizeof(address.sun_path)) {
    result = ENAMETOOLONG;
    goto cleanup;
  }
  memcpy(address.sun_path, AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH,
         strlen(AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_PATH) + 1U);
  result = aqt_trusted_time_v2_supervisor_transport_resources_revalidate(
      resources, interpreter_instance_identity);
  if (result != 0) {
    goto cleanup;
  }
  (void)umask(0177);
  result = bind(owner->listener_fd, (const struct sockaddr *)&address,
                (socklen_t)sizeof(address)) == 0
               ? 0
               : aqt_errno_or_io();
  if (result != 0) {
    goto cleanup;
  }
  result = aqt_trusted_time_v2_supervisor_transport_resources_bind_listener(
      resources, interpreter_instance_identity, owner->listener_fd);
  if (result != 0) {
    goto cleanup;
  }
  if (listen(owner->listener_fd, 1) != 0) {
    result = aqt_errno_or_io();
    goto cleanup;
  }
  result = aqt_trusted_time_v2_supervisor_transport_resources_revalidate(
      resources, interpreter_instance_identity);
  if (result != 0) {
    goto cleanup;
  }
  owner->common.handshake_deadline_boottime_ns = handshake_deadline;
  owner->common.disposition = AQT_ENDPOINT_OPEN;
  owner->state = AQT_SUPERVISOR_LISTENING;
  owner->resources = resources;
  *owner_out = owner;
  return 0;
cleanup:
  if (descriptor >= 0) {
    (void)close(descriptor);
  }
  if (owner != NULL) {
    if (owner->listener_fd >= 0) {
      (void)aqt_trusted_time_v2_fork_guard_close_fd(owner->listener_slot,
                                                    owner->listener_fd);
    }
    aqt_wipe(owner, sizeof(*owner));
    free(owner);
  }
  (void)aqt_trusted_time_v2_supervisor_transport_resources_close(
      &resources, interpreter_instance_identity);
  return result;
#endif
}

int aqt_trusted_time_graceful_stop_v2_supervisor_accept_once(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity) {
#if !defined(__linux__) || !defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
  (void)owner;
  (void)interpreter_instance_identity;
  return ENOTSUP;
#else
  int accepted;
  uint64_t handshake_deadline;
  AqtSocketFdIdentity listener_identity;
  int result;

  if (owner == NULL) {
    return EINVAL;
  }
  result =
      aqt_common_owner_require(&owner->common, interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  if (owner->common.disposition != AQT_ENDPOINT_OPEN ||
      owner->state != AQT_SUPERVISOR_LISTENING || owner->listener_fd < 0 ||
      owner->common.socket_fd >= 0) {
    return EPROTO;
  }
  result = aqt_capture_socket_identity(owner->listener_fd, &listener_identity);
  if (result != 0 || !aqt_socket_identity_equal(&owner->listener_identity,
                                                &listener_identity)) {
    return result == 0 ? ESTALE : result;
  }
  result = aqt_trusted_time_v2_supervisor_transport_resources_revalidate(
      owner->resources, interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  handshake_deadline = owner->common.handshake_deadline_boottime_ns;
  result = aqt_wait_ready(owner->listener_fd, POLLIN,
                          owner->common.handshake_deadline_boottime_ns);
  if (result != 0) {
    return result;
  }
  accepted =
      accept4(owner->listener_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
  if (accepted < 0) {
    return aqt_errno_or_io();
  }
  result = aqt_common_adopt(&owner->common, accepted, handshake_deadline,
                            interpreter_instance_identity);
  if (result != 0) {
    (void)aqt_trusted_time_v2_fork_guard_close_fd(owner->listener_slot,
                                                  owner->listener_fd);
    owner->listener_fd = -1;
    owner->listener_slot = AQT_INVALID_SLOT;
    return result;
  }
  result = aqt_trusted_time_v2_fork_guard_close_fd(owner->listener_slot,
                                                   owner->listener_fd);
  owner->listener_fd = -1;
  owner->listener_slot = AQT_INVALID_SLOT;
  if (result == 0) {
    result =
        aqt_trusted_time_v2_supervisor_transport_resources_bind_accepted_peer(
            owner->resources, interpreter_instance_identity,
            owner->common.socket_fd);
  }
  if (result != 0) {
    return aqt_common_burn(&owner->common, interpreter_instance_identity,
                           result);
  }
  owner->state = AQT_SUPERVISOR_ACCEPTED;
  return 0;
#endif
}

int aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_hello(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_hello_out, size_t output_capacity,
    size_t *encoded_length_out) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_SUPERVISOR_ACCEPTED ||
                      owner->common.incoming_counter != 0U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_receive_packet(
        &owner->common, canonical_signed_hello_out, output_capacity,
        encoded_length_out, AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_HELLO_LIMIT,
        0U, 0, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.incoming_counter = 1U;
  owner->state = AQT_SUPERVISOR_HOST_HELLO_RECEIVED;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_supervisor_send_hello(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    const unsigned char *canonical_signed_hello, size_t encoded_length) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_SUPERVISOR_HOST_HELLO_RECEIVED ||
                      owner->common.outgoing_counter != 0U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_send_packet(
        &owner->common, canonical_signed_hello, encoded_length,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SUPERVISOR_HELLO_LIMIT, 0U, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.outgoing_counter = 1U;
  owner->state = AQT_SUPERVISOR_HELLO_SENT;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_supervisor_receive_host_confirmation(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_confirmation_out, size_t output_capacity,
    size_t *encoded_length_out) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_SUPERVISOR_HELLO_SENT ||
                      owner->common.incoming_counter != 1U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_receive_packet(
        &owner->common, canonical_signed_confirmation_out, output_capacity,
        encoded_length_out,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_HOST_CONFIRMATION_LIMIT, 0U, 0, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.incoming_counter = 2U;
  owner->state = AQT_SUPERVISOR_CONFIRMED;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_supervisor_receive_clean_stop_request(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    unsigned char *canonical_signed_request_out, size_t output_capacity,
    size_t *encoded_length_out, uint64_t request_result_deadline_boottime_ns) {
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (result == 0 && (owner->state != AQT_SUPERVISOR_CONFIRMED ||
                      owner->common.incoming_counter != 2U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_receive_packet(
        &owner->common, canonical_signed_request_out, output_capacity,
        encoded_length_out,
        AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_REQUEST_ENVELOPE_LIMIT,
        request_result_deadline_boottime_ns, 1, 0);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.incoming_counter = 3U;
  owner->state = AQT_SUPERVISOR_REQUEST_RECEIVED;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_supervisor_send_terminal_result_or_error(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_terminal_kind terminal_kind,
    const unsigned char *canonical_signed_terminal, size_t encoded_length,
    uint64_t request_result_deadline_boottime_ns) {
  size_t maximum;
  int result =
      owner == NULL
          ? EINVAL
          : aqt_common_require(&owner->common, interpreter_instance_identity);

  if (terminal_kind == AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TERMINAL_RESULT) {
    maximum = AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_RESULT_ENVELOPE_LIMIT;
  } else if (terminal_kind ==
             AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TERMINAL_ERROR) {
    maximum = AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_ERROR_ENVELOPE_LIMIT;
  } else {
    maximum = 0U;
    result = EINVAL;
  }
  if (result == 0 && (owner->state != AQT_SUPERVISOR_REQUEST_RECEIVED ||
                      owner->common.outgoing_counter != 1U)) {
    result = EPROTO;
  }
  if (result == 0) {
    result = aqt_send_packet(&owner->common, canonical_signed_terminal,
                             encoded_length, maximum,
                             request_result_deadline_boottime_ns, 1);
  }
  if (result != 0) {
    return owner == NULL
               ? result
               : aqt_common_burn(&owner->common, interpreter_instance_identity,
                                 result);
  }
  owner->common.outgoing_counter = 2U;
  owner->state = AQT_SUPERVISOR_TERMINAL_SENT;
  owner->common.disposition = AQT_ENDPOINT_TERMINAL;
  return 0;
}

int aqt_trusted_time_graceful_stop_v2_supervisor_close(
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_io,
    uintptr_t interpreter_instance_identity) {
  aqt_trusted_time_graceful_stop_v2_supervisor_endpoint *owner;
  int result;
  int cleanup_result;

  if (owner_io == NULL || *owner_io == NULL) {
    return 0;
  }
  owner = *owner_io;
  result =
      aqt_common_owner_require(&owner->common, interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  result = owner->common.socket_fd < 0
               ? 0
               : aqt_require_socket_identity(owner->common.socket_fd,
                                             &owner->common.socket_identity);
  if (owner->listener_fd >= 0) {
    int listener_result = aqt_require_socket_identity(
        owner->listener_fd, &owner->listener_identity);

    if (listener_result != 0 && result == 0) {
      result = listener_result;
    }
  }
#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
  {
    int resource_result =
        aqt_trusted_time_v2_supervisor_transport_resources_close(
            &owner->resources, interpreter_instance_identity);

    if (resource_result != 0 && result == 0) {
      result = resource_result;
    }
  }
#endif
  if (owner->common.socket_fd >= 0) {
    cleanup_result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->common.socket_slot, owner->common.socket_fd);
    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
    owner->common.socket_fd = -1;
    owner->common.socket_slot = AQT_INVALID_SLOT;
  }
  if (owner->listener_fd >= 0) {
    cleanup_result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->listener_slot, owner->listener_fd);
    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
    owner->listener_fd = -1;
    owner->listener_slot = AQT_INVALID_SLOT;
  }
  aqt_wipe(owner, sizeof(*owner));
  free(owner);
  *owner_io = NULL;
  return result;
}

#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
int aqt_trusted_time_graceful_stop_v2_supervisor_adopt_preopened_for_test(
    int connected_socket, uint64_t handshake_deadline_boottime_ns,
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_graceful_stop_v2_supervisor_endpoint **owner_out) {
  return aqt_supervisor_adopt(connected_socket, handshake_deadline_boottime_ns,
                              interpreter_instance_identity, owner_out);
}
#endif
#endif

#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
uint64_t aqt_trusted_time_graceful_stop_v2_test_boottime_now_ns(void) {
  uint64_t sampled = 0U;

  return aqt_boottime_now(&sampled) == 0 ? sampled : 0U;
}

int aqt_trusted_time_graceful_stop_v2_test_packet_admission(
    size_t received_length, int message_flags, size_t method_limit,
    size_t control_length, size_t source_name_length) {
  return aqt_packet_admission_result(received_length, message_flags,
                                     method_limit, control_length,
                                     source_name_length);
}
#endif
