#define _GNU_SOURCE

#include "trusted_time_graceful_stop_v2_resources.h"

#include "trusted_time_v2_fork_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/magic.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>

#if !defined(NSFS_MAGIC)
#error "Linux trusted-time PID-namespace admission requires NSFS_MAGIC."
#endif
#endif

#if (defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) +                               \
     defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)) > 1
#error "Only one lifecycle-v2 endpoint resource role may be compiled."
#endif

#define AQT_MOUNTINFO_LIMIT (1024U * 1024U)
#define AQT_MOUNTINFO_LINE_LIMIT 4096U
#define AQT_PROC_FILE_LIMIT 65536U
#define AQT_CGROUP_LIMIT 8192U
#define AQT_EXECUTABLE_PATH_LIMIT 256U
#define AQT_EXECUTABLE_SIZE_LIMIT INT64_C(268435456)
#define AQT_INVALID_SLOT UINT32_MAX

#if defined(__GNUC__) || defined(__clang__)
#define AQT_MAYBE_UNUSED __attribute__((unused))
#else
#define AQT_MAYBE_UNUSED
#endif

typedef struct {
  uint64_t device;
  uint64_t inode;
  uint32_t file_type;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  uint64_t link_count;
  int64_t size;
  int64_t modification_seconds;
  int64_t modification_nanoseconds;
  int64_t change_seconds;
  int64_t change_nanoseconds;
} AqtStat9;

typedef struct {
  uint64_t mount_id;
  uint64_t parent_mount_id;
  uint32_t major_device;
  uint32_t minor_device;
  char root[8];
  char mount_options[128];
  char super_options[128];
} AqtMountIdentity;

typedef struct {
  uint32_t uid;
  uint32_t gid;
  int64_t pid;
} AqtPeerCredential;

typedef struct {
  int descriptor;
  uint32_t slot;
} AqtGuardedFd;

typedef struct {
  AqtStat9 root;
  AqtStat9 proc;
  AqtStat9 process;
} AqtProcPathIdentity;

typedef struct {
  AqtProcPathIdentity proc_path_identity;
  uint64_t start_time_ticks;
  AqtStat9 namespace_directory_identity;
  AqtStat9 namespace_link_identity;
  uint64_t pid_namespace_device;
  uint64_t pid_namespace_inode;
  char pid_namespace_path[64];
  uint64_t namespace_pid;
  AqtStat9 executable_identity;
  char executable_path[AQT_EXECUTABLE_PATH_LIMIT];
  unsigned char cgroup[AQT_CGROUP_LIMIT];
  size_t cgroup_length;
  char container_id[65];
} AqtHostVisibleProcessIdentity;

typedef struct {
  aqt_trusted_time_v2_fork_identity fork_identity;
  uintptr_t interpreter_instance_identity;
  int directory_fd;
  uint32_t directory_slot;
  AqtStat9 directory_identity;
  AqtMountIdentity mount_identity;
  int borrowed_socket;
  AqtStat9 borrowed_socket_identity;
  uint64_t borrowed_socket_cookie;
  int borrowed_socket_bound;
  AqtStat9 socket_identity;
  int socket_identity_bound;
  AqtPeerCredential peer_credential;
  int peer_bound;
  int process_directory_fd;
  uint32_t process_directory_slot;
  AqtHostVisibleProcessIdentity process_identity;
  int process_identity_bound;
  int unlink_socket_on_close;
} AqtTransportResources;

struct aqt_trusted_time_v2_host_transport_resources {
  AqtTransportResources base;
};

struct aqt_trusted_time_v2_supervisor_transport_resources {
  AqtTransportResources base;
};

#if defined(__linux__)
static int aqt_errno_or_io(void) { return errno == 0 ? EIO : errno; }

static void aqt_guarded_fd_initialize(AqtGuardedFd *owner) {
  owner->descriptor = -1;
  owner->slot = AQT_INVALID_SLOT;
}

static int aqt_guarded_fd_adopt(int descriptor, AqtGuardedFd *owner) {
  int result;

  if (owner == NULL) {
    if (descriptor >= 0) {
      (void)close(descriptor);
    }
    return EINVAL;
  }
  if (descriptor < 0) {
    return aqt_errno_or_io();
  }
  aqt_guarded_fd_initialize(owner);
  result = aqt_trusted_time_v2_fork_guard_register_fd(descriptor, &owner->slot);
  if (result != 0) {
    (void)close(descriptor);
    return result;
  }
  owner->descriptor = descriptor;
  return 0;
}

static int aqt_guarded_fd_close(AqtGuardedFd *owner) {
  int result;

  if (owner == NULL || owner->descriptor < 0) {
    return 0;
  }
  result =
      aqt_trusted_time_v2_fork_guard_close_fd(owner->slot, owner->descriptor);
  owner->descriptor = -1;
  owner->slot = AQT_INVALID_SLOT;
  return result;
}
#endif

#if defined(__linux__) || defined(AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING)
static int aqt_parse_u64(const char *text, uint64_t maximum,
                         uint64_t *value_out) {
  uint64_t value = 0U;
  const unsigned char *cursor = (const unsigned char *)text;

  if (text == NULL || value_out == NULL || *cursor == '\0') {
    return EINVAL;
  }
  while (*cursor != '\0') {
    uint64_t digit;

    if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9') {
      return EINVAL;
    }
    digit = (uint64_t)(*cursor - (unsigned char)'0');
    if (value > (maximum - digit) / UINT64_C(10)) {
      return ERANGE;
    }
    value = value * UINT64_C(10) + digit;
    cursor++;
  }
  *value_out = value;
  return 0;
}

static int aqt_option_set_is_exact(const char *options,
                                   const char *const *required,
                                   size_t required_count, const char *optional,
                                   int *optional_present_out) {
  int seen[8] = {0};
  int optional_seen = 0;
  const char *cursor = options;

  if (options == NULL || required == NULL || required_count == 0U ||
      required_count > sizeof(seen) / sizeof(seen[0]) || *options == '\0' ||
      options[strlen(options) - 1U] == ',') {
    return 0;
  }
  while (cursor != NULL && *cursor != '\0') {
    const char *end = strchr(cursor, ',');
    size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
    int matched = 0;

    if (length == 0U) {
      return 0;
    }
    for (size_t index = 0U; index < required_count; ++index) {
      if (strlen(required[index]) == length &&
          memcmp(cursor, required[index], length) == 0) {
        if (seen[index]) {
          return 0;
        }
        seen[index] = 1;
        matched = 1;
        break;
      }
    }
    if (!matched && optional != NULL && strlen(optional) == length &&
        memcmp(cursor, optional, length) == 0) {
      if (optional_seen) {
        return 0;
      }
      optional_seen = 1;
      matched = 1;
    }
    if (!matched) {
      return 0;
    }
    cursor = end == NULL ? NULL : end + 1;
  }
  for (size_t index = 0U; index < required_count; ++index) {
    if (!seen[index]) {
      return 0;
    }
  }
  if (optional_present_out != NULL) {
    *optional_present_out = optional_seen;
  }
  return 1;
}

static int aqt_parse_major_minor(const char *text, uint32_t *major_out,
                                 uint32_t *minor_out) {
  char copy[64];
  char *separator;
  uint64_t parsed_major;
  uint64_t parsed_minor;

  if (text == NULL || major_out == NULL || minor_out == NULL ||
      strlen(text) >= sizeof(copy)) {
    return EINVAL;
  }
  memcpy(copy, text, strlen(text) + 1U);
  separator = strchr(copy, ':');
  if (separator == NULL || strchr(separator + 1, ':') != NULL) {
    return EINVAL;
  }
  *separator = '\0';
  if (aqt_parse_u64(copy, UINT32_MAX, &parsed_major) != 0 ||
      aqt_parse_u64(separator + 1, UINT32_MAX, &parsed_minor) != 0) {
    return EINVAL;
  }
  *major_out = (uint32_t)parsed_major;
  *minor_out = (uint32_t)parsed_minor;
  return 0;
}

#if defined(__linux__)
static int aqt_mount_identity_equal(const AqtMountIdentity *left,
                                    const AqtMountIdentity *right) {
  return left != NULL && right != NULL && left->mount_id == right->mount_id &&
         left->parent_mount_id == right->parent_mount_id &&
         left->major_device == right->major_device &&
         left->minor_device == right->minor_device &&
         strcmp(left->root, right->root) == 0 &&
         strcmp(left->mount_options, right->mount_options) == 0 &&
         strcmp(left->super_options, right->super_options) == 0;
}
#endif

static int aqt_parse_transport_mountinfo(const unsigned char *bytes,
                                         size_t length,
                                         AqtMountIdentity *identity_out) {
  size_t offset = 0U;
  int matches = 0;
  AqtMountIdentity selected;

  if (bytes == NULL || identity_out == NULL || length == 0U ||
      length > AQT_MOUNTINFO_LIMIT ||
      bytes[length - 1U] != (unsigned char)'\n' ||
      memchr(bytes, '\0', length) != NULL) {
    return EINVAL;
  }
  for (size_t index = 0U; index < length; ++index) {
    unsigned char value = bytes[index];

    if ((value < (unsigned char)' ' && value != (unsigned char)'\n') ||
        value == 0x7fU) {
      return EINVAL;
    }
  }
  memset(&selected, 0, sizeof(selected));
  while (offset < length) {
    size_t end = offset;
    size_t line_length;
    char line[AQT_MOUNTINFO_LINE_LIMIT + 1U];
    char *fields[96];
    size_t field_count = 0U;
    char *save = NULL;
    char *token;
    size_t separator_index = SIZE_MAX;

    while (end < length && bytes[end] != (unsigned char)'\n') {
      end++;
    }
    line_length = end - offset;
    if (line_length == 0U || line_length > AQT_MOUNTINFO_LINE_LIMIT) {
      return EINVAL;
    }
    memcpy(line, bytes + offset, line_length);
    line[line_length] = '\0';
    if (line[0] == ' ' || line[line_length - 1U] == ' ' ||
        strstr(line, "  ") != NULL) {
      return EINVAL;
    }
    token = strtok_r(line, " ", &save);
    while (token != NULL) {
      if (field_count >= sizeof(fields) / sizeof(fields[0])) {
        return E2BIG;
      }
      fields[field_count++] = token;
      token = strtok_r(NULL, " ", &save);
    }
    if (field_count < 10U) {
      return EINVAL;
    }
    for (size_t index = 6U; index < field_count; ++index) {
      if (strcmp(fields[index], "-") == 0) {
        separator_index = index;
        break;
      }
    }
    if (separator_index == SIZE_MAX || separator_index + 3U >= field_count) {
      return EINVAL;
    }
    if (strcmp(fields[4],
               AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_TRANSPORT_DIRECTORY) == 0) {
      uint64_t mount_id;
      uint64_t parent_id;
      AqtMountIdentity candidate;
      const char *mount_options = fields[5];
      const char *filesystem = fields[separator_index + 1U];
      const char *mount_source = fields[separator_index + 2U];
      const char *super_options = fields[separator_index + 3U];
      static const char *const required_mount_options[] = {
          "rw", "nosuid", "nodev", "noexec", "relatime",
      };
      static const char *const required_super_options[] = {
          "rw",
          "size=64k",
          "mode=770",
          "gid=10001",
      };
      int inode64_present = 0;

      memset(&candidate, 0, sizeof(candidate));
      if (++matches != 1 || separator_index != 6U ||
          field_count != separator_index + 4U ||
          aqt_parse_u64(fields[0], INT64_MAX, &mount_id) != 0 ||
          aqt_parse_u64(fields[1], INT64_MAX, &parent_id) != 0 ||
          aqt_parse_major_minor(fields[2], &candidate.major_device,
                                &candidate.minor_device) != 0 ||
          strcmp(fields[3], "/") != 0 || strcmp(filesystem, "tmpfs") != 0 ||
          strcmp(mount_source, "tmpfs") != 0 ||
          strlen(fields[3]) >= sizeof(candidate.root) ||
          strlen(mount_options) >= sizeof(candidate.mount_options) ||
          strlen(super_options) >= sizeof(candidate.super_options) ||
          !aqt_option_set_is_exact(mount_options, required_mount_options,
                                   sizeof(required_mount_options) /
                                       sizeof(required_mount_options[0]),
                                   NULL, NULL) ||
          !aqt_option_set_is_exact(super_options, required_super_options,
                                   sizeof(required_super_options) /
                                       sizeof(required_super_options[0]),
                                   "inode64", &inode64_present)) {
        return EPERM;
      }
      candidate.mount_id = mount_id;
      candidate.parent_mount_id = parent_id;
      memcpy(candidate.root, fields[3], strlen(fields[3]) + 1U);
      memcpy(candidate.mount_options, "nodev,noexec,nosuid,relatime,rw",
             sizeof("nodev,noexec,nosuid,relatime,rw"));
      if (inode64_present) {
        memcpy(candidate.super_options,
               "gid=10001,inode64,mode=770,rw,size=64K",
               sizeof("gid=10001,inode64,mode=770,rw,size=64K"));
      } else {
        memcpy(candidate.super_options, "gid=10001,mode=770,rw,size=64K",
               sizeof("gid=10001,mode=770,rw,size=64K"));
      }
      selected = candidate;
    }
    offset = end == length ? end : end + 1U;
  }
  if (matches != 1) {
    return ENOENT;
  }
  *identity_out = selected;
  return 0;
}
#endif

#if defined(__linux__)
static void aqt_stat9_from_stat(const struct stat *metadata,
                                AqtStat9 *identity) {
  identity->device = (uint64_t)metadata->st_dev;
  identity->inode = (uint64_t)metadata->st_ino;
  identity->file_type = (uint32_t)(metadata->st_mode & S_IFMT);
  identity->mode = (uint32_t)(metadata->st_mode & 07777);
  identity->uid = (uint32_t)metadata->st_uid;
  identity->gid = (uint32_t)metadata->st_gid;
  identity->link_count = (uint64_t)metadata->st_nlink;
  identity->size = (int64_t)metadata->st_size;
  identity->modification_seconds = (int64_t)metadata->st_mtim.tv_sec;
  identity->modification_nanoseconds = (int64_t)metadata->st_mtim.tv_nsec;
  identity->change_seconds = (int64_t)metadata->st_ctim.tv_sec;
  identity->change_nanoseconds = (int64_t)metadata->st_ctim.tv_nsec;
}

static int aqt_stat9_equal(const AqtStat9 *left, const AqtStat9 *right) {
  return left != NULL && right != NULL && left->device == right->device &&
         left->inode == right->inode && left->file_type == right->file_type &&
         left->mode == right->mode && left->uid == right->uid &&
         left->gid == right->gid && left->link_count == right->link_count &&
         left->size == right->size &&
         left->modification_seconds == right->modification_seconds &&
         left->modification_nanoseconds == right->modification_nanoseconds &&
         left->change_seconds == right->change_seconds &&
         left->change_nanoseconds == right->change_nanoseconds;
}

static int AQT_MAYBE_UNUSED aqt_directory_binding_equal(const AqtStat9 *left,
                                                        const AqtStat9 *right) {
  return left != NULL && right != NULL && left->device == right->device &&
         left->inode == right->inode && left->file_type == right->file_type &&
         left->mode == right->mode && left->uid == right->uid &&
         left->gid == right->gid && left->link_count == right->link_count;
}

static int aqt_fstat9(int descriptor, AqtStat9 *identity_out) {
  struct stat first;
  struct stat second;
  AqtStat9 first_identity;
  AqtStat9 second_identity;

  if (fstat(descriptor, &first) != 0 || fstat(descriptor, &second) != 0) {
    return aqt_errno_or_io();
  }
  aqt_stat9_from_stat(&first, &first_identity);
  aqt_stat9_from_stat(&second, &second_identity);
  if (!aqt_stat9_equal(&first_identity, &second_identity)) {
    return ESTALE;
  }
  *identity_out = first_identity;
  return 0;
}

static int aqt_fstatat9(int directory_fd, const char *name,
                        AqtStat9 *identity_out) {
  struct stat first;
  struct stat second;
  AqtStat9 first_identity;
  AqtStat9 second_identity;

  if (fstatat(directory_fd, name, &first, AT_SYMLINK_NOFOLLOW) != 0 ||
      fstatat(directory_fd, name, &second, AT_SYMLINK_NOFOLLOW) != 0) {
    return aqt_errno_or_io();
  }
  aqt_stat9_from_stat(&first, &first_identity);
  aqt_stat9_from_stat(&second, &second_identity);
  if (!aqt_stat9_equal(&first_identity, &second_identity)) {
    return ESTALE;
  }
  *identity_out = first_identity;
  return 0;
}

static int aqt_read_bounded_descriptor(int descriptor, unsigned char *buffer,
                                       size_t capacity, size_t *length_out) {
  size_t length = 0U;

  if (buffer == NULL || length_out == NULL || capacity == 0U) {
    return EINVAL;
  }
  while (length < capacity) {
    ssize_t count =
        pread(descriptor, buffer + length, capacity - length, (off_t)length);

    if (count > 0) {
      length += (size_t)count;
      continue;
    }
    if (count == 0) {
      *length_out = length;
      return 0;
    }
    if (errno == EINTR) {
      continue;
    }
    return aqt_errno_or_io();
  }
  {
    unsigned char extra;
    ssize_t count = pread(descriptor, &extra, 1U, (off_t)length);

    if (count == 0) {
      *length_out = length;
      return 0;
    }
    if (count < 0 && errno != EINTR) {
      return aqt_errno_or_io();
    }
  }
  return EFBIG;
}

static int aqt_root_owned_ancestor_is_valid(const AqtStat9 *identity,
                                            uint64_t minimum_link_count) {
  return identity != NULL && identity->file_type == S_IFDIR &&
                 identity->uid == 0U && identity->gid == 0U &&
                 (identity->mode & 0022U) == 0U &&
                 identity->link_count >= minimum_link_count
             ? 0
             : EPERM;
}

static int aqt_proc_directory_is_valid(const AqtStat9 *identity,
                                       uint32_t expected_uid,
                                       uint32_t expected_gid,
                                       uint32_t expected_mode) {
  return identity != NULL && identity->file_type == S_IFDIR &&
                 identity->uid == expected_uid &&
                 identity->gid == expected_gid &&
                 identity->mode == expected_mode && identity->link_count >= 2U
             ? 0
             : EPERM;
}

static int aqt_process_directory_is_valid(const AqtStat9 *identity,
                                          uint32_t expected_uid,
                                          uint32_t expected_gid) {
  return aqt_proc_directory_is_valid(identity, expected_uid, expected_gid,
                                     0555U);
}

static int aqt_open_root_correlated(AqtGuardedFd *root_out,
                                    AqtStat9 *identity_out) {
  AqtGuardedFd first;
  AqtGuardedFd second;
  AqtStat9 first_identity;
  AqtStat9 second_identity;
  int result;

  if (root_out == NULL || identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(root_out);
  aqt_guarded_fd_initialize(&first);
  aqt_guarded_fd_initialize(&second);
  result = aqt_guarded_fd_adopt(
      open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW), &first);
  if (result == 0) {
    result = aqt_fstat9(first.descriptor, &first_identity);
  }
  if (result == 0) {
    result = aqt_root_owned_ancestor_is_valid(&first_identity, 1U);
  }
  if (result == 0) {
    result = aqt_guarded_fd_adopt(
        open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW), &second);
  }
  if (result == 0) {
    result = aqt_fstat9(second.descriptor, &second_identity);
  }
  if (result == 0 && !aqt_stat9_equal(&first_identity, &second_identity)) {
    result = ESTALE;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&second);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result != 0) {
    (void)aqt_guarded_fd_close(&first);
    return result;
  }
  *root_out = first;
  *identity_out = first_identity;
  return 0;
}

static int aqt_openat_correlated_directory(int parent_fd, const char *name,
                                           int require_root_owned_ancestor,
                                           uint64_t minimum_link_count,
                                           AqtGuardedFd *directory_out,
                                           AqtStat9 *identity_out) {
  AqtGuardedFd directory;
  AqtStat9 before;
  AqtStat9 held;
  AqtStat9 after;
  int result;

  if (parent_fd < 0 || name == NULL || *name == '\0' ||
      strchr(name, '/') != NULL || directory_out == NULL ||
      identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(directory_out);
  aqt_guarded_fd_initialize(&directory);
  result = aqt_fstatat9(parent_fd, name, &before);
  if (result == 0 && before.file_type != S_IFDIR) {
    result = EPERM;
  }
  if (result == 0 && before.link_count < minimum_link_count) {
    result = EPERM;
  }
  if (result == 0 && require_root_owned_ancestor) {
    result = aqt_root_owned_ancestor_is_valid(&before, minimum_link_count);
  }
  if (result == 0) {
    result = aqt_guarded_fd_adopt(
        openat(parent_fd, name,
               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
        &directory);
  }
  if (result == 0) {
    result = aqt_fstat9(directory.descriptor, &held);
  }
  if (result == 0) {
    result = aqt_fstatat9(parent_fd, name, &after);
  }
  if (result == 0 &&
      (!aqt_stat9_equal(&before, &held) || !aqt_stat9_equal(&held, &after))) {
    result = ESTALE;
  }
  if (result != 0) {
    (void)aqt_guarded_fd_close(&directory);
    return result;
  }
  *directory_out = directory;
  *identity_out = held;
  return 0;
}

static int aqt_open_numeric_proc_directory(pid_t pid, uint32_t expected_uid,
                                           uint32_t expected_gid,
                                           AqtGuardedFd *process_out,
                                           AqtProcPathIdentity *identity_out) {
  char pid_name[32];
  AqtGuardedFd root;
  AqtGuardedFd proc;
  AqtGuardedFd process;
  AqtProcPathIdentity identity;
  struct statfs filesystem;
  int length;
  int result;

  if (pid <= 0 || process_out == NULL || identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(process_out);
  aqt_guarded_fd_initialize(&root);
  aqt_guarded_fd_initialize(&proc);
  aqt_guarded_fd_initialize(&process);
  memset(&identity, 0, sizeof(identity));
  length = snprintf(pid_name, sizeof(pid_name), "%" PRIdMAX, (intmax_t)pid);
  if (length <= 0 || (size_t)length >= sizeof(pid_name)) {
    return EINVAL;
  }
  result = aqt_open_root_correlated(&root, &identity.root);
  if (result == 0) {
    result = aqt_openat_correlated_directory(root.descriptor, "proc", 1, 2U,
                                             &proc, &identity.proc);
  }
  if (result == 0) {
    result = aqt_proc_directory_is_valid(&identity.proc, 0U, 0U, 0555U);
  }
  if (result == 0 && fstatfs(proc.descriptor, &filesystem) != 0) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && filesystem.f_type != PROC_SUPER_MAGIC) {
    result = EPERM;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&root);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result == 0) {
    result = aqt_openat_correlated_directory(proc.descriptor, pid_name, 0, 2U,
                                             &process, &identity.process);
  }
  if (result == 0) {
    result = aqt_process_directory_is_valid(&identity.process, expected_uid,
                                            expected_gid);
  }
  if (result == 0 && fstatfs(process.descriptor, &filesystem) != 0) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && filesystem.f_type != PROC_SUPER_MAGIC) {
    result = EPERM;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&proc);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result != 0) {
    (void)aqt_guarded_fd_close(&process);
    return result;
  }
  *process_out = process;
  *identity_out = identity;
  return 0;
}

static int aqt_proc_path_identity_equal(const AqtProcPathIdentity *left,
                                        const AqtProcPathIdentity *right) {
  return left != NULL && right != NULL &&
         aqt_stat9_equal(&left->root, &right->root) &&
         aqt_stat9_equal(&left->proc, &right->proc) &&
         aqt_stat9_equal(&left->process, &right->process);
}

static int aqt_read_mountinfo_once(int process_fd, unsigned char *buffer,
                                   size_t capacity, size_t *length_out,
                                   AqtStat9 *identity_out) {
  AqtGuardedFd descriptor;
  AqtStat9 named_before;
  AqtStat9 held_before;
  AqtStat9 held_after;
  AqtStat9 named_after;
  struct statfs filesystem;
  int result;

  if (process_fd < 0 || buffer == NULL || capacity == 0U ||
      length_out == NULL || identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(&descriptor);
  result = aqt_fstatat9(process_fd, "mountinfo", &named_before);
  if (result == 0 &&
      (named_before.file_type != S_IFREG ||
       named_before.uid != (uint32_t)geteuid() ||
       named_before.gid != (uint32_t)getegid() || named_before.mode != 0444U ||
       named_before.link_count != 1U || named_before.size != 0)) {
    result = EPERM;
  }
  if (result == 0) {
    result = aqt_guarded_fd_adopt(
        openat(process_fd, "mountinfo", O_RDONLY | O_CLOEXEC | O_NOFOLLOW),
        &descriptor);
  }
  if (result == 0) {
    result = aqt_fstat9(descriptor.descriptor, &held_before);
  }
  if (result == 0) {
    result = aqt_fstatat9(process_fd, "mountinfo", &named_after);
  }
  if (result == 0 && (!aqt_stat9_equal(&named_before, &held_before) ||
                      !aqt_stat9_equal(&held_before, &named_after))) {
    result = ESTALE;
  }
  if (result == 0 && fstatfs(descriptor.descriptor, &filesystem) != 0) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && filesystem.f_type != PROC_SUPER_MAGIC) {
    result = EPERM;
  }
  if (result == 0) {
    result = aqt_read_bounded_descriptor(descriptor.descriptor, buffer,
                                         capacity, length_out);
  }
  if (result == 0) {
    result = aqt_fstat9(descriptor.descriptor, &held_after);
  }
  if (result == 0) {
    result = aqt_fstatat9(process_fd, "mountinfo", &named_after);
  }
  if (result == 0 && (!aqt_stat9_equal(&held_before, &held_after) ||
                      !aqt_stat9_equal(&held_after, &named_after))) {
    result = ESTALE;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&descriptor);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result == 0) {
    *identity_out = held_after;
  }
  return result;
}

static int aqt_capture_mount_identity(pid_t pid,
                                      AqtMountIdentity *identity_out) {
  unsigned char *first = NULL;
  unsigned char *second = NULL;
  size_t first_length = 0U;
  size_t second_length = 0U;
  AqtProcPathIdentity first_path;
  AqtProcPathIdentity second_path;
  AqtStat9 first_file;
  AqtStat9 second_file;
  AqtGuardedFd process;
  int result = 0;

  if (pid <= 0 || pid != getpid() || identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(&process);
  first = calloc(AQT_MOUNTINFO_LIMIT, 1U);
  second = calloc(AQT_MOUNTINFO_LIMIT, 1U);
  if (first == NULL || second == NULL) {
    result = ENOMEM;
    goto cleanup;
  }
  result = aqt_open_numeric_proc_directory(
      pid, (uint32_t)geteuid(), (uint32_t)getegid(), &process, &first_path);
  if (result == 0) {
    result =
        aqt_read_mountinfo_once(process.descriptor, first, AQT_MOUNTINFO_LIMIT,
                                &first_length, &first_file);
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&process);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result == 0) {
    result = aqt_open_numeric_proc_directory(
        pid, (uint32_t)geteuid(), (uint32_t)getegid(), &process, &second_path);
  }
  if (result == 0 && !aqt_proc_path_identity_equal(&first_path, &second_path)) {
    result = ESTALE;
  }
  if (result == 0) {
    result =
        aqt_read_mountinfo_once(process.descriptor, second, AQT_MOUNTINFO_LIMIT,
                                &second_length, &second_file);
  }
  if (result == 0 && (!aqt_stat9_equal(&first_file, &second_file) ||
                      first_length != second_length ||
                      memcmp(first, second, first_length) != 0)) {
    result = ESTALE;
  }
  if (result == 0) {
    result = aqt_parse_transport_mountinfo(first, first_length, identity_out);
  }
cleanup: {
  int cleanup_result = aqt_guarded_fd_close(&process);

  if (cleanup_result != 0 && result == 0) {
    result = cleanup_result;
  }
}
  free(first);
  free(second);
  return result;
}

static int aqt_open_literal_transport_directory(AqtGuardedFd *directory_out) {
  static const char *const components[] = {
      "run", "autoquant", "trusted-time", "graceful-stop-v2", "transport",
  };
  AqtGuardedFd descriptor;
  int result;

  if (directory_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(directory_out);
  aqt_guarded_fd_initialize(&descriptor);
  {
    AqtStat9 root_identity;

    result = aqt_open_root_correlated(&descriptor, &root_identity);
  }
  if (result != 0) {
    return result;
  }
  for (size_t index = 0U; index < sizeof(components) / sizeof(components[0]);
       ++index) {
    AqtGuardedFd next;
    AqtStat9 identity;

    aqt_guarded_fd_initialize(&next);
    result = aqt_openat_correlated_directory(
        descriptor.descriptor, components[index],
        index + 1U < sizeof(components) / sizeof(components[0]),
        index == 0U ? 1U : 2U, &next, &identity);
    if (result != 0) {
      (void)aqt_guarded_fd_close(&descriptor);
      return result;
    }
    result = aqt_guarded_fd_close(&descriptor);
    if (result != 0) {
      (void)aqt_guarded_fd_close(&next);
      return result;
    }
    descriptor = next;
  }
  *directory_out = descriptor;
  return 0;
}

static int aqt_validate_directory(int directory_fd,
                                  const AqtMountIdentity *mount,
                                  AqtStat9 *identity_out) {
  struct statfs filesystem;
  AqtStat9 identity;
  int result = aqt_fstat9(directory_fd, &identity);

  if (result != 0) {
    return result;
  }
  if (fstatfs(directory_fd, &filesystem) != 0) {
    return aqt_errno_or_io();
  }
  if (identity.file_type != S_IFDIR || identity.uid != 0U ||
      identity.gid != 10001U || identity.mode != 0770U ||
      identity.link_count < 2U || filesystem.f_type != TMPFS_MAGIC ||
      (uint32_t)major((dev_t)identity.device) != mount->major_device ||
      (uint32_t)minor((dev_t)identity.device) != mount->minor_device) {
    return EPERM;
  }
  *identity_out = identity;
  return 0;
}

static int aqt_validate_socket_identity(const AqtStat9 *identity) {
  return identity != NULL && identity->file_type == S_IFSOCK &&
                 identity->uid == 10001U && identity->gid == 10001U &&
                 identity->mode == 0600U && identity->link_count == 1U
             ? 0
             : EPERM;
}

static int aqt_capture_named_socket(int directory_fd, AqtStat9 *identity_out) {
  int result = aqt_fstatat9(directory_fd,
                            AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_BASENAME,
                            identity_out);

  return result == 0 ? aqt_validate_socket_identity(identity_out) : result;
}

static int aqt_host_peer_values_valid(uint32_t uid, uint32_t gid, int64_t pid) {
  return uid == 10001U && gid == 10001U && pid > 0 ? 0 : EPERM;
}

static int aqt_supervisor_peer_values_valid(uint32_t uid, uint32_t gid,
                                            int64_t pid) {
  return uid == 0U && gid == 0U && pid == 0 ? 0 : EPERM;
}

static int aqt_capture_peer_credential(int socket_fd,
                                       AqtPeerCredential *credential_out) {
  struct ucred first;
  struct ucred second;
  socklen_t first_length = (socklen_t)sizeof(first);
  socklen_t second_length = (socklen_t)sizeof(second);

  memset(&first, 0, sizeof(first));
  memset(&second, 0, sizeof(second));
  if (getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &first, &first_length) !=
          0 ||
      getsockopt(socket_fd, SOL_SOCKET, SO_PEERCRED, &second, &second_length) !=
          0) {
    return aqt_errno_or_io();
  }
  if (first_length != sizeof(first) || second_length != sizeof(second) ||
      first.pid != second.pid || first.uid != second.uid ||
      first.gid != second.gid) {
    return ESTALE;
  }
  credential_out->uid = (uint32_t)first.uid;
  credential_out->gid = (uint32_t)first.gid;
  credential_out->pid = (int64_t)first.pid;
  return 0;
}

static int aqt_capture_borrowed_socket_identity(int socket_fd,
                                                AqtStat9 *identity_out,
                                                uint64_t *cookie_out) {
#if !defined(SO_COOKIE)
  (void)socket_fd;
  (void)identity_out;
  (void)cookie_out;
  return ENOTSUP;
#else
  AqtStat9 first;
  AqtStat9 second;
  uint64_t first_cookie = 0U;
  uint64_t second_cookie = 0U;
  socklen_t first_length = (socklen_t)sizeof(first_cookie);
  socklen_t second_length = (socklen_t)sizeof(second_cookie);
  int result;

  if (identity_out == NULL || cookie_out == NULL || socket_fd < 0) {
    return EINVAL;
  }
  result = aqt_fstat9(socket_fd, &first);
  if (result != 0 || getsockopt(socket_fd, SOL_SOCKET, SO_COOKIE, &first_cookie,
                                &first_length) != 0) {
    return result == 0 ? aqt_errno_or_io() : result;
  }
  result = aqt_fstat9(socket_fd, &second);
  if (result != 0 || getsockopt(socket_fd, SOL_SOCKET, SO_COOKIE,
                                &second_cookie, &second_length) != 0) {
    return result == 0 ? aqt_errno_or_io() : result;
  }
  if (first_length != sizeof(first_cookie) ||
      second_length != sizeof(second_cookie) || first.file_type != S_IFSOCK ||
      !aqt_stat9_equal(&first, &second) || first_cookie == 0U ||
      first_cookie != second_cookie) {
    return ESTALE;
  }
  *identity_out = first;
  *cookie_out = first_cookie;
  return 0;
#endif
}

static int aqt_parse_proc_start_ticks(const unsigned char *bytes, size_t length,
                                      uint64_t *ticks_out) {
  const unsigned char *right_parenthesis = NULL;
  const unsigned char *cursor;
  unsigned int field = 3U;

  if (bytes == NULL || ticks_out == NULL || length == 0U ||
      memchr(bytes, '\0', length) != NULL) {
    return EINVAL;
  }
  for (size_t index = length; index > 0U; --index) {
    if (bytes[index - 1U] == (unsigned char)')') {
      right_parenthesis = bytes + index - 1U;
      break;
    }
  }
  if (right_parenthesis == NULL || right_parenthesis + 2 >= bytes + length ||
      right_parenthesis[1] != (unsigned char)' ') {
    return EINVAL;
  }
  cursor = right_parenthesis + 2;
  while (field <= 22U) {
    const unsigned char *start;
    char token[64];
    size_t token_length;

    while (cursor < bytes + length && *cursor == (unsigned char)' ') {
      cursor++;
    }
    start = cursor;
    while (cursor < bytes + length && *cursor != (unsigned char)' ' &&
           *cursor != (unsigned char)'\n') {
      cursor++;
    }
    token_length = (size_t)(cursor - start);
    if (token_length == 0U || token_length >= sizeof(token)) {
      return EINVAL;
    }
    if (field == 22U) {
      memcpy(token, start, token_length);
      token[token_length] = '\0';
      return aqt_parse_u64(token, INT64_MAX, ticks_out);
    }
    field++;
  }
  return EINVAL;
}

static int aqt_parse_terminal_nspid(const unsigned char *bytes, size_t length,
                                    uint64_t *pid_out) {
  size_t offset = 0U;
  int found = 0;
  uint64_t selected = 0U;

  while (offset < length) {
    size_t end = offset;

    while (end < length && bytes[end] != (unsigned char)'\n') {
      end++;
    }
    if (end - offset >= 6U && memcmp(bytes + offset, "NSpid:", 6U) == 0) {
      size_t cursor = offset + 6U;
      int has_value = 0;

      if (++found != 1) {
        return EINVAL;
      }
      while (cursor < end) {
        size_t start;
        char token[32];
        size_t token_length;

        while (cursor < end && (bytes[cursor] == (unsigned char)' ' ||
                                bytes[cursor] == (unsigned char)'\t')) {
          cursor++;
        }
        if (cursor == end) {
          break;
        }
        start = cursor;
        while (cursor < end && bytes[cursor] != (unsigned char)' ' &&
               bytes[cursor] != (unsigned char)'\t') {
          cursor++;
        }
        token_length = cursor - start;
        if (token_length == 0U || token_length >= sizeof(token)) {
          return EINVAL;
        }
        memcpy(token, bytes + start, token_length);
        token[token_length] = '\0';
        if (aqt_parse_u64(token, INT64_MAX, &selected) != 0 || selected == 0U) {
          return EINVAL;
        }
        has_value = 1;
      }
      if (!has_value) {
        return EINVAL;
      }
    }
    offset = end == length ? end : end + 1U;
  }
  if (found != 1) {
    return EINVAL;
  }
  *pid_out = selected;
  return 0;
}

static int aqt_extract_unique_container_id(const unsigned char *bytes,
                                           size_t length, char output[65]) {
  int found = 0;
  char selected[65];

  memset(selected, 0, sizeof(selected));
  for (size_t offset = 0U; offset + 64U <= length; ++offset) {
    int valid = 1;

    for (size_t index = 0U; index < 64U; ++index) {
      unsigned char value = bytes[offset + index];

      if (!((value >= (unsigned char)'0' && value <= (unsigned char)'9') ||
            (value >= (unsigned char)'a' && value <= (unsigned char)'f'))) {
        valid = 0;
        break;
      }
    }
    if (!valid ||
        (offset > 0U && bytes[offset - 1U] >= (unsigned char)'0' &&
         bytes[offset - 1U] <= (unsigned char)'f') ||
        (offset + 64U < length && bytes[offset + 64U] >= (unsigned char)'0' &&
         bytes[offset + 64U] <= (unsigned char)'f')) {
      continue;
    }
    if (!found) {
      memcpy(selected, bytes + offset, 64U);
      selected[64] = '\0';
      found = 1;
    } else if (memcmp(selected, bytes + offset, 64U) != 0) {
      return EINVAL;
    }
    offset += 63U;
  }
  if (!found) {
    return EPERM;
  }
  memcpy(output, selected, sizeof(selected));
  return 0;
}

static int aqt_proc_regular_file_is_valid(const AqtStat9 *identity,
                                          uint32_t expected_uid,
                                          uint32_t expected_gid) {
  return identity != NULL && identity->file_type == S_IFREG &&
                 identity->uid == expected_uid &&
                 identity->gid == expected_gid && identity->mode == 0444U &&
                 identity->link_count == 1U && identity->size == 0
             ? 0
             : EPERM;
}

static int aqt_read_proc_file_once(int process_directory_fd, const char *name,
                                   uint32_t expected_uid, uint32_t expected_gid,
                                   unsigned char *buffer, size_t *length_out,
                                   size_t capacity, AqtStat9 *identity_out) {
  AqtGuardedFd descriptor;
  AqtStat9 named_before;
  AqtStat9 held_before;
  AqtStat9 held_after;
  AqtStat9 named_after;
  struct statfs filesystem;
  int result;

  if (process_directory_fd < 0 || name == NULL || *name == '\0' ||
      strchr(name, '/') != NULL || buffer == NULL || length_out == NULL ||
      capacity == 0U || identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(&descriptor);
  result = aqt_fstatat9(process_directory_fd, name, &named_before);
  if (result == 0) {
    result = aqt_proc_regular_file_is_valid(&named_before, expected_uid,
                                            expected_gid);
  }
  if (result == 0) {
    result = aqt_guarded_fd_adopt(
        openat(process_directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW),
        &descriptor);
  }
  if (result == 0) {
    result = aqt_fstat9(descriptor.descriptor, &held_before);
  }
  if (result == 0) {
    result = aqt_fstatat9(process_directory_fd, name, &named_after);
  }
  if (result == 0 && (!aqt_stat9_equal(&named_before, &held_before) ||
                      !aqt_stat9_equal(&held_before, &named_after))) {
    result = ESTALE;
  }
  if (result == 0 && fstatfs(descriptor.descriptor, &filesystem) != 0) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && filesystem.f_type != PROC_SUPER_MAGIC) {
    result = EPERM;
  }
  if (result == 0) {
    result = aqt_read_bounded_descriptor(descriptor.descriptor, buffer,
                                         capacity, length_out);
  }
  if (result == 0) {
    result = aqt_fstat9(descriptor.descriptor, &held_after);
  }
  if (result == 0) {
    result = aqt_fstatat9(process_directory_fd, name, &named_after);
  }
  if (result == 0 && (!aqt_stat9_equal(&held_before, &held_after) ||
                      !aqt_stat9_equal(&held_after, &named_after))) {
    result = ESTALE;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&descriptor);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result == 0) {
    *identity_out = held_after;
  }
  return result;
}

static int aqt_read_proc_file_twice(int process_directory_fd, const char *name,
                                    uint32_t expected_uid,
                                    uint32_t expected_gid, unsigned char *first,
                                    size_t *first_length, unsigned char *second,
                                    size_t *second_length, size_t capacity) {
  AqtStat9 first_identity;
  AqtStat9 second_identity;
  int result = aqt_read_proc_file_once(process_directory_fd, name, expected_uid,
                                       expected_gid, first, first_length,
                                       capacity, &first_identity);

  if (result == 0) {
    result = aqt_read_proc_file_once(process_directory_fd, name, expected_uid,
                                     expected_gid, second, second_length,
                                     capacity, &second_identity);
  }
  return result == 0 && !aqt_stat9_equal(&first_identity, &second_identity)
             ? ESTALE
             : result;
}

static int aqt_proc_symlink_is_valid(const AqtStat9 *identity,
                                     uint32_t expected_uid,
                                     uint32_t expected_gid) {
  return identity != NULL && identity->file_type == S_IFLNK &&
                 identity->uid == expected_uid &&
                 identity->gid == expected_gid && identity->mode == 0777U &&
                 identity->link_count == 1U && identity->size == 0
             ? 0
             : EPERM;
}

static int aqt_capture_pid_namespace_identity(
    int process_directory_fd, const AqtStat9 *expected_process_directory,
    uint32_t expected_uid, uint32_t expected_gid,
    AqtStat9 *namespace_directory_identity_out,
    AqtStat9 *namespace_link_identity_out, uint64_t *namespace_device_out,
    uint64_t *namespace_inode_out, char namespace_path_out[64]) {
  AqtGuardedFd namespace_directory;
  AqtGuardedFd namespace_fd;
  AqtStat9 process_before;
  AqtStat9 process_after;
  AqtStat9 namespace_directory_identity;
  AqtStat9 namespace_directory_after;
  AqtStat9 namespace_directory_named_after;
  AqtStat9 namespace_link_before;
  AqtStat9 namespace_link_after;
  struct stat namespace_first;
  struct stat namespace_second;
  struct statfs filesystem;
  char namespace_path_before[64];
  char namespace_path_after[64];
  ssize_t namespace_path_length_before = -1;
  ssize_t namespace_path_length_after = -1;
  int result;

  if (process_directory_fd < 0 || expected_process_directory == NULL ||
      namespace_directory_identity_out == NULL ||
      namespace_link_identity_out == NULL || namespace_device_out == NULL ||
      namespace_inode_out == NULL || namespace_path_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(&namespace_directory);
  aqt_guarded_fd_initialize(&namespace_fd);
  result = aqt_fstat9(process_directory_fd, &process_before);
  if (result == 0 &&
      !aqt_stat9_equal(expected_process_directory, &process_before)) {
    result = ESTALE;
  }
  if (result == 0) {
    result = aqt_process_directory_is_valid(&process_before, expected_uid,
                                            expected_gid);
  }
  if (result == 0) {
    result = aqt_openat_correlated_directory(process_directory_fd, "ns", 0, 2U,
                                             &namespace_directory,
                                             &namespace_directory_identity);
  }
  if (result == 0) {
    result = aqt_proc_directory_is_valid(&namespace_directory_identity,
                                         expected_uid, expected_gid, 0511U);
  }
  if (result == 0 &&
      fstatfs(namespace_directory.descriptor, &filesystem) != 0) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && filesystem.f_type != PROC_SUPER_MAGIC) {
    result = EPERM;
  }
  if (result == 0) {
    result = aqt_fstatat9(namespace_directory.descriptor, "pid",
                          &namespace_link_before);
  }
  if (result == 0) {
    result = aqt_proc_symlink_is_valid(&namespace_link_before, expected_uid,
                                       expected_gid);
  }
  if (result == 0) {
    namespace_path_length_before =
        readlinkat(namespace_directory.descriptor, "pid", namespace_path_before,
                   sizeof(namespace_path_before));
    if (namespace_path_length_before <= 0 ||
        (size_t)namespace_path_length_before >= sizeof(namespace_path_before)) {
      result = ESTALE;
    }
  }
  if (result == 0) {
    result = aqt_guarded_fd_adopt(
        openat(namespace_directory.descriptor, "pid", O_RDONLY | O_CLOEXEC),
        &namespace_fd);
  }
  if (result == 0 && (fstat(namespace_fd.descriptor, &namespace_first) != 0 ||
                      fstat(namespace_fd.descriptor, &namespace_second) != 0)) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && fstatfs(namespace_fd.descriptor, &filesystem) != 0) {
    result = aqt_errno_or_io();
  }
  if (result == 0 && filesystem.f_type != NSFS_MAGIC) {
    result = EPERM;
  }
  if (result == 0) {
    namespace_path_length_after =
        readlinkat(namespace_directory.descriptor, "pid", namespace_path_after,
                   sizeof(namespace_path_after));
    if (namespace_path_length_after <= 0 ||
        (size_t)namespace_path_length_after >= sizeof(namespace_path_after)) {
      result = ESTALE;
    }
  }
  if (result == 0) {
    result = aqt_fstatat9(namespace_directory.descriptor, "pid",
                          &namespace_link_after);
  }
  if (result == 0) {
    result =
        aqt_fstat9(namespace_directory.descriptor, &namespace_directory_after);
  }
  if (result == 0) {
    result = aqt_fstatat9(process_directory_fd, "ns",
                          &namespace_directory_named_after);
  }
  if (result == 0) {
    result = aqt_fstat9(process_directory_fd, &process_after);
  }
  if (result == 0 &&
      (namespace_path_length_after != namespace_path_length_before ||
       memcmp(namespace_path_before, namespace_path_after,
              (size_t)namespace_path_length_before) != 0 ||
       !aqt_stat9_equal(&namespace_link_before, &namespace_link_after) ||
       !aqt_stat9_equal(&namespace_directory_identity,
                        &namespace_directory_after) ||
       !aqt_stat9_equal(&namespace_directory_identity,
                        &namespace_directory_named_after) ||
       !aqt_stat9_equal(expected_process_directory, &process_after) ||
       namespace_first.st_dev != namespace_second.st_dev ||
       namespace_first.st_ino != namespace_second.st_ino ||
       namespace_first.st_ino == 0)) {
    result = ESTALE;
  }
  if (result == 0) {
    *namespace_directory_identity_out = namespace_directory_identity;
    *namespace_link_identity_out = namespace_link_after;
    *namespace_device_out = (uint64_t)namespace_first.st_dev;
    *namespace_inode_out = (uint64_t)namespace_first.st_ino;
    memcpy(namespace_path_out, namespace_path_before,
           (size_t)namespace_path_length_before);
    namespace_path_out[(size_t)namespace_path_length_before] = '\0';
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&namespace_fd);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&namespace_directory);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  return result;
}

static int aqt_executable_path_pair_is_valid(const char *first,
                                             ssize_t first_length,
                                             const char *second,
                                             ssize_t second_length) {
  return first != NULL && second != NULL && first_length > 0 &&
                 first_length <= 255 && second_length == first_length &&
                 first[0] == '/' &&
                 memcmp(first, second, (size_t)first_length) == 0
             ? 0
             : ESTALE;
}

static int aqt_executable_identity_is_valid(const AqtStat9 *identity) {
  return identity != NULL && identity->file_type == S_IFREG &&
                 identity->uid == 0U && identity->gid == 0U &&
                 (identity->mode & 0022U) == 0U && identity->link_count > 0U &&
                 identity->size >= 0 &&
                 identity->size <= AQT_EXECUTABLE_SIZE_LIMIT
             ? 0
             : EPERM;
}

static int aqt_capture_executable_identity(
    int process_directory_fd, const AqtStat9 *expected_process_directory,
    uint32_t expected_uid, uint32_t expected_gid,
    char executable_path_out[AQT_EXECUTABLE_PATH_LIMIT],
    AqtStat9 *executable_identity_out) {
  AqtGuardedFd executable;
  AqtStat9 process_before;
  AqtStat9 process_after;
  AqtStat9 link_before;
  AqtStat9 link_after;
  AqtStat9 executable_identity;
  AqtStat9 executable_after;
  char path_before[AQT_EXECUTABLE_PATH_LIMIT];
  char path_after[AQT_EXECUTABLE_PATH_LIMIT];
  ssize_t path_length_before;
  ssize_t path_length_after;
  int result;

  if (process_directory_fd < 0 || expected_process_directory == NULL ||
      executable_path_out == NULL || executable_identity_out == NULL) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(&executable);
  result = aqt_fstat9(process_directory_fd, &process_before);
  if (result == 0 &&
      !aqt_stat9_equal(expected_process_directory, &process_before)) {
    result = ESTALE;
  }
  if (result == 0) {
    result = aqt_fstatat9(process_directory_fd, "exe", &link_before);
  }
  if (result == 0) {
    result =
        aqt_proc_symlink_is_valid(&link_before, expected_uid, expected_gid);
  }
  if (result == 0) {
    path_length_before = readlinkat(process_directory_fd, "exe", path_before,
                                    sizeof(path_before));
    if (path_length_before <= 0 ||
        (size_t)path_length_before >= sizeof(path_before)) {
      result = ESTALE;
    }
  } else {
    path_length_before = -1;
  }
  if (result == 0) {
    result = aqt_guarded_fd_adopt(
        openat(process_directory_fd, "exe", O_RDONLY | O_CLOEXEC), &executable);
  }
  if (result == 0) {
    result = aqt_fstat9(executable.descriptor, &executable_identity);
  }
  if (result == 0) {
    result = aqt_executable_identity_is_valid(&executable_identity);
  }
  if (result == 0) {
    path_length_after =
        readlinkat(process_directory_fd, "exe", path_after, sizeof(path_after));
    if (path_length_after <= 0 ||
        (size_t)path_length_after >= sizeof(path_after)) {
      result = ESTALE;
    }
  } else {
    path_length_after = -1;
  }
  if (result == 0) {
    result = aqt_fstatat9(process_directory_fd, "exe", &link_after);
  }
  if (result == 0) {
    result = aqt_fstat9(process_directory_fd, &process_after);
  }
  if (result == 0 &&
      (!aqt_stat9_equal(&link_before, &link_after) ||
       !aqt_stat9_equal(expected_process_directory, &process_after))) {
    result = ESTALE;
  }
  if (result == 0) {
    result = aqt_executable_path_pair_is_valid(path_before, path_length_before,
                                               path_after, path_length_after);
  }
  if (result == 0) {
    result = aqt_fstat9(executable.descriptor, &executable_after);
  }
  if (result == 0 &&
      !aqt_stat9_equal(&executable_identity, &executable_after)) {
    result = ESTALE;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&executable);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (result == 0) {
    memcpy(executable_path_out, path_before, (size_t)path_length_before);
    executable_path_out[(size_t)path_length_before] = '\0';
    *executable_identity_out = executable_identity;
  }
  return result;
}

static int
aqt_capture_process_identity(int process_directory_fd,
                             const AqtProcPathIdentity *proc_path_identity,
                             uint32_t expected_uid, uint32_t expected_gid,
                             AqtHostVisibleProcessIdentity *identity_out) {
  unsigned char first[AQT_PROC_FILE_LIMIT];
  unsigned char second[AQT_PROC_FILE_LIMIT];
  size_t first_length;
  size_t second_length;
  uint64_t first_value;
  uint64_t second_value;
  AqtHostVisibleProcessIdentity captured;
  AqtStat9 process_directory_after;
  int result;

  if (process_directory_fd < 0 || proc_path_identity == NULL ||
      identity_out == NULL) {
    return EINVAL;
  }
  memset(&captured, 0, sizeof(captured));
  captured.proc_path_identity = *proc_path_identity;
  result = aqt_fstat9(process_directory_fd, &process_directory_after);
  if (result != 0) {
    return result;
  }
  if (!aqt_stat9_equal(&captured.proc_path_identity.process,
                       &process_directory_after)) {
    return ESTALE;
  }
  result = aqt_process_directory_is_valid(&process_directory_after,
                                          expected_uid, expected_gid);
  if (result != 0) {
    return result;
  }
  result = aqt_read_proc_file_twice(process_directory_fd, "stat", expected_uid,
                                    expected_gid, first, &first_length, second,
                                    &second_length, sizeof(first));
  if (result != 0 ||
      aqt_parse_proc_start_ticks(first, first_length, &first_value) != 0 ||
      aqt_parse_proc_start_ticks(second, second_length, &second_value) != 0 ||
      first_value == 0U || first_value != second_value) {
    return result == 0 ? ESTALE : result;
  }
  captured.start_time_ticks = first_value;

  result = aqt_read_proc_file_twice(
      process_directory_fd, "status", expected_uid, expected_gid, first,
      &first_length, second, &second_length, sizeof(first));
  if (result != 0 ||
      aqt_parse_terminal_nspid(first, first_length, &first_value) != 0 ||
      aqt_parse_terminal_nspid(second, second_length, &second_value) != 0 ||
      first_value != second_value) {
    return result == 0 ? ESTALE : result;
  }
  captured.namespace_pid = first_value;

  result = aqt_capture_pid_namespace_identity(
      process_directory_fd, &captured.proc_path_identity.process, expected_uid,
      expected_gid, &captured.namespace_directory_identity,
      &captured.namespace_link_identity, &captured.pid_namespace_device,
      &captured.pid_namespace_inode, captured.pid_namespace_path);
  if (result != 0) {
    return result;
  }

  result = aqt_capture_executable_identity(
      process_directory_fd, &captured.proc_path_identity.process, expected_uid,
      expected_gid, captured.executable_path, &captured.executable_identity);
  if (result != 0) {
    return result;
  }

  result = aqt_read_proc_file_twice(
      process_directory_fd, "cgroup", expected_uid, expected_gid, first,
      &first_length, second, &second_length, AQT_CGROUP_LIMIT);
  if (result != 0 || first_length == 0U || first_length != second_length ||
      memcmp(first, second, first_length) != 0) {
    result = result == 0 ? ESTALE : result;
    return result;
  }
  memcpy(captured.cgroup, first, first_length);
  captured.cgroup_length = first_length;
  result = aqt_extract_unique_container_id(first, first_length,
                                           captured.container_id);
  if (result == 0) {
    result = aqt_fstat9(process_directory_fd, &process_directory_after);
  }
  if (result == 0 && !aqt_stat9_equal(&captured.proc_path_identity.process,
                                      &process_directory_after)) {
    result = ESTALE;
  }
  if (result == 0) {
    *identity_out = captured;
  }
  return result;
}

static int
aqt_process_identity_equal(const AqtHostVisibleProcessIdentity *left,
                           const AqtHostVisibleProcessIdentity *right) {
  return aqt_proc_path_identity_equal(&left->proc_path_identity,
                                      &right->proc_path_identity) &&
         left->start_time_ticks == right->start_time_ticks &&
         aqt_stat9_equal(&left->namespace_directory_identity,
                         &right->namespace_directory_identity) &&
         aqt_stat9_equal(&left->namespace_link_identity,
                         &right->namespace_link_identity) &&
         left->pid_namespace_device == right->pid_namespace_device &&
         left->pid_namespace_inode == right->pid_namespace_inode &&
         strcmp(left->pid_namespace_path, right->pid_namespace_path) == 0 &&
         left->namespace_pid == right->namespace_pid &&
         aqt_stat9_equal(&left->executable_identity,
                         &right->executable_identity) &&
         strcmp(left->executable_path, right->executable_path) == 0 &&
         left->cgroup_length == right->cgroup_length &&
         memcmp(left->cgroup, right->cgroup, left->cgroup_length) == 0 &&
         strcmp(left->container_id, right->container_id) == 0;
}

static int AQT_MAYBE_UNUSED aqt_open_process_directory(
    int64_t pid, uint32_t expected_uid, uint32_t expected_gid,
    AqtGuardedFd *process_out, AqtProcPathIdentity *identity_out) {
  if (pid <= 0 || pid > INT_MAX || process_out == NULL ||
      identity_out == NULL) {
    return EINVAL;
  }
  return aqt_open_numeric_proc_directory((pid_t)pid, expected_uid, expected_gid,
                                         process_out, identity_out);
}

static int AQT_MAYBE_UNUSED aqt_validate_process_path_binding(
    int64_t pid, uint32_t expected_uid, uint32_t expected_gid,
    const AqtProcPathIdentity *expected_identity) {
  AqtGuardedFd reopened;
  AqtProcPathIdentity captured;
  int result;
  int cleanup_result;

  aqt_guarded_fd_initialize(&reopened);
  result = aqt_open_process_directory(pid, expected_uid, expected_gid,
                                      &reopened, &captured);
  if (result == 0 &&
      !aqt_proc_path_identity_equal(expected_identity, &captured)) {
    result = ESTALE;
  }
  cleanup_result = aqt_guarded_fd_close(&reopened);
  return cleanup_result != 0 && result == 0 ? cleanup_result : result;
}

static int AQT_MAYBE_UNUSED aqt_transport_resources_prepare(
    AqtTransportResources *owner, uintptr_t interpreter_instance_identity,
    int require_absent_socket) {
  AqtStat9 named;
  AqtGuardedFd directory;
  int result;

  if (owner == NULL || interpreter_instance_identity == 0U) {
    return EINVAL;
  }
  aqt_guarded_fd_initialize(&directory);
  memset(owner, 0, sizeof(*owner));
  owner->interpreter_instance_identity = interpreter_instance_identity;
  owner->directory_fd = -1;
  owner->directory_slot = AQT_INVALID_SLOT;
  owner->borrowed_socket = -1;
  owner->process_directory_fd = -1;
  owner->process_directory_slot = AQT_INVALID_SLOT;
  result =
      aqt_trusted_time_v2_fork_guard_capture_identity(&owner->fork_identity);
  if (result != 0) {
    return result;
  }
  result = aqt_capture_mount_identity(owner->fork_identity.origin_pid,
                                      &owner->mount_identity);
  if (result != 0) {
    return result;
  }
  result = aqt_open_literal_transport_directory(&directory);
  if (result != 0) {
    return result;
  }
  owner->directory_fd = directory.descriptor;
  owner->directory_slot = directory.slot;
  result = aqt_validate_directory(owner->directory_fd, &owner->mount_identity,
                                  &owner->directory_identity);
  if (result != 0) {
    return result;
  }
  result =
      aqt_fstatat9(owner->directory_fd,
                   AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_BASENAME, &named);
  if (require_absent_socket) {
    return result == ENOENT ? 0 : (result == 0 ? EEXIST : result);
  }
  if (result != 0) {
    return result;
  }
  result = aqt_validate_socket_identity(&named);
  if (result == 0) {
    owner->socket_identity = named;
    owner->socket_identity_bound = 1;
  }
  return result;
}

static int
aqt_transport_resources_require(AqtTransportResources *owner,
                                uintptr_t interpreter_instance_identity) {
  int result;

  if (owner == NULL || interpreter_instance_identity == 0U) {
    return EINVAL;
  }
  result =
      aqt_trusted_time_v2_fork_guard_require_identity(&owner->fork_identity);
  if (result != 0) {
    return result;
  }
  return owner->interpreter_instance_identity == interpreter_instance_identity
             ? 0
             : EPERM;
}

static int
aqt_validate_literal_directory_binding(const AqtTransportResources *owner,
                                       const AqtMountIdentity *mount) {
  AqtGuardedFd reopened;
  AqtStat9 identity;
  int result;
  int cleanup_result;

  aqt_guarded_fd_initialize(&reopened);
  result = aqt_open_literal_transport_directory(&reopened);
  if (result == 0) {
    result = aqt_validate_directory(reopened.descriptor, mount, &identity);
  }
  if (result == 0 && !aqt_stat9_equal(&owner->directory_identity, &identity)) {
    result = ESTALE;
  }
  cleanup_result = aqt_guarded_fd_close(&reopened);
  return cleanup_result != 0 && result == 0 ? cleanup_result : result;
}

static int
aqt_transport_resources_revalidate(AqtTransportResources *owner,
                                   uintptr_t interpreter_instance_identity,
                                   int host_role) {
  AqtMountIdentity mount;
  AqtStat9 directory;
  AqtStat9 socket_identity;
  AqtStat9 borrowed_socket_identity;
  uint64_t borrowed_socket_cookie;
  AqtPeerCredential peer;
  int result;

  result =
      aqt_transport_resources_require(owner, interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  result = aqt_capture_mount_identity(owner->fork_identity.origin_pid, &mount);
  if (result != 0 ||
      !aqt_mount_identity_equal(&owner->mount_identity, &mount)) {
    return result == 0 ? ESTALE : result;
  }
  result = aqt_validate_directory(owner->directory_fd, &mount, &directory);
  if (result != 0 || !aqt_stat9_equal(&owner->directory_identity, &directory)) {
    return result == 0 ? ESTALE : result;
  }
  result = aqt_validate_literal_directory_binding(owner, &mount);
  if (result != 0) {
    return result;
  }
  if (owner->socket_identity_bound) {
    result = aqt_capture_named_socket(owner->directory_fd, &socket_identity);
    if (result != 0 ||
        !aqt_stat9_equal(&owner->socket_identity, &socket_identity)) {
      return result == 0 ? ESTALE : result;
    }
  }
  if (owner->borrowed_socket_bound) {
    result = aqt_capture_borrowed_socket_identity(owner->borrowed_socket,
                                                  &borrowed_socket_identity,
                                                  &borrowed_socket_cookie);
    if (result != 0 ||
        !aqt_stat9_equal(&owner->borrowed_socket_identity,
                         &borrowed_socket_identity) ||
        owner->borrowed_socket_cookie != borrowed_socket_cookie) {
      return result == 0 ? ESTALE : result;
    }
  }
  if (owner->peer_bound) {
    result = aqt_capture_peer_credential(owner->borrowed_socket, &peer);
    if (result != 0 || peer.uid != owner->peer_credential.uid ||
        peer.gid != owner->peer_credential.gid ||
        peer.pid != owner->peer_credential.pid) {
      return result == 0 ? ESTALE : result;
    }
    result =
        host_role
            ? aqt_host_peer_values_valid(peer.uid, peer.gid, peer.pid)
            : aqt_supervisor_peer_values_valid(peer.uid, peer.gid, peer.pid);
    if (result != 0) {
      return result;
    }
  }
  if (owner->process_identity_bound) {
    AqtHostVisibleProcessIdentity process;

    result = aqt_validate_process_path_binding(
        owner->peer_credential.pid, owner->peer_credential.uid,
        owner->peer_credential.gid,
        &owner->process_identity.proc_path_identity);
    if (result == 0) {
      result = aqt_capture_process_identity(
          owner->process_directory_fd,
          &owner->process_identity.proc_path_identity,
          owner->peer_credential.uid, owner->peer_credential.gid, &process);
    }
    if (result != 0 ||
        !aqt_process_identity_equal(&owner->process_identity, &process)) {
      return result == 0 ? ESTALE : result;
    }
  }
  return 0;
}

static int AQT_MAYBE_UNUSED aqt_transport_resources_close(
    AqtTransportResources *owner, uintptr_t interpreter_instance_identity,
    int host_role) {
  int result;
  int cleanup_result;

  if (owner == NULL) {
    return 0;
  }
  result =
      aqt_transport_resources_require(owner, interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  result = aqt_transport_resources_revalidate(
      owner, interpreter_instance_identity, host_role);
  if (!host_role && owner->unlink_socket_on_close &&
      owner->socket_identity_bound) {
    AqtStat9 named;

    cleanup_result = aqt_capture_named_socket(owner->directory_fd, &named);
    if (cleanup_result == 0 &&
        aqt_stat9_equal(&named, &owner->socket_identity)) {
      struct stat unexpected;

      if (unlinkat(owner->directory_fd,
                   AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_BASENAME, 0) != 0) {
        cleanup_result = aqt_errno_or_io();
      } else if (fstatat(owner->directory_fd,
                         AQT_TRUSTED_TIME_GRACEFUL_STOP_V2_SOCKET_BASENAME,
                         &unexpected, AT_SYMLINK_NOFOLLOW) == 0 ||
                 errno != ENOENT) {
        cleanup_result = ESTALE;
      } else {
        cleanup_result = 0;
      }
    } else if (cleanup_result == 0) {
      cleanup_result = ESTALE;
    }
    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  if (owner->process_directory_fd >= 0) {
    cleanup_result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->process_directory_slot, owner->process_directory_fd);
    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
    owner->process_directory_fd = -1;
    owner->process_directory_slot = AQT_INVALID_SLOT;
  }
  if (owner->directory_fd >= 0) {
    cleanup_result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->directory_slot, owner->directory_fd);
    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
    owner->directory_fd = -1;
    owner->directory_slot = AQT_INVALID_SLOT;
  }
  memset(owner, 0, sizeof(*owner));
  owner->directory_fd = -1;
  owner->process_directory_fd = -1;
  owner->borrowed_socket = -1;
  return result;
}
#endif /* __linux__ */

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
int aqt_trusted_time_v2_host_transport_resources_prepare(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_v2_host_transport_resources **owner_out) {
#if !defined(__linux__)
  (void)interpreter_instance_identity;
  (void)owner_out;
  return ENOTSUP;
#else
  aqt_trusted_time_v2_host_transport_resources *owner;
  int result;

  if (interpreter_instance_identity == 0U || owner_out == NULL ||
      *owner_out != NULL) {
    return EINVAL;
  }
  if (geteuid() != 0U || getegid() != 0U) {
    return EPERM;
  }
  owner = calloc(1U, sizeof(*owner));
  if (owner == NULL) {
    return ENOMEM;
  }
  result = aqt_transport_resources_prepare(&owner->base,
                                           interpreter_instance_identity, 0);
  if (result != 0) {
    (void)aqt_transport_resources_close(&owner->base,
                                        interpreter_instance_identity, 1);
    free(owner);
    return result;
  }
  *owner_out = owner;
  return 0;
#endif
}

int aqt_trusted_time_v2_host_transport_resources_bind_connected_peer(
    aqt_trusted_time_v2_host_transport_resources *owner,
    uintptr_t interpreter_instance_identity, int connected_socket) {
#if !defined(__linux__)
  (void)owner;
  (void)interpreter_instance_identity;
  (void)connected_socket;
  return ENOTSUP;
#else
  AqtPeerCredential credential;
  AqtGuardedFd process_directory;
  AqtProcPathIdentity process_path;
  int result;

  if (owner == NULL || connected_socket < 0) {
    return EINVAL;
  }
  result = aqt_transport_resources_require(&owner->base,
                                           interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  if (owner->base.peer_bound) {
    return EINVAL;
  }
  result = aqt_capture_peer_credential(connected_socket, &credential);
  if (result != 0) {
    return result;
  }
  result = aqt_host_peer_values_valid(credential.uid, credential.gid,
                                      credential.pid);
  if (result != 0) {
    return result;
  }
  aqt_guarded_fd_initialize(&process_directory);
  result =
      aqt_open_process_directory(credential.pid, credential.uid, credential.gid,
                                 &process_directory, &process_path);
  if (result != 0) {
    return result;
  }
  owner->base.process_directory_fd = process_directory.descriptor;
  owner->base.process_directory_slot = process_directory.slot;
  result = aqt_capture_process_identity(
      owner->base.process_directory_fd, &process_path, credential.uid,
      credential.gid, &owner->base.process_identity);
  if (result != 0) {
    return result;
  }
  owner->base.process_identity_bound = 1;
  result = aqt_capture_borrowed_socket_identity(
      connected_socket, &owner->base.borrowed_socket_identity,
      &owner->base.borrowed_socket_cookie);
  if (result != 0) {
    return result;
  }
  owner->base.borrowed_socket = connected_socket;
  owner->base.borrowed_socket_bound = 1;
  owner->base.peer_credential = credential;
  owner->base.peer_bound = 1;
  return aqt_transport_resources_revalidate(&owner->base,
                                            interpreter_instance_identity, 1);
#endif
}

int aqt_trusted_time_v2_host_transport_resources_revalidate(
    aqt_trusted_time_v2_host_transport_resources *owner,
    uintptr_t interpreter_instance_identity) {
#if !defined(__linux__)
  (void)owner;
  (void)interpreter_instance_identity;
  return ENOTSUP;
#else
  return owner == NULL ? EINVAL
                       : aqt_transport_resources_revalidate(
                             &owner->base, interpreter_instance_identity, 1);
#endif
}

int aqt_trusted_time_v2_host_transport_resources_close(
    aqt_trusted_time_v2_host_transport_resources **owner_io,
    uintptr_t interpreter_instance_identity) {
#if !defined(__linux__)
  (void)owner_io;
  (void)interpreter_instance_identity;
  return ENOTSUP;
#else
  aqt_trusted_time_v2_host_transport_resources *owner;
  int result;

  if (owner_io == NULL || *owner_io == NULL) {
    return 0;
  }
  owner = *owner_io;
  result = aqt_transport_resources_require(&owner->base,
                                           interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  result = aqt_transport_resources_close(&owner->base,
                                         interpreter_instance_identity, 1);
  free(owner);
  *owner_io = NULL;
  return result;
#endif
}
#endif

#if defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
int aqt_trusted_time_v2_supervisor_transport_resources_prepare(
    uintptr_t interpreter_instance_identity,
    aqt_trusted_time_v2_supervisor_transport_resources **owner_out) {
#if !defined(__linux__)
  (void)interpreter_instance_identity;
  (void)owner_out;
  return ENOTSUP;
#else
  aqt_trusted_time_v2_supervisor_transport_resources *owner;
  int result;

  if (interpreter_instance_identity == 0U || owner_out == NULL ||
      *owner_out != NULL) {
    return EINVAL;
  }
  if (geteuid() != 10001U || getegid() != 10001U) {
    return EPERM;
  }
  owner = calloc(1U, sizeof(*owner));
  if (owner == NULL) {
    return ENOMEM;
  }
  result = aqt_transport_resources_prepare(&owner->base,
                                           interpreter_instance_identity, 1);
  if (result != 0) {
    (void)aqt_transport_resources_close(&owner->base,
                                        interpreter_instance_identity, 0);
    free(owner);
    return result;
  }
  *owner_out = owner;
  return 0;
#endif
}

int aqt_trusted_time_v2_supervisor_transport_resources_bind_listener(
    aqt_trusted_time_v2_supervisor_transport_resources *owner,
    uintptr_t interpreter_instance_identity, int listener_socket) {
#if !defined(__linux__)
  (void)owner;
  (void)interpreter_instance_identity;
  (void)listener_socket;
  return ENOTSUP;
#else
  AqtStat9 directory_before;
  AqtStat9 directory_after;
  int result;

  if (owner == NULL || listener_socket < 0) {
    return EINVAL;
  }
  result = aqt_transport_resources_require(&owner->base,
                                           interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  if (owner->base.socket_identity_bound) {
    return EINVAL;
  }
  result = aqt_validate_directory(
      owner->base.directory_fd, &owner->base.mount_identity, &directory_before);
  if (result != 0 || !aqt_directory_binding_equal(
                         &owner->base.directory_identity, &directory_before)) {
    return result == 0 ? ESTALE : result;
  }
  result = aqt_capture_named_socket(owner->base.directory_fd,
                                    &owner->base.socket_identity);
  if (result != 0) {
    return result;
  }
  owner->base.socket_identity_bound = 1;
  owner->base.unlink_socket_on_close = 1;
  result = aqt_capture_borrowed_socket_identity(
      listener_socket, &owner->base.borrowed_socket_identity,
      &owner->base.borrowed_socket_cookie);
  if (result != 0) {
    return result;
  }
  owner->base.borrowed_socket = listener_socket;
  owner->base.borrowed_socket_bound = 1;
  result = aqt_validate_directory(
      owner->base.directory_fd, &owner->base.mount_identity, &directory_after);
  if (result != 0 || !aqt_stat9_equal(&directory_before, &directory_after)) {
    return result == 0 ? ESTALE : result;
  }
  owner->base.directory_identity = directory_after;
  return aqt_transport_resources_revalidate(&owner->base,
                                            interpreter_instance_identity, 0);
#endif
}

int aqt_trusted_time_v2_supervisor_transport_resources_bind_accepted_peer(
    aqt_trusted_time_v2_supervisor_transport_resources *owner,
    uintptr_t interpreter_instance_identity, int accepted_socket) {
#if !defined(__linux__)
  (void)owner;
  (void)interpreter_instance_identity;
  (void)accepted_socket;
  return ENOTSUP;
#else
  AqtPeerCredential credential;
  int result;

  if (owner == NULL || accepted_socket < 0) {
    return EINVAL;
  }
  result = aqt_transport_resources_require(&owner->base,
                                           interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  if (owner->base.peer_bound || !owner->base.socket_identity_bound) {
    return EINVAL;
  }
  result = aqt_capture_peer_credential(accepted_socket, &credential);
  if (result != 0) {
    return result;
  }
  result = aqt_supervisor_peer_values_valid(credential.uid, credential.gid,
                                            credential.pid);
  if (result != 0) {
    return result;
  }
  result = aqt_capture_borrowed_socket_identity(
      accepted_socket, &owner->base.borrowed_socket_identity,
      &owner->base.borrowed_socket_cookie);
  if (result != 0) {
    return result;
  }
  owner->base.borrowed_socket = accepted_socket;
  owner->base.borrowed_socket_bound = 1;
  owner->base.peer_credential = credential;
  owner->base.peer_bound = 1;
  return aqt_transport_resources_revalidate(&owner->base,
                                            interpreter_instance_identity, 0);
#endif
}

int aqt_trusted_time_v2_supervisor_transport_resources_revalidate(
    aqt_trusted_time_v2_supervisor_transport_resources *owner,
    uintptr_t interpreter_instance_identity) {
#if !defined(__linux__)
  (void)owner;
  (void)interpreter_instance_identity;
  return ENOTSUP;
#else
  return owner == NULL ? EINVAL
                       : aqt_transport_resources_revalidate(
                             &owner->base, interpreter_instance_identity, 0);
#endif
}

int aqt_trusted_time_v2_supervisor_transport_resources_close(
    aqt_trusted_time_v2_supervisor_transport_resources **owner_io,
    uintptr_t interpreter_instance_identity) {
#if !defined(__linux__)
  (void)owner_io;
  (void)interpreter_instance_identity;
  return ENOTSUP;
#else
  aqt_trusted_time_v2_supervisor_transport_resources *owner;
  int result;

  if (owner_io == NULL || *owner_io == NULL) {
    return 0;
  }
  owner = *owner_io;
  result = aqt_transport_resources_require(&owner->base,
                                           interpreter_instance_identity);
  if (result != 0) {
    return result;
  }
  result = aqt_transport_resources_close(&owner->base,
                                         interpreter_instance_identity, 0);
  free(owner);
  *owner_io = NULL;
  return result;
#endif
}
#endif

#ifdef AQT_TRUSTED_TIME_V2_ENDPOINT_TESTING
int aqt_trusted_time_v2_resources_test_parse_transport_mountinfo(
    const unsigned char *mountinfo, size_t mountinfo_length,
    aqt_trusted_time_v2_test_mount_identity *identity_out) {
  AqtMountIdentity parsed;
  int result;

  if (identity_out == NULL) {
    return EINVAL;
  }
  result = aqt_parse_transport_mountinfo(mountinfo, mountinfo_length, &parsed);
  if (result != 0) {
    return result;
  }
  memset(identity_out, 0, sizeof(*identity_out));
  identity_out->mount_id = parsed.mount_id;
  identity_out->parent_mount_id = parsed.parent_mount_id;
  identity_out->major_device = parsed.major_device;
  identity_out->minor_device = parsed.minor_device;
  memcpy(identity_out->mount_root, parsed.root, strlen(parsed.root) + 1U);
  {
    size_t mount_length = strlen(parsed.mount_options);
    size_t super_length = strlen(parsed.super_options);

    if (mount_length + 1U + super_length >=
        sizeof(identity_out->mount_options)) {
      return EOVERFLOW;
    }
    memcpy(identity_out->mount_options, parsed.mount_options, mount_length);
    identity_out->mount_options[mount_length] = ';';
    memcpy(identity_out->mount_options + mount_length + 1U,
           parsed.super_options, super_length + 1U);
  }
  return 0;
}

int aqt_trusted_time_v2_resources_test_host_peer_values(uint32_t uid,
                                                        uint32_t gid,
                                                        int64_t pid) {
#if defined(__linux__)
  return aqt_host_peer_values_valid(uid, gid, pid);
#else
  return uid == 10001U && gid == 10001U && pid > 0 ? 0 : EPERM;
#endif
}

int aqt_trusted_time_v2_resources_test_supervisor_peer_values(uint32_t uid,
                                                              uint32_t gid,
                                                              int64_t pid) {
#if defined(__linux__)
  return aqt_supervisor_peer_values_valid(uid, gid, pid);
#else
  return uid == 0U && gid == 0U && pid == 0 ? 0 : EPERM;
#endif
}

int aqt_trusted_time_v2_resources_test_transport_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count) {
  return uid == 0U && gid == 10001U && mode == 0770U && link_count >= 2U
             ? 0
             : EPERM;
}

int aqt_trusted_time_v2_resources_test_socket_metadata(uint32_t uid,
                                                       uint32_t gid,
                                                       uint32_t mode,
                                                       uint64_t link_count) {
  return uid == 10001U && gid == 10001U && mode == 0600U && link_count == 1U
             ? 0
             : EPERM;
}

int aqt_trusted_time_v2_resources_test_stat9_equal(
    const aqt_trusted_time_v2_test_stat9 *left,
    const aqt_trusted_time_v2_test_stat9 *right) {
  if (left == NULL || right == NULL) {
    return 0;
  }
  return left->device == right->device && left->inode == right->inode &&
         left->mode == right->mode && left->uid == right->uid &&
         left->gid == right->gid && left->link_count == right->link_count &&
         left->size == right->size &&
         left->modification_seconds == right->modification_seconds &&
         left->modification_nanoseconds == right->modification_nanoseconds &&
         left->change_seconds == right->change_seconds &&
         left->change_nanoseconds == right->change_nanoseconds;
}

int aqt_trusted_time_v2_resources_test_overlay_link_count(uint64_t link_count) {
  return link_count >= 1U ? 0 : EPERM;
}

int aqt_trusted_time_v2_resources_test_strict_directory_link_count(
    uint64_t link_count) {
  return link_count >= 2U ? 0 : EPERM;
}

int aqt_trusted_time_v2_resources_test_transport_component_link_count(
    size_t component_index, uint64_t link_count) {
  if (component_index >= 5U) {
    return EINVAL;
  }
  return link_count >= (component_index == 0U ? 1U : 2U) ? 0 : EPERM;
}

static int aqt_test_proc_directory_metadata(uint32_t uid, uint32_t gid,
                                            uint32_t mode, uint64_t link_count,
                                            uint32_t expected_uid,
                                            uint32_t expected_gid,
                                            uint32_t expected_mode) {
#if defined(__linux__)
  AqtStat9 identity;

  memset(&identity, 0, sizeof(identity));
  identity.file_type = S_IFDIR;
  identity.uid = uid;
  identity.gid = gid;
  identity.mode = mode;
  identity.link_count = link_count;
  return aqt_proc_directory_is_valid(&identity, expected_uid, expected_gid,
                                     expected_mode);
#else
  return uid == expected_uid && gid == expected_gid && mode == expected_mode &&
                 link_count >= 2U
             ? 0
             : EPERM;
#endif
}

int aqt_trusted_time_v2_resources_test_proc_root_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count) {
  return aqt_test_proc_directory_metadata(uid, gid, mode, link_count, 0U, 0U,
                                          0555U);
}

int aqt_trusted_time_v2_resources_test_peer_process_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count) {
  return aqt_test_proc_directory_metadata(uid, gid, mode, link_count, 10001U,
                                          10001U, 0555U);
}

int aqt_trusted_time_v2_resources_test_peer_namespace_directory_metadata(
    uint32_t uid, uint32_t gid, uint32_t mode, uint64_t link_count) {
  return aqt_test_proc_directory_metadata(uid, gid, mode, link_count, 10001U,
                                          10001U, 0511U);
}

int aqt_trusted_time_v2_resources_test_executable_metadata(uint32_t uid,
                                                           uint32_t gid,
                                                           uint32_t mode,
                                                           uint64_t link_count,
                                                           int64_t size) {
#if defined(__linux__)
  AqtStat9 identity;

  memset(&identity, 0, sizeof(identity));
  identity.file_type = S_IFREG;
  identity.uid = uid;
  identity.gid = gid;
  identity.mode = mode;
  identity.link_count = link_count;
  identity.size = size;
  return aqt_executable_identity_is_valid(&identity);
#else
  return uid == 0U && gid == 0U && (mode & 0022U) == 0U && link_count > 0U &&
                 size >= 0 && size <= INT64_C(268435456)
             ? 0
             : EPERM;
#endif
}

int aqt_trusted_time_v2_resources_test_executable_path_pair(
    const char *first, int64_t first_length, const char *second,
    int64_t second_length) {
#if defined(__linux__)
  if (first_length < 0 || second_length < 0 || first_length > SSIZE_MAX ||
      second_length > SSIZE_MAX) {
    return ESTALE;
  }
  return aqt_executable_path_pair_is_valid(first, (ssize_t)first_length, second,
                                           (ssize_t)second_length);
#else
  return first != NULL && second != NULL && first_length > 0 &&
                 first_length <= 255 && second_length == first_length &&
                 first[0] == '/' &&
                 memcmp(first, second, (size_t)first_length) == 0
             ? 0
             : ESTALE;
#endif
}

int aqt_trusted_time_v2_resources_test_current_process_proc_admission(void) {
#if !defined(__linux__)
  return ENOTSUP;
#else
  unsigned char first[AQT_PROC_FILE_LIMIT];
  unsigned char second[AQT_PROC_FILE_LIMIT];
  size_t first_length = 0U;
  size_t second_length = 0U;
  AqtGuardedFd process;
  AqtProcPathIdentity path;
  AqtStat9 executable_identity;
  AqtStat9 namespace_directory_identity;
  AqtStat9 namespace_link_identity;
  AqtStat9 process_after;
  char executable_path[AQT_EXECUTABLE_PATH_LIMIT];
  char namespace_path[64];
  uint64_t namespace_device = 0U;
  uint64_t namespace_inode = 0U;
  uint32_t expected_uid = (uint32_t)geteuid();
  uint32_t expected_gid = (uint32_t)getegid();
  int result;

  aqt_guarded_fd_initialize(&process);
  result = aqt_open_numeric_proc_directory(getpid(), expected_uid, expected_gid,
                                           &process, &path);
  if (result == 0) {
    result = aqt_read_proc_file_twice(process.descriptor, "stat", expected_uid,
                                      expected_gid, first, &first_length,
                                      second, &second_length, sizeof(first));
  }
  if (result == 0) {
    result = aqt_read_proc_file_twice(
        process.descriptor, "status", expected_uid, expected_gid, first,
        &first_length, second, &second_length, sizeof(first));
  }
  if (result == 0) {
    result = aqt_read_proc_file_twice(
        process.descriptor, "cgroup", expected_uid, expected_gid, first,
        &first_length, second, &second_length, AQT_CGROUP_LIMIT);
  }
  if (result == 0 && (first_length == 0U || first_length != second_length ||
                      memcmp(first, second, first_length) != 0)) {
    result = ESTALE;
  }
  if (result == 0) {
    result = aqt_capture_pid_namespace_identity(
        process.descriptor, &path.process, expected_uid, expected_gid,
        &namespace_directory_identity, &namespace_link_identity,
        &namespace_device, &namespace_inode, namespace_path);
  }
  if (result == 0 && (namespace_device == 0U || namespace_inode == 0U ||
                      namespace_path[0] == '\0')) {
    result = ESTALE;
  }
  if (result == 0) {
    result = aqt_capture_executable_identity(
        process.descriptor, &path.process, expected_uid, expected_gid,
        executable_path, &executable_identity);
  }
  if (result == 0) {
    result = aqt_fstat9(process.descriptor, &process_after);
  }
  if (result == 0 && !aqt_stat9_equal(&path.process, &process_after)) {
    result = ESTALE;
  }
  {
    int cleanup_result = aqt_guarded_fd_close(&process);

    if (cleanup_result != 0 && result == 0) {
      result = cleanup_result;
    }
  }
  return result;
#endif
}
#endif
