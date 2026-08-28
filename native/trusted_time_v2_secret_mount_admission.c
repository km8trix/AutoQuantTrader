#if defined(__linux__)
#define _GNU_SOURCE
#else
#define _DARWIN_C_SOURCE
#endif

#include "trusted_time_v2_secret_mount_admission.h"

#include "trusted_time_v2_fork_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <linux/magic.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#endif

#define AQT_SECRET_MOUNTINFO_LIMIT (1024U * 1024U)
#define AQT_SECRET_MOUNTINFO_LINE_LIMIT 4096U
#define AQT_SECRET_INVALID_SLOT UINT32_MAX
#define AQT_SECRET_ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))

#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
#define AQT_SECRET_MOUNTPOINT \
    "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets"
#define AQT_SECRET_DIRECTORY_UID UINT32_C(0)
#define AQT_SECRET_DIRECTORY_GID UINT32_C(0)
#define AQT_SECRET_DIRECTORY_MODE UINT32_C(0700)
#define AQT_SECRET_SUPER_MODE_OPTION "mode=700"
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
#define AQT_SECRET_MOUNTPOINT \
    "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets"
#define AQT_SECRET_DIRECTORY_UID UINT32_C(0)
#define AQT_SECRET_DIRECTORY_GID UINT32_C(10001)
#define AQT_SECRET_DIRECTORY_MODE UINT32_C(0730)
#define AQT_SECRET_SUPER_MODE_OPTION "mode=730"
#define AQT_SECRET_SUPER_GID_OPTION "gid=10001"
#else
#define AQT_SECRET_MOUNTPOINT \
    "/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets"
#define AQT_SECRET_DIRECTORY_UID UINT32_C(0)
#define AQT_SECRET_DIRECTORY_GID UINT32_C(0)
#define AQT_SECRET_DIRECTORY_MODE UINT32_C(0700)
#define AQT_SECRET_SUPER_MODE_OPTION "mode=700"
#endif

#if defined(__GNUC__) || defined(__clang__)
#define AQT_SECRET_USED __attribute__((used))
#define AQT_SECRET_MAYBE_UNUSED __attribute__((unused))
#else
#define AQT_SECRET_USED
#define AQT_SECRET_MAYBE_UNUSED
#endif

static const char aqt_secret_mountpoint[] AQT_SECRET_USED = AQT_SECRET_MOUNTPOINT;

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
} aqt_secret_stat9;

typedef struct {
    uint64_t mount_id;
    uint64_t parent_mount_id;
    uint32_t major_device;
    uint32_t minor_device;
    int inode64_present;
} aqt_secret_mount_identity;

typedef struct {
    int descriptor;
    uint32_t slot;
} aqt_secret_guarded_fd;

struct aqt_trusted_time_v2_secret_mount_admission {
    aqt_trusted_time_v2_fork_identity fork_identity;
    uintptr_t interpreter_identity;
    aqt_secret_stat9 directory_identity;
    aqt_secret_mount_identity mount_identity;
};

static int
aqt_secret_errno_or_io(void)
{
    return errno == 0 ? EIO : errno;
}

static void
aqt_secret_stat9_from_stat(
    const struct stat *metadata,
    aqt_secret_stat9 *identity)
{
    identity->device = (uint64_t)metadata->st_dev;
    identity->inode = (uint64_t)metadata->st_ino;
    identity->file_type = (uint32_t)(metadata->st_mode & S_IFMT);
    identity->mode = (uint32_t)(metadata->st_mode & (mode_t)07777);
    identity->uid = (uint32_t)metadata->st_uid;
    identity->gid = (uint32_t)metadata->st_gid;
    identity->link_count = (uint64_t)metadata->st_nlink;
    identity->size = (int64_t)metadata->st_size;
#if defined(__APPLE__)
    identity->modification_seconds = (int64_t)metadata->st_mtimespec.tv_sec;
    identity->modification_nanoseconds = (int64_t)metadata->st_mtimespec.tv_nsec;
    identity->change_seconds = (int64_t)metadata->st_ctimespec.tv_sec;
    identity->change_nanoseconds = (int64_t)metadata->st_ctimespec.tv_nsec;
#else
    identity->modification_seconds = (int64_t)metadata->st_mtim.tv_sec;
    identity->modification_nanoseconds = (int64_t)metadata->st_mtim.tv_nsec;
    identity->change_seconds = (int64_t)metadata->st_ctim.tv_sec;
    identity->change_nanoseconds = (int64_t)metadata->st_ctim.tv_nsec;
#endif
}

static int
aqt_secret_stat9_equal(
    const aqt_secret_stat9 *left,
    const aqt_secret_stat9 *right)
{
    return left != NULL && right != NULL
        && left->device == right->device
        && left->inode == right->inode
        && left->file_type == right->file_type
        && left->mode == right->mode
        && left->uid == right->uid
        && left->gid == right->gid
        && left->link_count == right->link_count
        && left->size == right->size
        && left->modification_seconds == right->modification_seconds
        && left->modification_nanoseconds == right->modification_nanoseconds
        && left->change_seconds == right->change_seconds
        && left->change_nanoseconds == right->change_nanoseconds;
}

static int AQT_SECRET_MAYBE_UNUSED
aqt_secret_fstat9(int descriptor, aqt_secret_stat9 *identity_out)
{
    struct stat first;
    struct stat second;
    aqt_secret_stat9 first_identity;
    aqt_secret_stat9 second_identity;

    if (descriptor < 0 || identity_out == NULL) {
        return EINVAL;
    }
    if (fstat(descriptor, &first) != 0 || fstat(descriptor, &second) != 0) {
        return aqt_secret_errno_or_io();
    }
    aqt_secret_stat9_from_stat(&first, &first_identity);
    aqt_secret_stat9_from_stat(&second, &second_identity);
    if (!aqt_secret_stat9_equal(&first_identity, &second_identity)) {
        return ESTALE;
    }
    *identity_out = first_identity;
    return 0;
}

#if defined(__linux__)
static int
aqt_secret_fstatat9(
    int directory_fd,
    const char *name,
    aqt_secret_stat9 *identity_out)
{
    struct stat first;
    struct stat second;
    aqt_secret_stat9 first_identity;
    aqt_secret_stat9 second_identity;

    if (directory_fd < 0 || name == NULL || identity_out == NULL) {
        return EINVAL;
    }
    if (fstatat(directory_fd, name, &first, AT_SYMLINK_NOFOLLOW) != 0
        || fstatat(directory_fd, name, &second, AT_SYMLINK_NOFOLLOW) != 0) {
        return aqt_secret_errno_or_io();
    }
    aqt_secret_stat9_from_stat(&first, &first_identity);
    aqt_secret_stat9_from_stat(&second, &second_identity);
    if (!aqt_secret_stat9_equal(&first_identity, &second_identity)) {
        return ESTALE;
    }
    *identity_out = first_identity;
    return 0;
}

static void
aqt_secret_guarded_fd_initialize(aqt_secret_guarded_fd *owner)
{
    owner->descriptor = -1;
    owner->slot = AQT_SECRET_INVALID_SLOT;
}

static int
aqt_secret_guarded_fd_adopt(int descriptor, aqt_secret_guarded_fd *owner)
{
    int result;

    if (owner == NULL) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return EINVAL;
    }
    aqt_secret_guarded_fd_initialize(owner);
    if (descriptor < 0) {
        return aqt_secret_errno_or_io();
    }
    result = aqt_trusted_time_v2_fork_guard_register_fd(descriptor, &owner->slot);
    if (result != 0) {
        (void)close(descriptor);
        return result;
    }
    owner->descriptor = descriptor;
    return 0;
}

static int
aqt_secret_guarded_fd_close(aqt_secret_guarded_fd *owner)
{
    int result;

    if (owner == NULL || owner->descriptor < 0) {
        return 0;
    }
    result = aqt_trusted_time_v2_fork_guard_close_fd(
        owner->slot,
        owner->descriptor
    );
    owner->descriptor = -1;
    owner->slot = AQT_SECRET_INVALID_SLOT;
    return result;
}
#endif

#if defined(__linux__) || defined(AQT_TRUSTED_TIME_V2_SECRET_MOUNT_ADMISSION_TESTING)
static int
aqt_secret_parse_u64(
    const char *text,
    uint64_t maximum,
    uint64_t *value_out)
{
    const unsigned char *cursor = (const unsigned char *)text;
    uint64_t value = 0U;

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

static int
aqt_secret_option_set_is_exact(
    const char *options,
    const char *const *required,
    size_t required_count,
    const char *optional,
    int *optional_present_out)
{
    int seen[8] = {0};
    int optional_seen = 0;
    const char *cursor = options;

    if (options == NULL || required == NULL || required_count == 0U
        || required_count > AQT_SECRET_ARRAY_LENGTH(seen)) {
        return 0;
    }
    while (cursor != NULL && *cursor != '\0') {
        const char *end = strchr(cursor, ',');
        const size_t length = end == NULL
            ? strlen(cursor)
            : (size_t)(end - cursor);
        int matched = 0;
        size_t index;

        if (length == 0U) {
            return 0;
        }
        if (end != NULL && end[1] == '\0') {
            return 0;
        }
        for (index = 0U; index < required_count; ++index) {
            if (strlen(required[index]) == length
                && memcmp(cursor, required[index], length) == 0) {
                if (seen[index] != 0) {
                    return 0;
                }
                seen[index] = 1;
                matched = 1;
                break;
            }
        }
        if (matched == 0 && optional != NULL && strlen(optional) == length
            && memcmp(cursor, optional, length) == 0) {
            if (optional_seen != 0) {
                return 0;
            }
            optional_seen = 1;
            matched = 1;
        }
        if (matched == 0) {
            return 0;
        }
        cursor = end == NULL ? NULL : end + 1;
    }
    for (size_t index = 0U; index < required_count; ++index) {
        if (seen[index] == 0) {
            return 0;
        }
    }
    if (optional_present_out != NULL) {
        *optional_present_out = optional_seen;
    }
    return 1;
}

static int
aqt_secret_parse_major_minor(
    const char *text,
    uint32_t *major_out,
    uint32_t *minor_out)
{
    char copy[64];
    char *separator;
    uint64_t parsed_major;
    uint64_t parsed_minor;
    const size_t text_length = text == NULL ? 0U : strlen(text);

    if (text == NULL || major_out == NULL || minor_out == NULL
        || text_length == 0U || text_length >= sizeof(copy)) {
        return EINVAL;
    }
    (void)memcpy(copy, text, text_length + 1U);
    separator = strchr(copy, ':');
    if (separator == NULL || strchr(separator + 1, ':') != NULL) {
        return EINVAL;
    }
    *separator = '\0';
    if (aqt_secret_parse_u64(copy, UINT32_MAX, &parsed_major) != 0
        || aqt_secret_parse_u64(
            separator + 1,
            UINT32_MAX,
            &parsed_minor) != 0) {
        return EINVAL;
    }
    *major_out = (uint32_t)parsed_major;
    *minor_out = (uint32_t)parsed_minor;
    return 0;
}

static int
aqt_secret_mount_identity_equal(
    const aqt_secret_mount_identity *left,
    const aqt_secret_mount_identity *right)
{
    return left != NULL && right != NULL
        && left->mount_id == right->mount_id
        && left->parent_mount_id == right->parent_mount_id
        && left->major_device == right->major_device
        && left->minor_device == right->minor_device
        && left->inode64_present == right->inode64_present;
}

static int
aqt_secret_parse_mountinfo(
    const unsigned char *bytes,
    size_t length,
    aqt_secret_mount_identity *identity_out)
{
    size_t offset = 0U;
    int matches = 0;
    aqt_secret_mount_identity selected;

    if (bytes == NULL || identity_out == NULL || length == 0U
        || length > AQT_SECRET_MOUNTINFO_LIMIT
        || memchr(bytes, '\0', length) != NULL) {
        return EINVAL;
    }
    (void)memset(&selected, 0, sizeof(selected));
    while (offset < length) {
        size_t end = offset;
        size_t line_length;
        char line[AQT_SECRET_MOUNTINFO_LINE_LIMIT + 1U];
        char *fields[96];
        size_t field_count = 0U;
        size_t separator_index = SIZE_MAX;
        char *save = NULL;
        char *token;

        while (end < length && bytes[end] != (unsigned char)'\n') {
            end++;
        }
        if (end == length) {
            return EINVAL;
        }
        line_length = end - offset;
        if (line_length == 0U || line_length > AQT_SECRET_MOUNTINFO_LINE_LIMIT) {
            return EINVAL;
        }
        if (bytes[offset] == (unsigned char)' '
            || bytes[end - 1U] == (unsigned char)' ') {
            return EINVAL;
        }
        for (size_t scan = offset; scan < end; ++scan) {
            if (bytes[scan] < UINT8_C(0x20) || bytes[scan] == UINT8_C(0x7f)
                || (bytes[scan] == (unsigned char)' '
                    && scan + 1U < end
                    && bytes[scan + 1U] == (unsigned char)' ')) {
                return EINVAL;
            }
        }
        (void)memcpy(line, bytes + offset, line_length);
        line[line_length] = '\0';
        token = strtok_r(line, " ", &save);
        while (token != NULL) {
            if (field_count >= AQT_SECRET_ARRAY_LENGTH(fields)) {
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
        if (strcmp(fields[4], aqt_secret_mountpoint) == 0) {
            static const char *const required_mount_options[] = {
                "rw", "nosuid", "nodev", "noexec", "relatime",
            };
#if defined(AQT_SECRET_SUPER_GID_OPTION)
            static const char *const required_super_options[] = {
                "rw", "size=64k", AQT_SECRET_SUPER_MODE_OPTION,
                AQT_SECRET_SUPER_GID_OPTION,
            };
#else
            static const char *const required_super_options[] = {
                "rw", "size=64k", AQT_SECRET_SUPER_MODE_OPTION,
            };
#endif
            aqt_secret_mount_identity candidate;
            uint64_t mount_id;
            uint64_t parent_mount_id;
            int inode64_present = 0;

            (void)memset(&candidate, 0, sizeof(candidate));
            matches++;
            if (matches != 1 || separator_index != 6U
                || field_count != separator_index + 4U
                || aqt_secret_parse_u64(
                    fields[0], INT64_MAX, &mount_id) != 0
                || aqt_secret_parse_u64(
                    fields[1], INT64_MAX, &parent_mount_id) != 0
                || aqt_secret_parse_major_minor(
                    fields[2],
                    &candidate.major_device,
                    &candidate.minor_device) != 0
                || strcmp(fields[3], "/") != 0
                || !aqt_secret_option_set_is_exact(
                    fields[5],
                    required_mount_options,
                    AQT_SECRET_ARRAY_LENGTH(required_mount_options),
                    NULL,
                    NULL)
                || strcmp(fields[separator_index + 1U], "tmpfs") != 0
                || strcmp(fields[separator_index + 2U], "tmpfs") != 0
                || !aqt_secret_option_set_is_exact(
                    fields[separator_index + 3U],
                    required_super_options,
                    AQT_SECRET_ARRAY_LENGTH(required_super_options),
                    "inode64",
                    &inode64_present)) {
                return EPERM;
            }
            candidate.mount_id = mount_id;
            candidate.parent_mount_id = parent_mount_id;
            candidate.inode64_present = inode64_present;
            selected = candidate;
        }
        offset = end + 1U;
    }
    if (matches != 1) {
        return ENOENT;
    }
    *identity_out = selected;
    return 0;
}
#endif

#if defined(__linux__)
static int
aqt_secret_validate_secure_directory(
    const aqt_secret_stat9 *identity,
    uint32_t expected_uid,
    uint32_t expected_gid,
    uint64_t minimum_link_count)
{
    return identity != NULL
        && identity->file_type == (uint32_t)S_IFDIR
        && identity->uid == expected_uid
        && identity->gid == expected_gid
        && (identity->mode & UINT32_C(0022)) == 0U
        && identity->link_count >= minimum_link_count;
}

static int
aqt_secret_validate_role_directory(const aqt_secret_stat9 *identity)
{
    return identity != NULL
        && identity->file_type == (uint32_t)S_IFDIR
        && identity->uid == AQT_SECRET_DIRECTORY_UID
        && identity->gid == AQT_SECRET_DIRECTORY_GID
        && identity->mode == AQT_SECRET_DIRECTORY_MODE
        && identity->link_count >= UINT64_C(2);
}

static int
aqt_secret_open_correlated_child(
    const aqt_secret_guarded_fd *parent,
    const char *name,
    int flags,
    aqt_secret_guarded_fd *child_out,
    aqt_secret_stat9 *identity_out)
{
    aqt_secret_stat9 path_before;
    aqt_secret_stat9 descriptor_identity;
    aqt_secret_stat9 path_after;
    int result;

    if (parent == NULL || parent->descriptor < 0 || name == NULL
        || child_out == NULL || identity_out == NULL) {
        return EINVAL;
    }
    aqt_secret_guarded_fd_initialize(child_out);
    result = aqt_secret_fstatat9(parent->descriptor, name, &path_before);
    if (result != 0) {
        return result;
    }
    result = aqt_secret_guarded_fd_adopt(
        openat(parent->descriptor, name, flags | O_CLOEXEC | O_NOFOLLOW),
        child_out
    );
    if (result != 0) {
        return result;
    }
    result = aqt_secret_fstat9(child_out->descriptor, &descriptor_identity);
    if (result == 0) {
        result = aqt_secret_fstatat9(parent->descriptor, name, &path_after);
    }
    if (result == 0
        && (!aqt_secret_stat9_equal(&path_before, &descriptor_identity)
            || !aqt_secret_stat9_equal(&descriptor_identity, &path_after))) {
        result = ESTALE;
    }
    if (result != 0) {
        (void)aqt_secret_guarded_fd_close(child_out);
        return result;
    }
    *identity_out = descriptor_identity;
    return 0;
}

static int
aqt_secret_open_literal_directory(
    aqt_secret_guarded_fd *directory_out,
    aqt_secret_stat9 *identity_out)
{
    static const char *const components[] = {
        "run", "autoquant", "trusted-time", "graceful-stop-v2",
#if defined(AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
        "host-secrets",
#elif defined(AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE) \
    || defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
        "supervisor-secrets",
#else
        "recovery-secrets",
#endif
    };
    aqt_secret_guarded_fd current;
    aqt_secret_stat9 current_identity;
    int result;

    if (directory_out == NULL || identity_out == NULL) {
        return EINVAL;
    }
    aqt_secret_guarded_fd_initialize(directory_out);
    aqt_secret_guarded_fd_initialize(&current);
    result = aqt_secret_guarded_fd_adopt(
        open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
        &current
    );
    if (result != 0) {
        return result;
    }
    result = aqt_secret_fstat9(current.descriptor, &current_identity);
    if (result != 0
        || !aqt_secret_validate_secure_directory(
            &current_identity,
            0U,
            0U,
            UINT64_C(1))) {
        result = result == 0 ? EPERM : result;
        (void)aqt_secret_guarded_fd_close(&current);
        return result;
    }
    for (size_t index = 0U; index < AQT_SECRET_ARRAY_LENGTH(components); ++index) {
        aqt_secret_guarded_fd next;
        aqt_secret_stat9 next_identity;
        int cleanup_result;

        aqt_secret_guarded_fd_initialize(&next);
        result = aqt_secret_open_correlated_child(
            &current,
            components[index],
            O_RDONLY | O_DIRECTORY,
            &next,
            &next_identity
        );
        if (result == 0) {
            if (index + 1U == AQT_SECRET_ARRAY_LENGTH(components)) {
                if (!aqt_secret_validate_role_directory(&next_identity)) {
                    result = EPERM;
                }
            } else if (!aqt_secret_validate_secure_directory(
                           &next_identity,
                           0U,
                           0U,
                           index == 0U ? UINT64_C(1) : UINT64_C(2))) {
                result = EPERM;
            }
        }
        cleanup_result = aqt_secret_guarded_fd_close(&current);
        if (cleanup_result != 0 && result == 0) {
            result = cleanup_result;
        }
        if (result != 0) {
            (void)aqt_secret_guarded_fd_close(&next);
            return result;
        }
        current = next;
    }
    *directory_out = current;
    result = aqt_secret_fstat9(directory_out->descriptor, identity_out);
    if (result != 0) {
        (void)aqt_secret_guarded_fd_close(directory_out);
    }
    return result;
}

static int
aqt_secret_read_bounded_descriptor(
    int descriptor,
    unsigned char *buffer,
    size_t capacity,
    size_t *length_out)
{
    size_t length = 0U;

    if (descriptor < 0 || buffer == NULL || capacity == 0U || length_out == NULL) {
        return EINVAL;
    }
    while (length < capacity) {
        ssize_t count = pread(
            descriptor,
            buffer + length,
            capacity - length,
            (off_t)length
        );

        if (count > 0) {
            length += (size_t)count;
            continue;
        }
        if (count == 0) {
            *length_out = length;
            return 0;
        }
        if (errno != EINTR) {
            return aqt_secret_errno_or_io();
        }
    }
    for (;;) {
        unsigned char extra = 0U;
        const ssize_t count = pread(descriptor, &extra, 1U, (off_t)length);

        if (count == 0) {
            *length_out = length;
            return 0;
        }
        if (count > 0) {
            return EFBIG;
        }
        if (errno != EINTR) {
            return aqt_secret_errno_or_io();
        }
    }
}

static int
aqt_secret_read_mountinfo_once(
    unsigned char *buffer,
    size_t capacity,
    size_t *length_out,
    aqt_secret_stat9 *identity_out)
{
    aqt_secret_guarded_fd current;
    aqt_secret_guarded_fd next;
    aqt_secret_guarded_fd mountinfo;
    aqt_secret_stat9 root_identity;
    aqt_secret_stat9 proc_identity;
    aqt_secret_stat9 process_identity;
    aqt_secret_stat9 mountinfo_before;
    aqt_secret_stat9 mountinfo_after;
    struct statfs filesystem;
    char pid_text[32];
    int result;
    int cleanup_result;

    aqt_secret_guarded_fd_initialize(&current);
    aqt_secret_guarded_fd_initialize(&next);
    aqt_secret_guarded_fd_initialize(&mountinfo);
    result = aqt_secret_guarded_fd_adopt(
        open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW),
        &current
    );
    if (result != 0) {
        goto cleanup;
    }
    result = aqt_secret_fstat9(current.descriptor, &root_identity);
    if (result != 0
        || !aqt_secret_validate_secure_directory(
            &root_identity,
            0U,
            0U,
            UINT64_C(1))) {
        result = result == 0 ? EPERM : result;
        goto cleanup;
    }
    result = aqt_secret_open_correlated_child(
        &current,
        "proc",
        O_RDONLY | O_DIRECTORY,
        &next,
        &proc_identity
    );
    if (result != 0
        || !aqt_secret_validate_secure_directory(
            &proc_identity,
            0U,
            0U,
            UINT64_C(2))
        || fstatfs(next.descriptor, &filesystem) != 0
        || filesystem.f_type != PROC_SUPER_MAGIC) {
        result = result == 0 ? EPERM : result;
        goto cleanup;
    }
    result = aqt_secret_guarded_fd_close(&current);
    if (result != 0) {
        goto cleanup;
    }
    current = next;
    aqt_secret_guarded_fd_initialize(&next);
    {
        char reversed[32];
        uint64_t value;
        size_t length = 0U;
        size_t index;
        const pid_t pid = getpid();

        if (pid <= 0) {
            result = EPERM;
            goto cleanup;
        }
        value = (uint64_t)pid;
        do {
            if (length >= sizeof(reversed)) {
                result = EOVERFLOW;
                goto cleanup;
            }
            reversed[length++] = (char)('0' + (char)(value % UINT64_C(10)));
            value /= UINT64_C(10);
        } while (value != 0U);
        if (length >= sizeof(pid_text)) {
            result = EOVERFLOW;
            goto cleanup;
        }
        for (index = 0U; index < length; ++index) {
            pid_text[index] = reversed[length - index - 1U];
        }
        pid_text[length] = '\0';
    }
    result = aqt_secret_open_correlated_child(
        &current,
        pid_text,
        O_RDONLY | O_DIRECTORY,
        &next,
        &process_identity
    );
    if (result != 0
        || !aqt_secret_validate_secure_directory(
            &process_identity,
            (uint32_t)geteuid(),
            (uint32_t)getegid(),
            UINT64_C(2))
        || fstatfs(next.descriptor, &filesystem) != 0
        || filesystem.f_type != PROC_SUPER_MAGIC) {
        result = result == 0 ? EPERM : result;
        goto cleanup;
    }
    result = aqt_secret_guarded_fd_close(&current);
    if (result != 0) {
        goto cleanup;
    }
    current = next;
    aqt_secret_guarded_fd_initialize(&next);
    result = aqt_secret_open_correlated_child(
        &current,
        "mountinfo",
        O_RDONLY,
        &mountinfo,
        &mountinfo_before
    );
    if (result != 0 || mountinfo_before.file_type != (uint32_t)S_IFREG
        || (mountinfo_before.mode & UINT32_C(0222)) != 0U
        || mountinfo_before.link_count != UINT64_C(1)) {
        result = result == 0 ? EPERM : result;
        goto cleanup;
    }
    result = aqt_secret_guarded_fd_close(&current);
    if (result != 0) {
        goto cleanup;
    }
    result = aqt_secret_read_bounded_descriptor(
        mountinfo.descriptor,
        buffer,
        capacity,
        length_out
    );
    if (result == 0) {
        result = aqt_secret_fstat9(mountinfo.descriptor, &mountinfo_after);
    }
    if (result == 0
        && !aqt_secret_stat9_equal(&mountinfo_before, &mountinfo_after)) {
        result = ESTALE;
    }
    if (result == 0) {
        *identity_out = mountinfo_before;
    }

cleanup:
    cleanup_result = aqt_secret_guarded_fd_close(&mountinfo);
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    cleanup_result = aqt_secret_guarded_fd_close(&next);
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    cleanup_result = aqt_secret_guarded_fd_close(&current);
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    return result;
}

static int
aqt_secret_capture_mount_identity(aqt_secret_mount_identity *identity_out)
{
    unsigned char *first = MAP_FAILED;
    unsigned char *second = MAP_FAILED;
    size_t first_length = 0U;
    size_t second_length = 0U;
    aqt_secret_stat9 first_identity;
    aqt_secret_stat9 second_identity;
    int result;

    if (identity_out == NULL) {
        return EINVAL;
    }
    first = (unsigned char *)mmap(
        NULL,
        AQT_SECRET_MOUNTINFO_LIMIT,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    second = (unsigned char *)mmap(
        NULL,
        AQT_SECRET_MOUNTINFO_LIMIT,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    if (first == MAP_FAILED || second == MAP_FAILED) {
        result = errno == 0 ? ENOMEM : errno;
        goto cleanup;
    }
    result = aqt_secret_read_mountinfo_once(
        first,
        AQT_SECRET_MOUNTINFO_LIMIT,
        &first_length,
        &first_identity
    );
    if (result != 0) {
        goto cleanup;
    }
    result = aqt_secret_read_mountinfo_once(
        second,
        AQT_SECRET_MOUNTINFO_LIMIT,
        &second_length,
        &second_identity
    );
    if (result != 0) {
        goto cleanup;
    }
    if (!aqt_secret_stat9_equal(&first_identity, &second_identity)
        || first_length != second_length
        || memcmp(first, second, first_length) != 0) {
        result = ESTALE;
        goto cleanup;
    }
    result = aqt_secret_parse_mountinfo(first, first_length, identity_out);

cleanup:
    if (first != MAP_FAILED
        && munmap(first, AQT_SECRET_MOUNTINFO_LIMIT) != 0
        && result == 0) {
        result = aqt_secret_errno_or_io();
    }
    if (second != MAP_FAILED
        && munmap(second, AQT_SECRET_MOUNTINFO_LIMIT) != 0
        && result == 0) {
        result = aqt_secret_errno_or_io();
    }
    return result;
}

static int
aqt_secret_validate_directory(
    int directory_fd,
    const aqt_secret_mount_identity *mount,
    aqt_secret_stat9 *identity_out)
{
    struct statfs filesystem;
    aqt_secret_guarded_fd literal_directory;
    aqt_secret_stat9 identity;
    aqt_secret_stat9 literal_identity;
    int result;
    int cleanup_result;

    if (directory_fd < 0 || mount == NULL || identity_out == NULL) {
        return EINVAL;
    }
    aqt_secret_guarded_fd_initialize(&literal_directory);
    result = aqt_secret_fstat9(directory_fd, &identity);
    if (result != 0) {
        return result;
    }
    if (!aqt_secret_validate_role_directory(&identity)
        || fstatfs(directory_fd, &filesystem) != 0
        || filesystem.f_type != TMPFS_MAGIC
        || (uint32_t)major((dev_t)identity.device) != mount->major_device
        || (uint32_t)minor((dev_t)identity.device) != mount->minor_device) {
        return EPERM;
    }
    result = aqt_secret_open_literal_directory(
        &literal_directory,
        &literal_identity
    );
    if (result == 0
        && !aqt_secret_stat9_equal(&identity, &literal_identity)) {
        result = ESTALE;
    }
    cleanup_result = aqt_secret_guarded_fd_close(&literal_directory);
    if (cleanup_result != 0 && result == 0) {
        result = cleanup_result;
    }
    if (result != 0) {
        return result;
    }
    *identity_out = identity;
    return 0;
}
#endif

static int
aqt_secret_require_owner(
    const aqt_trusted_time_v2_secret_mount_admission *admission,
    uintptr_t interpreter_identity)
{
    int result;

    if (admission == NULL || interpreter_identity == (uintptr_t)0) {
        return EINVAL;
    }
    result = aqt_trusted_time_v2_fork_guard_require_identity(
        &admission->fork_identity
    );
    if (result != 0) {
        return result;
    }
    if (admission->interpreter_identity != interpreter_identity) {
        return EPERM;
    }
    return 0;
}

int
aqt_trusted_time_v2_secret_mount_admission_capture(
    aqt_trusted_time_v2_secret_mount_admission **admission_out,
    int directory_fd,
    uintptr_t interpreter_identity)
{
    if (admission_out == NULL || *admission_out != NULL || directory_fd < 0
        || interpreter_identity == (uintptr_t)0) {
        return EINVAL;
    }
#if defined(__linux__)
    {
        aqt_trusted_time_v2_secret_mount_admission *admission;
        aqt_secret_mount_identity post_mount_identity;
        int result;

        admission = (aqt_trusted_time_v2_secret_mount_admission *)mmap(
            NULL,
            sizeof(*admission),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0
        );
        if (admission == MAP_FAILED) {
            return errno == 0 ? ENOMEM : errno;
        }
        (void)memset(admission, 0, sizeof(*admission));
        result = aqt_secret_capture_mount_identity(&admission->mount_identity);
        if (result == 0) {
            result = aqt_secret_validate_directory(
                directory_fd,
                &admission->mount_identity,
                &admission->directory_identity
            );
        }
        if (result == 0) {
            result = aqt_secret_capture_mount_identity(&post_mount_identity);
        }
        if (result == 0
            && !aqt_secret_mount_identity_equal(
                &admission->mount_identity,
                &post_mount_identity)) {
            result = ESTALE;
        }
        if (result == 0) {
            result = aqt_trusted_time_v2_fork_guard_capture_identity(
                &admission->fork_identity
            );
        }
        if (result != 0) {
            (void)memset(admission, 0, sizeof(*admission));
            (void)munmap(admission, sizeof(*admission));
            return result;
        }
        admission->interpreter_identity = interpreter_identity;
        *admission_out = admission;
        return 0;
    }
#else
    return ENOTSUP;
#endif
}

int
aqt_trusted_time_v2_secret_mount_admission_revalidate(
    const aqt_trusted_time_v2_secret_mount_admission *admission,
    int directory_fd,
    uintptr_t interpreter_identity)
{
    int result = aqt_secret_require_owner(admission, interpreter_identity);

    if (result != 0 || directory_fd < 0) {
        return result != 0 ? result : EINVAL;
    }
#if defined(__linux__)
    {
        aqt_secret_mount_identity current_mount;
        aqt_secret_mount_identity post_mount;
        aqt_secret_stat9 current_directory;

        result = aqt_secret_capture_mount_identity(&current_mount);
        if (result != 0
            || !aqt_secret_mount_identity_equal(
                &admission->mount_identity,
                &current_mount)) {
            return result == 0 ? ESTALE : result;
        }
        result = aqt_secret_validate_directory(
            directory_fd,
            &current_mount,
            &current_directory
        );
        if (result != 0
            || !aqt_secret_stat9_equal(
                &admission->directory_identity,
                &current_directory)) {
            return result == 0 ? ESTALE : result;
        }
        result = aqt_secret_capture_mount_identity(&post_mount);
        if (result != 0
            || !aqt_secret_mount_identity_equal(&current_mount, &post_mount)) {
            return result == 0 ? ESTALE : result;
        }
        return 0;
    }
#else
    return ENOTSUP;
#endif
}

int
aqt_trusted_time_v2_secret_mount_admission_close(
    aqt_trusted_time_v2_secret_mount_admission **admission_io,
    uintptr_t interpreter_identity)
{
    aqt_trusted_time_v2_secret_mount_admission *admission;
    int result;

    if (admission_io == NULL) {
        return EINVAL;
    }
    admission = *admission_io;
    if (admission == NULL) {
        return 0;
    }
    result = aqt_secret_require_owner(admission, interpreter_identity);
    if (result != 0
        && (admission->fork_identity.origin_pid != getpid()
            || admission->fork_identity.fork_epoch
                != aqt_trusted_time_v2_fork_guard_current_epoch()
            || pthread_equal(
                admission->fork_identity.origin_thread,
                pthread_self()) == 0
            || admission->interpreter_identity != interpreter_identity)) {
        return result;
    }
    (void)memset(admission, 0, sizeof(*admission));
    *admission_io = NULL;
    return munmap(admission, sizeof(*admission)) == 0
        ? 0
        : aqt_secret_errno_or_io();
}

#ifdef AQT_TRUSTED_TIME_V2_SECRET_MOUNT_ADMISSION_TESTING
int
aqt_trusted_time_v2_secret_mount_admission_test_parse_mountinfo(
    const unsigned char *mountinfo,
    size_t mountinfo_length,
    uint32_t expected_major_device,
    uint32_t expected_minor_device)
{
    aqt_secret_mount_identity parsed;
    int result = aqt_secret_parse_mountinfo(
        mountinfo,
        mountinfo_length,
        &parsed
    );

    if (result != 0) {
        return result;
    }
    return parsed.major_device == expected_major_device
            && parsed.minor_device == expected_minor_device
        ? 0
        : ESTALE;
}

int
aqt_trusted_time_v2_secret_mount_admission_test_compare_mountinfo(
    const unsigned char *first,
    size_t first_length,
    const unsigned char *second,
    size_t second_length)
{
    aqt_secret_mount_identity first_identity;
    aqt_secret_mount_identity second_identity;
    int result = aqt_secret_parse_mountinfo(first, first_length, &first_identity);

    if (result == 0) {
        result = aqt_secret_parse_mountinfo(
            second,
            second_length,
            &second_identity
        );
    }
    if (result != 0) {
        return result;
    }
    return aqt_secret_mount_identity_equal(&first_identity, &second_identity)
        ? 0
        : ESTALE;
}

int
aqt_trusted_time_v2_secret_mount_admission_test_secure_directory_metadata(
    uint32_t uid,
    uint32_t gid,
    uint32_t mode,
    uint64_t link_count)
{
#if defined(__linux__)
    aqt_secret_stat9 identity;

    (void)memset(&identity, 0, sizeof(identity));
    identity.file_type = (uint32_t)S_IFDIR;
    identity.uid = uid;
    identity.gid = gid;
    identity.mode = mode;
    identity.link_count = link_count;
    return aqt_secret_validate_secure_directory(
               &identity,
               0U,
               0U,
               UINT64_C(2))
        ? 0
        : EPERM;
#else
    return uid == 0U && gid == 0U && (mode & UINT32_C(0022)) == 0U
            && link_count >= UINT64_C(2)
        ? 0
        : EPERM;
#endif
}

int
aqt_trusted_time_v2_secret_mount_admission_test_root_directory_metadata(
    uint32_t uid,
    uint32_t gid,
    uint32_t mode,
    uint64_t link_count)
{
#if defined(__linux__)
    aqt_secret_stat9 identity;

    (void)memset(&identity, 0, sizeof(identity));
    identity.file_type = (uint32_t)S_IFDIR;
    identity.uid = uid;
    identity.gid = gid;
    identity.mode = mode;
    identity.link_count = link_count;
    return aqt_secret_validate_secure_directory(
               &identity,
               0U,
               0U,
               UINT64_C(1))
        ? 0
        : EPERM;
#else
    return uid == 0U && gid == 0U && (mode & UINT32_C(0022)) == 0U
            && link_count >= UINT64_C(1)
        ? 0
        : EPERM;
#endif
}

int
aqt_trusted_time_v2_secret_mount_admission_test_run_directory_metadata(
    uint32_t uid,
    uint32_t gid,
    uint32_t mode,
    uint64_t link_count)
{
    return aqt_trusted_time_v2_secret_mount_admission_test_root_directory_metadata(
        uid,
        gid,
        mode,
        link_count
    );
}
#endif
