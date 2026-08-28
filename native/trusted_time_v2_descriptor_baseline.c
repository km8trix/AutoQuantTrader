#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "trusted_time_v2_descriptor_baseline.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/magic.h>
#include <sys/statfs.h>
#include <sys/syscall.h>

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1U)
#endif
#endif

int
aqt_trusted_time_v2_close_ambient_descriptors(void)
{
#ifdef __linux__
#ifdef SYS_close_range
    if (syscall(
            SYS_close_range,
            (unsigned int)(STDERR_FILENO + 1),
            UINT_MAX,
            CLOSE_RANGE_UNSHARE
        ) == 0) {
        return 0;
    }
    return -1;
#else
    return -1;
#endif
#else
    struct rlimit descriptor_limit;
    rlim_t descriptor;

    if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) != 0
        || descriptor_limit.rlim_cur == RLIM_INFINITY
        || descriptor_limit.rlim_cur > (rlim_t)INT_MAX) {
        return -1;
    }
    for (descriptor = (rlim_t)(STDERR_FILENO + 1);
         descriptor < descriptor_limit.rlim_cur;
         descriptor++) {
        if (close((int)descriptor) != 0 && errno != EBADF) {
            return -1;
        }
    }
    return 0;
#endif
}

int
aqt_trusted_time_v2_validate_standard_descriptors(void)
{
    int descriptor;

    for (descriptor = STDIN_FILENO; descriptor <= STDERR_FILENO; descriptor++) {
        struct stat metadata;

        if (fcntl(descriptor, F_GETFD) < 0
            || fstat(descriptor, &metadata) != 0
            || S_ISSOCK(metadata.st_mode)
            || S_ISBLK(metadata.st_mode)) {
            return -1;
        }
#ifdef __linux__
#ifdef ANON_INODE_FS_MAGIC
        {
            struct statfs filesystem;

            if (fstatfs(descriptor, &filesystem) != 0
                || (unsigned long)filesystem.f_type
                    == (unsigned long)ANON_INODE_FS_MAGIC) {
                return -1;
            }
        }
#endif
#endif
    }
    return 0;
}
