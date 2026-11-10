#define _POSIX_C_SOURCE 200809L

#include "trusted_time_v2_descriptor_baseline.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int
aqt_is_closed(int descriptor)
{
    errno = 0;
    return fcntl(descriptor, F_GETFD) == -1 && errno == EBADF;
}

int
main(int argument_count, char **argument_values)
{
    int descriptors[2];

    if (argument_count != 2 || argument_values == NULL
        || argument_values[1] == NULL) {
        return 2;
    }
    if (strcmp(argument_values[1], "ambient") == 0) {
        if (pipe(descriptors) != 0 || descriptors[0] < 3 || descriptors[1] < 3) {
            return 3;
        }
        if (aqt_trusted_time_v2_close_ambient_descriptors() != 0
            || !aqt_is_closed(descriptors[0])
            || !aqt_is_closed(descriptors[1])
            || aqt_trusted_time_v2_validate_standard_descriptors() != 0) {
            return 4;
        }
        return 0;
    }
    if (strcmp(argument_values[1], "socket-stdio") == 0) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) != 0
            || dup2(descriptors[0], STDIN_FILENO) != STDIN_FILENO) {
            return 5;
        }
        if (descriptors[0] != STDIN_FILENO) {
            (void)close(descriptors[0]);
        }
        (void)close(descriptors[1]);
        return aqt_trusted_time_v2_validate_standard_descriptors() == -1 ? 0 : 6;
    }
    if (strcmp(argument_values[1], "standard") == 0) {
        return aqt_trusted_time_v2_validate_standard_descriptors() == 0 ? 0 : 7;
    }
    return 8;
}
