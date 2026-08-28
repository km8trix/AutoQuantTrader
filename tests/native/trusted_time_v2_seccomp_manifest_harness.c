#include "trusted_time_v2_seccomp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int
aqt_parse_phase(const char *value, int *phase)
{
    char *end;
    long parsed;

    if (value == NULL || phase == NULL || value[0] == '\0') {
        return 0;
    }
    errno = 0;
    end = NULL;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || end == NULL || end[0] != '\0'
        || parsed < AQT_TRUSTED_TIME_V2_SECCOMP_INITIAL_PHASE
        || parsed > AQT_TRUSTED_TIME_V2_SECCOMP_CHILD_EXEC_PHASE) {
        return 0;
    }
    *phase = (int)parsed;
    return 1;
}

int
main(int argument_count, char **argument_values)
{
    const unsigned char *bytes;
    size_t size;
    int phase;

    if (argument_count != 2 || argument_values == NULL
        || !aqt_parse_phase(argument_values[1], &phase)) {
        return 64;
    }
    bytes = NULL;
    size = 0U;
    if (aqt_trusted_time_v2_seccomp_filter_bytes(
            phase,
            0U,
            &bytes,
            &size
        ) != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        || bytes == NULL || size == 0U || size % 8U != 0U) {
        return 65;
    }
    if (fwrite(bytes, 1U, size, stdout) != size || fflush(stdout) != 0) {
        return 74;
    }
    return 0;
}
