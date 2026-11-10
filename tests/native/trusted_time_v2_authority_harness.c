#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include "trusted_time_v2_authority.h"
#include "trusted_time_v2_fork_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    int directory_descriptor;
    AqtTrustedTimeV2AuthorityTestRole role;
    uint32_t generation;
    unsigned char digest[AQT_TRUSTED_TIME_V2_AUTHORITY_SHA256_BYTES];
    int digest_present;
    int result;
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration output;
} ConsumeArguments;

static int
hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

static int
decode_sha256(
    const char *text,
    unsigned char destination[AQT_TRUSTED_TIME_V2_AUTHORITY_SHA256_BYTES]
)
{
    size_t index;

    if (text == NULL || strlen(text) != 64U) {
        return -1;
    }
    for (index = 0U; index < AQT_TRUSTED_TIME_V2_AUTHORITY_SHA256_BYTES; index++) {
        int high = hex_value(text[index * 2U]);
        int low = hex_value(text[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return -1;
        }
        destination[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static AqtTrustedTimeV2AuthorityTestRole
parse_role(const char *text)
{
    if (strcmp(text, "host") == 0) {
        return AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_HOST;
    }
    if (strcmp(text, "supervisor") == 0) {
        return AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_SUPERVISOR;
    }
    if (strcmp(text, "recovery") == 0) {
        return AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_RECOVERY;
    }
    return (AqtTrustedTimeV2AuthorityTestRole)0;
}

static int
open_directory(const char *path)
{
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static int
consume(ConsumeArguments *arguments)
{
    return aqt_trusted_time_v2_authority_test_consume_preopened(
        arguments->directory_descriptor,
        arguments->role,
        arguments->generation,
        arguments->digest_present ? arguments->digest : NULL,
        &arguments->output
    );
}

static void *
consume_thread(void *opaque)
{
    ConsumeArguments *arguments = opaque;
    arguments->result = consume(arguments);
    return NULL;
}

static void
print_result(const ConsumeArguments *arguments)
{
    size_t index;
    int owners = aqt_trusted_time_v2_fork_guard_require_owner_table_empty();

    (void)printf(
        "result=%d owners=%d generation=%u key=",
        arguments->result,
        owners,
        arguments->output.generation
    );
    for (index = 0U; index < sizeof(arguments->output.expected_public_key); index++) {
        (void)printf("%02x", arguments->output.expected_public_key[index]);
    }
    (void)printf("\n");
}

int
main(int argument_count, char **argument_values)
{
    ConsumeArguments arguments;
    const char *action;

    memset(&arguments, 0, sizeof(arguments));
    if (argument_count < 4
        || aqt_trusted_time_v2_fork_guard_initialize_before_python() != 0) {
        return 90;
    }
    action = argument_values[1];
    arguments.role = parse_role(argument_values[2]);
    if (arguments.role == 0) {
        return 91;
    }
    if (arguments.role == AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_RECOVERY) {
        char *end = NULL;
        unsigned long generation;
        if (argument_count < 6) {
            return 92;
        }
        errno = 0;
        generation = strtoul(argument_values[4], &end, 10);
        if (errno != 0 || end == argument_values[4] || *end != '\0'
            || generation == 0UL || generation > UINT32_MAX
            || decode_sha256(argument_values[5], arguments.digest) != 0) {
            return 93;
        }
        arguments.generation = (uint32_t)generation;
        arguments.digest_present = 1;
    }
    if (strcmp(action, "fork") == 0) {
        pid_t child = fork();
        int status;
        if (child < 0) {
            return 94;
        }
        if (child == 0) {
            arguments.directory_descriptor = open_directory(argument_values[3]);
            arguments.result = consume(&arguments);
            _exit(arguments.result == 0 ? 1 : 0);
        }
        if (waitpid(child, &status, 0) != child
            || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            return 95;
        }
        return 0;
    }
    arguments.directory_descriptor = open_directory(argument_values[3]);
    if (arguments.directory_descriptor < 3) {
        return 96;
    }
    if (strcmp(action, "double") == 0) {
        int first = consume(&arguments);
        AqtTrustedTimeV2AuthenticatedProvisioningGeneration first_output = arguments.output;
        arguments.directory_descriptor = open_directory(argument_values[3]);
        memset(&arguments.output, 0, sizeof(arguments.output));
        arguments.result = consume(&arguments);
        print_result(&arguments);
        return first == 0 && first_output.generation != 0U && arguments.result != 0 ? 0 : 101;
    }
    if (strcmp(action, "wrong-pid") == 0) {
        aqt_trusted_time_v2_authority_test_set_identity_fault(
            AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_PID
        );
    } else if (strcmp(action, "wrong-thread") == 0) {
        aqt_trusted_time_v2_authority_test_set_identity_fault(
            AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_THREAD
        );
    } else if (strcmp(action, "wrong-interpreter") == 0) {
        aqt_trusted_time_v2_authority_test_set_identity_fault(
            AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_INTERPRETER
        );
    } else if (strcmp(action, "wrong-epoch") == 0) {
        aqt_trusted_time_v2_authority_test_set_identity_fault(
            AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_FAULT_FORK_EPOCH
        );
    }
    if (strcmp(action, "race") == 0) {
        pthread_t thread;
        size_t waits = 0U;
        int victim_index =
            arguments.role == AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_RECOVERY ? 6 : 4;
        if (argument_count <= victim_index + 1) {
            return 97;
        }
        aqt_trusted_time_v2_authority_test_pause_after_read(1);
        if (pthread_create(&thread, NULL, consume_thread, &arguments) != 0) {
            return 98;
        }
        while (!aqt_trusted_time_v2_authority_test_read_is_paused() && waits < 1000000U) {
            (void)sched_yield();
            waits++;
        }
        if (waits == 1000000U
            || chmod(argument_values[3], 0700) != 0
            || rename(
                argument_values[victim_index + 1],
                argument_values[victim_index]
            ) != 0
            || chmod(argument_values[3], 0500) != 0) {
            aqt_trusted_time_v2_authority_test_resume_read();
            (void)pthread_join(thread, NULL);
            return 99;
        }
        aqt_trusted_time_v2_authority_test_resume_read();
        if (pthread_join(thread, NULL) != 0) {
            return 100;
        }
    } else {
        arguments.result = consume(&arguments);
    }
    print_result(&arguments);
    return arguments.result == 0 ? 0 : 1;
}
