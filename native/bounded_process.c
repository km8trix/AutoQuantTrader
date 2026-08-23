#define PY_SSIZE_T_CLEAN

#if defined(__linux__)
#define _GNU_SOURCE 1
#elif defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include <Python.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(Py_GIL_DISABLED)
#error "the bounded-process primitive requires a GIL-enabled CPython build"
#endif

#if !defined(__linux__) && !defined(__APPLE__)
#error "the bounded-process primitive supports only Linux and Darwin"
#endif

#if PY_MAJOR_VERSION != 3 || (PY_MINOR_VERSION != 12 && PY_MINOR_VERSION != 13)
#error "the bounded-process primitive supports exactly CPython 3.12 and 3.13"
#endif

#ifndef AQT_NATIVE_PROCESS_MODULE_NAME
#define AQT_NATIVE_PROCESS_MODULE_NAME "_autoquant_native_bounded_process"
#endif

#ifndef AQT_NATIVE_PROCESS_LAUNCHER_BASENAME
#error "the bounded-process primitive requires an exact launcher basename"
#endif

#define AQT_MAX_ARGUMENT_COUNT 128
#define AQT_MAX_ARGUMENT_BYTES 4096
#define AQT_MAX_ARGUMENT_TOTAL_BYTES (64 * 1024)
#define AQT_MAX_ENVIRONMENT_COUNT 128
#define AQT_MAX_ENVIRONMENT_BYTES 4096
#define AQT_MAX_ENVIRONMENT_TOTAL_BYTES (64 * 1024)
#define AQT_MAX_STDIN_BYTES (16 * 1024 * 1024)
#define AQT_MAX_CAPTURE_BYTES (16 * 1024 * 1024)
#define AQT_MAX_TIMEOUT_NS (300LL * 1000LL * 1000LL * 1000LL)
#define AQT_POLL_SLICE_NS (10LL * 1000LL * 1000LL)
#ifdef AQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE
#define AQT_TEST_FAIL_RESULT_ALLOCATION_ARGUMENT \
    "__autoquant_test_fail_result_allocation_after_reap__"
#endif

typedef struct {
    int initialized;
    pid_t origin_pid;
} AqtProcessModuleState;

typedef enum {
    AQT_PROCESS_OK = 0,
    AQT_PROCESS_TIMEOUT,
    AQT_PROCESS_OVERFLOW,
    AQT_PROCESS_INTERRUPTED,
    AQT_PROCESS_SYSTEM_ERROR
} AqtProcessOutcome;

typedef struct {
    char **argv;
    Py_ssize_t argc;
    char **environment;
    Py_ssize_t environment_count;
} AqtPreparedStrings;

#if defined(__APPLE__)
/*
 * The deployment floor is macOS 11, whose only descriptor-relative spawn
 * working-directory API is the _np spelling.  SDK 26 deprecates that spelling
 * in favor of a new symbol that is itself available only on macOS 26.  Keep
 * the supported-floor call isolated so the rest of the translation unit stays
 * under strict deprecation diagnostics.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int
aqt_add_chdir_action(posix_spawn_file_actions_t *actions, const char *cwd)
{
    return posix_spawn_file_actions_addchdir_np(actions, cwd);
}
#pragma clang diagnostic pop
#else
static int
aqt_add_chdir_action(posix_spawn_file_actions_t *actions, const char *cwd)
{
    return posix_spawn_file_actions_addchdir_np(actions, cwd);
}
#endif

static _Atomic int aqt_process_module_activation = 0;

static void
aqt_fail_stop(const char *message)
{
    Py_FatalError(message);
}

static int
aqt_require_active_module(PyObject *module)
{
    AqtProcessModuleState *state;

    if (!PyModule_CheckExact(module)) {
        PyErr_SetString(PyExc_RuntimeError, "native process module identity is invalid");
        return -1;
    }
    if (PyInterpreterState_Get() != PyInterpreterState_Main()) {
        PyErr_SetString(PyExc_RuntimeError, "native process module interpreter is invalid");
        return -1;
    }
    state = (AqtProcessModuleState *)PyModule_GetState(module);
    if (state == NULL) {
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_RuntimeError, "native process module is not active");
        }
        return -1;
    }
    if (state->initialized != 2) {
        PyErr_SetString(PyExc_RuntimeError, "native process module is not active");
        return -1;
    }
    if (state->origin_pid != getpid()) {
        PyErr_SetString(PyExc_RuntimeError, "native process module process is invalid");
        return -1;
    }
    if (atomic_load_explicit(
            &aqt_process_module_activation,
            memory_order_acquire
        ) != 2) {
        PyErr_SetString(PyExc_RuntimeError, "native process activation is invalid");
        return -1;
    }
    return 0;
}

static int
aqt_validate_module_origin(void)
{
    Dl_info image_information;
    const wchar_t *program_path_wide;
    PyObject *program_path_unicode = NULL;
    PyObject *program_path_bytes = NULL;
    const char *program_path;
    Py_ssize_t program_path_length;
    static const char launcher_suffix[] =
        "/bin/" AQT_NATIVE_PROCESS_LAUNCHER_BASENAME;
    size_t launcher_suffix_length = sizeof(launcher_suffix) - 1U;
    int result = -1;

    memset(&image_information, 0, sizeof(image_information));
    if (dladdr((const void *)&aqt_process_module_activation, &image_information) == 0
        || image_information.dli_fname == NULL) {
        PyErr_SetString(PyExc_ImportError, "native process image origin is unavailable");
        return -1;
    }
    program_path_wide = Py_GetProgramFullPath();
    if (program_path_wide == NULL) {
        PyErr_SetString(PyExc_ImportError, "native process launcher path is unavailable");
        return -1;
    }
    program_path_unicode = PyUnicode_FromWideChar(program_path_wide, -1);
    if (program_path_unicode == NULL) {
        goto cleanup;
    }
    program_path_bytes = PyUnicode_EncodeFSDefault(program_path_unicode);
    if (program_path_bytes == NULL) {
        goto cleanup;
    }
    program_path = PyBytes_AS_STRING(program_path_bytes);
    program_path_length = PyBytes_GET_SIZE(program_path_bytes);
    if (program_path_length <= (Py_ssize_t)launcher_suffix_length
        || program_path[0] != '/'
        || strlen(program_path) != (size_t)program_path_length
        || memcmp(
            program_path + (size_t)program_path_length - launcher_suffix_length,
            launcher_suffix,
            launcher_suffix_length
        ) != 0
        || strcmp(image_information.dli_fname, program_path) != 0) {
        PyErr_SetString(PyExc_ImportError, "native process launcher origin is invalid");
        goto cleanup;
    }
    result = 0;

cleanup:
    Py_XDECREF(program_path_bytes);
    Py_XDECREF(program_path_unicode);
    return result;
}

static int
aqt_exact_unicode_bytes(
    PyObject *value,
    const char **payload,
    Py_ssize_t *length,
    Py_ssize_t maximum,
    const char *message
)
{
    if (!PyUnicode_CheckExact(value)) {
        PyErr_SetString(PyExc_TypeError, message);
        return -1;
    }
    *payload = PyUnicode_AsUTF8AndSize(value, length);
    if (*payload == NULL) {
        return -1;
    }
    if (*length < 0 || *length > maximum
        || strlen(*payload) != (size_t)*length) {
        PyErr_SetString(PyExc_ValueError, message);
        return -1;
    }
    return 0;
}

static int
aqt_exact_nonnegative_integer(
    PyObject *value,
    long long maximum,
    long long *output,
    const char *message
)
{
    long long converted;

    if (!PyLong_CheckExact(value)) {
        PyErr_SetString(PyExc_TypeError, message);
        return -1;
    }
    converted = PyLong_AsLongLong(value);
    if (converted == -1 && PyErr_Occurred()) {
        return -1;
    }
    if (converted < 0 || converted > maximum) {
        PyErr_SetString(PyExc_ValueError, message);
        return -1;
    }
    *output = converted;
    return 0;
}

static int
aqt_environment_key_is_valid(const char *key, Py_ssize_t length)
{
    Py_ssize_t index;

    if (length <= 0) {
        return 0;
    }
    for (index = 0; index < length; index++) {
        unsigned char character = (unsigned char)key[index];

        if (!((character >= (unsigned char)'A' && character <= (unsigned char)'Z')
                || (character >= (unsigned char)'a'
                    && character <= (unsigned char)'z')
                || (character >= (unsigned char)'0'
                    && character <= (unsigned char)'9')
                || character == (unsigned char)'_')) {
            return 0;
        }
    }
    return 1;
}

static void
aqt_free_prepared_strings(AqtPreparedStrings *prepared)
{
    Py_ssize_t index;

    if (prepared->environment != NULL) {
        for (index = 0; index < prepared->environment_count; index++) {
            free(prepared->environment[index]);
        }
    }
    free(prepared->environment);
    free(prepared->argv);
    prepared->environment = NULL;
    prepared->argv = NULL;
    prepared->environment_count = 0;
    prepared->argc = 0;
}

static int
aqt_prepare_strings(
    PyObject *argv_object,
    PyObject *environment_object,
    AqtPreparedStrings *prepared
)
{
    Py_ssize_t index;
    Py_ssize_t total = 0;
    const char *previous_key = NULL;

    memset(prepared, 0, sizeof(*prepared));
    if (!PyTuple_CheckExact(argv_object)) {
        PyErr_SetString(PyExc_TypeError, "process argv must be an exact tuple");
        return -1;
    }
    prepared->argc = PyTuple_GET_SIZE(argv_object);
    if (prepared->argc <= 0 || prepared->argc > AQT_MAX_ARGUMENT_COUNT) {
        PyErr_SetString(PyExc_ValueError, "process argv count is invalid");
        return -1;
    }
    prepared->argv = calloc((size_t)prepared->argc + 1U, sizeof(char *));
    if (prepared->argv == NULL) {
        PyErr_NoMemory();
        return -1;
    }
    for (index = 0; index < prepared->argc; index++) {
        const char *payload;
        Py_ssize_t length;

        if (aqt_exact_unicode_bytes(
                PyTuple_GET_ITEM(argv_object, index),
                &payload,
                &length,
                AQT_MAX_ARGUMENT_BYTES,
                "process argv contains an invalid value"
            ) < 0) {
            goto error;
        }
        if (index == 0 && (length == 0 || payload[0] != '/')) {
            PyErr_SetString(PyExc_ValueError, "process executable must be absolute");
            goto error;
        }
        if (total > AQT_MAX_ARGUMENT_TOTAL_BYTES - length - 1) {
            PyErr_SetString(PyExc_ValueError, "process argv exceeds its byte bound");
            goto error;
        }
        total += length + 1;
        prepared->argv[index] = (char *)payload;
    }

    if (!PyTuple_CheckExact(environment_object)) {
        PyErr_SetString(PyExc_TypeError, "process environment must be an exact tuple");
        goto error;
    }
    prepared->environment_count = PyTuple_GET_SIZE(environment_object);
    if (prepared->environment_count < 0
        || prepared->environment_count > AQT_MAX_ENVIRONMENT_COUNT) {
        PyErr_SetString(PyExc_ValueError, "process environment count is invalid");
        goto error;
    }
    prepared->environment = calloc(
        (size_t)prepared->environment_count + 1U,
        sizeof(char *)
    );
    if (prepared->environment == NULL) {
        PyErr_NoMemory();
        goto error;
    }
    total = 0;
    for (index = 0; index < prepared->environment_count; index++) {
        PyObject *entry = PyTuple_GET_ITEM(environment_object, index);
        const char *key;
        const char *value;
        Py_ssize_t key_length;
        Py_ssize_t value_length;
        size_t allocation_length;

        if (!PyTuple_CheckExact(entry) || PyTuple_GET_SIZE(entry) != 2) {
            PyErr_SetString(PyExc_TypeError, "process environment entries are invalid");
            goto error;
        }
        if (aqt_exact_unicode_bytes(
                PyTuple_GET_ITEM(entry, 0),
                &key,
                &key_length,
                AQT_MAX_ENVIRONMENT_BYTES,
                "process environment key is invalid"
            ) < 0
            || aqt_exact_unicode_bytes(
                PyTuple_GET_ITEM(entry, 1),
                &value,
                &value_length,
                AQT_MAX_ENVIRONMENT_BYTES,
                "process environment value is invalid"
            ) < 0) {
            goto error;
        }
        if (!aqt_environment_key_is_valid(key, key_length)
            || (previous_key != NULL && strcmp(previous_key, key) >= 0)) {
            PyErr_SetString(
                PyExc_ValueError,
                "process environment keys must be valid, sorted, and unique"
            );
            goto error;
        }
        if (total > AQT_MAX_ENVIRONMENT_TOTAL_BYTES - key_length - value_length - 2) {
            PyErr_SetString(PyExc_ValueError, "process environment exceeds its byte bound");
            goto error;
        }
        total += key_length + value_length + 2;
        allocation_length = (size_t)key_length + (size_t)value_length + 2U;
        prepared->environment[index] = malloc(allocation_length);
        if (prepared->environment[index] == NULL) {
            PyErr_NoMemory();
            goto error;
        }
        memcpy(prepared->environment[index], key, (size_t)key_length);
        prepared->environment[index][key_length] = '=';
        memcpy(
            prepared->environment[index] + key_length + 1,
            value,
            (size_t)value_length
        );
        prepared->environment[index][key_length + value_length + 1] = '\0';
        previous_key = key;
    }
    return 0;

error:
    aqt_free_prepared_strings(prepared);
    return -1;
}

static int
aqt_validate_path_chain(char *path, int require_directory)
{
    char *cursor;
    struct stat metadata;

    if (path[0] != '/') {
        return -1;
    }
    for (cursor = path + 1; ; cursor++) {
        char saved;
        int is_leaf;
        int valid_owner;

        if (*cursor != '/' && *cursor != '\0') {
            continue;
        }
        saved = *cursor;
        is_leaf = saved == '\0';
        *cursor = '\0';
        valid_owner = 0;
        if (lstat(path, &metadata) == 0) {
#ifdef AQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE
            valid_owner = metadata.st_uid == 0 || metadata.st_uid == geteuid();
#else
            valid_owner = metadata.st_uid == 0 && metadata.st_gid == 0;
#endif
        }
        if (!valid_owner || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0
            || (!is_leaf && !S_ISDIR(metadata.st_mode))
            || (is_leaf && require_directory != 0 && !S_ISDIR(metadata.st_mode))
            || (is_leaf && require_directory == 0
                && (!S_ISREG(metadata.st_mode)
                    || metadata.st_nlink != 1
                    || (metadata.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0))) {
            *cursor = saved;
            return -1;
        }
        *cursor = saved;
        if (is_leaf) {
            break;
        }
    }
    return 0;
}

static int
aqt_validate_process_paths(const char *executable, const char *cwd)
{
    char executable_copy[PATH_MAX];
    char executable_canonical[PATH_MAX];
    char cwd_copy[PATH_MAX];
    char cwd_canonical[PATH_MAX];
    size_t executable_length = strlen(executable);
    size_t cwd_length = strlen(cwd);

    if (executable_length == 0U || executable_length >= PATH_MAX
        || cwd_length == 0U || cwd_length >= PATH_MAX
        || executable[0] != '/' || cwd[0] != '/') {
        PyErr_SetString(PyExc_ValueError, "process executable and cwd must be bounded absolute paths");
        return -1;
    }
    memcpy(executable_copy, executable, executable_length + 1U);
    memcpy(cwd_copy, cwd, cwd_length + 1U);
    if (realpath(executable, executable_canonical) == NULL
        || strcmp(executable, executable_canonical) != 0
        || realpath(cwd, cwd_canonical) == NULL
        || strcmp(cwd, cwd_canonical) != 0
        || aqt_validate_path_chain(executable_copy, 0) < 0
        || aqt_validate_path_chain(cwd_copy, 1) < 0) {
        PyErr_SetString(PyExc_ValueError, "process executable or cwd is not admitted");
        return -1;
    }
    return 0;
}

static int
aqt_set_descriptor_flags(int descriptor, int add_nonblocking)
{
    int descriptor_flags = fcntl(descriptor, F_GETFD);

    if (descriptor_flags < 0
        || fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
        return -1;
    }
    if (add_nonblocking != 0) {
        int status_flags = fcntl(descriptor, F_GETFL);

        if (status_flags < 0
            || fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) < 0) {
            return -1;
        }
    }
    return 0;
}

static void
aqt_close_once(int *descriptor, int *close_failed)
{
    int owned = *descriptor;

    *descriptor = -1;
    if (owned >= 0 && close(owned) < 0) {
        *close_failed = 1;
    }
}

static int
aqt_make_pipe(int descriptors[2])
{
    int index;

#if defined(__linux__)
    if (pipe2(descriptors, O_CLOEXEC) < 0) {
        return -1;
    }
#else
    if (pipe(descriptors) < 0) {
        return -1;
    }
#endif
    for (index = 0; index < 2; index++) {
        if (descriptors[index] < 3) {
            errno = EBADF;
            return -1;
        }
        if (aqt_set_descriptor_flags(descriptors[index], 0) < 0) {
            return -1;
        }
    }
    return 0;
}

static int64_t
aqt_monotonic_nanoseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return -1;
    }
    if (now.tv_sec < 0
        || now.tv_sec > (time_t)(INT64_MAX / 1000000000LL)) {
        errno = EOVERFLOW;
        return -1;
    }
    return (int64_t)now.tv_sec * 1000000000LL + (int64_t)now.tv_nsec;
}

static int
aqt_poll_timeout_ms(int64_t deadline)
{
    int64_t now = aqt_monotonic_nanoseconds();
    int64_t remaining;

    if (now < 0 || now >= deadline) {
        return 0;
    }
    remaining = deadline - now;
    if (remaining > AQT_POLL_SLICE_NS) {
        remaining = AQT_POLL_SLICE_NS;
    }
    return (int)((remaining + 999999LL) / 1000000LL);
}

static int
aqt_add_close_action(posix_spawn_file_actions_t *actions, int descriptor)
{
    return posix_spawn_file_actions_addclose(actions, descriptor);
}

static int
aqt_prepare_spawn(
    posix_spawn_file_actions_t *actions,
    posix_spawnattr_t *attributes,
    const char *cwd,
    int stdin_pipe[2],
    int stdout_pipe[2],
    int stderr_pipe[2]
)
{
    sigset_t empty_mask;
    sigset_t default_signals;
    short flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK
        | POSIX_SPAWN_SETSIGDEF;
    int result;

#if defined(__APPLE__)
    flags = (short)(flags | POSIX_SPAWN_CLOEXEC_DEFAULT);
#endif
    result = posix_spawn_file_actions_init(actions);
    if (result != 0) {
        return result;
    }
    result = posix_spawnattr_init(attributes);
    if (result != 0) {
        (void)posix_spawn_file_actions_destroy(actions);
        return result;
    }
    if (sigemptyset(&empty_mask) < 0 || sigfillset(&default_signals) < 0
        || sigdelset(&default_signals, SIGKILL) < 0
        || sigdelset(&default_signals, SIGSTOP) < 0) {
        result = errno;
        goto error;
    }
    result = posix_spawnattr_setflags(attributes, flags);
    if (result == 0) {
        result = posix_spawnattr_setpgroup(attributes, (pid_t)0);
    }
    if (result == 0) {
        result = posix_spawnattr_setsigmask(attributes, &empty_mask);
    }
    if (result == 0) {
        result = posix_spawnattr_setsigdefault(attributes, &default_signals);
    }
    if (result == 0) {
        result = posix_spawn_file_actions_adddup2(actions, stdin_pipe[0], STDIN_FILENO);
    }
    if (result == 0) {
        result = posix_spawn_file_actions_adddup2(actions, stdout_pipe[1], STDOUT_FILENO);
    }
    if (result == 0) {
        result = posix_spawn_file_actions_adddup2(actions, stderr_pipe[1], STDERR_FILENO);
    }
    if (result == 0) {
        result = aqt_add_close_action(actions, stdin_pipe[0]);
    }
    if (result == 0) {
        result = aqt_add_close_action(actions, stdin_pipe[1]);
    }
    if (result == 0) {
        result = aqt_add_close_action(actions, stdout_pipe[0]);
    }
    if (result == 0) {
        result = aqt_add_close_action(actions, stdout_pipe[1]);
    }
    if (result == 0) {
        result = aqt_add_close_action(actions, stderr_pipe[0]);
    }
    if (result == 0) {
        result = aqt_add_close_action(actions, stderr_pipe[1]);
    }
    if (result == 0) {
        result = aqt_add_chdir_action(actions, cwd);
    }
#if defined(__linux__)
    if (result == 0) {
        result = posix_spawn_file_actions_addclosefrom_np(actions, 3);
    }
#endif
    if (result == 0) {
        return 0;
    }

error:
    (void)posix_spawnattr_destroy(attributes);
    (void)posix_spawn_file_actions_destroy(actions);
    return result;
}

static int
aqt_read_capture(
    int *descriptor,
    unsigned char *output,
    size_t *output_length,
    size_t output_cap,
    int *close_failed,
    int *overflow,
    int *operation_error
)
{
    unsigned char scratch[8192];

    for (;;) {
        ssize_t received = read(*descriptor, scratch, sizeof(scratch));

        if (received > 0) {
            size_t count = (size_t)received;

            if (*output_length > output_cap || count > output_cap - *output_length) {
                *overflow = 1;
                return 0;
            }
            if (count > 0U) {
                memcpy(output + *output_length, scratch, count);
            }
            *output_length += count;
            continue;
        }
        if (received == 0) {
            aqt_close_once(descriptor, close_failed);
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EINTR) {
            return 1;
        }
        *operation_error = errno;
        return -1;
    }
}

static int
aqt_write_stdin(
    int *descriptor,
    const unsigned char *payload,
    size_t payload_length,
    size_t *offset,
    int *close_failed,
    int *operation_error
)
{
    ssize_t written;

    if (*offset == payload_length) {
        aqt_close_once(descriptor, close_failed);
        return 0;
    }
    written = write(*descriptor, payload + *offset, payload_length - *offset);
    if (written > 0) {
        *offset += (size_t)written;
        if (*offset == payload_length) {
            aqt_close_once(descriptor, close_failed);
        }
        return 0;
    }
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 0;
    }
    if (written < 0 && errno == EINTR) {
        return 1;
    }
    if (written < 0 && errno == EPIPE) {
        aqt_close_once(descriptor, close_failed);
        return 0;
    }
    *operation_error = written < 0 ? errno : EIO;
    return -1;
}

static int
aqt_observe_child_exit(pid_t child, int *exited, int *operation_error)
{
    siginfo_t information;

    memset(&information, 0, sizeof(information));
    if (waitid(P_PID, (id_t)child, &information, WEXITED | WNOHANG | WNOWAIT) < 0) {
        if (errno == EINTR) {
            return 1;
        }
        *operation_error = errno;
        return -1;
    }
    if (information.si_pid == child) {
        *exited = 1;
    }
    return 0;
}

static void
aqt_kill_group_and_reap(
    pid_t child,
    int child_was_observed_exited,
    int *status,
    int *cleanup_failed
)
{
    pid_t reaped;
    int kill_result;
    int kill_error = 0;

    do {
        kill_result = kill(-child, SIGKILL);
    } while (kill_result < 0 && errno == EINTR);
    if (kill_result < 0) {
        kill_error = errno;
    }
#if defined(__APPLE__)
    if (kill_result < 0 && kill_error == EPERM && child_was_observed_exited == 0) {
        siginfo_t information;
        int direct_kill_result;
        int wait_result;

        do {
            direct_kill_result = kill(child, SIGKILL);
        } while (direct_kill_result < 0 && errno == EINTR);
        if (direct_kill_result < 0 && errno != ESRCH) {
            *cleanup_failed |= 1;
        }
        memset(&information, 0, sizeof(information));
        do {
            wait_result = waitid(
                P_PID,
                (id_t)child,
                &information,
                WEXITED | WNOWAIT
            );
        } while (wait_result < 0 && errno == EINTR);
        if (wait_result == 0 && information.si_pid == child) {
            child_was_observed_exited = 1;
        }
    }
    if (kill_result < 0 && kill_error == EPERM
        && child_was_observed_exited != 0) {
        do {
            kill_result = kill(-child, SIGKILL);
        } while (kill_result < 0 && errno == EINTR);
        if (kill_result < 0) {
            kill_error = errno;
        } else {
            kill_error = 0;
        }
    }
    if (kill_result < 0 && kill_error != ESRCH
        && !(kill_error == EPERM && child_was_observed_exited != 0)) {
#else
    (void)child_was_observed_exited;
    if (kill_result < 0 && kill_error != ESRCH) {
#endif
        *cleanup_failed |= 1;
    }
    do {
        reaped = waitpid(child, status, 0);
    } while (reaped < 0 && errno == EINTR);
    if (reaped != child) {
        *cleanup_failed |= 2;
    }
}

static PyObject *
aqt_run_bounded_process(PyObject *module, PyObject *arguments)
{
    PyObject *argv_object;
    PyObject *cwd_object;
    PyObject *environment_object;
    PyObject *stdin_object;
    PyObject *stdout_cap_object;
    PyObject *stderr_cap_object;
    PyObject *timeout_object;
    const char *cwd;
    Py_ssize_t cwd_length;
    const unsigned char *stdin_payload;
    Py_ssize_t stdin_length_signed;
    long long stdout_cap_value;
    long long stderr_cap_value;
    long long timeout_value;
    size_t stdout_cap;
    size_t stderr_cap;
    unsigned char *stdout_output = NULL;
    unsigned char *stderr_output = NULL;
    size_t stdout_length = 0U;
    size_t stderr_length = 0U;
    size_t stdin_offset = 0U;
    AqtPreparedStrings prepared;
    int stdin_pipe[2] = {-1, -1};
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    pid_t child = (pid_t)-1;
    int child_exited = 0;
    int child_status = 0;
    int close_failed = 0;
    int cleanup_failed = 0;
    int operation_error = 0;
    int spawn_result;
    int action_destroy_result;
    int attribute_destroy_result;
    int overflow = 0;
    int interrupted = 0;
#ifdef AQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE
    int fail_result_allocation_after_reap = 0;
#endif
    int64_t started;
    int64_t deadline;
    AqtProcessOutcome outcome = AQT_PROCESS_OK;
#if defined(__linux__)
    sigset_t sigpipe_set;
    sigset_t previous_mask;
    int sigpipe_blocked = 0;
    int previous_sigpipe_blocked = 0;
#endif
    PyObject *stdout_bytes = NULL;
    PyObject *stderr_bytes = NULL;
    PyObject *returncode = NULL;
    PyObject *result = NULL;

    memset(&prepared, 0, sizeof(prepared));
    if (aqt_require_active_module(module) < 0) {
        return NULL;
    }
    if (!PyTuple_CheckExact(arguments) || PyTuple_GET_SIZE(arguments) != 7) {
        PyErr_SetString(PyExc_TypeError, "bounded process requires exactly seven arguments");
        return NULL;
    }
    argv_object = PyTuple_GET_ITEM(arguments, 0);
    cwd_object = PyTuple_GET_ITEM(arguments, 1);
    environment_object = PyTuple_GET_ITEM(arguments, 2);
    stdin_object = PyTuple_GET_ITEM(arguments, 3);
    stdout_cap_object = PyTuple_GET_ITEM(arguments, 4);
    stderr_cap_object = PyTuple_GET_ITEM(arguments, 5);
    timeout_object = PyTuple_GET_ITEM(arguments, 6);
    if (aqt_exact_unicode_bytes(
            cwd_object,
            &cwd,
            &cwd_length,
            PATH_MAX - 1,
            "process cwd is invalid"
        ) < 0
        || cwd_length <= 0
        || cwd[0] != '/') {
        if (!PyErr_Occurred()) {
            PyErr_SetString(PyExc_ValueError, "process cwd must be absolute");
        }
        return NULL;
    }
    if (!PyBytes_CheckExact(stdin_object)) {
        PyErr_SetString(PyExc_TypeError, "process stdin must be exact bytes");
        return NULL;
    }
    stdin_length_signed = PyBytes_GET_SIZE(stdin_object);
    if (stdin_length_signed < 0 || stdin_length_signed > AQT_MAX_STDIN_BYTES) {
        PyErr_SetString(PyExc_ValueError, "process stdin exceeds its bound");
        return NULL;
    }
    stdin_payload = (const unsigned char *)PyBytes_AS_STRING(stdin_object);
    if (aqt_exact_nonnegative_integer(
            stdout_cap_object,
            AQT_MAX_CAPTURE_BYTES,
            &stdout_cap_value,
            "process stdout cap is invalid"
        ) < 0
        || aqt_exact_nonnegative_integer(
            stderr_cap_object,
            AQT_MAX_CAPTURE_BYTES,
            &stderr_cap_value,
            "process stderr cap is invalid"
        ) < 0
        || aqt_exact_nonnegative_integer(
            timeout_object,
            AQT_MAX_TIMEOUT_NS,
            &timeout_value,
            "process timeout is invalid"
        ) < 0) {
        return NULL;
    }
    stdout_cap = (size_t)stdout_cap_value;
    stderr_cap = (size_t)stderr_cap_value;
    if (aqt_prepare_strings(argv_object, environment_object, &prepared) < 0) {
        return NULL;
    }
#ifdef AQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE
    fail_result_allocation_after_reap =
        prepared.argc > 1
        && strcmp(
            prepared.argv[prepared.argc - 1],
            AQT_TEST_FAIL_RESULT_ALLOCATION_ARGUMENT
        ) == 0;
#endif
    if (aqt_validate_process_paths(prepared.argv[0], cwd) < 0) {
        goto python_error;
    }
    stdout_output = malloc(stdout_cap == 0U ? 1U : stdout_cap);
    stderr_output = malloc(stderr_cap == 0U ? 1U : stderr_cap);
    if (stdout_output == NULL || stderr_output == NULL) {
        PyErr_NoMemory();
        goto python_error;
    }
    if (aqt_make_pipe(stdin_pipe) < 0
        || aqt_make_pipe(stdout_pipe) < 0
        || aqt_make_pipe(stderr_pipe) < 0
        || aqt_set_descriptor_flags(stdin_pipe[1], 1) < 0
        || aqt_set_descriptor_flags(stdout_pipe[0], 1) < 0
        || aqt_set_descriptor_flags(stderr_pipe[0], 1) < 0) {
        operation_error = errno;
        goto pre_spawn_system_error;
    }
#if defined(__APPLE__)
    if (fcntl(stdin_pipe[1], F_SETNOSIGPIPE, 1) < 0) {
        operation_error = errno;
        goto pre_spawn_system_error;
    }
#else
    if (sigemptyset(&sigpipe_set) < 0 || sigaddset(&sigpipe_set, SIGPIPE) < 0) {
        operation_error = errno;
        goto pre_spawn_system_error;
    }
    operation_error = pthread_sigmask(SIG_BLOCK, &sigpipe_set, &previous_mask);
    if (operation_error != 0) {
        goto pre_spawn_system_error;
    }
    sigpipe_blocked = 1;
    previous_sigpipe_blocked = sigismember(&previous_mask, SIGPIPE) == 1;
#endif
    started = aqt_monotonic_nanoseconds();
    if (started < 0 || timeout_value > INT64_MAX - started) {
        operation_error = started < 0 ? errno : EOVERFLOW;
        goto pre_spawn_system_error;
    }
    deadline = started + timeout_value;
    spawn_result = aqt_prepare_spawn(
        &actions,
        &attributes,
        cwd,
        stdin_pipe,
        stdout_pipe,
        stderr_pipe
    );
    if (spawn_result != 0) {
        operation_error = spawn_result;
        goto pre_spawn_system_error;
    }
    spawn_result = posix_spawn(
        &child,
        prepared.argv[0],
        &actions,
        &attributes,
        prepared.argv,
        prepared.environment
    );
    action_destroy_result = posix_spawn_file_actions_destroy(&actions);
    attribute_destroy_result = posix_spawnattr_destroy(&attributes);
    if (spawn_result != 0) {
        operation_error = spawn_result;
        if (action_destroy_result != 0 || attribute_destroy_result != 0) {
            cleanup_failed |= 4;
        }
        goto pre_spawn_system_error;
    }
    if (action_destroy_result != 0 || attribute_destroy_result != 0) {
        cleanup_failed |= 4;
        outcome = AQT_PROCESS_SYSTEM_ERROR;
        operation_error = EIO;
    }
    aqt_close_once(&stdin_pipe[0], &close_failed);
    aqt_close_once(&stdout_pipe[1], &close_failed);
    aqt_close_once(&stderr_pipe[1], &close_failed);
    if (stdin_length_signed == 0) {
        aqt_close_once(&stdin_pipe[1], &close_failed);
    }

    while (outcome == AQT_PROCESS_OK) {
        struct pollfd descriptors[3];
        nfds_t descriptor_count = 0;
        int poll_result;
        int observation_result;
        int timeout_ms;
        int64_t now;

        if (PyOS_InterruptOccurred()) {
            interrupted = 1;
            outcome = AQT_PROCESS_INTERRUPTED;
            break;
        }
        now = aqt_monotonic_nanoseconds();
        if (now < 0) {
            operation_error = errno;
            outcome = AQT_PROCESS_SYSTEM_ERROR;
            break;
        }
        if (now >= deadline) {
            outcome = AQT_PROCESS_TIMEOUT;
            break;
        }
        if (stdin_pipe[1] >= 0) {
            descriptors[descriptor_count].fd = stdin_pipe[1];
            descriptors[descriptor_count].events = POLLOUT;
            descriptors[descriptor_count].revents = 0;
            descriptor_count++;
        }
        if (stdout_pipe[0] >= 0) {
            descriptors[descriptor_count].fd = stdout_pipe[0];
            descriptors[descriptor_count].events = POLLIN;
            descriptors[descriptor_count].revents = 0;
            descriptor_count++;
        }
        if (stderr_pipe[0] >= 0) {
            descriptors[descriptor_count].fd = stderr_pipe[0];
            descriptors[descriptor_count].events = POLLIN;
            descriptors[descriptor_count].revents = 0;
            descriptor_count++;
        }
        timeout_ms = aqt_poll_timeout_ms(deadline);
        poll_result = poll(descriptors, descriptor_count, timeout_ms);
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            operation_error = errno;
            outcome = AQT_PROCESS_SYSTEM_ERROR;
            break;
        }
        for (nfds_t index = 0; index < descriptor_count; index++) {
            int io_result;

            if ((descriptors[index].revents & POLLNVAL) != 0) {
                operation_error = EBADF;
                outcome = AQT_PROCESS_SYSTEM_ERROR;
                break;
            }
            if (descriptors[index].fd == stdin_pipe[1]
                && (descriptors[index].revents
                    & (POLLOUT | POLLERR | POLLHUP)) != 0) {
                io_result = aqt_write_stdin(
                    &stdin_pipe[1],
                    stdin_payload,
                    (size_t)stdin_length_signed,
                    &stdin_offset,
                    &close_failed,
                    &operation_error
                );
            } else if (descriptors[index].fd == stdout_pipe[0]
                && (descriptors[index].revents
                    & (POLLIN | POLLERR | POLLHUP)) != 0) {
                io_result = aqt_read_capture(
                    &stdout_pipe[0],
                    stdout_output,
                    &stdout_length,
                    stdout_cap,
                    &close_failed,
                    &overflow,
                    &operation_error
                );
            } else if (descriptors[index].fd == stderr_pipe[0]
                && (descriptors[index].revents
                    & (POLLIN | POLLERR | POLLHUP)) != 0) {
                io_result = aqt_read_capture(
                    &stderr_pipe[0],
                    stderr_output,
                    &stderr_length,
                    stderr_cap,
                    &close_failed,
                    &overflow,
                    &operation_error
                );
            } else {
                io_result = 0;
            }
            if (io_result < 0) {
                outcome = AQT_PROCESS_SYSTEM_ERROR;
                break;
            }
            if (overflow != 0) {
                outcome = AQT_PROCESS_OVERFLOW;
                break;
            }
        }
        if (outcome != AQT_PROCESS_OK) {
            break;
        }
        observation_result = aqt_observe_child_exit(
            child,
            &child_exited,
            &operation_error
        );
        if (observation_result < 0) {
            outcome = AQT_PROCESS_SYSTEM_ERROR;
            break;
        }
        if (child_exited != 0 && stdin_pipe[1] >= 0) {
            aqt_close_once(&stdin_pipe[1], &close_failed);
        }
        if (child_exited != 0 && stdout_pipe[0] < 0 && stderr_pipe[0] < 0) {
            break;
        }
    }

    aqt_kill_group_and_reap(
        child,
        child_exited,
        &child_status,
        &cleanup_failed
    );
    aqt_close_once(&stdin_pipe[1], &close_failed);
    aqt_close_once(&stdout_pipe[0], &close_failed);
    aqt_close_once(&stderr_pipe[0], &close_failed);
pre_spawn_system_error:
    aqt_close_once(&stdin_pipe[0], &close_failed);
    aqt_close_once(&stdin_pipe[1], &close_failed);
    aqt_close_once(&stdout_pipe[0], &close_failed);
    aqt_close_once(&stdout_pipe[1], &close_failed);
    aqt_close_once(&stderr_pipe[0], &close_failed);
    aqt_close_once(&stderr_pipe[1], &close_failed);
#if defined(__linux__)
    if (sigpipe_blocked != 0) {
        if (previous_sigpipe_blocked == 0) {
            struct timespec zero = {0, 0};
            sigset_t pending;

            if (sigpending(&pending) < 0) {
                cleanup_failed |= 8;
            } else if (sigismember(&pending, SIGPIPE) == 1) {
                int signal_result;

                do {
                    signal_result = sigtimedwait(&sigpipe_set, NULL, &zero);
                } while (signal_result < 0 && errno == EINTR);
                if (signal_result != SIGPIPE) {
                    cleanup_failed |= 8;
                }
            }
        }
        if (pthread_sigmask(SIG_SETMASK, &previous_mask, NULL) != 0) {
            cleanup_failed |= 8;
        }
    }
#endif
    if (close_failed != 0) {
        aqt_fail_stop("bounded process descriptor cleanup failed");
    }
    if ((cleanup_failed & 1) != 0) {
        aqt_fail_stop("bounded process group cleanup failed");
    }
    if ((cleanup_failed & 2) != 0) {
        aqt_fail_stop("bounded process reap cleanup failed");
    }
    if ((cleanup_failed & 4) != 0) {
        aqt_fail_stop("bounded process spawn-state cleanup failed");
    }
    if ((cleanup_failed & 8) != 0) {
        aqt_fail_stop("bounded process signal-state cleanup failed");
    }
    aqt_free_prepared_strings(&prepared);
    if (interrupted != 0 || outcome == AQT_PROCESS_INTERRUPTED) {
        free(stderr_output);
        free(stdout_output);
        PyErr_SetInterruptEx(SIGINT);
        if (PyErr_CheckSignals() == 0) {
            PyErr_SetNone(PyExc_KeyboardInterrupt);
        }
        return NULL;
    }
    if (outcome == AQT_PROCESS_TIMEOUT) {
        free(stderr_output);
        free(stdout_output);
        PyErr_SetString(PyExc_TimeoutError, "bounded process exceeded its deadline");
        return NULL;
    }
    if (outcome == AQT_PROCESS_OVERFLOW) {
        free(stderr_output);
        free(stdout_output);
        PyErr_SetString(PyExc_OverflowError, "bounded process output exceeded its cap");
        return NULL;
    }
    if (outcome == AQT_PROCESS_SYSTEM_ERROR || operation_error != 0) {
        free(stderr_output);
        free(stdout_output);
        errno = operation_error == 0 ? EIO : operation_error;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (!WIFEXITED(child_status) && !WIFSIGNALED(child_status)) {
        free(stderr_output);
        free(stdout_output);
        PyErr_SetString(PyExc_RuntimeError, "bounded process returned an invalid wait status");
        return NULL;
    }
#ifdef AQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE
    if (fail_result_allocation_after_reap != 0) {
        free(stderr_output);
        free(stdout_output);
        return PyErr_NoMemory();
    }
#endif
    stdout_bytes = PyBytes_FromStringAndSize(
        (const char *)stdout_output,
        (Py_ssize_t)stdout_length
    );
    stderr_bytes = PyBytes_FromStringAndSize(
        (const char *)stderr_output,
        (Py_ssize_t)stderr_length
    );
    free(stderr_output);
    free(stdout_output);
    if (stdout_bytes == NULL || stderr_bytes == NULL) {
        Py_XDECREF(stderr_bytes);
        Py_XDECREF(stdout_bytes);
        return NULL;
    }
    returncode = PyLong_FromLong(
        WIFEXITED(child_status)
            ? (long)WEXITSTATUS(child_status)
            : -(long)WTERMSIG(child_status)
    );
    if (returncode == NULL) {
        Py_DECREF(stderr_bytes);
        Py_DECREF(stdout_bytes);
        return NULL;
    }
    result = PyTuple_New(4);
    if (result == NULL) {
        Py_DECREF(returncode);
        Py_DECREF(stderr_bytes);
        Py_DECREF(stdout_bytes);
        return NULL;
    }
    PyTuple_SET_ITEM(result, 0, Py_NewRef(argv_object));
    PyTuple_SET_ITEM(result, 1, returncode);
    PyTuple_SET_ITEM(result, 2, stdout_bytes);
    PyTuple_SET_ITEM(result, 3, stderr_bytes);
    return result;

python_error:
    aqt_close_once(&stdin_pipe[0], &close_failed);
    aqt_close_once(&stdin_pipe[1], &close_failed);
    aqt_close_once(&stdout_pipe[0], &close_failed);
    aqt_close_once(&stdout_pipe[1], &close_failed);
    aqt_close_once(&stderr_pipe[0], &close_failed);
    aqt_close_once(&stderr_pipe[1], &close_failed);
    if (close_failed != 0) {
        aqt_fail_stop("bounded process pre-spawn cleanup failed");
    }
    free(stderr_output);
    free(stdout_output);
    aqt_free_prepared_strings(&prepared);
    return NULL;
}

static PyObject *
aqt_capabilities(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    if (aqt_require_active_module(module) < 0) {
        return NULL;
    }
    return Py_BuildValue(
        "(ssssssss)",
        "cpython-c-bounded-process-v1",
        "exact-immutable-input-and-result-tuples",
        "absolute-executable-no-path-search",
        "native-posix-spawn-chdir-process-group",
        "exact-stdio-pipes-and-environment",
        "bounded-stdin-stdout-stderr-deadline",
        "kill-group-and-reap-before-python-signal",
        "gil-held-no-live-process-capability"
    );
}

static PyObject *
aqt_self_test(PyObject *module, PyObject *Py_UNUSED(ignored))
{
    if (aqt_require_active_module(module) < 0) {
        return NULL;
    }
    if (AQT_MAX_CAPTURE_BYTES <= 0
        || AQT_MAX_STDIN_BYTES <= 0
        || AQT_MAX_TIMEOUT_NS <= 0
        || sizeof(pid_t) > sizeof(long long)) {
        PyErr_SetString(PyExc_RuntimeError, "native bounded-process invariants failed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyMethodDef aqt_process_methods[] = {
    {
        "_run_bounded_process",
        (PyCFunction)aqt_run_bounded_process,
        METH_VARARGS,
        PyDoc_STR("Run, capture, terminate, and reap one exact bounded process transaction.")
    },
    {
        "_capabilities",
        (PyCFunction)aqt_capabilities,
        METH_NOARGS,
        PyDoc_STR("Return the immutable native process capability declaration.")
    },
    {
        "_self_test",
        (PyCFunction)aqt_self_test,
        METH_NOARGS,
        PyDoc_STR("Fail unless the compiled bounded-process primitive is active.")
    },
    {NULL, NULL, 0, NULL}
};

static int
aqt_process_module_exec(PyObject *module)
{
    AqtProcessModuleState *state;
    int expected_activation = 0;

    state = (AqtProcessModuleState *)PyModule_GetState(module);
    if (state == NULL) {
        return -1;
    }
    if (state->initialized != 0) {
        PyErr_SetString(PyExc_ImportError, "native process module was already initialized");
        return -1;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &aqt_process_module_activation,
            &expected_activation,
            1,
            memory_order_acq_rel,
            memory_order_acquire
        )) {
        PyErr_SetString(PyExc_ImportError, "native process activation was consumed");
        return -1;
    }
    state->initialized = 1;
    state->origin_pid = (pid_t)-1;
    if (PyInterpreterState_Get() != PyInterpreterState_Main()) {
        PyErr_SetString(PyExc_ImportError, "native process supports only the main interpreter");
        return -1;
    }
    if (aqt_validate_module_origin() < 0) {
        return -1;
    }
    state->origin_pid = getpid();
    state->initialized = 2;
    atomic_store_explicit(&aqt_process_module_activation, 2, memory_order_release);
    return 0;
}

static PyModuleDef_Slot aqt_process_slots[] = {
    {Py_mod_exec, (void *)aqt_process_module_exec},
    {Py_mod_multiple_interpreters, Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED},
    {0, NULL},
};

static struct PyModuleDef aqt_process_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = AQT_NATIVE_PROCESS_MODULE_NAME,
    .m_doc = "Private native bounded-process transaction.",
    .m_size = sizeof(AqtProcessModuleState),
    .m_methods = aqt_process_methods,
    .m_slots = aqt_process_slots,
};

PyMODINIT_FUNC
PyInit__native_bounded_process(void)
{
    return PyModuleDef_Init(&aqt_process_module);
}
