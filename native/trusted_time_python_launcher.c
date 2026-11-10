#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "embedded_owned_file_descriptor_wrapper.h"

#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
#include "embedded_bounded_process_wrapper.h"
#endif

#if (defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE) \
    + defined(AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE) \
    + defined(AQT_NATIVE_LAUNCHER_TEST_PROFILE) \
) != 1
#error "Exactly one trusted-time launcher profile must be selected."
#endif

#ifdef AQT_NATIVE_LAUNCHER_TEST_PROFILE
#define AQT_LAUNCHER_BASENAME "autoquant-trusted-time-python-test"
#elif defined(AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE)
#define AQT_LAUNCHER_BASENAME "autoquant-trusted-time-python-admission"
#else
#define AQT_LAUNCHER_BASENAME "autoquant-trusted-time-python"
#endif
#define AQT_NATIVE_MODULE_NAME "_autoquant_native_owned_file_descriptor"
#define AQT_WRAPPER_MODULE_NAME \
    "packages.adapters.trusted_time._owned_file_descriptor"
#define AQT_WRAPPER_PACKAGE_NAME "packages.adapters.trusted_time"
#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
#define AQT_PROCESS_NATIVE_MODULE_NAME "_autoquant_native_bounded_process"
#define AQT_PROCESS_WRAPPER_MODULE_NAME \
    "packages.adapters.trusted_time._bounded_process"
#define AQT_PROCESS_HANDOFF_NAME "_AQT_PRELOADED_NATIVE_PROCESS_MODULE"
#endif
#define AQT_FAILURE_STATUS 191

#ifndef AQT_TRUSTED_TIME_PREFIX
#error "AQT_TRUSTED_TIME_PREFIX must name the exact installed runtime prefix."
#endif

#ifndef AQT_PYTHON_HOME
#error "AQT_PYTHON_HOME must name the exact admitted Python home."
#endif

#ifndef AQT_PYTHON_STDLIB
#error "AQT_PYTHON_STDLIB must name the exact admitted Python standard library."
#endif

#ifndef AQT_PYTHON_DYNLOAD
#error "AQT_PYTHON_DYNLOAD must name the exact admitted Python dynload directory."
#endif

#if defined(AQT_NATIVE_LAUNCHER_TEST_PROFILE) && !defined(AQT_TEST_SOURCE_ROOT)
#error "AQT_TEST_SOURCE_ROOT must name the exact test-only source checkout."
#endif

#ifdef AQT_NATIVE_LAUNCHER_TEST_PROFILE
#define AQT_SOURCE_ROOT AQT_TEST_SOURCE_ROOT
#define AQT_HAS_SOURCE_ROOT 1
#elif defined(AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE)
#ifndef AQT_TRUSTED_TIME_SOURCE_ROOT
#error "AQT_TRUSTED_TIME_SOURCE_ROOT must name the fixed reviewed source root."
#endif
#define AQT_SOURCE_ROOT AQT_TRUSTED_TIME_SOURCE_ROOT
#define AQT_HAS_SOURCE_ROOT 1
#endif

extern PyObject *PyInit__native_owned_file_descriptor(void);
#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
extern PyObject *PyInit__native_bounded_process(void);
#endif
extern char **environ;

typedef struct {
    const char *identifier;
    const char *module_name;
    const char *callable_name;
    const char *fixed_argument;
    int run_as_main;
} AqtTarget;

static const AqtTarget aqt_targets[] = {
#ifdef AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE
    {"verify-compose", "scripts.verify_trusted_time_compose", NULL, NULL, 1},
    {"verify-images-build", "scripts.verify_trusted_time_images", NULL, "--build", 1},
    {
        "verify-images-readmit",
        "scripts.verify_trusted_time_images",
        NULL,
        "--admit-existing",
        1
    },
    {"start", "scripts.start_trusted_time_supervisor", NULL, NULL, 1},
    {
        "admit-unenrolled",
        "scripts.start_trusted_time_supervisor",
        NULL,
        "--expect-unenrolled-fail-closed",
        1
    },
    {"enroll-first", "scripts.enroll_trusted_time_head_anchor", NULL, NULL, 1},
    {
        "recover-first-enrollment",
        "scripts.enroll_trusted_time_head_anchor",
        NULL,
        "--recover-pending",
        1
    },
    {
        "post-enrollment-start",
        "scripts.trusted_time_post_enrollment_host_orchestrator",
        NULL,
        NULL,
        1
    },
    {
        "operator-authority-prepare",
        "scripts.provision_trusted_time_post_enrollment_operator_authority",
        NULL,
        "prepare",
        1
    },
    {
        "operator-authority-install",
        "scripts.provision_trusted_time_post_enrollment_operator_authority",
        NULL,
        "install",
        1
    },
    {
        "graceful-stop-authority-prepare",
        "scripts.provision_trusted_time_post_enrollment_graceful_stop_operator_authority",
        NULL,
        "prepare",
        1
    },
    {
        "graceful-stop-authority-install",
        "scripts.provision_trusted_time_post_enrollment_graceful_stop_operator_authority",
        NULL,
        "install",
        1
    },
    {
        "operator-attestation-prepare",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts",
        NULL,
        "prepare-statement",
        1
    },
    {
        "operator-attestation-verify",
        "scripts.trusted_time_post_enrollment_operator_attestation_artifacts",
        NULL,
        "verify-signature",
        1
    },
    {
        "graceful-stop-decision-prepare",
        "scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts",
        NULL,
        "prepare-decision",
        1
    },
    {
        "graceful-stop-attestation-prepare",
        "scripts.trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts",
        NULL,
        "prepare-statement",
        1
    },
    {
        "graceful-stop-attestation-verify",
        "scripts.trusted_time_post_enrollment_graceful_stop_operator_attestation_artifacts",
        NULL,
        "verify-signature",
        1
    },
    {"runtime-diagnostic", "scripts.diagnose_trusted_time_runtime", NULL, NULL, 1},
    {"inspect", "scripts.inspect_trusted_time_qualification", NULL, NULL, 1},
#elif defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
    {"supervisor", "apps.trusted_time_supervisor.main", "main", NULL, 0},
    {
        "first-enrollment",
        "apps.trusted_time_supervisor.first_enrollment",
        "main",
        NULL,
        0
    },
    {
        "first-enrollment-recovery-release",
        "apps.trusted_time_supervisor.first_enrollment",
        "release_main",
        "--recover-pending",
        0
    },
    {
        "first-enrollment-release",
        "apps.trusted_time_supervisor.first_enrollment",
        "release_main",
        NULL,
        0
    },
    {
        "image-schema-contract",
        "apps.trusted_time_supervisor.image_schema_contract",
        "schema_contract_main",
        NULL,
        0
    },
    {
        "post-enrollment-persistent-barrier-read",
        "apps.trusted_time_supervisor.post_enrollment_read_probes",
        "persistent_barrier_main",
        NULL,
        0
    },
    {
        "post-enrollment-pre-effect-runtime-absence",
        "apps.trusted_time_supervisor.post_enrollment_read_probes",
        "pre_effect_runtime_absence_main",
        NULL,
        0
    },
    {
        "post-enrollment-release",
        "apps.trusted_time_supervisor.post_enrollment_release",
        "release_main",
        NULL,
        0
    },
    {
        "post-enrollment-runtime-state",
        "apps.trusted_time_supervisor.post_enrollment_runtime_state",
        "runtime_state_main",
        NULL,
        0
    },
    {
        "post-enrollment-staged-barrier-read",
        "apps.trusted_time_supervisor.post_enrollment_read_probes",
        "staged_barrier_main",
        NULL,
        0
    },
#elif defined(AQT_NATIVE_LAUNCHER_TEST_PROFILE)
    {"verify-images-build", "scripts.verify_trusted_time_images", NULL, "--build", 1},
    {"test-suite", "pytest", "console_main", NULL, 0},
#endif
};

static void
aqt_fail_before_python(const char *message)
{
    (void)fprintf(stderr, "trusted-time native launcher: %s\n", message);
    _exit(AQT_FAILURE_STATUS);
}

static void
aqt_fail_after_python(const char *message)
{
    if (PyErr_Occurred()) {
        PyErr_Print();
    }
    (void)fprintf(stderr, "trusted-time native launcher: %s\n", message);
    _exit(AQT_FAILURE_STATUS);
}

static void
aqt_ignore_sigpipe_before_python(void)
{
    struct sigaction disposition;

    memset(&disposition, 0, sizeof(disposition));
    disposition.sa_handler = SIG_IGN;
    if (sigemptyset(&disposition.sa_mask) < 0
        || sigaction(SIGPIPE, &disposition, NULL) < 0) {
        aqt_fail_before_python("the SIGPIPE disposition could not be installed");
    }
}

static const AqtTarget *
aqt_resolve_target(int argument_count, char **argument_values)
{
    size_t index;

    if (argument_count < 2 || argument_values == NULL
        || argument_values[1] == NULL || argument_values[1][0] == '\0') {
        aqt_fail_before_python("one exact policy target identifier is required");
    }
#ifdef AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE
    if (argument_count != 2) {
        aqt_fail_before_python("operational policy targets do not accept arguments");
    }
#endif
    for (index = 0U; index < sizeof(aqt_targets) / sizeof(aqt_targets[0]); index++) {
        if (strcmp(argument_values[1], aqt_targets[index].identifier) == 0) {
            return &aqt_targets[index];
        }
    }
    aqt_fail_before_python("the policy target identifier is not admitted");
    return NULL;
}

#ifdef AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE
static int
aqt_is_lower_hex_digest(const char *value)
{
    size_t index;

    if (value == NULL || strlen(value) != 64U) {
        return 0;
    }
    for (index = 0U; index < 64U; index++) {
        if (!((value[index] >= '0' && value[index] <= '9')
                || (value[index] >= 'a' && value[index] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}
#endif

static void
aqt_clear_environment(void)
{
    char name[256];
    size_t count = 0U;

    while (environ != NULL && environ[0] != NULL) {
        const char *separator = strchr(environ[0], '=');
        size_t length;

        if (separator == NULL) {
            aqt_fail_before_python("the inherited environment is malformed");
        }
        length = (size_t)(separator - environ[0]);
        if (length == 0U || length >= sizeof(name) || count >= 256U) {
            aqt_fail_before_python("the inherited environment exceeds its policy bound");
        }
        memcpy(name, environ[0], length);
        name[length] = '\0';
        if (unsetenv(name) != 0) {
            aqt_fail_before_python("the inherited environment could not be cleared");
        }
        count++;
    }
}

static void
aqt_sanitize_environment(const AqtTarget *target)
{
    static const char *digest_names[] = {
        "AQT_TRUSTED_TIME_EXPECTED_DATABASE_URL_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTHORITY_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTH_SECRET_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_SIGNING_KEY_SHA256",
    };
    char digest_values[4][65];
    size_t digest_count = 0U;
    size_t index;

#ifdef AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE
    if (strcmp(target->identifier, "supervisor") == 0) {
        digest_count = sizeof(digest_names) / sizeof(digest_names[0]);
        for (index = 0U; index < digest_count; index++) {
            const char *value = getenv(digest_names[index]);

            if (!aqt_is_lower_hex_digest(value)) {
                aqt_fail_before_python("a supervisor input digest is missing or invalid");
            }
            memcpy(digest_values[index], value, 65U);
        }
    }
#else
    (void)target;
#endif
    aqt_clear_environment();
    if (setenv("LANG", "C", 1) != 0
        || setenv("LC_ALL", "C", 1) != 0
        || setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1) != 0) {
        aqt_fail_before_python("the policy target environment could not be sanitized");
    }
    for (index = 0U; index < digest_count; index++) {
        if (setenv(digest_names[index], digest_values[index], 1) != 0) {
            aqt_fail_before_python("a supervisor input digest could not be restored");
        }
    }
}

static void
aqt_append_module_search_path(PyConfig *config, const char *path)
{
    wchar_t *decoded = Py_DecodeLocale(path, NULL);
    PyStatus status;

    if (decoded == NULL) {
        aqt_fail_before_python("an admitted Python search path could not be decoded");
    }
    status = PyWideStringList_Append(&config->module_search_paths, decoded);
    PyMem_RawFree(decoded);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }
}

static void
aqt_publish_target_arguments(
    const AqtTarget *target,
    int argument_count,
    char **argument_values
)
{
    PyObject *arguments;
    PyObject *value;
    Py_ssize_t output_index = 0;
    Py_ssize_t caller_index;
    Py_ssize_t output_count = (Py_ssize_t)argument_count - 1;

    if (target->fixed_argument != NULL) {
        output_count++;
    }
    arguments = PyList_New(output_count);
    if (arguments == NULL) {
        aqt_fail_after_python("the exact target argument vector could not be allocated");
    }
    value = PyUnicode_FromString(target->identifier);
    if (value == NULL) {
        Py_DECREF(arguments);
        aqt_fail_after_python("the policy target identifier could not be published");
    }
    PyList_SET_ITEM(arguments, output_index++, value);
    if (target->fixed_argument != NULL) {
        value = PyUnicode_FromString(target->fixed_argument);
        if (value == NULL) {
            Py_DECREF(arguments);
            aqt_fail_after_python("the fixed policy target argument could not be published");
        }
        PyList_SET_ITEM(arguments, output_index++, value);
    }
    for (caller_index = 2; caller_index < (Py_ssize_t)argument_count; caller_index++) {
        value = PyUnicode_DecodeFSDefault(argument_values[caller_index]);
        if (value == NULL) {
            Py_DECREF(arguments);
            aqt_fail_after_python("a policy target argument could not be decoded");
        }
        PyList_SET_ITEM(arguments, output_index++, value);
    }
    if (output_index != output_count || PySys_SetObject("argv", arguments) < 0) {
        Py_DECREF(arguments);
        aqt_fail_after_python("the exact policy target arguments could not be installed");
    }
    Py_DECREF(arguments);
}

static int
aqt_run_target(const AqtTarget *target)
{
    PyObject *module;
    PyObject *callable;
    PyObject *result;

    if (target->run_as_main != 0 || target->callable_name == NULL) {
        aqt_fail_after_python("the callable policy target mapping is invalid");
    }
    module = PyImport_ImportModule(target->module_name);
    if (module == NULL) {
        aqt_fail_after_python("the admitted policy target module could not be imported");
    }
    callable = PyObject_GetAttrString(module, target->callable_name);
    Py_DECREF(module);
    if (callable == NULL || !PyCallable_Check(callable)) {
        Py_XDECREF(callable);
        aqt_fail_after_python("the admitted policy target callable is invalid");
    }
    result = PyObject_CallNoArgs(callable);
    Py_DECREF(callable);
    if (result == NULL) {
        aqt_fail_after_python("the admitted policy target failed");
    }
#ifdef AQT_NATIVE_LAUNCHER_TEST_PROFILE
    if (!PyLong_Check(result) || PyLong_AsLong(result) != 0L) {
#else
    if (result != Py_None) {
#endif
        Py_DECREF(result);
        aqt_fail_after_python("the admitted policy target returned an invalid result");
    }
    Py_DECREF(result);
    if (Py_FinalizeEx() < 0) {
        return 120;
    }
    return 0;
}

static int
aqt_has_suffix(const char *value, const char *suffix)
{
    size_t value_length = strlen(value);
    size_t suffix_length = strlen(suffix);

    return value_length >= suffix_length
        && memcmp(value + value_length - suffix_length, suffix, suffix_length) == 0;
}

#ifndef AQT_NATIVE_LAUNCHER_TEST_PROFILE
static void
aqt_validate_root_owned_directory_chain(char *path)
{
    char *cursor;
    struct stat metadata;

    if (path[0] != '/') {
        aqt_fail_before_python("an admitted runtime path is not absolute");
    }
    for (cursor = path + 1; ; cursor++) {
        char saved;

        if (*cursor != '/' && *cursor != '\0') {
            continue;
        }
        saved = *cursor;
        *cursor = '\0';
        if (lstat(path, &metadata) < 0
            || !S_ISDIR(metadata.st_mode)
            || metadata.st_uid != 0
            || metadata.st_gid != 0
            || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            *cursor = saved;
            aqt_fail_before_python("an admitted runtime ancestor is mutable");
        }
        *cursor = saved;
        if (saved == '\0') {
            break;
        }
    }
}

static void
aqt_validate_root_owned_directory_literal(const char *literal)
{
    char canonical[PATH_MAX];

    if (strlen(literal) >= sizeof(canonical)
        || realpath(literal, canonical) == NULL
        || strcmp(canonical, literal) != 0) {
        aqt_fail_before_python("an admitted runtime directory is not canonical");
    }
    aqt_validate_root_owned_directory_chain(canonical);
}
#endif

#ifdef AQT_NATIVE_LAUNCHER_TEST_PROFILE
static int
aqt_is_exact_test_virtualenv_hook(DIR *directory, const char *name)
{
    static const char expected[] = "import _virtualenv";
    char payload[sizeof(expected)];
    struct stat metadata;
    ssize_t received;
    int descriptor;
    int close_result;

    if (strcmp(name, "_virtualenv.pth") != 0) {
        return 0;
    }
    descriptor = openat(
        dirfd(directory),
        name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );
    if (descriptor < 0
        || fstat(descriptor, &metadata) < 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_nlink != 1
        || metadata.st_uid != geteuid()
        || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0
        || metadata.st_size != (off_t)(sizeof(expected) - 1U)) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return 0;
    }
    received = read(descriptor, payload, sizeof(payload));
    close_result = close(descriptor);
    return received == (ssize_t)(sizeof(expected) - 1U)
        && close_result == 0
        && memcmp(payload, expected, sizeof(expected) - 1U) == 0;
}
#endif

static void
aqt_validate_no_startup_hooks(const char *site_packages)
{
    DIR *directory;
    struct dirent *entry;
    int operation_errno = 0;

    errno = 0;
    directory = opendir(site_packages);
    if (directory == NULL) {
        aqt_fail_before_python("site-packages cannot be inspected");
    }
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            operation_errno = errno;
            break;
        }
        if (strcmp(entry->d_name, "sitecustomize.py") == 0
            || strcmp(entry->d_name, "usercustomize.py") == 0) {
            (void)closedir(directory);
            aqt_fail_before_python("site-packages contains an automatic startup hook");
        }
        if (aqt_has_suffix(entry->d_name, ".pth")) {
#ifdef AQT_NATIVE_LAUNCHER_TEST_PROFILE
            if (aqt_is_exact_test_virtualenv_hook(directory, entry->d_name)) {
                continue;
            }
#endif
            (void)closedir(directory);
            aqt_fail_before_python("site-packages contains an automatic startup hook");
        }
    }
    if (closedir(directory) < 0 || operation_errno != 0) {
        aqt_fail_before_python("site-packages inspection was ambiguous");
    }
}

static void
aqt_resolve_layout(
    int argument_count,
    char **argument_values,
    char launcher_path[PATH_MAX],
    char prefix_path[PATH_MAX],
    char site_packages_path[PATH_MAX],
    char source_root_path[PATH_MAX],
    char wrapper_path[PATH_MAX]
)
{
    static const char launcher_suffix[] = "/bin/" AQT_LAUNCHER_BASENAME;
    struct stat metadata;
    size_t launcher_length;
    size_t suffix_length = sizeof(launcher_suffix) - 1U;
    size_t prefix_length;
    int site_length;
#ifdef AQT_HAS_SOURCE_ROOT
    int source_root_length;
#endif
    int wrapper_length;

    if (argument_count < 2 || argument_values == NULL || argument_values[0] == NULL
        || argument_values[0][0] != '/') {
        aqt_fail_before_python("the launcher requires an absolute executable and a target");
    }
    if (realpath(argument_values[0], launcher_path) == NULL
        || strcmp(launcher_path, argument_values[0]) != 0) {
        aqt_fail_before_python("the launcher executable path is not canonical");
    }
    launcher_length = strlen(launcher_path);
    if (launcher_length <= suffix_length
        || memcmp(
            launcher_path + launcher_length - suffix_length,
            launcher_suffix,
            suffix_length
        ) != 0) {
        aqt_fail_before_python("the launcher executable path has an invalid layout");
    }
    if (lstat(launcher_path, &metadata) < 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_nlink != 1) {
        aqt_fail_before_python("the launcher executable metadata is invalid");
    }
#ifndef AQT_NATIVE_LAUNCHER_TEST_PROFILE
    if (metadata.st_uid != 0 || metadata.st_gid != 0
        || (metadata.st_mode & 07777) != 0555) {
        aqt_fail_before_python("the production launcher ownership is invalid");
    }
    {
        char launcher_directory[PATH_MAX];
        char *separator;

        memcpy(launcher_directory, launcher_path, strlen(launcher_path) + 1U);
        separator = strrchr(launcher_directory, '/');
        if (separator == NULL || separator == launcher_directory) {
            aqt_fail_before_python("the production launcher directory is invalid");
        }
        *separator = '\0';
        aqt_validate_root_owned_directory_literal(launcher_directory);
    }
#else
    if (metadata.st_uid != geteuid()
        || ((metadata.st_mode & 07777) != 0555
            && (metadata.st_mode & 07777) != 0755)) {
        aqt_fail_before_python("the test launcher ownership is invalid");
    }
#endif
    prefix_length = launcher_length - suffix_length;
    if (prefix_length == 0U || prefix_length >= PATH_MAX) {
        aqt_fail_before_python("the launcher prefix is invalid");
    }
    memcpy(prefix_path, launcher_path, prefix_length);
    prefix_path[prefix_length] = '\0';
#ifndef AQT_NATIVE_LAUNCHER_TEST_PROFILE
    if (strcmp(prefix_path, AQT_TRUSTED_TIME_PREFIX) != 0) {
        aqt_fail_before_python("the launcher prefix is not the fixed production runtime");
    }
    aqt_validate_root_owned_directory_chain(prefix_path);
    aqt_validate_root_owned_directory_literal(AQT_PYTHON_HOME);
    aqt_validate_root_owned_directory_literal(AQT_PYTHON_STDLIB);
    aqt_validate_root_owned_directory_literal(AQT_PYTHON_DYNLOAD);
#endif
    site_length = snprintf(
        site_packages_path,
        PATH_MAX,
        "%s/lib/python%d.%d/site-packages",
        prefix_path,
        PY_MAJOR_VERSION,
        PY_MINOR_VERSION
    );
#ifdef AQT_HAS_SOURCE_ROOT
    source_root_length = snprintf(source_root_path, PATH_MAX, "%s", AQT_SOURCE_ROOT);
    wrapper_length = snprintf(
        wrapper_path,
        PATH_MAX,
        "%s/packages/adapters/trusted_time/_owned_file_descriptor.py",
        source_root_path
    );
    if (site_length <= 0 || site_length >= PATH_MAX
        || source_root_length <= 0 || source_root_length >= PATH_MAX
        || wrapper_length <= 0 || wrapper_length >= PATH_MAX) {
#else
    source_root_path[0] = '\0';
    wrapper_length = snprintf(
        wrapper_path,
        PATH_MAX,
        "%s/packages/adapters/trusted_time/_owned_file_descriptor.py",
        site_packages_path
    );
    if (site_length <= 0 || site_length >= PATH_MAX
        || wrapper_length <= 0 || wrapper_length >= PATH_MAX) {
#endif
        aqt_fail_before_python("the launcher runtime path is too long");
    }
    if (lstat(site_packages_path, &metadata) < 0
        || !S_ISDIR(metadata.st_mode)
        || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        aqt_fail_before_python("the launcher site-packages metadata is invalid");
    }
#ifndef AQT_NATIVE_LAUNCHER_TEST_PROFILE
    if (metadata.st_uid != 0 || metadata.st_gid != 0) {
        aqt_fail_before_python("the production site-packages ownership is invalid");
    }
    aqt_validate_root_owned_directory_literal(site_packages_path);
#else
    if (metadata.st_uid != geteuid()) {
        aqt_fail_before_python("the test site-packages ownership is invalid");
    }
#endif
#ifdef AQT_HAS_SOURCE_ROOT
    if (realpath(AQT_SOURCE_ROOT, source_root_path) == NULL
        || strcmp(source_root_path, AQT_SOURCE_ROOT) != 0
        || lstat(source_root_path, &metadata) < 0
        || !S_ISDIR(metadata.st_mode)
        || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        aqt_fail_before_python("the reviewed source root is invalid");
    }
#ifndef AQT_NATIVE_LAUNCHER_TEST_PROFILE
    if (metadata.st_uid != 0 || metadata.st_gid != 0) {
        aqt_fail_before_python("the production source-root ownership is invalid");
    }
    aqt_validate_root_owned_directory_chain(source_root_path);
#else
    if (metadata.st_uid != geteuid()) {
        aqt_fail_before_python("the test source-root ownership is invalid");
    }
#endif
    if (chdir(source_root_path) < 0) {
        aqt_fail_before_python("the reviewed source root cannot become the working directory");
    }
#else
    if (chdir("/") < 0) {
        aqt_fail_before_python("the operational working directory is unavailable");
    }
#endif
    aqt_validate_no_startup_hooks(site_packages_path);
}

static void
aqt_require_isolated_runtime(
    const char *launcher_path,
    const char *prefix_path,
    const char *site_packages_path,
    const char *source_root_path
)
{
    PyObject *flags;
    PyObject *isolated;
    PyObject *no_site;
    PyObject *no_user_site;
    PyObject *dont_write_bytecode;
    PyObject *sys_path;
    PyObject *prefix;

    if (Py_GetProgramFullPath() == NULL || Py_GetProgramFullPath()[0] == L'\0') {
        aqt_fail_after_python("the Python program path is unavailable");
    }
    flags = PySys_GetObject("flags");
    if (flags == NULL) {
        aqt_fail_after_python("the Python runtime flags are unavailable");
    }
    isolated = PyObject_GetAttrString(flags, "isolated");
    no_site = PyObject_GetAttrString(flags, "no_site");
    no_user_site = PyObject_GetAttrString(flags, "no_user_site");
    dont_write_bytecode = PyObject_GetAttrString(flags, "dont_write_bytecode");
    if (isolated == NULL || no_site == NULL || no_user_site == NULL
        || dont_write_bytecode == NULL
        || PyLong_AsLong(isolated) != 1L
        || PyLong_AsLong(no_site) != 1L
        || PyLong_AsLong(no_user_site) != 1L
        || PyLong_AsLong(dont_write_bytecode) != 1L) {
        Py_XDECREF(dont_write_bytecode);
        Py_XDECREF(no_user_site);
        Py_XDECREF(no_site);
        Py_XDECREF(isolated);
        aqt_fail_after_python("the Python runtime is not isolated");
    }
    Py_DECREF(dont_write_bytecode);
    Py_DECREF(no_user_site);
    Py_DECREF(no_site);
    Py_DECREF(isolated);

    sys_path = PySys_GetObject("path");
    if (sys_path == NULL || !PyList_CheckExact(sys_path)
#ifdef AQT_HAS_SOURCE_ROOT
        || PyList_GET_SIZE(sys_path) != 4
#else
        || PyList_GET_SIZE(sys_path) != 3
#endif
        || !PyUnicode_CheckExact(PyList_GET_ITEM(sys_path, 0))
        || !PyUnicode_CheckExact(PyList_GET_ITEM(sys_path, 1))
        || !PyUnicode_CheckExact(PyList_GET_ITEM(sys_path, 2))
        || PyUnicode_CompareWithASCIIString(
            PyList_GET_ITEM(sys_path, 0),
            AQT_PYTHON_STDLIB
        ) != 0
        || PyUnicode_CompareWithASCIIString(
            PyList_GET_ITEM(sys_path, 1),
            AQT_PYTHON_DYNLOAD
        ) != 0
        || PyUnicode_CompareWithASCIIString(
            PyList_GET_ITEM(sys_path, 2),
#ifdef AQT_HAS_SOURCE_ROOT
            source_root_path
#else
            site_packages_path
#endif
        ) != 0
#ifdef AQT_HAS_SOURCE_ROOT
        || !PyUnicode_CheckExact(PyList_GET_ITEM(sys_path, 3))
        || PyUnicode_CompareWithASCIIString(
            PyList_GET_ITEM(sys_path, 3),
            site_packages_path
        ) != 0
#else
        || source_root_path[0] != '\0'
#endif
    ) {
        aqt_fail_after_python("the isolated Python search path is invalid");
    }

    prefix = PyUnicode_DecodeFSDefault(prefix_path);
    if (prefix == NULL
        || PySys_SetObject("prefix", prefix) < 0
        || PySys_SetObject("exec_prefix", prefix) < 0) {
        Py_XDECREF(prefix);
        aqt_fail_after_python("the fixed Python runtime prefix could not be established");
    }
    Py_DECREF(prefix);

    {
        PyObject *executable = PySys_GetObject("executable");
        PyObject *expected = PyUnicode_DecodeFSDefault(launcher_path);
        int equal;

        if (executable == NULL || expected == NULL || !PyUnicode_CheckExact(executable)) {
            Py_XDECREF(expected);
            aqt_fail_after_python("the Python executable identity is unavailable");
        }
        equal = PyObject_RichCompareBool(executable, expected, Py_EQ);
        Py_DECREF(expected);
        if (equal != 1) {
            aqt_fail_after_python("the Python executable identity changed");
        }
    }
}

static void
aqt_execute_embedded_wrapper(const char *wrapper_path)
{
    PyObject *native_module;
    PyObject *native_dictionary;
    PyObject *wrapper_module;
    PyObject *wrapper_dictionary;
    PyObject *wrapper_file;
    PyObject *wrapper_package;
    PyObject *compiled;
    PyObject *result;
    PyObject *modules = PyImport_GetModuleDict();

    if (modules == NULL
        || PyDict_GetItemString(modules, AQT_NATIVE_MODULE_NAME) != NULL
        || PyDict_GetItemString(modules, AQT_WRAPPER_MODULE_NAME) != NULL) {
        aqt_fail_after_python("the native launcher namespace was prepopulated");
    }
    native_module = PyImport_ImportModule(AQT_NATIVE_MODULE_NAME);
    if (native_module == NULL
        || PyDict_GetItemString(modules, AQT_NATIVE_MODULE_NAME) != native_module
        || PyDict_DelItemString(modules, AQT_NATIVE_MODULE_NAME) < 0
        || PyDict_GetItemString(modules, AQT_NATIVE_MODULE_NAME) != NULL) {
        Py_XDECREF(native_module);
        aqt_fail_after_python("the native builtin could not be captured exactly");
    }
    native_dictionary = PyModule_GetDict(native_module);
    if (native_dictionary == NULL
        || PyDict_DelItemString(native_dictionary, "__loader__") < 0
        || PyDict_DelItemString(native_dictionary, "__package__") < 0
        || PyDict_DelItemString(native_dictionary, "__spec__") < 0
        || PyDict_GetItemString(native_dictionary, "__loader__") != NULL
        || PyDict_GetItemString(native_dictionary, "__package__") != NULL
        || PyDict_GetItemString(native_dictionary, "__spec__") != NULL) {
        Py_DECREF(native_module);
        aqt_fail_after_python("the native builtin metadata could not be removed");
    }

    wrapper_module = PyModule_New(AQT_WRAPPER_MODULE_NAME);
    wrapper_file = PyUnicode_DecodeFSDefault(wrapper_path);
    wrapper_package = PyUnicode_FromString(AQT_WRAPPER_PACKAGE_NAME);
    if (wrapper_module == NULL || wrapper_file == NULL || wrapper_package == NULL) {
        Py_XDECREF(wrapper_package);
        Py_XDECREF(wrapper_file);
        Py_XDECREF(wrapper_module);
        Py_DECREF(native_module);
        aqt_fail_after_python("the embedded wrapper module could not be allocated");
    }
    wrapper_dictionary = PyModule_GetDict(wrapper_module);
    if (wrapper_dictionary == NULL
        || PyDict_SetItemString(wrapper_dictionary, "__file__", wrapper_file) < 0
        || PyDict_SetItemString(wrapper_dictionary, "__package__", wrapper_package) < 0
        || PyDict_SetItemString(
            wrapper_dictionary,
            "_AQT_PRELOADED_NATIVE_MODULE",
            native_module
        ) < 0
        || PyDict_SetItemString(modules, AQT_WRAPPER_MODULE_NAME, wrapper_module) < 0) {
        Py_DECREF(wrapper_package);
        Py_DECREF(wrapper_file);
        Py_DECREF(wrapper_module);
        Py_DECREF(native_module);
        aqt_fail_after_python("the embedded wrapper handoff could not be established");
    }
    Py_DECREF(wrapper_package);
    Py_DECREF(wrapper_file);
    Py_DECREF(native_module);

    compiled = Py_CompileString(
        (const char *)aqt_embedded_owned_file_descriptor_wrapper,
        wrapper_path,
        Py_file_input
    );
    if (compiled == NULL) {
        (void)PyDict_DelItemString(modules, AQT_WRAPPER_MODULE_NAME);
        Py_DECREF(wrapper_module);
        aqt_fail_after_python("the embedded wrapper could not be compiled");
    }
    result = PyEval_EvalCode(compiled, wrapper_dictionary, wrapper_dictionary);
    Py_DECREF(compiled);
    if (result == NULL) {
        (void)PyDict_DelItemString(modules, AQT_WRAPPER_MODULE_NAME);
        Py_DECREF(wrapper_module);
        aqt_fail_after_python("the embedded wrapper could not be initialized");
    }
    Py_DECREF(result);
    if (PyDict_DelItemString(
            wrapper_dictionary,
            "_AQT_PRELOADED_NATIVE_MODULE"
        ) < 0
        || PyDict_GetItemString(modules, AQT_NATIVE_MODULE_NAME) != NULL
        || PyDict_GetItemString(modules, AQT_WRAPPER_MODULE_NAME) != wrapper_module
        || PyDict_GetItemString(
            wrapper_dictionary,
            "_AQT_PRELOADED_NATIVE_MODULE"
        ) != NULL) {
        Py_DECREF(wrapper_module);
        aqt_fail_after_python("the embedded wrapper namespace changed");
    }
    Py_DECREF(wrapper_module);
}

#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
static void
aqt_execute_embedded_process_wrapper(const char *wrapper_path)
{
    PyObject *native_module;
    PyObject *native_dictionary;
    PyObject *wrapper_module;
    PyObject *wrapper_dictionary;
    PyObject *wrapper_file;
    PyObject *wrapper_package;
    PyObject *compiled;
    PyObject *result;
    PyObject *modules = PyImport_GetModuleDict();

    if (modules == NULL
        || PyDict_GetItemString(modules, AQT_PROCESS_NATIVE_MODULE_NAME) != NULL
        || PyDict_GetItemString(modules, AQT_PROCESS_WRAPPER_MODULE_NAME) != NULL) {
        aqt_fail_after_python("the process launcher namespace was prepopulated");
    }
    native_module = PyImport_ImportModule(AQT_PROCESS_NATIVE_MODULE_NAME);
    if (native_module == NULL
        || PyDict_GetItemString(
            modules,
            AQT_PROCESS_NATIVE_MODULE_NAME
        ) != native_module
        || PyDict_DelItemString(modules, AQT_PROCESS_NATIVE_MODULE_NAME) < 0
        || PyDict_GetItemString(modules, AQT_PROCESS_NATIVE_MODULE_NAME) != NULL) {
        Py_XDECREF(native_module);
        aqt_fail_after_python("the native process builtin could not be captured exactly");
    }
    native_dictionary = PyModule_GetDict(native_module);
    if (native_dictionary == NULL
        || PyDict_DelItemString(native_dictionary, "__loader__") < 0
        || PyDict_DelItemString(native_dictionary, "__package__") < 0
        || PyDict_DelItemString(native_dictionary, "__spec__") < 0
        || PyDict_GetItemString(native_dictionary, "__loader__") != NULL
        || PyDict_GetItemString(native_dictionary, "__package__") != NULL
        || PyDict_GetItemString(native_dictionary, "__spec__") != NULL) {
        Py_DECREF(native_module);
        aqt_fail_after_python("the native process builtin metadata could not be removed");
    }

    wrapper_module = PyModule_New(AQT_PROCESS_WRAPPER_MODULE_NAME);
    wrapper_file = PyUnicode_DecodeFSDefault(wrapper_path);
    wrapper_package = PyUnicode_FromString(AQT_WRAPPER_PACKAGE_NAME);
    if (wrapper_module == NULL || wrapper_file == NULL || wrapper_package == NULL) {
        Py_XDECREF(wrapper_package);
        Py_XDECREF(wrapper_file);
        Py_XDECREF(wrapper_module);
        Py_DECREF(native_module);
        aqt_fail_after_python("the embedded process wrapper could not be allocated");
    }
    wrapper_dictionary = PyModule_GetDict(wrapper_module);
    if (wrapper_dictionary == NULL
        || PyDict_SetItemString(wrapper_dictionary, "__file__", wrapper_file) < 0
        || PyDict_SetItemString(wrapper_dictionary, "__package__", wrapper_package) < 0
        || PyDict_SetItemString(
            wrapper_dictionary,
            AQT_PROCESS_HANDOFF_NAME,
            native_module
        ) < 0
        || PyDict_SetItemString(
            modules,
            AQT_PROCESS_WRAPPER_MODULE_NAME,
            wrapper_module
        ) < 0) {
        Py_DECREF(wrapper_package);
        Py_DECREF(wrapper_file);
        Py_DECREF(wrapper_module);
        Py_DECREF(native_module);
        aqt_fail_after_python("the embedded process handoff could not be established");
    }
    Py_DECREF(wrapper_package);
    Py_DECREF(wrapper_file);
    Py_DECREF(native_module);

    compiled = Py_CompileString(
        (const char *)aqt_embedded_bounded_process_wrapper,
        wrapper_path,
        Py_file_input
    );
    if (compiled == NULL) {
        (void)PyDict_DelItemString(modules, AQT_PROCESS_WRAPPER_MODULE_NAME);
        Py_DECREF(wrapper_module);
        aqt_fail_after_python("the embedded process wrapper could not be compiled");
    }
    result = PyEval_EvalCode(compiled, wrapper_dictionary, wrapper_dictionary);
    Py_DECREF(compiled);
    if (result == NULL) {
        (void)PyDict_DelItemString(modules, AQT_PROCESS_WRAPPER_MODULE_NAME);
        Py_DECREF(wrapper_module);
        aqt_fail_after_python("the embedded process wrapper could not be initialized");
    }
    Py_DECREF(result);
    if (PyDict_DelItemString(wrapper_dictionary, AQT_PROCESS_HANDOFF_NAME) < 0
        || PyDict_GetItemString(modules, AQT_PROCESS_NATIVE_MODULE_NAME) != NULL
        || PyDict_GetItemString(
            modules,
            AQT_PROCESS_WRAPPER_MODULE_NAME
        ) != wrapper_module
        || PyDict_GetItemString(
            wrapper_dictionary,
            AQT_PROCESS_HANDOFF_NAME
        ) != NULL) {
        Py_DECREF(wrapper_module);
        aqt_fail_after_python("the embedded process wrapper namespace changed");
    }
    Py_DECREF(wrapper_module);
}
#endif

int
main(int argument_count, char **argument_values)
{
    char launcher_path[PATH_MAX];
    char prefix_path[PATH_MAX];
    char site_packages_path[PATH_MAX];
    char source_root_path[PATH_MAX];
    char wrapper_path[PATH_MAX];
#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
    char process_wrapper_path[PATH_MAX];
#endif
    PyConfig config;
    PyStatus status;
    const AqtTarget *target;

#if PY_MAJOR_VERSION != 3 || (PY_MINOR_VERSION != 12 && PY_MINOR_VERSION != 13)
#error "The trusted-time native launcher supports only CPython 3.12 and 3.13."
#endif
    aqt_ignore_sigpipe_before_python();
    target = aqt_resolve_target(argument_count, argument_values);
    aqt_resolve_layout(
        argument_count,
        argument_values,
        launcher_path,
        prefix_path,
        site_packages_path,
        source_root_path,
        wrapper_path
    );
#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
    {
        int process_wrapper_length = snprintf(
            process_wrapper_path,
            PATH_MAX,
            "%s/packages/adapters/trusted_time/_bounded_process.py",
            source_root_path
        );

        if (process_wrapper_length <= 0 || process_wrapper_length >= PATH_MAX) {
            aqt_fail_before_python("the bounded-process wrapper path is invalid");
        }
    }
#endif
    aqt_sanitize_environment(target);
    if (PyImport_AppendInittab(
            AQT_NATIVE_MODULE_NAME,
            PyInit__native_owned_file_descriptor
        ) != 0) {
        aqt_fail_before_python("the native builtin could not be registered");
    }
#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
    if (PyImport_AppendInittab(
            AQT_PROCESS_NATIVE_MODULE_NAME,
            PyInit__native_bounded_process
        ) != 0) {
        aqt_fail_before_python("the native process builtin could not be registered");
    }
#endif

    PyConfig_InitIsolatedConfig(&config);
    config.isolated = 1;
    config.use_environment = 0;
    config.site_import = 0;
    config.user_site_directory = 0;
    config.write_bytecode = 0;
    config.safe_path = 1;
    config.parse_argv = 0;
    config.module_search_paths_set = 1;
    status = PyConfig_SetBytesString(&config, &config.program_name, launcher_path);
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetBytesString(&config, &config.executable, launcher_path);
    }
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetBytesString(&config, &config.home, AQT_PYTHON_HOME);
    }
    if (!PyStatus_Exception(status) && target->run_as_main != 0) {
        status = PyConfig_SetBytesString(
            &config,
            &config.run_module,
            target->module_name
        );
    }
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetBytesArgv(&config, argument_count, argument_values);
    }
    if (!PyStatus_Exception(status)) {
        status = PyConfig_SetString(&config, &config.pycache_prefix, L"/dev/null");
    }
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        Py_ExitStatusException(status);
    }
    aqt_append_module_search_path(&config, AQT_PYTHON_STDLIB);
    aqt_append_module_search_path(&config, AQT_PYTHON_DYNLOAD);
#ifdef AQT_HAS_SOURCE_ROOT
    aqt_append_module_search_path(&config, source_root_path);
#endif
    aqt_append_module_search_path(&config, site_packages_path);
    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }

    aqt_require_isolated_runtime(
        launcher_path,
        prefix_path,
        site_packages_path,
        source_root_path
    );
    aqt_execute_embedded_wrapper(wrapper_path);
#if !defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)
    aqt_execute_embedded_process_wrapper(process_wrapper_path);
#endif
    aqt_publish_target_arguments(target, argument_count, argument_values);
    if (target->run_as_main != 0) {
        return Py_RunMain();
    }
    return aqt_run_target(target);
}
