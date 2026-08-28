#define _POSIX_C_SOURCE 200809L

#include "trusted_time_v2_role_launcher.h"

#include "trusted_time_graceful_stop_v2_signer.h"
#include "trusted_time_v2_fork_guard.h"
#include "trusted_time_v2_seccomp.h"

#include <Python.h>

#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
#include "trusted_time_graceful_stop_v2_endpoint.h"
#endif

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if (defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE) \
     + defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)) != 1
#error "Exactly one trusted-time lifecycle-v2 role launcher profile must be selected."
#endif

#if defined(AQT_TRUSTED_TIME_V2_HOST_PROFILE)
#define AQT_ROLE_NAME "host"
#define AQT_ROLE_EXECUTABLE \
    "/opt/autoquant/trusted-time-graceful-stop-v2-host/bin/" \
    "autoquant-trusted-time-graceful-stop-v2-host"
#define AQT_ROLE_BASENAME "autoquant-trusted-time-graceful-stop-v2-host"
#define AQT_ROLE_IMPORT_ROOT \
    "/opt/autoquant/trusted-time-graceful-stop-v2-host/lib/python"
#define AQT_ROLE_ENTRY_MODULE "autoquant_trusted_time_v2_host_entry"
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE)
#define AQT_ROLE_NAME "supervisor"
#define AQT_ROLE_EXECUTABLE \
    "/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/bin/" \
    "autoquant-trusted-time-graceful-stop-v2-supervisor"
#define AQT_ROLE_BASENAME "autoquant-trusted-time-graceful-stop-v2-supervisor"
#define AQT_ROLE_IMPORT_ROOT \
    "/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/lib/python"
#define AQT_ROLE_ENTRY_MODULE "autoquant_trusted_time_v2_supervisor_entry"
#else
#define AQT_ROLE_NAME "recovery"
#define AQT_ROLE_EXECUTABLE \
    "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/bin/" \
    "autoquant-trusted-time-graceful-stop-v2-recovery"
#define AQT_ROLE_BASENAME "autoquant-trusted-time-graceful-stop-v2-recovery"
#define AQT_ROLE_IMPORT_ROOT \
    "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python"
#define AQT_ROLE_ENTRY_MODULE "autoquant_trusted_time_v2_recovery_entry"
#endif

#ifdef AQT_TRUSTED_TIME_V2_CANDIDATE_CLOSED_RUNTIME
#ifndef AQT_TRUSTED_TIME_V2_TEST_ROLE_IMPORT_ROOT
#error "A candidate role launcher requires one exact test import root."
#endif
#undef AQT_ROLE_IMPORT_ROOT
#define AQT_ROLE_IMPORT_ROOT AQT_TRUSTED_TIME_V2_TEST_ROLE_IMPORT_ROOT
#endif

#ifndef AQT_TRUSTED_TIME_V2_PYTHON_HOME
#error "The fixed Python home must be compiled into each role launcher."
#endif
#ifndef AQT_TRUSTED_TIME_V2_PYTHON_STDLIB
#error "The fixed Python standard-library root must be compiled into each role launcher."
#endif
#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE) \
    && !defined(AQT_TRUSTED_TIME_V2_PYTHON_DYNLOAD)
#error "Normal role launchers require one fixed dynamic-extension root."
#endif

#define AQT_FAILURE_STATUS 191
#define AQT_MAXIMUM_ENVIRONMENT_ENTRIES 256U

enum {
    AQT_BOOTSTRAP_START = 0,
    AQT_BOOTSTRAP_GUARD_READY = 1,
    AQT_BOOTSTRAP_SECCOMP_READY = 2,
    AQT_BOOTSTRAP_SIGNER_READY = 3,
    AQT_BOOTSTRAP_ENDPOINT_READY = 4,
};

static int aqt_bootstrap_state = AQT_BOOTSTRAP_START;

extern char **environ;

static void
aqt_fail(const char *message)
{
    (void)fprintf(
        stderr,
        "trusted-time lifecycle-v2 %s launcher: %s\n",
        AQT_ROLE_NAME,
        message
    );
    _exit(AQT_FAILURE_STATUS);
}

static const char *
aqt_basename(const char *path)
{
    const char *separator;

    if (path == NULL) {
        return NULL;
    }
    separator = strrchr(path, '/');
    return separator == NULL ? path : separator + 1;
}

#ifndef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
static void
aqt_validate_ancestors(char path[PATH_MAX], uid_t expected_uid, gid_t expected_gid)
{
    char *cursor;
    struct stat metadata;

    if (path[0] != '/') {
        aqt_fail("the executable path is not absolute");
    }
    for (cursor = path + 1; ; cursor++) {
        char saved;

        if (*cursor != '/' && *cursor != '\0') {
            continue;
        }
        saved = *cursor;
        *cursor = '\0';
        if (lstat(path, &metadata) != 0
            || !S_ISDIR(metadata.st_mode)
            || metadata.st_uid != expected_uid
            || metadata.st_gid != expected_gid
            || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
            *cursor = saved;
            aqt_fail("an executable ancestor is not admitted");
        }
        *cursor = saved;
        if (saved == '\0') {
            break;
        }
    }
}
#endif

static void
aqt_validate_executable(int argument_count, char **argument_values)
{
    char canonical[PATH_MAX];
#ifndef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
    char ancestors[PATH_MAX];
#endif
    const char *presented;
    struct stat metadata;
    uid_t expected_uid = 0;
#ifndef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
    gid_t expected_gid = 0;
#endif

    if (argument_count != 1 || argument_values == NULL
        || argument_values[0] == NULL || argument_values[0][0] != '/') {
        aqt_fail("exactly one absolute argv[0] and no arguments are required");
    }
    presented = argument_values[0];
    if (realpath(presented, canonical) == NULL || strcmp(canonical, presented) != 0) {
        aqt_fail("the executable path is not canonical");
    }
    if (lstat(canonical, &metadata) != 0
        || !S_ISREG(metadata.st_mode)
        || metadata.st_nlink != 1) {
        aqt_fail("the executable inode is not admitted");
    }
#ifdef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
    expected_uid = geteuid();
    if (strcmp(aqt_basename(canonical), AQT_ROLE_BASENAME) != 0
        || metadata.st_uid != expected_uid
        || ((metadata.st_mode & 07777) != 0555
            && (metadata.st_mode & 07777) != 0755)) {
        aqt_fail("the portable-test executable metadata is invalid");
    }
#else
    if (strcmp(canonical, AQT_ROLE_EXECUTABLE) != 0
        || metadata.st_uid != 0 || metadata.st_gid != 0
        || (metadata.st_mode & 07777) != 0555) {
        aqt_fail("the fixed executable identity is invalid");
    }
#endif
#ifndef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
    if (strlen(canonical) >= sizeof(ancestors)) {
        aqt_fail("the executable path exceeds its bound");
    }
    memcpy(ancestors, canonical, strlen(canonical) + 1U);
    {
        char *separator = strrchr(ancestors, '/');
        if (separator == NULL || separator == ancestors) {
            aqt_fail("the executable directory is invalid");
        }
        *separator = '\0';
    }
    aqt_validate_ancestors(ancestors, expected_uid, expected_gid);
#endif
}

static void
aqt_clear_environment(void)
{
    char name[256];
    size_t count = 0U;

    while (environ != NULL && environ[0] != NULL) {
        const char *separator = strchr(environ[0], '=');
        size_t length;

        if (separator == NULL) {
            aqt_fail("the inherited environment is malformed");
        }
        length = (size_t)(separator - environ[0]);
        if (length == 0U || length >= sizeof(name)
            || count >= AQT_MAXIMUM_ENVIRONMENT_ENTRIES) {
            aqt_fail("the inherited environment exceeds its policy bound");
        }
        memcpy(name, environ[0], length);
        name[length] = '\0';
        if (unsetenv(name) != 0) {
            aqt_fail("the inherited environment could not be cleared");
        }
        count++;
    }
    if (setenv("LANG", "C", 1) != 0
        || setenv("LC_ALL", "C", 1) != 0
        || setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1) != 0) {
        aqt_fail("the fixed environment could not be installed");
    }
}

static void
aqt_install_sigpipe_disposition(void)
{
    struct sigaction disposition;

    memset(&disposition, 0, sizeof(disposition));
    disposition.sa_handler = SIG_IGN;
    if (sigemptyset(&disposition.sa_mask) != 0
        || sigaction(SIGPIPE, &disposition, NULL) != 0) {
        aqt_fail("the SIGPIPE disposition could not be installed");
    }
}

static void
aqt_validate_import_root(void)
{
    char canonical[PATH_MAX];
    struct stat metadata;

    if (realpath(AQT_ROLE_IMPORT_ROOT, canonical) == NULL
        || strcmp(canonical, AQT_ROLE_IMPORT_ROOT) != 0
        || lstat(canonical, &metadata) != 0
        || !S_ISDIR(metadata.st_mode)
        || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        aqt_fail("the fixed role import root is not admitted");
    }
#ifdef AQT_TRUSTED_TIME_V2_CANDIDATE_CLOSED_RUNTIME
    if (metadata.st_uid != geteuid()) {
#else
    if (metadata.st_uid != 0 || metadata.st_gid != 0) {
#endif
        aqt_fail("the fixed role import root owner is not admitted");
    }
}

static int
aqt_append_module_search_path(PyConfig *config, const char *path)
{
    wchar_t *decoded;
    PyStatus status;

    decoded = Py_DecodeLocale(path, NULL);
    if (decoded == NULL) {
        return -1;
    }
    status = PyWideStringList_Append(&config->module_search_paths, decoded);
    PyMem_RawFree(decoded);
    return PyStatus_Exception(status) ? -1 : 0;
}

static int
aqt_run_fixed_entry(void)
{
    PyObject *module = NULL;
    PyObject *callable = NULL;
    PyObject *result = NULL;
    int status = -1;

    module = PyImport_ImportModule(AQT_ROLE_ENTRY_MODULE);
    if (module == NULL) {
        goto cleanup;
    }
    callable = PyObject_GetAttrString(module, "run");
    if (callable == NULL || !PyCallable_Check(callable)) {
        goto cleanup;
    }
    result = PyObject_CallNoArgs(callable);
    if (result != Py_None) {
        goto cleanup;
    }
    status = 0;
cleanup:
    Py_XDECREF(result);
    Py_XDECREF(callable);
    Py_XDECREF(module);
    return status;
}

/* These tiny adapters are the sole ABI reconciliation points for owner lanes. */
static int
aqt_initialize_fork_guard(void)
{
    if (aqt_bootstrap_state != AQT_BOOTSTRAP_START) {
        return -1;
    }
    if (aqt_trusted_time_v2_fork_guard_initialize_before_python() != 0
        || aqt_trusted_time_v2_fork_guard_is_poisoned() != 0) {
        return -1;
    }
    aqt_bootstrap_state = AQT_BOOTSTRAP_GUARD_READY;
    return 0;
}

static int
aqt_initialize_signer(void)
{
    if (aqt_bootstrap_state != AQT_BOOTSTRAP_SECCOMP_READY
        || aqt_trusted_time_v2_signer_initialize_before_python() != 0) {
        return -1;
    }
    aqt_bootstrap_state = AQT_BOOTSTRAP_SIGNER_READY;
    return 0;
}

#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
static int
aqt_initialize_endpoint(void)
{
    if (aqt_bootstrap_state != AQT_BOOTSTRAP_SIGNER_READY
        || aqt_trusted_time_graceful_stop_v2_endpoint_initialize_before_python() != 0) {
        return -1;
    }
    aqt_bootstrap_state = AQT_BOOTSTRAP_ENDPOINT_READY;
    return 0;
}
#endif

static int
aqt_enter_fixed_runtime(int argument_count, char **argument_values)
{
    PyConfig config;
    PyStatus python_status;
    int expected_state;
    int result = -1;

#if PY_MAJOR_VERSION != 3 || (PY_MINOR_VERSION != 12 && PY_MINOR_VERSION != 13)
#error "The lifecycle-v2 fixed launchers support only CPython 3.12 and 3.13."
#endif
#if defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
    expected_state = AQT_BOOTSTRAP_SIGNER_READY;
#else
    expected_state = AQT_BOOTSTRAP_ENDPOINT_READY;
#endif
    if (aqt_bootstrap_state != expected_state || Py_IsInitialized() != 0) {
        return -1;
    }
    aqt_validate_import_root();
    PyConfig_InitIsolatedConfig(&config);
    config.isolated = 1;
    config.use_environment = 0;
    config.site_import = 0;
    config.user_site_directory = 0;
    config.write_bytecode = 0;
    config.safe_path = 1;
    config.parse_argv = 0;
    config.module_search_paths_set = 1;
    python_status = PyConfig_SetBytesString(
        &config,
        &config.program_name,
        AQT_ROLE_EXECUTABLE
    );
    if (!PyStatus_Exception(python_status)) {
        python_status = PyConfig_SetBytesString(
            &config,
            &config.executable,
            AQT_ROLE_EXECUTABLE
        );
    }
    if (!PyStatus_Exception(python_status)) {
        python_status = PyConfig_SetBytesString(
            &config,
            &config.home,
            AQT_TRUSTED_TIME_V2_PYTHON_HOME
        );
    }
    if (!PyStatus_Exception(python_status)) {
        python_status = PyConfig_SetBytesArgv(
            &config,
            argument_count,
            argument_values
        );
    }
    if (PyStatus_Exception(python_status)
        || aqt_append_module_search_path(
            &config,
            AQT_TRUSTED_TIME_V2_PYTHON_STDLIB
        ) != 0
#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
        || aqt_append_module_search_path(
            &config,
            AQT_TRUSTED_TIME_V2_PYTHON_DYNLOAD
        ) != 0
#endif
        || aqt_append_module_search_path(&config, AQT_ROLE_IMPORT_ROOT) != 0) {
        PyConfig_Clear(&config);
        return -1;
    }
    python_status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(python_status) || Py_IsInitialized() == 0) {
        return -1;
    }
    result = aqt_run_fixed_entry();
    if (Py_FinalizeEx() < 0) {
        result = -1;
    }
    return result;
}

int
aqt_trusted_time_v2_role_launcher_main(int argument_count, char **argument_values)
{
    int seccomp_result;

    aqt_validate_executable(argument_count, argument_values);
    aqt_install_sigpipe_disposition();
    aqt_clear_environment();
    if (aqt_initialize_fork_guard() != 0) {
        aqt_fail("the native pre-Python fork guard could not be installed");
    }
    seccomp_result = aqt_trusted_time_v2_seccomp_install_initial();
#ifdef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
    if (seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_OK
        && seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_UNSUPPORTED) {
#else
    if (seccomp_result != AQT_TRUSTED_TIME_V2_SECCOMP_OK) {
#endif
        aqt_fail("the fixed seccomp profile could not be installed");
    }
    if (aqt_bootstrap_state != AQT_BOOTSTRAP_GUARD_READY) {
        aqt_fail("the pre-Python seccomp ordering was violated");
    }
    aqt_bootstrap_state = AQT_BOOTSTRAP_SECCOMP_READY;
    if (aqt_initialize_signer() != 0) {
        aqt_fail("the role-constrained native signer could not be registered");
    }
#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)
    if (aqt_initialize_endpoint() != 0) {
        aqt_fail("the role-constrained native endpoint could not be registered");
    }
#endif
    if (aqt_trusted_time_v2_fork_guard_is_poisoned() != 0) {
        aqt_fail("the process was poisoned before fixed runtime entry");
    }
    if (aqt_enter_fixed_runtime(argument_count, argument_values) != 0) {
        aqt_fail("the fixed role runtime failed");
    }
    return 0;
}

#ifndef AQT_TRUSTED_TIME_V2_NO_MAIN
int
main(int argument_count, char **argument_values)
{
    return aqt_trusted_time_v2_role_launcher_main(argument_count, argument_values);
}
#endif
