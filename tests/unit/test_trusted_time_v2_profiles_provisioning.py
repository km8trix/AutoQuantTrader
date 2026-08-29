from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from build_support import build_trusted_time_v2_profile_test as profile_builder

_ROOT = Path(__file__).resolve().parents[2]
_ROLE_SOURCE = _ROOT / "native/trusted_time_v2_role_launcher.c"
_PROVISIONER_SOURCE = _ROOT / "native/trusted_time_v2_provisioner.c"
_SECCOMP_SOURCE = _ROOT / "native/trusted_time_v2_seccomp.c"


@pytest.fixture(scope="module")
def profile_build(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[Path, dict[str, object]]]:
    parent = tmp_path_factory.mktemp("trusted-time-v2-profile-build")
    output = parent / "candidate"
    result = profile_builder.build(output)
    yield output, result


def test_fixed_profile_matrix_is_closed_and_argument_free(
    profile_build: tuple[Path, dict[str, object]],
) -> None:
    output, result = profile_build
    receipt = json.loads((output / "profile-test-build.json").read_text(encoding="ascii"))

    assert result == receipt
    assert result["activation_authorized"] is False
    assert result["status"] == "candidate_unactivated"
    artifacts = result["artifacts"]
    assert type(artifacts) is list
    assert len(artifacts) == 9
    assert {record["role"] for record in artifacts} == {"host", "supervisor", "recovery"}

    for role in ("host", "supervisor", "recovery"):
        launcher = output / f"autoquant-trusted-time-graceful-stop-v2-{role}"
        provisioner = output / f"autoquant-trusted-time-graceful-stop-v2-{role}-provision"
        assert subprocess.run([launcher], check=False).returncode == 0
        assert subprocess.run([launcher, "forbidden"], check=False).returncode == 191
        assert subprocess.run([provisioner], check=False).returncode == 191
        assert subprocess.run([provisioner, "forbidden"], check=False).returncode == 191


def test_launcher_performs_native_guard_and_seccomp_before_real_python_bootstrap() -> None:
    source = _ROLE_SOURCE.read_text(encoding="utf-8")
    main_source = source[source.index("aqt_trusted_time_v2_role_launcher_main(") :]

    guard = main_source.index("aqt_initialize_fork_guard()")
    seccomp = main_source.index("aqt_trusted_time_v2_seccomp_install_initial()")
    runtime = main_source.index("aqt_enter_fixed_runtime(argument_count, argument_values)")
    assert guard < seccomp < runtime
    assert "Py_InitializeFromConfig(&config)" in source
    assert "PyConfig_InitIsolatedConfig(&config)" in source
    assert "config.module_search_paths_set = 1" in source
    assert "AQT_TRUSTED_TIME_V2_CANDIDATE_CLOSED_RUNTIME" in source
    assert '#include "trusted_time_graceful_stop_v2_endpoint.h"' in source
    endpoint_include = source.index('#include "trusted_time_graceful_stop_v2_endpoint.h"')
    recovery_guard = source.rfind(
        "#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)",
        0,
        endpoint_include,
    )
    assert recovery_guard >= 0


def test_recovery_fixture_and_profile_source_have_no_normal_authority() -> None:
    recovery_fixture = (
        _ROOT / "tests/fixtures/native/trusted-time-v2/import-roots/recovery/"
        "autoquant_trusted_time_v2_recovery_entry.py"
    ).read_text(encoding="utf-8")
    launcher = _ROLE_SOURCE.read_text(encoding="utf-8")

    assert "socket" not in recovery_fixture
    assert "subprocess" not in recovery_fixture
    assert "docker" not in recovery_fixture.lower()
    assert "AQT_TRUSTED_TIME_V2_PYTHON_DYNLOAD" in launcher
    assert "#if !defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE)" in launcher


def test_provisioner_contract_is_descriptor_pinned_and_fail_closed() -> None:
    source = _PROVISIONER_SOURCE.read_text(encoding="utf-8")

    for required in (
        "aqt_capture_blob_identity(blob_path, &blob_identity)",
        "aqt_revalidate_blob_identity(",
        "aqt_trusted_time_v2_fork_guard_require_owner_table_empty()",
        "atomic_compare_exchange_strong(&aqt_generation_state",
        "SYS_execveat",
        "AT_EMPTY_PATH",
        "dup3(target_descriptor, STDOUT_FILENO, 0)",
        "aqt_trusted_time_v2_seccomp_install_child_exec()",
        "AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_FD",
        "aqt_unlink_exact_target(",
        "MADV_DONTDUMP",
        "MADV_WIPEONFORK",
        "mlock(mapping, mapping_size)",
        "AQT_CHILD_TIMEOUT_SECONDS",
        '#include "trusted_time_v2_secret_mount_admission.h"',
    ):
        assert required in source
    assert "argument_count != 1" in source
    assert "target_descriptor < 3" in source
    assert "executable_descriptor < 3" in source
    assert "null_descriptor < 3" in source

    blob_capture = source[
        source.index("static int\naqt_capture_blob_identity(") : source.index(
            "static int\naqt_revalidate_blob_identity("
        )
    ]
    assert (
        """#ifdef AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD
        || identity->st_uid != geteuid()
        || identity->st_gid != getegid()
#else
        || identity->st_uid != 0
        || identity->st_gid != 0
#endif"""
        in blob_capture
    )

    main = source[source.index("aqt_trusted_time_v2_provisioner_main(") :]
    pre_capture = main.index("&pre_create_mount_admission")
    pre_revalidate = main.index(
        "aqt_trusted_time_v2_secret_mount_admission_revalidate(", pre_capture
    )
    create = main.index("aqt_create_target(", pre_revalidate)
    pre_close = main.index("aqt_trusted_time_v2_secret_mount_admission_close(", create)
    post_capture = main.index("&post_create_mount_admission", pre_close)
    before_child = main.index(
        "aqt_trusted_time_v2_secret_mount_admission_revalidate(", post_capture
    )
    child = main.index("aqt_run_child(", before_child)
    post_filter = main.index("aqt_trusted_time_v2_seccomp_install_post_child()", child)
    blob_revalidate = main.index("aqt_revalidate_blob_identity(", post_filter)
    after_child = main.index(
        "aqt_trusted_time_v2_secret_mount_admission_revalidate(", blob_revalidate
    )
    verify = main.index("aqt_read_and_verify_seed(", post_filter)
    final_revalidate = main.index("aqt_trusted_time_v2_secret_mount_admission_revalidate(", verify)
    final_close = main.index("aqt_trusted_time_v2_secret_mount_admission_close(", final_revalidate)
    assert (
        pre_capture
        < pre_revalidate
        < create
        < pre_close
        < post_capture
        < before_child
        < child
        < post_filter
        < blob_revalidate
        < after_child
        < verify
        < final_revalidate
        < final_close
    )

    cleanup = main[main.index("cleanup:") :]
    cleanup_revalidate = cleanup.index("aqt_trusted_time_v2_secret_mount_admission_revalidate(")
    exact_unlink = cleanup.index("aqt_unlink_exact_target(", cleanup_revalidate)
    cleanup_close = cleanup.index("aqt_trusted_time_v2_secret_mount_admission_close(", exact_unlink)
    assert cleanup_revalidate < exact_unlink < cleanup_close


def test_seccomp_policy_is_embedded_default_deny_and_two_phase() -> None:
    source = _SECCOMP_SOURCE.read_text(encoding="utf-8")

    assert 'return "ordered-default-deny-allowlist-v1"' in source
    assert "SECCOMP_FILTER_FLAG_TSYNC" in source
    assert "SECCOMP_RET_KILL_PROCESS" in source
    assert "AQT_X32_REJECTION" in source
    assert "aqt_trusted_time_v2_seccomp_filter_bytes" in source
    assert "aqt_trusted_time_v2_seccomp_filter_count" in source
    assert "aqt_initial_filter" in source
    assert "aqt_post_child_filter" in source
    assert "aqt_trusted_time_v2_seccomp_install_post_child" in source
    assert "__NR_io_uring" not in source
    assert "__NR_ptrace" not in source
    assert "__NR_process_vm" not in source
    assert "json" not in source.lower()
