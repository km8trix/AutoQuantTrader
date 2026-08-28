from __future__ import annotations

import json
import os
import stat
import sys
import tomllib
from pathlib import Path

import pytest

from build_support import build_trusted_time_v2_candidates as candidate_builder
from build_support import build_trusted_time_v2_linked_role_test as linked_role_test

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "build_support/build_trusted_time_v2_candidates.py"
LINKED_ROLE_TEST = ROOT / "build_support/build_trusted_time_v2_linked_role_test.py"
EXACT_EXECUTION = ROOT / "build_support/exercise_trusted_time_v2_exact_candidates.py"
QUALIFICATION = ROOT / "build_support/qualify_trusted_time_v2_candidates.py"
EXECUTION_DOCKERFILE = ROOT / "build_support/trusted_time_v2_candidate_execution.Dockerfile"
SDIST_SMOKE = ROOT / "build_support/smoke_trusted_time_v2_sdist.py"
WORKFLOW = ROOT / ".github/workflows/ci.yml"
ROLE_LAUNCHER = ROOT / "native/trusted_time_v2_role_launcher.c"
PROVISIONER = ROOT / "native/trusted_time_v2_provisioner.c"
RECEIPT = "candidate-build.json"
LICENSE = "MONOCYPHER-LICENCE.md"
ROLES = {"host", "supervisor", "recovery"}


@pytest.fixture(scope="module")
def candidate_build(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, object]]:
    output = tmp_path_factory.mktemp("trusted-time-v2-candidate-parent") / "candidate"
    result = candidate_builder.build(output)
    return output, result


@pytest.fixture(scope="module")
def linked_role_execution(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, dict[str, object]]:
    output = tmp_path_factory.mktemp("trusted-time-v2-linked-role-parent") / "execution"
    result = linked_role_test.exercise(output)
    return output, result


def test_builder_is_source_only_and_has_no_test_profile_or_activation_surface() -> None:
    source = BUILDER.read_text(encoding="utf-8")

    assert "profile_stubs" not in source
    assert "AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE" not in source
    assert "AQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD" not in source
    assert "AQT_TRUSTED_TIME_V2_AUTHORITY_TEST_ROOT_PIN" not in source
    assert '"-Wl,--gc-sections"' not in source
    assert '"-Wl,--no-gc-sections"' in source
    assert '"activation_authorized": False' in source
    assert "systemctl" not in source
    assert "daemon-reload" not in source
    assert "docker run" not in source.lower()
    assert "compose" not in source.lower()
    assert "seccomp_manifests_included" in source


def test_role_launcher_omits_portable_only_basename_helper_from_production() -> None:
    source = ROLE_LAUNCHER.read_text(encoding="utf-8")
    guarded_helper = """#ifdef AQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE
static const char *
aqt_basename(const char *path)
"""

    assert guarded_helper in source
    assert source.count("aqt_basename(") == 2


def test_provisioner_realpath_scratch_buffers_satisfy_glibc_fortify() -> None:
    source = PROVISIONER.read_text(encoding="utf-8")

    assert "char canonical[AQT_MAX_PATH_BYTES];" not in source
    assert source.count("char canonical[PATH_MAX];") == 3


def test_builder_requires_one_absent_absolute_output(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()

    with pytest.raises(candidate_builder.CandidateBuildError, match="absent absolute"):
        candidate_builder._validate_absent_output_directory(existing)
    with pytest.raises(candidate_builder.CandidateBuildError, match="absent absolute"):
        candidate_builder._validate_absent_output_directory(Path("relative-candidate"))


def test_builder_rejects_non_linux_before_creating_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "unsupported"
    monkeypatch.setattr(candidate_builder.sys, "platform", "darwin")

    with pytest.raises(candidate_builder.CandidateBuildError, match="Linux-only"):
        candidate_builder.build(output)
    assert not output.exists()


def test_inert_candidate_import_sources_are_exact_and_reject_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = candidate_builder._validate_candidate_import_sources()

    assert set(records) == ROLES
    assert all(record["size"] > 0 for record in records.values())
    unsafe_root = tmp_path / "recovery"
    unsafe_root.mkdir()
    unsafe = unsafe_root / "autoquant_trusted_time_v2_recovery_entry.py"
    unsafe.write_text("import subprocess\n", encoding="ascii")
    monkeypatch.setitem(candidate_builder._ROLE_IMPORT_SOURCE_PATHS, "recovery", unsafe)
    with pytest.raises(candidate_builder.CandidateBuildError, match="not exact"):
        candidate_builder._validate_candidate_import_sources()


def test_managed_python_tree_manifest_rejects_aliases_and_binds_topology(
    tmp_path: Path,
) -> None:
    home = tmp_path / "managed-python"
    library = home / "lib"
    home.mkdir(mode=0o700)
    library.mkdir(mode=0o700)
    payload = library / "payload.bin"
    alternate = library / "alternate.bin"
    independent = library / "independent.bin"
    for path, contents in (
        (payload, b"payload"),
        (alternate, b"alternate"),
        (independent, b"independent"),
    ):
        path.write_bytes(contents)
        path.chmod(0o600)
    alias = library / "alias.bin"
    alias.symlink_to("payload.bin")

    baseline = candidate_builder._python_base_prefix_manifest(home)
    assert baseline["hardlinks_absent"] is True
    assert baseline["symlink_count"] == 1

    payload.write_bytes(b"changed")
    assert (
        candidate_builder._python_base_prefix_manifest(home)["tree_sha256"]
        != baseline["tree_sha256"]
    )
    payload.write_bytes(b"payload")
    payload.chmod(0o400)
    assert (
        candidate_builder._python_base_prefix_manifest(home)["tree_sha256"]
        != baseline["tree_sha256"]
    )
    payload.chmod(0o600)
    moved = library / "moved.bin"
    independent.rename(moved)
    assert (
        candidate_builder._python_base_prefix_manifest(home)["tree_sha256"]
        != baseline["tree_sha256"]
    )
    moved.rename(independent)
    library.chmod(0o500)
    assert (
        candidate_builder._python_base_prefix_manifest(home)["tree_sha256"]
        != baseline["tree_sha256"]
    )
    library.chmod(0o700)
    renamed_library = home / "runtime"
    library.rename(renamed_library)
    assert (
        candidate_builder._python_base_prefix_manifest(home)["tree_sha256"]
        != baseline["tree_sha256"]
    )
    renamed_library.rename(library)
    alias.unlink()
    alias.symlink_to("alternate.bin")
    assert (
        candidate_builder._python_base_prefix_manifest(home)["tree_sha256"]
        != baseline["tree_sha256"]
    )

    def admitted_root(name: str) -> tuple[Path, Path]:
        root = tmp_path / name
        root.mkdir(mode=0o700)
        regular = root / "regular"
        regular.write_bytes(b"input")
        regular.chmod(0o600)
        return root, regular

    absolute_root, absolute_file = admitted_root("absolute-symlink")
    (absolute_root / "alias").symlink_to(absolute_file)
    escaping_root, _ = admitted_root("escaping-symlink")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (escaping_root / "alias").symlink_to("../outside")
    dangling_root, _ = admitted_root("dangling-symlink")
    (dangling_root / "alias").symlink_to("missing")
    loop_root, _ = admitted_root("loop-symlink")
    (loop_root / "alias").symlink_to("alias")
    hardlink_root, hardlink_file = admitted_root("hardlink")
    os.link(hardlink_file, hardlink_root / "second-name")
    special_root, _ = admitted_root("special")
    os.mkfifo(special_root / "fifo", mode=0o600)
    writable_file_root, writable_file = admitted_root("writable-file")
    writable_file.chmod(0o620)
    writable_directory_root, _ = admitted_root("writable-directory")
    writable_directory = writable_directory_root / "writable"
    writable_directory.mkdir(mode=0o720)
    writable_directory.chmod(0o720)

    for rejected_root in (
        absolute_root,
        escaping_root,
        dangling_root,
        loop_root,
        hardlink_root,
        special_root,
        writable_file_root,
        writable_directory_root,
    ):
        with pytest.raises(candidate_builder.CandidateBuildError):
            candidate_builder._python_base_prefix_manifest(rejected_root)


def test_candidate_sources_and_vendor_evidence_are_exactly_sdist_only() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    targets = configuration["tool"]["hatch"]["build"]["targets"]
    required = {
        "build_support/build_trusted_time_v2_candidates.py",
        "build_support/trusted_time_v2_seccomp_manifests.py",
        (
            "build_support/trusted_time_v2_candidate_import_roots/host/"
            "autoquant_trusted_time_v2_host_entry.py"
        ),
        (
            "build_support/trusted_time_v2_candidate_import_roots/recovery/"
            "autoquant_trusted_time_v2_recovery_entry.py"
        ),
        (
            "build_support/trusted_time_v2_candidate_import_roots/supervisor/"
            "autoquant_trusted_time_v2_supervisor_entry.py"
        ),
        "infra/trusted-time/graceful-stop-v2/seccomp/host.json",
        "infra/trusted-time/graceful-stop-v2/seccomp/provisioner.json",
        "infra/trusted-time/graceful-stop-v2/seccomp/recovery.json",
        "infra/trusted-time/graceful-stop-v2/seccomp/supervisor.json",
        "native/trusted_time_graceful_stop_v2_endpoint.c",
        "native/trusted_time_graceful_stop_v2_endpoint.h",
        "native/trusted_time_graceful_stop_v2_resources.c",
        "native/trusted_time_graceful_stop_v2_resources.h",
        "native/trusted_time_graceful_stop_v2_signer.c",
        "native/trusted_time_graceful_stop_v2_signer.h",
        "native/trusted_time_v2_authority.c",
        "native/trusted_time_v2_authority.h",
        "native/trusted_time_v2_descriptor_baseline.c",
        "native/trusted_time_v2_descriptor_baseline.h",
        "native/trusted_time_v2_fork_guard.c",
        "native/trusted_time_v2_fork_guard.h",
        "native/trusted_time_v2_provisioner.c",
        "native/trusted_time_v2_provisioner.h",
        "native/trusted_time_v2_role_launcher.c",
        "native/trusted_time_v2_role_launcher.h",
        "native/trusted_time_v2_seccomp.c",
        "native/trusted_time_v2_seccomp.h",
        "native/trusted_time_v2_secret_mount_admission.c",
        "native/trusted_time_v2_secret_mount_admission.h",
        "third_party/monocypher/4.0.3/LICENCE.md",
        "third_party/monocypher/4.0.3/VENDORING.json",
        "third_party/monocypher/4.0.3/src/monocypher.c",
        "third_party/monocypher/4.0.3/src/monocypher.h",
        "third_party/monocypher/4.0.3/src/optional/monocypher-ed25519.c",
        "third_party/monocypher/4.0.3/src/optional/monocypher-ed25519.h",
        "tests/native/trusted_time_v2_seccomp_manifest_harness.c",
    }
    sdist_only = {
        "build_support/build_trusted_time_v2_linked_role_test.py",
        "build_support/exercise_trusted_time_v2_exact_candidates.py",
        "build_support/qualify_trusted_time_v2_candidates.py",
        "build_support/smoke_trusted_time_v2_sdist.py",
        "build_support/trusted_time_v2_candidate_execution.Dockerfile",
        (
            "tests/fixtures/native/trusted-time-v2/import-roots/host/"
            "autoquant_trusted_time_v2_host_entry.py"
        ),
        (
            "tests/fixtures/native/trusted-time-v2/import-roots/recovery/"
            "autoquant_trusted_time_v2_recovery_entry.py"
        ),
        (
            "tests/fixtures/native/trusted-time-v2/import-roots/supervisor/"
            "autoquant_trusted_time_v2_supervisor_entry.py"
        ),
    }
    legacy = {
        "build_support/native_build_constraints.txt",
        "build_support/native_image_manifest.py",
        "build_support/native_owned_file_descriptor_hook.py",
        "native/bounded_process.c",
        "native/owned_file_descriptor.c",
        "native/trusted_time_python_launcher.c",
        "packages/adapters/trusted_time/_bounded_process.py",
    }

    sdist_force_include = targets["sdist"]["force-include"]
    expected = required | sdist_only | legacy
    assert set(sdist_force_include) == expected
    for path in expected:
        assert sdist_force_include[path] == path
    assert "force-include" not in targets["wheel"]


def test_exact_candidate_execution_is_locked_to_disposable_container() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    dockerfile = EXECUTION_DOCKERFILE.read_text(encoding="utf-8")
    executor = EXACT_EXECUTION.read_text(encoding="utf-8")
    qualification = QUALIFICATION.read_text(encoding="utf-8")
    sdist_smoke = SDIST_SMOKE.read_text(encoding="utf-8")
    pinned_base = "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"

    assert dockerfile.splitlines()[0] == f"FROM {pinned_base}"
    assert pinned_base in executor
    assert "apt-get install" in dockerfile
    assert workflow.index("Build pinned disposable Wave 7 qualification image") < workflow.index(
        "Execute exact six candidates in locked disposable container"
    )
    execution_step = workflow.split(
        "- name: Execute exact six candidates in locked disposable container",
        1,
    )[1]
    assert "--rm" in execution_step
    assert "--network none" in execution_step
    assert "--ipc private" in execution_step
    assert "--cap-drop ALL" in execution_step
    assert "--security-opt no-new-privileges" in execution_step
    assert "--read-only" in execution_step
    assert "--tmpfs /opt:rw,exec,nosuid,nodev" in execution_step
    assert "--tmpfs /tmp:rw,noexec,nosuid,nodev" in execution_step
    assert "${AQT_WAVE7_SDIST_ROOT}:/workspace:ro" in execution_step
    assert "${GITHUB_WORKSPACE}:/workspace:ro" not in execution_step
    assert "${python_home}:${python_home}:ro" in execution_step
    assert "--privileged" not in execution_step
    assert "docker.sock" not in execution_step
    assert "/opt:/opt" not in execution_step
    assert "all_non_loopback_interfaces_inactive" in executor
    assert "all_non_loopback_ip_addresses_absent" in executor
    assert "all_active_non_loopback_routes_absent" in executor
    assert 'interfaces != ["lo"]' not in executor
    assert 'Path("/proc/net/route")' in executor
    assert 'Path("/proc/net/ipv6_route")' in executor
    assert '"observed_ipc_namespace_identity"' in executor
    assert '"private_ipc_namespace": True' not in executor
    assert '"outer_runner_ipc_mode_contract"' not in executor
    assert '"candidate_staging_installed"' not in executor
    assert '"transient_exact_path_staging_performed": True' in executor
    assert '"candidate_staging_persisted": False' in executor
    assert '"runtime_owner_installed": False' in executor
    assert all(
        capability in executor for capability in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    )
    assert 'for option in ("noexec", "nosuid", "nodev")' in executor
    assert 'Path("/opt/.wave7-evidence")' in qualification
    assert '"candidate_artifacts_copied_back": False' in qualification
    assert '"document":' not in qualification
    assert '"workspace_pre_qualification_sha256"' in qualification
    assert '"workspace_post_qualification_sha256"' in qualification
    assert '"recovery_python_runtime": recovery_runtime' in qualification
    assert 'source.extractall(extraction, filter="data")' in sdist_smoke
    assert '"captured_bytes_used_for_extraction": True' in sdist_smoke
    assert '"stable_opened_file_identity": True' in sdist_smoke
    assert "Extract and validate Wave 7 sdist evidence outside checkout" in workflow
    assert (
        '"${AQT_WAVE7_SDIST_ROOT}/build_support/'
        'trusted_time_v2_candidate_execution.Dockerfile"' in workflow
    )
    assert "Remove disposable Wave 7 qualification state" in workflow
    assert "AQT_WAVE7_IMAGE_ID_FILE" in workflow
    assert 'receipt["exact_execution"]["qualification_image_id"]' in workflow
    assert "sdist_receipt = json.loads(Path(sys.argv[3])" in workflow
    assert "! docker container inspect" not in workflow
    assert "! docker image inspect" not in workflow
    assert "forbidden_fragments" in workflow


@pytest.mark.skipif(sys.platform != "linux", reason="real candidates are Linux-only")
def test_builder_emits_six_reproducible_unactivated_real_candidates(
    candidate_build: tuple[Path, dict[str, object]],
) -> None:
    output, result = candidate_build
    receipt = json.loads((output / RECEIPT).read_text(encoding="ascii"))

    assert receipt == result
    assert result["schema"] == "autoquant-trusted-time-graceful-stop-v2-candidate-build-v1"
    assert result["status"] == "candidate_unactivated"
    assert result["activation_authorized"] is False
    assert result["reproducible_build_count"] == 2
    assert result["seccomp_manifests_included"] is True
    assert result["role_import_trees_included"] is True
    assert set(result["command_environment"]) == {
        "LANG",
        "LC_ALL",
        "PATH",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
    }
    assert result["command_path_placeholders"]["<SOURCE_ROOT>"] == (
        "the canonical source root used for this build, including an extracted-sdist root "
        "during locked qualification"
    )
    assert result["compiler"]["lto"] == {
        "compiler_flag": "-fno-lto",
        "linker_plugin_disabled": True,
        "linker_plugin_used": False,
    }
    assert result["first_party_crypto_calls"] == [
        "crypto_ed25519_check",
        "crypto_ed25519_key_pair",
        "crypto_ed25519_sign",
        "crypto_wipe",
    ]
    assert result["production_release_root"] == {
        "available": False,
        "provisioner_authority_results": {
            "host": "ENOKEY",
            "recovery": "ENOKEY",
            "supervisor": "ENOKEY",
        },
        "production_provisioners_compiled_without_release_pin": True,
        "test_pin_compiled": False,
    }

    artifacts = result["artifacts"]
    assert type(artifacts) is list
    assert len(artifacts) == 6
    assert {record["role"] for record in artifacts} == ROLES
    assert {record["kind"] for record in artifacts} == {"role", "provisioner"}
    assert all(record["reproducible_build_count"] == 2 for record in artifacts)
    assert all(record["build_commands"] for record in artifacts)
    assert all(record["audit"]["lto_absent"] is True for record in artifacts)
    assert all(record["audit"]["build_id_absent"] is True for record in artifacts)
    assert all(record["audit"]["full_relro"] is True for record in artifacts)
    assert all(record["audit"]["nonexecutable_stack"] is True for record in artifacts)
    assert all(
        record["audit"]["forbidden_dynamic_dependencies_absent"] is True for record in artifacts
    )
    assert all(record["audit"]["forbidden_exports_absent"] is True for record in artifacts)
    assert all(record["audit"]["test_symbols_absent"] is True for record in artifacts)
    assert all(record["audit"]["opposite_role_symbols_absent"] is True for record in artifacts)
    assert all(
        record["audit"]["dynamic_dependency_allowlist_enforced"] is True for record in artifacts
    )
    for record in artifacts:
        expected_dependencies = {"libc.so.6"}
        if record["kind"] == "role":
            expected_dependencies.add(result["python"]["soname"])
        assert set(record["audit"]["dynamic_dependencies"]) == expected_dependencies
        assert set(record["audit"]["dynamic_dependency_allowlist"]) == expected_dependencies
        assert record["audit"]["dynamic_dependency_exact"] is True
    assert all(record["audit"]["elf_machine"] == "EM_X86_64" for record in artifacts)
    assert all(
        record["audit"]["monocypher_conditional_operations"]["operations"][operation][
            "branchless_assertion_passed"
        ]
        is True
        for record in artifacts
        for operation in ("fe_ccopy", "fe_cswap")
    )
    assert {
        (record["role"], record["kind"]): record["seccomp_profile"] for record in artifacts
    } == {
        ("host", "provisioner"): "provisioner",
        ("host", "role"): "host",
        ("recovery", "provisioner"): "provisioner",
        ("recovery", "role"): "recovery",
        ("supervisor", "provisioner"): "provisioner",
        ("supervisor", "role"): "supervisor",
    }
    for artifact in artifacts:
        profile = artifact["seccomp_profile"]
        manifest = result["seccomp_manifests"][profile]
        assert artifact["seccomp_binding"] == {
            "bpf_phases": manifest["bpf_phases"],
            "manifest_sha256": manifest["manifest_sha256"],
            "profile": profile,
            "source_sha256": manifest["source_sha256"],
        }
    assert {
        profile: record["output_name"] for profile, record in result["seccomp_manifests"].items()
    } == {
        "host": "seccomp-host.json",
        "provisioner": "seccomp-provisioner.json",
        "recovery": "seccomp-recovery.json",
        "supervisor": "seccomp-supervisor.json",
    }
    assert all(
        record["status"] == "bound"
        and len(record["manifest_sha256"]) == 64
        and record["bpf_phases"]
        and len(record["source_sha256"]) == 64
        for record in result["seccomp_manifests"].values()
    )
    assert result["architecture_binding"]["all_equal"] is True
    python_record = result["python"]
    assert python_record["base_prefix_tree"]["entry_count"] > 0
    assert python_record["base_prefix_tree"]["regular_file_count"] > 0
    assert len(python_record["base_prefix_tree"]["tree_sha256"]) == 64
    assert python_record["executable"]["sha256"]
    assert python_record["include_tree"]["file_count"] > 0
    assert len(python_record["include_tree"]["manifest_sha256"]) == 64
    assert {
        record["relative_path"]
        for record in python_record["normal_role_startup_standard_library"]["files"]
    } == {"encodings/__init__.py", "encodings/aliases.py", "encodings/utf_8.py"}
    import_trees = result["role_import_trees"]
    assert set(import_trees) == ROLES
    assert all(record["file_count"] == 1 for record in import_trees.values())
    assert all(record["installed"] is False for record in import_trees.values())
    assert all(record["activation_authorized"] is False for record in import_trees.values())
    assert all(
        record["operational_composition_included"] is False for record in import_trees.values()
    )
    assert {
        record["role"]: record["import_tree"]["tree_sha256"]
        for record in artifacts
        if record["kind"] == "role"
    } == {role: record["tree_sha256"] for role, record in import_trees.items()}
    assert all(
        record["import_tree"] is None for record in artifacts if record["kind"] == "provisioner"
    )
    recovery_runtime = result["recovery_python_runtime"]
    assert recovery_runtime["full_standard_library_included"] is False
    assert recovery_runtime["dynamic_extensions_included"] is False
    assert {record["path"] for record in recovery_runtime["files"]} == {
        "LICENSE.txt",
        "encodings/__init__.py",
        "encodings/aliases.py",
        "encodings/utf_8.py",
    }
    recovery_role = next(
        record for record in artifacts if record["role"] == "recovery" and record["kind"] == "role"
    )
    assert recovery_role["python_runtime"]["tree_sha256"] == recovery_runtime["tree_sha256"]
    assert recovery_runtime["runtime_search_path"] == [
        "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python-runtime",
        "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python",
    ]
    assert recovery_runtime["security_boundary"]["arbitrary_python_compromise_safe"] is False
    assert len(recovery_runtime["module_inventory"]["builtin_modules_sha256"]) == 64
    assert len(recovery_runtime["module_inventory"]["frozen_modules_sha256"]) == 64
    assert all(
        record["python_runtime"] is None for record in artifacts if record is not recovery_role
    )
    assert {
        (record["role"], record["kind"]): record["audit"]["role_socket_surface"]
        for record in artifacts
    } == {
        ("host", "provisioner"): "network_absent",
        ("host", "role"): "connector_only",
        ("recovery", "provisioner"): "network_absent",
        ("recovery", "role"): "network_absent",
        ("supervisor", "provisioner"): "network_absent",
        ("supervisor", "role"): "listener_only",
    }

    expected_names = {
        RECEIPT,
        LICENSE,
        *(record["output_name"] for record in result["seccomp_manifests"].values()),
        "candidate-import-manifests",
        "candidate-import-trees",
        "candidate-python-runtime-manifests",
        "candidate-python-runtimes",
    }
    for record in result["seccomp_manifests"].values():
        output_name = record["output_name"]
        assert stat.S_IMODE((output / output_name).stat().st_mode) == 0o444
        assert candidate_builder._sha256(output / output_name) == record["manifest_sha256"]
    for record in artifacts:
        basename = record["basename"]
        link_map = record["link_map"]
        expected_names.update((basename, link_map))
        assert stat.S_IMODE((output / basename).stat().st_mode) == 0o555
        assert stat.S_IMODE((output / link_map).stat().st_mode) == 0o444
        assert b"profile_stubs" not in (output / basename).read_bytes()
        assert record["monocypher"]["license"] == LICENSE
    for role, record in import_trees.items():
        tree = output / record["output_root"]
        manifest_path = output / record["manifest_output"]
        assert stat.S_IMODE(tree.stat().st_mode) == 0o555
        assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
        assert {path.name for path in tree.iterdir()} == {f"{record['entry_module']}.py"}
        entry = next(tree.iterdir())
        assert stat.S_IMODE(entry.stat().st_mode) == 0o444
        assert candidate_builder._sha256(entry) == record["files"][0]["sha256"]
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
        assert manifest == {
            key: value
            for key, value in record.items()
            if key not in {"manifest_output", "manifest_sha256"}
        }
        if role == "recovery":
            lowered = entry.read_bytes().lower()
            assert all(
                fragment.encode("ascii") not in lowered
                for fragment in candidate_builder._RECOVERY_IMPORT_FORBIDDEN_FRAGMENTS
            )
    runtime_root = output / recovery_runtime["output_root"]
    runtime_manifest = output / recovery_runtime["manifest_output"]
    assert stat.S_IMODE(runtime_root.stat().st_mode) == 0o555
    assert stat.S_IMODE(runtime_manifest.stat().st_mode) == 0o444
    assert {
        path.relative_to(runtime_root).as_posix()
        for path in runtime_root.rglob("*")
        if path.is_file()
    } == {record["path"] for record in recovery_runtime["files"]}
    assert all(
        stat.S_IMODE(path.stat().st_mode) == (0o444 if path.is_file() else 0o555)
        for path in runtime_root.rglob("*")
    )
    assert {path.name for path in output.iterdir()} == expected_names
    assert stat.S_IMODE((output / RECEIPT).stat().st_mode) == 0o444
    assert stat.S_IMODE((output / LICENSE).stat().st_mode) == 0o444


@pytest.mark.skipif(sys.platform != "linux", reason="real candidates are Linux-only")
def test_recovery_link_topology_is_structurally_separate(
    candidate_build: tuple[Path, dict[str, object]],
) -> None:
    output, result = candidate_build
    records = {(record["role"], record["kind"]): record for record in result["artifacts"]}
    recovery_role = records[("recovery", "role")]
    recovery_provisioner = records[("recovery", "provisioner")]

    assert "endpoint" not in recovery_role["source_aliases"]
    assert "resources" not in recovery_role["source_aliases"]
    assert "authority" not in recovery_role["source_aliases"]
    assert "endpoint" not in recovery_provisioner["source_aliases"]
    assert "resources" not in recovery_provisioner["source_aliases"]
    assert "descriptor_baseline" in recovery_provisioner["source_aliases"]
    assert "secret_mount_admission" in recovery_provisioner["source_aliases"]
    assert {
        record["alias"] for record in recovery_role["audit"]["recovery_preprocessed_sources"]
    } == set(recovery_role["source_aliases"])
    assert {
        record["alias"] for record in recovery_provisioner["audit"]["recovery_preprocessed_sources"]
    } == set(recovery_provisioner["source_aliases"])
    assert recovery_role["audit"]["recovery_exclusions_passed"] is True
    assert recovery_provisioner["audit"]["recovery_exclusions_passed"] is True

    role_map = (output / recovery_role["link_map"]).read_text(encoding="utf-8")
    provisioner_map = (output / recovery_provisioner["link_map"]).read_text(encoding="utf-8")
    assert "/endpoint.o" not in role_map
    assert "/resources.o" not in role_map
    assert "/authority.o" not in role_map
    assert "/role_launcher.o" not in provisioner_map
    assert "/signer.o" not in provisioner_map


@pytest.mark.skipif(sys.platform != "linux", reason="real linked roles are Linux-only")
def test_real_linked_role_topology_executes_without_retaining_test_binaries(
    linked_role_execution: tuple[Path, dict[str, object]],
) -> None:
    output, result = linked_role_execution
    receipt = json.loads((output / "linked-role-execution.json").read_text(encoding="ascii"))

    assert receipt == result
    assert result["schema"] == ("autoquant-trusted-time-graceful-stop-v2-linked-role-execution-v1")
    assert result["status"] == "linked_test_profiles_passed"
    assert result["activation_authorized"] is False
    assert result["candidate_artifact"] is False
    assert result["production_candidate_receipt"] is None
    assert result["test_profile"] is True
    assert result["test_profile_binaries_retained"] is False
    assert set(result["staged_entry_roots"]) == ROLES
    assert all(
        not Path(record["ephemeral_import_root_during_execution"]).exists()
        for record in result["staged_entry_roots"].values()
    )
    assert len(result["profiles"]) == 6
    assert {record["role"] for record in result["profiles"]} == ROLES
    assert {record["profile_kind"] for record in result["profiles"]} == {
        "provisioner",
        "role",
    }
    assert {path.name for path in output.iterdir()} == {"linked-role-execution.json"}

    profiles = {(record["role"], record["profile_kind"]): record for record in result["profiles"]}
    assert all(profiles[(role, "role")]["status"] == "passed" for role in ROLES)
    assert all(
        profiles[(role, "provisioner")]["status"] == "expected_fail_closed_passed" for role in ROLES
    )
    assert profiles[("host", "role")]["ordered_stages"] == [
        "fork_guard",
        "seccomp",
        "signer_self_test",
        "endpoint_bootstrap",
        "fixed_python_entry",
    ]
    assert (
        profiles[("supervisor", "role")]["ordered_stages"]
        == profiles[("host", "role")]["ordered_stages"]
    )
    assert profiles[("recovery", "role")]["ordered_stages"] == [
        "fork_guard",
        "seccomp",
        "signer_self_test",
        "fixed_python_entry",
    ]
    assert "endpoint" not in profiles[("recovery", "role")]["linked_source_aliases"]
    assert "resources" not in profiles[("recovery", "role")]["linked_source_aliases"]
    for role in ROLES:
        assert profiles[(role, "provisioner")]["ordered_stages"] == [
            "descriptor_and_signal_baseline",
            "fork_guard",
            "seccomp_pre_child",
            "authority_consumer_enokey",
            "fail_closed_191",
        ]
