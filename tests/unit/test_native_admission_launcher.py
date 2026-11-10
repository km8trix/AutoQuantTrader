from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from build_support import build_native_admission_launcher as builder
from build_support import install_native_admission_launcher as installer

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _run_git(repository: Path, *arguments: str) -> None:
    completed = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=False,
        capture_output=True,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_EMAIL": "native-admission-test@example.invalid",
            "GIT_AUTHOR_NAME": "Native Admission Test",
            "GIT_COMMITTER_EMAIL": "native-admission-test@example.invalid",
            "GIT_COMMITTER_NAME": "Native Admission Test",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        },
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr).decode(
        "utf-8", errors="replace"
    )


def _copy_reviewed_source(source_root: Path) -> None:
    relative_paths = (
        ".gitignore",
        *(relative for relative, _digest in builder._EXPECTED_SOURCES),
    )
    for relative in relative_paths:
        source = REPOSITORY_ROOT / relative
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755 if os.access(source, os.X_OK) else 0o644)
    artifacts = source_root / "artifacts"
    artifact_directory = artifacts / "trusted-time"
    artifacts.mkdir(mode=0o700)
    artifact_directory.mkdir(mode=0o700)
    artifact = artifact_directory / "reviewed-input.json"
    artifact.write_bytes(b'{"reviewed":true}\n')
    artifact.chmod(0o600)


def _source_candidate(path: Path) -> Path:
    path.mkdir(mode=0o700)
    _copy_reviewed_source(path)
    _run_git(path, "init", "--quiet")
    _run_git(path, "config", "user.name", "Native Admission Test")
    _run_git(path, "config", "user.email", "native-admission-test@example.invalid")
    _run_git(path, "add", "--all")
    _run_git(path, "commit", "--quiet", "-m", "native admission fixture")
    _run_git(path, "checkout", "--quiet", "--detach", "HEAD")
    return path.resolve(strict=True)


def _runtime_candidate(path: Path) -> Path:
    site_packages = path / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages /= "site-packages"
    site_packages.mkdir(parents=True)
    dependency = site_packages / "admitted_dependency.py"
    dependency.write_bytes(b"ADMITTED = True\n")
    dependency.chmod(0o644)
    return path.resolve(strict=True)


@pytest.fixture(scope="module")
def built_candidate(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[Path, dict[str, object]]]:
    root = tmp_path_factory.mktemp("native-admission-build")
    source = _source_candidate(root / "source")
    runtime = _runtime_candidate(root / "runtime")
    output = root / "candidate"
    result = builder._build_candidate(
        source_root=source,
        runtime_candidate=runtime,
        output_directory=output,
        require_production_runtime=False,
    )
    yield output, result


def _native_metadata(candidate: Path, basename: str) -> bytes:
    return (candidate / builder._NATIVE_RELATIVE_PATH / basename).read_bytes()


def test_builder_contract_is_exact_and_has_no_ambient_runtime_fallback() -> None:
    assert builder._PREFIX.as_posix() == "/opt/autoquant/trusted-time-admission"
    assert builder._LAUNCHER_BASENAME == "autoquant-trusted-time-python-admission"
    assert builder._TARGET_IDS == (
        "verify-compose",
        "verify-images-build",
        "verify-images-readmit",
        "start",
        "admit-unenrolled",
        "enroll-first",
        "recover-first-enrollment",
        "post-enrollment-start",
        "operator-authority-prepare",
        "operator-authority-install",
        "graceful-stop-authority-prepare",
        "graceful-stop-authority-install",
        "operator-attestation-prepare",
        "operator-attestation-verify",
        "graceful-stop-decision-prepare",
        "graceful-stop-attestation-prepare",
        "graceful-stop-attestation-verify",
        "runtime-diagnostic",
        "inspect",
    )
    assert dict(builder._EXPECTED_SOURCES) == installer._EXPECTED_SOURCES
    source = Path(builder.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    main = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    assert "--runtime-candidate" in source
    assert "--output-directory" in source
    assert 'sysconfig.get_path("purelib")' not in source
    assert "copytree" not in source
    assert "TemporaryDirectory" not in source
    assert "_discard_candidate" not in source
    assert ".rmdir(" not in source
    assert ".unlink(" not in source
    assert "rmtree(" not in source
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    for function_name in ("main", "_build_candidate", "_build_candidate_once"):
        first_statement = functions[function_name].body[0]
        assert isinstance(first_statement, ast.Expr)
        assert isinstance(first_statement.value, ast.Call)
        assert isinstance(first_statement.value.func, ast.Name)
        assert first_statement.value.func.id == "_require_nonroot_builder"
    assert any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "source_root" for target in node.targets
        )
        for node in ast.walk(main)
    )


def test_compiler_profile_embeds_both_wrappers_and_never_enables_test_process_mode() -> None:
    source = Path(builder.__file__).read_text(encoding="utf-8")
    assert "AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE=1" in source
    assert 'AQT_TRUSTED_TIME_SOURCE_ROOT"' in source
    assert "embedded_owned_file_descriptor_wrapper.h" in source
    assert "embedded_bounded_process_wrapper.h" in source
    assert "AQT_NATIVE_PROCESS_LAUNCHER_BASENAME" in source
    assert "AQT_NATIVE_BOUNDED_PROCESS_TEST_PROFILE" not in source
    assert "AQT_NATIVE_LAUNCHER_TEST_PROFILE" not in source
    assert "AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE" not in source


def test_candidate_has_canonical_manifests_reproducible_launcher_and_false_boundaries(
    built_candidate: tuple[Path, dict[str, object]],
) -> None:
    candidate, result = built_candidate
    build_payload = _native_metadata(candidate, builder._BUILD_MANIFEST_BASENAME)
    source_payload = _native_metadata(candidate, builder._SOURCE_MANIFEST_BASENAME)
    runtime_payload = _native_metadata(candidate, builder._RUNTIME_MANIFEST_BASENAME)
    receipt_payload = _native_metadata(candidate, builder._INSTALL_RECEIPT_BASENAME)
    build = json.loads(build_payload)
    receipt = json.loads(receipt_payload)

    assert result["receipt_sha256"] == hashlib.sha256(receipt_payload).hexdigest()
    assert result["build_manifest_sha256"] == hashlib.sha256(build_payload).hexdigest()
    assert result["source_manifest_sha256"] == hashlib.sha256(source_payload).hexdigest()
    assert result["runtime_manifest_sha256"] == hashlib.sha256(runtime_payload).hexdigest()
    residue = result["retained_non_authorizing_residue"]
    assert isinstance(residue, dict)
    assert residue["authorizing"] is False
    assert residue["comparison_equal"] is True
    assert residue["comparison_fields"] == [
        "path",
        "type",
        "mode",
        "uid",
        "gid",
        "nlink",
        "size",
        "sha256",
    ]
    residue_directories = residue["directories"]
    assert isinstance(residue_directories, dict)
    assert set(residue_directories) == {
        "first_compiler_scratch",
        "second_candidate",
        "second_compiler_scratch",
    }
    retained_paths = {
        name: Path(value)
        for name, value in residue_directories.items()
        if isinstance(name, str) and isinstance(value, str)
    }
    assert set(retained_paths) == set(residue_directories)
    assert all(
        path.is_absolute() and path.parent == candidate.parent for path in retained_paths.values()
    )
    assert all(path.is_dir() and not path.is_symlink() for path in retained_paths.values())
    assert stat.S_IMODE(retained_paths["first_compiler_scratch"].stat().st_mode) == 0o700
    assert stat.S_IMODE(retained_paths["second_compiler_scratch"].stat().st_mode) == 0o700
    assert stat.S_IMODE(retained_paths["second_candidate"].stat().st_mode) == 0o555
    assert (
        builder._candidate_payload_snapshot(candidate)[1]
        == builder._candidate_payload_snapshot(retained_paths["second_candidate"])[1]
    )
    assert build["schema"] == "autoquant-native-admission-launcher-build-v1"
    assert build["reproducible_build_count"] == 2
    assert build["launcher"]["profile"] == "admission"
    assert build["launcher"]["target_ids"] == list(builder._TARGET_IDS)
    assert build["sources"] == dict(builder._EXPECTED_SOURCES)
    assert receipt["schema"] == "autoquant-native-admission-launcher-install-receipt-v1"
    assert receipt["status"] == "candidate_unactivated"
    assert receipt["activation_authorized"] is False
    assert receipt["external_boundaries"] == {
        boundary: False for boundary in builder._EXTERNAL_BOUNDARIES
    }
    assert len(receipt_payload) <= 64 * 1024
    assert receipt_payload == builder._canonical_json(receipt)

    for payload in (source_payload, runtime_payload):
        lines = payload.splitlines()
        header = json.loads(lines[0])
        records = tuple(json.loads(line) for line in lines[1:])
        assert header["entry_count"] == len(records)
        paths = tuple(record["path"] for record in records)
        assert paths == tuple(sorted(paths, key=lambda path: path.encode("utf-8")))
        assert len(paths) == len(set(paths))
        for record in records:
            assert set(record) == (
                {"gid", "mode", "path", "type", "uid"}
                if record["type"] == "directory"
                else {"gid", "mode", "nlink", "path", "sha256", "size", "type", "uid"}
            )
            if record["type"] == "file":
                assert record["nlink"] == 1

    launcher = candidate / builder._LAUNCHER_RELATIVE_PATH
    launcher_metadata = launcher.stat()
    assert stat.S_IMODE(launcher_metadata.st_mode) == 0o555
    assert launcher_metadata.st_nlink == 1
    assert hashlib.sha256(launcher.read_bytes()).hexdigest() == build["launcher"]["sha256"]


def test_candidate_contains_minimal_detached_git_and_operator_artifact_exception(
    built_candidate: tuple[Path, dict[str, object]],
) -> None:
    candidate, _result = built_candidate
    source = candidate / builder._SOURCE_RELATIVE_PATH
    git_entries = {path.name for path in (source / ".git").iterdir()}
    assert git_entries == {"HEAD", "config", "index", "objects", "refs"}
    head = (source / ".git" / "HEAD").read_text(encoding="ascii")
    assert len(head) == 41 and head.endswith("\n")
    assert all(character in "0123456789abcdef\n" for character in head)
    artifact_root = source / "artifacts"
    artifact = artifact_root / "trusted-time" / "reviewed-input.json"
    assert stat.S_IMODE(artifact_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE(source.stat().st_mode) == 0o555
    assert artifact.stat().st_uid == os.geteuid()


def test_installer_is_stdlib_only_unroutable_and_has_no_process_boundary() -> None:
    source = Path(installer.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])
    assert imported_roots <= {
        "__future__",
        "collections",
        "ctypes",
        "dataclasses",
        "errno",
        "hashlib",
        "json",
        "os",
        "secrets",
        "stat",
        "sys",
        "typing",
    }
    assert "subprocess" not in imported_roots
    assert "/opt/autoquant/trusted-time-admission" in source
    assert "--destination" not in source
    assert "--test" not in source
    assert "add_parser" not in source
    assert "_parse_arguments" not in source
    assert "os.system" not in source
    assert "os.spawn" not in source
    assert "os.exec" not in source
    assert "renameat2" in source and "renameatx_np" in source
    assert "candidate_unactivated" in source
    main = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    main_names = {
        node.id
        for node in ast.walk(main)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    assert "_install" not in main_names
    assert "_verify_installed" not in main_names
    assert "_parse_arguments" not in main_names
    module_entry = next(
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "__name__"
    )
    module_entry_names = {node.id for node in ast.walk(module_entry) if isinstance(node, ast.Name)}
    assert "_install" not in module_entry_names
    assert "_verify_installed" not in module_entry_names


def test_private_nonroot_seam_installs_verifies_and_refuses_overwrite(
    built_candidate: tuple[Path, dict[str, object]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, result = built_candidate
    tmp_path.chmod(0o700)
    destination = tmp_path / "trusted-time-admission-test-installed"
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "native-admission-private-seam")
    expected = str(result["receipt_sha256"])

    installed = installer._install_for_test(str(candidate), str(destination), expected)
    assert installed.receipt_sha256 == expected
    verified = installer._verify_for_test(str(destination), expected)
    assert verified.receipt == installed.receipt
    assert stat.S_IMODE(destination.stat().st_mode) == 0o555
    receipt = destination / installer._INSTALL_RECEIPT_RELATIVE_PATH
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o444
    assert receipt.stat().st_nlink == 1
    installed_receipt = json.loads(receipt.read_bytes())
    assert installed_receipt["status"] == "candidate_unactivated"
    assert installed_receipt["activation_authorized"] is False

    with pytest.raises(
        installer.NativeAdmissionLauncherInstallError,
        match="overwrite are forbidden",
    ):
        installer._install_for_test(str(candidate), str(destination), expected)


def test_wrong_receipt_is_rejected_before_test_destination_mutation(
    built_candidate: tuple[Path, dict[str, object]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, _result = built_candidate
    tmp_path.chmod(0o700)
    destination = tmp_path / "trusted-time-admission-test-wrong-receipt"
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "native-admission-private-seam")

    with pytest.raises(
        installer.NativeAdmissionLauncherInstallError,
        match="not the approved artifact",
    ):
        installer._install_for_test(str(candidate), str(destination), "0" * 64)
    assert not destination.exists()
    assert tuple(tmp_path.iterdir()) == ()


def test_runtime_candidate_rejects_startup_hooks_symlinks_and_hardlinks(tmp_path: Path) -> None:
    runtime = _runtime_candidate(tmp_path / "runtime")
    site_packages = runtime / "lib" / (f"python{sys.version_info.major}.{sys.version_info.minor}")
    site_packages /= "site-packages"
    hook = site_packages / "startup.pth"
    hook.write_text("import hostile\n", encoding="utf-8")
    with pytest.raises(
        builder.NativeAdmissionLauncherBuildError,
        match="forbidden import path",
    ):
        builder._runtime_paths(runtime)
    hook.unlink()

    target = site_packages / "target.py"
    alias = site_packages / "alias.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    os.link(target, alias)
    with pytest.raises(
        builder.NativeAdmissionLauncherBuildError,
        match="metadata is invalid",
    ):
        builder._runtime_paths(runtime)
    alias.unlink()
    target.unlink()

    target.write_text("VALUE = 1\n", encoding="utf-8")
    alias.symlink_to(target.name)
    with pytest.raises(
        builder.NativeAdmissionLauncherBuildError,
        match="symbolic link",
    ):
        builder._runtime_paths(runtime)


def test_production_entrypoint_is_unroutable_before_argument_or_mutation_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutation_attempts: list[str] = []

    def forbidden_mutation(*_arguments: object, **_keywords: object) -> None:
        mutation_attempts.append("mutation")
        raise AssertionError("production stub reached a mutation primitive")

    monkeypatch.setattr(installer, "_install", forbidden_mutation)
    monkeypatch.setattr(installer, "_verify_installed", forbidden_mutation)
    monkeypatch.setattr(os, "mkdir", forbidden_mutation)
    with pytest.raises(
        installer.NativeAdmissionLauncherInstallError,
        match="production installer CLI is unavailable",
    ):
        installer.main(
            (
                "install",
                "--candidate-directory",
                "/untrusted/candidate",
                "--expected-receipt-sha256",
                "0" * 64,
            )
        )
    assert mutation_attempts == []


def test_builder_rejects_root_before_parser_or_filesystem_mutator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutation_attempts: list[str] = []

    def forbidden_mutation(*_arguments: object, **_keywords: object) -> None:
        mutation_attempts.append("mutation")
        raise AssertionError("root builder reached a parser or filesystem mutator")

    monkeypatch.setattr(os, "getuid", lambda: 0)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getgid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)
    monkeypatch.setattr(builder, "_parse_arguments", forbidden_mutation)
    monkeypatch.setattr(tempfile, "mkdtemp", forbidden_mutation)

    with pytest.raises(
        builder.NativeAdmissionLauncherBuildError,
        match="without root privilege",
    ):
        builder.main(("--runtime-candidate", "/ignored", "--output-directory", "/ignored"))
    with pytest.raises(
        builder.NativeAdmissionLauncherBuildError,
        match="without root privilege",
    ):
        builder._build_candidate(
            source_root=tmp_path / "ignored-source",
            runtime_candidate=tmp_path / "ignored-runtime",
            output_directory=tmp_path / "ignored-output",
            require_production_runtime=False,
        )
    assert mutation_attempts == []


def test_regular_file_opens_are_nonblocking_and_reject_fifo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fifo = tmp_path / "candidate-fifo"
    os.mkfifo(fifo, 0o600)
    assert installer._file_flags() & os.O_NONBLOCK

    root_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(
            installer.NativeAdmissionLauncherInstallError,
            match="not a regular file",
        ):
            installer._open_file_at(root_descriptor, fifo.name)
    finally:
        os.close(root_descriptor)

    observed_flags: list[int] = []
    original_open = os.open

    def recording_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        observed_flags.append(flags)
        return int(original_open(path, flags, mode, dir_fd=dir_fd))

    monkeypatch.setattr(os, "open", recording_open)
    with pytest.raises(
        builder.NativeAdmissionLauncherBuildError,
        match="metadata is invalid",
    ):
        builder._validate_regular_input(fifo)
    assert observed_flags[-1] & os.O_NONBLOCK


def test_private_test_seam_is_unavailable_without_exact_nonroot_process_condition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    unchecked = installer._test_policy
    with pytest.raises(
        installer.NativeAdmissionLauncherInstallError,
        match="test seam is unavailable",
    ):
        unchecked(str(tmp_path / "trusted-time-admission-test-unavailable"))


def test_manifest_parser_rejects_noncanonical_or_duplicate_path_records() -> None:
    header = {
        "entry_count": 2,
        "root": installer._PREFIX,
        "schema": installer._RUNTIME_MANIFEST_SCHEMA,
    }
    record: dict[str, Any] = {
        "gid": 0,
        "mode": 0o555,
        "path": "lib",
        "type": "directory",
        "uid": 0,
    }
    payload = b"".join(
        (
            installer._canonical_json(header),
            installer._canonical_json(record),
            installer._canonical_json(record),
        )
    )
    with pytest.raises(
        installer.NativeAdmissionLauncherInstallError,
        match="not strictly ordered",
    ):
        installer._parse_manifest(
            payload,
            schema=installer._RUNTIME_MANIFEST_SCHEMA,
            root=installer._PREFIX,
            label="test manifest",
        )
