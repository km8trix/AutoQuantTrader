"""Exercise real linked lifecycle-v2 role topology under explicit test paths.

This is intentionally separate from the production candidate builder and its
receipt.  Test executables are removed after successful execution; no binary
is installed or admitted for activation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import stat
import sys
from pathlib import Path

_BUILD_SUPPORT_ROOT = Path(__file__).resolve(strict=True).parent
_ROOT = _BUILD_SUPPORT_ROOT.parent
if not __package__:
    sys.path.insert(0, str(_BUILD_SUPPORT_ROOT))
candidate_builder = importlib.import_module(
    "build_support.build_trusted_time_v2_candidates"
    if __package__
    else "build_trusted_time_v2_candidates"
)
_ENTRY_ROOT = _ROOT / "tests/fixtures/native/trusted-time-v2/import-roots"
_RECEIPT_NAME = "linked-role-execution.json"


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _entry_manifest() -> list[dict[str, object]]:
    script = Path(__file__).resolve(strict=True)
    script_metadata = candidate_builder._regular_file(script)
    records: list[dict[str, object]] = [
        {
            "path": script.relative_to(_ROOT).as_posix(),
            "sha256": _sha256(script),
            "size": script_metadata.st_size,
        }
    ]
    for role in candidate_builder._ROLES:
        path = _ENTRY_ROOT / role.name / f"autoquant_trusted_time_v2_{role.name}_entry.py"
        metadata = candidate_builder._regular_file(path)
        records.append(
            {
                "path": path.relative_to(_ROOT).as_posix(),
                "sha256": _sha256(path),
                "size": metadata.st_size,
            }
        )
    return records


def _stage_entry_roots(build_root: Path) -> dict[str, dict[str, object]]:
    staged_root = build_root / "import-roots"
    staged_root.mkdir(mode=0o700)
    records: dict[str, dict[str, object]] = {}
    for role in candidate_builder._ROLES:
        basename = f"autoquant_trusted_time_v2_{role.name}_entry.py"
        source = _ENTRY_ROOT / role.name / basename
        destination_root = staged_root / role.name
        destination_root.mkdir(mode=0o700)
        destination = destination_root / basename
        shutil.copyfile(source, destination)
        destination.chmod(0o444)
        destination_root.chmod(0o555)
        metadata = candidate_builder._regular_file(destination)
        if _sha256(destination) != _sha256(source) or stat.S_IMODE(metadata.st_mode) != 0o444:
            candidate_builder._fail(f"the staged {role.name} linked-test entry changed")
        records[role.name] = {
            "directory_mode": "0555",
            "entry_mode": "0444",
            "entry_sha256": _sha256(destination),
            "ephemeral_import_root_during_execution": str(destination_root),
            "source_path": source.relative_to(_ROOT).as_posix(),
            "source_sha256": _sha256(source),
        }
    staged_root.chmod(0o555)
    return records


def _remove_build_root(build_root: Path) -> None:
    for directory in sorted(
        (path for path in build_root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        directory.chmod(0o700)
    build_root.chmod(0o700)
    shutil.rmtree(build_root)


def exercise(output_directory: Path) -> dict[str, object]:
    if sys.platform != "linux":
        candidate_builder._fail("linked lifecycle-v2 role execution is Linux-only")
    if not output_directory.is_absolute() or output_directory.exists():
        candidate_builder._fail("execution output directory must be one absent absolute path")
    parent = output_directory.parent.resolve(strict=True)
    if parent != output_directory.parent:
        candidate_builder._fail("the execution output-directory parent must be canonical")
    output_directory.mkdir(mode=0o700)
    build_root = output_directory / ".linked-test-profiles"
    build_root.mkdir(mode=0o700)

    toolchain = candidate_builder._toolchain()
    python = candidate_builder._python_build(toolchain)
    python_record = candidate_builder._python_record(python)
    python_record_sha256 = hashlib.sha256(
        json.dumps(
            python_record,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    compiler_record = candidate_builder._compiler_record(toolchain)
    audit_tools = candidate_builder._audit_tool_records(toolchain)
    source_manifest = candidate_builder._validate_sources()
    vendor = candidate_builder._validate_vendoring()
    entry_manifest = _entry_manifest()
    staged_entry_roots = _stage_entry_roots(build_root)
    test_child = Path("/usr/bin/true").resolve(strict=True)
    candidate_builder._regular_file(test_child)
    test_child_sha256 = _sha256(test_child)
    records: list[dict[str, object]] = []
    for role in candidate_builder._ROLES:
        import_root = Path(
            str(staged_entry_roots[role.name]["ephemeral_import_root_during_execution"])
        ).resolve(strict=True)
        definitions = (
            f"-D{role.role_macro}=1",
            f"-D{role.signer_macro}=1",
            "-DAQT_TRUSTED_TIME_V2_PORTABLE_TEST_PROFILE=1",
            "-DAQT_TRUSTED_TIME_V2_CANDIDATE_CLOSED_RUNTIME=1",
            candidate_builder._quoted_definition(
                "AQT_TRUSTED_TIME_V2_TEST_ROLE_IMPORT_ROOT", import_root
            ),
            *candidate_builder._python_definitions(
                role,
                python,
                recovery_standard_library=python.standard_library,
            ),
        )
        plan = candidate_builder._BuildPlan(
            basename=role.executable,
            kind="role",
            role=role.name,
            definitions=definitions,
            source_aliases=(
                candidate_builder._RECOVERY_SOURCE_ALIASES
                if role.name == "recovery"
                else candidate_builder._ROLE_SOURCE_ALIASES
            ),
            python_link=True,
        )
        built = candidate_builder._build_artifact(
            plan,
            build_root,
            toolchain,
            python,
        )
        candidate_builder._run((str(built.binary),))
        stages = ["fork_guard", "seccomp", "signer_self_test"]
        if role.name != "recovery":
            stages.append("endpoint_bootstrap")
        stages.append("fixed_python_entry")
        records.append(
            {
                "audit": built.audit,
                "binary_sha256": _sha256(built.binary),
                "build_commands": [list(command) for command in built.commands],
                "build_command_sha256": built.command_digest,
                "linked_source_aliases": list(plan.source_aliases),
                "object_sha256": dict(built.object_digests),
                "ordered_stages": stages,
                "profile_kind": "role",
                "role": role.name,
                "status": "passed",
            }
        )
        provisioner_plan = candidate_builder._BuildPlan(
            basename=role.provisioner,
            kind="provisioner",
            role=role.name,
            definitions=(
                f"-D{role.provisioner_macro}=1",
                "-DAQT_TRUSTED_TIME_V2_PROVISIONER_TEST_BUILD=1",
                candidate_builder._quoted_definition(
                    "AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256",
                    test_child_sha256,
                ),
                candidate_builder._quoted_definition(
                    "AQT_TRUSTED_TIME_V2_TEST_SYSTEMD_CREDS_PATH",
                    test_child,
                ),
            ),
            source_aliases=candidate_builder._PROVISIONER_SOURCE_ALIASES,
            python_link=False,
        )
        provisioner = candidate_builder._build_artifact(
            provisioner_plan,
            build_root,
            toolchain,
            python,
        )
        candidate_builder._run_expect_status((str(provisioner.binary),), 191)
        records.append(
            {
                "audit": provisioner.audit,
                "binary_sha256": _sha256(provisioner.binary),
                "build_commands": [list(command) for command in provisioner.commands],
                "build_command_sha256": provisioner.command_digest,
                "linked_source_aliases": list(provisioner_plan.source_aliases),
                "object_sha256": dict(provisioner.object_digests),
                "ordered_stages": [
                    "descriptor_and_signal_baseline",
                    "fork_guard",
                    "seccomp_pre_child",
                    "authority_consumer_enokey",
                    "fail_closed_191",
                ],
                "profile_kind": "provisioner",
                "role": role.name,
                "status": "expected_fail_closed_passed",
            }
        )
    if (
        candidate_builder._validate_sources() != source_manifest
        or candidate_builder._validate_vendoring() != vendor
        or _entry_manifest() != entry_manifest
        or candidate_builder._compiler_record(toolchain) != compiler_record
        or candidate_builder._audit_tool_records(toolchain) != audit_tools
        or candidate_builder._python_record(python) != python_record
        or _sha256(test_child) != test_child_sha256
    ):
        candidate_builder._fail("a linked-role execution input changed during the gate")
    for role, staged in staged_entry_roots.items():
        staged_entry = Path(str(staged["ephemeral_import_root_during_execution"])) / (
            f"autoquant_trusted_time_v2_{role}_entry.py"
        )
        if _sha256(staged_entry) != staged["entry_sha256"]:
            candidate_builder._fail(f"the staged {role} entry mutated during execution")
    _remove_build_root(build_root)

    result: dict[str, object] = {
        "activation_authorized": False,
        "audit_tools": audit_tools,
        "candidate_artifact": False,
        "command_environment": candidate_builder._command_environment(),
        "compiler": compiler_record,
        "entry_manifest": entry_manifest,
        "monocypher": vendor,
        "profiles": records,
        "production_candidate_receipt": None,
        "python_record_sha256": python_record_sha256,
        "schema": "autoquant-trusted-time-graceful-stop-v2-linked-role-execution-v1",
        "source_manifest_sha256": hashlib.sha256(
            json.dumps(
                source_manifest,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest(),
        "status": "linked_test_profiles_passed",
        "staged_entry_roots": staged_entry_roots,
        "test_profile": True,
        "test_profile_binaries_retained": False,
        "test_systemd_creds_substitute": {
            "path": str(test_child),
            "sha256": test_child_sha256,
        },
    }
    receipt = output_directory / _RECEIPT_NAME
    receipt.write_text(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    receipt.chmod(0o444)
    return result


def main(argument_values: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output-directory", required=True)
    arguments = parser.parse_args(argument_values)
    result = exercise(Path(arguments.output_directory))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
