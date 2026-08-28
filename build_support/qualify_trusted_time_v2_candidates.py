"""Run the complete Wave 7 candidate gate inside its locked Linux container."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import cast

_BUILD_SUPPORT_ROOT = Path(__file__).resolve(strict=True).parent
if not __package__:
    sys.path.insert(0, str(_BUILD_SUPPORT_ROOT))
candidate_builder = importlib.import_module(
    "build_support.build_trusted_time_v2_candidates"
    if __package__
    else "build_trusted_time_v2_candidates"
)
linked_test = importlib.import_module(
    "build_support.build_trusted_time_v2_linked_role_test"
    if __package__
    else "build_trusted_time_v2_linked_role_test"
)
exact_test = importlib.import_module(
    "build_support.exercise_trusted_time_v2_exact_candidates"
    if __package__
    else "exercise_trusted_time_v2_exact_candidates"
)
sdist_smoke = importlib.import_module(
    "build_support.smoke_trusted_time_v2_sdist" if __package__ else "smoke_trusted_time_v2_sdist"
)


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _canonical_sha256(document: object) -> str:
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _document(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="ascii"))
    if type(document) is not dict:
        raise RuntimeError(f"qualification receipt is not one object: {path}")
    return cast(dict[str, object], document)


def _required_digest(name: str) -> str:
    value = os.environ.get(name, "")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeError(f"qualification digest environment is invalid: {name}")
    return value


def _receipt_record(path: Path, document: dict[str, object]) -> dict[str, object]:
    return {
        "activation_authorized": document["activation_authorized"],
        "name": path.name,
        "schema": document["schema"],
        "sha256": _sha256(path),
        "status": document["status"],
    }


def _candidate_projection(
    path: Path,
    document: dict[str, object],
) -> dict[str, object]:
    artifacts = cast(list[dict[str, object]], document["artifacts"])
    import_trees = cast(dict[str, dict[str, object]], document["role_import_trees"])
    recovery_runtime = cast(dict[str, object], document["recovery_python_runtime"])
    seccomp_manifests = cast(dict[str, dict[str, object]], document["seccomp_manifests"])

    def audit_projection(record: dict[str, object]) -> dict[str, object]:
        audit = cast(dict[str, object], record["audit"])
        conditional = cast(dict[str, object], audit["monocypher_conditional_operations"])
        operations = cast(dict[str, dict[str, object]], conditional["operations"])
        return {
            "binary_strings_sha256": audit["binary_strings_sha256"],
            "build_id_absent": audit["build_id_absent"],
            "defined_symbol_count": audit["defined_symbol_count"],
            "defined_symbols_sha256": audit["defined_symbols_sha256"],
            "dynamic_dependencies": audit["dynamic_dependencies"],
            "dynamic_dependency_allowlist": audit["dynamic_dependency_allowlist"],
            "dynamic_dependency_exact": audit["dynamic_dependency_exact"],
            "dynamic_export_count": audit["dynamic_export_count"],
            "dynamic_exports_sha256": audit["dynamic_exports_sha256"],
            "elf_machine": audit["elf_machine"],
            "elf_pie": audit["elf_pie"],
            "forbidden_dynamic_dependencies_absent": audit["forbidden_dynamic_dependencies_absent"],
            "forbidden_exports_absent": audit["forbidden_exports_absent"],
            "full_relro": audit["full_relro"],
            "lto_absent": audit["lto_absent"],
            "monocypher_conditional_operations": {
                "exact_candidate_object": conditional["exact_candidate_object"],
                "mitigation_source_sha256": conditional["mitigation_source_sha256"],
                "object_sha256": conditional["object_sha256"],
                "operations": {
                    operation: {
                        "branchless_assertion_passed": evidence["branchless_assertion_passed"],
                        "disassembly_sha256": evidence["disassembly_sha256"],
                        "instruction_count": evidence["instruction_count"],
                        "required_instruction_counts": evidence["required_instruction_counts"],
                    }
                    for operation, evidence in sorted(operations.items())
                },
                "same_compile_flags_as_candidate": conditional["same_compile_flags_as_candidate"],
            },
            "nonexecutable_stack": audit["nonexecutable_stack"],
            "opposite_role_symbols_absent": audit["opposite_role_symbols_absent"],
            "recovery_exclusions_passed": audit["recovery_exclusions_passed"],
            "recovery_preprocessed_sources": audit["recovery_preprocessed_sources"],
            "role_socket_surface": audit["role_socket_surface"],
            "test_symbols_absent": audit["test_symbols_absent"],
            "undefined_symbol_count": audit["undefined_symbol_count"],
            "undefined_symbols_sha256": audit["undefined_symbols_sha256"],
        }

    return {
        "activation_authorized": document["activation_authorized"],
        "architecture_binding": document["architecture_binding"],
        "artifacts": [
            {
                "basename": record["basename"],
                "audit": audit_projection(record),
                "build_command_sha256": record["build_command_sha256"],
                "build_commands": record["build_commands"],
                "import_tree": record["import_tree"],
                "kind": record["kind"],
                "link_map_sha256": record["link_map_sha256"],
                "object_sha256": record["object_sha256"],
                "python_runtime": record["python_runtime"],
                "reproducible_build_count": record["reproducible_build_count"],
                "role": record["role"],
                "seccomp_binding": record["seccomp_binding"],
                "sha256": record["sha256"],
                "size": record["size"],
                "source_aliases": record["source_aliases"],
            }
            for record in artifacts
        ],
        "audit_tools": document["audit_tools"],
        "command_environment": document["command_environment"],
        "command_path_placeholders": document["command_path_placeholders"],
        "compiler": document["compiler"],
        "first_party_crypto_calls": document["first_party_crypto_calls"],
        "monocypher": document["monocypher"],
        "production_release_root": document["production_release_root"],
        "python": document["python"],
        "receipt_sha256": _sha256(path),
        "recovery_python_runtime": recovery_runtime,
        "role_import_trees": {role: record for role, record in sorted(import_trees.items())},
        "reproducible_build_count": document["reproducible_build_count"],
        "seccomp_manifests": {
            profile: {
                "bpf_phases": record["bpf_phases"],
                "manifest_sha256": record["manifest_sha256"],
                "output_name": record["output_name"],
                "source_sha256": record["source_sha256"],
            }
            for profile, record in sorted(seccomp_manifests.items())
        },
        "source_manifest": document["source_manifest"],
        "status": document["status"],
        "systemd_creds": document["systemd_creds"],
    }


def _exact_projection(path: Path, document: dict[str, object]) -> dict[str, object]:
    executions = cast(list[dict[str, object]], document["executions"])
    candidate_receipt = cast(dict[str, object], document["candidate_build_receipt"])
    return {
        "base_image": document["base_image"],
        "candidate_artifacts_copied_back": document["candidate_artifacts_copied_back"],
        "candidate_build_receipt": {
            "ephemeral_path_during_qualification": candidate_receipt["path"],
            "sha256": candidate_receipt["sha256"],
        },
        "candidate_staging_persisted": document["candidate_staging_persisted"],
        "container_boundary": document["container_boundary"],
        "container_packages": document["container_packages"],
        "dpkg_status_sha256": document["dpkg_status_sha256"],
        "enokey_consumer_probe_bound": document["enokey_consumer_probe_bound"],
        "exact_execution_count": document["exact_execution_count"],
        "executions": [
            {
                "candidate_artifact_sha256": record["candidate_artifact_sha256"],
                "candidate_sha256": record["candidate_sha256"],
                "expected_status": record["expected_status"],
                "kind": record["kind"],
                "marker": record["marker"],
                "marker_count": record["marker_count"],
                "output_sha256": record["output_sha256"],
                "path": record["path"],
                "role": record["role"],
                "status": record["status"],
            }
            for record in executions
        ],
        "qualification_image_id": document["qualification_image_id"],
        "python_mount_provenance": document["python_mount_provenance"],
        "receipt_sha256": _sha256(path),
        "snapshot_sha256": {
            "input": document["input_snapshot_sha256"],
            "output": document["output_snapshot_sha256"],
        },
        "status": document["status"],
        "systemd_creds": document["systemd_creds"],
        "transient_container_opt_staging_removed": document[
            "transient_container_opt_staging_removed"
        ],
        "transient_exact_path_staging_performed": document[
            "transient_exact_path_staging_performed"
        ],
        "runtime_owner_installed": document["runtime_owner_installed"],
    }


def _linked_projection(path: Path, document: dict[str, object]) -> dict[str, object]:
    profiles = cast(list[dict[str, object]], document["profiles"])
    return {
        "activation_authorized": document["activation_authorized"],
        "candidate_artifact": document["candidate_artifact"],
        "entry_manifest": document["entry_manifest"],
        "production_candidate_receipt": document["production_candidate_receipt"],
        "profiles": [
            {
                "binary_sha256": record["binary_sha256"],
                "linked_source_aliases": record["linked_source_aliases"],
                "ordered_stages": record["ordered_stages"],
                "profile_kind": record["profile_kind"],
                "role": record["role"],
                "status": record["status"],
            }
            for record in profiles
        ],
        "receipt_sha256": _sha256(path),
        "python_record_sha256": document["python_record_sha256"],
        "staged_entry_roots": document["staged_entry_roots"],
        "status": document["status"],
        "test_profile": document["test_profile"],
        "test_profile_binaries_retained": document["test_profile_binaries_retained"],
    }


def main() -> int:
    workspace = Path("/workspace")
    sdist_archive_sha256 = _required_digest("AQT_WAVE7_SDIST_ARCHIVE_SHA256")
    sdist_root_sha256 = _required_digest("AQT_WAVE7_SDIST_ROOT_SHA256")
    tree_records, observed_root_sha256 = sdist_smoke._tree_manifest(workspace)
    if observed_root_sha256 != sdist_root_sha256:
        raise RuntimeError("the mounted extracted sdist differs from its validated host receipt")
    qualification_python_home = str(Path(sys.base_prefix).resolve(strict=True))
    exact_test._validate_container_boundary(qualification_python_home)
    qualification_python_before = candidate_builder._python_record(
        candidate_builder._python_build(candidate_builder._toolchain())
    )

    evidence = Path("/opt/.wave7-evidence")
    if evidence.exists():
        raise RuntimeError("the transient qualification evidence root is not absent")
    evidence.mkdir(mode=0o700)
    temporary = evidence / "tmp"
    temporary.mkdir(mode=0o700)
    os.environ["TMPDIR"] = str(temporary)
    tempfile.tempdir = str(temporary)
    candidates = evidence / "candidates"
    linked = evidence / "linked"
    exact = evidence / "exact"
    candidate_builder.build(candidates)
    linked_test.exercise(linked)
    exact_test.exercise(candidates, exact)
    after_tree_records, after_root_sha256 = sdist_smoke._tree_manifest(workspace)
    if after_root_sha256 != observed_root_sha256 or after_tree_records != tree_records:
        raise RuntimeError("qualification mutated its read-only extracted-sdist source")

    candidate_path = candidates / "candidate-build.json"
    linked_path = linked / "linked-role-execution.json"
    exact_path = exact / "exact-candidate-execution.json"
    candidate_document = _document(candidate_path)
    linked_document = _document(linked_path)
    exact_document = _document(exact_path)
    if candidate_document.get("python") != qualification_python_before:
        raise RuntimeError("candidate build did not bind the pre-build qualification Python mount")
    if linked_document.get("python_record_sha256") != _canonical_sha256(
        qualification_python_before
    ):
        raise RuntimeError("linked tests did not bind the qualification Python mount")
    qualification_python_after = candidate_builder._python_record(
        candidate_builder._python_build(candidate_builder._toolchain())
    )
    if qualification_python_after != qualification_python_before:
        raise RuntimeError("qualification mutated the read-only managed Python base prefix")
    result = {
        "activation_authorized": False,
        "candidate_artifacts_copied_back": False,
        "candidate_build": _candidate_projection(candidate_path, candidate_document),
        "exact_execution": _exact_projection(exact_path, exact_document),
        "ephemeral_evidence_root": str(evidence),
        "linked_test": _linked_projection(linked_path, linked_document),
        "managed_python_mount": {
            "post_qualification_sha256": _canonical_sha256(qualification_python_after),
            "pre_qualification_sha256": _canonical_sha256(qualification_python_before),
            "unchanged": True,
        },
        "receipts": [
            _receipt_record(candidate_path, candidate_document),
            _receipt_record(linked_path, linked_document),
            _receipt_record(exact_path, exact_document),
        ],
        "schema": "autoquant-trusted-time-graceful-stop-v2-container-qualification-v1",
        "source_sdist": {
            "archive_sha256": sdist_archive_sha256,
            "extracted_root_entry_count": len(tree_records),
            "extracted_root_sha256": sdist_root_sha256,
            "workspace_post_qualification_sha256": after_root_sha256,
            "workspace_pre_qualification_sha256": observed_root_sha256,
        },
        "status": "passed",
    }
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
