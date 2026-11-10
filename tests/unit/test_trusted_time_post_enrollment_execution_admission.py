from __future__ import annotations

import copy
import dis
import fcntl
import gc
import hashlib
import json
import os
import pickle
import stat
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from packages.adapters.trusted_time.ed25519_operator_attestation import (
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    build_post_enrollment_operator_attestation_envelope,
    build_post_enrollment_operator_attestation_statement,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts import trusted_time_post_enrollment_execution_admission as execution
from scripts import verify_trusted_time_images as image_verifier
from scripts.trusted_time_post_enrollment_execution_admission import (
    POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION,
    POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION,
    POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX,
    POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
    POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
    POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS,
    TrustedTimePostEnrollmentExecutionAdmissionRejected,
    TrustedTimePostEnrollmentExecutionAttemptConsumed,
    TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed,
    load_post_enrollment_execution_approval,
    post_enrollment_execution_approval_artifact_path,
    post_enrollment_execution_approval_bytes,
    retain_post_enrollment_execution_approval,
)
from scripts.verify_trusted_time_images import (
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    TrustedTimeImageAdmission,
    TrustedTimeImageIdentities,
)

OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"
SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256 = "d" * 64


def _reviewed_bindings() -> image_verifier._ReviewedInputBindings:
    return image_verifier._make_reviewed_input_bindings(
        authority_sha256="9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c",
        chrony_config_sha256="5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23",
        compose_sha256="445a8db57052d973934d710562891ec1a4307af2ba2082c4f30e6da579d29240",
        database_ca_sha256="700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7",
        dockerfile_sha256="96b1fe3f7358965bf9a5c0d4b99e0fe68abe68daf73ba4247dcaa8f00d606c87",
        migration_sha256="9928c457f2593c7b3b4d6f3520eec716bb63375edb1dba3226d44d88cddcdda4",
        schema_revision="0036_phase6_time_anchors",
        catalog_relations=(
            "phase6_trusted_time_head_anchor_intents",
            "phase6_trusted_time_head_anchor_receipts",
        ),
        source_revision_sha256=("34db2fefb35b3222d903ca2771756d6826b8d72e0ae6d697fb5eafda68984e52"),
        uv_lock_sha256="3a7acc80ba5a76eda440a78058b8e35041d9bd012ab2d474623734d7711970d9",
    )


@pytest.fixture(autouse=True)
def _use_public_fixed_vector_reviewed_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep public signature vectors independent from concurrent source-tree edits."""

    monkeypatch.setattr(image_verifier, "reviewed_input_bindings", _reviewed_bindings)


def _identities() -> TrustedTimeFirstEnrollmentIdentities:
    return TrustedTimeFirstEnrollmentIdentities(
        anchor_authority_sha256="1" * 64,
        anchor_project_identity_sha256="2" * 64,
        bucket_identity_sha256="3" * 64,
        deployment_identity_sha256="4" * 64,
        host_identity_sha256="5" * 64,
        principal_identity_sha256="6" * 64,
        runtime_database_identity_sha256="7" * 64,
        signing_public_key_sha256="8" * 64,
        source_authority_sha256="9" * 64,
    )


def _sequence_one() -> TrustedTimeSequenceOneEvidence:
    return TrustedTimeSequenceOneEvidence(
        completion_disposition="new_intent_completed",
        uploaded_anchor_count=1,
        idempotent_duplicate_count=0,
        anchor_intent_semantic_sha256="a" * 64,
        candidate_remote_readback_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        current_anchor_sha256="b" * 64,
        current_host_head_sha256="d" * 64,
        receipt_semantic_sha256="e" * 64,
        remote_namespace_sha256="f" * 64,
    )


def _confirmed() -> TrustedTimeConfirmedFirstEnrollment:
    return TrustedTimeConfirmedFirstEnrollment(
        operation_id="123e4567-e89b-42d3-a456-426614174000",
        approval_sha256="0" * 64,
        claim_sha256="1" * 64,
        outcome_sha256="2" * 64,
        unenrolled_admission_sha256="3" * 64,
        enrollment_launch=TrustedTimeImmutableLaunchEvidence(
            git_revision="a" * 40,
            image_admission_sha256="4" * 64,
            source_image_id="sha256:" + "5" * 64,
            supervisor_image_id="sha256:" + "6" * 64,
        ),
        identities=_identities(),
        sequence_one=_sequence_one(),
    )


def _approval(
    *,
    operation_id: str = OPERATION_ID,
    image_admission_sha256: str = "7" * 64,
) -> TrustedTimePostEnrollmentStartApproval:
    return TrustedTimePostEnrollmentStartApproval(
        operation_id=operation_id,
        review=build_post_enrollment_start_review(
            confirmed_enrollment=_confirmed(),
            proposed_launch=TrustedTimeImmutableLaunchEvidence(
                git_revision="f" * 40,
                image_admission_sha256=image_admission_sha256,
                source_image_id="sha256:" + "8" * 64,
                supervisor_image_id="sha256:" + "9" * 64,
            ),
        ),
    )


def _artifact_roots(tmp_path: Path) -> tuple[Path, Path]:
    ignored_root = tmp_path / "artifacts"
    ignored_root.mkdir(mode=0o700)
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(mode=0o700)
    return ignored_root, artifact_directory


def _retain_approval(
    tmp_path: Path,
    *,
    approval: TrustedTimePostEnrollmentStartApproval | None = None,
) -> tuple[Path, Path, TrustedTimePostEnrollmentStartApproval, Path, bytes]:
    ignored_root, artifact_directory = _artifact_roots(tmp_path)
    bindings = _reviewed_bindings()
    provenance_encoded = image_verifier._canonical_json_bytes(
        image_verifier._admission_payload(
            TrustedTimeImageIdentities(
                source_id="sha256:" + "8" * 64,
                supervisor_id="sha256:" + "9" * 64,
            ),
            bindings,
            supervisor_executable_import_manifest_sha256=(
                SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
            ),
            boot_session_id="darwin:11111111-2222-3333-4444-555555555555",
            git_revision="f" * 40,
            created_at_utc="2026-08-08T15:00:00.000000Z",
            created_monotonic_ns=1,
        )
    )
    provenance_sha256 = hashlib.sha256(provenance_encoded).hexdigest()
    provenance_path = artifact_directory / f"image-admission-{provenance_sha256}.json"
    provenance_path.write_bytes(provenance_encoded)
    provenance_path.chmod(0o600)
    exact = approval or _approval(image_admission_sha256=provenance_sha256)
    encoded = post_enrollment_execution_approval_bytes(
        exact,
        expected_approval_sha256=exact.approval_sha256,
    )
    path = post_enrollment_execution_approval_artifact_path(
        exact,
        expected_approval_sha256=exact.approval_sha256,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    path.write_bytes(encoded)
    path.chmod(0o600)
    return ignored_root, artifact_directory, exact, path, encoded


def _image_admission(
    approval: TrustedTimePostEnrollmentStartApproval,
    artifact_directory: Path,
    *,
    created_monotonic_ns: int,
    **changes: object,
) -> TrustedTimeImageAdmission:
    bindings = _reviewed_bindings()
    encoded = image_verifier._canonical_json_bytes(
        image_verifier._admission_payload(
            TrustedTimeImageIdentities(
                source_id=approval.proposed_launch.source_image_id,
                supervisor_id=approval.proposed_launch.supervisor_image_id,
            ),
            bindings,
            supervisor_executable_import_manifest_sha256=(
                SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
            ),
            boot_session_id="darwin:11111111-2222-3333-4444-555555555555",
            git_revision=approval.proposed_launch.git_revision,
            created_at_utc="2026-08-08T16:00:00.000000Z",
            created_monotonic_ns=created_monotonic_ns,
        )
    )
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    path = artifact_directory / f"image-admission-{artifact_sha256}.json"
    path.write_bytes(encoded)
    path.chmod(0o600)
    admission = TrustedTimeImageAdmission(
        path=path,
        identities=TrustedTimeImageIdentities(
            source_id=approval.proposed_launch.source_image_id,
            supervisor_id=approval.proposed_launch.supervisor_image_id,
        ),
        boot_session_id="darwin:11111111-2222-3333-4444-555555555555",
        git_revision=approval.proposed_launch.git_revision,
        source_revision_sha256=tuple.__getitem__(bindings, 9),
        artifact_sha256=artifact_sha256,
        created_at_utc="2026-08-08T16:00:00.000000Z",
        created_monotonic_ns=created_monotonic_ns,
    )
    return replace(admission, **changes)  # type: ignore[arg-type]


class _ImageLoader:
    def __init__(self, admission: TrustedTimeImageAdmission) -> None:
        self.admission = admission
        self.calls: list[tuple[Path, Path, int]] = []

    def __call__(
        self,
        path: Path,
        *,
        ignored_root: Path,
        monotonic_ns: int,
    ) -> TrustedTimeImageAdmission:
        self.calls.append((path, ignored_root, monotonic_ns))
        return self.admission


_FIXED_EXECUTION_APPROVAL_V2_SHA256 = (
    "ab0c3007a88d626375a05347f1bea0eba2928997182eadd597b36b24bd023886"
)
_FIXED_OPERATOR_ATTESTATION_SIGNATURE = bytes.fromhex(
    "a3c8afeedde9ba9ad33f421952ceadc8700f02a33dc1563844bd5462017a2038e"
    "3c3d6d57ea8c7753df05163a69a55080d7f7f48e14db382fa2b9d6164c58901"
)
_SEMANTICALLY_INVALID_V2_SIGNATURE = bytes.fromhex(
    "93b1832b809b989f90b750b3d64ba2eb82eaea390934bc388ca7bc90c3b686e1"
    "64cf6b9f8a738b381c4a518a4e7f460c1a5d6fcae6d3a0088b27a3629becb708"
)


def _operator_attested_artifact(
    *,
    approval_artifact: Path,
    ignored_root: Path,
) -> tuple[Path, bytes]:
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    execution_approval_v2 = approval_artifact.read_bytes()
    assert hashlib.sha256(execution_approval_v2).hexdigest() == (
        _FIXED_EXECUTION_APPROVAL_V2_SHA256
    )
    statement = build_post_enrollment_operator_attestation_statement(
        authority=authority,
        execution_approval_v2_sha256=hashlib.sha256(execution_approval_v2).hexdigest(),
    )
    envelope = build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=execution_approval_v2,
        statement=statement,
        signature_ed25519=_FIXED_OPERATOR_ATTESTATION_SIGNATURE,
    )
    encoded = canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
    envelope_sha256 = hashlib.sha256(encoded).hexdigest()
    external_directory = ignored_root.parent / "external-operator-attested-approvals"
    external_directory.mkdir(mode=0o700, exist_ok=True)
    external_directory.chmod(0o700)
    path = external_directory / (
        f"{execution.POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX}{envelope_sha256}.json"
    )
    if not path.exists():
        path.write_bytes(encoded)
        path.chmod(0o600)
    return path, authority_encoded


def _load_operator_attested_fixture(
    *,
    approval_artifact: Path,
    artifact_directory: Path,
    ignored_root: Path,
) -> tuple[
    Path,
    bytes,
    execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
]:
    path, authority_encoded = _operator_attested_artifact(
        approval_artifact=approval_artifact,
        ignored_root=ignored_root,
    )
    loaded = execution._load_post_enrollment_operator_attested_execution_approval(
        operator_attested_approval_artifact=path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        image_provenance_loader=image_verifier.load_image_admission_provenance_artifact,
        git_operator_authority_loader=lambda _: (
            "100644",
            "b" * 40,
            authority_encoded,
        ),
    )
    return path, authority_encoded, loaded


def _retained_attempt_fixture(
    tmp_path: Path,
) -> tuple[
    Path,
    Path,
    Path,
    execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
    dict[str, object],
    bytes,
]:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    attested_path, _, loaded = _load_operator_attested_fixture(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    provenance = loaded.image_provenance
    checked_monotonic_ns = provenance.created_monotonic_ns + 1
    payload = execution._attempt_slot_payload(
        loaded_attested_approval=loaded,
        image_provenance=provenance,
        image_witness=provenance,
        observed_monotonic_ns=checked_monotonic_ns,
        remaining_headroom_ns=(
            image_verifier.IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
            - (checked_monotonic_ns - provenance.created_monotonic_ns)
        ),
    )
    encoded = canonical_first_enrollment_json_bytes(payload)
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    slot_path.write_bytes(encoded)
    slot_path.chmod(0o600)
    return (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        payload,
        encoded,
    )


def _load_retained_fixture(
    *,
    attested_path: Path,
    artifact_directory: Path,
    ignored_root: Path,
    loaded: execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
) -> execution.RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt:
    return execution._load_retained_post_enrollment_operator_attested_execution_attempt(
        start_operator_attested_approval_artifact=attested_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        operator_attested_approval_loader=lambda **_: loaded,
    )


def _historical_attempt_slot_bytes(
    loaded: execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
) -> bytes:
    approval = loaded.approval
    provenance = loaded.image_provenance
    payload = execution._closed_payload()
    payload.update(execution._tuple_payload(approval))
    payload.update(
        {
            "approval_artifact_sha256": loaded.execution_approval_v2_sha256,
            "approved_image_provenance_source_revision_sha256": (provenance.source_revision_sha256),
            "contract_version": (
                execution.HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
            ),
            "image_witness_boot_session_id": provenance.boot_session_id,
            "image_witness_checked_monotonic_ns": provenance.created_monotonic_ns,
            "image_witness_contract_version": image_verifier.IMAGE_ADMISSION_CONTRACT_VERSION,
            "image_witness_created_monotonic_ns": provenance.created_monotonic_ns,
            "image_witness_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "image_witness_remaining_headroom_nanoseconds": 1,
            "image_witness_sha256": provenance.artifact_sha256,
            "image_witness_source_revision_sha256": provenance.source_revision_sha256,
            "service": execution.POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE,
            "status": "execution_attempt_reserved",
        }
    )
    return canonical_first_enrollment_json_bytes(payload)


def _admitter(
    *,
    loader: _ImageLoader,
    observed: list[int],
    process_id: Any = os.getpid,
) -> tuple[Any, Any, Any]:
    values = iter(observed)
    authority_by_artifact: dict[Path, bytes] = {}
    attested_path_by_v2_artifact: dict[Path, Path] = {}
    attested_load_calls: list[Path] = []

    def load_attested(
        *,
        operator_attested_approval_artifact: Path,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
        attested_load_calls.append(operator_attested_approval_artifact)
        authority_encoded = authority_by_artifact[operator_attested_approval_artifact]
        return execution._load_post_enrollment_operator_attested_execution_approval(
            operator_attested_approval_artifact=operator_attested_approval_artifact,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            image_provenance_loader=(image_verifier.load_image_admission_provenance_artifact),
            git_operator_authority_loader=lambda _: (
                "100644",
                "b" * 40,
                authority_encoded,
            ),
        )

    reserve, validate, consume = execution._build_execution_admitter(
        image_admission_loader=loader,
        operator_attested_approval_loader=load_attested,
        monotonic_ns=lambda: next(values),
        process_id=process_id,
    )

    def admit(
        *,
        approval_artifact: Path,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> object:
        operator_attested_path, authority_encoded = _operator_attested_artifact(
            approval_artifact=approval_artifact,
            ignored_root=ignored_root,
        )
        authority_by_artifact[operator_attested_path] = authority_encoded
        attested_path_by_v2_artifact[approval_artifact] = operator_attested_path
        loaded = load_attested(
            operator_attested_approval_artifact=operator_attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return reserve(
            loaded_attested_approval=loaded,
            image_admission=loader.admission,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    def consume_attested(
        candidate: object,
        *,
        approval_artifact: Path,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        return consume(
            candidate,
            operator_attested_approval_artifact=(
                attested_path_by_v2_artifact.get(approval_artifact, approval_artifact)
            ),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    admit._reserve = reserve  # type: ignore[attr-defined]
    admit._attested_paths = attested_path_by_v2_artifact  # type: ignore[attr-defined]
    admit._attested_load_calls = attested_load_calls  # type: ignore[attr-defined]
    return admit, validate, consume_attested


def _interrupt_instruction(
    target: Any,
    instruction_offset: int,
    action: Any,
    *,
    async_error: type[BaseException] = KeyboardInterrupt,
) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == instruction_offset:
            raise async_error()

    sys.monitoring.use_tool_id(tool_id, "execution-admission-instruction-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        action()
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)


def _open_descriptor_names() -> set[str]:
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.exists():
        descriptor_root = Path("/dev/fd")
    return {entry.name for entry in descriptor_root.iterdir()}


@pytest.mark.parametrize("relative", [False, True])
def test_owned_descriptor_call_store_interruption_closes_native_result(
    tmp_path: Path,
    relative: bool,
) -> None:
    target = execution._open_owned_descriptor
    stores = [
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "STORE_FAST" and instruction.argval == "owner"
    ]
    parent_owner = execution._open_owned_descriptor(
        tmp_path,
        flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    before = _open_descriptor_names()
    try:
        with pytest.raises(KeyboardInterrupt):
            _interrupt_instruction(
                target,
                stores[1 if relative else 0],
                lambda: target(
                    "." if relative else tmp_path,
                    flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    dir_fd=parent_owner.fileno() if relative else None,
                ),
            )
        gc.collect()
        assert _open_descriptor_names() == before
    finally:
        parent_owner.close()


def test_owned_descriptor_close_retries_one_async_interruption(
    tmp_path: Path,
) -> None:
    owner = execution._open_owned_descriptor(
        tmp_path,
        flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    descriptor = owner.fileno()
    target = execution._OwnedFileDescriptor.close
    instructions = list(dis.get_instructions(target))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "value"
    )
    with pytest.raises(KeyboardInterrupt):
        _interrupt_instruction(
            target,
            instructions[store_index + 1].offset,
            owner.close,
        )

    assert owner.value == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_execution_approval_artifact_is_exact_closed_and_content_addressed(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory = _artifact_roots(tmp_path)
    approval = _approval()
    encoded = post_enrollment_execution_approval_bytes(
        approval,
        expected_approval_sha256=approval.approval_sha256,
    )
    payload = json.loads(encoded)
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    path = post_enrollment_execution_approval_artifact_path(
        approval,
        expected_approval_sha256=approval.approval_sha256,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert payload["contract_version"] == POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION
    assert payload["status"] == "execution_approval_artifact"
    assert payload["approval"] == approval.payload()
    assert payload["approval_sha256"] == approval.approval_sha256
    assert payload["operation_id"] == approval.operation_id
    assert payload["review_projection_sha256"] == approval.review.projection_sha256
    assert (
        payload["confirmed_enrollment_evidence_sha256"]
        == approval.confirmed_enrollment.evidence_sha256
    )
    assert payload["git_revision"] == approval.proposed_launch.git_revision
    assert (
        payload["approved_image_provenance_sha256"]
        == approval.proposed_launch.image_admission_sha256
    )
    assert payload["source_image_id"] == approval.proposed_launch.source_image_id
    assert payload["supervisor_image_id"] == approval.proposed_launch.supervisor_image_id
    assert (
        payload["image_witness_minimum_headroom_seconds"]
        == POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
    )
    assert payload["image_witness_contract_version"] == (
        image_verifier.IMAGE_ADMISSION_CONTRACT_VERSION
    )
    for field_name in (
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *execution._CLOSED_EXECUTION_FIELDS,
    ):
        assert payload[field_name] is False
    assert path.name == (f"{POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX}{artifact_sha256}.json")
    assert canonical_first_enrollment_json_bytes(payload) == encoded


def test_load_reconstructs_exact_approval_from_owner_only_inode_and_bytes(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, path, encoded = _retain_approval(tmp_path)

    loaded = load_post_enrollment_execution_approval(
        approval_artifact=path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert loaded.approval == approval
    assert loaded.approval is not approval
    assert loaded.artifact_path == path
    assert loaded.artifact_sha256 == hashlib.sha256(encoded).hexdigest()
    assert loaded.encoded == encoded
    assert stat.S_IMODE(loaded.file_identity[2]) == 0o600
    assert loaded.file_identity[5] == 1

    wrong_name = path.with_name(path.name.replace(path.name[-69:-5], "0" * 64))
    path.rename(wrong_name)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        load_post_enrollment_execution_approval(
            approval_artifact=wrong_name,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_retain_stable_approval_is_o_excl_durable_and_exactly_idempotent(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, prior_path, encoded = _retain_approval(tmp_path)
    prior_path.unlink()

    first = retain_post_enrollment_execution_approval(
        approval,
        expected_approval_sha256=approval.approval_sha256,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    second = retain_post_enrollment_execution_approval(
        approval,
        expected_approval_sha256=approval.approval_sha256,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert first == second
    assert first.encoded == encoded
    assert first.artifact_path == prior_path
    assert stat.S_IMODE(first.artifact_path.stat().st_mode) == 0o600
    assert first.file_identity == second.file_identity

    first.artifact_path.write_bytes(b"tampered")
    first.artifact_path.chmod(0o600)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        retain_post_enrollment_execution_approval(
            approval,
            expected_approval_sha256=approval.approval_sha256,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_exact_approval_retry_reestablishes_file_and_directory_durability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, approval, path, encoded = _retain_approval(tmp_path)
    path.unlink()
    real_fsync = os.fsync
    failed_directory_fsync = False

    def fail_first_directory_fsync(descriptor: int) -> None:
        nonlocal failed_directory_fsync
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode) and not failed_directory_fsync:
            failed_directory_fsync = True
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_directory_fsync)
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="retention is unconfirmed",
    ):
        retain_post_enrollment_execution_approval(
            approval,
            expected_approval_sha256=approval.approval_sha256,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    ambiguous_identity = (path.stat().st_dev, path.stat().st_ino)
    assert path.read_bytes() == encoded

    def fail_retry_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected retry directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_retry_directory_fsync)
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="retention is unconfirmed",
    ):
        retain_post_enrollment_execution_approval(
            approval,
            expected_approval_sha256=approval.approval_sha256,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    observed_fsync_kinds: list[str] = []

    def observe_retry_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        observed_fsync_kinds.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", observe_retry_fsync)
    retained = retain_post_enrollment_execution_approval(
        approval,
        expected_approval_sha256=approval.approval_sha256,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert retained.encoded == encoded
    assert (path.stat().st_dev, path.stat().st_ino) == ambiguous_identity
    assert observed_fsync_kinds == ["file", "directory"]


def test_retain_stable_approval_reports_async_partial_write_as_unconfirmed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, approval, path, _ = _retain_approval(tmp_path)
    path.unlink()
    real_write = os.write
    interrupted = False

    class InjectedInterrupt(BaseException):
        pass

    def interrupt_after_prefix(descriptor: int, value: Any) -> int:
        nonlocal interrupted
        if stat.S_ISREG(os.fstat(descriptor).st_mode) and not interrupted:
            interrupted = True
            real_write(descriptor, bytes(value[:1]))
            raise InjectedInterrupt
        return real_write(descriptor, value)

    monkeypatch.setattr(os, "write", interrupt_after_prefix)
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="retention is unconfirmed",
    ) as captured:
        retain_post_enrollment_execution_approval(
            approval,
            expected_approval_sha256=approval.approval_sha256,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert isinstance(captured.value.__cause__, InjectedInterrupt)
    monkeypatch.setattr(os, "write", real_write)

    assert path.exists()
    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        retain_post_enrollment_execution_approval(
            approval,
            expected_approval_sha256=approval.approval_sha256,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_retain_approval_open_call_store_interruption_is_unconfirmed_and_closes_fd(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, path, _ = _retain_approval(tmp_path)
    path.unlink()
    target = retain_post_enrollment_execution_approval
    store_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "file_owner"
        and instruction.offset > 600
    )
    before = _open_descriptor_names()

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="retention is unconfirmed",
    ) as unconfirmed:
        _interrupt_instruction(
            target,
            store_offset,
            lambda: retain_post_enrollment_execution_approval(
                approval,
                expected_approval_sha256=approval.approval_sha256,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ),
        )

    gc.collect()
    assert isinstance(unconfirmed.value.__cause__, KeyboardInterrupt)
    assert path.exists()
    assert path.read_bytes() == b""
    assert _open_descriptor_names() == before
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="retention is unconfirmed",
    ):
        retain_post_enrollment_execution_approval(
            approval,
            expected_approval_sha256=approval.approval_sha256,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_execution_wrapper_v1_is_historical_only_and_never_translated(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, path, encoded = _retain_approval(tmp_path)
    payload = json.loads(encoded)
    payload["contract_version"] = "phase6d-post-enrollment-start-execution-approval-v1"
    changed = canonical_first_enrollment_json_bytes(payload)
    changed_path = path.with_name(
        f"{POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX}"
        f"{hashlib.sha256(changed).hexdigest()}.json"
    )
    changed_path.write_bytes(changed)
    changed_path.chmod(0o600)

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        load_post_enrollment_execution_approval(
            approval_artifact=changed_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


@pytest.mark.parametrize("mutation", ["missing", "tampered", "same_bytes_replacement"])
def test_early_approval_load_authenticates_exact_base_provenance_inode(
    tmp_path: Path,
    mutation: str,
) -> None:
    ignored_root, artifact_directory, approval, path, _ = _retain_approval(tmp_path)
    provenance_path = artifact_directory / (
        f"image-admission-{approval.proposed_launch.image_admission_sha256}.json"
    )
    encoded = provenance_path.read_bytes()
    if mutation == "missing":
        provenance_path.unlink()
    elif mutation == "tampered":
        provenance_path.write_bytes(b"x" + encoded[1:])
        provenance_path.chmod(0o600)
    else:
        replacement = artifact_directory / ".replacement-base-provenance"
        replacement.write_bytes(encoded)
        replacement.chmod(0o600)
        replacement.replace(provenance_path)

    if mutation == "same_bytes_replacement":
        # Early load authenticates the replacement as the exact current inode;
        # late admission freezes and compares that identity again.
        assert (
            load_post_enrollment_execution_approval(
                approval_artifact=path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ).image_provenance.encoded
            == encoded
        )
    else:
        with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
            load_post_enrollment_execution_approval(
                approval_artifact=path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )


@pytest.mark.parametrize("failure", ["mode", "hardlink", "tamper", "symlink"])
def test_load_fails_closed_for_unsafe_or_changed_artifact(
    tmp_path: Path,
    failure: str,
) -> None:
    ignored_root, artifact_directory, _, path, encoded = _retain_approval(tmp_path)
    if failure == "mode":
        path.chmod(0o640)
    elif failure == "hardlink":
        os.link(path, artifact_directory / "extra-link")
    elif failure == "tamper":
        payload = json.loads(encoded)
        payload["status"] = "tampered"
        path.write_bytes(canonical_first_enrollment_json_bytes(payload))
        path.chmod(0o600)
    else:
        target = artifact_directory / "target"
        target.write_bytes(encoded)
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target.name)

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        load_post_enrollment_execution_approval(
            approval_artifact=path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_admission_reserves_exact_permanent_slot_and_is_consumed_once(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    observed = created + 100 * 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, consume = _admitter(
        loader=loader,
        observed=[observed, observed + 1, observed + 2],
    )

    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    slot_encoded = slot_path.read_bytes()
    slot = json.loads(slot_encoded)
    assert stat.S_IMODE(slot_path.stat().st_mode) == 0o600
    assert slot["contract_version"] == POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
    assert slot["status"] == "execution_attempt_reserved"
    assert slot["approval_sha256"] == approval.approval_sha256
    assert slot["operation_id"] == approval.operation_id
    assert slot["review_projection_sha256"] == approval.review.projection_sha256
    assert (
        slot["confirmed_enrollment_evidence_sha256"]
        == approval.confirmed_enrollment.evidence_sha256
    )
    assert slot["git_revision"] == approval.proposed_launch.git_revision
    assert (
        slot["approved_image_provenance_sha256"] == approval.proposed_launch.image_admission_sha256
    )
    assert slot["image_witness_sha256"] == loader.admission.artifact_sha256
    assert slot["source_image_id"] == approval.proposed_launch.source_image_id
    assert slot["supervisor_image_id"] == approval.proposed_launch.supervisor_image_id
    assert slot["image_witness_remaining_headroom_nanoseconds"] == (
        (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS - 100) * 1_000_000_000
    )
    assert admission.attempt_slot_sha256 == hashlib.sha256(slot_encoded).hexdigest()
    attested_path = admit._attested_paths[approval_path]
    assert (
        admission.operator_attestation_envelope_sha256
        == hashlib.sha256(attested_path.read_bytes()).hexdigest()
    )
    assert (
        admission.execution_approval_v2_sha256
        == hashlib.sha256(approval_path.read_bytes()).hexdigest()
    )
    assert admission.operator_authority_git_revision == approval.proposed_launch.git_revision
    assert admission.operator_authority_git_relative_path == (
        execution.POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
    )
    assert admission.operator_authority_git_mode == "100644"
    assert admission.operator_authority_git_blob_object_id == "b" * 40
    assert admission.payload()["contract_version"] == (
        POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION
    )
    assert admission.status == "execution_admission_unqualified"
    assert admission.operator_authority_git_object_authenticated is True
    assert admission.operator_attestation_envelope_authenticated is True
    assert admission.operator_attestation_signature_authenticated is True
    assert admission.execution_approval_v2_semantically_authenticated is True
    assert admission.execution_attempt_retained is True
    assert admission.approved_image_provenance_authenticated is True
    assert admission.image_witness_authenticated is True
    assert admission.image_witness_headroom_authenticated is True
    assert admission.owner_only_artifacts_authenticated is True
    assert admission.image_witness_remaining_headroom_nanoseconds == (
        (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS - 100) * 1_000_000_000 - 1
    )
    for field_name in (*POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,):
        assert admission.payload()[field_name] is False
        assert getattr(admission, field_name) is False
    expected_image_path = artifact_directory / (
        f"image-admission-{loader.admission.artifact_sha256}.json"
    )
    assert loader.calls == [
        (expected_image_path, ignored_root, observed),
        (expected_image_path, ignored_root, observed + 1),
    ]

    assert consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert loader.calls[-1] == (expected_image_path, ignored_root, observed + 2)
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    for operation in (
        lambda: copy.copy(admission),
        lambda: copy.deepcopy(admission),
        lambda: pickle.dumps(admission),
    ):
        with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
            operation()


def test_lost_admission_return_revokes_every_process_registry_entry(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[created, created])
    reserve = admit._reserve
    closure = dict(
        zip(
            reserve.__code__.co_freevars,
            (cell.cell_contents for cell in reserve.__closure__ or ()),
            strict=True,
        )
    )
    capabilities = closure["capabilities"]
    continuations = closure["continuations"]
    validator_count = len(execution._CAPABILITY_VALIDATORS)

    admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    gc.collect()

    assert capabilities == {}
    assert continuations == {}
    assert len(execution._CAPABILITY_VALIDATORS) == validator_count
    assert (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()


def test_caller_held_admission_remains_consumable_exactly_once(tmp_path: Path) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, consume = _admitter(
        loader=loader,
        observed=[created, created, created],
    )

    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def test_image_admission_accepts_exact_headroom_boundary(tmp_path: Path) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    boundary = (
        created
        + (
            IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
            - POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        )
        * 1_000_000_000
    )
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[boundary, boundary])

    result = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert result.image_witness_headroom_authenticated is True
    assert result.image_witness_remaining_headroom_nanoseconds == (
        POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS * 1_000_000_000
    )


def test_two_fresh_witnesses_reuse_identical_stable_human_approval_bytes(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = _retain_approval(first_root)
    second = _retain_approval(second_root, approval=first[2])
    assert first[4] == second[4]
    assert first[2].approval_sha256 == second[2].approval_sha256

    first_witness = _image_admission(
        first[2],
        first[1],
        created_monotonic_ns=1_000_000_000,
    )
    second_witness = _image_admission(
        second[2],
        second[1],
        created_monotonic_ns=2_000_000_000,
    )
    assert first_witness.artifact_sha256 != second_witness.artifact_sha256

    first_loader = _ImageLoader(first_witness)
    second_loader = _ImageLoader(second_witness)
    first_admit, _, _ = _admitter(
        loader=first_loader,
        observed=[1_000_000_000, 1_000_000_001],
    )
    second_admit, _, _ = _admitter(
        loader=second_loader,
        observed=[2_000_000_000, 2_000_000_001],
    )
    first_result = first_admit(
        approval_artifact=first[3],
        artifact_directory=first[1],
        ignored_root=first[0],
    )
    second_result = second_admit(
        approval_artifact=second[3],
        artifact_directory=second[1],
        ignored_root=second[0],
    )

    assert first_result.approval_sha256 == second_result.approval_sha256
    assert first_result.image_witness_sha256 == first_witness.artifact_sha256
    assert second_result.image_witness_sha256 == second_witness.artifact_sha256


def test_consume_rechecks_headroom_and_burns_expired_admission_once(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    just_before_boundary = (
        created
        + (
            IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
            - POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        )
        * 1_000_000_000
        - 1
    )
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, consume = _admitter(
        loader=loader,
        observed=[just_before_boundary, just_before_boundary, just_before_boundary + 2],
    )
    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    slot_encoded = slot_path.read_bytes()

    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert slot_path.read_bytes() == slot_encoded
    assert len(loader.calls) == 3
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert len(loader.calls) == 3


def test_production_execution_admission_uses_image_admission_suspend_aware_clock() -> None:
    defaults = execution._build_execution_admitter.__kwdefaults__

    assert defaults is not None
    assert defaults["monotonic_ns"] is image_verifier._suspend_aware_monotonic_ns


def test_suspend_aware_jump_rejects_before_attempt_reservation(tmp_path: Path) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    after_suspend = (
        created
        + (
            IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
            - POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        )
        * 1_000_000_000
        + 1
    )
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(
        loader=loader,
        observed=[after_suspend],
    )

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="headroom",
    ):
        admit(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert not (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()


@pytest.mark.parametrize(
    "mutation",
    [
        {"artifact_sha256": "a" * 64},
        {"git_revision": "b" * 40},
        {"source_revision_sha256": "a" * 64},
        {
            "identities": TrustedTimeImageIdentities(
                source_id="sha256:" + "1" * 64,
                supervisor_id="sha256:" + "2" * 64,
            )
        },
    ],
)
def test_image_tuple_drift_rejects_before_attempt_reservation(
    tmp_path: Path,
    mutation: dict[str, object],
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
            **mutation,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[created])

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        admit(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert not (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()


def test_insufficient_image_headroom_rejects_before_attempt_reservation(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    too_late = (
        created
        + (
            IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
            - POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        )
        * 1_000_000_000
        + 1
    )
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[too_late])

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="headroom",
    ):
        admit(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert not (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()


def test_global_attempt_slot_is_o_excl_and_consumes_every_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    image_witness = _image_admission(
        approval,
        artifact_directory,
        created_monotonic_ns=created,
    )
    real_write = os.write
    real_flock = fcntl.flock
    creator_write_started = threading.Event()
    release_creator_write = threading.Event()
    observer_lock_attempted = threading.Event()
    pause_guard = threading.Lock()
    creator_thread: int | None = None

    def pause_first_slot_write(descriptor: int, value: Any) -> int:
        nonlocal creator_thread
        with pause_guard:
            should_pause = creator_thread is None
            if should_pause:
                creator_thread = threading.get_ident()
        if should_pause:
            creator_write_started.set()
            if not release_creator_write.wait(timeout=5):
                raise AssertionError("creator write was not released")
        return real_write(descriptor, value)

    def observe_contending_flock(descriptor: int, operation: int) -> None:
        if (
            operation == fcntl.LOCK_EX
            and creator_thread is not None
            and threading.get_ident() != creator_thread
        ):
            observer_lock_attempted.set()
        real_flock(descriptor, operation)

    monkeypatch.setattr(os, "write", pause_first_slot_write)
    monkeypatch.setattr(fcntl, "flock", observe_contending_flock)

    def execute_once() -> str:
        loader = _ImageLoader(image_witness)
        admit, _, _ = _admitter(loader=loader, observed=[created, created])
        try:
            admit(
                approval_artifact=approval_path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except TrustedTimePostEnrollmentExecutionAttemptConsumed:
            return "consumed"
        return "admitted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        creator = executor.submit(execute_once)
        assert creator_write_started.wait(timeout=5)
        observer = executor.submit(execute_once)
        try:
            assert observer_lock_attempted.wait(timeout=5)
            assert not observer.done()
        finally:
            release_creator_write.set()
        outcomes = sorted((creator.result(), observer.result()))

    assert outcomes == ["admitted", "consumed"]
    assert execute_once() == "consumed"


def test_async_slot_write_failure_leaves_permanent_closed_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[created])
    real_write = os.write
    interrupted = False

    class InjectedInterrupt(BaseException):
        pass

    def interrupt_after_partial_write(descriptor: int, value: Any) -> int:
        nonlocal interrupted
        metadata = os.fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode) and not interrupted:
            interrupted = True
            prefix = bytes(value[:1])
            real_write(descriptor, prefix)
            raise InjectedInterrupt
        return real_write(descriptor, value)

    monkeypatch.setattr(os, "write", interrupt_after_partial_write)
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed
    ) as unconfirmed:
        admit(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert isinstance(unconfirmed.value.__cause__, InjectedInterrupt)
    monkeypatch.setattr(os, "write", real_write)

    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    assert slot_path.exists()
    partial_encoded = slot_path.read_bytes()
    partial_identity = (slot_path.stat().st_dev, slot_path.stat().st_ino)
    assert len(partial_encoded) == 1
    retry_loader = _ImageLoader(loader.admission)
    retry, _, _ = _admitter(loader=retry_loader, observed=[created])
    with pytest.raises(TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed):
        retry(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert slot_path.read_bytes() == partial_encoded
    assert (slot_path.stat().st_dev, slot_path.stat().st_ino) == partial_identity


def test_attempt_slot_open_call_store_interruption_is_permanently_unconfirmed(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[created])
    target = execution._reserve_attempt_slot
    store_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "file_owner"
        and instruction.offset > 150
    )
    before = _open_descriptor_names()

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed
    ) as unconfirmed:
        _interrupt_instruction(
            target,
            store_offset,
            lambda: admit(
                approval_artifact=approval_path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ),
        )

    gc.collect()
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    assert isinstance(unconfirmed.value.__cause__, KeyboardInterrupt)
    assert slot_path.exists()
    assert slot_path.read_bytes() == b""
    assert _open_descriptor_names() == before
    retry_loader = _ImageLoader(loader.admission)
    retry, _, _ = _admitter(loader=retry_loader, observed=[created])
    with pytest.raises(TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed):
        retry(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_fsync_failure_reports_unconfirmed_and_never_reopens_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, _ = _admitter(loader=loader, observed=[created])
    real_fsync = os.fsync
    failed = False

    def fail_slot_fsync(descriptor: int) -> None:
        nonlocal failed
        metadata = os.fstat(descriptor)
        if stat.S_ISDIR(metadata.st_mode) and not failed:
            failed = True
            raise OSError("injected fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_slot_fsync)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed):
        admit(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    monkeypatch.setattr(os, "fsync", real_fsync)

    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    slot_identity = (slot_path.stat().st_dev, slot_path.stat().st_ino)
    slot_encoded = slot_path.read_bytes()
    retry_loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    retry, _, _ = _admitter(loader=retry_loader, observed=[created, created])

    def fail_retry_directory_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected retry directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_retry_directory_fsync)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed):
        retry(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    observed_fsync_kinds: list[str] = []

    def observe_retry_fsync(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        observed_fsync_kinds.append("directory" if stat.S_ISDIR(metadata.st_mode) else "file")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", observe_retry_fsync)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAttemptConsumed):
        retry(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert observed_fsync_kinds == ["file", "directory"]
    assert (slot_path.stat().st_dev, slot_path.stat().st_ino) == slot_identity
    assert slot_path.read_bytes() == slot_encoded


def test_wrong_thread_consumption_is_destructive_and_replay_fails(tmp_path: Path) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, consume = _admitter(loader=loader, observed=[created, created])
    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        wrong_thread = executor.submit(
            consume,
            admission,
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ).result()

    assert wrong_thread is False
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert len(loader.calls) == 2
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


@pytest.mark.parametrize("mutation", ["removed", "tampered", "same_bytes_replacement"])
def test_attempt_slot_drift_consumes_admission_before_image_recheck(
    tmp_path: Path,
    mutation: str,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, consume = _admitter(loader=loader, observed=[created, created, created])
    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    exact_bytes = slot_path.read_bytes()
    if mutation == "removed":
        slot_path.unlink()
    elif mutation == "tampered":
        slot_path.write_bytes(b"x" + exact_bytes[1:])
        slot_path.chmod(0o600)
    else:
        replacement = artifact_directory / ".replacement-attempt-slot"
        replacement.write_bytes(exact_bytes)
        replacement.chmod(0o600)
        replacement.replace(slot_path)

    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


@pytest.mark.parametrize("mutation", ["removed", "tampered", "same_bytes_replacement"])
def test_witness_archive_drift_after_reservation_consumes_capability(
    tmp_path: Path,
    mutation: str,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    witness = _image_admission(
        approval,
        artifact_directory,
        created_monotonic_ns=created,
    )
    loader = _ImageLoader(witness)
    admit, _, consume = _admitter(
        loader=loader,
        observed=[created, created, created],
    )
    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    witness_path = witness.path
    exact_bytes = witness_path.read_bytes()
    if mutation == "removed":
        witness_path.unlink()
    elif mutation == "tampered":
        witness_path.write_bytes(b"x" + exact_bytes[1:])
        witness_path.chmod(0o600)
    else:
        replacement = artifact_directory / ".replacement-witness"
        replacement.write_bytes(exact_bytes)
        replacement.chmod(0o600)
        replacement.replace(witness_path)

    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert len(loader.calls) == (3 if mutation == "same_bytes_replacement" else 2)
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def test_fork_identity_change_rejects_admission_and_consumption(tmp_path: Path) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    pid = [100]
    loader = _ImageLoader(
        _image_admission(
            approval,
            artifact_directory,
            created_monotonic_ns=created,
        )
    )
    admit, _, consume = _admitter(
        loader=loader,
        observed=[created, created],
        process_id=lambda: pid[0],
    )
    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    pid[0] = 101
    assert not consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="after fork",
    ):
        admit(
            approval_artifact=approval_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_noncanonical_root_fails_before_any_artifact_access(tmp_path: Path) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    alternate = artifact_directory / "nested"
    alternate.mkdir(mode=0o700)

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="root is invalid",
    ):
        load_post_enrollment_execution_approval(
            approval_artifact=approval_path,
            artifact_directory=alternate,
            ignored_root=ignored_root,
        )


def test_semantic_v2_bytes_decoder_round_trips_exact_approval(tmp_path: Path) -> None:
    _, _, approval, _, encoded = _retain_approval(tmp_path)

    assert execution.decode_post_enrollment_execution_approval_bytes(encoded) == approval
    for invalid in (bytearray(encoded), encoded[:-1], b" " + encoded, b"{}\n"):
        with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
            execution.decode_post_enrollment_execution_approval_bytes(invalid)


def test_public_v3_loader_authenticates_exact_git_authority_and_all_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    path, authority_encoded = _operator_attested_artifact(
        approval_artifact=approval_path,
        ignored_root=ignored_root,
    )
    revisions: list[str] = []

    def git_authority(revision: str) -> tuple[str, str, bytes]:
        revisions.append(revision)
        return "100644", "b" * 40, authority_encoded

    monkeypatch.setattr(execution, "_head_reviewed_operator_authority_object", git_authority)
    loaded = execution.load_post_enrollment_operator_attested_execution_approval(
        operator_attested_approval_artifact=path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    assert revisions == [approval.proposed_launch.git_revision]
    assert loaded.approval == approval
    assert loaded.artifact_path == path
    assert loaded.operator_authority_git_revision == approval.proposed_launch.git_revision
    assert loaded.operator_authority_git_relative_path == (
        execution.POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
    )
    assert loaded.operator_authority_git_mode == "100644"
    assert loaded.operator_authority_git_blob_object_id == "b" * 40
    assert (
        loaded.operator_authority_artifact_sha256 == hashlib.sha256(authority_encoded).hexdigest()
    )
    assert (
        loaded.execution_approval_v2_sha256
        == hashlib.sha256(approval_path.read_bytes()).hexdigest()
    )
    assert (
        loaded.operator_attestation_envelope_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    assert loaded.operator_authority_git_object_authenticated is True
    assert loaded.operator_attestation_envelope_authenticated is True
    assert loaded.operator_attestation_signature_authenticated is True
    assert loaded.execution_approval_v2_semantically_authenticated is True


@pytest.mark.parametrize(
    "mutation",
    ["relative", "parent_mode", "file_mode", "hardlink", "symlink", "internal"],
)
def test_v3_loader_rejects_nonexternal_or_non_owner_only_artifact(
    tmp_path: Path,
    mutation: str,
) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    path, authority_encoded = _operator_attested_artifact(
        approval_artifact=approval_path,
        ignored_root=ignored_root,
    )
    candidate = path
    if mutation == "relative":
        candidate = Path(path.name)
    elif mutation == "parent_mode":
        path.parent.chmod(0o755)
    elif mutation == "file_mode":
        path.chmod(0o640)
    elif mutation == "hardlink":
        os.link(path, path.parent / "second-link")
    elif mutation == "symlink":
        target = path.parent / "target.json"
        path.replace(target)
        path.symlink_to(target.name)
    else:
        candidate = artifact_directory / path.name
        candidate.write_bytes(path.read_bytes())
        candidate.chmod(0o600)

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        execution._load_post_enrollment_operator_attested_execution_approval(
            operator_attested_approval_artifact=candidate,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            image_provenance_loader=(image_verifier.load_image_admission_provenance_artifact),
            git_operator_authority_loader=lambda _: (
                "100644",
                "b" * 40,
                authority_encoded,
            ),
        )


@pytest.mark.parametrize("replacement", ["file", "parent"])
def test_v3_loader_final_named_rebind_rejects_same_bytes_replacement(
    tmp_path: Path,
    replacement: str,
) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    path, authority_encoded = _operator_attested_artifact(
        approval_artifact=approval_path,
        ignored_root=ignored_root,
    )

    def replace_during_git_read(_: str) -> tuple[str, str, bytes]:
        encoded = path.read_bytes()
        if replacement == "file":
            replacement_path = path.parent / "replacement.json"
            replacement_path.write_bytes(encoded)
            replacement_path.chmod(0o600)
            replacement_path.replace(path)
        else:
            original_parent = path.parent
            moved_parent = original_parent.with_name(f"{original_parent.name}-moved")
            original_parent.rename(moved_parent)
            original_parent.mkdir(mode=0o700)
            new_path = original_parent / path.name
            new_path.write_bytes(encoded)
            new_path.chmod(0o600)
        return "100644", "b" * 40, authority_encoded

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAdmissionRejected,
        match="changed during authentication",
    ):
        execution._load_post_enrollment_operator_attested_execution_approval(
            operator_attested_approval_artifact=path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            image_provenance_loader=(image_verifier.load_image_admission_provenance_artifact),
            git_operator_authority_loader=replace_during_git_read,
        )


@pytest.mark.parametrize(
    ("mode", "blob_object_id"),
    [("100755", "b" * 40), ("100644", "b" * 64), ("100644", "B" * 40)],
)
def test_v3_loader_rejects_wrong_git_object_metadata(
    tmp_path: Path,
    mode: str,
    blob_object_id: str,
) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    path, authority_encoded = _operator_attested_artifact(
        approval_artifact=approval_path,
        ignored_root=ignored_root,
    )

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        execution._load_post_enrollment_operator_attested_execution_approval(
            operator_attested_approval_artifact=path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            image_provenance_loader=(image_verifier.load_image_admission_provenance_artifact),
            git_operator_authority_loader=lambda _: (
                mode,
                blob_object_id,
                authority_encoded,
            ),
        )


def test_v3_loader_rejects_authenticated_but_semantically_invalid_embedded_v2(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    payload = json.loads(approval_path.read_bytes())
    payload["operation_id"] = "semantic-drift"
    malformed_v2 = canonical_first_enrollment_json_bytes(payload)
    assert hashlib.sha256(malformed_v2).hexdigest() == (
        "96f68b53758ff253e85d9eb0d3b10923886d115d6778d718a6aaf02290610b6e"
    )
    statement = build_post_enrollment_operator_attestation_statement(
        authority=authority,
        execution_approval_v2_sha256=hashlib.sha256(malformed_v2).hexdigest(),
    )
    envelope = build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=malformed_v2,
        statement=statement,
        signature_ed25519=_SEMANTICALLY_INVALID_V2_SIGNATURE,
    )
    encoded = canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
    external_directory = tmp_path / "semantic-invalid-external"
    external_directory.mkdir(mode=0o700)
    path = external_directory / (
        f"{execution.POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX}"
        f"{hashlib.sha256(encoded).hexdigest()}.json"
    )
    path.write_bytes(encoded)
    path.chmod(0o600)

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        execution._load_post_enrollment_operator_attested_execution_approval(
            operator_attested_approval_artifact=path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            image_provenance_loader=(image_verifier.load_image_admission_provenance_artifact),
            git_operator_authority_loader=lambda _: (
                "100644",
                "b" * 40,
                authority_encoded,
            ),
        )


@pytest.mark.parametrize(
    ("field_name", "replacement_value"),
    [
        ("operator_authority_git_blob_object_id", "c" * 40),
        ("operator_authority_artifact_sha256", "c" * 64),
        ("operator_public_key_sha256", "c" * 64),
        ("execution_approval_v2_sha256", "c" * 64),
        ("operator_attestation_statement_sha256", "c" * 64),
        ("operator_attestation_signature_sha256", "c" * 64),
        ("operator_attestation_envelope_sha256", "c" * 64),
        ("directory_identity", (1, 2)),
        ("file_identity", (1, 2, stat.S_IFREG | 0o600, os.geteuid(), 0, 1, 1, 1, 1)),
    ],
)
def test_loaded_v3_receipt_seal_rejects_valid_shaped_scalar_mutation(
    tmp_path: Path,
    field_name: str,
    replacement_value: object,
) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    _, _, loaded = _load_operator_attested_fixture(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    object.__setattr__(loaded, field_name, replacement_value)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        loaded.__post_init__()
    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        _ = loaded.operator_authority_git_object_authenticated


def test_loaded_v3_receipt_rejects_replace_copy_pickle_and_nested_mutation(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, approval_path, _ = _retain_approval(tmp_path)
    _, _, loaded = _load_operator_attested_fixture(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    for operation in (
        lambda: replace(loaded, operator_authority_git_blob_object_id="c" * 40),
        lambda: copy.copy(loaded),
        lambda: copy.deepcopy(loaded),
        lambda: pickle.dumps(loaded),
    ):
        with pytest.raises((TypeError, TrustedTimePostEnrollmentExecutionAdmissionRejected)):
            operation()
    object.__setattr__(loaded.image_provenance, "git_revision", "e" * 40)
    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        loaded.__post_init__()


def test_historical_v2_and_current_v3_complete_slots_are_both_consumed(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    provenance = load_post_enrollment_execution_approval(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    ).image_provenance
    historical = execution._closed_payload()
    historical.update(execution._tuple_payload(approval))
    historical.update(
        {
            "approval_artifact_sha256": hashlib.sha256(approval_path.read_bytes()).hexdigest(),
            "approved_image_provenance_source_revision_sha256": (provenance.source_revision_sha256),
            "contract_version": (
                execution.HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
            ),
            "image_witness_boot_session_id": provenance.boot_session_id,
            "image_witness_checked_monotonic_ns": 1,
            "image_witness_contract_version": image_verifier.IMAGE_ADMISSION_CONTRACT_VERSION,
            "image_witness_created_monotonic_ns": provenance.created_monotonic_ns,
            "image_witness_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "image_witness_remaining_headroom_nanoseconds": 1,
            "image_witness_sha256": provenance.artifact_sha256,
            "image_witness_source_revision_sha256": provenance.source_revision_sha256,
            "service": execution.POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE,
            "status": "execution_attempt_reserved",
        }
    )
    historical_encoded = canonical_first_enrollment_json_bytes(historical)
    assert execution._is_complete_attempt_slot_artifact(historical_encoded)
    historical["contract_version"] = "unknown"
    assert not execution._is_complete_attempt_slot_artifact(
        canonical_first_enrollment_json_bytes(historical)
    )
    assert not execution._is_complete_attempt_slot_artifact(b"not-json")


def test_reserve_rejects_preparation_only_v2_loaded_receipt_before_slot(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    v2_loaded = load_post_enrollment_execution_approval(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    image_admission = _image_admission(
        approval,
        artifact_directory,
        created_monotonic_ns=1,
    )
    reserve, _, _ = execution._build_execution_admitter()

    with pytest.raises(TrustedTimePostEnrollmentExecutionAdmissionRejected):
        reserve(
            loaded_attested_approval=v2_loaded,
            image_admission=image_admission,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert not (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()
    assert not hasattr(execution, "admit_post_enrollment_execution_attempt")


def test_reserve_reloads_v3_before_and_after_slot_and_consume_reloads_again(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    created = 1_000_000_000
    loader = _ImageLoader(
        _image_admission(approval, artifact_directory, created_monotonic_ns=created)
    )
    admit, _, consume = _admitter(loader=loader, observed=[created, created, created])

    admission = admit(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert len(admit._attested_load_calls) == 3
    assert consume(
        admission,
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert len(admit._attested_load_calls) == 4


def test_post_slot_v3_reload_failure_is_retention_unconfirmed(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    _, _, loaded = _load_operator_attested_fixture(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    created = 1_000_000_000
    image_admission = _image_admission(
        approval,
        artifact_directory,
        created_monotonic_ns=created,
    )
    image_loader = _ImageLoader(image_admission)
    calls = 0

    def reload_then_interrupt(**_: object) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            return loaded
        raise KeyboardInterrupt

    reserve, _, _ = execution._build_execution_admitter(
        image_admission_loader=image_loader,
        operator_attested_approval_loader=reload_then_interrupt,
        monotonic_ns=lambda: created,
    )
    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed
    ) as unconfirmed:
        reserve(
            loaded_attested_approval=loaded,
            image_admission=image_admission,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert isinstance(unconfirmed.value.__cause__, KeyboardInterrupt)
    assert (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()


def test_reserve_slot_call_return_interruption_is_retention_unconfirmed(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, approval, approval_path, _ = _retain_approval(tmp_path)
    _, _, loaded = _load_operator_attested_fixture(
        approval_artifact=approval_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    created = 1_000_000_000
    image_admission = _image_admission(
        approval,
        artifact_directory,
        created_monotonic_ns=created,
    )
    image_loader = _ImageLoader(image_admission)
    reserve, _, _ = execution._build_execution_admitter(
        image_admission_loader=image_loader,
        operator_attested_approval_loader=lambda **_: loaded,
        monotonic_ns=lambda: created,
    )
    instructions = tuple(dis.get_instructions(reserve))
    load_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.argval == "_reserve_attempt_slot"
    )
    store_offset = next(
        instruction.offset
        for instruction in instructions[load_index:]
        if instruction.opname == "STORE_FAST" and instruction.argval == "slot_identity"
    )

    with pytest.raises(
        TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed
    ) as unconfirmed:
        _interrupt_instruction(
            reserve,
            store_offset,
            lambda: reserve(
                loaded_attested_approval=loaded,
                image_admission=image_admission,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ),
        )
    assert isinstance(unconfirmed.value.__cause__, KeyboardInterrupt)
    assert (artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).exists()


def test_retained_v3_loader_authenticates_exact_historical_attempt_without_currentness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        encoded,
    ) = _retained_attempt_fixture(tmp_path)
    calls: list[tuple[Path, Path, Path]] = []

    def reload_attested(
        *,
        operator_attested_approval_artifact: Path,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
        calls.append(
            (
                operator_attested_approval_artifact,
                artifact_directory,
                ignored_root,
            )
        )
        return loaded

    def reject_clock_read() -> int:
        raise AssertionError("historical evidence loading must not read a current clock")

    real_flock = fcntl.flock
    flock_operations: list[int] = []

    def observe_flock(descriptor: int, operation: int) -> None:
        flock_operations.append(operation)
        real_flock(descriptor, operation)

    monkeypatch.setattr(
        execution,
        "load_post_enrollment_operator_attested_execution_approval",
        reload_attested,
    )
    monkeypatch.setattr(execution, "_suspend_aware_monotonic_ns", reject_clock_read)
    monkeypatch.setattr(fcntl, "flock", observe_flock)

    retained = execution.load_retained_post_enrollment_operator_attested_execution_attempt(
        start_operator_attested_approval_artifact=attested_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    assert calls == [
        (attested_path, artifact_directory, ignored_root),
        (attested_path, artifact_directory, ignored_root),
    ]
    assert flock_operations.count(fcntl.LOCK_SH) == 5
    assert retained.loaded_attested_approval == loaded
    assert retained.approval == loaded.approval
    assert retained.artifact_path == slot_path
    assert retained.encoded == encoded
    assert retained.attempt_slot_sha256 == hashlib.sha256(encoded).hexdigest()
    assert retained.operator_attestation_envelope_sha256 == (
        loaded.operator_attestation_envelope_sha256
    )
    assert retained.directory_identity == (
        artifact_directory.stat().st_dev,
        artifact_directory.stat().st_ino,
    )
    assert retained.file_identity == execution._stable_file_identity(slot_path.stat())
    assert retained.execution_attempt_retained is True
    assert retained.execution_approval_v2_semantically_authenticated is True
    assert retained.operator_attestation_envelope_authenticated is True
    assert retained.operator_attestation_signature_authenticated is True
    assert retained.operator_authority_git_object_authenticated is True
    for fact_name in (
        "currentness_authenticated",
        "freshness_authenticated",
        "single_use_authenticated",
        "stop_attempt_reservation_authorized",
        "stop_execution_authorized",
        "shutdown_authorized",
        "topology_mutation_authorized",
    ):
        assert getattr(retained, fact_name) is False


def test_retained_v3_private_snapshot_seam_uses_exact_native_locked_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        _,
        _,
        encoded,
    ) = _retained_attempt_fixture(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )

    retained, snapshot = (
        execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot(
            start_operator_attested_approval_artifact=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    )

    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    assert type(snapshot) is tuple
    assert len(snapshot) == 10
    assert tuple.__getitem__(snapshot, 0) == (
        "retained-operator-attested-execution-attempt-snapshot-v1"
    )
    assert tuple.__getitem__(snapshot, 1) == os.fspath(artifact_directory)
    assert tuple.__getitem__(snapshot, 2) == os.fspath(ignored_root)
    assert tuple.__getitem__(snapshot, 3) == os.fspath(slot_path)
    assert tuple.__getitem__(snapshot, 4) == encoded
    assert tuple.__getitem__(snapshot, 5) == hashlib.sha256(encoded).hexdigest()
    assert tuple.__getitem__(snapshot, 6) == (
        artifact_directory.stat().st_dev,
        artifact_directory.stat().st_ino,
    )
    assert tuple.__getitem__(snapshot, 7) == execution._stable_file_identity(slot_path.stat())
    approval_snapshot = tuple.__getitem__(snapshot, 8)
    assert type(approval_snapshot) is tuple
    assert len(approval_snapshot) == 31
    assert tuple.__getitem__(approval_snapshot, 0) == (
        "loaded-operator-attested-approval-snapshot-v1"
    )
    provenance_snapshot = tuple.__getitem__(approval_snapshot, 29)
    assert type(provenance_snapshot) is tuple
    assert len(provenance_snapshot) == 14
    assert tuple.__getitem__(provenance_snapshot, 0) == (
        "trusted-time-image-admission-provenance-snapshot-v1"
    )
    assert tuple.__getitem__(provenance_snapshot, 7) == SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SHA256
    assert retained.encoded == tuple.__getitem__(snapshot, 4)
    assert (
        execution._revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot(
            snapshot,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        is True
    )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("approval_sha256", "c" * 64),
        ("approved_image_provenance_sha256", "c" * 64),
        ("confirmed_enrollment_evidence_sha256", "c" * 64),
        ("git_revision", "e" * 40),
        ("operation_id", "323e4567-e89b-42d3-a456-426614174001"),
        ("review_projection_sha256", "c" * 64),
        ("source_image_id", "sha256:" + "c" * 64),
        ("supervisor_image_id", "sha256:" + "d" * 64),
        ("approved_image_provenance_source_revision_sha256", "c" * 64),
        ("execution_approval_v2_sha256", "c" * 64),
        ("operator_attestation_envelope_sha256", "c" * 64),
        ("operator_attestation_signature_sha256", "c" * 64),
        ("operator_attestation_statement_sha256", "c" * 64),
        ("operator_attestation_verification_contract_version", "unknown"),
        ("operator_attestation_verification_service", "unknown"),
        ("operator_attestation_verification_status", "unknown"),
        ("operator_authority_artifact_sha256", "c" * 64),
        ("operator_authority_git_blob_object_id", "c" * 40),
        ("operator_authority_git_mode", "100755"),
        ("operator_authority_git_relative_path", "infra/other-authority.json"),
        ("operator_authority_git_revision", "e" * 40),
        ("operator_public_key_sha256", "c" * 64),
        ("image_witness_source_revision_sha256", "c" * 64),
    ],
)
def test_retained_v3_loader_rejects_every_mutated_authenticated_binding(
    tmp_path: Path,
    field_name: str,
    replacement: object,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        payload,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    payload[field_name] = replacement
    if field_name in {"git_revision", "operator_authority_git_revision"}:
        payload["git_revision"] = replacement
        payload["operator_authority_git_revision"] = replacement
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    slot_path.write_bytes(canonical_first_enrollment_json_bytes(payload))
    slot_path.chmod(0o600)

    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        _load_retained_fixture(
            attested_path=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            loaded=loaded,
        )


@pytest.mark.parametrize("artifact_kind", ["v2", "partial", "unknown", "noncanonical"])
def test_retained_v3_loader_rejects_historical_partial_unknown_and_noncanonical_slots(
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        payload,
        encoded,
    ) = _retained_attempt_fixture(tmp_path)
    if artifact_kind == "v2":
        replacement = _historical_attempt_slot_bytes(loaded)
        assert execution._is_complete_attempt_slot_artifact(replacement)
    elif artifact_kind == "partial":
        replacement = canonical_first_enrollment_json_bytes(
            {"contract_version": POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION}
        )
    elif artifact_kind == "unknown":
        payload["contract_version"] = "unknown-attempt-contract"
        replacement = canonical_first_enrollment_json_bytes(payload)
    else:
        replacement = encoded + b" "
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    slot_path.write_bytes(replacement)
    slot_path.chmod(0o600)

    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        _load_retained_fixture(
            attested_path=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            loaded=loaded,
        )


@pytest.mark.parametrize(
    "unsafe_kind",
    ["missing", "mode", "hardlink", "symlink", "oversized", "directory_mode"],
)
def test_retained_v3_loader_rejects_unsafe_fixed_slot_and_directory(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        encoded,
    ) = _retained_attempt_fixture(tmp_path)
    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    if unsafe_kind == "missing":
        slot_path.unlink()
    elif unsafe_kind == "mode":
        slot_path.chmod(0o640)
    elif unsafe_kind == "hardlink":
        os.link(slot_path, artifact_directory / "extra-slot-link")
    elif unsafe_kind == "symlink":
        target = artifact_directory / "slot-target"
        target.write_bytes(encoded)
        target.chmod(0o600)
        slot_path.unlink()
        slot_path.symlink_to(target.name)
    elif unsafe_kind == "oversized":
        slot_path.write_bytes(
            b"x" * (execution.MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES + 1)
        )
        slot_path.chmod(0o600)
    else:
        artifact_directory.chmod(0o750)

    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        _load_retained_fixture(
            attested_path=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            loaded=loaded,
        )


def test_retained_v3_loader_rejects_noncanonical_artifact_roots(tmp_path: Path) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)

    for invalid_directory, invalid_root in (
        (Path("relative/trusted-time"), ignored_root),
        (artifact_directory, Path("relative/artifacts")),
        (ignored_root, ignored_root),
        (ignored_root / "other", ignored_root),
    ):
        with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
            _load_retained_fixture(
                attested_path=attested_path,
                artifact_directory=invalid_directory,
                ignored_root=invalid_root,
                loaded=loaded,
            )


def test_retained_v3_loader_rebinds_the_named_directory_before_return(
    tmp_path: Path,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        encoded,
    ) = _retained_attempt_fixture(tmp_path)
    displaced_directory = ignored_root / "displaced-trusted-time"
    calls = 0

    def replace_named_directory(**_: object) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            artifact_directory.rename(displaced_directory)
            artifact_directory.mkdir(mode=0o700)
            replacement_slot = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
            replacement_slot.write_bytes(encoded)
            replacement_slot.chmod(0o600)
        return loaded

    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        execution._load_retained_post_enrollment_operator_attested_execution_attempt(
            start_operator_attested_approval_artifact=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            operator_attested_approval_loader=replace_named_directory,
        )
    assert calls == 2


@pytest.mark.parametrize("directory_open_index", [0, 1])
def test_retained_v3_directory_open_call_store_interruption_closes_every_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    directory_open_index: int,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        _,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )
    target = (
        execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot
    )
    instructions = tuple(dis.get_instructions(target))
    open_indexes = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.argval == "_native_open_root_directory"
    ]
    store_offset = next(
        instruction.offset
        for instruction in instructions[open_indexes[directory_open_index] :]
        if instruction.opname == "STORE_FAST"
        and instruction.argval
        in {
            "directory_owner",
            "rebound_directory_owner",
        }
    )
    before = _open_descriptor_names()

    with pytest.raises(KeyboardInterrupt):
        _interrupt_instruction(
            target,
            store_offset,
            lambda: target(
                start_operator_attested_approval_artifact=attested_path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ),
        )
    gc.collect()
    assert _open_descriptor_names() == before


@pytest.mark.parametrize("directory_open_index", [0, 1])
def test_retained_v3_directory_child_open_call_store_interruption_closes_every_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    directory_open_index: int,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        _,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )
    target = (
        execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot
    )
    instructions = tuple(dis.get_instructions(target))
    open_indexes = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.argval == "_native_open_child_directory"
    ]
    store_offset = next(
        instruction.offset
        for instruction in instructions[open_indexes[directory_open_index] :]
        if instruction.opname == "STORE_FAST"
        and instruction.argval
        in {
            "next_directory_owner",
            "next_rebound_directory_owner",
        }
    )
    before = _open_descriptor_names()

    with pytest.raises(KeyboardInterrupt):
        _interrupt_instruction(
            target,
            store_offset,
            lambda: target(
                start_operator_attested_approval_artifact=attested_path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ),
        )
    gc.collect()
    assert _open_descriptor_names() == before


def test_retained_v3_slot_open_call_store_interruption_closes_every_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        _,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )
    target = execution._read_locked_retained_execution_attempt_slot
    instructions = tuple(dis.get_instructions(target))
    open_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.argval == "_native_open_child_regular"
    )
    store_offset = next(
        instruction.offset
        for instruction in instructions[open_index:]
        if instruction.opname == "STORE_FAST" and instruction.argval == "file_owner"
    )
    before = _open_descriptor_names()

    with pytest.raises(KeyboardInterrupt):
        _interrupt_instruction(
            target,
            store_offset,
            lambda: (
                execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot(
                    start_operator_attested_approval_artifact=attested_path,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            ),
        )
    gc.collect()
    assert _open_descriptor_names() == before


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("shared_lock_index", [0, 1, 3, 4])
def test_retained_v3_acquire_then_async_releases_every_lock_and_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    async_error: type[BaseException],
    shared_lock_index: int,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    real_flock = fcntl.flock
    observed_shared = 0
    interrupted = False

    def acquire_then_interrupt(descriptor: int, operation: int) -> None:
        nonlocal observed_shared, interrupted
        real_flock(descriptor, operation)
        if operation == fcntl.LOCK_SH:
            current = observed_shared
            observed_shared += 1
            if current == shared_lock_index:
                interrupted = True
                raise async_error()

    monkeypatch.setattr(fcntl, "flock", acquire_then_interrupt)
    before = _open_descriptor_names()
    with pytest.raises(async_error):
        _load_retained_fixture(
            attested_path=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            loaded=loaded,
        )
    assert interrupted
    gc.collect()
    assert _open_descriptor_names() == before

    directory_descriptor = os.open(
        artifact_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    slot_descriptor = os.open(
        artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
        os.O_RDONLY,
    )
    try:
        real_flock(directory_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        real_flock(directory_descriptor, fcntl.LOCK_UN)
        real_flock(slot_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        real_flock(slot_descriptor, fcntl.LOCK_UN)
    finally:
        os.close(slot_descriptor)
        os.close(directory_descriptor)


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("shared_lock_index", range(6))
def test_retained_v3_native_acquire_then_async_releases_every_lock_and_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    async_error: type[BaseException],
    shared_lock_index: int,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        _,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )
    real_native_flock = execution._native_flock
    observed_shared = 0
    interrupted = False

    def acquire_then_interrupt(owner: Any, operation: int) -> None:
        nonlocal observed_shared, interrupted
        real_native_flock(owner, operation)
        if operation == fcntl.LOCK_SH | fcntl.LOCK_NB:
            current = observed_shared
            observed_shared += 1
            if current == shared_lock_index:
                interrupted = True
                raise async_error()

    monkeypatch.setattr(execution, "_native_flock", acquire_then_interrupt)
    before = _open_descriptor_names()
    with pytest.raises(async_error):
        execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot(
            start_operator_attested_approval_artifact=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert interrupted
    gc.collect()
    assert _open_descriptor_names() == before

    directory_descriptor = os.open(
        artifact_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    slot_descriptor = os.open(
        artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
        os.O_RDONLY,
    )
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        fcntl.flock(slot_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(slot_descriptor, fcntl.LOCK_UN)
    finally:
        os.close(slot_descriptor)
        os.close(directory_descriptor)


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", ["unlock", "close"])
@pytest.mark.parametrize("owner_index", [0, 1, 2])
def test_locked_owner_cleanup_finishes_all_resources_before_propagating_async(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    async_error: type[BaseException],
    boundary: str,
    owner_index: int,
) -> None:
    before = _open_descriptor_names()
    owners = tuple(
        execution._open_owned_descriptor(
            tmp_path,
            flags=os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        for _ in range(3)
    )
    descriptors = tuple(owner.fileno() for owner in owners)
    real_flock = fcntl.flock
    real_close = os.close
    for descriptor in descriptors:
        real_flock(descriptor, fcntl.LOCK_SH)
    target_descriptor = descriptors[owner_index]
    interrupted = False

    def interrupt_unlock(descriptor: int, operation: int) -> None:
        nonlocal interrupted
        real_flock(descriptor, operation)
        if (
            boundary == "unlock"
            and descriptor == target_descriptor
            and operation == fcntl.LOCK_UN
            and not interrupted
        ):
            interrupted = True
            raise async_error()

    def interrupt_close(descriptor: int) -> None:
        nonlocal interrupted
        real_close(descriptor)
        if boundary == "close" and descriptor == target_descriptor and not interrupted:
            interrupted = True
            raise async_error()

    monkeypatch.setattr(fcntl, "flock", interrupt_unlock)
    monkeypatch.setattr(os, "close", interrupt_close)
    cleanup_error = execution._cleanup_locked_owners(tuple((owner, True) for owner in owners))

    assert type(cleanup_error) is async_error
    assert interrupted
    assert all(owner.value == -1 for owner in owners)
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    gc.collect()
    assert _open_descriptor_names() == before


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", ["slot", "snapshot", "legacy"])
def test_retained_cleanup_transition_async_retries_every_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    async_error: type[BaseException],
    boundary: str,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    authority = build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )
    targets = {
        "slot": execution._read_locked_retained_execution_attempt_slot,
        "snapshot": (
            execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot
        ),
        "legacy": (execution._load_retained_post_enrollment_operator_attested_execution_attempt),
    }
    target = targets[boundary]
    cleanup_name = (
        "_cleanup_locked_owners" if boundary == "legacy" else "_cleanup_native_locked_owners"
    )
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "LOAD_GLOBAL" and instruction.argval == cleanup_name
    )

    def load() -> object:
        if boundary in {"slot", "snapshot"}:
            snapshot_loader = execution._load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot  # noqa: E501
            return snapshot_loader(
                start_operator_attested_approval_artifact=attested_path,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        return _load_retained_fixture(
            attested_path=attested_path,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            loaded=loaded,
        )

    before = _open_descriptor_names()
    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            cleanup_offset,
            load,
            async_error=async_error,
        )
    gc.collect()
    assert _open_descriptor_names() == before

    directory_descriptor = os.open(
        artifact_directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    slot_descriptor = os.open(
        artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
        os.O_RDONLY,
    )
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        fcntl.flock(slot_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(slot_descriptor, fcntl.LOCK_UN)
    finally:
        os.close(slot_descriptor)
        os.close(directory_descriptor)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("attempt_slot_sha256", "c" * 64),
        ("encoded", b"{}\n"),
        ("directory_identity", (1, 2)),
        ("file_identity", (1, 2, stat.S_IFREG | 0o600, os.geteuid(), 0, 1, 3, 1, 1)),
    ],
)
def test_retained_v3_receipt_seal_rejects_scalar_mutation(
    tmp_path: Path,
    field_name: str,
    replacement: object,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    retained = _load_retained_fixture(
        attested_path=attested_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        loaded=loaded,
    )

    object.__setattr__(retained, field_name, replacement)
    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        retained.__post_init__()


def test_retained_v3_receipt_rejects_construction_copy_pickle_and_nested_mutation(
    tmp_path: Path,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        _,
    ) = _retained_attempt_fixture(tmp_path)
    retained = _load_retained_fixture(
        attested_path=attested_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        loaded=loaded,
    )

    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        execution.RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt(
            loaded_attested_approval=retained.loaded_attested_approval,
            artifact_path=retained.artifact_path,
            attempt_slot_sha256=retained.attempt_slot_sha256,
            encoded=retained.encoded,
            directory_identity=retained.directory_identity,
            file_identity=retained.file_identity,
            _construction_capability=object(),
        )
    for operation in (
        lambda: replace(retained, attempt_slot_sha256="c" * 64),
        lambda: copy.copy(retained),
        lambda: copy.deepcopy(retained),
        lambda: pickle.dumps(retained),
    ):
        with pytest.raises(
            (TypeError, execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable)
        ):
            operation()

    object.__setattr__(retained.loaded_attested_approval.image_provenance, "git_revision", "e" * 40)
    with pytest.raises(execution.TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable):
        retained.__post_init__()


@pytest.mark.parametrize("mutation", ["slot_inode", "directory_inode", "envelope"])
def test_retained_v3_revalidation_detects_external_evidence_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    (
        ignored_root,
        artifact_directory,
        attested_path,
        loaded,
        _,
        encoded,
    ) = _retained_attempt_fixture(tmp_path)
    retained = _load_retained_fixture(
        attested_path=attested_path,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        loaded=loaded,
    )
    expected_envelope = attested_path.read_bytes()

    def authenticate_unchanged_envelope(
        *, operator_attested_approval_artifact: Path, **_: object
    ) -> execution.LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
        if operator_attested_approval_artifact.read_bytes() != expected_envelope:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected
        return loaded

    monkeypatch.setattr(
        execution,
        "load_post_enrollment_operator_attested_execution_approval",
        authenticate_unchanged_envelope,
    )
    assert execution.revalidate_retained_post_enrollment_operator_attested_execution_attempt(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    slot_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    if mutation == "slot_inode":
        slot_path.unlink()
        slot_path.write_bytes(encoded)
        slot_path.chmod(0o600)
    elif mutation == "directory_inode":
        artifact_directory.rename(ignored_root / "prior-trusted-time")
        artifact_directory.mkdir(mode=0o700)
        slot_path.write_bytes(encoded)
        slot_path.chmod(0o600)
    else:
        attested_path.write_bytes(expected_envelope + b" ")
        attested_path.chmod(0o600)

    assert not execution.revalidate_retained_post_enrollment_operator_attested_execution_attempt(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert not execution.revalidate_retained_post_enrollment_operator_attested_execution_attempt(
        object(),  # type: ignore[arg-type]
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
