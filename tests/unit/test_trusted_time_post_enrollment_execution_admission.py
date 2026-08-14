from __future__ import annotations

import copy
import dis
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

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
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
    bindings = image_verifier.reviewed_input_bindings()
    provenance_encoded = image_verifier._canonical_json_bytes(
        image_verifier._admission_payload(
            TrustedTimeImageIdentities(
                source_id="sha256:" + "8" * 64,
                supervisor_id="sha256:" + "9" * 64,
            ),
            bindings,
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
    bindings = image_verifier.reviewed_input_bindings()
    encoded = image_verifier._canonical_json_bytes(
        image_verifier._admission_payload(
            TrustedTimeImageIdentities(
                source_id=approval.proposed_launch.source_image_id,
                supervisor_id=approval.proposed_launch.supervisor_image_id,
            ),
            bindings,
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
        source_revision_sha256=bindings.source_revision_sha256,
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


def _admitter(
    *,
    loader: _ImageLoader,
    observed: list[int],
    process_id: Any = os.getpid,
) -> tuple[Any, Any, Any]:
    values = iter(observed)
    reserve, validate, consume = execution._build_execution_admitter(
        image_admission_loader=loader,
        monotonic_ns=lambda: next(values),
        process_id=process_id,
    )

    def admit(
        *,
        approval_artifact: Path,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> object:
        loaded = load_post_enrollment_execution_approval(
            approval_artifact=approval_artifact,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return reserve(
            loaded_approval=loaded,
            image_admission=loader.admission,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    admit._reserve = reserve  # type: ignore[attr-defined]
    return admit, validate, consume


def _interrupt_instruction(
    target: Any,
    instruction_offset: int,
    action: Any,
) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == instruction_offset:
            raise KeyboardInterrupt

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
    assert (
        admission.approval_artifact_sha256 == hashlib.sha256(approval_path.read_bytes()).hexdigest()
    )
    assert admission.payload()["contract_version"] == (
        POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION
    )
    assert admission.status == "execution_admission_unqualified"
    assert admission.approval_artifact_authenticated is True
    assert admission.execution_attempt_retained is True
    assert admission.approved_image_provenance_authenticated is True
    assert admission.image_witness_authenticated is True
    assert admission.image_witness_headroom_authenticated is True
    assert admission.owner_only_artifacts_authenticated is True
    assert admission.image_witness_remaining_headroom_nanoseconds == (
        (IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS - 100) * 1_000_000_000 - 1
    )
    for field_name in (
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *execution._CLOSED_EXECUTION_FIELDS,
    ):
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
    real_flock = execution.fcntl.flock
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
            operation == execution.fcntl.LOCK_EX
            and creator_thread is not None
            and threading.get_ident() != creator_thread
        ):
            observer_lock_attempted.set()
        real_flock(descriptor, operation)

    monkeypatch.setattr(os, "write", pause_first_slot_write)
    monkeypatch.setattr(execution.fcntl, "flock", observe_contending_flock)

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
