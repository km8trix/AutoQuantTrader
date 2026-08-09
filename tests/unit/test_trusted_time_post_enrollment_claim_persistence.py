from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentRuntimeReauthentication,
    TrustedTimePostEnrollmentStartApproval,
    TrustedTimePostEnrollmentStartClaim,
)
from scripts import trusted_time_post_enrollment_start as persistence
from scripts.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_RETAINED_CLAIM_CONTRACT_VERSION,
    POST_ENROLLMENT_START_RETAINED_CLAIM_SERVICE,
    RetainedTrustedTimePostEnrollmentStartClaim,
    TrustedTimePostEnrollmentStartClaimConsumed,
    TrustedTimePostEnrollmentStartClaimPersistenceError,
    TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed,
    retain_post_enrollment_start_claim,
    retained_post_enrollment_start_claim_bytes,
    revalidate_retained_post_enrollment_start_claim,
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


def _approval() -> TrustedTimePostEnrollmentStartApproval:
    return TrustedTimePostEnrollmentStartApproval(
        operation_id=OPERATION_ID,
        review=build_post_enrollment_start_review(
            confirmed_enrollment=_confirmed(),
            proposed_launch=TrustedTimeImmutableLaunchEvidence(
                git_revision="f" * 40,
                image_admission_sha256="7" * 64,
                source_image_id="sha256:" + "8" * 64,
                supervisor_image_id="sha256:" + "9" * 64,
            ),
        ),
    )


def _claim() -> TrustedTimePostEnrollmentStartClaim:
    approval = _approval()
    confirmed = approval.confirmed_enrollment
    sequence = confirmed.sequence_one
    reauthentication = TrustedTimePostEnrollmentRuntimeReauthentication(
        operation_id=approval.operation_id,
        approval_sha256=approval.approval_sha256,
        confirmed_enrollment_evidence_sha256=confirmed.evidence_sha256,
        review_projection_sha256=approval.review.projection_sha256,
        identities=confirmed.identities,
        anchor_sequence=1,
        checkpoint_reason="enrollment",
        confirmed_anchor_count=1,
        local_highest_anchor_sequence=1,
        remote_highest_anchor_sequence=1,
        remote_object_count=1,
        anchor_intent_semantic_sha256=sequence.anchor_intent_semantic_sha256,
        candidate_remote_readback_sha256=sequence.candidate_remote_readback_sha256,
        current_anchor_semantic_sha256=sequence.current_anchor_semantic_sha256,
        current_anchor_sha256=sequence.current_anchor_sha256,
        current_host_head_sha256=sequence.current_host_head_sha256,
        receipt_semantic_sha256=sequence.receipt_semantic_sha256,
        remote_namespace_sha256=sequence.remote_namespace_sha256,
        full_audit_completed=True,
        pending_intent_present=False,
        higher_sequence_present=False,
    )
    return TrustedTimePostEnrollmentStartClaim(
        approval=approval,
        reauthentication=reauthentication,
    )


def _artifact_paths(tmp_path: Path) -> tuple[Path, Path]:
    ignored_root = tmp_path / "artifacts"
    ignored_root.mkdir(mode=0o700)
    return ignored_root, ignored_root / "trusted-time"


def test_retained_claim_wire_payload_is_exact_closed_and_deterministic() -> None:
    claim = _claim()
    encoded = retained_post_enrollment_start_claim_bytes(claim)
    payload = json.loads(encoded)

    assert set(payload) == {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        "authority_granted",
        "claim",
        "claim_projection_sha256",
        "contract_version",
        "database_secret_disclosed",
        "operation_id",
        "persistent_start_authorized",
        "release_authorized",
        "sequence_2_authorized",
        "service",
        "shutdown_authorized",
        "status",
    }
    assert payload["contract_version"] == POST_ENROLLMENT_START_RETAINED_CLAIM_CONTRACT_VERSION
    assert payload["service"] == POST_ENROLLMENT_START_RETAINED_CLAIM_SERVICE
    assert payload["status"] == "claim_persistence_payload"
    assert payload["operation_id"] == claim.operation_id
    assert payload["claim_projection_sha256"] == claim.claim_sha256
    assert payload["claim"] == claim.payload()
    for field_name in (
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        "authority_granted",
        "database_secret_disclosed",
        "persistent_start_authorized",
        "release_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
    ):
        assert payload[field_name] is False
    assert hashlib.sha256(encoded).hexdigest() == (
        "992092fe6c00b8cef6ac5e9f75b73fca84973af0457bdd98171ed0c0ef9fce22"
    )


def test_claim_retention_is_owner_only_durable_exact_and_revalidates(tmp_path: Path) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    claim = _claim()

    retained = retain_post_enrollment_start_claim(
        claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    metadata = retained.artifact_path.stat()
    assert retained.encoded == retained_post_enrollment_start_claim_bytes(claim)
    assert retained.artifact_path.read_bytes() == retained.encoded
    assert retained.claim is claim
    assert retained.operation_id == claim.operation_id
    assert retained.claim_projection_sha256 == claim.claim_sha256
    assert retained.file_identity[0:2] == (metadata.st_dev, metadata.st_ino)
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    assert metadata.st_mode & 0o777 == 0o600
    assert artifact_directory.stat().st_mode & 0o777 == 0o700
    assert revalidate_retained_post_enrollment_start_claim(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def test_replay_is_consumed_without_overwriting_first_inode(tmp_path: Path) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    claim = _claim()
    retained = retain_post_enrollment_start_claim(
        claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    before = retained.artifact_path.stat()

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimConsumed,
        match="already consumed",
    ):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    after = retained.artifact_path.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns, retained.artifact_path.read_bytes()) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
        retained.encoded,
    )


def test_revalidation_rejects_unlink_recreate_even_with_identical_bytes(tmp_path: Path) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    retained = retain_post_enrollment_start_claim(
        _claim(),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    retained.artifact_path.unlink()
    retained.artifact_path.write_bytes(retained.encoded)
    retained.artifact_path.chmod(0o600)

    assert not revalidate_retained_post_enrollment_start_claim(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def test_revalidation_rejects_content_mode_link_and_receipt_drift(tmp_path: Path) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    retained = retain_post_enrollment_start_claim(
        _claim(),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    retained.artifact_path.chmod(0o644)
    assert not revalidate_retained_post_enrollment_start_claim(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    retained.artifact_path.chmod(0o600)
    os.link(retained.artifact_path, retained.artifact_path.with_name("second-link"))
    assert not revalidate_retained_post_enrollment_start_claim(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    with pytest.raises(TrustedTimePostEnrollmentStartClaimPersistenceError):
        replace(retained, claim_projection_sha256="0" * 64)


def test_partial_write_uncertainty_leaves_consumed_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    claim = _claim()
    monkeypatch.setattr(os, "write", lambda *_: 0)

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed,
        match="retention is unconfirmed",
    ):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.undo()
    with pytest.raises(TrustedTimePostEnrollmentStartClaimConsumed):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_fsync_uncertainty_leaves_consumed_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    artifact_directory.mkdir(mode=0o700)
    claim = _claim()
    monkeypatch.setattr(os, "fsync", lambda *_: (_ for _ in ()).throw(OSError()))

    with pytest.raises(TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.undo()
    with pytest.raises(TrustedTimePostEnrollmentStartClaimConsumed):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_write_descriptor_close_uncertainty_leaves_consumed_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    claim = _claim()
    real_close = os.close
    failed = False

    def close_then_report_uncertainty(descriptor: int) -> None:
        nonlocal failed
        metadata = os.fstat(descriptor)
        real_close(descriptor)
        if not failed and stat.S_ISREG(metadata.st_mode):
            failed = True
            raise OSError

    monkeypatch.setattr(persistence.os, "close", close_then_report_uncertainty)

    with pytest.raises(TrustedTimePostEnrollmentStartClaimRetentionUnconfirmed):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.undo()
    with pytest.raises(TrustedTimePostEnrollmentStartClaimConsumed):
        retain_post_enrollment_start_claim(
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_revalidation_rejects_canonical_name_swap_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    retained = retain_post_enrollment_start_claim(
        _claim(),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    original_read = os.read
    swapped = False

    def read_then_swap(descriptor: int, maximum: int) -> bytes:
        nonlocal swapped
        observed = original_read(descriptor, maximum)
        if observed and not swapped:
            swapped = True
            retained.artifact_path.rename(retained.artifact_path.with_suffix(".original"))
            retained.artifact_path.write_bytes(retained.encoded)
            retained.artifact_path.chmod(0o600)
        return observed

    monkeypatch.setattr(persistence.os, "read", read_then_swap)

    assert not revalidate_retained_post_enrollment_start_claim(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert swapped


def test_directory_walk_close_failure_does_not_leak_opened_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_directory = ignored_root / "trusted-time"
    original_open = os.open
    original_close = os.close
    original_fstat = os.fstat
    opened: list[int] = []
    failed = False

    def tracked_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        opened.append(descriptor)
        return descriptor

    def close_then_fail_once(descriptor: int) -> None:
        nonlocal failed
        original_close(descriptor)
        if not failed:
            failed = True
            raise OSError

    monkeypatch.setattr(persistence.os, "open", tracked_open)
    monkeypatch.setattr(persistence.os, "close", close_then_fail_once)

    with pytest.raises(TrustedTimePostEnrollmentStartClaimPersistenceError):
        persistence._open_owner_only_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
            create=True,
        )

    assert len(opened) == 2
    for descriptor in opened:
        with pytest.raises(OSError):
            original_fstat(descriptor)


@pytest.mark.parametrize("kind", ["relative", "outside", "noncanonical"])
def test_invalid_artifact_path_rejects_before_creation(tmp_path: Path, kind: str) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    candidate = {
        "relative": Path("artifacts/trusted-time"),
        "outside": tmp_path / "outside",
        "noncanonical": ignored_root / "trusted-time" / ".." / "trusted-time",
    }[kind]

    with pytest.raises(
        TrustedTimePostEnrollmentStartClaimPersistenceError,
        match="directory is invalid",
    ):
        retain_post_enrollment_start_claim(
            _claim(),
            artifact_directory=candidate,
            ignored_root=ignored_root,
        )

    assert not artifact_directory.exists()


def test_public_receipt_cannot_rebind_arbitrary_bytes_or_operation(tmp_path: Path) -> None:
    ignored_root, artifact_directory = _artifact_paths(tmp_path)
    retained = retain_post_enrollment_start_claim(
        _claim(),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    forged_bytes = b"{}\n"

    with pytest.raises(TrustedTimePostEnrollmentStartClaimPersistenceError):
        RetainedTrustedTimePostEnrollmentStartClaim(
            claim=retained.claim,
            operation_id=retained.operation_id,
            claim_projection_sha256=retained.claim_projection_sha256,
            artifact_sha256=hashlib.sha256(forged_bytes).hexdigest(),
            artifact_path=retained.artifact_path,
            encoded=forged_bytes,
            file_identity=retained.file_identity,
        )
    with pytest.raises(TrustedTimePostEnrollmentStartClaimPersistenceError):
        replace(retained, operation_id="323e4567-e89b-42d3-a456-426614174002")
