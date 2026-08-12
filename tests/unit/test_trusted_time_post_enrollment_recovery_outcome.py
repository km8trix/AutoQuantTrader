from __future__ import annotations

import dis
import hashlib
import io
import json
import multiprocessing
import os
import stat
import sys
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
)
from scripts import trusted_time_post_enrollment_outcome as outcome
from scripts import trusted_time_post_enrollment_topology_reader as reader
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
    retain_post_enrollment_start_claim,
)
from tests.unit import test_trusted_time_post_enrollment_claim_persistence as claim_fixtures


def _load_recovery_outcome_in_spawned_process(
    artifact_directory: str,
    ignored_root: str,
    connection: Any,
) -> None:
    connection.send(("attempting", None))
    try:
        retained = outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=Path(artifact_directory),
            ignored_root=Path(ignored_root),
        )
    except BaseException as error:
        connection.send(("error", type(error).__name__))
    else:
        connection.send(("loaded", retained.outcome_sha256))
    finally:
        connection.close()


def _retained_claim(
    tmp_path: Path,
) -> tuple[Path, Path, RetainedTrustedTimePostEnrollmentStartClaim]:
    ignored_root, artifact_directory = claim_fixtures._artifact_paths(tmp_path)
    retained = retain_post_enrollment_start_claim(
        claim_fixtures._claim(),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    return ignored_root, artifact_directory, retained


def _checkpoint(
    retained_claim: RetainedTrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint:
    started = 5_000_000_000
    return reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint(
        retained_claim=retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        started_monotonic_ns=started,
        deadline_monotonic_ns=(
            started
            + outcome.POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS * 1_000_000_000
        ),
        observed_monotonic_ns=started + 1,
    )


def _fake_issuer(
    monkeypatch: pytest.MonkeyPatch,
    checkpoint: reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint,
    *,
    begin_error: BaseException | None = None,
    complete_error: BaseException | None = None,
) -> tuple[
    reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    dict[str, list[tuple[object, ...]]],
]:
    calls: dict[str, list[tuple[object, ...]]] = {
        "abandon": [],
        "begin": [],
        "complete": [],
    }

    def begin(
        _: object,
        capability: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint:
        calls["begin"].append((capability, artifact_directory, ignored_root))
        if begin_error is not None:
            raise begin_error
        return checkpoint

    def complete(
        _: object,
        capability: object,
        observed: object,
        retained_outcome: object,
    ) -> None:
        calls["complete"].append((capability, observed, retained_outcome))
        if complete_error is not None:
            raise complete_error

    def abandon(_: object, capability: object, observed: object) -> None:
        calls["abandon"].append((capability, observed))

    issuer_type = cast(Any, reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
    monkeypatch.setattr(issuer_type, "_begin_recovery_outcome_retention", begin)
    monkeypatch.setattr(issuer_type, "_complete_recovery_outcome_retention", complete)
    monkeypatch.setattr(issuer_type, "_abandon_recovery_outcome_retention", abandon)
    return object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer), calls


def _retain_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    complete_error: BaseException | None = None,
) -> tuple[
    Path,
    Path,
    RetainedTrustedTimePostEnrollmentStartClaim,
    outcome.RetainedTrustedTimePostEnrollmentStartOutcome,
    dict[str, list[tuple[object, ...]]],
]:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(
        monkeypatch,
        checkpoint,
        complete_error=complete_error,
    )
    capability = object()
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained) as terminal:
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    return (
        ignored_root,
        artifact_directory,
        retained_claim,
        terminal.value.retained_outcome,
        calls,
    )


def test_recovery_outcome_wire_payload_is_fixed_closed_and_secret_free(tmp_path: Path) -> None:
    _, _, retained_claim = _retained_claim(tmp_path)
    claim = retained_claim.claim

    encoded = outcome.retained_post_enrollment_start_recovery_required_outcome_bytes(
        operation_id=retained_claim.operation_id,
        approval_sha256=claim.approval.approval_sha256,
        claim_sha256=claim.claim_sha256,
        retained_claim_artifact_sha256=retained_claim.artifact_sha256,
    )
    payload = json.loads(encoded)

    closed_fields = {
        "authority_granted",
        "claim_chronology_authenticated",
        "claim_retention_authorized",
        "database_secret_disclosed",
        "outcome_retention_authorized",
        "persistent_start_authorized",
        "persistent_start_confirmed",
        "qualified",
        "release_attempted",
        "release_authorized",
        "release_confirmed",
        "retry_authorized",
        "sequence_2_authorized",
        "sequence_2_confirmed",
        "shutdown_authorized",
        "source_start_authorized",
        "supervisor_start_authorized",
        "topology_mutation_authorized",
        "topology_qualified",
    }
    assert set(payload) == {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *closed_fields,
        "approval_sha256",
        "claim_retention_revalidated",
        "claim_sha256",
        "contract_version",
        "operation_id",
        "reason",
        "retained_claim_artifact_sha256",
        "service",
        "status",
    }
    assert payload["contract_version"] == (
        outcome.POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION
    )
    assert payload["service"] == outcome.POST_ENROLLMENT_START_RETAINED_OUTCOME_SERVICE
    assert payload["status"] == "recovery_required"
    assert payload["reason"] == "post_enrollment_start_recovery_required"
    assert payload["claim_retention_revalidated"] is True
    assert payload["operation_id"] == retained_claim.operation_id
    assert payload["approval_sha256"] == claim.approval.approval_sha256
    assert payload["claim_sha256"] == claim.claim_sha256
    assert payload["retained_claim_artifact_sha256"] == retained_claim.artifact_sha256
    for field_name in {*FIRST_ENROLLMENT_AUTHORITY_FIELDS, *closed_fields}:
        assert payload[field_name] is False
    forbidden_fragments = (
        b"artifact_path",
        b"capability",
        b"deadline",
        b"docker",
        b"monotonic",
        b"pid",
        b"process",
        b"release_argv",
        b"secret_value",
        b"thread",
    )
    assert all(fragment not in encoded for fragment in forbidden_fragments)
    assert hashlib.sha256(encoded).hexdigest() == (
        "e7c122580af060045f0b4d4d261493163902214673169260781199cb5939aa5f"
    )


def test_writer_retains_content_addressed_owner_only_outcome_and_raises_terminal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim, retained_outcome, calls = _retain_outcome(
        monkeypatch,
        tmp_path,
    )

    metadata = retained_outcome.artifact_path.stat()
    expected_name = (
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}"
        f"{retained_outcome.outcome_sha256}"
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    assert retained_outcome.artifact_path.name == expected_name
    assert retained_outcome.artifact_path.read_bytes() == retained_outcome.encoded
    assert hashlib.sha256(retained_outcome.encoded).hexdigest() == retained_outcome.outcome_sha256
    assert retained_outcome.file_identity[0:2] == (metadata.st_dev, metadata.st_ino)
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_nlink == 1
    assert metadata.st_mode & 0o777 == 0o600
    assert artifact_directory.stat().st_mode & 0o777 == 0o700
    assert not (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    ).exists()
    slot_path = artifact_directory / outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
    slot_metadata = slot_path.stat()
    assert slot_path.read_bytes() == outcome._outcome_slot_bytes(
        retained_outcome.outcome_sha256,
        outcome_contract_version=outcome.POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION,
        status="retained",
    )
    assert retained_outcome.slot_file_identity[0:2] == (
        slot_metadata.st_dev,
        slot_metadata.st_ino,
    )
    assert retained_claim.artifact_path.exists()
    assert len(calls["begin"]) == 1
    assert len(calls["complete"]) == 1
    assert calls["complete"][0][2] is retained_outcome
    assert calls["abandon"] == []
    loaded = outcome.load_retained_post_enrollment_start_outcome(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert loaded == retained_outcome
    assert outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def test_begin_failure_is_capability_unavailable_and_does_not_touch_disk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(
        monkeypatch,
        checkpoint,
        begin_error=RuntimeError("private detail"),
    )

    with pytest.raises(
        outcome.TrustedTimePostEnrollmentStartOutcomeCapabilityUnavailable,
        match="capability is unavailable",
    ) as rejected:
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert "private detail" not in str(rejected.value)
    assert len(calls["begin"]) == 1
    assert calls["complete"] == []
    assert calls["abandon"] == []
    outcome_paths = artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*")
    assert list(outcome_paths) == []


def test_duck_typed_issuer_cannot_bypass_exact_capability_or_create_outcome(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )

    class DuckIssuer:
        begin_called = False

        def _begin_recovery_outcome_retention(
            self,
            _: object,
            *,
            artifact_directory: Path,
            ignored_root: Path,
        ) -> reader._TrustedTimePostEnrollmentRecoveryRetentionCheckpoint:
            self.begin_called = True
            return checkpoint

    duck = DuckIssuer()

    with pytest.raises(
        outcome.TrustedTimePostEnrollmentStartOutcomeCapabilityUnavailable,
        match="capability is unavailable",
    ):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=cast(Any, duck),
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert duck.begin_called is False
    outcome_paths = artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*")
    assert list(outcome_paths) == []


def test_invalid_checkpoint_is_evidence_unavailable_and_consumes_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = replace(
        _checkpoint(
            retained_claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ),
        deadline_monotonic_ns=5_000_000_000 + 304 * 1_000_000_000,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert calls["complete"] == []
    assert len(calls["abandon"]) == 1
    outcome_paths = artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*")
    assert list(outcome_paths) == []


def test_complete_failure_is_unconfirmed_but_never_deletes_durable_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(
        monkeypatch,
        checkpoint,
        complete_error=RuntimeError("deadline detail"),
    )

    with pytest.raises(
        outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed,
        match="retention is unconfirmed",
    ) as unconfirmed:
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert "deadline detail" not in str(unconfirmed.value)
    assert len(calls["complete"]) == 1
    completed_outcome = calls["complete"][0][2]
    assert type(completed_outcome) is outcome.RetainedTrustedTimePostEnrollmentStartOutcome
    assert completed_outcome.artifact_path.exists()
    assert len(calls["abandon"]) == 1
    loaded = outcome.load_retained_post_enrollment_start_outcome(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert loaded.status is (
        outcome.TrustedTimePostEnrollmentStartRetainedOutcomeStatus.RECOVERY_REQUIRED
    )


def test_post_write_claim_revalidation_failure_keeps_outcome_and_abandons(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    revalidations = iter((True, True, False))
    monkeypatch.setattr(
        outcome,
        "revalidate_retained_post_enrollment_start_claim",
        lambda *args, **kwargs: next(revalidations),
    )

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert calls["complete"] == []
    assert len(calls["abandon"]) == 1
    loaded = outcome.load_retained_post_enrollment_start_outcome(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert loaded.claim_sha256 == retained_claim.claim.claim_sha256


@pytest.mark.parametrize("interference", ["remove", "rename"])
def test_final_outcome_interference_is_unconfirmed_before_completion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interference: str,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    displaced: list[Path] = []
    original_revalidate = outcome.revalidate_retained_post_enrollment_start_outcome

    def interfere_then_revalidate(
        retained: outcome.RetainedTrustedTimePostEnrollmentStartOutcome,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        if interference == "remove":
            retained.artifact_path.unlink()
        else:
            replacement = retained.artifact_path.with_suffix(".displaced")
            retained.artifact_path.rename(replacement)
            displaced.append(replacement)
        return original_revalidate(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.setattr(
        outcome,
        "revalidate_retained_post_enrollment_start_outcome",
        interfere_then_revalidate,
    )

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert calls["complete"] == []
    assert len(calls["abandon"]) == 1
    if interference == "remove":
        assert displaced == []
    else:
        assert len(displaced) == 1
        assert displaced[0].exists()


def test_replay_never_overwrites_first_outcome_inode_and_abandons(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    before = retained_outcome.artifact_path.stat()
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)

    with pytest.raises(
        outcome.TrustedTimePostEnrollmentStartOutcomeAlreadyRetained,
        match="already retained",
    ):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    after = retained_outcome.artifact_path.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
    )
    assert retained_outcome.artifact_path.read_bytes() == retained_outcome.encoded
    assert calls["complete"] == []
    assert len(calls["abandon"]) == 1


def test_partial_write_failure_preserves_private_staging_and_never_publishes_final(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    real_write = os.write
    write_count = 0

    def partial_then_fail(descriptor: int, value: object) -> int:
        nonlocal write_count
        write_count += 1
        if write_count == 1:
            return int(real_write(descriptor, cast(Any, value)))
        if write_count == 2:
            view = memoryview(cast(Any, value))
            return int(real_write(descriptor, view[:1]))
        raise OSError("injected")

    monkeypatch.setattr(os, "write", partial_then_fail)
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    claim = retained_claim.claim
    encoded = outcome.retained_post_enrollment_start_recovery_required_outcome_bytes(
        operation_id=retained_claim.operation_id,
        approval_sha256=claim.approval.approval_sha256,
        claim_sha256=claim.claim_sha256,
        retained_claim_artifact_sha256=retained_claim.artifact_sha256,
    )
    expected_path = artifact_directory / (
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}"
        f"{hashlib.sha256(encoded).hexdigest()}"
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    staging_path = (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    )
    assert not expected_path.exists()
    assert staging_path.is_file()
    assert staging_path.stat().st_size == 1
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert calls["complete"] == []
    assert len(calls["abandon"]) == 1


def test_loader_and_revalidator_fail_closed_on_tamper_mode_and_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    retained_outcome.artifact_path.chmod(0o640)

    assert not outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    retained_outcome.artifact_path.chmod(0o600)
    second = artifact_directory / (
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}{'0' * 64}"
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    second.write_bytes(b"{}\n")
    second.chmod(0o600)
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_revalidator_detects_inode_replacement_even_with_exact_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    retained_outcome.artifact_path.unlink()
    retained_outcome.artifact_path.write_bytes(retained_outcome.encoded)
    retained_outcome.artifact_path.chmod(0o600)

    assert not outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    loaded = outcome.load_retained_post_enrollment_start_outcome(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert loaded.encoded == retained_outcome.encoded
    assert loaded.file_identity != retained_outcome.file_identity


def test_loader_rejects_same_name_inode_replacement_during_final_inventory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    original_inventory = outcome._outcome_names
    inventory_calls = 0

    def replace_during_final_inventory(directory_descriptor: int) -> frozenset[str]:
        nonlocal inventory_calls
        inventory_calls += 1
        names = original_inventory(directory_descriptor)
        if inventory_calls == 2:
            retained_outcome.artifact_path.unlink()
            retained_outcome.artifact_path.write_bytes(retained_outcome.encoded)
            retained_outcome.artifact_path.chmod(0o600)
        return names

    monkeypatch.setattr(outcome, "_outcome_names", replace_during_final_inventory)
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert inventory_calls == 2


def test_loader_and_revalidator_reject_surviving_publication_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    staging_path = (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    )
    os.link(retained_outcome.artifact_path, staging_path)

    assert not outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_loader_rejects_absent_outcome_and_noncanonical_directory(tmp_path: Path) -> None:
    ignored_root, artifact_directory, _ = _retained_claim(tmp_path)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=ignored_root,
            ignored_root=ignored_root,
        )


def test_receipt_rejects_scalar_byte_path_and_identity_forgery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, _, _, retained_outcome, _ = _retain_outcome(monkeypatch, tmp_path)

    for changes in (
        {"operation_id": "not-an-operation"},
        {"claim_sha256": "0" * 64},
        {"encoded": retained_outcome.encoded + b" "},
        {"artifact_path": retained_outcome.artifact_path.parent / "wrong"},
        {
            "file_identity": (
                *retained_outcome.file_identity[:5],
                2,
                *retained_outcome.file_identity[6:],
            )
        },
        {
            "slot_file_identity": (
                *retained_outcome.slot_file_identity[:5],
                2,
                *retained_outcome.slot_file_identity[6:],
            )
        },
    ):
        with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRejected):
            replace(retained_outcome, **changes)


def test_module_has_no_runtime_or_command_surface() -> None:
    assert not hasattr(outcome, "main")
    assert not hasattr(outcome, "release")
    assert not hasattr(outcome, "run_bounded_subprocess")
    assert "subprocess" not in outcome.__dict__
    assert "psycopg" not in outcome.__dict__


def test_loader_rejects_legacy_final_bound_to_controller_contract_slot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    slot = artifact_directory / outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
    slot.unlink()
    slot.write_bytes(
        outcome._outcome_slot_bytes(
            retained_outcome.outcome_sha256,
            outcome_contract_version=(
                "phase6d-post-enrollment-start-retained-controller-outcome-v1"
            ),
        )
    )
    slot.chmod(0o600)

    assert not outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_legacy_slot_removal_and_same_bytes_replacement_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _, retained_outcome, _ = _retain_outcome(
        monkeypatch,
        tmp_path,
    )
    slot = artifact_directory / outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
    encoded = slot.read_bytes()
    original_identity = retained_outcome.slot_file_identity
    slot.unlink()

    assert not outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    slot.write_bytes(encoded)
    slot.chmod(0o600)
    assert not outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    reconstructed = outcome.load_retained_post_enrollment_start_outcome(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert reconstructed.slot_file_identity != original_identity
    assert outcome.revalidate_retained_post_enrollment_start_outcome(
        reconstructed,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def test_legacy_outcome_name_consumes_slot_without_overwrite(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    legacy = artifact_directory / outcome.POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME
    legacy.write_bytes(b"legacy\n")
    legacy.chmod(0o600)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeAlreadyRetained):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert legacy.read_bytes() == b"legacy\n"
    assert len(calls["abandon"]) == 1
    assert (
        list(artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*")) == []
    )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


@pytest.mark.parametrize("artifact_kind", ["symlink", "hardlink", "fifo"])
def test_recognized_nonexclusive_outcome_entry_blocks_writer_and_loader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    artifact_kind: str,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    candidate = artifact_directory / (
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}{'f' * 64}"
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    if artifact_kind == "symlink":
        candidate.symlink_to(retained_claim.artifact_path.name)
    elif artifact_kind == "hardlink":
        hardlink_target = tmp_path / "foreign-outcome-target"
        hardlink_target.write_bytes(b"foreign\n")
        hardlink_target.chmod(0o600)
        os.link(hardlink_target, candidate)
    else:
        os.mkfifo(candidate, 0o600)

    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeAlreadyRetained):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert candidate.lstat()
    assert len(calls["abandon"]) == 1
    assert calls["complete"] == []


def test_loader_rejects_hash_named_noncanonical_json(
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, _ = _retained_claim(tmp_path)
    encoded = b'{"status":"recovery_required"}\n'
    digest = hashlib.sha256(encoded).hexdigest()
    candidate = artifact_directory / (
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}{digest}"
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    candidate.write_bytes(encoded)
    candidate.chmod(0o600)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_owner_only_directory_mode_is_required_before_outcome_io(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    artifact_directory.chmod(0o750)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert len(calls["abandon"]) == 1
    assert calls["complete"] == []


def test_file_fsync_failure_is_unconfirmed_and_preserves_private_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    real_fsync = os.fsync
    failed = False

    def fail_outcome_file_fsync(descriptor: int) -> None:
        nonlocal failed
        if not failed and os.fstat(descriptor).st_size > 256:
            failed = True
            raise OSError("injected")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_outcome_file_fsync)
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    paths = list(artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"))
    staging_path = (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    )
    assert paths == []
    assert staging_path.is_file()
    assert staging_path.stat().st_nlink == 1
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert len(calls["abandon"]) == 1
    assert calls["complete"] == []


def test_link_directory_fsync_failure_preserves_same_inode_staging_barrier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    real_fsync = os.fsync
    directory_fsync_calls = 0

    def fail_second_directory_fsync(descriptor: int) -> None:
        nonlocal directory_fsync_calls
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_fsync_calls += 1
        if directory_fsync_calls == 2:
            raise OSError("injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_second_directory_fsync)
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    paths = list(artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"))
    staging_path = (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    )
    assert directory_fsync_calls == 3
    assert len(paths) == 1
    assert staging_path.is_file()
    assert paths[0].stat().st_ino == staging_path.stat().st_ino
    assert paths[0].stat().st_nlink == 2
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert len(calls["abandon"]) == 1
    assert calls["complete"] == []


@pytest.mark.parametrize(
    "failure_window",
    ["staging_file_fsync", "linked_directory_fsync", "final_directory_fsync"],
)
def test_spawned_loader_never_observes_an_unconfirmed_publication_window(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_window: str,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    claim = retained_claim.claim
    encoded = outcome.retained_post_enrollment_start_recovery_required_outcome_bytes(
        operation_id=retained_claim.operation_id,
        approval_sha256=claim.approval.approval_sha256,
        claim_sha256=claim.claim_sha256,
        retained_claim_artifact_sha256=retained_claim.artifact_sha256,
    )
    real_fsync = os.fsync
    publication_paused = threading.Event()
    release_publication = threading.Event()
    directory_fsync_calls = 0
    failure_injected = False

    def pause_then_fail(descriptor: int) -> None:
        nonlocal directory_fsync_calls, failure_injected
        metadata = os.fstat(descriptor)
        is_directory = stat.S_ISDIR(metadata.st_mode)
        if is_directory:
            directory_fsync_calls += 1
        selected = (
            (
                failure_window == "staging_file_fsync"
                and not is_directory
                and metadata.st_size == len(encoded)
            )
            or (
                failure_window == "linked_directory_fsync"
                and is_directory
                and directory_fsync_calls == 2
            )
            or (
                failure_window == "final_directory_fsync"
                and is_directory
                and directory_fsync_calls == 3
            )
        )
        if selected and not failure_injected:
            failure_injected = True
            publication_paused.set()
            if not release_publication.wait(timeout=10.0):
                raise RuntimeError("publication barrier timed out")
            raise OSError("injected publication failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", pause_then_fail)
    writer_errors: list[BaseException] = []

    def write_outcome() -> None:
        try:
            outcome._persist_outcome(
                retained_claim=retained_claim,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except BaseException as error:
            writer_errors.append(error)

    writer = threading.Thread(target=write_outcome)
    writer.start()
    assert publication_paused.wait(timeout=10.0)

    process_context = multiprocessing.get_context("spawn")
    receive_connection, send_connection = process_context.Pipe(duplex=False)
    loader = process_context.Process(
        target=_load_recovery_outcome_in_spawned_process,
        args=(str(artifact_directory), str(ignored_root), send_connection),
    )
    try:
        loader.start()
        send_connection.close()
        assert receive_connection.poll(10.0)
        assert receive_connection.recv() == ("attempting", None)
        assert not receive_connection.poll(0.5)

        release_publication.set()
        writer.join(timeout=10.0)
        assert not writer.is_alive()
        assert receive_connection.poll(10.0)
        assert receive_connection.recv() == (
            "error",
            "TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable",
        )
        loader.join(timeout=10.0)
        assert not loader.is_alive()
        assert loader.exitcode == 0
    finally:
        release_publication.set()
        writer.join(timeout=10.0)
        if loader.is_alive():
            loader.terminate()
            loader.join(timeout=10.0)
        receive_connection.close()
        send_connection.close()

    assert failure_injected is True
    assert len(writer_errors) == 1
    assert isinstance(
        writer_errors[0],
        outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed,
    )
    staging_path = (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    )
    assert staging_path.is_file()
    assert (artifact_directory / outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME).is_file()


def test_reserved_slot_rejects_ambiguous_final_when_every_obscuring_fallback_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    claim = retained_claim.claim
    encoded = outcome.retained_post_enrollment_start_recovery_required_outcome_bytes(
        operation_id=retained_claim.operation_id,
        approval_sha256=claim.approval.approval_sha256,
        claim_sha256=claim.claim_sha256,
        retained_claim_artifact_sha256=retained_claim.artifact_sha256,
    )
    outcome_sha256 = hashlib.sha256(encoded).hexdigest()
    final_path = artifact_directory / (
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}"
        f"{outcome_sha256}"
        f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    staging_name = outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    slot_path = artifact_directory / outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
    real_open_owner_only_file = outcome._open_owner_only_file
    real_unlink = os.unlink
    real_write_locked_slot = outcome._write_locked_slot
    slot_writes = 0
    obscuring_started = False
    obscuring_attempts: list[str] = []

    def fail_retained_slot_rewrite(descriptor: int, value: bytes) -> tuple[int, ...]:
        nonlocal obscuring_started, slot_writes
        slot_writes += 1
        if slot_writes == 2:
            obscuring_started = True
            raise OSError("injected retained-slot rewrite failure")
        return real_write_locked_slot(descriptor, value)

    def fail_obscuring_rename(*_: object, **__: object) -> None:
        obscuring_attempts.append("rename")
        raise OSError("injected rename failure")

    def fail_obscuring_sentinel(
        directory_descriptor: int,
        file_name: str,
        *,
        exclusive: bool,
    ) -> io.FileIO:
        if obscuring_started and file_name == staging_name:
            obscuring_attempts.append("sentinel")
            raise OSError("injected sentinel failure")
        return real_open_owner_only_file(
            directory_descriptor,
            file_name,
            exclusive=exclusive,
        )

    def fail_obscuring_unlink(
        path: str | bytes | os.PathLike[str],
        *,
        dir_fd: int | None = None,
    ) -> None:
        if obscuring_started:
            obscuring_attempts.append("unlink")
            raise OSError("injected unlink failure")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(outcome, "_write_locked_slot", fail_retained_slot_rewrite)
    monkeypatch.setattr(os, "rename", fail_obscuring_rename)
    monkeypatch.setattr(outcome, "_open_owner_only_file", fail_obscuring_sentinel)
    monkeypatch.setattr(os, "unlink", fail_obscuring_unlink)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome._persist_outcome(
            retained_claim=retained_claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert slot_writes == 2
    assert obscuring_attempts == ["rename", "sentinel", "unlink"]
    assert final_path.read_bytes() == encoded
    assert not (artifact_directory / staging_name).exists()
    assert slot_path.read_bytes() == outcome._outcome_slot_bytes(
        outcome_sha256,
        outcome_contract_version=outcome.POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION,
        status="reserved",
    )
    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable):
        outcome.load_retained_post_enrollment_start_outcome(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def test_concurrent_writers_create_at_most_one_content_addressed_inode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, _ = _fake_issuer(monkeypatch, checkpoint)
    barrier = threading.Barrier(3)
    terminals: list[BaseException] = []

    def compete() -> None:
        barrier.wait(timeout=2.0)
        try:
            outcome.retain_post_enrollment_start_recovery_required_outcome(
                topology_issuer=issuer,
                recovery_retention_capability=object(),
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except BaseException as terminal:
            terminals.append(terminal)

    workers = [threading.Thread(target=compete) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait(timeout=2.0)
    for worker in workers:
        worker.join(timeout=2.0)
        assert not worker.is_alive()

    paths = list(artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"))
    assert len(paths) == 1
    assert len(terminals) == 2
    assert (
        sum(
            isinstance(
                terminal,
                outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained,
            )
            for terminal in terminals
        )
        == 1
    )
    assert all(
        isinstance(
            terminal,
            outcome.TrustedTimePostEnrollmentStartOutcomeAlreadyRetained
            | outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed
            | outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained,
        )
        for terminal in terminals
    )


def test_outcome_directory_walk_async_failure_closes_every_owned_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_directory = ignored_root / "trusted-time"
    original_open = os.open
    original_fstat = os.fstat
    opened: list[int] = []

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

    def interrupt_fstat(_: int) -> os.stat_result:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "fstat", interrupt_fstat)

    with pytest.raises(KeyboardInterrupt):
        outcome._open_owner_only_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
            create=True,
        )

    assert len(opened) >= 2
    for descriptor in set(opened):
        with pytest.raises(OSError):
            original_fstat(descriptor)


def test_async_outcome_write_failure_closes_every_owned_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    original_open = os.open
    original_fstat = os.fstat
    opened: list[int] = []

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

    def interrupt_write(_: int, __: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "write", interrupt_write)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert opened
    for descriptor in set(opened):
        with pytest.raises(OSError):
            original_fstat(descriptor)
    assert len(calls["abandon"]) == 1
    assert calls["complete"] == []


def test_async_publication_failure_closes_slot_staging_and_directory_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    checkpoint = _checkpoint(
        retained_claim,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    issuer, calls = _fake_issuer(monkeypatch, checkpoint)
    original_open = os.open
    original_fstat = os.fstat
    opened: list[int] = []

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

    def interrupt_link(*_: object, **__: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "link", interrupt_link)

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=object(),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert opened
    for descriptor in set(opened):
        with pytest.raises(OSError):
            original_fstat(descriptor)
    assert (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    ).is_file()
    assert len(calls["abandon"]) == 1
    assert calls["complete"] == []


def test_opcode_interruption_between_staging_call_and_store_closes_both_file_owners(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root, artifact_directory, retained_claim = _retained_claim(tmp_path)
    original_fstat = os.fstat
    real_open_owner_only_file = outcome._open_owner_only_file
    opened: list[tuple[str, int]] = []

    def tracked_open_owner_only_file(
        directory_descriptor: int,
        file_name: str,
        *,
        exclusive: bool,
    ) -> io.FileIO:
        file_owner = real_open_owner_only_file(
            directory_descriptor,
            file_name,
            exclusive=exclusive,
        )
        opened.append((file_name, file_owner.fileno()))
        return file_owner

    instructions = list(dis.get_instructions(outcome._persist_outcome))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "file_owner"
        and index > 0
        and instructions[index - 1].opname == "CALL"
    )
    store_offset = instructions[store_index].offset
    target_code = outcome._persist_outcome.__code__

    def interrupt_before_store(_: object, instruction_offset: int) -> None:
        if instruction_offset == store_offset:
            raise KeyboardInterrupt

    monkeypatch.setattr(outcome, "_open_owner_only_file", tracked_open_owner_only_file)
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    interrupted = False
    sys.monitoring.use_tool_id(tool_id, "trusted-time-outcome-test")
    try:
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            interrupt_before_store,
        )
        sys.monitoring.set_local_events(
            tool_id,
            target_code,
            sys.monitoring.events.INSTRUCTION,
        )
        try:
            outcome._persist_outcome(
                retained_claim=retained_claim,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except KeyboardInterrupt:
            interrupted = True
    finally:
        sys.monitoring.set_local_events(tool_id, target_code, 0)
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            None,
        )
        sys.monitoring.free_tool_id(tool_id)

    assert interrupted is True
    assert [file_name for file_name, _ in opened] == [
        outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
        outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
    ]
    assert len({descriptor for _, descriptor in opened}) == 2
    for _, descriptor in opened:
        with pytest.raises(OSError):
            original_fstat(descriptor)
    assert (
        artifact_directory / outcome._POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME
    ).is_file()
    assert not list(
        artifact_directory.glob(f"{outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*")
    )
