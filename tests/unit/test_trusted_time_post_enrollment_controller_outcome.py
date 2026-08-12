from __future__ import annotations

import hashlib
import inspect
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_active_controller_admission as admission_module
import scripts.trusted_time_post_enrollment_controller_outcome as controller_outcome
import scripts.trusted_time_post_enrollment_outcome as recovery_outcome
import scripts.trusted_time_post_enrollment_topology_reader as reader
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
)
from tests.unit import test_trusted_time_post_enrollment_active_controller_admission as admission_fx
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_persistent_topology as persistent_fx


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fx._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )


def _admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    claimed_fx._Context,
    object,
    object,
    admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
    RetainedTrustedTimePostEnrollmentStartClaim,
]:
    context, lease, recovery, action_fence = admission_fx._action_context(
        monkeypatch,
        tmp_path,
    )
    admission = admission_module.prepare_post_enrollment_start_active_controller_admission(
        **admission_fx._admission_kwargs(context, lease, recovery, action_fence)
    )
    retained = action_fence._claimed_fence._handoff.retained_claim
    return context, lease, recovery, admission, retained


def _release_unconfirmed_evidence(
    admission: admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
    *,
    pre_effect_observation_sha256: str = "e" * 64,
) -> controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence:
    return controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ),
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
        ),
        pre_effect_observation_sha256=pre_effect_observation_sha256,
        verifier_binding_sha256="f" * 64,
        read_only_configuration_sha256="0" * 64,
        verification_transcript_sha256=None,
        release_execution_sha256=None,
        runtime_state_sha256=None,
        successor=None,
        persistent_topology=None,
        persistent_topology_transcript_sha256=None,
    )


def _install_retention(
    monkeypatch: pytest.MonkeyPatch,
    *,
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    artifact_directory: Path,
    ignored_root: Path,
    expected_outcome_kind: str = "failure",
) -> tuple[object, list[object]]:
    capability = object()
    completed: list[object] = []

    def begin(
        _issuer: object,
        candidate: object,
        choreography_lease: object,
        retained_claim: object,
        *,
        outcome_kind: str,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint:
        assert choreography_lease is not None
        assert candidate is capability
        assert retained_claim is retained
        assert outcome_kind == expected_outcome_kind
        assert artifact_directory == retained.artifact_path.parent
        assert ignored_root == artifact_directory.parent
        return reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint(
            retained_claim=retained,
            outcome_kind=cast(Any, expected_outcome_kind),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            started_monotonic_ns=1,
            action_deadline_monotonic_ns=300_000_000_001,
            deadline_monotonic_ns=(
                300_000_000_001 if expected_outcome_kind == "success" else 305_000_000_001
            ),
            observed_monotonic_ns=2,
        )

    def complete(
        _issuer: object,
        candidate: object,
        checkpoint: object,
        receipt: object,
    ) -> None:
        assert candidate is capability
        assert type(checkpoint) is (
            reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint
        )
        completed.append(receipt)

    def abandon(
        _issuer: object,
        candidate: object,
        checkpoint: object,
        receipt: object | None,
    ) -> None:
        assert candidate is capability
        completed.append(("abandoned", checkpoint, receipt))

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_begin_post_effect_controller_outcome_retention",
        begin,
        raising=False,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_complete_post_effect_controller_outcome_retention",
        complete,
        raising=False,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_abandon_post_effect_controller_outcome_retention",
        abandon,
        raising=False,
    )
    return capability, completed


def test_retains_one_truthful_post_effect_failure_in_the_global_outcome_slot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = _release_unconfirmed_evidence(admission)

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert completed == [receipt]
    assert receipt.status is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
    )
    assert receipt.reason is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
    )
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        receipt,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert json.loads(receipt.encoded) == evidence.payload()
    assert receipt.outcome_sha256 == hashlib.sha256(receipt.encoded).hexdigest()
    assert receipt.artifact_path.read_bytes() == receipt.encoded
    slot = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    )
    assert slot.read_bytes() == controller_outcome._slot_bytes(receipt.outcome_sha256)


def test_retains_and_reloads_one_fully_bound_confirmed_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
    origin = next(
        candidate
        for candidate in admission_fx._registry_state()[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
        expected_outcome_kind="success",
    )
    persistent_topology = persistent_fx._validate(inputs)
    evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED,
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=persistent_topology,
        persistent_topology_transcript_sha256="d" * 64,
    )

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert completed == [receipt]
    assert loaded == receipt
    payload = json.loads(loaded.encoded)
    assert payload["controller_execution_confirmed"] is True
    assert payload["pre_effect_observation_sha256"] == "a" * 64
    assert payload["persistent_topology_transcript_sha256"] == "d" * 64
    assert payload["success_outcome_retained"] is True


def test_post_effect_failure_payload_is_progress_truthful_and_non_authorizing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, _, _, admission, _ = _admission(monkeypatch, tmp_path)
    evidence = _release_unconfirmed_evidence(admission)
    payload = evidence.payload()

    assert payload["release_attempted"] is True
    assert payload["release_confirmed"] is False
    assert payload["sequence_2_confirmed"] is False
    assert payload["topology_qualified"] is False
    assert payload["success_outcome_retained"] is False
    assert payload["controller_execution_confirmed"] is False
    for field in controller_outcome._CLOSED_FIELDS:
        assert payload[field] is False


def test_success_retention_failure_preserves_only_completed_runtime_facts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ),
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=persistent_fx._validate(inputs),
        persistent_topology_transcript_sha256="d" * 64,
    )

    payload = evidence.payload()

    assert payload["release_confirmed"] is True
    assert payload["sequence_2_confirmed"] is True
    assert payload["runtime_start_confirmed"] is True
    assert payload["topology_qualified"] is True
    assert payload["persistent_start_confirmed"] is True
    assert payload["controller_execution_confirmed"] is False
    assert payload["success_outcome_retained"] is False
    assert payload["qualified"] is False


def test_retains_and_reloads_success_outcome_unconfirmed_as_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
    origin = next(
        candidate
        for candidate in admission_fx._registry_state()[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ),
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=persistent_fx._validate(inputs),
        persistent_topology_transcript_sha256="d" * 64,
    )

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert completed == [receipt]
    assert loaded == receipt
    assert loaded.reason is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
    )
    payload = json.loads(loaded.encoded)
    assert payload["sequence_2_confirmed"] is True
    assert payload["topology_qualified"] is True
    assert payload["controller_execution_confirmed"] is False
    assert payload["verification_transcript_sha256"] == "9" * 64


@pytest.mark.parametrize(
    ("reason", "release_sha256", "runtime_sha256"),
    [
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED,
            "1" * 64,
            None,
        ),
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED,
            None,
            None,
        ),
    ],
)
def test_rejects_progress_inconsistent_failure_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reason: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason,
    release_sha256: str | None,
    runtime_sha256: str | None,
) -> None:
    _, _, _, admission, _ = _admission(monkeypatch, tmp_path)

    with pytest.raises(controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRejected):
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
            admission=admission,
            status=(
                controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
            ),
            reason=reason,
            pre_effect_observation_sha256="e" * 64,
            verifier_binding_sha256="f" * 64,
            read_only_configuration_sha256="0" * 64,
            verification_transcript_sha256=None,
            release_execution_sha256=release_sha256,
            runtime_state_sha256=runtime_sha256,
            successor=None,
            persistent_topology=None,
            persistent_topology_transcript_sha256=None,
        )


def test_global_outcome_slot_rejects_a_second_controller_disposition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = _release_unconfirmed_evidence(admission)
    first = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert first.artifact_path.exists()

    second_capability, abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=second_capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert len(abandoned) == 1
    assert cast(tuple[object, object, object], abandoned[0])[0] == "abandoned"


def test_fixed_slot_linearizes_two_concurrent_distinct_controller_dispositions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, _, _, admission, retained = _admission(monkeypatch, tmp_path)
    evidence = (
        _release_unconfirmed_evidence(
            admission,
            pre_effect_observation_sha256="a" * 64,
        ),
        _release_unconfirmed_evidence(
            admission,
            pre_effect_observation_sha256="b" * 64,
        ),
    )
    original_outcome_names = controller_outcome._outcome_names
    first_inventory = threading.local()
    both_checked_empty = threading.Barrier(2)

    def synchronized_empty_inventory(directory_descriptor: int) -> frozenset[str]:
        observed = original_outcome_names(directory_descriptor)
        if not getattr(first_inventory, "completed", False):
            first_inventory.completed = True
            assert observed == frozenset()
            both_checked_empty.wait(timeout=5)
        return observed

    monkeypatch.setattr(
        controller_outcome,
        "_outcome_names",
        synchronized_empty_inventory,
    )

    def retain(
        candidate: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
    ) -> object:
        try:
            return controller_outcome._persist(
                candidate,
                retained_claim=retained,
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
        except BaseException as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(retain, evidence))
    monkeypatch.setattr(controller_outcome, "_outcome_names", original_outcome_names)

    receipts = tuple(
        result
        for result in results
        if type(result)
        is controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome
    )
    failures = tuple(
        result
        for result in results
        if type(result)
        is controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained
    )
    assert len(receipts) == 1
    assert len(failures) == 1
    outcome_names = frozenset(
        candidate.name
        for candidate in context.artifact_directory.iterdir()
        if candidate.name.startswith(controller_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX)
        and candidate.name.endswith(controller_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX)
    )
    assert outcome_names == frozenset({cast(Any, receipts[0]).artifact_path.name})
    assert controller_outcome._revalidate_prepared_controller_outcome(
        cast(Any, receipts[0]),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )


def test_failed_publication_leaves_one_unreadable_reservation_and_blocks_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = _release_unconfirmed_evidence(admission)
    monkeypatch.setattr(
        controller_outcome.os,
        "link",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("link failed")),
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    staging = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_STAGING_FILE_NAME
    )
    assert staging.is_file()
    assert (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    ).is_file()
    assert len(abandoned) == 1

    second_capability, second_abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=second_capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert len(second_abandoned) == 1


@pytest.mark.parametrize(
    ("transitioned", "expected_error"),
    [
        (
            True,
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed,
        ),
        (
            False,
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable,
        ),
    ],
)
def test_begin_call_store_ambiguity_falls_back_only_when_transition_never_committed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transitioned: bool,
    expected_error: type[BaseException],
) -> None:
    context, lease, _, admission, _ = _admission(monkeypatch, tmp_path)
    capability = object()
    abandoned: list[tuple[object, object | None]] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_begin_post_effect_controller_outcome_retention",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_post_effect_outcome_retention_was_transitioned",
        lambda _issuer, candidate: candidate is capability and transitioned,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_abandon_post_effect_controller_outcome_retention",
        lambda _issuer, candidate, checkpoint, receipt=None: abandoned.append(
            (candidate, checkpoint)
        ),
    )

    with pytest.raises(expected_error):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert abandoned == [(capability, None)]


def test_retained_projection_can_be_loaded_without_reconstructing_process_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    original = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=_release_unconfirmed_evidence(admission),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert loaded == original
    assert loaded._evidence is None
    assert loaded.status is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
    )


def test_revalidator_rejects_same_bytes_commit_marker_inode_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    original = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=_release_unconfirmed_evidence(admission),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    marker = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    )
    encoded = marker.read_bytes()
    original_identity = original.commit_file_identity
    marker.unlink()
    marker.write_bytes(encoded)
    marker.chmod(0o600)

    assert not controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        original,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    reconstructed = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert reconstructed.commit_file_identity != original_identity
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        reconstructed,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )


def test_registry_completion_failure_never_publishes_a_committed_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    prepared: list[controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome] = []
    real_persist = controller_outcome._persist

    def capture_prepared(*args: object, **kwargs: object) -> object:
        receipt = real_persist(*args, **kwargs)  # type: ignore[arg-type]
        prepared.append(receipt)
        return receipt

    monkeypatch.setattr(controller_outcome, "_persist", capture_prepared)
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_complete_post_effect_controller_outcome_retention",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("injected completion")),
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert len(prepared) == 1
    assert prepared[0].commit_file_identity is None
    assert not controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        prepared[0],
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome.load_retained_post_enrollment_start_controller_outcome(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert not (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    ).exists()
    assert len(abandoned) == 1


def test_final_commit_directory_fsync_failure_remains_publicly_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    real_fsync = controller_outcome.os.fsync
    artifact_directory_identity = context.artifact_directory.stat()
    directory_fsync_count = 0

    def fail_final_commit_directory_fsync(descriptor: int) -> None:
        nonlocal directory_fsync_count
        metadata = controller_outcome.os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            artifact_directory_identity.st_dev,
            artifact_directory_identity.st_ino,
        ):
            directory_fsync_count += 1
            if directory_fsync_count == 5:
                raise OSError("injected final commit directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(controller_outcome.os, "fsync", fail_final_commit_directory_fsync)
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    final_marker = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    )
    staging_marker = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME
    )
    assert directory_fsync_count >= 5
    assert final_marker.is_file()
    assert staging_marker.is_file()
    assert final_marker.stat().st_ino == staging_marker.stat().st_ino
    assert final_marker.stat().st_nlink == 2
    assert len(completed) == 2
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome.load_retained_post_enrollment_start_controller_outcome(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )


def test_async_interruption_after_durable_commit_returns_exact_confirmed_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    retain = controller_outcome.retain_post_enrollment_start_controller_outcome
    source, first_line = inspect.getsourcelines(retain)
    return_line = first_line + next(
        offset for offset, line in enumerate(source) if line.strip() == "return retained_outcome"
    )
    interrupted = False

    def interrupt_before_return(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None) is retain.__code__
            and getattr(frame, "f_lineno", None) == return_line
        ):
            interrupted = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_before_return

    sys.settrace(interrupt_before_return)
    try:
        receipt = retain(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    finally:
        sys.settrace(None)

    assert interrupted is True
    assert completed == [receipt]
    assert receipt.commit_file_identity is not None
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        receipt,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )


def test_partial_controller_publication_atomically_blocks_legacy_recovery_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, _, _, admission, retained = _admission(monkeypatch, tmp_path)
    monkeypatch.setattr(
        controller_outcome.os,
        "link",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected publication")),
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome._persist(
            _release_unconfirmed_evidence(admission),
            retained_claim=retained,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartOutcomeAlreadyRetained):
        recovery_outcome._persist_outcome(
            retained_claim=retained,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert (
        context.artifact_directory / recovery_outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
    ).is_file()
    assert not tuple(
        context.artifact_directory.glob(
            f"{recovery_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"
        )
    )


def test_controller_outcome_module_has_no_cli_or_effecting_import_surface() -> None:
    source = Path(cast(str, controller_outcome.__file__)).read_text(encoding="utf-8")
    assert "def main(" not in source
    assert "if __name__" not in source
    assert "subprocess" not in source
    assert "docker" not in source.lower()
    assert "sqlalchemy" not in source
    assert "alpaca" not in source.lower()
    assert "etrade" not in source.lower()
    assert "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION" in (
        controller_outcome.__all__
    )
