from __future__ import annotations

import ast
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_active_controller as controller
import scripts.trusted_time_post_enrollment_controller_outcome as outcome
import scripts.trusted_time_post_enrollment_sequence_two_verifier as sequence_verifier
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartSuccessor,
)
from scripts.trusted_time_post_enrollment_sequence_two_verifier import (
    TrustedTimePostEnrollmentStartSequenceTwoVerifier,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_persistent_topology as persistent_fx
from tests.unit import test_trusted_time_post_enrollment_sequence_two_verifier as verifier_fx
from tests.unit import test_trusted_time_post_enrollment_start as start_fx


def _runtime_marker(
    *,
    path: str,
    byte_sha256: str,
    size: int,
    inode: int,
    modified_time_ns: int,
    changed_time_ns: int,
) -> dict[str, object]:
    return {
        "byte_sha256": byte_sha256,
        "changed_time_ns": changed_time_ns,
        "device": 4,
        "inode": inode,
        "link_count": 1,
        "mode": 0o400,
        "modified_time_ns": modified_time_ns,
        "owner_gid": 10_001,
        "owner_uid": 10_001,
        "path": path,
        "regular": True,
        "size": size,
    }


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
    monkeypatch.setattr(
        controller,
        "TrustedTimePostEnrollmentStartSequenceTwoVerifier",
        _SequenceTwoVerifier,
    )


class _SequenceTwoVerifier:
    def __init__(self, observed: object) -> None:
        self.observed = observed
        self.calls = 0
        self.closed = 0
        self.verifier_binding_sha256 = "e" * 64
        self.read_only_configuration_sha256 = "f" * 64
        self.verification_transcript_sha256: str | None = None

    def reauthenticate_post_enrollment_start_successor(self, **_: object) -> Any:
        self.calls += 1
        if self.calls == 2:
            self.verification_transcript_sha256 = "0" * 64
        return self.observed

    def abort(self) -> None:
        self.closed += 1


class _PreReleaseRetained(BaseException):
    pass


def _paths(inputs: dict[str, object]) -> dict[str, Path]:
    return {
        name: cast(Path, inputs[name])
        for name in (
            "expected_database_secret_file",
            "expected_head_anchor_authority_file",
            "expected_head_anchor_auth_secret_file",
            "expected_head_anchor_signing_key_secret_file",
        )
    }


def _install_controller_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    context: claimed_fx._Context,
    retained: object,
    post_effect_capability: object,
    observed_monotonic_ns: int = 20_000_000_001,
) -> list[str]:
    events: list[str] = []

    def active(_issuer: object, lease: object) -> reader._ChoreographyCheckpoint:
        assert lease is not None
        events.append("active_lease")
        return reader._ChoreographyCheckpoint(
            lease_sha256="1" * 64,
            started_monotonic_ns=1,
            deadline_monotonic_ns=300_000_000_001,
            observed_monotonic_ns=observed_monotonic_ns,
        )

    def armed(
        _issuer: object,
        lease: object,
        recovery: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        assert lease is not None
        assert recovery is not None
        assert artifact_directory == context.artifact_directory
        assert ignored_root == context.ignored_root
        events.append("armed")

    def issue(_issuer: object) -> object:
        events.append("issue_post_effect_candidate")
        return post_effect_capability

    def transition(
        _issuer: object,
        lease: object,
        recovery: object,
        candidate: object,
        *,
        post_effect_outcome_candidate: object,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        assert lease is not None
        assert recovery is not None
        assert candidate is retained
        assert post_effect_outcome_candidate is post_effect_capability
        assert artifact_directory == context.artifact_directory
        assert ignored_root == context.ignored_root
        events.append("transition")

    def require_post(
        _issuer: object,
        capability: object,
        lease: object,
        candidate: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> reader._ChoreographyCheckpoint:
        assert capability is post_effect_capability
        assert lease is not None
        assert candidate is retained
        assert artifact_directory == context.artifact_directory
        assert ignored_root == context.ignored_root
        events.append("post_effect")
        return active(_issuer, lease)

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_active_choreography_lease",
        active,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_armed_recovery_outcome_retention",
        armed,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_issue_post_effect_outcome_retention_candidate",
        issue,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_transition_to_post_effect_outcome_retention",
        transition,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_active_post_effect_outcome_retention",
        require_post,
    )
    return events


def _install_outcome_retention(
    monkeypatch: pytest.MonkeyPatch,
    *,
    context: claimed_fx._Context,
    retained: object,
    post_effect_capability: object,
) -> list[object]:
    completed: list[object] = []

    def begin(
        _issuer: object,
        capability: object,
        lease: object,
        candidate: object,
        *,
        outcome_kind: str,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint:
        assert capability is post_effect_capability
        assert lease is not None
        assert candidate is retained
        assert outcome_kind in {"success", "failure"}
        assert artifact_directory == context.artifact_directory
        assert ignored_root == context.ignored_root
        return reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint(
            retained_claim=cast(Any, retained),
            outcome_kind=cast(Any, outcome_kind),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            started_monotonic_ns=1,
            action_deadline_monotonic_ns=300_000_000_001,
            deadline_monotonic_ns=(
                300_000_000_001 if outcome_kind == "success" else 305_000_000_001
            ),
            observed_monotonic_ns=200_000_000_001,
        )

    def complete(
        _issuer: object,
        capability: object,
        checkpoint: object,
        receipt: object,
    ) -> None:
        assert capability is post_effect_capability
        assert checkpoint is not None
        completed.append(receipt)

    def abandon(
        _issuer: object,
        capability: object,
        checkpoint: object,
        receipt: object | None,
    ) -> None:
        assert capability is post_effect_capability
        completed.append(("abandoned", checkpoint, receipt))

    def return_failure(
        _issuer: object,
        lease: object,
        receipt: object,
    ) -> object:
        assert lease is not None
        assert receipt in completed
        return receipt

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_begin_post_effect_controller_outcome_retention",
        begin,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_complete_post_effect_controller_outcome_retention",
        complete,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_abandon_post_effect_controller_outcome_retention",
        abandon,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_return_confirmed_post_effect_controller_failure",
        return_failure,
    )
    return completed


def _prepared(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict[str, object], claimed_fx._Context, object, object, object]:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = inputs["admission"]
    action_fence = cast(Any, admission)._action_fence
    retained = action_fence._claimed_fence._handoff.retained_claim
    lease = object()
    recovery = cast(Any, context).action_recovery_retention_capability
    # The admission continuation is bound to the lease created by its fixture.
    continuation_state = persistent_fx.admission_fixtures._registry_state()
    origin = next(
        candidate
        for candidate in continuation_state[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    return inputs, context, lease, recovery, retained


def test_exact_controller_tail_releases_once_and_retains_confirmed_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    successor = cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"])
    persistent = persistent_fx._validate(inputs)
    post_effect_capability = object()
    lifecycle = _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    completed = _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    release_calls: list[object] = []
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)

    def execute(*args: object, **kwargs: object) -> str:
        release_calls.append((args, kwargs))
        return "b" * 64

    monkeypatch.setattr(controller, "_execute_release", execute)
    monkeypatch.setattr(
        controller,
        "_observe_runtime_state",
        lambda *a, **k: ({"status": "sequence_two_ready_observed"}, "c" * 64),
    )
    monkeypatch.setattr(controller, "bind_post_enrollment_start_successor", lambda **_: successor)
    monkeypatch.setattr(
        controller,
        "_fresh_persistent_topology",
        lambda *a, **k: (persistent, "d" * 64),
    )

    receipt = controller.run_post_enrollment_start_active_controller(
        admission=admission,
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        recovery_retention_capability=recovery,
        sequence_two_verifier=sequence_issuer,
        **_paths(inputs),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert receipt.status is outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
    assert receipt.reason is (
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
    )
    assert release_calls and len(release_calls) == 1
    assert sequence_issuer.calls == 2
    assert sequence_issuer.closed == 1
    assert completed == [receipt]
    assert lifecycle.count("transition") == 1
    assert receipt.artifact_path.exists()
    evidence = cast(
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
        receipt._evidence,
    )
    assert evidence.verifier_binding_sha256 == sequence_issuer.verifier_binding_sha256
    assert evidence.read_only_configuration_sha256 == sequence_issuer.read_only_configuration_sha256
    assert evidence.verification_transcript_sha256 == sequence_issuer.verification_transcript_sha256


def test_interruption_before_successor_publication_retains_sequence_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    successor = cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"])
    persistent = persistent_fx._validate(inputs)
    post_effect_capability = object()
    _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)
    monkeypatch.setattr(controller, "_execute_release", lambda *a, **k: "b" * 64)
    monkeypatch.setattr(
        controller,
        "_observe_runtime_state",
        lambda *a, **k: ({"status": "sequence_two_ready_observed"}, "c" * 64),
    )
    monkeypatch.setattr(controller, "bind_post_enrollment_start_successor", lambda **_: successor)
    monkeypatch.setattr(
        controller,
        "_fresh_persistent_topology",
        lambda *a, **k: (persistent, "d" * 64),
    )
    source, first_line = inspect.getsourcelines(
        controller.run_post_enrollment_start_active_controller
    )
    publication_line = first_line + next(
        offset for offset, line in enumerate(source) if "successor = first_successor" in line
    )
    interrupted = False

    def interrupt_before_publication(frame: object, event: str, _arg: object) -> object:
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and getattr(frame, "f_code", None)
            is controller.run_post_enrollment_start_active_controller.__code__
            and getattr(frame, "f_lineno", None) == publication_line
        ):
            interrupted = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_before_publication

    sys.settrace(interrupt_before_publication)
    try:
        with pytest.raises(
            controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
        ) as raised:
            controller.run_post_enrollment_start_active_controller(
                admission=admission,
                topology_issuer=context.topology_issuer,
                choreography_lease=lease,
                recovery_retention_capability=recovery,
                sequence_two_verifier=sequence_issuer,
                **_paths(inputs),
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
    finally:
        sys.settrace(None)

    assert interrupted is True
    assert sequence_issuer.closed == 1
    assert raised.value.retained_outcome.reason is (
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
    )
    evidence = cast(
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
        raised.value.retained_outcome._evidence,
    )
    assert evidence.payload()["sequence_2_confirmed"] is False
    assert evidence.successor is None
    assert evidence.verification_transcript_sha256 is None


def test_controller_consumes_the_real_process_private_sequence_two_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    successor = cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"])
    persistent = persistent_fx._validate(inputs)
    post_effect_capability = object()
    _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    monkeypatch.setattr(
        controller,
        "TrustedTimePostEnrollmentStartSequenceTwoVerifier",
        TrustedTimePostEnrollmentStartSequenceTwoVerifier,
    )
    calls: list[dict[str, object]] = []
    closed: list[str] = []
    origin = object()

    def preparation_validator(**kwargs: object) -> sequence_verifier._PreparationBinding:
        assert kwargs["admission"] is admission
        assert kwargs["topology_issuer"] is context.topology_issuer
        assert kwargs["choreography_lease"] is lease
        assert kwargs["recovery_retention_capability"] is recovery
        return sequence_verifier._PreparationBinding(
            origin_token=origin,
            retained_claim=retained,
            payload={
                "claim_sha256": admission.claim_sha256,
                "operation_id": admission.operation_id,
            },
        )

    def call_validator(**kwargs: object) -> None:
        calls.append(kwargs)

    class Resources:
        def close(self) -> None:
            closed.append("closed")

    def resource_factory(*, owner: object, **_: object) -> Resources:
        resources = Resources()
        cast(Any, owner).register(resources.close)
        return resources

    observed = start_fx._observed_successor_postcondition()

    def verification_runner(resources: object, guard: object) -> object:
        assert type(resources) is Resources
        cast(Any, guard).require_remaining()
        return observed

    prepare = (
        sequence_verifier._build_trusted_time_post_enrollment_start_sequence_two_verifier_preparer(
            preparation_validator=preparation_validator,
            call_validator=call_validator,
            resource_factory=resource_factory,
            verification_runner=verification_runner,
            monotonic_ns=lambda: 20_000_000_001,
        )
    )
    exact_verifier = prepare(
        admission=admission,
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        recovery_retention_capability=recovery,
        action_deadline_monotonic_ns=300_000_000_001,
        database_url=verifier_fx._DATABASE_URL,
        configuration=verifier_fx._configuration(),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)
    monkeypatch.setattr(controller, "_execute_release", lambda *a, **k: "b" * 64)
    monkeypatch.setattr(
        controller,
        "_observe_runtime_state",
        lambda *a, **k: ({"status": "sequence_two_ready_observed"}, "c" * 64),
    )
    monkeypatch.setattr(controller, "bind_post_enrollment_start_successor", lambda **_: successor)
    monkeypatch.setattr(
        controller,
        "_fresh_persistent_topology",
        lambda *a, **k: (persistent, "d" * 64),
    )

    receipt = controller.run_post_enrollment_start_active_controller(
        admission=admission,
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        recovery_retention_capability=recovery,
        sequence_two_verifier=exact_verifier,
        **_paths(inputs),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert receipt.status is outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
    assert len(calls) == 2
    assert all(call["admission"] is admission for call in calls)
    assert all(call["topology_issuer"] is context.topology_issuer for call in calls)
    assert all(call["choreography_lease"] is lease for call in calls)
    assert all(call["recovery_retention_capability"] is recovery for call in calls)
    assert all(call["action_deadline_monotonic_ns"] == 300_000_000_001 for call in calls)
    assert all(call["artifact_directory"] == context.artifact_directory for call in calls)
    assert all(call["ignored_root"] == context.ignored_root for call in calls)
    assert closed == ["closed"]
    assert exact_verifier.verification_transcript_sha256 is not None
    evidence = cast(
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
        receipt._evidence,
    )
    assert evidence.verifier_binding_sha256 == exact_verifier.verifier_binding_sha256
    assert evidence.read_only_configuration_sha256 == exact_verifier.read_only_configuration_sha256
    assert evidence.verification_transcript_sha256 == exact_verifier.verification_transcript_sha256


def test_post_release_sequence_failure_is_not_retried_and_retains_truthful_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    post_effect_capability = object()
    _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    release_calls: list[object] = []
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)

    def release_once(*args: object, **kwargs: object) -> str:
        release_calls.append((args, kwargs))
        return "b" * 64

    monkeypatch.setattr(controller, "_execute_release", release_once)
    monkeypatch.setattr(
        controller,
        "_observe_runtime_state",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("not ready")),
    )

    with pytest.raises(
        controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
    ) as raised:
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert len(release_calls) == 1
    assert raised.value.retained_outcome.reason is (
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
    )
    evidence = cast(
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
        raised.value.retained_outcome._evidence,
    )
    payload = evidence.payload()
    assert payload["release_attempted"] is True
    assert payload["release_confirmed"] is True
    assert payload["sequence_2_confirmed"] is False
    assert payload["retry_authorized"] is False
    assert evidence.verification_transcript_sha256 is None
    assert sequence_issuer.closed == 1


def test_post_effect_transition_is_the_conservative_release_attempt_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    post_effect_capability = object()
    _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    sequence_verifier = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    release_calls: list[object] = []
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_active_post_effect_outcome_retention",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("post-effect checkpoint failed")),
    )
    monkeypatch.setattr(
        controller,
        "_execute_release",
        lambda *a, **k: release_calls.append((a, k)),
    )

    with pytest.raises(
        controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
    ) as raised:
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_verifier,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert release_calls == []
    assert raised.value.retained_outcome.reason is (
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
    )
    evidence = cast(
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
        raised.value.retained_outcome._evidence,
    )
    assert evidence.payload()["release_attempted"] is True
    assert evidence.payload()["release_confirmed"] is False
    assert sequence_verifier.closed == 1


def test_second_sequence_observation_must_match_before_sequence_is_durably_confirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    successor = cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"])
    persistent = persistent_fx._validate(inputs)
    post_effect_capability = object()
    _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)
    monkeypatch.setattr(controller, "_execute_release", lambda *a, **k: "b" * 64)
    monkeypatch.setattr(
        controller,
        "_observe_runtime_state",
        lambda *a, **k: ({"status": "sequence_two_ready_observed"}, "c" * 64),
    )
    bound: list[object] = []

    def bind(**_: object) -> object:
        bound.append(object())
        return successor if len(bound) == 1 else object()

    monkeypatch.setattr(controller, "bind_post_enrollment_start_successor", bind)
    monkeypatch.setattr(
        controller,
        "_fresh_persistent_topology",
        lambda *a, **k: (persistent, "d" * 64),
    )

    with pytest.raises(
        controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
    ) as raised:
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert sequence_issuer.calls == 2
    assert sequence_issuer.closed == 1
    assert raised.value.retained_outcome.reason is (
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
    )
    evidence = cast(
        outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
        raised.value.retained_outcome._evidence,
    )
    assert evidence.payload()["sequence_2_confirmed"] is False
    assert evidence.payload()["topology_qualified"] is False


def test_failure_is_not_returned_after_its_final_durable_handoff_revalidation_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    post_effect_capability = object()
    _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    _install_outcome_retention(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)
    monkeypatch.setattr(controller, "_execute_release", lambda *a, **k: "b" * 64)
    monkeypatch.setattr(
        controller,
        "_observe_runtime_state",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("not ready")),
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_return_confirmed_post_effect_controller_failure",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("receipt changed")),
    )

    with pytest.raises(outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed):
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )


def test_pre_effect_failure_uses_only_the_old_pre_release_recovery_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    post_effect_capability = object()
    lifecycle = _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=post_effect_capability,
    )
    recovery_calls: list[dict[str, object]] = []
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    monkeypatch.setattr(
        controller,
        "_fresh_pre_effect_observation",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("drift")),
    )

    def retain_recovery(**kwargs: object) -> None:
        recovery_calls.append(kwargs)
        raise _PreReleaseRetained

    monkeypatch.setattr(
        controller,
        "retain_post_enrollment_start_recovery_required_outcome",
        retain_recovery,
    )
    monkeypatch.setattr(
        controller,
        "_execute_release",
        lambda *a, **k: pytest.fail("release must not run"),
    )

    with pytest.raises(_PreReleaseRetained):
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert len(recovery_calls) == 1
    assert "transition" not in lifecycle
    assert sequence_issuer.closed == 1


def test_duck_sequence_two_verifier_is_rejected_before_release(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, _ = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    duck = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    recovery_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        controller,
        "TrustedTimePostEnrollmentStartSequenceTwoVerifier",
        TrustedTimePostEnrollmentStartSequenceTwoVerifier,
    )

    def retain_recovery(**kwargs: object) -> None:
        recovery_calls.append(kwargs)
        raise _PreReleaseRetained

    monkeypatch.setattr(
        controller,
        "retain_post_enrollment_start_recovery_required_outcome",
        retain_recovery,
    )
    monkeypatch.setattr(
        controller,
        "_execute_release",
        lambda *args, **kwargs: pytest.fail("release must not run"),
    )

    with pytest.raises(_PreReleaseRetained):
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=cast(Any, duck),
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert len(recovery_calls) == 1
    assert duck.closed == 0


def test_release_is_rejected_when_less_than_the_full_completion_budget_remains(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, retained = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    lifecycle = _install_controller_lifecycle(
        monkeypatch,
        context=context,
        retained=retained,
        post_effect_capability=object(),
        observed_monotonic_ns=40_000_000_002,
    )
    recovery_calls: list[dict[str, object]] = []
    monkeypatch.setattr(controller, "_fresh_pre_effect_observation", lambda *a, **k: "a" * 64)

    def retain_recovery(**kwargs: object) -> None:
        recovery_calls.append(kwargs)
        raise _PreReleaseRetained

    monkeypatch.setattr(
        controller,
        "retain_post_enrollment_start_recovery_required_outcome",
        retain_recovery,
    )
    monkeypatch.setattr(
        controller,
        "_execute_release",
        lambda *args, **kwargs: pytest.fail("release must not run"),
    )

    with pytest.raises(_PreReleaseRetained):
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert len(recovery_calls) == 1
    assert "issue_post_effect_candidate" not in lifecycle
    assert "transition" not in lifecycle
    assert sequence_issuer.closed == 1


def test_wrong_issuer_consumes_the_exact_continuation_and_poisons_its_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context, lease, recovery, _ = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    poisoned = persistent_fx.admission_fixtures._install_poison_tracker(
        monkeypatch,
        context,
    )
    sequence_issuer = _SequenceTwoVerifier(start_fx._observed_successor_postcondition())
    release_calls: list[object] = []
    monkeypatch.setattr(
        controller,
        "_execute_release",
        lambda *args, **kwargs: release_calls.append((args, kwargs)),
    )

    with pytest.raises(controller.TrustedTimePostEnrollmentStartActiveControllerRejected):
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=cast(Any, object()),
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert poisoned == [context.topology_issuer]
    assert release_calls == []
    with pytest.raises(controller.TrustedTimePostEnrollmentStartActiveControllerRejected):
        controller.run_post_enrollment_start_active_controller(
            admission=admission,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            sequence_two_verifier=sequence_issuer,
            **_paths(inputs),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert release_calls == []


def test_current_scope_adoption_never_swallows_an_async_query_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    topology_issuer = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)

    def interrupt_query(*_: object, **__: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_adopt_registered_confirmed_terminal_outcome",
        interrupt_query,
    )

    with pytest.raises(KeyboardInterrupt):
        controller._adopt_current_scope_terminal_controller_outcome(
            topology_issuer,
            object(),
            object(),
            artifact_directory=tmp_path / "trusted-time",
            ignored_root=tmp_path,
        )


def test_pre_effect_probe_requires_all_six_runtime_names_absent() -> None:
    compile(controller._PRE_EFFECT_RUNTIME_ABSENCE_PROBE_SOURCE, "<pre-effect>", "exec")
    compile(controller._PERSISTENT_BARRIER_PROBE_SOURCE, "<persistent>", "exec")

    class Issuer:
        _docker_executable_path = Path("/usr/bin/docker")

        def _run_json(self, _receipts: object, **kwargs: object) -> dict[str, object]:
            assert kwargs["label"] == "pre_effect_runtime_absences"
            argv = cast(tuple[str, ...], kwargs["argv"])
            assert argv[-1] == controller._PRE_EFFECT_RUNTIME_ABSENCE_PROBE_SOURCE
            return {
                "absences": [
                    {"path": path, "status": "absent"}
                    for path in controller._PRE_EFFECT_RUNTIME_PATHS
                ],
                "contract_version": (controller._PRE_EFFECT_RUNTIME_ABSENCE_PROBE_CONTRACT_VERSION),
            }

    observed = controller._observe_pre_effect_runtime_absences(
        cast(Any, Issuer()),
        [],
        supervisor_container_id="b" * 64,
    )

    assert tuple(candidate.path for candidate in observed) == controller._PRE_EFFECT_RUNTIME_PATHS
    assert len(set(controller._PRE_EFFECT_RUNTIME_PATHS)) == 6


def test_runtime_state_binds_the_dynamic_deadline_marker_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload: dict[str, object] = {
        field_name: False for field_name in controller._RUNTIME_STATE_CLOSED_FIELDS
    }
    payload.update(
        {
            "contract_version": controller.POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION,
            "release_marker_sha256": controller.POST_ENROLLMENT_START_RELEASE_SHA256,
            "sequence_two_deadline_marker_sha256": "d" * 64,
            "sequence_two_ready_marker_sha256": (
                controller.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256
            ),
            "service": "trusted-time-supervisor",
            "status": controller.POST_ENROLLMENT_RUNTIME_STATE_STATUS,
        }
    )
    monkeypatch.setattr(
        controller,
        "_run_exact_control",
        lambda *args, **kwargs: (
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            + b"\n"
        ),
    )
    issuer = SimpleNamespace(_docker_executable_path=Path("/usr/bin/docker"))
    checkpoint = SimpleNamespace(
        deadline_monotonic_ns=200_000_000_000,
        observed_monotonic_ns=1,
    )

    observed, observed_sha256 = controller._observe_runtime_state(
        cast(Any, issuer),
        "b" * 64,
        checkpoint,
    )

    assert observed == payload
    assert observed_sha256 == controller._canonical_sha256(payload)
    payload["sequence_two_deadline_marker_sha256"] = "not-a-digest"
    with pytest.raises(ValueError):
        controller._observe_runtime_state(cast(Any, issuer), "b" * 64, checkpoint)


def test_persistent_barrier_binds_deadline_release_ready_chronology_and_staging_absence() -> None:
    deadline_sha256 = "d" * 64
    deadline = _runtime_marker(
        path=controller.POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
        byte_sha256=deadline_sha256,
        size=200,
        inode=7,
        modified_time_ns=7,
        changed_time_ns=8,
    )
    release = persistent_fx._release_marker(
        inode=8,
        modified_time_ns=9,
        changed_time_ns=10,
    )
    ready = _runtime_marker(
        path=controller.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
        byte_sha256=controller.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256,
        size=len(controller.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES),
        inode=9,
        modified_time_ns=11,
        changed_time_ns=12,
    )
    database_candidate = persistent_fx.staged_fixtures._marker_candidate()
    database = {
        key: value for key, value in database_candidate.payload().items() if key != "status"
    }
    release_payload = {key: value for key, value in release.payload().items() if key != "status"}

    class Issuer:
        _docker_executable_path = Path("/usr/bin/docker")

        def _run_json(self, _receipts: object, **kwargs: object) -> dict[str, object]:
            assert kwargs["label"] == "persistent_barrier"
            return {
                "contract_version": controller._PERSISTENT_BARRIER_PROBE_CONTRACT_VERSION,
                "database_marker": database,
                "deadline_marker": deadline,
                "release_marker": release_payload,
                "runtime_staging_absences": [
                    {"path": path, "status": "absent"}
                    for path in controller._POST_EFFECT_RUNTIME_STAGING_PATHS
                ],
                "sequence_marker": ready,
            }

    observed = controller._observe_persistent_barrier(
        cast(Any, Issuer()),
        [],
        supervisor_container_id="b" * 64,
        expected_deadline_marker_sha256=deadline_sha256,
    )

    assert observed[1] == deadline
    assert observed[2] == release
    assert observed[3] == ready
    assert tuple(candidate.path for candidate in observed[4]) == (
        controller._POST_EFFECT_RUNTIME_STAGING_PATHS
    )
    drifted_ready = dict(ready, modified_time_ns=8)
    with pytest.raises(ValueError):
        controller._require_runtime_marker_chronology(
            deadline=deadline,
            release=release,
            sequence=drifted_ready,
        )


def test_final_persistent_barrier_rejects_marker_drift_after_prior_barrier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _context, lease, _, _ = _prepared(monkeypatch, tmp_path)
    admission = cast(Any, inputs["admission"])
    final = admission._action_fence._final_action_observation
    successor = cast(TrustedTimePostEnrollmentStartSuccessor, inputs["successor"])
    staged_paths = tuple(_paths(inputs).values())
    events: list[str] = []

    def add_receipts(receipts: list[object], label: str, count: int) -> None:
        events.append(label)
        receipts.extend(object() for _ in range(count))

    class Issuer:
        def _begin_observation(self, exact_lease: object) -> None:
            assert exact_lease is lease
            events.append("begin")

        def _observe_daemon(self, receipts: list[object]) -> object:
            add_receipts(receipts, "daemon", 1)
            return object()

        def _observe_volumes(self, receipts: list[object]) -> object:
            add_receipts(receipts, "volumes", 2)
            return object()

        def _observe_inventory(self, receipts: list[object]) -> object:
            add_receipts(receipts, "inventory", 1)
            return object()

        def _observe_image_configurations(
            self,
            receipts: list[object],
            **_: object,
        ) -> tuple[object, object]:
            add_receipts(receipts, "images", 2)
            return object(), object()

        def _observe_containers(self, receipts: list[object], **_: object) -> object:
            add_receipts(receipts, "containers", 2)
            return object()

        def _fail_observation(self) -> None:
            events.append("fail")

        def _finish_observation(self) -> None:
            events.append("finish")

    def observe_network(
        _issuer: object,
        receipts: list[object],
        **_: object,
    ) -> tuple[object, SimpleNamespace]:
        add_receipts(receipts, "network", 1)
        return object(), SimpleNamespace(network_id="network", identity_sha256="1" * 64)

    retirement = SimpleNamespace(root_identity=(1, 2, 3, 4, 5, 6), candidates=())
    barrier_calls = 0
    database = object()
    deadline = object()
    release = object()
    stable_sequence = object()
    drifted_sequence = object()
    absences = (object(),)

    def observe_barrier(
        _issuer: object,
        receipts: list[object],
        **_: object,
    ) -> tuple[object, object, object, object, tuple[object, ...]]:
        nonlocal barrier_calls
        barrier_calls += 1
        add_receipts(receipts, f"barrier-{barrier_calls}", 1)
        return (
            database,
            deadline,
            release,
            stable_sequence if barrier_calls < 3 else drifted_sequence,
            absences,
        )

    monkeypatch.setattr(controller, "_observe_network_raw", observe_network)
    monkeypatch.setattr(controller, "_observe_host_retirements", lambda _: retirement)
    monkeypatch.setattr(controller, "_observe_persistent_barrier", observe_barrier)

    with pytest.raises(ValueError):
        controller._fresh_persistent_topology(
            cast(Any, Issuer()),
            lease,
            admission=admission,
            final=final,
            successor=successor,
            runtime_state={"sequence_two_deadline_marker_sha256": "d" * 64},
            approved_launch=cast(Any, inputs["approved_launch"]),
            staged_paths=cast(Any, staged_paths),
        )

    assert barrier_calls == 3
    assert events[events.index("barrier-3") - 1] == "daemon"
    assert events[-3:] == ["barrier-3", "fail", "finish"]


def test_controller_has_no_supported_runtime_or_trading_surface() -> None:
    source = Path(cast(str, controller.__file__)).read_text(encoding="utf-8")
    module = ast.parse(source)
    assert not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "main"
        for node in module.body
    )
    assert "if __name__" not in source
    assert "alpaca" not in source.lower()
    assert "etrade" not in source.lower()
    assert "run_post_enrollment_start_active_controller" in controller.__all__
