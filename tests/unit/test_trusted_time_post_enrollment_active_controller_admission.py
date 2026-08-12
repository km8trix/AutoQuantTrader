from __future__ import annotations

import inspect
import json
import os
import pickle
import sys
import threading
from copy import copy, deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, Never, cast

import pytest

import apps.trusted_time_supervisor.post_enrollment_release as release
import apps.trusted_time_supervisor.post_enrollment_start as successor
import scripts.start_trusted_time_supervisor as launcher
import scripts.trusted_time_post_enrollment_action_topology_fence as action_fence_module
import scripts.trusted_time_post_enrollment_active_controller_admission as admission
import scripts.trusted_time_post_enrollment_outcome as outcome
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
)
from scripts.trusted_time_post_enrollment_action_topology_fence import (
    TrustedTimePostEnrollmentStartClaimedActionTopologyFence,
)
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from tests.unit import test_trusted_time_post_enrollment_action_topology_fence as action_fixtures
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fixtures


class _AsyncInterruption(BaseException):
    pass


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fixtures._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )


def _action_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    claimed_fixtures._Context,
    object,
    object,
    TrustedTimePostEnrollmentStartClaimedActionTopologyFence,
]:
    context, lease, claimed = action_fixtures._claimed_context(monkeypatch, tmp_path)
    final = action_fixtures._final_observation(context, claimed)
    action_fixtures._install_final_issuer(monkeypatch, context, lease, claimed, final)
    action_fence = (
        action_fence_module.prepare_post_enrollment_start_leased_claimed_action_topology_fence(
            **action_fixtures._action_kwargs(context, lease, claimed)
        )
    )
    context.events.clear()
    return (
        context,
        lease,
        cast(Any, context).action_recovery_retention_capability,
        action_fence,
    )


def _admission_kwargs(
    context: claimed_fixtures._Context,
    lease: object,
    recovery_retention_capability: object,
    action_fence: TrustedTimePostEnrollmentStartClaimedActionTopologyFence,
) -> dict[str, object]:
    return {
        "action_fence": action_fence,
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery_retention_capability,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }


def _install_poison_tracker(
    monkeypatch: pytest.MonkeyPatch,
    context: claimed_fixtures._Context,
) -> list[object]:
    issuer = context.topology_issuer
    issuer._owner_pid = os.getpid()
    issuer._lifecycle_lock = threading.RLock()
    issuer._poisoned = False
    issuer._closed = False
    poisoned: list[object] = []

    def poison(candidate: object) -> None:
        poisoned.append(candidate)
        candidate._poisoned = True  # type: ignore[attr-defined]

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        poison,
    )
    return poisoned


def _registry_state() -> tuple[dict[object, object], dict[object, object], dict[object, object]]:
    prepare = admission.prepare_post_enrollment_start_active_controller_admission
    unregister = cast(Any, inspect.getclosurevars(prepare).nonlocals["unregister"])
    state = inspect.getclosurevars(unregister).nonlocals
    return (
        cast(dict[object, object], state["result_capabilities"]),
        cast(dict[object, object], state["continuations"]),
        cast(dict[object, object], state["consumed_origins"]),
    )


def test_admits_exact_action_origin_and_reserves_only_one_private_continuation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)

    def revalidate(
        candidate: RetainedTrustedTimePostEnrollmentStartClaim,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        context.events.append("revalidate_claim")
        return revalidate_retained_post_enrollment_start_claim(
            candidate,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.setattr(admission, "revalidate_retained_post_enrollment_start_claim", revalidate)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )

    assert result.status == admission.POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS
    assert result.operation_id == action_fence.operation_id
    assert result.claimed_action_fence_sha256 == action_fence.fence_sha256
    assert result.final_action_observation_sha256 == action_fence.final_action_observation_sha256
    assert result.final_action_snapshot_sha256 == action_fence.final_action_snapshot_sha256
    assert (
        result.final_action_stable_topology_sha256
        == action_fence.final_action_stable_topology_sha256
    )
    assert context.events == [
        "require_armed_recovery",
        "checkpoint_lease",
        "revalidate_claim",
        "require_armed_recovery",
        "checkpoint_lease",
        "revalidate_claim",
        "require_armed_recovery",
        "checkpoint_lease",
        "require_armed_recovery",
        "checkpoint_lease",
    ]
    assert result.action_topology_fence_authenticated is True
    assert result.controller_origin_authenticated is True
    assert result.retained_claim_revalidated is True


def test_continuation_is_exact_one_shot_and_replay_poisons_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    arguments = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }

    assert admission._consume_active_controller_continuation(result, **arguments) is True
    assert admission._consume_active_controller_continuation(result, **arguments) is False
    assert poisoned == [context.topology_issuer]


@pytest.mark.parametrize(
    "changed",
    ["issuer", "lease", "recovery", "artifact_directory", "ignored_root"],
)
def test_wrong_action_origin_is_consumed_and_recovery_required(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changed: str,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    kwargs = _admission_kwargs(context, lease, recovery, action_fence)
    if changed == "issuer":
        wrong = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
        wrong._owner_pid = os.getpid()
        wrong._lifecycle_lock = threading.RLock()
        wrong._poisoned = False
        wrong._closed = False
        kwargs["topology_issuer"] = wrong
    elif changed in {"lease", "recovery"}:
        kwargs["choreography_lease" if changed == "lease" else "recovery_retention_capability"] = (
            object()
        )
    elif changed == "artifact_directory":
        kwargs["artifact_directory"] = context.artifact_directory / "other"
    else:
        kwargs["ignored_root"] = context.ignored_root.parent

    with pytest.raises(
        admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired
    ):
        admission.prepare_post_enrollment_start_active_controller_admission(**kwargs)

    assert context.events == []
    assert context.topology_issuer in poisoned


def test_action_fence_replay_cannot_reserve_a_second_continuation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    kwargs = _admission_kwargs(context, lease, recovery, action_fence)
    admission.prepare_post_enrollment_start_active_controller_admission(**kwargs)

    with pytest.raises(
        admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired
    ):
        admission.prepare_post_enrollment_start_active_controller_admission(**kwargs)

    assert poisoned
    assert all(candidate is context.topology_issuer for candidate in poisoned)


def test_cross_thread_continuation_theft_consumes_and_poisons(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    arguments = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }
    consumed: list[bool] = []
    worker = threading.Thread(
        target=lambda: consumed.append(
            admission._consume_active_controller_continuation(result, **arguments)
        )
    )
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert consumed == [False]
    assert admission._consume_active_controller_continuation(result, **arguments) is False
    assert poisoned == [context.topology_issuer, context.topology_issuer]


@pytest.mark.parametrize(
    "changed",
    ["issuer", "lease", "recovery", "artifact_directory", "ignored_root"],
)
def test_continuation_tuple_substitution_consumes_and_poisons(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changed: str,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    arguments: dict[str, object] = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }
    if changed == "issuer":
        wrong = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
        wrong._owner_pid = os.getpid()
        wrong._lifecycle_lock = threading.RLock()
        wrong._poisoned = False
        wrong._closed = False
        arguments["topology_issuer"] = wrong
    elif changed in {"lease", "recovery"}:
        arguments[
            "choreography_lease" if changed == "lease" else "recovery_retention_capability"
        ] = object()
    elif changed == "artifact_directory":
        arguments["artifact_directory"] = context.artifact_directory / "other"
    else:
        arguments["ignored_root"] = context.ignored_root.parent

    assert admission._consume_active_controller_continuation(result, **arguments) is False
    assert (
        admission._consume_active_controller_continuation(
            result,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
        is False
    )
    assert poisoned == [context.topology_issuer, context.topology_issuer]


def test_post_registration_baseexception_revokes_every_admission_registry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    _install_poison_tracker(monkeypatch, context)
    registrations, continuations, tombstones = _registry_state()
    baseline = (set(registrations), set(continuations), set(tombstones))
    checkpoints = 0
    original_checkpoint = (
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer._require_active_choreography_lease
    )

    def interrupt_after_transfer(
        candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        candidate_lease: object,
    ) -> object:
        nonlocal checkpoints
        checkpoints += 1
        if checkpoints == 4:
            raise _AsyncInterruption
        return original_checkpoint(candidate, candidate_lease)

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_active_choreography_lease",
        interrupt_after_transfer,
    )
    with pytest.raises(
        admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired
    ):
        admission.prepare_post_enrollment_start_active_controller_admission(
            **_admission_kwargs(context, lease, recovery, action_fence)
        )

    assert (set(registrations), set(continuations), set(tombstones)) == baseline


def test_postconstruction_claim_drift_revokes_continuation_and_requires_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    validations = iter([True, False])
    monkeypatch.setattr(
        admission,
        "revalidate_retained_post_enrollment_start_claim",
        lambda *_args, **_kwargs: next(validations),
    )
    registrations, continuations, tombstones = _registry_state()
    baseline = (set(registrations), set(continuations), set(tombstones))

    with pytest.raises(
        admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired
    ):
        admission.prepare_post_enrollment_start_active_controller_admission(
            **_admission_kwargs(context, lease, recovery, action_fence)
        )

    assert poisoned == [context.topology_issuer]
    assert (set(registrations), set(continuations), set(tombstones)) == baseline


def test_continuation_checkpoint_baseexception_consumes_and_poisons(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    arguments = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_require_armed_recovery_outcome_retention",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(_AsyncInterruption()),
    )

    with pytest.raises(_AsyncInterruption):
        admission._consume_active_controller_continuation(result, **arguments)
    assert admission._consume_active_controller_continuation(result, **arguments) is False
    assert poisoned == [context.topology_issuer, context.topology_issuer]


def test_line_interruption_after_continuation_pop_recovers_and_poisons_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    arguments = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }
    _, continuations, tombstones = _registry_state()
    capability = result._capability
    source, first_line = inspect.getsourcelines(admission._consume_active_controller_continuation)
    interruption_line = first_line + next(
        index
        for index, line in enumerate(source)
        if "consumed_origin = consumed_origins.get(capability)" in line
    )

    def interrupt_after_pop(frame: Any, event: str, _argument: object) -> Any:
        if (
            event == "line"
            and frame.f_code is admission._consume_active_controller_continuation.__code__
            and frame.f_lineno == interruption_line
        ):
            raise _AsyncInterruption
        return interrupt_after_pop

    assert capability in continuations
    previous_trace = sys.gettrace()
    sys.settrace(interrupt_after_pop)
    try:
        with pytest.raises(_AsyncInterruption):
            admission._consume_active_controller_continuation(result, **arguments)
    finally:
        sys.settrace(previous_trace)

    assert capability not in continuations
    assert capability in tombstones
    assert poisoned == [context.topology_issuer]
    assert admission._consume_active_controller_continuation(result, **arguments) is False
    assert poisoned == [context.topology_issuer, context.topology_issuer]


def test_line_interruption_before_continuation_pop_revokes_and_poisons_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    arguments = {
        "topology_issuer": context.topology_issuer,
        "choreography_lease": lease,
        "recovery_retention_capability": recovery,
        "artifact_directory": context.artifact_directory,
        "ignored_root": context.ignored_root,
    }
    _, continuations, tombstones = _registry_state()
    capability = result._capability
    source, first_line = inspect.getsourcelines(admission._consume_active_controller_continuation)
    interruption_line = first_line + next(
        index
        for index, line in enumerate(source)
        if "origin = continuations.pop(capability, None)" in line
    )

    def interrupt_before_pop(frame: Any, event: str, _argument: object) -> Any:
        if (
            event == "line"
            and frame.f_code is admission._consume_active_controller_continuation.__code__
            and frame.f_lineno == interruption_line
        ):
            raise _AsyncInterruption
        return interrupt_before_pop

    assert capability in continuations
    previous_trace = sys.gettrace()
    sys.settrace(interrupt_before_pop)
    try:
        with pytest.raises(_AsyncInterruption):
            admission._consume_active_controller_continuation(result, **arguments)
    finally:
        sys.settrace(previous_trace)

    assert capability not in continuations
    assert capability in tombstones
    assert poisoned == [context.topology_issuer]
    assert admission._consume_active_controller_continuation(result, **arguments) is False
    assert poisoned == [context.topology_issuer, context.topology_issuer]


def test_result_is_process_sealed_noncopyable_nonserializable_and_unforgeable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )

    for operation in (
        lambda: copy(result),
        lambda: deepcopy(result),
        lambda: pickle.dumps(result),
        lambda: replace(result),
    ):
        with pytest.raises(
            admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected
        ):
            operation()
    forged_capability = object.__new__(admission._ActiveControllerAdmissionCapability)
    with pytest.raises(admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected):
        admission.TrustedTimePostEnrollmentStartActiveControllerAdmission(
            operation_id=action_fence.operation_id,
            approval_sha256=action_fence.approval_sha256,
            session_sha256=action_fence.session_sha256,
            claim_sha256=action_fence.claim_sha256,
            retained_claim_artifact_sha256=action_fence.retained_claim_artifact_sha256,
            claimed_action_fence_sha256=action_fence.fence_sha256,
            final_action_observation_sha256=action_fence.final_action_observation_sha256,
            final_action_snapshot_sha256=action_fence.final_action_snapshot_sha256,
            final_action_stable_topology_sha256=(action_fence.final_action_stable_topology_sha256),
            _action_fence=action_fence,
            _capability=forged_capability,
        )
    forged_result = object.__new__(
        admission.TrustedTimePostEnrollmentStartActiveControllerAdmission
    )
    assert (
        admission._consume_active_controller_continuation(
            forged_result,
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            recovery_retention_capability=recovery,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
        is False
    )
    owner_pid = os.getpid()
    with monkeypatch.context() as forked:
        forked.setattr(os, "getpid", lambda: owner_pid + 1)
        with pytest.raises(
            admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected
        ):
            result.__post_init__()


def test_admission_performs_no_release_runtime_sequence2_success_or_write_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    effects: list[str] = []

    def forbidden(name: str) -> Any:
        def fail(*_args: object, **_kwargs: object) -> Never:
            effects.append(name)
            raise AssertionError(f"forbidden effect: {name}")

        return fail

    monkeypatch.setattr(launcher, "_run_docker", forbidden("docker"))
    monkeypatch.setattr(release, "write_post_enrollment_start_release", forbidden("release"))
    monkeypatch.setattr(
        successor,
        "bind_post_enrollment_start_successor",
        forbidden("sequence_2"),
    )
    monkeypatch.setattr(
        outcome,
        "retain_post_enrollment_start_recovery_required_outcome",
        forbidden("outcome"),
    )
    monkeypatch.setattr(os, "write", forbidden("file_write"))
    monkeypatch.setattr(os, "link", forbidden("file_link"))
    monkeypatch.setattr(os, "unlink", forbidden("file_unlink"))
    monkeypatch.setattr(os, "replace", forbidden("file_replace"))

    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )

    assert result.status == admission.POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS
    assert effects == []


def test_payload_and_surface_are_secret_free_and_all_effect_authority_is_false(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    result = admission.prepare_post_enrollment_start_active_controller_admission(
        **_admission_kwargs(context, lease, recovery, action_fence)
    )
    payload = result.payload()
    encoded = json.dumps(payload, sort_keys=True)
    false_fields = set(FIRST_ENROLLMENT_AUTHORITY_FIELDS) | set(admission._CLOSED_ADMISSION_FIELDS)

    assert all(payload[field_name] is False for field_name in false_fields)
    assert all(getattr(result, field_name) is False for field_name in false_fields)
    assert str(context.artifact_directory) not in encoded
    assert "choreography_lease" not in encoded
    assert "recovery_retention_capability" not in encoded
    assert not hasattr(result, "choreography_lease")
    assert not hasattr(result, "recovery_retention_capability")
    assert not callable(result)
    assert set(admission.__all__) == {
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS",
        "TrustedTimePostEnrollmentStartActiveControllerAdmission",
        "TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired",
        "TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected",
        "prepare_post_enrollment_start_active_controller_admission",
    }
    for name in (
        "main",
        "run",
        "start",
        "release",
        "publish",
        "sequence_2",
        "retain_success",
        "qualify_topology",
    ):
        assert not hasattr(admission, name)


def test_nonexact_action_candidate_is_rejected_without_poison_or_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, recovery, action_fence = _action_context(monkeypatch, tmp_path)
    poisoned = _install_poison_tracker(monkeypatch, context)
    kwargs = _admission_kwargs(context, lease, recovery, action_fence)
    kwargs["action_fence"] = object()

    with pytest.raises(admission.TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected):
        admission.prepare_post_enrollment_start_active_controller_admission(**kwargs)

    assert poisoned == []
    assert context.events == []
