from __future__ import annotations

import ctypes
import inspect
import os
import pickle
import sys
import threading
from collections.abc import Callable
from copy import copy, deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Never, cast

import pytest

import scripts.trusted_time_post_enrollment_claimed_fence as claimed_fence
import scripts.trusted_time_post_enrollment_controller_outcome as controller_outcome
import scripts.trusted_time_post_enrollment_staging as staging
import scripts.trusted_time_post_enrollment_topology_reader as reader
from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from scripts import trusted_time_post_enrollment_outcome as recovery_outcome
from scripts.start_trusted_time_supervisor import (
    _acquire_trusted_time_launch_lock,
    _release_trusted_time_launch_lock,
)
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
    retain_post_enrollment_start_claim,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fixtures
from tests.unit import test_trusted_time_post_enrollment_staging as claim_fixtures
from tests.unit import test_trusted_time_post_enrollment_topology_reader as fixtures


class _MonotonicClock:
    def __init__(self, values: list[int]) -> None:
        self._remaining = list(values)
        self.calls: list[int] = []
        self.call_count = 0

    def __call__(self) -> int:
        self.call_count += 1
        if not self._remaining:
            raise AssertionError("unexpected monotonic clock sample")
        value = self._remaining.pop(0)
        self.calls.append(value)
        return value

    @property
    def remaining(self) -> list[int]:
        return list(self._remaining)


def _fake_darwin_clock_library(
    *,
    ticks: int = 10,
    numerator: int = 3,
    denominator: int = 2,
) -> tuple[SimpleNamespace, list[str]]:
    calls: list[str] = []

    def mach_continuous_time() -> int:
        calls.append("continuous")
        return ticks

    def mach_timebase_info(pointer: object) -> int:
        calls.append("timebase")
        timebase = ctypes.cast(
            pointer,
            ctypes.POINTER(reader._DarwinMachTimebaseInfo),
        ).contents
        timebase.numer = numerator
        timebase.denom = denominator
        return 0

    return (
        SimpleNamespace(
            mach_continuous_time=mach_continuous_time,
            mach_timebase_info=mach_timebase_info,
        ),
        calls,
    )


def test_linux_suspend_aware_clock_captures_one_exact_native_callable_and_id() -> None:
    calls: list[int] = []

    def clock_gettime_ns(clock_id: int) -> int:
        calls.append(clock_id)
        return 41 + len(calls)

    clock = reader._build_suspend_aware_monotonic_clock(
        platform_name="linux",
        clock_gettime_ns=clock_gettime_ns,
        clock_boottime=7,
        darwin_library_loader=lambda _: (_ for _ in ()).throw(AssertionError),
    )

    assert clock() == 42
    assert clock() == 43
    assert calls == [7, 7]


def test_darwin_suspend_aware_clock_captures_timebase_once() -> None:
    library, native_calls = _fake_darwin_clock_library()
    loader_calls: list[object] = []

    def load_library(name: object) -> SimpleNamespace:
        loader_calls.append(name)
        return library

    clock = reader._build_suspend_aware_monotonic_clock(
        platform_name="darwin",
        clock_gettime_ns=None,
        clock_boottime=None,
        darwin_library_loader=load_library,
    )

    assert clock() == 15
    assert clock() == 15
    assert loader_calls == [None]
    assert native_calls == ["timebase", "continuous", "continuous"]


@pytest.mark.parametrize(("numerator", "denominator"), [(0, 1), (1, 0)])
def test_darwin_suspend_aware_clock_rejects_invalid_timebase(
    numerator: int,
    denominator: int,
) -> None:
    library, native_calls = _fake_darwin_clock_library(
        numerator=numerator,
        denominator=denominator,
    )
    clock = reader._build_suspend_aware_monotonic_clock(
        platform_name="darwin",
        clock_gettime_ns=None,
        clock_boottime=None,
        darwin_library_loader=lambda _: library,
    )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        clock()

    assert native_calls == ["timebase"]


def test_unsupported_suspend_aware_clock_fails_closed() -> None:
    clock = reader._build_suspend_aware_monotonic_clock(
        platform_name="unsupported",
        clock_gettime_ns=None,
        clock_boottime=None,
        darwin_library_loader=None,
    )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        clock()


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin production clock only")
def test_darwin_production_suspend_aware_clock_is_available_and_monotonic() -> None:
    first = reader._suspend_aware_monotonic_ns()
    second = reader._suspend_aware_monotonic_ns()

    assert 0 <= first <= second


def _install_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
    clock: _MonotonicClock,
) -> None:
    open_with_dependencies = cast(
        Any,
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer._open_with_dependencies,
    )
    defaults = open_with_dependencies.__func__.__kwdefaults__
    assert defaults is not None
    monkeypatch.setitem(defaults, "monotonic_ns", clock)


def _open_issuer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    outputs: list[bytes | BaseException] | None = None,
    monotonic_clock: _MonotonicClock | None = None,
) -> tuple[
    reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    fixtures._QueuedRunner,
]:
    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    queued = fixtures._QueuedRunner([fixtures._json_line("LOCAL:DAEMON:1"), *(outputs or [])])
    if monotonic_clock is not None:
        _install_monotonic_clock(monkeypatch, monotonic_clock)
    issuer = fixtures._public_open(
        monkeypatch,
        tmp_path,
        queued,
        socket_path,
        executable,
    )
    return issuer, queued


def test_issuer_exposes_only_the_exact_clock_sealed_at_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = _MonotonicClock([])
    issuer, _ = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    try:
        assert issuer._bound_choreography_monotonic_clock() is clock
    finally:
        _close_and_assert_launch_lock_is_reacquirable(issuer)


def _seed_cursor_state(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> None:
    issuer._issued_created_observation_sha256 = "3" * 64
    issuer._last_observation_sha256 = "4" * 64
    issuer._first_staged_snapshot_sha256 = "5" * 64
    issuer._staged_observation_count = 1


def _assert_launch_lock_is_held(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> None:
    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="another trusted-time launcher is active",
    ):
        _acquire_trusted_time_launch_lock(
            path=issuer._lock_path,
            ignored_root=issuer._ignored_root,
        )


def _close_and_assert_launch_lock_is_reacquirable(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> None:
    issuer.close()
    descriptor = _acquire_trusted_time_launch_lock(
        path=issuer._lock_path,
        ignored_root=issuer._ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)


def _retain_claim_for_issuer(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> tuple[RetainedTrustedTimePostEnrollmentStartClaim, Path, Path]:
    ignored_root = issuer._ignored_root
    artifact_directory = ignored_root / "trusted-time"
    retained = retain_post_enrollment_start_claim(
        claim_fixtures._claim(),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    return retained, artifact_directory, ignored_root


def _issue_registered_recovery_claim_binder(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    lease: object,
    capability: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> reader._TrustedTimePostEnrollmentRecoveryClaimBinder:
    closure = inspect.getclosurevars(
        claimed_fence.prepare_post_enrollment_start_claimed_pre_release_fence
    )
    issue = cast(
        Callable[..., reader._TrustedTimePostEnrollmentRecoveryClaimBinder],
        closure.nonlocals["issue_recovery_binder"],
    )
    return issue(
        topology_issuer=issuer,
        choreography_lease=lease,
        recovery_retention_capability=capability,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def _bind_registered_recovery_claim(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    lease: object,
    capability: object,
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> reader._TrustedTimePostEnrollmentRecoveryClaimBinder:
    binder = _issue_registered_recovery_claim_binder(
        issuer,
        lease,
        capability,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    binder._checkpoint(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    binder(retained)
    return binder


def _persist_recovery_outcome(
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> recovery_outcome.RetainedTrustedTimePostEnrollmentStartOutcome:
    return recovery_outcome._persist_outcome(
        retained_claim=retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )


def _active_choreography_registration(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> Any:
    closure = inspect.getclosurevars(reader._transition_authenticated_post_effect_outcome_retention)
    registrations = cast(dict[object, Any], closure.nonlocals["active_choreographies"])
    return registrations[issuer]


def _transition_registered_post_effect_retention(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    lease: object,
    recovery_capability: object,
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> reader._TrustedTimePostEnrollmentPostEffectOutcomeCapability:
    _bind_registered_recovery_claim(
        issuer,
        lease,
        recovery_capability,
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    candidate = issuer._issue_post_effect_outcome_retention_candidate()
    issuer._transition_to_post_effect_outcome_retention(
        lease,
        recovery_capability,
        retained,
        post_effect_outcome_candidate=candidate,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    return candidate


def _confirmed_controller_receipt(
    artifact_directory: Path,
) -> controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    retained = object.__new__(
        controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome
    )
    object.__setattr__(
        retained,
        "status",
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED,
    )
    object.__setattr__(
        retained,
        "reason",
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED,
    )
    object.__setattr__(retained, "artifact_path", artifact_directory / "exact-receipt.json")
    return retained


def _recovery_controller_receipt(
    artifact_directory: Path,
    *,
    reason: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason = (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
    ),
) -> controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    retained = object.__new__(
        controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome
    )
    object.__setattr__(
        retained,
        "status",
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED,
    )
    object.__setattr__(retained, "reason", reason)
    object.__setattr__(retained, "artifact_path", artifact_directory / "exact-failure.json")
    return retained


def test_nominal_callback_uses_one_private_lease_for_exact_observation_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    created_snapshot, staged_snapshot, _ = fixtures._install_pure_validator_stubs(
        monkeypatch,
        endpoint=endpoint,
    )
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            *fixtures._state_outputs("created"),
            *fixtures._state_outputs("staged_unreleased"),
        ],
    )
    leases: list[object] = []

    def observe(lease: object) -> tuple[object, object]:
        leases.append(lease)
        before = issuer._require_active_choreography_lease(lease)
        created = issuer.issue_created_snapshot(
            **fixtures._issue_arguments(paths),
            _choreography_lease=lease,
        )
        staged = issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **fixtures._issue_arguments(paths),
            _choreography_lease=lease,
        )
        after = issuer._require_active_choreography_lease(lease)
        assert before.lease_sha256 == after.lease_sha256
        assert before.started_monotonic_ns == after.started_monotonic_ns
        assert before.deadline_monotonic_ns == after.deadline_monotonic_ns
        assert before.observed_monotonic_ns <= after.observed_monotonic_ns
        return created, staged

    created, staged = issuer._run_exclusive_choreography(observe)

    assert len(leases) == 1
    assert type(leases[0]) is reader._TrustedTimePostEnrollmentTopologyChoreographyLease
    assert created.snapshot is created_snapshot
    assert staged.snapshot is staged_snapshot
    assert staged.staged_observation_ordinal == 1
    assert staged.predecessor_observation_sha256 == created.observation_sha256
    assert issuer._choreography_consumed is True
    assert issuer._choreography_inflight is False
    assert len(queued.calls) == 31
    assert queued.outputs == []
    for call in queued.calls[1:]:
        timeout_seconds = call["timeout_seconds"]
        assert type(timeout_seconds) is float
        assert 0 < timeout_seconds <= 2.0
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_direct_observation_workflow_remains_available_before_choreography(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[fixtures._json_line("LOCAL:DAEMON:1")],
    )
    _seed_cursor_state(issuer)

    cursor = issuer.issue_observation_cursor()

    assert cursor.cursor_ordinal == 1
    assert cursor.observation_cursor_authenticated is True
    assert issuer._choreography_consumed is False
    assert issuer._choreography_inflight is False
    assert len(queued.calls) == 2
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_deadline_equality_rejects_before_callback_or_docker_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 1_000_000_000
    deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    clock = _MonotonicClock([started, deadline])
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    callback_called = False

    def action(_: object) -> None:
        nonlocal callback_called
        callback_called = True

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="choreography lease is unavailable",
    ):
        issuer._run_exclusive_choreography(action)

    assert callback_called is False
    assert clock.calls == [started, deadline]
    assert clock.call_count == 2
    assert clock.remaining == []
    assert len(queued.calls) == 1
    assert queued.outputs == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_monotonic_regression_rejects_inside_scope_without_docker_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = _MonotonicClock([100, 101, 100])
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )

    def regress(lease: object) -> None:
        issuer._require_active_choreography_lease(lease)

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="choreography lease is unavailable",
    ):
        issuer._run_exclusive_choreography(regress)

    assert clock.calls == [100, 101, 100]
    assert clock.call_count == 3
    assert clock.remaining == []
    assert len(queued.calls) == 1
    assert queued.outputs == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_command_timeout_shrinks_against_one_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 1_000_000_000
    deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    values = [
        started,
        started + 1,
        deadline - 1_500_000_000,
        deadline - 1_000_000_000,
        deadline - 1,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[fixtures._json_line("LOCAL:DAEMON:1")],
        monotonic_clock=clock,
    )

    def issue(lease: object) -> object:
        _seed_cursor_state(issuer)
        return issuer.issue_observation_cursor(_choreography_lease=lease)

    cursor = issuer._run_exclusive_choreography(issue)

    assert cursor.cursor_ordinal == 1
    assert queued.calls[1]["timeout_seconds"] == 1.5
    assert clock.calls == values
    assert clock.call_count == len(values)
    assert clock.remaining == []
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("candidate_kind", ["missing", "wrong"])
def test_missing_or_wrong_lease_fails_before_any_observation_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    candidate_kind: str,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path)

    def issue(lease: object) -> None:
        if candidate_kind == "missing":
            issuer.issue_created_snapshot(
                **fixtures._issue_arguments(paths),
            )
        else:
            issuer.issue_created_snapshot(
                **fixtures._issue_arguments(paths),
                _choreography_lease=object(),
            )
        raise AssertionError(lease)

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="observation choreography is unavailable",
    ):
        issuer._run_exclusive_choreography(issue)

    assert len(queued.calls) == 1
    assert queued.outputs == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_cross_thread_lease_use_fails_before_any_observation_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    errors: list[BaseException] = []

    def action(lease: object) -> None:
        def issue_from_foreign_thread() -> None:
            try:
                issuer.issue_created_snapshot(
                    **fixtures._issue_arguments(paths),
                    _choreography_lease=lease,
                )
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=issue_from_foreign_thread)
        worker.start()
        worker.join(timeout=2.0)
        assert not worker.is_alive()

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(action)

    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert len(queued.calls) == 1
    assert queued.outputs == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_nested_choreography_poison_fails_before_inner_callback_or_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    inner_called = False

    def inner(_: object) -> None:
        nonlocal inner_called
        inner_called = True

    def outer(_: object) -> None:
        issuer._run_exclusive_choreography(inner)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(outer)

    assert inner_called is False
    assert len(queued.calls) == 1
    assert queued.outputs == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_caught_nested_rejection_cannot_clear_outer_scope_or_release_flock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    close_errors: list[BaseException] = []

    def outer(_: object) -> None:
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._run_exclusive_choreography(lambda _lease: None)
        assert issuer._choreography_inflight is True
        try:
            issuer.close()
        except BaseException as error:
            close_errors.append(error)
        _assert_launch_lock_is_held(issuer)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(outer)

    assert len(close_errors) == 1
    assert isinstance(close_errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._choreography_inflight is False
    assert issuer._lock_descriptor >= 0
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_success_finalization_revokes_scope_atomically_before_close_can_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    original_active = reader._authenticated_choreography_is_active
    final_validation_entered = threading.Event()
    close_started = threading.Event()
    close_finished = threading.Event()
    active_calls = 0

    def gated_active(owner: object, candidate: object) -> bool:
        nonlocal active_calls
        active_calls += 1
        if active_calls == 5:
            final_validation_entered.set()
            assert close_started.wait(timeout=2.0)
            assert close_finished.is_set() is False
        return original_active(owner, candidate)

    monkeypatch.setattr(reader, "_authenticated_choreography_is_active", gated_active)
    close_errors: list[BaseException] = []

    def close_when_finalizing() -> None:
        assert final_validation_entered.wait(timeout=2.0)
        close_started.set()
        try:
            issuer.close()
        except BaseException as error:
            close_errors.append(error)
        finally:
            close_finished.set()

    worker = threading.Thread(target=close_when_finalizing)
    worker.start()
    result = issuer._run_exclusive_choreography(lambda _lease: "accepted")
    worker.join(timeout=2.0)

    assert result == "accepted"
    assert not worker.is_alive()
    assert close_errors == []
    assert close_finished.is_set() is True
    assert issuer._closed is True
    assert issuer._choreography_inflight is False
    assert issuer._lock_descriptor == -1
    assert len(queued.calls) == 1
    assert queued.outputs == []
    descriptor = _acquire_trusted_time_launch_lock(
        path=issuer._lock_path,
        ignored_root=issuer._ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)


def test_close_between_choreography_calls_poisons_without_releasing_flock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    close_errors: list[BaseException] = []
    lock_was_held_inside_callback = False

    def action(_: object) -> None:
        nonlocal lock_was_held_inside_callback
        try:
            issuer.close()
        except BaseException as error:
            close_errors.append(error)
        _assert_launch_lock_is_held(issuer)
        lock_was_held_inside_callback = True

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(action)

    assert len(close_errors) == 1
    assert isinstance(close_errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert lock_was_held_inside_callback is True
    assert issuer._lock_descriptor >= 0
    os.fstat(issuer._lock_descriptor)
    _assert_launch_lock_is_held(issuer)
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit])
def test_callback_baseexception_poisons_but_retains_flock_until_close(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_type: type[BaseException],
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)

    def fail(_: object) -> Any:
        raise failure_type

    with pytest.raises(failure_type):
        issuer._run_exclusive_choreography(fail)

    assert issuer._poisoned is True
    assert issuer._authentication_capability is None
    assert issuer._choreography_inflight is False
    assert issuer._lock_descriptor >= 0
    _assert_launch_lock_is_held(issuer)
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_scope_revocation_baseexception_cannot_wedge_inflight_or_flock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    original_revoke = reader._revoke_authenticated_choreography_scope

    def revoke_then_interrupt(owner: object, scope_nonce: object | None) -> None:
        original_revoke(owner, scope_nonce)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        reader,
        "_revoke_authenticated_choreography_scope",
        revoke_then_interrupt,
    )

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="choreography cleanup is unavailable",
    ):
        issuer._run_exclusive_choreography(lambda _lease: "unreachable")

    assert issuer._choreography_inflight is False
    assert issuer._choreography_scope_nonce is None
    assert issuer._poisoned is True
    _assert_launch_lock_is_held(issuer)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_failure_after_inflight_visibility_still_cleans_scope_and_flock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    method = (
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    )._run_authenticated_choreography_scope
    source, first_line = inspect.getsourcelines(method)
    registrar_line = first_line + next(
        offset
        for offset, line in enumerate(source)
        if "registered = choreography_registrar(" in line
    )

    def interrupt_after_inflight(frame: object, event: str, _arg: object) -> Any:
        if (
            event == "line"
            and getattr(frame, "f_code", None) is method.__code__
            and getattr(frame, "f_lineno", None) == registrar_line
        ):
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_after_inflight

    sys.settrace(interrupt_after_inflight)
    try:
        with pytest.raises(KeyboardInterrupt):
            issuer._run_exclusive_choreography(lambda _lease: None)
    finally:
        sys.settrace(None)

    assert issuer._choreography_inflight is False
    assert issuer._choreography_scope_nonce is None
    assert issuer._poisoned is True
    _assert_launch_lock_is_held(issuer)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_lease_rejects_constructor_copy_deepcopy_and_pickle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._TrustedTimePostEnrollmentTopologyChoreographyLease()

    def inspect_lease(lease: object) -> str:
        operations: tuple[Callable[[], object], ...] = (
            lambda: copy(lease),
            lambda: deepcopy(lease),
            lambda: pickle.dumps(lease),
        )
        for operation in operations:
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                operation()
        return "accepted"

    assert issuer._run_exclusive_choreography(inspect_lease) == "accepted"
    assert issuer._poisoned is False
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_raw_lease_forgery_fails_before_any_observation_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path)

    def forge(lease: object) -> None:
        forged = object.__new__(type(lease))
        assert forged is not lease
        issuer.issue_created_snapshot(
            **fixtures._issue_arguments(paths),
            _choreography_lease=forged,
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(forge)

    assert len(queued.calls) == 1
    assert queued.outputs == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_choreography_is_one_shot_and_never_runs_a_second_callback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    assert issuer._run_exclusive_choreography(lambda _lease: "first") == "first"
    second_called = False

    def second(_: object) -> None:
        nonlocal second_called
        second_called = True

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(second)

    assert second_called is False
    assert issuer._poisoned is True
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_lease_cannot_be_reused_after_callback_scope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    leases: list[object] = []

    def retain(lease: object) -> None:
        leases.append(lease)

    issuer._run_exclusive_choreography(retain)
    assert len(leases) == 1

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="observation choreography is unavailable",
    ):
        issuer.issue_created_snapshot(
            **fixtures._issue_arguments(paths),
            _choreography_lease=leases[0],
        )

    assert issuer._poisoned is True
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_forked_child_cannot_use_lease_or_keep_inherited_flock_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    inherited_descriptor = issuer._lock_descriptor

    def inspect_child(lease: object) -> bytes:
        read_descriptor, write_descriptor = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the pipe
            os.close(read_descriptor)
            try:
                descriptor_closed = False
                try:
                    os.fstat(inherited_descriptor)
                except OSError:
                    descriptor_closed = True
                lease_rejected = not reader._authenticated_choreography_is_active(issuer, lease)
                state_closed = (
                    issuer._lock_descriptor == -1
                    and issuer._closed is True
                    and issuer._poisoned is True
                    and issuer._choreography_inflight is False
                    and issuer._authentication_capability is None
                )
                payload = (
                    b"safe" if descriptor_closed and lease_rejected and state_closed else b"unsafe"
                )
                os.write(write_descriptor, payload)
            finally:
                os.close(write_descriptor)
            os._exit(0)

        os.close(write_descriptor)
        try:
            return os.read(read_descriptor, 16)
        finally:
            os.close(read_descriptor)
            os.waitpid(child_pid, 0)

    assert issuer._run_exclusive_choreography(inspect_child) == b"safe"
    assert issuer._poisoned is False
    assert issuer._choreography_inflight is False
    assert len(queued.calls) == 1
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


class _RecoveryRetentionTerminal(BaseException):
    pass


def test_recovery_capability_binds_exact_claim_and_uses_same_deadline_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 1_000_000_000
    values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        started + 5,
        started + 6,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    capabilities: list[object] = []

    def retain_recovery(lease: object, capability: object) -> None:
        capabilities.append(capability)
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert checkpoint.retained_claim is retained
        assert checkpoint.artifact_directory == artifact_directory
        assert checkpoint.ignored_root == ignored_root
        assert checkpoint.started_monotonic_ns == started
        assert checkpoint.deadline_monotonic_ns == (
            started + reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_NANOSECONDS
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            capability,
            checkpoint,
            retained_outcome,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_recovery)

    assert len(capabilities) == 1
    assert type(capabilities[0]) is reader._TrustedTimePostEnrollmentRecoveryRetentionCapability
    assert issuer._poisoned is True
    assert issuer._choreography_inflight is False
    assert issuer._choreography_scope_nonce is None
    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_completion_rejects_zero_write_without_exact_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = [10_000, 10_001, 10_002, 10_003, 10_004, 10_005]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_zero_write(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery retention completion is unavailable",
        ):
            issuer._complete_recovery_outcome_retention(
                capability,
                checkpoint,
                object(),
            )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_zero_write)

    assert clock.calls == values
    assert (
        list(
            artifact_directory.glob(
                f"{recovery_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"
            )
        )
        == []
    )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("interference", ["remove", "replace"])
def test_real_recovery_completion_rejects_stale_outcome_inode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interference: str,
) -> None:
    values = [15_000, 15_001, 15_002, 15_003, 15_004, 15_005]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    displaced_path: Path | None = None

    def reject_stale_inode(lease: object, capability: object) -> None:
        nonlocal displaced_path
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        displaced_path = retained_outcome.artifact_path
        retained_outcome.artifact_path.unlink()
        if interference == "replace":
            retained_outcome.artifact_path.write_bytes(retained_outcome.encoded)
            retained_outcome.artifact_path.chmod(0o600)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery retention completion is unavailable",
        ):
            issuer._complete_recovery_outcome_retention(
                capability,
                checkpoint,
                retained_outcome,
            )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_recovery_outcome_retention(
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_stale_inode)

    assert displaced_path is not None
    assert displaced_path.exists() is (interference == "replace")
    assert clock.calls == values
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("interference", ["remove", "replace"])
def test_recovery_completion_revalidates_exact_outcome_after_monotonic_sample(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interference: str,
) -> None:
    values = [17_000, 17_001, 17_002, 17_003, 17_004, 17_005, 17_006]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    mutated_during_sample = False
    outcome_path: Path | None = None

    def reject_sample_time_interference(lease: object, capability: object) -> None:
        nonlocal mutated_during_sample, outcome_path
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        outcome_path = retained_outcome.artifact_path

        def mutate_then_sample() -> int:
            nonlocal mutated_during_sample
            assert mutated_during_sample is False
            mutated_during_sample = True
            retained_outcome.artifact_path.unlink()
            if interference == "replace":
                retained_outcome.artifact_path.write_bytes(retained_outcome.encoded)
                retained_outcome.artifact_path.chmod(0o600)
            return clock()

        issuer._monotonic_ns = mutate_then_sample
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery retention completion is unavailable",
        ):
            issuer._complete_recovery_outcome_retention(
                capability,
                checkpoint,
                retained_outcome,
            )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_recovery_outcome_retention(
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_sample_time_interference)

    assert mutated_during_sample is True
    assert outcome_path is not None
    assert outcome_path.exists() is (interference == "replace")
    assert clock.calls == values
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("interference", ["unlink", "replace"])
def test_recovery_completion_revalidates_named_flock_after_monotonic_sample(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interference: str,
) -> None:
    values = [18_000, 18_001, 18_002, 18_003, 18_004, 18_005, 18_006]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    original_complete = reader._complete_authenticated_recovery_retention
    authenticated_completion_calls = 0
    lock_mutated_during_sample = False

    def record_authenticated_completion(
        owner: object,
        capability: object,
        checkpoint: object,
        *,
        observed_monotonic_ns: object,
    ) -> None:
        nonlocal authenticated_completion_calls
        authenticated_completion_calls += 1
        original_complete(
            owner,
            capability,
            checkpoint,
            observed_monotonic_ns=observed_monotonic_ns,
        )

    monkeypatch.setattr(
        reader,
        "_complete_authenticated_recovery_retention",
        record_authenticated_completion,
    )

    def reject_lock_path_interference(lease: object, capability: object) -> None:
        nonlocal lock_mutated_during_sample
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

        def mutate_lock_then_sample() -> int:
            nonlocal lock_mutated_during_sample
            assert lock_mutated_during_sample is False
            lock_mutated_during_sample = True
            issuer._lock_path.unlink()
            if interference == "replace":
                issuer._lock_path.touch(mode=0o600, exist_ok=False)
                issuer._lock_path.chmod(0o600)
            return clock()

        issuer._monotonic_ns = mutate_lock_then_sample
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery retention completion is unavailable",
        ):
            issuer._complete_recovery_outcome_retention(
                capability,
                checkpoint,
                retained_outcome,
            )
        assert authenticated_completion_calls == 0
        assert issuer._poisoned is True
        assert retained_outcome.artifact_path.exists()
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_lock_path_interference)

    assert lock_mutated_during_sample is True
    assert authenticated_completion_calls == 0
    assert clock.calls == values
    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="issuer close is unavailable",
    ):
        issuer.close()
    assert issuer._closed is True
    assert issuer._lock_descriptor == -1
    descriptor = _acquire_trusted_time_launch_lock(
        path=issuer._lock_path,
        ignored_root=issuer._ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)


def test_removed_direct_recovery_claim_binding_cannot_arm_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    artifact_directory = issuer._ignored_root / "trusted-time"
    ignored_root = issuer._ignored_root

    assert "_bind_recovery_retention_to_claim" not in type(issuer).__dict__
    assert not hasattr(issuer, "_bind_recovery_retention_to_claim")

    def reject_unbound_retention(_lease: object, capability: object) -> None:
        issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="recovery retention capability is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_unbound_retention)

    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_forged_claimed_fence_authorization_cannot_issue_recovery_binder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    artifact_directory = issuer._ignored_root / "trusted-time"
    ignored_root = issuer._ignored_root

    with pytest.raises(claimed_fence.TrustedTimePostEnrollmentStartClaimedFenceRejected):
        claimed_fence._ClaimedFenceRecoveryBinderAuthorization()

    def reject_forged_authorization(lease: object, capability: object) -> None:
        forged = object.__new__(claimed_fence._ClaimedFenceRecoveryBinderAuthorization)
        issuer._issue_recovery_retention_claim_binder(
            lease,
            capability,
            claimed_fence_authorization=forged,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="recovery claim binder is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_forged_authorization)

    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_exact_recovery_claim_binder_cannot_bind_before_path_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    callback_caught_rejection = False

    def reject_uncheckpointed_binding(lease: object, capability: object) -> str:
        nonlocal callback_caught_rejection
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery claim binder is unavailable",
        ):
            binder(retained)
        callback_caught_rejection = True
        assert issuer._poisoned is True
        assert not reader._authenticated_recovery_claim_binder_is_available(
            binder,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery retention capability is unavailable",
        ):
            issuer._begin_recovery_outcome_retention(
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        return "must not escape"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_uncheckpointed_binding)

    assert callback_caught_rejection is True
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_second_checkpoint_lock_validation_failure_poisons_and_revokes_binder(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    artifact_directory = issuer._ignored_root / "trusted-time"
    ignored_root = issuer._ignored_root
    validation_calls = 0
    callback_caught_rejection = False

    def reject_second_lock_validation(lease: object, capability: object) -> str:
        nonlocal callback_caught_rejection, validation_calls
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer_type = type(issuer)
        original_validate_lock = issuer_type._validate_lock

        def fail_second(
            candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        ) -> None:
            nonlocal validation_calls
            validation_calls += 1
            if validation_calls == 2:
                raise OSError("lock identity changed between validations")
            original_validate_lock(candidate)

        with monkeypatch.context() as scoped:
            scoped.setattr(issuer_type, "_validate_lock", fail_second)
            with pytest.raises(
                reader.TrustedTimePostEnrollmentTopologyReaderError,
                match="recovery claim binder is unavailable",
            ):
                binder._checkpoint(
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
        callback_caught_rejection = True
        assert issuer._poisoned is True
        assert not reader._authenticated_recovery_claim_binder_is_available(
            binder,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return "must not escape"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_second_lock_validation)

    assert callback_caught_rejection is True
    assert validation_calls == 2
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_interruption_during_binder_discovery_cannot_be_caught_to_continue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    consume = reader._consume_authenticated_recovery_claim_binder
    source, first_line = inspect.getsourcelines(consume)
    discovery_line = first_line + next(
        offset
        for offset, line in enumerate(source)
        if "registration = active_choreographies.get(owner)" in line
    )
    interruption_injected = False
    callback_caught_rejection = False

    def interrupt_during_discovery(frame: object, event: str, _arg: object) -> Any:
        nonlocal interruption_injected
        if (
            not interruption_injected
            and event == "line"
            and getattr(frame, "f_code", None) is consume.__code__
            and getattr(frame, "f_lineno", None) == discovery_line
        ):
            interruption_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_during_discovery

    def catch_interruption(lease: object, capability: object) -> str:
        nonlocal callback_caught_rejection
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        binder._checkpoint(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        sys.settrace(interrupt_during_discovery)
        try:
            with pytest.raises(
                reader.TrustedTimePostEnrollmentTopologyReaderError,
                match="recovery claim binder is unavailable",
            ):
                binder(retained)
        finally:
            sys.settrace(None)
        callback_caught_rejection = True
        assert issuer._poisoned is True
        assert not reader._authenticated_recovery_claim_binder_is_available(
            binder,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._require_active_choreography_lease(lease)
        return "must not escape"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(catch_interruption)

    assert interruption_injected is True
    assert callback_caught_rejection is True
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_opaque_claim_binder_is_exact_one_shot_and_fixed_to_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = [20_000, 20_001, 20_002, 20_003, 20_004, 20_005, 20_006]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def bind_and_retain(lease: object, capability: object) -> None:
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert type(binder) is reader._TrustedTimePostEnrollmentRecoveryClaimBinder
        assert reader._authenticated_recovery_claim_binder_is_available(
            binder,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            copy(binder)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            pickle.dumps(binder)

        binder._checkpoint(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        binder(retained)
        assert not reader._authenticated_recovery_claim_binder_is_available(
            binder,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            binder(retained)

        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            capability,
            checkpoint,
            retained_outcome,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(bind_and_retain)

    assert clock.calls == values
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_real_claim_binder_survives_later_claimed_chronology_failure_to_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def valid_test_seal(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fixtures._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid_test_seal)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid_test_seal(candidate, payload),
    )
    context = claimed_fixtures._context(tmp_path)
    clock = _MonotonicClock([30_000 + offset for offset in range(20)])
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    context.topology_issuer = issuer
    cursors = iter(context.cursors)

    def issue_cursor(
        candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        *,
        _choreography_lease: object | None = None,
    ) -> reader.TrustedTimePostEnrollmentTopologyObservationCursor:
        candidate._require_active_choreography_lease(_choreography_lease)
        return next(cursors)

    def issue_staged(
        candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        *,
        _choreography_lease: object | None = None,
        **_: object,
    ) -> reader.TrustedTimePostEnrollmentStagedTopologyObservation:
        candidate._require_active_choreography_lease(_choreography_lease)
        return context.staged_two

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "issue_observation_cursor",
        issue_cursor,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "issue_staged_unreleased_snapshot",
        issue_staged,
    )
    monkeypatch.setattr(
        staging,
        "load_confirmed_first_enrollment_evidence",
        lambda **_: context.approval.confirmed_enrollment,
    )
    monkeypatch.setattr(
        claimed_fence,
        "revalidate_retained_post_enrollment_start_claim",
        lambda *_args, **_kwargs: False,
    )

    def retain_after_later_failure(lease: object, capability: object) -> Never:
        try:
            claimed_fence.prepare_post_enrollment_start_leased_claimed_pre_release_fence(
                **context.kwargs(),  # type: ignore[arg-type]
                choreography_lease=lease,
                recovery_retention_capability=capability,
            )
        except claimed_fence.TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired:
            recovery_outcome.retain_post_enrollment_start_recovery_required_outcome(
                topology_issuer=issuer,
                recovery_retention_capability=capability,
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
        raise AssertionError("claimed chronology failure was not retained")

    with pytest.raises(
        recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained
    ) as terminal:
        issuer._run_exclusive_choreography_with_recovery_retention(retain_after_later_failure)

    retained = terminal.value.retained_outcome
    assert retained.operation_id == context.approval.operation_id
    assert recovery_outcome.revalidate_retained_post_enrollment_start_outcome(
        retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert clock.call_count < 20
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_action_deadline_equality_revokes_action_but_preserves_bound_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 2_000_000_000
    action_deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    retention_deadline = (
        started + reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_NANOSECONDS
    )
    values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        action_deadline,
        action_deadline + 1,
        retention_deadline - 1,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def retain_after_expiry(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._require_active_choreography_lease(lease)
        assert issuer._poisoned is True
        _assert_launch_lock_is_held(issuer)
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            capability,
            checkpoint,
            retained_outcome,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_after_expiry)

    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_unbound_claim_cannot_arm_after_action_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 3_000_000_000
    action_deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    values = [
        started,
        started + 1,
        action_deadline + 1,
    ]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_after_action_deadline(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_after_action_deadline)

    assert clock.calls == values
    assert issuer._poisoned is True
    assert (
        list(
            artifact_directory.glob(
                f"{recovery_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"
            )
        )
        == []
    )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_deadline_equality_rejects_before_any_outcome_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 4_000_000_000
    retention_deadline = (
        started + reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_NANOSECONDS
    )
    values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        retention_deadline,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    writer_called = False

    def reject_at_retention_deadline(lease: object, capability: object) -> None:
        nonlocal writer_called
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        writer_called = True

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="recovery retention capability is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_at_retention_deadline)

    assert writer_called is False
    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_forged_recovery_capability_cannot_consume_the_exact_bound_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = [100, 101, 102, 103, 104, 105, 106]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_forgery_then_retain(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        forged = object.__new__(type(capability))
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_recovery_outcome_retention(
                forged,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            capability,
            checkpoint,
            retained_outcome,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_forgery_then_retain)

    assert clock.calls == values
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_cross_thread_recovery_use_poison_does_not_consume_owner_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = [200, 201, 202, 203, 204, 205, 206]
    clock = _MonotonicClock(values)
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    errors: list[BaseException] = []

    def reject_foreign_thread_then_retain(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

        def foreign_use() -> None:
            try:
                issuer._begin_recovery_outcome_retention(
                    capability,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=foreign_use)
        worker.start()
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            capability,
            checkpoint,
            retained_outcome,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(
            reject_foreign_thread_then_retain
        )

    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert clock.calls == values
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_capability_rejects_constructor_copy_pickle_and_stale_scope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    capabilities: list[object] = []

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._TrustedTimePostEnrollmentRecoveryRetentionCapability()

    def inspect(lease: object, capability: object) -> str:
        capabilities.append(capability)
        operations: tuple[Callable[[], object], ...] = (
            lambda: copy(capability),
            lambda: deepcopy(capability),
            lambda: pickle.dumps(capability),
        )
        for operation in operations:
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                operation()
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return "accepted"

    assert issuer._run_exclusive_choreography_with_recovery_retention(inspect) == "accepted"
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._begin_recovery_outcome_retention(
            capabilities[0],
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_exact_reader_capability_retains_fixed_recovery_outcome_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 6_000_000_000
    values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        started + 5,
        started + 6,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def retain(lease: object, capability: object) -> Never:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        recovery_outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    with pytest.raises(
        recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained
    ) as terminal:
        issuer._run_exclusive_choreography_with_recovery_retention(retain)

    retained_outcome = terminal.value.retained_outcome
    assert retained_outcome.operation_id == retained.operation_id
    assert retained_outcome.claim_sha256 == retained.claim.claim_sha256
    assert retained_outcome.retained_claim_artifact_sha256 == retained.artifact_sha256
    assert recovery_outcome.revalidate_retained_post_enrollment_start_outcome(
        retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert issuer._choreography_inflight is False
    assert issuer._choreography_scope_nonce is None
    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_retention_crossing_305_is_unconfirmed_and_preserves_possible_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 7_000_000_000
    retention_deadline = (
        started + reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_NANOSECONDS
    )
    values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        retention_deadline - 1,
        retention_deadline,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def retain_too_late(lease: object, capability: object) -> Never:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        recovery_outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_too_late)

    retained_outcome = recovery_outcome.load_retained_post_enrollment_start_outcome(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    assert retained_outcome.status.value == "recovery_required"
    assert retained_outcome.artifact_path.exists()
    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_clock_regression_after_action_expiry_revokes_recovery_before_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 8_000_000_000
    action_deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    values = [
        started,
        started + 1,
        started + 2,
        started + 3,
        started + 4,
        action_deadline,
        action_deadline - 1,
    ]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        monotonic_clock=clock,
    )
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    writer_called = False

    def reject_regression(lease: object, capability: object) -> None:
        nonlocal writer_called
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._require_active_choreography_lease(lease)
        issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        writer_called = True

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_regression)

    assert writer_called is False
    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_clock_failure_after_binding_irreversibly_revokes_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = [300, 301, 302, 303, 304]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_clock(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

        def unavailable_clock() -> int:
            raise RuntimeError("private clock detail")

        issuer._monotonic_ns = unavailable_clock
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._require_active_choreography_lease(lease)
        issuer._monotonic_ns = lambda: 400
        issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_clock)

    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_close_interference_revokes_action_but_preserves_bound_recovery_and_flock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = [400, 401, 402, 403, 404, 405, 406]
    clock = _MonotonicClock(values)
    issuer, queued = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def recover_after_close(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.close()
        assert issuer._poisoned is True
        _assert_launch_lock_is_held(issuer)
        checkpoint = issuer._begin_recovery_outcome_retention(
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained_outcome = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            capability,
            checkpoint,
            retained_outcome,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(recover_after_close)

    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


class _PostEffectRetentionTerminal(BaseException):
    pass


@pytest.mark.parametrize(
    "mutation",
    [
        "runner",
        "runner_and_mirror",
        "environment",
        "environment_and_mirrors",
        "monotonic_clock",
    ],
)
def test_bound_control_rejects_open_session_provenance_mutation_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    attacker_runner = fixtures._QueuedRunner([])

    def reject_mutated_control(_lease: object) -> None:
        if mutation == "runner":
            issuer._runner = attacker_runner
        elif mutation == "runner_and_mirror":
            issuer._runner = attacker_runner
            issuer._runner_identity_value = attacker_runner
        elif mutation == "environment":
            issuer._environment["DOCKER_HOST"] = "unix:///tmp/attacker-docker.sock"
        elif mutation == "environment_and_mirrors":
            forged_environment = dict(issuer._environment)
            forged_environment["DOCKER_HOST"] = "unix:///tmp/attacker-docker.sock"
            issuer._environment = forged_environment
            issuer._environment_identity_value = tuple(sorted(forged_environment.items()))
            issuer._environment_sha256_value = reader._canonical_sha256(forged_environment)
        else:
            issuer._monotonic_ns = _MonotonicClock([1])
        issuer._run_bound_control(
            (os.fspath(issuer._docker_executable_path), "version"),
            timeout_seconds=1.0,
            maximum_stdout_bytes=1,
            maximum_stderr_bytes=1,
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(reject_mutated_control)

    assert len(queued.calls) == 1
    assert attacker_runner.calls == []
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_effect_success_retention_is_exact_one_shot_and_scope_sealed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    escaped: list[tuple[object, object]] = []

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._TrustedTimePostEnrollmentPostEffectOutcomeCapability()

    def retain_success(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        escaped.append((lease, post_effect_capability))
        for operation in (
            lambda: copy(post_effect_capability),
            lambda: deepcopy(post_effect_capability),
            lambda: pickle.dumps(post_effect_capability),
        ):
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                operation()
        active = issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="success",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert checkpoint.retained_claim is retained
        assert checkpoint.outcome_kind == "success"
        assert checkpoint.started_monotonic_ns == active.started_monotonic_ns
        assert checkpoint.action_deadline_monotonic_ns == active.deadline_monotonic_ns
        assert checkpoint.deadline_monotonic_ns == active.deadline_monotonic_ns
        receipt = object()
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_confirmed"
        assert registration.controller_outcome_checkpoint is checkpoint
        assert registration.controller_outcome_receipt is receipt
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._complete_post_effect_controller_outcome_retention(
                post_effect_capability,
                checkpoint,
                receipt,
            )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_success)

    lease, post_effect_capability = escaped[0]
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_exact_revalidated_confirmed_receipt_is_the_only_normal_terminal_handoff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = _confirmed_controller_receipt(artifact_directory)
    revalidated: list[object] = []

    def revalidate(
        candidate: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        revalidated.append(candidate)
        return (
            candidate is receipt
            and artifact_directory == retained.artifact_path.parent
            and ignored_root == artifact_directory.parent
        )

    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        revalidate,
    )

    def retain_success(lease: object, recovery_capability: object) -> object:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="success",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        return receipt

    returned = issuer._run_exclusive_choreography_with_recovery_retention(retain_success)

    assert returned is receipt
    assert revalidated == [receipt]
    assert issuer._poisoned is True
    assert issuer._choreography_inflight is False
    assert issuer._choreography_scope_nonce is None
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("failure", ["wrong_identity", "receipt_revalidation"])
def test_terminal_success_handoff_rejects_false_or_unrevalidated_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = _confirmed_controller_receipt(artifact_directory)
    revalidated: list[object] = []

    def revalidate(
        candidate: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        revalidated.append(candidate)
        assert artifact_directory == retained.artifact_path.parent
        assert ignored_root == artifact_directory.parent
        return False

    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        revalidate,
    )

    def reject_false_handoff(lease: object, recovery_capability: object) -> object:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="success",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        return object() if failure == "wrong_identity" else receipt

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_false_handoff)

    assert revalidated == ([] if failure == "wrong_identity" else [receipt])
    assert issuer._poisoned is True
    assert issuer._choreography_inflight is False
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize(
    "reason",
    [
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED,
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED,
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED,
    ],
)
def test_exact_revalidated_failure_receipt_is_returned_after_issuer_poison(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reason: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = _recovery_controller_receipt(artifact_directory, reason=reason)
    revalidated: list[object] = []

    def revalidate(
        candidate: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        revalidated.append(candidate)
        return (
            candidate is receipt
            and artifact_directory == retained.artifact_path.parent
            and ignored_root == artifact_directory.parent
        )

    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        revalidate,
    )

    def retain_failure(lease: object, recovery_capability: object) -> Never:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        assert bool(issuer._poisoned) is True
        returned = issuer._return_confirmed_post_effect_controller_failure(lease, receipt)
        assert returned is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_failure)

    assert revalidated == [receipt]
    assert issuer._choreography_inflight is False
    assert issuer._choreography_scope_nonce is None
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize(
    "failure",
    ["wrong_identity", "success_status", "success_reason", "revalidation", "registry", "deadline"],
)
def test_terminal_failure_handoff_rejects_false_or_unrevalidated_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: str,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    if failure == "success_status":
        receipt = _confirmed_controller_receipt(artifact_directory)
    elif failure == "success_reason":
        receipt = _recovery_controller_receipt(
            artifact_directory,
            reason=(
                controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
            ),
        )
    else:
        receipt = _recovery_controller_receipt(artifact_directory)
    revalidated: list[object] = []

    def revalidate(
        candidate: object,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> bool:
        revalidated.append(candidate)
        assert artifact_directory == retained.artifact_path.parent
        assert ignored_root == artifact_directory.parent
        if failure == "registry":
            registration = _active_choreography_registration(issuer)
            registration.retention_state = "post_effect_unconfirmed"
        return failure != "revalidation"

    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        revalidate,
    )

    def reject_false_failure(lease: object, recovery_capability: object) -> Never:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        if failure == "deadline":
            object.__setattr__(
                checkpoint,
                "deadline_monotonic_ns",
                checkpoint.action_deadline_monotonic_ns,
            )
        presented = object() if failure == "wrong_identity" else receipt
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._return_confirmed_post_effect_controller_failure(lease, presented)
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_false_failure)

    rejects_before_revalidation = {
        "wrong_identity",
        "success_status",
        "success_reason",
        "deadline",
    }
    assert revalidated == ([] if failure in rejects_before_revalidation else [receipt])
    assert issuer._choreography_inflight is False
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_effect_transition_retires_old_writer_and_survives_poison_for_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def retain_failure(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_recovery_outcome_retention(
                recovery_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        assert issuer._poisoned is True
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        receipt = object()
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_confirmed"
        assert registration.controller_outcome_receipt is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_failure)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_real_registry_terminal_outcomes_are_mutually_exclusive_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    success_root = tmp_path / "success"
    success_root.mkdir()
    success_issuer, _ = _open_issuer(monkeypatch, success_root)
    success_claim, success_directory, success_ignored_root = _retain_claim_for_issuer(
        success_issuer
    )
    success_receipt = object()

    def retain_success(lease: object, recovery_capability: object) -> Never:
        post_effect_capability = _transition_registered_post_effect_retention(
            success_issuer,
            lease,
            recovery_capability,
            success_claim,
            artifact_directory=success_directory,
            ignored_root=success_ignored_root,
        )
        checkpoint = success_issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            success_claim,
            outcome_kind="success",
            artifact_directory=success_directory,
            ignored_root=success_ignored_root,
        )
        success_issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            success_receipt,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            success_issuer._begin_post_effect_controller_outcome_retention(
                post_effect_capability,
                lease,
                success_claim,
                outcome_kind="failure",
                artifact_directory=success_directory,
                ignored_root=success_ignored_root,
            )
        registration = _active_choreography_registration(success_issuer)
        assert registration.retention_state == "post_effect_confirmed"
        assert registration.controller_outcome_receipt is success_receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        success_issuer._run_exclusive_choreography_with_recovery_retention(retain_success)
    _close_and_assert_launch_lock_is_reacquirable(success_issuer)

    failure_root = tmp_path / "failure"
    failure_root.mkdir()
    failure_issuer, _ = _open_issuer(monkeypatch, failure_root)
    failure_claim, failure_directory, failure_ignored_root = _retain_claim_for_issuer(
        failure_issuer
    )
    failure_receipt = object()

    def abandon_lost_failure_checkpoint(
        lease: object,
        recovery_capability: object,
    ) -> Never:
        post_effect_capability = _transition_registered_post_effect_retention(
            failure_issuer,
            lease,
            recovery_capability,
            failure_claim,
            artifact_directory=failure_directory,
            ignored_root=failure_ignored_root,
        )
        failure_issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            failure_claim,
            outcome_kind="failure",
            artifact_directory=failure_directory,
            ignored_root=failure_ignored_root,
        )
        failure_issuer._abandon_post_effect_controller_outcome_retention(
            post_effect_capability,
            None,
            failure_receipt,
        )
        for outcome_kind in ("success", "failure"):
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                failure_issuer._begin_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    lease,
                    failure_claim,
                    outcome_kind=cast(Any, outcome_kind),
                    artifact_directory=failure_directory,
                    ignored_root=failure_ignored_root,
                )
        registration = _active_choreography_registration(failure_issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert registration.controller_outcome_receipt is failure_receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        failure_issuer._run_exclusive_choreography_with_recovery_retention(
            abandon_lost_failure_checkpoint
        )
    _close_and_assert_launch_lock_is_reacquirable(failure_issuer)


def test_commit_publication_failure_downgrades_completed_controller_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = object()

    def complete_then_abandon(lease: object, recovery_capability: object) -> Never:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_confirmed"

        issuer._abandon_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )

        assert registration.retention_state == "post_effect_unconfirmed"
        assert registration.controller_outcome_receipt is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(complete_then_abandon)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_abandonment_preserves_exact_publicly_committed_controller_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = object()
    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda candidate, **kwargs: candidate is receipt,
    )

    def complete_then_preserve(lease: object, recovery_capability: object) -> Never:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        issuer._abandon_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )

        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_confirmed"
        assert registration.controller_outcome_receipt is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(complete_then_preserve)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_effect_transition_classification_is_exact_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def classify_transition(lease: object, recovery_capability: object) -> Never:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        candidate = issuer._issue_post_effect_outcome_retention_candidate()
        registration = _active_choreography_registration(issuer)
        before = (
            registration.action_active,
            registration.retention_state,
            registration.post_effect_outcome_capability,
        )
        assert issuer._post_effect_outcome_retention_was_transitioned(candidate) is False
        assert (
            registration.action_active,
            registration.retention_state,
            registration.post_effect_outcome_capability,
        ) == before

        cross_thread: list[BaseException] = []

        def classify_from_wrong_thread() -> None:
            try:
                issuer._post_effect_outcome_retention_was_transitioned(candidate)
            except BaseException as error:
                cross_thread.append(error)

        thread = threading.Thread(target=classify_from_wrong_thread)
        thread.start()
        thread.join(timeout=5.0)
        assert not thread.is_alive()
        assert len(cross_thread) == 1
        assert type(cross_thread[0]) is reader.TrustedTimePostEnrollmentTopologyReaderError
        assert bool(issuer._poisoned) is False

        issuer._transition_to_post_effect_outcome_retention(
            lease,
            recovery_capability,
            retained,
            post_effect_outcome_candidate=candidate,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert issuer._post_effect_outcome_retention_was_transitioned(candidate) is True
        forged = object.__new__(reader._TrustedTimePostEnrollmentPostEffectOutcomeCapability)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._post_effect_outcome_retention_was_transitioned(forged)
        assert registration.retention_state == "post_effect_armed"
        assert registration.post_effect_outcome_capability is candidate
        assert bool(issuer._poisoned) is False

        issuer._begin_post_effect_controller_outcome_retention(
            candidate,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert bool(issuer._poisoned) is True
        assert issuer._post_effect_outcome_retention_was_transitioned(candidate) is True
        issuer._abandon_post_effect_controller_outcome_retention(candidate, None)
        assert issuer._post_effect_outcome_retention_was_transitioned(candidate) is True
        assert registration.retention_state == "post_effect_unconfirmed"
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(classify_transition)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._post_effect_outcome_retention_was_transitioned(
            object.__new__(reader._TrustedTimePostEnrollmentPostEffectOutcomeCapability)
        )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_effect_failure_can_begin_after_action_deadline_but_success_cannot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def retain_after_action_deadline(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        active = issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._monotonic_ns = lambda: active.deadline_monotonic_ns
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._require_active_post_effect_outcome_retention(
                post_effect_capability,
                lease,
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_post_effect_controller_outcome_retention(
                post_effect_capability,
                lease,
                retained,
                outcome_kind="success",
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        issuer._monotonic_ns = lambda: active.deadline_monotonic_ns + 1
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert checkpoint.deadline_monotonic_ns == (
            checkpoint.started_monotonic_ns
            + reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_NANOSECONDS
        )
        issuer._monotonic_ns = lambda: active.deadline_monotonic_ns + 2
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            object(),
        )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_after_action_deadline)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_effect_failure_deadline_equality_rejects_before_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    writer_called = False

    def reject_at_failure_deadline(lease: object, recovery_capability: object) -> None:
        nonlocal writer_called
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        registration = _active_choreography_registration(issuer)
        issuer._monotonic_ns = lambda: registration.retention_deadline_monotonic_ns
        issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        writer_called = True

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_at_failure_deadline)

    assert writer_called is False
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("attack", ["forged_capability", "wrong_root", "transition_replay"])
def test_post_effect_failed_authority_attacks_do_not_consume_exact_failure_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    attack: str,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_attack_then_retain(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            if attack == "forged_capability":
                forged = object.__new__(
                    reader._TrustedTimePostEnrollmentPostEffectOutcomeCapability
                )
                issuer._begin_post_effect_controller_outcome_retention(
                    forged,
                    lease,
                    retained,
                    outcome_kind="failure",
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            elif attack == "wrong_root":
                issuer._begin_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    lease,
                    retained,
                    outcome_kind="failure",
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root / "wrong",
                )
            else:
                issuer._transition_to_post_effect_outcome_retention(
                    lease,
                    recovery_capability,
                    retained,
                    post_effect_outcome_candidate=post_effect_capability,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
        assert issuer._poisoned is True
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert (
            issuer._post_effect_outcome_retention_was_transitioned(post_effect_capability) is True
        )
        receipt = object()
        issuer._abandon_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert registration.controller_outcome_receipt is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_attack_then_retain)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_effect_exact_checkpoint_survives_replay_and_forgery_only_for_abandonment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_replay_and_forgery(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_post_effect_controller_outcome_retention(
                post_effect_capability,
                lease,
                retained,
                outcome_kind="failure",
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        forged_checkpoint = copy(checkpoint)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._complete_post_effect_controller_outcome_retention(
                post_effect_capability,
                forged_checkpoint,
                object(),
            )
        receipt = object()
        issuer._abandon_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert registration.controller_outcome_checkpoint is checkpoint
        assert registration.controller_outcome_receipt is receipt
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._abandon_post_effect_controller_outcome_retention(
                post_effect_capability,
                checkpoint,
                receipt,
            )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_replay_and_forgery)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_cross_thread_post_effect_use_poison_preserves_owner_failure_retention(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    errors: list[BaseException] = []

    def reject_foreign_thread(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

        def foreign_use() -> None:
            try:
                issuer._begin_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    lease,
                    retained,
                    outcome_kind="failure",
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=foreign_use)
        worker.start()
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            object(),
        )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_foreign_thread)

    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_forked_child_cannot_use_post_effect_capability_but_parent_can_retain_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def inspect_child(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        read_descriptor, write_descriptor = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the pipe
            os.close(read_descriptor)
            try:
                try:
                    issuer._begin_post_effect_controller_outcome_retention(
                        post_effect_capability,
                        lease,
                        retained,
                        outcome_kind="failure",
                        artifact_directory=artifact_directory,
                        ignored_root=ignored_root,
                    )
                except BaseException:
                    payload = b"rejected"
                else:
                    payload = b"accepted"
                os.write(write_descriptor, payload)
            finally:
                os.close(write_descriptor)
            os._exit(0)

        os.close(write_descriptor)
        try:
            assert os.read(read_descriptor, 16) == b"rejected"
        finally:
            os.close(read_descriptor)
            os.waitpid(child_pid, 0)
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            object(),
        )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(inspect_child)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_interruption_after_post_effect_transition_preserves_failure_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    interruption_injected = False

    def reject_interrupted_transition(lease: object, recovery_capability: object) -> None:
        nonlocal interruption_injected
        _bind_registered_recovery_claim(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        candidate = issuer._issue_post_effect_outcome_retention_candidate()

        def transition_like_controller() -> None:
            issuer._transition_to_post_effect_outcome_retention(
                lease,
                recovery_capability,
                retained,
                post_effect_outcome_candidate=candidate,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            raise AssertionError("post-effect transition interruption was not injected")

        source, first_line = inspect.getsourcelines(transition_like_controller)
        interrupt_line = first_line + next(
            offset
            for offset, line in enumerate(source)
            if "post-effect transition interruption was not injected" in line
        )

        def interrupt_after_transition(frame: object, event: str, _arg: object) -> Any:
            nonlocal interruption_injected
            if (
                not interruption_injected
                and event == "line"
                and getattr(frame, "f_code", None) is transition_like_controller.__code__
                and getattr(frame, "f_lineno", None) == interrupt_line
            ):
                interruption_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt
            return interrupt_after_transition

        sys.settrace(interrupt_after_transition)
        try:
            with pytest.raises(KeyboardInterrupt):
                transition_like_controller()
        finally:
            sys.settrace(None)
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_armed"
        assert registration.post_effect_outcome_capability is candidate
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_recovery_outcome_retention(
                recovery_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            candidate,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        receipt = object()
        issuer._complete_post_effect_controller_outcome_retention(
            candidate,
            checkpoint,
            receipt,
        )
        assert registration.retention_state == "post_effect_confirmed"
        assert registration.controller_outcome_receipt is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_interrupted_transition)

    assert interruption_injected is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_interruption_after_post_effect_begin_consumes_one_shot_as_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    begin = reader._begin_authenticated_post_effect_controller_outcome_retention
    source, first_line = inspect.getsourcelines(begin)
    return_line = first_line + next(
        offset for offset, line in enumerate(source) if "return checkpoint" in line
    )
    interruption_injected = False

    def interrupt_after_begin(frame: object, event: str, _arg: object) -> Any:
        nonlocal interruption_injected
        if (
            not interruption_injected
            and event == "line"
            and getattr(frame, "f_code", None) is begin.__code__
            and getattr(frame, "f_lineno", None) == return_line
        ):
            interruption_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_after_begin

    def reject_interrupted_begin(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        sys.settrace(interrupt_after_begin)
        try:
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                issuer._begin_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    lease,
                    retained,
                    outcome_kind="failure",
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
        finally:
            sys.settrace(None)
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert (
            type(registration.controller_outcome_checkpoint)
            is reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_post_effect_controller_outcome_retention(
                post_effect_capability,
                lease,
                retained,
                outcome_kind="failure",
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_interrupted_begin)

    assert interruption_injected is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_caller_store_interruption_after_post_effect_begin_can_abandon_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    interruption_injected = False

    def abandon_interrupted_begin(lease: object, recovery_capability: object) -> None:
        nonlocal interruption_injected
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        receipt = object()

        def begin_like_outcome_writer() -> None:
            checkpoint = None
            begin_attempted = False
            try:
                begin_attempted = True
                issuer._begin_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    lease,
                    retained,
                    outcome_kind="failure",
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
                raise AssertionError("post-effect begin interruption was not injected")
            except KeyboardInterrupt:
                assert checkpoint is None
                if begin_attempted:
                    issuer._abandon_post_effect_controller_outcome_retention(
                        post_effect_capability,
                        checkpoint,
                        receipt,
                    )
                raise

        source, first_line = inspect.getsourcelines(begin_like_outcome_writer)
        interrupt_line = first_line + next(
            offset
            for offset, line in enumerate(source)
            if "post-effect begin interruption was not injected" in line
        )

        def interrupt_before_checkpoint_store(frame: object, event: str, _arg: object) -> Any:
            nonlocal interruption_injected
            if (
                not interruption_injected
                and event == "line"
                and getattr(frame, "f_code", None) is begin_like_outcome_writer.__code__
                and getattr(frame, "f_lineno", None) == interrupt_line
            ):
                interruption_injected = True
                sys.settrace(None)
                raise KeyboardInterrupt
            return interrupt_before_checkpoint_store

        sys.settrace(interrupt_before_checkpoint_store)
        try:
            with pytest.raises(KeyboardInterrupt):
                begin_like_outcome_writer()
        finally:
            sys.settrace(None)
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert (
            type(registration.controller_outcome_checkpoint)
            is reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint
        )
        assert registration.controller_outcome_receipt is receipt
        assert (
            issuer._post_effect_outcome_retention_was_transitioned(post_effect_capability) is True
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._begin_post_effect_controller_outcome_retention(
                post_effect_capability,
                lease,
                retained,
                outcome_kind="failure",
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(abandon_interrupted_begin)

    assert interruption_injected is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_interruption_after_post_effect_complete_keeps_exact_receipt_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    complete = reader._complete_authenticated_post_effect_controller_outcome_retention
    source, first_line = inspect.getsourcelines(complete)
    completed_line = first_line + next(
        offset for offset, line in enumerate(source) if "registration.action_active = False" in line
    )
    interruption_injected = False

    def interrupt_after_completion(frame: object, event: str, _arg: object) -> Any:
        nonlocal interruption_injected
        if (
            not interruption_injected
            and event == "line"
            and getattr(frame, "f_code", None) is complete.__code__
            and getattr(frame, "f_lineno", None) == completed_line
        ):
            interruption_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_after_completion

    def reject_interrupted_completion(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        receipt = object()
        sys.settrace(interrupt_after_completion)
        try:
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                issuer._complete_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    checkpoint,
                    receipt,
                )
        finally:
            sys.settrace(None)
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert registration.controller_outcome_checkpoint is checkpoint
        assert registration.controller_outcome_receipt is receipt
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._complete_post_effect_controller_outcome_retention(
                post_effect_capability,
                checkpoint,
                receipt,
            )
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_interrupted_completion)

    assert interruption_injected is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_interruption_after_post_effect_abandonment_keeps_receipt_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    abandon = reader._abandon_authenticated_post_effect_controller_outcome_retention
    source, first_line = inspect.getsourcelines(abandon)
    abandoned_line = first_line + next(
        offset for offset, line in enumerate(source) if "abandoned = True" in line
    )
    interruption_injected = False

    def interrupt_after_abandonment(frame: object, event: str, _arg: object) -> Any:
        nonlocal interruption_injected
        if (
            not interruption_injected
            and event == "line"
            and getattr(frame, "f_code", None) is abandon.__code__
            and getattr(frame, "f_lineno", None) == abandoned_line
        ):
            interruption_injected = True
            sys.settrace(None)
            raise KeyboardInterrupt
        return interrupt_after_abandonment

    def reject_interrupted_abandonment(lease: object, recovery_capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_post_effect_controller_outcome_retention(
            post_effect_capability,
            lease,
            retained,
            outcome_kind="failure",
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        receipt = object()
        sys.settrace(interrupt_after_abandonment)
        try:
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                issuer._abandon_post_effect_controller_outcome_retention(
                    post_effect_capability,
                    checkpoint,
                    receipt,
                )
        finally:
            sys.settrace(None)
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_unconfirmed"
        assert registration.controller_outcome_checkpoint is checkpoint
        assert registration.controller_outcome_receipt is receipt
        raise _PostEffectRetentionTerminal

    with pytest.raises(_PostEffectRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_interrupted_abandonment)

    assert interruption_injected is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)
