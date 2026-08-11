from __future__ import annotations

import os
import pickle
import threading
from collections.abc import Callable
from copy import copy, deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as reader
from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from scripts.start_trusted_time_supervisor import (
    _acquire_trusted_time_launch_lock,
    _release_trusted_time_launch_lock,
)
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
