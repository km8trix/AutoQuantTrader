from __future__ import annotations

import ctypes
import dis
import gc
import hashlib
import inspect
import io
import json
import os
import pickle
import subprocess
import sys
import threading
from collections.abc import Callable
from copy import copy, deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Never, cast

import pytest

import scripts.trusted_time_post_enrollment_active_controller as active_controller
import scripts.trusted_time_post_enrollment_claimed_fence as claimed_fence
import scripts.trusted_time_post_enrollment_controller_outcome as controller_outcome
import scripts.trusted_time_post_enrollment_staging as staging
import scripts.trusted_time_post_enrollment_start as claim_persistence
import scripts.trusted_time_post_enrollment_topology_reader as reader
from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from scripts import trusted_time_post_enrollment_outcome as recovery_outcome
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT,
    LocalDockerDaemonIdentity,
    _acquire_trusted_time_launch_lock,
    _release_trusted_time_launch_lock,
)
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
    retain_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology import (
    post_enrollment_created_topology_network_name,
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
    bind_reviewed_create_outputs: bool = False,
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
    if bind_reviewed_create_outputs:
        _bind_reviewed_create_outputs_to_invocation(issuer, queued)
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


def test_reader_deadlines_are_exact_six_hundred_plus_five_second_tail() -> None:
    assert reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_SECONDS == 600
    assert reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS == 605
    assert (
        reader._POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_NANOSECONDS
        - reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
        == 5_000_000_000
    )


def test_lock_fileio_owner_closes_on_call_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    lock_path = ignored_root / "trusted-time" / "trusted-time-launch.lock"
    executable = tmp_path / "unreached-docker"
    fixtures._make_executable(executable)
    opened: list[int] = []
    real_open = reader._open_trusted_time_launch_lock_owner

    def tracked_open(*, path: Path, ignored_root: Path) -> io.FileIO:
        owner = real_open(path=path, ignored_root=ignored_root)
        opened.append(owner.fileno())
        return owner

    instructions = list(
        dis.get_instructions(
            reader.TrustedTimePostEnrollmentTopologyObservationIssuer._open_with_dependencies
        )
    )
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "lock_owner"
        and index > 0
        and instructions[index - 1].opname == "CALL"
    )
    store_offset = instructions[store_index].offset
    target_code = (
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer._open_with_dependencies.__code__
    )

    def interrupt_before_store(_: object, instruction_offset: int) -> None:
        if instruction_offset == store_offset:
            raise KeyboardInterrupt

    monkeypatch.setattr(reader, "_open_trusted_time_launch_lock_owner", tracked_open)
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, "trusted-time-reader-lock-test")
    interrupted = False
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
            reader.TrustedTimePostEnrollmentTopologyObservationIssuer._open_with_dependencies(
                expected_daemon_identity=LocalDockerDaemonIdentity(
                    context_name="<DOCKER_HOST>",
                    endpoint="unix:///tmp/unreached.sock",
                    daemon_id="LOCAL:DAEMON:1",
                ),
                docker_environment={},
                docker_executable=executable,
                lock_path=lock_path,
                ignored_root=ignored_root,
                runner=fixtures._QueuedRunner([]),
                session_token_factory=lambda: b"x" * 32,
            )
        except reader.TrustedTimePostEnrollmentTopologyReaderError:
            interrupted = True
    finally:
        sys.monitoring.set_local_events(tool_id, target_code, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)
    gc.collect()

    assert interrupted is True
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    descriptor = _acquire_trusted_time_launch_lock(
        path=lock_path,
        ignored_root=ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)


def test_authenticated_open_lost_return_releases_named_flock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A caller-side CALL/STORE interruption cannot be retained by the registry."""

    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    queued = fixtures._QueuedRunner([fixtures._json_line("LOCAL:DAEMON:1")])
    ignored_root = tmp_path / "artifacts"
    lock_path = ignored_root / "trusted-time" / "trusted-time-launch.lock"
    capability_registry = cast(
        dict[object, object],
        inspect.getclosurevars(reader._authenticated_issuer_capability_is_active).nonlocals[
            "active_capabilities"
        ],
    )
    registrations_before = len(capability_registry)

    def interrupted_caller() -> None:
        issuer = fixtures._public_open(
            monkeypatch,
            tmp_path,
            queued,
            socket_path,
            executable,
        )
        issuer.close()

    instructions = list(dis.get_instructions(interrupted_caller))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "issuer"
        and index > 0
        and instructions[index - 1].opname == "CALL"
    )
    store_offset = instructions[store_index].offset

    def interrupt_before_store(_: object, instruction_offset: int) -> None:
        if instruction_offset == store_offset:
            raise KeyboardInterrupt

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, "trusted-time-reader-open-return-test")
    try:
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            interrupt_before_store,
        )
        sys.monitoring.set_local_events(
            tool_id,
            interrupted_caller.__code__,
            sys.monitoring.events.INSTRUCTION,
        )
        with pytest.raises(KeyboardInterrupt):
            interrupted_caller()
    finally:
        sys.monitoring.set_local_events(tool_id, interrupted_caller.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)
    gc.collect()

    assert len(capability_registry) == registrations_before
    descriptor = _acquire_trusted_time_launch_lock(
        path=lock_path,
        ignored_root=ignored_root,
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


def _instruction_offset(
    callable_object: Callable[..., object],
    *,
    opname: str,
    argval: object,
    occurrence: Literal["first", "last"] = "first",
) -> int:
    """Locate one exact bytecode boundary used by async-interruption tests."""

    matching = [
        instruction.offset
        for instruction in dis.get_instructions(callable_object)
        if instruction.opname == opname and instruction.argval == argval
    ]
    assert matching
    return matching[0] if occurrence == "first" else matching[-1]


def _open_descriptor_count() -> int:
    descriptor_root = Path("/dev/fd") if Path("/dev/fd").is_dir() else Path("/proc/self/fd")
    return len(os.listdir(descriptor_root))


def _enable_instruction_interrupt(
    callable_object: Callable[..., object],
    offset: int,
    *,
    tool_name: str,
) -> int:
    """Raise once immediately before the selected instruction executes."""

    target_code = callable_object.__code__
    injected = False

    def interrupt(_: object, instruction_offset: int) -> None:
        nonlocal injected
        if not injected and instruction_offset == offset:
            injected = True
            raise KeyboardInterrupt

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, tool_name)
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target_code,
        sys.monitoring.events.INSTRUCTION,
    )
    return tool_id


def _disable_instruction_interrupt(
    tool_id: int,
    callable_object: Callable[..., object],
) -> None:
    sys.monitoring.set_local_events(tool_id, callable_object.__code__, 0)
    sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
    sys.monitoring.free_tool_id(tool_id)


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


def _interrupt_next_choreography_action_result_store(
    interruption_type: type[BaseException] = KeyboardInterrupt,
) -> Callable[[], None]:
    """Interrupt exactly after the recovery-retention callback CALL returns."""

    issuer_type = reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    target_code = issuer_type._run_authenticated_choreography_scope.__code__
    instructions = list(dis.get_instructions(target_code))
    target_offset = next(
        instruction.offset
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "result"
        and index > 0
        and instructions[index - 1].opname == "CALL"
    )
    return _interrupt_exact_instruction(
        target_code,
        target_offset,
        tool_name="trusted-time-terminal-action-return-test",
        interruption_type=interruption_type,
    )


def _interrupt_exact_instruction(
    target_code: Any,
    target_offset: int,
    *,
    tool_name: str,
    interruption_type: type[BaseException] = KeyboardInterrupt,
) -> Callable[[], None]:
    """Install one self-verifying instruction-boundary interruption."""

    injected = False
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, tool_name)

    def interrupt(code: object, instruction_offset: int) -> None:
        nonlocal injected
        if not injected and code is target_code and instruction_offset == target_offset:
            injected = True
            raise interruption_type

    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target_code,
        sys.monitoring.events.INSTRUCTION,
    )

    def close() -> None:
        sys.monitoring.set_local_events(tool_id, target_code, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)
        assert injected is True

    return close


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


def test_unbound_recovery_preparation_authenticates_exact_inert_tuple(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)

    def inspect(lease: object, capability: object) -> object:
        assert reader._authenticated_recovery_retention_is_available(
            issuer,
            capability,
            expected_state="unbound",
            choreography_lease=lease,
        )
        checkpoint = issuer._require_unbound_recovery_retention_preparation(
            lease,
            capability,
        )
        assert reader._authenticated_recovery_retention_is_available(
            issuer,
            capability,
            expected_state="unbound",
            choreography_lease=lease,
        )
        assert not reader._authenticated_recovery_retention_is_available(
            issuer,
            capability,
            expected_state="armed",
            artifact_directory=issuer._ignored_root / "trusted-time",
            ignored_root=issuer._ignored_root,
        )
        return checkpoint

    checkpoint = issuer._run_exclusive_choreography_with_recovery_retention(inspect)

    assert type(checkpoint) is reader._ChoreographyCheckpoint
    assert checkpoint.deadline_monotonic_ns - checkpoint.started_monotonic_ns == (
        reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    )
    assert issuer._poisoned is False
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_armed_query_is_read_only_across_live_pre_effect_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def inspect(lease: object, capability: object) -> tuple[bool, ...]:
        registration = _active_choreography_registration(issuer)

        def classify() -> bool:
            before = tuple(
                getattr(registration, name) for name in registration.__dataclass_fields__
            )
            poisoned_before = issuer._poisoned
            result = issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            assert (
                tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
                == before
            )
            assert issuer._poisoned is poisoned_before
            return result

        states = [classify()]
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        states.append(classify())
        binder._checkpoint(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        states.append(classify())
        binder(retained)
        states.append(classify())
        candidate = issuer._issue_post_effect_outcome_retention_candidate()
        issuer._transition_to_post_effect_outcome_retention(
            lease,
            capability,
            retained,
            post_effect_outcome_candidate=candidate,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        states.append(classify())
        return tuple(states)

    assert issuer._run_exclusive_choreography_with_recovery_retention(inspect) == (
        False,
        False,
        False,
        True,
        False,
    )
    assert issuer._poisoned is False
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_claim_persistence_interruption_before_o_excl_cannot_arm_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    ignored_root = issuer._ignored_root
    artifact_directory = ignored_root / "trusted-time"
    instructions = list(dis.get_instructions(claim_persistence.retain_post_enrollment_start_claim))
    descriptor_store_index = max(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST" and instruction.argval == "file_descriptor"
    )
    create_call = instructions[descriptor_store_index - 1]
    assert create_call.opname == "CALL"

    def interrupt_before_create(lease: object, capability: object) -> None:
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        tool_id = _enable_instruction_interrupt(
            claim_persistence.retain_post_enrollment_start_claim,
            create_call.offset,
            tool_name="trusted-time-claim-before-o-excl-test",
        )
        try:
            with pytest.raises(KeyboardInterrupt):
                claim_persistence.retain_post_enrollment_start_claim(
                    claim_fixtures._claim(),
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                    _retained_claim_binder=binder,
                )
        finally:
            _disable_instruction_interrupt(
                tool_id,
                claim_persistence.retain_post_enrollment_start_claim,
            )

        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "claim_admitted"
        assert registration.retained_claim is None
        assert registration.retained_claim_binding_sha256 is None
        assert registration.recovery_claim_binder is binder
        assert not (
            artifact_directory / claim_persistence.POST_ENROLLMENT_START_CLAIM_FILE_NAME
        ).exists()
        assert not issuer._recovery_outcome_retention_is_armed(
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(interrupt_before_create)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_durable_claim_call_to_staging_store_interruption_leaves_recovery_armed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    ignored_root = issuer._ignored_root
    artifact_directory = ignored_root / "trusted-time"
    approval = claim_fixtures._approval()
    reauthentication_issuer = claim_fixtures._Issuer(claim_fixtures._observed_postcondition())
    monkeypatch.setattr(
        staging,
        "load_confirmed_first_enrollment_evidence",
        lambda **_: approval.confirmed_enrollment,
    )
    retained_store = _instruction_offset(
        staging.prepare_post_enrollment_start_release_under_lock,
        opname="STORE_FAST",
        argval="retained",
    )

    def interrupt_caller_store(lease: object, capability: object) -> None:
        binder = _issue_registered_recovery_claim_binder(
            issuer,
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        tool_id = _enable_instruction_interrupt(
            staging.prepare_post_enrollment_start_release_under_lock,
            retained_store,
            tool_name="trusted-time-durable-claim-caller-store-test",
        )
        try:
            with pytest.raises(staging.TrustedTimePostEnrollmentStartClaimedRecoveryRequired):
                staging.prepare_post_enrollment_start_release_under_lock(
                    approval=approval,
                    expected_approval_sha256=approval.approval_sha256,
                    supervisor_container_id=claim_fixtures.SUPERVISOR_CONTAINER_ID,
                    reauthentication_issuer=reauthentication_issuer,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                    _retained_claim_binder=binder,
                )
        finally:
            _disable_instruction_interrupt(
                tool_id,
                staging.prepare_post_enrollment_start_release_under_lock,
            )

        registration = _active_choreography_registration(issuer)
        retained = registration.retained_claim
        assert registration.retention_state == "armed"
        assert registration.action_active is True
        assert type(retained) is RetainedTrustedTimePostEnrollmentStartClaim
        assert registration.recovery_claim_binder is None
        assert claim_persistence.revalidate_retained_post_enrollment_start_claim(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert issuer._recovery_outcome_retention_is_armed(
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        raise _RecoveryRetentionTerminal

    with pytest.raises(_RecoveryRetentionTerminal):
        issuer._run_exclusive_choreography_with_recovery_retention(interrupt_caller_store)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize(
    "binding_store",
    [
        "last_monotonic_ns",
        "retained_claim",
        "retained_claim_binding_sha256",
        "artifact_directory",
        "ignored_root",
        "retention_state",
    ],
)
def test_interruption_before_internal_binding_commit_never_exposes_armed_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    binding_store: str,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    bind_recovery_retention = cast(
        Callable[..., object],
        inspect.getclosurevars(reader._consume_authenticated_recovery_claim_binder).nonlocals[
            "bind_recovery_retention"
        ],
    )
    store_offset = _instruction_offset(
        bind_recovery_retention,
        opname="STORE_ATTR",
        argval=binding_store,
        occurrence="last",
    )

    def interrupt_internal_store(lease: object, capability: object) -> str:
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
        tool_id = _enable_instruction_interrupt(
            bind_recovery_retention,
            store_offset,
            tool_name=f"trusted-time-binding-{binding_store}-test",
        )
        try:
            with pytest.raises(
                reader.TrustedTimePostEnrollmentTopologyReaderError,
                match="recovery claim binder is unavailable",
            ):
                binder(retained)
        finally:
            _disable_instruction_interrupt(tool_id, bind_recovery_retention)

        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "revoked"
        assert registration.action_active is False
        assert registration.recovery_claim_binder is None
        assert issuer._poisoned is True
        try:
            armed = issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except reader.TrustedTimePostEnrollmentTopologyReaderError:
            pass
        else:
            assert armed is False
        return "must not escape"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(interrupt_internal_store)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_interruption_after_bind_before_return_preserves_exact_armed_recovery(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    monitored = cast(
        Callable[..., object],
        reader._consume_authenticated_recovery_claim_binder,
    )
    instructions = list(dis.get_instructions(monitored))
    bind_load_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "LOAD_DEREF" and instruction.argval == "bind_recovery_retention"
    )
    bind_call_index = next(
        index
        for index in range(bind_load_index + 1, len(instructions))
        if instructions[index].opname == "CALL"
    )
    interrupt_offset = instructions[bind_call_index + 1].offset

    def interrupt_after_commit(lease: object, capability: object) -> str:
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
        tool_id = _enable_instruction_interrupt(
            monitored,
            interrupt_offset,
            tool_name="trusted-time-binding-after-bind-test",
        )
        try:
            with pytest.raises(
                reader.TrustedTimePostEnrollmentTopologyReaderError,
                match="recovery claim binder is unavailable",
            ):
                binder(retained)
        finally:
            _disable_instruction_interrupt(tool_id, monitored)

        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "armed"
        assert registration.action_active is False
        assert registration.retained_claim is retained
        assert registration.recovery_claim_binder is None
        assert issuer._poisoned is True
        assert claim_persistence.revalidate_retained_post_enrollment_start_claim(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        assert issuer._recovery_outcome_retention_is_armed(
            lease,
            capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return "must not escape"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(interrupt_after_commit)

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_armed_query_returns_false_for_consuming_and_terminal_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    classifications: list[bool] = []

    def consume_then_abandon(lease: object, capability: object) -> None:
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
        registration = _active_choreography_registration(issuer)
        before = tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
        classifications.append(
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )
        assert (
            tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
            == before
        )
        issuer._abandon_recovery_outcome_retention(capability, checkpoint)
        before = tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
        classifications.append(
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )
        assert (
            tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
            == before
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(consume_then_abandon)

    assert classifications == [False, False]
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_armed_query_recognizes_armed_escape_after_action_poison(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    classifications: list[bool] = []

    def poison_after_arming(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with issuer._lifecycle_lock:
            issuer._poison_locked()
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "armed"
        assert registration.action_active is False
        before = tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
        classifications.append(
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )
        assert (
            tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
            == before
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(poison_after_arming)

    assert classifications == [True]
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_armed_query_returns_false_for_post_effect_terminal_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    classifications: list[bool] = []

    def retain_controller_outcome(lease: object, capability: object) -> None:
        post_effect_capability = _transition_registered_post_effect_retention(
            issuer,
            lease,
            capability,
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
        classifications.append(
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )
        retained_outcome_receipt = object()
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            retained_outcome_receipt,
        )
        classifications.append(
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )
        issuer._abandon_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            retained_outcome_receipt,
        )
        classifications.append(
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(retain_controller_outcome)

    assert classifications == [False, False, False]
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_armed_query_rejects_forged_or_inconsistent_tuple_without_poison(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    artifact_directory = issuer._ignored_root / "trusted-time"
    ignored_root = issuer._ignored_root

    def inspect(lease: object, capability: object) -> None:
        registration = _active_choreography_registration(issuer)

        def rejected(candidate_lease: object, candidate_capability: object) -> None:
            before = tuple(
                getattr(registration, name) for name in registration.__dataclass_fields__
            )
            with pytest.raises(
                reader.TrustedTimePostEnrollmentTopologyReaderError,
                match="recovery retention state is unavailable",
            ):
                issuer._recovery_outcome_retention_is_armed(
                    candidate_lease,
                    candidate_capability,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            assert (
                tuple(getattr(registration, name) for name in registration.__dataclass_fields__)
                == before
            )
            assert issuer._poisoned is False

        rejected(object(), capability)
        rejected(lease, object())
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="recovery retention state is unavailable",
        ):
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=tmp_path / "forged-root" / "trusted-time",
                ignored_root=tmp_path / "forged-root",
            )
        assert issuer._poisoned is False

        corruptions = (
            (registration, "lock_identity", (0, 0, 0, 0, 0)),
            (issuer, "_choreography_scope_nonce", object()),
            (registration, "retention_state", "impossible"),
            (registration, "artifact_directory", artifact_directory),
        )
        for target, attribute, forged in corruptions:
            original = getattr(target, attribute)
            setattr(target, attribute, forged)
            try:
                with pytest.raises(
                    reader.TrustedTimePostEnrollmentTopologyReaderError,
                    match="recovery retention state is unavailable",
                ):
                    issuer._recovery_outcome_retention_is_armed(
                        lease,
                        capability,
                        artifact_directory=artifact_directory,
                        ignored_root=ignored_root,
                    )
                assert getattr(target, attribute) is forged
                assert issuer._poisoned is False
            finally:
                setattr(target, attribute, original)

    issuer._run_exclusive_choreography_with_recovery_retention(inspect)
    assert issuer._poisoned is False
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_recovery_armed_query_rejects_foreign_thread_without_poison(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    artifact_directory = issuer._ignored_root / "trusted-time"
    ignored_root = issuer._ignored_root

    def inspect(lease: object, capability: object) -> None:
        failures: list[BaseException] = []

        def foreign_query() -> None:
            try:
                issuer._recovery_outcome_retention_is_armed(
                    lease,
                    capability,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=foreign_query)
        worker.start()
        worker.join()
        assert len(failures) == 1
        assert type(failures[0]) is reader.TrustedTimePostEnrollmentTopologyReaderError
        assert issuer._poisoned is False
        assert (
            issuer._recovery_outcome_retention_is_armed(
                lease,
                capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            is False
        )

    issuer._run_exclusive_choreography_with_recovery_retention(inspect)
    assert issuer._poisoned is False
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("forged_member", ["lease", "capability"])
def test_unbound_recovery_preparation_rejects_every_forged_tuple_member(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    forged_member: str,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)

    def reject(lease: object, capability: object) -> None:
        issuer._require_unbound_recovery_retention_preparation(
            object() if forged_member == "lease" else lease,
            object() if forged_member == "capability" else capability,
        )

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="unbound recovery preparation is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject)

    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_unbound_recovery_preparation_rejects_foreign_thread(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    errors: list[BaseException] = []

    def reject_foreign_thread(lease: object, capability: object) -> None:
        def worker() -> None:
            try:
                issuer._require_unbound_recovery_retention_preparation(lease, capability)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_foreign_thread)

    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_unbound_recovery_preparation_rejects_at_exact_action_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    started = 7_000_000_000
    deadline = started + reader._POST_ENROLLMENT_START_CHOREOGRAPHY_DEADLINE_NANOSECONDS
    clock = _MonotonicClock([started, started + 1, deadline])
    issuer, _ = _open_issuer(monkeypatch, tmp_path, monotonic_clock=clock)

    def reject_at_deadline(lease: object, capability: object) -> None:
        issuer._require_unbound_recovery_retention_preparation(lease, capability)

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="unbound recovery preparation is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_at_deadline)

    assert clock.calls == [started, started + 1, deadline]
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_unbound_recovery_preparation_revalidates_lock_after_deadline_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    validation_calls = 0

    def reject_second_validation(lease: object, capability: object) -> None:
        nonlocal validation_calls
        issuer_type = type(issuer)
        original_validate_lock = issuer_type._validate_lock

        def fail_fourth(
            candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        ) -> None:
            nonlocal validation_calls
            validation_calls += 1
            if validation_calls == 4:
                raise OSError("lock identity changed after the second checkpoint")
            original_validate_lock(candidate)

        with monkeypatch.context() as scoped:
            scoped.setattr(issuer_type, "_validate_lock", fail_fourth)
            issuer._require_unbound_recovery_retention_preparation(lease, capability)

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="unbound recovery preparation is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_second_validation)

    assert validation_calls == 4
    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_unbound_recovery_preparation_rejects_claim_armed_capability(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)

    def reject_armed(lease: object, capability: object) -> None:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._require_unbound_recovery_retention_preparation(lease, capability)

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="unbound recovery preparation is unavailable",
    ):
        issuer._run_exclusive_choreography_with_recovery_retention(reject_armed)

    assert issuer._poisoned is True
    _close_and_assert_launch_lock_is_reacquirable(issuer)


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

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained):
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

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained):
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

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained):
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

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained):
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

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained):
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


def test_retention_crossing_605_is_unconfirmed_and_preserves_possible_outcome(
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

    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained):
        issuer._run_exclusive_choreography_with_recovery_retention(recover_after_close)

    assert clock.calls == values
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


class _PostEffectRetentionTerminal(BaseException):
    pass


class _CustomAsyncTerminalInterruption(BaseException):
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
    monkeypatch.setattr(
        controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
        "__post_init__",
        lambda _self: None,
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


@pytest.mark.parametrize("outcome_kind", ["success", "failure"])
@pytest.mark.parametrize(
    "interruption_type",
    [KeyboardInterrupt, _CustomAsyncTerminalInterruption],
)
def test_action_call_store_interruption_adopts_exact_durable_controller_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outcome_kind: str,
    interruption_type: type[BaseException],
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = (
        _confirmed_controller_receipt(artifact_directory)
        if outcome_kind == "success"
        else _recovery_controller_receipt(artifact_directory)
    )
    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda candidate, **_: candidate is receipt,
    )
    if outcome_kind == "failure":
        monkeypatch.setattr(
            controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
            "__post_init__",
            lambda _self: None,
        )

    def completed_action(lease: object, recovery_capability: object) -> object:
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
            outcome_kind=cast(Literal["success", "failure"], outcome_kind),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_post_effect_controller_outcome_retention(
            post_effect_capability,
            checkpoint,
            receipt,
        )
        return receipt

    close_monitor = _interrupt_next_choreography_action_result_store(interruption_type)
    try:
        if outcome_kind == "success":
            returned = issuer._run_exclusive_choreography_with_recovery_retention(completed_action)
            assert returned is receipt
        else:
            with pytest.raises(
                active_controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
            ) as terminal:
                issuer._run_exclusive_choreography_with_recovery_retention(completed_action)
            assert terminal.value.retained_outcome is receipt
    finally:
        close_monitor()

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_outer_scope_retries_one_async_interruption_inside_exact_adopter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = _confirmed_controller_receipt(artifact_directory)
    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda candidate, **_: candidate is receipt,
    )
    real_adopt = reader.TrustedTimePostEnrollmentTopologyObservationIssuer.__dict__[
        "_adopt_registered_confirmed_terminal_outcome"
    ]
    adoption_attempts = 0

    def interrupt_once(candidate: object, *args: object, **kwargs: object) -> object:
        nonlocal adoption_attempts
        assert candidate is issuer
        adoption_attempts += 1
        if adoption_attempts == 1:
            raise KeyboardInterrupt
        return real_adopt(candidate, *args, **kwargs)

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_adopt_registered_confirmed_terminal_outcome",
        interrupt_once,
    )

    def complete_then_fail(lease: object, recovery_capability: object) -> Never:
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
        raise _CustomAsyncTerminalInterruption

    returned = issuer._run_exclusive_choreography_with_recovery_retention(complete_then_fail)

    assert returned is receipt
    assert adoption_attempts == 2
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_action_call_store_interruption_adopts_exact_durable_legacy_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    expected: recovery_outcome.RetainedTrustedTimePostEnrollmentStartOutcome | None = None

    def completed_action(lease: object, recovery_capability: object) -> object:
        nonlocal expected
        _bind_registered_recovery_claim(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            recovery_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        expected = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._complete_recovery_outcome_retention(
            recovery_capability,
            checkpoint,
            expected,
        )
        return expected

    close_monitor = _interrupt_next_choreography_action_result_store()
    try:
        with pytest.raises(
            recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained
        ) as terminal:
            issuer._run_exclusive_choreography_with_recovery_retention(completed_action)
    finally:
        close_monitor()

    assert expected is not None
    assert terminal.value.retained_outcome is expected
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_legacy_helper_complete_call_return_interruption_adopts_exact_registered_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    target_code = recovery_outcome.retain_post_enrollment_start_recovery_required_outcome.__code__
    instructions = list(dis.get_instructions(target_code))
    load_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "LOAD_ATTR"
        and instruction.argval == "_complete_recovery_outcome_retention"
    )
    call_index = next(
        index
        for index in range(load_index + 1, len(instructions))
        if instructions[index].opname == "CALL"
    )
    assert instructions[call_index + 1].opname == "POP_TOP"

    def retain_via_helper(lease: object, recovery_capability: object) -> Never:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        recovery_outcome.retain_post_enrollment_start_recovery_required_outcome(
            topology_issuer=issuer,
            recovery_retention_capability=recovery_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    close_monitor = _interrupt_exact_instruction(
        target_code,
        instructions[call_index + 1].offset,
        tool_name="trusted-time-legacy-complete-return-test",
    )
    try:
        with pytest.raises(
            recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained
        ) as terminal:
            issuer._run_exclusive_choreography_with_recovery_retention(retain_via_helper)
    finally:
        close_monitor()

    assert terminal.value.retained_outcome.operation_id == retained.operation_id
    assert recovery_outcome.revalidate_retained_post_enrollment_start_outcome(
        terminal.value.retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_legacy_registry_receipt_store_interruption_repairs_exact_confirmed_tuple(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    target_code = reader._complete_authenticated_recovery_retention.__code__
    instructions = list(dis.get_instructions(target_code))
    receipt_store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "recovery_outcome_receipt"
    )
    state_store = next(
        instruction
        for instruction in instructions[receipt_store_index + 1 :]
        if instruction.opname == "STORE_ATTR" and instruction.argval == "retention_state"
    )

    def complete_then_interrupt(lease: object, recovery_capability: object) -> Never:
        _bind_registered_recovery_claim(
            issuer,
            lease,
            recovery_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = issuer._begin_recovery_outcome_retention(
            recovery_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        exact_receipt = _persist_recovery_outcome(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._complete_recovery_outcome_retention(
                recovery_capability,
                checkpoint,
                exact_receipt,
            )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "confirmed"
        assert registration.recovery_outcome_receipt is exact_receipt
        raise KeyboardInterrupt

    close_monitor = _interrupt_exact_instruction(
        target_code,
        state_store.offset,
        tool_name="trusted-time-legacy-registry-commit-test",
    )
    try:
        with pytest.raises(
            recovery_outcome.TrustedTimePostEnrollmentStartRecoveryOutcomeRetained
        ) as terminal:
            issuer._run_exclusive_choreography_with_recovery_retention(complete_then_interrupt)
    finally:
        close_monitor()

    assert recovery_outcome.revalidate_retained_post_enrollment_start_outcome(
        terminal.value.retained_outcome,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize("outcome_kind", ["success", "failure"])
def test_controller_registry_return_interruption_preserves_exact_confirmed_tuple(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outcome_kind: str,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    receipt = (
        _confirmed_controller_receipt(artifact_directory)
        if outcome_kind == "success"
        else _recovery_controller_receipt(artifact_directory)
    )
    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda candidate, **_: candidate is receipt,
    )
    if outcome_kind == "failure":
        monkeypatch.setattr(
            controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
            "__post_init__",
            lambda _self: None,
        )
    target_code = reader._complete_authenticated_post_effect_controller_outcome_retention.__code__
    instructions = list(dis.get_instructions(target_code))
    action_store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "action_active"
    )
    return_instruction = next(
        instruction
        for instruction in instructions[action_store_index + 1 :]
        if instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
    )

    def complete_then_adopt(lease: object, recovery_capability: object) -> Never:
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
            outcome_kind=cast(Literal["success", "failure"], outcome_kind),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._complete_post_effect_controller_outcome_retention(
                post_effect_capability,
                checkpoint,
                receipt,
            )
        registration = _active_choreography_registration(issuer)
        assert registration.retention_state == "post_effect_confirmed"
        assert registration.controller_outcome_receipt is receipt
        assert (
            issuer._adopt_registered_confirmed_terminal_outcome(
                lease,
                recovery_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            is receipt
        )
        raise KeyboardInterrupt

    close_monitor = _interrupt_exact_instruction(
        target_code,
        return_instruction.offset,
        tool_name="trusted-time-controller-registry-return-test",
    )
    try:
        if outcome_kind == "success":
            returned = issuer._run_exclusive_choreography_with_recovery_retention(
                complete_then_adopt
            )
            assert returned is receipt
        else:
            with pytest.raises(
                active_controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
            ) as terminal:
                issuer._run_exclusive_choreography_with_recovery_retention(complete_then_adopt)
            assert terminal.value.retained_outcome is receipt
    finally:
        close_monitor()

    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_current_scope_registry_never_substitutes_a_presented_prior_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    current = _confirmed_controller_receipt(artifact_directory)
    prior = _recovery_controller_receipt(artifact_directory)
    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda candidate, **_: candidate is current,
    )
    monkeypatch.setattr(
        controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
        "__post_init__",
        lambda _self: None,
    )

    def present_prior(lease: object, recovery_capability: object) -> Never:
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
            current,
        )
        raise active_controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired(
            prior
        )

    returned = issuer._run_exclusive_choreography_with_recovery_retention(present_prior)
    assert returned is current
    assert returned is not prior
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_current_scope_adopter_rejects_a_forged_registered_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    retained, artifact_directory, ignored_root = _retain_claim_for_issuer(issuer)
    current = _confirmed_controller_receipt(artifact_directory)
    monkeypatch.setattr(
        controller_outcome,
        "revalidate_retained_post_enrollment_start_controller_outcome",
        lambda candidate, **_: candidate is current,
    )

    def forge_after_completion(lease: object, recovery_capability: object) -> Never:
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
            current,
        )
        _active_choreography_registration(issuer).controller_outcome_receipt = object()
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        issuer._run_exclusive_choreography_with_recovery_retention(forge_after_completion)

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

    assert revalidated == ([receipt] if failure == "wrong_identity" else [receipt, receipt])
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
    monkeypatch.setattr(
        controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
        "__post_init__",
        lambda _self: None,
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

    with pytest.raises(
        active_controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
    ) as terminal:
        issuer._run_exclusive_choreography_with_recovery_retention(retain_failure)

    assert terminal.value.retained_outcome is receipt
    assert revalidated == [receipt, receipt]
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

    if failure == "wrong_identity":
        monkeypatch.setattr(
            controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
            "__post_init__",
            lambda _self: None,
        )
        with pytest.raises(
            active_controller.TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired
        ) as terminal:
            issuer._run_exclusive_choreography_with_recovery_retention(reject_false_failure)
        assert terminal.value.retained_outcome is receipt
    else:
        with pytest.raises(_PostEffectRetentionTerminal):
            issuer._run_exclusive_choreography_with_recovery_retention(reject_false_failure)

    expected_revalidations = {
        "wrong_identity": [receipt],
        "revalidation": [receipt, receipt],
        "registry": [receipt],
    }
    assert revalidated == expected_revalidations.get(failure, [])
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


def _reviewed_mutation_arguments(
    paths: tuple[Path, Path, Path, Path],
    compose_payload: bytes,
) -> dict[str, object]:
    for path, payload in zip(
        paths,
        (b"database", b"authority", b"auth-secret", b"s" * 32),
        strict=True,
    ):
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if not path.exists():
            path.write_bytes(payload)
            path.chmod(0o400)
    return {
        **fixtures._issue_arguments(paths),
        "compose_payload": compose_payload,
    }


def _reviewed_prepare_arguments(
    paths: tuple[Path, Path, Path, Path],
    compose_payload: bytes,
) -> dict[str, object]:
    arguments = _reviewed_mutation_arguments(paths, compose_payload)
    database_secret, head_anchor_inputs = reader._snapshot_reviewed_staged_input_receipts(paths)
    arguments.update(
        {
            "database_secret_receipt": database_secret,
            "head_anchor_inputs_receipt": head_anchor_inputs,
        }
    )
    return arguments


def _drift_staged_input(path: Path, drift: str) -> None:
    if drift == "same_bytes_replacement":
        replacement = path.with_name(path.name + ".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o400)
        original_inode = path.stat().st_ino
        path.unlink()
        replacement.rename(path)
        assert path.stat().st_ino != original_inode
    elif drift == "removal":
        path.unlink()
    elif drift == "content":
        original = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(bytes(byte ^ 0xFF for byte in original))
        path.chmod(0o400)
    elif drift == "mode":
        path.chmod(0o600)
    else:  # pragma: no cover - test helper is closed above
        raise AssertionError("unsupported staged-input drift")


_REVIEWED_COMPOSE_PAYLOAD = b"""name: autoquanttrader-trusted-time
services:
  chrony-nts:
    image: source
  trusted-time-supervisor:
    image: supervisor
"""


def _bind_reviewed_create_outputs_to_invocation(
    issuer: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    queued: fixtures._QueuedRunner,
    *,
    bind_containers: bool = True,
    bind_network: bool = True,
) -> None:
    bound_containers = 0
    bound_networks = 0
    expected_network_name = post_enrollment_created_topology_network_name(issuer._session_sha256)
    for index, output in enumerate(queued.outputs):
        if type(output) is not bytes or not output.endswith(b"\n"):
            continue
        try:
            value = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if type(value) is not dict:
            continue
        configuration = value.get("Config")
        labels = configuration.get("Labels") if type(configuration) is dict else None
        if (
            bind_containers
            and type(labels) is dict
            and labels.get("com.docker.compose.service")
            in {"chrony-nts", "trusted-time-supervisor"}
        ):
            labels[reader._REVIEWED_CREATE_INVOCATION_LABEL] = issuer._session_sha256
            queued.outputs[index] = fixtures._json_line(value)
            bound_containers += 1
            continue
        network_labels = value.get("Labels")
        if (
            bind_network
            and value.get("Name") == expected_network_name
            and type(network_labels) is dict
            and network_labels.get("com.docker.compose.network") == "default"
        ):
            network_labels[reader._REVIEWED_CREATE_INVOCATION_LABEL] = issuer._session_sha256
            queued.outputs[index] = fixtures._json_line(value)
            bound_networks += 1
    if (bind_containers and bound_containers < 1) or (bind_network and bound_networks < 1):
        raise AssertionError("reviewed create outputs were unavailable")


def _reviewed_teardown_container(
    state: Literal["created", "staged_unreleased"],
    service: Literal["chrony-nts", "trusted-time-supervisor"],
) -> dict[str, object]:
    container = deepcopy(fixtures._container(state, service))
    image_id = fixtures.SOURCE_IMAGE_ID if service == "chrony-nts" else fixtures.SUPERVISOR_IMAGE_ID
    container["Image"] = image_id
    configuration = cast(dict[str, object], container["Config"])
    configuration["Image"] = image_id
    return container


def _reviewed_teardown_authentication_outputs(
    *,
    state: Literal["created", "staged_unreleased"] = "created",
    services: tuple[
        Literal["chrony-nts", "trusted-time-supervisor"],
        ...,
    ] = ("chrony-nts", "trusted-time-supervisor"),
) -> list[bytes]:
    ids = {
        "chrony-nts": fixtures.SOURCE_CONTAINER_ID,
        "trusted-time-supervisor": fixtures.SUPERVISOR_CONTAINER_ID,
    }
    inventory = b"".join(fixtures._json_line(ids[service]) for service in services)
    network = deepcopy(fixtures._network(state))
    if state == "staged_unreleased":
        network_containers = cast(dict[str, object], network["Containers"])
        network["Containers"] = {
            container_id: value
            for container_id, value in network_containers.items()
            if container_id in {ids[service] for service in services}
        }
    return [
        inventory,
        fixtures._json_line({"Config": {}, "Id": fixtures.SOURCE_IMAGE_ID}),
        fixtures._json_line({"Config": {}, "Id": fixtures.SUPERVISOR_IMAGE_ID}),
        *(
            fixtures._json_line(_reviewed_teardown_container(state, service))
            for service in services
        ),
        fixtures._json_line(network),
        inventory,
    ]


def test_split_reviewed_creation_finishes_inert_work_before_one_shot_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    fixtures._install_pure_validator_stubs(
        monkeypatch,
        endpoint=f"unix://{socket_path}",
    )
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", b"", *fixtures._state_outputs("created")],
        bind_reviewed_create_outputs=True,
    )
    events: list[str] = []
    issuer_type = reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    original_material = issuer_type._reviewed_mutation_material
    original_empty = issuer_type._run_exact_empty_precreate_observation
    original_transform = issuer_type._reviewed_compose_create_payload
    original_prepare_fence = reader._reviewed_staged_input_seals_from_materialized_receipts
    original_execute_fence = reader._revalidate_reviewed_staged_input_seals
    original_mutation = issuer_type._run_reviewed_mutation_command

    def track_material(*args: Any, **kwargs: Any) -> tuple[str, dict[str, str]]:
        events.append("binding")
        return original_material(*args, **kwargs)

    def track_empty(*args: Any, **kwargs: Any) -> None:
        events.append("empty_observation")
        original_empty(*args, **kwargs)

    def track_transform(*args: Any, **kwargs: Any) -> bytes:
        events.append("compose_transform")
        return original_transform(*args, **kwargs)

    def track_prepare_fence(*args: Any, **kwargs: Any) -> object:
        events.append("prepare_input_fence")
        return original_prepare_fence(*args, **kwargs)

    def track_execute_fence(*args: Any, **kwargs: Any) -> None:
        events.append("execute_input_fence")
        original_execute_fence(*args, **kwargs)

    def track_mutation(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        events.append("docker_create")
        return original_mutation(*args, **kwargs)

    monkeypatch.setattr(issuer_type, "_reviewed_mutation_material", track_material)
    monkeypatch.setattr(issuer_type, "_run_exact_empty_precreate_observation", track_empty)
    monkeypatch.setattr(issuer_type, "_reviewed_compose_create_payload", track_transform)
    monkeypatch.setattr(
        reader,
        "_reviewed_staged_input_seals_from_materialized_receipts",
        track_prepare_fence,
    )
    monkeypatch.setattr(reader, "_revalidate_reviewed_staged_input_seals", track_execute_fence)
    monkeypatch.setattr(issuer_type, "_run_reviewed_mutation_command", track_mutation)

    def run(lease: object) -> None:
        prepared = issuer._prepare_reviewed_topology_creation(
            **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        assert type(prepared) is reader._TrustedTimePostEnrollmentPreparedReviewedTopologyCreation
        assert issuer._reviewed_mutation_state == "prepared"
        registration = issuer._reviewed_mutation_prepared_registration
        assert type(registration) is reader._PreparedReviewedTopologyCreationRegistration
        assert tuple(seal.path for seal in registration.staged_input_seals) == paths
        assert tuple(seal.sha256 for seal in registration.staged_input_seals) == tuple(
            hashlib.sha256(payload).hexdigest()
            for payload in (b"database", b"authority", b"auth-secret", b"s" * 32)
        )
        assert all(
            not hasattr(seal, "payload") and not hasattr(seal, "content")
            for seal in registration.staged_input_seals
        )
        assert events == [
            "binding",
            "empty_observation",
            "prepare_input_fence",
            "compose_transform",
        ]
        assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
        for operation in (
            lambda: copy(prepared),
            lambda: deepcopy(prepared),
            lambda: pickle.dumps(prepared),
        ):
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                operation()

        created = issuer._execute_prepared_reviewed_topology_creation(
            prepared,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "created"
        assert events == [
            "binding",
            "empty_observation",
            "prepare_input_fence",
            "compose_transform",
            "execute_input_fence",
            "docker_create",
        ]
        observed_call_count = len(queued.calls)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="prepared reviewed topology creation is unavailable",
        ):
            issuer._execute_prepared_reviewed_topology_creation(
                prepared,
                _choreography_lease=lease,
            )
        assert len(queued.calls) == observed_call_count
        assert created is issuer._reviewed_mutation_created_observation

    issuer._run_exclusive_choreography(run)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_created_truth_is_one_atomic_registration_across_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    fixtures._install_pure_validator_stubs(
        monkeypatch,
        endpoint=f"unix://{socket_path}",
    )
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", b"", *fixtures._state_outputs("created")],
        bind_reviewed_create_outputs=True,
    )
    issuer_type = reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    execute = issuer_type._execute_prepared_reviewed_topology_creation
    interrupt_offset = _instruction_offset(
        execute,
        opname="STORE_ATTR",
        argval="_reviewed_mutation_state",
        occurrence="last",
    )

    def run(lease: object) -> None:
        prepared = issuer._prepare_reviewed_topology_creation(
            **_reviewed_prepare_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        tool_id = _enable_instruction_interrupt(
            execute,
            interrupt_offset,
            tool_name="trusted-time-created-registration-store-test",
        )
        try:
            with pytest.raises(KeyboardInterrupt):
                issuer._execute_prepared_reviewed_topology_creation(
                    prepared,
                    _choreography_lease=lease,
                )
        finally:
            _disable_instruction_interrupt(tool_id, execute)

        registration = issuer._reviewed_mutation_created_registration
        assert type(registration) is reader._ReviewedCreatedTopologyRegistration
        assert issuer._reviewed_mutation_state == "create_effected"
        assert issuer._reviewed_mutation_created_observation is registration.observation
        assert (
            issuer._reviewed_mutation_created_observation_sha256
            == registration.observation_sha256
            == registration.observation.observation_sha256
        )
        assert registration.staged_input_sha256s == tuple(
            hashlib.sha256(payload).hexdigest()
            for payload in (b"database", b"authority", b"auth-secret", b"s" * 32)
        )

    issuer._run_exclusive_choreography(run)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_staged_input_file_descriptor_owner_closes_on_call_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    opened_descriptors: list[int] = []
    real_open = reader._open_reviewed_staged_input_owner

    def tracked_open(
        file_name: str,
        *,
        directory_descriptor: int,
    ) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(
            file_name,
            directory_descriptor=directory_descriptor,
        )
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(reader, "_open_reviewed_staged_input_owner", tracked_open)
    observe = reader._observe_reviewed_staged_input_seal
    interrupt_offset = _instruction_offset(
        observe,
        opname="STORE_FAST",
        argval="file_owner",
        occurrence="last",
    )
    tool_id = _enable_instruction_interrupt(
        observe,
        interrupt_offset,
        tool_name="trusted-time-staged-input-file-owner-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            observe(paths[0])
    finally:
        _disable_instruction_interrupt(tool_id, observe)
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_staged_input_directory_owner_closes_on_call_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    opened_descriptors: list[int] = []
    real_open = reader._open_reviewed_staged_input_directory_owner

    def tracked_open(path: Path) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(path)
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(
        reader,
        "_open_reviewed_staged_input_directory_owner",
        tracked_open,
    )
    observe = reader._observe_reviewed_staged_input_seal
    interrupt_offset = _instruction_offset(
        observe,
        opname="STORE_FAST",
        argval="directory_owner",
        occurrence="last",
    )
    tool_id = _enable_instruction_interrupt(
        observe,
        interrupt_offset,
        tool_name="trusted-time-staged-input-directory-owner-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            observe(paths[0])
    finally:
        _disable_instruction_interrupt(tool_id, observe)
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_staged_input_directory_libc_owner_closes_inside_wrapper_call_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    opened_descriptors: list[int] = []
    real_open = reader._REVIEWED_DESCRIPTOR_OPEN

    def tracked_open(*arguments: object) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(*arguments)
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(reader, "_REVIEWED_DESCRIPTOR_OPEN", tracked_open)
    wrapper = reader._open_reviewed_staged_input_directory_owner
    interrupt_offset = _instruction_offset(
        wrapper,
        opname="STORE_FAST",
        argval="owner",
    )
    tool_id = _enable_instruction_interrupt(
        wrapper,
        interrupt_offset,
        tool_name="trusted-time-staged-input-directory-libc-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            wrapper(paths[0].parent)
    finally:
        _disable_instruction_interrupt(tool_id, wrapper)
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_reviewed_descriptor_owner_close_retries_one_shot_call_interruption(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "reviewed"
    directory.mkdir(mode=0o700)
    owner = reader._open_reviewed_staged_input_directory_owner(directory)
    descriptor = owner.fileno()
    close = reader._ReviewedStagedInputDescriptorOwner.close
    instructions = list(dis.get_instructions(close))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "value"
    )
    interrupt_offset = instructions[store_index + 1].offset
    tool_id = _enable_instruction_interrupt(
        close,
        interrupt_offset,
        tool_name="trusted-time-reviewed-descriptor-close-retry-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            owner.close()
    finally:
        _disable_instruction_interrupt(tool_id, close)

    assert owner.value == -1
    with pytest.raises(OSError):
        os.fstat(descriptor)
    owner.close()


def test_staged_input_file_libc_owner_closes_inside_wrapper_call_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    directory_owner = reader._open_reviewed_staged_input_directory_owner(paths[0].parent)
    opened_descriptors: list[int] = []
    real_open = reader._REVIEWED_DESCRIPTOR_OPENAT

    def tracked_open(*arguments: object) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(*arguments)
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(reader, "_REVIEWED_DESCRIPTOR_OPENAT", tracked_open)
    wrapper = reader._open_reviewed_staged_input_owner
    interrupt_offset = _instruction_offset(
        wrapper,
        opname="STORE_FAST",
        argval="owner",
    )
    tool_id = _enable_instruction_interrupt(
        wrapper,
        interrupt_offset,
        tool_name="trusted-time-staged-input-file-libc-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            wrapper(
                paths[0].name,
                directory_descriptor=directory_owner.fileno(),
            )
    finally:
        _disable_instruction_interrupt(tool_id, wrapper)
        directory_owner.close()
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_host_retirement_root_owner_closes_on_call_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    observe = reader._observe_host_retirements
    interrupt_offset = _instruction_offset(
        observe,
        opname="STORE_FAST",
        argval="descriptor_owner",
        occurrence="last",
    )
    descriptor_count = _open_descriptor_count()
    tool_id = _enable_instruction_interrupt(
        observe,
        interrupt_offset,
        tool_name="trusted-time-retirement-root-owner-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            observe(paths)
    finally:
        _disable_instruction_interrupt(tool_id, observe)
    gc.collect()

    assert _open_descriptor_count() == descriptor_count


def test_host_retirement_parent_owner_closes_before_registration_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    paths[0].parent.mkdir(mode=0o700)
    observe = reader._observe_host_retirements
    interrupt_offset = _instruction_offset(
        observe,
        opname="STORE_SUBSCR",
        argval=None,
    )
    descriptor_count = _open_descriptor_count()
    tool_id = _enable_instruction_interrupt(
        observe,
        interrupt_offset,
        tool_name="trusted-time-retirement-parent-registration-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            observe(paths)
    finally:
        _disable_instruction_interrupt(tool_id, observe)
    gc.collect()

    assert _open_descriptor_count() == descriptor_count


def test_host_retirement_parent_owner_closes_on_call_store_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    paths[0].parent.mkdir(mode=0o700)
    opened_descriptors: list[int] = []
    real_open = reader._open_reviewed_staged_input_directory_at_owner

    def tracked_open(
        directory_name: str,
        *,
        directory_descriptor: int,
    ) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(
            directory_name,
            directory_descriptor=directory_descriptor,
        )
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(
        reader,
        "_open_reviewed_staged_input_directory_at_owner",
        tracked_open,
    )
    observe = reader._observe_host_retirements
    interrupt_offset = _instruction_offset(
        observe,
        opname="STORE_FAST",
        argval="parent_owner",
        occurrence="last",
    )
    tool_id = _enable_instruction_interrupt(
        observe,
        interrupt_offset,
        tool_name="trusted-time-retirement-parent-owner-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            observe(paths)
    finally:
        _disable_instruction_interrupt(tool_id, observe)
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_host_retirement_parent_libc_owner_closes_inside_wrapper_call_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    paths[0].parent.mkdir(mode=0o700)
    root_owner = reader._open_reviewed_staged_input_directory_owner(paths[0].parent.parent)
    opened_descriptors: list[int] = []
    real_open = reader._REVIEWED_DESCRIPTOR_OPENAT

    def tracked_open(*arguments: object) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(*arguments)
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(reader, "_REVIEWED_DESCRIPTOR_OPENAT", tracked_open)
    wrapper = reader._open_reviewed_staged_input_directory_at_owner
    interrupt_offset = _instruction_offset(
        wrapper,
        opname="STORE_FAST",
        argval="owner",
    )
    tool_id = _enable_instruction_interrupt(
        wrapper,
        interrupt_offset,
        tool_name="trusted-time-retirement-parent-libc-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            wrapper(
                paths[0].parent.name,
                directory_descriptor=root_owner.fileno(),
            )
    finally:
        _disable_instruction_interrupt(tool_id, wrapper)
        root_owner.close()
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_lock_guard_libc_owner_closes_inside_wrapper_call_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "trusted-time-launch.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    opened_descriptors: list[int] = []
    real_open = reader._REVIEWED_DESCRIPTOR_OPEN

    def tracked_open(*arguments: object) -> reader._ReviewedStagedInputDescriptorOwner:
        owner = real_open(*arguments)
        opened_descriptors.append(owner.fileno())
        return owner

    monkeypatch.setattr(reader, "_REVIEWED_DESCRIPTOR_OPEN", tracked_open)
    wrapper = reader._open_reviewed_lock_guard_owner
    interrupt_offset = _instruction_offset(
        wrapper,
        opname="STORE_FAST",
        argval="owner",
    )
    tool_id = _enable_instruction_interrupt(
        wrapper,
        interrupt_offset,
        tool_name="trusted-time-lock-guard-libc-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            wrapper(lock_path)
    finally:
        _disable_instruction_interrupt(tool_id, wrapper)
    gc.collect()

    assert len(opened_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(opened_descriptors[0])


def test_validate_lock_guard_owner_closes_on_call_store_interruption(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "trusted-time-launch.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    lock_owner = io.FileIO(lock_path, mode="r+b")
    reader.fcntl.flock(lock_owner.fileno(), reader.fcntl.LOCK_EX | reader.fcntl.LOCK_NB)
    metadata = os.fstat(lock_owner.fileno())
    issuer = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
    issuer._lock_descriptor = lock_owner.fileno()
    issuer._lock_owner = lock_owner
    issuer._lock_path = lock_path
    issuer._lock_identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )
    validate = reader.TrustedTimePostEnrollmentTopologyObservationIssuer._validate_lock
    interrupt_offset = _instruction_offset(
        validate,
        opname="STORE_FAST",
        argval="guard_owner",
        occurrence="last",
    )
    descriptor_count = _open_descriptor_count()
    tool_id = _enable_instruction_interrupt(
        validate,
        interrupt_offset,
        tool_name="trusted-time-lock-guard-owner-store-test",
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            issuer._validate_lock()
    finally:
        _disable_instruction_interrupt(tool_id, validate)
    gc.collect()

    assert _open_descriptor_count() == descriptor_count
    lock_owner.close()


@pytest.mark.parametrize(
    ("drift", "path_index"),
    [
        ("same_bytes_replacement", 0),
        ("same_bytes_replacement", 1),
        ("removal", 2),
        ("content", 1),
        ("mode", 3),
    ],
)
def test_prepare_revalidates_original_staged_receipts_after_exact_empty_observation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    drift: str,
    path_index: int,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    arguments = _reviewed_prepare_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    issuer, queued = _open_issuer(monkeypatch, tmp_path, outputs=[b"", b""])
    issuer_type = reader.TrustedTimePostEnrollmentTopologyObservationIssuer
    exact_empty = issuer_type._run_exact_empty_precreate_observation

    def drift_after_exact_empty(*args: Any, **kwargs: Any) -> None:
        exact_empty(*args, **kwargs)
        _drift_staged_input(paths[path_index], drift)

    monkeypatch.setattr(
        issuer_type,
        "_run_exact_empty_precreate_observation",
        drift_after_exact_empty,
    )

    def run(lease: object) -> None:
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="staged-input fence is unavailable",
        ):
            issuer._prepare_reviewed_topology_creation(
                **arguments,  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "pristine"
        assert issuer._reviewed_mutation_prepared_registration is None
        assert issuer._reviewed_mutation_binding_sha256 is None

    issuer._run_exclusive_choreography(run)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


@pytest.mark.parametrize(
    ("drift", "path_index"),
    [
        ("same_bytes_replacement", 0),
        ("same_bytes_replacement", 1),
        ("removal", 2),
        ("content", 1),
        ("mode", 3),
    ],
)
def test_execute_revalidates_prepared_staged_seals_before_create_state_or_docker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    drift: str,
    path_index: int,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    arguments = _reviewed_prepare_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    issuer, queued = _open_issuer(monkeypatch, tmp_path, outputs=[b"", b""])

    def run(lease: object) -> None:
        prepared = issuer._prepare_reviewed_topology_creation(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        _drift_staged_input(paths[path_index], drift)
        call_count_before_execute = len(queued.calls)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="staged-input fence is unavailable",
        ):
            issuer._execute_prepared_reviewed_topology_creation(
                prepared,
                _choreography_lease=lease,
            )
        assert len(queued.calls) == call_count_before_execute
        assert issuer._reviewed_mutation_state == "prepared"
        assert issuer._reviewed_mutation_prepared_registration is not None
        del prepared
        gc.collect()
        assert issuer._reviewed_mutation_state == "pristine"
        assert issuer._reviewed_mutation_prepared_registration is None

    issuer._run_exclusive_choreography(run)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_execute_input_revalidation_interruption_leaves_prepared_state_inert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    arguments = _reviewed_prepare_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
    issuer, queued = _open_issuer(monkeypatch, tmp_path, outputs=[b"", b""])

    def interrupt_revalidation(*_: object, **__: object) -> None:
        raise KeyboardInterrupt

    def run(lease: object) -> None:
        prepared = issuer._prepare_reviewed_topology_creation(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        call_count_before_execute = len(queued.calls)
        monkeypatch.setattr(
            reader,
            "_revalidate_reviewed_staged_input_seals",
            interrupt_revalidation,
        )
        with pytest.raises(KeyboardInterrupt):
            issuer._execute_prepared_reviewed_topology_creation(
                prepared,
                _choreography_lease=lease,
            )
        assert len(queued.calls) == call_count_before_execute
        assert issuer._reviewed_mutation_state == "prepared"
        assert issuer._reviewed_mutation_prepared_registration is not None
        del prepared
        gc.collect()
        assert issuer._reviewed_mutation_state == "pristine"

    issuer._run_exclusive_choreography(run)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_lost_prepared_return_restores_pristine_before_caller_store(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path, outputs=[b"", b""])
    interrupted = False

    def host_like(lease: object) -> None:
        nonlocal interrupted
        try:
            prepared = issuer._prepare_reviewed_topology_creation(  # noqa: F841
                **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        except KeyboardInterrupt:
            interrupted = True
            gc.collect()
            assert issuer._reviewed_mutation_state == "pristine"
            assert issuer._reviewed_mutation_binding_sha256 is None
            assert issuer._reviewed_mutation_prepared_registration is None
            return
        raise AssertionError("prepared creation return was not interrupted")

    instructions = list(dis.get_instructions(host_like))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "prepared"
        and index > 0
        and instructions[index - 1].opname in {"CALL", "CALL_FUNCTION_EX"}
    )
    tool_id = _enable_instruction_interrupt(
        host_like,
        instructions[store_index].offset,
        tool_name="trusted-time-prepared-create-return-test",
    )
    try:
        issuer._run_exclusive_choreography(host_like)
    finally:
        _disable_instruction_interrupt(tool_id, host_like)

    assert interrupted is True
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_interrupted_prepared_consume_before_effect_commit_uses_inert_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    one_empty_proof = [
        b"",
        b"",
        fixtures._json_line("LOCAL:DAEMON:1"),
        b"",
        b"",
    ]
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", *one_empty_proof],
    )

    def run(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
        prepared = issuer._prepare_reviewed_topology_creation(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        issuer_type = reader.TrustedTimePostEnrollmentTopologyObservationIssuer
        execute = issuer_type._execute_prepared_reviewed_topology_creation
        interrupt_offset = _instruction_offset(
            execute,
            opname="STORE_ATTR",
            argval="_reviewed_mutation_state",
            occurrence="first",
        )
        tool_id = _enable_instruction_interrupt(
            execute,
            interrupt_offset,
            tool_name="trusted-time-prepared-create-consume-test",
        )
        try:
            with pytest.raises(KeyboardInterrupt):
                issuer._execute_prepared_reviewed_topology_creation(
                    prepared,
                    _choreography_lease=lease,
                )
        finally:
            _disable_instruction_interrupt(tool_id, execute)
        assert issuer._reviewed_mutation_state == "prepared"
        assert issuer._reviewed_mutation_prepared_registration is None
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"

    issuer._run_exclusive_choreography(run)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_prepared_reviewed_creation_teardown_is_inert_and_invalidates_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    one_empty_proof = [
        b"",
        b"",
        fixtures._json_line("LOCAL:DAEMON:1"),
        b"",
        b"",
    ]
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", *one_empty_proof],
    )

    def run(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
        prepared = issuer._prepare_reviewed_topology_creation(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"
        assert issuer._reviewed_mutation_prepared_registration is None
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._execute_prepared_reviewed_topology_creation(
                prepared,
                _choreography_lease=lease,
            )

    issuer._run_exclusive_choreography(run)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_prepared_reviewed_creation_rejects_wrong_issuer_before_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    paths = fixtures._staged_paths(first_root / "retired")
    one_empty_proof = [
        b"",
        b"",
        fixtures._json_line("LOCAL:DAEMON:1"),
        b"",
        b"",
    ]
    first, first_queued = _open_issuer(
        monkeypatch,
        first_root,
        outputs=[b"", b"", *one_empty_proof],
    )
    second, second_queued = _open_issuer(monkeypatch, second_root)

    def first_action(first_lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
        prepared = first._prepare_reviewed_topology_creation(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=first_lease,
        )

        def second_action(second_lease: object) -> None:
            with pytest.raises(
                reader.TrustedTimePostEnrollmentTopologyReaderError,
                match="prepared reviewed topology creation is unavailable",
            ):
                second._execute_prepared_reviewed_topology_creation(
                    prepared,
                    _choreography_lease=second_lease,
                )

        second._run_exclusive_choreography(second_action)
        first._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=first_lease,
        )

    first._run_exclusive_choreography(first_action)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in first_queued.calls)
    assert len(second_queued.calls) == 1
    assert first_queued.outputs == []
    assert second_queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(second)
    _close_and_assert_launch_lock_is_reacquirable(first)


@pytest.mark.parametrize("foreign_context", ["wrong-lease", "foreign-thread"])
def test_prepared_reviewed_creation_rejects_foreign_context_before_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    foreign_context: Literal["wrong-lease", "foreign-thread"],
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path, outputs=[b"", b""])
    errors: list[BaseException] = []

    def action(lease: object) -> None:
        prepared = issuer._prepare_reviewed_topology_creation(
            **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        if foreign_context == "wrong-lease":
            with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
                issuer._execute_prepared_reviewed_topology_creation(
                    prepared,
                    _choreography_lease=object(),
                )
            return

        def worker() -> None:
            try:
                issuer._execute_prepared_reviewed_topology_creation(
                    prepared,
                    _choreography_lease=lease,
                )
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=2.0)
        assert not thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(action)
    assert issuer._reviewed_mutation_prepared_registration is None
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_forked_child_cannot_execute_parent_prepared_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    paths = fixtures._staged_paths(tmp_path / "retired")
    one_empty_proof = [
        b"",
        b"",
        fixtures._json_line("LOCAL:DAEMON:1"),
        b"",
        b"",
    ]
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", *one_empty_proof],
    )

    def action(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
        prepared = issuer._prepare_reviewed_topology_creation(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        read_descriptor, write_descriptor = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the pipe
            os.close(read_descriptor)
            try:
                try:
                    issuer._execute_prepared_reviewed_topology_creation(
                        prepared,
                        _choreography_lease=lease,
                    )
                except BaseException:
                    payload = (
                        b"safe"
                        if issuer._reviewed_mutation_prepared_registration is None
                        and issuer._reviewed_mutation_state == "forked"
                        else b"unsafe"
                    )
                else:
                    payload = b"unsafe"
                os.write(write_descriptor, payload)
            finally:
                os.close(write_descriptor)
            os._exit(0)

        os.close(write_descriptor)
        try:
            assert os.read(read_descriptor, 16) == b"safe"
        finally:
            os.close(read_descriptor)
            os.waitpid(child_pid, 0)
        assert issuer._reviewed_mutation_state == "prepared"
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )

    issuer._run_exclusive_choreography(action)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_close_invalidates_escaped_prepared_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(monkeypatch, tmp_path, outputs=[b"", b""])
    escaped: list[tuple[object, object]] = []

    def action(lease: object) -> None:
        prepared = issuer._prepare_reviewed_topology_creation(
            **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        escaped.append((prepared, lease))

    issuer._run_exclusive_choreography(action)
    assert issuer._reviewed_mutation_state == "prepared"
    issuer.close()
    assert issuer._reviewed_mutation_state == "closed"
    assert issuer._reviewed_mutation_prepared_registration is None
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._execute_prepared_reviewed_topology_creation(
            escaped[0][0],
            _choreography_lease=escaped[0][1],
        )
    descriptor = _acquire_trusted_time_launch_lock(
        path=issuer._lock_path,
        ignored_root=issuer._ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []


def test_pristine_exact_teardown_is_idempotent_and_never_effects_compose(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    one_empty_proof = [
        b"",
        b"",
        fixtures._json_line("LOCAL:DAEMON:1"),
        b"",
        b"",
    ]
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[*one_empty_proof, *one_empty_proof],
    )

    def run(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, compose_payload)
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"
        retained_binding = issuer._reviewed_mutation_binding_sha256
        assert type(retained_binding) is str
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"
        assert issuer._reviewed_mutation_binding_sha256 == retained_binding
        observed_call_count = len(queued.calls)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="teardown is unavailable",
        ):
            issuer._teardown_reviewed_topology_before_claim(
                **{**arguments, "compose_payload": b"different\n"},  # type: ignore[arg-type]
                created_observation=None,
                _choreography_lease=lease,
            )
        assert len(queued.calls) == observed_call_count

    issuer._run_exclusive_choreography(run)

    mutation_calls = [
        call
        for call in queued.calls
        if any(
            argument in {"create", "down", "start"}
            for argument in cast(tuple[str, ...], call["argv"])
        )
    ]
    assert mutation_calls == []
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_async_interruption_after_host_may_mutate_store_uses_pristine_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            fixtures._json_line("LOCAL:DAEMON:1"),
            b"",
            b"",
        ],
    )
    interrupted = False

    def host_like(lease: object) -> None:
        nonlocal interrupted
        mutation_may_have_begun = False
        try:
            mutation_may_have_begun = True
            issuer._create_reviewed_topology(
                **_reviewed_mutation_arguments(paths, compose_payload),  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        except KeyboardInterrupt:
            interrupted = True
            assert mutation_may_have_begun is True
            issuer._teardown_reviewed_topology_before_claim(
                **_reviewed_mutation_arguments(paths, compose_payload),  # type: ignore[arg-type]
                created_observation=None,
                _choreography_lease=lease,
            )

    instructions = list(dis.get_instructions(host_like))
    may_mutate_store = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "mutation_may_have_begun"
        and instructions[index - 1].argval is True
    )
    interrupt_offset = next(
        instruction.offset
        for instruction in instructions[may_mutate_store + 1 :]
        if instruction.opname == "LOAD_DEREF" and instruction.argval == "issuer"
    )

    def interrupt_before_create(_: object, instruction_offset: int) -> None:
        if instruction_offset == interrupt_offset:
            raise KeyboardInterrupt

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, "trusted-time-precreate-interruption-test")
    try:
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            interrupt_before_create,
        )
        sys.monitoring.set_local_events(
            tool_id,
            host_like.__code__,
            sys.monitoring.events.INSTRUCTION,
        )
        issuer._run_exclusive_choreography(host_like)
    finally:
        sys.monitoring.set_local_events(tool_id, host_like.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert interrupted is True
    assert issuer._reviewed_mutation_state == "torn_down"
    assert not any("compose" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_mutation_choreography_is_fixed_order_and_claim_boundary_is_irreversible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
            (fixtures.SOURCE_CONTAINER_ID + "\n").encode("ascii"),
            (fixtures.SUPERVISOR_CONTAINER_ID + "\n").encode("ascii"),
            fixtures._json_line(fixtures._barrier()),
            *fixtures._state_outputs("staged_unreleased"),
        ],
        bind_reviewed_create_outputs=True,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_observe_exact_started_container",
        lambda *_args, **_kwargs: True,
    )

    def run(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, compose_payload)
        created = issuer._create_reviewed_topology(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "created"
        issuer._start_reviewed_source(
            created_observation=created,
            expected_database_secret_file=paths[0],
            expected_head_anchor_authority_file=paths[1],
            expected_head_anchor_auth_secret_file=paths[2],
            expected_head_anchor_signing_key_secret_file=paths[3],
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "source_ready"
        issuer._start_reviewed_supervisor(
            created_observation=created,
            expected_database_secret_file=paths[0],
            expected_head_anchor_authority_file=paths[1],
            expected_head_anchor_auth_secret_file=paths[2],
            expected_head_anchor_signing_key_secret_file=paths[3],
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "staged_ready"
        for staged_path in paths:
            staged_path.unlink()
            staged_path.parent.rmdir()
        issuer.issue_staged_unreleased_snapshot(
            created_observation=created,
            **fixtures._issue_arguments(paths),
            _choreography_lease=lease,
        )
        issuer._mark_reviewed_topology_claim_boundary(
            created_observation=created,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "claim_boundary"
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="teardown is unavailable",
        ):
            issuer._teardown_reviewed_topology_before_claim(
                **arguments,  # type: ignore[arg-type]
                created_observation=created,
                _choreography_lease=lease,
            )

    issuer._run_exclusive_choreography(run)

    create_call = queued.calls[3]
    assert create_call["argv"] == (
        os.fspath(issuer._docker_executable_path),
        "compose",
        "--env-file",
        os.devnull,
        "--project-directory",
        os.fspath(reader.COMPOSE_PATH.parent),
        "--file",
        "-",
        "create",
        "--no-build",
        "--pull",
        "never",
        "--no-recreate",
        "chrony-nts",
        "trusted-time-supervisor",
    )
    effecting_payload = cast(bytes, create_call["stdin_bytes"])
    expected_network_name = post_enrollment_created_topology_network_name(issuer._session_sha256)
    assert effecting_payload != compose_payload
    assert effecting_payload.count(reader._REVIEWED_CREATE_INVOCATION_LABEL.encode("ascii")) == 3
    assert effecting_payload.count(issuer._session_sha256.encode("ascii")) == 3
    assert effecting_payload.count(expected_network_name.encode("ascii")) == 1
    expected_input_sha256s = tuple(
        hashlib.sha256(payload).hexdigest()
        for payload in (b"database", b"authority", b"auth-secret", b"s" * 32)
    )
    for name, value in zip(
        POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT,
        expected_input_sha256s,
        strict=True,
    ):
        assert effecting_payload.count(name.encode("ascii")) == 1
        assert effecting_payload.count(value.encode("ascii")) == 1
    assert COMPOSE_NETWORK_NAME.encode("ascii") not in effecting_payload
    precreate_network_argv = cast(tuple[str, ...], queued.calls[2]["argv"])
    assert precreate_network_argv[-1] == f"name=^{expected_network_name}$"
    assert COMPOSE_NETWORK_NAME not in precreate_network_argv
    assert all(
        COMPOSE_NETWORK_NAME not in cast(tuple[str, ...], call["argv"]) for call in queued.calls
    )
    assert create_call["maximum_stdin_bytes"] == 8_192
    source_start = queued.calls[18]
    supervisor_start = queued.calls[19]
    assert source_start["argv"] == (
        os.fspath(issuer._docker_executable_path),
        "container",
        "start",
        fixtures.SOURCE_CONTAINER_ID,
    )
    assert supervisor_start["argv"] == (
        os.fspath(issuer._docker_executable_path),
        "container",
        "start",
        fixtures.SUPERVISOR_CONTAINER_ID,
    )
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_create_collision_fails_without_replacement_or_removal_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _CollisionRunner(fixtures._QueuedRunner):
        def __call__(
            self,
            argv: tuple[str, ...],
            **kwargs: Any,
        ) -> subprocess.CompletedProcess[bytes]:
            if "compose" in argv and "create" in argv:
                self.calls.append({"argv": argv, **kwargs})
                return subprocess.CompletedProcess(
                    argv,
                    1,
                    b"",
                    b"container name is already in use by inserted topology",
                )
            return super().__call__(argv, **kwargs)

    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    queued = _CollisionRunner(
        [
            fixtures._json_line("LOCAL:DAEMON:1"),
            b"",
            b"",
        ]
    )
    issuer = fixtures._public_open(
        monkeypatch,
        tmp_path,
        queued,
        socket_path,
        executable,
    )
    paths = fixtures._staged_paths(tmp_path / "retired")

    def reject_collision(lease: object) -> None:
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="creation is unconfirmed",
        ):
            issuer._create_reviewed_topology(
                **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "create_effecting"

    issuer._run_exclusive_choreography(reject_collision)

    compose_calls = [
        cast(tuple[str, ...], call["argv"])
        for call in queued.calls
        if "compose" in cast(tuple[str, ...], call["argv"])
    ]
    assert len(compose_calls) == 1
    assert "create" in compose_calls[0]
    assert "--force-recreate" not in compose_calls[0]
    assert "--no-recreate" in compose_calls[0]
    assert "--remove-orphans" not in compose_calls[0]
    assert not any(
        any(argument in {"down", "rm", "remove"} for argument in argv) for argv in compose_calls
    )
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_create_rejects_successfully_reused_exact_unlabeled_race(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
        ],
    )
    _bind_reviewed_create_outputs_to_invocation(
        issuer,
        queued,
        bind_containers=False,
    )

    def reject_reused_race(lease: object) -> None:
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="created topology observation is unavailable",
        ):
            issuer._create_reviewed_topology(
                **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "create_effected"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(reject_reused_race)

    create_call = next(
        call
        for call in queued.calls
        if "compose" in cast(tuple[str, ...], call["argv"])
        and "create" in cast(tuple[str, ...], call["argv"])
    )
    create_argv = cast(tuple[str, ...], create_call["argv"])
    effecting_payload = cast(bytes, create_call["stdin_bytes"])
    assert "--no-recreate" in create_argv
    assert "--force-recreate" not in create_argv
    assert effecting_payload.count(reader._REVIEWED_CREATE_INVOCATION_LABEL.encode("ascii")) == 3
    assert effecting_payload.count(issuer._session_sha256.encode("ascii")) == 3
    assert not any(
        any(
            argument in {"down", "rm", "remove"} for argument in cast(tuple[str, ...], call["argv"])
        )
        for call in queued.calls
    )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_create_rejects_successfully_reused_exact_unlabeled_network_race(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
        ],
    )
    _bind_reviewed_create_outputs_to_invocation(
        issuer,
        queued,
        bind_network=False,
    )

    def reject_reused_network(lease: object) -> None:
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="created topology observation is unavailable",
        ):
            issuer._create_reviewed_topology(
                **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "create_effected"

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(reject_reused_network)

    create_call = next(
        call
        for call in queued.calls
        if "compose" in cast(tuple[str, ...], call["argv"])
        and "create" in cast(tuple[str, ...], call["argv"])
    )
    create_argv = cast(tuple[str, ...], create_call["argv"])
    effecting_payload = cast(bytes, create_call["stdin_bytes"])
    assert "--no-recreate" in create_argv
    assert "--force-recreate" not in create_argv
    assert effecting_payload.count(reader._REVIEWED_CREATE_INVOCATION_LABEL.encode("ascii")) == 3
    assert effecting_payload.count(issuer._session_sha256.encode("ascii")) == 3
    expected_network_name = post_enrollment_created_topology_network_name(
        issuer._session_sha256
    ).encode("ascii")
    assert (
        b'networks:\n  default:\n    name: "' + expected_network_name + b'"\n    labels:\n'
    ) in effecting_payload
    assert not any(
        any(
            argument in {"down", "rm", "remove"} for argument in cast(tuple[str, ...], call["argv"])
        )
        for call in queued.calls
    )
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_mutation_wrong_tuple_replay_and_order_fail_before_effect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", b"", *fixtures._state_outputs("created")],
        bind_reviewed_create_outputs=True,
    )

    def reject(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, compose_payload)
        created = issuer._create_reviewed_topology(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        observed_call_count = len(queued.calls)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._create_reviewed_topology(
                **arguments,  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._start_reviewed_supervisor(
                created_observation=created,
                expected_database_secret_file=paths[0],
                expected_head_anchor_authority_file=paths[1],
                expected_head_anchor_auth_secret_file=paths[2],
                expected_head_anchor_signing_key_secret_file=paths[3],
                _choreography_lease=lease,
            )
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer._teardown_reviewed_topology_before_claim(
                **{**arguments, "compose_payload": b"different\n"},  # type: ignore[arg-type]
                created_observation=created,
                _choreography_lease=lease,
            )
        assert len(queued.calls) == observed_call_count

    issuer._run_exclusive_choreography(reject)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_mutation_foreign_thread_cannot_use_callback_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_issuer(monkeypatch, tmp_path)
    errors: list[BaseException] = []

    def reject(lease: object) -> None:
        def worker() -> None:
            try:
                issuer._run_exact_empty_precreate_observation(lease)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=2.0)
        assert not thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer._run_exclusive_choreography(reject)
    assert len(queued.calls) == 1
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_reviewed_mutation_marks_possible_effect_before_interrupted_call(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, _ = _open_issuer(monkeypatch, tmp_path)
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_run_exact_empty_precreate_observation",
        lambda *_args, **_kwargs: None,
    )

    def interrupt(
        candidate: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        operation: object,
        **_: object,
    ) -> Never:
        assert candidate is issuer
        assert operation == "compose_create"
        assert issuer._reviewed_mutation_state == "create_effecting"
        raise KeyboardInterrupt

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_run_reviewed_mutation_command",
        interrupt,
    )

    def reject(lease: object) -> None:
        with pytest.raises(KeyboardInterrupt):
            issuer._create_reviewed_topology(
                **_reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD),  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "create_effecting"

    issuer._run_exclusive_choreography(reject)
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_lost_created_return_uses_only_retained_observation_for_exact_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
            *_reviewed_teardown_authentication_outputs(),
            (fixtures.SOURCE_CONTAINER_ID + "\n" + fixtures.SUPERVISOR_CONTAINER_ID + "\n").encode(
                "ascii"
            ),
            (fixtures.NETWORK_ID + "\n").encode("ascii"),
            b"",
            b"",
            fixtures._json_line({"volume": "socket"}),
            fixtures._json_line({"volume": "state"}),
            fixtures._json_line("LOCAL:DAEMON:1"),
        ],
        bind_reviewed_create_outputs=True,
    )
    arguments = _reviewed_mutation_arguments(paths, compose_payload)
    interrupted = False
    retained_created: list[reader.TrustedTimePostEnrollmentCreatedTopologyObservation] = []

    def run(lease: object) -> str:
        nonlocal interrupted
        try:
            created = issuer._create_reviewed_topology(  # noqa: F841
                **arguments,  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        except KeyboardInterrupt:
            interrupted = True
            retained = issuer._reviewed_mutation_created_observation
            assert type(retained) is reader.TrustedTimePostEnrollmentCreatedTopologyObservation
            assert issuer._reviewed_mutation_state == "created"
            assert (
                retained.observation_sha256 == issuer._reviewed_mutation_created_observation_sha256
            )
            retained_created.append(retained)
            issuer._teardown_reviewed_topology_before_claim(
                **arguments,  # type: ignore[arg-type]
                created_observation=None,
                _choreography_lease=lease,
            )
            assert issuer._reviewed_mutation_state == "torn_down"
            assert issuer._reviewed_mutation_created_observation is None
            assert issuer._reviewed_mutation_created_observation_sha256 is None
            return "exact_teardown_confirmed"
        raise AssertionError("created observation return was not interrupted")

    instructions = list(dis.get_instructions(run))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST"
        and instruction.argval == "created"
        and index > 0
        and instructions[index - 1].opname in {"CALL", "CALL_FUNCTION_EX"}
    )
    store_offset = instructions[store_index].offset

    def interrupt_before_store(_: object, instruction_offset: int) -> None:
        if instruction_offset == store_offset:
            raise KeyboardInterrupt

    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, "trusted-time-created-return-test")
    try:
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            interrupt_before_store,
        )
        sys.monitoring.set_local_events(
            tool_id,
            run.__code__,
            sys.monitoring.events.INSTRUCTION,
        )
        result = issuer._run_exclusive_choreography(run)
    finally:
        sys.monitoring.set_local_events(tool_id, run.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert result == "exact_teardown_confirmed"
    assert interrupted is True
    assert len(retained_created) == 1
    container_remove_calls = [
        call
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:4] == ("container", "rm", "--force")
    ]
    assert len(container_remove_calls) == 1
    container_remove_argv = cast(tuple[str, ...], container_remove_calls[0]["argv"])
    assert container_remove_argv[-2:] == (
        fixtures.SOURCE_CONTAINER_ID,
        fixtures.SUPERVISOR_CONTAINER_ID,
    )
    network_remove_calls = [
        call
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:3] == ("network", "rm")
    ]
    assert len(network_remove_calls) == 1
    assert cast(tuple[str, ...], network_remove_calls[0]["argv"])[-1] == fixtures.NETWORK_ID
    assert not any("down" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    volume_names = {
        cast(tuple[str, ...], call["argv"])[-1]
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:4] == ("volume", "inspect", "--format")
    }
    assert volume_names == {
        reader.COMPOSE_SOCKET_VOLUME_NAME,
        reader.COMPOSE_STATE_VOLUME_NAME,
    }
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)
    assert issuer._reviewed_mutation_created_observation is None


@pytest.mark.parametrize(
    "unexpected_inventory",
    [
        fixtures._inventory_bytes() + fixtures._json_line("d" * 64),
        fixtures._json_line(fixtures.SOURCE_CONTAINER_ID) + fixtures._json_line("e" * 64),
    ],
    ids=["extra-container", "replaced-container"],
)
def test_reviewed_teardown_rejects_unsealed_inventory_before_down(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unexpected_inventory: bytes,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
            unexpected_inventory,
        ],
        bind_reviewed_create_outputs=True,
    )

    def reject(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, compose_payload)
        created = issuer._create_reviewed_topology(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="teardown inventory is unavailable",
        ):
            issuer._teardown_reviewed_topology_before_claim(
                **arguments,  # type: ignore[arg-type]
                created_observation=created,
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "created"

    issuer._run_exclusive_choreography(reject)

    down_calls = [call for call in queued.calls if "down" in cast(tuple[str, ...], call["argv"])]
    assert down_calls == []
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_ambiguous_partial_create_is_exactly_authenticated_before_safe_down(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            RuntimeError("one container was created before the runner return was lost"),
            *_reviewed_teardown_authentication_outputs(services=("chrony-nts",)),
            (fixtures.SOURCE_CONTAINER_ID + "\n").encode("ascii"),
            (fixtures.NETWORK_ID + "\n").encode("ascii"),
            b"",
            b"",
            fixtures._json_line({"volume": "socket"}),
            fixtures._json_line({"volume": "state"}),
            fixtures._json_line("LOCAL:DAEMON:1"),
        ],
        bind_reviewed_create_outputs=True,
    )

    def recover_partial(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, compose_payload)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="mutation command is unavailable",
        ):
            issuer._create_reviewed_topology(
                **arguments,  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "create_effecting"
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"

    issuer._run_exclusive_choreography(recover_partial)

    container_remove_calls = [
        cast(tuple[str, ...], call["argv"])
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:4] == ("container", "rm", "--force")
    ]
    assert len(container_remove_calls) == 1
    assert container_remove_calls[0][-1:] == (fixtures.SOURCE_CONTAINER_ID,)
    network_remove_calls = [
        cast(tuple[str, ...], call["argv"])
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:3] == ("network", "rm")
    ]
    assert len(network_remove_calls) == 1
    assert network_remove_calls[0][-1:] == (fixtures.NETWORK_ID,)
    assert not any("down" in cast(tuple[str, ...], call["argv"]) for call in queued.calls)
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_network_only_partial_create_removes_exact_session_network_without_container_rm(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    fixtures._install_pure_validator_stubs(
        monkeypatch,
        endpoint=f"unix://{socket_path}",
    )
    paths = fixtures._staged_paths(tmp_path / "retired")
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[b"", b"", RuntimeError("network created before Compose return was lost")],
    )
    expected_network_name = post_enrollment_created_topology_network_name(issuer._session_sha256)
    network = deepcopy(fixtures._network("created"))
    network["Name"] = expected_network_name
    labels = cast(dict[str, object], network["Labels"])
    labels[reader._REVIEWED_CREATE_INVOCATION_LABEL] = issuer._session_sha256
    queued.outputs.extend(
        [
            b"",
            fixtures._json_line(fixtures.NETWORK_ID),
            fixtures._json_line(network),
            b"",
            fixtures._json_line(fixtures.NETWORK_ID),
            (fixtures.NETWORK_ID + "\n").encode("ascii"),
            b"",
            b"",
            fixtures._json_line({"volume": "socket"}),
            fixtures._json_line({"volume": "state"}),
            fixtures._json_line("LOCAL:DAEMON:1"),
        ]
    )

    def recover_network_only(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="mutation command is unavailable",
        ):
            issuer._create_reviewed_topology(
                **arguments,  # type: ignore[arg-type]
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "create_effecting"
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=None,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"

    issuer._run_exclusive_choreography(recover_network_only)
    assert not any(
        cast(tuple[str, ...], call["argv"])[1:4] == ("container", "rm", "--force")
        for call in queued.calls
    )
    network_remove_calls = [
        cast(tuple[str, ...], call["argv"])
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:3] == ("network", "rm")
    ]
    assert network_remove_calls == [
        (os.fspath(issuer._docker_executable_path), "network", "rm", fixtures.NETWORK_ID)
    ]
    assert all(
        COMPOSE_NETWORK_NAME not in cast(tuple[str, ...], call["argv"]) for call in queued.calls
    )
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_post_create_staged_input_replacement_exits_before_marker_and_exactly_tears_down(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    fixtures._install_pure_validator_stubs(
        monkeypatch,
        endpoint=f"unix://{socket_path}",
    )
    paths = fixtures._staged_paths(tmp_path / "retired")
    expected_sha256s = tuple(
        hashlib.sha256(payload).hexdigest()
        for payload in (b"database", b"authority", b"auth-secret", b"s" * 32)
    )
    source_running = _reviewed_teardown_container("staged_unreleased", "chrony-nts")
    supervisor_exited = _reviewed_teardown_container("created", "trusted-time-supervisor")
    supervisor_configuration = cast(dict[str, object], supervisor_exited["Config"])
    supervisor_configuration["Env"] = [
        f"{name}={value}"
        for name, value in zip(
            POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT,
            expected_sha256s,
            strict=True,
        )
    ]
    supervisor_exited["State"] = {
        "Dead": False,
        "Error": "",
        "ExitCode": 2,
        "FinishedAt": "2026-08-09T12:34:57.123456789Z",
        "OOMKilled": False,
        "Paused": False,
        "Pid": 0,
        "Restarting": False,
        "Running": False,
        "StartedAt": "2026-08-09T12:34:56.123456789Z",
        "Status": "exited",
    }
    network = deepcopy(fixtures._network("staged_unreleased"))
    network_containers = cast(dict[str, object], network["Containers"])
    network["Containers"] = {
        fixtures.SOURCE_CONTAINER_ID: network_containers[fixtures.SOURCE_CONTAINER_ID]
    }
    inventory = fixtures._inventory_bytes()
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
            (fixtures.SOURCE_CONTAINER_ID + "\n").encode("ascii"),
            (fixtures.SUPERVISOR_CONTAINER_ID + "\n").encode("ascii"),
            inventory,
            fixtures._json_line({"Config": {}, "Id": fixtures.SOURCE_IMAGE_ID}),
            fixtures._json_line({"Config": {}, "Id": fixtures.SUPERVISOR_IMAGE_ID}),
            fixtures._json_line(source_running),
            fixtures._json_line(supervisor_exited),
            fixtures._json_line(network),
            inventory,
            (fixtures.SOURCE_CONTAINER_ID + "\n" + fixtures.SUPERVISOR_CONTAINER_ID + "\n").encode(
                "ascii"
            ),
            (fixtures.NETWORK_ID + "\n").encode("ascii"),
            b"",
            b"",
            fixtures._json_line({"volume": "socket"}),
            fixtures._json_line({"volume": "state"}),
            fixtures._json_line("LOCAL:DAEMON:1"),
        ],
        bind_reviewed_create_outputs=True,
    )
    barrier_attempts = 0
    exited_validation_calls: list[dict[str, object]] = []

    def observe_started(
        _candidate: object,
        *,
        service: str,
        **_kwargs: object,
    ) -> bool:
        if service != "chrony-nts":
            raise AssertionError("supervisor state was observed without its consumed marker")
        return True

    def reject_missing_marker(
        _candidate: object,
        _receipts: object,
        *,
        supervisor_container_id: str,
    ) -> Never:
        nonlocal barrier_attempts
        barrier_attempts += 1
        assert supervisor_container_id == fixtures.SUPERVISOR_CONTAINER_ID
        registration = issuer._reviewed_mutation_created_registration
        assert type(registration) is reader._ReviewedCreatedTopologyRegistration
        assert (
            hashlib.sha256(paths[0].read_bytes()).hexdigest()
            != registration.staged_input_sha256s[0]
        )
        raise reader.TrustedTimePostEnrollmentTopologyReaderError(
            "trusted-time staged barrier observation is unavailable"
        )

    def validate_exited(inspection: object, **kwargs: object) -> None:
        assert type(inspection) is list and len(inspection) == 1
        observed = cast(dict[str, object], inspection[0])
        state = cast(dict[str, object], observed["State"])
        configuration = cast(dict[str, object], observed["Config"])
        assert observed["Id"] == fixtures.SUPERVISOR_CONTAINER_ID
        assert state["Status"] == "exited"
        assert state["ExitCode"] == 2
        assert configuration["Env"] == supervisor_configuration["Env"]
        assert kwargs["expected_staged_input_sha256s"] == expected_sha256s
        assert kwargs["expected_network_name"] == post_enrollment_created_topology_network_name(
            issuer._session_sha256
        )
        exited_validation_calls.append(dict(kwargs))

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_observe_exact_started_container",
        observe_started,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_observe_barrier",
        reject_missing_marker,
    )
    monkeypatch.setattr(
        reader,
        "validate_exact_post_start_exited_supervisor_container",
        validate_exited,
    )

    def reject_then_teardown(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, _REVIEWED_COMPOSE_PAYLOAD)
        original_database_bytes = paths[0].read_bytes()
        created = issuer._create_reviewed_topology(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        registration = issuer._reviewed_mutation_created_registration
        assert type(registration) is reader._ReviewedCreatedTopologyRegistration
        assert registration.staged_input_sha256s == expected_sha256s
        issuer._start_reviewed_source(
            created_observation=created,
            expected_database_secret_file=paths[0],
            expected_head_anchor_authority_file=paths[1],
            expected_head_anchor_auth_secret_file=paths[2],
            expected_head_anchor_signing_key_secret_file=paths[3],
            _choreography_lease=lease,
        )
        paths[0].chmod(0o600)
        paths[0].write_bytes(b"post-create replacement")
        paths[0].chmod(0o400)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="supervisor readiness is unconfirmed",
        ):
            issuer._start_reviewed_supervisor(
                created_observation=created,
                expected_database_secret_file=paths[0],
                expected_head_anchor_authority_file=paths[1],
                expected_head_anchor_auth_secret_file=paths[2],
                expected_head_anchor_signing_key_secret_file=paths[3],
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "supervisor_start_effecting"
        issuer._teardown_reviewed_topology_before_claim(
            **arguments,  # type: ignore[arg-type]
            created_observation=created,
            _choreography_lease=lease,
        )
        assert issuer._reviewed_mutation_state == "torn_down"

        # Restoring the original bytes cannot turn this failed attempt into a
        # qualifying topology: its exact IDs and network are already retired.
        paths[0].chmod(0o600)
        paths[0].write_bytes(original_database_bytes)
        paths[0].chmod(0o400)
        call_count = len(queued.calls)
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="created topology is unavailable",
        ):
            issuer._start_reviewed_supervisor(
                created_observation=created,
                expected_database_secret_file=paths[0],
                expected_head_anchor_authority_file=paths[1],
                expected_head_anchor_auth_secret_file=paths[2],
                expected_head_anchor_signing_key_secret_file=paths[3],
                _choreography_lease=lease,
            )
        assert len(queued.calls) == call_count

    issuer._run_exclusive_choreography(reject_then_teardown)
    assert barrier_attempts == reader._MAXIMUM_SUPERVISOR_READINESS_ATTEMPTS
    assert len(exited_validation_calls) == 1
    assert not any(
        cast(tuple[str, ...], call["argv"])[1:3] == ("container", "exec") for call in queued.calls
    )
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)


def test_insertion_after_final_inventory_read_is_never_targeted_by_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    compose_payload = _REVIEWED_COMPOSE_PAYLOAD
    inserted_container_id = "d" * 64
    issuer, queued = _open_issuer(
        monkeypatch,
        tmp_path,
        outputs=[
            b"",
            b"",
            b"",
            *fixtures._state_outputs("created"),
            *_reviewed_teardown_authentication_outputs(),
            (fixtures.SOURCE_CONTAINER_ID + "\n" + fixtures.SUPERVISOR_CONTAINER_ID + "\n").encode(
                "ascii"
            ),
            RuntimeError(
                "inserted container attached after final inventory read; exact network rm failed"
            ),
        ],
        bind_reviewed_create_outputs=True,
    )

    def reject_late_insertion(lease: object) -> None:
        arguments = _reviewed_mutation_arguments(paths, compose_payload)
        created = issuer._create_reviewed_topology(
            **arguments,  # type: ignore[arg-type]
            _choreography_lease=lease,
        )
        with pytest.raises(
            reader.TrustedTimePostEnrollmentTopologyReaderError,
            match="mutation command is unavailable",
        ):
            issuer._teardown_reviewed_topology_before_claim(
                **arguments,  # type: ignore[arg-type]
                created_observation=created,
                _choreography_lease=lease,
            )
        assert issuer._reviewed_mutation_state == "teardown_effecting"

    issuer._run_exclusive_choreography(reject_late_insertion)

    container_remove_argv = next(
        cast(tuple[str, ...], call["argv"])
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:4] == ("container", "rm", "--force")
    )
    assert container_remove_argv[-2:] == (
        fixtures.SOURCE_CONTAINER_ID,
        fixtures.SUPERVISOR_CONTAINER_ID,
    )
    assert inserted_container_id not in container_remove_argv
    network_remove_argv = next(
        cast(tuple[str, ...], call["argv"])
        for call in queued.calls
        if cast(tuple[str, ...], call["argv"])[1:3] == ("network", "rm")
    )
    assert network_remove_argv[-1] == fixtures.NETWORK_ID
    assert not any(
        "compose" in cast(tuple[str, ...], call["argv"])
        and "down" in cast(tuple[str, ...], call["argv"])
        for call in queued.calls
    )
    assert queued.outputs == []
    _close_and_assert_launch_lock_is_reacquirable(issuer)
