"""Finite original preparation and terminal installation delivery.

The original configured context exclusively owns its graph, lease and cleanup.
Caller abandonment cannot undo a retained dependency object or end owned work.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from threading import Condition, Event, Lock, Thread, current_thread
from typing import Literal
from uuid import uuid4

from apps.trader import configured_readiness_owner as configured
from apps.trader import continuous_readiness_owner as readiness
from apps.trader import initial_selection_descriptor as descriptors
from apps.trader import initial_selection_installation as installation
from apps.trader import initial_selection_preparation as preparation
from apps.trader.continuous_readiness_owner import ReadinessOwnerLimits
from apps.trader.initial_selection_descriptor import InitialSelectionDescriptor, _DescriptorValues
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.domain.research_job_contracts import require_identifier

_ARGUMENT = "INITIAL_SELECTION_PREPARATION_OWNER_ARGUMENT_INVALID"
_STATE = "INITIAL_SELECTION_PREPARATION_OWNER_STATE_INVALID"
_BINDING = "INITIAL_SELECTION_PREPARATION_OWNER_BINDING_CHANGED"
_MAX_NS = 2**63 - 1
_RESERVE_NS = 1_000_000_000
_POLL_SECONDS = 0.02
_DEFAULT_LIMITS = ReadinessOwnerLimits()
_LIMITS = ReadinessOwnerLimits
_LIMITS_INIT = ReadinessOwnerLimits.__init__
_LIMITS_VALIDATE = ReadinessOwnerLimits.__post_init__
_ARGUMENT_PATH = configured._argument_path
_GENERATOR = configured._CONFIGURED_RUNTIME_GENERATOR
_ADAPTER = preparation._InitialSelectionPreparation
_ADAPTER_INIT = _ADAPTER.__init__
_PREPARE = _ADAPTER.prepare
_DESCRIPTOR = _ADAPTER.descriptor
_RUNTIME = readiness._ReadinessRuntime
_RUNTIME_REQUIRE = _RUNTIME._require
_LEASE_PROPERTY = vars(_RUNTIME)["lease_deadline_ns"]
_LEASE_GET = _LEASE_PROPERTY.fget
_D_CLASS = InitialSelectionDescriptor
_D_INIT = InitialSelectionDescriptor.__post_init__
_D_VALUES = descriptors._descriptor_values
_D_VALIDATE = descriptors._validated_values
_D_COPY = descriptors._from_values
_EVENT_IS_SET = Event.is_set
_EVENT_SET = Event.set
_THREAD_START = Thread.start
_THREAD_ALIVE = Thread.is_alive
_THREAD_JOIN = Thread.join
_INSTALLATION = installation._InitialSelectionInstallation
_INSTALLATION_INIT = _INSTALLATION.__init__
_INSTALL = _INSTALLATION.install
_OBSERVE = _INSTALLATION.observation
_RECEIPT_VALUES = installation._receipt_values
_RECEIPT_FROM_VALUES = installation._receipt_from_values
_NATIVE_RECEIPT_VALUES = installation._native_receipt_values
_I_VALUES = installation._observation_values
_I_FROM_VALUES = installation._observation_from_values
_I_CLASS = installation.InitialSelectionInstallationObservation
_I_INIT = _I_CLASS.__init__
_I_VALIDATE = _I_CLASS.__post_init__

type _Phase = Literal["new", "starting", "idle", "busy", "stopping", "stopped"]
type _Reason = Literal[
    "prepared",
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "startup_failed",
    "preparation_failed",
    "cleanup_failed",
]
_PHASES = ("new", "starting", "idle", "busy", "stopping", "stopped")
_REASONS = (
    "prepared",
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "startup_failed",
    "preparation_failed",
    "cleanup_failed",
)
_FAILURES = (
    "clock_invalid",
    "startup_failed",
    "startup_deadline",
    "lifetime_expired",
    "preparation_failed",
    "cleanup_failed",
    "installation_failed",
    "verification_failed",
)

type _InstallReason = Literal[
    "installed",
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "preparation_unavailable",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "installation_failed",
    "cleanup_failed",
]
_INSTALL_REASONS = (
    "installed",
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "preparation_unavailable",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "installation_failed",
    "cleanup_failed",
)


@dataclass(frozen=True, slots=True)
class InitialSelectionPreparationOwnerStatus:
    phase: _Phase
    busy: bool
    attempted: bool
    cleanup_complete: bool
    primary_failure: str | None
    cleanup_failure: str | None
    incarnation: str

    def __post_init__(self) -> None:
        if type(self) is not InitialSelectionPreparationOwnerStatus:
            raise ValueError(_ARGUMENT)
        if (
            not _native_text(self.phase)
            or type(self.incarnation) is not str
            or any(
                type(item) is not bool
                for item in (self.busy, self.attempted, self.cleanup_complete)
            )
            or any(
                item is not None and type(item) is not str
                for item in (
                    self.primary_failure,
                    self.cleanup_failure,
                )
            )
        ):
            raise ValueError(_ARGUMENT)
        if self.phase not in _PHASES or any(
            item is not None and item not in _FAILURES
            for item in (self.primary_failure, self.cleanup_failure)
        ):
            raise ValueError(_ARGUMENT)
        _identifier(self.incarnation)


@dataclass(frozen=True, slots=True)
class InitialSelectionPreparationResult:
    status: Literal["prepared", "unavailable"]
    reason: _Reason
    call_id: str
    incarnation: str
    descriptor: InitialSelectionDescriptor | None

    def __post_init__(self) -> None:
        if type(self) is not InitialSelectionPreparationResult:
            raise ValueError(_ARGUMENT)
        if any(
            type(item) is not str
            for item in (
                self.status,
                self.reason,
                self.call_id,
                self.incarnation,
            )
        ):
            raise ValueError(_ARGUMENT)
        _identifier(self.call_id)
        _identifier(self.incarnation)
        if self.reason not in _REASONS:
            raise ValueError(_ARGUMENT)
        if self.status == "prepared" and self.reason == "prepared":
            _data_bindings()
            _D_VALUES(self.descriptor)
        elif (
            self.status != "unavailable" or self.reason == "prepared" or self.descriptor is not None
        ):
            raise ValueError(_ARGUMENT)


@dataclass(slots=True)
class _Request:
    call_id: str
    incarnation: str
    deadline_ns: int
    cancel_event: Event | None
    nonce: object = field(default_factory=object)
    abandoned: bool = False
    dispatched: bool = False
    result: tuple[_Reason, _DescriptorValues | None] | None = None


@dataclass(frozen=True, slots=True)
class InitialSelectionInstallationResult:
    status: Literal["installed", "unavailable"]
    reason: _InstallReason
    call_id: str
    incarnation: str
    observation: installation.InitialSelectionInstallationObservation | None

    def __post_init__(self) -> None:
        if type(self) is not _INSTALL_RESULT_CLASS or any(
            type(value) is not str
            for value in (self.status, self.reason, self.call_id, self.incarnation)
        ):
            raise ValueError(_ARGUMENT)
        _identifier(self.call_id)
        _identifier(self.incarnation)
        if self.reason not in _INSTALL_REASONS:
            raise ValueError(_ARGUMENT)
        if self.status == "installed" and self.reason == "installed":
            try:
                values = _OBSERVATION_SNAPSHOT(self.observation)
            except ValueError:
                raise ValueError(_ARGUMENT) from None
            if values[:3] != (True, True, True) or values[3] is None or values[4] is None:
                raise ValueError(_ARGUMENT)
        elif (
            self.status != "unavailable"
            or self.reason == "installed"
            or self.observation is not None
        ):
            raise ValueError(_ARGUMENT)


@dataclass(slots=True)
class _InstallRequest:
    call_id: str
    incarnation: str
    deadline_ns: int
    cancel_event: Event | None
    receipt_values: installation._ReceiptValues
    request_receipt_sha256: str
    nonce: object = field(default_factory=object)
    abandoned: bool = False
    dispatched: bool = False
    result: tuple[_InstallReason, installation._ObservationValues | None] | None = None
    _admission: tuple[object, ...] = field(init=False, repr=False)
    _worker_thread: Thread | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._admission = (
            self.call_id,
            self.incarnation,
            self.cancel_event,
            self.receipt_values,
            self.request_receipt_sha256,
            self.nonce,
            self.deadline_ns,
        )


type _ProofReason = Literal[
    "verified",
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "verification_failed",
]
_PROOF_REASONS = (
    "verified",
    "not_started",
    "starting",
    "busy",
    "reentrant",
    "already_attempted",
    "cancelled",
    "deadline",
    "stopping",
    "stopped",
    "clock_invalid",
    "verification_failed",
)


@dataclass(frozen=True, slots=True)
class InitialSelectionReadinessResult:
    status: Literal["ready", "unavailable"]
    reason: _ProofReason
    call_id: str
    incarnation: str

    def __post_init__(self) -> None:
        if type(self) is not _PROOF_RESULT_CLASS or any(
            type(value) is not str
            for value in (self.status, self.reason, self.call_id, self.incarnation)
        ):
            raise ValueError(_ARGUMENT)
        _identifier(self.call_id)
        _identifier(self.incarnation)
        if self.reason not in _PROOF_REASONS or (
            (self.status, self.reason) != ("ready", "verified")
            and (self.status != "unavailable" or self.reason == "verified")
        ):
            raise ValueError(_ARGUMENT)


@dataclass(slots=True)
class _ProofRequest:
    call_id: str
    incarnation: str
    deadline_ns: int
    cancel_event: Event | None
    nonce: object = field(default_factory=object, init=False)
    abandoned: bool = field(default=False, init=False)
    dispatched: bool = field(default=False, init=False)
    completed: bool = field(default=False, init=False)
    result: _ProofReason | None = field(default=None, init=False)
    _worker_thread: Thread | None = field(default=None, init=False, repr=False)
    _admission: tuple[object, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._admission = (
            self.call_id,
            self.incarnation,
            self.cancel_event,
            self.nonce,
            self.deadline_ns,
        )
        _PROOF_REQUEST(self)


def _proof_bindings(runtime: readiness._ReadinessRuntime | None = None) -> None:
    for name, expected in (*_PROOF_HELPERS, *_PROOF_DISPATCH):
        if globals().get(name) is not expected:
            raise RuntimeError(_BINDING)
    for cls, name, expected_method in (
        (_PROOF_REQUEST_CLASS, "__init__", _PROOF_REQUEST_INIT),
        (_PROOF_REQUEST_CLASS, "__post_init__", _PROOF_REQUEST_VALIDATE),
        (_PROOF_RESULT_CLASS, "__init__", _PROOF_RESULT_INIT),
        (_PROOF_RESULT_CLASS, "__post_init__", _PROOF_RESULT_VALIDATE),
        *tuple((_RUNTIME, name, method) for name, method in _PROOF_RUNTIME_METHODS),
    ):
        if vars(cls).get(name) is not expected_method:
            raise RuntimeError(_BINDING)
    if (
        _ProofRequest is not _PROOF_REQUEST_CLASS
        or InitialSelectionReadinessResult is not _PROOF_RESULT_CLASS
        or readiness._ReadinessRuntime is not _RUNTIME
        or readiness._DeadlineExpired is not _PROOF_DEADLINE
        or readiness._ClockInvalid is not _PROOF_CLOCK
        or vars(_RUNTIME).get("lease_deadline_ns") is not _LEASE_PROPERTY
        or type(_LEASE_PROPERTY) is not property
        or _LEASE_PROPERTY.fget is not _LEASE_GET
    ):
        raise RuntimeError(_BINDING)
    if runtime is not None:
        if type(runtime) is not _RUNTIME:
            raise ValueError(_STATE)
        state = vars(runtime)
        if state.get("_instance") is not runtime or state.get("_thread") is not current_thread():
            raise ValueError(_STATE)
        if any(name in state for name, _ in _PROOF_RUNTIME_METHODS) or "lease_deadline_ns" in state:
            raise RuntimeError(_BINDING)


def _proof_reason(value: object) -> bool:
    return type(value) is str and value in _PROOF_REASONS


def _proof_request(value: object) -> _ProofRequest:
    _PROOF_BINDINGS()
    if type(value) is not _PROOF_REQUEST_CLASS or not isinstance(value, _ProofRequest):
        raise ValueError(_STATE)
    if (
        type(value.call_id) is not str
        or type(value.incarnation) is not str
        or type(value.deadline_ns) is not int
        or not 0 < value.deadline_ns <= _MAX_NS
        or (value.cancel_event is not None and type(value.cancel_event) is not Event)
        or type(value.nonce) is not object
        or any(
            type(item) is not bool for item in (value.abandoned, value.dispatched, value.completed)
        )
        or (value._worker_thread is not None and type(value._worker_thread) is not Thread)
        or (value.result is not None and not _PROOF_REASON(value.result))
    ):
        raise ValueError(_STATE)
    admission = value._admission
    if (
        type(admission) is not tuple
        or len(admission) != 5
        or type(admission[0]) is not str
        or type(admission[1]) is not str
        or (admission[2] is not None and type(admission[2]) is not Event)
        or type(admission[3]) is not object
        or type(admission[4]) is not int
        or not 0 < admission[4] <= _MAX_NS
    ):
        raise ValueError(_STATE)
    try:
        _identifier(value.call_id)
        _identifier(value.incarnation)
    except ValueError:
        raise ValueError(_STATE) from None
    if (
        value.call_id != admission[0]
        or value.incarnation != admission[1]
        or value.cancel_event is not admission[2]
        or value.nonce is not admission[3]
        or value.deadline_ns > admission[4]
        or value.dispatched != (value._worker_thread is not None)
        or value.completed != (value.result is not None)
        or (value.result is not None and not _PROOF_REASON(value.result))
        or (
            value.completed
            and not value.dispatched
            and value.result not in ("cancelled", "deadline", "stopping", "clock_invalid")
        )
    ):
        raise ValueError(_STATE)
    return value


def _proof_eligible(owner: InitialSelectionPreparationOwner) -> None:
    if (
        owner._attempted
        or owner._preparation_return_admitted
        or owner._prepared_proposal_sha256 is not None
        or owner._install_dispatched
        or owner._terminal_install is not None
        or owner._install_observation is not None
        or owner._install_succeeded
        or owner._install_return_admitted
    ):
        raise ValueError(_STATE)


def _proof_result(
    call_id: str, incarnation: str, reason: _ProofReason
) -> InitialSelectionReadinessResult:
    _PROOF_BINDINGS()
    return _PROOF_RESULT_CLASS(
        "ready" if reason == "verified" else "unavailable", reason, call_id, incarnation
    )


def _proof_identity(
    owner: InitialSelectionPreparationOwner,
    request: _ProofRequest,
    condition: Condition,
    admission: tuple[object, ...],
) -> None:
    _HOST_ENTRY(owner)
    _PROOF_REQUEST(request)
    if (
        type(condition) is not Condition
        or condition is not owner._original[4]
        or request._admission is not admission
        or request.incarnation != owner._incarnation
    ):
        raise ValueError(_STATE)


def _proof_release(
    owner: InitialSelectionPreparationOwner,
    request: _ProofRequest,
    condition: Condition,
) -> bool:
    # The caller already holds this original lock. Never follow a replaced alias.
    _HOST_ENTRY(owner)
    if type(condition) is not Condition or condition is not owner._original[4]:
        raise ValueError(_STATE)
    _PROOF_REQUEST(request)
    if not request.completed or owner._slot is not request:
        return False
    if owner._active_nonce is not request.nonce:
        raise ValueError(_STATE)
    owner._slot, owner._active_nonce, owner._busy = None, None, False
    if not owner._stop_latched and not owner._finalized:
        owner._phase = "idle"
    condition.notify_all()
    return True


def _proof_ack(owner: InitialSelectionPreparationOwner, request: _ProofRequest) -> None:
    _HOST_STATE(owner)
    _PROOF_REQUEST(request)
    _PROOF_ELIGIBLE(owner)
    if (
        owner._slot is not request
        or owner._active_nonce is not request.nonce
        or request.incarnation != owner._incarnation
        or request.abandoned
        or not request.dispatched
        or not request.completed
        or request.result != "verified"
        or request._worker_thread is None
        or owner._thread is not request._worker_thread
        or not _THREAD_ALIVE(request._worker_thread)
        or owner._finalized
        or owner._stop_latched
        or owner._phase != "busy"
        or not owner._busy
    ):
        raise ValueError(_STATE)


def _proof_unavailable(
    owner: InitialSelectionPreparationOwner, request: _ProofRequest
) -> _ProofReason | None:
    now = _NOW(owner)
    if now is None:
        return "clock_invalid"
    if request.cancel_event is not None and _event_is_set(request.cancel_event):
        return "cancelled"
    if now >= min(request.deadline_ns, owner._work_deadline):
        return "deadline"
    if request.abandoned:
        return request.result if request.result not in (None, "verified") else "cancelled"
    if owner._stop_latched and (request.result is None or request.result == "verified"):
        return "stopping"
    return None


def _proof_work_bindings(
    owner: InitialSelectionPreparationOwner,
    runtime: readiness._ReadinessRuntime,
    request: _ProofRequest,
    condition: Condition,
    admission: tuple[object, ...],
) -> None:
    _HOST_ENTRY(owner)
    _PROOF_BINDINGS(runtime)
    _PROOF_REQUEST(request)
    _PROOF_ELIGIBLE(owner)
    if (
        condition is not owner._original[4]
        or request._admission is not admission
        or owner._slot is not request
        or owner._active_nonce is not request.nonce
        or request.incarnation != owner._incarnation
        or request._worker_thread is not current_thread()
        or owner._thread is not current_thread()
        or not request.dispatched
        or request.completed
    ):
        raise ValueError(_STATE)


def _proof_failure(
    owner: InitialSelectionPreparationOwner,
    condition: Condition,
    failure: BaseException,
) -> BaseException:
    # Safe failure recording uses the captured native lock; no repeated _state
    # check can replace an already retained original proof or postcheck failure.
    owner._primary_error = failure
    if owner._primary_failure is None:
        owner._primary_failure = (
            "clock_invalid" if type(failure) is _PROOF_CLOCK else "verification_failed"
        )
    owner._stop_latched, owner._phase = True, "stopping"
    condition.notify_all()
    original = owner._original
    if (
        type(original) is not tuple
        or len(original) != 7
        or original[4] is not condition
        or type(original[5]) is not Event
    ):
        # The already retained guard failure prevents use of this changed
        # baseline. Literal _run skips its unlatched fallback and still exits
        # its originally captured G context and signals its original Event.
        return failure
    try:
        _LATCH(owner, None)
    except BaseException as error:
        if error is not failure:
            failure = BaseExceptionGroup(
                "initial selection proof and binding check failed", [failure, error]
            )
        owner._primary_error = failure
    return failure


def _serve_proof(
    owner: InitialSelectionPreparationOwner,
    runtime: readiness._ReadinessRuntime,
    request: _ProofRequest,
) -> None:
    _HOST_ENTRY(owner)
    condition = owner._condition
    _PROOF_REQUEST(request)
    admission = request._admission
    with condition:
        _HOST_STATE(owner)
        _PROOF_REQUEST(request)
        _PROOF_ELIGIBLE(owner)
        if owner._slot is not request:
            if request.completed:
                return
            raise ValueError(_STATE)
        if owner._active_nonce is not request.nonce or request.incarnation != owner._incarnation:
            raise ValueError(_STATE)
        unavailable = _PROOF_UNAVAILABLE(owner, request)
        _HOST_STATE(owner)
        _PROOF_IDENTITY(owner, request, condition, admission)
        if unavailable is not None:
            request.result = unavailable
            request.completed, request.abandoned = True, True
            _PROOF_RELEASE(owner, request, condition)
            return
        if request.completed:
            sampled = owner._last_ns
            if sampled is None:
                raise ValueError(_STATE)
            condition.wait(min(_POLL_SECONDS, max(0, request.deadline_ns - sampled) / 1e9))
            return
        if request.dispatched or owner._thread is not current_thread():
            raise ValueError(_STATE)
        _PROOF_BINDINGS(runtime)
        request._worker_thread, request.dispatched = current_thread(), True
        deadline = min(request.deadline_ns, owner._work_deadline)
        ceiling = owner._work_deadline
    failure: BaseException | None = None
    returned = deadline
    try:
        _PROOF_WORK_BINDINGS(owner, runtime, request, condition, admission)
        candidate = _VERIFY(runtime, deadline)
        if type(candidate) is not int or not 0 < candidate <= deadline:
            raise ValueError(_STATE)
        returned = candidate
    except BaseException as error:
        failure = error
    postcheck_ok = True
    try:
        _PROOF_WORK_BINDINGS(owner, runtime, request, condition, admission)
    except BaseException as error:
        postcheck_ok = False
        failure = (
            error
            if failure is None
            else BaseExceptionGroup(
                "initial selection proof and binding check failed", [failure, error]
            )
        )
    if failure is None:
        try:
            refreshed = _PROOF_LEASE_CEILING(runtime) - _RESERVE_NS
            if not 0 < refreshed <= _MAX_NS:
                raise ValueError(_STATE)
            ceiling = min(ceiling, refreshed)
        except BaseException as error:
            failure = error
    with condition:
        if not postcheck_ok:
            if failure is None:
                raise ValueError(_STATE)
            request.abandoned = True
            raise _PROOF_FAILURE(owner, condition, failure)
        try:
            _HOST_STATE(owner)
            _PROOF_WORK_BINDINGS(owner, runtime, request, condition, admission)
            clean_deadline = type(failure) is _PROOF_DEADLINE
            request.deadline_ns = min(request.deadline_ns, deadline, returned, ceiling)
            owner._work_deadline = min(owner._work_deadline, ceiling)
            unavailable = _PROOF_UNAVAILABLE(owner, request)
            _HOST_STATE(owner)
            _PROOF_WORK_BINDINGS(owner, runtime, request, condition, admission)
            if failure is not None and not clean_deadline:
                reason: _ProofReason = (
                    "clock_invalid" if type(failure) is _PROOF_CLOCK else "verification_failed"
                )
            elif clean_deadline:
                reason = "deadline" if unavailable is None else unavailable
            else:
                reason = "verified" if unavailable is None else unavailable
            request.result, request.completed = reason, True
            if reason != "verified":
                request.abandoned = True
                _PROOF_RELEASE(owner, request, condition)
            condition.notify_all()
            if clean_deadline:
                failure = None
        except BaseException as error:
            failure = (
                error
                if failure is None
                else BaseExceptionGroup(
                    "initial selection proof and binding check failed", [failure, error]
                )
            )
        if failure is not None:
            request.abandoned = True
            raise _PROOF_FAILURE(owner, condition, failure)


def _identifier(value: object) -> str:
    if type(value) is not str:
        raise ValueError(_ARGUMENT)
    try:
        require_identifier(value, "preparation owner identifier")
    except ValueError:
        raise ValueError(_ARGUMENT) from None
    return value


def _native_text(value: object) -> bool:
    return type(value) is str


def _native_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError(_STATE)
    return value


def _require_reason(value: object) -> None:
    if type(value) is not str or value not in _REASONS:
        raise ValueError(_STATE)


def _native_limits(value: object) -> tuple[int, int, int, int]:
    if type(value) is not _LIMITS:
        raise ValueError(_ARGUMENT)
    values = (value.startup_ns, value.request_ns, value.shutdown_ns, value.lifetime_ns)
    if any(type(item) is not int for item in values):
        raise ValueError(_ARGUMENT)
    if (
        readiness.ReadinessOwnerLimits is not _LIMITS
        or vars(_LIMITS).get("__init__") is not _LIMITS_INIT
        or vars(_LIMITS).get("__post_init__") is not _LIMITS_VALIDATE
    ):
        raise RuntimeError(_BINDING)
    try:
        # Only the admitted immutable snapshot supplies this private original
        # constructor. Never validate by rereading the caller's mutable record.
        _LIMITS(
            startup_ns=values[0],
            request_ns=values[1],
            shutdown_ns=values[2],
            lifetime_ns=values[3],
        )
    except ValueError:
        raise ValueError(_ARGUMENT) from None
    return values


def _event_is_set(value: Event) -> bool:
    if type(value) is not Event:
        raise ValueError(_STATE)
    result = _EVENT_IS_SET(value)
    if type(result) is not bool:
        raise ValueError(_STATE)
    return result


def _data_bindings() -> None:
    if (
        descriptors.InitialSelectionDescriptor is not _D_CLASS
        or vars(_D_CLASS).get("__post_init__") is not _D_INIT
        or descriptors._descriptor_values is not _D_VALUES
        or descriptors._validated_values is not _D_VALIDATE
        or descriptors._from_values is not _D_COPY
    ):
        raise RuntimeError(_BINDING)


def _operation_bindings(adapter: preparation._InitialSelectionPreparation | None = None) -> None:
    _data_bindings()
    if adapter is not None and type(adapter) is not _ADAPTER:
        raise ValueError(_STATE)
    if (
        configured._argument_path is not _ARGUMENT_PATH
        or configured._configured_runtime_generator is not _GENERATOR
        or preparation._InitialSelectionPreparation is not _ADAPTER
    ):
        raise RuntimeError(_BINDING)
    for name, original in (
        ("__init__", _ADAPTER_INIT),
        ("prepare", _PREPARE),
        ("descriptor", _DESCRIPTOR),
    ):
        if vars(_ADAPTER).get(name) is not original or (
            adapter is not None and name in vars(adapter)
        ):
            raise RuntimeError(_BINDING)


def _lease_ceiling(runtime: readiness._ReadinessRuntime) -> int:
    if type(runtime) is not _RUNTIME:
        raise ValueError(_STATE)
    state = vars(runtime)
    if state.get("_instance") is not runtime or state.get("_thread") is not current_thread():
        raise ValueError(_STATE)
    if (
        readiness._ReadinessRuntime is not _RUNTIME
        or vars(_RUNTIME).get("lease_deadline_ns") is not _LEASE_PROPERTY
        or type(_LEASE_PROPERTY) is not property
        or _LEASE_PROPERTY.fget is not _LEASE_GET
        or vars(_RUNTIME).get("_require") is not _RUNTIME_REQUIRE
        or "lease_deadline_ns" in state
        or "_require" in state
    ):
        raise RuntimeError(_BINDING)
    getter = _LEASE_GET
    if getter is None:
        raise RuntimeError(_BINDING)
    result = getter(runtime)
    if type(result) is not int or not 0 < result <= _MAX_NS:
        raise ValueError(_STATE)
    return result


def _result(
    call_id: str,
    incarnation: str,
    reason: _Reason,
    values: _DescriptorValues | None = None,
) -> InitialSelectionPreparationResult:
    _identifier(call_id)
    _identifier(incarnation)
    _require_reason(reason)
    if reason == "prepared":
        _data_bindings()
        descriptor = _D_COPY(_D_VALIDATE(values))
        return InitialSelectionPreparationResult(
            "prepared", reason, call_id, incarnation, descriptor
        )
    if values is not None:
        raise ValueError(_STATE)
    return InitialSelectionPreparationResult("unavailable", reason, call_id, incarnation, None)


def _entry(value: object) -> None:
    if type(value) is not _OWNER or InitialSelectionPreparationOwner is not _OWNER:
        raise ValueError(_ARGUMENT)
    state = vars(value)
    for name, original_method in _OWN_METHODS:
        if vars(_OWNER).get(name) is not original_method or name in state:
            raise RuntimeError(_BINDING)
    for name, original_install_method in _INSTALL_METHODS:
        if vars(_OWNER).get(name) is not original_install_method or name in state:
            raise RuntimeError(_BINDING)
    for name, original_helper in _INSTALL_HELPERS:
        if globals().get(name) is not original_helper:
            raise RuntimeError(_BINDING)
    for name, original_proof_method in _PROOF_METHODS:
        if vars(_OWNER).get(name) is not original_proof_method or name in state:
            raise RuntimeError(_BINDING)
    for name, original_proof_helper in (*_PROOF_HELPERS, *_PROOF_DISPATCH):
        if globals().get(name) is not original_proof_helper:
            raise RuntimeError(_BINDING)
    original = state.get("_original")
    if (
        state.get("_instance") is not value
        or type(original) is not tuple
        or len(original) != 7
        or type(state.get("_condition")) is not Condition
        or type(state.get("_stop_event")) is not Event
        or type(state.get("_account_id")) is not str
        or type(state.get("_incarnation")) is not str
        or type(state.get("_limits")) is not tuple
        or len(state["_limits"]) != 4
        or any(type(item) is not int for item in state["_limits"])
    ):
        raise ValueError(_STATE)
    current = tuple(
        state.get(name)
        for name in (
            "_configuration_file",
            "_account_id",
            "_lock_path",
            "_limits",
            "_condition",
            "_stop_event",
            "_incarnation",
        )
    )
    if any(a is not b for a, b in zip(current, original, strict=True)):
        raise ValueError(_STATE)


def _request(value: object) -> _Request:
    if type(value) is not _Request:
        raise ValueError(_STATE)
    if (
        type(value.call_id) is not str
        or type(value.incarnation) is not str
        or type(value.deadline_ns) is not int
        or not 0 < value.deadline_ns <= _MAX_NS
        or (value.cancel_event is not None and type(value.cancel_event) is not Event)
        or type(value.nonce) is not object
        or type(value.abandoned) is not bool
        or type(value.dispatched) is not bool
        or (
            value.result is not None and (type(value.result) is not tuple or len(value.result) != 2)
        )
    ):
        raise ValueError(_STATE)
    if value.result is not None:
        reason, values = value.result
        _require_reason(reason)
        if values is not None and type(values) is not tuple:
            raise ValueError(_STATE)
    return value


def _state(owner: InitialSelectionPreparationOwner) -> None:
    _entry(owner)
    state = vars(owner)
    if any(
        name not in state
        for name in (
            "_thread",
            "_slot",
            "_active_nonce",
            "_last_ns",
            "_shutdown_deadline",
            "_primary_failure",
            "_cleanup_failure",
        )
    ):
        raise ValueError(_STATE)
    if (
        type(state.get("_phase")) is not str
        or state["_phase"] not in _PHASES
        or any(
            type(state.get(name)) is not bool
            for name in (
                "_busy",
                "_attempted",
                "_finalized",
                "_cleanup_ok",
                "_stop_latched",
            )
        )
        or (state.get("_thread") is not None and type(state["_thread"]) is not Thread)
        or any(
            type(state.get(name)) is not int or not 0 <= state[name] <= _MAX_NS
            for name in (
                "_startup_deadline",
                "_lifetime_deadline",
                "_work_deadline",
            )
        )
        or any(
            state.get(name) is not None
            and (type(state[name]) is not int or not 0 <= state[name] <= _MAX_NS)
            for name in ("_last_ns", "_shutdown_deadline")
        )
        or any(
            state.get(name) is not None
            and (type(state[name]) is not str or state[name] not in _FAILURES)
            for name in ("_primary_failure", "_cleanup_failure")
        )
    ):
        raise ValueError(_STATE)
    _INSTALL_STATE(owner)
    if owner._slot is not None:
        request = (
            _PROOF_REQUEST(owner._slot)
            if type(owner._slot) is _PROOF_REQUEST_CLASS
            else _INSTALL_REQUEST(owner._slot)
            if type(owner._slot) is _INSTALL_REQUEST_CLASS
            else _request(owner._slot)
        )
        if isinstance(request, _ProofRequest):
            _PROOF_ELIGIBLE(owner)
            if request.dispatched and owner._thread is not request._worker_thread:
                raise ValueError(_STATE)
        if request.nonce is not owner._active_nonce or request.incarnation != owner._incarnation:
            raise ValueError(_STATE)
    elif owner._active_nonce is not None:
        raise ValueError(_STATE)


def _prepared_ack(owner: InitialSelectionPreparationOwner, request: _Request) -> None:
    # Both objects may have changed while Condition.wait released the lock.
    _state(owner)
    _request(request)
    if (
        not request.dispatched
        or not owner._attempted
        or owner._slot is not None
        or owner._active_nonce is not None
        or owner._busy
        or owner._phase != "idle"
    ):
        raise ValueError(_STATE)


def _install_bindings(adapter: installation._InitialSelectionInstallation | None = None) -> None:
    if (
        installation._InitialSelectionInstallation is not _INSTALLATION
        or installation.InitialSelectionInstallationObservation is not _I_CLASS
        or _InstallRequest is not _INSTALL_REQUEST_CLASS
        or vars(_INSTALL_REQUEST_CLASS).get("__init__") is not _INSTALL_REQUEST_INIT
        or vars(_INSTALL_REQUEST_CLASS).get("__post_init__") is not _INSTALL_REQUEST_VALIDATE
        or InitialSelectionInstallationResult is not _INSTALL_RESULT_CLASS
        or vars(_INSTALL_RESULT_CLASS).get("__init__") is not _INSTALL_RESULT_INIT
        or vars(_INSTALL_RESULT_CLASS).get("__post_init__") is not _INSTALL_RESULT_VALIDATE
    ):
        raise RuntimeError(_BINDING)
    for name, expected in (
        ("_receipt_values", _RECEIPT_VALUES),
        ("_receipt_from_values", _RECEIPT_FROM_VALUES),
        ("_native_receipt_values", _NATIVE_RECEIPT_VALUES),
        ("_observation_values", _I_VALUES),
        ("_observation_from_values", _I_FROM_VALUES),
    ):
        if vars(installation).get(name) is not expected:
            raise RuntimeError(_BINDING)
    if adapter is not None and type(adapter) is not _INSTALLATION:
        raise ValueError(_STATE)
    for name, expected_method in (
        ("__init__", _INSTALLATION_INIT),
        ("install", _INSTALL),
        ("observation", _OBSERVE),
    ):
        if vars(_INSTALLATION).get(name) is not expected_method or (
            adapter is not None and name in vars(adapter)
        ):
            raise RuntimeError(_BINDING)
    if (
        vars(_I_CLASS).get("__init__") is not _I_INIT
        or vars(_I_CLASS).get("__post_init__") is not _I_VALIDATE
    ):
        raise RuntimeError(_BINDING)


def _install_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(_STATE)
    return value


def _observation_snapshot(value: object) -> installation._ObservationValues:
    _INSTALL_BINDINGS()
    if type(value) is not _I_CLASS:
        raise ValueError(_STATE)
    if not isinstance(value, installation.InitialSelectionInstallationObservation):
        raise ValueError(_STATE)
    try:
        return _I_VALUES(
            (
                value.attempted,
                value.publication_started,
                value.publication_returned,
                value.request_receipt_sha256,
                value.assignment_sha256,
            )
        )
    except ValueError:
        raise ValueError(_STATE) from None


def _install_request(value: object) -> _InstallRequest:
    _INSTALL_BINDINGS()
    if type(value) is not _INSTALL_REQUEST_CLASS:
        raise ValueError(_STATE)
    if not isinstance(value, _InstallRequest):
        raise ValueError(_STATE)
    if (
        type(value.call_id) is not str
        or type(value.incarnation) is not str
        or type(value.deadline_ns) is not int
        or not 0 < value.deadline_ns <= _MAX_NS
        or (value.cancel_event is not None and type(value.cancel_event) is not Event)
        or type(value.nonce) is not object
        or type(value.abandoned) is not bool
        or type(value.dispatched) is not bool
        or (value._worker_thread is not None and type(value._worker_thread) is not Thread)
        or value.dispatched != (value._worker_thread is not None)
    ):
        raise ValueError(_STATE)
    _INSTALL_DIGEST(value.request_receipt_sha256)
    try:
        _NATIVE_RECEIPT_VALUES(value.receipt_values)
    except ValueError:
        raise ValueError(_STATE) from None
    try:
        admission = value._admission
    except AttributeError:
        raise ValueError(_STATE) from None
    if (
        type(admission) is not tuple
        or len(admission) != 7
        or type(admission[0]) is not str
        or type(admission[1]) is not str
        or (admission[2] is not None and type(admission[2]) is not Event)
        or type(admission[5]) is not object
        or type(admission[6]) is not int
        or not 0 < admission[6] <= _MAX_NS
    ):
        raise ValueError(_STATE)
    _INSTALL_DIGEST(admission[4])
    try:
        original_receipt = _NATIVE_RECEIPT_VALUES(admission[3])
    except ValueError:
        raise ValueError(_STATE) from None
    if (
        value.call_id != admission[0]
        or value.incarnation != admission[1]
        or value.cancel_event is not admission[2]
        or value.receipt_values != original_receipt
        or value.request_receipt_sha256 != admission[4]
        or value.nonce is not admission[5]
        or value.deadline_ns > admission[6]
    ):
        raise ValueError(_STATE)
    if value.result is not None:
        if type(value.result) is not tuple or len(value.result) != 2:
            raise ValueError(_STATE)
        reason, observation = value.result
        if not _native_text(reason) or reason not in _INSTALL_REASONS:
            raise ValueError(_STATE)
        if observation is not None:
            try:
                _I_VALUES(observation)
            except ValueError:
                raise ValueError(_STATE) from None
        if (reason == "installed") != (observation is not None):
            raise ValueError(_STATE)
    return value


def _install_state(owner: InitialSelectionPreparationOwner) -> None:
    values = vars(owner)
    if any(
        type(values.get(name)) is not bool
        for name in (
            "_preparation_return_admitted",
            "_install_dispatched",
            "_install_succeeded",
            "_install_return_admitted",
        )
    ):
        raise ValueError(_STATE)
    proposal = values.get("_prepared_proposal_sha256")
    if owner._preparation_return_admitted or proposal is not None:
        _INSTALL_DIGEST(proposal)
    terminal = values.get("_terminal_install")
    if terminal is not None:
        request = _INSTALL_REQUEST(terminal)
        if (
            not owner._install_dispatched
            or not request.dispatched
            or owner._thread is not request._worker_thread
        ):
            raise ValueError(_STATE)
    elif owner._install_dispatched:
        raise ValueError(_STATE)
    observation = values.get("_install_observation")
    if observation is not None:
        try:
            _I_VALUES(observation)
        except ValueError:
            raise ValueError(_STATE) from None
    if owner._install_succeeded and observation is None:
        raise ValueError(_STATE)
    if owner._install_return_admitted and not owner._install_succeeded:
        raise ValueError(_STATE)


def _install_result(
    call_id: str,
    incarnation: str,
    reason: _InstallReason,
    values: installation._ObservationValues | None = None,
) -> InitialSelectionInstallationResult:
    _INSTALL_BINDINGS()
    _identifier(call_id)
    _identifier(incarnation)
    if not _native_text(reason) or reason not in _INSTALL_REASONS:
        raise ValueError(_STATE)
    if reason == "installed":
        if values is None:
            raise ValueError(_STATE)
        observation = _I_FROM_VALUES(_I_VALUES(values))
        return _INSTALL_RESULT_CLASS("installed", reason, call_id, incarnation, observation)
    if values is not None:
        raise ValueError(_STATE)
    return _INSTALL_RESULT_CLASS("unavailable", reason, call_id, incarnation, None)


def _install_ack(owner: InitialSelectionPreparationOwner, request: _InstallRequest) -> None:
    _HOST_STATE(owner)
    _INSTALL_REQUEST(request)
    if (
        owner._terminal_install is not request
        or not request.dispatched
        or request.incarnation != owner._incarnation
        or not owner._install_dispatched
        or not owner._preparation_return_admitted
        or not owner._install_succeeded
        or owner._install_return_admitted
        or request.abandoned
        or owner._slot is not None
        or owner._active_nonce is not None
        or owner._busy
        or not owner._finalized
        or not owner._cleanup_ok
        or owner._cleanup_failure is not None
        or owner._primary_error is not None
        or request._worker_thread is None
        or owner._thread is not request._worker_thread
        or _THREAD_ALIVE(request._worker_thread)
        or owner._phase not in ("stopping", "stopped")
        or request.result is None
        or request.result[0] != "installed"
    ):
        raise ValueError(_STATE)
    values = owner._install_observation
    if (
        values is None
        or request.result[1] != values
        or values[:3] != (True, True, True)
        or values[3] != request.request_receipt_sha256
        or values[4] != owner._prepared_proposal_sha256
    ):
        raise ValueError(_STATE)


def _install_unavailable(
    owner: InitialSelectionPreparationOwner,
    request: _InstallRequest,
) -> _InstallReason | None:
    now = _NOW(owner)
    if now is None:
        return "clock_invalid"
    if request.abandoned or (
        request.cancel_event is not None and _event_is_set(request.cancel_event)
    ):
        return "cancelled"
    if now >= min(request.deadline_ns, owner._work_deadline):
        if now >= owner._work_deadline:
            _LATCH(owner, "lifetime_expired")
        return "deadline"
    if owner._stop_latched or _event_is_set(owner._stop_event):
        _LATCH(owner, None)
        return "stopping"
    return None


def _serve_install(
    owner: InitialSelectionPreparationOwner,
    runtime: readiness._ReadinessRuntime,
    preparation_adapter: preparation._InitialSelectionPreparation,
    request: _InstallRequest,
) -> None:
    _HOST_ENTRY(owner)
    condition = owner._condition
    nonce = request.nonce
    failure: BaseException | None = None
    adapter: installation._InitialSelectionInstallation | None = None
    observation: installation._ObservationValues | None = None
    returned: installation._ObservationValues | None = None
    ceiling = request.deadline_ns
    try:
        _HOST_ENTRY(owner)
        _INSTALL_REQUEST(request)
        if (
            request._worker_thread is not current_thread()
            or owner._thread is not request._worker_thread
        ):
            raise ValueError(_STATE)
        _operation_bindings(preparation_adapter)
        _INSTALL_BINDINGS()
        receipt = _RECEIPT_FROM_VALUES(request.receipt_values)
        adapter = _INSTALLATION(preparation_adapter)
        _INSTALL_BINDINGS(adapter)
        candidate = _INSTALL(adapter, receipt, deadline_ns=request.deadline_ns)
        _INSTALL_BINDINGS(adapter)
        returned = _OBSERVATION_SNAPSHOT(candidate)
        if (
            returned[:3] != (True, True, True)
            or returned[3] != request.request_receipt_sha256
            or returned[4] != owner._prepared_proposal_sha256
        ):
            raise ValueError(_STATE)
        # Only a successful original install is refreshed. A failed original
        # call must not be replaced by a redundant R1/stop exception.
        refreshed = _lease_ceiling(runtime) - _RESERVE_NS
        if not 0 < refreshed <= _MAX_NS:
            raise ValueError(_STATE)
        ceiling = min(ceiling, refreshed)
    except BaseException as error:
        failure = error
    finally:
        if adapter is not None:
            try:
                _INSTALL_BINDINGS(adapter)
                observation = _OBSERVATION_SNAPSHOT(_OBSERVE(adapter))
                if returned is not None and observation != returned:
                    raise ValueError(_STATE)
            except BaseException as error:
                failure = (
                    error
                    if failure is None
                    else BaseExceptionGroup(
                        "initial selection installation and observation failed", [failure, error]
                    )
                )
    try:
        with condition:
            # Retain already observed publication facts even if the following
            # host acknowledgement guard rejects a changed private carrier.
            owner._install_observation = observation
            _HOST_STATE(owner)
            _INSTALL_REQUEST(request)
            if (
                owner._slot is not request
                or owner._active_nonce is not nonce
                or owner._terminal_install is not request
                or request.nonce is not nonce
                or not owner._install_dispatched
                or not request.dispatched
                or request._worker_thread is not current_thread()
            ):
                raise ValueError(_STATE)
            owner._install_succeeded = failure is None and returned is not None
            request.deadline_ns = min(request.deadline_ns, ceiling)
            owner._work_deadline = min(owner._work_deadline, ceiling)
            owner._phase = "stopping"
            condition.notify_all()
    except BaseException as error:
        if failure is not None:
            raise BaseExceptionGroup(
                "initial selection installation and completion failed", [failure, error]
            ) from None
        raise
    if failure is not None:
        raise failure


def _finalize_install(owner: InitialSelectionPreparationOwner, cleanup_ok: bool) -> None:
    # The original context-exit block has already completed. This function
    # never owns financial cleanup and never signals ordinary terminal exit.
    _HOST_ENTRY(owner)
    condition = owner._condition
    if type(condition) is not Condition or condition is not owner._original[4]:
        raise ValueError(_STATE)
    with condition:
        _HOST_STATE(owner)
        request = _INSTALL_REQUEST(owner._terminal_install)
        if (
            owner._slot is not request
            or owner._active_nonce is not request.nonce
            or not request.dispatched
            or not owner._install_dispatched
            or request._worker_thread is not current_thread()
        ):
            raise ValueError(_STATE)
        if not cleanup_ok:
            owner._cleanup_failure = "cleanup_failed"
        owner._cleanup_ok = cleanup_ok
        if owner._primary_error is not None or not owner._install_succeeded:
            request.result = ("installation_failed", None)
        elif not cleanup_ok:
            request.result = ("cleanup_failed", None)
        else:
            values = owner._install_observation
            if values is None:
                raise ValueError(_STATE)
            request.result = ("installed", values)
        owner._slot, owner._active_nonce = None, None
        owner._busy, owner._finalized, owner._phase = False, True, "stopping"
        condition.notify_all()


class InitialSelectionPreparationOwner:
    """One original context, preparation and terminal installation dispatch."""

    def __init__(
        self,
        *,
        configuration_path: str,
        account_id: str,
        instance_lock: str,
        limits: ReadinessOwnerLimits = _DEFAULT_LIMITS,
    ) -> None:
        if type(self) is not _OWNER or InitialSelectionPreparationOwner is not _OWNER:
            raise ValueError(_ARGUMENT)
        if vars(self):
            raise ValueError(_STATE)
        for name, original in _OWN_METHODS:
            if vars(_OWNER).get(name) is not original:
                raise RuntimeError(_BINDING)
        for name, original_install_method in _INSTALL_METHODS:
            if vars(_OWNER).get(name) is not original_install_method:
                raise RuntimeError(_BINDING)
        for name, original_install_helper in _INSTALL_HELPERS:
            if globals().get(name) is not original_install_helper:
                raise RuntimeError(_BINDING)
        _operation_bindings()
        native_limits = _native_limits(limits)
        account_id = _identifier(account_id)
        try:
            configuration_file = _ARGUMENT_PATH(configuration_path)
            lock_path = _ARGUMENT_PATH(instance_lock)
            if configuration_file.suffix != ".json":
                raise ValueError(_ARGUMENT)
        except ValueError:
            raise ValueError(_ARGUMENT) from None
        self._instance = self
        self._configuration_file, self._account_id, self._lock_path = (
            configuration_file,
            account_id,
            lock_path,
        )
        self._limits = native_limits
        self._condition = Condition(Lock())
        self._stop_event = Event()
        self._incarnation = uuid4().hex
        self._original = (
            configuration_file,
            account_id,
            lock_path,
            native_limits,
            self._condition,
            self._stop_event,
            self._incarnation,
        )
        self._thread: Thread | None = None
        self._phase: _Phase = "new"
        self._busy, self._attempted, self._finalized = False, False, False
        self._cleanup_ok, self._stop_latched = True, False
        self._slot: _Request | _InstallRequest | _ProofRequest | None = None
        self._active_nonce: object | None = None
        self._last_ns: int | None = None
        self._shutdown_deadline: int | None = None
        self._startup_deadline = self._lifetime_deadline = self._work_deadline = _MAX_NS
        self._primary_failure: str | None = None
        self._cleanup_failure: str | None = None
        self._primary_error: BaseException | None = None
        self._cleanup_error: BaseException | None = None
        self._context_error: BaseException | None = None
        self._preparation_return_admitted = False
        self._prepared_proposal_sha256: str | None = None
        self._install_dispatched = False
        self._terminal_install: _InstallRequest | None = None
        self._install_observation: installation._ObservationValues | None = None
        self._install_succeeded = False
        self._install_return_admitted = False

    def _snapshot(self) -> InitialSelectionPreparationOwnerStatus:
        _state(self)
        alive = self._thread is not None and _THREAD_ALIVE(self._thread)
        if self._finalized and not alive:
            self._phase = "stopped"
        complete = self._phase == "new" or (self._finalized and not alive and self._cleanup_ok)
        return InitialSelectionPreparationOwnerStatus(
            self._phase,
            self._busy,
            self._attempted,
            complete,
            self._primary_failure,
            self._cleanup_failure,
            self._incarnation,
        )

    def _latch(self, reason: str | None) -> None:
        # A failed binding check must not direct stop/notification to a foreign
        # replacement. These are the originally retained native primitives.
        original = self._original
        if type(original) is not tuple or len(original) != 7:
            raise ValueError(_STATE)
        condition, stop_event = original[4], original[5]
        if type(condition) is not Condition or type(stop_event) is not Event:
            raise ValueError(_STATE)
        if reason is not None and self._primary_failure is None:
            self._primary_failure = reason
        _EVENT_SET(stop_event)
        self._stop_latched, self._phase = True, "stopping"
        if self._thread is None:
            self._finalized, self._cleanup_ok = True, True
        condition.notify_all()

    def _now(self) -> int | None:
        _state(self)
        try:
            now = time.monotonic_ns()
        except BaseException:
            _LATCH(self, "clock_invalid")
            return None
        if (
            type(now) is not int
            or not 0 <= now <= _MAX_NS
            or (self._last_ns is not None and now < self._last_ns)
        ):
            _LATCH(self, "clock_invalid")
            return None
        self._last_ns = now
        try:
            stopped = _event_is_set(self._stop_event)
        except ValueError:
            _LATCH(self, "preparation_failed")
            return None
        if stopped or self._stop_latched:
            _LATCH(self, None)
        if self._phase not in ("new", "stopping", "stopped") and now >= self._work_deadline:
            _LATCH(self, "lifetime_expired")
        return now

    def start(self) -> InitialSelectionPreparationOwnerStatus:
        _entry(self)
        with self._condition:
            _state(self)
            if self._phase != "new":
                return _SNAPSHOT(self)
            now = _NOW(self)
            if now is None or self._stop_latched:
                return _SNAPSHOT(self)
            if now > _MAX_NS - self._limits[3]:
                _LATCH(self, "clock_invalid")
                return _SNAPSHOT(self)
            self._lifetime_deadline = now + self._limits[3]
            self._work_deadline = max(0, self._lifetime_deadline - _RESERVE_NS)
            self._startup_deadline = min(now + self._limits[0], self._work_deadline)
            self._phase, self._busy, self._cleanup_ok = "starting", True, False
            self._thread = Thread(
                target=_RUN, args=(self,), name="initial-selection-preparation", daemon=False
            )
            try:
                _THREAD_START(self._thread)
            except BaseException as error:
                # Failed acknowledgement does not prove a native Thread never ran.
                self._primary_error = error
                _LATCH(self, "startup_failed")
                return _SNAPSHOT(self)
            try:
                while self._phase == "starting":
                    now = _NOW(self)
                    if now is None or self._stop_latched:
                        break
                    if now >= self._startup_deadline:
                        _LATCH(self, "startup_deadline")
                        break
                    self._condition.wait(min(_POLL_SECONDS, (self._startup_deadline - now) / 1e9))
            except BaseException:
                _LATCH(self, None)
                raise
            return _SNAPSHOT(self)

    def status(self) -> InitialSelectionPreparationOwnerStatus:
        _entry(self)
        with self._condition:
            return _SNAPSHOT(self)

    def check_initial_selection_readiness(
        self,
        call_id: str,
        *,
        cancel_event: Event | None = None,
    ) -> InitialSelectionReadinessResult:
        _HOST_ENTRY(self)
        original = self._original
        condition = self._condition
        worker = self._thread
        _PROOF_BINDINGS()
        call_id = _identifier(call_id)
        if cancel_event is not None and type(cancel_event) is not Event:
            raise ValueError(_ARGUMENT)
        with condition:
            if (
                self._original is not original
                or self._condition is not condition
                or self._thread is not worker
                or original[4] is not condition
            ):
                raise ValueError(_STATE)
            _HOST_STATE(self)
            _PROOF_BINDINGS()
            incarnation = self._incarnation
            if current_thread() is self._thread:
                return _PROOF_RESULT(call_id, incarnation, "reentrant")
            if _SNAPSHOT(self).phase == "stopped":
                return _PROOF_RESULT(call_id, incarnation, "stopped")
            now = _NOW(self)
            if (
                self._original is not original
                or self._condition is not condition
                or self._thread is not worker
            ):
                raise ValueError(_STATE)
            _HOST_STATE(self)
            if now is None:
                return _PROOF_RESULT(call_id, incarnation, "clock_invalid")
            if self._phase != "idle":
                if self._phase == "new":
                    return _PROOF_RESULT(call_id, incarnation, "not_started")
                if self._phase == "starting":
                    return _PROOF_RESULT(call_id, incarnation, "starting")
                if self._phase == "busy":
                    return _PROOF_RESULT(call_id, incarnation, "busy")
                return _PROOF_RESULT(call_id, incarnation, "stopping")
            if self._slot is not None or self._busy:
                return _PROOF_RESULT(call_id, incarnation, "busy")
            if self._attempted:
                return _PROOF_RESULT(call_id, incarnation, "already_attempted")
            _PROOF_ELIGIBLE(self)
            if cancel_event is not None and _event_is_set(cancel_event):
                return _PROOF_RESULT(call_id, incarnation, "cancelled")
            request = _PROOF_REQUEST_CLASS(
                call_id,
                incarnation,
                min(now + self._limits[1], self._work_deadline),
                cancel_event,
            )
            admission = request._admission
            if (
                self._original is not original
                or self._condition is not condition
                or self._thread is not worker
            ):
                raise ValueError(_STATE)
            _HOST_STATE(self)
            _PROOF_ELIGIBLE(self)
            if (
                self._slot is not None
                or self._active_nonce is not None
                or self._busy
                or self._phase != "idle"
            ):
                raise ValueError(_STATE)
            self._slot, self._active_nonce = request, request.nonce
            self._busy, self._phase = True, "busy"
            condition.notify_all()
            try:
                while True:
                    if (
                        self._original is not original
                        or self._condition is not condition
                        or self._thread is not worker
                    ):
                        raise ValueError(_STATE)
                    _HOST_STATE(self)
                    _PROOF_IDENTITY(self, request, condition, admission)
                    unavailable = _PROOF_UNAVAILABLE(self, request)
                    if (
                        self._original is not original
                        or self._condition is not condition
                        or self._thread is not worker
                    ):
                        raise ValueError(_STATE)
                    _PROOF_IDENTITY(self, request, condition, admission)
                    if unavailable is not None:
                        request.abandoned = True
                        _PROOF_RELEASE(self, request, condition)
                        condition.notify_all()
                        return _PROOF_RESULT(call_id, incarnation, unavailable)
                    if request.completed:
                        reason = request.result
                        if reason is None:
                            raise ValueError(_STATE)
                        if reason != "verified":
                            request.abandoned = True
                            _PROOF_RELEASE(self, request, condition)
                            return _PROOF_RESULT(call_id, incarnation, reason)
                        _PROOF_ACK(self, request)
                        result = _PROOF_RESULT(call_id, incarnation, "verified")
                        if (
                            self._original is not original
                            or self._condition is not condition
                            or self._thread is not worker
                        ):
                            raise ValueError(_STATE)
                        _HOST_STATE(self)
                        _PROOF_IDENTITY(self, request, condition, admission)
                        unavailable = _PROOF_UNAVAILABLE(self, request)
                        if (
                            self._original is not original
                            or self._condition is not condition
                            or self._thread is not worker
                        ):
                            raise ValueError(_STATE)
                        _PROOF_IDENTITY(self, request, condition, admission)
                        if unavailable is not None:
                            request.abandoned = True
                            _PROOF_RELEASE(self, request, condition)
                            condition.notify_all()
                            return _PROOF_RESULT(call_id, incarnation, unavailable)
                        _PROOF_ACK(self, request)
                        if not _PROOF_RELEASE(self, request, condition):
                            raise ValueError(_STATE)
                        return result
                    sampled = self._last_ns
                    if sampled is None:
                        raise ValueError(_STATE)
                    condition.wait(min(_POLL_SECONDS, max(0, request.deadline_ns - sampled) / 1e9))
            except BaseException:
                # Even a changed host alias cannot redirect this notification.
                # The worker releases only this request once it is quiescent.
                request.abandoned = True
                condition.notify_all()
                raise

    def prepare_initial_selection(
        self,
        call_id: str,
        *,
        cancel_event: Event | None = None,
    ) -> InitialSelectionPreparationResult:
        _entry(self)
        call_id = _identifier(call_id)
        if cancel_event is not None and type(cancel_event) is not Event:
            raise ValueError(_ARGUMENT)
        with self._condition:
            _state(self)
            if current_thread() is self._thread:
                return _result(call_id, self._incarnation, "reentrant")
            if _SNAPSHOT(self).phase == "stopped":
                return _result(call_id, self._incarnation, "stopped")
            now = _NOW(self)
            if now is None:
                return _result(call_id, self._incarnation, "clock_invalid")
            if self._phase != "idle":
                reason: _Reason = "not_started" if self._phase == "new" else self._phase
                return _result(call_id, self._incarnation, reason)
            if self._slot is not None or self._busy:
                return _result(call_id, self._incarnation, "busy")
            if self._attempted:
                return _result(call_id, self._incarnation, "already_attempted")
            if cancel_event is not None and _event_is_set(cancel_event):
                return _result(call_id, self._incarnation, "cancelled")
            request = _Request(
                call_id,
                self._incarnation,
                min(now + self._limits[1], self._work_deadline),
                cancel_event,
            )
            nonce = request.nonce
            self._slot, self._active_nonce = request, request.nonce
            self._busy, self._phase = True, "busy"
            self._condition.notify_all()
            try:
                while True:
                    _state(self)
                    _request(request)
                    if request.nonce is not nonce or request.incarnation != self._incarnation:
                        raise ValueError(_STATE)
                    now = _NOW(self)
                    unavailable: _Reason | None = "clock_invalid" if now is None else None
                    if (
                        unavailable is None
                        and cancel_event is not None
                        and _event_is_set(cancel_event)
                    ):
                        unavailable = "cancelled"
                    if unavailable is None and now is not None and now >= request.deadline_ns:
                        unavailable = "deadline"
                    if (
                        unavailable is None
                        and self._stop_latched
                        and (request.result is None or request.result[0] == "prepared")
                    ):
                        unavailable = "stopping"
                    if unavailable is not None:
                        request.abandoned = True
                        self._condition.notify_all()
                        return _result(call_id, self._incarnation, unavailable)
                    if request.result is not None:
                        completion = request.result
                        if request.result[0] == "prepared":
                            _prepared_ack(self, request)
                        result = _result(call_id, self._incarnation, *completion)
                        if result.status == "unavailable":
                            return result
                        prepared_values = completion[1]
                        if prepared_values is None:
                            raise ValueError(_STATE)
                        proposal_sha = _INSTALL_DIGEST(prepared_values[3])
                        # Projection is also inside the original delivery budget.
                        final_now = _NOW(self)
                        if final_now is None:
                            request.abandoned = True
                            return _result(call_id, self._incarnation, "clock_invalid")
                        if self._stop_latched:
                            request.abandoned = True
                            return _result(call_id, self._incarnation, "stopping")
                        if final_now >= request.deadline_ns:
                            request.abandoned = True
                            return _result(call_id, self._incarnation, "deadline")
                        if request.abandoned or (
                            cancel_event is not None and _event_is_set(cancel_event)
                        ):
                            request.abandoned = True
                            return _result(call_id, self._incarnation, "cancelled")
                        self._prepared_proposal_sha256 = proposal_sha
                        self._preparation_return_admitted = True
                        return result
                    if now is None:
                        raise ValueError(_STATE)
                    self._condition.wait(min(_POLL_SECONDS, (request.deadline_ns - now) / 1e9))
            except BaseException:
                request.abandoned = True
                self._preparation_return_admitted = False
                self._prepared_proposal_sha256 = None
                self._condition.notify_all()
                raise

    def install_initial_selection(
        self,
        call_id: str,
        *,
        request_receipt: JournalReceipt,
        cancel_event: Event | None = None,
    ) -> InitialSelectionInstallationResult:
        _HOST_ENTRY(self)
        condition = self._condition
        if type(condition) is not Condition or condition is not self._original[4]:
            raise ValueError(_STATE)
        call_id = _identifier(call_id)
        if cancel_event is not None and type(cancel_event) is not Event:
            raise ValueError(_ARGUMENT)
        _INSTALL_BINDINGS()
        try:
            receipt_values = _RECEIPT_VALUES(request_receipt)
            receipt = _RECEIPT_FROM_VALUES(receipt_values)
            request_sha = _INSTALL_DIGEST(receipt.semantic_sha256)
        except ValueError:
            raise ValueError(_ARGUMENT) from None
        _INSTALL_BINDINGS()
        with condition:
            _HOST_STATE(self)
            if current_thread() is self._thread:
                return _INSTALL_RESULT(call_id, self._incarnation, "reentrant")
            if _SNAPSHOT(self).phase == "stopped":
                return _INSTALL_RESULT(call_id, self._incarnation, "stopped")
            now = _NOW(self)
            if now is None:
                return _INSTALL_RESULT(call_id, self._incarnation, "clock_invalid")
            if self._phase != "idle":
                if self._phase == "new":
                    return _INSTALL_RESULT(call_id, self._incarnation, "not_started")
                if self._phase == "starting":
                    return _INSTALL_RESULT(call_id, self._incarnation, "starting")
                if self._phase == "busy":
                    return _INSTALL_RESULT(call_id, self._incarnation, "busy")
                return _INSTALL_RESULT(call_id, self._incarnation, "stopping")
            if self._slot is not None or self._busy:
                return _INSTALL_RESULT(call_id, self._incarnation, "busy")
            if not self._preparation_return_admitted:
                return _INSTALL_RESULT(call_id, self._incarnation, "preparation_unavailable")
            if self._install_dispatched:
                return _INSTALL_RESULT(call_id, self._incarnation, "already_attempted")
            if cancel_event is not None and _event_is_set(cancel_event):
                return _INSTALL_RESULT(call_id, self._incarnation, "cancelled")
            request = _INSTALL_REQUEST_CLASS(
                call_id,
                self._incarnation,
                min(now + self._limits[1], self._work_deadline),
                cancel_event,
                receipt_values,
                request_sha,
            )
            nonce = request.nonce
            self._slot, self._active_nonce = request, nonce
            self._busy, self._phase = True, "busy"
            condition.notify_all()
            try:
                while True:
                    _HOST_STATE(self)
                    _INSTALL_REQUEST(request)
                    if (
                        request.nonce is not nonce
                        or request.incarnation != self._incarnation
                        or request.call_id != call_id
                        or request.receipt_values != receipt_values
                        or request.request_receipt_sha256 != request_sha
                        or request.cancel_event is not cancel_event
                    ):
                        raise ValueError(_STATE)
                    unavailable = _INSTALL_UNAVAILABLE(self, request)
                    if unavailable is not None:
                        request.abandoned = True
                        condition.notify_all()
                        return _INSTALL_RESULT(call_id, self._incarnation, unavailable)
                    if request.result is not None:
                        reason, values = request.result
                        if reason != "installed":
                            request.abandoned = True
                            return _INSTALL_RESULT(call_id, self._incarnation, reason)
                        # Finalization occurs before Thread death. Keep the original
                        # bounded wait; no success or extra shutdown budget yet.
                        if self._thread is None:
                            raise ValueError(_STATE)
                        if not _THREAD_ALIVE(self._thread):
                            _INSTALL_ACK(self, request)
                            result = _INSTALL_RESULT(call_id, self._incarnation, reason, values)
                            _HOST_STATE(self)
                            _INSTALL_REQUEST(request)
                            if (
                                request.nonce is not nonce
                                or request.incarnation != self._incarnation
                                or request.call_id != call_id
                                or request.receipt_values != receipt_values
                                or request.request_receipt_sha256 != request_sha
                                or request.cancel_event is not cancel_event
                            ):
                                raise ValueError(_STATE)
                            unavailable = _INSTALL_UNAVAILABLE(self, request)
                            if unavailable is not None:
                                request.abandoned = True
                                condition.notify_all()
                                return _INSTALL_RESULT(call_id, self._incarnation, unavailable)
                            _INSTALL_ACK(self, request)
                            self._install_return_admitted = True
                            return result
                    sampled = self._last_ns
                    if sampled is None:
                        raise ValueError(_STATE)
                    remaining = max(0, request.deadline_ns - sampled)
                    condition.wait(min(_POLL_SECONDS, remaining / 1e9))
            except BaseException:
                request.abandoned = True
                self._install_return_admitted = False
                condition.notify_all()
                raise

    def stop(self) -> InitialSelectionPreparationOwnerStatus:
        _entry(self)
        with self._condition:
            _state(self)
            if self._phase == "new":
                _LATCH(self, None)
                return _SNAPSHOT(self)
            terminal = self._terminal_install
            if (
                terminal is not None
                and not terminal.abandoned
                and not self._install_return_admitted
            ):
                # A completed worker can still have a pending caller. Record an
                # explicit stop before the original stopped fast return.
                _LATCH(self, None)
            if _SNAPSHOT(self).phase == "stopped":
                return _SNAPSHOT(self)
            _LATCH(self, None)
            now = _NOW(self)
            if self._shutdown_deadline is None and now is not None:
                self._shutdown_deadline = min(now + self._limits[2], _MAX_NS)
            if current_thread() is self._thread or now is None:
                return _SNAPSHOT(self)
            deadline = self._shutdown_deadline
            if deadline is None:
                return _SNAPSHOT(self)
            while not (
                self._finalized and self._thread is not None and not _THREAD_ALIVE(self._thread)
            ):
                now = _NOW(self)
                if now is None or now >= deadline:
                    break
                self._condition.wait(min(_POLL_SECONDS, (deadline - now) / 1e9))
            result = _SNAPSHOT(self)
        if result.phase == "stopped" and self._thread is not None:
            _THREAD_JOIN(self._thread, timeout=0)
        return result

    def _serve(
        self,
        runtime: readiness._ReadinessRuntime,
        adapter: preparation._InitialSelectionPreparation,
    ) -> None:
        while True:
            install_request: _InstallRequest | None = None
            proof_request: _ProofRequest | None = None
            with self._condition:
                if type(self._slot) is _PROOF_REQUEST_CLASS:
                    _state(self)
                    proof_request = _PROOF_REQUEST(self._slot)
                else:
                    _state(self)
                    now = _NOW(self)
                    if now is None or self._stop_latched:
                        return
                    request = self._slot
                    if request is None:
                        self._condition.wait(min(_POLL_SECONDS, (self._work_deadline - now) / 1e9))
                        continue
                    if type(request) is _INSTALL_REQUEST_CLASS:
                        install_request = _INSTALL_REQUEST(request)
                        cancelled = install_request.cancel_event is not None and _event_is_set(
                            install_request.cancel_event
                        )
                        if (
                            install_request.abandoned
                            or now >= install_request.deadline_ns
                            or cancelled
                        ):
                            install_request.result = (
                                "cancelled"
                                if install_request.abandoned or cancelled
                                else "deadline",
                                None,
                            )
                            self._slot, self._active_nonce = None, None
                            self._busy, self._phase = False, "idle"
                            self._condition.notify_all()
                            continue
                        if self._install_dispatched or not self._preparation_return_admitted:
                            raise ValueError(_STATE)
                        worker_thread = current_thread()
                        if self._thread is not worker_thread:
                            raise ValueError(_STATE)
                        install_request._worker_thread = worker_thread
                        install_request.dispatched, self._install_dispatched = True, True
                        self._terminal_install = install_request
                    else:
                        request = _request(request)
                        cancelled = request.cancel_event is not None and _event_is_set(
                            request.cancel_event
                        )
                        if request.abandoned or now >= request.deadline_ns or cancelled:
                            request.result = (
                                "cancelled" if request.abandoned or cancelled else "deadline",
                                None,
                            )
                            self._slot, self._active_nonce = None, None
                            self._busy, self._phase = False, "idle"
                            self._condition.notify_all()
                            continue
                        if self._attempted:
                            raise ValueError(_STATE)
                        request.dispatched, self._attempted = True, True
                        nonce = request.nonce
                        deadline = request.deadline_ns
            if proof_request is not None:
                _SERVE_PROOF(self, runtime, proof_request)
                continue
            if install_request is not None:
                _SERVE_INSTALL(self, runtime, adapter, install_request)
                return
            request = _request(request)
            failure: BaseException | None = None
            values: _DescriptorValues | None = None
            ceiling = deadline
            try:
                _entry(self)
                _operation_bindings(adapter)
                candidate = _PREPARE(adapter, deadline_ns=deadline)
                _operation_bindings(adapter)
                values = _D_VALUES(candidate)
                ceiling = _lease_ceiling(runtime) - _RESERVE_NS
            except BaseException as error:
                failure = error
            with self._condition:
                _state(self)
                if self._slot is not request or self._active_nonce is not nonce:
                    raise ValueError(_STATE)
                now = _NOW(self)
                request.deadline_ns = min(request.deadline_ns, ceiling)
                reason: _Reason = "prepared"
                if failure is not None:
                    self._primary_error = failure
                    _LATCH(self, "preparation_failed")
                    reason = "preparation_failed"
                elif now is None:
                    reason = "clock_invalid"
                elif _native_bool(self._stop_latched):
                    reason = "stopping"
                elif now >= request.deadline_ns:
                    reason = "deadline"
                elif request.abandoned or (
                    request.cancel_event is not None and _event_is_set(request.cancel_event)
                ):
                    reason = "cancelled"
                self._work_deadline = min(self._work_deadline, max(0, ceiling))
                request.result = (reason, values if reason == "prepared" else None)
                self._slot, self._active_nonce, self._busy = None, None, False
                if not _native_bool(self._stop_latched):
                    self._phase = "idle"
                self._condition.notify_all()
            if failure is not None:
                raise failure

    def _run(self) -> None:
        condition, stop_event = self._original[4], self._original[5]
        if type(condition) is not Condition or type(stop_event) is not Event:
            return
        context: AbstractContextManager[readiness._ReadinessRuntime] | None = None
        entered = False
        primary: BaseException | None = None
        partial_cleanup_failed = False
        try:
            _entry(self)
            with condition:
                _state(self)
                now = _NOW(self)
                if now is not None and now >= self._startup_deadline:
                    _LATCH(self, "startup_deadline")
                if now is None or self._stop_latched:
                    return
            _operation_bindings()

            @contextmanager
            def open_runtime() -> Iterator[readiness._ReadinessRuntime]:
                _entry(self)
                _operation_bindings()
                yield from _GENERATOR(
                    configuration_file=self._configuration_file,
                    lock_path=self._lock_path,
                    account_id=self._account_id,
                    stop_event=stop_event,
                )

            context = open_runtime()
            runtime = context.__enter__()
            entered = True
            if type(runtime) is not _RUNTIME or runtime.stop_event is not stop_event:
                raise ValueError(_STATE)
            ceiling = _lease_ceiling(runtime) - _RESERVE_NS
            _operation_bindings()
            adapter = _ADAPTER(runtime)
            _operation_bindings(adapter)
            with condition:
                _state(self)
                self._work_deadline = min(self._work_deadline, max(0, ceiling))
                now = _NOW(self)
                if now is not None and now >= self._startup_deadline:
                    _LATCH(self, "startup_deadline")
                if now is None or self._stop_latched:
                    return
                self._phase, self._busy = "idle", False
                condition.notify_all()
            _SERVE(self, runtime, adapter)
        except BaseException as error:
            primary = error
            partial_cleanup_failed = not entered and isinstance(error, BaseExceptionGroup)
            with condition:
                self._primary_error = error
                if self._install_dispatched:
                    if self._primary_failure is None:
                        self._primary_failure = "installation_failed"
                    self._phase = "stopping"
                    condition.notify_all()
                elif self._primary_failure is None:
                    phase = vars(self).get("_phase")
                    _LATCH(
                        self,
                        "startup_failed"
                        if type(phase) is str and phase == "starting"
                        else "preparation_failed",
                    )
        finally:
            cleanup_ok = not partial_cleanup_failed
            if entered and context is not None:
                try:
                    if primary is None:
                        context.__exit__(None, None, None)
                    else:
                        context.__exit__(type(primary), primary, primary.__traceback__)
                except BaseException as error:
                    cleanup_ok = False
                    self._cleanup_error = self._context_error = error
            elif partial_cleanup_failed:
                self._context_error = primary
            if self._install_dispatched:
                try:
                    _FINALIZE_INSTALL(self, cleanup_ok)
                except BaseException as error:
                    # G exit has already run once. Retain that exact context
                    # outcome and the primary; never invoke a changed Condition
                    # or repeat cleanup to repair a rejected finalization.
                    with condition:
                        previous = self._cleanup_error
                        if previous is None:
                            previous = self._primary_error
                        self._cleanup_error = (
                            error
                            if previous is None
                            else BaseExceptionGroup(
                                "initial selection cleanup and finalization failed",
                                [previous, error],
                            )
                        )
                        self._cleanup_failure = "cleanup_failed"
                        self._cleanup_ok = False
                        self._busy, self._finalized, self._phase = False, True, "stopping"
                        condition.notify_all()
            else:
                with condition:
                    if not cleanup_ok:
                        self._cleanup_failure = "cleanup_failed"
                    self._cleanup_ok = cleanup_ok
                    self._busy, self._finalized, self._phase = False, True, "stopping"
                    self._stop_latched = True
                    _EVENT_SET(stop_event)
                    condition.notify_all()


_OWNER = InitialSelectionPreparationOwner
_SNAPSHOT = _OWNER._snapshot
_LATCH = _OWNER._latch
_NOW = _OWNER._now
_SERVE = _OWNER._serve
_RUN = _OWNER._run
_OWN_METHODS = (
    ("__init__", _OWNER.__init__),
    ("start", _OWNER.start),
    ("status", _OWNER.status),
    ("stop", _OWNER.stop),
    ("prepare_initial_selection", _OWNER.prepare_initial_selection),
    ("_snapshot", _SNAPSHOT),
    ("_latch", _LATCH),
    ("_now", _NOW),
    ("_serve", _SERVE),
    ("_run", _RUN),
)

_INSTALL_REQUEST_CLASS = _InstallRequest
_INSTALL_REQUEST_INIT = _InstallRequest.__init__
_INSTALL_REQUEST_VALIDATE = _InstallRequest.__post_init__
_INSTALL_RESULT_CLASS = InitialSelectionInstallationResult
_INSTALL_RESULT_INIT = InitialSelectionInstallationResult.__init__
_INSTALL_RESULT_VALIDATE = InitialSelectionInstallationResult.__post_init__
_HOST_ENTRY = _entry
_HOST_STATE = _state
_INSTALL_BINDINGS = _install_bindings
_INSTALL_DIGEST = _install_digest
_OBSERVATION_SNAPSHOT = _observation_snapshot
_INSTALL_REQUEST = _install_request
_INSTALL_STATE = _install_state
_INSTALL_RESULT = _install_result
_INSTALL_ACK = _install_ack
_INSTALL_UNAVAILABLE = _install_unavailable
_SERVE_INSTALL = _serve_install
_FINALIZE_INSTALL = _finalize_install
_INSTALL_METHODS = (("install_initial_selection", _OWNER.install_initial_selection),)
_INSTALL_HELPERS = (
    ("_entry", _HOST_ENTRY),
    ("_state", _HOST_STATE),
    ("_install_bindings", _INSTALL_BINDINGS),
    ("_install_digest", _INSTALL_DIGEST),
    ("_observation_snapshot", _OBSERVATION_SNAPSHOT),
    ("_install_request", _INSTALL_REQUEST),
    ("_install_state", _INSTALL_STATE),
    ("_install_result", _INSTALL_RESULT),
    ("_install_ack", _INSTALL_ACK),
    ("_install_unavailable", _INSTALL_UNAVAILABLE),
    ("_serve_install", _SERVE_INSTALL),
    ("_finalize_install", _FINALIZE_INSTALL),
)

_VERIFY = _RUNTIME.verify
_PROOF_RUNTIME_METHODS = (
    ("verify", _VERIFY),
    ("_require", _RUNTIME_REQUIRE),
    ("_now", _RUNTIME._now),
    ("_before", _RUNTIME._before),
    ("_lease_deadline", _RUNTIME._lease_deadline),
)
_PROOF_DEADLINE = readiness._DeadlineExpired
_PROOF_CLOCK = readiness._ClockInvalid
_PROOF_LEASE_CEILING = _lease_ceiling
_PROOF_REQUEST_CLASS = _ProofRequest
_PROOF_REQUEST_INIT = _ProofRequest.__init__
_PROOF_REQUEST_VALIDATE = _ProofRequest.__post_init__
_PROOF_RESULT_CLASS = InitialSelectionReadinessResult
_PROOF_RESULT_INIT = InitialSelectionReadinessResult.__init__
_PROOF_RESULT_VALIDATE = InitialSelectionReadinessResult.__post_init__
_PROOF_BINDINGS = _proof_bindings
_PROOF_REASON = _proof_reason
_PROOF_REQUEST = _proof_request
_PROOF_ELIGIBLE = _proof_eligible
_PROOF_RESULT = _proof_result
_PROOF_IDENTITY = _proof_identity
_PROOF_RELEASE = _proof_release
_PROOF_ACK = _proof_ack
_PROOF_UNAVAILABLE = _proof_unavailable
_PROOF_WORK_BINDINGS = _proof_work_bindings
_PROOF_FAILURE = _proof_failure
_SERVE_PROOF = _serve_proof
_PROOF_METHODS = (("check_initial_selection_readiness", _OWNER.check_initial_selection_readiness),)
_PROOF_HELPERS = (
    ("_proof_bindings", _PROOF_BINDINGS),
    ("_proof_reason", _PROOF_REASON),
    ("_proof_request", _PROOF_REQUEST),
    ("_proof_eligible", _PROOF_ELIGIBLE),
    ("_proof_result", _PROOF_RESULT),
    ("_proof_identity", _PROOF_IDENTITY),
    ("_proof_release", _PROOF_RELEASE),
    ("_proof_ack", _PROOF_ACK),
    ("_proof_unavailable", _PROOF_UNAVAILABLE),
    ("_proof_work_bindings", _PROOF_WORK_BINDINGS),
    ("_proof_failure", _PROOF_FAILURE),
    ("_serve_proof", _SERVE_PROOF),
)
_PROOF_DISPATCH = (
    ("_PROOF_BINDINGS", _PROOF_BINDINGS),
    ("_PROOF_REASON", _PROOF_REASON),
    ("_PROOF_REQUEST", _PROOF_REQUEST),
    ("_PROOF_ELIGIBLE", _PROOF_ELIGIBLE),
    ("_PROOF_RESULT", _PROOF_RESULT),
    ("_PROOF_IDENTITY", _PROOF_IDENTITY),
    ("_PROOF_RELEASE", _PROOF_RELEASE),
    ("_PROOF_ACK", _PROOF_ACK),
    ("_PROOF_UNAVAILABLE", _PROOF_UNAVAILABLE),
    ("_PROOF_WORK_BINDINGS", _PROOF_WORK_BINDINGS),
    ("_PROOF_FAILURE", _PROOF_FAILURE),
    ("_SERVE_PROOF", _SERVE_PROOF),
    ("_PROOF_METHODS", _PROOF_METHODS),
    ("_PROOF_HELPERS", _PROOF_HELPERS),
    ("_PROOF_REQUEST_CLASS", _PROOF_REQUEST_CLASS),
    ("_PROOF_REQUEST_INIT", _PROOF_REQUEST_INIT),
    ("_PROOF_REQUEST_VALIDATE", _PROOF_REQUEST_VALIDATE),
    ("_PROOF_RESULT_CLASS", _PROOF_RESULT_CLASS),
    ("_PROOF_RESULT_INIT", _PROOF_RESULT_INIT),
    ("_PROOF_RESULT_VALIDATE", _PROOF_RESULT_VALIDATE),
    ("_PROOF_RUNTIME_METHODS", _PROOF_RUNTIME_METHODS),
    ("_PROOF_REASONS", _PROOF_REASONS),
    ("_PROOF_DEADLINE", _PROOF_DEADLINE),
    ("_PROOF_CLOCK", _PROOF_CLOCK),
    ("_VERIFY", _VERIFY),
    ("_PROOF_LEASE_CEILING", _PROOF_LEASE_CEILING),
    ("_lease_ceiling", _PROOF_LEASE_CEILING),
    ("_HOST_ENTRY", _HOST_ENTRY),
    ("_HOST_STATE", _HOST_STATE),
    ("_NOW", _NOW),
    ("_LATCH", _LATCH),
    ("_SNAPSHOT", _SNAPSHOT),
    ("_THREAD_ALIVE", _THREAD_ALIVE),
    ("_event_is_set", _event_is_set),
    ("_identifier", _identifier),
)
