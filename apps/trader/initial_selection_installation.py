"""One private terminal installation of an original disabled selection.

Native delivery bounds do not make SQL COMMIT atomic with a timer or stop.
Publication observations survive late returns, faults and original G cleanup.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import current_thread

from apps.trader import initial_selection_descriptor as descriptors
from apps.trader import initial_selection_preparation as preparation_module
from apps.trader.initial_selection_descriptor import _DescriptorValues
from packages.domain import durable_journal_contracts as journal_values
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.durable_journal_contracts import JournalHead, JournalReceipt
from packages.domain.operational_control import OperationalControlState
from packages.persistence import continuous_account as account_module
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk import PreparedDailyAssignment, SqlDailyRuntimeRisk
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_dependencies import (
    PreparedRuntimeOwnerDependencies,
    SqlRuntimeOwnerDependencies,
)

_INVALID = "INITIAL_SELECTION_INSTALLATION_INVALID"
_ATTEMPTED = "INITIAL_SELECTION_INSTALLATION_ALREADY_ATTEMPTED"
_MAX_NS = 2**63 - 1
_REQUEST_NS = 5_000_000_000
_PREPARATION = preparation_module._InitialSelectionPreparation
_E_IDENTITY = preparation_module._adapter_identity
_E_CHECK = _PREPARATION._check
_E_REFRESH = _PREPARATION._refresh
_E_VERIFY = _PREPARATION._verify
_E_FINGERPRINT = preparation_module._fingerprint
_METHOD_BINDINGS = preparation_module._method_bindings
_D_VALUES = descriptors._validated_values
_RUNTIME = preparation_module._RUNTIME
_R_NOW = preparation_module._R_NOW
_A_RESTORE = SqlContinuousAccount.restore
_A_REQUIRE = SqlContinuousAccount.require_resolved
_A_STOP = SqlContinuousAccount.cooperative_stop_scope
_D_READ = SqlDailyRuntimeRisk.read_snapshot
_D_RESOLVE = SqlDailyRuntimeRisk.resolve_snapshot
_D_REQUIRE = SqlDailyRuntimeRisk.require_resolved_snapshot
_D_PREPARE = SqlDailyRuntimeRisk.prepare_assignment
_D_PREPARED = SqlDailyRuntimeRisk.require_prepared_assignment
_DEP_REQUIRE = SqlRuntimeOwnerDependencies.require_prepared
_DEP_READ = SqlRuntimeOwnerDependencies.prepare_owner_command_read
_DEP_PLAN = SqlRuntimeOwnerDependencies.require_plan
_DEP_FENCE = SqlRuntimeOwnerDependencies.require_original_fence
_DEP_FENCE_DESCRIPTOR = vars(SqlRuntimeOwnerDependencies)["require_original_fence"]
_PUBLICATION = SqlRuntimeAssignmentPublication
_PUBLICATION_INIT = _PUBLICATION.__init__
_PUBLISH = _PUBLICATION.publish
_STOP_SCOPE = account_module._ContinuousStopScope
_SCOPE_INIT = _STOP_SCOPE.__init__
_SCOPE_ENTER = _STOP_SCOPE.__enter__
_SCOPE_EXIT = _STOP_SCOPE.__exit__
_HEAD = JournalHead
_HEAD_INIT = JournalHead.__init__
_HEAD_VALIDATE = JournalHead.__post_init__
_RECEIPT = JournalReceipt
_RECEIPT_INIT = JournalReceipt.__init__
_RECEIPT_VALIDATE = JournalReceipt.__post_init__

type _ReceiptValues = tuple[
    str,
    str,
    str,
    str,
    int,
    str,
    str,
    int,
    str,
    tuple[str, ...],
    tuple[str, ...],
]
type _ObservationValues = tuple[bool, bool, bool, str | None, str | None]


def _digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(_INVALID)
    return value


def _deadline(value: object) -> int:
    if type(value) is not int or not 0 < value <= _MAX_NS:
        raise ValueError(_INVALID)
    return value


def _receipt_bindings() -> None:
    if journal_values.JournalHead is not _HEAD or journal_values.JournalReceipt is not _RECEIPT:
        raise ValueError(_INVALID)
    for expected, init, validate in (
        (_HEAD, _HEAD_INIT, _HEAD_VALIDATE),
        (_RECEIPT, _RECEIPT_INIT, _RECEIPT_VALIDATE),
    ):
        if (
            vars(expected).get("__init__") is not init
            or vars(expected).get("__post_init__") is not validate
        ):
            raise ValueError(_INVALID)


def _native_receipt_values(value: object) -> _ReceiptValues:
    if type(value) is not tuple or len(value) != 11:
        raise ValueError(_INVALID)
    if (
        any(type(value[index]) is not str for index in (0, 1, 2, 3, 5, 6, 8))
        or type(value[4]) is not int
        or type(value[7]) is not int
        or type(value[9]) is not tuple
        or type(value[10]) is not tuple
        or not 1 <= len(value[9]) <= journal_values.MAX_APPEND_RECORDS
        or not 1 <= len(value[10]) <= journal_values.MAX_APPEND_RECORDS
    ):
        raise ValueError(_INVALID)
    if any(type(item) is not str for item in (*value[9], *value[10])):
        raise ValueError(_INVALID)
    # All leaves are native before any original constructor or arithmetic.
    return (
        value[0],
        value[1],
        value[2],
        value[3],
        value[4],
        value[5],
        value[6],
        value[7],
        value[8],
        tuple(item for item in value[9]),
        tuple(item for item in value[10]),
    )


def _receipt_from_values(value: _ReceiptValues) -> JournalReceipt:
    values = _native_receipt_values(value)
    _receipt_bindings()
    if values[9] != (values[0],):
        raise ValueError(_INVALID)
    try:
        previous = _HEAD(values[3], values[4], values[5])
        committed = _HEAD(values[6], values[7], values[8])
        return _RECEIPT(values[0], values[1], values[2], previous, committed, values[9], values[10])
    except ValueError:
        raise ValueError(_INVALID) from None


def _receipt_values(value: object) -> _ReceiptValues:
    if type(value) is not _RECEIPT:
        raise ValueError(_INVALID)
    previous, committed = value.previous_head, value.committed_head
    if type(previous) is not _HEAD or type(committed) is not _HEAD:
        raise ValueError(_INVALID)
    values = _native_receipt_values(
        (
            value.command_id,
            value.command_sha256,
            value.append_sha256,
            previous.key_sha256,
            previous.sequence,
            previous.entry_sha256,
            committed.key_sha256,
            committed.sequence,
            committed.entry_sha256,
            value.record_ids,
            value.record_hashes,
        )
    )
    _receipt_from_values(values)
    return values


def _observation_values(value: object) -> _ObservationValues:
    if type(value) is not tuple or len(value) != 5:
        raise ValueError(_INVALID)
    attempted, started, returned, request_sha, assignment_sha = value
    if any(type(item) is not bool for item in (attempted, started, returned)):
        raise ValueError(_INVALID)
    for digest in (request_sha, assignment_sha):
        if digest is not None:
            _digest(digest)
    if (
        (
            not attempted
            and (started or returned or request_sha is not None or assignment_sha is not None)
        )
        or (attempted and request_sha is None)
        or (returned and not started)
        or (assignment_sha is not None and not returned)
    ):
        raise ValueError(_INVALID)
    return attempted, started, returned, request_sha, assignment_sha


@dataclass(frozen=True, slots=True, kw_only=True)
class InitialSelectionInstallationObservation:
    attempted: bool
    publication_started: bool
    publication_returned: bool
    request_receipt_sha256: str | None
    assignment_sha256: str | None

    def __post_init__(self) -> None:
        if type(self) is not _OBSERVATION:
            raise ValueError(_INVALID)
        _observation_values(
            (
                self.attempted,
                self.publication_started,
                self.publication_returned,
                self.request_receipt_sha256,
                self.assignment_sha256,
            )
        )


def _observation_from_values(value: _ObservationValues) -> InitialSelectionInstallationObservation:
    values = _observation_values(value)
    if (
        InitialSelectionInstallationObservation is not _OBSERVATION
        or vars(_OBSERVATION).get("__init__") is not _OBSERVATION_INIT
        or vars(_OBSERVATION).get("__post_init__") is not _OBSERVATION_VALIDATE
    ):
        raise ValueError(_INVALID)
    return _OBSERVATION(
        attempted=values[0],
        publication_started=values[1],
        publication_returned=values[2],
        request_receipt_sha256=values[3],
        assignment_sha256=values[4],
    )


def _identity(value: object) -> None:
    if type(value) is not _INSTALLATION or _InitialSelectionInstallation is not _INSTALLATION:
        raise ValueError(_INVALID)
    state = vars(value)
    if state.get("_instance") is not value or state.get("_thread") is not current_thread():
        raise ValueError(_INVALID)
    for name, original in _OWN_METHODS:
        if vars(_INSTALLATION).get(name) is not original or name in state:
            raise ValueError(_INVALID)
    _observation_values(state.get("_observation"))


def _preparation_bindings(value: object) -> preparation_module._InitialSelectionPreparation:
    if (
        type(value) is not _PREPARATION
        or type(value) is not preparation_module._InitialSelectionPreparation
    ):
        raise ValueError(_INVALID)
    state = vars(value)
    if state.get("_instance") is not value or state.get("_thread") is not current_thread():
        raise ValueError(_INVALID)
    if (
        preparation_module._InitialSelectionPreparation is not _PREPARATION
        or preparation_module._adapter_identity is not _E_IDENTITY
        or preparation_module._CHECK is not _E_CHECK
        or preparation_module._REFRESH is not _E_REFRESH
        or preparation_module._VERIFY is not _E_VERIFY
        or preparation_module._fingerprint is not _E_FINGERPRINT
        or preparation_module._method_bindings is not _METHOD_BINDINGS
        or descriptors._validated_values is not _D_VALUES
    ):
        raise ValueError(_INVALID)
    _E_IDENTITY(value)
    # A retained partial put does not qualify a preparation for installation.
    if (
        state.get("_descriptor_values") is None
        or type(state.get("_prepared")) is not PreparedRuntimeOwnerDependencies
    ):
        raise ValueError(_INVALID)
    # Dict identity comparisons lose static narrowing; exact admission is above.
    if not isinstance(value, preparation_module._InitialSelectionPreparation):
        raise ValueError(_INVALID)
    return value


def _extra_bindings(
    value: preparation_module._InitialSelectionPreparation,
) -> SqlRuntimeOwnerDependencies:
    runtime = value._runtime
    producer = runtime.reader.daily.producers
    if type(producer) is not SqlContinuousRuntimeSources:
        raise ValueError(_INVALID)
    dependencies = producer.owner_dependencies
    if type(dependencies) is not SqlRuntimeOwnerDependencies:
        raise ValueError(_INVALID)
    _METHOD_BINDINGS(
        runtime.reader.account, SqlContinuousAccount, (("cooperative_stop_scope", _A_STOP),)
    )
    _METHOD_BINDINGS(
        runtime.reader.daily,
        SqlDailyRuntimeRisk,
        (
            ("prepare_assignment", _D_PREPARE),
            ("require_prepared_assignment", _D_PREPARED),
        ),
    )
    _METHOD_BINDINGS(
        dependencies,
        SqlRuntimeOwnerDependencies,
        (
            ("prepare_owner_command_read", _DEP_READ),
            ("require_plan", _DEP_PLAN),
        ),
    )
    if (
        vars(SqlRuntimeOwnerDependencies).get("require_original_fence") is not _DEP_FENCE_DESCRIPTOR
        or "require_original_fence" in vars(dependencies)
        or vars(_PUBLICATION).get("__init__") is not _PUBLICATION_INIT
        or vars(_PUBLICATION).get("publish") is not _PUBLISH
        or account_module._ContinuousStopScope is not _STOP_SCOPE
        or vars(_STOP_SCOPE).get("__init__") is not _SCOPE_INIT
        or vars(_STOP_SCOPE).get("__enter__") is not _SCOPE_ENTER
        or vars(_STOP_SCOPE).get("__exit__") is not _SCOPE_EXIT
    ):
        raise ValueError(_INVALID)
    return dependencies


def _prepared_values(value: PreparedRuntimeOwnerDependencies) -> _DescriptorValues:
    record, reference = value.record, value.reference
    heads = record.heads
    return _D_VALUES(
        (
            record.scope.account_id,
            record.scope.account_binding_sha256,
            record.scope.stream_id,
            record.proposed.semantic_sha256,
            heads.ledger_sha256,
            heads.order_sha256,
            heads.capacity_sha256,
            heads.effect_watermark,
            heads.attempt_sha256,
            heads.control_revision,
            heads.lease_generation,
            reference.schema_id,
            reference.object_ref.object_sha256,
            reference.object_ref.byte_count,
            reference.object_ref.codec_version,
            reference.semantic_sha256,
            record.checked_at,
            record.valid_until,
            record.previous.semantic_sha256,
            record.control_sha256,
            record.fence.lease_sha256,
        )
    )


@contextmanager
def _stop_scope(
    account: SqlContinuousAccount, preparation: preparation_module._InitialSelectionPreparation
) -> Iterator[None]:
    scope = _A_STOP(account, preparation._runtime.stop_event)
    if type(scope) is not _STOP_SCOPE:
        raise ValueError(_INVALID)
    _SCOPE_ENTER(scope)
    try:
        yield
    except BaseException as error:
        _SCOPE_EXIT(scope, type(error), error, error.__traceback__)
        raise
    else:
        _SCOPE_EXIT(scope, None, None, None)


class _InitialSelectionInstallation:
    """One private install attempt; original G remains the cleanup owner."""

    def __init__(self, preparation: preparation_module._InitialSelectionPreparation) -> None:
        if (
            type(self) is not _INSTALLATION
            or _InitialSelectionInstallation is not _INSTALLATION
            or vars(self)
        ):
            raise ValueError(_INVALID)
        for name, original_method in _OWN_METHODS:
            if vars(_INSTALLATION).get(name) is not original_method:
                raise ValueError(_INVALID)
        original = _preparation_bindings(preparation)
        _E_CHECK(original)
        dependencies = _extra_bindings(original)
        prepared = original._prepared
        if type(prepared) is not PreparedRuntimeOwnerDependencies:
            raise ValueError(_INVALID)
        _DEP_REQUIRE(dependencies, prepared)
        values = _D_VALUES(original._descriptor_values)
        if _prepared_values(prepared) != values:
            raise ValueError(_INVALID)
        self._instance = self
        self._thread = current_thread()
        self._preparation = original
        self._runtime = original._runtime
        self._prepared = prepared
        self._values = values
        self._fingerprint = _E_FINGERPRINT(original._fingerprint)
        self._digests = (
            _digest(original._lease_sha),
            _digest(original._scope_sha),
            _digest(original._map_sha),
        )
        self._graph = tuple(item for item in original._graph)
        self._observation: _ObservationValues = (False, False, False, None, None)
        _CHECK(self)

    def _check(self) -> None:
        _identity(self)
        own = vars(self)
        if (
            type(own.get("_preparation")) is not _PREPARATION
            or type(own.get("_runtime")) is not _RUNTIME
            or type(own.get("_prepared")) is not PreparedRuntimeOwnerDependencies
            or type(own.get("_graph")) is not tuple
            or type(own.get("_digests")) is not tuple
            or len(own["_digests"]) != 3
        ):
            raise ValueError(_INVALID)
        _D_VALUES(own.get("_values"))
        _E_FINGERPRINT(own.get("_fingerprint"))
        for digest in own["_digests"]:
            _digest(digest)
        original = _preparation_bindings(self._preparation)
        state = vars(original)
        if (
            state.get("_runtime") is not self._runtime
            or state.get("_prepared") is not self._prepared
            or type(state.get("_graph")) is not tuple
            or len(state["_graph"]) != len(self._graph)
            or any(a is not b for a, b in zip(state["_graph"], self._graph, strict=True))
            or _D_VALUES(state.get("_descriptor_values")) != self._values
            or _E_FINGERPRINT(state.get("_fingerprint")) != self._fingerprint
            or tuple(_digest(state.get(name)) for name in ("_lease_sha", "_scope_sha", "_map_sha"))
            != self._digests
        ):
            raise ValueError(_INVALID)
        _E_CHECK(original)
        dependencies = _extra_bindings(original)
        _DEP_REQUIRE(dependencies, self._prepared)
        if _prepared_values(self._prepared) != self._values:
            raise ValueError(_INVALID)

    def _refresh(self, deadline_ns: int) -> int:
        _CHECK(self)
        returned = _deadline(_E_REFRESH(self._preparation, deadline_ns))
        _CHECK(self)
        if returned > deadline_ns:
            raise ValueError(_INVALID)
        return returned

    def install(
        self, request: JournalReceipt, *, deadline_ns: int
    ) -> InitialSelectionInstallationObservation:
        _identity(self)
        deadline_ns = _deadline(deadline_ns)
        receipt = _receipt_from_values(_receipt_values(request))
        _CHECK(self)
        if self._observation[0]:
            raise ValueError(_ATTEMPTED)
        request_sha = _digest(receipt.semantic_sha256)
        self._observation = (True, False, False, request_sha, None)
        original, runtime = self._preparation, self._runtime
        started = _R_NOW(runtime)
        deadline_ns = _REFRESH(self, min(deadline_ns, started + _REQUEST_NS, _MAX_NS))
        # verify owns its own stop scope. It must finish before the write scope.
        verified = _deadline(_E_VERIFY(original, deadline_ns))
        if verified > deadline_ns:
            raise ValueError(_INVALID)
        deadline_ns = _REFRESH(self, min(deadline_ns, verified))
        reader, account, daily = runtime.reader, runtime.reader.account, runtime.reader.daily
        with _stop_scope(account, original):
            previous = _A_RESTORE(account, reader.scope)
            deadline_ns = _REFRESH(self, deadline_ns)
            if previous is None:
                raise ValueError(_INVALID)
            _A_REQUIRE(account, previous)
            deadline_ns = _REFRESH(self, deadline_ns)
            raw = _D_READ(daily, account_id=reader.scope.account_id, fence=runtime.lease.fence)
            deadline_ns = _REFRESH(self, deadline_ns)
            current = _D_RESOLVE(daily, raw)
            deadline_ns = _REFRESH(self, deadline_ns)
            _D_REQUIRE(daily, current)
            deadline_ns = _REFRESH(self, deadline_ns)
            if (
                current.assignment is not None
                or current.assignment_rows
                or current.control is None
                or current.control.effective_state is not OperationalControlState.HALTED
                or current.control.active_operation is not None
                or current.admissions
                or current.obligations.bindings
                or current.attempts
                or current.attempt_envelopes
                or current.observed_groups
                or previous.receipt.semantic_sha256 != self._fingerprint[0]
                or previous.checkpoint.semantic_sha256 != self._fingerprint[1]
                or current.control.semantic_sha256 != self._fingerprint[2]
            ):
                raise ValueError(_INVALID)
            dependencies = _extra_bindings(original)
            _DEP_FENCE(self._prepared.record.fence, runtime.lease)
            plan = _DEP_READ(
                dependencies, previous=previous, original_receipt=receipt, fence=runtime.lease.fence
            )
            deadline_ns = _REFRESH(self, deadline_ns)
            _DEP_PLAN(dependencies, plan)
            deadline_ns = _REFRESH(self, deadline_ns)
            if (
                plan.dependencies.record != self._prepared.record
                or plan.dependencies.reference != self._prepared.reference
            ):
                raise ValueError(_INVALID)
            _DEP_FENCE(plan.dependencies.record.fence, runtime.lease)
            raw = _D_READ(
                daily,
                account_id=reader.scope.account_id,
                fence=runtime.lease.fence,
                owner_command_ref=receipt,
            )
            deadline_ns = _REFRESH(self, deadline_ns)
            current = _D_RESOLVE(daily, raw)
            deadline_ns = _REFRESH(self, deadline_ns)
            _D_REQUIRE(daily, current)
            deadline_ns = _REFRESH(self, deadline_ns)
            proposed = self._prepared.record.proposed
            prepared_assignment = _D_PREPARE(
                daily,
                current,
                assignment=proposed,
                expected_previous_sha256=None,
                owner_command_ref=receipt,
            )
            if type(prepared_assignment) is not PreparedDailyAssignment:
                raise ValueError(_INVALID)
            deadline_ns = _REFRESH(self, deadline_ns)
            _D_PREPARED(daily, prepared_assignment)
            deadline_ns = _REFRESH(self, deadline_ns)
            if prepared_assignment.result is not proposed or prepared_assignment.retry is not False:
                raise ValueError(_INVALID)
            publication = _PUBLICATION(account=account, daily=daily)
            _METHOD_BINDINGS(publication, _PUBLICATION, (("publish", _PUBLISH),))
            deadline_ns = _REFRESH(self, deadline_ns)
            self._observation = (True, True, False, request_sha, None)
            installed = _PUBLISH(publication, prepared_assignment, fence=runtime.lease.fence)
            # Preserve the actual call-return fact BEFORE validating its value.
            self._observation = (True, True, True, request_sha, None)
            if (
                type(installed) is not RuntimeRiskAssignment
                or installed is not proposed
                or installed is not prepared_assignment.result
            ):
                raise ValueError(_INVALID)
            if _digest(installed.semantic_sha256) != self._values[3]:
                raise ValueError(_INVALID)
            self._observation = (True, True, True, request_sha, self._values[3])
        # These helpers check native/owner bindings and R1, never current B or
        # Runtime.verify/_supported_state. Intentional B must not be rebased.
        deadline_ns = _REFRESH(self, deadline_ns)
        candidate = _observation_from_values(self._observation)
        _REFRESH(self, deadline_ns)
        return candidate

    def observation(self) -> InitialSelectionInstallationObservation:
        _identity(self)
        return _observation_from_values(self._observation)


_OBSERVATION = InitialSelectionInstallationObservation
_OBSERVATION_INIT = _OBSERVATION.__init__
_OBSERVATION_VALIDATE = _OBSERVATION.__post_init__
_INSTALLATION = _InitialSelectionInstallation
_CHECK = _INSTALLATION._check
_REFRESH = _INSTALLATION._refresh
_OWN_METHODS = (
    ("__init__", _INSTALLATION.__init__),
    ("install", _INSTALLATION.install),
    ("observation", _INSTALLATION.observation),
    ("_check", _CHECK),
    ("_refresh", _REFRESH),
)
