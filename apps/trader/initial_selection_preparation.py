"""One private preparation attempt on an original configured owner thread.

Only detached historical metadata escapes. The surrounding original configured
runtime context remains the sole owner of its lease and resource cleanup.
"""

from __future__ import annotations

from threading import current_thread

from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader import continuous_readiness_owner as readiness
from apps.trader import initial_selection_descriptor as descriptors
from apps.trader import synthetic_initial_selection as selection
from apps.trader.initial_selection_descriptor import (
    InitialSelectionDescriptor,
    _DescriptorValues,
)
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import content_digest
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
from packages.persistence.runtime_owner_dependencies import (
    PreparedRuntimeOwnerDependencies,
    SqlRuntimeOwnerDependencies,
)

_INVALID = "INITIAL_SELECTION_PREPARATION_INVALID"
_ATTEMPTED = "INITIAL_SELECTION_PREPARATION_ALREADY_ATTEMPTED"
_EMPTY_B = "INITIAL_SELECTION_PREPARATION_REQUIRES_EMPTY_B"
_MAX_NS = 2**63 - 1
_REQUEST_NS = 5_000_000_000
_RESERVE_NS = 1_000_000_000
_RUNTIME = readiness._ReadinessRuntime
_R_REQUIRE = _RUNTIME._require
_R_NOW = _RUNTIME._now
_R_LEASE = _RUNTIME._lease_deadline
_R_BEFORE = _RUNTIME._before
_R_VERIFY = _RUNTIME.verify
_A_RESTORE = SqlContinuousAccount.restore
_A_REQUIRE = SqlContinuousAccount.require_resolved
_D_READ = SqlDailyRuntimeRisk.read_snapshot
_D_RESOLVE = SqlDailyRuntimeRisk.resolve_snapshot
_D_REQUIRE = SqlDailyRuntimeRisk.require_resolved_snapshot
_DEP_BOUND = SqlRuntimeOwnerDependencies._bound
_DEP_PREPARE = SqlRuntimeOwnerDependencies.prepare_dependencies
_DEP_REQUIRE = SqlRuntimeOwnerDependencies.require_prepared
_BUILDER = selection._default_synthetic_initial_assignment
_DIGEST = content_digest
_DESCRIPTOR = InitialSelectionDescriptor
_DESCRIPTOR_INIT = InitialSelectionDescriptor.__post_init__
_DESCRIPTOR_VALUES = descriptors._descriptor_values
_VALIDATED_VALUES = descriptors._validated_values
_FROM_VALUES = descriptors._from_values

type _Fingerprint = tuple[str, str, str, str | None, tuple[str, str, str]]


def _deadline(value: object) -> int:
    if type(value) is not int or not 0 < value <= _MAX_NS:
        raise ValueError(_INVALID)
    return value


def _fingerprint(value: object) -> _Fingerprint:
    if (
        type(value) is not tuple
        or len(value) != 5
        or type(value[4]) is not tuple
        or len(value[4]) != 3
    ):
        raise ValueError(_INVALID)
    first, checkpoint, control, assignment, venue = value
    leaves = (first, checkpoint, control, *venue)
    if any(type(item) is not str for item in leaves) or (
        assignment is not None and type(assignment) is not str
    ):
        raise ValueError(_INVALID)
    for item in (*leaves, *((assignment,) if assignment is not None else ())):
        if len(item) != 64 or any(character not in "0123456789abcdef" for character in item):
            raise ValueError(_INVALID)
    return (first, checkpoint, control, assignment, (venue[0], venue[1], venue[2]))


def _method_bindings(
    value: object, expected: type[object], methods: tuple[tuple[str, object], ...]
) -> None:
    if type(value) is not expected:
        raise ValueError(_INVALID)
    for name, original in methods:
        if vars(expected).get(name) is not original or name in vars(value):
            raise ValueError(_INVALID)


def _direct_bindings(runtime: readiness._ReadinessRuntime) -> None:
    if type(runtime) is not _RUNTIME:
        raise ValueError(_INVALID)
    state = vars(runtime)
    if state.get("_instance") is not runtime or state.get("_thread") is not current_thread():
        raise ValueError(_INVALID)
    _method_bindings(
        runtime,
        _RUNTIME,
        (
            ("_require", _R_REQUIRE),
            ("_now", _R_NOW),
            ("_lease_deadline", _R_LEASE),
            ("_before", _R_BEFORE),
            ("verify", _R_VERIFY),
        ),
    )
    if (
        readiness._ReadinessRuntime is not _RUNTIME
        or type(state.get("reader")) is not SqlContinuousIntegrityReader
    ):
        raise ValueError(_INVALID)
    reader = runtime.reader
    _method_bindings(
        reader.account,
        SqlContinuousAccount,
        (("restore", _A_RESTORE), ("require_resolved", _A_REQUIRE)),
    )
    _method_bindings(
        reader.daily,
        SqlDailyRuntimeRisk,
        (
            ("read_snapshot", _D_READ),
            ("resolve_snapshot", _D_RESOLVE),
            ("require_resolved_snapshot", _D_REQUIRE),
        ),
    )
    producer = reader.daily.producers
    if type(producer) is not SqlContinuousRuntimeSources:
        raise ValueError(_INVALID)
    if (
        type(reader.associations) is not SqlRuntimeOwnerAssociations
        or type(reader.publisher) is not SqlContinuousReconciliationPublication
    ):
        raise ValueError(_INVALID)
    _method_bindings(
        producer.owner_dependencies,
        SqlRuntimeOwnerDependencies,
        (
            ("_bound", _DEP_BOUND),
            ("prepare_dependencies", _DEP_PREPARE),
            ("require_prepared", _DEP_REQUIRE),
        ),
    )


def _descriptor_bindings() -> None:
    if (
        descriptors.InitialSelectionDescriptor is not _DESCRIPTOR
        or vars(_DESCRIPTOR).get("__post_init__") is not _DESCRIPTOR_INIT
        or descriptors._descriptor_values is not _DESCRIPTOR_VALUES
        or descriptors._validated_values is not _VALIDATED_VALUES
        or descriptors._from_values is not _FROM_VALUES
    ):
        raise ValueError(_INVALID)


def _pure_bindings() -> None:
    _descriptor_bindings()
    if (
        selection._default_synthetic_initial_assignment is not _BUILDER
        or selection._DEFAULT_SYNTHETIC_INITIAL_ASSIGNMENT is not _BUILDER
        or vars(selection).get("content_digest") is not _DIGEST
        or content_digest is not _DIGEST
    ):
        raise ValueError(_INVALID)


def _graph(runtime: readiness._ReadinessRuntime) -> tuple[object, ...]:
    _direct_bindings(runtime)
    reader, account, daily = runtime.reader, runtime.reader.account, runtime.reader.daily
    producer = daily.producers
    if type(producer) is not SqlContinuousRuntimeSources:
        raise ValueError(_INVALID)
    dependencies = producer.owner_dependencies
    if type(dependencies) is not SqlRuntimeOwnerDependencies:
        raise ValueError(_INVALID)
    commands = dependencies.commands
    if type(commands) is not SqlRuntimeOwnerCommands:
        raise ValueError(_INVALID)
    authenticator = commands.authenticator
    if type(authenticator) is not LocalRuntimeOwnerAuthenticator:
        raise ValueError(_INVALID)
    security = authenticator.security
    if type(security) is not LocalOperatorSecurity or security._enabled is not False:
        raise ValueError(_INVALID)
    if (
        dependencies is not reader.associations.owner_dependencies
        or dependencies.accounts is not account
        or dependencies.daily is not daily
        or dependencies.publisher is not reader.publisher
        or dependencies.producer is not producer
        or dependencies.engine is not reader.engine
        or dependencies.artifacts is not account.artifacts
        or dependencies.codec is not account.codec
        or commands is not reader.associations.commands
    ):
        raise ValueError(_INVALID)
    return (
        runtime,
        runtime.reader,
        runtime.lease,
        runtime.guard,
        runtime.stop_event,
        runtime._thread,
        reader.scope,
        reader.engine,
        account,
        account.coordinator,
        account.artifacts,
        account.codec,
        daily,
        reader.publisher,
        reader.associations,
        producer,
        producer.producer_map,
        dependencies,
        commands,
        commands.journal,
        authenticator,
        security,
    )


def _adapter_identity(value: object) -> None:
    if _InitialSelectionPreparation is not _PREPARATION or type(value) is not _PREPARATION:
        raise ValueError(_INVALID)
    _method_bindings(value, _PREPARATION, _OWN_METHODS)
    state = vars(value)
    if (
        state.get("_instance") is not value
        or state.get("_thread") is not current_thread()
        or type(state.get("_attempted")) is not bool
        or "_descriptor_values" not in state
        or (
            state["_descriptor_values"] is not None
            and (type(state["_descriptor_values"]) is not tuple or not state["_attempted"])
        )
    ):
        raise ValueError(_INVALID)


class _InitialSelectionPreparation:
    """Private original-owner work, not an issuer, installer or cleanup owner."""

    def __init__(self, runtime: readiness._ReadinessRuntime) -> None:
        if (
            _InitialSelectionPreparation is not _PREPARATION
            or type(self) is not _PREPARATION
            or vars(self)
        ):
            raise ValueError(_INVALID)
        _method_bindings(self, _PREPARATION, _OWN_METHODS)
        _direct_bindings(runtime)
        _pure_bindings()
        _R_REQUIRE(runtime)
        graph = _graph(runtime)
        producer = runtime.reader.daily.producers
        if type(producer) is not SqlContinuousRuntimeSources:
            raise ValueError(_INVALID)
        dependencies = producer.owner_dependencies
        if type(dependencies) is not SqlRuntimeOwnerDependencies:
            raise ValueError(_INVALID)
        _DEP_BOUND(dependencies)
        self._instance = self
        self._thread = current_thread()
        self._runtime = runtime
        self._graph = graph
        self._fingerprint = _fingerprint(vars(runtime).get("_original"))
        self._lease_sha = runtime.lease.semantic_sha256
        self._scope_sha = runtime.reader.scope.semantic_sha256
        self._map_sha = producer.producer_map.semantic_sha256
        self._attempted = False
        self._prepared: PreparedRuntimeOwnerDependencies | None = None
        self._descriptor_values: _DescriptorValues | None = None
        _CHECK(self)

    def _identity(self) -> None:
        _adapter_identity(self)

    def _check(self) -> None:
        _adapter_identity(self)
        _pure_bindings()
        state = vars(self)
        runtime = state.get("_runtime")
        if (
            type(runtime) is not _RUNTIME
            or type(state.get("_graph")) is not tuple
            or any(
                type(state.get(name)) is not str
                for name in ("_lease_sha", "_scope_sha", "_map_sha")
            )
        ):
            raise ValueError(_INVALID)
        graph = _graph(runtime)
        if (
            len(graph) != len(self._graph)
            or any(a is not b for a, b in zip(graph, self._graph, strict=True))
            or _fingerprint(vars(runtime).get("_original"))
            != _fingerprint(state.get("_fingerprint"))
        ):
            raise ValueError(_INVALID)
        producer = runtime.reader.daily.producers
        if type(producer) is not SqlContinuousRuntimeSources:
            raise ValueError(_INVALID)
        current = (
            runtime.lease.semantic_sha256,
            runtime.reader.scope.semantic_sha256,
            producer.producer_map.semantic_sha256,
        )
        original = (self._lease_sha, self._scope_sha, self._map_sha)
        if any(type(item) is not str for item in (*current, *original)) or current != original:
            raise ValueError(_INVALID)
        _R_REQUIRE(runtime)
        dependencies = producer.owner_dependencies
        if type(dependencies) is not SqlRuntimeOwnerDependencies:
            raise ValueError(_INVALID)
        _DEP_BOUND(dependencies)

    def _refresh(self, deadline_ns: int) -> int:
        _CHECK(self)
        ceiling = _deadline(_R_LEASE(self._runtime))
        _CHECK(self)
        deadline_ns = min(deadline_ns, ceiling - _RESERVE_NS)
        _R_BEFORE(self._runtime, deadline_ns)
        _CHECK(self)
        return deadline_ns

    def _verify(self, deadline_ns: int) -> int:
        _CHECK(self)
        verified = _deadline(_R_VERIFY(self._runtime, deadline_ns))
        _CHECK(self)
        if verified > deadline_ns:
            raise ValueError(_INVALID)
        return _REFRESH(self, min(deadline_ns, verified))

    def prepare(self, *, deadline_ns: int) -> InitialSelectionDescriptor:
        _adapter_identity(self)
        deadline_ns = _deadline(deadline_ns)
        _CHECK(self)
        if self._attempted:
            raise ValueError(_ATTEMPTED)
        self._attempted = True
        runtime = self._runtime
        started = _R_NOW(runtime)
        deadline_ns = _REFRESH(self, min(deadline_ns, started + _REQUEST_NS, _MAX_NS))
        deadline_ns = _VERIFY(self, deadline_ns)
        reader, account, daily = runtime.reader, runtime.reader.account, runtime.reader.daily
        previous = _A_RESTORE(account, reader.scope)
        _CHECK(self)
        _R_BEFORE(runtime, deadline_ns)
        if previous is None:
            raise ValueError(_INVALID)
        _A_REQUIRE(account, previous)
        _CHECK(self)
        raw = _D_READ(daily, account_id=reader.scope.account_id, fence=runtime.lease.fence)
        _CHECK(self)
        _R_BEFORE(runtime, deadline_ns)
        current = _D_RESOLVE(daily, raw)
        _CHECK(self)
        _D_REQUIRE(daily, current)
        _CHECK(self)
        if current.assignment is not None or current.assignment_rows:
            raise ValueError(_EMPTY_B)
        if (
            current.control is None
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
        deadline_ns = _REFRESH(self, deadline_ns)
        spec = previous.checkpoint.inputs.spec
        producer = daily.producers
        if type(producer) is not SqlContinuousRuntimeSources:
            raise ValueError(_INVALID)
        proposed = _BUILDER(
            account_id=reader.scope.account_id,
            account_binding_sha256=reader.scope.account_binding_sha256,
            policy=spec.risk_policy,
            strategy=spec.strategy,
            configuration_sha256=_DIGEST(spec.strategy_configuration),
            instrument_symbols=spec.instruments,
            producer_map_sha256=producer.producer_map.semantic_sha256,
            effective_at=current.raw.receipt.validated_at,
        )
        deadline_ns = _REFRESH(self, deadline_ns)
        dependencies = producer.owner_dependencies
        if type(dependencies) is not SqlRuntimeOwnerDependencies:
            raise ValueError(_INVALID)
        prepared = _DEP_PREPARE(
            dependencies, previous=previous, proposed=proposed, fence=runtime.lease.fence
        )
        if type(prepared) is not PreparedRuntimeOwnerDependencies:
            raise ValueError(_INVALID)
        self._prepared = prepared
        _CHECK(self)
        _DEP_REQUIRE(dependencies, prepared)
        deadline_ns = _REFRESH(self, deadline_ns)
        deadline_ns = _VERIFY(self, deadline_ns)
        _DEP_REQUIRE(dependencies, prepared)
        _CHECK(self)
        record, reference = prepared.record, prepared.reference
        heads = record.heads
        values = _VALIDATED_VALUES(
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
        candidate = _FROM_VALUES(values)
        _CHECK(self)
        _DEP_REQUIRE(dependencies, prepared)
        _REFRESH(self, deadline_ns)
        self._descriptor_values = values
        return candidate

    def descriptor(self) -> InitialSelectionDescriptor | None:
        """Fresh detached historical data, including after original context exit."""
        _adapter_identity(self)
        _descriptor_bindings()
        if self._descriptor_values is None:
            return None
        values = _VALIDATED_VALUES(self._descriptor_values)
        return _FROM_VALUES(values)


_PREPARATION = _InitialSelectionPreparation
_CHECK = _InitialSelectionPreparation._check
_REFRESH = _InitialSelectionPreparation._refresh
_VERIFY = _InitialSelectionPreparation._verify
_OWN_METHODS = (
    ("__init__", _InitialSelectionPreparation.__init__),
    ("prepare", _InitialSelectionPreparation.prepare),
    ("descriptor", _InitialSelectionPreparation.descriptor),
    ("_identity", _InitialSelectionPreparation._identity),
    ("_check", _CHECK),
    ("_refresh", _REFRESH),
    ("_verify", _VERIFY),
)
