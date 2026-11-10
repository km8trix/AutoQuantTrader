"""Actual retained C/B/A dependencies for bounded local owner requests.

Preparation and source validation run outside SQL. The same daily producer uses
this reader for owner requests only. The reader does not publish a C transition,
issue dispatch authority, or alter independent Stop/Pause controls.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Any, TypeVar
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.domain.account_coordinator import (
    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
)
from packages.domain.accounting_contracts import AccountingState
from packages.domain.canonical import canonical_json_bytes
from packages.domain.continuous_engine_contracts import ContinuousEngineSpec
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.daily_attempt_contracts import CanonicalDailyAttempt, DailyFenceReference
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.daily_runtime_contracts import RuntimeRiskAssignment
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.domain.operational_control import OperationalControlTransition
from packages.domain.order_reducer import CanonicalOrderStatus, reduce_order_lifecycle
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads, ReconciliationPolicy
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.runtime_owner_dependency_contracts import (
    MAX_OWNER_DEPENDENCIES_BYTES,
    OWNER_DEPENDENCIES_SCHEMA,
    RuntimeOwnerDependencies,
)
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.persistence.account_coordinator import account_lease_from_row
from packages.persistence.continuous_account import ResolvedContinuousAccount, SqlContinuousAccount
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.continuous_reconciliation_publication import (
    ResolvedContinuousReconciliationPublication,
    SqlContinuousReconciliationPublication,
)
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_TOTAL_BYTES,
    PreparedDailyAssignment,
    ResolvedDailyRuntimeSnapshot,
    RuntimeProducerRawSnapshot,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    SqlDailyRuntimeRisk,
    VerifiedRuntimeAssignmentCommand,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import JournalReadSnapshot
from packages.persistence.immutable import as_aware_utc
from packages.persistence.runtime_owner_commands import (
    ResolvedRuntimeOwnerCommand,
    RuntimeOwnerCommandSnapshot,
    SqlRuntimeOwnerCommands,
)
from packages.persistence.schema import phase2_account_leases


class RuntimeOwnerDependencyError(ValueError):
    """Original local owner dependency identity, freshness or integrity differs."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedRuntimeOwnerDependencies:
    reference: ContinuousEvidenceRef
    record: RuntimeOwnerDependencies
    previous: ResolvedContinuousAccount
    daily: ResolvedDailyRuntimeSnapshot
    reconciliation: ResolvedContinuousReconciliationPublication | None
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeOwnerDependencyReadPlan:
    dependencies: PreparedRuntimeOwnerDependencies
    request: ResolvedRuntimeOwnerCommand
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _Captured:
    plan: RuntimeOwnerDependencyReadPlan
    request: RuntimeOwnerCommandSnapshot
    tables: tuple[RuntimeTableSnapshot, ...]
    journals: tuple[JournalReadSnapshot, ...]
    reconciliation_row: Mapping[str, Any] | None


Owned = TypeVar("Owned")


def _identity_graph(
    value: object,
) -> tuple[tuple[object | None, tuple[tuple[str, object], ...]], ...]:
    pending, seen, result = [value], set(), []
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if is_dataclass(item) and not isinstance(item, type):
            attributes = tuple(
                (f.name, getattr(item, f.name))
                for f in fields(item)
                if f.name not in {"_owner", "_validated_values"}
            )
            result.append((None if item is value else item, attributes))
            pending.extend(original for _, original in attributes)
        elif type(item) is tuple:
            pending.extend(item)
    return tuple(result)


def _disable_only(before: RuntimeRiskAssignment | None, after: RuntimeRiskAssignment) -> bool:
    if before is None or after.enabled_for_new_exposure:
        return False
    return (
        replace(
            after,
            generation=before.generation,
            previous_assignment_sha256=before.previous_assignment_sha256,
            effective_at=before.effective_at,
            enabled_for_new_exposure=before.enabled_for_new_exposure,
        )
        == before
    )


class SqlRuntimeOwnerDependencies:
    def __init__(
        self,
        engine: Engine,
        *,
        accounts: SqlContinuousAccount,
        daily: SqlDailyRuntimeRisk,
        publisher: SqlContinuousReconciliationPublication,
        commands: SqlRuntimeOwnerCommands,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
    ) -> None:
        from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources

        if (
            type(accounts) is not SqlContinuousAccount
            or type(daily) is not SqlDailyRuntimeRisk
            or type(publisher) is not SqlContinuousReconciliationPublication
            or type(commands) is not SqlRuntimeOwnerCommands
            or type(daily.producers) is not SqlContinuousRuntimeSources
            or any(item.engine is not engine for item in (accounts, daily, publisher, commands))
            or publisher.account is not accounts
            or publisher.coordinator is not accounts.coordinator
            or daily.coordinator is not accounts.coordinator
            or daily.producers.accounts is not accounts
            or daily.producers.daily is not daily
            or daily.producers.publisher is not publisher
            or accounts.artifacts is not artifacts
            or publisher.artifacts is not artifacts
            or any(item.codec is not codec for item in (accounts, daily, publisher, commands))
        ):
            raise RuntimeOwnerDependencyError("EXACT_OWNER_DEPENDENCY_STORES_REQUIRED")
        self.engine, self.accounts, self.daily, self.publisher, self.commands = (
            engine,
            accounts,
            daily,
            publisher,
            commands,
        )
        self.artifacts, self.codec = artifacts, codec
        self.producer = daily.producers
        self._bindings = self._binding_values()
        self._seal = object()
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._original: dict[int, Any] = {}
        self._fingerprints: dict[int, str] = {}
        self._active: WeakValueDictionary[str, RuntimeOwnerDependencyReadPlan] = (
            WeakValueDictionary()
        )
        self._raw: dict[int, _Captured] = {}
        self._resolved: dict[int, ResolvedRuntimeOwnerCommand] = {}

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self.engine,
            self.accounts,
            self.daily,
            self.publisher,
            self.commands,
            self.artifacts,
            self.codec,
            self.producer,
            self.accounts.composer,
            self.publisher.applied,
            self.commands.journal,
            self.commands.authenticator,
            self.daily.producers,
            self.producer.accounts,
            self.producer.daily,
            self.producer.publisher,
        )

    def _bound(self) -> None:
        if any(
            current is not original
            for current, original in zip(self._binding_values(), self._bindings, strict=True)
        ):
            raise RuntimeOwnerDependencyError("ORIGINAL_OWNER_DEPENDENCY_BINDINGS_CHANGED")

    def _own(self, value: Owned) -> Owned:
        self._owned[id(value)] = value
        self._original[id(value)] = _identity_graph(value)
        finalize(value, self._original.pop, id(value), None)
        return value

    def _require(self, value: object, expected: type[Any]) -> None:
        self._bound()
        if type(value) is not expected or self._owned.get(id(value)) is not value:
            raise RuntimeOwnerDependencyError("OWNED_ORIGINAL_OWNER_DEPENDENCIES_REQUIRED")
        for item, attributes in self._original[id(value)]:
            if any(
                getattr(value if item is None else item, name) is not old
                for name, old in attributes
            ):
                raise RuntimeOwnerDependencyError("ORIGINAL_OWNER_DEPENDENCY_FIELDS_CHANGED")

    @staticmethod
    def _fingerprint(value: PreparedRuntimeOwnerDependencies) -> str:
        return content_digest(
            (
                value.reference,
                value.record,
                value.previous.checkpoint,
                value.daily.assignment_rows,
                value.daily.admissions,
                value.daily.obligations,
                value.daily.control,
                value.daily.attempts,
                value.daily.attempt_envelopes,
                value.daily.observed_groups,
                tuple(
                    tuple(detached_journal_value(row) for row in table.rows)
                    for table in value.daily.raw.tables
                ),
            )
        )

    @staticmethod
    def _object_bound(value: PreparedRuntimeOwnerDependencies) -> None:
        """Intern exact immutable references across the C and independent A closure."""
        pending: list[object] = [value.reference, value.record, value.daily.admissions]
        if value.reconciliation is not None:
            paired = value.reconciliation
            pending.extend(
                (paired.sources.capture, paired.sources.pages, paired.reconciliation.resolved)
            )
        seen: set[int] = set()
        objects: dict[str, ObjectRef] = {}
        total = 0
        while pending:
            item = pending.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if type(item) is ObjectRef:
                original = objects.get(item.object_sha256)
                if original is not None and original != item:
                    raise RuntimeOwnerDependencyError("OWNER_OBJECT_REFERENCE_METADATA_CONFLICT")
                if original is None:
                    objects[item.object_sha256] = item
                    total += item.byte_count
                    if total > MAX_TOTAL_BYTES or len(objects) > 4096:
                        raise RuntimeOwnerDependencyError("OWNER_COMPLETE_SOURCE_OBJECT_BOUND")
            elif is_dataclass(item) and not isinstance(item, type):
                pending.extend(
                    getattr(item, f.name)
                    for f in fields(item)
                    if f.name not in {"seal", "_owner", "_validated_values"}
                )
            elif type(item) is tuple:
                pending.extend(item)

    def _prepared(
        self, value: PreparedRuntimeOwnerDependencies
    ) -> PreparedRuntimeOwnerDependencies:
        self._object_bound(value)
        self._own(value)
        self._fingerprints[id(value)] = self._fingerprint(value)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    def require_prepared(self, value: PreparedRuntimeOwnerDependencies) -> None:
        self._require(value, PreparedRuntimeOwnerDependencies)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise RuntimeOwnerDependencyError("ORIGINAL_OWNER_DEPENDENCY_CONTENT_CHANGED")
        self.accounts.require_resolved(value.previous)
        self.daily.require_resolved_snapshot(value.daily)
        if value.reconciliation is not None:
            self.publisher.require_resolved(value.reconciliation)

    def _heads(
        self, previous: ResolvedContinuousAccount, daily: ResolvedDailyRuntimeSnapshot
    ) -> ReconciliationHeads:
        return ReconciliationHeads(
            previous.checkpoint.current.snapshot.journal_sha256,
            previous.checkpoint.current.snapshot.order_sha256,
            daily.obligations.semantic_sha256,
            daily_runtime_effect_watermark(
                attempt_envelopes=daily.attempt_envelopes, observed_groups=daily.observed_groups
            ),
            daily_attempt_inventory_sha256(daily.attempts),
            0 if daily.control is None else daily.control.sequence_number,
            daily.raw.receipt.fence.fencing_generation,
        )

    def _quiescent(
        self, previous: ResolvedContinuousAccount, daily: ResolvedDailyRuntimeSnapshot
    ) -> None:
        self.require_quiescent_state(previous.checkpoint.state, daily.attempts)

    @staticmethod
    def require_quiescent_state(
        state: AccountingState, attempts: tuple[CanonicalDailyAttempt, ...]
    ) -> None:
        """Pure classification only; callers must authenticate state and complete history."""
        if any(
            hold.state != "terminal"
            or hold.remaining_quantity
            or hold.reserved_cash
            or hold.reserved_sell_quantity
            for hold in state.commitments
        ) or any(
            attempt.state
            not in (
                SubmissionAttemptState.ABANDONED,
                SubmissionAttemptState.CONFIRMED,
                SubmissionAttemptState.RESOLVED,
            )
            for attempt in attempts
        ):
            raise RuntimeOwnerDependencyError("OWNER_CUTOVER_HAS_UNRESOLVED_CAPACITY_OR_SENDS")
        for submission in state.submissions:
            order = reduce_order_lifecycle(
                submission=submission,
                broker_events=tuple(
                    event for event in state.broker_events if event.order_id == submission.order_id
                ),
                cancel_request=next(
                    (
                        item
                        for item in state.cancel_requests
                        if item.order_id == submission.order_id
                    ),
                    None,
                ),
            )
            if order.status not in (
                CanonicalOrderStatus.FILLED,
                CanonicalOrderStatus.CANCELED,
                CanonicalOrderStatus.REJECTED,
            ):
                raise RuntimeOwnerDependencyError("OWNER_CUTOVER_HAS_WORKING_ORDER")

    @staticmethod
    def require_engine_match(spec: object, proposed: RuntimeRiskAssignment) -> None:
        """No policy/strategy changes until the sole engine has a real cutover command."""
        if type(spec) is not ContinuousEngineSpec:
            raise RuntimeOwnerDependencyError("OWNER_ACTUAL_CONTINUOUS_ENGINE_SPEC_REQUIRED")
        if (
            proposed.policy != spec.risk_policy
            or proposed.strategy != spec.strategy
            or proposed.configuration_sha256 != content_digest(spec.strategy_configuration)
            or proposed.instrument_symbols != spec.instruments
        ):
            raise RuntimeOwnerDependencyError("OWNER_ENGINE_STRATEGY_POLICY_CUTOVER_UNSUPPORTED")

    @staticmethod
    def require_original_fence(reference: DailyFenceReference, lease: AccountLease) -> None:
        """Verify original scalar references against an actual decoded retained lease."""
        digest = sha256(
            canonical_json_bytes(
                (
                    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
                    "fence_receipt",
                    reference.fence.semantic_sha256,
                    reference.validated_at,
                    reference.valid_until,
                    reference.policy_sha256,
                    reference.lease_sha256,
                )
            )
        ).hexdigest()
        if (
            lease.semantic_sha256 != reference.lease_sha256
            or lease.fence != reference.fence
            or lease.expires_at != reference.valid_until
            or lease.policy_sha256 != reference.policy_sha256
            or not lease.heartbeat_at <= reference.validated_at < lease.expires_at
            or digest != reference.original_receipt_sha256
        ):
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_LEASE_PROVENANCE_DIFFERS")

    def _derive(
        self,
        *,
        previous: ResolvedContinuousAccount,
        proposed: RuntimeRiskAssignment,
        daily: ResolvedDailyRuntimeSnapshot,
        original: DailyFenceReference | None = None,
    ) -> tuple[RuntimeOwnerDependencies, ResolvedContinuousReconciliationPublication | None]:
        self._bound()
        self.accounts.require_resolved(previous)
        self.daily.require_resolved_snapshot(daily)
        scope, before = previous.receipt.commit.scope, daily.assignment
        self.require_engine_match(previous.checkpoint.inputs.spec, proposed)
        receipt = daily.raw.receipt
        if (
            proposed.account_id != scope.account_id
            or proposed.account_binding_sha256 != scope.account_binding_sha256
            or proposed.producer_map_sha256 != self.producer.producer_map.semantic_sha256
            or proposed.previous_assignment_sha256
            != (None if before is None else before.semantic_sha256)
            or proposed.generation != (1 if before is None else before.generation + 1)
            or daily.raw.account_id != scope.account_id
            or tuple(
                sorted(previous.checkpoint.state.commitments, key=lambda item: item.commitment_id)
            )
            != tuple(item.commitment for item in daily.obligations.bindings)
        ):
            raise RuntimeOwnerDependencyError(
                "OWNER_ACTUAL_ASSIGNMENT_OR_COMPLETE_INVENTORY_DIFFERS"
            )
        if before is None and (
            previous.receipt.commit.sequence != 1 or proposed.enabled_for_new_exposure
        ):
            raise RuntimeOwnerDependencyError("OWNER_INITIAL_DISABLED_REQUIRES_ACTUAL_GENESIS")
        fence = original or DailyFenceReference(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256=receipt.lease_sha256,
            original_receipt_sha256=receipt.semantic_sha256,
        )
        if (fence.fence, fence.lease_sha256, fence.policy_sha256, fence.valid_until) != (
            receipt.fence,
            receipt.lease_sha256,
            receipt.policy_sha256,
            receipt.valid_until,
        ) or not fence.validated_at <= receipt.validated_at < fence.valid_until:
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_FENCE_OR_TIME_DIFFERS")
        heads = self._heads(previous, daily)
        paired = None
        valid_until = min(fence.valid_until, fence.validated_at + timedelta(seconds=60))
        if before is None:
            self._quiescent(previous, daily)
        elif not _disable_only(before, proposed):
            self._quiescent(previous, daily)
            ancestor = self.accounts.nearest_source_ancestor(
                previous, schema_id="continuous-venue-capture/1"
            )
            if ancestor is None:
                raise RuntimeOwnerDependencyError("OWNER_CUTOVER_REQUIRES_ACTUAL_RECONCILIATION")
            paired = self.publisher.resolve_for_account(
                ancestor, scope=self.publisher.sources.scope
            )
            if paired is None:
                raise RuntimeOwnerDependencyError("OWNER_CUTOVER_REQUIRES_ACTUAL_RECONCILIATION")
            self.publisher.require_resolved(paired)
            result = paired.reconciliation.resolved.result
            if (
                result.status != "converged"
                or result.heads != heads
                or result.scope.account_id != scope.account_id
                or result.scope.binding_sha256 != scope.account_binding_sha256
                or result.scope.environment != "stateful_simulation"
                or result.policy_sha256 != ReconciliationPolicy().semantic_sha256
            ):
                raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_RECONCILIATION_HEADS_DIFFER")
            for instant in (
                result.observation_started_at,
                result.observation_received_through,
                result.completed_at,
            ):
                deadline = instant + timedelta(seconds=60)
                if not instant <= fence.validated_at <= receipt.validated_at < deadline:
                    raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_RECONCILIATION_EXPIRED")
                valid_until = min(valid_until, deadline)
        if receipt.validated_at >= valid_until:
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_DEPENDENCIES_EXPIRED")
        return RuntimeOwnerDependencies(
            scope=scope,
            previous=previous.receipt,
            proposed=proposed,
            previous_assignment_sha256=None if before is None else before.semantic_sha256,
            control_sha256=None if daily.control is None else daily.control.semantic_sha256,
            obligations_sha256=daily.obligations.semantic_sha256,
            attempts_sha256=daily_attempt_inventory_sha256(daily.attempts),
            heads=heads,
            fence=fence,
            reconciliation=None if paired is None else paired.reconciliation.receipt,
            checked_at=fence.validated_at,
            valid_until=valid_until,
        ), paired

    def prepare_dependencies(
        self,
        *,
        previous: ResolvedContinuousAccount,
        proposed: RuntimeRiskAssignment,
        fence: AccountFence,
    ) -> PreparedRuntimeOwnerDependencies:
        current = self.daily.resolve_snapshot(
            self.daily.read_snapshot(account_id=fence.account_id, fence=fence)
        )
        record, paired = self._derive(previous=previous, proposed=proposed, daily=current)
        payload = self.codec.encode_record(record)
        if not 0 < len(payload) <= MAX_OWNER_DEPENDENCIES_BYTES:
            raise RuntimeOwnerDependencyError("OWNER_DEPENDENCY_OBJECT_BOUND")
        reference = ContinuousEvidenceRef(
            OWNER_DEPENDENCIES_SCHEMA,
            self.artifacts.put(payload, max_bytes=MAX_OWNER_DEPENDENCIES_BYTES),
            record.semantic_sha256,
        )
        return self._prepared(
            PreparedRuntimeOwnerDependencies(
                reference, record, previous, current, paired, self._seal
            )
        )

    def _read(self, reference: ContinuousEvidenceRef) -> RuntimeOwnerDependencies:
        if (
            reference.schema_id != OWNER_DEPENDENCIES_SCHEMA
            or reference.object_ref.byte_count > MAX_OWNER_DEPENDENCIES_BYTES
        ):
            raise RuntimeOwnerDependencyError("OWNER_DEPENDENCY_OBJECT_BOUND")
        payload = self.artifacts.read(reference.object_ref, max_bytes=MAX_OWNER_DEPENDENCIES_BYTES)
        value = self.codec.decode_record(payload, RuntimeOwnerDependencies)
        if (
            len(payload),
            sha256(payload).hexdigest(),
            value.semantic_sha256,
            self.codec.encode_record(value),
        ) != (
            reference.object_ref.byte_count,
            reference.object_ref.object_sha256,
            reference.semantic_sha256,
            payload,
        ):
            raise RuntimeOwnerDependencyError("OWNER_DEPENDENCY_OBJECT_BINDING_DIFFERS")
        return value

    def prepare_owner_command_read(
        self,
        *,
        previous: ResolvedContinuousAccount,
        original_receipt: JournalReceipt,
        fence: AccountFence,
    ) -> RuntimeOwnerDependencyReadPlan:
        self.accounts.require_resolved(previous)
        request = self.commands.read(
            previous.receipt.commit.scope,
            command_id=original_receipt.command_id,
            budget=RuntimeReadBudget(),
        )
        if request is None or request.read.receipt != original_receipt:
            raise RuntimeOwnerDependencyError("ACTUAL_RETAINED_OWNER_REQUEST_REQUIRED")
        self.commands.require_resolved(request)
        original = self._read(request.record.dependencies)
        current = self.daily.resolve_snapshot(
            self.daily.read_snapshot(account_id=fence.account_id, fence=fence)
        )
        actual, paired = self._derive(
            previous=previous, proposed=original.proposed, daily=current, original=original.fence
        )
        command = request.record.command
        at = current.raw.receipt.validated_at
        if (
            actual != original
            or command.expected_heads != actual.heads
            or command.before_assignment_sha256 != actual.previous_assignment_sha256
            or command.after_assignment_sha256 != actual.proposed.semantic_sha256
            or command.quiescence_sha256 != actual.semantic_sha256
            or command.expires_at > actual.valid_until
            or not actual.checked_at
            <= command.requested_at
            <= at
            < min(command.expires_at, actual.valid_until)
        ):
            raise RuntimeOwnerDependencyError(
                "OWNER_REQUEST_ORIGINAL_DEPENDENCIES_DIFFER_OR_EXPIRED"
            )
        prepared = self._prepared(
            PreparedRuntimeOwnerDependencies(
                request.record.dependencies, actual, previous, current, paired, self._seal
            )
        )
        plan = self._own(RuntimeOwnerDependencyReadPlan(prepared, request, self._seal))
        self._active[original_receipt.semantic_sha256] = plan
        return plan

    def require_plan(self, plan: RuntimeOwnerDependencyReadPlan) -> None:
        self._require(plan, RuntimeOwnerDependencyReadPlan)
        self.require_prepared(plan.dependencies)
        self.commands.require_resolved(plan.request)

    def owns_snapshot(self, snapshot: RuntimeProducerRawSnapshot) -> bool:
        return self._owned.get(id(snapshot)) is snapshot and id(snapshot) in self._raw

    def capture_in_transaction(
        self,
        connection: Connection,
        *,
        account_id: str,
        owner_command_ref: JournalReceipt,
        budget: RuntimeReadBudget,
    ) -> RuntimeProducerRawSnapshot:
        plan = self._active.get(owner_command_ref.semantic_sha256)
        if plan is None:
            raise RuntimeOwnerDependencyError("OWNER_REQUEST_MUST_BE_RESOLVED_BEFORE_CAPTURE")
        self._require(plan, RuntimeOwnerDependencyReadPlan)
        value = plan.dependencies
        if account_id != value.record.scope.account_id:
            raise RuntimeOwnerDependencyError("OWNER_REQUEST_CAPTURE_SCOPE_DIFFERS")
        before = len(budget.captured)
        # B already captured its complete tables with this same budget. Require the
        # exact original inventories; do not claim a partial table as a footprint.
        for original in value.daily.raw.tables:
            current = next(
                (
                    item
                    for item in budget.captured
                    if item.table is original.table and item.account_id == account_id
                ),
                None,
            )
            if current is None or current.rows != original.rows:
                raise RuntimeOwnerDependencyError(
                    "OWNER_CURRENT_DAILY_OR_CONTROL_INVENTORY_CHANGED"
                )
        tables = []
        for table in (*CONTINUOUS_ACCOUNT_TABLES, phase2_account_leases):
            current = next(
                (
                    item
                    for item in budget.captured
                    if item.table is table and item.account_id == account_id
                ),
                None,
            )
            tables.append(
                current
                or capture_runtime_table(connection, table, account_id=account_id, budget=budget)
            )
        request = self.commands.capture_in_transaction(
            connection, value.record.scope, command_id=owner_command_ref.command_id, budget=budget
        )
        sources = [(self.accounts.journal, value.previous.journal)]
        paired_row = None
        if value.reconciliation is not None:
            paired = value.reconciliation
            row = self.publisher.applied.capture_commit_in_transaction(
                connection,
                scope=paired.reconciliation.snapshot.scope,
                command_id=paired.reconciliation.receipt.commit.command_id,
            )
            if row is None:
                raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_RECONCILIATION_MISSING")
            paired_row = row.row
            budget.charge(
                1,
                sum(len(v) for v in paired_row.values() if type(v) is bytes),
                sum(
                    len(str(v).encode())
                    for v in paired_row.values()
                    if v is not None and type(v) is not bytes
                ),
            )
            sources += [
                (self.accounts.journal, paired.continuous.journal),
                (self.publisher.journal, paired.journal),
            ]
            sources += [(self.publisher.sources.journal, read) for read in paired.sources.reads]
        pool = DetachedJournalCapture(
            max_bytes=MAX_TOTAL_BYTES - budget.payload_bytes,
            max_metadata_bytes=MAX_METADATA_BYTES - budget.metadata_bytes,
        )
        detached = []
        for store, original_read in sources:
            old_rows, old_bytes, old_metadata = len(pool.rows), pool.byte_count, pool.metadata_bytes
            detached.append(
                pool.capture(
                    store.capture_in_transaction(
                        connection,
                        original_read.snapshot.key,
                        command_id=original_read.snapshot.command_id,
                    )
                )
            )
            # Charge newly interned physical rows before the next journal read.
            budget.charge(
                len(pool.rows) - old_rows,
                pool.byte_count - old_bytes,
                pool.metadata_bytes - old_metadata,
            )
        journals = tuple(detached)
        raw = self._own(RuntimeProducerRawSnapshot(tuple(budget.captured[before:])))
        self._raw[id(raw)] = _Captured(plan, request, tuple(tables), journals, paired_row)
        self._original[id(raw)] = _identity_graph(self._raw[id(raw)])
        # _Captured is a distinct retained root: preserve it explicitly for cheap guards.
        self._original[id(raw)] = tuple(
            (self._raw[id(raw)] if item is None else item, attrs)
            for item, attrs in self._original[id(raw)]
        ) + _identity_graph(raw)
        finalize(raw, self._raw.pop, id(raw), None)
        return raw

    def resolve(
        self,
        snapshot: RuntimeProducerRawSnapshot,
        *,
        assignment: RuntimeRiskAssignment | None,
        previous: RuntimeRiskAssignment | None,
        owner_command_ref: JournalReceipt,
        fence_receipt: AccountFenceReceipt,
        control: OperationalControlTransition | None,
    ) -> VerifiedRuntimeAssignmentCommand:
        self._require(snapshot, RuntimeProducerRawSnapshot)
        captured = self._raw[id(snapshot)]
        plan, value = captured.plan, captured.plan.dependencies
        self.require_plan(plan)
        request = self.commands.resolve_snapshot(captured.request)
        record = value.record
        at = fence_receipt.validated_at
        if (
            request is None
            or request.record != plan.request.record
            or request.read.receipt != owner_command_ref
            or assignment != record.proposed
            or previous != value.daily.assignment
            or control != value.daily.control
            or self._read(value.reference) != record
            or (
                fence_receipt.fence,
                fence_receipt.lease_sha256,
                fence_receipt.policy_sha256,
                fence_receipt.valid_until,
            )
            != (
                record.fence.fence,
                record.fence.lease_sha256,
                record.fence.policy_sha256,
                record.fence.valid_until,
            )
            or not value.daily.raw.receipt.validated_at
            <= at
            < min(record.valid_until, plan.request.record.command.expires_at)
        ):
            raise RuntimeOwnerDependencyError("OWNER_CAPTURE_OR_CURRENT_ASSIGNMENT_FENCE_DIFFERS")
        rows = next(
            item.rows for item in captured.tables if item.table is CONTINUOUS_ACCOUNT_TABLES[0]
        )
        if (
            value.previous.snapshot.row not in rows
            or max(rows, key=lambda row: row["sequence"]) != value.previous.snapshot.row
        ):
            raise RuntimeOwnerDependencyError("OWNER_CURRENT_CANONICAL_PREFIX_CHANGED")
        head_rows = next(
            item.rows for item in captured.tables if item.table is CONTINUOUS_ACCOUNT_TABLES[1]
        )
        commit = value.previous.receipt.commit
        if len(head_rows) != 1 or any(
            head_rows[0][name] != expected
            for name, expected in (
                ("scope_sha256", commit.scope.semantic_sha256),
                ("command_id", commit.transition.command_id),
                ("sequence", commit.sequence),
                ("commit_sha256", commit.semantic_sha256),
                ("checkpoint_sha256", commit.transition.checkpoint_sha256),
            )
        ):
            raise RuntimeOwnerDependencyError("OWNER_CURRENT_CANONICAL_HEAD_MIRROR_DIFFERS")
        originals = [value.previous.journal]
        if value.reconciliation is not None:
            paired = value.reconciliation
            if captured.reconciliation_row != paired.reconciliation.snapshot.row:
                raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_RECONCILIATION_CHANGED")
            originals += [paired.continuous.journal, paired.journal, *paired.sources.reads]
        if any(
            new.requested_receipt != old.snapshot.requested_receipt
            for new, old in zip(captured.journals, originals, strict=True)
        ):
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_SOURCE_JOURNAL_CHANGED")
        leases = next(item.rows for item in captured.tables if item.table is phase2_account_leases)
        selected = [row for row in leases if row["lease_sha256"] == record.fence.lease_sha256]
        if len(selected) != 1:
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_LEASE_MISSING")
        values = dict(selected[0])
        for name in ("acquired_at", "heartbeat_at", "expires_at"):
            values[name] = as_aware_utc(datetime.fromisoformat(values[name]))
        lease = account_lease_from_row(values)
        self.require_original_fence(record.fence, lease)
        self._resolved[id(snapshot)] = request
        finalize(snapshot, self._resolved.pop, id(snapshot), None)
        return VerifiedRuntimeAssignmentCommand(
            plan.request.record.command,
            record.heads,
            None
            if value.reconciliation is None
            else value.reconciliation.reconciliation.resolved.result,
        )

    def recheck_in_transaction(
        self, connection: Connection, snapshot: RuntimeProducerRawSnapshot
    ) -> None:
        self._require(snapshot, RuntimeProducerRawSnapshot)
        request = self._resolved.get(id(snapshot))
        if request is None:
            raise RuntimeOwnerDependencyError("OWNER_CAPTURE_REQUIRES_ORIGINAL_RESOLUTION")
        value = self._raw[id(snapshot)].plan.dependencies
        receipt = self.daily.recheck_snapshot_in_transaction(
            connection, value.daily, fence=value.record.fence.fence
        )
        if receipt.validated_at >= min(value.record.valid_until, request.record.command.expires_at):
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_REQUEST_EXPIRED_BEFORE_COMMIT")
        self.accounts.recheck_in_transaction(connection, value.previous, require_current=True)
        self.commands.recheck_in_transaction(connection, request)
        if value.reconciliation is not None:
            self.publisher.recheck_in_transaction(
                connection, value.reconciliation, fence=receipt.fence, require_current=False
            )

    def recheck_installed_owner_sources_in_transaction(
        self, connection: Connection, *, prepared: PreparedDailyAssignment, fence: AccountFence
    ) -> AccountFenceReceipt:
        """Original sources after B proves this exact assignment's complete poststate.

        B authenticates the post-write B/control rows before calling this guard.
        This method never rechecks old-before assignment rows, decodes sources,
        or claims that the outer transaction has committed.
        """
        self.daily.require_prepared_assignment_in_transaction(connection, prepared)
        snapshot = prepared.snapshot.raw.producer
        self._require(snapshot, RuntimeProducerRawSnapshot)
        request = self._resolved.get(id(snapshot))
        if request is None:
            raise RuntimeOwnerDependencyError("OWNER_CAPTURE_REQUIRES_ORIGINAL_RESOLUTION")
        value = self._raw[id(snapshot)].plan.dependencies
        if prepared.result != value.record.proposed or fence != value.record.fence.fence:
            raise RuntimeOwnerDependencyError("OWNER_INSTALLED_ASSIGNMENT_OR_FENCE_DIFFERS")
        self.accounts.recheck_in_transaction(connection, value.previous, require_current=True)
        self.commands.recheck_in_transaction(connection, request)
        if value.reconciliation is not None:
            self.publisher.recheck_in_transaction(
                connection, value.reconciliation, fence=fence, require_current=False
            )
        receipt = self.accounts.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        if receipt.validated_at >= min(
            value.record.valid_until, request.record.command.expires_at, prepared.valid_until
        ):
            raise RuntimeOwnerDependencyError("OWNER_ORIGINAL_REQUEST_EXPIRED_BEFORE_COMMIT")
        return receipt
