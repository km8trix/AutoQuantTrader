"""Authenticate original applied owner assignments without renewing their authority.

This historical reader consumes an actual owned complete B history, immutable C
publication metadata/checkpoints, the original local request journal and original
independent A evidence. It does not restore C or read a fresh B snapshot. Its
owned result is an association only, never VerifiedRuntimeAssignmentCommand.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import timedelta
from hashlib import sha256
from itertools import pairwise
from typing import Any, TypeVar
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection

from packages.application.continuous_reconciliation_publication import (
    validate_continuous_application_times,
)
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import (
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads, ReconciliationPolicy
from packages.domain.reconciliation_persistence_contracts import ReconciliationEvidenceRef
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.runtime_owner_dependency_contracts import (
    MAX_OWNER_DEPENDENCIES_BYTES,
    OWNER_DEPENDENCIES_SCHEMA,
    RuntimeOwnerDependencies,
)
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture
from packages.persistence.applied_reconciliation import (
    ReconciliationCommitSnapshot,
    ResolvedReconciliationSnapshot,
)
from packages.persistence.continuous_account import (
    ContinuousReferenceSnapshot,
    ResolvedContinuousReference,
)
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.continuous_venue_sources import ResolvedContinuousVenueSources
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_ROWS,
    MAX_TOTAL_BYTES,
    ResolvedDailyRuntimeSnapshot,
    RetainedDailyAssignmentPrefix,
    RuntimeAssignmentCommand,
    RuntimeReadBudget,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import ResolvedJournalRead
from packages.persistence.runtime_owner_commands import ResolvedRuntimeOwnerCommand
from packages.persistence.runtime_owner_dependencies import (
    RuntimeOwnerDependencyError,
    SqlRuntimeOwnerDependencies,
    _disable_only,
    _identity_graph,
)
from packages.persistence.schema import phase2_account_leases

RecordT = TypeVar("RecordT", bound=ContractRecord)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedRuntimeOwnerAssociation:
    dependencies: RuntimeOwnerDependencies
    reference: ContinuousEvidenceRef
    prefix: RetainedDailyAssignmentPrefix
    request: ResolvedRuntimeOwnerCommand
    canonical: ResolvedContinuousReference
    checkpoint: CausalEngineCheckpoint
    canonical_chain: tuple[ResolvedContinuousReference, ...]
    reconciliation: ResolvedReconciliationSnapshot | None
    sources: ResolvedContinuousVenueSources | None
    reconciliation_journal: ResolvedJournalRead | None
    seal: object = field(repr=False, compare=False)


class _Objects:
    def __init__(self, reader: SqlRuntimeOwnerAssociations) -> None:
        self.reader = reader
        self.references: dict[str, ObjectRef] = {}
        self.decoded: dict[str, ContractRecord] = {}
        self.total = 0

    def retain(self, reference: ObjectRef) -> None:
        old = self.references.get(reference.object_sha256)
        if old is not None and old != reference:
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_OBJECT_REFERENCE_CONFLICT")
        if old is None:
            self.references[reference.object_sha256] = reference
            self.total += reference.byte_count
            if self.total > MAX_TOTAL_BYTES or len(self.references) > MAX_ROWS:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_OBJECT_CLOSURE_BOUND")

    def graph(self, value: object) -> None:
        pending, seen = [value], set()
        while pending:
            item = pending.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if type(item) is ObjectRef:
                self.retain(item)
            elif is_dataclass(item) and not isinstance(item, type):
                pending.extend(
                    getattr(item, f.name)
                    for f in fields(item)
                    if f.name not in {"seal", "_owner", "_validated_values"}
                )
            elif type(item) is tuple:
                pending.extend(item)

    def read(self, reference: ObjectRef, expected: type[RecordT], semantic: str) -> RecordT:
        self.retain(reference)
        old = self.decoded.get(reference.object_sha256)
        if old is not None:
            if type(old) is not expected or old.semantic_sha256 != semantic:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_OBJECT_TYPE_DIFFERS")
            return old
        payload = self.reader.artifacts.read(reference, max_bytes=MAX_TOTAL_BYTES)
        value = self.reader.codec.decode_record(payload, expected)
        if (
            len(payload),
            sha256(payload).hexdigest(),
            value.semantic_sha256,
            self.reader.codec.encode_record(value),
        ) != (reference.byte_count, reference.object_sha256, semantic, payload):
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_OBJECT_BINDING_DIFFERS")
        self.decoded[reference.object_sha256] = value
        return value


class SqlRuntimeOwnerAssociations:
    def __init__(self, *, owner_dependencies: SqlRuntimeOwnerDependencies) -> None:
        if type(owner_dependencies) is not SqlRuntimeOwnerDependencies:
            raise RuntimeOwnerDependencyError("EXACT_HISTORICAL_OWNER_DEPENDENCIES_REQUIRED")
        owner_dependencies._bound()
        self.owner_dependencies = owner_dependencies
        self.engine, self.accounts, self.daily, self.publisher, self.commands = (
            owner_dependencies.engine,
            owner_dependencies.accounts,
            owner_dependencies.daily,
            owner_dependencies.publisher,
            owner_dependencies.commands,
        )
        self.artifacts, self.codec = owner_dependencies.artifacts, owner_dependencies.codec
        self._bindings = self._binding_values()
        self._seal = object()
        self._owned: WeakValueDictionary[int, ResolvedRuntimeOwnerAssociation] = (
            WeakValueDictionary()
        )
        self._original: dict[int, Any] = {}
        self._fingerprints: dict[int, str] = {}

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self.owner_dependencies,
            self.engine,
            self.accounts,
            self.daily,
            self.publisher,
            self.commands,
            self.artifacts,
            self.codec,
        )

    def _bound(self) -> None:
        self.owner_dependencies._bound()
        if any(a is not b for a, b in zip(self._bindings, self._binding_values(), strict=True)):
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_READER_BINDINGS_CHANGED")

    @staticmethod
    def _fingerprint(value: ResolvedRuntimeOwnerAssociation) -> str:
        return content_digest(
            (
                value.dependencies,
                value.reference,
                value.checkpoint,
                value.prefix.before_assignment,
                value.prefix.after_assignment,
                value.prefix.command,
                value.prefix.recorded_at,
                value.prefix.obligations,
                value.prefix.attempts,
                value.prefix.attempt_envelopes,
                value.prefix.observed_groups,
                value.prefix.control,
                detached_journal_value(value.request.read),
                tuple(detached_journal_value(item.snapshot) for item in value.canonical_chain),
                None
                if value.reconciliation is None
                else detached_journal_value(value.reconciliation),
                None
                if value.sources is None
                else (
                    value.sources.capture,
                    value.sources.pages,
                    detached_journal_value(value.sources.reads),
                ),
                None
                if value.reconciliation_journal is None
                else detached_journal_value(value.reconciliation_journal),
            )
        )

    def _own(self, value: ResolvedRuntimeOwnerAssociation) -> ResolvedRuntimeOwnerAssociation:
        self._owned[id(value)] = value
        self._original[id(value)] = _identity_graph(value)
        self._fingerprints[id(value)] = self._fingerprint(value)
        finalize(value, self._original.pop, id(value), None)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    def _require(self, value: ResolvedRuntimeOwnerAssociation) -> None:
        self._bound()
        if (
            type(value) is not ResolvedRuntimeOwnerAssociation
            or self._owned.get(id(value)) is not value
        ):
            raise RuntimeOwnerDependencyError("OWNED_HISTORICAL_OWNER_ASSOCIATION_REQUIRED")
        for item, attributes in self._original[id(value)]:
            if any(
                getattr(value if item is None else item, name) is not old
                for name, old in attributes
            ):
                raise RuntimeOwnerDependencyError("ORIGINAL_HISTORICAL_OWNER_FIELDS_CHANGED")

    def require_association(self, value: ResolvedRuntimeOwnerAssociation) -> None:
        self._require(value)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise RuntimeOwnerDependencyError("ORIGINAL_HISTORICAL_OWNER_CONTENT_CHANGED")
        self.daily.require_assignment_prefix(value.prefix)
        self.commands.require_resolved(value.request)
        for original in value.canonical_chain:
            self.accounts.require_reference(original)
        if value.sources is not None:
            self.publisher.sources.require_resolved(value.sources)

    def require_owned(self, value: ResolvedRuntimeOwnerAssociation) -> None:
        self.require_association(value)

    @staticmethod
    def _charge_row(budget: RuntimeReadBudget, row: Mapping[str, Any]) -> None:
        budget.charge(
            1,
            sum(len(v) for v in row.values() if type(v) is bytes),
            sum(
                len(str(v).encode()) for v in row.values() if v is not None and type(v) is not bytes
            ),
        )

    def _canonical_capture(
        self,
        connection: Connection,
        record: RuntimeOwnerDependencies,
        budget: RuntimeReadBudget,
    ) -> tuple[
        tuple[ContinuousReferenceSnapshot, ...],
        ReconciliationCommitSnapshot | None,
        DetachedJournalCapture,
    ]:
        tables = []
        for table in (*CONTINUOUS_ACCOUNT_TABLES, phase2_account_leases):
            existing = next(
                (
                    item
                    for item in budget.captured
                    if item.table is table and item.account_id == record.scope.account_id
                ),
                None,
            )
            tables.append(
                existing
                or capture_runtime_table(
                    connection, table, account_id=record.scope.account_id, budget=budget
                )
            )
        commits = tables[0].rows
        leases = tables[2].rows
        pool = DetachedJournalCapture(
            max_bytes=MAX_TOTAL_BYTES - budget.payload_bytes,
            max_metadata_bytes=MAX_METADATA_BYTES - budget.metadata_bytes,
        )
        command_id = record.previous.commit.transition.command_id
        stop = (
            command_id if record.reconciliation is None else record.reconciliation.commit.command_id
        )
        result: list[ContinuousReferenceSnapshot] = []
        while True:
            before = len(pool.rows), pool.byte_count, pool.metadata_bytes
            raw = self.accounts.capture_reference_in_transaction(
                connection,
                scope=record.scope,
                command_id=command_id,
                source_lease_sha256=record.fence.lease_sha256 if not result else None,
                journal_pool=pool,
            )
            budget.charge(
                len(pool.rows) - before[0],
                pool.byte_count - before[1],
                pool.metadata_bytes - before[2],
            )
            if raw is None or raw.current.row not in commits or raw.lease not in leases:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_CANONICAL_REFERENCE_MISSING")
            if raw.previous is not None and (
                raw.previous.row not in commits or raw.previous_lease not in leases
            ):
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_CANONICAL_PARENT_MISSING")
            if raw.source_lease is not None and raw.source_lease not in leases:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_LEASE_MISSING")
            result.append(raw)
            if len(result) > MAX_ROWS:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ANCESTRY_BOUND")
            if command_id == stop:
                break
            if raw.previous is None:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_RECONCILIATION_NOT_ANCESTOR")
            command_id = raw.previous.row["command_id"]
        paired = None
        if record.reconciliation is not None:
            paired = self.publisher.applied.capture_commit_in_transaction(
                connection,
                scope=record.reconciliation.commit.scope,
                command_id=record.reconciliation.commit.command_id,
            )
            if paired is None:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_RECONCILIATION_MISSING")
            self._charge_row(budget, paired.row)
        return tuple(result), paired, pool

    def read(
        self,
        scope: ContinuousAccountScope,
        *,
        current: ResolvedDailyRuntimeSnapshot,
        assignment_generation: int,
        budget: RuntimeReadBudget | None = None,
    ) -> ResolvedRuntimeOwnerAssociation:
        self._bound()
        self.daily.require_resolved_snapshot(current)
        if (
            type(scope) is not ContinuousAccountScope
            or scope.account_id != current.raw.account_id
            or type(assignment_generation) is not int
            or assignment_generation < 1
        ):
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_SCOPE_OR_GENERATION_DIFFERS")
        rows = next(
            item.rows for item in current.raw.tables if item.table is daily_runtime_assignments
        )
        selected = [row for row in rows if row["generation"] == assignment_generation]
        if len(selected) != 1:
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ASSIGNMENT_ROW_MISSING")
        row = selected[0]
        command = self.codec.decode_record(row["command_payload"], RuntimeAssignmentCommand)
        shared = budget if budget is not None else RuntimeReadBudget()
        request = self.commands.read(scope, command_id=row["command_id"], budget=shared)
        if (
            request is None
            or request.record.command != command
            or request.read.receipt is None
            or request.read.receipt.command_sha256 != command.semantic_sha256
        ):
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ACTUAL_REQUEST_REQUIRED")
        reference = request.record.dependencies
        if (
            reference.schema_id != OWNER_DEPENDENCIES_SCHEMA
            or reference.object_ref.byte_count > MAX_OWNER_DEPENDENCIES_BYTES
        ):
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_DEPENDENCY_SCHEMA_OR_BOUND")
        objects = _Objects(self)
        record = objects.read(
            reference.object_ref, RuntimeOwnerDependencies, reference.semantic_sha256
        )
        objects.graph(record)
        if record.scope != scope or record.proposed.generation != assignment_generation:
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_DEPENDENCY_SCOPE_DIFFERS")
        with _repeatable_read_transaction(self.engine) as connection:
            captured, paired_raw, pool = self._canonical_capture(connection, record, shared)
        canonical = tuple(self.accounts.resolve_reference(item) for item in captured)
        original = canonical[0]
        if original.receipt != record.previous or original.source_lease is None:
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_CANONICAL_RECEIPT_DIFFERS")
        for child, parent in pairwise(canonical):
            if child.previous_receipt != parent.receipt:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_CANONICAL_ANCESTRY_DIFFERS")
        self.owner_dependencies.require_original_fence(record.fence, original.source_lease)
        checkpoint = objects.read(
            original.receipt.commit.transition.checkpoint,
            CausalEngineCheckpoint,
            original.receipt.commit.transition.checkpoint_sha256,
        )
        if type(checkpoint.inputs) is not ContinuousEngineInputs:
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_CONTINUOUS_INPUTS_REQUIRED")
        if (
            checkpoint.inputs.spec.account_id != scope.account_id
            or checkpoint.inputs.spec.account_binding_sha256 != scope.account_binding_sha256
            or checkpoint.inputs.spec.deployment_id != scope.stream_id
            or checkpoint.now > record.checked_at
        ):
            raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_CHECKPOINT_SCOPE_OR_TIME_DIFFERS")
        self.owner_dependencies.require_engine_match(checkpoint.inputs.spec, record.proposed)
        prefix = self.daily.inspect_assignment_prefix(
            current,
            assignment_generation=assignment_generation,
            through_coordinator_sequence=original.receipt.commit.sequence,
            commitment_ids=tuple(
                sorted(item.commitment_id for item in checkpoint.state.commitments)
            ),
        )
        self.daily.require_assignment_prefix(prefix)
        heads = ReconciliationHeads(
            checkpoint.current.snapshot.journal_sha256,
            checkpoint.current.snapshot.order_sha256,
            prefix.obligations.semantic_sha256,
            daily_runtime_effect_watermark(
                attempt_envelopes=prefix.attempt_envelopes, observed_groups=prefix.observed_groups
            ),
            daily_attempt_inventory_sha256(prefix.attempts),
            0 if prefix.control is None else prefix.control.sequence_number,
            record.fence.fence.fencing_generation,
        )
        if (
            prefix.command != command
            or prefix.after_assignment != record.proposed
            or (
                None
                if prefix.before_assignment is None
                else prefix.before_assignment.semantic_sha256
            )
            != record.previous_assignment_sha256
            or prefix.after_assignment.previous_assignment_sha256
            != record.previous_assignment_sha256
            or prefix.obligations.semantic_sha256 != record.obligations_sha256
            or daily_attempt_inventory_sha256(prefix.attempts) != record.attempts_sha256
            or (None if prefix.control is None else prefix.control.semantic_sha256)
            != record.control_sha256
            or heads != record.heads
            or command.expected_heads != heads
            or command.quiescence_sha256 != record.semantic_sha256
            or command.after_assignment_sha256 != record.proposed.semantic_sha256
            or command.before_assignment_sha256 != record.previous_assignment_sha256
            or tuple(item.commitment for item in prefix.obligations.bindings)
            != tuple(sorted(checkpoint.state.commitments, key=lambda item: item.commitment_id))
            or not record.checked_at
            <= command.requested_at
            <= prefix.recorded_at
            < command.expires_at
            <= record.valid_until
            or record.valid_until
            > min(record.fence.valid_until, record.checked_at + timedelta(seconds=60))
        ):
            raise RuntimeOwnerDependencyError(
                "HISTORICAL_OWNER_COMPLETE_ORIGINAL_DEPENDENCIES_DIFFER"
            )
        paired = None
        sources = None
        journal = None
        needs_reconciliation = prefix.before_assignment is not None and not _disable_only(
            prefix.before_assignment, prefix.after_assignment
        )
        if prefix.before_assignment is None:
            if original.receipt.commit.sequence != 1 or record.proposed.enabled_for_new_exposure:
                raise RuntimeOwnerDependencyError(
                    "HISTORICAL_OWNER_INITIAL_DISABLED_REQUIRES_GENESIS"
                )
            self.owner_dependencies.require_quiescent_state(checkpoint.state, prefix.attempts)
        if needs_reconciliation:
            self.owner_dependencies.require_quiescent_state(checkpoint.state, prefix.attempts)
        if (record.reconciliation is not None) != needs_reconciliation:
            raise RuntimeOwnerDependencyError(
                "HISTORICAL_OWNER_ORIGINAL_RECONCILIATION_REQUIREMENT_DIFFERS"
            )
        if paired_raw is not None:
            assert record.reconciliation is not None
            anchor = canonical[-1].receipt
            source_ref = anchor.commit.source_evidence
            capture = objects.read(
                source_ref.object_ref, RetainedVenueCapture, source_ref.semantic_sha256
            )
            objects.graph(capture)
            anchor_checkpoint = objects.read(
                anchor.commit.transition.checkpoint,
                CausalEngineCheckpoint,
                anchor.commit.transition.checkpoint_sha256,
            )
            objects.graph(anchor_checkpoint)
            # Bound every original source journal before the next SQL capture.
            # Existing source resolution must reproduce these authentic originals.
            source_snapshots = []
            with _repeatable_read_transaction(self.engine) as connection:
                for source in capture.manifest.sources:
                    before = len(pool.rows), pool.byte_count, pool.metadata_bytes
                    source_snapshots.append(
                        pool.capture(
                            self.publisher.sources.journal.capture_in_transaction(
                                connection, source.key, command_id=source.receipt.command_id
                            )
                        )
                    )
                    shared.charge(
                        len(pool.rows) - before[0],
                        pool.byte_count - before[1],
                        pool.metadata_bytes - before[2],
                    )
            # Existing A evidence resolution performs canonical application and
            # original comparison replay outside SQL; no second financial reducer.
            paired = self.publisher.applied.resolve_snapshot(paired_raw)
            objects.graph(paired.resolved)
            commit = paired.receipt.commit
            source_ref = anchor.commit.source_evidence
            if (
                paired.receipt != record.reconciliation
                or commit.canonical_transition_ref != anchor.commit.transition
                or commit.capture_binding is None
                or commit.capture_binding.capture
                != ReconciliationEvidenceRef(
                    source_ref.schema_id, source_ref.object_ref, source_ref.semantic_sha256
                )
                or commit.capture_binding.source_closure_sha256
                != anchor.commit.transition.source_closure_sha256
            ):
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ACTUAL_A_C_BINDING_DIFFERS")
            sources = self.publisher.sources.resolve(capture)
            if sources.capture.manifest != paired.resolved.sources or tuple(
                read.snapshot for read in sources.reads
            ) != tuple(source_snapshots):
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_A_SOURCE_DIFFERS")
            validate_continuous_application_times(
                anchor_checkpoint,
                capture=capture,
                applications=paired.resolved.applications.applications,
                accounting=self.publisher.accounting,
            )
            result = paired.resolved.result
            if (
                result.status != "converged"
                or result.heads != heads
                or result.scope.account_id != scope.account_id
                or result.scope.binding_sha256 != scope.account_binding_sha256
                or result.scope.environment != "stateful_simulation"
                or result.policy_sha256 != ReconciliationPolicy().semantic_sha256
            ):
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_A_HEADS_DIFFER")
            if any(
                not instant
                <= record.checked_at
                <= prefix.recorded_at
                < instant + timedelta(seconds=60)
                for instant in (
                    result.observation_started_at,
                    result.observation_received_through,
                    result.completed_at,
                )
            ):
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_A_WAS_EXPIRED")
            with _repeatable_read_transaction(self.engine) as connection:
                before = len(pool.rows), pool.byte_count, pool.metadata_bytes
                raw = pool.capture(
                    self.publisher.journal.capture_in_transaction(
                        connection,
                        paired.receipt.journal_key,
                        command_id=paired.receipt.commit.command_id,
                    )
                )
                shared.charge(
                    len(pool.rows) - before[0],
                    pool.byte_count - before[1],
                    pool.metadata_bytes - before[2],
                )
                if (
                    self.publisher.applied.capture_commit_in_transaction(
                        connection, scope=commit.scope, command_id=commit.command_id
                    )
                    != paired_raw
                ):
                    raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_A_ROW_CHANGED")
            journal = self.publisher.journal.resolve_snapshot(raw)
            if journal.receipt != paired.receipt.journal:
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_A_JOURNAL_DIFFERS")
        value = self._own(
            ResolvedRuntimeOwnerAssociation(
                record,
                reference,
                prefix,
                request,
                original,
                checkpoint,
                canonical,
                paired,
                sources,
                journal,
                self._seal,
            )
        )
        with _repeatable_read_transaction(self.engine) as connection:
            self.recheck_in_transaction(connection, value)
        return value

    def recheck_in_transaction(
        self, connection: Connection, value: ResolvedRuntimeOwnerAssociation
    ) -> None:
        """Original immutable rows only; later heads and expired authority are allowed."""
        self._require(value)
        self.daily.recheck_assignment_prefix_in_transaction(connection, value.prefix)
        self.commands.recheck_in_transaction(connection, value.request)
        for original in value.canonical_chain:
            self.accounts.recheck_reference_in_transaction(connection, original)
        if value.reconciliation is not None:
            commit = value.reconciliation.receipt.commit
            raw = self.publisher.applied.capture_commit_in_transaction(
                connection, scope=commit.scope, command_id=commit.command_id
            )
            if (
                raw != value.reconciliation.snapshot
                or value.reconciliation_journal is None
                or value.sources is None
            ):
                raise RuntimeOwnerDependencyError("HISTORICAL_OWNER_ORIGINAL_A_ROW_CHANGED")
            self.publisher.journal.recheck_in_transaction(
                connection, value.reconciliation_journal, require_current_head=False
            )
            self.publisher.sources.recheck_in_transaction(connection, value.sources)
