"""Original activation descriptor evidence, with no current runtime authority.

A supplies its owned raw original provenance. C authenticates original metadata,
checkpoint and source journals; B subsequently owns the complete financial replay.
No synthetic ResolvedContinuousAccount or partial resolved B snapshot is created.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields, is_dataclass
from hashlib import sha256
from itertools import pairwise
from types import MappingProxyType
from typing import Any, TypeVar
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection

from packages.application.continuous_reconciliation_publication import (
    validate_continuous_application_times,
)
from packages.application.continuous_runtime_evidence import ContinuousRuntimeEvidencePort
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
)
from packages.domain.continuous_runtime_source_contracts import (
    MAX_RUNTIME_SOURCE_BYTES,
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
)
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.durable_journal_contracts import JournalReceipt
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.reconciliation_persistence_contracts import (
    ReconciliationCommitReceipt,
    ReconciliationEvidenceRef,
)
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.runtime_operating_contracts import RuntimeClockReference
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture
from packages.persistence.applied_reconciliation import (
    ReconciliationCommitSnapshot,
    ResolvedReconciliationSnapshot,
)
from packages.persistence.continuous_account import (
    ContinuousReferenceSnapshot,
    ResolvedContinuousReference,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.continuous_forward_sources import ResolvedContinuousForwardSources
from packages.persistence.continuous_runtime_attempt_sources import (
    OriginalContinuousRuntimeAttemptPrefix,
)
from packages.persistence.continuous_runtime_sources import (
    CLOCK_REFERENCE_SCHEMA,
    MODEL_REFERENCE_SCHEMA,
    RECONCILIATION_REFERENCE_SCHEMA,
    ContinuousRuntimeSourceError,
    ResolvedOriginalRuntimeClock,
    RuntimeRoleSourceContext,
    SqlContinuousRuntimeSources,
    evaluate_original_runtime_roles,
    original_cash_restriction,
    original_reconciliation_reasons,
    runtime_source_key,
)
from packages.persistence.continuous_venue_sources import ResolvedContinuousVenueSources
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_ROWS,
    MAX_TOTAL_BYTES,
    RuntimeReadBudget,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import JournalReadSnapshot, ResolvedJournalRead
from packages.persistence.runtime_operating_evidence import RuntimeOperatingSourceContext
from packages.persistence.runtime_owner_dependencies import (
    SqlRuntimeOwnerDependencies,
    _identity_graph,
)
from packages.persistence.schema import phase2_account_leases

T = TypeVar("T")
R = TypeVar("R", bound=ContractRecord)


class _Objects:
    def __init__(
        self,
        owner: SqlHistoricalRuntimeDescriptors,
        admit: Callable[[tuple[ObjectRef, ...]], None] | None,
    ) -> None:
        self.owner, self.admit = owner, admit
        self.refs: dict[str, ObjectRef] = {}
        self.bytes = 0

    def retain(self, value: ObjectRef) -> None:
        old = self.refs.get(value.object_sha256)
        if old is not None:
            if old != value:
                raise ContinuousRuntimeSourceError(
                    "HISTORICAL_DESCRIPTOR_OBJECT_REFERENCE_CONFLICT"
                )
            return
        self.bytes += value.byte_count
        if self.bytes > MAX_TOTAL_BYTES or len(self.refs) >= MAX_ROWS:
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_OBJECT_CLOSURE_BOUND")
        if self.admit is not None:
            self.admit((value,))
        self.refs[value.object_sha256] = value

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

    def read(self, reference: ContinuousEvidenceRef, kind: type[R]) -> R:
        self.retain(reference.object_ref)
        raw = self.owner.artifacts.read(reference.object_ref, max_bytes=MAX_TOTAL_BYTES)
        value = self.owner.codec.decode_record(raw, kind)
        if (
            len(raw),
            sha256(raw).hexdigest(),
            value.semantic_sha256,
            self.owner.codec.encode_record(value),
        ) != (
            reference.object_ref.byte_count,
            reference.object_ref.object_sha256,
            reference.semantic_sha256,
            raw,
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_OBJECT_BINDING_DIFFERS")
        self.graph(value)
        return value


@dataclass(frozen=True, slots=True, weakref_slot=True)
class HistoricalRuntimeDescriptorPlan:
    descriptor: ContinuousRuntimeSourceDescriptor
    reference: ContinuousEvidenceRef
    request: ClosedEngineFrontier
    checkpoint: CausalEngineCheckpoint
    market: ResolvedContinuousForwardSources
    clock: ResolvedOriginalRuntimeClock
    quote_clock: ResolvedOriginalRuntimeClock
    reconciliation: ReconciliationCommitReceipt | None
    capture: RetainedVenueCapture | None
    reconciliation_checkpoint: CausalEngineCheckpoint | None
    object_refs: tuple[ObjectRef, ...]
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class HistoricalRuntimeDescriptorSnapshot:
    plan: HistoricalRuntimeDescriptorPlan
    canonical: tuple[ContinuousReferenceSnapshot, ...]
    descriptor: JournalReadSnapshot
    clock: JournalReadSnapshot
    quote_clock: JournalReadSnapshot
    markets: tuple[JournalReadSnapshot, ...]
    reconciliation: ReconciliationCommitSnapshot | None
    reconciliation_journal: JournalReadSnapshot | None
    venue: tuple[JournalReadSnapshot, ...]
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedHistoricalRuntimeDescriptor:
    snapshot: HistoricalRuntimeDescriptorSnapshot
    prefix: OriginalContinuousRuntimeAttemptPrefix
    canonical: tuple[ResolvedContinuousReference, ...]
    descriptor: ResolvedJournalRead
    reconciliation: ResolvedReconciliationSnapshot | None
    reconciliation_journal: ResolvedJournalRead | None
    venue: ResolvedContinuousVenueSources | None
    context: RuntimeRoleSourceContext
    seal: object = field(repr=False, compare=False)

    @property
    def receipt(self) -> JournalReceipt:
        assert self.descriptor.receipt is not None
        return self.descriptor.receipt


class SqlHistoricalRuntimeDescriptors:
    def __init__(self, producer: SqlContinuousRuntimeSources) -> None:
        if type(producer) is not SqlContinuousRuntimeSources:
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_EXACT_PRODUCER_REQUIRED")
        self.producer = producer
        self.accounts, self.daily = producer._stores()
        self.publisher = producer.publisher
        self.engine, self.artifacts, self.codec = (
            producer.engine,
            producer.artifacts,
            producer.codec,
        )
        self._bindings = (
            producer,
            self.accounts,
            self.daily,
            self.publisher,
            self.engine,
            self.artifacts,
            self.codec,
        )
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._original: dict[int, Any] = {}
        self._fingerprints: dict[int, str] = {}
        self._seal = object()
        self._dependencies = self._dependency_values()
        self._pins = _identity_graph(
            (producer.producer_map, producer.venue_model, producer.venue_reference)
        )

    def _dependency_values(self) -> tuple[object, ...]:
        producer, publisher = self.producer, self.publisher
        return (
            producer.journal,
            producer.operating,
            producer.operating.journal,
            producer.operating.clock_sampler,
            producer.forward_sources,
            producer.forward_sources.journal,
            producer.accounting,
            producer.strategy,
            producer.venue_model,
            producer.venue_reference,
            producer.producer_map,
            self.accounts.engine,
            self.accounts.coordinator,
            self.accounts.preparer,
            self.accounts.journal,
            self.daily.engine,
            self.daily.producers,
            self.daily.coordinator,
            *(
                (
                    publisher.account,
                    publisher.engine,
                    publisher.applied,
                    publisher.journal,
                    publisher.sources,
                    publisher.sources.journal,
                    publisher.accounting,
                    publisher.artifacts,
                    publisher.codec,
                )
                if publisher is not None
                else ()
            ),
        )

    def _bound(self) -> None:
        current = (
            self.producer,
            *self.producer._stores(),
            self.producer.publisher,
            self.producer.engine,
            self.producer.artifacts,
            self.producer.codec,
        )
        stored = (
            self.producer,
            self.accounts,
            self.daily,
            self.publisher,
            self.engine,
            self.artifacts,
            self.codec,
        )
        if any(old is not new for old, new in zip(self._bindings, current, strict=True)) or any(
            old is not new for old, new in zip(self._bindings, stored, strict=True)
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_BINDINGS_CHANGED")
        if any(
            old is not new
            for old, new in zip(self._dependencies, self._dependency_values(), strict=True)
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_DEPENDENCIES_CHANGED")
        for item, attributes in self._pins:
            if any(getattr(item, name) is not old for name, old in attributes):
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_PRODUCER_PINS_CHANGED")

    def _own(self, value: T) -> T:
        self._owned[id(value)] = value
        self._original[id(value)] = _identity_graph(value)
        finalize(value, self._original.pop, id(value), None)
        return value

    def _require(self, value: object, kind: type[Any]) -> None:
        self._bound()
        if type(value) is not kind or self._owned.get(id(value)) is not value:
            raise ContinuousRuntimeSourceError("OWNED_HISTORICAL_DESCRIPTOR_REQUIRED")
        for item, attributes in self._original[id(value)]:
            if any(
                getattr(value if item is None else item, name) is not old
                for name, old in attributes
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_HISTORICAL_DESCRIPTOR_FIELDS_CHANGED")

    @staticmethod
    def _plan_digest(plan: HistoricalRuntimeDescriptorPlan) -> str:
        return content_digest(
            (
                plan.descriptor,
                plan.reference,
                plan.request,
                plan.checkpoint,
                plan.market.closure,
                plan.market.state,
                plan.clock.reference,
                plan.clock.observation,
                plan.quote_clock.reference,
                plan.quote_clock.observation,
                plan.reconciliation,
                plan.capture,
                plan.reconciliation_checkpoint,
                plan.object_refs,
            )
        )

    def require_plan(self, plan: HistoricalRuntimeDescriptorPlan) -> None:
        self._require(plan, HistoricalRuntimeDescriptorPlan)
        if self._fingerprints[id(plan)] != self._plan_digest(plan):
            raise ContinuousRuntimeSourceError("ORIGINAL_HISTORICAL_DESCRIPTOR_PLAN_CHANGED")
        self.producer.forward_sources.require_resolved(plan.market)
        self.producer.require_original_clock(plan.clock)
        self.producer.require_original_clock(plan.quote_clock)

    def require_same_capture(
        self,
        original: HistoricalRuntimeDescriptorSnapshot,
        fresh: HistoricalRuntimeDescriptorSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare the complete original historical plan and captured footprint.

        Existing full semantic/source guards remain the later terminal authority.
        Here each opaque child is admitted by its original owner, then its full
        data projection is compared without codec, replay, hash or SQL work.
        """
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousRuntimeSourceError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            self._require(value, HistoricalRuntimeDescriptorSnapshot)
            self._require(value.plan, HistoricalRuntimeDescriptorPlan)
        left, right = original.plan, fresh.plan
        comparison.data(
            (
                left.descriptor,
                left.reference,
                left.request,
                left.checkpoint,
                left.reconciliation,
                left.capture,
                left.reconciliation_checkpoint,
                left.object_refs,
            ),
            (
                right.descriptor,
                right.reference,
                right.request,
                right.checkpoint,
                right.reconciliation,
                right.capture,
                right.reconciliation_checkpoint,
                right.object_refs,
            ),
        )
        forward = self.producer.forward_sources
        for market in (left.market, right.market):
            forward._require_owned(market)
        comparison.data(
            (left.market.closure, left.market.state), (right.market.closure, right.market.state)
        )
        for old_read, fresh_read in comparison.pairs(left.market.reads, right.market.reads):
            forward.journal.require_same_resolved_read(old_read, fresh_read, comparison=comparison)
        for market in (left.market, right.market):
            forward._require_owned(market)
        self.producer.require_same_original_clock(left.clock, right.clock, comparison=comparison)
        self.producer.require_same_original_clock(
            left.quote_clock, right.quote_clock, comparison=comparison
        )
        for old_reference, fresh_reference in comparison.pairs(original.canonical, fresh.canonical):
            self.accounts.require_same_reference_capture(
                old_reference, fresh_reference, comparison=comparison
            )
        self.producer.journal.require_same_capture(
            original.descriptor, fresh.descriptor, comparison=comparison
        )
        self.producer.operating.journal.require_same_capture(
            original.clock, fresh.clock, comparison=comparison
        )
        self.producer.operating.journal.require_same_capture(
            original.quote_clock, fresh.quote_clock, comparison=comparison
        )
        for old_market, fresh_market in comparison.pairs(original.markets, fresh.markets):
            forward.journal.require_same_capture(old_market, fresh_market, comparison=comparison)
        if original.reconciliation is None or fresh.reconciliation is None:
            comparison.identity(original.reconciliation, fresh.reconciliation)
        else:
            if (
                type(original.reconciliation) is not ReconciliationCommitSnapshot
                or type(fresh.reconciliation) is not ReconciliationCommitSnapshot
            ):
                raise ContinuousRuntimeSourceError("HISTORICAL_RECONCILIATION_CAPTURE_TYPE")
            comparison.data(
                (original.reconciliation.scope, original.reconciliation.row),
                (fresh.reconciliation.scope, fresh.reconciliation.row),
            )
        if original.reconciliation_journal is None or fresh.reconciliation_journal is None:
            comparison.identity(original.reconciliation_journal, fresh.reconciliation_journal)
        else:
            if self.publisher is None:
                raise ContinuousRuntimeSourceError("HISTORICAL_RECONCILIATION_OWNER_MISSING")
            self.publisher.journal.require_same_capture(
                original.reconciliation_journal,
                fresh.reconciliation_journal,
                comparison=comparison,
            )
        for old_venue, fresh_venue in comparison.pairs(original.venue, fresh.venue):
            if self.publisher is None:
                raise ContinuousRuntimeSourceError("HISTORICAL_RECONCILIATION_OWNER_MISSING")
            self.publisher.sources.journal.require_same_capture(
                old_venue, fresh_venue, comparison=comparison
            )
        for value in (original, fresh):
            self._require(value.plan, HistoricalRuntimeDescriptorPlan)
            self._require(value, HistoricalRuntimeDescriptorSnapshot)

    def prepare_historical_descriptor(
        self,
        reference: ContinuousEvidenceRef,
        *,
        admit_objects: Callable[[tuple[ObjectRef, ...]], None] | None = None,
    ) -> HistoricalRuntimeDescriptorPlan:
        self._bound()
        objects = _Objects(self, admit_objects)
        if (
            reference.schema_id != RUNTIME_SOURCE_SCHEMA
            or reference.object_ref.byte_count > MAX_RUNTIME_SOURCE_BYTES
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_SCHEMA_OR_BOUND")
        descriptor = objects.read(reference, ContinuousRuntimeSourceDescriptor)
        if descriptor.request_kind != "activation_dependencies" or descriptor.previous is None:
            raise ContinuousRuntimeSourceError("HISTORICAL_ACTIVATION_DESCRIPTOR_REQUIRED")
        request = objects.read(descriptor.request, ClosedEngineFrontier)
        checkpoint = objects.read(
            ContinuousEvidenceRef(
                "continuous-checkpoint/1",
                descriptor.previous.commit.transition.checkpoint,
                descriptor.previous.commit.transition.checkpoint_sha256,
            ),
            CausalEngineCheckpoint,
        )
        if descriptor.market_source.schema_id != CONTINUOUS_QUOTE_CLOSURE_SCHEMA:
            raise ContinuousRuntimeSourceError("HISTORICAL_ORIGINAL_QUOTE_SOURCE_REQUIRED")
        closure = objects.read(descriptor.market_source, ContinuousQuoteClosure)
        market = self.producer.forward_sources.resolve(closure)
        self.producer._require_market_producers(market)
        objects.graph(market.closure)
        roles: dict[str, tuple[ContinuousEvidenceRef, ...]] = {
            item.role: item.references for item in descriptor.role_references
        }
        if set(roles) != (
            {"clock", "quotes", "request_budget"}
            | ({"reconciliation"} if "reconciliation" in roles else set())
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ROLE_INVENTORY_DIFFERS")

        def selected(role: str, schema: str) -> ContinuousEvidenceRef:
            refs = roles[role]
            if len(refs) != 1 or refs[0].schema_id != schema:
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ROLE_REFERENCE_DIFFERS")
            return refs[0]

        model = objects.read(
            selected("request_budget", MODEL_REFERENCE_SCHEMA), VenueSourceReference
        )
        if (
            descriptor.producer_map != self.producer.producer_map
            or model != self.producer.venue_reference
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_MODEL_OR_PRODUCER_DIFFERS")
        clock_reference = objects.read(
            selected("clock", CLOCK_REFERENCE_SCHEMA), RuntimeClockReference
        )
        quote_reference = objects.read(
            selected("quotes", CLOCK_REFERENCE_SCHEMA), RuntimeClockReference
        )
        clock = self.producer.read_original_clock(clock_reference)
        quote_clock = (
            clock
            if quote_reference == clock_reference
            else self.producer.read_original_clock(quote_reference)
        )
        reconciliation = None
        capture = None
        reconciliation_checkpoint = None
        if "reconciliation" in roles:
            if self.publisher is None:
                raise ContinuousRuntimeSourceError(
                    "HISTORICAL_ACTUAL_RECONCILIATION_READER_REQUIRED"
                )
            reconciliation = objects.read(
                selected("reconciliation", RECONCILIATION_REFERENCE_SCHEMA),
                ReconciliationCommitReceipt,
            )
            binding = reconciliation.commit.capture_binding
            transition = reconciliation.commit.canonical_transition_ref
            if binding is None or transition is None:
                raise ContinuousRuntimeSourceError("HISTORICAL_ACTUAL_A_C_BINDING_REQUIRED")
            capture = objects.read(
                ContinuousEvidenceRef(
                    binding.capture.schema_id,
                    binding.capture.object_ref,
                    binding.capture.semantic_sha256,
                ),
                RetainedVenueCapture,
            )
            reconciliation_checkpoint = objects.read(
                ContinuousEvidenceRef(
                    "continuous-checkpoint/1",
                    transition.checkpoint,
                    transition.checkpoint_sha256,
                ),
                CausalEngineCheckpoint,
            )
        plan = self._own(
            HistoricalRuntimeDescriptorPlan(
                descriptor,
                reference,
                request,
                checkpoint,
                market,
                clock,
                quote_clock,
                reconciliation,
                capture,
                reconciliation_checkpoint,
                tuple(objects.refs[key] for key in sorted(objects.refs)),
                self._seal,
            )
        )
        self._fingerprints[id(plan)] = self._plan_digest(plan)
        finalize(plan, self._fingerprints.pop, id(plan), None)
        return plan

    def capture_historical_descriptor_in_transaction(
        self,
        connection: Connection,
        plan: HistoricalRuntimeDescriptorPlan,
        *,
        budget: RuntimeReadBudget,
    ) -> HistoricalRuntimeDescriptorSnapshot:
        self._require(plan, HistoricalRuntimeDescriptorPlan)
        if connection.engine is not self.engine or type(budget) is not RuntimeReadBudget:
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_SAME_ENGINE_BUDGET_REQUIRED")
        tables = []
        for table in (continuous_account_commits, phase2_account_leases):
            old = next(
                (
                    value
                    for value in budget.captured
                    if value.table is table and value.account_id == plan.descriptor.scope.account_id
                ),
                None,
            )
            tables.append(
                old
                or capture_runtime_table(
                    connection, table, account_id=plan.descriptor.scope.account_id, budget=budget
                )
            )
        pool = DetachedJournalCapture(
            max_bytes=MAX_TOTAL_BYTES - budget.payload_bytes,
            max_metadata_bytes=MAX_METADATA_BYTES - budget.metadata_bytes,
        )

        def charge(before: tuple[int, int, int]) -> None:
            budget.charge(
                len(pool.rows) - before[0],
                pool.byte_count - before[1],
                pool.metadata_bytes - before[2],
            )

        def read(journal: Any, key: Any, command_id: str | None) -> JournalReadSnapshot:
            before = len(pool.rows), pool.byte_count, pool.metadata_bytes
            result = pool.capture(
                journal.capture_in_transaction(connection, key, command_id=command_id)
            )
            charge(before)
            return result

        assert plan.descriptor.previous is not None
        command_id = plan.descriptor.previous.commit.transition.command_id
        originals: list[ContinuousReferenceSnapshot] = []
        while True:
            before = len(pool.rows), pool.byte_count, pool.metadata_bytes
            original = self.accounts.capture_reference_in_transaction(
                connection,
                scope=plan.descriptor.scope,
                command_id=command_id,
                source_lease_sha256=plan.descriptor.captured_fence.lease_sha256
                if not originals
                else None,
                journal_pool=pool,
            )
            charge(before)
            if (
                original is None
                or original.current.row not in tables[0].rows
                or original.lease not in tables[1].rows
            ):
                raise ContinuousRuntimeSourceError(
                    "HISTORICAL_DESCRIPTOR_ACTUAL_C_REFERENCE_MISSING"
                )
            if original.previous is not None and (
                original.previous.row not in tables[0].rows
                or original.previous_lease not in tables[1].rows
            ):
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ACTUAL_C_PARENT_MISSING")
            if original.source_lease is not None and original.source_lease not in tables[1].rows:
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_LEASE_MISSING")
            originals.append(original)
            if original.previous is None:
                break
            if len(originals) >= MAX_ROWS:
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ACTUAL_ANCESTRY_BOUND")
            command_id = original.previous.row["command_id"]
        descriptor = read(
            self.producer.journal,
            runtime_source_key(plan.descriptor.scope),
            plan.descriptor.descriptor_id,
        )
        clock = read(
            self.producer.operating.journal,
            plan.clock.reference.key,
            plan.clock.reference.receipt.command_id,
        )
        quote_clock = read(
            self.producer.operating.journal,
            plan.quote_clock.reference.key,
            plan.quote_clock.reference.receipt.command_id,
        )
        markets = tuple(
            read(
                self.producer.forward_sources.journal, value.snapshot.key, value.snapshot.command_id
            )
            for value in plan.market.reads
        )
        paired = None
        paired_journal = None
        venue: tuple[JournalReadSnapshot, ...] = ()
        if plan.reconciliation is not None:
            assert self.publisher is not None and plan.capture is not None
            paired = self.publisher.applied.capture_commit_in_transaction(
                connection,
                scope=plan.reconciliation.commit.scope,
                command_id=plan.reconciliation.commit.command_id,
            )
            if paired is None:
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ACTUAL_A_ROW_MISSING")
            budget.charge(
                1,
                sum(len(v) for v in paired.row.values() if type(v) is bytes),
                sum(
                    len(str(v).encode())
                    for v in paired.row.values()
                    if v is not None and type(v) is not bytes
                ),
            )
            paired_journal = read(
                self.publisher.journal,
                plan.reconciliation.journal_key,
                plan.reconciliation.commit.command_id,
            )
            venue = tuple(
                read(self.publisher.sources.journal, item.key, item.receipt.command_id)
                for item in plan.capture.manifest.sources
            )
        return self._own(
            HistoricalRuntimeDescriptorSnapshot(
                plan,
                tuple(originals),
                descriptor,
                clock,
                quote_clock,
                markets,
                paired,
                paired_journal,
                venue,
                self._seal,
            )
        )

    def resolve_historical_descriptor(
        self,
        raw: HistoricalRuntimeDescriptorSnapshot,
        *,
        prefix: OriginalContinuousRuntimeAttemptPrefix,
    ) -> ResolvedHistoricalRuntimeDescriptor:
        self._require(raw, HistoricalRuntimeDescriptorSnapshot)
        plan = raw.plan
        self.require_plan(plan)
        self.producer._attempt_reader().require_prefix(prefix)
        canonical = tuple(self.accounts.resolve_reference(item) for item in raw.canonical)
        original = canonical[0]
        desc, cp = plan.descriptor, plan.checkpoint
        if original.receipt != desc.previous or original.source_lease is None:
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ACTUAL_PREDECESSOR_DIFFERS")
        if any(child.previous_receipt != parent.receipt for child, parent in pairwise(canonical)):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_CANONICAL_LINEAGE_DIFFERS")
        SqlRuntimeOwnerDependencies.require_original_fence(
            desc.captured_fence, original.source_lease
        )
        if type(cp.inputs) is not ContinuousEngineInputs:
            raise ContinuousRuntimeSourceError(
                "HISTORICAL_DESCRIPTOR_ACTUAL_CONTINUOUS_CHECKPOINT_REQUIRED"
            )
        SqlRuntimeOwnerDependencies.require_engine_match(cp.inputs.spec, prefix.assignment)
        if (
            cp != prefix.checkpoint
            or prefix.through_coordinator_sequence != original.receipt.commit.sequence
            or prefix.source.account_id != desc.scope.account_id
            or prefix.source.checked_at != desc.original_checked_at
            or cp.semantic_sha256 != original.receipt.commit.transition.checkpoint_sha256
            or cp.inputs.spec.account_id != desc.scope.account_id
            or cp.inputs.spec.account_binding_sha256 != desc.scope.account_binding_sha256
            or cp.inputs.spec.deployment_id != desc.scope.stream_id
            or cp.now > desc.original_checked_at
            or prefix.assignment.semantic_sha256 != desc.assignment_sha256
            or (None if prefix.control is None else prefix.control.semantic_sha256)
            != desc.control_sha256
            or prefix.obligations.semantic_sha256 != desc.obligations_sha256
            or daily_attempt_inventory_sha256(prefix.attempts) != desc.attempts_sha256
            or tuple(item.commitment for item in prefix.obligations.bindings)
            != tuple(sorted(cp.state.commitments, key=lambda item: item.commitment_id))
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_PREFIX_DIFFERS")
        heads = ReconciliationHeads(
            cp.current.snapshot.journal_sha256,
            cp.current.snapshot.order_sha256,
            prefix.obligations.semantic_sha256,
            daily_runtime_effect_watermark(
                attempt_envelopes=prefix.attempt_envelopes, observed_groups=prefix.observed_groups
            ),
            daily_attempt_inventory_sha256(prefix.attempts),
            0 if prefix.control is None else prefix.control.sequence_number,
            desc.captured_fence.fence.fencing_generation,
        )
        old_heads = original.receipt.commit.transition.resulting_heads
        if (
            heads != prefix.source.heads
            or heads.capacity_sha256 != old_heads.capacity_sha256
            or heads.attempt_sha256 != old_heads.attempt_sha256
            or heads.effect_watermark != old_heads.effect_watermark
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_SEVEN_HEADS_DIFFER")
        quote = next(
            (
                item
                for item in canonical
                if item.receipt.commit.source_evidence.schema_id == CONTINUOUS_QUOTE_CLOSURE_SCHEMA
            ),
            None,
        )
        if (
            quote is None
            or quote.receipt.commit.source_evidence != desc.market_source
            or quote.receipt.commit.request != desc.request
            or quote.receipt.commit.transition.applied_at != plan.market.closure.admitted_at
        ):
            raise ContinuousRuntimeSourceError(
                "HISTORICAL_DESCRIPTOR_ORIGINAL_QUOTE_ANCESTOR_DIFFERS"
            )
        descriptor = self.producer.journal.resolve_snapshot(raw.descriptor)
        if (
            descriptor.receipt is None
            or descriptor.receipt.command_sha256 != desc.semantic_sha256
            or descriptor.receipt.command_id != desc.descriptor_id
            or descriptor.receipt.record_ids != (desc.semantic_sha256,)
            or raw.descriptor.requested_receipt is None
            or len(raw.descriptor.requested_receipt.entries) != 1
            or raw.descriptor.requested_receipt.entries[0]["payload_sha256"]
            != plan.reference.object_ref.object_sha256
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ACTUAL_JOURNAL_DIFFERS")
        for captured, original_clock in (
            (raw.clock, plan.clock),
            (raw.quote_clock, plan.quote_clock),
        ):
            if captured.requested_receipt != original_clock.read.snapshot.requested_receipt:
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_CLOCK_CHANGED")
        if any(
            actual.requested_receipt != expected.snapshot.requested_receipt
            for actual, expected in zip(raw.markets, plan.market.reads, strict=True)
        ):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_MARKET_CHANGED")
        paired, journal, venue = None, None, None
        reconciliation_sequence = 0
        if plan.reconciliation is not None:
            assert self.publisher is not None and plan.capture is not None
            assert plan.reconciliation_checkpoint is not None
            if raw.reconciliation is None or raw.reconciliation_journal is None:
                raise ContinuousRuntimeSourceError(
                    "HISTORICAL_DESCRIPTOR_ACTUAL_A_SNAPSHOT_MISSING"
                )
            paired = self.publisher.applied.resolve_snapshot(raw.reconciliation)
            anchor = next(
                (
                    item
                    for item in canonical
                    if item.receipt.commit.source_evidence.schema_id == VENUE_CAPTURE_CLOSURE_SCHEMA
                ),
                None,
            )
            binding = paired.receipt.commit.capture_binding
            if (
                anchor is None
                or anchor.receipt.commit.transition.command_id
                != plan.reconciliation.commit.command_id
                or paired.receipt != plan.reconciliation
                or binding is None
                or paired.receipt.commit.canonical_transition_ref
                != anchor.receipt.commit.transition
                or binding.capture
                != ReconciliationEvidenceRef(
                    anchor.receipt.commit.source_evidence.schema_id,
                    anchor.receipt.commit.source_evidence.object_ref,
                    anchor.receipt.commit.source_evidence.semantic_sha256,
                )
                or binding.source_closure_sha256
                != anchor.receipt.commit.transition.source_closure_sha256
                or plan.reconciliation_checkpoint.semantic_sha256
                != anchor.receipt.commit.transition.checkpoint_sha256
            ):
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ACTUAL_A_C_PAIR_DIFFERS")
            reconciliation_sequence = anchor.receipt.commit.sequence
            venue = self.publisher.sources.resolve(plan.capture)
            if (
                venue.capture.manifest != paired.resolved.sources
                or venue.pages[0].request.binding.model != self.producer.venue_model
                or any(
                    actual.requested_receipt != expected.snapshot.requested_receipt
                    for actual, expected in zip(raw.venue, venue.reads, strict=True)
                )
            ):
                raise ContinuousRuntimeSourceError(
                    "HISTORICAL_DESCRIPTOR_ORIGINAL_A_SOURCES_DIFFER"
                )
            validate_continuous_application_times(
                plan.reconciliation_checkpoint,
                capture=plan.capture,
                applications=paired.resolved.applications.applications,
                accounting=self.publisher.accounting,
            )
            journal = self.publisher.journal.resolve_snapshot(raw.reconciliation_journal)
            if journal.receipt != paired.receipt.journal:
                raise ContinuousRuntimeSourceError(
                    "HISTORICAL_DESCRIPTOR_ORIGINAL_A_JOURNAL_DIFFERS"
                )
        result = None if paired is None else paired.resolved.result
        reasons = original_reconciliation_reasons(
            result, heads=heads, checked_at=desc.original_checked_at
        )
        control = (
            None
            if prefix.control is None
            else MappingProxyType(
                {
                    "effective_state": prefix.control.effective_state.value,
                    "decided_at": prefix.control.decided_at.isoformat(),
                    "sequence_number": prefix.control.sequence_number,
                }
            )
        )
        context = RuntimeRoleSourceContext(
            desc,
            cp,
            original.receipt,
            RuntimeOperatingSourceContext(
                cp,
                original.receipt,
                plan.clock.reference,
                plan.clock.observation,
                desc.original_checked_at,
                prefix.attempts,
                self.producer.venue_model.account_id,
                self.producer.venue_reference,
            ),
            plan.market,
            control,
            result,
            reconciliation_sequence,
            reasons,
            None
            if reasons or venue is None
            else original_cash_restriction(venue.capture, self.producer.venue_model),
            plan.quote_clock.observation,
        )
        value = self._own(
            ResolvedHistoricalRuntimeDescriptor(
                raw,
                prefix,
                canonical,
                descriptor,
                paired,
                journal,
                venue,
                context,
                self._seal,
            )
        )
        self._fingerprints[id(value)] = self._resolved_digest(value)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    @staticmethod
    def _resolved_digest(value: ResolvedHistoricalRuntimeDescriptor) -> str:
        return content_digest(
            (
                value.snapshot.plan.descriptor,
                value.snapshot.plan.reference,
                tuple(item.receipt for item in value.canonical),
                value.prefix.source,
                value.context.control,
                value.context.reconciliation,
                value.context.reconciliation_reasons,
                value.context.cash_restrictions,
                detached_journal_value(value.descriptor),
                None
                if value.reconciliation is None
                else detached_journal_value(value.reconciliation),
                None
                if value.reconciliation_journal is None
                else detached_journal_value(value.reconciliation_journal),
                None
                if value.venue is None
                else (
                    value.venue.capture,
                    value.venue.pages,
                    detached_journal_value(value.venue.reads),
                ),
            )
        )

    def require_historical_descriptor(self, value: ResolvedHistoricalRuntimeDescriptor) -> None:
        self._require(value, ResolvedHistoricalRuntimeDescriptor)
        self.require_plan(value.snapshot.plan)
        self.producer._attempt_reader().require_prefix(value.prefix)
        for reference in value.canonical:
            self.accounts.require_reference(reference)
        if value.venue is not None:
            assert self.publisher is not None
            self.publisher.sources.require_resolved(value.venue)
        if self._fingerprints[id(value)] != self._resolved_digest(value):
            raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_CONTENT_CHANGED")

    def historical_evidence_port(
        self, value: ResolvedHistoricalRuntimeDescriptor
    ) -> ContinuousRuntimeEvidencePort:
        self.require_historical_descriptor(value)
        return ContinuousRuntimeEvidencePort(
            descriptor=value.snapshot.plan.descriptor,
            assignment=value.prefix.assignment,
            obligations=value.prefix.obligations,
            original_heads=value.prefix.source.heads,
            cash_restrictions=value.context.cash_restrictions,
            reconciliation=value.context.reconciliation,
            evaluator=_Evaluator(self, value),
        )

    def recheck_historical_descriptor_in_transaction(
        self,
        connection: Connection,
        value: ResolvedHistoricalRuntimeDescriptor,
    ) -> None:
        self._require(value, ResolvedHistoricalRuntimeDescriptor)
        self.producer._attempt_reader().recheck_prefix_in_transaction(connection, value.prefix)
        self.producer.journal.recheck_in_transaction(
            connection, value.descriptor, require_current_head=False
        )
        plan = value.snapshot.plan
        self.producer.recheck_original_clock_in_transaction(connection, plan.clock)
        self.producer.recheck_original_clock_in_transaction(connection, plan.quote_clock)
        self.producer.forward_sources.recheck_in_transaction(connection, plan.market)
        for reference in value.canonical:
            self.accounts.recheck_reference_in_transaction(connection, reference)
        if value.reconciliation is not None:
            assert (
                self.publisher is not None
                and value.reconciliation_journal is not None
                and value.venue is not None
            )
            commit = value.reconciliation.receipt.commit
            if (
                self.publisher.applied.capture_commit_in_transaction(
                    connection, scope=commit.scope, command_id=commit.command_id
                )
                != value.reconciliation.snapshot
            ):
                raise ContinuousRuntimeSourceError("HISTORICAL_DESCRIPTOR_ORIGINAL_A_ROW_CHANGED")
            self.publisher.journal.recheck_in_transaction(
                connection, value.reconciliation_journal, require_current_head=False
            )
            self.publisher.sources.recheck_in_transaction(connection, value.venue)


class _Evaluator:
    def __init__(
        self, owner: SqlHistoricalRuntimeDescriptors, value: ResolvedHistoricalRuntimeDescriptor
    ) -> None:
        self.owner, self.value = owner, value

    def evaluate(self, **kwargs: Any) -> Any:
        self.owner.require_historical_descriptor(self.value)
        return evaluate_original_runtime_roles(self.value.context, **kwargs)
