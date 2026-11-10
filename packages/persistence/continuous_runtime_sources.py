"""Retain original runtime dependencies and authenticate sole-engine risk rows.

Source preparation/decoding/replay is detached. Mutations use existing journals
and exact account/daily owners; metadata captures share the daily read budget.
This module does not authorize owner commands, dispatch or provider transport.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from decimal import Decimal
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Literal, TypeVar, cast
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.application.causal_engine import advance_continuous_engine
from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.application.continuous_runtime_evidence import (
    ContinuousRuntimeEvidencePort,
    RuntimeSourceCondition,
)
from packages.application.continuous_source_events import (
    compile_continuous_bootstrap,
    project_continuous_daily_frontier,
)
from packages.domain.account_coordinator import (
    ACCOUNT_COORDINATOR_CONTRACT_VERSION,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.accounting_contracts import AccountSnapshot, ExecutionAccountingPort
from packages.domain.canonical import canonical_json_bytes
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_composition_contracts import (
    FORWARD_CLOSURE_SCHEMA,
    SYNTHETIC_BOOTSTRAP_SCHEMA,
    SyntheticContinuousBootstrap,
)
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousAccountReceipt,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
)
from packages.domain.continuous_runtime_source_contracts import (
    MAX_RUNTIME_SOURCE_BYTES,
    RUNTIME_RECONCILIATION_PROFILE,
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeRoleReferences,
    ContinuousRuntimeSourceDescriptor,
    runtime_producer_map,
)
from packages.domain.daily_attempt_contracts import DailyFenceReference
from packages.domain.daily_observed_hold_contracts import daily_runtime_effect_watermark
from packages.domain.daily_runtime_contracts import (
    DailyRuntimeRiskEvidence,
    RuntimeObligationInventory,
    RuntimeProducerMap,
    RuntimeRiskAssignment,
    RuntimeRiskInputRefs,
    RuntimeRole,
)
from packages.domain.durable_journal_contracts import (
    JournalAppend,
    JournalKey,
    JournalReceipt,
    JournalRecord,
)
from packages.domain.engine_contracts import DailyIntentBatch, DailyPrice, DailyStrategy
from packages.domain.forward_contracts import CaptureReceipt, ForwardQuote
from packages.domain.operational_control import OperationalControlTransition
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import (
    ReconciliationHeads,
    ReconciliationPolicy,
    ReconciliationResult,
    ReconciliationScope,
)
from packages.domain.reconciliation_persistence_contracts import ReconciliationCommitReceipt
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.runtime_operating_contracts import (
    RuntimeClockObservation,
    RuntimeClockReference,
)
from packages.domain.stateful_venue_contracts import VenueModel, VenueSourceReference
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture
from packages.persistence.account_coordinator import SqlAccountCoordinator, account_lease_from_row
from packages.persistence.continuous_account import (
    PreparedContinuousCommit,
    ResolvedContinuousAccount,
    SqlContinuousAccount,
)
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.continuous_composition import (
    ContinuousProducerPlan,
    ContinuousProducerSnapshot,
    ResolvedContinuousProducerClosure,
)
from packages.persistence.continuous_forward_sources import (
    ResolvedContinuousForwardSources,
    SqlContinuousForwardSources,
)
from packages.persistence.continuous_reconciliation_publication import (
    ResolvedContinuousReconciliationPublication,
    SqlContinuousReconciliationPublication,
)
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_TOTAL_BYTES,
    PreparedDailyAdmission,
    PreparedDailyAssignment,
    ResolvedDailyRuntimeSnapshot,
    ResolvedRuntimeAttemptSources,
    ResolvedRuntimeObservedHoldSources,
    ResolvedRuntimeRiskInputs,
    RetainedDailyAdmission,
    RetainedDailyAssignmentPrefix,
    RuntimeAttemptSourcePlan,
    RuntimeAttemptSourceSnapshot,
    RuntimeObservedHoldSourcePlan,
    RuntimeObservedHoldSourceSnapshot,
    RuntimeProducerRawSnapshot,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    SqlDailyRuntimeRisk,
    VerifiedRuntimeAssignmentCommand,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import (
    JournalReadSnapshot,
    PreparedJournalAppend,
    ResolvedJournalRead,
    SqlDurableJournal,
)
from packages.persistence.immutable import as_aware_utc
from packages.persistence.runtime_operating_evidence import (
    ResolvedRuntimeOperatingEvidence,
    RuntimeOperatingPlan,
    RuntimeOperatingSnapshot,
    RuntimeOperatingSourceContext,
    SqlRuntimeOperatingEvidence,
    evaluate_original_operating_facts,
)
from packages.persistence.runtime_owner_dependencies import (
    SqlRuntimeOwnerDependencies,
    _identity_graph,
)
from packages.persistence.schema import (
    phase2_account_leases,
    phase5_operational_control_transitions,
)

if TYPE_CHECKING:
    from packages.persistence.continuous_account import ResolvedContinuousReference
    from packages.persistence.continuous_observed_hold_sources import (
        SqlContinuousObservedHoldSources,
    )
    from packages.persistence.continuous_runtime_attempt_sources import (
        OriginalContinuousRuntimeAttemptPrefix,
        ResolvedCommittedContinuousRuntimeAttemptSources,
        SqlContinuousRuntimeAttemptSources,
    )
    from packages.persistence.continuous_runtime_history import (
        HistoricalRuntimeDescriptorPlan,
        HistoricalRuntimeDescriptorSnapshot,
        ResolvedHistoricalRuntimeDescriptor,
        SqlHistoricalRuntimeDescriptors,
    )

CLOCK_REFERENCE_SCHEMA = "continuous-runtime-clock-reference/1"
MODEL_REFERENCE_SCHEMA = "continuous-runtime-venue-reference/1"
T = TypeVar("T")
RecordT = TypeVar("RecordT", bound=ContractRecord)
RECONCILIATION_REFERENCE_SCHEMA = "continuous-runtime-reconciliation-reference/1"


class ContinuousRuntimeSourceError(ValueError):
    """Static source identity, original-time or retained-record boundary failure."""


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedOriginalRuntimeClock:
    reference: RuntimeClockReference
    observation: RuntimeClockObservation
    read: ResolvedJournalRead
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedRuntimeDescriptor:
    descriptor: ContinuousRuntimeSourceDescriptor
    reference: ContinuousEvidenceRef
    append: PreparedJournalAppend
    previous: ResolvedContinuousAccount | None
    daily: ResolvedDailyRuntimeSnapshot
    request: ContinuousEngineInputs | ClosedEngineFrontier
    market: ResolvedContinuousForwardSources | None
    operating: RuntimeOperatingPlan | None
    reconciliation: ResolvedContinuousReconciliationPublication | None
    seal: object = field(repr=False, compare=False)
    quote_clock: ResolvedOriginalRuntimeClock | None = None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RuntimeDescriptorReadPlan:
    descriptor: ContinuousRuntimeSourceDescriptor
    reference: ContinuousEvidenceRef
    previous: ResolvedContinuousAccount | None
    daily: ResolvedDailyRuntimeSnapshot
    request: ContinuousEngineInputs | ClosedEngineFrontier
    market: ResolvedContinuousForwardSources | None
    operating: RuntimeOperatingPlan | None
    reconciliation: ResolvedContinuousReconciliationPublication | None
    seal: object = field(repr=False, compare=False)
    quote_clock: ResolvedOriginalRuntimeClock | None = None


@dataclass(frozen=True, slots=True)
class _Captured:
    plan: RuntimeDescriptorReadPlan
    tables: tuple[RuntimeTableSnapshot, ...]
    descriptor: JournalReadSnapshot
    markets: tuple[JournalReadSnapshot, ...]
    previous: JournalReadSnapshot | None
    operating: RuntimeOperatingSnapshot | None
    reconciliation: Mapping[str, Any] | None
    auxiliary: tuple[JournalReadSnapshot, ...]
    quote_clock: JournalReadSnapshot | None = None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedRuntimeDescriptor:
    snapshot: RuntimeProducerRawSnapshot
    plan: RuntimeDescriptorReadPlan
    descriptor: ResolvedJournalRead
    operating: ResolvedRuntimeOperatingEvidence | None
    lease: Mapping[str, Any]
    seal: object = field(repr=False, compare=False)


def runtime_source_key(scope: ContinuousAccountScope) -> JournalKey:
    return JournalKey(
        "coordinator",
        scope.stream_id,
        scope.account_id,
        RUNTIME_SOURCE_SCHEMA,
        "synthetic",
        scope.semantic_sha256,
    )


def _charge_journals(budget: RuntimeReadBudget, reads: tuple[JournalReadSnapshot, ...]) -> None:
    """Charge each physical auxiliary row once, including repeated head anchors."""
    unique: dict[tuple[object, ...], Mapping[str, Any]] = {}

    def add(kind: str, row: Mapping[str, Any] | None) -> None:
        if row is None:
            return
        identity = (
            kind,
            row.get("key_sha256"),
            row.get("sequence") if kind == "entry" else row.get("command_id"),
        )
        if identity in unique and unique[identity] != row:
            raise ContinuousRuntimeSourceError("RUNTIME_CAPTURE_AUXILIARY_ROW_CHANGED")
        unique[identity] = row

    for read in reads:
        add("stream", read.stream)
        add("entry", read.head_anchor)
        for receipt in (read.head_receipt, read.requested_receipt):
            if receipt is not None:
                add("append", receipt.append)
                add("entry", receipt.previous)
                for row in receipt.entries:
                    add("entry", row)
    payload = sum(
        len(value) for row in unique.values() for value in row.values() if type(value) is bytes
    )
    metadata = sum(
        len(str(value).encode("utf-8"))
        for row in unique.values()
        for value in row.values()
        if value is not None and type(value) is not bytes
    )
    budget.charge(len(unique), payload, metadata)


class SqlContinuousRuntimeSources:
    def __init__(
        self,
        engine: Engine,
        *,
        coordinator: SqlAccountCoordinator,
        journal: SqlDurableJournal,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        forward_sources: SqlContinuousForwardSources,
        operating: SqlRuntimeOperatingEvidence,
        accounting: ExecutionAccountingPort,
        strategy: DailyStrategy,
        venue_model: VenueModel,
        venue_reference: VenueSourceReference,
        producer_map: RuntimeProducerMap,
        benchmark_instrument_id: str | None,
        current_fence: Callable[[], AccountFence],
    ) -> None:
        if (
            type(coordinator) is not SqlAccountCoordinator
            or type(journal) is not SqlDurableJournal
            or type(forward_sources) is not SqlContinuousForwardSources
            or type(operating) is not SqlRuntimeOperatingEvidence
            or journal._engine is not engine
            or forward_sources.engine is not engine
            or operating.engine is not engine
            or venue_reference.semantic_sha256_ref != venue_model.semantic_sha256
            or venue_reference.producer != venue_model.producer
        ):
            raise ContinuousRuntimeSourceError("EXACT_RUNTIME_SOURCE_COMPOSITION_REQUIRED")
        self.engine, self.coordinator, self.journal = engine, coordinator, journal
        self.artifacts, self.codec, self.forward_sources, self.operating = (
            artifacts,
            codec,
            forward_sources,
            operating,
        )
        self.accounting, self.strategy = accounting, strategy
        declared = {item.role: item for item in producer_map.producers}
        if producer_map != runtime_producer_map(
            account_id=declared["account"].account_scope,
            venue_model=venue_model,
            daily=declared["daily_inputs"],
            quotes=declared["quotes"],
        ):
            raise ContinuousRuntimeSourceError("RUNTIME_FIXED_PRODUCER_PROFILE_DIFFERS")
        self.producer_map = producer_map
        self.current_fence = current_fence
        self.publisher: SqlContinuousReconciliationPublication | None = None
        self.owner_dependencies: SqlRuntimeOwnerDependencies | None = None
        self.attempt_sources: SqlContinuousRuntimeAttemptSources | None = None
        self._attempt_sources_binding: tuple[object, ...] | None = None
        self.observed_hold_sources: SqlContinuousObservedHoldSources | None = None
        self._observed_sources_binding: tuple[object, ...] | None = None
        self._observed_sources_pins: Any = None
        self._historical_descriptors: SqlHistoricalRuntimeDescriptors | None = None
        self._historical_owner: object | None = None
        self.venue_model, self.venue_reference, self.benchmark_instrument_id = (
            venue_model,
            venue_reference,
            benchmark_instrument_id,
        )
        self.accounts: SqlContinuousAccount | None = None
        self.daily: SqlDailyRuntimeRisk | None = None
        self._seal = object()
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._identity: dict[int, tuple[object, ...]] = {}
        self._fingerprints: dict[int, str] = {}
        self._protected: dict[int, tuple[tuple[ContractRecord, tuple[object, ...]], ...]] = {}
        self._raw: dict[int, _Captured] = {}
        self._clock_original: dict[int, Any] = {}
        self._active: WeakValueDictionary[str, ResolvedRuntimeDescriptor] = WeakValueDictionary()
        self._resolved_by_raw: dict[
            int,
            tuple[ResolvedJournalRead, ResolvedRuntimeOperatingEvidence | None, Mapping[str, Any]],
        ] = {}
        if (
            self._read(
                ContinuousEvidenceRef(
                    "venue-model/1", venue_reference.object_ref, venue_model.semantic_sha256
                ),
                VenueModel,
                MAX_RUNTIME_SOURCE_BYTES,
            )
            != venue_model
        ):
            raise ContinuousRuntimeSourceError("EXACT_RETAINED_VENUE_MODEL_REQUIRED")

    def bind_stores(self, *, accounts: SqlContinuousAccount, daily: SqlDailyRuntimeRisk) -> None:
        if (
            type(accounts) is not SqlContinuousAccount
            or type(daily) is not SqlDailyRuntimeRisk
            or accounts.engine is not self.engine
            or daily.engine is not self.engine
            or accounts.coordinator is not self.coordinator
            or daily.coordinator is not self.coordinator
            or daily.producers is not self
            or (self.accounts is not None and self.accounts is not accounts)
            or (self.daily is not None and self.daily is not daily)
        ):
            raise ContinuousRuntimeSourceError("EXACT_RUNTIME_STORE_BINDING_REQUIRED")
        self.accounts, self.daily = accounts, daily

    def bind_reconciliation(self, publisher: SqlContinuousReconciliationPublication) -> None:
        accounts, _ = self._stores()
        if (
            type(publisher) is not SqlContinuousReconciliationPublication
            or publisher.engine is not self.engine
            or publisher.account is not accounts
            or publisher.coordinator is not self.coordinator
            or (self.publisher is not None and self.publisher is not publisher)
        ):
            raise ContinuousRuntimeSourceError("EXACT_RECONCILIATION_BINDING_REQUIRED")
        self.publisher = publisher

    def bind_owner_dependencies(self, reader: SqlRuntimeOwnerDependencies) -> None:
        accounts, daily = self._stores()
        if (
            type(reader) is not SqlRuntimeOwnerDependencies
            or reader.engine is not self.engine
            or reader.accounts is not accounts
            or reader.daily is not daily
            or reader.publisher is not self.publisher
            or reader.producer is not self
            or (self.owner_dependencies is not None and self.owner_dependencies is not reader)
        ):
            raise ContinuousRuntimeSourceError("EXACT_OWNER_DEPENDENCY_BINDING_REQUIRED")
        self.owner_dependencies = reader

    def bind_attempt_sources(self, reader: SqlContinuousRuntimeAttemptSources) -> None:
        from packages.persistence.continuous_runtime_attempt_sources import (
            SqlContinuousRuntimeAttemptSources,
        )

        accounts, daily = self._stores()
        if (
            type(reader) is not SqlContinuousRuntimeAttemptSources
            or reader.engine is not self.engine
            or reader.accounts is not accounts
            or reader.preparer is not accounts.preparer
            or reader.daily is not daily
            or reader.runtime_sources is not self
            or reader.artifacts is not self.artifacts
            or reader.codec is not self.codec
            or (self.attempt_sources is not None and self.attempt_sources is not reader)
        ):
            raise ContinuousRuntimeSourceError("EXACT_ATTEMPT_SOURCE_BINDING_REQUIRED")
        current = (
            reader,
            self.engine,
            accounts,
            accounts.preparer,
            daily,
            self,
            self.artifacts,
            self.codec,
        )
        if self._attempt_sources_binding is not None and any(
            old is not new for old, new in zip(self._attempt_sources_binding, current, strict=True)
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_ATTEMPT_SOURCE_BINDING_CHANGED")
        self.attempt_sources = reader
        self._attempt_sources_binding = current

    def _attempt_reader(self) -> SqlContinuousRuntimeAttemptSources:
        reader = self.attempt_sources
        if reader is None or self._attempt_sources_binding is None:
            raise ContinuousRuntimeSourceError("BOUND_ATTEMPT_SOURCE_READER_REQUIRED")
        self.bind_attempt_sources(reader)
        return reader

    def prepare_attempt_source_read(
        self, references: tuple[ContinuousEvidenceRef, ...]
    ) -> RuntimeAttemptSourcePlan:
        return self._attempt_reader().prepare_attempt_source_read(references)

    def capture_attempt_sources_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeAttemptSourcePlan,
        *,
        account_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeAttemptSourceSnapshot:
        return self._attempt_reader().capture_attempt_sources_in_transaction(
            connection, plan, account_id=account_id, budget=budget
        )

    def resolve_attempt_sources(
        self,
        snapshot: RuntimeAttemptSourceSnapshot,
        *,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> ResolvedRuntimeAttemptSources:
        return self._attempt_reader().resolve_attempt_sources(snapshot, admissions=admissions)

    def recheck_attempt_sources_in_transaction(
        self, connection: Connection, resolved: ResolvedRuntimeAttemptSources
    ) -> None:
        self._attempt_reader().recheck_attempt_sources_in_transaction(connection, resolved)

    def recheck_attempt_sources_after_publication_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeAttemptSources,
        *,
        prepared_account: object,
        account_receipt: object,
    ) -> None:
        self._attempt_reader().recheck_attempt_sources_after_publication_in_transaction(
            connection, resolved, prepared_account=prepared_account, account_receipt=account_receipt
        )

    def resolve_committed_attempt_sources(
        self,
        original: ResolvedRuntimeAttemptSources,
        *,
        publication: ResolvedContinuousReference,
    ) -> ResolvedCommittedContinuousRuntimeAttemptSources:
        return self._attempt_reader().resolve_committed_attempt_sources(
            original, publication=publication
        )

    def require_committed_attempt_sources(
        self, value: ResolvedCommittedContinuousRuntimeAttemptSources
    ) -> None:
        self._attempt_reader().require_committed_attempt_sources(value)

    def recheck_committed_attempt_sources_in_transaction(
        self, connection: Connection, value: ResolvedCommittedContinuousRuntimeAttemptSources
    ) -> None:
        self._attempt_reader().recheck_committed_attempt_sources_in_transaction(connection, value)

    def bind_observed_hold_sources(self, reader: SqlContinuousObservedHoldSources) -> None:
        from packages.persistence.continuous_observed_hold_sources import (
            SqlContinuousObservedHoldSources,
        )

        accounts, daily = self._stores()
        publisher = self.publisher
        if (
            type(reader) is not SqlContinuousObservedHoldSources
            or publisher is None
            or reader.engine is not self.engine
            or reader.accounts is not accounts
            or reader.preparer is not accounts.preparer
            or reader.daily is not daily
            or reader.venue_sources is not publisher.sources
            or reader.venue_sources.model is not self.venue_model
            or reader.artifacts is not self.artifacts
            or reader.codec is not self.codec
            or reader.venue_sources.engine is not self.engine
            or reader.venue_sources.artifacts is not self.artifacts
            or reader.venue_sources.codec is not self.codec
            or (self.observed_hold_sources is not None and self.observed_hold_sources is not reader)
        ):
            raise ContinuousRuntimeSourceError("EXACT_OBSERVED_SOURCE_BINDING_REQUIRED")
        current = (
            reader,
            self.engine,
            accounts,
            accounts.preparer,
            daily,
            self,
            publisher,
            publisher.sources,
            reader.venue_sources.journal,
            reader.venue_sources.resolver,
            self.venue_model,
            self.artifacts,
            self.codec,
        )
        if self._observed_sources_binding is not None and any(
            old is not new for old, new in zip(self._observed_sources_binding, current, strict=True)
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_OBSERVED_SOURCE_BINDING_CHANGED")
        if self._observed_sources_pins is None:
            self._observed_sources_pins = _identity_graph(
                (reader.venue_sources.model, reader.venue_sources.scope)
            )
        for item, attributes in self._observed_sources_pins:
            if any(getattr(item, name) is not old for name, old in attributes):
                raise ContinuousRuntimeSourceError("ORIGINAL_OBSERVED_SOURCE_PINS_CHANGED")
        self.observed_hold_sources = reader
        self._observed_sources_binding = current

    def _observed_reader(self) -> SqlContinuousObservedHoldSources:
        reader = self.observed_hold_sources
        if reader is None or self._observed_sources_binding is None:
            raise ContinuousRuntimeSourceError("BOUND_OBSERVED_SOURCE_READER_REQUIRED")
        self.bind_observed_hold_sources(reader)
        return reader

    def prepare_observed_hold_source_read(
        self, references: tuple[ContinuousEvidenceRef, ...]
    ) -> RuntimeObservedHoldSourcePlan:
        return self._observed_reader().prepare_observed_hold_source_read(references)

    def capture_observed_hold_sources_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeObservedHoldSourcePlan,
        *,
        account_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeObservedHoldSourceSnapshot:
        return self._observed_reader().capture_observed_hold_sources_in_transaction(
            connection, plan, account_id=account_id, budget=budget
        )

    def resolve_observed_hold_sources(
        self,
        snapshot: RuntimeObservedHoldSourceSnapshot,
        *,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> ResolvedRuntimeObservedHoldSources:
        return self._observed_reader().resolve_observed_hold_sources(
            snapshot, admissions=admissions
        )

    def require_same_observed_capture(
        self,
        original: ResolvedRuntimeObservedHoldSources,
        fresh: RuntimeObservedHoldSourceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousRuntimeSourceError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        self._observed_reader().require_same_capture(original, fresh, comparison=comparison)

    def require_same_attempt_capture(
        self,
        original: ResolvedRuntimeAttemptSources,
        fresh: RuntimeAttemptSourceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousRuntimeSourceError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        self._attempt_reader().require_same_capture(original, fresh, comparison=comparison)

    def recheck_observed_hold_sources_in_transaction(
        self, connection: Connection, resolved: ResolvedRuntimeObservedHoldSources
    ) -> None:
        self._observed_reader().recheck_observed_hold_sources_in_transaction(connection, resolved)

    def recheck_observed_hold_sources_after_publication_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeObservedHoldSources,
        *,
        prepared_account: object,
        account_receipt: object,
    ) -> None:
        self._observed_reader().recheck_observed_hold_sources_after_publication_in_transaction(
            connection, resolved, prepared_account=prepared_account, account_receipt=account_receipt
        )

    def _history_reader(self) -> SqlHistoricalRuntimeDescriptors:
        from packages.persistence.continuous_runtime_history import SqlHistoricalRuntimeDescriptors

        if self._historical_descriptors is None:
            if self._historical_owner is not None:
                raise ContinuousRuntimeSourceError("ORIGINAL_HISTORICAL_READER_REPLACED")
            self._historical_descriptors = SqlHistoricalRuntimeDescriptors(self)
            self._historical_owner = self._historical_descriptors
        reader = self._historical_descriptors
        if (
            type(reader) is not SqlHistoricalRuntimeDescriptors
            or reader is not self._historical_owner
            or reader.producer is not self
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_HISTORICAL_READER_REPLACED")
        reader._bound()
        return reader

    def prepare_historical_descriptor(
        self,
        reference: ContinuousEvidenceRef,
        *,
        admit_objects: Callable[[tuple[ObjectRef, ...]], None] | None = None,
    ) -> HistoricalRuntimeDescriptorPlan:
        return self._history_reader().prepare_historical_descriptor(
            reference, admit_objects=admit_objects
        )

    def capture_historical_descriptor_in_transaction(
        self,
        connection: Connection,
        plan: HistoricalRuntimeDescriptorPlan,
        *,
        budget: RuntimeReadBudget,
    ) -> HistoricalRuntimeDescriptorSnapshot:
        return self._history_reader().capture_historical_descriptor_in_transaction(
            connection, plan, budget=budget
        )

    def resolve_historical_descriptor(
        self,
        raw: HistoricalRuntimeDescriptorSnapshot,
        *,
        prefix: OriginalContinuousRuntimeAttemptPrefix,
    ) -> ResolvedHistoricalRuntimeDescriptor:
        return self._history_reader().resolve_historical_descriptor(raw, prefix=prefix)

    def require_same_historical_capture(
        self,
        original: HistoricalRuntimeDescriptorSnapshot,
        fresh: HistoricalRuntimeDescriptorSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousRuntimeSourceError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        self._history_reader().require_same_capture(original, fresh, comparison=comparison)

    def require_historical_descriptor(self, value: ResolvedHistoricalRuntimeDescriptor) -> None:
        self._history_reader().require_historical_descriptor(value)

    def historical_evidence_port(
        self, value: ResolvedHistoricalRuntimeDescriptor
    ) -> ContinuousRuntimeEvidencePort:
        return self._history_reader().historical_evidence_port(value)

    def recheck_historical_descriptor_in_transaction(
        self,
        connection: Connection,
        value: ResolvedHistoricalRuntimeDescriptor,
    ) -> None:
        self._history_reader().recheck_historical_descriptor_in_transaction(connection, value)

    def read_original_clock(
        self, reference: RuntimeClockReference, *, budget: RuntimeReadBudget | None = None
    ) -> ResolvedOriginalRuntimeClock:
        if (
            type(reference) is not RuntimeClockReference
            or reference.key != self.operating.clock_key()
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_CLOCK_SCOPE_DIFFERS")
        reference.__post_init__()
        observation = self._read(
            reference.record, RuntimeClockObservation, MAX_RUNTIME_SOURCE_BYTES
        )
        if (
            observation.scope != self.operating.clock_sampler.scope
            or observation.profile != self.operating.clock_sampler.profile
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_CLOCK_PROFILE_DIFFERS")
        shared = budget if budget is not None else RuntimeReadBudget()
        pool = DetachedJournalCapture(
            max_bytes=MAX_TOTAL_BYTES - shared.payload_bytes,
            max_metadata_bytes=MAX_METADATA_BYTES - shared.metadata_bytes,
        )
        with _repeatable_read_transaction(self.engine) as connection:
            raw = pool.capture(
                self.operating.journal.capture_in_transaction(
                    connection, reference.key, command_id=reference.receipt.command_id
                )
            )
            shared.charge(len(pool.rows), pool.byte_count, pool.metadata_bytes)
        read = self.operating.journal.resolve_snapshot(raw)
        if (
            read.receipt != reference.receipt
            or raw.requested_receipt is None
            or not any(
                row["payload_sha256"] == reference.record.object_ref.object_sha256
                for row in raw.requested_receipt.entries
            )
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_CLOCK_JOURNAL_DIFFERS")
        value = self._own(ResolvedOriginalRuntimeClock(reference, observation, read, self._seal))
        self._clock_original[id(value)] = _identity_graph(value)
        self._fingerprints[id(value)] = content_digest(
            (reference, observation, detached_journal_value(read))
        )
        finalize(value, self._clock_original.pop, id(value), None)
        finalize(value, self._fingerprints.pop, id(value), None)
        return value

    def require_original_clock(
        self, value: ResolvedOriginalRuntimeClock, *, deep: bool = True
    ) -> None:
        self._require(value, ResolvedOriginalRuntimeClock)
        for item, attributes in self._clock_original[id(value)]:
            if any(
                getattr(value if item is None else item, name) is not old
                for name, old in attributes
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_CLOCK_FIELDS_CHANGED")
        if deep and self._fingerprints[id(value)] != content_digest(
            (value.reference, value.observation, detached_journal_value(value.read))
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_CLOCK_CONTENT_CHANGED")

    def require_same_original_clock(
        self,
        original: ResolvedOriginalRuntimeClock,
        fresh: ResolvedOriginalRuntimeClock,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousRuntimeSourceError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            self.require_original_clock(value, deep=False)
        comparison.data(
            (original.reference, original.observation), (fresh.reference, fresh.observation)
        )
        self.operating.journal.require_same_resolved_read(
            original.read, fresh.read, comparison=comparison
        )
        for value in (original, fresh):
            self.require_original_clock(value, deep=False)

    def recheck_original_clock_in_transaction(
        self, connection: Connection, value: ResolvedOriginalRuntimeClock
    ) -> None:
        self.require_original_clock(value, deep=False)
        self.operating.journal.recheck_in_transaction(
            connection, value.read, require_current_head=False
        )

    def _paired(
        self, previous: ResolvedContinuousAccount | None
    ) -> ResolvedContinuousReconciliationPublication | None:
        if previous is None or self.publisher is None:
            return None
        ancestor = self._stores()[0].nearest_source_ancestor(
            previous, schema_id="continuous-venue-capture/1"
        )
        if ancestor is None:
            return None
        scope = ancestor.receipt.commit.scope
        return self.publisher.resolve_for_account(
            ancestor,
            scope=ReconciliationScope(
                scope.account_id,
                self.venue_model.venue_id,
                "stateful_simulation",
                scope.account_binding_sha256,
                "stateful_simulation",
            ),
        )

    def _original_prefix(self, plan: RuntimeDescriptorReadPlan) -> RetainedDailyAssignmentPrefix:
        if plan.previous is None:
            raise ContinuousRuntimeSourceError("INITIALIZED_ORIGINAL_HEADS_REQUIRED")
        self._stores()[0].require_resolved(plan.previous)
        selected = [
            item
            for item in plan.daily.assignment_rows
            if item.semantic_sha256 == plan.descriptor.assignment_sha256
        ]
        if len(selected) != 1:
            raise ContinuousRuntimeSourceError("ORIGINAL_ASSIGNMENT_PREFIX_MISSING")
        prefix = self._stores()[1].inspect_assignment_prefix(
            plan.daily,
            assignment_generation=selected[0].generation,
            through_coordinator_sequence=plan.previous.receipt.commit.sequence,
            commitment_ids=tuple(
                sorted(item.commitment_id for item in plan.previous.checkpoint.state.commitments)
            ),
        )
        if tuple(item.commitment for item in prefix.obligations.bindings) != tuple(
            sorted(plan.previous.checkpoint.state.commitments, key=lambda item: item.commitment_id)
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_CANONICAL_HOLD_BINDING_DIFFERS")
        return prefix

    def _inventory(self, plan: RuntimeDescriptorReadPlan) -> RuntimeObligationInventory:
        if plan.previous is None:
            return plan.daily.obligations
        result = self._original_prefix(plan).obligations
        if (
            result.semantic_sha256 != plan.descriptor.obligations_sha256
            or result.semantic_sha256
            != plan.previous.receipt.commit.transition.resulting_heads.capacity_sha256
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_COMPLETE_HOLD_PREFIX_DIFFERS")
        return result

    def _original_heads(self, plan: RuntimeDescriptorReadPlan) -> ReconciliationHeads:
        if plan.previous is None:
            raise ContinuousRuntimeSourceError("INITIALIZED_ORIGINAL_HEADS_REQUIRED")
        prefix = self._original_prefix(plan)
        control = self._control(plan)
        attempts = daily_attempt_inventory_sha256(prefix.attempts)
        effect = daily_runtime_effect_watermark(
            attempt_envelopes=prefix.attempt_envelopes, observed_groups=prefix.observed_groups
        )
        original = plan.previous.receipt.commit.transition.resulting_heads
        if (prefix.obligations.semantic_sha256, attempts, effect) != (
            plan.descriptor.obligations_sha256,
            plan.descriptor.attempts_sha256,
            original.effect_watermark,
        ) or attempts != original.attempt_sha256:
            raise ContinuousRuntimeSourceError("ORIGINAL_COMPLETE_RUNTIME_PREFIX_DIFFERS")
        return ReconciliationHeads(
            plan.previous.checkpoint.current.snapshot.journal_sha256,
            plan.previous.checkpoint.current.snapshot.order_sha256,
            prefix.obligations.semantic_sha256,
            effect,
            attempts,
            0 if control is None else control["sequence_number"],
            plan.descriptor.captured_fence.fence.fencing_generation,
        )

    def _reconciliation_reasons(self, plan: RuntimeDescriptorReadPlan) -> tuple[str, ...]:
        return original_reconciliation_reasons(
            None
            if plan.reconciliation is None
            else plan.reconciliation.reconciliation.resolved.result,
            heads=None if plan.previous is None else self._original_heads(plan),
            checked_at=plan.descriptor.original_checked_at,
        )

    def _cash_restrictions(self, plan: RuntimeDescriptorReadPlan) -> Decimal | None:
        paired = plan.reconciliation
        if paired is None or self._reconciliation_reasons(plan):
            return None
        assert self.publisher is not None
        self.publisher.require_resolved(paired)
        if paired.sources.pages[0].request.binding.model != self.venue_model:
            raise ContinuousRuntimeSourceError("ORIGINAL_INDEPENDENT_CASH_MODEL_DIFFERS")
        return original_cash_restriction(paired.sources.capture, self.venue_model)

    def _stores(self) -> tuple[SqlContinuousAccount, SqlDailyRuntimeRisk]:
        if self.accounts is None or self.daily is None:
            raise ContinuousRuntimeSourceError("RUNTIME_STORES_NOT_BOUND")
        return self.accounts, self.daily

    def _own(self, value: T) -> T:
        self._owned[id(value)] = value
        self._identity[id(value)] = tuple(getattr(value, f.name) for f in fields(value))  # type: ignore[arg-type]
        records: dict[int, tuple[ContractRecord, tuple[object, ...]]] = {}

        def protect(item: object) -> None:
            if isinstance(item, ContractRecord) and id(item) not in records:
                attributes = tuple(getattr(item, f.name) for f in fields(cast(Any, item)))
                records[id(item)] = (item, attributes)
                for attribute in attributes:
                    protect(attribute)
            elif type(item) is tuple:
                for child in item:
                    protect(child)

        if isinstance(value, (PreparedRuntimeDescriptor, RuntimeDescriptorReadPlan)):
            protect(value.descriptor)
            protect(value.reference)
        self._protected[id(value)] = tuple(records.values())
        finalize(value, self._identity.pop, id(value), None)
        finalize(value, self._protected.pop, id(value), None)
        return value

    def _require(self, value: object, expected: type[Any]) -> None:
        if (
            type(value) is not expected
            or self._owned.get(id(value)) is not value
            or any(
                getattr(value, f.name) is not original
                for f, original in zip(
                    fields(cast(Any, value)), self._identity.get(id(value), ()), strict=True
                )
            )
        ):
            raise ContinuousRuntimeSourceError("OWNED_RUNTIME_SOURCE_REQUIRED")
        for record, attributes in self._protected.get(id(value), ()):
            if any(
                getattr(record, f.name) is not original
                for f, original in zip(fields(cast(Any, record)), attributes, strict=True)
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_DESCRIPTOR_MUTATED")

    def _read(
        self,
        reference: ContinuousEvidenceRef,
        expected: type[RecordT],
        limit: int = MAX_CONTINUOUS_OBJECT_BYTES,
    ) -> RecordT:
        if reference.object_ref.byte_count > limit:
            raise ContinuousRuntimeSourceError("RUNTIME_SOURCE_OBJECT_BOUND")
        payload = self.artifacts.read(reference.object_ref, max_bytes=limit)
        result = self.codec.decode_record(payload, expected)
        if (
            len(payload) != reference.object_ref.byte_count
            or sha256(payload).hexdigest() != reference.object_ref.object_sha256
            or self.codec.encode_record(result) != payload
            or result.semantic_sha256 != reference.semantic_sha256
        ):
            raise ContinuousRuntimeSourceError("RUNTIME_SOURCE_OBJECT_BINDING_DIFFERS")
        return result

    def _put(
        self, value: ContractRecord, schema: str, limit: int = MAX_CONTINUOUS_OBJECT_BYTES
    ) -> ContinuousEvidenceRef:
        payload = self.codec.encode_record(value)
        if not 0 < len(payload) <= limit:
            raise ContinuousRuntimeSourceError("RUNTIME_SOURCE_OBJECT_BOUND")
        return ContinuousEvidenceRef(
            schema, self.artifacts.put(payload, max_bytes=limit), value.semantic_sha256
        )

    def _current(self, fence: AccountFence) -> ResolvedDailyRuntimeSnapshot:
        _, daily = self._stores()
        return daily.resolve_snapshot(daily.read_snapshot(account_id=fence.account_id, fence=fence))

    def _normalize(
        self,
        reference: ContinuousEvidenceRef,
        request: ContinuousEngineInputs | ClosedEngineFrontier,
        previous: ResolvedContinuousAccount | None,
        kind: str,
    ) -> ResolvedContinuousForwardSources | None:
        if reference.schema_id == SYNTHETIC_BOOTSTRAP_SCHEMA:
            value = self._read(reference, SyntheticContinuousBootstrap)
            if previous is not None or request != value.inputs or kind != "initialize":
                raise ContinuousRuntimeSourceError("SYNTHETIC_RUNTIME_BOOTSTRAP_DIFFERS")
            return None
        if reference.schema_id == FORWARD_CLOSURE_SCHEMA:
            closure: ContinuousForwardClosure | ContinuousQuoteClosure = self._read(
                reference, ContinuousForwardClosure
            )
        elif reference.schema_id == CONTINUOUS_QUOTE_CLOSURE_SCHEMA:
            closure = self._read(reference, ContinuousQuoteClosure)
        else:
            raise ContinuousRuntimeSourceError("RUNTIME_MARKET_SOURCE_SCHEMA_UNSUPPORTED")
        expected: ContinuousEngineInputs | ClosedEngineFrontier
        resolved = self.forward_sources.resolve(closure)
        self.forward_sources.require_resolved(resolved)
        self._require_market_producers(resolved)
        if type(request) is ContinuousEngineInputs:
            if type(closure) is not ContinuousForwardClosure or previous is not None:
                raise ContinuousRuntimeSourceError("RUNTIME_BOOTSTRAP_SOURCE_DIFFERS")
            expected = compile_continuous_bootstrap(
                request.spec,
                resolved.state,
                closure.observation_ids,
                closure.admitted_at,
                benchmark_instrument_id=self.benchmark_instrument_id,
                capture_evidence_class=closure.evidence_class,
            )
        else:
            if previous is None:
                raise ContinuousRuntimeSourceError("RUNTIME_AUTHENTICATED_PREVIOUS_REQUIRED")
            if kind == "activation_dependencies":
                ancestor = self._stores()[0].nearest_source_ancestor(
                    previous, schema_id=CONTINUOUS_QUOTE_CLOSURE_SCHEMA
                )
                if (
                    type(closure) is not ContinuousQuoteClosure
                    or ancestor is None
                    or request != ancestor.request
                    or reference != ancestor.receipt.commit.source_evidence
                    or closure.admitted_at != ancestor.checkpoint.now
                ):
                    raise ContinuousRuntimeSourceError("RUNTIME_ORIGINAL_QUOTE_PREFIX_REQUIRED")
                return resolved
            expected = (
                project_continuous_quote_frontier(
                    checkpoint=previous.checkpoint, closure=closure, source_state=resolved.state
                )
                if type(closure) is ContinuousQuoteClosure
                else project_continuous_daily_frontier(
                    checkpoint=previous.checkpoint,
                    source_state=resolved.state,
                    observation_ids=closure.observation_ids,
                    frontier_id=closure.closure_id,
                    admitted_at=closure.admitted_at,
                    benchmark_instrument_id=self.benchmark_instrument_id,
                    capture_evidence_class=closure.evidence_class,
                )
            )
        if request != expected:
            raise ContinuousRuntimeSourceError("RUNTIME_SOURCE_ONLY_REQUEST_DIFFERS")
        return resolved

    def _require_market_producers(self, market: ResolvedContinuousForwardSources) -> None:
        """Match available roles to actual retained normalization and source scope."""
        closure = market.closure
        role: RuntimeRole = "quotes" if type(closure) is ContinuousQuoteClosure else "daily_inputs"
        expected = next(item for item in self.producer_map.producers if item.role == role)
        selected = set(closure.observation_ids)
        publications = [
            publication
            for publication in closure.publications
            if any(item.observation_id in selected for item in publication.record.observations)
        ]
        if not publications:
            raise ContinuousRuntimeSourceError("ORIGINAL_MARKET_PRODUCER_MISSING")
        for publication in publications:
            request = publication.record.request
            source = request.source
            if (
                expected.provider_id != source.provider
                or expected.source_environment != source.environment
                or expected.account_scope != source.account_scope
                or (role == "daily_inputs" and expected.producer != request.producer)
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_MARKET_PRODUCER_SCOPE_DIFFERS")
        if type(closure) is ContinuousQuoteClosure and any(
            item.producer != expected.producer for item in closure.selections
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_QUOTE_NORMALIZER_PIN_DIFFERS")

    def prepare_descriptor(
        self,
        *,
        descriptor_id: str,
        scope: ContinuousAccountScope,
        request: ContinuousEngineInputs | ClosedEngineFrontier,
        market_source: ContinuousEvidenceRef,
        previous: ResolvedContinuousAccount | None,
        fence: AccountFence,
        clock_reference: RuntimeClockReference | None,
        request_kind: Literal["initialize", "frontier", "activation_dependencies"],
        accounts: SqlContinuousAccount,
        daily: SqlDailyRuntimeRisk,
        quote_clock_reference: RuntimeClockReference | None = None,
    ) -> PreparedRuntimeDescriptor:
        self.bind_stores(accounts=accounts, daily=daily)
        if type(request) not in (ContinuousEngineInputs, ClosedEngineFrontier):
            raise ContinuousRuntimeSourceError("RUNTIME_ACTION_IS_NOT_PRECOMPUTE_INPUT")
        if previous is not None:
            accounts.require_resolved(previous)
        at = (
            request.spec.initialized_at
            if type(request) is ContinuousEngineInputs
            else cast(ClosedEngineFrontier, request).knowledge_at
        )
        current = self._current(fence)
        if request_kind == "activation_dependencies":
            at = current.raw.receipt.validated_at
        spec = (
            request.spec
            if isinstance(request, ContinuousEngineInputs)
            else cast(ContinuousEngineInputs, previous.checkpoint.inputs).spec
            if previous is not None
            else None
        )
        if (
            spec is None
            or scope.account_id != spec.account_id
            or scope.account_binding_sha256 != spec.account_binding_sha256
            or scope.stream_id != spec.deployment_id
            or fence.account_id != scope.account_id
            or self.venue_model.instruments != spec.instruments
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_ACCOUNT_MODEL_SCOPE_DIFFERS")
        market = self._normalize(market_source, request, previous, request_kind)
        operating = None
        quote_clock = None
        roles: tuple[ContinuousRuntimeRoleReferences, ...] = ()
        paired = self._paired(previous)
        if previous is not None:
            if clock_reference is None:
                raise ContinuousRuntimeSourceError("ACTUAL_ORIGINAL_CLOCK_REFERENCE_REQUIRED")
            operating = self.operating.prepare(
                clock_reference=clock_reference,
                accounts=accounts,
                daily=daily,
                previous=previous,
                daily_snapshot=current,
                original_checked_at=at,
                venue_account_id=self.venue_model.account_id,
                venue_model=self.venue_reference,
            )
            roles = (
                ContinuousRuntimeRoleReferences(
                    "clock",
                    (self._put(clock_reference, CLOCK_REFERENCE_SCHEMA, MAX_RUNTIME_SOURCE_BYTES),),
                ),
                ContinuousRuntimeRoleReferences(
                    "request_budget",
                    (
                        self._put(
                            self.venue_reference, MODEL_REFERENCE_SCHEMA, MAX_RUNTIME_SOURCE_BYTES
                        ),
                    ),
                ),
            )
        if paired is not None:
            roles += (
                ContinuousRuntimeRoleReferences(
                    "reconciliation",
                    (
                        self._put(
                            paired.reconciliation.receipt,
                            RECONCILIATION_REFERENCE_SCHEMA,
                            MAX_RUNTIME_SOURCE_BYTES,
                        ),
                    ),
                ),
            )
        if market is not None and type(market.closure) is ContinuousQuoteClosure:
            original_clock = quote_clock_reference or clock_reference
            if original_clock is None:
                raise ContinuousRuntimeSourceError("ORIGINAL_QUOTE_CLOCK_REQUIRED")
            quote_clock = self.read_original_clock(original_clock)
            roles += (
                ContinuousRuntimeRoleReferences(
                    "quotes",
                    (self._put(original_clock, CLOCK_REFERENCE_SCHEMA, MAX_RUNTIME_SOURCE_BYTES),),
                ),
            )
        elif quote_clock_reference is not None:
            raise ContinuousRuntimeSourceError("QUOTE_CLOCK_REQUIRES_QUOTE_SOURCE")
        roles = tuple(sorted(roles, key=lambda item: item.role))
        receipt = current.raw.receipt
        actual = receipt.fence
        original = DailyFenceReference(
            fence=actual,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256=receipt.lease_sha256,
            original_receipt_sha256=receipt.semantic_sha256,
        )
        descriptor = ContinuousRuntimeSourceDescriptor(
            descriptor_id=descriptor_id,
            scope=scope,
            request_kind=request_kind,
            request=self._put(request, "continuous-account-request/1"),
            market_source=market_source,
            market_evidence_class="synthetic_fixture"
            if market is None
            else market.closure.evidence_class,
            previous=None if previous is None else previous.receipt,
            original_checked_at=at,
            captured_fence=original,
            producer_map=self.producer_map,
            assignment_sha256=None
            if current.assignment is None
            else current.assignment.semantic_sha256,
            control_sha256=None if current.control is None else current.control.semantic_sha256,
            obligations_sha256=current.obligations.semantic_sha256,
            attempts_sha256=daily_attempt_inventory_sha256(current.attempts),
            role_references=roles,
        )
        reference = self._put(descriptor, RUNTIME_SOURCE_SCHEMA, MAX_RUNTIME_SOURCE_BYTES)
        key = runtime_source_key(scope)
        append = self.journal.prepare_append(
            key,
            JournalAppend(
                descriptor_id,
                descriptor.semantic_sha256,
                self.journal.read_head(key),
                (
                    JournalRecord(
                        descriptor.semantic_sha256,
                        RUNTIME_SOURCE_SCHEMA,
                        self.codec.encode_record(descriptor),
                    ),
                ),
            ),
        )
        return self._own(
            PreparedRuntimeDescriptor(
                descriptor,
                reference,
                append,
                previous,
                current,
                request,
                market,
                operating,
                paired,
                self._seal,
                quote_clock,
            )
        )

    def append_descriptor_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedRuntimeDescriptor,
        *,
        fence: AccountFence,
    ) -> ContinuousEvidenceRef:
        self._require(prepared, PreparedRuntimeDescriptor)
        accounts, daily = self._stores()
        if connection.engine is not self.engine:
            raise ContinuousRuntimeSourceError("RUNTIME_SAME_ENGINE_REQUIRED")
        # This only retains dependencies; it does not publish a checkpoint or
        # consume a request. Real final account admission rechecks all sources.
        if prepared.previous is not None:
            accounts.recheck_in_transaction(connection, prepared.previous, require_current=True)
        daily.recheck_snapshot_in_transaction(connection, prepared.daily, fence=fence)
        if prepared.market is not None:
            self.forward_sources.recheck_in_transaction(connection, prepared.market)
        if prepared.quote_clock is not None:
            self.recheck_original_clock_in_transaction(connection, prepared.quote_clock)
        receipt = self.journal.append_in_transaction(connection, prepared.append)
        if receipt != prepared.append.receipt:
            raise ContinuousRuntimeSourceError("RUNTIME_DESCRIPTOR_ACK_DIFFERS")
        self.coordinator.revalidate_for_commit_in_transaction(connection, fence)
        return prepared.reference

    def resolve_prepared_descriptor(
        self, prepared: PreparedRuntimeDescriptor
    ) -> ResolvedRuntimeDescriptor:
        self._require(prepared, PreparedRuntimeDescriptor)
        plan = self._own(
            RuntimeDescriptorReadPlan(
                prepared.descriptor,
                prepared.reference,
                prepared.previous,
                prepared.daily,
                prepared.request,
                prepared.market,
                prepared.operating,
                prepared.reconciliation,
                self._seal,
                prepared.quote_clock,
            )
        )
        with _repeatable_read_transaction(self.engine) as connection:
            raw = self._capture(connection, plan, RuntimeReadBudget())
        value = self._resolve_descriptor(raw)
        self._active[prepared.descriptor.semantic_sha256] = value
        return value

    def _capture(
        self,
        connection: Connection,
        plan: RuntimeDescriptorReadPlan,
        budget: RuntimeReadBudget,
    ) -> RuntimeProducerRawSnapshot:
        self._require(plan, RuntimeDescriptorReadPlan)
        before = len(budget.captured)
        tables = []
        for table in (
            *CONTINUOUS_ACCOUNT_TABLES,
            phase2_account_leases,
        ):
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
                if old is not None
                else capture_runtime_table(
                    connection, table, account_id=plan.descriptor.scope.account_id, budget=budget
                )
            )
        descriptor = self.journal.capture_in_transaction(
            connection,
            runtime_source_key(plan.descriptor.scope),
            command_id=plan.descriptor.descriptor_id,
        )
        markets = (
            ()
            if plan.market is None
            else tuple(
                self.forward_sources.journal.capture_in_transaction(
                    connection, read.snapshot.key, command_id=read.snapshot.command_id
                )
                for read in plan.market.reads
            )
        )
        previous = (
            None
            if plan.previous is None
            else self._stores()[0].journal.capture_in_transaction(
                connection,
                plan.previous.journal.snapshot.key,
                command_id=plan.previous.journal.snapshot.command_id,
            )
        )
        paired_row = None
        extra: tuple[JournalReadSnapshot, ...] = ()
        if plan.reconciliation is not None:
            assert self.publisher is not None
            paired = plan.reconciliation
            captured_pair = self.publisher.applied.capture_commit_in_transaction(
                connection,
                scope=paired.reconciliation.snapshot.scope,
                command_id=paired.reconciliation.receipt.commit.command_id,
            )
            if captured_pair is None:
                raise ContinuousRuntimeSourceError("ORIGINAL_RECONCILIATION_COMMIT_MISSING")
            paired_row = captured_pair.row
            budget.charge(
                1,
                sum(len(v) for v in paired_row.values() if type(v) is bytes),
                sum(
                    len(str(v).encode())
                    for v in paired_row.values()
                    if v is not None and type(v) is not bytes
                ),
            )
            extra = (
                self._stores()[0].journal.capture_in_transaction(
                    connection,
                    paired.continuous.journal.snapshot.key,
                    command_id=paired.continuous.journal.snapshot.command_id,
                ),
                self.publisher.journal.capture_in_transaction(
                    connection,
                    paired.journal.snapshot.key,
                    command_id=paired.journal.snapshot.command_id,
                ),
                *(
                    self.publisher.sources.journal.capture_in_transaction(
                        connection, read.snapshot.key, command_id=read.snapshot.command_id
                    )
                    for read in paired.sources.reads
                ),
            )
        quote_raw = None
        if plan.quote_clock is not None:
            self.require_original_clock(plan.quote_clock, deep=False)
            quote_raw = self.operating.journal.capture_in_transaction(
                connection,
                plan.quote_clock.reference.key,
                command_id=plan.quote_clock.reference.receipt.command_id,
            )
        _charge_journals(
            budget,
            (
                descriptor,
                *markets,
                *extra,
                *((previous,) if previous is not None else ()),
                *((quote_raw,) if quote_raw is not None else ()),
            ),
        )
        operating = (
            None
            if plan.operating is None
            else self.operating.capture_in_transaction(connection, plan.operating, budget=budget)
        )
        raw = RuntimeProducerRawSnapshot(tuple(budget.captured[before:]))
        self._own(raw)
        self._raw[id(raw)] = _Captured(
            plan,
            tuple(tables),
            descriptor,
            markets,
            previous,
            operating,
            paired_row,
            extra,
            quote_raw,
        )
        finalize(raw, self._raw.pop, id(raw), None)
        return raw

    def _resolve_descriptor(self, raw: RuntimeProducerRawSnapshot) -> ResolvedRuntimeDescriptor:
        self._require(raw, RuntimeProducerRawSnapshot)
        captured = self._raw[id(raw)]
        plan = captured.plan
        descriptor = self.journal.resolve_snapshot(captured.descriptor)
        receipt = descriptor.receipt
        if receipt is None or (
            receipt.command_id != plan.descriptor.descriptor_id
            or receipt.command_sha256 != plan.descriptor.semantic_sha256
            or receipt.record_ids != (plan.descriptor.semantic_sha256,)
            or receipt.record_hashes != (plan.reference.object_ref.object_sha256,)
        ):
            raise ContinuousRuntimeSourceError("RUNTIME_DESCRIPTOR_NEVER_RETAINED_OR_CHANGED")
        if (
            self._read(plan.reference, ContinuousRuntimeSourceDescriptor, MAX_RUNTIME_SOURCE_BYTES)
            != plan.descriptor
        ):
            raise ContinuousRuntimeSourceError("RUNTIME_DESCRIPTOR_OBJECT_DIFFERS")
        if plan.previous is not None:
            self._stores()[0].require_resolved(plan.previous)
            expected = plan.previous.snapshot.row
            if not any(row == expected for row in captured.tables[0].rows):
                raise ContinuousRuntimeSourceError("RUNTIME_ORIGINAL_ACCOUNT_INDEX_CHANGED")
            if (
                captured.previous is None
                or captured.previous.requested_receipt
                != plan.previous.journal.snapshot.requested_receipt
            ):
                raise ContinuousRuntimeSourceError("RUNTIME_ORIGINAL_ACCOUNT_JOURNAL_CHANGED")
        if plan.market is not None:
            for current, original in zip(captured.markets, plan.market.reads, strict=True):
                if current.requested_receipt != original.snapshot.requested_receipt:
                    raise ContinuousRuntimeSourceError("RUNTIME_ORIGINAL_CAPTURE_CHANGED")
        leases = next(item.rows for item in captured.tables if item.table is phase2_account_leases)
        lease_rows = [
            row
            for row in leases
            if row["lease_sha256"] == plan.descriptor.captured_fence.lease_sha256
        ]
        if len(lease_rows) != 1:
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_LEASE_MISSING")
        lease_values = dict(lease_rows[0])
        for name in ("acquired_at", "heartbeat_at", "expires_at"):
            lease_values[name] = as_aware_utc(datetime.fromisoformat(lease_values[name]))
        lease = account_lease_from_row(lease_values)
        reference = plan.descriptor.captured_fence
        receipt_digest = sha256(
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
            lease.fence != reference.fence
            or lease.expires_at != reference.valid_until
            or lease.policy_sha256 != reference.policy_sha256
            or not lease.heartbeat_at <= reference.validated_at < lease.expires_at
            or receipt_digest != reference.original_receipt_sha256
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_FENCE_BINDING_DIFFERS")
        if plan.reconciliation is not None:
            assert self.publisher is not None
            self.publisher.require_resolved(plan.reconciliation)
            row = plan.reconciliation.reconciliation.snapshot.row
            if captured.reconciliation != row:
                raise ContinuousRuntimeSourceError("ORIGINAL_RECONCILIATION_COMMIT_CHANGED")
            originals = (
                plan.reconciliation.continuous.journal,
                plan.reconciliation.journal,
                *plan.reconciliation.sources.reads,
            )
            if any(
                read.requested_receipt != old.snapshot.requested_receipt
                for read, old in zip(captured.auxiliary, originals, strict=True)
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_RECONCILIATION_SOURCE_CHANGED")
        if plan.quote_clock is not None:
            self.require_original_clock(plan.quote_clock)
            if (
                captured.quote_clock is None
                or captured.quote_clock.requested_receipt
                != plan.quote_clock.read.snapshot.requested_receipt
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_QUOTE_CLOCK_JOURNAL_CHANGED")
        operating = (
            None if captured.operating is None else self.operating.resolve(captured.operating)
        )
        result = self._own(
            ResolvedRuntimeDescriptor(raw, plan, descriptor, operating, lease_rows[0], self._seal)
        )
        self._fingerprints[id(result)] = content_digest(
            (plan.descriptor, plan.request, plan.reference)
        )
        finalize(result, self._fingerprints.pop, id(result), None)
        self._resolved_by_raw[id(raw)] = (descriptor, operating, lease_rows[0])
        finalize(raw, self._resolved_by_raw.pop, id(raw), None)
        return result

    def require_resolved(self, value: ResolvedRuntimeDescriptor) -> None:
        """Heavy original fingerprints and source ownership, outside SQL only."""
        self._require(value, ResolvedRuntimeDescriptor)
        if (
            content_digest((value.plan.descriptor, value.plan.request, value.plan.reference))
            != self._fingerprints[id(value)]
        ):
            raise ContinuousRuntimeSourceError("RUNTIME_ORIGINAL_RESOLUTION_CHANGED")
        if value.plan.previous is not None:
            self._stores()[0].require_resolved(value.plan.previous)
        if value.plan.quote_clock is not None:
            self.require_original_clock(value.plan.quote_clock)
        if value.plan.market is not None:
            self.forward_sources.require_resolved(value.plan.market)
        if value.operating is not None:
            self.operating.require_resolved(value.operating)
        if value.plan.reconciliation is not None:
            assert self.publisher is not None
            self.publisher.require_resolved(value.plan.reconciliation)

    def recheck_descriptor_in_transaction(
        self,
        connection: Connection,
        value: ResolvedRuntimeDescriptor,
        *,
        require_current: bool,
    ) -> None:
        self._require(value, ResolvedRuntimeDescriptor)
        self._recheck(
            connection,
            value.plan,
            value.descriptor,
            value.operating,
            value.lease,
            require_current=require_current,
        )

    def _recheck(
        self,
        connection: Connection,
        plan: RuntimeDescriptorReadPlan,
        descriptor: ResolvedJournalRead,
        operating: ResolvedRuntimeOperatingEvidence | None,
        lease: Mapping[str, Any],
        *,
        require_current: bool,
    ) -> None:
        self._require(plan, RuntimeDescriptorReadPlan)
        self.journal.recheck_in_transaction(connection, descriptor, require_current_head=False)
        if plan.previous is not None:
            self._stores()[0].recheck_in_transaction(
                connection, plan.previous, require_current=require_current
            )
        if plan.market is not None:
            self.forward_sources.recheck_in_transaction(connection, plan.market)
        if plan.quote_clock is not None:
            self.recheck_original_clock_in_transaction(connection, plan.quote_clock)
        if operating is not None:
            self.operating.recheck_in_transaction(
                connection, operating, require_current=require_current
            )
            if require_current:
                self.operating.require_current_clock(operating)
        # The actual current fence is used only for this read's physical ownership;
        # the original source lease/time remains the retained descriptor value.
        if plan.reconciliation is not None:
            assert self.publisher is not None
            self.publisher.recheck_in_transaction(
                connection,
                plan.reconciliation,
                fence=plan.daily.raw.receipt.fence,
                require_current=False,
            )
        current = capture_runtime_table(
            connection,
            phase2_account_leases,
            account_id=plan.descriptor.scope.account_id,
            budget=RuntimeReadBudget(),
        )
        if lease not in current.rows:
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_LEASE_CHANGED")

    def capture_in_transaction(
        self,
        connection: Connection,
        *,
        account_id: str,
        refs: RuntimeRiskInputRefs | None,
        owner_command_ref: JournalReceipt | None,
        budget: RuntimeReadBudget,
    ) -> RuntimeProducerRawSnapshot:
        if owner_command_ref is not None:
            if self.owner_dependencies is not None and refs is None:
                return self.owner_dependencies.capture_in_transaction(
                    connection,
                    account_id=account_id,
                    owner_command_ref=owner_command_ref,
                    budget=budget,
                )
            raise ContinuousRuntimeSourceError("RETAINED_OWNER_COMMAND_AUTHENTICATOR_REQUIRED")
        if (
            refs is None
            or not refs.sources
            or len({source.source_sha256 for source in refs.sources}) != 1
        ):
            raise ContinuousRuntimeSourceError("EXACT_ORIGINAL_RUNTIME_SOURCE_REQUIRED")
        original = self._active.get(refs.sources[0].source_sha256)
        if original is None or original.plan.descriptor.scope.account_id != account_id:
            raise ContinuousRuntimeSourceError("RUNTIME_SOURCE_MUST_BE_RESOLVED_BEFORE_CAPTURE")
        return self._capture(connection, original.plan, budget)

    def _control(self, plan: RuntimeDescriptorReadPlan) -> Mapping[str, Any] | None:
        if plan.descriptor.control_sha256 is None:
            return None
        rows = next(
            value.rows
            for value in plan.daily.raw.tables
            if value.table is phase5_operational_control_transitions
        )
        matched = [row for row in rows if row["semantic_sha256"] == plan.descriptor.control_sha256]
        if len(matched) != 1:
            raise ContinuousRuntimeSourceError("RUNTIME_ORIGINAL_CONTROL_NOT_FOUND")
        return matched[0]

    def evidence_port(self, value: ResolvedRuntimeDescriptor) -> ContinuousRuntimeEvidencePort:
        self.require_resolved(value)
        plan = value.plan
        assignment = next(
            (
                item
                for item in plan.daily.assignment_rows
                if item.semantic_sha256 == plan.descriptor.assignment_sha256
            ),
            None,
        )
        if assignment is None or plan.previous is None or plan.operating is None:
            raise ContinuousRuntimeSourceError(
                "RUNTIME_DECISION_REQUIRES_INITIALIZED_ASSIGNED_SOURCES"
            )
        inventory = self._inventory(plan)
        control = self._control(plan)
        heads = self._original_heads(plan)
        return ContinuousRuntimeEvidencePort(
            descriptor=plan.descriptor,
            assignment=assignment,
            obligations=inventory,
            original_heads=heads,
            cash_restrictions=self._cash_restrictions(plan),
            reconciliation=None
            if plan.reconciliation is None
            else plan.reconciliation.reconciliation.resolved.result,
            evaluator=_RoleEvaluator(self, value, control),
        )

    def build(
        self,
        *,
        snapshot: AccountSnapshot,
        batch: DailyIntentBatch,
        phase: Literal["decision", "activation"],
        evaluated_at: datetime,
        accepted_intent_ids: tuple[str, ...],
        daily_return: Decimal | None,
        drawdown: Decimal | None,
        request_rows: tuple[tuple[datetime, bool], ...],
    ) -> DailyRuntimeRiskEvidence:
        candidates = [
            value
            for value in self._active.values()
            if value.plan.descriptor.scope.account_id == snapshot.account_id
            and value.plan.descriptor.original_checked_at == evaluated_at
            and (value.plan.descriptor.request_kind == "activation_dependencies")
            == (phase == "activation")
        ]
        if len(candidates) != 1:
            raise ContinuousRuntimeSourceError("EXACT_ACTIVE_ORIGINAL_DESCRIPTOR_REQUIRED")
        return self.evidence_port(candidates[0]).build(
            snapshot=snapshot,
            batch=batch,
            phase=phase,
            evaluated_at=evaluated_at,
            accepted_intent_ids=accepted_intent_ids,
            daily_return=daily_return,
            drawdown=drawdown,
            request_rows=request_rows,
        )

    def resolve(
        self,
        snapshot: RuntimeProducerRawSnapshot,
        *,
        assignment: RuntimeRiskAssignment | None,
        previous: RuntimeRiskAssignment | None,
        refs: RuntimeRiskInputRefs | None,
        owner_command_ref: JournalReceipt | None,
        fence_receipt: AccountFenceReceipt,
        control: OperationalControlTransition | None,
    ) -> ResolvedRuntimeRiskInputs | VerifiedRuntimeAssignmentCommand:
        if owner_command_ref is not None and refs is None and self.owner_dependencies is not None:
            return self.owner_dependencies.resolve(
                snapshot,
                assignment=assignment,
                previous=previous,
                owner_command_ref=owner_command_ref,
                fence_receipt=fence_receipt,
                control=control,
            )
        if (
            owner_command_ref is not None
            or refs is None
            or assignment is None
            or previous is not None
        ):
            raise ContinuousRuntimeSourceError("RETAINED_OWNER_COMMAND_AUTHENTICATOR_REQUIRED")
        value = self._resolve_descriptor(snapshot)
        plan = value.plan
        if (
            assignment.semantic_sha256 != plan.descriptor.assignment_sha256
            or plan.previous is None
            or type(plan.request) is not ClosedEngineFrontier
            or plan.descriptor.request_kind != "frontier"
        ):
            raise ContinuousRuntimeSourceError("RUNTIME_DECISION_SCOPE_OR_PHASE_DIFFERS")
        result = advance_continuous_engine(
            plan.previous.checkpoint,
            plan.request,
            expected_sha256=plan.previous.checkpoint.semantic_sha256,
            accounting=self.accounting,
            strategy=self.strategy,
            runtime_evidence=self.evidence_port(value),
        )
        candidates = tuple(
            item
            for item in result.runtime_decisions[len(plan.previous.checkpoint.runtime_decisions) :]
            if item.evidence.inputs == refs
        )
        if len(candidates) != 1:
            raise ContinuousRuntimeSourceError("RUNTIME_SOLE_ENGINE_CALLBACK_DIFFERS")
        (item,) = candidates
        return ResolvedRuntimeRiskInputs(
            item.source_state,
            item.snapshot,
            item.evidence.inputs,
            self.producer_map,
            item.source_context,
            result.inputs.spec.execution_policy,
        )

    def recheck_in_transaction(
        self, connection: Connection, snapshot: RuntimeProducerRawSnapshot
    ) -> None:
        if self.owner_dependencies is not None and self.owner_dependencies.owns_snapshot(snapshot):
            self.owner_dependencies.recheck_in_transaction(connection, snapshot)
            return
        self._require(snapshot, RuntimeProducerRawSnapshot)
        binding = self._resolved_by_raw.get(id(snapshot))
        if binding is None:
            raise ContinuousRuntimeSourceError("OWNED_RESOLVED_RUNTIME_CAPTURE_REQUIRED")
        journal, operating, lease = binding
        self._recheck(
            connection,
            self._raw[id(snapshot)].plan,
            journal,
            operating,
            lease,
            require_current=True,
        )

    def recheck_admission_sources_after_publication_in_transaction(
        self,
        connection: Connection,
        raw_producer: RuntimeProducerRawSnapshot,
        *,
        admission: PreparedDailyAdmission,
        prepared_account: PreparedContinuousCommit,
        account_receipt: ContinuousAccountReceipt,
        fence: AccountFence,
    ) -> None:
        """Keep original dependencies after exactly this owned B/C publication."""
        accounts, daily = self._stores()
        self._require(raw_producer, RuntimeProducerRawSnapshot)
        binding = self._resolved_by_raw.get(id(raw_producer))
        if binding is None or raw_producer is not admission.snapshot.raw.producer:
            raise ContinuousRuntimeSourceError("ORIGINAL_ADMISSION_CAPTURE_REQUIRED")
        daily.recheck_admission_publication_rows_in_transaction(
            connection,
            admission,
            prepared_account=prepared_account,
            account_receipt=account_receipt,
            fence=fence,
        )
        plan = self._raw[id(raw_producer)].plan
        if (
            plan.previous is not prepared_account.previous
            or plan.descriptor.request_kind != "frontier"
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_ADMISSION_PREDECESSOR_REQUIRED")
        journal, operating, lease = binding
        self._recheck(connection, plan, journal, operating, lease, require_current=False)
        if operating is not None:
            self.operating.journal.recheck_in_transaction(
                connection, operating.clock, require_current_head=True
            )
            self.operating.require_current_clock(operating)
        accounts.require_committed_in_transaction(
            connection, prepared=prepared_account, receipt=account_receipt
        )

    def require_current_admission_clock(self, raw_producer: RuntimeProducerRawSnapshot) -> None:
        """Final original clock scalar guard, after the caller's last SQL read."""
        self._require(raw_producer, RuntimeProducerRawSnapshot)
        binding = self._resolved_by_raw.get(id(raw_producer))
        if binding is None:
            raise ContinuousRuntimeSourceError("OWNED_RESOLVED_RUNTIME_CAPTURE_REQUIRED")
        _journal, operating, _lease = binding
        if operating is not None:
            self.operating.require_current_clock(operating)

    def recheck_installed_owner_sources_in_transaction(
        self, connection: Connection, *, prepared: PreparedDailyAssignment, fence: AccountFence
    ) -> AccountFenceReceipt:
        if self.owner_dependencies is None:
            raise ContinuousRuntimeSourceError("RETAINED_OWNER_COMMAND_AUTHENTICATOR_REQUIRED")
        return self.owner_dependencies.recheck_installed_owner_sources_in_transaction(
            connection, prepared=prepared, fence=fence
        )

    def retain_admission_sources(
        self, view: RetainedDailyAdmission, *, snapshot: RuntimeProducerRawSnapshot
    ) -> ContinuousEvidenceRef:
        self._stores()[1].require_admission_view(view)
        self._require(snapshot, RuntimeProducerRawSnapshot)
        plan = self._raw[id(snapshot)].plan
        if (
            id(snapshot) not in self._resolved_by_raw
            or not view.resolved.inputs.sources
            or any(
                source.source_sha256 != plan.descriptor.semantic_sha256
                for source in view.resolved.inputs.sources
            )
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_ADMISSION_SOURCE_DIFFERS")
        return plan.reference

    def prepare_admission_source_read(
        self,
        reference: ContinuousEvidenceRef,
        *,
        record_sha256: str,
        previous: ResolvedContinuousAccount | None,
    ) -> ContinuousProducerPlan:
        if reference.schema_id != RUNTIME_SOURCE_SCHEMA:
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_SCHEMA_REQUIRED")
        descriptor = self._read(
            reference, ContinuousRuntimeSourceDescriptor, MAX_RUNTIME_SOURCE_BYTES
        )
        accounts, daily = self._stores()
        if previous is None or descriptor.previous != previous.receipt:
            raise ContinuousRuntimeSourceError("ORIGINAL_AUTHENTICATED_PREDECESSOR_REQUIRED")
        accounts.require_resolved(previous)
        current = self._current(self.current_fence())
        request = self._read(descriptor.request, ClosedEngineFrontier)
        market = self._normalize(
            descriptor.market_source, request, previous, descriptor.request_kind
        )
        roles = {item.role: item.references for item in descriptor.role_references}
        model_refs = roles.get("request_budget", ())
        if (
            descriptor.producer_map != self.producer_map
            or len(model_refs) != 1
            or model_refs[0].schema_id != MODEL_REFERENCE_SCHEMA
            or self._read(model_refs[0], VenueSourceReference, MAX_RUNTIME_SOURCE_BYTES)
            != self.venue_reference
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_MODEL_OR_PRODUCERS_DIFFER")
        clock_refs = roles.get("clock", ())
        if len(clock_refs) != 1 or clock_refs[0].schema_id != CLOCK_REFERENCE_SCHEMA:
            raise ContinuousRuntimeSourceError("ORIGINAL_RUNTIME_CLOCK_REFERENCE_MISSING")
        clock = self._read(clock_refs[0], RuntimeClockReference, MAX_RUNTIME_SOURCE_BYTES)
        operating = self.operating.prepare(
            clock_reference=clock,
            accounts=accounts,
            daily=daily,
            previous=previous,
            daily_snapshot=current,
            original_checked_at=descriptor.original_checked_at,
            venue_account_id=self.venue_model.account_id,
            venue_model=self.venue_reference,
        )
        paired = None
        if "reconciliation" in roles:
            paired = self._paired(previous)
            refs = roles["reconciliation"]
            if (
                paired is None
                or len(refs) != 1
                or refs[0].schema_id != RECONCILIATION_REFERENCE_SCHEMA
                or self._read(refs[0], ReconciliationCommitReceipt, MAX_RUNTIME_SOURCE_BYTES)
                != paired.reconciliation.receipt
            ):
                raise ContinuousRuntimeSourceError("ORIGINAL_PAIRED_RECONCILIATION_MISSING")
        quote_clock = None
        if "quotes" in roles:
            quote_refs = roles["quotes"]
            if len(quote_refs) != 1 or quote_refs[0].schema_id != CLOCK_REFERENCE_SCHEMA:
                raise ContinuousRuntimeSourceError("ORIGINAL_QUOTE_CLOCK_REFERENCE_DIFFERS")
            quote_clock = self.read_original_clock(
                self._read(quote_refs[0], RuntimeClockReference, MAX_RUNTIME_SOURCE_BYTES)
            )
        plan = self._own(
            RuntimeDescriptorReadPlan(
                descriptor,
                reference,
                previous,
                current,
                request,
                market,
                operating,
                paired,
                self._seal,
                quote_clock,
            )
        )
        self._inventory(plan)
        self._control(plan)
        if not any(
            item.semantic_sha256 == descriptor.assignment_sha256 for item in current.assignment_rows
        ):
            raise ContinuousRuntimeSourceError("ORIGINAL_ASSIGNMENT_PREFIX_MISSING")
        return self._own(ContinuousProducerPlan(reference, record_sha256, plan, self._seal))

    def capture_admission_sources_in_transaction(
        self, connection: Connection, plan: ContinuousProducerPlan
    ) -> ContinuousProducerSnapshot:
        self._require(plan, ContinuousProducerPlan)
        raw = self._capture(
            connection, cast(RuntimeDescriptorReadPlan, plan.state), RuntimeReadBudget()
        )
        return self._own(
            ContinuousProducerSnapshot(plan.reference, plan.record_sha256, raw, self._seal)
        )

    def resolve_admission_sources(
        self,
        snapshot: ContinuousProducerSnapshot,
        *,
        admission: RetainedDailyAdmission,
        previous: ResolvedContinuousAccount | None,
    ) -> ResolvedContinuousProducerClosure:
        self._require(snapshot, ContinuousProducerSnapshot)
        self._stores()[1].require_admission_view(admission)
        raw = cast(RuntimeProducerRawSnapshot, snapshot.state)
        plan = self._raw[id(raw)].plan
        if previous is not plan.previous or snapshot.record_sha256 != admission.record_sha256:
            raise ContinuousRuntimeSourceError("ORIGINAL_ADMISSION_OR_PREDECESSOR_DIFFERS")
        assignment = next(
            (
                item
                for item in plan.daily.assignment_rows
                if item.semantic_sha256 == plan.descriptor.assignment_sha256
            ),
            None,
        )
        actual = self.resolve(
            raw,
            assignment=assignment,
            previous=None,
            refs=admission.resolved.inputs,
            owner_command_ref=None,
            fence_receipt=plan.daily.raw.receipt,
            control=plan.daily.control,
        )
        if actual != admission.resolved:
            raise ContinuousRuntimeSourceError("ORIGINAL_SOLE_ENGINE_ADMISSION_REPLAY_DIFFERS")
        journal, operating, lease = self._resolved_by_raw[id(raw)]
        value = self._own(
            ResolvedRuntimeDescriptor(raw, plan, journal, operating, lease, self._seal)
        )
        return self._own(
            ResolvedContinuousProducerClosure(
                snapshot.reference, snapshot.record_sha256, value, self._seal
            )
        )

    def recheck_admission_sources_in_transaction(
        self, connection: Connection, resolved: ResolvedContinuousProducerClosure
    ) -> None:
        self._require(resolved, ResolvedContinuousProducerClosure)
        value = cast(ResolvedRuntimeDescriptor, resolved.state)
        self.recheck_descriptor_in_transaction(connection, value, require_current=False)


def original_reconciliation_reasons(
    result: ReconciliationResult | None,
    *,
    heads: ReconciliationHeads | None,
    checked_at: datetime,
) -> tuple[str, ...]:
    if result is None:
        return ("ORIGINAL_RECONCILIATION_MISSING",)
    if result.policy_sha256 != RUNTIME_RECONCILIATION_PROFILE.sha256:
        raise ContinuousRuntimeSourceError("ORIGINAL_RECONCILIATION_POLICY_DIFFERS")
    reasons = []
    if result.heads != heads:
        reasons.append("ORIGINAL_RECONCILIATION_HEADS_DIFFER")
    if result.status != "converged":
        reasons.append("ORIGINAL_RECONCILIATION_NOT_CONVERGED")
    freshness = timedelta(seconds=ReconciliationPolicy().freshness_seconds)
    if any(
        not instant <= checked_at < instant + freshness
        for instant in (
            result.observation_started_at,
            result.observation_received_through,
            result.completed_at,
        )
    ):
        reasons.append("ORIGINAL_RECONCILIATION_TIME_UNAVAILABLE")
    return tuple(sorted(reasons))


def original_cash_restriction(capture: RetainedVenueCapture, model: VenueModel) -> Decimal | None:
    if capture.observed.scope.source_class != "stateful_simulation":
        raise ContinuousRuntimeSourceError("ORIGINAL_INDEPENDENT_CASH_MODEL_DIFFERS")
    values = [item for item in capture.observed.cash if item.field == "restricted_cash"]
    if len(values) != 1:
        return None
    value = values[0]
    if (
        value.currency != "USD"
        or value.semantics_sha256
        != content_digest(("venue-cash-semantics/1", model.semantic_sha256, "restricted_cash"))
        or value.value is None
        or value.value < 0
    ):
        return None
    return value.value


@dataclass(frozen=True, slots=True)
class RuntimeRoleSourceContext:
    """Authenticated original source values; this DTO grants no current authority."""

    descriptor: ContinuousRuntimeSourceDescriptor
    checkpoint: CausalEngineCheckpoint
    receipt: ContinuousAccountReceipt
    operating: RuntimeOperatingSourceContext
    market: ResolvedContinuousForwardSources | None
    control: Mapping[str, Any] | None
    reconciliation: ReconciliationResult | None
    reconciliation_sequence: int
    reconciliation_reasons: tuple[str, ...]
    cash_restrictions: Decimal | None
    quote_clock: RuntimeClockObservation | None


class _RoleEvaluator:
    def __init__(
        self,
        owner: SqlContinuousRuntimeSources,
        value: ResolvedRuntimeDescriptor,
        control: Mapping[str, Any] | None,
    ):
        self.owner, self.value, self.control = owner, value, control

    def evaluate(
        self,
        *,
        snapshot: AccountSnapshot,
        batch: DailyIntentBatch,
        phase: Literal["decision", "activation"],
        evaluated_at: datetime,
        request_rows: tuple[tuple[datetime, bool], ...],
    ) -> tuple[RuntimeSourceCondition, ...]:
        value = self.value
        self.owner.require_resolved(value)
        plan = value.plan
        assert plan.previous is not None and value.operating is not None
        operating = value.operating.snapshot.plan
        context = RuntimeRoleSourceContext(
            plan.descriptor,
            plan.previous.checkpoint,
            plan.previous.receipt,
            RuntimeOperatingSourceContext(
                plan.previous.checkpoint,
                plan.previous.receipt,
                operating.clock_reference,
                operating.clock,
                operating.original_checked_at,
                operating.attempts,
                operating.venue_account_id,
                operating.venue_model,
            ),
            plan.market,
            self.control,
            None
            if plan.reconciliation is None
            else plan.reconciliation.reconciliation.resolved.result,
            0
            if plan.reconciliation is None
            else plan.reconciliation.continuous.receipt.commit.sequence,
            self.owner._reconciliation_reasons(plan),
            self.owner._cash_restrictions(plan),
            None if plan.quote_clock is None else plan.quote_clock.observation,
        )
        return evaluate_original_runtime_roles(
            context,
            snapshot=snapshot,
            batch=batch,
            phase=phase,
            evaluated_at=evaluated_at,
            request_rows=request_rows,
        )


def evaluate_original_runtime_roles(
    context: RuntimeRoleSourceContext,
    *,
    snapshot: AccountSnapshot,
    batch: DailyIntentBatch,
    phase: Literal["decision", "activation"],
    evaluated_at: datetime,
    request_rows: tuple[tuple[datetime, bool], ...],
) -> tuple[RuntimeSourceCondition, ...]:
    """Shared projection after a caller authenticates its original source ownership."""
    if type(context.checkpoint.inputs) is not ContinuousEngineInputs:
        raise ContinuousRuntimeSourceError("ACTUAL_CONTINUOUS_ROLE_CONTEXT_REQUIRED")
    original = context.descriptor
    facts = evaluate_original_operating_facts(
        context.operating,
        batch=batch,
        phase=phase,
        evaluated_at=evaluated_at,
        request_rows=request_rows,
    )
    conditions = [
        RuntimeSourceCondition(
            f.role, f.source_at, f.received_at, f.valid_until, f.revision, f.status, f.reasons
        )
        for f in facts
        if f.source_at is not None and f.received_at is not None and f.valid_until is not None
    ]
    now, received = context.checkpoint.now, context.receipt.recorded_at
    # Current raw-head equality, bounded by the original actual lease,
    # authenticates immutable canonical values; it does not refresh them.
    expiry = original.captured_fence.valid_until
    for role in cast(
        tuple[RuntimeRole, ...], ("account", "commitments", "intent_registry", "ledger", "loss")
    ):
        conditions.append(
            RuntimeSourceCondition(
                role,
                now,
                received,
                expiry,
                context.receipt.commit.sequence,
                "available",
                (),
            )
        )
    reasons: tuple[str, ...] = (
        ()
        if context.control is not None and context.control["effective_state"] == "running"
        else ("RUNTIME_ORIGINAL_CONTROL_NOT_RUNNING",)
    )
    conditions.append(
        RuntimeSourceCondition(
            "controls",
            now
            if context.control is None
            else as_aware_utc(datetime.fromisoformat(context.control["decided_at"])),
            received
            if context.control is None
            else as_aware_utc(datetime.fromisoformat(context.control["decided_at"])),
            expiry,
            0 if context.control is None else context.control["sequence_number"],
            "available" if not reasons else "blocked",
            reasons,
        )
    )
    if context.reconciliation is not None:
        result = context.reconciliation
        for role in cast(tuple[RuntimeRole, ...], ("cash", "reconciliation")):
            reasons = context.reconciliation_reasons
            if role == "cash" and context.cash_restrictions is None:
                reasons = tuple(sorted(set((*reasons, "ORIGINAL_CASH_RESTRICTION_UNAVAILABLE"))))
            conditions.append(
                RuntimeSourceCondition(
                    role,
                    result.observation_started_at,
                    result.observation_received_through,
                    min(
                        expiry,
                        *(
                            instant + timedelta(seconds=ReconciliationPolicy().freshness_seconds)
                            for instant in (
                                result.observation_started_at,
                                result.observation_received_through,
                                result.completed_at,
                            )
                        ),
                    ),
                    context.reconciliation_sequence,
                    "available" if not reasons else "unavailable",
                    reasons,
                )
            )
    if context.market is not None:
        closure = context.market.closure
        by_id = {item.observation_id: item for item in context.market.state.observations}
        if type(closure) is ContinuousForwardClosure:
            observations = [by_id[identity] for identity in closure.observation_ids]
            selected = [
                item
                for item in observations
                if isinstance(item.payload, DailyPrice)
                and item.payload.session == batch.target.trigger.source_session
            ]
            if (
                selected
                and {item.payload.instrument_id for item in selected}
                == {item[0] for item in context.checkpoint.inputs.spec.instruments}
                and all(isinstance(item.availability, CaptureReceipt) for item in selected)
            ):
                source_at = next(
                    session.closes_at
                    for session in context.checkpoint.inputs.spec.calendar.sessions
                    if session.session_label == batch.target.trigger.source_session
                )
                received_at = max(
                    cast(CaptureReceipt, item.availability).validated_at for item in selected
                )
                conditions.append(
                    RuntimeSourceCondition(
                        "daily_inputs",
                        source_at,
                        received_at,
                        batch.target.expires_at,
                        max(item.revision for item in selected),
                        "available",
                        (),
                    )
                )
        elif type(closure) is ContinuousQuoteClosure:
            observed = [by_id[item.observation_id] for item in closure.selections]
            clock = context.operating.clock if context.quote_clock is None else context.quote_clock
            # The original quote cutoff's UTC/monotonic/boot tuple must come
            # from the actual retained sampler, never a DTO-only assertion.
            clock_matches = (
                clock.observed_at_utc == closure.admitted_at
                and clock.observed_monotonic_ns == closure.admitted_monotonic_ns
                and clock.epoch == closure.boot_id
            )
            if observed and all(
                isinstance(item.payload, ForwardQuote)
                and isinstance(item.availability, CaptureReceipt)
                and item.payload.bid_at is not None
                and item.payload.ask_at is not None
                for item in observed
            ):
                side_times = [
                    at
                    for item in observed
                    for at in (
                        cast(ForwardQuote, item.payload).bid_at,
                        cast(ForwardQuote, item.payload).ask_at,
                    )
                    if at is not None
                ]
                receipts = [
                    cast(CaptureReceipt, item.availability).received_at for item in observed
                ]
                quote_expiry = min(
                    *(at + timedelta(seconds=5) for at in side_times),
                    *(at + timedelta(seconds=1) for at in receipts),
                    expiry,
                )
                reasons = () if clock_matches else ("ORIGINAL_QUOTE_CLOCK_TUPLE_DIFFERS",)
                conditions.append(
                    RuntimeSourceCondition(
                        "quotes",
                        min(side_times),
                        min(receipts),
                        quote_expiry,
                        max(item.revision for item in observed),
                        "available" if not reasons else "unavailable",
                        reasons,
                    )
                )
            # A quote capture does not establish daily signal dependencies.
            # Preserve an already authenticated prior decision's original
            # daily source condition only for that same exact trigger.
            matching = [
                decision
                for decision in context.checkpoint.runtime_decisions
                if decision.batch.target.trigger == batch.target.trigger
            ]
            if matching:
                old = [
                    source
                    for source in matching[-1].evidence.inputs.sources
                    if source.spec.role == "daily_inputs"
                ]
                if len(old) == 1:
                    source = old[0]
                    if source.spec != next(
                        spec
                        for spec in original.producer_map.producers
                        if spec.role == "daily_inputs"
                    ):
                        return tuple(conditions)
                    conditions.append(
                        RuntimeSourceCondition(
                            "daily_inputs",
                            source.source_at,
                            source.received_at,
                            source.valid_until,
                            source.revision,
                            source.status,
                            source.reasons,
                        )
                    )
    return tuple(conditions)
