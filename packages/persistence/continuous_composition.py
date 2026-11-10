"""Compose sole-engine checkpoints with actual retained daily risk admissions.

The same required runtime producer owns current and historical source semantics.
All replay and private-object work is detached; final SQL rechecks original rows
and invokes the actual daily risk store. Observed hold revisions retain their
original canonical financial source. This composer never dispatches or
manufactures a historical fence receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Protocol, TypeVar, cast
from weakref import WeakValueDictionary, finalize

if TYPE_CHECKING:
    from packages.persistence.continuous_integrity import (
        SqlContinuousIntegrityReader,
        _OriginalDailyEpisode,
    )

from sqlalchemy import Connection, Engine

from packages.application.causal_engine import continuous_runtime_action_context
from packages.application.continuous_account_transition import PreparedContinuousTransition
from packages.application.continuous_quote_frontier import project_continuous_quote_frontier
from packages.application.continuous_reconciliation_publication import (
    validate_continuous_application_times,
)
from packages.application.continuous_source_events import (
    compile_continuous_bootstrap,
    project_continuous_daily_frontier,
)
from packages.application.continuous_venue_frontier import project_continuous_venue_frontier
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.accounting_contracts import ActivateRuntimeCommitments, ExecutionAccountingPort
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_composition_contracts import (
    COMPOSITION_EVIDENCE_SCHEMA,
    FORWARD_CLOSURE_SCHEMA,
    SYNTHETIC_BOOTSTRAP_SCHEMA,
    VENUE_CAPTURE_CLOSURE_SCHEMA,
    ContinuousAdmissionReference,
    ContinuousCompositionEvidence,
    SyntheticContinuousBootstrap,
)
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousAccountCommit,
    ContinuousAccountReceipt,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_quote_contracts import (
    CONTINUOUS_QUOTE_CLOSURE_SCHEMA,
    ContinuousQuoteClosure,
)
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.continuous_runtime_action import ContinuousRuntimeAction
from packages.domain.continuous_runtime_attempt_contracts import RUNTIME_ATTEMPT_SOURCE_SCHEMA
from packages.domain.daily_attempt_contracts import DailyAttemptEnvelope
from packages.domain.daily_observed_hold_contracts import (
    DailyObservedHoldResult,
    RuntimeObservedHoldInputs,
    daily_runtime_attempt_prefix,
    daily_runtime_effect_watermark,
)
from packages.domain.daily_runtime_contracts import RuntimeObligationInventory
from packages.domain.personal_contracts import content_digest
from packages.domain.reconciliation_contracts import FactApplication, ReconciliationHeads
from packages.domain.research_job_contracts import ResearchArtifactStore, ResearchRecordCodec
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.continuous_account import (
    ContinuousCompositionPlan,
    ContinuousCompositionSnapshot,
    PreparedContinuousCommit,
    PreparedContinuousComposition,
    ResolvedContinuousAccount,
    ResolvedContinuousComposition,
)
from packages.persistence.continuous_forward_sources import (
    ResolvedContinuousForwardSources,
    SqlContinuousForwardSources,
)
from packages.persistence.continuous_venue_sources import (
    ResolvedContinuousVenueSources,
    SqlContinuousVenueSources,
)
from packages.persistence.daily_runtime_risk import (
    DailyAttemptMutationResult,
    HistoricalDailyAdmissionSnapshot,
    PreparedDailyAdmission,
    PreparedDailyAttemptMutation,
    PreparedDailyObservedHolds,
    ResolvedDailyRuntimeSnapshot,
    ResolvedHistoricalDailyAdmission,
    RetainedDailyAdmission,
    RetainedDailyAttemptGroup,
    RetainedDailyObservedHolds,
    RuntimeAttemptAccountingSource,
    RuntimeProducerRawSnapshot,
    RuntimeProducerReader,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    SqlDailyRuntimeRisk,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.schema import phase5_operational_control_transitions


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContinuousProducerPlan:
    reference: ContinuousEvidenceRef
    record_sha256: str
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContinuousProducerSnapshot:
    reference: ContinuousEvidenceRef
    record_sha256: str
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedContinuousProducerClosure:
    reference: ContinuousEvidenceRef
    record_sha256: str
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


class ContinuousHistoricalRuntimeProducer(RuntimeProducerReader, Protocol):
    """Additional methods on the SAME actual RuntimeProducerReader object.

    Every returned token must be owned by that exact producer instance. A copied
    seal/record is not authority. Historical resolution validates original role
    values and immutable source/journal closure without requiring mutable heads
    to remain current or creating an AccountFenceReceipt from supplied fields.
    """

    def retain_admission_sources(
        self,
        view: RetainedDailyAdmission,
        *,
        snapshot: RuntimeProducerRawSnapshot,
    ) -> ContinuousEvidenceRef: ...

    def prepare_admission_source_read(
        self,
        reference: ContinuousEvidenceRef,
        *,
        record_sha256: str,
        previous: ResolvedContinuousAccount | None,
    ) -> ContinuousProducerPlan: ...

    def capture_admission_sources_in_transaction(
        self,
        connection: Connection,
        plan: ContinuousProducerPlan,
    ) -> ContinuousProducerSnapshot: ...

    def resolve_admission_sources(
        self,
        snapshot: ContinuousProducerSnapshot,
        *,
        admission: RetainedDailyAdmission,
        previous: ResolvedContinuousAccount | None,
    ) -> ResolvedContinuousProducerClosure: ...

    def recheck_admission_sources_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedContinuousProducerClosure,
    ) -> None: ...


class ContinuousCompositionError(ValueError):
    """Static composition boundary codes; no private dependency diagnostics."""


@dataclass(frozen=True, slots=True)
class _Sources:
    reference: ContinuousEvidenceRef
    value: (
        SyntheticContinuousBootstrap
        | ContinuousForwardClosure
        | ContinuousQuoteClosure
        | RetainedVenueCapture
        | RuntimeAttemptAccountingSource
    )
    captured: ResolvedContinuousForwardSources | ResolvedContinuousVenueSources | None


@dataclass(frozen=True, slots=True)
class _Prepared:
    checkpoint_sha256: str
    sources: _Sources
    current: ResolvedDailyRuntimeSnapshot
    evidence: ContinuousCompositionEvidence
    admissions: tuple[PreparedDailyAdmission, ...]
    views: tuple[RetainedDailyAdmission, ...]
    observed_holds: PreparedDailyObservedHolds | None = None
    attempts: PreparedDailyAttemptMutation | None = None


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousCompositionView:
    """Owned detached preparation inspection, never a caller-created authority."""

    composition: PreparedContinuousComposition
    current: ResolvedDailyRuntimeSnapshot
    evidence: ContinuousCompositionEvidence
    venue: ResolvedContinuousVenueSources
    state: object = field(repr=False, compare=False)
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _Plan:
    commit: ContinuousAccountCommit
    sources: _Sources
    evidence: ContinuousCompositionEvidence
    current: ResolvedDailyRuntimeSnapshot
    producer_plans: tuple[ContinuousProducerPlan, ...]
    observed_holds: RetainedDailyObservedHolds | None = None
    attempts: RetainedDailyAttemptGroup | None = None


@dataclass(frozen=True, slots=True)
class _Captured:
    plan: ContinuousCompositionPlan
    admissions: tuple[HistoricalDailyAdmissionSnapshot, ...]
    producers: tuple[ContinuousProducerSnapshot, ...]
    controls: RuntimeTableSnapshot


@dataclass(frozen=True, slots=True)
class _Resolved:
    sources: _Sources
    evidence: ContinuousCompositionEvidence
    admissions: tuple[ResolvedHistoricalDailyAdmission, ...]
    producers: tuple[ResolvedContinuousProducerClosure, ...]
    control_rows: tuple[dict[str, Any], ...]
    observed_holds: RetainedDailyObservedHolds | None = None
    attempts: RetainedDailyAttemptGroup | None = None


def _inventory(bindings: tuple[Any, ...]) -> RuntimeObligationInventory:
    ordered = tuple(sorted(bindings, key=lambda item: item.commitment.commitment_id))
    return RuntimeObligationInventory(
        bindings=ordered,
        legacy_universe_sha256=content_digest(
            tuple(b for b in ordered if b.origin == "legacy_phase2")
        ),
        daily_universe_sha256=content_digest(
            tuple(b for b in ordered if b.origin == "daily_runtime")
        ),
    )


Owned = TypeVar("Owned")


class SqlContinuousCommitComposer:
    def __init__(
        self,
        engine: Engine,
        *,
        daily: SqlDailyRuntimeRisk,
        coordinator: SqlAccountCoordinator,
        forward_sources: SqlContinuousForwardSources,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
        producer_history: ContinuousHistoricalRuntimeProducer,
        fence: AccountFence,
        benchmark_instrument_id: str | None,
        venue_sources: SqlContinuousVenueSources | None = None,
        accounting: ExecutionAccountingPort | None = None,
    ) -> None:
        if (
            type(daily) is not SqlDailyRuntimeRisk
            or type(coordinator) is not SqlAccountCoordinator
            or type(forward_sources) is not SqlContinuousForwardSources
            or daily.engine is not engine
            or forward_sources.engine is not engine
            or daily.coordinator is not coordinator
            or coordinator.account_id != fence.account_id
            or daily.producers is not producer_history
        ):
            raise ContinuousCompositionError("EXACT_CONTINUOUS_COMPOSITION_DEPENDENCIES_REQUIRED")
        for name in (
            "retain_admission_sources",
            "prepare_admission_source_read",
            "capture_admission_sources_in_transaction",
            "resolve_admission_sources",
            "recheck_admission_sources_in_transaction",
        ):
            if not callable(getattr(producer_history, name, None)):
                raise ContinuousCompositionError("EXPLICIT_HISTORICAL_PRODUCER_REQUIRED")
        if venue_sources is not None and (
            type(venue_sources) is not SqlContinuousVenueSources
            or venue_sources.engine is not engine
            or venue_sources.scope.account_id != fence.account_id
            or accounting is None
        ):
            raise ContinuousCompositionError("EXACT_VENUE_COMPOSITION_DEPENDENCIES_REQUIRED")
        self.venue_sources, self.accounting = venue_sources, accounting
        self.engine, self.daily, self.coordinator = engine, daily, coordinator
        self.forward_sources, self.artifacts, self.codec = forward_sources, artifacts, codec
        self.producer_history, self.fence = producer_history, fence
        self.benchmark_instrument_id = benchmark_instrument_id
        self._seal = object()
        self._fingerprints: dict[int, str] = {}
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._owned_fields: dict[int, tuple[object, ...]] = {}
        self._state_fields: dict[int, tuple[tuple[object, tuple[object, ...]], ...]] = {}
        self._integrity_daily: tuple[SqlContinuousIntegrityReader, _OriginalDailyEpisode] | None = (
            None
        )
        self._integrity_daily_active: _OriginalDailyEpisode | None = None

    def _own(self, value: Owned) -> Owned:
        self._owned[id(value)] = value
        self._owned_fields[id(value)] = tuple(
            getattr(value, f.name) for f in fields(cast(Any, value))
        )
        state = cast(Any, value).state
        guarded = [state]
        if isinstance(state, (_Prepared, _Plan, _Resolved)):
            guarded.extend((state.sources, state.evidence))
        self._state_fields[id(value)] = tuple(
            (item, tuple(getattr(item, f.name) for f in fields(item))) for item in guarded
        )
        finalize(value, self._owned_fields.pop, id(value), None)
        finalize(value, self._state_fields.pop, id(value), None)
        return value

    def _require(self, value: Any, kind: type[Any]) -> None:
        if (
            type(value) is not kind
            or value.seal is not self._seal
            or id(value) not in self._owned
            or self._owned[id(value)] is not value
        ):
            raise ContinuousCompositionError("OWNED_CONTINUOUS_COMPOSITION_REQUIRED")
        if any(
            getattr(value, f.name) is not original
            for f, original in zip(
                fields(value),
                self._owned_fields[id(value)],
                strict=True,
            )
        ):
            raise ContinuousCompositionError("CONTINUOUS_COMPOSITION_TOKEN_CHANGED")
        for item, originals in self._state_fields[id(value)]:
            if any(
                getattr(item, f.name) is not original
                for f, original in zip(fields(cast(Any, item)), originals, strict=True)
            ):
                raise ContinuousCompositionError("CONTINUOUS_COMPOSITION_STATE_CHANGED")

    def _read(self, reference: ContinuousEvidenceRef, kind: type[Any]) -> Any:
        raw = self.artifacts.read(reference.object_ref, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
        if (
            type(raw) is not bytes
            or len(raw) != reference.object_ref.byte_count
            or (sha256(raw).hexdigest() != reference.object_ref.object_sha256)
        ):
            raise ContinuousCompositionError("COMPOSITION_OBJECT_BYTES_DIFFER")
        value = self.codec.decode_record(raw, kind)
        if (
            type(value) is not kind
            or self.codec.encode_record(value) != raw
            or (value.semantic_sha256 != reference.semantic_sha256)
        ):
            raise ContinuousCompositionError("COMPOSITION_OBJECT_SEMANTICS_DIFFER")
        return value

    def _sources(self, reference: ContinuousEvidenceRef) -> _Sources:
        if reference.schema_id == RUNTIME_ATTEMPT_SOURCE_SCHEMA:
            return _Sources(reference, self._read(reference, RuntimeAttemptAccountingSource), None)
        if reference.schema_id == SYNTHETIC_BOOTSTRAP_SCHEMA:
            if self.forward_sources.evidence_class != "synthetic_fixture":
                raise ContinuousCompositionError("SYNTHETIC_SOURCE_CANNOT_PROMOTE_PROVIDER")
            value = self._read(reference, SyntheticContinuousBootstrap)
            return _Sources(reference, value, None)
        if reference.schema_id == VENUE_CAPTURE_CLOSURE_SCHEMA:
            if self.venue_sources is None:
                raise ContinuousCompositionError("VENUE_SOURCE_RESOLVER_REQUIRED")
            value = self._read(reference, RetainedVenueCapture)
            return _Sources(reference, value, self.venue_sources.resolve(value))
        if reference.schema_id == CONTINUOUS_QUOTE_CLOSURE_SCHEMA:
            quote = self._read(reference, ContinuousQuoteClosure)
            return _Sources(reference, quote, self.forward_sources.resolve(quote))
        if reference.schema_id != FORWARD_CLOSURE_SCHEMA:
            raise ContinuousCompositionError("CONTINUOUS_SOURCE_SCHEMA_UNSUPPORTED")
        closure = self._read(reference, ContinuousForwardClosure)
        captured = self.forward_sources.resolve(closure)
        return _Sources(reference, closure, captured)

    def _source_request(
        self,
        sources: _Sources,
        request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction,
        *,
        previous: ResolvedContinuousAccount | None,
        checkpoint: CausalEngineCheckpoint,
        source_closure_sha256: str,
    ) -> None:
        if type(request) is ContinuousRuntimeAction:
            if (
                previous is None
                or type(sources.value) is not RuntimeAttemptAccountingSource
                or sources.reference.semantic_sha256 != source_closure_sha256
                or request.source_closure_sha256 != source_closure_sha256
                or request.previous_checkpoint_sha256 != previous.checkpoint.semantic_sha256
                or checkpoint.inputs != previous.checkpoint.inputs
                or request.checked_at != sources.value.checked_at
            ):
                raise ContinuousCompositionError("EXACT_RUNTIME_ACTION_SOURCE_REQUIRED")
            return
        if type(sources.value) is RuntimeAttemptAccountingSource:
            raise ContinuousCompositionError("ATTEMPT_SOURCE_REQUIRES_INTERNAL_RUNTIME_ACTION")
        if type(sources.value) is SyntheticContinuousBootstrap:
            if (
                previous is not None
                or request != sources.value.inputs
                or (source_closure_sha256 != sources.value.semantic_sha256)
            ):
                raise ContinuousCompositionError("EXACT_SYNTHETIC_INITIALIZATION_REQUIRED")
            return
        if type(sources.value) is ContinuousQuoteClosure:
            if previous is None or type(request) is not ClosedEngineFrontier:
                raise ContinuousCompositionError("AUTHENTICATED_QUOTE_PREVIOUS_REQUIRED")
            assert type(sources.captured) is ResolvedContinuousForwardSources
            self.forward_sources.require_resolved(sources.captured)
            compiled_quote = project_continuous_quote_frontier(
                checkpoint=previous.checkpoint,
                closure=sources.value,
                source_state=sources.captured.state,
            )
            if (
                compiled_quote != request
                or request.source_frontier_sha256 != source_closure_sha256
                or checkpoint.inputs != previous.checkpoint.inputs
            ):
                raise ContinuousCompositionError("EXACT_CAPTURED_QUOTE_FRONTIER_REQUIRED")
            return
        if type(sources.value) is RetainedVenueCapture:
            if previous is None or type(request) is not ClosedEngineFrontier:
                raise ContinuousCompositionError("AUTHENTICATED_VENUE_PREVIOUS_REQUIRED")
            assert self.venue_sources is not None and self.accounting is not None
            assert type(sources.captured) is ResolvedContinuousVenueSources
            self.venue_sources.require_resolved(sources.captured)
            if (
                len(request.events) != 1
                or type(request.events[0].payload) is not ContinuousReconciliationBatch
            ):
                raise ContinuousCompositionError("EXACT_VENUE_BATCH_FRONTIER_REQUIRED")
            batch = request.events[0].payload
            validate_continuous_application_times(
                previous.checkpoint,
                capture=sources.value,
                applications=batch.prior_applications,
                accounting=self.accounting,
            )
            expected = project_continuous_venue_frontier(
                checkpoint=previous.checkpoint,
                capture=sources.value,
                prior_applications=batch.prior_applications,
                frontier_id=request.frontier_id,
                admitted_at=request.knowledge_at,
            )
            if (
                expected != request
                or request.source_frontier_sha256 != source_closure_sha256
                or checkpoint.inputs != previous.checkpoint.inputs
            ):
                raise ContinuousCompositionError("EXACT_RETAINED_VENUE_FRONTIER_REQUIRED")
            return
        closure, captured = sources.value, sources.captured
        assert isinstance(closure, ContinuousForwardClosure)
        assert type(captured) is ResolvedContinuousForwardSources
        self.forward_sources.require_resolved(captured)
        if closure.account_id != self.fence.account_id:
            raise ContinuousCompositionError("CAPTURED_SOURCE_ACCOUNT_DIFFERS")
        if isinstance(request, ContinuousEngineInputs):
            compiled = compile_continuous_bootstrap(
                request.spec,
                captured.state,
                closure.observation_ids,
                closure.admitted_at,
                benchmark_instrument_id=self.benchmark_instrument_id,
                capture_evidence_class=closure.evidence_class,
            )
            if (
                previous is not None
                or compiled != request
                or source_closure_sha256 != closure.semantic_sha256
            ):
                raise ContinuousCompositionError("EXACT_CAPTURED_INITIALIZATION_REQUIRED")
        else:
            if previous is None:
                raise ContinuousCompositionError("AUTHENTICATED_PREVIOUS_CHECKPOINT_REQUIRED")
            compiled_frontier = project_continuous_daily_frontier(
                checkpoint=previous.checkpoint,
                source_state=captured.state,
                observation_ids=closure.observation_ids,
                frontier_id=closure.closure_id,
                admitted_at=closure.admitted_at,
                benchmark_instrument_id=self.benchmark_instrument_id,
                capture_evidence_class=closure.evidence_class,
            )
            if (
                compiled_frontier != request
                or request.source_frontier_sha256 != source_closure_sha256
            ):
                raise ContinuousCompositionError("EXACT_CAPTURED_FRONTIER_REQUIRED")
        if checkpoint.inputs != (
            request
            if isinstance(request, ContinuousEngineInputs)
            else cast(ResolvedContinuousAccount, previous).checkpoint.inputs
        ):
            raise ContinuousCompositionError("CONTINUOUS_SOURCE_STREAM_INPUTS_DIFFER")

    def _current(self) -> ResolvedDailyRuntimeSnapshot:
        return self.daily.resolve_snapshot(
            self.daily.read_snapshot(
                account_id=self.fence.account_id,
                fence=self.fence,
            )
        )

    def _bind_integrity_daily(
        self, reader: SqlContinuousIntegrityReader, episode: _OriginalDailyEpisode
    ) -> None:
        from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader

        if (
            type(reader) is not SqlContinuousIntegrityReader
            or self._integrity_daily is not None
            or self._integrity_daily_active is not None
        ):
            raise ContinuousCompositionError("ORIGINAL_INTEGRITY_DAILY_BINDING_REQUIRED")
        reader._require_daily_episode(episode)
        if episode.composer is not self:
            raise ContinuousCompositionError("ORIGINAL_INTEGRITY_COMPOSER_REQUIRED")
        self._integrity_daily = (reader, episode)
        self._integrity_daily_active = episode

    def _require_integrity_daily(
        self, reader: SqlContinuousIntegrityReader, episode: _OriginalDailyEpisode
    ) -> None:
        binding = self._integrity_daily
        if (
            type(binding) is not tuple
            or len(binding) != 2
            or binding[0] is not reader
            or binding[1] is not episode
            or self._integrity_daily_active is not episode
            or episode.composer is not self
        ):
            raise ContinuousCompositionError("ORIGINAL_INTEGRITY_DAILY_BINDING_CHANGED")

    def _unbind_integrity_daily(
        self, reader: SqlContinuousIntegrityReader, episode: _OriginalDailyEpisode
    ) -> None:
        binding = self._integrity_daily
        if (
            type(binding) is tuple
            and len(binding) == 2
            and binding[0] is reader
            and binding[1] is episode
        ):
            self._integrity_daily = None
        if self._integrity_daily_active is episode:
            self._integrity_daily_active = None

    def _historical_current(self) -> ResolvedDailyRuntimeSnapshot:
        from packages.persistence.continuous_integrity import (
            SqlContinuousIntegrityReader,
            _OriginalDailyEpisode,
        )

        binding = self._integrity_daily
        active = self._integrity_daily_active
        if binding is None and active is None:
            return self._current()
        candidates: list[tuple[SqlContinuousIntegrityReader, _OriginalDailyEpisode]] = []
        if (
            type(active) is _OriginalDailyEpisode
            and type(active.reader) is SqlContinuousIntegrityReader
        ):
            candidates.append((active.reader, active))
        if (
            type(binding) is tuple
            and len(binding) == 2
            and type(binding[0]) is SqlContinuousIntegrityReader
            and type(binding[1]) is _OriginalDailyEpisode
        ):
            candidates.append(binding)
        owned: list[tuple[SqlContinuousIntegrityReader, _OriginalDailyEpisode]] = []
        for reader, episode in candidates:
            if reader._owned_daily_episode_for(episode, consumer=self) is not None and not any(
                reader is prior_reader and episode is prior_episode
                for prior_reader, prior_episode in owned
            ):
                owned.append((reader, episode))
        if len(owned) != 1:
            raise ContinuousCompositionError("ORIGINAL_INTEGRITY_DAILY_BINDING_REQUIRED")
        # Neither slot's type is authority. The actual original owner performs
        # every guard and latches any binding mismatch before a financial read.
        reader, episode = owned[0]
        return reader._borrow_original_daily(episode, consumer=self)

    @staticmethod
    def _control_prefix(
        snapshot: RuntimeTableSnapshot, revision: int
    ) -> tuple[dict[str, Any], ...]:
        return tuple(
            dict(row)
            for row in sorted(snapshot.rows, key=lambda r: r["sequence_number"])
            if row["sequence_number"] <= revision
        )

    @staticmethod
    def _controls(current: ResolvedDailyRuntimeSnapshot) -> RuntimeTableSnapshot:
        return next(
            t for t in current.raw.tables if t.table is phase5_operational_control_transitions
        )

    @staticmethod
    def _heads(
        checkpoint: CausalEngineCheckpoint | None,
        obligations: RuntimeObligationInventory,
        control_revision: int,
        generation: int,
        effect_watermark: int = 0,
        attempt_sha256: str | None = None,
    ) -> ReconciliationHeads:
        # ContinuousEngineInputs rejects every nonempty genesis AccountingState.
        return ReconciliationHeads(
            content_digest(())
            if checkpoint is None
            else checkpoint.current.snapshot.journal_sha256,
            content_digest(()) if checkpoint is None else checkpoint.current.snapshot.order_sha256,
            obligations.semantic_sha256,
            effect_watermark,
            daily_attempt_inventory_sha256(()) if attempt_sha256 is None else attempt_sha256,
            control_revision,
            generation,
        )

    @staticmethod
    def _commitments(
        checkpoint: CausalEngineCheckpoint | None, inventory: RuntimeObligationInventory
    ) -> None:
        expected = () if checkpoint is None else checkpoint.state.commitments
        retained = tuple(b.commitment for b in inventory.bindings)
        if tuple(sorted(expected, key=lambda c: c.commitment_id)) != retained:
            raise ContinuousCompositionError("CANONICAL_CONTINUOUS_HOLD_INVENTORY_DIFFERS")

    def _match(
        self,
        decisions: tuple[Any, ...],
        views: tuple[RetainedDailyAdmission, ...],
        *,
        checkpoint: CausalEngineCheckpoint,
        before: RuntimeObligationInventory,
        expected: ReconciliationHeads,
    ) -> RuntimeObligationInventory:
        assert isinstance(checkpoint.inputs, ContinuousEngineInputs)
        if len(decisions) > 1 or len(views) != len(decisions):
            raise ContinuousCompositionError("ONE_EXACT_ATOMIC_ADMISSION_PER_DECISION_REQUIRED")
        bindings = list(before.bindings)
        for decision, view in zip(decisions, views, strict=True):
            self.daily.require_admission_view(view)
            resolved = view.resolved
            evidence = view.admission.evidence
            if (
                decision.evidence != evidence
                or decision.decision != view.admission.decision
                or decision.batch != view.admission.decision.batch
                or decision.source_state != resolved.state
                or decision.source_context != resolved.context
                or decision.snapshot != resolved.snapshot
                or decision.installed_commitments != view.prepared_commitments
                or resolved.execution_policy != checkpoint.inputs.spec.execution_policy
                or resolved.inputs.obligations != before
                or evidence.assignment.account_id != checkpoint.inputs.spec.account_id
                or evidence.assignment.account_binding_sha256
                != checkpoint.inputs.spec.account_binding_sha256
                or evidence.assignment.policy != checkpoint.inputs.spec.risk_policy
                or evidence.assignment.strategy != checkpoint.inputs.spec.strategy
                or evidence.assignment.configuration_sha256
                != content_digest(checkpoint.inputs.spec.strategy_configuration)
                or decision.disposition == "rolled_back"
            ):
                raise ContinuousCompositionError("CANONICAL_DECISION_ADMISSION_DIFFERS")
            # Decision's mark/order projection can advance within this frontier;
            # its actual ledger/order hashes are bound by the retained snapshot.
            heads = resolved.inputs.heads
            if (
                heads.ledger_sha256 != decision.snapshot.journal_sha256
                or heads.order_sha256 != decision.snapshot.order_sha256
                or heads.capacity_sha256 != before.semantic_sha256
                or heads.control_revision != expected.control_revision
                or heads.lease_generation != expected.lease_generation
                or heads.effect_watermark != expected.effect_watermark
                or heads.attempt_sha256 != expected.attempt_sha256
            ):
                raise ContinuousCompositionError("ACTUAL_RUNTIME_HEADS_DIFFER")
            bindings.extend(view.bindings)
        after = _inventory(tuple(bindings))
        self._commitments(checkpoint, after)
        return after

    def _put(self, schema: str, value: Any) -> ContinuousEvidenceRef:
        raw = self.codec.encode_record(value)
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTINUOUS_OBJECT_BYTES:
            raise ContinuousCompositionError("CONTINUOUS_EVIDENCE_BYTES_BOUND")
        reference = ContinuousEvidenceRef(schema, self.artifacts.put(raw), value.semantic_sha256)
        self._read(reference, type(value))
        return reference

    def _observed_match(
        self,
        inputs: RuntimeObservedHoldInputs,
        result: DailyObservedHoldResult,
        *,
        previous: ResolvedContinuousAccount | None,
        checkpoint: CausalEngineCheckpoint,
        request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction,
        source: ContinuousEvidenceRef,
        command_id: str,
        expected: ReconciliationHeads,
        before: RuntimeObligationInventory,
        applications: tuple[FactApplication, ...],
    ) -> RuntimeObligationInventory:
        """Bind B's authenticated original financial result to this exact C step."""
        original = inputs.source
        if previous is None or (
            original.scope != previous.receipt.commit.scope
            or original.coordinator_command_id != command_id
            or original.coordinator_sequence != previous.receipt.commit.sequence + 1
            or original.coordinator_command_id != result.coordinator_command_id
            or original.coordinator_sequence != result.coordinator_sequence
            or original.previous_checkpoint.object_ref
            != previous.receipt.commit.transition.checkpoint
            or original.previous_checkpoint.semantic_sha256 != previous.checkpoint.semantic_sha256
            or original.resulting_checkpoint.semantic_sha256 != checkpoint.semantic_sha256
            or inputs.previous != previous.checkpoint
            or inputs.resulting != checkpoint
            or inputs.frontier != request
            or original.frontier.semantic_sha256 != request.semantic_sha256
            or original.venue_capture != source
            or source.schema_id != VENUE_CAPTURE_CLOSURE_SCHEMA
            or original.source_closure_sha256 != inputs.frontier.source_frontier_sha256
            or original.heads != expected
            or original.execution_policy != checkpoint.inputs.spec.execution_policy
            or original.applied_at != checkpoint.now
            or result.accounting_state_sha256 != checkpoint.state.semantic_sha256
            or result.before != before
            or tuple(ref.semantic_sha256 for ref in original.application_batches)
            != tuple(batch.semantic_sha256 for batch in inputs.application_batches)
            or tuple(
                sorted(
                    {
                        item.fact_id: item
                        for batch in inputs.application_batches
                        for item in batch.applications
                    }.values(),
                    key=lambda item: item.fact_id,
                )
            )
            != applications
        ):
            raise ContinuousCompositionError("EXACT_CANONICAL_OBSERVED_HOLD_SOURCE_REQUIRED")
        self._commitments(checkpoint, result.after)
        return result.after

    def _attempt_match(
        self,
        source: RuntimeAttemptAccountingSource,
        result: DailyAttemptMutationResult,
        envelopes: tuple[DailyAttemptEnvelope, ...],
        *,
        previous: ResolvedContinuousAccount | None,
        checkpoint: CausalEngineCheckpoint,
        request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction,
        reference: ContinuousEvidenceRef,
        command_id: str,
        expected: ReconciliationHeads,
        before: RuntimeObligationInventory,
    ) -> RuntimeObligationInventory:
        if previous is None or type(request) is not ContinuousRuntimeAction:
            raise ContinuousCompositionError("OWNED_RUNTIME_ACTION_PREDECESSOR_REQUIRED")
        # The actual B reader authenticates source closure and replays this entire
        # event group; the composer binds that result to the sole engine result.
        if (
            source.account_id != previous.receipt.commit.scope.account_id
            or source.coordinator_command_id != command_id
            or source.coordinator_sequence != previous.receipt.commit.sequence + 1
            or (result.coordinator_command_id, result.coordinator_sequence)
            != (command_id, source.coordinator_sequence)
            or source.state != previous.checkpoint.state
            or source.obligations != before
            or source.heads != expected
            or source.execution_policy != checkpoint.inputs.spec.execution_policy
            or source.semantic_sha256 != reference.semantic_sha256
            or reference.schema_id != RUNTIME_ATTEMPT_SOURCE_SCHEMA
            or request.action_id != command_id
            or request.stream_id != previous.checkpoint.inputs.spec.run_id
            or request.command != source.accounting_command
            or request.checked_at != source.checked_at
            or checkpoint.now != source.checked_at
            or result.accounting_state != checkpoint.state
            or not envelopes
            or any(
                (
                    item.account_id,
                    item.coordinator_command_id,
                    item.coordinator_sequence,
                    item.source_ref,
                    item.event.recorded_at,
                )
                != (
                    source.account_id,
                    command_id,
                    source.coordinator_sequence,
                    reference,
                    source.checked_at,
                )
                for item in envelopes
            )
            or (
                request.command is None
                and request.attempt_events != tuple(item.event for item in envelopes)
            )
        ):
            raise ContinuousCompositionError("EXACT_CANONICAL_ATTEMPT_RESULT_REQUIRED")
        if source.context != continuous_runtime_action_context(
            previous.checkpoint,
            command_id=command_id if request.command is None else request.command.command_id,
            activation=request.command is not None
            and isinstance(request.command.payload, ActivateRuntimeCommitments),
            checked_at=source.checked_at,
        ):
            raise ContinuousCompositionError("ORIGINAL_RUNTIME_ACTION_CONTEXT_DIFFERS")
        if request.command is None:
            allowed = {"now", "processed", "closed_source_frontiers", "remaining_wall_nanoseconds"}
            prior = previous.checkpoint
            if (
                any(
                    getattr(checkpoint, item.name) != getattr(prior, item.name)
                    for item in fields(checkpoint)
                    if item.name not in allowed
                )
                or checkpoint.processed != prior.processed + 1
                or dict(checkpoint.closed_source_frontiers)
                != {
                    **dict(prior.closed_source_frontiers),
                    request.retained_id: request.semantic_sha256,
                }
            ):
                raise ContinuousCompositionError("METADATA_ACTION_CHANGED_CANONICAL_HISTORY")
        self._commitments(checkpoint, result.obligations)
        return result.obligations

    def prepare(
        self,
        transition: PreparedContinuousTransition,
        *,
        previous: ResolvedContinuousAccount | None,
        source_evidence: ContinuousEvidenceRef,
        admissions: tuple[PreparedDailyAdmission, ...],
        observed_holds: PreparedDailyObservedHolds | None = None,
        attempts: PreparedDailyAttemptMutation | None = None,
    ) -> PreparedContinuousComposition:
        checkpoint = transition.checkpoint
        if checkpoint.inputs.spec.account_id != self.fence.account_id:
            raise ContinuousCompositionError("CONTINUOUS_ACCOUNT_SCOPE_DIFFERS")
        sources = self._sources(source_evidence)
        self._source_request(
            sources,
            transition.request,
            previous=previous,
            checkpoint=checkpoint,
            source_closure_sha256=transition.source_closure_sha256,
        )
        applications: dict[str, FactApplication] = {}
        if type(sources.value) is RetainedVenueCapture:
            if transition.new_decisions or admissions:
                raise ContinuousCompositionError("VENUE_RECONCILIATION_ADMISSION_UNSUPPORTED")
            for batch in transition.application_batches:
                for application in batch.applications:
                    old = applications.setdefault(application.fact_id, application)
                    if old != application:
                        raise ContinuousCompositionError("ENGINE_APPLICATION_RECEIPT_CONFLICT")
            # Replaying the identical already-consumed capture emits no batch;
            # its original evidence remains the only accepted application set.
            if not transition.application_batches:
                assert previous is not None
                self.require_resolved(previous.composition)
                prior = previous.composition.state
                assert type(prior) is _Resolved
                if prior.sources.reference != source_evidence:
                    raise ContinuousCompositionError("MISSING_ACTUAL_APPLICATION_BATCH")
                applications = {a.fact_id: a for a in prior.evidence.applications}
            assert self.accounting is not None
            validate_continuous_application_times(
                checkpoint,
                capture=sources.value,
                applications=tuple(applications[key] for key in sorted(applications)),
                accounting=self.accounting,
            )
        elif transition.application_batches:
            raise ContinuousCompositionError("APPLICATION_BATCH_REQUIRES_VENUE_SOURCE")
        prior_checkpoint = None if previous is None else previous.checkpoint
        previous_sha = None if prior_checkpoint is None else prior_checkpoint.semantic_sha256
        prior_decisions = () if prior_checkpoint is None else prior_checkpoint.runtime_decisions
        if (
            transition.previous_checkpoint_sha256 != previous_sha
            or checkpoint.runtime_decisions != (*prior_decisions, *transition.new_decisions)
        ):
            raise ContinuousCompositionError("CONTINUOUS_DECISION_PREFIX_DIFFERS")
        if observed_holds is not None:
            self.daily.require_prepared_observed_holds(observed_holds)
            self.daily.require_resolved_snapshot(observed_holds.snapshot)
            if observed_holds.retry or admissions or transition.new_decisions:
                raise ContinuousCompositionError("FRESH_OBSERVED_HOLD_PREPARATION_REQUIRED")
        if attempts is not None:
            self.daily.require_prepared_attempt(attempts)
            self.daily.require_resolved_snapshot(attempts.snapshot)
            if (
                attempts.retry
                or observed_holds is not None
                or admissions
                or transition.new_decisions
            ):
                raise ContinuousCompositionError("FRESH_EXCLUSIVE_ATTEMPT_PREPARATION_REQUIRED")
        if (type(sources.value) is RuntimeAttemptAccountingSource) != (attempts is not None):
            raise ContinuousCompositionError("ACTUAL_ATTEMPT_SOURCE_PREPARATION_REQUIRED")
        current = (
            attempts.snapshot
            if attempts is not None
            else observed_holds.snapshot
            if observed_holds is not None
            else self._current()
        )
        before = current.obligations
        self._commitments(prior_checkpoint, before)
        revision = 0 if current.control is None else current.control.sequence_number
        watermark = daily_runtime_effect_watermark(
            attempt_envelopes=current.attempt_envelopes, observed_groups=current.observed_groups
        )
        expected = self._heads(
            prior_checkpoint,
            before,
            revision,
            self.fence.fencing_generation,
            watermark,
            daily_attempt_inventory_sha256(current.attempts),
        )
        if any(item.retry for item in admissions):
            raise ContinuousCompositionError("ORIGINAL_ACCOUNT_RETRY_REQUIRED")
        if any(item.valid_until is None for item in admissions):
            raise ContinuousCompositionError("ORIGINAL_ADMISSION_DEADLINE_REQUIRED")
        preparations = (
            *admissions,
            *((observed_holds,) if observed_holds is not None else ()),
            *((attempts,) if attempts is not None else ()),
        )
        if attempts is not None and attempts.valid_until is None:
            raise ContinuousCompositionError("ORIGINAL_ATTEMPT_DEADLINE_REQUIRED")
        if observed_holds is not None and observed_holds.valid_until is None:
            raise ContinuousCompositionError("ORIGINAL_OBSERVED_HOLD_DEADLINE_REQUIRED")
        valid_until = min(
            (item.valid_until for item in preparations if item.valid_until is not None),
            default=None,
        )
        views = tuple(self.daily.inspect_prepared_admission(item) for item in admissions)
        attempt_sha256 = expected.attempt_sha256
        if attempts is not None:
            assert type(sources.value) is RuntimeAttemptAccountingSource
            assert current.attempt_sources is not None
            if sources.value not in current.attempt_sources.sources:
                raise ContinuousCompositionError("ACTUAL_AUTHENTICATED_ATTEMPT_SOURCE_REQUIRED")
            after = self._attempt_match(
                sources.value,
                attempts.result,
                current.raw.requested_envelopes,
                previous=previous,
                checkpoint=checkpoint,
                request=transition.request,
                reference=source_evidence,
                command_id=transition.command_id,
                expected=expected,
                before=before,
            )
            watermark = attempts.result.coordinator_sequence
            attempt_sha256 = daily_attempt_inventory_sha256(attempts.result.attempts)
        elif observed_holds is None:
            after = self._match(
                transition.new_decisions,
                views,
                checkpoint=checkpoint,
                before=before,
                expected=expected,
            )
        else:
            assert current.observed_sources is not None
            source_ref = current.raw.requested_observed_source
            if source_ref is None:
                raise ContinuousCompositionError("ORIGINAL_OBSERVED_SOURCE_REFERENCE_REQUIRED")
            selected = tuple(
                item
                for item in current.observed_sources.inputs
                if item.source.semantic_sha256 == source_ref.semantic_sha256
            )
            if (
                len(selected) != 1
                or selected[0].application_batches != transition.application_batches
            ):
                raise ContinuousCompositionError("ORIGINAL_OBSERVED_APPLICATION_BATCHES_DIFFER")
            after = self._observed_match(
                selected[0],
                observed_holds.result,
                previous=previous,
                checkpoint=checkpoint,
                request=transition.request,
                source=source_evidence,
                command_id=transition.command_id,
                expected=expected,
                before=before,
                applications=tuple(applications[key] for key in sorted(applications)),
            )
            if observed_holds.result.group is not None:
                watermark = observed_holds.result.coordinator_sequence
        resulting = self._heads(
            checkpoint,
            after,
            revision,
            self.fence.fencing_generation,
            watermark,
            attempt_sha256,
        )
        refs = []
        for admission, view in zip(admissions, views, strict=True):
            ref = self.producer_history.retain_admission_sources(
                view, snapshot=admission.snapshot.raw.producer
            )
            if type(ref) is not ContinuousEvidenceRef:
                raise ContinuousCompositionError("RETAINED_TYPED_PRODUCER_REFERENCE_REQUIRED")
            refs.append(
                ContinuousAdmissionReference(
                    view.command_id,
                    view.request_sha256,
                    view.record_sha256,
                    view.payload_sha256,
                    view.admission.semantic_sha256,
                    content_digest(view.prepared_commitments),
                    ref,
                )
            )
        evidence = ContinuousCompositionEvidence(
            previous_sha,
            checkpoint.semantic_sha256,
            transition.new_decisions,
            tuple(refs),
            expected,
            resulting,
            before,
            after,
            current.control,
            self.benchmark_instrument_id,
            tuple(applications[key] for key in sorted(applications)),
            None if observed_holds is None else observed_holds.result.group,
            () if attempts is None else current.raw.requested_envelopes,
        )
        decision_ref = self._put(COMPOSITION_EVIDENCE_SCHEMA, evidence)
        return self._own(
            PreparedContinuousComposition(
                expected,
                resulting,
                source_evidence,
                decision_ref,
                tuple(c for view in views for c in view.prepared_commitments),
                _Prepared(
                    checkpoint.semantic_sha256,
                    sources,
                    current,
                    evidence,
                    admissions,
                    views,
                    observed_holds,
                    attempts,
                ),
                self._seal,
                valid_until,
            )
        )

    def require_prepared(self, value: PreparedContinuousComposition) -> None:
        self._require(value, PreparedContinuousComposition)
        state = value.state
        if type(state) is not _Prepared or (
            value.expected_heads != state.evidence.expected_heads
            or value.resulting_heads != state.evidence.resulting_heads
            or value.decision_evidence.semantic_sha256 != state.evidence.semantic_sha256
            or value.valid_until
            != min(
                (
                    a.valid_until
                    for a in (
                        *state.admissions,
                        *((state.observed_holds,) if state.observed_holds is not None else ()),
                        *((state.attempts,) if state.attempts is not None else ()),
                    )
                    if a.valid_until is not None
                ),
                default=None,
            )
            or value.source_evidence != state.sources.reference
            or value.installed_commitments
            != tuple(c for v in state.views for c in v.prepared_commitments)
        ):
            raise ContinuousCompositionError("PREPARED_CONTINUOUS_EVIDENCE_CHANGED")
        self._require_sources(state.sources)
        self.daily.require_resolved_snapshot(state.current)
        for admission in state.admissions:
            self.daily.require_prepared_admission(admission)
        for view in state.views:
            self.daily.require_admission_view(view)
        if state.observed_holds is not None:
            self.daily.require_prepared_observed_holds(state.observed_holds)
            self.daily.require_resolved_snapshot(state.observed_holds.snapshot)
        if state.attempts is not None:
            self.daily.require_prepared_attempt(state.attempts)
            self.daily.require_resolved_snapshot(state.attempts.snapshot)

    def inspect_prepared_attempt(
        self, value: PreparedContinuousComposition
    ) -> PreparedDailyAttemptMutation:
        """Inspect the original owned B preparation; this is not delivery authority."""
        self.require_prepared(value)
        state = value.state
        assert type(state) is _Prepared
        if state.attempts is None:
            raise ContinuousCompositionError("ACTUAL_ATTEMPT_PREPARATION_REQUIRED")
        return state.attempts

    def _require_sources(self, sources: _Sources) -> None:
        if type(sources.captured) is ResolvedContinuousVenueSources:
            assert self.venue_sources is not None
            self.venue_sources.require_resolved(sources.captured)
        elif type(sources.captured) is ResolvedContinuousForwardSources:
            self.forward_sources.require_resolved(sources.captured)

    def _recheck_sources(self, connection: Connection, sources: _Sources) -> None:
        if type(sources.captured) is ResolvedContinuousVenueSources:
            assert self.venue_sources is not None
            self.venue_sources.recheck_in_transaction(connection, sources.captured)
        elif type(sources.captured) is ResolvedContinuousForwardSources:
            self.forward_sources.recheck_in_transaction(connection, sources.captured)

    @staticmethod
    def _view_fingerprint(view: PreparedContinuousCompositionView) -> str:
        return content_digest(
            (
                view.evidence,
                view.current.assignment,
                view.current.assignment_rows,
                view.current.admissions,
                view.current.obligations,
                view.current.control,
                view.current.raw.receipt,
                tuple(
                    (
                        str(table.table.name),
                        tuple(
                            tuple((str(key), value) for key, value in sorted(row.items()))
                            for row in table.rows
                        ),
                    )
                    for table in view.current.raw.tables
                ),
                view.venue.capture.semantic_sha256,
            )
        )

    def inspect_prepared(
        self, value: PreparedContinuousComposition
    ) -> PreparedContinuousCompositionView:
        self.require_prepared(value)
        state = value.state
        assert type(state) is _Prepared
        if type(state.sources.captured) is not ResolvedContinuousVenueSources:
            raise ContinuousCompositionError("VENUE_COMPOSITION_VIEW_REQUIRED")
        self._require_sources(state.sources)
        view = self._own(
            PreparedContinuousCompositionView(
                value, state.current, state.evidence, state.sources.captured, state, self._seal
            )
        )
        self._fingerprints[id(view)] = self._view_fingerprint(view)
        finalize(view, self._fingerprints.pop, id(view), None)
        return view

    def require_prepared_view(self, view: PreparedContinuousCompositionView) -> None:
        """Full original fingerprint validation must occur before account SQL."""
        self._require(view, PreparedContinuousCompositionView)
        self.require_prepared(view.composition)
        self._require_sources(cast(_Prepared, view.state).sources)
        if self._fingerprints.get(id(view)) != self._view_fingerprint(view):
            raise ContinuousCompositionError("ORIGINAL_COMPOSITION_VIEW_CHANGED")

    def recheck_prepared_view_in_transaction(
        self,
        connection: Connection,
        view: PreparedContinuousCompositionView,
        *,
        fence: AccountFence,
        prepared_account: PreparedContinuousCommit | None = None,
        account_receipt: ContinuousAccountReceipt | None = None,
    ) -> ReconciliationHeads:
        """Exact current B rows plus source receipts; no codec, hashing or replay."""
        self._require(view, PreparedContinuousCompositionView)
        self._require(view.composition, PreparedContinuousComposition)
        state = cast(_Prepared, view.state)
        if (prepared_account is None) != (account_receipt is None):
            raise ContinuousCompositionError("EXACT_PAIRED_ACCOUNT_PUBLICATION_REQUIRED")
        if prepared_account is not None and (
            type(prepared_account) is not PreparedContinuousCommit
            or type(account_receipt) is not ContinuousAccountReceipt
            or prepared_account.composition is not view.composition
        ):
            raise ContinuousCompositionError("ORIGINAL_ACCOUNT_COMPOSITION_REQUIRED")
        if state.observed_holds is None:
            if prepared_account is None:
                self.daily.recheck_snapshot_in_transaction(connection, view.current, fence=fence)
            else:
                assert account_receipt is not None
                self.daily.recheck_snapshot_after_continuous_publication_in_transaction(
                    connection,
                    view.current,
                    fence=fence,
                    prepared_account=prepared_account,
                    account_receipt=account_receipt,
                )
        else:
            if prepared_account is None or account_receipt is None:
                raise ContinuousCompositionError("OWNED_OBSERVED_ACCOUNT_PUBLICATION_REQUIRED")
            if prepared_account.composition is not view.composition:
                raise ContinuousCompositionError("OBSERVED_ACCOUNT_COMPOSITION_DIFFERS")
            result = self.daily.recheck_observed_publication_in_transaction(
                connection,
                state.observed_holds,
                fence=fence,
                prepared_account=prepared_account,
                account_receipt=account_receipt,
            )
            if result is not state.observed_holds.result:
                raise ContinuousCompositionError("ATOMIC_OBSERVED_RESULT_DIFFERS")
        self._recheck_sources(connection, state.sources)
        return view.evidence.resulting_heads

    def apply_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedContinuousComposition,
        *,
        fence: AccountFence,
        fence_receipt: AccountFenceReceipt,
    ) -> ReconciliationHeads:
        self._require(prepared, PreparedContinuousComposition)
        state = prepared.state
        assert type(state) is _Prepared
        if fence != self.fence or fence_receipt.fence != fence:
            raise ContinuousCompositionError("CURRENT_CONTINUOUS_FENCE_DIFFERS")
        self.daily.recheck_snapshot_in_transaction(connection, state.current, fence=fence)
        self._recheck_sources(connection, state.sources)
        for admission in state.admissions:
            result = self.daily.admit_prepared_in_transaction(connection, admission, fence=fence)
            if result is not admission.result:
                raise ContinuousCompositionError("ATOMIC_ADMISSION_RESULT_DIFFERS")
        if state.observed_holds is not None:
            observed = self.daily.commit_observed_holds_in_transaction(
                connection, state.observed_holds, fence=fence
            )
            if observed is not state.observed_holds.result:
                raise ContinuousCompositionError("ATOMIC_OBSERVED_RESULT_DIFFERS")
        if state.attempts is not None:
            attempted = self.daily.commit_attempt_prepared_in_transaction(
                connection, state.attempts, fence=fence
            )
            if attempted is not state.attempts.result:
                raise ContinuousCompositionError("ATOMIC_ATTEMPT_RESULT_DIFFERS")
        return prepared.resulting_heads

    def require_frontier_admission_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedContinuousCommit,
        admission: PreparedDailyAdmission,
    ) -> ResolvedDailyRuntimeSnapshot:
        """Check original composition membership; the actual C pair is checked by B."""
        if connection.engine is not self.engine or not connection.in_transaction():
            raise ContinuousCompositionError("CALLER_OWNED_CONTINUOUS_TRANSACTION_REQUIRED")
        self._require(prepared.composition, PreparedContinuousComposition)
        state = prepared.composition.state
        if (
            type(state) is not _Prepared
            or state.attempts is not None
            or state.observed_holds is not None
            or len(state.admissions) != 1
            or state.admissions[0] is not admission
            or type(state.sources.value) is not ContinuousForwardClosure
            or type(state.sources.captured) is not ResolvedContinuousForwardSources
            or state.sources.reference.schema_id != FORWARD_CLOSURE_SCHEMA
        ):
            raise ContinuousCompositionError("ORIGINAL_FRONTIER_ADMISSION_REQUIRED")
        self.daily.require_prepared_admission_in_transaction(connection, admission)
        return state.current

    def recheck_frontier_publication_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedContinuousCommit,
        receipt: ContinuousAccountReceipt,
        *,
        fence: AccountFence,
    ) -> None:
        """Authenticate complete B plus its exact zero/one admission and actual C pair."""
        from packages.persistence.continuous_account import SqlContinuousAccount

        self._require(prepared.composition, PreparedContinuousComposition)
        state = prepared.composition.state
        accounts = getattr(self.producer_history, "accounts", None)
        if (
            type(state) is not _Prepared
            or type(accounts) is not SqlContinuousAccount
            or accounts.composer is not self
            or accounts.engine is not self.engine
            or accounts.coordinator is not self.coordinator
            or fence != self.fence
            or state.attempts is not None
            or state.observed_holds is not None
            or len(state.admissions) > 1
            or type(state.sources.captured) is not ResolvedContinuousForwardSources
            or (type(state.sources.value), state.sources.reference.schema_id)
            not in (
                (ContinuousForwardClosure, FORWARD_CLOSURE_SCHEMA),
                (ContinuousQuoteClosure, CONTINUOUS_QUOTE_CLOSURE_SCHEMA),
            )
            or (state.admissions and type(state.sources.value) is not ContinuousForwardClosure)
        ):
            raise ContinuousCompositionError("ACTUAL_FRONTIER_PUBLICATION_REQUIRED")
        accounts.require_committed_in_transaction(connection, prepared=prepared, receipt=receipt)
        self._recheck_sources(connection, state.sources)
        if state.admissions:
            (admission,) = state.admissions
            result = self.daily.recheck_admission_publication_in_transaction(
                connection,
                admission,
                prepared_account=prepared,
                account_receipt=receipt,
                fence=fence,
            )
            if result is not admission.result:
                raise ContinuousCompositionError("ATOMIC_ADMISSION_RESULT_DIFFERS")
        else:
            self.daily.recheck_snapshot_after_continuous_publication_in_transaction(
                connection,
                state.current,
                prepared_account=prepared,
                account_receipt=receipt,
                fence=fence,
            )
        accounts.require_committed_in_transaction(connection, prepared=prepared, receipt=receipt)

    def recheck_attempt_publication_in_transaction(
        self,
        connection: Connection,
        prepared: PreparedContinuousCommit,
        receipt: ContinuousAccountReceipt,
        *,
        fence: AccountFence,
    ) -> None:
        self._require(prepared.composition, PreparedContinuousComposition)
        state = prepared.composition.state
        assert type(state) is _Prepared
        if state.attempts is None:
            raise ContinuousCompositionError("ACTUAL_ATTEMPT_PUBLICATION_REQUIRED")
        result = self.daily.recheck_attempt_publication_in_transaction(
            connection,
            state.attempts,
            fence=fence,
            prepared_account=prepared,
            account_receipt=receipt,
        )
        if result is not state.attempts.result:
            raise ContinuousCompositionError("ATOMIC_ATTEMPT_RESULT_DIFFERS")

    def prepare_capture(
        self,
        commit: ContinuousAccountCommit,
        *,
        previous: ResolvedContinuousAccount | None,
    ) -> ContinuousCompositionPlan:
        if commit.decision_evidence.schema_id != COMPOSITION_EVIDENCE_SCHEMA:
            raise ContinuousCompositionError("CONTINUOUS_DECISION_SCHEMA_UNSUPPORTED")
        sources = self._sources(commit.source_evidence)
        evidence = self._read(commit.decision_evidence, ContinuousCompositionEvidence)
        if (
            evidence.checkpoint_sha256 != commit.transition.checkpoint_sha256
            or evidence.previous_checkpoint_sha256 != commit.transition.previous_checkpoint_sha256
            or evidence.expected_heads != commit.transition.expected_heads
            or evidence.resulting_heads != commit.transition.resulting_heads
            or evidence.benchmark_instrument_id != self.benchmark_instrument_id
            or len(evidence.admissions) > 1
        ):
            raise ContinuousCompositionError("RETAINED_COMPOSITION_BINDINGS_DIFFER")
        plans = tuple(
            self.producer_history.prepare_admission_source_read(
                ref.producer_closure,
                record_sha256=ref.record_sha256,
                previous=previous,
            )
            for ref in evidence.admissions
        )
        current = self._historical_current()
        observed = (
            None
            if evidence.observed_holds is None
            else self.daily.inspect_observed_group(current, group=evidence.observed_holds)
        )
        attempts = (
            None
            if not evidence.attempt_envelopes
            else self.daily.inspect_attempt_group(current, envelopes=evidence.attempt_envelopes)
        )
        if (type(sources.value) is RuntimeAttemptAccountingSource) != (attempts is not None):
            raise ContinuousCompositionError("RETAINED_ATTEMPT_SOURCE_GROUP_DIFFERS")
        return self._own(
            ContinuousCompositionPlan(
                commit.semantic_sha256,
                _Plan(commit, sources, evidence, current, plans, observed, attempts),
                self._seal,
            )
        )

    def capture_in_transaction(
        self,
        connection: Connection,
        *,
        commit: ContinuousAccountCommit,
        plan: ContinuousCompositionPlan,
    ) -> ContinuousCompositionSnapshot:
        self._require(plan, ContinuousCompositionPlan)
        value = plan.state
        assert type(value) is _Plan
        if commit != value.commit or plan.commit_sha256 != commit.semantic_sha256:
            raise ContinuousCompositionError("CONTINUOUS_CAPTURE_PLAN_DIFFERS")
        self._recheck_sources(connection, value.sources)
        # All seven historical heads below derive from this real complete B
        # history, captured before SQL and rechecked in the coherent C read.
        self.daily.recheck_snapshot_in_transaction(connection, value.current, fence=self.fence)
        if value.observed_holds is not None:
            self.daily.recheck_observed_group_in_transaction(connection, value.observed_holds)
        if value.attempts is not None:
            self.daily.recheck_attempt_group_in_transaction(connection, value.attempts)
        budget = RuntimeReadBudget()
        admissions = tuple(
            self.daily.capture_historical_admission_in_transaction(
                connection,
                account_id=commit.scope.account_id,
                command_id=ref.command_id,
                expected_record_sha256=ref.record_sha256,
                budget=budget,
            )
            for ref in value.evidence.admissions
        )
        producers = tuple(
            self.producer_history.capture_admission_sources_in_transaction(connection, p)
            for p in value.producer_plans
        )
        controls = capture_runtime_table(
            connection,
            phase5_operational_control_transitions,
            account_id=commit.scope.account_id,
            budget=budget,
        )
        revision = value.evidence.expected_heads.control_revision
        if self._control_prefix(controls, revision) != self._control_prefix(
            self._controls(value.current), revision
        ):
            raise ContinuousCompositionError("ORIGINAL_CONTROL_PREFIX_CHANGED")
        return self._own(
            ContinuousCompositionSnapshot(
                commit.semantic_sha256,
                _Captured(plan, admissions, producers, controls),
                self._seal,
            )
        )

    def resolve(
        self,
        snapshot: ContinuousCompositionSnapshot,
        *,
        commit: ContinuousAccountCommit,
        checkpoint: CausalEngineCheckpoint,
        request: ContinuousEngineInputs | ClosedEngineFrontier | ContinuousRuntimeAction,
        previous: ResolvedContinuousAccount | None,
    ) -> ResolvedContinuousComposition:
        self._require(snapshot, ContinuousCompositionSnapshot)
        raw = snapshot.state
        assert type(raw) is _Captured
        self._require(raw.plan, ContinuousCompositionPlan)
        plan = raw.plan.state
        assert type(plan) is _Plan
        if snapshot.commit_sha256 != commit.semantic_sha256 or commit != plan.commit:
            raise ContinuousCompositionError("RESOLVED_CONTINUOUS_COMMIT_DIFFERS")
        evidence = plan.evidence
        self._source_request(
            plan.sources,
            request,
            previous=previous,
            checkpoint=checkpoint,
            source_closure_sha256=commit.transition.source_closure_sha256,
        )
        if type(plan.sources.value) is RetainedVenueCapture:
            if evidence.new_decisions or evidence.admissions:
                raise ContinuousCompositionError("VENUE_RECONCILIATION_ADMISSION_UNSUPPORTED")
            assert self.accounting is not None
            validate_continuous_application_times(
                checkpoint,
                capture=plan.sources.value,
                applications=evidence.applications,
                accounting=self.accounting,
            )
        elif evidence.applications:
            raise ContinuousCompositionError("APPLICATION_RECEIPTS_REQUIRE_VENUE_SOURCE")
        prior_checkpoint = None if previous is None else previous.checkpoint
        prior_decisions = () if prior_checkpoint is None else prior_checkpoint.runtime_decisions
        if checkpoint.runtime_decisions != (*prior_decisions, *evidence.new_decisions):
            raise ContinuousCompositionError("RETAINED_DECISION_PREFIX_DIFFERS")
        before = _inventory(())
        if previous is not None:
            self.require_resolved(previous.composition)
            prior = previous.composition.state
            assert type(prior) is _Resolved
            before = prior.evidence.after_obligations
        if before != evidence.before_obligations:
            raise ContinuousCompositionError("RETAINED_ORIGINAL_OBLIGATIONS_DIFFER")
        self._commitments(prior_checkpoint, before)
        original_attempts = daily_runtime_attempt_prefix(
            attempts=plan.current.attempts,
            attempt_envelopes=plan.current.attempt_envelopes,
            through_coordinator_sequence=commit.sequence - 1,
        )
        watermark = daily_runtime_effect_watermark(
            attempt_envelopes=tuple(
                item
                for item in plan.current.attempt_envelopes
                if item.coordinator_sequence < commit.sequence
            ),
            observed_groups=tuple(
                item
                for item in plan.current.observed_groups
                if item.coordinator_sequence < commit.sequence
            ),
        )
        expected = self._heads(
            prior_checkpoint,
            before,
            evidence.expected_heads.control_revision,
            evidence.expected_heads.lease_generation,
            watermark,
            daily_attempt_inventory_sha256(original_attempts),
        )
        if expected != evidence.expected_heads:
            raise ContinuousCompositionError("RETAINED_EXPECTED_HEADS_DIFFER")
        admissions = tuple(self.daily.resolve_historical_admission(a) for a in raw.admissions)
        views = tuple(a.admission for a in admissions)
        for view, ref in zip(views, evidence.admissions, strict=True):
            if (
                view.command_id,
                view.request_sha256,
                view.record_sha256,
                view.payload_sha256,
                view.admission.semantic_sha256,
                content_digest(view.prepared_commitments),
            ) != (
                ref.command_id,
                ref.request_sha256,
                ref.record_sha256,
                ref.payload_sha256,
                ref.admission_sha256,
                ref.commitments_sha256,
            ):
                raise ContinuousCompositionError("ORIGINAL_ADMISSION_REFERENCE_DIFFERS")
        attempt_sha256 = expected.attempt_sha256
        if plan.attempts is not None:
            self.daily.require_attempt_group_view(plan.attempts)
            if (
                plan.attempts.envelopes != evidence.attempt_envelopes
                or plan.attempts.source != plan.sources.value
            ):
                raise ContinuousCompositionError("ORIGINAL_ATTEMPT_GROUP_DIFFERS")
            after = self._attempt_match(
                plan.attempts.source,
                plan.attempts.result,
                plan.attempts.envelopes,
                previous=previous,
                checkpoint=checkpoint,
                request=request,
                reference=commit.source_evidence,
                command_id=commit.transition.command_id,
                expected=expected,
                before=before,
            )
            watermark = plan.attempts.result.coordinator_sequence
            attempt_sha256 = daily_attempt_inventory_sha256(plan.attempts.result.attempts)
        elif plan.observed_holds is None:
            after = self._match(
                evidence.new_decisions,
                views,
                checkpoint=checkpoint,
                before=before,
                expected=expected,
            )
        else:
            self.daily.require_observed_group_view(plan.observed_holds)
            after = self._observed_match(
                plan.observed_holds.inputs,
                plan.observed_holds.result,
                previous=previous,
                checkpoint=checkpoint,
                request=request,
                source=commit.source_evidence,
                command_id=commit.transition.command_id,
                expected=expected,
                before=before,
                applications=evidence.applications,
            )
            if plan.observed_holds.result.group != evidence.observed_holds:
                raise ContinuousCompositionError("ORIGINAL_OBSERVED_GROUP_DIFFERS")
            watermark = plan.observed_holds.result.coordinator_sequence
        if (
            after != evidence.after_obligations
            or self._heads(
                checkpoint,
                after,
                expected.control_revision,
                expected.lease_generation,
                watermark,
                attempt_sha256,
            )
            != evidence.resulting_heads
        ):
            raise ContinuousCompositionError("RETAINED_RESULTING_HEADS_DIFFER")
        controls = self._control_prefix(raw.controls, expected.control_revision)
        if len(controls) != expected.control_revision or (
            evidence.control is not None
            and (
                not controls or controls[-1]["semantic_sha256"] != evidence.control.semantic_sha256
            )
        ):
            raise ContinuousCompositionError("ORIGINAL_CONTROL_TRANSITION_DIFFERS")
        producers = tuple(
            self.producer_history.resolve_admission_sources(s, admission=v, previous=previous)
            for s, v in zip(raw.producers, views, strict=True)
        )
        for resolved, ref in zip(producers, evidence.admissions, strict=True):
            if (
                resolved.reference != ref.producer_closure
                or resolved.record_sha256 != ref.record_sha256
            ):
                raise ContinuousCompositionError("ORIGINAL_PRODUCER_CLOSURE_DIFFERS")
        return self._own(
            ResolvedContinuousComposition(
                commit.semantic_sha256,
                _Resolved(
                    plan.sources,
                    evidence,
                    admissions,
                    producers,
                    controls,
                    plan.observed_holds,
                    plan.attempts,
                ),
                self._seal,
            )
        )

    def require_resolved(self, value: ResolvedContinuousComposition) -> None:
        self._require(value, ResolvedContinuousComposition)
        state = value.state
        assert type(state) is _Resolved
        for admission in state.admissions:
            self.daily.require_admission_view(admission.admission)
        if state.observed_holds is not None:
            self.daily.require_observed_group_view(state.observed_holds)
        if state.attempts is not None:
            self.daily.require_attempt_group_view(state.attempts)
        self._require_sources(state.sources)

    def inspect_resolved_evidence(
        self, value: ResolvedContinuousComposition
    ) -> ContinuousCompositionEvidence:
        """Return original evidence only from this composer's authenticated restore."""
        self.require_resolved(value)
        state = value.state
        assert type(state) is _Resolved
        return state.evidence

    def recheck_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedContinuousComposition,
        *,
        require_current: bool,
    ) -> None:
        self._require(resolved, ResolvedContinuousComposition)
        state = resolved.state
        assert type(state) is _Resolved
        # The account store checks its actual current checkpoint/index when
        # require_current is set. Original control/fence/source values remain
        # historical; new mutations separately recheck a fresh actual B snapshot.
        self._recheck_sources(connection, state.sources)
        for admission in state.admissions:
            self.daily.recheck_historical_admission_in_transaction(connection, admission)
        for producer in state.producers:
            self.producer_history.recheck_admission_sources_in_transaction(connection, producer)
        if state.observed_holds is not None:
            self.daily.recheck_observed_group_in_transaction(connection, state.observed_holds)
        if state.attempts is not None:
            self.daily.recheck_attempt_group_in_transaction(connection, state.attempts)
        controls = capture_runtime_table(
            connection,
            phase5_operational_control_transitions,
            account_id=self.fence.account_id,
            budget=RuntimeReadBudget(),
        )
        if (
            self._control_prefix(controls, state.evidence.expected_heads.control_revision)
            != state.control_rows
        ):
            raise ContinuousCompositionError("ORIGINAL_CONTROL_PREFIX_CHANGED")
