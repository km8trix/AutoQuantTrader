"""Authenticate observed hold provenance through retained venue and sole-engine facts.

Fresh sources require this instance's retained preparation. Historical sources
require their actual account parent publication; reading B history never calls
account.restore or the account composer. Objects and replay remain outside SQL.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from hashlib import sha256
from typing import Any, TypeVar, cast
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection, Engine

from packages.application.continuous_account_transition import (
    ContinuousAccountTransitionPreparer,
    PreparedContinuousTransition,
)
from packages.application.continuous_reconciliation_publication import (
    validate_continuous_application_times,
)
from packages.application.continuous_venue_frontier import project_continuous_venue_frontier
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_REQUEST_SCHEMA,
    ContinuousAccountReceipt,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.daily_attempt import daily_fence_reference
from packages.domain.daily_observed_hold_contracts import (
    OBSERVED_HOLD_SOURCE_SCHEMA,
    RuntimeObservedHoldInputs,
    RuntimeObservedHoldSource,
    daily_runtime_effect_watermark,
)
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_application_contracts import AppliedReconciliationBatch
from packages.domain.reconciliation_contracts import ReconciliationHeads
from packages.domain.research_job_contracts import (
    ObjectRef,
    ResearchArtifactStore,
    ResearchRecordCodec,
)
from packages.domain.venue_reconciliation_contracts import (
    VENUE_CAPTURE_SCHEMA,
    RetainedVenueCapture,
)
from packages.persistence.continuous_account import (
    ContinuousReferenceSnapshot,
    PreparedContinuousCommit,
    ResolvedContinuousAccount,
    ResolvedContinuousReference,
    SqlContinuousAccount,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.continuous_venue_sources import (
    ResolvedContinuousVenueSources,
    SqlContinuousVenueSources,
)
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    ResolvedDailyRuntimeSnapshot,
    ResolvedRuntimeObservedHoldSources,
    RetainedDailyAdmission,
    RuntimeObservedHoldSourcePlan,
    RuntimeObservedHoldSourceSnapshot,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    SqlDailyRuntimeRisk,
    _require_same_runtime_tables,
    capture_runtime_table,
    daily_attempt_inventory_sha256,
)
from packages.persistence.detached_journal_capture import (
    DetachedJournalCapture,
    detached_journal_value,
)
from packages.persistence.durable_journal import JournalReadSnapshot

T = TypeVar("T")

CHECKPOINT_SCHEMA = "continuous-checkpoint/1"
APPLICATION_BATCH_SCHEMA = "applied-batch/1"
MAX_OBSERVED_OBJECT_BYTES = 32 * 1024 * 1024
MAX_OBSERVED_REFERENCES = 4096


class ContinuousObservedHoldSourceError(ValueError):
    pass


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedContinuousObservedHoldSource:
    reference: ContinuousEvidenceRef
    inputs: RuntimeObservedHoldInputs
    previous: ResolvedContinuousAccount
    transition: PreparedContinuousTransition
    venue: ResolvedContinuousVenueSources
    current: ResolvedDailyRuntimeSnapshot
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class _Objects:
    """One bounded, content-interned object graph, including source manifest pages."""

    references: tuple[ObjectRef, ...]
    payloads: tuple[bytes, ...]


class _ObjectGraph:
    def __init__(self, artifacts: ResearchArtifactStore, codec: ResearchRecordCodec) -> None:
        self.artifacts, self.codec = artifacts, codec
        self.refs: dict[str, ObjectRef] = {}
        self.raw: dict[str, bytes] = {}
        self.decoded: dict[tuple[str, type[Any]], Any] = {}
        self.total = 0

    def admit(self, refs: tuple[ObjectRef, ...]) -> None:
        for ref in refs:
            ref.__post_init__()
            if ref.codec_version != "personal-record/1":
                raise ContinuousObservedHoldSourceError("OBSERVED_TYPED_OBJECT_REQUIRED")
            previous = self.refs.get(ref.object_sha256)
            if previous is not None:
                if previous != ref:
                    raise ContinuousObservedHoldSourceError("OBSERVED_OBJECT_IDENTITY_CONFLICT")
                continue
            self.total += ref.byte_count
            if self.total > MAX_OBSERVED_OBJECT_BYTES or len(self.refs) >= MAX_OBSERVED_REFERENCES:
                raise ContinuousObservedHoldSourceError("OBSERVED_COMPLETE_OBJECT_GRAPH_LIMIT")
            self.refs[ref.object_sha256] = ref

    def read(self, ref: ContinuousEvidenceRef, kind: type[Any], schema: str) -> Any:
        if type(ref) is not ContinuousEvidenceRef or ref.schema_id != schema:
            raise ContinuousObservedHoldSourceError("OBSERVED_OBJECT_SCHEMA_DIFFERS")
        self.admit((ref.object_ref,))
        key = ref.object_ref.object_sha256
        if key not in self.raw:
            raw = self.artifacts.read(ref.object_ref, max_bytes=ref.object_ref.byte_count)
            if (
                type(raw) is not bytes
                or len(raw) != ref.object_ref.byte_count
                or sha256(raw).hexdigest() != key
            ):
                raise ContinuousObservedHoldSourceError("OBSERVED_ORIGINAL_OBJECT_BYTES_DIFFER")
            self.raw[key] = raw
        identity = (key, kind)
        if identity not in self.decoded:
            value = self.codec.decode_record(self.raw[key], kind)
            if type(value) is not kind or self.codec.encode_record(value) != self.raw[key]:
                raise ContinuousObservedHoldSourceError("OBSERVED_ORIGINAL_OBJECT_CODEC_DIFFERS")
            self.decoded[identity] = value
        value = self.decoded[identity]
        if value.semantic_sha256 != ref.semantic_sha256:
            raise ContinuousObservedHoldSourceError("OBSERVED_OBJECT_SEMANTICS_DIFFER")
        return value

    def encode(self, schema: str, value: ContractRecord) -> ContinuousEvidenceRef:
        raw = self.codec.encode_record(value)
        if type(raw) is not bytes or not raw:
            raise ContinuousObservedHoldSourceError("OBSERVED_OBJECT_BYTES_INVALID")
        obj = ObjectRef(sha256(raw).hexdigest(), len(raw))
        self.admit((obj,))
        self.raw[obj.object_sha256] = raw
        return ContinuousEvidenceRef(schema, obj, value.semantic_sha256)

    def retained(self) -> _Objects:
        return _Objects(
            tuple(self.refs.values()), tuple(self.raw[key] for key in self.refs if key in self.raw)
        )

    def publish(self) -> None:
        for ref in self.refs.values():
            if (
                ref.object_sha256 in self.raw
                and self.artifacts.put(self.raw[ref.object_sha256]) != ref
            ):
                raise ContinuousObservedHoldSourceError("OBSERVED_OBJECT_STORE_DIFFERS")


def _source_objects(source: RuntimeObservedHoldSource) -> tuple[ContinuousEvidenceRef, ...]:
    return (
        source.previous_checkpoint,
        source.resulting_checkpoint,
        source.frontier,
        source.venue_capture,
        *source.application_batches,
    )


def _heads(
    previous: CausalEngineCheckpoint, current: ResolvedDailyRuntimeSnapshot
) -> ReconciliationHeads:
    return ReconciliationHeads(
        previous.current.snapshot.journal_sha256,
        previous.current.snapshot.order_sha256,
        current.obligations.semantic_sha256,
        daily_runtime_effect_watermark(
            attempt_envelopes=current.attempt_envelopes, observed_groups=current.observed_groups
        ),
        daily_attempt_inventory_sha256(current.attempts),
        0 if current.control is None else current.control.sequence_number,
        current.raw.receipt.fence.fencing_generation,
    )


def _same_replayed_checkpoint(
    original: CausalEngineCheckpoint,
    replayed: CausalEngineCheckpoint,
) -> bool:
    # Each newly admitted continuous step has its own bounded compute allowance.
    # Replay measures it again; preserve the original positive bounded value.
    return (
        0 < original.remaining_wall_nanoseconds <= original.inputs.spec.max_wall_seconds * 10** 9
        and (
            replace(replayed, remaining_wall_nanoseconds=original.remaining_wall_nanoseconds)
            == original
        )
    )


# SQL metadata capture/recheck implementation follows the account-owned reference
# seam; no composer callbacks or recursive account restoration are permitted.


@dataclass(frozen=True, slots=True)
class _Plan:
    inputs: tuple[RuntimeObservedHoldInputs, ...]
    venues: tuple[ResolvedContinuousVenueSources, ...]
    fresh: tuple[PreparedContinuousObservedHoldSource | None, ...]
    objects: _Objects


@dataclass(frozen=True, slots=True)
class _Captured:
    plan: _Plan
    account_rows: RuntimeTableSnapshot
    references: tuple[ContinuousReferenceSnapshot, ...]
    historical: tuple[bool, ...]
    venue_journals: tuple[tuple[JournalReadSnapshot, ...], ...]


@dataclass(frozen=True, slots=True)
class _Resolved:
    captured: _Captured
    references: tuple[ResolvedContinuousReference, ...]


class SqlContinuousObservedHoldSources:
    def __init__(
        self,
        engine: Engine,
        *,
        accounts: SqlContinuousAccount,
        preparer: ContinuousAccountTransitionPreparer,
        venue_sources: SqlContinuousVenueSources,
        daily: SqlDailyRuntimeRisk,
        artifacts: ResearchArtifactStore,
        codec: ResearchRecordCodec,
    ) -> None:
        if (
            type(accounts) is not SqlContinuousAccount
            or type(preparer) is not ContinuousAccountTransitionPreparer
            or type(venue_sources) is not SqlContinuousVenueSources
            or type(daily) is not SqlDailyRuntimeRisk
            or accounts.engine is not engine
            or venue_sources.engine is not engine
            or daily.engine is not engine
            or accounts.preparer is not preparer
            or accounts.artifacts is not artifacts
            or venue_sources.artifacts is not artifacts
            or accounts.codec is not codec
            or venue_sources.codec is not codec
            or daily.codec is not codec
            or daily.coordinator is not accounts.coordinator
        ):
            raise ContinuousObservedHoldSourceError("OBSERVED_EXACT_CONCRETE_INSTANCES_REQUIRED")
        self.engine, self.accounts, self.preparer, self.venue_sources = (
            engine,
            accounts,
            preparer,
            venue_sources,
        )
        self.daily, self.artifacts, self.codec = daily, artifacts, codec
        self._seal = object()
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._fresh: WeakValueDictionary[str, PreparedContinuousObservedHoldSource] = (
            WeakValueDictionary()
        )
        self._fields: dict[int, tuple[tuple[str, object], ...]] = {}
        self._fingerprints: dict[int, str] = {}
        self._state_fields: dict[
            int, tuple[tuple[object, tuple[tuple[str, object], ...]], ...]
        ] = {}

    def _own(self, value: T) -> T:
        self._owned[id(value)] = value
        self._fields[id(value)] = tuple(
            (f.name, getattr(value, f.name)) for f in fields(cast(Any, value))
        )
        states: list[tuple[object, tuple[tuple[str, object], ...]]] = []
        state = getattr(value, "state", None)
        while type(state) in (_Plan, _Captured, _Resolved):
            states.append(
                (state, tuple((f.name, getattr(state, f.name)) for f in fields(cast(Any, state))))
            )
            state = (
                state.captured
                if type(state) is _Resolved
                else state.plan
                if type(state) is _Captured
                else None
            )
        self._state_fields[id(value)] = tuple(states)
        finalize(value, self._fields.pop, id(value), None)
        finalize(value, self._state_fields.pop, id(value), None)
        return value

    def _require(self, value: object, kind: type[Any]) -> None:
        if (
            type(value) is not kind
            or self._owned.get(id(value)) is not value
            or any(
                getattr(value, name) is not original for name, original in self._fields[id(value)]
            )
            or any(
                getattr(state, name) is not original
                for state, pairs in self._state_fields[id(value)]
                for name, original in pairs
            )
        ):
            raise ContinuousObservedHoldSourceError("OWNED_ORIGINAL_OBSERVED_SOURCE_REQUIRED")

    @staticmethod
    def _fingerprint(
        value: PreparedContinuousObservedHoldSource | ResolvedRuntimeObservedHoldSources,
    ) -> str:
        if isinstance(value, PreparedContinuousObservedHoldSource):
            return content_digest(
                (
                    value.reference,
                    value.inputs,
                    value.previous.receipt,
                    value.transition.checkpoint.semantic_sha256,
                    value.venue.capture.semantic_sha256,
                    value.current.raw.receipt,
                    value.current.obligations,
                    value.current.attempts,
                    value.current.observed_groups,
                    value.current.control,
                )
            )
        state = cast(_Resolved, value.state)
        return content_digest(
            (
                value.inputs,
                detached_journal_value(state.captured.account_rows.rows),
                detached_journal_value(state.captured.references),
                detached_journal_value(state.captured.venue_journals),
            )
        )

    def _remember(
        self, value: PreparedContinuousObservedHoldSource | ResolvedRuntimeObservedHoldSources
    ) -> None:
        self._fingerprints[id(value)] = self._fingerprint(value)
        finalize(value, self._fingerprints.pop, id(value), None)

    def require_prepared(self, value: PreparedContinuousObservedHoldSource) -> None:
        self._require(value, PreparedContinuousObservedHoldSource)
        self.accounts.require_resolved(value.previous)
        self.preparer.require_prepared(value.transition)
        self.venue_sources.require_resolved(value.venue)
        self.daily.require_resolved_snapshot(value.current)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise ContinuousObservedHoldSourceError("ORIGINAL_OBSERVED_PREPARATION_CHANGED")

    def _validate_inputs(
        self, inputs: RuntimeObservedHoldInputs, venue: ResolvedContinuousVenueSources
    ) -> None:
        source, before, after, frontier = (
            inputs.source,
            inputs.previous,
            inputs.resulting,
            inputs.frontier,
        )
        self.venue_sources.require_resolved(venue)
        if (
            type(before.inputs) is not ContinuousEngineInputs
            or before.inputs != after.inputs
            or before.inputs.spec.account_id != source.scope.account_id
            or before.inputs.spec.account_binding_sha256 != source.scope.account_binding_sha256
            or before.inputs.spec.deployment_id != source.scope.stream_id
            or before.inputs.spec.execution_policy != source.execution_policy
            or after.runtime_decisions != before.runtime_decisions
            or after.state.submissions != before.state.submissions
            or after.request_rows != before.request_rows
            or {c.commitment_id for c in after.state.commitments}
            != {c.commitment_id for c in before.state.commitments}
            or source.applied_at != after.now
            or source.checked_at != source.fence.validated_at
            or len(frontier.events) != 1
            or type(frontier.events[0].payload) is not ContinuousReconciliationBatch
            or not inputs.application_batches
        ):
            raise ContinuousObservedHoldSourceError(
                "OBSERVED_ENGINE_SOURCE_SCOPE_OR_HISTORY_DIFFERS"
            )
        batch = frontier.events[0].payload
        assert isinstance(batch, ContinuousReconciliationBatch)
        validate_continuous_application_times(
            before,
            capture=venue.capture,
            applications=batch.prior_applications,
            accounting=self.preparer.accounting,
        )
        normalized = project_continuous_venue_frontier(
            checkpoint=before,
            capture=venue.capture,
            prior_applications=batch.prior_applications,
            frontier_id=frontier.frontier_id,
            admitted_at=frontier.knowledge_at,
        )
        if (
            normalized != frontier
            or source.source_closure_sha256 != normalized.source_frontier_sha256
        ):
            raise ContinuousObservedHoldSourceError("OBSERVED_RETAINED_FRONTIER_DIFFERS")
        replay = self.preparer.prepare_frontier(
            command_id=source.coordinator_command_id, checkpoint=before, frontier=frontier
        )
        if (
            replay.new_decisions
            or not _same_replayed_checkpoint(after, replay.checkpoint)
            or replay.application_batches != inputs.application_batches
        ):
            raise ContinuousObservedHoldSourceError("OBSERVED_SOLE_ENGINE_REPLAY_DIFFERS")

    def retain_source(
        self,
        *,
        previous: ResolvedContinuousAccount,
        transition: PreparedContinuousTransition,
        venue: ResolvedContinuousVenueSources,
        current: ResolvedDailyRuntimeSnapshot,
    ) -> PreparedContinuousObservedHoldSource:
        try:
            self.accounts.require_resolved(previous)
            self.preparer.require_prepared(transition)
            self.venue_sources.require_resolved(venue)
            self.daily.require_resolved_snapshot(current)
            before = previous.checkpoint
            if (
                type(transition.request) is not ClosedEngineFrontier
                or transition.new_decisions
                or transition.previous_checkpoint_sha256 != before.semantic_sha256
                or current.raw.account_id != before.state.account_id
                or tuple(sorted(before.state.commitments, key=lambda c: c.commitment_id))
                != tuple(binding.commitment for binding in current.obligations.bindings)
            ):
                raise ContinuousObservedHoldSourceError("OBSERVED_FRESH_CURRENT_PREFIX_DIFFERS")
            graph = _ObjectGraph(self.artifacts, self.codec)
            prev_ref = graph.encode(CHECKPOINT_SCHEMA, before)
            if prev_ref.object_ref != previous.receipt.commit.transition.checkpoint:
                raise ContinuousObservedHoldSourceError("OBSERVED_ORIGINAL_PREVIOUS_OBJECT_DIFFERS")
            graph.admit(tuple(s.evidence.object_ref for s in venue.capture.manifest.sources))
            for page_source, page in zip(venue.capture.manifest.sources, venue.pages, strict=True):
                if (
                    graph.encode(page_source.evidence.schema_id, page).object_ref
                    != page_source.evidence.object_ref
                ):
                    raise ContinuousObservedHoldSourceError(
                        "OBSERVED_ORIGINAL_VENUE_OBJECT_DIFFERS"
                    )
            source = RuntimeObservedHoldSource(
                scope=previous.receipt.commit.scope,
                coordinator_command_id=transition.command_id,
                coordinator_sequence=previous.receipt.commit.sequence + 1,
                previous_checkpoint=prev_ref,
                resulting_checkpoint=graph.encode(CHECKPOINT_SCHEMA, transition.checkpoint),
                frontier=graph.encode(CONTINUOUS_REQUEST_SCHEMA, transition.request),
                venue_capture=graph.encode(VENUE_CAPTURE_CLOSURE_SCHEMA, venue.capture),
                application_batches=tuple(
                    graph.encode(APPLICATION_BATCH_SCHEMA, b)
                    for b in transition.application_batches
                ),
                source_closure_sha256=transition.source_closure_sha256,
                heads=_heads(before, current),
                fence=daily_fence_reference(current.raw.receipt),
                execution_policy=before.inputs.spec.execution_policy,
                applied_at=transition.checkpoint.now,
                checked_at=current.raw.receipt.validated_at,
                valid_until=current.raw.receipt.valid_until,
            )
            inputs = RuntimeObservedHoldInputs(
                source,
                before,
                transition.checkpoint,
                transition.request,
                transition.application_batches,
            )
            self._validate_inputs(inputs, venue)
            ref = graph.encode(OBSERVED_HOLD_SOURCE_SCHEMA, source)
            graph.publish()
            value = self._own(
                PreparedContinuousObservedHoldSource(
                    ref, inputs, previous, transition, venue, current, self._seal
                )
            )
            self._remember(value)
            self._fresh[ref.semantic_sha256] = value
            return value
        except ContinuousObservedHoldSourceError:
            raise
        except Exception:
            raise ContinuousObservedHoldSourceError("OBSERVED_FRESH_RETENTION_FAILED") from None

    def prepare_observed_hold_source_read(
        self, references: tuple[ContinuousEvidenceRef, ...]
    ) -> RuntimeObservedHoldSourcePlan:
        try:
            if (
                type(references) is not tuple
                or not 1 <= len(references) <= MAX_OBSERVED_REFERENCES
                or len(set(references)) != len(references)
            ):
                raise ContinuousObservedHoldSourceError(
                    "OBSERVED_EXACT_REFERENCE_INVENTORY_REQUIRED"
                )
            graph = _ObjectGraph(self.artifacts, self.codec)
            graph.admit(tuple(r.object_ref for r in references))
            sources = tuple(
                graph.read(r, RuntimeObservedHoldSource, OBSERVED_HOLD_SOURCE_SCHEMA)
                for r in references
            )
            graph.admit(
                tuple(ref.object_ref for source in sources for ref in _source_objects(source))
            )
            captures = tuple(
                graph.read(s.venue_capture, RetainedVenueCapture, VENUE_CAPTURE_CLOSURE_SCHEMA)
                for s in sources
            )
            graph.admit(
                tuple(
                    ref.evidence.object_ref
                    for capture in captures
                    for ref in capture.manifest.sources
                )
            )
            inputs = []
            venues = []
            fresh = []
            retained_venues: dict[ContinuousEvidenceRef, ResolvedContinuousVenueSources] = {}
            for reference, source, capture in zip(references, sources, captures, strict=True):
                before = graph.read(
                    source.previous_checkpoint, CausalEngineCheckpoint, CHECKPOINT_SCHEMA
                )
                after = graph.read(
                    source.resulting_checkpoint, CausalEngineCheckpoint, CHECKPOINT_SCHEMA
                )
                frontier = graph.read(
                    source.frontier, ClosedEngineFrontier, CONTINUOUS_REQUEST_SCHEMA
                )
                batches = tuple(
                    graph.read(ref, AppliedReconciliationBatch, APPLICATION_BATCH_SCHEMA)
                    for ref in source.application_batches
                )
                venue = retained_venues.get(source.venue_capture)
                if venue is None:
                    venue = self.venue_sources.resolve(capture)
                    for page_source, page in zip(
                        capture.manifest.sources, venue.pages, strict=True
                    ):
                        ref = page_source.evidence
                        if graph.encode(VENUE_CAPTURE_SCHEMA, page) != ContinuousEvidenceRef(
                            ref.schema_id, ref.object_ref, ref.semantic_sha256
                        ):
                            raise ContinuousObservedHoldSourceError(
                                "OBSERVED_ORIGINAL_VENUE_OBJECT_DIFFERS"
                            )
                    retained_venues[source.venue_capture] = venue
                item = RuntimeObservedHoldInputs(source, before, after, frontier, batches)
                self._validate_inputs(item, venue)
                candidate = self._fresh.get(reference.semantic_sha256)
                if candidate is not None:
                    self.require_prepared(candidate)
                    if candidate.reference != reference or candidate.inputs != item:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_ORIGINAL_FRESH_SOURCE_DIFFERS"
                        )
                inputs.append(item)
                venues.append(venue)
                fresh.append(candidate)
            state = _Plan(tuple(inputs), tuple(venues), tuple(fresh), graph.retained())
            return self._own(RuntimeObservedHoldSourcePlan(references, state))
        except ContinuousObservedHoldSourceError:
            raise
        except Exception:
            raise ContinuousObservedHoldSourceError("OBSERVED_SOURCE_PLANNING_FAILED") from None

    def capture_observed_hold_sources_in_transaction(
        self,
        connection: Connection,
        plan: RuntimeObservedHoldSourcePlan,
        *,
        account_id: str,
        budget: RuntimeReadBudget,
    ) -> RuntimeObservedHoldSourceSnapshot:
        self._require(plan, RuntimeObservedHoldSourcePlan)
        state = cast(_Plan, plan.state)
        if type(budget) is not RuntimeReadBudget or connection.engine is not self.engine:
            raise ContinuousObservedHoldSourceError("OBSERVED_SAME_ENGINE_SHARED_BUDGET_REQUIRED")
        try:
            initial_count = len(budget.captured)
            retained = tuple(
                t
                for t in budget.captured
                if t.table is continuous_account_commits and t.account_id == account_id
            )
            if len(retained) > 1:
                raise ContinuousObservedHoldSourceError("OBSERVED_DUPLICATE_ACCOUNT_FOOTPRINT")
            table = (
                retained[0]
                if retained
                else capture_runtime_table(
                    connection, continuous_account_commits, account_id=account_id, budget=budget
                )
            )
            rows = {row["command_id"]: row for row in table.rows}
            pool = DetachedJournalCapture(
                max_bytes=MAX_OBSERVED_OBJECT_BYTES, max_metadata_bytes=MAX_METADATA_BYTES
            )
            charged = (0, 0, 0)
            leases: dict[str, Mapping[str, Any]] = {}
            refs = []
            historical = []
            venue_rows = []
            for item, venue, fresh in zip(state.inputs, state.venues, state.fresh, strict=True):
                source = item.source
                if source.scope.account_id != account_id:
                    raise ContinuousObservedHoldSourceError("OBSERVED_CAPTURE_ACCOUNT_DIFFERS")
                captured = self.accounts.capture_reference_in_transaction(
                    connection,
                    scope=source.scope,
                    command_id=source.coordinator_command_id,
                    source_lease_sha256=source.fence.lease_sha256,
                    journal_pool=pool,
                )
                is_history = captured is not None
                if captured is None:
                    if fresh is None:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_ACTUAL_PARENT_OR_FRESH_TOKEN_REQUIRED"
                        )
                    self._require(fresh, PreparedContinuousObservedHoldSource)
                    captured = self.accounts.capture_reference_in_transaction(
                        connection,
                        scope=source.scope,
                        command_id=fresh.previous.receipt.commit.transition.command_id,
                        source_lease_sha256=source.fence.lease_sha256,
                        journal_pool=pool,
                    )
                    if captured is None or captured.current.row != fresh.previous.snapshot.row:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_ACTUAL_FRESH_PREVIOUS_DIFFERS"
                        )
                    current = self.accounts.capture_current_in_transaction(
                        connection, scope=source.scope
                    )
                    if current != captured.current:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_FRESH_CURRENT_ACCOUNT_DIFFERS"
                        )
                    self.daily.recheck_snapshot_in_transaction(
                        connection, fresh.current, fence=source.fence.fence
                    )
                for index in (captured.current, captured.previous):
                    if index is not None and rows.get(index.row["command_id"]) != index.row:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_COHERENT_FULL_ACCOUNT_ROWS_DIFFER"
                        )
                for row in (captured.lease, captured.previous_lease, captured.source_lease):
                    if row is None:
                        continue
                    identity = str(row["lease_sha256"])
                    old = leases.get(identity)
                    if old is not None:
                        if old != row:
                            raise ContinuousObservedHoldSourceError("OBSERVED_LEASE_ROWS_DIFFER")
                    else:
                        leases[identity] = row
                        budget.charge(
                            1,
                            sum(len(v) for v in row.values() if type(v) is bytes),
                            sum(
                                len(str(v).encode())
                                for v in row.values()
                                if v is not None and type(v) is not bytes
                            ),
                        )
                now = (len(pool.rows), pool.byte_count, pool.metadata_bytes)
                budget.charge(*(a - b for a, b in zip(now, charged, strict=True)))
                charged = now
                captured_venue = []
                for ref in venue.capture.manifest.sources:
                    raw = pool.capture(
                        self.venue_sources.journal.capture_in_transaction(
                            connection, ref.key, command_id=ref.receipt.command_id
                        )
                    )
                    now = (len(pool.rows), pool.byte_count, pool.metadata_bytes)
                    budget.charge(*(a - b for a, b in zip(now, charged, strict=True)))
                    charged = now
                    captured_venue.append(raw)
                refs.append(captured)
                historical.append(is_history)
                venue_rows.append(tuple(captured_venue))
            return self._own(
                RuntimeObservedHoldSourceSnapshot(
                    plan,
                    tuple(budget.captured[initial_count:]),
                    _Captured(state, table, tuple(refs), tuple(historical), tuple(venue_rows)),
                )
            )
        except ContinuousObservedHoldSourceError:
            raise
        except Exception:
            raise ContinuousObservedHoldSourceError("OBSERVED_SOURCE_CAPTURE_FAILED") from None

    def _validate_reference(
        self,
        item: RuntimeObservedHoldInputs,
        reference: ResolvedContinuousReference,
        *,
        historical: bool,
        fresh: PreparedContinuousObservedHoldSource | None,
    ) -> None:
        source = item.source
        receipt = reference.receipt
        commit = receipt.commit
        lease = reference.source_lease
        if (
            lease is None
            or lease.semantic_sha256 != source.fence.lease_sha256
            or lease.fence != source.fence.fence
            or lease.policy_sha256 != source.fence.policy_sha256
            or not lease.heartbeat_at
            <= source.fence.validated_at
            < source.valid_until
            <= lease.expires_at
            or source.fence.valid_until > lease.expires_at
        ):
            raise ContinuousObservedHoldSourceError("OBSERVED_ORIGINAL_SOURCE_LEASE_DIFFERS")
        if historical:
            prior = reference.previous_receipt
            parent_fence = receipt.fence_reference
            if (
                prior is None
                or commit.scope != source.scope
                or commit.sequence != source.coordinator_sequence
                or commit.transition.command_id != source.coordinator_command_id
                or commit.transition.checkpoint != source.resulting_checkpoint.object_ref
                or commit.transition.checkpoint_sha256
                != source.resulting_checkpoint.semantic_sha256
                or prior.commit.transition.checkpoint != source.previous_checkpoint.object_ref
                or prior.commit.transition.checkpoint_sha256
                != source.previous_checkpoint.semantic_sha256
                or commit.request != source.frontier
                or commit.source_evidence != source.venue_capture
                or commit.transition.source_closure_sha256 != source.source_closure_sha256
                or commit.transition.expected_heads != source.heads
                or commit.transition.applied_at != source.applied_at
                or not source.checked_at <= receipt.recorded_at < source.valid_until
                or (
                    parent_fence.owner_id,
                    parent_fence.lease_id,
                    parent_fence.fencing_generation,
                    parent_fence.policy_sha256,
                )
                != (
                    source.fence.fence.owner_id,
                    source.fence.fence.lease_id,
                    source.fence.fence.fencing_generation,
                    source.fence.policy_sha256,
                )
            ):
                raise ContinuousObservedHoldSourceError(
                    "OBSERVED_ACTUAL_PARENT_PUBLICATION_DIFFERS"
                )
        else:
            if fresh is None:
                raise ContinuousObservedHoldSourceError("OBSERVED_FRESH_TOKEN_MISSING")
            self.require_prepared(fresh)
            if (
                receipt != fresh.previous.receipt
                or commit.sequence + 1 != source.coordinator_sequence
            ):
                raise ContinuousObservedHoldSourceError(
                    "OBSERVED_ACTUAL_PREVIOUS_PUBLICATION_DIFFERS"
                )

    def resolve_observed_hold_sources(
        self,
        snapshot: RuntimeObservedHoldSourceSnapshot,
        *,
        admissions: tuple[RetainedDailyAdmission, ...],
    ) -> ResolvedRuntimeObservedHoldSources:
        self._require(snapshot, RuntimeObservedHoldSourceSnapshot)
        state = cast(_Captured, snapshot.state)
        try:
            for admission in admissions:
                self.daily.require_admission_view(admission)
            references = []
            for item, venue, fresh, raw, historical, venue_raw in zip(
                state.plan.inputs,
                state.plan.venues,
                state.plan.fresh,
                state.references,
                state.historical,
                state.venue_journals,
                strict=True,
            ):
                reference = self.accounts.resolve_reference(raw)
                self._validate_reference(item, reference, historical=historical, fresh=fresh)
                for original, source in zip(venue_raw, venue.capture.manifest.sources, strict=True):
                    read = self.venue_sources.journal.resolve_snapshot(original)
                    if read.receipt != source.receipt:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_ORIGINAL_VENUE_RECEIPT_DIFFERS"
                        )
                self._validate_inputs(item, venue)
                references.append(reference)
            result = self._own(
                ResolvedRuntimeObservedHoldSources(
                    snapshot, state.plan.inputs, _Resolved(state, tuple(references))
                )
            )
            self._remember(result)
            return result
        except ContinuousObservedHoldSourceError:
            raise
        except Exception:
            raise ContinuousObservedHoldSourceError("OBSERVED_SOURCE_RESOLUTION_FAILED") from None

    def require_resolved(self, value: ResolvedRuntimeObservedHoldSources) -> None:
        self._require(value, ResolvedRuntimeObservedHoldSources)
        state = cast(_Resolved, value.state)
        for reference in state.references:
            self.accounts.require_reference(reference)
        for venue in state.captured.plan.venues:
            self.venue_sources.require_resolved(venue)
        if self._fingerprints.get(id(value)) != self._fingerprint(value):
            raise ContinuousObservedHoldSourceError("ORIGINAL_OBSERVED_SOURCE_CONTENT_CHANGED")

    def require_same_capture(
        self,
        original: ResolvedRuntimeObservedHoldSources,
        fresh: RuntimeObservedHoldSourceSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare complete actual captures without replaying or issuing new inputs."""
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousObservedHoldSourceError("OBSERVED_EXACT_COMPARISON_REQUIRED")
        self._require(original, ResolvedRuntimeObservedHoldSources)
        old = original.snapshot
        for snapshot in (old, fresh):
            self._require(snapshot, RuntimeObservedHoldSourceSnapshot)
            self._require(snapshot.plan, RuntimeObservedHoldSourcePlan)
            if (
                type(snapshot.state) is not _Captured
                or type(snapshot.plan.state) is not _Plan
                or snapshot.state.plan is not snapshot.plan.state
                or type(snapshot.state.plan.objects) is not _Objects
            ):
                raise ContinuousObservedHoldSourceError("OBSERVED_ORIGINAL_CAPTURE_PLAN_DIFFERS")
        resolved = cast(_Resolved, original.state)
        before, after = cast(_Captured, old.state), cast(_Captured, fresh.state)
        if type(resolved) is not _Resolved or resolved.captured is not before:
            raise ContinuousObservedHoldSourceError("OBSERVED_ORIGINAL_RESOLVED_CAPTURE_DIFFERS")
        comparison.data(old.plan.references, fresh.plan.references)
        comparison.data(before.plan.inputs, after.plan.inputs)
        comparison.identity(original.inputs, before.plan.inputs)
        comparison.data(
            (before.plan.objects.references, before.plan.objects.payloads),
            (after.plan.objects.references, after.plan.objects.payloads),
        )
        _require_same_runtime_tables(old.tables, fresh.tables, comparison=comparison)
        _require_same_runtime_tables(
            (before.account_rows,), (after.account_rows,), comparison=comparison
        )
        comparison.data(before.historical, after.historical)
        for old_prepared, fresh_prepared in comparison.pairs(before.plan.fresh, after.plan.fresh):
            comparison.identity(old_prepared, fresh_prepared)
            if old_prepared is not None:
                self._require(old_prepared, PreparedContinuousObservedHoldSource)
        for old_venue, fresh_venue in comparison.pairs(before.plan.venues, after.plan.venues):
            self.venue_sources.require_same_resolved_capture(
                old_venue, fresh_venue, comparison=comparison
            )
        for old_reference, fresh_reference in comparison.pairs(before.references, after.references):
            self.accounts.require_same_reference_capture(
                old_reference, fresh_reference, comparison=comparison
            )
        for left_group, right_group in comparison.pairs(
            before.venue_journals, after.venue_journals
        ):
            for old_journal, fresh_journal in comparison.pairs(left_group, right_group):
                self.venue_sources.journal.require_same_capture(
                    old_journal, fresh_journal, comparison=comparison
                )
        self._require(original, ResolvedRuntimeObservedHoldSources)
        for snapshot in (old, fresh):
            self._require(snapshot, RuntimeObservedHoldSourceSnapshot)
            self._require(snapshot.plan, RuntimeObservedHoldSourcePlan)

    def recheck_observed_hold_sources_in_transaction(
        self, connection: Connection, resolved: ResolvedRuntimeObservedHoldSources
    ) -> None:
        self._require(resolved, ResolvedRuntimeObservedHoldSources)
        state = cast(_Resolved, resolved.state)
        try:
            for reference, venue, historical, fresh in zip(
                state.references,
                state.captured.plan.venues,
                state.captured.historical,
                state.captured.plan.fresh,
                strict=True,
            ):
                self.accounts.recheck_reference_in_transaction(connection, reference)
                self.venue_sources.recheck_in_transaction(connection, venue)
                if not historical:
                    if fresh is None:
                        raise ContinuousObservedHoldSourceError("OBSERVED_FRESH_TOKEN_MISSING")
                    self._require(fresh, PreparedContinuousObservedHoldSource)
                    current = self.accounts.capture_current_in_transaction(
                        connection, scope=fresh.inputs.source.scope
                    )
                    if current != reference.snapshot.current:
                        raise ContinuousObservedHoldSourceError(
                            "OBSERVED_FRESH_CURRENT_ACCOUNT_CHANGED"
                        )
                    self.daily.recheck_snapshot_in_transaction(
                        connection, fresh.current, fence=fresh.inputs.source.fence.fence
                    )
        except ContinuousObservedHoldSourceError:
            raise
        except Exception:
            raise ContinuousObservedHoldSourceError("OBSERVED_SOURCE_RECHECK_FAILED") from None

    def recheck_observed_hold_sources_after_publication_in_transaction(
        self,
        connection: Connection,
        resolved: ResolvedRuntimeObservedHoldSources,
        *,
        prepared_account: object,
        account_receipt: object,
    ) -> None:
        """Recheck original facts against C's actual pending publication.

        The exact C owner authenticates its original issued pair in this same
        transaction. Only that proof replaces the fresh before-head checks;
        B separately rechecks its exact post-write inventory and deadline.
        Detached callers must already have required the complete owned graph.
        """
        self._require(resolved, ResolvedRuntimeObservedHoldSources)
        if (
            type(prepared_account) is not PreparedContinuousCommit
            or type(account_receipt) is not ContinuousAccountReceipt
        ):
            raise ContinuousObservedHoldSourceError("OBSERVED_EXACT_ACCOUNT_PUBLICATION_REQUIRED")
        state = cast(_Resolved, resolved.state)
        try:
            self.accounts.require_committed_in_transaction(
                connection, prepared=prepared_account, receipt=account_receipt
            )
            commit = account_receipt.commit
            for item, reference, venue, historical, fresh in zip(
                resolved.inputs,
                state.references,
                state.captured.plan.venues,
                state.captured.historical,
                state.captured.plan.fresh,
                strict=True,
            ):
                source = item.source
                if source.scope != commit.scope:
                    raise ContinuousObservedHoldSourceError(
                        "OBSERVED_POST_PUBLICATION_ACCOUNT_DIFFERS"
                    )
                self.accounts.recheck_reference_in_transaction(connection, reference)
                self.venue_sources.recheck_in_transaction(connection, venue)
                if historical:
                    continue
                if fresh is None:
                    raise ContinuousObservedHoldSourceError("OBSERVED_FRESH_TOKEN_MISSING")
                self._require(fresh, PreparedContinuousObservedHoldSource)
                parent_fence = account_receipt.fence_reference
                if (
                    prepared_account.previous is None
                    or prepared_account.previous.receipt != reference.receipt
                    or commit.sequence != source.coordinator_sequence
                    or commit.previous_commit_sha256
                    != reference.snapshot.current.row["commit_sha256"]
                    or commit.transition.command_id != source.coordinator_command_id
                    or commit.transition.previous_checkpoint_sha256
                    != source.previous_checkpoint.semantic_sha256
                    or reference.receipt.commit.transition.checkpoint
                    != source.previous_checkpoint.object_ref
                    or commit.transition.checkpoint != source.resulting_checkpoint.object_ref
                    or commit.transition.checkpoint_sha256
                    != source.resulting_checkpoint.semantic_sha256
                    or commit.request != source.frontier
                    or commit.source_evidence != source.venue_capture
                    or commit.transition.source_closure_sha256 != source.source_closure_sha256
                    or commit.transition.expected_heads != source.heads
                    or commit.transition.applied_at != source.applied_at
                    or not source.checked_at <= account_receipt.recorded_at < source.valid_until
                    or (
                        parent_fence.owner_id,
                        parent_fence.lease_id,
                        parent_fence.fencing_generation,
                        parent_fence.policy_sha256,
                    )
                    != (
                        source.fence.fence.owner_id,
                        source.fence.fence.lease_id,
                        source.fence.fence.fencing_generation,
                        source.fence.policy_sha256,
                    )
                ):
                    raise ContinuousObservedHoldSourceError(
                        "OBSERVED_ACTUAL_PENDING_PUBLICATION_DIFFERS"
                    )
        except ContinuousObservedHoldSourceError:
            raise
        except Exception:
            raise ContinuousObservedHoldSourceError(
                "OBSERVED_POST_PUBLICATION_RECHECK_FAILED"
            ) from None
