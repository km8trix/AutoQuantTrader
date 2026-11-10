"""Original independent venue observations for attempt metadata, never delivery.

The observation producer reads the actual independent venue before retaining its
capture. Historical resolution uses original coordinator capture journals and C
metadata; it does not query the venue or restore C from within B history replay.
"""

from collections.abc import Callable
from dataclasses import dataclass, field, fields
from typing import Any, TypeVar, cast
from weakref import WeakValueDictionary, finalize

from sqlalchemy import Connection

from packages.application.stateful_venue import venue_order_id
from packages.domain.accounting_contracts import RegisterVenueSubmission
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.continuous_runtime_attempt_contracts import (
    RUNTIME_ATTEMPT_OUTCOME_SCHEMA,
    ContinuousRuntimeOutcomeEvidence,
)
from packages.domain.daily_attempt_contracts import (
    CanonicalDailyAttempt,
    DailyAttemptEnvelope,
    DailyDispatchClaim,
    DailyObservedOutcome,
)
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.research_job_contracts import ObjectRef
from packages.domain.stateful_venue_contracts import VenueSourceReference, VenueSubmit
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.domain.venue_reconciliation_contracts import (
    VENUE_CAPTURE_SCHEMA,
    RetainedVenueCapture,
    VenueAccountBinding,
    VenueCaptureRequest,
    VenueSubmissionBinding,
)
from packages.persistence.continuous_account import (
    ContinuousReferenceSnapshot,
    ResolvedContinuousAccount,
    ResolvedContinuousReference,
)
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_capture_comparison import ContinuousCaptureComparison
from packages.persistence.continuous_runtime_attempt_sources import (
    CHECKPOINT_SCHEMA,
    OriginalContinuousRuntimeAttemptPrefix,
    SqlContinuousRuntimeAttemptSources,
    _Graph,
)
from packages.persistence.continuous_venue_sources import (
    ResolvedContinuousVenueSources,
    SqlContinuousVenueSources,
)
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    RuntimeReadBudget,
    RuntimeTableSnapshot,
    _recheck_table,
    capture_runtime_table,
)
from packages.persistence.detached_journal_capture import DetachedJournalCapture
from packages.persistence.durable_journal import JournalReadSnapshot
from packages.persistence.schema import phase2_account_leases
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture

T = TypeVar("T")


class ContinuousAttemptOutcomeError(ValueError):
    pass


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OriginalAttemptOutcomePlan:
    reference: ContinuousEvidenceRef
    evidence: ContinuousRuntimeOutcomeEvidence
    checkpoint: CausalEngineCheckpoint
    venue: ResolvedContinuousVenueSources
    outcome: DailyObservedOutcome | None
    object_refs: tuple[ObjectRef, ...]
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OriginalCapturedAttemptOutcome:
    plan: OriginalAttemptOutcomePlan
    activation: ResolvedContinuousReference
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class AttemptOutcomeSnapshot:
    plan: OriginalAttemptOutcomePlan
    activation: ContinuousReferenceSnapshot
    venue: tuple[JournalReadSnapshot, ...]
    leases: RuntimeTableSnapshot
    seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ResolvedAttemptOutcome:
    snapshot: AttemptOutcomeSnapshot
    activation: ResolvedContinuousReference
    prefix: OriginalContinuousRuntimeAttemptPrefix
    outcome: DailyObservedOutcome
    seal: object = field(repr=False, compare=False)


class SqlContinuousAttemptOutcomeSources:
    def __init__(
        self,
        *,
        attempts: SqlContinuousRuntimeAttemptSources,
        venue: SqlStatefulVenue,
        capture: SqlVenueReconciliationCapture,
        venue_sources: SqlContinuousVenueSources,
    ) -> None:
        from packages.persistence.continuous_simulation_delivery import (
            SqlContinuousSimulationDelivery,
        )

        if (
            type(attempts) is not SqlContinuousRuntimeAttemptSources
            or type(venue) is not SqlStatefulVenue
            or type(capture) is not SqlVenueReconciliationCapture
            or type(venue_sources) is not SqlContinuousVenueSources
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_EXACT_ACTUAL_OWNERS_REQUIRED")
        attempts._require_bindings()
        delivery = venue.verified_sources
        if (
            type(delivery) is not SqlContinuousSimulationDelivery
            or delivery.sources is not attempts
            or delivery.publisher.account is not attempts.accounts
            or delivery.venue is not venue
            or delivery._require_owners() is not venue
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_DELIVERY_VENUE_GRAPH_REQUIRED")
        runtime = attempts.runtime_sources
        scope = ReconciliationScope(
            runtime.venue_model.account_id,
            runtime.venue_model.venue_id,
            "stateful_simulation",
            runtime.venue_reference.semantic_sha256_ref,
            "stateful_simulation",
        )
        if (
            venue.model != runtime.venue_model
            or venue.journal._engine is attempts.engine
            or venue.codec is not attempts.codec
            or capture.engine is not attempts.engine
            or capture.codec is not attempts.codec
            or capture.artifacts is not attempts.artifacts
            or venue_sources.engine is not attempts.engine
            or venue_sources.codec is not attempts.codec
            or venue_sources.artifacts is not attempts.artifacts
            or venue_sources.scope != scope
            or venue_sources.model != runtime.venue_model
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_VENUE_SCOPE_OR_GRAPH_DIFFERS")
        self.attempts, self.venue, self.capture = attempts, venue, capture
        self.venue_sources, self.scope = venue_sources, scope
        self._delivery = delivery
        self._seal = object()
        self._owned: WeakValueDictionary[int, Any] = WeakValueDictionary()
        self._value_fields: dict[int, tuple[tuple[str, object], ...]] = {}
        self._fields: dict[int, tuple[tuple[object, tuple[tuple[str, object], ...]], ...]] = {}
        self._bindings = self._binding_values()

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self.attempts,
            self.attempts.accounts,
            self.attempts.daily,
            self.attempts.runtime_sources,
            self.attempts.engine,
            self.attempts.artifacts,
            self.attempts.codec,
            self.venue,
            self.venue.model,
            self.venue.journal,
            self.venue.journal._engine,
            self.venue.journal._codec,
            self.venue.artifacts,
            self.venue.codec,
            self.venue.accounting,
            self.venue.verified_sources,
            self._delivery,
            self._delivery.venue,
            *self._delivery._bindings(),
            self.capture,
            self.capture.engine,
            self.capture.artifacts,
            self.capture.codec,
            self.capture.clock,
            self.capture.journal,
            self.venue_sources,
            self.venue_sources.engine,
            self.venue_sources.artifacts,
            self.venue_sources.codec,
            self.venue_sources.resolver,
            self.venue_sources.scope,
            self.venue_sources.model,
            self.venue_sources.journal,
        )

    def require_bindings(self) -> None:
        self.attempts._require_bindings()
        if any(a is not b for a, b in zip(self._bindings, self._binding_values(), strict=True)):
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_OWNERS_CHANGED")

    def _own(self, value: T) -> T:
        records: list[object] = []
        plan = value if type(value) is OriginalAttemptOutcomePlan else getattr(value, "plan", None)
        if type(value) is ResolvedAttemptOutcome:
            plan = cast(ResolvedAttemptOutcome, value).snapshot.plan
        if type(value) is AttemptOutcomeSnapshot:
            snapshot = cast(AttemptOutcomeSnapshot, value)
            records.append(snapshot.leases)
            for captured_read in snapshot.venue:
                records.extend((captured_read, captured_read.key))
        if type(plan) is OriginalAttemptOutcomePlan:
            e = plan.evidence
            records.extend(
                (
                    plan,
                    plan.reference,
                    plan.reference.object_ref,
                    plan.venue,
                    plan.venue.capture,
                    plan.venue.capture.manifest,
                    e,
                    e.activation,
                    e.activation.commit,
                    e.activation.commit.transition,
                    e.activation.fence_reference,
                    e.activation_checkpoint,
                    e.activation_checkpoint.object_ref,
                    e.activation_source,
                    e.activation_source.object_ref,
                    e.capture,
                    e.capture.object_ref,
                    e.registration,
                    e.registration.registration,
                    e.registration.registration.source_commitment,
                    e.registration.registration.submission,
                    e.registration.registration.submission.intent,
                    e.registration.risk_source,
                    e.registration.risk_source.object_ref,
                    e.registration.dispatch_source,
                    e.registration.dispatch_source.object_ref,
                )
            )
            if plan.outcome is not None:
                records.extend(
                    (
                        plan.outcome,
                        plan.outcome.scope,
                        plan.outcome.order,
                        plan.outcome.source,
                        plan.outcome.source.object_ref,
                    )
                )
            for source, read in zip(
                plan.venue.capture.manifest.sources, plan.venue.reads, strict=True
            ):
                records.extend(
                    (
                        source,
                        source.evidence,
                        source.evidence.object_ref,
                        source.key,
                        source.receipt,
                        source.receipt.previous_head,
                        source.receipt.committed_head,
                        read,
                        read.head,
                        read.snapshot,
                        read.snapshot.key,
                    )
                )
        self._owned[id(value)] = value
        self._value_fields[id(value)] = tuple(
            (f.name, getattr(value, f.name)) for f in fields(cast(Any, value))
        )
        self._fields[id(value)] = tuple(
            (record, tuple((f.name, getattr(record, f.name)) for f in fields(cast(Any, record))))
            for record in records
            if record is not value
        )
        finalize(value, self._value_fields.pop, id(value), None)
        finalize(value, self._fields.pop, id(value), None)
        return value

    def _require(self, value: object, kind: type[Any]) -> None:
        self.require_bindings()
        if (
            type(value) is not kind
            or self._owned.get(id(value)) is not value
            or any(
                getattr(value, name) is not original
                for name, original in self._value_fields.get(id(value), ())
            )
            or any(
                getattr(record, name) is not original
                for record, values in self._fields.get(id(value), ())
                for name, original in values
            )
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_OWNED_ORIGINAL_REQUIRED")

    @staticmethod
    def _original_dispatch(
        attempt: CanonicalDailyAttempt, envelopes: tuple[DailyAttemptEnvelope, ...]
    ) -> tuple[DailyDispatchClaim, DailyAttemptEnvelope]:
        claims = [event.dispatch for event in attempt.events if event.dispatch is not None]
        parents = [
            envelope
            for envelope in envelopes
            if envelope.event.attempt_id == attempt.attempt_id
            and envelope.event.dispatch is not None
        ]
        if len(claims) != 1 or len(parents) != 1 or parents[0].event.dispatch != claims[0]:
            raise ContinuousAttemptOutcomeError("OUTCOME_EXACT_ORIGINAL_DISPATCH_REQUIRED")
        return claims[0], parents[0]

    def _packet(self, checkpoint: CausalEngineCheckpoint, claim: DailyDispatchClaim) -> VenueSubmit:
        prep = claim.record.preparation
        request = prep.request
        holds = [
            hold
            for hold in checkpoint.state.commitments
            if hold.commitment_id == request.original_commitment.commitment_id
        ]
        model = self.venue_sources.model
        if (
            len(holds) != 1
            or holds[0].state != "active"
            or request.venue_account_id != model.account_id
            or request.venue_model != self.attempts.runtime_sources.venue_reference
            or checkpoint.state.account_id != request.source_account_id
            or request.submission not in checkpoint.state.submissions
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_ACTIVE_RESULT_REQUIRED")
        return VenueSubmit(
            RegisterVenueSubmission(
                account_id=model.account_id,
                submission=request.submission,
                source_commitment=holds[0],
                source_risk_admission_sha256=prep.admission_source.semantic_sha256_ref,
                source_dispatch_sha256=claim.record.semantic_sha256,
                venue_model_sha256=model.execution_policy.semantic_sha256,
            ),
            prep.admission_source,
            VenueSourceReference(model.producer, claim.record.semantic_sha256, claim.record_ref),
        )

    def observe(
        self,
        *,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        attempt_id: str,
        capture_id: str,
    ) -> OriginalCapturedAttemptOutcome:
        """Collect independently; an unresolved capture remains unusable as an outcome."""
        self.require_bindings()
        self.attempts._fresh_prefix(previous, current)
        matches = [item for item in current.attempts if item.attempt_id == attempt_id]
        if len(matches) != 1 or matches[0].state not in (
            SubmissionAttemptState.IN_FLIGHT,
            SubmissionAttemptState.UNKNOWN,
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_UNRESOLVED_ATTEMPT_REQUIRED")
        claim, parent = self._original_dispatch(matches[0], current.attempt_envelopes)
        with self.attempts.accounts.write_transaction() as connection:
            raw = self.attempts.accounts.capture_reference_in_transaction(
                connection,
                scope=previous.receipt.commit.scope,
                command_id=parent.coordinator_command_id,
                source_lease_sha256=claim.record.activation.fence.lease_sha256,
            )
        if raw is None:
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_ACTIVATION_PARENT_REQUIRED")
        activation = self.attempts.accounts.resolve_reference(raw)
        receipt = activation.receipt
        graph = _Graph(self.attempts.artifacts, self.attempts.codec)
        cp_ref = ContinuousEvidenceRef(
            CHECKPOINT_SCHEMA,
            receipt.commit.transition.checkpoint,
            receipt.commit.transition.checkpoint_sha256,
        )
        cp = graph.read(cp_ref, CausalEngineCheckpoint, CHECKPOINT_SCHEMA)
        expected = self._packet(cp, claim)
        if (
            receipt.commit.source_evidence != parent.source_ref
            or receipt.commit.sequence != parent.coordinator_sequence
            or receipt.fence_reference.lease_sha256 != claim.record.activation.fence.lease_sha256
            or cp.now != claim.record.dispatched_at
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_ACTIVATION_PARENT_DIFFERS")
        independent = self.venue.read()
        registrations = [
            command.payload
            for command, ack in zip(
                independent.state.commands, independent.state.acknowledgments, strict=True
            )
            if type(command.payload) is VenueSubmit
            and command.payload.registration.submission.order_id
            == expected.registration.submission.order_id
            and ack.disposition == "registered"
        ]
        if registrations != [expected]:
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_REGISTERED_ORDER_REQUIRED")
        mapping = VenueSubmissionBinding(
            expected.registration.submission,
            registrations[0].registration.semantic_sha256,
            venue_order_id(self.venue.model, expected.registration.submission.order_id),
        )
        captured = self.capture.capture(
            VenueCaptureRequest(
                capture_id,
                VenueAccountBinding(
                    self.scope, self.venue.model, self.venue.model.semantic_sha256, (mapping,)
                ),
                claim.record.dispatched_at,
                independent.state.as_of,
                independent.head,
            ),
            venue=self.venue,
        )
        capture_ref = graph.encode(VENUE_CAPTURE_CLOSURE_SCHEMA, captured)
        evidence = ContinuousRuntimeOutcomeEvidence(
            attempt_id=attempt_id,
            activation=receipt,
            activation_checkpoint=cp_ref,
            activation_source=parent.source_ref,
            capture=capture_ref,
            registration=registrations[0],
        )
        reference = graph.encode(RUNTIME_ATTEMPT_OUTCOME_SCHEMA, evidence)
        graph.publish()
        plan = self.prepare(reference, admit_objects=graph.admit)
        return self._own(OriginalCapturedAttemptOutcome(plan, activation, self._seal))

    def prepare(
        self,
        reference: ContinuousEvidenceRef,
        *,
        admit_objects: Callable[[tuple[ObjectRef, ...]], None],
    ) -> OriginalAttemptOutcomePlan:
        self.require_bindings()
        graph = _Graph(self.attempts.artifacts, self.attempts.codec)

        def admit(refs: tuple[ObjectRef, ...]) -> None:
            admit_objects(refs)
            graph.admit(refs)

        admit((reference.object_ref,))
        evidence = graph.read(
            reference, ContinuousRuntimeOutcomeEvidence, RUNTIME_ATTEMPT_OUTCOME_SCHEMA
        )
        admit(
            (
                evidence.activation_checkpoint.object_ref,
                evidence.activation_source.object_ref,
                evidence.capture.object_ref,
            )
        )
        checkpoint = graph.read(
            evidence.activation_checkpoint, CausalEngineCheckpoint, CHECKPOINT_SCHEMA
        )
        capture = graph.read(evidence.capture, RetainedVenueCapture, VENUE_CAPTURE_CLOSURE_SCHEMA)
        admit(tuple(source.evidence.object_ref for source in capture.manifest.sources))
        venue = self.venue_sources.resolve(capture)
        if capture.observed.source_blockers:
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_CAPTURE_BLOCKED")
        for source, page in zip(capture.manifest.sources, venue.pages, strict=True):
            if graph.encode(VENUE_CAPTURE_SCHEMA, page) != ContinuousEvidenceRef(
                source.evidence.schema_id,
                source.evidence.object_ref,
                source.evidence.semantic_sha256,
            ):
                raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_CAPTURE_OBJECT_DIFFERS")
            if page.request.binding.orders != (
                VenueSubmissionBinding(
                    evidence.registration.registration.submission,
                    evidence.registration.registration.semantic_sha256,
                    venue_order_id(
                        self.venue_sources.model,
                        evidence.registration.registration.submission.order_id,
                    ),
                ),
            ):
                raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_CAPTURE_MAPPING_DIFFERS")
        selected = [
            order
            for order in capture.observed.orders
            if order.order_id == evidence.registration.registration.submission.order_id
        ]
        outcome = None
        if len(selected) == 1 and selected[0].status in (
            "working",
            "partial",
            "pending_cancel",
            "filled",
            "canceled",
            "rejected",
        ):
            order = selected[0]
            original_pages = [
                (source, page)
                for source, page in zip(capture.manifest.sources, venue.pages, strict=True)
                if order in page.body.orders
            ]
            if not original_pages:
                raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_ORDER_PAGE_MISSING")
            source, _page = original_pages[0]
            outcome = DailyObservedOutcome(
                scope=self.scope,
                order=order,
                source=VenueSourceReference(
                    self.venue_sources.model.producer,
                    source.evidence.semantic_sha256,
                    source.evidence.object_ref,
                ),
                observed_at=capture.observed.completed_at,
                resolution="rejected" if order.status == "rejected" else "accepted",
            )
        elif len(selected) > 1:
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_ORDER_INVENTORY_DIFFERS")
        return self._own(
            OriginalAttemptOutcomePlan(
                reference,
                evidence,
                checkpoint,
                venue,
                outcome,
                tuple(graph.refs.values()),
                self._seal,
            )
        )

    def require_plan(self, value: OriginalAttemptOutcomePlan) -> None:
        self._require(value, OriginalAttemptOutcomePlan)
        if self._delivery._require_owners() is not self.venue:
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_DELIVERY_VENUE_GRAPH_REQUIRED")
        self.venue_sources.require_resolved(value.venue)
        if (
            value.reference.semantic_sha256 != value.evidence.semantic_sha256
            or value.checkpoint.semantic_sha256
            != value.evidence.activation_checkpoint.semantic_sha256
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_PLAN_CONTENT_CHANGED")

    def require_same_capture(
        self,
        original: AttemptOutcomeSnapshot,
        fresh: AttemptOutcomeSnapshot,
        *,
        comparison: ContinuousCaptureComparison,
    ) -> None:
        """Compare complete original outcome inputs without resolving an outcome."""
        if type(comparison) is not ContinuousCaptureComparison:
            raise ContinuousAttemptOutcomeError("EXACT_CAPTURE_COMPARISON_REQUIRED")
        for value in (original, fresh):
            self._require(value, AttemptOutcomeSnapshot)
            self._require(value.plan, OriginalAttemptOutcomePlan)
        if self._delivery._require_owners() is not self.venue:
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_DELIVERY_VENUE_GRAPH_REQUIRED")
        left, right = original.plan, fresh.plan
        comparison.data(
            (left.reference, left.evidence, left.checkpoint, left.outcome, left.object_refs),
            (right.reference, right.evidence, right.checkpoint, right.outcome, right.object_refs),
        )
        self.venue_sources.require_same_resolved_capture(
            left.venue, right.venue, comparison=comparison
        )
        self.attempts.accounts.require_same_reference_capture(
            original.activation, fresh.activation, comparison=comparison
        )
        for a, b in comparison.pairs(original.venue, fresh.venue):
            self.venue_sources.journal.require_same_capture(a, b, comparison=comparison)
        for lease_table in (original.leases, fresh.leases):
            if (
                type(lease_table) is not RuntimeTableSnapshot
                or lease_table.table is not phase2_account_leases
            ):
                raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_LEASE_TABLE_REQUIRED")
        comparison.identity(original.leases.table, fresh.leases.table)
        comparison.data(
            (original.leases.account_id, original.leases.rows),
            (fresh.leases.account_id, fresh.leases.rows),
        )
        for value in (original, fresh):
            self._require(value.plan, OriginalAttemptOutcomePlan)
            self._require(value, AttemptOutcomeSnapshot)
        if self._delivery._require_owners() is not self.venue:
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_DELIVERY_VENUE_GRAPH_REQUIRED")

    def require_observation(self, value: OriginalCapturedAttemptOutcome) -> None:
        self._require(value, OriginalCapturedAttemptOutcome)
        self.require_plan(value.plan)
        self.attempts.accounts.require_reference(value.activation)
        if value.activation.receipt != value.plan.evidence.activation:
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_OBSERVATION_PARENT_DIFFERS")

    def capture_in_transaction(
        self,
        connection: Connection,
        plan: OriginalAttemptOutcomePlan,
        *,
        budget: RuntimeReadBudget,
        journal_pool: DetachedJournalCapture,
    ) -> AttemptOutcomeSnapshot:
        self._require(plan, OriginalAttemptOutcomePlan)
        if type(budget) is not RuntimeReadBudget or connection.engine is not self.attempts.engine:
            raise ContinuousAttemptOutcomeError("OUTCOME_SAME_ENGINE_SHARED_BUDGET_REQUIRED")
        account_id = plan.evidence.activation.commit.scope.account_id
        leases = [
            item
            for item in budget.captured
            if item.table is phase2_account_leases and item.account_id == account_id
        ]
        if len(leases) > 1:
            raise ContinuousAttemptOutcomeError("OUTCOME_DUPLICATE_LEASE_CAPTURE")
        lease_table = (
            leases[0]
            if leases
            else capture_runtime_table(
                connection, phase2_account_leases, account_id=account_id, budget=budget
            )
        )
        if leases:
            _recheck_table(connection, lease_table)
        before = (len(journal_pool.rows), journal_pool.byte_count, journal_pool.metadata_bytes)

        def charge() -> None:
            nonlocal before
            after = (len(journal_pool.rows), journal_pool.byte_count, journal_pool.metadata_bytes)
            budget.charge(*(new - old for new, old in zip(after, before, strict=True)))
            before = after

        activation = self.attempts.accounts.capture_reference_in_transaction(
            connection,
            scope=plan.evidence.activation.commit.scope,
            command_id=plan.evidence.activation.commit.transition.command_id,
            source_lease_sha256=plan.evidence.activation.fence_reference.lease_sha256,
            journal_pool=journal_pool,
        )
        if activation is None:
            raise ContinuousAttemptOutcomeError("OUTCOME_ACTUAL_ACTIVATION_PARENT_MISSING")
        # These compact rows are extra actual copies, even when an enclosing
        # source read already captured the complete C table. Charge each copy
        # before another journal read; lease rows share the table above.
        for index in (activation.current, activation.previous):
            if index is not None:
                budget.charge(
                    1,
                    *self.attempts.daily._row_sizes(continuous_account_commits, index.row),
                )
        charge()
        for lease in (activation.lease, activation.previous_lease, activation.source_lease):
            if lease is not None and not any(dict(row) == dict(lease) for row in lease_table.rows):
                raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_LEASE_CAPTURE_DIFFERS")
        rows = []
        for source in plan.venue.capture.manifest.sources:
            rows.append(
                journal_pool.capture(
                    self.venue_sources.journal.capture_in_transaction(
                        connection, source.key, command_id=source.receipt.command_id
                    )
                )
            )
            charge()
        return self._own(
            AttemptOutcomeSnapshot(plan, activation, tuple(rows), lease_table, self._seal)
        )

    def resolve(
        self, snapshot: AttemptOutcomeSnapshot, *, prefix: OriginalContinuousRuntimeAttemptPrefix
    ) -> ResolvedAttemptOutcome:
        self._require(snapshot, AttemptOutcomeSnapshot)
        self.require_plan(snapshot.plan)
        self.attempts.require_prefix(prefix)
        plan = snapshot.plan
        evidence = plan.evidence
        actual = self.attempts.accounts.resolve_reference(snapshot.activation)
        if actual.receipt != evidence.activation or plan.outcome is None:
            raise ContinuousAttemptOutcomeError(
                "OUTCOME_ACTUAL_PARENT_AND_DEFINITIVE_ORDER_REQUIRED"
            )
        for raw, original in zip(snapshot.venue, plan.venue.reads, strict=True):
            resolved = self.venue_sources.journal.resolve_snapshot(raw)
            if (
                resolved.receipt != original.receipt
                or raw.requested_receipt != original.snapshot.requested_receipt
            ):
                raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_CAPTURE_ROWS_DIFFER")
        matches = [
            attempt for attempt in prefix.attempts if attempt.attempt_id == evidence.attempt_id
        ]
        if len(matches) != 1 or matches[0].state not in (
            SubmissionAttemptState.IN_FLIGHT,
            SubmissionAttemptState.UNKNOWN,
        ):
            raise ContinuousAttemptOutcomeError("OUTCOME_ORIGINAL_UNRESOLVED_PREFIX_REQUIRED")
        claim, parent = self._original_dispatch(matches[0], prefix.attempt_envelopes)
        if (
            evidence.activation_source != parent.source_ref
            or evidence.activation.commit.sequence != parent.coordinator_sequence
            or evidence.activation.commit.scope != prefix.reference.receipt.commit.scope
            or evidence.activation.fence_reference.lease_sha256
            != claim.record.activation.fence.lease_sha256
            or plan.checkpoint.now != claim.record.dispatched_at
            or evidence.registration != self._packet(plan.checkpoint, claim)
            or not claim.record.dispatched_at
            <= plan.outcome.observed_at
            <= prefix.source.checked_at
        ):
            raise ContinuousAttemptOutcomeError(
                "OUTCOME_ORIGINAL_DISPATCH_ACTIVATION_OR_TIME_DIFFERS"
            )
        return self._own(ResolvedAttemptOutcome(snapshot, actual, prefix, plan.outcome, self._seal))

    def require_resolved(self, value: ResolvedAttemptOutcome) -> None:
        self._require(value, ResolvedAttemptOutcome)
        self.require_plan(value.snapshot.plan)
        self.attempts.accounts.require_reference(value.activation)
        self.attempts.require_prefix(value.prefix)

    def recheck_in_transaction(self, connection: Connection, value: ResolvedAttemptOutcome) -> None:
        self._require(value, ResolvedAttemptOutcome)
        self._require(value.snapshot, AttemptOutcomeSnapshot)
        self._require(value.snapshot.plan, OriginalAttemptOutcomePlan)
        self.attempts.accounts.recheck_reference_in_transaction(connection, value.activation)
        self.attempts.recheck_prefix_in_transaction(connection, value.prefix)
        self.venue_sources.recheck_in_transaction(connection, value.snapshot.plan.venue)
