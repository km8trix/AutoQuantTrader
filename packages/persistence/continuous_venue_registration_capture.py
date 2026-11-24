"""Capture financial observations with original coordinator registration mappings.

Read the independent venue once for discovery and capture that exact head. Only
registrations matching an original durable dispatch and its activated C result
receive coordinator order identities. External registrations stay unmapped and
remain reconciliation differences. This path changes no financial account state.
"""

from collections.abc import Mapping
from typing import Any

from packages.application.stateful_venue import venue_order_id
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ContinuousEngineSpec
from packages.domain.continuous_persistence_contracts import ContinuousEvidenceRef
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.stateful_venue_contracts import VenueSubmit
from packages.domain.venue_reconciliation_contracts import (
    VenueAccountBinding,
    VenueCaptureRequest,
    VenueSubmissionBinding,
)
from packages.persistence.continuous_account import ResolvedContinuousAccount
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_attempt_sources import CHECKPOINT_SCHEMA, _Graph
from packages.persistence.continuous_venue_sources import ResolvedContinuousVenueSources
from packages.persistence.daily_runtime_risk import (
    MAX_METADATA_BYTES,
    MAX_TOTAL_BYTES,
    ResolvedDailyRuntimeSnapshot,
    RuntimeReadBudget,
)
from packages.persistence.detached_journal_capture import DetachedJournalCapture


class SqlContinuousVenueRegistrationCapture:
    def __init__(self, *, outcomes: SqlContinuousAttemptOutcomeSources) -> None:
        if type(outcomes) is not SqlContinuousAttemptOutcomeSources:
            raise ValueError("EXACT_REGISTRATION_OUTCOME_OWNER_REQUIRED")
        outcomes.require_bindings()
        self.outcomes = outcomes
        self.attempts = outcomes.attempts
        self.account = self.attempts.accounts
        self.daily = self.attempts.daily
        self.runtime = self.attempts.runtime_sources
        publisher = self.runtime.publisher
        composer = self.account.composer
        if (
            type(publisher) is not SqlContinuousReconciliationPublication
            or type(composer) is not SqlContinuousCommitComposer
            or publisher.account is not self.account
            or publisher.sources is not composer.venue_sources
            or publisher.sources.model is not self.runtime.venue_model
        ):
            raise ValueError("EXACT_REGISTRATION_FINANCIAL_GRAPH_REQUIRED")
        self.publisher, self.composer = publisher, composer
        self.sources = publisher.sources
        self._bindings = self._binding_values()

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self.outcomes,
            self.attempts,
            self.account,
            self.daily,
            self.runtime,
            self.publisher,
            self.sources,
            self.publisher.account,
            self.publisher.sources,
            self.outcomes.attempts,
            self.attempts.accounts,
            self.attempts.daily,
            self.attempts.runtime_sources,
            self.runtime.publisher,
            self.composer,
            self.account.composer,
            self.composer.venue_sources,
            self.sources.engine,
            self.sources.artifacts,
            self.sources.codec,
            self.sources.scope,
            self.sources.model,
            self.sources.resolver,
            self.sources.journal,
        )

    def _require_bindings(self) -> None:
        self.outcomes.require_bindings()
        if any(a is not b for a, b in zip(self._bindings, self._binding_values(), strict=True)):
            raise ValueError("ORIGINAL_REGISTRATION_GRAPH_CHANGED")
        if self.outcomes._delivery._require_owners() is not self.outcomes.venue:
            raise ValueError("ORIGINAL_REGISTRATION_VENUE_CHANGED")

    @staticmethod
    def _charge_row(budget: RuntimeReadBudget, row: Mapping[str, Any] | None) -> None:
        if row is None:
            return
        payload = sum(len(value) for value in row.values() if type(value) is bytes)
        metadata = sum(
            len(value.encode("utf-8")) if type(value) is str else 16
            for value in row.values()
            if type(value) is not bytes
        )
        budget.charge(1, payload, metadata)

    def capture(
        self,
        *,
        capture_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
    ) -> ResolvedContinuousVenueSources:
        self._require_bindings()
        self.attempts._fresh_prefix(previous, current)
        scope = previous.receipt.commit.scope
        spec = previous.checkpoint.inputs.spec
        if type(spec) is not ContinuousEngineSpec:
            raise ValueError("ORIGINAL_CONTINUOUS_REGISTRATION_SPEC_REQUIRED")
        if self.sources.scope != ReconciliationScope(
            scope.account_id,
            self.outcomes.venue.model.venue_id,
            "stateful_simulation",
            scope.account_binding_sha256,
            "stateful_simulation",
        ):
            raise ValueError("ORIGINAL_REGISTRATION_FINANCIAL_SCOPE_DIFFERS")
        independent = self.outcomes.venue.read()
        registrations: dict[str, VenueSubmit] = {}
        for command, ack in zip(
            independent.state.commands, independent.state.acknowledgments, strict=True
        ):
            if type(command.payload) is VenueSubmit and ack.disposition == "registered":
                order_id = command.payload.registration.submission.order_id
                if order_id in registrations:
                    raise ValueError("ORIGINAL_REGISTRATION_INVENTORY_DUPLICATE")
                registrations[order_id] = command.payload
        if len(registrations) > 200:
            raise ValueError("ORIGINAL_REGISTRATION_INVENTORY_LIMIT")
        selected = []
        for attempt in current.attempts:
            if any(event.dispatch is not None for event in attempt.events):
                claim, parent = self.outcomes._original_dispatch(attempt, current.attempt_envelopes)
                order_id = claim.record.preparation.request.submission.order_id
                if order_id in registrations:
                    selected.append((claim, parent))
        if len(selected) > 200:
            raise ValueError("ORIGINAL_REGISTRATION_MAPPING_LIMIT")
        budget = RuntimeReadBudget()
        pool = DetachedJournalCapture(
            max_bytes=MAX_TOTAL_BYTES, max_metadata_bytes=MAX_METADATA_BYTES
        )
        snapshots = []
        fence = self.runtime.current_fence()
        with self.account.write_transaction() as connection:
            self.account.recheck_in_transaction(connection, previous, require_current=True)
            self.daily.recheck_snapshot_in_transaction(connection, current, fence=fence)
            for claim, parent in selected:
                before_pool = (len(pool.rows), pool.byte_count, pool.metadata_bytes)
                raw = self.account.capture_reference_in_transaction(
                    connection,
                    scope=scope,
                    command_id=parent.coordinator_command_id,
                    source_lease_sha256=claim.record.activation.fence.lease_sha256,
                    journal_pool=pool,
                )
                if raw is None:
                    raise ValueError("ORIGINAL_REGISTRATION_ACTIVATION_MISSING")
                budget.charge(
                    len(pool.rows) - before_pool[0],
                    pool.byte_count - before_pool[1],
                    pool.metadata_bytes - before_pool[2],
                )
                for row in (
                    raw.current.row,
                    None if raw.previous is None else raw.previous.row,
                    raw.lease,
                    raw.previous_lease,
                    raw.source_lease,
                ):
                    self._charge_row(budget, row)
                # The journal pool already retains its earlier rows. Its next
                # capture must share the remaining allowance with all C rows.
                pool.max_bytes = pool.byte_count + MAX_TOTAL_BYTES - budget.payload_bytes
                pool.max_metadata_bytes = (
                    pool.metadata_bytes + MAX_METADATA_BYTES - budget.metadata_bytes
                )
                snapshots.append(raw)
        graph = _Graph(self.attempts.artifacts, self.attempts.codec)
        mappings = []
        resolved = []
        for (claim, parent), raw in zip(selected, snapshots, strict=True):
            activation = self.account.resolve_reference(raw)
            receipt = activation.receipt
            checkpoint_ref = ContinuousEvidenceRef(
                CHECKPOINT_SCHEMA,
                receipt.commit.transition.checkpoint,
                receipt.commit.transition.checkpoint_sha256,
            )
            graph.admit((checkpoint_ref.object_ref,))
            if graph.total + budget.payload_bytes > MAX_TOTAL_BYTES:
                raise ValueError("ORIGINAL_REGISTRATION_COMPLETE_GRAPH_LIMIT")
            checkpoint = graph.read(checkpoint_ref, CausalEngineCheckpoint, CHECKPOINT_SCHEMA)
            expected = self.outcomes._packet(checkpoint, claim)
            if (
                receipt.commit.source_evidence != parent.source_ref
                or receipt.commit.sequence != parent.coordinator_sequence
                or receipt.fence_reference.lease_sha256
                != claim.record.activation.fence.lease_sha256
                or checkpoint.now != claim.record.dispatched_at
                or registrations[expected.registration.submission.order_id] != expected
            ):
                raise ValueError("ORIGINAL_REGISTRATION_ACTIVATION_DIFFERS")
            mappings.append(
                VenueSubmissionBinding(
                    expected.registration.submission,
                    expected.registration.semantic_sha256,
                    venue_order_id(
                        self.outcomes.venue.model, expected.registration.submission.order_id
                    ),
                )
            )
            resolved.append(activation)
        captured = self.outcomes.capture.capture(
            VenueCaptureRequest(
                capture_id,
                VenueAccountBinding(
                    self.sources.scope,
                    self.outcomes.venue.model,
                    self.outcomes.venue.model.semantic_sha256,
                    tuple(sorted(mappings, key=lambda item: item.submission.order_id)),
                ),
                spec.initialized_at,
                independent.state.as_of,
                independent.head,
            ),
            venue=self.outcomes.venue,
        )
        result = self.sources.resolve(captured)
        self._require_bindings()
        self.attempts._fresh_prefix(previous, current)
        self.sources.require_resolved(result)
        for activation in resolved:
            self.account.require_reference(activation)
        with self.account.write_transaction() as connection:
            self.account.recheck_in_transaction(connection, previous, require_current=True)
            for activation in resolved:
                self.account.recheck_reference_in_transaction(connection, activation)
            self.sources.recheck_in_transaction(connection, result)
            self.daily.recheck_snapshot_in_transaction(connection, current, fence=fence)
        self.sources.require_resolved(result)
        return result
