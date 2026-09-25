"""Finite routing through the existing continuous simulation owners.

Original market and clock references are supplied by their capture owners.
Independent model events, control changes, initialization and provider I/O are
outside this API. No restored receipt can recreate a first-send token.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Event, Lock

from packages.domain.continuous_composition_contracts import VENUE_CAPTURE_CLOSURE_SCHEMA
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier
from packages.domain.continuous_persistence_contracts import ContinuousAccountReceipt
from packages.domain.continuous_quote_contracts import CONTINUOUS_QUOTE_CLOSURE_SCHEMA
from packages.domain.durable_journal_contracts import journal_identifier
from packages.domain.identifiers import canonical_id
from packages.domain.runtime_operating_contracts import RuntimeClockReference
from packages.domain.stateful_venue_contracts import VenueReceipt
from packages.domain.submission_attempt import SubmissionAttemptState
from packages.persistence.continuous_account import (
    ContinuousAccountConflict,
    ResolvedContinuousAccount,
    SqlContinuousAccount,
)
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_forward_sources import ResolvedContinuousForwardSources
from packages.persistence.continuous_frontier_publication import SqlContinuousFrontierPublication
from packages.persistence.continuous_observed_publication import SqlContinuousObservedPublication
from packages.persistence.continuous_reconciliation_publication import (
    ContinuousReconciliationPublicationReceipt,
    ResolvedContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_attempt_sources import (
    PreparedContinuousRuntimeAttemptSource,
)
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.continuous_venue_registration_capture import (
    SqlContinuousVenueRegistrationCapture,
)
from packages.persistence.daily_runtime_risk import (
    ResolvedDailyRuntimeSnapshot,
    RetainedDailyAdmission,
)

_EVENT_IS_SET = Event.is_set


class ContinuousSessionStopped(ValueError):
    """Cooperative stop adds denial; it cannot grant financial authority."""


@dataclass(frozen=True, slots=True)
class SessionDeliveryFailure:
    operation_id: str
    selected_attempt_ids: tuple[str, ...]
    returned_receipts: tuple[VenueReceipt, ...]
    unknown_receipt: ContinuousAccountReceipt | None
    recovery_failed: bool


class ContinuousSessionCoordinator:
    def __init__(
        self,
        *,
        account: SqlContinuousAccount,
        delivery: SqlContinuousSimulationDelivery,
        outcomes: SqlContinuousAttemptOutcomeSources,
        stop_event: Event,
    ) -> None:
        if (
            type(account) is not SqlContinuousAccount
            or type(delivery) is not SqlContinuousSimulationDelivery
            or type(outcomes) is not SqlContinuousAttemptOutcomeSources
            or type(stop_event) is not Event
            or delivery.accounts is not account
            or delivery.publisher.account is not account
            or outcomes.attempts is not delivery.sources
            or outcomes.venue is not delivery.venue
            or outcomes.venue.verified_sources is not delivery
        ):
            raise ValueError("EXACT_CONTINUOUS_SESSION_OWNERS_REQUIRED")
        outcomes.require_bindings()
        self.account, self.delivery, self.outcomes = account, delivery, outcomes
        self.runtime, self.daily = delivery.runtime, delivery.daily
        self.attempts, self.attempt_publisher = delivery.sources, delivery.publisher
        self.frontiers = SqlContinuousFrontierPublication(account=account)
        self.observed = SqlContinuousObservedPublication(account=account)
        self.registrations = SqlContinuousVenueRegistrationCapture(outcomes=outcomes)
        self.scope = self.runtime.operating.clock_sampler.scope
        if self.scope.account_id != self.runtime.current_fence().account_id:
            raise ValueError("ORIGINAL_CONTINUOUS_SESSION_SCOPE_REQUIRED")
        self.stop_event = stop_event
        self._scope_sha256 = self.scope.semantic_sha256
        self._stopped = False
        self._busy = Lock()
        self._failure: SessionDeliveryFailure | None = None
        self._instance = self
        self._bindings = self._binding_values()

    @property
    def last_delivery_failure(self) -> SessionDeliveryFailure | None:
        """Ordinary retained evidence; contains no send token or success verdict."""
        return self._failure

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self.account,
            self.delivery,
            self.outcomes,
            self.runtime,
            self.daily,
            self.attempts,
            self.attempt_publisher,
            self.frontiers,
            self.observed,
            self.registrations,
            self.scope,
            self.stop_event,
            self.account.composer,
            self.account.preparer,
            self.account.coordinator,
            self.delivery.accounts,
            self.delivery.publisher,
            self.delivery.sources,
            self.delivery.runtime,
            self.delivery.daily,
            self.delivery.venue,
            self.outcomes.attempts,
            self.outcomes.venue,
            self.outcomes.capture,
            self.runtime.accounts,
            self.runtime.daily,
            self.runtime.attempt_sources,
            self.runtime.publisher,
            self.runtime.operating,
            self.runtime.operating.clock_sampler,
            self.runtime.operating.clock_sampler.scope,
            self.runtime.current_fence,
            self.frontiers.account,
            self.observed.account,
            self.registrations.outcomes,
        )

    def _check(self) -> None:
        if self._instance is not self or any(
            a is not b for a, b in zip(self._bindings, self._binding_values(), strict=True)
        ):
            raise ValueError("ORIGINAL_CONTINUOUS_SESSION_OWNERS_CHANGED")
        if self.scope.semantic_sha256 != self._scope_sha256:
            raise ValueError("ORIGINAL_CONTINUOUS_SESSION_SCOPE_CHANGED")
        self.outcomes.require_bindings()
        self._check_stop()

    def _check_stop(self) -> None:
        observed = _EVENT_IS_SET(self.stop_event)
        self._stopped = self._stopped or type(observed) is not bool or observed
        if self._stopped:
            raise ContinuousSessionStopped("CONTINUOUS_SESSION_STOPPED")

    @contextmanager
    def _operation(self, operation_id: str) -> Iterator[None]:
        if not self._busy.acquire(blocking=False):
            raise ValueError("CONTINUOUS_SESSION_OPERATION_ALREADY_RUNNING")
        try:
            journal_identifier(operation_id)
            self._check()
            with self.account.cooperative_stop_scope(self.stop_event):
                yield
        except ContinuousAccountConflict as exc:
            if exc.args == ("CONTINUOUS_COOPERATIVE_STOPPED",):
                self._stopped = True
                raise ContinuousSessionStopped("CONTINUOUS_SESSION_STOPPED") from exc
            raise
        finally:
            self._busy.release()

    def _current(self) -> tuple[ResolvedContinuousAccount, ResolvedDailyRuntimeSnapshot]:
        self._check()
        previous = self.account.restore(self.scope)
        if previous is None:
            raise ValueError("CONTINUOUS_SESSION_EXISTING_GENESIS_REQUIRED")
        return previous, self._daily()

    def _daily(self) -> ResolvedDailyRuntimeSnapshot:
        self._check()
        return self.daily.resolve_snapshot(
            self.daily.read_snapshot(
                account_id=self.scope.account_id, fence=self.runtime.current_fence()
            )
        )

    def _prior(
        self, previous: ResolvedContinuousAccount
    ) -> ResolvedContinuousReconciliationPublication | None:
        ancestor = self.account.nearest_source_ancestor(
            previous, schema_id=VENUE_CAPTURE_CLOSURE_SCHEMA
        )
        if ancestor is None:
            return None
        prior = self.observed.publisher.resolve_for_account(
            ancestor, scope=self.observed.venue_sources.scope
        )
        if prior is None:
            raise ValueError("CONTINUOUS_SESSION_ORIGINAL_APPLIED_ANCESTOR_REQUIRED")
        return prior

    @staticmethod
    def _ids(attempt_ids: tuple[str, ...]) -> tuple[str, ...]:
        if type(attempt_ids) is not tuple or not 1 <= len(attempt_ids) <= 4:
            raise ValueError("CONTINUOUS_SESSION_EXACT_ATTEMPT_GROUP_REQUIRED")
        for identifier in attempt_ids:
            journal_identifier(identifier)
        if attempt_ids != tuple(sorted(set(attempt_ids))):
            raise ValueError("CONTINUOUS_SESSION_EXACT_ATTEMPT_GROUP_REQUIRED")
        return attempt_ids

    def _admissions(
        self, current: ResolvedDailyRuntimeSnapshot, attempt_ids: tuple[str, ...]
    ) -> tuple[RetainedDailyAdmission, ...]:
        self._ids(attempt_ids)
        selected = tuple(item for item in current.attempts if item.attempt_id in attempt_ids)
        if len(selected) != len(attempt_ids):
            raise ValueError("CONTINUOUS_SESSION_ORIGINAL_ATTEMPTS_REQUIRED")
        needed = {item.preparation.original_admission.semantic_sha256 for item in selected}
        views = tuple(
            view
            for view in self.daily.inspect_snapshot_admissions(current)
            if view.admission.semantic_sha256 in needed
        )
        if {view.admission.semantic_sha256 for view in views} != needed:
            raise ValueError("CONTINUOUS_SESSION_ORIGINAL_ADMISSIONS_REQUIRED")
        return views

    def _publish_attempt(
        self, source: PreparedContinuousRuntimeAttemptSource
    ) -> ContinuousAccountReceipt:
        prepared = self.attempt_publisher.prepare_source(source, sources=self.attempts)
        self._check()
        return self.attempt_publisher.publish(prepared, fence=self.runtime.current_fence())

    def publish_daily(
        self,
        *,
        operation_id: str,
        market: ResolvedContinuousForwardSources,
        clock_reference: RuntimeClockReference,
    ) -> ContinuousAccountReceipt:
        with self._operation(operation_id):
            previous, _ = self._current()
            prepared = self.frontiers.prepare_daily(
                command_id=operation_id,
                previous=previous,
                market=market,
                clock_reference=clock_reference,
            )
            self._check()
            return self.frontiers.publish(prepared)

    def publish_pending(
        self, *, operation_id: str, admission_command_id: str
    ) -> ContinuousAccountReceipt:
        with self._operation(operation_id):
            journal_identifier(admission_command_id)
            previous, current = self._current()
            selected = tuple(
                view
                for view in self.daily.inspect_snapshot_admissions(current)
                if view.command_id == admission_command_id
            )
            if len(selected) != 1 or not 1 <= len(selected[0].bindings) <= 4:
                raise ValueError("CONTINUOUS_SESSION_ORIGINAL_UNSENT_ADMISSION_REQUIRED")
            return self._publish_attempt(
                self.attempts.retain_pending(
                    coordinator_command_id=operation_id,
                    previous=previous,
                    current=current,
                    admissions=selected,
                )
            )

    def publish_quote(
        self, *, operation_id: str, market: ResolvedContinuousForwardSources
    ) -> ContinuousAccountReceipt:
        with self._operation(operation_id):
            previous, _ = self._current()
            prepared = self.frontiers.prepare_quote(
                command_id=operation_id, previous=previous, market=market
            )
            self._check()
            return self.frontiers.publish(prepared)

    def reconcile(
        self, *, operation_id: str, capture_id: str
    ) -> ContinuousReconciliationPublicationReceipt:
        with self._operation(operation_id):
            journal_identifier(capture_id)
            previous, current = self._current()
            captured = self.registrations.capture(
                capture_id=capture_id, previous=previous, current=current
            )
            prepared = self.observed.prepare(
                command_id=operation_id,
                previous=previous,
                current=self._daily(),
                venue=captured,
                prior=self._prior(previous),
            )
            self._check()
            return self.observed.publish(prepared)

    def _unknown(
        self,
        *,
        operation_id: str,
        previous: ResolvedContinuousAccount,
        current: ResolvedDailyRuntimeSnapshot,
        attempt_ids: tuple[str, ...],
        reason: str,
    ) -> ContinuousAccountReceipt:
        admissions = self._admissions(current, attempt_ids)
        keys = self.attempts.inspect_dispatch_keys(
            previous=previous, current=current, attempt_ids=attempt_ids
        )
        return self._publish_attempt(
            self.attempts.retain_unknown(
                coordinator_command_id=operation_id,
                previous=previous,
                current=current,
                admissions=admissions,
                attempt_ids=attempt_ids,
                reason=reason,
                dispatch_keys=keys,
            )
        )

    def activate_and_send(
        self,
        *,
        operation_id: str,
        attempt_ids: tuple[str, ...],
        clock_reference: RuntimeClockReference,
        quote_clock_reference: RuntimeClockReference,
    ) -> tuple[VenueReceipt, ...]:
        with self._operation(operation_id):
            self._ids(attempt_ids)
            previous, _ = self._current()
            quote = self.account.nearest_source_ancestor(
                previous, schema_id=CONTINUOUS_QUOTE_CLOSURE_SCHEMA
            )
            if quote is None or type(quote.request) is not ClosedEngineFrontier:
                raise ValueError("CONTINUOUS_SESSION_ORIGINAL_QUOTE_FRONTIER_REQUIRED")
            descriptor = self.runtime.prepare_descriptor(
                descriptor_id=canonical_id("continuous-session-descriptor/1", operation_id),
                scope=self.scope,
                request=quote.request,
                market_source=quote.receipt.commit.source_evidence,
                previous=previous,
                fence=self.runtime.current_fence(),
                clock_reference=clock_reference,
                quote_clock_reference=quote_clock_reference,
                request_kind="activation_dependencies",
                accounts=self.account,
                daily=self.daily,
            )
            self._check()
            with self.account.write_transaction() as connection:
                self.runtime.append_descriptor_in_transaction(
                    connection, descriptor, fence=self.runtime.current_fence()
                )
                self._check_stop()
            resolved = self.runtime.resolve_prepared_descriptor(descriptor)
            current = resolved.plan.daily
            source = self.attempts.retain_activation(
                coordinator_command_id=operation_id,
                previous=previous,
                current=current,
                admissions=self._admissions(current, attempt_ids),
                descriptor=resolved,
                attempt_ids=attempt_ids,
            )
            prepared = self.attempt_publisher.prepare_source(source, sources=self.attempts)
            receipts: list[VenueReceipt] = []
            self._check()
            try:
                batch = self.attempt_publisher.publish_dispatch(
                    prepared, fence=self.runtime.current_fence()
                )
                for identifier in attempt_ids:
                    self._check()
                    receipt = self.delivery.deliver(batch, source=source, attempt_id=identifier)
                    receipts.append(receipt)
                    if receipt.acknowledgment.disposition != "registered":
                        raise ValueError("CONTINUOUS_SESSION_REGISTRATION_REJECTED")
            except Exception:
                unknown_receipt = None
                recovery_failed = False
                try:
                    retained, remaining = self._current()
                    uncertain = tuple(
                        item.attempt_id
                        for item in remaining.attempts
                        if item.attempt_id in attempt_ids
                        and item.state is SubmissionAttemptState.IN_FLIGHT
                    )
                    if uncertain:
                        unknown_receipt = self._unknown(
                            operation_id=canonical_id(
                                "continuous-session-send-unknown/1", operation_id
                            ),
                            previous=retained,
                            current=remaining,
                            attempt_ids=tuple(sorted(uncertain)),
                            reason="simulation_send_incomplete",
                        )
                except Exception:
                    recovery_failed = True
                self._failure = SessionDeliveryFailure(
                    operation_id, attempt_ids, tuple(receipts), unknown_receipt, recovery_failed
                )
                raise
            return tuple(receipts)

    def observe_attempt(
        self, *, operation_id: str, capture_id: str, attempt_id: str
    ) -> ContinuousAccountReceipt | None:
        with self._operation(operation_id):
            self._ids((attempt_id,))
            journal_identifier(capture_id)
            previous, current = self._current()
            observation = self.outcomes.observe(
                previous=previous, current=current, attempt_id=attempt_id, capture_id=capture_id
            )
            self.outcomes.require_observation(observation)
            if observation.plan.outcome is None:
                return None
            current = self._daily()
            return self._publish_attempt(
                self.attempts.retain_outcome(
                    coordinator_command_id=operation_id,
                    previous=previous,
                    current=current,
                    admissions=self._admissions(current, (attempt_id,)),
                    attempt_id=attempt_id,
                    observation=observation,
                )
            )

    def recover_in_flight(
        self, *, operation_id: str, attempt_ids: tuple[str, ...]
    ) -> ContinuousAccountReceipt:
        with self._operation(operation_id):
            self._ids(attempt_ids)
            previous, current = self._current()
            return self._unknown(
                operation_id=operation_id,
                previous=previous,
                current=current,
                attempt_ids=attempt_ids,
                reason="simulation_process_recovery",
            )

    def expire_unsent(self, *, operation_id: str, attempt_id: str) -> ContinuousAccountReceipt:
        with self._operation(operation_id):
            self._ids((attempt_id,))
            previous, current = self._current()
            return self._publish_attempt(
                self.attempts.retain_expired_unsent(
                    coordinator_command_id=operation_id,
                    previous=previous,
                    current=current,
                    admissions=self._admissions(current, (attempt_id,)),
                    attempt_id=attempt_id,
                )
            )
