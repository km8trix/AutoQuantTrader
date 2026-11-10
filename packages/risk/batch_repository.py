"""Process-local atomic repository for intent-batch risk authorizations."""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable
from datetime import datetime
from decimal import Decimal
from typing import TypeVar

from packages.domain.batch_risk import (
    BatchRiskAuthority,
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskFactConflict,
    BatchRiskOperationalState,
    BatchRiskReservation,
    VersionedBatchRiskSnapshot,
    evaluate_batch_risk_decision,
    initial_active_capacity_universe,
)
from packages.domain.decimal_math import exact_decimal_add, exact_decimal_sum
from packages.domain.models import OrderIntent, OrderIntentBatch, TargetPortfolio
from packages.domain.risk import (
    RiskAuthorizationError,
    intent_payload_hash,
    validate_authorization_consumption,
)

TransactionResultT = TypeVar("TransactionResultT")


class _InMemoryBatchRiskStore:
    """One shared process-local account lock and immutable-fact registry."""

    def __init__(self) -> None:
        self.authority_identity: object | None = None
        self.decisions: dict[str, BatchRiskDecision] = {}
        self.batch_decision_ids: dict[str, str] = {}
        self.batch_payloads: dict[str, str] = {}
        self.intent_records: dict[str, tuple[str, str]] = {}
        self.authorizations: dict[str, BatchRiskAuthorization] = {}
        self.reservations: dict[str, BatchRiskReservation] = {}
        self.authorization_snapshots: dict[str, tuple[str, str, str]] = {}
        self.account_snapshots: dict[str, tuple[str, str]] = {}
        self.consumed: set[str] = set()
        self.lock = threading.Lock()


class _InMemoryBatchRiskAccountState:
    """One process-local state object shared by every provider for an account."""

    __slots__ = ("__weakref__", "snapshot", "store", "transition_lock")

    def __init__(self, snapshot: VersionedBatchRiskSnapshot) -> None:
        self.snapshot = snapshot
        self.store = _InMemoryBatchRiskStore()
        self.transition_lock = threading.RLock()


_ACCOUNT_STATES_LOCK = threading.Lock()
_ACCOUNT_STATES: weakref.WeakValueDictionary[
    str,
    _InMemoryBatchRiskAccountState,
] = weakref.WeakValueDictionary()


class InMemoryBatchRiskSnapshotProvider:
    """Own one transition lock and one reservation store for an account authority."""

    def __init__(self, snapshot: VersionedBatchRiskSnapshot) -> None:
        if type(snapshot) is not VersionedBatchRiskSnapshot:
            raise BatchRiskFactConflict("in-memory provider requires an exact batch risk snapshot")
        snapshot._validate()
        with _ACCOUNT_STATES_LOCK:
            state = _ACCOUNT_STATES.get(snapshot.account_id)
            if state is None:
                state = _InMemoryBatchRiskAccountState(snapshot)
                _ACCOUNT_STATES[snapshot.account_id] = state
            elif state.snapshot.semantic_sha256 != snapshot.semantic_sha256:
                raise BatchRiskFactConflict(
                    "an active account provider already owns different snapshot evidence"
                )
            self._state = state

    @property
    def store(self) -> _InMemoryBatchRiskStore:
        return self._state.store

    def current(self) -> VersionedBatchRiskSnapshot:
        with self._state.transition_lock:
            return self._state.snapshot

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], TransactionResultT],
    ) -> TransactionResultT:
        with self._state.transition_lock:
            return operation(self._state.snapshot)

    def transition_to(self, snapshot: VersionedBatchRiskSnapshot) -> None:
        if type(snapshot) is not VersionedBatchRiskSnapshot:
            raise BatchRiskFactConflict("risk snapshot transition requires an exact value")
        snapshot._validate()
        if snapshot.account_id != self._state.snapshot.account_id:
            raise BatchRiskFactConflict("risk snapshot transition changed its account identity")
        with self._state.transition_lock:
            self._state.snapshot = snapshot


class InMemoryBatchRiskRepository:
    """Issue a complete batch decision and every resource hold under one lock.

    The lock proves atomic visibility and capacity conservation only inside this
    process. Holds intentionally survive consumption and authorization expiry;
    lifecycle-driven release belongs to the durable coordinator contract.
    """

    def __init__(
        self,
        authority: BatchRiskAuthority,
    ) -> None:
        if type(authority.snapshots) is not InMemoryBatchRiskSnapshotProvider:
            raise BatchRiskFactConflict(
                "in-memory repository requires its account-scoped snapshot provider"
            )
        store = authority.snapshots.store
        self._authority = authority
        with store.lock:
            if store.authority_identity is None:
                store.authority_identity = authority._identity
            elif store.authority_identity is not authority._identity:
                raise BatchRiskFactConflict(
                    "one in-memory batch risk store cannot span multiple authorities"
                )
        self._decisions = store.decisions
        self._batch_decision_ids = store.batch_decision_ids
        self._batch_payloads = store.batch_payloads
        self._intent_records = store.intent_records
        self._authorizations = store.authorizations
        self._reservations = store.reservations
        self._authorization_snapshots = store.authorization_snapshots
        self._account_snapshots = store.account_snapshots
        self._consumed = store.consumed
        self._lock = store.lock

    @staticmethod
    def _require_snapshot(snapshot: VersionedBatchRiskSnapshot) -> None:
        if type(snapshot) is not VersionedBatchRiskSnapshot:
            raise BatchRiskFactConflict(
                "batch risk snapshot provider returned a non-canonical value"
            )
        snapshot._validate()

    def _validate_account_epoch(self, snapshot: VersionedBatchRiskSnapshot) -> None:
        prior = self._account_snapshots.get(snapshot.account_id)
        if prior is None:
            if self._account_snapshots:
                raise BatchRiskFactConflict(
                    "process-local batch risk authority changed its account identity"
                )
            return
        version, digest = prior
        if version != snapshot.version:
            raise BatchRiskFactConflict(
                "process-local risk reservations belong to a different snapshot version"
            )
        if digest != snapshot.semantic_sha256:
            raise BatchRiskFactConflict("risk snapshot version changed its immutable semantics")

    def authorize(
        self,
        batch: OrderIntentBatch,
        target: TargetPortfolio,
    ) -> BatchRiskDecision:
        """Return an exact retry or atomically publish one all-or-none result."""

        if type(batch) is not OrderIntentBatch:
            raise BatchRiskFactConflict("batch authorization requires an exact OrderIntentBatch")
        if type(target) is not TargetPortfolio:
            raise BatchRiskFactConflict("batch authorization requires exact target evidence")
        if batch.target_id != target.target_id or batch.target_sha256 != target.semantic_sha256:
            raise BatchRiskFactConflict("intent batch does not bind the supplied target evidence")

        def operation(snapshot: VersionedBatchRiskSnapshot) -> BatchRiskDecision:
            return self._authorize_snapshot(batch, target, snapshot)

        return self._authority.snapshots.transact(operation)

    def _authorize_snapshot(
        self,
        batch: OrderIntentBatch,
        target: TargetPortfolio,
        snapshot: VersionedBatchRiskSnapshot,
    ) -> BatchRiskDecision:
        self._require_snapshot(snapshot)
        batch_digest = batch.semantic_sha256

        with self._lock:
            evaluated_at = self._authority.evaluation_clock.now()
            self._validate_account_epoch(snapshot)
            prior_decision_id = self._batch_decision_ids.get(batch.intent_batch_id)
            if prior_decision_id is not None:
                if self._batch_payloads[batch.intent_batch_id] != batch_digest:
                    raise BatchRiskFactConflict("intent batch IDs are immutable")
                prior = self._decisions[prior_decision_id]
                if (
                    prior.account_id != snapshot.account_id
                    or prior.snapshot_version != snapshot.version
                    or prior.snapshot_sha256 != snapshot.semantic_sha256
                ):
                    raise BatchRiskFactConflict(
                        "intent batch decision belongs to a different capacity snapshot"
                    )
                return prior

            pending_intent_records: dict[str, tuple[str, str]] = {}
            for intent in batch.intents:
                record = (intent_payload_hash(intent), batch.intent_batch_id)
                existing = self._intent_records.get(intent.intent_id)
                if existing is not None and existing != record:
                    raise BatchRiskFactConflict("intent IDs are immutable across batches")
                if existing is not None:
                    raise BatchRiskFactConflict(
                        "an existing intent identity cannot be attached to another decision"
                    )
                pending_intent_records[intent.intent_id] = record

            active_reservations = tuple(
                self._reservations[key] for key in sorted(self._reservations)
            )
            decision = evaluate_batch_risk_decision(
                batch=batch,
                target=target,
                snapshot=snapshot,
                limits=self._authority.limits,
                active_capacity=initial_active_capacity_universe(
                    snapshot.account_id,
                    active_reservations,
                ),
                evaluated_at=evaluated_at,
            )
            existing_decision = self._decisions.get(decision.decision_id)
            if existing_decision is not None and existing_decision != decision:
                raise BatchRiskFactConflict("batch risk decision IDs are immutable")
            if decision.reservation is not None:
                existing_reservation = self._reservations.get(decision.reservation.reservation_id)
                if (
                    existing_reservation is not None
                    and existing_reservation != decision.reservation
                ):
                    raise BatchRiskFactConflict("batch reservation IDs are immutable")
            for authorization in decision.authorizations:
                existing_authorization = self._authorizations.get(authorization.decision_id)
                if existing_authorization is not None and existing_authorization != authorization:
                    raise BatchRiskFactConflict("batch authorization IDs are immutable")

            decisions = dict(self._decisions)
            batch_decision_ids = dict(self._batch_decision_ids)
            batch_payloads = dict(self._batch_payloads)
            intent_records = dict(self._intent_records)
            authorizations = dict(self._authorizations)
            reservations = dict(self._reservations)
            authorization_snapshots = dict(self._authorization_snapshots)
            account_snapshots = dict(self._account_snapshots)

            decisions[decision.decision_id] = decision
            batch_decision_ids[batch.intent_batch_id] = decision.decision_id
            batch_payloads[batch.intent_batch_id] = batch_digest
            intent_records.update(pending_intent_records)
            for authorization in decision.authorizations:
                authorizations[authorization.decision_id] = authorization
                authorization_snapshots[authorization.decision_id] = (
                    snapshot.account_id,
                    snapshot.version,
                    snapshot.semantic_sha256,
                )
            if decision.reservation is not None:
                reservations[decision.reservation.reservation_id] = decision.reservation
            account_snapshots[snapshot.account_id] = (
                snapshot.version,
                snapshot.semantic_sha256,
            )

            self._decisions.clear()
            self._decisions.update(decisions)
            self._batch_decision_ids.clear()
            self._batch_decision_ids.update(batch_decision_ids)
            self._batch_payloads.clear()
            self._batch_payloads.update(batch_payloads)
            self._intent_records.clear()
            self._intent_records.update(intent_records)
            self._authorizations.clear()
            self._authorizations.update(authorizations)
            self._reservations.clear()
            self._reservations.update(reservations)
            self._authorization_snapshots.clear()
            self._authorization_snapshots.update(authorization_snapshots)
            self._account_snapshots.clear()
            self._account_snapshots.update(account_snapshots)
            return decision

    def get(self, decision_id: str) -> BatchRiskAuthorization | None:
        """Return one child authorization through the legacy execution shape."""

        with self._lock:
            return self._authorizations.get(decision_id)

    def get_batch(self, decision_id: str) -> BatchRiskDecision | None:
        with self._lock:
            return self._decisions.get(decision_id)

    def decision_for_batch(self, intent_batch_id: str) -> BatchRiskDecision | None:
        with self._lock:
            decision_id = self._batch_decision_ids.get(intent_batch_id)
            return None if decision_id is None else self._decisions[decision_id]

    def get_reservation(self, reservation_id: str) -> BatchRiskReservation | None:
        with self._lock:
            return self._reservations.get(reservation_id)

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        """Consume one child once while retaining its complete parent hold."""

        return self._consume(decision_id, intent)

    def _consume(
        self,
        decision_id: str,
        intent: OrderIntent,
    ) -> datetime:
        if type(intent) is not OrderIntent:
            raise RiskAuthorizationError(
                "batch authorization consumption requires an exact OrderIntent"
            )

        def operation(snapshot: VersionedBatchRiskSnapshot) -> datetime:
            return self._consume_snapshot(
                decision_id,
                intent,
                snapshot=snapshot,
            )

        return self._authority.snapshots.transact(operation)

    def _consume_snapshot(
        self,
        decision_id: str,
        intent: OrderIntent,
        *,
        snapshot: VersionedBatchRiskSnapshot,
    ) -> datetime:
        self._require_snapshot(snapshot)
        with self._lock:
            consumed_at = self._authority.consumption_clock.now()
            authorization = self._authorizations.get(decision_id)
            if authorization is None:
                raise RiskAuthorizationError(
                    "execution requires a persisted batch risk authorization"
                )
            validate_authorization_consumption(authorization, intent, consumed_at)
            expected_snapshot = self._authorization_snapshots[decision_id]
            if expected_snapshot != (
                snapshot.account_id,
                snapshot.version,
                snapshot.semantic_sha256,
            ):
                raise RiskAuthorizationError(
                    "batch authorization capacity snapshot changed before consumption"
                )
            if authorization.intent_batch_id != intent.intent_batch_id:
                raise RiskAuthorizationError("authorization does not bind the intent batch")
            parent = self._decisions.get(authorization.parent_decision_id)
            if (
                parent is None
                or parent.status is not BatchRiskDecisionStatus.APPROVED
                or parent.intent_batch_sha256 != authorization.intent_batch_sha256
                or parent.snapshot_sha256 != authorization.snapshot_sha256
                or parent.policy_sha256 != authorization.policy_sha256
                or parent.currency != authorization.currency
            ):
                raise RiskAuthorizationError("authorization parent evidence is unavailable")
            if snapshot.operational_state is not BatchRiskOperationalState.RUNNING:
                raise RiskAuthorizationError("batch risk control is no longer running")
            if intent.instrument_id in snapshot.halted_instruments:
                raise RiskAuthorizationError("instrument became halted before consumption")
            if snapshot.session.semantic_sha256 != authorization.session_sha256:
                raise RiskAuthorizationError("authorization session evidence changed")
            if not snapshot.session.contains(consumed_at):
                raise RiskAuthorizationError("batch authorization is outside its session")
            if consumed_at - authorization.snapshot_as_of > self._authority.limits.max_snapshot_age:
                raise RiskAuthorizationError("batch authorization snapshot became stale")
            if (
                consumed_at - authorization.reference_event_time
                > self._authority.limits.max_price_age
            ):
                raise RiskAuthorizationError("batch authorization reference price became stale")
            if decision_id in self._consumed:
                raise RiskAuthorizationError("batch authorization has already been consumed")
            self._consumed.add(decision_id)
            return consumed_at

    def was_consumed(self, decision_id: str) -> bool:
        with self._lock:
            return decision_id in self._consumed

    def active_reservations(self) -> tuple[BatchRiskReservation, ...]:
        with self._lock:
            return tuple(self._reservations[key] for key in sorted(self._reservations))

    def reserved_cash(self, snapshot: VersionedBatchRiskSnapshot) -> Decimal:
        self._require_snapshot(snapshot)
        with self._lock:
            self._validate_account_epoch(snapshot)
            return exact_decimal_sum(
                reservation.reserved_cash for reservation in self._reservations.values()
            )

    def reserved_sell_quantity(
        self,
        snapshot: VersionedBatchRiskSnapshot,
        instrument_id: str,
    ) -> Decimal:
        self._require_snapshot(snapshot)
        with self._lock:
            self._validate_account_epoch(snapshot)
            return exact_decimal_sum(
                authorization.reserved_sell_quantity
                for reservation in self._reservations.values()
                for authorization in reservation.authorizations
                if authorization.instrument_id == instrument_id
            )

    def reserved_buy_exposure(self, snapshot: VersionedBatchRiskSnapshot) -> Decimal:
        self._require_snapshot(snapshot)
        with self._lock:
            self._validate_account_epoch(snapshot)
            return exact_decimal_sum(
                reservation.reserved_buy_exposure for reservation in self._reservations.values()
            )

    def total_reserved_resources(
        self,
        snapshot: VersionedBatchRiskSnapshot,
    ) -> tuple[Decimal, Decimal]:
        """Return cash and buy exposure from one locked conservation view."""

        self._require_snapshot(snapshot)
        with self._lock:
            self._validate_account_epoch(snapshot)
            cash = Decimal(0)
            exposure = Decimal(0)
            for reservation in self._reservations.values():
                cash = exact_decimal_add(cash, reservation.reserved_cash)
                exposure = exact_decimal_add(exposure, reservation.reserved_buy_exposure)
            return cash, exposure
