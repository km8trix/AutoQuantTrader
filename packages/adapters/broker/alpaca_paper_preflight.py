"""Pure, non-authorizing Alpaca paper dispatch-preflight evidence binding.

This module deliberately stops before the broker effect boundary.  It
cross-binds the immutable evidence currently available to the repository and
records expected fail-closed findings, but it cannot authenticate that caller-
supplied projections are the current durable SQL heads.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_CAPABILITIES,
    AlpacaPaperContractError,
    AlpacaPaperSubmissionDescription,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAccountObservationOutcome,
    AlpacaAssetObservationOutcome,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaAccountObservation,
    PersistedAlpacaAssetObservation,
)
from packages.domain.account_coordinator import AccountFenceReceipt
from packages.domain.batch_risk import (
    ActiveCapacityAuthorization,
    ActiveCapacityReservation,
    ActiveCapacityReservationState,
    ActiveCapacityUniverse,
    BatchRiskAuthorization,
    BatchRiskReservation,
    BatchRiskSession,
)
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetPolicy,
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPurpose,
    require_fresh_broker_request_permit,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import Side, require_utc
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    ParentBatchSubmissionBarrier,
    SubmissionAttemptError,
    SubmissionAttemptState,
    reduce_submission_attempt,
    submission_barrier_for_parent,
)

ALPACA_PAPER_DISPATCH_PREFLIGHT_CONTRACT_VERSION = "phase4f-alpaca-paper-dispatch-preflight-v1"
ALPACA_PAPER_MAX_PARENT_ATTEMPTS = 1_000
ALPACA_PAPER_UNRESOLVED_RUNTIME_GATES = tuple(
    gate for gate, ready in ALPACA_PAPER_CAPABILITIES.runtime_readiness.items() if not ready
)


class AlpacaPaperDispatchPreflightError(AlpacaPaperContractError):
    """Dispatch-preflight evidence is malformed or conflicts immutably."""


class AlpacaPaperDispatchBlocker(StrEnum):
    """Expected local reasons an offline dispatch candidate remains blocked."""

    ATTEMPT_NOT_PENDING = "attempt_not_pending"
    PARENT_UNKNOWN_UNRESOLVED = "parent_unknown_unresolved"
    RISK_APPROVAL_EXPIRED = "risk_approval_expired"
    INTENT_EXPIRED = "intent_expired"
    SESSION_CLOSED = "session_closed"
    RESERVATION_CAPACITY_UNAVAILABLE = "reservation_capacity_unavailable"
    REQUEST_PERMIT_NOT_FRESH = "request_permit_not_fresh"
    ACCOUNT_NOT_LOCALLY_USABLE = "account_not_locally_usable"
    ASSET_NOT_LOCALLY_USABLE = "asset_not_locally_usable"
    SELL_REDUCE_ONLY_UNPROVEN = "sell_reduce_only_unproven"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime:
        raise AlpacaPaperDispatchPreflightError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperDispatchPreflightError(str(error)) from error


def _require_canonical_attempt(attempt: CanonicalSubmissionAttempt) -> None:
    if type(attempt) is not CanonicalSubmissionAttempt:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment requires an exact CanonicalSubmissionAttempt"
        )
    try:
        canonical = reduce_submission_attempt(attempt.preparation, attempt.events)
    except SubmissionAttemptError as error:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment attempt does not reduce canonically"
        ) from error
    if canonical != attempt:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment attempt is not reducer-produced"
        )


def _require_attempt_description_binding(
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaPaperSubmissionDescription,
) -> None:
    _require_canonical_attempt(attempt)
    if type(description) is not AlpacaPaperSubmissionDescription:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment requires an exact Alpaca submission description"
        )
    try:
        description.__post_init__()
        expected = create_alpaca_paper_submission_description(attempt.preparation.intent)
    except AlpacaPaperContractError as error:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment Alpaca description is malformed"
        ) from error
    if description != expected:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment description does not bind the exact attempt intent"
        )
    if attempt.preparation.request != description.request:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment request does not bind the durable preparation"
        )


def alpaca_paper_submission_budget_correlation_sha256(
    *,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaPaperSubmissionDescription,
) -> str:
    """Derive the submission-budget correlation from exact request evidence."""

    _require_attempt_description_binding(attempt, description)
    return _semantic_sha256(
        (
            ALPACA_PAPER_DISPATCH_PREFLIGHT_CONTRACT_VERSION,
            "submission_budget_correlation",
            attempt.preparation.semantic_sha256,
            description.semantic_sha256,
        )
    )


def create_alpaca_paper_submission_budget_demand(
    *,
    attempt: CanonicalSubmissionAttempt,
    description: AlpacaPaperSubmissionDescription,
    idempotency_key: str,
    requested_at: datetime,
) -> BrokerRequestDemand:
    """Create a submission demand whose purpose and correlation are not caller-selected."""

    return create_alpaca_paper_request_demand(
        account_id=attempt.preparation.account_id,
        idempotency_key=idempotency_key,
        operation=AlpacaPaperBudgetOperation.SUBMIT_ORDER,
        correlation_sha256=alpaca_paper_submission_budget_correlation_sha256(
            attempt=attempt,
            description=description,
        ),
        requested_at=requested_at,
    )


def _authorization(
    attempt: CanonicalSubmissionAttempt,
) -> BatchRiskAuthorization:
    matches = tuple(
        authorization
        for authorization in attempt.preparation.risk_decision.authorizations
        if authorization.decision_id == attempt.preparation.authorization_id
    )
    if len(matches) != 1:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment requires one exact child risk authorization"
        )
    return matches[0]


def _reservation(
    attempt: CanonicalSubmissionAttempt,
) -> BatchRiskReservation:
    reservation = attempt.preparation.risk_decision.reservation
    if (
        type(reservation) is not BatchRiskReservation
        or reservation.reservation_id != attempt.preparation.reservation_id
    ):
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment requires the exact parent risk reservation"
        )
    return reservation


def _active_child(
    *,
    active_capacity: ActiveCapacityUniverse,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
) -> tuple[ActiveCapacityReservation | None, ActiveCapacityAuthorization | None]:
    matching_reservations = tuple(
        item
        for item in active_capacity.reservations
        if item.reservation_id == reservation.reservation_id
    )
    if not matching_reservations:
        return None, None
    if len(matching_reservations) != 1:
        raise AlpacaPaperDispatchPreflightError(
            "active capacity repeats the dispatch reservation identity"
        )
    active_reservation = matching_reservations[0]
    if (
        active_reservation.reservation_sha256 != reservation.semantic_sha256
        or active_reservation.currency != reservation.currency
    ):
        raise AlpacaPaperDispatchPreflightError(
            "active capacity conflicts with the exact risk reservation"
        )
    matching_authorizations = tuple(
        item
        for item in active_reservation.authorizations
        if item.authorization_id == authorization.decision_id
    )
    if not matching_authorizations:
        return active_reservation, None
    if len(matching_authorizations) != 1:
        raise AlpacaPaperDispatchPreflightError(
            "active capacity repeats the dispatch authorization identity"
        )
    active_authorization = matching_authorizations[0]
    if (
        active_authorization.authorization_sha256 != authorization.semantic_sha256
        or active_authorization.intent_id != authorization.intent_id
        or active_authorization.instrument_id != authorization.instrument_id
        or active_authorization.side is not authorization.side
        or active_authorization.reserved_cash != authorization.reserved_cash
        or active_authorization.reserved_sell_quantity != authorization.reserved_sell_quantity
        or active_authorization.reserved_buy_exposure != authorization.reserved_buy_exposure
    ):
        raise AlpacaPaperDispatchPreflightError(
            "active capacity conflicts with the exact risk authorization"
        )
    return active_reservation, active_authorization


def _capacity_is_complete(
    active_reservation: ActiveCapacityReservation | None,
    active_authorization: ActiveCapacityAuthorization | None,
    authorization: BatchRiskAuthorization,
) -> bool:
    if active_reservation is None or active_authorization is None:
        return False
    if active_reservation.state is ActiveCapacityReservationState.FROZEN:
        return False
    return (
        active_authorization.remaining_cash == authorization.reserved_cash
        and active_authorization.remaining_buy_exposure == authorization.reserved_buy_exposure
        and active_authorization.remaining_sell_quantity == authorization.reserved_sell_quantity
    )


def _parent_barrier(
    *,
    attempt: CanonicalSubmissionAttempt,
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...],
) -> ParentBatchSubmissionBarrier:
    if (
        type(parent_attempts) is not tuple
        or len(parent_attempts) > ALPACA_PAPER_MAX_PARENT_ATTEMPTS
    ):
        raise AlpacaPaperDispatchPreflightError(
            "parent attempt snapshot must be a bounded immutable tuple"
        )
    if sum(item == attempt for item in parent_attempts) != 1:
        raise AlpacaPaperDispatchPreflightError(
            "parent attempt snapshot must contain the assessed attempt exactly once"
        )
    try:
        barrier = submission_barrier_for_parent(
            parent_decision_id=attempt.parent_decision_id,
            attempts=parent_attempts,
        )
    except SubmissionAttemptError as error:
        raise AlpacaPaperDispatchPreflightError(
            "parent attempt snapshot is not a canonical same-parent projection"
        ) from error
    slots = tuple((item.order_id, item.attempt_number) for item in parent_attempts)
    if len(slots) != len(set(slots)):
        raise AlpacaPaperDispatchPreflightError(
            "parent attempt snapshot reuses an order attempt-number slot"
        )
    order_ids = tuple(dict.fromkeys(item.order_id for item in parent_attempts))
    for order_id in order_ids:
        attempt_numbers = tuple(
            item.attempt_number for item in parent_attempts if item.order_id == order_id
        )
        if attempt_numbers != tuple(range(1, len(attempt_numbers) + 1)):
            raise AlpacaPaperDispatchPreflightError(
                "parent attempt snapshot must contain each order's contiguous history from one"
            )
    return barrier


def _require_source_bindings(
    *,
    attempt: CanonicalSubmissionAttempt,
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...],
    description: AlpacaPaperSubmissionDescription,
    session: BatchRiskSession,
    active_capacity: ActiveCapacityUniverse,
    dispatch_fence_receipt: AccountFenceReceipt,
    account_observation: PersistedAlpacaAccountObservation,
    asset_observation: PersistedAlpacaAssetObservation,
    budget_policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
    assessed_at: datetime,
) -> tuple[
    ParentBatchSubmissionBarrier,
    BatchRiskAuthorization,
    BatchRiskReservation,
    ActiveCapacityReservation | None,
    ActiveCapacityAuthorization | None,
]:
    _require_attempt_description_binding(attempt, description)
    barrier = _parent_barrier(attempt=attempt, parent_attempts=parent_attempts)
    for value, expected_type, field_name in (
        (session, BatchRiskSession, "risk session"),
        (active_capacity, ActiveCapacityUniverse, "active capacity"),
        (dispatch_fence_receipt, AccountFenceReceipt, "dispatch fence receipt"),
        (
            account_observation,
            PersistedAlpacaAccountObservation,
            "persisted account observation",
        ),
        (
            asset_observation,
            PersistedAlpacaAssetObservation,
            "persisted asset observation",
        ),
        (budget_policy, BrokerRequestBudgetPolicy, "request-budget policy"),
        (demand, BrokerRequestDemand, "request demand"),
        (permit, BrokerRequestPermit, "request permit"),
    ):
        if type(value) is not expected_type:
            raise AlpacaPaperDispatchPreflightError(
                f"dispatch assessment requires an exact {field_name}"
            )
    try:
        session.__post_init__()
        active_capacity.__post_init__()
        dispatch_fence_receipt._validate()
        account_observation.__post_init__()
        asset_observation.__post_init__()
        budget_policy.__post_init__()
        demand.__post_init__()
        permit.__post_init__()
    except (ValueError, TypeError) as error:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment source evidence is malformed"
        ) from error
    _require_utc(assessed_at, "dispatch assessed_at")

    preparation = attempt.preparation
    authorization = _authorization(attempt)
    reservation = _reservation(attempt)
    if session.semantic_sha256 != authorization.session_sha256:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch session does not bind the exact risk authorization"
        )
    if active_capacity.account_id != preparation.account_id:
        raise AlpacaPaperDispatchPreflightError("active capacity belongs to another account")

    prepared_fence = preparation.fence_receipt
    if (
        dispatch_fence_receipt.fence != prepared_fence.fence
        or dispatch_fence_receipt.policy_sha256 != prepared_fence.policy_sha256
        or dispatch_fence_receipt.fence.account_id != preparation.account_id
    ):
        raise AlpacaPaperDispatchPreflightError(
            "dispatch receipt changed the prepared stable fence, policy, or account"
        )
    if dispatch_fence_receipt.validated_at != assessed_at:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment instant must equal fence validation time"
        )

    account = account_observation.observation
    asset = asset_observation.observation
    if account.description.account_id != preparation.account_id:
        raise AlpacaPaperDispatchPreflightError(
            "account observation belongs to another local account"
        )
    if (
        asset.description.account_id != preparation.account_id
        or asset.description.instrument_id != preparation.intent.instrument_id
        or asset.description.symbol != preparation.intent.symbol
    ):
        raise AlpacaPaperDispatchPreflightError(
            "asset observation does not bind the exact intent identity"
        )
    for recorded_at, field_name in (
        (attempt.as_of, "attempt head"),
        (account_observation.receipt.delivery.recorded_at, "account observation"),
        (asset_observation.receipt.delivery.recorded_at, "asset observation"),
    ):
        if recorded_at > assessed_at:
            raise AlpacaPaperDispatchPreflightError(
                f"dispatch {field_name} cannot be recorded after assessment"
            )

    if budget_policy.semantic_sha256 != ALPACA_PAPER_REQUEST_BUDGET_POLICY.semantic_sha256:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment requires the exact fixed Alpaca budget policy"
        )
    expected_correlation = alpaca_paper_submission_budget_correlation_sha256(
        attempt=attempt,
        description=description,
    )
    if (
        demand.account_id != preparation.account_id
        or demand.operation != AlpacaPaperBudgetOperation.SUBMIT_ORDER.value
        or demand.purpose is not BrokerRequestPurpose.SUBMISSION
        or demand.correlation_sha256 != expected_correlation
    ):
        raise AlpacaPaperDispatchPreflightError(
            "dispatch demand does not bind the exact submission evidence and purpose"
        )
    if demand.requested_at > permit.issued_at:
        raise AlpacaPaperDispatchPreflightError("dispatch permit cannot precede its exact demand")
    try:
        require_fresh_broker_request_permit(
            permit=permit,
            policy=budget_policy,
            demand=demand,
            checked_at=permit.issued_at,
        )
    except ValueError as error:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch permit does not bind the exact demand and budget policy"
        ) from error

    active_reservation, active_authorization = _active_child(
        active_capacity=active_capacity,
        reservation=reservation,
        authorization=authorization,
    )
    return (
        barrier,
        authorization,
        reservation,
        active_reservation,
        active_authorization,
    )


def _derive_blockers(
    *,
    attempt: CanonicalSubmissionAttempt,
    barrier: ParentBatchSubmissionBarrier,
    session: BatchRiskSession,
    authorization: BatchRiskAuthorization,
    active_reservation: ActiveCapacityReservation | None,
    active_authorization: ActiveCapacityAuthorization | None,
    account_observation: PersistedAlpacaAccountObservation,
    asset_observation: PersistedAlpacaAssetObservation,
    permit: BrokerRequestPermit,
    assessed_at: datetime,
) -> tuple[AlpacaPaperDispatchBlocker, ...]:
    blockers: list[AlpacaPaperDispatchBlocker] = []
    if attempt.state is not SubmissionAttemptState.PENDING:
        blockers.append(AlpacaPaperDispatchBlocker.ATTEMPT_NOT_PENDING)
    if barrier.blocked:
        blockers.append(AlpacaPaperDispatchBlocker.PARENT_UNKNOWN_UNRESOLVED)
    if assessed_at >= attempt.preparation.risk_decision.expires_at:
        blockers.append(AlpacaPaperDispatchBlocker.RISK_APPROVAL_EXPIRED)
    if assessed_at >= attempt.preparation.intent.expires_at:
        blockers.append(AlpacaPaperDispatchBlocker.INTENT_EXPIRED)
    if not session.contains(assessed_at):
        blockers.append(AlpacaPaperDispatchBlocker.SESSION_CLOSED)
    if not _capacity_is_complete(
        active_reservation,
        active_authorization,
        authorization,
    ):
        blockers.append(AlpacaPaperDispatchBlocker.RESERVATION_CAPACITY_UNAVAILABLE)
    if not permit.is_fresh(assessed_at):
        blockers.append(AlpacaPaperDispatchBlocker.REQUEST_PERMIT_NOT_FRESH)
    if (
        account_observation.observation.outcome
        is not AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    ):
        blockers.append(AlpacaPaperDispatchBlocker.ACCOUNT_NOT_LOCALLY_USABLE)
    if (
        asset_observation.observation.outcome
        is not AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
    ):
        blockers.append(AlpacaPaperDispatchBlocker.ASSET_NOT_LOCALLY_USABLE)
    if attempt.preparation.intent.side is Side.SELL:
        blockers.append(AlpacaPaperDispatchBlocker.SELL_REDUCE_ONLY_UNPROVEN)
    return tuple(blockers)


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperDispatchPreflightAssessment:
    """Cross-bound offline evidence that never authorizes a broker effect."""

    attempt: CanonicalSubmissionAttempt
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...]
    parent_barrier_sha256: str
    description: AlpacaPaperSubmissionDescription
    session: BatchRiskSession
    active_capacity: ActiveCapacityUniverse
    dispatch_fence_receipt: AccountFenceReceipt
    account_observation: PersistedAlpacaAccountObservation
    asset_observation: PersistedAlpacaAssetObservation
    budget_policy: BrokerRequestBudgetPolicy
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit
    assessed_at: datetime
    blockers: tuple[AlpacaPaperDispatchBlocker, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperDispatchPreflightAssessment must be proof-constructed")

    def _validate(self) -> None:
        (
            barrier,
            authorization,
            _reservation_value,
            active_reservation,
            active_authorization,
        ) = _require_source_bindings(
            attempt=self.attempt,
            parent_attempts=self.parent_attempts,
            description=self.description,
            session=self.session,
            active_capacity=self.active_capacity,
            dispatch_fence_receipt=self.dispatch_fence_receipt,
            account_observation=self.account_observation,
            asset_observation=self.asset_observation,
            budget_policy=self.budget_policy,
            demand=self.demand,
            permit=self.permit,
            assessed_at=self.assessed_at,
        )
        expected_blockers = _derive_blockers(
            attempt=self.attempt,
            barrier=barrier,
            session=self.session,
            authorization=authorization,
            active_reservation=active_reservation,
            active_authorization=active_authorization,
            account_observation=self.account_observation,
            asset_observation=self.asset_observation,
            permit=self.permit,
            assessed_at=self.assessed_at,
        )
        if self.parent_barrier_sha256 != barrier.semantic_sha256:
            raise AlpacaPaperDispatchPreflightError(
                "dispatch assessment parent barrier digest was altered"
            )
        if self.blockers != expected_blockers:
            raise AlpacaPaperDispatchPreflightError("dispatch assessment blocker set was altered")

    @property
    def contract_version(self) -> str:
        return ALPACA_PAPER_DISPATCH_PREFLIGHT_CONTRACT_VERSION

    @property
    def unresolved_runtime_gates(self) -> tuple[str, ...]:
        return ALPACA_PAPER_UNRESOLVED_RUNTIME_GATES

    @property
    def local_findings_clear(self) -> bool:
        return not self.blockers

    @property
    def offline_evidence_consistent(self) -> bool:
        return True

    @property
    def budget_permit_fresh(self) -> bool:
        return AlpacaPaperDispatchBlocker.REQUEST_PERMIT_NOT_FRESH not in self.blockers

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(
            (
                self.contract_version,
                "dispatch_preflight_assessment",
                ALPACA_PAPER_CAPABILITIES.semantic_sha256,
                self.attempt.preparation.semantic_sha256,
                self.attempt.semantic_sha256,
                tuple(item.semantic_sha256 for item in self.parent_attempts),
                self.parent_barrier_sha256,
                self.description.semantic_sha256,
                self.session.semantic_sha256,
                self.active_capacity.semantic_sha256,
                self.dispatch_fence_receipt.semantic_sha256,
                self.account_observation.receipt.semantic_sha256,
                self.account_observation.observation.semantic_sha256,
                self.asset_observation.receipt.semantic_sha256,
                self.asset_observation.observation.semantic_sha256,
                self.budget_policy.semantic_sha256,
                self.demand.semantic_sha256,
                self.permit.semantic_sha256,
                self.assessed_at,
                tuple(blocker.value for blocker in self.blockers),
                self.unresolved_runtime_gates,
            )
        )

    @property
    def assessment_id(self) -> str:
        return canonical_id(
            "alpaca-paper-dispatch-preflight-assessment",
            self.semantic_sha256,
        )

    @property
    def credential_resolution_ready(self) -> bool:
        return False

    @property
    def authenticated_account_ready(self) -> bool:
        return False

    @property
    def account_observation_current(self) -> bool:
        return False

    @property
    def authenticated_security_ready(self) -> bool:
        return False

    @property
    def asset_observation_current(self) -> bool:
        return False

    @property
    def security_mapping_ready(self) -> bool:
        return False

    @property
    def asset_tradability_validation_ready(self) -> bool:
        return False

    @property
    def reduce_only_validation_ready(self) -> bool:
        return False

    @property
    def exchange_calendar_binding_ready(self) -> bool:
        return False

    @property
    def session_validation_ready(self) -> bool:
        return False

    @property
    def quote_collar_ready(self) -> bool:
        return False

    @property
    def current_reservation_ready(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
        return False

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def transport_submission_ready(self) -> bool:
        return False

    @property
    def mark_in_flight_ready(self) -> bool:
        return False

    @property
    def coordinator_dispatch_ready(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def assess_alpaca_paper_dispatch_preflight(
    *,
    attempt: CanonicalSubmissionAttempt,
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...],
    description: AlpacaPaperSubmissionDescription,
    session: BatchRiskSession,
    active_capacity: ActiveCapacityUniverse,
    dispatch_fence_receipt: AccountFenceReceipt,
    account_observation: PersistedAlpacaAccountObservation,
    asset_observation: PersistedAlpacaAssetObservation,
    budget_policy: BrokerRequestBudgetPolicy,
    demand: BrokerRequestDemand,
    permit: BrokerRequestPermit,
) -> AlpacaPaperDispatchPreflightAssessment:
    """Assess exact offline evidence at the fence receipt's trusted instant."""

    if type(dispatch_fence_receipt) is not AccountFenceReceipt:
        raise AlpacaPaperDispatchPreflightError(
            "dispatch assessment requires an exact AccountFenceReceipt"
        )
    assessed_at = dispatch_fence_receipt.validated_at
    (
        barrier,
        authorization,
        _reservation_value,
        active_reservation,
        active_authorization,
    ) = _require_source_bindings(
        attempt=attempt,
        parent_attempts=parent_attempts,
        description=description,
        session=session,
        active_capacity=active_capacity,
        dispatch_fence_receipt=dispatch_fence_receipt,
        account_observation=account_observation,
        asset_observation=asset_observation,
        budget_policy=budget_policy,
        demand=demand,
        permit=permit,
        assessed_at=assessed_at,
    )
    blockers = _derive_blockers(
        attempt=attempt,
        barrier=barrier,
        session=session,
        authorization=authorization,
        active_reservation=active_reservation,
        active_authorization=active_authorization,
        account_observation=account_observation,
        asset_observation=asset_observation,
        permit=permit,
        assessed_at=assessed_at,
    )
    assessment = object.__new__(AlpacaPaperDispatchPreflightAssessment)
    for field_name, value in (
        ("attempt", attempt),
        ("parent_attempts", parent_attempts),
        ("parent_barrier_sha256", barrier.semantic_sha256),
        ("description", description),
        ("session", session),
        ("active_capacity", active_capacity),
        ("dispatch_fence_receipt", dispatch_fence_receipt),
        ("account_observation", account_observation),
        ("asset_observation", asset_observation),
        ("budget_policy", budget_policy),
        ("demand", demand),
        ("permit", permit),
        ("assessed_at", assessed_at),
        ("blockers", blockers),
    ):
        object.__setattr__(assessment, field_name, value)
    assessment._validate()
    return assessment


__all__ = [
    "ALPACA_PAPER_DISPATCH_PREFLIGHT_CONTRACT_VERSION",
    "ALPACA_PAPER_MAX_PARENT_ATTEMPTS",
    "ALPACA_PAPER_UNRESOLVED_RUNTIME_GATES",
    "AlpacaPaperDispatchBlocker",
    "AlpacaPaperDispatchPreflightAssessment",
    "AlpacaPaperDispatchPreflightError",
    "alpaca_paper_submission_budget_correlation_sha256",
    "assess_alpaca_paper_dispatch_preflight",
    "create_alpaca_paper_submission_budget_demand",
]
