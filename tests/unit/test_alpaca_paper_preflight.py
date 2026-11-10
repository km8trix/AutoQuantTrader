from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_CAPABILITIES,
    AlpacaPaperSubmissionDescription,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    create_alpaca_account_observation_description,
    create_alpaca_asset_observation_description,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
    create_alpaca_paper_request_demand,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    PersistedAlpacaAccountObservation,
    PersistedAlpacaAssetObservation,
    persist_then_decode_alpaca_account_observation_response,
    persist_then_decode_alpaca_asset_observation_response,
)
from packages.adapters.broker.alpaca_paper_preflight import (
    ALPACA_PAPER_DISPATCH_PREFLIGHT_CONTRACT_VERSION,
    ALPACA_PAPER_UNRESOLVED_RUNTIME_GATES,
    AlpacaPaperDispatchBlocker,
    AlpacaPaperDispatchPreflightAssessment,
    AlpacaPaperDispatchPreflightError,
    alpaca_paper_submission_budget_correlation_sha256,
    assess_alpaca_paper_dispatch_preflight,
    create_alpaca_paper_submission_budget_demand,
)
from packages.domain.account_coordinator import AccountFenceReceipt
from packages.domain.batch_risk import (
    ActiveCapacityReservationState,
    ActiveCapacityUniverse,
    BatchRiskDecision,
    BatchRiskSession,
    initial_active_capacity_universe,
)
from packages.domain.broker_request_budget import (
    BrokerRequestDemand,
    BrokerRequestPermit,
    issue_broker_request_permit,
)
from packages.domain.models import OrderIntent, Side
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    _abandon_pending_submission,
    mark_submission_in_flight,
    mark_submission_unknown,
    prepare_submission_attempt,
)
from tests.unit.test_alpaca_paper_account_asset_ingress import (
    InMemoryIngressRecorder,
    _account_body,
    _asset_body,
)
from tests.unit.test_submission_attempt import (
    EVALUATED_AT,
    PREPARED_AT,
    RECEIPT_AT,
    fence_receipt,
    intent,
    risk_decision,
)

ACCOUNT_ID = "fixture-submission-account"
ASSESSED_AT = PREPARED_AT + timedelta(seconds=2)
SESSION_CLOSE = EVALUATED_AT + timedelta(hours=6)


@dataclass(frozen=True, slots=True)
class Scenario:
    attempt: CanonicalSubmissionAttempt
    parent_attempts: tuple[CanonicalSubmissionAttempt, ...]
    description: AlpacaPaperSubmissionDescription
    session: BatchRiskSession
    active_capacity: ActiveCapacityUniverse
    dispatch_fence_receipt: AccountFenceReceipt
    account_observation: PersistedAlpacaAccountObservation
    asset_observation: PersistedAlpacaAssetObservation
    demand: BrokerRequestDemand
    permit: BrokerRequestPermit

    def assess(self) -> AlpacaPaperDispatchPreflightAssessment:
        return assess_alpaca_paper_dispatch_preflight(
            attempt=self.attempt,
            parent_attempts=self.parent_attempts,
            description=self.description,
            session=self.session,
            active_capacity=self.active_capacity,
            dispatch_fence_receipt=self.dispatch_fence_receipt,
            account_observation=self.account_observation,
            asset_observation=self.asset_observation,
            budget_policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
            demand=self.demand,
            permit=self.permit,
        )


def _session(
    *,
    opens_at: datetime = EVALUATED_AT - timedelta(minutes=1),
    closes_at: datetime = SESSION_CLOSE,
    calendar_version: str = "fixture-calendar-v1",
) -> BatchRiskSession:
    return BatchRiskSession(
        calendar_id="fixture-calendar",
        calendar_version=calendar_version,
        calendar_sha256="a" * 64,
        venue="XNYS",
        session_label=date(2026, 7, 15),
        opens_at=opens_at,
        closes_at=closes_at,
    )


def _decision(
    order_intent: OrderIntent,
    session: BatchRiskSession,
) -> BatchRiskDecision:
    source = risk_decision((order_intent,))
    authorization = replace(
        source.authorizations[0],
        session_sha256=session.semantic_sha256,
    )
    assert source.reservation is not None
    reservation = replace(
        source.reservation,
        authorizations=(authorization,),
    )
    return replace(
        source,
        reservation=reservation,
        authorizations=(authorization,),
    )


def _json_override(body: bytes, **updates: object) -> bytes:
    value = json.loads(body)
    assert type(value) is dict
    value.update(updates)
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _observations(
    order_intent: OrderIntent,
    *,
    account_body: bytes | None = None,
    asset_body: bytes | None = None,
) -> tuple[PersistedAlpacaAccountObservation, PersistedAlpacaAssetObservation]:
    recorder = InMemoryIngressRecorder()
    account = persist_then_decode_alpaca_account_observation_response(
        recorder,
        create_alpaca_account_observation_description(account_id=ACCOUNT_ID),
        delivery_idempotency_key="preflight-account-delivery",
        http_status=200,
        provider_request_id="preflight-account-request",
        response_body=_account_body() if account_body is None else account_body,
        received_at=datetime(2026, 7, 15, 13, 30, tzinfo=UTC),
        recorded_at=datetime(2026, 7, 15, 13, 30, 1, tzinfo=UTC),
    )
    asset = persist_then_decode_alpaca_asset_observation_response(
        recorder,
        create_alpaca_asset_observation_description(
            account_id=ACCOUNT_ID,
            instrument_id=order_intent.instrument_id,
            symbol=order_intent.symbol,
        ),
        delivery_idempotency_key="preflight-asset-delivery",
        http_status=200,
        provider_request_id="preflight-asset-request",
        response_body=_asset_body() if asset_body is None else asset_body,
        received_at=datetime(2026, 7, 15, 13, 30, 2, tzinfo=UTC),
        recorded_at=datetime(2026, 7, 15, 13, 30, 3, tzinfo=UTC),
    )
    return account, asset


def _scenario(
    *,
    side: Side = Side.BUY,
    assessed_at: datetime = ASSESSED_AT,
    session: BatchRiskSession | None = None,
    account_body: bytes | None = None,
    asset_body: bytes | None = None,
    permit_issued_at: datetime | None = None,
    idempotency_key: str = "preflight-submit-001",
) -> Scenario:
    order_intent = replace(intent(), side=side)
    bound_session = session or _session()
    decision = _decision(order_intent, bound_session)
    valid_until = assessed_at + timedelta(minutes=5)
    preparation_receipt = fence_receipt(
        validated_at=RECEIPT_AT,
        valid_until=valid_until,
    )
    description = create_alpaca_paper_submission_description(order_intent)
    attempt = prepare_submission_attempt(
        intent=order_intent,
        risk_decision=decision,
        fence_receipt=preparation_receipt,
        request=description.request,
        prepared_at=PREPARED_AT,
        recorded_at=PREPARED_AT,
        parent_attempts=(),
    )
    active_capacity = initial_active_capacity_universe(
        ACCOUNT_ID,
        (decision.reservation,),
    )
    account, asset = _observations(
        order_intent,
        account_body=account_body,
        asset_body=asset_body,
    )
    issued_at = assessed_at - timedelta(seconds=1) if permit_issued_at is None else permit_issued_at
    demand = create_alpaca_paper_submission_budget_demand(
        attempt=attempt,
        description=description,
        idempotency_key=idempotency_key,
        requested_at=issued_at,
    )
    permit = issue_broker_request_permit(
        policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
        demand=demand,
        issued_at=issued_at,
        active_permits=(),
        previous_permit=None,
        previous_policy=None,
    )
    return Scenario(
        attempt=attempt,
        parent_attempts=(attempt,),
        description=description,
        session=bound_session,
        active_capacity=active_capacity,
        dispatch_fence_receipt=fence_receipt(
            validated_at=assessed_at,
            valid_until=valid_until,
        ),
        account_observation=account,
        asset_observation=asset,
        demand=demand,
        permit=permit,
    )


def test_coherent_offline_buy_is_deterministic_but_never_authorized() -> None:
    scenario = _scenario()

    first = scenario.assess()
    second = scenario.assess()

    assert first == second
    assert first.contract_version == ALPACA_PAPER_DISPATCH_PREFLIGHT_CONTRACT_VERSION
    assert first.blockers == ()
    assert first.local_findings_clear is True
    assert first.offline_evidence_consistent is True
    assert first.budget_permit_fresh is True
    assert first.semantic_sha256 == second.semantic_sha256
    assert first.assessment_id == second.assessment_id
    assert scenario.attempt.state.value == "pending"
    assert len(scenario.attempt.events) == 1
    assert scenario.attempt.semantic_sha256 == first.attempt.semantic_sha256
    assert first.unresolved_runtime_gates == ALPACA_PAPER_UNRESOLVED_RUNTIME_GATES
    assert set(first.unresolved_runtime_gates) == set(ALPACA_PAPER_CAPABILITIES.runtime_readiness)
    assert all(
        value is False
        for value in (
            first.credential_resolution_ready,
            first.authenticated_account_ready,
            first.account_observation_current,
            first.authenticated_security_ready,
            first.asset_observation_current,
            first.security_mapping_ready,
            first.asset_tradability_validation_ready,
            first.reduce_only_validation_ready,
            first.exchange_calendar_binding_ready,
            first.session_validation_ready,
            first.quote_collar_ready,
            first.current_reservation_ready,
            first.reconciliation_ready,
            first.paper_startup_ready,
            first.request_budget_enforced,
            first.transport_submission_ready,
            first.mark_in_flight_ready,
            first.coordinator_dispatch_ready,
            first.dispatch_preflight_ready,
            first.transport_authorized,
            first.trading_effect_authorized,
        )
    )
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperDispatchPreflightAssessment()


def test_submission_demand_derives_account_purpose_and_correlation() -> None:
    scenario = _scenario()

    expected = alpaca_paper_submission_budget_correlation_sha256(
        attempt=scenario.attempt,
        description=scenario.description,
    )

    assert scenario.demand.account_id == ACCOUNT_ID
    assert scenario.demand.operation == AlpacaPaperBudgetOperation.SUBMIT_ORDER.value
    assert scenario.demand.correlation_sha256 == expected
    assert scenario.permit.demand_sha256 == scenario.demand.semantic_sha256
    assert scenario.permit.transport_authorized is False

    changed = _scenario(idempotency_key="preflight-submit-002").assess()
    assert changed.semantic_sha256 != scenario.assess().semantic_sha256


@pytest.mark.parametrize(
    ("scenario", "expected"),
    (
        (
            _scenario(
                assessed_at=EVALUATED_AT + timedelta(minutes=3),
                permit_issued_at=EVALUATED_AT + timedelta(minutes=3, seconds=-1),
            ),
            AlpacaPaperDispatchBlocker.RISK_APPROVAL_EXPIRED,
        ),
        (
            _scenario(
                assessed_at=intent().expires_at,
                permit_issued_at=intent().expires_at - timedelta(seconds=1),
            ),
            AlpacaPaperDispatchBlocker.INTENT_EXPIRED,
        ),
        (
            _scenario(
                assessed_at=ASSESSED_AT,
                session=_session(closes_at=ASSESSED_AT),
            ),
            AlpacaPaperDispatchBlocker.SESSION_CLOSED,
        ),
        (
            _scenario(permit_issued_at=ASSESSED_AT - ALPACA_PAPER_REQUEST_BUDGET_POLICY.permit_ttl),
            AlpacaPaperDispatchBlocker.REQUEST_PERMIT_NOT_FRESH,
        ),
    ),
)
def test_expiry_and_session_close_equalities_fail_closed(
    scenario: Scenario,
    expected: AlpacaPaperDispatchBlocker,
) -> None:
    assessment = scenario.assess()

    assert expected in assessment.blockers
    assert assessment.local_findings_clear is False
    assert assessment.dispatch_preflight_ready is False


def test_session_open_is_inclusive() -> None:
    scenario = _scenario(session=_session(opens_at=ASSESSED_AT))

    assert AlpacaPaperDispatchBlocker.SESSION_CLOSED not in scenario.assess().blockers


@pytest.mark.parametrize(
    ("account_body", "asset_body", "expected"),
    (
        (
            _json_override(_account_body(), trading_blocked=True),
            None,
            AlpacaPaperDispatchBlocker.ACCOUNT_NOT_LOCALLY_USABLE,
        ),
        (
            None,
            _json_override(_asset_body(), tradable=False),
            AlpacaPaperDispatchBlocker.ASSET_NOT_LOCALLY_USABLE,
        ),
        (
            None,
            _json_override(_asset_body(), attributes=["ptp_no_exception"]),
            AlpacaPaperDispatchBlocker.ASSET_NOT_LOCALLY_USABLE,
        ),
    ),
)
def test_provider_status_findings_remain_explicit_and_non_authorizing(
    account_body: bytes | None,
    asset_body: bytes | None,
    expected: AlpacaPaperDispatchBlocker,
) -> None:
    assessment = _scenario(
        account_body=account_body,
        asset_body=asset_body,
    ).assess()

    assert expected in assessment.blockers
    assert assessment.offline_evidence_consistent is True
    assert assessment.transport_authorized is False


def test_missing_frozen_or_partially_consumed_capacity_blocks() -> None:
    scenario = _scenario()
    empty = replace(
        scenario,
        active_capacity=ActiveCapacityUniverse(
            account_id=ACCOUNT_ID,
            reservations=(),
        ),
    )
    assert AlpacaPaperDispatchBlocker.RESERVATION_CAPACITY_UNAVAILABLE in empty.assess().blockers

    reservation = scenario.active_capacity.reservations[0]
    frozen = replace(
        scenario,
        active_capacity=replace(
            scenario.active_capacity,
            reservations=(
                replace(
                    reservation,
                    state=ActiveCapacityReservationState.FROZEN,
                ),
            ),
        ),
    )
    assert AlpacaPaperDispatchBlocker.RESERVATION_CAPACITY_UNAVAILABLE in frozen.assess().blockers

    active_authorization = reservation.authorizations[0]
    partially_consumed = replace(
        scenario,
        active_capacity=replace(
            scenario.active_capacity,
            reservations=(
                replace(
                    reservation,
                    state=ActiveCapacityReservationState.PARTIALLY_RELEASED,
                    authorizations=(
                        replace(
                            active_authorization,
                            remaining_cash=active_authorization.remaining_buy_exposure,
                        ),
                    ),
                ),
            ),
        ),
    )
    assert (
        AlpacaPaperDispatchBlocker.RESERVATION_CAPACITY_UNAVAILABLE
        in partially_consumed.assess().blockers
    )


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    (
        ("intent_id", "different-intent"),
        ("instrument_id", "US-ETF-QQQ"),
        ("reserved_cash", None),
    ),
)
def test_active_capacity_immutable_child_drift_is_a_hard_conflict(
    field_name: str,
    field_value: object,
) -> None:
    scenario = _scenario()
    reservation = scenario.active_capacity.reservations[0]
    authorization = reservation.authorizations[0]
    if field_name == "reserved_cash":
        field_value = authorization.reserved_cash + 1
    altered_authorization = replace(
        authorization,
        **{field_name: field_value},
    )
    altered_capacity = replace(
        scenario.active_capacity,
        reservations=(
            replace(
                reservation,
                authorizations=(altered_authorization,),
            ),
        ),
    )

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="exact risk authorization",
    ):
        replace(scenario, active_capacity=altered_capacity).assess()


def test_active_capacity_reservation_currency_drift_is_a_hard_conflict() -> None:
    scenario = _scenario()
    reservation = scenario.active_capacity.reservations[0]
    altered_capacity = replace(
        scenario.active_capacity,
        reservations=(replace(reservation, currency="EUR"),),
    )

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="exact risk reservation",
    ):
        replace(scenario, active_capacity=altered_capacity).assess()


def test_sell_retains_exact_capacity_but_reduce_only_is_never_inferred() -> None:
    assessment = _scenario(side=Side.SELL).assess()

    assert AlpacaPaperDispatchBlocker.RESERVATION_CAPACITY_UNAVAILABLE not in assessment.blockers
    assert AlpacaPaperDispatchBlocker.SELL_REDUCE_ONLY_UNPROVEN in assessment.blockers
    assert assessment.asset_observation.observation.shortable is True
    assert assessment.reduce_only_validation_ready is False
    assert assessment.trading_effect_authorized is False


def test_nonpending_and_parent_unknown_states_are_closed_findings() -> None:
    scenario = _scenario()
    in_flight = mark_submission_in_flight(
        scenario.attempt,
        dispatch_fence_receipt=scenario.dispatch_fence_receipt,
        occurred_at=ASSESSED_AT,
        recorded_at=ASSESSED_AT,
    )
    in_flight_scenario = replace(
        scenario,
        attempt=in_flight,
        parent_attempts=(in_flight,),
    )
    assert AlpacaPaperDispatchBlocker.ATTEMPT_NOT_PENDING in in_flight_scenario.assess().blockers

    unknown = mark_submission_unknown(
        in_flight,
        occurred_at=ASSESSED_AT,
        recorded_at=ASSESSED_AT,
        error_class="TimeoutError",
    )
    unknown_scenario = replace(
        scenario,
        attempt=unknown,
        parent_attempts=(unknown,),
    )
    assessment = unknown_scenario.assess()
    assert AlpacaPaperDispatchBlocker.ATTEMPT_NOT_PENDING in assessment.blockers
    assert AlpacaPaperDispatchBlocker.PARENT_UNKNOWN_UNRESOLVED in assessment.blockers


def test_parent_snapshot_rejects_an_omitted_attempt_predecessor() -> None:
    scenario = _scenario()
    abandoned_at = PREPARED_AT + timedelta(milliseconds=500)
    abandoned = _abandon_pending_submission(
        scenario.attempt,
        occurred_at=abandoned_at,
        recorded_at=abandoned_at,
        error_class="RecoveredPreparedWithoutDispatch",
    )
    retry_at = PREPARED_AT + timedelta(seconds=1)
    retry = prepare_submission_attempt(
        intent=scenario.attempt.preparation.intent,
        risk_decision=scenario.attempt.preparation.risk_decision,
        fence_receipt=scenario.attempt.preparation.fence_receipt,
        request=scenario.description.request,
        prepared_at=retry_at,
        recorded_at=retry_at,
        parent_attempts=(abandoned,),
    )
    demand = create_alpaca_paper_submission_budget_demand(
        attempt=retry,
        description=scenario.description,
        idempotency_key="preflight-submit-retry",
        requested_at=scenario.demand.requested_at,
    )
    permit = issue_broker_request_permit(
        policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
        demand=demand,
        issued_at=scenario.permit.issued_at,
        active_permits=(),
        previous_permit=None,
        previous_policy=None,
    )

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="contiguous history from one",
    ):
        replace(
            scenario,
            attempt=retry,
            parent_attempts=(retry,),
            demand=demand,
            permit=permit,
        ).assess()


def test_parent_snapshot_rejects_a_reused_order_attempt_number_slot() -> None:
    scenario = _scenario()
    alternate = prepare_submission_attempt(
        intent=scenario.attempt.preparation.intent,
        risk_decision=scenario.attempt.preparation.risk_decision,
        fence_receipt=fence_receipt(
            validated_at=RECEIPT_AT,
            valid_until=scenario.attempt.preparation.fence_receipt.valid_until,
            fencing_generation=2,
        ),
        request=scenario.description.request,
        prepared_at=PREPARED_AT,
        recorded_at=PREPARED_AT,
        parent_attempts=(),
    )
    duplicate_slot_snapshot = tuple(
        sorted(
            (scenario.attempt, alternate),
            key=lambda item: (item.order_id, item.attempt_number, item.attempt_id),
        )
    )

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="reuses an order attempt-number slot",
    ):
        replace(
            scenario,
            parent_attempts=duplicate_slot_snapshot,
        ).assess()


def test_immutable_crossbinding_conflicts_reject_construction() -> None:
    scenario = _scenario()
    wrong_correlation = create_alpaca_paper_request_demand(
        account_id=ACCOUNT_ID,
        idempotency_key="preflight-wrong-correlation",
        operation=AlpacaPaperBudgetOperation.SUBMIT_ORDER,
        correlation_sha256="f" * 64,
        requested_at=scenario.demand.requested_at,
    )
    wrong_permit = issue_broker_request_permit(
        policy=ALPACA_PAPER_REQUEST_BUDGET_POLICY,
        demand=wrong_correlation,
        issued_at=scenario.permit.issued_at,
        active_permits=(),
        previous_permit=None,
        previous_policy=None,
    )
    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="demand does not bind",
    ):
        replace(
            scenario,
            demand=wrong_correlation,
            permit=wrong_permit,
        ).assess()

    with pytest.raises(AlpacaPaperDispatchPreflightError, match="session"):
        replace(
            scenario,
            session=_session(calendar_version="different-calendar-version"),
        ).assess()

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="active capacity belongs",
    ):
        replace(
            scenario,
            active_capacity=ActiveCapacityUniverse(
                account_id="other-account",
                reservations=(),
            ),
        ).assess()

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="stable fence",
    ):
        replace(
            scenario,
            dispatch_fence_receipt=fence_receipt(
                account_id="other-account",
                validated_at=ASSESSED_AT,
                valid_until=ASSESSED_AT + timedelta(minutes=5),
            ),
        ).assess()

    with pytest.raises(
        AlpacaPaperDispatchPreflightError,
        match="contain the assessed attempt exactly once",
    ):
        replace(
            scenario,
            parent_attempts=(scenario.attempt, scenario.attempt),
        ).assess()


def test_assessment_digest_authenticates_blockers_and_every_source() -> None:
    usable = _scenario().assess()
    blocked = _scenario(asset_body=_json_override(_asset_body(), tradable=False)).assess()

    assert usable.semantic_sha256 != blocked.semantic_sha256
    assert usable.asset_observation.receipt.semantic_sha256 != (
        blocked.asset_observation.receipt.semantic_sha256
    )
    assert usable.blockers != blocked.blockers
    assert "APCA-API-SECRET-KEY" not in repr(usable)
