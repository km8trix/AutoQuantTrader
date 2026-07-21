from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, localcontext
from itertools import permutations

import pytest

from packages.backtest.simulated_broker import (
    ConservativeSimulatedBroker,
    SimulatedBrokerError,
    SimulatedBrokerFactConflict,
    SimulatedBrokerOutcome,
    SimulatedBrokerResult,
    SimulatedBrokerSession,
    SimulatedDeferredSourceBlockReason,
    SimulatedMarketOrderModel,
    SimulatedRiskCapViolation,
)
from packages.domain.batch_risk import (
    BatchRiskAuthorization,
    BatchRiskSession,
    BatchRiskSessionKind,
)
from packages.domain.decimal_math import exact_decimal_add, exact_decimal_multiply
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import reduce_execution_ledger
from packages.domain.market_batch import MarketBatch, MarketWatermark
from packages.domain.models import DecisionStatus, MarketEvent, OrderIntent, Side
from packages.domain.order_reducer import (
    BrokerOrderEventKind,
    CanonicalOrderStatus,
    reduce_order_lifecycle,
)
from packages.domain.replay import replay_market_events
from packages.domain.risk import (
    ExecutableRiskAuthorization,
    InMemoryRiskDecisionRepository,
    RiskAuthorizationError,
    intent_payload_hash,
    validate_authorization_consumption,
)
from packages.domain.walking_thread import WalkingThread
from packages.market_data.calendar import ExchangeSession, SessionKind

SESSION_OPEN = datetime(2026, 7, 15, 13, 30, tzinfo=UTC)
SESSION_CLOSE = datetime(2026, 7, 15, 20, tzinfo=UTC)
SUBMITTED_AT = datetime(2026, 7, 15, 13, 31, 2, tzinfo=UTC)
INSTRUMENT_ID = WalkingThread.instrument_id
SYMBOL = WalkingThread.symbol


def intent() -> OrderIntent:
    return WalkingThread.run().intent


def simulated_session(
    *,
    opens_at: datetime = SESSION_OPEN,
    closes_at: datetime = SESSION_CLOSE,
    kind: SessionKind = SessionKind.REGULAR,
) -> SimulatedBrokerSession:
    return SimulatedBrokerSession(
        calendar_id="xnys-test-calendar",
        calendar_version="2026.07.15",
        calendar_sha256="a" * 64,
        session=ExchangeSession(
            venue="XNYS",
            session_label=date(2026, 7, 15),
            opens_at=opens_at,
            closes_at=closes_at,
            kind=kind,
        ),
    )


def market_model(**changes: object) -> SimulatedMarketOrderModel:
    values: dict[str, object] = {
        "model_id": "conservative-market-order",
        "model_version": "1.0.0",
        "activation_latency": timedelta(0),
        "half_spread_per_share": Decimal("0.05"),
        "slippage_per_share": Decimal("0.02"),
        "fixed_fee": Decimal("0.50"),
        "fee_per_share": Decimal("0.01"),
        "currency": "USD",
    }
    values.update(changes)
    return SimulatedMarketOrderModel(**values)  # type: ignore[arg-type]


def market_batch(
    event_time: datetime,
    *,
    close_price: Decimal = Decimal("101.00"),
    closed_at: datetime | None = None,
    instrument_id: str = INSTRUMENT_ID,
    symbol: str = SYMBOL,
    expected_instrument_ids: tuple[str, ...] | None = None,
    include_event: bool = True,
    event_id: str | None = None,
    observation_id: str | None = None,
    watermark_id: str | None = None,
) -> MarketBatch:
    resolved_closed_at = closed_at or event_time + timedelta(seconds=5)
    resolved_expected = expected_instrument_ids or (instrument_id,)
    event = MarketEvent(
        event_id=event_id or f"broker-{instrument_id}-{event_time.isoformat()}",
        instrument_id=instrument_id,
        symbol=symbol,
        event_time=event_time,
        available_at=resolved_closed_at,
        close_price=close_price,
        source="broker-test-tape-v1",
        source_sequence=int(event_time.timestamp()),
        observation_id=observation_id,
    )
    watermark = MarketWatermark(
        watermark_id=watermark_id
        or f"broker-watermark-{event_time.isoformat()}-{resolved_closed_at.isoformat()}",
        event_time_through=event_time,
        closed_at=resolved_closed_at,
        expected_instrument_ids=tuple(sorted(resolved_expected)),
    )
    return replay_market_events(
        events=(event,) if include_event else (),
        watermarks=(watermark,),
    ).batches[0]


def authorization(
    submitted_intent: OrderIntent,
) -> tuple[InMemoryRiskDecisionRepository, str]:
    repository = InMemoryRiskDecisionRepository(WalkingThread.risk_authority())
    decision = repository.authorize(submitted_intent)
    return repository, decision.decision_id


class CappedAuthorizationConsumer:
    def __init__(self, authorization: ExecutableRiskAuthorization) -> None:
        self.authorization = authorization
        self.consumed = False

    def get(self, decision_id: str) -> ExecutableRiskAuthorization | None:
        if decision_id != self.authorization.decision_id:
            return None
        return self.authorization

    def consume(self, decision_id: str, submitted_intent: OrderIntent) -> datetime:
        authorization = self.get(decision_id)
        if authorization is None:
            raise RiskAuthorizationError("execution requires a persisted risk authorization")
        validate_authorization_consumption(authorization, submitted_intent, SUBMITTED_AT)
        if self.consumed:
            raise RiskAuthorizationError("risk authorization has already been consumed")
        self.consumed = True
        return SUBMITTED_AT


def batch_risk_session(
    broker_session: SimulatedBrokerSession | None = None,
) -> BatchRiskSession:
    evidence = broker_session or simulated_session()
    return BatchRiskSession(
        calendar_id=evidence.calendar_id,
        calendar_version=evidence.calendar_version,
        calendar_sha256=evidence.calendar_sha256,
        venue=evidence.session.venue,
        session_label=evidence.session.session_label,
        opens_at=evidence.session.opens_at,
        closes_at=evidence.session.closes_at,
        kind=BatchRiskSessionKind(evidence.session.kind.value),
    )


def capped_authorization(
    submitted_intent: OrderIntent,
    *,
    maximum_execution_price: Decimal,
    maximum_fee: Decimal,
    session_evidence: SimulatedBrokerSession | None = None,
    currency: str = "USD",
) -> BatchRiskAuthorization:
    parent_decision_id = "batch-risk-parent-decision"
    buy_exposure = (
        exact_decimal_multiply(submitted_intent.quantity, maximum_execution_price)
        if submitted_intent.side is Side.BUY
        else Decimal(0)
    )
    maximum_cash = exact_decimal_add(buy_exposure, maximum_fee)
    return BatchRiskAuthorization(
        decision_id=canonical_id(
            "batch-risk-authorization",
            parent_decision_id,
            submitted_intent.intent_id,
        ),
        parent_decision_id=parent_decision_id,
        reservation_id=canonical_id("batch-risk-reservation", parent_decision_id),
        intent_batch_id=submitted_intent.intent_batch_id,
        intent_batch_sha256="b" * 64,
        snapshot_sha256="c" * 64,
        policy_sha256="d" * 64,
        session_sha256=batch_risk_session(session_evidence).semantic_sha256,
        currency=currency,
        intent_id=submitted_intent.intent_id,
        intent_payload_hash=intent_payload_hash(submitted_intent),
        status=DecisionStatus.APPROVED,
        evaluated_at=SUBMITTED_AT - timedelta(seconds=1),
        expires_at=SUBMITTED_AT + timedelta(seconds=29),
        instrument_id=submitted_intent.instrument_id,
        symbol=submitted_intent.symbol,
        side=submitted_intent.side,
        quantity=submitted_intent.quantity,
        reference_price=submitted_intent.reference_price,
        snapshot_as_of=submitted_intent.created_at,
        reference_event_time=submitted_intent.decision_event_time,
        maximum_execution_price=maximum_execution_price,
        maximum_fee=maximum_fee,
        maximum_cash_requirement=maximum_cash,
        reserved_cash=maximum_cash,
        reserved_sell_quantity=(
            submitted_intent.quantity if submitted_intent.side is Side.SELL else Decimal(0)
        ),
        reserved_buy_exposure=buy_exposure,
    )


@dataclass(frozen=True, slots=True)
class MalformedCappedAuthorization:
    decision_id: str
    intent_id: str
    intent_payload_hash: str
    status: DecisionStatus
    evaluated_at: datetime
    expires_at: datetime
    maximum_execution_price: object
    maximum_cash_requirement: object
    session_sha256: str
    currency: str


def submit(
    *,
    submitted_intent: OrderIntent | None = None,
    batches: tuple[MarketBatch, ...],
    model: SimulatedMarketOrderModel | None = None,
    session: SimulatedBrokerSession | None = None,
    submission_attempt_id: str = "broker-test-attempt",
) -> SimulatedBrokerResult:
    resolved_intent = submitted_intent or intent()
    repository, decision_id = authorization(resolved_intent)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=repository,
        model=model or market_model(),
        session=session or simulated_session(),
        market_batches=batches,
    )
    return broker.submit(resolved_intent, decision_id, submission_attempt_id)


def test_authorized_order_is_fully_filled_with_exact_evidence_and_lifecycle() -> None:
    source_batch = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))

    result = submit(batches=(source_batch,))

    assert result.outcome is SimulatedBrokerOutcome.FILLED
    assert result.activation_at == SUBMITTED_AT
    assert result.order_state.status is CanonicalOrderStatus.FILLED
    assert result.order_state.filled_quantity == Decimal("10")
    assert result.order_state.remaining_quantity == 0
    assert result.order_state.total_fees == Decimal("0.60")
    assert tuple(event.kind for event in result.broker_events) == (
        BrokerOrderEventKind.ACCEPTED,
        BrokerOrderEventKind.EXECUTION,
    )
    assert tuple(event.broker_sequence for event in result.broker_events) == (1, 2)
    assert (
        reduce_order_lifecycle(
            submission=result.submission,
            broker_events=result.broker_events,
        )
        == result.order_state
    )

    evidence = result.fill_evidence
    assert evidence is not None
    source_event = source_batch.event_for(INSTRUMENT_ID)
    working = reduce_order_lifecycle(
        submission=result.submission,
        broker_events=(result.broker_events[0],),
    )
    assert evidence.working_order_state_sha256 == working.semantic_sha256
    assert evidence.source_batch_id == source_batch.batch_id
    assert evidence.source_batch_sha256 == source_batch.semantic_sha256
    assert evidence.source_event_id == source_event.event_id
    assert evidence.source_event_sha256 == source_event.semantic_sha256
    assert evidence.model_sha256 == result.model.semantic_sha256
    assert evidence.session_sha256 == result.session.semantic_sha256
    assert evidence.occurred_at == source_event.event_time
    assert evidence.received_at == source_batch.as_of
    assert evidence.terms.reference_price == Decimal("101.00")
    assert evidence.terms.execution_price == Decimal("101.07")
    assert evidence.terms.variable_fee == Decimal("0.10")
    assert evidence.terms.total_fee == Decimal("0.60")
    ledger = reduce_execution_ledger(
        order_states=(result.order_state,),
        execution_currency=result.model.currency,
    )
    assert ledger.position_quantity(INSTRUMENT_ID) == Decimal("10")
    assert ledger.balance("expenses:execution_fees").amount == Decimal("0.60")


def test_batch_child_authorization_allows_a_fully_reserved_buy() -> None:
    submitted_intent = intent()
    source_batch = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=Decimal("101.07"),
        maximum_fee=Decimal("0.60"),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(source_batch,),
    )

    result = broker.submit(
        submitted_intent,
        authorization.decision_id,
        "capped-buy-attempt",
    )

    assert consumer.consumed
    assert result.fill_evidence is not None
    assert result.fill_evidence.terms.execution_price == authorization.maximum_execution_price
    assert authorization.maximum_cash_requirement == Decimal("1011.30")
    assert result.risk_execution_caps is not None
    assert result.risk_execution_caps.authorization_decision_id == authorization.decision_id
    assert (
        result.risk_execution_caps.maximum_cash_requirement
        == authorization.maximum_cash_requirement
    )
    assert result.cap_block_evidence is None


def test_batch_price_cap_uses_only_the_first_eligible_fill() -> None:
    submitted_intent = intent()
    within_cap = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        close_price=Decimal("101.00"),
    )
    later_above_cap = market_batch(
        datetime(2026, 7, 15, 13, 33, tzinfo=UTC),
        close_price=Decimal("101.01"),
    )
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=Decimal("101.07"),
        maximum_fee=Decimal("0.60"),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(within_cap, later_above_cap),
    )

    result = broker.submit(
        submitted_intent,
        authorization.decision_id,
        "price-cap-prefix-causality-attempt",
    )

    assert consumer.consumed
    assert result.fill_evidence is not None
    assert result.fill_evidence.source_batch_id == within_cap.batch_id


def test_first_eligible_price_cap_breach_preserves_acceptance_and_blocks_execution() -> None:
    submitted_intent = intent()
    above_cap = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        close_price=Decimal("101.01"),
    )
    later_within_cap = market_batch(
        datetime(2026, 7, 15, 13, 33, tzinfo=UTC),
        close_price=Decimal("101.00"),
    )
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=Decimal("101.07"),
        maximum_fee=Decimal("0.60"),
    )
    empty_consumer = CappedAuthorizationConsumer(authorization)
    empty_broker = ConservativeSimulatedBroker(
        risk_authorizations=empty_consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(),
    )
    baseline = empty_broker.submit(
        submitted_intent,
        authorization.decision_id,
        "first-price-cap-attempt",
    )

    blocked_consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=blocked_consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(above_cap, later_within_cap),
    )
    blocked = broker.submit(
        submitted_intent,
        authorization.decision_id,
        "first-price-cap-attempt",
    )

    assert empty_consumer.consumed
    assert blocked_consumer.consumed
    assert baseline.outcome is SimulatedBrokerOutcome.WORKING_NO_ELIGIBLE_EVENT
    assert blocked.outcome is SimulatedBrokerOutcome.WORKING_RISK_CAP_BLOCKED
    assert blocked.submission == baseline.submission
    assert blocked.broker_events == baseline.broker_events
    assert blocked.order_state == baseline.order_state
    assert blocked.fill_evidence is None
    assert blocked.risk_execution_caps is not None
    evidence = blocked.cap_block_evidence
    assert evidence is not None
    assert evidence.source_batch_id == above_cap.batch_id
    assert evidence.violations == (
        SimulatedRiskCapViolation.BUY_PRICE,
        SimulatedRiskCapViolation.CASH_REQUIREMENT,
    )

    with pytest.raises(SimulatedBrokerError, match="does not match"):
        replace(
            blocked,
            cap_block_evidence=replace(evidence, source_event_sha256="0" * 64),
        )


def test_capped_extreme_price_product_preserves_acceptance_after_consumption() -> None:
    submitted_intent = intent()
    extreme_source = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        close_price=Decimal("999999999999999999"),
    )
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=Decimal("101.07"),
        maximum_fee=Decimal("0.60"),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(extreme_source,),
    )

    result = broker.submit(
        submitted_intent,
        authorization.decision_id,
        "extreme-price-cap-attempt",
    )

    assert consumer.consumed
    assert result.outcome is SimulatedBrokerOutcome.WORKING_RISK_CAP_BLOCKED
    assert result.order_state.status is CanonicalOrderStatus.WORKING
    assert result.fill_evidence is None
    evidence = result.cap_block_evidence
    assert evidence is not None
    assert evidence.violations == (
        SimulatedRiskCapViolation.BUY_PRICE,
        SimulatedRiskCapViolation.CASH_REQUIREMENT,
    )


@pytest.mark.parametrize("mismatch", ["session", "currency"])
def test_batch_execution_context_must_match_before_consumption(mismatch: str) -> None:
    submitted_intent = intent()
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=Decimal("101.07"),
        maximum_fee=Decimal("0.60"),
        session_evidence=(
            simulated_session(kind=SessionKind.HALF_DAY) if mismatch == "session" else None
        ),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(currency="EUR" if mismatch == "currency" else "USD"),
        session=simulated_session(),
        market_batches=(market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC)),),
    )

    with pytest.raises(SimulatedBrokerError, match=mismatch):
        broker.submit(
            submitted_intent,
            authorization.decision_id,
            f"{mismatch}-mismatch-attempt",
        )

    assert not consumer.consumed


@pytest.mark.parametrize("side", [Side.BUY, Side.SELL])
def test_batch_cash_cap_blocks_future_buy_cost_or_sell_fee(side: Side) -> None:
    submitted_intent = replace(intent(), side=side)
    source_batch = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=(
            Decimal("101.07") if side is Side.BUY else submitted_intent.reference_price
        ),
        maximum_fee=Decimal("0") if side is Side.BUY else Decimal("0.50"),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(source_batch,),
    )

    result = broker.submit(
        submitted_intent,
        authorization.decision_id,
        f"{side.value}-cash-cap-attempt",
    )

    assert consumer.consumed
    assert result.outcome is SimulatedBrokerOutcome.WORKING_RISK_CAP_BLOCKED
    assert result.order_state.status is CanonicalOrderStatus.WORKING
    assert result.fill_evidence is None
    assert result.cap_block_evidence is not None
    assert result.cap_block_evidence.violations == (SimulatedRiskCapViolation.CASH_REQUIREMENT,)


@pytest.mark.parametrize(
    ("maximum_execution_price", "maximum_cash_requirement", "message"),
    [
        (Decimal("NaN"), Decimal("2000"), "finite exact Decimal"),
        (Decimal("101.07"), "1011.30", "finite exact Decimal"),
        (Decimal("99"), Decimal("2000"), "below the intent reference"),
        (Decimal("101.07"), Decimal("1000"), "does not cover its buy price cap"),
    ],
)
def test_malformed_batch_execution_caps_fail_before_consumption(
    maximum_execution_price: object,
    maximum_cash_requirement: object,
    message: str,
) -> None:
    submitted_intent = intent()
    malformed = MalformedCappedAuthorization(
        decision_id="malformed-batch-authorization",
        intent_id=submitted_intent.intent_id,
        intent_payload_hash=intent_payload_hash(submitted_intent),
        status=DecisionStatus.APPROVED,
        evaluated_at=SUBMITTED_AT - timedelta(seconds=1),
        expires_at=SUBMITTED_AT + timedelta(seconds=29),
        maximum_execution_price=maximum_execution_price,
        maximum_cash_requirement=maximum_cash_requirement,
        session_sha256=batch_risk_session().semantic_sha256,
        currency="USD",
    )
    consumer = CappedAuthorizationConsumer(malformed)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC)),),
    )

    with pytest.raises(SimulatedBrokerError, match=message):
        broker.submit(
            submitted_intent,
            malformed.decision_id,
            "malformed-cap-attempt",
        )

    assert not consumer.consumed


def test_fill_uses_first_event_strictly_later_than_activation() -> None:
    model = market_model(activation_latency=timedelta(seconds=3))
    delayed_old = market_batch(
        datetime(2026, 7, 15, 13, 31, tzinfo=UTC),
        closed_at=datetime(2026, 7, 15, 13, 31, 20, tzinfo=UTC),
        close_price=Decimal("98"),
    )
    equal_activation = market_batch(
        datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC),
        closed_at=datetime(2026, 7, 15, 13, 31, 21, tzinfo=UTC),
        close_price=Decimal("99"),
    )
    first_later = market_batch(
        datetime(2026, 7, 15, 13, 31, 6, tzinfo=UTC),
        closed_at=datetime(2026, 7, 15, 13, 31, 22, tzinfo=UTC),
        close_price=Decimal("100"),
    )
    later = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        closed_at=datetime(2026, 7, 15, 13, 32, 5, tzinfo=UTC),
        close_price=Decimal("200"),
    )

    result = submit(
        batches=(later, equal_activation, delayed_old, first_later),
        model=model,
    )

    assert result.activation_at == datetime(2026, 7, 15, 13, 31, 5, tzinfo=UTC)
    assert result.fill_evidence is not None
    assert result.fill_evidence.source_batch_id == first_later.batch_id
    assert result.fill_evidence.terms.reference_price == Decimal("100")


def test_no_strictly_later_event_leaves_the_accepted_order_working() -> None:
    equal_activation = market_batch(SUBMITTED_AT)

    result = submit(batches=(equal_activation,))

    assert result.outcome is SimulatedBrokerOutcome.WORKING_NO_ELIGIBLE_EVENT
    assert result.fill_evidence is None
    assert len(result.broker_events) == 1
    assert result.broker_events[0].kind is BrokerOrderEventKind.ACCEPTED
    assert result.order_state.status is CanonicalOrderStatus.WORKING
    assert result.order_state.filled_quantity == 0


def test_exported_results_reprove_tape_horizon_and_first_eligible_selection() -> None:
    equal_activation = market_batch(SUBMITTED_AT)
    first_later = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))
    later = market_batch(datetime(2026, 7, 15, 13, 33, tzinfo=UTC))
    working = submit(batches=(equal_activation,))
    later_only = submit(batches=(later,))

    with pytest.raises(SimulatedBrokerError, match="ignores an eligible"):
        replace(
            working,
            market_batches=(equal_activation, first_later),
            completed_at=first_later.as_of,
        )
    with pytest.raises(SimulatedBrokerError, match="first eligible"):
        replace(later_only, market_batches=(first_later, later))
    with pytest.raises(SimulatedBrokerError, match="completion does not cover"):
        replace(working, completed_at=working.completed_at + timedelta(seconds=1))


def test_incomplete_first_relevant_future_batch_fails_closed() -> None:
    incomplete = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        include_event=False,
    )
    complete_later = market_batch(datetime(2026, 7, 15, 13, 33, tzinfo=UTC))

    submitted_intent = intent()
    repository, decision_id = authorization(submitted_intent)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=repository,
        model=market_model(),
        session=simulated_session(),
        market_batches=(complete_later, incomplete),
    )

    with pytest.raises(SimulatedBrokerError, match=r"incomplete.*unknowable"):
        broker.submit(submitted_intent, decision_id, "incomplete-tape-attempt")

    assert not repository.was_consumed(decision_id)


def test_capped_incomplete_future_batch_preserves_accepted_working_result() -> None:
    submitted_intent = intent()
    incomplete = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        include_event=False,
    )
    complete_later = market_batch(datetime(2026, 7, 15, 13, 33, tzinfo=UTC))
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=Decimal("101.07"),
        maximum_fee=Decimal("0.60"),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(incomplete, complete_later),
    )

    result = broker.submit(
        submitted_intent,
        authorization.decision_id,
        "capped-incomplete-source-attempt",
    )

    assert consumer.consumed
    assert result.outcome is SimulatedBrokerOutcome.WORKING_DEFERRED_SOURCE_BLOCKED
    assert result.order_state.status is CanonicalOrderStatus.WORKING
    assert tuple(event.kind for event in result.broker_events) == (BrokerOrderEventKind.ACCEPTED,)
    evidence = result.deferred_source_block_evidence
    assert evidence is not None
    assert evidence.reason is SimulatedDeferredSourceBlockReason.INCOMPLETE_BATCH
    assert evidence.source_batch_id == incomplete.batch_id
    assert evidence.source_event_id is None

    with pytest.raises(SimulatedBrokerError, match="causal context"):
        replace(
            result,
            deferred_source_block_evidence=replace(
                evidence,
                source_batch_sha256="0" * 64,
            ),
        )


def test_capped_invalid_future_execution_terms_preserve_acceptance() -> None:
    submitted_intent = replace(intent(), side=Side.SELL)
    source_batch = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        close_price=Decimal("0.01"),
    )
    authorization = capped_authorization(
        submitted_intent,
        maximum_execution_price=submitted_intent.reference_price,
        maximum_fee=Decimal("0.60"),
    )
    consumer = CappedAuthorizationConsumer(authorization)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=market_model(),
        session=simulated_session(),
        market_batches=(source_batch,),
    )

    result = broker.submit(
        submitted_intent,
        authorization.decision_id,
        "capped-invalid-terms-attempt",
    )

    assert consumer.consumed
    assert result.outcome is SimulatedBrokerOutcome.WORKING_DEFERRED_SOURCE_BLOCKED
    assert result.order_state.status is CanonicalOrderStatus.WORKING
    evidence = result.deferred_source_block_evidence
    assert evidence is not None
    assert evidence.reason is SimulatedDeferredSourceBlockReason.INVALID_EXECUTION_TERMS
    assert evidence.source_batch_id == source_batch.batch_id
    assert evidence.source_event_id == source_batch.event_for(INSTRUMENT_ID).event_id


def test_tape_rejects_out_of_session_frontiers_and_availability_regressions() -> None:
    outside = market_batch(SESSION_CLOSE + timedelta(minutes=1))
    repository, _ = authorization(intent())
    with pytest.raises(SimulatedBrokerError, match="outside the configured session"):
        ConservativeSimulatedBroker(
            risk_authorizations=repository,
            model=market_model(),
            session=simulated_session(),
            market_batches=(outside,),
        )

    later_frontier = market_batch(
        datetime(2026, 7, 15, 13, 34, tzinfo=UTC),
        closed_at=datetime(2026, 7, 15, 13, 34, 1, tzinfo=UTC),
    )
    delayed_older_frontier = market_batch(
        datetime(2026, 7, 15, 13, 33, tzinfo=UTC),
        closed_at=datetime(2026, 7, 15, 13, 35, tzinfo=UTC),
    )
    with pytest.raises(SimulatedBrokerFactConflict, match="frontier regresses"):
        ConservativeSimulatedBroker(
            risk_authorizations=repository,
            model=market_model(),
            session=simulated_session(),
            market_batches=(delayed_older_frontier, later_frontier),
        )


@pytest.mark.parametrize(
    ("bad_batch", "message"),
    [
        (
            market_batch(
                datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
                instrument_id="US-ETF-QQQ",
                symbol="QQQ",
            ),
            "does not expect the submitted instrument",
        ),
        (
            market_batch(
                datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
                symbol="QQQ",
            ),
            "symbol conflicts",
        ),
    ],
)
def test_wrong_tape_instrument_or_symbol_fails_before_consuming_approval(
    bad_batch: MarketBatch,
    message: str,
) -> None:
    submitted_intent = intent()
    repository, decision_id = authorization(submitted_intent)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=repository,
        model=market_model(),
        session=simulated_session(),
        market_batches=(bad_batch,),
    )

    with pytest.raises(SimulatedBrokerError, match=message):
        broker.submit(submitted_intent, decision_id, "bad-tape-attempt")

    assert not repository.was_consumed(decision_id)


def test_intent_and_session_must_share_explicit_regular_session_evidence() -> None:
    source_batch = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))
    early_close = datetime(2026, 7, 15, 17, 0, tzinfo=UTC)
    half_day = submit(
        batches=(source_batch,),
        session=simulated_session(closes_at=early_close, kind=SessionKind.HALF_DAY),
    )
    assert half_day.order_state.status is CanonicalOrderStatus.FILLED

    later_open = datetime(2026, 7, 15, 13, 31, 30, tzinfo=UTC)
    submitted_intent = intent()
    repository, decision_id = authorization(submitted_intent)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=repository,
        model=market_model(),
        session=simulated_session(opens_at=later_open),
        market_batches=(source_batch,),
    )

    with pytest.raises(SimulatedBrokerError, match="intent creation is outside"):
        broker.submit(submitted_intent, decision_id, "wrong-session-attempt")
    assert not repository.was_consumed(decision_id)


def test_approval_window_must_guarantee_pre_close_activation_before_consumption() -> None:
    submitted_intent = intent()
    repository, decision_id = authorization(submitted_intent)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=repository,
        model=market_model(activation_latency=timedelta(seconds=1)),
        session=simulated_session(closes_at=datetime(2026, 7, 15, 13, 31, 31, tzinfo=UTC)),
        market_batches=(),
    )

    with pytest.raises(SimulatedBrokerError, match="cannot guarantee activation"):
        broker.submit(submitted_intent, decision_id, "unsafe-window-attempt")

    assert not repository.was_consumed(decision_id)


def test_adverse_buy_and_sell_prices_and_fees_are_explicit() -> None:
    model = market_model()

    buy = model.execution_terms(
        side=Side.BUY,
        quantity=Decimal("10"),
        reference_price=Decimal("100"),
    )
    sell = model.execution_terms(
        side=Side.SELL,
        quantity=Decimal("10"),
        reference_price=Decimal("100"),
    )

    assert buy.execution_price == Decimal("100.07")
    assert sell.execution_price == Decimal("99.93")
    assert buy.variable_fee == sell.variable_fee == Decimal("0.10")
    assert buy.total_fee == sell.total_fee == Decimal("0.60")
    with pytest.raises(SimulatedBrokerError, match="non-positive price"):
        model.execution_terms(
            side=Side.SELL,
            quantity=Decimal("1"),
            reference_price=Decimal("0.07"),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"model_id": " untrimmed"},
        {"activation_latency": timedelta(microseconds=-1)},
        {"half_spread_per_share": Decimal("-0.01")},
        {"slippage_per_share": Decimal("NaN")},
        {"fixed_fee": Decimal("0.00000000001")},
        {"currency": "usd"},
    ],
)
def test_invalid_market_model_values_are_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(SimulatedBrokerError):
        market_model(**changes)


def test_tape_permutations_and_exact_duplicates_are_canonical() -> None:
    old = market_batch(datetime(2026, 7, 15, 13, 31, tzinfo=UTC))
    first_later = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))
    later = market_batch(datetime(2026, 7, 15, 13, 33, tzinfo=UTC))
    expected = None

    for ordering in permutations((old, first_later, later)):
        result = submit(batches=(*ordering, first_later))
        if expected is None:
            expected = result
        else:
            assert result == expected
            assert result.semantic_sha256 == expected.semantic_sha256
            assert result.result_id == expected.result_id

    assert expected is not None
    assert expected.market_batches == (old, first_later, later)


def test_conflicting_batches_at_the_same_frontier_fail_closed() -> None:
    event_time = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)
    first = market_batch(event_time, close_price=Decimal("100"), event_id="first")
    conflicting = market_batch(
        event_time,
        close_price=Decimal("101"),
        event_id="conflicting",
    )
    repository, _ = authorization(intent())

    with pytest.raises(SimulatedBrokerFactConflict, match="conflicting slices"):
        ConservativeSimulatedBroker(
            risk_authorizations=repository,
            model=market_model(),
            session=simulated_session(),
            market_batches=(conflicting, first),
        )


@pytest.mark.parametrize(
    "batches",
    [
        (
            market_batch(
                datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
                watermark_id="reused-watermark",
            ),
            market_batch(
                datetime(2026, 7, 15, 13, 33, tzinfo=UTC),
                watermark_id="reused-watermark",
            ),
        ),
        (
            market_batch(
                datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
                event_id="first-observation-event",
                observation_id="reused-observation",
            ),
            market_batch(
                datetime(2026, 7, 15, 13, 33, tzinfo=UTC),
                event_id="second-observation-event",
                observation_id="reused-observation",
            ),
        ),
    ],
)
def test_tape_rejects_cross_batch_identity_stitching(
    batches: tuple[MarketBatch, MarketBatch],
) -> None:
    repository, _ = authorization(intent())

    with pytest.raises(SimulatedBrokerFactConflict, match="identity"):
        ConservativeSimulatedBroker(
            risk_authorizations=repository,
            model=market_model(),
            session=simulated_session(),
            market_batches=batches,
        )


def test_source_and_model_changes_alter_evidence_and_result_identity() -> None:
    event_time = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)
    original_batch = market_batch(event_time, close_price=Decimal("101"))
    revised_source = market_batch(
        event_time,
        close_price=Decimal("102"),
        event_id="different-source-fact",
    )
    original = submit(batches=(original_batch,))
    source_changed = submit(batches=(revised_source,))
    model_changed = submit(
        batches=(original_batch,),
        model=market_model(slippage_per_share=Decimal("0.03")),
    )

    assert original.fill_evidence is not None
    assert source_changed.fill_evidence is not None
    assert model_changed.fill_evidence is not None
    assert (
        original.fill_evidence.source_event_sha256
        != source_changed.fill_evidence.source_event_sha256
    )
    assert original.fill_evidence.model_sha256 != model_changed.fill_evidence.model_sha256
    assert len({original.result_id, source_changed.result_id, model_changed.result_id}) == 3


def test_simulation_is_independent_of_ambient_decimal_context() -> None:
    submitted_intent = intent()
    source_batch = market_batch(
        datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        close_price=Decimal("101.1234567890"),
    )
    model = market_model(
        half_spread_per_share=Decimal("0.0000000004"),
        slippage_per_share=Decimal("0.0000000005"),
        fixed_fee=Decimal("0.0000000001"),
        fee_per_share=Decimal("0.0000000007"),
    )

    def simulate(precision: int) -> SimulatedBrokerResult:
        repository, decision_id = authorization(submitted_intent)
        broker = ConservativeSimulatedBroker(
            risk_authorizations=repository,
            model=model,
            session=simulated_session(),
            market_batches=(source_batch,),
        )
        with localcontext() as context:
            context.prec = precision
            return broker.submit(
                submitted_intent,
                decision_id,
                "decimal-context-attempt",
            )

    low_precision = simulate(4)
    high_precision = simulate(40)

    assert low_precision == high_precision
    assert low_precision.fill_evidence is not None
    assert low_precision.fill_evidence.terms.execution_price == Decimal("101.1234567899")
    assert low_precision.fill_evidence.terms.total_fee == Decimal("0.0000000071")


def test_missing_reused_and_payload_mismatched_approvals_are_rejected() -> None:
    submitted_intent = intent()
    source_batch = market_batch(datetime(2026, 7, 15, 13, 32, tzinfo=UTC))
    repository, decision_id = authorization(submitted_intent)
    broker = ConservativeSimulatedBroker(
        risk_authorizations=repository,
        model=market_model(),
        session=simulated_session(),
        market_batches=(source_batch,),
    )

    with pytest.raises(RiskAuthorizationError, match="persisted"):
        broker.submit(submitted_intent, "missing-decision", "missing-attempt")

    broker.submit(submitted_intent, decision_id, "first-attempt")
    with pytest.raises(RiskAuthorizationError, match="already been consumed"):
        broker.submit(submitted_intent, decision_id, "reused-attempt")

    second_repository, second_decision_id = authorization(submitted_intent)
    second_broker = ConservativeSimulatedBroker(
        risk_authorizations=second_repository,
        model=market_model(),
        session=simulated_session(),
        market_batches=(source_batch,),
    )
    with pytest.raises(RiskAuthorizationError, match="payload"):
        second_broker.submit(
            replace(submitted_intent, quantity=Decimal("11")),
            second_decision_id,
            "mismatched-attempt",
        )
