from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

from packages.backtest.simulated_broker import (
    ConservativeSimulatedBroker,
    SimulatedBrokerResult,
    SimulatedBrokerSession,
    SimulatedMarketOrderModel,
    SimulatedRiskExecutionCaps,
)
from packages.backtest.simulation_horizon import (
    SimulationHorizonConflict,
    SimulationHorizonError,
    SimulationHorizonFact,
    create_conservative_simulation_request,
    create_simulation_horizon_fact,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    _account_fence_receipt,
)
from packages.domain.batch_risk import (
    BATCH_RISK_RULES,
    BatchRiskAuthorization,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    BatchRiskReservation,
    BatchRiskSession,
    BatchRiskSessionKind,
    initial_active_capacity_universe,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.market_batch import MarketWatermark
from packages.domain.models import DecisionStatus, MarketEvent, OrderIntent, RiskRuleResult, Side
from packages.domain.replay import ReplayResult, replay_market_events
from packages.domain.replay_manifest import (
    DatasetPartitionPin,
    DatasetPin,
    EnginePin,
    ReplayPlanPin,
    ReplayRunManifest,
    RuntimePin,
)
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    BrokerSubmissionRequest,
    CanonicalSubmissionAttempt,
    UnknownSubmissionResolution,
    confirm_submission,
    create_broker_submission_request,
    mark_submission_in_flight,
    mark_submission_unknown,
    prepare_submission_attempt,
    resolve_unknown_submission,
)
from packages.domain.walking_thread import WalkingThread
from packages.market_data.calendar import ExchangeSession, SessionKind

SESSION_OPEN = datetime(2026, 7, 15, 13, 30, tzinfo=UTC)
SESSION_CLOSE = datetime(2026, 7, 15, 20, 0, tzinfo=UTC)
EVALUATED_AT = datetime(2026, 7, 15, 13, 31, 1, tzinfo=UTC)
PREPARED_AT = EVALUATED_AT + timedelta(milliseconds=200)
DISPATCHED_AT = EVALUATED_AT + timedelta(milliseconds=500)
SUBMITTED_AT = EVALUATED_AT + timedelta(seconds=1)
EVENT_TIME = datetime(2026, 7, 15, 13, 32, tzinfo=UTC)
CLOSED_AT = EVENT_TIME + timedelta(seconds=5)
ACCOUNT_ID = "simulation-horizon-account"


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _intent() -> OrderIntent:
    return WalkingThread.run().intent


def _session(
    manifest: ReplayRunManifest,
    *,
    calendar_version: str | None = None,
) -> SimulatedBrokerSession:
    return SimulatedBrokerSession(
        calendar_id="xnys-horizon-calendar",
        calendar_version=(
            manifest.dataset.calendar_version if calendar_version is None else calendar_version
        ),
        calendar_sha256=manifest.dataset.calendar_sha256,
        session=ExchangeSession(
            venue="XNYS",
            session_label=date(2026, 7, 15),
            opens_at=SESSION_OPEN,
            closes_at=SESSION_CLOSE,
            kind=SessionKind.REGULAR,
        ),
    )


def _model() -> SimulatedMarketOrderModel:
    return SimulatedMarketOrderModel(
        model_id="horizon-market-order",
        model_version="1.0.0",
        activation_latency=timedelta(0),
        half_spread_per_share=Decimal("0.05"),
        slippage_per_share=Decimal("0.02"),
        fixed_fee=Decimal("0.50"),
        fee_per_share=Decimal("0.01"),
        currency="USD",
    )


def _risk_session_sha256(session: SimulatedBrokerSession) -> str:
    return BatchRiskSession(
        calendar_id=session.calendar_id,
        calendar_version=session.calendar_version,
        calendar_sha256=session.calendar_sha256,
        venue=session.session.venue,
        session_label=session.session.session_label,
        opens_at=session.session.opens_at,
        closes_at=session.session.closes_at,
        kind=BatchRiskSessionKind(session.session.kind.value),
    ).semantic_sha256


def _decision(
    intent: OrderIntent,
    session: SimulatedBrokerSession,
) -> BatchRiskDecision:
    intent_batch_sha256 = "b" * 64
    snapshot_sha256 = "c" * 64
    policy_sha256 = "d" * 64
    active_capacity_sha256 = initial_active_capacity_universe(ACCOUNT_ID).semantic_sha256
    decision_id = canonical_id(
        "batch-risk-decision",
        intent.intent_batch_id,
        intent_batch_sha256,
        snapshot_sha256,
        active_capacity_sha256,
        policy_sha256,
        EVALUATED_AT,
    )
    reservation_id = canonical_id("batch-risk-reservation", decision_id)
    maximum_execution_price = Decimal("102")
    maximum_fee = Decimal("1")
    buy_exposure = intent.quantity * maximum_execution_price
    maximum_cash = buy_exposure + maximum_fee
    authorization = BatchRiskAuthorization(
        decision_id=canonical_id(
            "batch-risk-authorization",
            decision_id,
            intent.intent_id,
        ),
        parent_decision_id=decision_id,
        reservation_id=reservation_id,
        intent_batch_id=intent.intent_batch_id,
        intent_batch_sha256=intent_batch_sha256,
        snapshot_sha256=snapshot_sha256,
        policy_sha256=policy_sha256,
        session_sha256=_risk_session_sha256(session),
        currency="USD",
        intent_id=intent.intent_id,
        intent_payload_hash=intent_payload_hash(intent),
        status=DecisionStatus.APPROVED,
        evaluated_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(seconds=30),
        instrument_id=intent.instrument_id,
        symbol=intent.symbol,
        side=intent.side,
        quantity=intent.quantity,
        reference_price=intent.reference_price,
        snapshot_as_of=intent.created_at,
        reference_event_time=intent.decision_event_time,
        maximum_execution_price=maximum_execution_price,
        maximum_fee=maximum_fee,
        maximum_cash_requirement=maximum_cash,
        reserved_cash=maximum_cash,
        reserved_sell_quantity=(intent.quantity if intent.side is Side.SELL else Decimal(0)),
        reserved_buy_exposure=buy_exposure,
    )
    reservation = BatchRiskReservation(
        reservation_id=reservation_id,
        parent_decision_id=decision_id,
        intent_batch_id=intent.intent_batch_id,
        intent_batch_sha256=intent_batch_sha256,
        snapshot_sha256=snapshot_sha256,
        policy_sha256=policy_sha256,
        currency="USD",
        authorizations=(authorization,),
        reserved_cash=authorization.reserved_cash,
        reserved_buy_exposure=authorization.reserved_buy_exposure,
    )
    rules = tuple(
        RiskRuleResult(
            rule=rule,
            passed=True,
            observed="horizon-fixture",
            limit="horizon-fixture",
        )
        for rule in BATCH_RISK_RULES
    )
    return BatchRiskDecision(
        decision_id=decision_id,
        intent_batch_id=intent.intent_batch_id,
        intent_batch_sha256=intent_batch_sha256,
        account_id=ACCOUNT_ID,
        snapshot_version="horizon-snapshot-v1",
        snapshot_sha256=snapshot_sha256,
        active_capacity_sha256=active_capacity_sha256,
        policy_id="horizon-risk-policy",
        policy_version="1.0.0",
        policy_sha256=policy_sha256,
        currency="USD",
        status=BatchRiskDecisionStatus.APPROVED,
        evaluated_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(seconds=30),
        intent_count=1,
        rules=rules,
        reservation=reservation,
        authorizations=(authorization,),
    )


def _receipt(*, validated_at: datetime) -> AccountFenceReceipt:
    lease = AccountLease(
        account_id=ACCOUNT_ID,
        owner_id="horizon-worker",
        lease_id="horizon-lease",
        fencing_generation=1,
        acquired_at=SESSION_OPEN,
        heartbeat_at=EVALUATED_AT,
        expires_at=EVALUATED_AT + timedelta(minutes=5),
        policy_sha256="e" * 64,
    )
    return _account_fence_receipt(
        fence=AccountFence(
            account_id=lease.account_id,
            owner_id=lease.owner_id,
            lease_id=lease.lease_id,
            fencing_generation=lease.fencing_generation,
        ),
        validated_at=validated_at,
        valid_until=lease.expires_at,
        policy_sha256=lease.policy_sha256,
        lease_sha256=lease.semantic_sha256,
    )


def _in_flight_attempt(
    intent: OrderIntent,
    decision: BatchRiskDecision,
    *,
    request: BrokerSubmissionRequest,
) -> CanonicalSubmissionAttempt:
    pending = prepare_submission_attempt(
        intent=intent,
        risk_decision=decision,
        fence_receipt=_receipt(validated_at=PREPARED_AT),
        request=request,
        prepared_at=PREPARED_AT,
        recorded_at=PREPARED_AT,
        parent_attempts=(),
    )
    return mark_submission_in_flight(
        pending,
        dispatch_fence_receipt=_receipt(validated_at=DISPATCHED_AT),
        occurred_at=DISPATCHED_AT,
        recorded_at=DISPATCHED_AT,
    )


def _replay(*, close_price: Decimal = Decimal("101")) -> ReplayResult:
    event = MarketEvent(
        event_id=f"horizon-event-{close_price}",
        instrument_id=WalkingThread.instrument_id,
        symbol=WalkingThread.symbol,
        event_time=EVENT_TIME,
        available_at=CLOSED_AT,
        close_price=close_price,
        source="horizon-recorded-fixture",
        source_sequence=1,
        observation_id="horizon-observation",
    )
    watermark = MarketWatermark(
        watermark_id="horizon-watermark",
        event_time_through=EVENT_TIME,
        closed_at=CLOSED_AT,
        expected_instrument_ids=(WalkingThread.instrument_id,),
    )
    return replay_market_events(events=(event,), watermarks=(watermark,))


def _incomplete_replay() -> ReplayResult:
    watermark = MarketWatermark(
        watermark_id="horizon-incomplete-watermark",
        event_time_through=EVENT_TIME,
        closed_at=CLOSED_AT,
        expected_instrument_ids=(WalkingThread.instrument_id,),
    )
    return replay_market_events(events=(), watermarks=(watermark,))


def _watermarks_sha256(replay: ReplayResult) -> str:
    return _sha256(
        tuple(
            (
                batch.watermark.watermark_id,
                batch.watermark.event_time_through,
                batch.watermark.closed_at,
                batch.watermark.expected_instrument_ids,
                batch.watermark.revision_policy,
                batch.watermark.missing_data_policy,
                batch.watermark.late_event_policy,
            )
            for batch in replay.batches
        )
    )


def _manifest(
    replay: ReplayResult,
    *,
    source_revision: str = "9" * 40,
) -> ReplayRunManifest:
    event_count = len(replay.processed_event_ids)
    dataset = DatasetPin(
        manifest_id="1" * 64,
        manifest_sha256="1" * 64,
        source_tape_sha256="2" * 64,
        source_id="horizon-recorded-fixture",
        source_kind="recorded_fixture",
        schema_version="raw-bar-v1",
        price_basis="raw",
        revision_policy=replay.batches[0].watermark.revision_policy,
        calendar_version="xnys-horizon-v1",
        calendar_sha256="3" * 64,
        calendar_hash_version="input-v1",
        tzdata_version="2026a",
        universe_version="horizon-universe-v1",
        universe_sha256="4" * 64,
        universe_hash_version="input-v1",
        corporate_action_version="horizon-actions-v1",
        corporate_action_sha256="5" * 64,
        corporate_action_hash_version="input-v1",
        row_count=max(event_count, 1),
        partitions=(
            DatasetPartitionPin(
                ordinal=0,
                partition_id="6" * 64,
                object_id="7" * 64,
                object_key=f"normalized/sha256/77/{'7' * 64}.parquet",
                format="parquet",
                byte_sha256="7" * 64,
                semantic_sha256="8" * 64,
                semantic_checksum_version="input-v1",
                size_bytes=1024,
                row_count=max(event_count, 1),
                event_time_start=EVENT_TIME,
                event_time_end=EVENT_TIME,
                available_at_start=CLOSED_AT,
                available_at_end=CLOSED_AT,
            ),
        ),
    )
    watermark = replay.batches[0].watermark
    plan = ReplayPlanPin(
        coverage_start=replay.batches[0].watermark.event_time_through,
        coverage_end=replay.batches[-1].watermark.event_time_through,
        interval="1m",
        decision_lag=watermark.closed_at - watermark.event_time_through,
        revision_policy=watermark.revision_policy,
        missing_data_policy=watermark.missing_data_policy,
        late_event_policy=watermark.late_event_policy,
        expected_instrument_ids=tuple(
            sorted(
                {
                    instrument_id
                    for batch in replay.batches
                    for instrument_id in batch.watermark.expected_instrument_ids
                }
            )
        ),
        watermark_count=len(replay.batches),
        watermarks_sha256=_watermarks_sha256(replay),
    )
    return ReplayRunManifest.from_replay_result(
        dataset=dataset,
        plan=plan,
        engine=EnginePin(
            tape_adapter_version="horizon-raw-bar-tape-v1",
            watermark_policy_version="horizon-watermark-v1",
        ),
        runtime=RuntimePin(
            source_revision=source_revision,
            dirty_patch_sha256="a" * 64,
            dependency_lock_sha256="b" * 64,
            schema_revision="simulation-horizon-fixture",
            python_version="3.12.10",
            pyarrow_version="21.0.0",
        ),
        result=replay,
        source_tape_sha256=dataset.source_tape_sha256,
    )


@dataclass(slots=True)
class _AuthorizationConsumer:
    authorization: BatchRiskAuthorization
    consumed: bool = False

    def get(self, decision_id: str) -> BatchRiskAuthorization | None:
        return self.authorization if decision_id == self.authorization.decision_id else None

    def consume(self, decision_id: str, submitted_intent: OrderIntent) -> datetime:
        if (
            self.consumed
            or decision_id != self.authorization.decision_id
            or submitted_intent.intent_id != self.authorization.intent_id
            or intent_payload_hash(submitted_intent) != self.authorization.intent_payload_hash
        ):
            raise ValueError("fixture authorization consumption is invalid")
        self.consumed = True
        return SUBMITTED_AT


@dataclass(frozen=True, slots=True)
class _Proofs:
    result: SimulatedBrokerResult
    replay: ReplayResult
    manifest: ReplayRunManifest
    reservation: BatchRiskReservation
    authorization: BatchRiskAuthorization
    in_flight: CanonicalSubmissionAttempt
    confirmed: CanonicalSubmissionAttempt


def _proofs(
    *,
    adapter_id: str = "conservative-simulated-broker",
    adapter_version: str = "1.0.0",
    operation: str = "submit_order",
    payload: dict[str, object] | None = None,
    result_model: SimulatedMarketOrderModel | None = None,
    session_calendar_version: str | None = None,
) -> _Proofs:
    intent = _intent()
    replay = _replay()
    manifest = _manifest(replay)
    session = _session(
        manifest,
        calendar_version=session_calendar_version,
    )
    committed_model = _model()
    decision = _decision(intent, session)
    assert decision.reservation is not None
    authorization = decision.authorizations[0]
    canonical_request = create_conservative_simulation_request(
        intent=intent,
        manifest=manifest,
        session=session,
        model=committed_model,
    )
    request = canonical_request
    if (
        adapter_id != canonical_request.adapter_id
        or adapter_version != canonical_request.adapter_version
        or operation != canonical_request.operation
        or payload is not None
    ):
        request = create_broker_submission_request(
            intent=intent,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            operation=operation,
            payload=dict(canonical_request.payload) if payload is None else payload,
        )
    in_flight = _in_flight_attempt(
        intent,
        decision,
        request=request,
    )
    consumer = _AuthorizationConsumer(authorization)
    result = ConservativeSimulatedBroker(
        risk_authorizations=consumer,
        model=committed_model if result_model is None else result_model,
        session=session,
        market_batches=replay.batches,
    ).submit(
        intent,
        authorization.decision_id,
        in_flight.attempt_id,
    )
    confirmed = confirm_submission(
        in_flight,
        occurred_at=result.completed_at,
        recorded_at=result.completed_at,
        response_sha256=result.semantic_sha256,
        broker_order_id=result.broker_events[0].broker_order_id,
    )
    return _Proofs(
        result=result,
        replay=replay,
        manifest=manifest,
        reservation=decision.reservation,
        authorization=authorization,
        in_flight=in_flight,
        confirmed=confirmed,
    )


def _create(proofs: _Proofs) -> SimulationHorizonFact:
    return create_simulation_horizon_fact(
        result=proofs.result,
        replay=proofs.replay,
        manifest=proofs.manifest,
        reservation=proofs.reservation,
        authorization=proofs.authorization,
        attempt=proofs.confirmed,
    )


def test_factory_derives_one_deterministic_release_ready_horizon() -> None:
    proofs = _proofs()
    first = _create(proofs)
    second = _create(proofs)
    final_event = proofs.result.broker_events[-1]

    assert first == second
    assert first.horizon_at == max(
        proofs.replay.completed_at,
        proofs.result.completed_at,
        proofs.confirmed.as_of,
        proofs.result.order_state.as_of,
    )
    assert first.replay_run_id == proofs.manifest.run_id
    assert first.replay_semantic_sha256 == proofs.replay.semantic_sha256
    assert first.simulation_result_sha256 == proofs.result.semantic_sha256
    assert first.reservation_sha256 == proofs.reservation.semantic_sha256
    assert first.authorization_sha256 == proofs.authorization.semantic_sha256
    assert first.attempt_sha256 == proofs.confirmed.semantic_sha256
    assert first.final_order_event_sha256 == final_event.semantic_sha256
    assert first.final_batch_sha256 == proofs.replay.batches[-1].semantic_sha256
    assert first.horizon_source_sha256 not in {
        proofs.confirmed.semantic_sha256,
        proofs.result.order_state.semantic_sha256,
        final_event.semantic_sha256,
    }
    first._validate()
    with pytest.raises(TypeError, match="proof factory"):
        SimulationHorizonFact()
    with pytest.raises(FrozenInstanceError):
        first.horizon_at = CLOSED_AT  # type: ignore[misc]


def test_factory_requires_manifest_to_exactly_reproduce_replay() -> None:
    proofs = _proofs()
    forged_manifest = replace(
        proofs.manifest,
        replay_semantic_sha256="0" * 64,
    )

    with pytest.raises(SimulationHorizonConflict, match="exactly bind"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=proofs.replay,
            manifest=forged_manifest,
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=proofs.confirmed,
        )


def test_factory_requires_simulation_batches_to_equal_complete_replay() -> None:
    proofs = _proofs()
    different_replay = _replay(close_price=Decimal("100"))

    with pytest.raises(SimulationHorizonConflict, match="must equal"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=different_replay,
            manifest=_manifest(different_replay),
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=proofs.confirmed,
        )

    incomplete = _incomplete_replay()
    with pytest.raises(SimulationHorizonError, match=r"every replay batch.*complete"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=incomplete,
            manifest=_manifest(incomplete),
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=proofs.confirmed,
        )


def test_factory_authenticates_plan_coverage_and_watermark_digest() -> None:
    proofs = _proofs()
    forged_plan = replace(
        proofs.manifest.plan,
        watermarks_sha256="0" * 64,
    )
    forged_manifest = replace(proofs.manifest, plan=forged_plan)

    with pytest.raises(SimulationHorizonConflict, match="watermark digest"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=proofs.replay,
            manifest=forged_manifest,
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=proofs.confirmed,
        )


def test_factory_requires_simulator_session_to_match_manifest_calendar() -> None:
    proofs = _proofs(session_calendar_version="forged-calendar-version")

    with pytest.raises(
        SimulationHorizonConflict,
        match="pinned calendar",
    ):
        _create(proofs)


def test_factory_rejects_unaccepted_attempt_and_non_authorized_caps() -> None:
    proofs = _proofs()
    with pytest.raises(SimulationHorizonError, match="known accepted"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=proofs.replay,
            manifest=proofs.manifest,
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=proofs.in_flight,
        )

    unrelated_confirmation = confirm_submission(
        proofs.in_flight,
        occurred_at=proofs.result.completed_at,
        recorded_at=proofs.result.completed_at,
        response_sha256="0" * 64,
        broker_order_id=proofs.result.broker_events[0].broker_order_id,
    )
    with pytest.raises(SimulationHorizonConflict, match="response does not bind"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=proofs.replay,
            manifest=proofs.manifest,
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=unrelated_confirmation,
        )

    caps = proofs.result.risk_execution_caps
    assert caps is not None
    forged_caps = SimulatedRiskExecutionCaps(
        authorization_decision_id=caps.authorization_decision_id,
        session_sha256=caps.session_sha256,
        currency=caps.currency,
        maximum_execution_price=Decimal("103"),
        maximum_cash_requirement=Decimal("1031"),
    )
    forged_result = replace(proofs.result, risk_execution_caps=forged_caps)
    with pytest.raises(SimulationHorizonConflict, match="authorization caps"):
        create_simulation_horizon_fact(
            result=forged_result,
            replay=proofs.replay,
            manifest=proofs.manifest,
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=proofs.confirmed,
        )


def test_factory_requires_exact_conservative_simulator_request() -> None:
    mismatched_proofs = (
        _proofs(adapter_id="paper-live-broker"),
        _proofs(adapter_version="99.0.0"),
        _proofs(operation="transmit_live_order"),
        _proofs(payload={"opaque": "not-the-simulated-request"}),
    )

    for proofs in mismatched_proofs:
        with pytest.raises(
            SimulationHorizonConflict,
            match="exact conservative simulator request",
        ):
            _create(proofs)


def test_factory_rejects_model_or_manifest_swap_after_dispatch() -> None:
    alternate_model = replace(
        _model(),
        model_version="1.0.1",
        fixed_fee=Decimal("0.60"),
    )
    model_swap = _proofs(result_model=alternate_model)
    with pytest.raises(
        SimulationHorizonConflict,
        match="exact conservative simulator request",
    ):
        _create(model_swap)

    manifest_swap = _proofs()
    alternate_manifest = _manifest(
        manifest_swap.replay,
        source_revision="0" * 40,
    )
    assert alternate_manifest != manifest_swap.manifest
    assert alternate_manifest.replay_semantic_sha256 == manifest_swap.replay.semantic_sha256
    with pytest.raises(
        SimulationHorizonConflict,
        match="exact conservative simulator request",
    ):
        create_simulation_horizon_fact(
            result=manifest_swap.result,
            replay=manifest_swap.replay,
            manifest=alternate_manifest,
            reservation=manifest_swap.reservation,
            authorization=manifest_swap.authorization,
            attempt=manifest_swap.confirmed,
        )


def test_factory_rejects_unauthenticated_unknown_resolution() -> None:
    proofs = _proofs()
    unknown = mark_submission_unknown(
        proofs.in_flight,
        occurred_at=proofs.result.completed_at,
        recorded_at=proofs.result.completed_at,
        error_class="TimeoutError",
    )
    resolved_at = proofs.result.completed_at + timedelta(microseconds=1)
    resolved = resolve_unknown_submission(
        unknown,
        occurred_at=resolved_at,
        recorded_at=resolved_at,
        resolution=UnknownSubmissionResolution.BROKER_ACCEPTED,
        reconciliation_sha256="f" * 64,
        response_sha256=proofs.result.semantic_sha256,
        broker_order_id=proofs.result.broker_events[0].broker_order_id,
    )

    with pytest.raises(SimulationHorizonError, match="confirmed known accepted"):
        create_simulation_horizon_fact(
            result=proofs.result,
            replay=proofs.replay,
            manifest=proofs.manifest,
            reservation=proofs.reservation,
            authorization=proofs.authorization,
            attempt=resolved,
        )


def test_fact_validation_detects_persisted_cross_binding_corruption() -> None:
    fact = _create(_proofs())
    object.__setattr__(fact, "final_order_event_sha256", "0" * 64)

    with pytest.raises(SimulationHorizonConflict, match="source digest"):
        fact._validate()
