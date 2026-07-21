from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa

from packages.adapters.market_data.reference_fixture import (
    SPY_SECURITY_ID,
)
from packages.adapters.market_data.reference_fixture import (
    calendar as reference_calendar,
)
from packages.application.manifest_replay import execute_and_seal_manifest_replay
from packages.application.market_data_ingestion import ingest_recorded_fixture
from packages.backtest.simulated_broker import (
    ConservativeSimulatedBroker,
    SimulatedBrokerResult,
    SimulatedBrokerSession,
    SimulatedMarketOrderModel,
)
from packages.backtest.simulation_horizon import create_conservative_simulation_request
from packages.datasets import (
    LocalParquetObjectStore,
    ManifestReplayTape,
    ManifestReplayTapeReader,
)
from packages.domain.account_coordinator import AccountLeaseOwnershipLost, AccountLeasePolicy
from packages.domain.batch_risk import (
    BatchRiskAuthority,
    BatchRiskAuthorization,
    BatchRiskSession,
    BatchRiskSessionKind,
)
from packages.domain.clock import ClockEvent
from packages.domain.decision import DecisionTrigger
from packages.domain.ledger_reducer import CanonicalLedgerEntry, reduce_execution_ledger
from packages.domain.models import (
    MarketEvent,
    OrderIntent,
    PositionTarget,
    Side,
    TargetPortfolio,
)
from packages.domain.order_reducer import (
    BrokerOrderEvent,
    BrokerOrderEventKind,
    reduce_order_lifecycle,
)
from packages.domain.portfolio import portfolio_snapshot, target_to_intent_batch
from packages.domain.replay import ReplayResult
from packages.domain.replay_manifest import ReplayRunManifest
from packages.domain.reservation_lifecycle import (
    ReservationCapacityState,
    ReservationReleaseReason,
)
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
)
from packages.market_data import BarInterval
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.batch_risk import SqlBatchRiskRepository
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    _verify_phase2_durability_integrity,
    create_database_engine,
)
from packages.persistence.immutable import as_aware_utc
from packages.persistence.market_data import SqlMarketDataCatalog
from packages.persistence.replay import SqlReplayRunManifestRepository
from packages.persistence.reservation_lifecycle import (
    ReservationLifecycleFrozen,
    ReservationLifecyclePersistenceError,
    SqlReservationLifecycleRepository,
)
from packages.persistence.schema import (
    metadata,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_simulation_horizon_facts,
)
from packages.persistence.simulation_horizon import (
    SimulationHorizonPersistenceError,
    load_simulation_horizon_fact,
)
from packages.persistence.submission_attempt import SqlSubmissionAttemptRepository
from tests.integration.test_phase2_submission_attempt_persistence import (
    SnapshotTransactions,
    SubmissionSystem,
)
from tests.integration.test_replay_run_persistence import _runtime
from tests.unit.test_batch_risk import (
    AS_OF,
    EVALUATED_AT,
    MutableClock,
    limits,
    snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "market_data" / "phase1_bars.jsonl"
REPLAY_START = datetime(2026, 7, 15, 14, 31, tzinfo=UTC)
REPLAY_END = datetime(2026, 7, 15, 14, 33, tzinfo=UTC)
_SHIFTED_TIMESTAMP_FIELDS = (
    "interval_start",
    "interval_end",
    "vendor_published_at",
    "received_at",
    "available_at",
    "ingested_at",
)
_PRICE_FIELDS = ("open", "high", "low", "close")


@dataclass(slots=True)
class _AuthorizationConsumer:
    authorization: BatchRiskAuthorization
    submitted_at: datetime
    consumed: bool = False

    def get(self, decision_id: str) -> BatchRiskAuthorization | None:
        if decision_id == self.authorization.decision_id:
            return self.authorization
        return None

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        assert self.consumed is False
        assert decision_id == self.authorization.decision_id
        assert intent.intent_id == self.authorization.intent_id
        assert intent_payload_hash(intent) == self.authorization.intent_payload_hash
        self.consumed = True
        return self.submitted_at


@dataclass(frozen=True, slots=True)
class _Scenario:
    system: SubmissionSystem
    lifecycle: SqlReservationLifecycleRepository
    authorization: BatchRiskAuthorization
    attempt: CanonicalSubmissionAttempt
    tape: ManifestReplayTape
    replay: ReplayResult
    manifest: ReplayRunManifest
    result: SimulatedBrokerResult


def _horizon_system(
    engine: sa.Engine,
    *,
    lease_ttl: timedelta,
    session_evidence: BatchRiskSession,
) -> SubmissionSystem:
    price = MarketEvent(
        event_id="phase2-horizon-risk-price",
        instrument_id=SPY_SECURITY_ID,
        symbol="SPY",
        event_time=AS_OF - timedelta(minutes=1),
        available_at=AS_OF,
        close_price=Decimal("100"),
        source="phase2-horizon-risk-tape-v1",
        source_sequence=1,
        observation_id="phase2-horizon-risk-price-spy",
    )
    portfolio = portfolio_snapshot(
        as_of=AS_OF,
        current_positions={},
        price_events=(price,),
    )
    clock_event = ClockEvent(
        clock_event_id="clock-phase2-horizon-target",
        schedule_id="regular-session-v1",
        scheduled_at=AS_OF,
        sequence=0,
    )
    target = TargetPortfolio(
        target_id="phase2-horizon-target",
        strategy_id="phase2-horizon-strategy",
        strategy_version="1.0.0",
        strategy_configuration_sha256="a" * 64,
        decision_trigger=DecisionTrigger.from_clock_event(clock_event),
        as_of=AS_OF,
        expires_at=AS_OF + timedelta(minutes=10),
        targets=(
            PositionTarget(
                instrument_id=SPY_SECURITY_ID,
                symbol="SPY",
                quantity=Decimal("3"),
            ),
        ),
        full_snapshot=False,
    )
    batch = target_to_intent_batch(target, portfolio)
    capacity = snapshot(portfolio, session_evidence=session_evidence)
    coordinator_clock = MutableClock(EVALUATED_AT)
    authority = SqlAccountCoordinatorAuthority(
        engine=engine,
        policy=AccountLeasePolicy(
            policy_id="phase2-horizon-integration",
            policy_version="1.0.0",
            lease_ttl=lease_ttl,
            maximum_in_flight_duration=timedelta(seconds=5),
            takeover_safety_interval=timedelta(seconds=10),
        ),
        clock=coordinator_clock,
    )
    coordinator = SqlAccountCoordinator(
        account_id=capacity.account_id,
        authority=authority,
    )
    lease = coordinator.acquire("worker-a")
    risk = SqlBatchRiskRepository(
        engine=engine,
        authority=BatchRiskAuthority(
            limits=limits(allowed_instruments=frozenset({SPY_SECURITY_ID})),
            snapshots=SnapshotTransactions(capacity),
            evaluation_clock=MutableClock(EVALUATED_AT),
            consumption_clock=MutableClock(EVALUATED_AT + timedelta(seconds=1)),
        ),
        coordinator=coordinator,
    )
    decision = risk.authorize(batch, target, lease.fence)
    assert decision.reservation is not None
    return SubmissionSystem(
        engine=engine,
        coordinator=coordinator,
        coordinator_clock=coordinator_clock,
        lease=lease,
        decision=decision,
        intents=batch.intents,
        repository=SqlSubmissionAttemptRepository(
            engine=engine,
            coordinator=coordinator,
        ),
    )


def _shifted_fillable_fixture(tmp_path: Path) -> Path:
    shifted_path = tmp_path / "phase2-horizon-bars.jsonl"
    records: list[str] = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        assert isinstance(record, dict)
        for field_name in _SHIFTED_TIMESTAMP_FIELDS:
            raw = record[field_name]
            assert isinstance(raw, str)
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            record[field_name] = (
                (parsed + timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
            )
        for field_name in _PRICE_FIELDS:
            record[field_name] = f"{Decimal(str(record[field_name])) - Decimal('1'):.2f}"
        records.append(json.dumps(record, separators=(",", ":"), sort_keys=True))
    shifted_path.write_text("\n".join(records) + "\n", encoding="utf-8")
    return shifted_path


def _session(manifest: ReplayRunManifest) -> SimulatedBrokerSession:
    exchange_session = next(
        item
        for item in reference_calendar().sessions
        if item.session_label.isoformat() == "2026-07-15"
    )
    return SimulatedBrokerSession(
        calendar_id="XNYS",
        calendar_version=manifest.dataset.calendar_version,
        calendar_sha256=manifest.dataset.calendar_sha256,
        session=exchange_session,
    )


def _model(*, cap_blocked: bool) -> SimulatedMarketOrderModel:
    return SimulatedMarketOrderModel(
        model_id="phase2-horizon-integration-model",
        model_version="1.0.0",
        activation_latency=timedelta(0),
        half_spread_per_share=Decimal("2") if cap_blocked else Decimal("0.05"),
        slippage_per_share=Decimal("0.02"),
        fixed_fee=Decimal("0.25"),
        fee_per_share=Decimal("0.01"),
        currency="USD",
    )


def _scenario(
    tmp_path: Path,
    *,
    cap_blocked: bool = False,
    retry_after_abandonment: bool = False,
) -> _Scenario:
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path / 'phase2-horizon.sqlite'}")
    metadata.create_all(engine)
    lake = tmp_path / "lake"
    ingestion = ingest_recorded_fixture(
        engine=engine,
        data_lake_path=lake,
        source_path=_shifted_fillable_fixture(tmp_path),
    )
    assert ingestion.manifest_id is not None
    reader = ManifestReplayTapeReader(
        catalog=SqlMarketDataCatalog(engine),
        object_store=LocalParquetObjectStore(lake),
    )
    plan = reader.build_plan(
        manifest_id=ingestion.manifest_id,
        event_time_start=REPLAY_START,
        event_time_end=REPLAY_END,
        interval=BarInterval.ONE_MINUTE,
        decision_lag=timedelta(minutes=1),
    )
    tape = reader.read(plan)
    sealed = execute_and_seal_manifest_replay(
        tape=tape,
        runtime=_runtime(),
        repository=SqlReplayRunManifestRepository(
            engine,
            tape_reader=reader,
        ),
    )
    assert sealed.result.skipped_batch_ids == ()
    assert all(batch.complete for batch in sealed.result.batches)
    broker_session = _session(sealed.manifest)
    system = _horizon_system(
        engine,
        lease_ttl=timedelta(hours=2),
        session_evidence=BatchRiskSession(
            calendar_id=broker_session.calendar_id,
            calendar_version=broker_session.calendar_version,
            calendar_sha256=broker_session.calendar_sha256,
            venue=broker_session.session.venue,
            session_label=broker_session.session.session_label,
            opens_at=broker_session.session.opens_at,
            closes_at=broker_session.session.closes_at,
            kind=BatchRiskSessionKind(broker_session.session.kind.value),
        ),
    )
    intent = next(item for item in system.intents if item.side is Side.BUY)
    authorization = next(
        item for item in system.decision.authorizations if item.intent_id == intent.intent_id
    )

    first_prepared_at = EVALUATED_AT + timedelta(seconds=1)
    model = _model(cap_blocked=cap_blocked)
    request = create_conservative_simulation_request(
        intent=intent,
        manifest=sealed.manifest,
        session=broker_session,
        model=model,
    )
    system.coordinator_clock.instant = first_prepared_at
    pending = system.repository.prepare(
        intent=intent,
        risk_decision=system.decision,
        fence=system.lease.fence,
        request=request,
        prepared_at=first_prepared_at,
        recorded_at=first_prepared_at,
    )
    submitted_at = first_prepared_at
    if retry_after_abandonment:
        recovered_at = first_prepared_at + timedelta(seconds=1)
        abandoned = system.repository.recover_stale_pending(
            stale_before=first_prepared_at + timedelta(microseconds=1),
            recovered_at=recovered_at,
            recorded_at=recovered_at,
        )
        assert len(abandoned) == 1
        assert abandoned[0].state is SubmissionAttemptState.ABANDONED
        submitted_at = recovered_at + timedelta(seconds=1)
        system.coordinator_clock.instant = submitted_at
        pending = system.repository.prepare(
            intent=intent,
            risk_decision=system.decision,
            fence=system.lease.fence,
            request=request,
            prepared_at=submitted_at,
            recorded_at=submitted_at,
        )
    in_flight = system.repository.mark_in_flight(
        pending.attempt_id,
        fence=system.lease.fence,
        occurred_at=submitted_at,
        recorded_at=submitted_at,
    )
    result = ConservativeSimulatedBroker(
        risk_authorizations=_AuthorizationConsumer(
            authorization=authorization,
            submitted_at=submitted_at,
        ),
        model=model,
        session=broker_session,
        market_batches=sealed.result.batches,
    ).submit(
        intent,
        authorization.decision_id,
        in_flight.attempt_id,
    )
    confirmed = system.repository.confirm(
        in_flight.attempt_id,
        occurred_at=result.completed_at,
        recorded_at=result.completed_at,
        response_sha256=result.semantic_sha256,
        broker_order_id=result.broker_events[0].broker_order_id,
    )
    return _Scenario(
        system=system,
        lifecycle=SqlReservationLifecycleRepository(
            engine=system.engine,
            coordinator=system.coordinator,
        ),
        authorization=authorization,
        attempt=confirmed,
        tape=tape,
        replay=sealed.result,
        manifest=sealed.manifest,
        result=result,
    )


def _ledger_entry(scenario: _Scenario) -> CanonicalLedgerEntry:
    execution = next(
        event
        for event in scenario.result.broker_events
        if event.kind is BrokerOrderEventKind.EXECUTION
    )
    entries = tuple(
        entry
        for entry in reduce_execution_ledger(
            order_states=(scenario.result.order_state,),
            execution_currency=scenario.system.decision.currency,
        ).entries
        if entry.reference_id == execution.event_id
    )
    assert len(entries) == 1
    return entries[0]


def _account_execution(scenario: _Scenario) -> None:
    execution = next(
        event
        for event in scenario.result.broker_events
        if event.kind is BrokerOrderEventKind.EXECUTION
    )
    entry = _ledger_entry(scenario)
    scenario.system.coordinator_clock.instant = execution.received_at
    scenario.lifecycle.execution_accounted(
        reservation_id=scenario.attempt.preparation.reservation_id,
        authorization_id=scenario.authorization.decision_id,
        attempt_id=scenario.attempt.attempt_id,
        order_state=scenario.result.order_state,
        execution_event=execution,
        accounting_reference=entry.entry_id,
        accounting_source_sha256=entry.semantic_sha256,
        fence=scenario.system.lease.fence,
        accounted_at=execution.received_at,
        recorded_at=execution.received_at,
    )


def _release_horizon(scenario: _Scenario):  # type: ignore[no-untyped-def]
    if scenario.system.coordinator_clock.instant < scenario.result.completed_at:
        scenario.system.coordinator_clock.instant = scenario.result.completed_at
    return scenario.lifecycle.simulation_horizon_final(
        result=scenario.result,
        replay=scenario.replay,
        replay_events=scenario.tape.events,
        replay_watermarks=scenario.tape.plan.watermarks,
        replay_manifest=scenario.manifest,
        fence=scenario.system.lease.fence,
        recorded_at=scenario.result.completed_at,
    )


def test_accounted_fill_releases_only_residual_fee_and_is_readiness_safe(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)

    released = _release_horizon(scenario)

    assert released.inserted is True
    assert released.fact.reason is ReservationReleaseReason.SIMULATION_HORIZON_FINAL
    assert released.fact.released_cash == scenario.authorization.maximum_fee
    assert released.fact.released_buy_exposure == 0
    assert released.snapshot.persisted_state is ReservationCapacityState.RELEASED
    with scenario.system.engine.connect() as connection:
        horizon_row = (
            connection.execute(sa.select(phase2_simulation_horizon_facts)).mappings().one()
        )
        horizon = load_simulation_horizon_fact(
            connection,
            str(horizon_row["horizon_id"]),
        )
        assert horizon is not None
        assert horizon.simulation_result_sha256 == scenario.result.semantic_sha256
        assert horizon.attempt_response_sha256 == scenario.result.semantic_sha256
        assert as_aware_utc(horizon_row["recorded_at"]) == released.fact.recorded_at
        _verify_phase2_durability_integrity(connection)


def test_unaccounted_fill_cannot_release_or_leave_partial_horizon_rows(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path)

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="execution-head accounting coverage",
    ):
        _release_horizon(scenario)

    with scenario.system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_simulation_horizon_facts)
            )
            == 0
        )
        assert connection.scalar(sa.select(sa.func.count()).select_from(phase2_order_events)) == 0
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_reservation_release_events)
            )
            == 0
        )


def test_correction_frozen_head_cannot_publish_a_horizon_proof_or_release(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)
    execution = next(
        event
        for event in scenario.result.broker_events
        if event.kind is BrokerOrderEventKind.EXECUTION
    )
    assert execution.quantity is not None and execution.quantity > 1
    correction_at = scenario.result.completed_at
    correction = BrokerOrderEvent(
        event_id="phase2-horizon-downward-correction",
        order_id=execution.order_id,
        broker_order_id=execution.broker_order_id,
        broker_sequence=scenario.result.order_state.last_broker_sequence + 1,
        occurred_at=correction_at,
        received_at=correction_at,
        kind=BrokerOrderEventKind.EXECUTION_CORRECTION,
        execution_id=execution.execution_id,
        execution_revision=2,
        supersedes_event_id=execution.event_id,
        quantity=execution.quantity - 1,
        price=execution.price,
        fee=execution.fee,
    )
    corrected_state = reduce_order_lifecycle(
        submission=scenario.result.order_state.submission,
        broker_events=(*scenario.result.order_state.broker_events, correction),
    )
    correction_entries = tuple(
        entry
        for entry in reduce_execution_ledger(
            order_states=(corrected_state,),
            execution_currency=scenario.system.decision.currency,
        ).entries
        if entry.reference_id == correction.event_id
    )
    assert len(correction_entries) == 1
    scenario.system.coordinator_clock.instant = correction.received_at
    with pytest.raises(ReservationLifecycleFrozen, match="downward"):
        scenario.lifecycle.execution_accounted(
            reservation_id=scenario.attempt.preparation.reservation_id,
            authorization_id=scenario.authorization.decision_id,
            attempt_id=scenario.attempt.attempt_id,
            order_state=corrected_state,
            execution_event=correction,
            accounting_reference=correction_entries[0].entry_id,
            accounting_source_sha256=correction_entries[0].semantic_sha256,
            fence=scenario.system.lease.fence,
            accounted_at=correction.received_at,
            recorded_at=correction.received_at,
        )

    frozen = scenario.lifecycle.get(scenario.attempt.preparation.reservation_id)
    assert frozen is not None
    assert frozen.persisted_state is ReservationCapacityState.FROZEN
    assert frozen.correction_frozen is True
    with pytest.raises(ReservationLifecyclePersistenceError):
        _release_horizon(scenario)
    with scenario.system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_simulation_horizon_facts)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase2_reservation_release_events)
                .where(
                    phase2_reservation_release_events.c.reason
                    == ReservationReleaseReason.SIMULATION_HORIZON_FINAL.value
                )
            )
            == 0
        )


def test_runtime_horizon_gate_rejects_missing_accounting_ledger_economics(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)
    entry = _ledger_entry(scenario)
    with scenario.system.engine.begin() as connection:
        connection.execute(
            sa.delete(phase2_ledger_postings).where(
                phase2_ledger_postings.c.entry_id == entry.entry_id
            )
        )
        connection.execute(
            sa.delete(phase2_ledger_entries).where(
                phase2_ledger_entries.c.entry_id == entry.entry_id
            )
        )

    with pytest.raises(
        ReservationLifecyclePersistenceError,
        match="exact canonical ledger economics",
    ):
        _release_horizon(scenario)

    with scenario.system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_simulation_horizon_facts)
            )
            == 0
        )


def test_zero_fill_horizon_releases_the_complete_child_reservation(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path, cap_blocked=True)
    assert scenario.result.order_state.executions == ()

    released = _release_horizon(scenario)

    assert released.fact.released_cash == scenario.authorization.reserved_cash
    assert released.fact.released_buy_exposure == scenario.authorization.reserved_buy_exposure
    assert released.snapshot.persisted_state is ReservationCapacityState.RELEASED
    with scenario.system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_exact_simulation_horizon_retry_is_idempotent(tmp_path: Path) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)

    first = _release_horizon(scenario)
    retry = _release_horizon(scenario)

    assert retry.inserted is False
    assert retry.fact == first.fact
    assert retry.snapshot == first.snapshot
    with scenario.system.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_simulation_horizon_facts)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase2_reservation_release_events)
                .where(
                    phase2_reservation_release_events.c.reason
                    == ReservationReleaseReason.SIMULATION_HORIZON_FINAL.value
                )
            )
            == 1
        )
        _verify_phase2_durability_integrity(connection)


def test_abandoned_first_attempt_then_confirmed_retry_can_release_horizon(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path, retry_after_abandonment=True)
    attempts = scenario.system.repository.for_parent(scenario.system.decision.decision_id)
    order_attempts = tuple(item for item in attempts if item.order_id == scenario.attempt.order_id)

    assert tuple(item.state for item in order_attempts) == (
        SubmissionAttemptState.ABANDONED,
        SubmissionAttemptState.CONFIRMED,
    )
    assert scenario.attempt.attempt_number == 2
    _account_execution(scenario)

    released = _release_horizon(scenario)

    assert released.fact.attempt_id == scenario.attempt.attempt_id
    assert released.snapshot.persisted_state is ReservationCapacityState.RELEASED
    with scenario.system.engine.connect() as connection:
        _verify_phase2_durability_integrity(connection)


def test_backdated_horizon_is_rejected_after_trusted_lease_expiry(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path, cap_blocked=True)
    scenario.system.coordinator_clock.instant = scenario.system.lease.expires_at + timedelta(
        microseconds=1
    )

    with pytest.raises(AccountLeaseOwnershipLost, match="expired"):
        _release_horizon(scenario)

    with scenario.system.engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(phase2_order_events)) == 0
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_simulation_horizon_facts)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase2_reservation_release_events)
            )
            == 0
        )


@pytest.mark.parametrize("calendar_field", ("calendar_version", "closes_at"))
def test_horizon_session_must_match_the_pinned_durable_calendar(
    tmp_path: Path,
    calendar_field: str,
) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)
    _release_horizon(scenario)
    with scenario.system.engine.begin() as connection:
        row = connection.execute(sa.select(phase2_simulation_horizon_facts)).mappings().one()
        horizon_id = str(row["horizon_id"])
        payload = json.loads(str(row["canonical_payload"]))
        if calendar_field == "calendar_version":
            payload["session"][calendar_field] = "forged-calendar-version"
        else:
            payload["session"][calendar_field] = "2026-07-15T19:59:00.000000Z"
        connection.execute(
            sa.update(phase2_simulation_horizon_facts).values(
                canonical_payload=json.dumps(
                    payload,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        )

    with (
        scenario.system.engine.connect() as connection,
        pytest.raises(
            SimulationHorizonPersistenceError,
            match="pinned durable replay calendar",
        ),
    ):
        load_simulation_horizon_fact(connection, horizon_id)
    with (
        scenario.system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)


def test_horizon_watermarks_must_match_the_pinned_durable_universe(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path, cap_blocked=True)
    _release_horizon(scenario)
    with scenario.system.engine.begin() as connection:
        row = connection.execute(sa.select(phase2_simulation_horizon_facts)).mappings().one()
        horizon_id = str(row["horizon_id"])
        payload = json.loads(str(row["canonical_payload"]))
        for watermark in payload["replay_watermarks"]:
            watermark["expected_instrument_ids"] = ["aqt-security-qqq"]
        connection.execute(
            sa.update(phase2_simulation_horizon_facts).values(
                canonical_payload=json.dumps(
                    payload,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        )

    with (
        scenario.system.engine.connect() as connection,
        pytest.raises(
            SimulationHorizonPersistenceError,
            match="pinned durable replay universe",
        ),
    ):
        load_simulation_horizon_fact(connection, horizon_id)


@pytest.mark.parametrize("corruption", ("payload", "event_count"))
def test_horizon_corruption_fails_strict_load_and_readiness(
    tmp_path: Path,
    corruption: str,
) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)
    released = _release_horizon(scenario)
    with scenario.system.engine.begin() as connection:
        row = connection.execute(sa.select(phase2_simulation_horizon_facts)).mappings().one()
        horizon_id = str(row["horizon_id"])
        if corruption == "payload":
            payload = json.loads(str(row["canonical_payload"]))
            payload["model"]["fixed_fee"] = "0.26"
            connection.execute(
                sa.update(phase2_simulation_horizon_facts).values(
                    canonical_payload=json.dumps(
                        payload,
                        ensure_ascii=True,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
            )
        else:
            connection.execute(
                sa.update(phase2_simulation_horizon_facts).values(
                    replay_event_count=phase2_simulation_horizon_facts.c.replay_event_count + 1
                )
            )

    with (
        scenario.system.engine.connect() as connection,
        pytest.raises(SimulationHorizonPersistenceError),
    ):
        load_simulation_horizon_fact(connection, horizon_id)
    with (
        scenario.system.engine.connect() as connection,
        pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"),
    ):
        _verify_phase2_durability_integrity(connection)
    assert released.fact.finality_reference


def test_horizon_release_rejects_a_distinct_durable_recorded_time(
    tmp_path: Path,
) -> None:
    scenario = _scenario(tmp_path)
    _account_execution(scenario)
    released = _release_horizon(scenario)
    with scenario.system.engine.begin() as connection:
        horizon_id = str(connection.scalar(sa.select(phase2_simulation_horizon_facts.c.horizon_id)))
        connection.execute(
            sa.update(phase2_simulation_horizon_facts).values(
                recorded_at=released.fact.recorded_at + timedelta(seconds=1)
            )
        )

    with scenario.system.engine.connect() as connection:
        # recorded_at is durable envelope metadata, so the horizon remains
        # internally canonical while its cross-fact binding is corrupt.
        assert load_simulation_horizon_fact(connection, horizon_id) is not None
        with pytest.raises(DatabaseSchemaNotReady, match="canonical execution evidence"):
            _verify_phase2_durability_integrity(connection)
