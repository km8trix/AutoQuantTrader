"""PostgreSQL concurrency exit gates for durable Phase 2 coordination."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TypeVar
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url

from packages.backtest.golden_runner import golden_strategy_registration, run_golden_backtest
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLease,
    AccountLeaseConflict,
    AccountLeasePolicy,
)
from packages.domain.backtest_job import BacktestJobStatus
from packages.domain.batch_risk import (
    BatchRiskAuthority,
    BatchRiskDecision,
    BatchRiskDecisionStatus,
    VersionedBatchRiskSnapshot,
)
from packages.domain.models import OrderIntentBatch, TargetPortfolio
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.backtest_workflow import BacktestJobSnapshot, SqlBacktestWorkflow
from packages.persistence.batch_risk import (
    SqlAccountFenceValidator,
    SqlBatchRiskRepository,
    _decode_active_capacity,
)
from packages.persistence.database import create_database_engine
from packages.persistence.reservation_lifecycle import SqlReservationLifecycleRepository
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase2_backtest_audit_events,
    phase2_backtest_fixtures,
    phase2_backtest_job_events,
    phase2_backtest_job_heads,
    phase2_backtest_jobs,
    phase2_batch_authorizations,
    phase2_batch_decisions,
    phase2_batch_members,
    phase2_batch_reservations,
    phase2_reservation_release_events,
)
from tests.unit.test_batch_risk import (
    CONSUMED_AT,
    EVALUATED_AT,
    MutableClock,
    limits,
    make_batch,
    make_portfolio,
    snapshot,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class SnapshotTransactions:
    snapshot: VersionedBatchRiskSnapshot

    def current(self) -> VersionedBatchRiskSnapshot:
        return self.snapshot

    def transact(
        self,
        operation: Callable[[VersionedBatchRiskSnapshot], ResultT],
    ) -> ResultT:
        return operation(self.snapshot)


@pytest.fixture(scope="module")
def postgres_engine() -> Iterator[Engine]:
    """Migrate only an explicitly selected PostgreSQL test database."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 2 exit tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")

    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def _coordinator(
    engine: Engine,
    *,
    account_id: str,
    clock: MutableClock,
) -> SqlAccountCoordinator:
    return SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase2-postgres-exit-coordinator",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=clock,
        ),
    )


def _delete_account_facts(engine: Engine, account_id: str) -> None:
    """Delete only the Phase 2 facts owned by one test account namespace."""

    with engine.begin() as connection:
        decision_ids = sa.select(phase2_batch_decisions.c.decision_id).where(
            phase2_batch_decisions.c.account_id == account_id
        )
        reservation_ids = sa.select(phase2_batch_reservations.c.reservation_id).where(
            phase2_batch_reservations.c.account_id == account_id
        )
        connection.execute(
            sa.delete(phase2_reservation_release_events).where(
                phase2_reservation_release_events.c.reservation_id.in_(reservation_ids)
            )
        )
        connection.execute(
            sa.delete(phase2_batch_authorizations).where(
                phase2_batch_authorizations.c.reservation_id.in_(reservation_ids)
            )
        )
        connection.execute(
            sa.delete(phase2_batch_reservations).where(
                phase2_batch_reservations.c.account_id == account_id
            )
        )
        connection.execute(
            sa.delete(phase2_batch_members).where(
                phase2_batch_members.c.decision_id.in_(decision_ids)
            )
        )
        connection.execute(
            sa.delete(phase2_batch_decisions).where(
                phase2_batch_decisions.c.account_id == account_id
            )
        )
        connection.execute(
            sa.delete(phase2_account_lease_releases).where(
                phase2_account_lease_releases.c.account_id == account_id
            )
        )
        connection.execute(
            sa.delete(phase2_account_lease_heads).where(
                phase2_account_lease_heads.c.account_id == account_id
            )
        )
        connection.execute(
            sa.delete(phase2_account_leases).where(phase2_account_leases.c.account_id == account_id)
        )


def test_two_owners_racing_for_first_coordinator_lease_have_one_winner(
    postgres_engine: Engine,
) -> None:
    token = uuid4().hex
    account_id = f"pytest-p2-lease-{token}"
    start_together = threading.Barrier(3)

    def acquire(owner_id: str) -> AccountLease | AccountLeaseConflict:
        contender = _coordinator(
            postgres_engine,
            account_id=account_id,
            clock=MutableClock(EVALUATED_AT),
        )
        start_together.wait(timeout=10)
        try:
            return contender.acquire(owner_id)
        except AccountLeaseConflict as error:
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(acquire, owner_id)
                for owner_id in (f"worker-a-{token}", f"worker-b-{token}")
            )
            start_together.wait(timeout=10)
            outcomes = tuple(future.result(timeout=20) for future in futures)

        leases = tuple(outcome for outcome in outcomes if type(outcome) is AccountLease)
        conflicts = tuple(outcome for outcome in outcomes if type(outcome) is AccountLeaseConflict)
        assert len(leases) == 1
        assert len(conflicts) == 1
        assert leases[0].fencing_generation == 1
        with postgres_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(phase2_account_leases)
                    .where(phase2_account_leases.c.account_id == account_id)
                )
                == 1
            )
            head = (
                connection.execute(
                    sa.select(phase2_account_lease_heads).where(
                        phase2_account_lease_heads.c.account_id == account_id
                    )
                )
                .mappings()
                .one()
            )
        assert head["current_lease_sha256"] == leases[0].semantic_sha256
        assert head["last_fencing_generation"] == 1
    finally:
        _delete_account_facts(postgres_engine, account_id)


def test_concurrent_batch_authorizations_cannot_overreserve_cash(
    postgres_engine: Engine,
) -> None:
    token = uuid4().hex
    account_id = f"pytest-p2-risk-{token}"
    portfolio = make_portfolio(current={}, instruments=("US-ETF-QQQ", "US-ETF-SPY"))
    cases: tuple[tuple[TargetPortfolio, OrderIntentBatch], ...] = (
        make_batch(
            portfolio,
            desired={"US-ETF-QQQ": Decimal("5")},
            target_id=f"pg-qqq-{token}",
        ),
        make_batch(
            portfolio,
            desired={"US-ETF-SPY": Decimal("5")},
            target_id=f"pg-spy-{token}",
        ),
    )
    capacity = snapshot(portfolio, account_id=account_id, available_cash=Decimal("700"))
    coordinator = _coordinator(
        postgres_engine,
        account_id=account_id,
        clock=MutableClock(EVALUATED_AT),
    )
    fence = coordinator.acquire(f"risk-worker-{token}").fence
    repositories = tuple(
        SqlBatchRiskRepository(
            engine=postgres_engine,
            authority=BatchRiskAuthority(
                limits=limits(),
                snapshots=SnapshotTransactions(capacity),
                evaluation_clock=MutableClock(EVALUATED_AT),
                consumption_clock=MutableClock(CONSUMED_AT),
            ),
            coordinator=coordinator,
        )
        for _ in cases
    )
    start_together = threading.Barrier(3)

    def authorize(index: int) -> BatchRiskDecisionStatus:
        start_together.wait(timeout=10)
        target, batch = cases[index]
        return repositories[index].authorize(batch, target, fence).status

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(executor.submit(authorize, index) for index in range(2))
            start_together.wait(timeout=10)
            statuses = tuple(future.result(timeout=20) for future in futures)

        assert sorted(status.value for status in statuses) == ["approved", "rejected"]
        with postgres_engine.connect() as connection:
            reservation_rows = tuple(
                connection.execute(
                    sa.select(phase2_batch_reservations).where(
                        phase2_batch_reservations.c.account_id == account_id
                    )
                ).mappings()
            )
            decision_statuses = tuple(
                connection.scalars(
                    sa.select(phase2_batch_decisions.c.status)
                    .where(phase2_batch_decisions.c.account_id == account_id)
                    .order_by(phase2_batch_decisions.c.status)
                )
            )
            active_capacity_rows = tuple(
                connection.execute(
                    sa.select(
                        phase2_batch_decisions.c.active_capacity_payload,
                        phase2_batch_decisions.c.active_capacity_sha256,
                    ).where(phase2_batch_decisions.c.account_id == account_id)
                ).mappings()
            )
        assert decision_statuses == ("approved", "rejected")
        assert len(active_capacity_rows) == 2
        assert len({row["active_capacity_sha256"] for row in active_capacity_rows}) == 2
        assert all(row["active_capacity_payload"] for row in active_capacity_rows)
        assert len(reservation_rows) == 1
        reserved_cash = Decimal(str(reservation_rows[0]["remaining_cash"]))
        assert reserved_cash == Decimal("504")
        assert reserved_cash <= capacity.available_cash
    finally:
        _delete_account_facts(postgres_engine, account_id)


@pytest.mark.parametrize(
    ("release_first", "equal_timestamp"),
    (
        (False, False),
        (True, False),
        (False, True),
        (True, True),
    ),
    ids=(
        "risk-first-distinct-time",
        "release-first-distinct-time",
        "risk-first-equal-time",
        "release-first-equal-time",
    ),
)
def test_release_racing_authorization_observes_one_serialized_capacity_prefix(
    postgres_engine: Engine,
    release_first: bool,
    equal_timestamp: bool,
) -> None:
    token = uuid4().hex
    account_id = f"pytest-p2-release-risk-{token}"
    portfolio = make_portfolio(current={}, instruments=("US-ETF-QQQ", "US-ETF-SPY"))
    first_target, first_batch = make_batch(
        portfolio,
        desired={"US-ETF-SPY": Decimal("5")},
        target_id=f"pg-release-parent-{token}",
    )
    second_target, second_batch = make_batch(
        portfolio,
        desired={"US-ETF-QQQ": Decimal("5")},
        target_id=f"pg-release-contender-{token}",
    )
    capacity = snapshot(portfolio, account_id=account_id, available_cash=Decimal("700"))
    coordinator = _coordinator(
        postgres_engine,
        account_id=account_id,
        clock=MutableClock(EVALUATED_AT),
    )
    fence = coordinator.acquire(f"release-risk-worker-{token}").fence

    def risk_repository(
        evaluated_at: datetime,
        validator: SqlAccountFenceValidator = coordinator,
    ) -> SqlBatchRiskRepository:
        return SqlBatchRiskRepository(
            engine=postgres_engine,
            authority=BatchRiskAuthority(
                limits=limits(),
                snapshots=SnapshotTransactions(capacity),
                evaluation_clock=MutableClock(evaluated_at),
                consumption_clock=MutableClock(evaluated_at),
            ),
            coordinator=validator,
        )

    try:
        first_risk = risk_repository(EVALUATED_AT)
        first = first_risk.authorize(first_batch, first_target, fence)
        assert first.reservation is not None
        first_reservation = first.reservation
        release_at = first.expires_at + timedelta(seconds=1)
        risk_at = (
            release_at
            if equal_timestamp
            else release_at
            + (timedelta(seconds=1) if release_first else -timedelta(microseconds=1))
        )
        first_locked = threading.Event()
        second_entered = threading.Event()

        @dataclass(frozen=True)
        class OrderedRaceValidator:
            first: bool

            def revalidate_in_transaction(
                self,
                connection: sa.Connection,
                requested_fence: AccountFence,
                *,
                checked_at: datetime,
            ) -> AccountFenceReceipt:
                if not self.first:
                    second_entered.set()
                receipt = coordinator.revalidate_in_transaction(
                    connection,
                    requested_fence,
                    checked_at=checked_at,
                )
                if self.first:
                    first_locked.set()
                    if not second_entered.wait(timeout=10):
                        raise TimeoutError("second account operation did not enter the lock race")
                return receipt

        first_validator = OrderedRaceValidator(first=True)
        second_validator = OrderedRaceValidator(first=False)
        risk_validator = second_validator if release_first else first_validator
        release_validator = first_validator if release_first else second_validator
        second_risk = risk_repository(risk_at, risk_validator)
        lifecycle = SqlReservationLifecycleRepository(
            engine=postgres_engine,
            coordinator=release_validator,
        )

        def release() -> None:
            lifecycle.expire_unsent(
                reservation_id=first_reservation.reservation_id,
                authorization_id=first.authorizations[0].decision_id,
                fence=fence,
                finality_reference=f"pg-race-release-{token}",
                observed_at=release_at,
                recorded_at=release_at,
            )

        def authorize() -> BatchRiskDecision:
            return second_risk.authorize(second_batch, second_target, fence)

        with ThreadPoolExecutor(max_workers=2) as executor:
            if release_first:
                release_future = executor.submit(release)
                assert first_locked.wait(timeout=10)
                authorization_future = executor.submit(authorize)
            else:
                authorization_future = executor.submit(authorize)
                assert first_locked.wait(timeout=10)
                release_future = executor.submit(release)
            second = authorization_future.result(timeout=20)
            release_future.result(timeout=20)

        persisted = second_risk.get_batch(second.decision_id)
        assert persisted == second
        with postgres_engine.connect() as connection:
            row = (
                connection.execute(
                    sa.select(
                        phase2_batch_decisions.c.active_capacity_payload,
                        phase2_batch_decisions.c.account_observation_sequence,
                    ).where(phase2_batch_decisions.c.decision_id == second.decision_id)
                )
                .mappings()
                .one()
            )
            first_head = (
                connection.execute(
                    sa.select(phase2_batch_reservations).where(
                        phase2_batch_reservations.c.reservation_id
                        == first_reservation.reservation_id
                    )
                )
                .mappings()
                .one()
            )
            release_marker = connection.scalar(
                sa.select(
                    phase2_reservation_release_events.c.visible_after_observation_sequence
                ).where(
                    phase2_reservation_release_events.c.reservation_id
                    == first_reservation.reservation_id
                )
            )
        observed = _decode_active_capacity(row["active_capacity_payload"])
        assert row["account_observation_sequence"] == 2
        assert first_head["state"] == "released"
        if release_first:
            assert release_marker == 1
            assert second.status is BatchRiskDecisionStatus.APPROVED
            assert observed.reservations == ()
            assert second.reservation is not None
        else:
            assert release_marker == 2
            assert second.status is BatchRiskDecisionStatus.REJECTED
            assert len(observed.reservations) == 1
            assert observed.reservations[0].reservation_id == first_reservation.reservation_id
            assert observed.reservations[0].remaining_cash == first_reservation.reserved_cash
            assert second.reservation is None
    finally:
        _delete_account_facts(postgres_engine, account_id)


def _delete_backtest_facts(
    engine: Engine,
    *,
    fixture_id: str,
    fixture_version: str,
    job_id: str | None,
) -> None:
    """Delete one test launch and its uniquely named fixture catalog row."""

    with engine.begin() as connection:
        if job_id is not None:
            connection.execute(
                sa.delete(phase2_backtest_job_heads).where(
                    phase2_backtest_job_heads.c.job_id == job_id
                )
            )
            connection.execute(
                sa.delete(phase2_backtest_audit_events).where(
                    phase2_backtest_audit_events.c.job_id == job_id
                )
            )
            connection.execute(
                sa.delete(phase2_backtest_job_events).where(
                    phase2_backtest_job_events.c.job_id == job_id
                )
            )
            connection.execute(
                sa.delete(phase2_backtest_jobs).where(phase2_backtest_jobs.c.job_id == job_id)
            )
        connection.execute(
            sa.delete(phase2_backtest_fixtures).where(
                phase2_backtest_fixtures.c.fixture_id == fixture_id,
                phase2_backtest_fixtures.c.fixture_version == fixture_version,
            )
        )


def test_two_workers_cannot_claim_the_same_queued_job(postgres_engine: Engine) -> None:
    token = uuid4().hex
    fixture_id = f"pytest-p2-fixture-{token}"
    fixture_version = "1.0.0"
    requested_at = datetime(2026, 7, 20, 14, 0, tzinfo=UTC)
    workflow = SqlBacktestWorkflow(postgres_engine)
    job_id: str | None = None

    try:
        version, configuration, display_name, parameter_schema = golden_strategy_registration()
        workflow.register_strategy(
            version=version,
            configuration=configuration,
            display_name=display_name,
            parameter_schema_payload=parameter_schema,
        )
        job_input = workflow.register_fixture(
            fixture_id=fixture_id,
            fixture_version=fixture_version,
            reference_manifest=run_golden_backtest().manifest,
            registered_at=requested_at - timedelta(minutes=1),
        )
        queued = workflow.launch(
            input=job_input,
            requested_by=f"pytest-operator-{token}",
            idempotency_key=f"pytest-claim-{token}",
            requested_at=requested_at,
        )
        job_id = queued.job_id
        start_together = threading.Barrier(3)

        def claim(worker_id: str) -> BacktestJobSnapshot | None:
            start_together.wait(timeout=10)
            return SqlBacktestWorkflow(postgres_engine).claim_next(
                worker_id=worker_id,
                claimed_at=requested_at + timedelta(seconds=1),
                claim_expires_at=requested_at + timedelta(minutes=5),
            )

        # Keep every unrelated head locked for this short race. PostgreSQL's
        # SKIP LOCKED queue query can then select only this test's job without
        # claiming or mutating another test invocation's durable facts.
        with postgres_engine.connect() as blocker, blocker.begin():
            blocker.execute(
                sa.select(phase2_backtest_job_heads.c.job_id)
                .where(phase2_backtest_job_heads.c.job_id != queued.job_id)
                .with_for_update(of=phase2_backtest_job_heads)
            ).all()
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = tuple(
                    executor.submit(claim, worker_id)
                    for worker_id in (f"worker-a-{token}", f"worker-b-{token}")
                )
                start_together.wait(timeout=10)
                outcomes = tuple(future.result(timeout=20) for future in futures)

        claimed = tuple(outcome for outcome in outcomes if outcome is not None)
        assert len(claimed) == 1
        assert claimed[0].job_id == queued.job_id
        assert claimed[0].status is BacktestJobStatus.RUNNING
        persisted = workflow.get(queued.job_id)
        assert persisted.worker_id == claimed[0].worker_id
        assert tuple(event.status for event in persisted.history) == (
            BacktestJobStatus.QUEUED,
            BacktestJobStatus.RUNNING,
        )
    finally:
        _delete_backtest_facts(
            postgres_engine,
            fixture_id=fixture_id,
            fixture_version=fixture_version,
            job_id=job_id,
        )
