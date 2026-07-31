from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from inspect import signature
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, make_url
from sqlalchemy.exc import IntegrityError

from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.broker_request_budget import (
    BrokerRequestBudgetError,
    BrokerRequestBudgetExhausted,
    BrokerRequestBudgetPolicy,
    BrokerRequestDemand,
    BrokerRequestPermit,
    BrokerRequestPermitConflict,
    BrokerRequestPermitExpired,
    BrokerRequestPermitFreshnessReceipt,
    BrokerRequestPurpose,
    issue_broker_request_permit,
)
from packages.domain.clock import FixedClock
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
    broker_request_permit_from_row,
    immutable_broker_request_permit_values,
    verify_broker_request_budget_integrity,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.immutable import assert_immutable
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase4_broker_request_heads,
    phase4_broker_request_permits,
)

ROOT = Path(__file__).resolve().parents[2]
ISSUED_AT = datetime(2026, 7, 26, 16, 0, tzinfo=UTC)
ACCOUNT_ID = "paper-budget-account"
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


@pytest.fixture
def phase4_budget_postgres_engine() -> Iterator[Engine]:
    """Migrate only an explicitly selected PostgreSQL test database."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4 budget tests")
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


def _engine(path: Path, *account_ids: str) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    with engine.begin() as connection:
        for account_id in account_ids:
            connection.execute(
                sa.insert(phase2_account_lease_heads).values(
                    account_id=account_id,
                    last_fencing_generation=0,
                    current_fencing_generation=None,
                    current_lease_sha256=None,
                    updated_at=ISSUED_AT,
                )
            )
    return engine


def _policy(
    *,
    policy_version: str = "v1",
    provider_id: str = "alpaca",
    environment: str = "paper",
    window: timedelta = timedelta(seconds=60),
    ttl: timedelta = timedelta(seconds=5),
    submission_capacity: int = 2,
    recovery_capacity: int = 3,
    total_capacity: int = 4,
) -> BrokerRequestBudgetPolicy:
    return BrokerRequestBudgetPolicy(
        policy_id="alpaca-paper-trading-api",
        policy_version=policy_version,
        provider_id=provider_id,
        environment=environment,
        window_duration=window,
        permit_ttl=ttl,
        submission_capacity=submission_capacity,
        recovery_capacity=recovery_capacity,
        total_capacity=total_capacity,
    )


def _demand(
    key: str,
    *,
    account_id: str = ACCOUNT_ID,
    purpose: BrokerRequestPurpose = BrokerRequestPurpose.SUBMISSION,
    requested_at: datetime = ISSUED_AT,
    correlation: str = "a" * 64,
) -> BrokerRequestDemand:
    return BrokerRequestDemand(
        account_id=account_id,
        idempotency_key=key,
        operation=f"operation-{purpose.value}",
        purpose=purpose,
        correlation_sha256=correlation,
        requested_at=requested_at,
    )


def _permit_count(engine: Engine) -> int:
    with engine.connect() as connection:
        count = connection.scalar(
            sa.select(sa.func.count()).select_from(phase4_broker_request_permits)
        )
    assert isinstance(count, int)
    return count


def _repository(
    engine: Engine,
    *,
    instant: datetime = ISSUED_AT,
) -> tuple[SqlBrokerRequestBudgetRepository, MutableClock]:
    clock = MutableClock(instant)
    return SqlBrokerRequestBudgetRepository(engine=engine, clock=clock), clock


def test_issue_load_history_and_exact_sql_readback(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "budget.sqlite", ACCOUNT_ID)
    repository, _ = _repository(engine)
    policy = _policy()
    demand = _demand("request-0001")

    permit = repository.issue(policy=policy, demand=demand)

    assert permit.sequence_number == 1
    assert permit.previous_permit_sha256 is None
    assert permit.transport_authorized is False
    assert permit.refundable is False
    assert repository.load(permit.permit_id) == permit
    assert repository.history(ACCOUNT_ID) == (permit,)
    verify_broker_request_budget_integrity(engine)
    with engine.connect() as connection:
        row = (
            connection.execute(
                sa.select(phase4_broker_request_permits).where(
                    phase4_broker_request_permits.c.permit_id == permit.permit_id
                )
            )
            .mappings()
            .one()
        )
        persisted = broker_request_permit_from_row(row)
        assert persisted.policy == policy
        assert persisted.demand == demand
        assert persisted.permit == permit
        assert persisted.window_permit_count == 1
        assert persisted.admission_ceiling == policy.submission_capacity
        expected_values = immutable_broker_request_permit_values(
            policy=policy,
            demand=demand,
            permit=permit,
            window_permit_count=1,
        )
        assert_immutable(
            phase4_broker_request_permits,
            permit.permit_id,
            row,
            expected_values,
        )


def test_exact_retry_ignores_new_issue_time_and_changed_content_conflicts(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "idempotency.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy()
    demand = _demand("request-0001")
    original = repository.issue(policy=policy, demand=demand)

    clock.instant = ISSUED_AT - timedelta(days=1)
    retried = repository.issue(policy=policy, demand=demand)

    assert retried == original
    assert _permit_count(engine) == 1
    with pytest.raises(BrokerRequestPermitConflict, match="already has a durable permit"):
        repository.issue_new(policy=policy, demand=demand)
    clock.instant = ISSUED_AT + timedelta(seconds=1)
    with pytest.raises(BrokerRequestPermitConflict, match="identity conflicts"):
        repository.issue(
            policy=policy,
            demand=replace(demand, correlation_sha256="b" * 64),
        )
    with pytest.raises(BrokerRequestPermitConflict, match="identity conflicts"):
        repository.issue(
            policy=replace(policy, policy_version="v2"),
            demand=demand,
        )
    assert _permit_count(engine) == 1


def test_all_active_traffic_counts_against_each_purpose_ceiling_and_never_refunds(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "purpose-ceilings.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy()

    critical = repository.issue(
        policy=policy,
        demand=_demand("request-0001", purpose=BrokerRequestPurpose.CANCEL),
    )
    clock.instant = ISSUED_AT + timedelta(seconds=1)
    submission = repository.issue(
        policy=policy,
        demand=_demand("request-0002"),
    )
    assert (critical.sequence_number, submission.sequence_number) == (1, 2)
    clock.instant = ISSUED_AT + timedelta(seconds=10)
    with pytest.raises(BrokerRequestBudgetExhausted, match="submission"):
        repository.issue(
            policy=policy,
            demand=_demand("request-0003"),
        )

    lookup = repository.issue(
        policy=policy,
        demand=_demand(
            "request-0004",
            purpose=BrokerRequestPurpose.UNKNOWN_LOOKUP,
        ),
    )
    assert lookup.sequence_number == 3
    clock.instant = ISSUED_AT + timedelta(seconds=11)
    with pytest.raises(BrokerRequestBudgetExhausted, match="unknown_lookup"):
        repository.issue(
            policy=policy,
            demand=_demand(
                "request-0005",
                purpose=BrokerRequestPurpose.UNKNOWN_LOOKUP,
            ),
        )

    reconciliation = repository.issue(
        policy=policy,
        demand=_demand(
            "request-0006",
            purpose=BrokerRequestPurpose.RECONCILIATION,
        ),
    )
    assert reconciliation.sequence_number == 4
    clock.instant = ISSUED_AT + timedelta(seconds=12)
    with pytest.raises(BrokerRequestBudgetExhausted, match="cancel"):
        repository.issue(
            policy=policy,
            demand=_demand("request-0007", purpose=BrokerRequestPurpose.CANCEL),
        )
    assert _permit_count(engine) == 4


def test_rolling_window_keeps_equality_active_then_expires_strictly_later(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "rolling-boundary.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy(
        submission_capacity=1,
        recovery_capacity=2,
        total_capacity=3,
    )
    first = repository.issue(
        policy=policy,
        demand=_demand("request-0001", purpose=BrokerRequestPurpose.CANCEL),
    )

    accounting_horizon = first.expires_at + policy.window_duration
    clock.instant = accounting_horizon
    with pytest.raises(BrokerRequestBudgetExhausted, match="submission"):
        repository.issue(
            policy=policy,
            demand=_demand("request-0002"),
        )
    clock.instant = accounting_horizon + timedelta(microseconds=1)
    second = repository.issue(
        policy=policy,
        demand=_demand("request-0003"),
    )

    assert second.sequence_number == 2
    assert second.previous_permit_sha256 == first.semantic_sha256
    with engine.connect() as connection:
        count = connection.scalar(
            sa.select(phase4_broker_request_permits.c.window_permit_count).where(
                phase4_broker_request_permits.c.permit_id == second.permit_id
            )
        )
    assert count == 1


def test_policy_rotation_waits_past_old_window_and_preserves_provider_identity(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "policy-rotation.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    first_policy = _policy()
    second_policy = replace(
        first_policy,
        policy_version="v2",
        window_duration=timedelta(seconds=10),
    )
    first = repository.issue(
        policy=first_policy,
        demand=_demand("request-0001", purpose=BrokerRequestPurpose.CANCEL),
    )

    first_horizon = first.expires_at + first_policy.window_duration
    clock.instant = first_horizon
    with pytest.raises(BrokerRequestPermitConflict, match="cannot change"):
        repository.issue(
            policy=second_policy,
            demand=_demand("request-0002"),
        )
    clock.instant = first_horizon + timedelta(microseconds=1)
    rotated = repository.issue(
        policy=second_policy,
        demand=_demand("request-0003"),
    )
    assert rotated.sequence_number == 2
    assert rotated.previous_permit_sha256 == first.semantic_sha256

    clock.instant = rotated.expires_at + second_policy.window_duration + timedelta(microseconds=1)
    with pytest.raises(BrokerRequestPermitConflict, match="provider or environment"):
        repository.issue(
            policy=replace(second_policy, provider_id="different-provider"),
            demand=_demand("request-0004"),
        )


def test_new_allocation_rejects_account_clock_regression(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "clock-regression.sqlite", ACCOUNT_ID)
    repository, clock = _repository(
        engine,
        instant=ISSUED_AT + timedelta(seconds=10),
    )
    policy = _policy()
    repository.issue(
        policy=policy,
        demand=_demand("request-0001"),
    )

    clock.instant = ISSUED_AT + timedelta(seconds=9)
    with pytest.raises(BrokerRequestPermitConflict, match="clock moved backwards"):
        repository.issue(
            policy=policy,
            demand=_demand("request-0002"),
        )
    assert _permit_count(engine) == 1


def test_issue_time_is_trusted_and_freshness_requires_durable_admission(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "trusted-clock.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy()
    durable_demand = _demand("request-0001")
    fabricated_demand = _demand("request-0002")
    fabricated = issue_broker_request_permit(
        policy=policy,
        demand=fabricated_demand,
        issued_at=ISSUED_AT,
        active_permits=(),
        previous_permit=None,
        previous_policy=None,
    )

    assert "issued_at" not in signature(repository.issue).parameters
    with pytest.raises(BrokerRequestPermitConflict, match="no durable admission"):
        repository.authenticate_fresh(
            permit=fabricated,
            policy=policy,
            demand=fabricated_demand,
        )

    persisted = repository.issue(policy=policy, demand=durable_demand)
    with pytest.raises(BrokerRequestPermitConflict, match="conflicts with supplied evidence"):
        repository.authenticate_fresh(
            permit=persisted,
            policy=replace(policy, policy_version="v2"),
            demand=durable_demand,
        )
    with pytest.raises(BrokerRequestPermitConflict, match="conflicts with supplied evidence"):
        repository.authenticate_fresh(
            permit=persisted,
            policy=policy,
            demand=replace(durable_demand, correlation_sha256="b" * 64),
        )

    receipt = repository.authenticate_fresh(
        permit=persisted,
        policy=policy,
        demand=durable_demand,
    )
    assert type(receipt) is BrokerRequestPermitFreshnessReceipt
    assert receipt.permit_id == persisted.permit_id
    assert receipt.permit_sha256 == persisted.semantic_sha256
    assert receipt.policy_sha256 == policy.semantic_sha256
    assert receipt.demand_sha256 == durable_demand.semantic_sha256
    assert receipt.checked_at == clock.instant
    assert receipt.expires_at == persisted.expires_at
    assert receipt.is_fresh is True
    assert receipt.transport_authorized is False
    assert (
        repository.require_fresh(
            permit=persisted,
            policy=policy,
            demand=durable_demand,
        )
        is None
    )

    clock.instant = ISSUED_AT + timedelta(seconds=1)
    later_receipt = repository.authenticate_fresh(
        permit=persisted,
        policy=policy,
        demand=durable_demand,
    )
    assert later_receipt.checked_at == clock.instant
    assert later_receipt.semantic_sha256 != receipt.semantic_sha256

    clock.instant = persisted.expires_at
    with pytest.raises(BrokerRequestPermitExpired, match="not fresh"):
        repository.authenticate_fresh(
            permit=persisted,
            policy=policy,
            demand=durable_demand,
        )


def test_database_rejects_skipped_predecessor_and_mismatched_head(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "relational-chain.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy(
        submission_capacity=3,
        recovery_capacity=4,
        total_capacity=5,
    )
    first = repository.issue(
        policy=policy,
        demand=_demand("request-0001"),
    )
    clock.instant = ISSUED_AT + timedelta(seconds=1)
    repository.issue(
        policy=policy,
        demand=_demand("request-0002"),
    )
    clock.instant = ISSUED_AT + timedelta(seconds=2)
    third = repository.issue(
        policy=policy,
        demand=_demand("request-0003"),
    )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_request_permits)
            .where(phase4_broker_request_permits.c.permit_id == third.permit_id)
            .values(
                previous_sequence_number=1,
                previous_permit_sha256=first.semantic_sha256,
            )
        )
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_request_heads)
            .where(phase4_broker_request_heads.c.account_id == ACCOUNT_ID)
            .values(last_sequence_number=2)
        )
    verify_broker_request_budget_integrity(engine)


def test_point_reads_reject_a_foreign_key_valid_full_head_rollback(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "point-head.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy()
    first_demand = _demand("request-0001")
    first = repository.issue(
        policy=policy,
        demand=first_demand,
    )
    clock.instant = ISSUED_AT + timedelta(seconds=1)
    second = repository.issue(
        policy=policy,
        demand=_demand("request-0002"),
    )
    with engine.begin() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        connection.execute(
            sa.update(phase4_broker_request_heads)
            .where(phase4_broker_request_heads.c.account_id == ACCOUNT_ID)
            .values(
                last_sequence_number=first.sequence_number,
                last_permit_sha256=first.semantic_sha256,
                last_issued_at=first.issued_at,
            )
        )

    assert second.sequence_number == 2
    with pytest.raises(BrokerRequestBudgetError, match="rolled back"):
        repository.load(first.permit_id)
    with pytest.raises(BrokerRequestBudgetError, match="rolled back"):
        repository.require_fresh(
            permit=first,
            policy=policy,
            demand=first_demand,
        )
    with pytest.raises(BrokerRequestBudgetError, match="durable terminal permit"):
        verify_broker_request_budget_integrity(engine)


def test_history_and_full_integrity_reject_tampered_rolling_count(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "tampered-count.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy()
    repository.issue(
        policy=policy,
        demand=_demand("request-0001"),
    )
    clock.instant = ISSUED_AT + timedelta(seconds=1)
    second = repository.issue(
        policy=policy,
        demand=_demand("request-0002"),
    )
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_request_permits)
            .where(phase4_broker_request_permits.c.permit_id == second.permit_id)
            .values(window_permit_count=1)
        )

    with pytest.raises(BrokerRequestBudgetError, match="rolling count conflicts"):
        repository.history(ACCOUNT_ID)
    with pytest.raises(BrokerRequestBudgetError, match="rolling count conflicts"):
        verify_broker_request_budget_integrity(engine)


def test_point_reads_freshness_and_append_reject_a_corrupted_predecessor(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "budget-broken-predecessor.sqlite", ACCOUNT_ID)
    repository, clock = _repository(engine)
    policy = _policy()
    first = repository.issue(
        policy=policy,
        demand=_demand("request-0001"),
    )
    clock.instant = ISSUED_AT + timedelta(seconds=1)
    second_demand = _demand("request-0002")
    second = repository.issue(
        policy=policy,
        demand=second_demand,
    )

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_request_permits)
            .where(phase4_broker_request_permits.c.permit_id == first.permit_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(BrokerRequestBudgetError, match="canonical_payload"):
        repository.load(second.permit_id)
    with pytest.raises(BrokerRequestBudgetError, match="canonical_payload"):
        repository.authenticate_fresh(
            permit=second,
            policy=policy,
            demand=second_demand,
        )
    clock.instant = ISSUED_AT + timedelta(seconds=2)
    with pytest.raises(BrokerRequestBudgetError, match="canonical_payload"):
        repository.issue_new(
            policy=policy,
            demand=_demand("request-0003"),
        )
    assert _permit_count(engine) == 2


def test_sqlite_concurrent_admission_serializes_one_capacity_prefix(
    tmp_path: Path,
) -> None:
    account_id = "sqlite-concurrent-budget"
    engine = _engine(tmp_path / "concurrent.sqlite", account_id)
    repository = SqlBrokerRequestBudgetRepository(
        engine=engine,
        clock=FixedClock(ISSUED_AT),
    )
    policy = _policy(
        submission_capacity=1,
        recovery_capacity=2,
        total_capacity=3,
    )
    barrier = Barrier(2)

    def allocate(index: int) -> BrokerRequestPermit | type[BrokerRequestBudgetExhausted]:
        barrier.wait(timeout=10)
        try:
            return repository.issue(
                policy=policy,
                demand=_demand(
                    f"concurrent-{index:04d}",
                    account_id=account_id,
                ),
            )
        except BrokerRequestBudgetExhausted:
            return BrokerRequestBudgetExhausted

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(allocate, range(2)))

    permits = tuple(result for result in results if isinstance(result, BrokerRequestPermit))
    exhausted = tuple(result for result in results if result is BrokerRequestBudgetExhausted)
    assert len(permits) == 1
    assert len(exhausted) == 1
    assert permits[0].sequence_number == 1
    assert repository.history(account_id) == permits


def test_postgresql_concurrent_admission_serializes_one_capacity_prefix(
    phase4_budget_postgres_engine: Engine,
) -> None:
    engine = phase4_budget_postgres_engine
    account_id = f"pg-budget-{uuid4().hex[:24]}"
    policy = _policy(
        submission_capacity=1,
        recovery_capacity=2,
        total_capacity=3,
    )
    repository = SqlBrokerRequestBudgetRepository(
        engine=engine,
        clock=FixedClock(ISSUED_AT),
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=account_id,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=ISSUED_AT,
            )
        )
    barrier = Barrier(2)

    def allocate(index: int) -> BrokerRequestPermit | type[BrokerRequestBudgetExhausted]:
        barrier.wait(timeout=10)
        try:
            return repository.issue(
                policy=policy,
                demand=_demand(
                    f"postgres-{index:04d}",
                    account_id=account_id,
                ),
            )
        except BrokerRequestBudgetExhausted:
            return BrokerRequestBudgetExhausted

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(allocate, range(2)))
        assert sum(isinstance(result, BrokerRequestPermit) for result in results) == 1
        assert sum(result is BrokerRequestBudgetExhausted for result in results) == 1
        assert len(repository.history(account_id)) == 1
    finally:
        with engine.begin() as connection:
            connection.execute(
                sa.delete(phase4_broker_request_heads).where(
                    phase4_broker_request_heads.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase4_broker_request_permits).where(
                    phase4_broker_request_permits.c.account_id == account_id
                )
            )
            connection.execute(
                sa.delete(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == account_id
                )
            )


def test_phase4_budget_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'budget-migration.sqlite'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0011_phase4_broker_ingress")
    engine = create_database_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "0012_phase4_request_budget")

    assert set(inspect(engine).get_table_names()) == prior_tables | {
        "phase4_broker_request_heads",
        "phase4_broker_request_permits",
    }
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_request_permits")
    ) == tuple(phase4_broker_request_permits.c.keys())
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase4_broker_request_heads")
    ) == tuple(phase4_broker_request_heads.c.keys())
    engine.dispose()

    command.downgrade(config, "0011_phase4_broker_ingress")
    downgraded_engine = create_database_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase4_budget_migration_refuses_data_loss_and_readiness_authenticates(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'budget-downgrade.sqlite'}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase4-budget-readiness",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=FixedClock(ISSUED_AT),
        ),
    )
    coordinator.acquire("phase4-budget-readiness-worker")
    SqlBrokerRequestBudgetRepository(
        engine=engine,
        clock=FixedClock(ISSUED_AT),
    ).issue(
        policy=_policy(),
        demand=_demand("request-0001"),
    )
    verify_operational_schema(engine, require_phase_zero_facts=False)
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="cannot downgrade after durable broker request permits",
    ):
        command.downgrade(config, "0011_phase4_broker_ingress")

    preserved_engine = create_database_engine(database_url)
    with preserved_engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0012_phase4_request_budget"
        )
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase4_broker_request_permits))
            == 1
        )
    preserved_engine.dispose()
    command.upgrade(config, "head")
    preserved_engine = create_database_engine(database_url)
    with preserved_engine.begin() as connection:
        connection.execute(sa.update(phase4_broker_request_permits).values(window_permit_count=2))
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="broker-request budget integrity",
    ):
        verify_operational_schema(preserved_engine, require_phase_zero_facts=False)
    preserved_engine.dispose()
