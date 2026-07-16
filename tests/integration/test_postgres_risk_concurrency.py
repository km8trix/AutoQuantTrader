"""PostgreSQL proof that account-scoped risk reservations serialize correctly."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url

from packages.application.market_data_ingestion import ingest_recorded_fixture
from packages.domain.clock import FixedClock
from packages.domain.models import DecisionStatus
from packages.domain.risk import (
    FixedRiskAccountSnapshotProvider,
    RiskAccountSnapshot,
    RiskAuthority,
    RiskLimits,
)
from packages.domain.walking_thread import WalkingThread
from packages.persistence.database import create_database_engine
from packages.persistence.risk import SqlRiskDecisionRepository
from packages.persistence.schema import (
    calendar_sessions,
    calendar_versions,
    corporate_action_revisions,
    corporate_action_set_members,
    corporate_action_sets,
    data_objects,
    data_quality_issues,
    data_quality_runs,
    dataset_manifest_partitions,
    dataset_manifests,
    dataset_partitions,
    ingestion_jobs,
    instrument_identifiers,
    instruments,
    market_data_admission_checks,
    market_data_admission_profiles,
    market_data_admission_runs,
    market_data_entitlements,
    market_data_sources,
    partition_quarantines,
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    universe_memberships,
    universe_versions,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
MARKET_FIXTURE = ROOT / "tests" / "fixtures" / "market_data" / "phase1_bars.jsonl"
PHASE1_TABLES_IN_DELETE_ORDER = (
    market_data_admission_checks,
    market_data_admission_runs,
    market_data_admission_profiles,
    dataset_manifest_partitions,
    dataset_manifests,
    partition_quarantines,
    data_quality_issues,
    data_quality_runs,
    dataset_partitions,
    data_objects,
    ingestion_jobs,
    corporate_action_set_members,
    corporate_action_sets,
    corporate_action_revisions,
    calendar_sessions,
    calendar_versions,
    universe_memberships,
    universe_versions,
    instrument_identifiers,
    instruments,
    market_data_entitlements,
    market_data_sources,
)


def _clear_phase1_catalog(engine: Engine) -> None:
    with engine.begin() as connection:
        for table in PHASE1_TABLES_IN_DELETE_ORDER:
            connection.execute(sa.delete(table))


@pytest.fixture
def postgres_engine() -> Iterator[Engine]:
    """Migrate an explicitly selected PostgreSQL test database to head."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL concurrency tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    # migrations/env.py intentionally gives AQT_DATABASE_URL precedence. Pin it
    # temporarily so an unrelated development database cannot override the
    # explicit test database selected above.
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")

    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.mark.parametrize("race_iteration", range(5))
def test_concurrent_reservations_cannot_exceed_account_capacity(
    postgres_engine: Engine,
    race_iteration: int,
) -> None:
    run_token = uuid4().hex
    account_id = f"pytest-risk-{race_iteration}-{run_token}"
    intent_ids = (f"pg1-{run_token}", f"pg2-{run_token}")
    base = WalkingThread.run()
    intents = (
        replace(base.intent, intent_id=intent_ids[0], target_id=f"pt1-{run_token}"),
        replace(base.intent, intent_id=intent_ids[1], target_id=f"pt2-{run_token}"),
    )
    snapshot = RiskAccountSnapshot(
        account_id=account_id,
        version="cash-v1",
        available_cash=Decimal("1500"),
    )
    limits = RiskLimits(
        allowed_instruments=frozenset({WalkingThread.instrument_id}),
        max_order_quantity=Decimal("100"),
        max_order_notional=Decimal("25000"),
        minimum_cash_buffer=Decimal("0"),
    )
    evaluated_at = base.risk_decision.evaluated_at
    start_together = threading.Barrier(3)

    def issue(index: int) -> DecisionStatus:
        start_together.wait(timeout=10)
        # Separate adapters model independent request/worker instances sharing
        # only PostgreSQL as the serialization boundary.
        authority = RiskAuthority(
            limits=limits,
            account_snapshots=FixedRiskAccountSnapshotProvider(snapshot),
            evaluation_clock=FixedClock(evaluated_at),
            consumption_clock=FixedClock(base.order.submitted_at),
        )
        decision = SqlRiskDecisionRepository(postgres_engine, authority).authorize(intents[index])
        return decision.status

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(issue, index) for index in range(2)]
            start_together.wait(timeout=10)
            statuses = [future.result(timeout=20) for future in futures]

        assert sorted(status.value for status in statuses) == ["approved", "rejected"]

        with postgres_engine.connect() as connection:
            guard = (
                connection.execute(
                    sa.select(risk_account_guards).where(
                        risk_account_guards.c.account_id == account_id
                    )
                )
                .mappings()
                .one()
            )
            persisted_statuses = connection.scalars(
                sa.select(risk_decisions.c.status)
                .where(risk_decisions.c.intent_id.in_(intent_ids))
                .order_by(risk_decisions.c.status)
            ).all()
            reservation_total = connection.scalar(
                sa.select(sa.func.coalesce(sa.func.sum(risk_reservations.c.cash_amount), 0)).where(
                    risk_reservations.c.account_id == account_id
                )
            )
            reservation_count = connection.scalar(
                sa.select(sa.func.count())
                .select_from(risk_reservations)
                .where(risk_reservations.c.account_id == account_id)
            )

        available_cash = Decimal(str(guard["available_cash"]))
        reserved_cash = Decimal(str(guard["reserved_cash"]))
        assert persisted_statuses == ["approved", "rejected"]
        assert reservation_count == 1
        assert Decimal(str(reservation_total)) == Decimal("1001")
        assert reserved_cash == Decimal("1001")
        assert reserved_cash <= available_cash == Decimal("1500")
    finally:
        # Remove only facts namespaced by this test invocation. Alembic state and
        # every unrelated account remain untouched.
        with postgres_engine.begin() as connection:
            connection.execute(
                sa.delete(risk_reservations).where(risk_reservations.c.account_id == account_id)
            )
            connection.execute(
                sa.delete(risk_decisions).where(risk_decisions.c.intent_id.in_(intent_ids))
            )
            connection.execute(
                sa.delete(risk_account_guards).where(risk_account_guards.c.account_id == account_id)
            )


def test_concurrent_identical_ingestion_publishes_one_manifest(
    postgres_engine: Engine,
    tmp_path: Path,
) -> None:
    _clear_phase1_catalog(postgres_engine)
    start_together = threading.Barrier(3)

    def ingest() -> bool:
        start_together.wait(timeout=10)
        return ingest_recorded_fixture(
            engine=postgres_engine,
            data_lake_path=tmp_path / "lake",
            source_path=MARKET_FIXTURE,
        ).first_publication

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(ingest) for _ in range(2)]
            start_together.wait(timeout=10)
            outcomes = [future.result(timeout=30) for future in futures]

        assert sorted(outcomes) == [False, True]
        with postgres_engine.connect() as connection:
            assert connection.scalar(sa.select(sa.func.count()).select_from(ingestion_jobs)) == 1
            assert connection.scalar(sa.select(sa.func.count()).select_from(dataset_manifests)) == 1
            assert (
                connection.scalar(sa.select(sa.func.count()).select_from(dataset_partitions)) == 3
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(market_data_admission_runs)
                )
                == 1
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(market_data_admission_checks)
                )
                == 18
            )
    finally:
        _clear_phase1_catalog(postgres_engine)
