"""PostgreSQL proofs for durable trusted-time fencing and exact-head CAS."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url
from sqlalchemy.exc import IntegrityError

from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.domain.trusted_time import evaluate_trusted_time
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    create_database_engine,
)
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import (
    SqlTrustedTimeRepository,
    TrustedTimePersistenceConflict,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
BASE = datetime(2026, 7, 31, 18, 0, tzinfo=UTC)
AUTHORITY = "a" * 64


@pytest.fixture
def postgres_engine() -> Iterator[Engine]:
    """Migrate only the explicitly designated PostgreSQL test database."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL trusted-time tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    # migrations/env.py gives AQT_DATABASE_URL precedence. Pin it to the
    # designated test URL so an unrelated runtime DSN cannot override this run.
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")

    engine = create_database_engine(database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                == EXPECTED_SCHEMA_REVISION
            )
        yield engine
    finally:
        engine.dispose()


def _register(
    repository: SqlTrustedTimeRepository,
    *,
    host_id: str,
    recorded_at: datetime,
):
    return repository.register_new_epoch(
        source_id="trusted-source-1",
        source_authority_sha256=AUTHORITY,
        host_id=host_id,
        recorded_at=recorded_at,
    )


def _unavailable_result(
    *,
    prior,
    evaluated_at_utc: datetime,
    evaluated_at_monotonic_ns: int,
) -> TrustedTimeMonitorResult:
    return TrustedTimeMonitorResult(
        status=TrustedTimeProbeStatus.SOURCE_UNAVAILABLE,
        evaluation=evaluate_trusted_time(
            prior,
            None,
            evaluated_at_utc=evaluated_at_utc,
            evaluated_at_monotonic_ns=evaluated_at_monotonic_ns,
        ),
    )


def _cleanup_host(engine: Engine, host_id: str) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.delete(phase6_trusted_time_host_heads).where(
                phase6_trusted_time_host_heads.c.host_id == host_id
            )
        )
        connection.execute(
            sa.delete(phase6_trusted_time_probe_evaluations).where(
                phase6_trusted_time_probe_evaluations.c.host_id == host_id
            )
        )
        connection.execute(
            sa.delete(phase6_trusted_time_epoch_registrations).where(
                phase6_trusted_time_epoch_registrations.c.host_id == host_id
            )
        )


def test_postgres_concurrent_preparations_commit_one_cas_winner(
    postgres_engine: Engine,
) -> None:
    host_id = f"pytest-time-cas-{uuid4().hex}"
    repository = SqlTrustedTimeRepository(postgres_engine)
    session = _register(repository, host_id=host_id, recorded_at=BASE)
    start_append = threading.Barrier(3)

    def append_one() -> str:
        prepared = repository.prepare_probe(session)
        result = _unavailable_result(
            prior=prepared.prior,
            evaluated_at_utc=BASE + timedelta(seconds=1),
            evaluated_at_monotonic_ns=1_000_000_000,
        )
        start_append.wait(timeout=10)
        try:
            repository.append_probe(
                session,
                prepared=prepared,
                result=result,
            )
        except TrustedTimePersistenceConflict:
            return "lost"
        return "won"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(append_one) for _ in range(2)]
            start_append.wait(timeout=10)
            outcomes = [future.result(timeout=20) for future in futures]

        assert sorted(outcomes) == ["lost", "won"]
        with postgres_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(phase6_trusted_time_probe_evaluations)
                    .where(phase6_trusted_time_probe_evaluations.c.host_id == host_id)
                )
                == 1
            )
            head = (
                connection.execute(
                    sa.select(phase6_trusted_time_host_heads).where(
                        phase6_trusted_time_host_heads.c.host_id == host_id
                    )
                )
                .mappings()
                .one()
            )
        assert head["evaluation_sequence"] == 1
        assert head["evaluation_record_sha256"] is not None
        repository.verify_integrity()
    finally:
        _cleanup_host(postgres_engine, host_id)


def test_postgres_epoch_rotation_fences_prepared_old_epoch_and_enforces_tip_fk(
    postgres_engine: Engine,
) -> None:
    host_id = f"pytest-time-rotate-{uuid4().hex}"
    first_repository = SqlTrustedTimeRepository(postgres_engine)
    second_repository = SqlTrustedTimeRepository(postgres_engine)
    first_session = _register(
        first_repository,
        host_id=host_id,
        recorded_at=BASE,
    )
    stale_preparation = first_repository.prepare_probe(first_session)
    stale_result = _unavailable_result(
        prior=stale_preparation.prior,
        evaluated_at_utc=BASE + timedelta(seconds=1),
        evaluated_at_monotonic_ns=1_000_000_000,
    )

    try:
        second_session = _register(
            second_repository,
            host_id=host_id,
            recorded_at=BASE + timedelta(seconds=2),
        )
        with pytest.raises(TrustedTimePersistenceConflict, match="head changed"):
            first_repository.append_probe(
                first_session,
                prepared=stale_preparation,
                result=stale_result,
            )
        fresh = second_repository.prepare_probe(second_session)
        assert fresh.prior is None
        assert fresh.next_evaluation_sequence == 1

        # The sequence-zero host head is physically bound to the exact epoch
        # tuple; PostgreSQL must reject deletion before repository replay runs.
        with postgres_engine.connect() as connection:
            transaction = connection.begin()
            with pytest.raises(IntegrityError):
                connection.execute(
                    sa.delete(phase6_trusted_time_epoch_registrations).where(
                        phase6_trusted_time_epoch_registrations.c.host_id == host_id
                    )
                )
            transaction.rollback()

        with postgres_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(phase6_trusted_time_epoch_registrations)
                    .where(phase6_trusted_time_epoch_registrations.c.host_id == host_id)
                )
                == 2
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(phase6_trusted_time_probe_evaluations)
                    .where(phase6_trusted_time_probe_evaluations.c.host_id == host_id)
                )
                == 0
            )
        second_repository.verify_integrity()
    finally:
        _cleanup_host(postgres_engine, host_id)
