"""PostgreSQL proofs for durable trusted-time fencing and exact-head CAS."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url
from sqlalchemy.exc import IntegrityError

from packages.application.durable_trusted_time_monitor import (
    DurableTrustedTimeEpochSession,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
    TrustedTimeSourceReading,
    run_trusted_time_probe,
)
from packages.domain.trusted_time import TrustedTimeState, evaluate_trusted_time
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, create_database_engine
from packages.persistence.postgres_tls import is_supabase_session_pooler_url
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import (
    SqlTrustedTimeRepository,
    TrustedTimePersistenceConflict,
)
from scripts.migrate_phase6_trusted_time_uncertainty import (
    PRIOR_REVISION,
    TARGET_REVISION,
    check_static_bindings,
    collect_catalog_snapshot,
    run_exact_migration,
    verify_postflight_catalog,
    verify_preflight_catalog,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
BASE = datetime(2026, 7, 31, 18, 0, tzinfo=UTC)
AUTHORITY = "a" * 64


class _RecordedSource:
    def __init__(self, reading: TrustedTimeSourceReading) -> None:
        self._reading = reading

    def read_trusted_time(
        self,
        *,
        deadline_monotonic_ns: int,
    ) -> TrustedTimeSourceReading:
        assert deadline_monotonic_ns == self._reading.observed_at_monotonic_ns + 1_000_000_000
        return self._reading


@pytest.fixture(scope="session")
def postgres_engine() -> Iterator[Engine]:
    """Exercise only exact 0034->0035 against the designated empty test DB."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL trusted-time tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    require_client_tls = is_supabase_session_pooler_url(make_url(database_url))

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    engine = create_database_engine(database_url)
    original_revision: str | None = None
    try:
        with engine.connect() as connection:
            revision = connection.scalar(sa.text("SELECT version_num FROM public.alembic_version"))
            original_revision = revision if isinstance(revision, str) else None
            history_count = sum(
                int(connection.scalar(sa.text(f'SELECT count(*) FROM public."{table.name}"')) or 0)
                for table in (
                    phase6_trusted_time_epoch_registrations,
                    phase6_trusted_time_probe_evaluations,
                    phase6_trusted_time_host_heads,
                )
            )
            anchor_history_count = (
                sum(
                    int(
                        connection.scalar(sa.text(f'SELECT count(*) FROM public."{table.name}"'))
                        or 0
                    )
                    for table in (
                        phase6_trusted_time_head_anchor_intents,
                        phase6_trusted_time_head_anchor_receipts,
                    )
                )
                if revision == EXPECTED_SCHEMA_REVISION
                else 0
            )
        if revision in {TARGET_REVISION, EXPECTED_SCHEMA_REVISION}:
            if history_count != 0:
                pytest.fail("designated test database has nonempty trusted-time history")
            if anchor_history_count != 0:
                pytest.fail("designated test database has nonempty trusted-time anchor history")
            engine.dispose()
            # migrations/env.py gives AQT_DATABASE_URL precedence. Pin it to the
            # designated test URL so an unrelated runtime DSN cannot override.
            with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
                command.downgrade(config, PRIOR_REVISION)
            engine = create_database_engine(database_url)
        elif revision != PRIOR_REVISION:
            pytest.fail("designated test database is not at exact revision 0034, 0035, or 0036")

        with engine.connect() as connection:
            connection.exec_driver_sql("SET LOCAL search_path TO public")
            verify_preflight_catalog(
                collect_catalog_snapshot(connection),
                require_client_tls=require_client_tls,
            )
        with engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL search_path TO public")
            run_exact_migration(connection, check_static_bindings())
        with engine.connect() as connection:
            connection.exec_driver_sql("SET LOCAL search_path TO public")
            assert (
                connection.scalar(sa.text("SELECT version_num FROM public.alembic_version"))
                == TARGET_REVISION
            )
            verify_postflight_catalog(
                collect_catalog_snapshot(connection),
                require_client_tls=require_client_tls,
            )
        yield engine
    finally:
        engine.dispose()
        if original_revision == EXPECTED_SCHEMA_REVISION:
            with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
                command.upgrade(config, EXPECTED_SCHEMA_REVISION)


def _register(
    repository: SqlTrustedTimeRepository,
    *,
    host_id: str,
    recorded_at: datetime,
) -> DurableTrustedTimeEpochSession:
    return repository.register_new_epoch(
        source_id="trusted-source-1",
        source_authority_sha256=AUTHORITY,
        host_id=host_id,
        recorded_at=recorded_at,
    )


def _unavailable_result(
    *,
    prior: TrustedTimeState | None,
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


def test_postgres_recorded_uncertainty_round_trips_exact_numeric_and_replay(
    postgres_engine: Engine,
) -> None:
    host_id = f"pytest-time-recorded-{uuid4().hex}"
    repository = SqlTrustedTimeRepository(postgres_engine)
    session = _register(repository, host_id=host_id, recorded_at=BASE)
    observed_at = BASE + timedelta(seconds=1)
    observed_monotonic_ns = 1_000_000_000
    source_uncertainty = Decimal("12.3456789012")
    reading = TrustedTimeSourceReading(
        source_id=session.binding.source_id,
        source_authority_sha256=session.binding.source_authority_sha256,
        local_observed_at_utc=observed_at,
        trusted_at_utc=observed_at + timedelta(milliseconds=2),
        observed_at_monotonic_ns=observed_monotonic_ns,
        source_uncertainty_milliseconds=source_uncertainty,
        source_evidence_sha256="b" * 64,
    )

    def utc_clock() -> datetime:
        return observed_at

    def monotonic_clock() -> int:
        return observed_monotonic_ns

    try:
        prepared = repository.prepare_probe(session)
        result = run_trusted_time_probe(
            prepared.prior,
            binding=session.binding,
            source=_RecordedSource(reading),
            utc_clock=utc_clock,
            monotonic_clock=monotonic_clock,
        )
        persisted = repository.append_probe(
            session,
            prepared=prepared,
            result=result,
        )

        assert persisted.result.status is TrustedTimeProbeStatus.RECORDED
        assert persisted.result.evaluation.sample is not None
        assert (
            persisted.result.evaluation.sample.source_uncertainty_milliseconds == source_uncertainty
        )

        columns = {
            column["name"]: column
            for column in sa.inspect(postgres_engine).get_columns(
                phase6_trusted_time_probe_evaluations.name
            )
        }
        uncertainty_type = columns["source_uncertainty_milliseconds"]["type"]
        assert isinstance(uncertainty_type, sa.Numeric)
        assert uncertainty_type.precision == 28
        assert uncertainty_type.scale == 10

        with postgres_engine.connect() as connection:
            stored = (
                connection.execute(
                    sa.select(phase6_trusted_time_probe_evaluations).where(
                        phase6_trusted_time_probe_evaluations.c.host_id == host_id
                    )
                )
                .mappings()
                .one()
            )
        assert stored["probe_status"] == "recorded"
        assert stored["source_uncertainty_milliseconds"] == source_uncertainty

        replayed = repository.prepare_probe(session)
        assert replayed.next_evaluation_sequence == 2
        assert replayed.prior == persisted.result.state
        assert replayed.prior is not None
        assert replayed.prior.latest_sample is not None
        assert replayed.prior.latest_sample.source_uncertainty_milliseconds == source_uncertainty

        SqlTrustedTimeRepository(postgres_engine).verify_integrity()
    finally:
        _cleanup_host(postgres_engine, host_id)


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
        with pytest.raises(TrustedTimePersistenceConflict, match="durable tip conflicts"):
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
