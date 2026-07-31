from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

import packages.persistence.trusted_time as trusted_time_persistence
from packages.application.durable_trusted_time_monitor import (
    DurableTrustedTimeEpochSession,
)
from packages.application.trusted_time_monitor import (
    TrustedTimeMonitorBinding,
    TrustedTimeMonitorResult,
    TrustedTimeProbeStatus,
)
from packages.domain.trusted_time import evaluate_trusted_time
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import (
    SqlTrustedTimeRepository,
    TrustedTimePersistenceConflict,
    TrustedTimePersistenceError,
    verify_trusted_time_integrity,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 7, 31, 16, 0, tzinfo=UTC)
AUTHORITY = "a" * 64


def _engine(path: Path) -> Engine:
    database_url = f"sqlite+pysqlite:///{path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
    return engine


def _register(
    repository: SqlTrustedTimeRepository,
    *,
    host_id: str,
    recorded_at: datetime = BASE,
) -> DurableTrustedTimeEpochSession:
    return repository.register_new_epoch(
        source_id="injected-source",
        source_authority_sha256=AUTHORITY,
        host_id=host_id,
        recorded_at=recorded_at,
    )


def test_issued_session_cannot_be_retargeted_to_another_active_host(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "session-retarget.sqlite")
    repository = SqlTrustedTimeRepository(engine)
    first = _register(repository, host_id="paper-host-a")
    second = _register(repository, host_id="paper-host-b")

    object.__setattr__(first, "binding", second.binding)
    object.__setattr__(
        first,
        "epoch_registration_sha256",
        second.epoch_registration_sha256,
    )

    with pytest.raises(
        TrustedTimePersistenceConflict,
        match="session identity was modified",
    ):
        repository.prepare_probe(first)

    prepared = repository.prepare_probe(second)
    assert prepared.binding == second.binding
    engine.dispose()


def test_same_repository_concurrent_rotations_leave_latest_session_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path / "registration-order.sqlite")
    repository = SqlTrustedTimeRepository(engine)
    original_factory = trusted_time_persistence._new_durable_trusted_time_epoch_session
    first_at_factory = threading.Event()
    second_at_factory = threading.Event()
    call_lock = threading.Lock()
    factory_calls = 0

    def delayed_factory(
        *,
        binding: TrustedTimeMonitorBinding,
        epoch_registration_sha256: str,
    ) -> DurableTrustedTimeEpochSession:
        nonlocal factory_calls
        with call_lock:
            factory_calls += 1
            call_number = factory_calls
        if call_number == 1:
            first_at_factory.set()
            second_at_factory.wait(timeout=1)
        else:
            second_at_factory.set()
        return original_factory(
            binding=binding,
            epoch_registration_sha256=epoch_registration_sha256,
        )

    monkeypatch.setattr(
        trusted_time_persistence,
        "_new_durable_trusted_time_epoch_session",
        delayed_factory,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            _register,
            repository,
            host_id="paper-host-race",
            recorded_at=BASE,
        )
        assert first_at_factory.wait(timeout=5)
        second_future = executor.submit(
            _register,
            repository,
            host_id="paper-host-race",
            recorded_at=BASE + timedelta(seconds=1),
        )
        first = first_future.result(timeout=10)
        second = second_future.result(timeout=10)

    with pytest.raises(
        TrustedTimePersistenceConflict,
        match="session is not active",
    ):
        repository.prepare_probe(first)
    prepared = repository.prepare_probe(second)
    assert prepared.binding.monitor_epoch_id == second.binding.monitor_epoch_id

    with engine.connect() as connection:
        persisted = connection.execute(
            sa.select(
                phase6_trusted_time_epoch_registrations.c.monitor_epoch_id,
                phase6_trusted_time_epoch_registrations.c.epoch_sequence,
            ).where(phase6_trusted_time_epoch_registrations.c.host_id == "paper-host-race")
        ).all()
    sequences = {monitor_epoch_id: sequence for monitor_epoch_id, sequence in persisted}
    assert sequences[first.binding.monitor_epoch_id] == 1
    assert sequences[second.binding.monitor_epoch_id] == 2
    engine.dispose()


def test_integrity_rejects_non_text_sqlite_host_identity(tmp_path: Path) -> None:
    engine = _engine(tmp_path / "non-text-host.sqlite")
    repository = SqlTrustedTimeRepository(engine)
    _register(repository, host_id="paper-host-bytes")

    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        with connection.begin():
            connection.exec_driver_sql(
                "UPDATE phase6_trusted_time_epoch_registrations SET host_id = CAST(host_id AS BLOB)"
            )
            connection.exec_driver_sql(
                "UPDATE phase6_trusted_time_host_heads SET host_id = CAST(host_id AS BLOB)"
            )
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()

    with pytest.raises(
        TrustedTimePersistenceError,
        match="host ID must be text",
    ):
        verify_trusted_time_integrity(engine)
    engine.dispose()


def test_integrity_rejects_foreign_epoch_evaluation_with_valid_host(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "foreign-epoch-evaluation.sqlite")
    repository = SqlTrustedTimeRepository(engine)
    session = _register(repository, host_id="paper-host-orphan")
    prepared = repository.prepare_probe(session)
    result = TrustedTimeMonitorResult(
        status=TrustedTimeProbeStatus.SOURCE_UNAVAILABLE,
        evaluation=evaluate_trusted_time(
            None,
            None,
            evaluated_at_utc=BASE + timedelta(seconds=1),
            evaluated_at_monotonic_ns=1_000_000_000,
        ),
    )
    repository.append_probe(session, prepared=prepared, result=result)

    with engine.connect() as connection:
        original = (
            connection.execute(sa.select(phase6_trusted_time_probe_evaluations)).mappings().one()
        )
    orphan = dict(original)
    orphan.update(
        {
            "evaluation_id": "88888888-8888-8888-8888-888888888888",
            "monitor_epoch_id": "99999999-9999-9999-9999-999999999999",
            "semantic_sha256": "9" * 64,
        }
    )
    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(sa.insert(phase6_trusted_time_probe_evaluations).values(**orphan))

    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        with connection.begin():
            connection.execute(sa.insert(phase6_trusted_time_probe_evaluations).values(**orphan))
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        connection.commit()

    with pytest.raises(
        TrustedTimePersistenceError,
        match="unknown host epoch",
    ):
        verify_trusted_time_integrity(engine)

    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_probe_evaluations)
            )
            == 2
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_host_heads)
            )
            == 1
        )
    engine.dispose()
