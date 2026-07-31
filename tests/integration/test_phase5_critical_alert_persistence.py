from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from packages.domain.critical_alert import (
    CriticalAlertConflict,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertIncident,
    CriticalAlertIncidentScanCursor,
    CriticalAlertRoute,
    record_critical_alert_delivery_result,
)
from packages.persistence.critical_alert import (
    SqlCriticalAlertRepository,
    verify_critical_alert_integrity,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    metadata,
    phase5_critical_alert_delivery_attempts,
    phase5_critical_alert_delivery_results,
    phase5_critical_alert_incidents,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 7, 28, 19, 0, tzinfo=UTC)
ALERT_TABLE_NAMES = frozenset(
    {
        "phase5_critical_alert_delivery_attempts",
        "phase5_critical_alert_delivery_results",
        "phase5_critical_alert_incidents",
    }
)


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


def _engine(path: Path) -> Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    return engine


def _incident() -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id="paper-account-1",
        source_id="strategy-supervisor",
        idempotency_key="incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )


def _command(
    incident: CriticalAlertIncident,
    *,
    requested_at: datetime,
    request_sha256: str = "c" * 64,
    route: CriticalAlertRoute = CriticalAlertRoute.PRIMARY,
    key: str = "delivery-0001",
) -> CriticalAlertDeliveryCommand:
    return CriticalAlertDeliveryCommand(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        route=route,
        provider_id="pager-provider",
        idempotency_key=key,
        request_sha256=request_sha256,
        requested_at=requested_at,
    )


def _repository(
    engine: Engine,
) -> tuple[SqlCriticalAlertRepository, MutableClock, CriticalAlertIncident]:
    clock = MutableClock(BASE)
    repository = SqlCriticalAlertRepository(engine=engine, clock=clock)
    incident = _incident()
    assert repository.record_incident(incident) == incident
    return repository, clock, incident


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_incident_attempt_and_result_round_trip_with_integrity(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "round-trip.sqlite")
    repository, clock, incident = _repository(engine)
    assert repository.record_incident(incident) == incident
    with pytest.raises(CriticalAlertConflict, match="idempotency key conflicts"):
        repository.record_incident(replace(incident, evidence_sha256="f" * 64))

    clock.instant = BASE + timedelta(seconds=1)
    delivery_command = _command(incident, requested_at=clock.instant)
    attempt, created = repository.claim_delivery_attempt(delivery_command)
    assert created is True
    assert repository.claim_delivery_attempt(delivery_command) == (attempt, False)

    clock.instant = BASE + timedelta(seconds=2)
    result = record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
        completed_at=clock.instant,
        elapsed_microseconds=1_000_000,
        provider_receipt_sha256="d" * 64,
    )
    assert repository.record_delivery_result(result) == result
    assert repository.record_delivery_result(result) == result
    assert repository.load_incident(incident.incident_id) == incident
    assert repository.load_delivery_result(attempt.attempt_id) == result
    assert repository.load_delivery_history(incident.incident_id) == (
        (attempt,),
        (result,),
    )
    verify_critical_alert_integrity(engine)


def test_same_provider_key_concurrent_claims_converge_despite_distinct_request_times(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "concurrent-claim.sqlite")
    repository, clock, incident = _repository(engine)
    clock.instant = BASE + timedelta(seconds=2)
    commands = (
        _command(incident, requested_at=BASE + timedelta(seconds=1)),
        _command(
            incident,
            requested_at=BASE + timedelta(seconds=1, microseconds=1),
        ),
    )
    barrier = Barrier(2)

    def claim(
        delivery_command: CriticalAlertDeliveryCommand,
    ) -> tuple[object, bool]:
        barrier.wait(timeout=10)
        return repository.claim_delivery_attempt(delivery_command)

    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = tuple(executor.map(claim, commands))

    assert {created for _, created in claims} == {False, True}
    assert claims[0][0] == claims[1][0]
    attempts, results = repository.load_delivery_history(incident.incident_id)
    assert len(attempts) == 1
    assert results == ()
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_critical_alert_delivery_attempts)
            )
            == 1
        )


def test_same_provider_key_rejects_changed_provider_request(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "claim-conflict.sqlite")
    repository, clock, incident = _repository(engine)
    clock.instant = BASE + timedelta(seconds=2)
    repository.claim_delivery_attempt(_command(incident, requested_at=BASE + timedelta(seconds=1)))

    with pytest.raises(CriticalAlertConflict, match="idempotency key conflicts"):
        repository.claim_delivery_attempt(
            _command(
                incident,
                requested_at=BASE + timedelta(seconds=1, microseconds=1),
                request_sha256="e" * 64,
            )
        )


def test_active_incident_scan_is_bounded_resumable_and_excludes_confirmation(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "active-scan.sqlite")
    clock = MutableClock(BASE)
    repository = SqlCriticalAlertRepository(engine=engine, clock=clock)
    first = _incident()
    second = replace(
        first,
        idempotency_key="incident-0002",
        detected_at=BASE - timedelta(milliseconds=50),
        recorded_at=BASE + timedelta(microseconds=1),
    )
    third = replace(
        first,
        idempotency_key="incident-0003",
        detected_at=BASE - timedelta(milliseconds=25),
        recorded_at=BASE + timedelta(microseconds=2),
    )
    for incident in (first, second, third):
        clock.instant = incident.recorded_at
        assert repository.record_incident(incident) == incident

    clock.instant = BASE + timedelta(seconds=1)
    attempt, created = repository.claim_delivery_attempt(
        _command(first, requested_at=clock.instant)
    )
    assert created is True
    clock.instant = BASE + timedelta(seconds=2)
    repository.record_delivery_result(
        record_critical_alert_delivery_result(
            incident=first,
            attempt=attempt,
            outcome=CriticalAlertDeliveryOutcome.CONFIRMED,
            completed_at=clock.instant,
            elapsed_microseconds=1_000_000,
            provider_receipt_sha256="d" * 64,
        )
    )

    first_page = repository.scan_active_incidents(
        as_of=BASE + timedelta(seconds=3),
        after=None,
        limit=2,
    )
    assert first_page.scanned_count == 2
    assert first_page.incidents == (second,)
    assert first_page.resume_after == CriticalAlertIncidentScanCursor(
        recorded_at=second.recorded_at,
        incident_id=second.incident_id,
    )

    second_page = repository.scan_active_incidents(
        as_of=BASE + timedelta(seconds=3),
        after=first_page.resume_after,
        limit=2,
    )
    assert second_page.scanned_count == 1
    assert second_page.incidents == (third,)
    assert second_page.resume_after is None


def test_tampering_fails_repository_integrity_and_operational_readiness(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "readiness.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = _alembic_config(database_url)
    alembic_command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    _repository_instance, _, incident = _repository(engine)
    verify_operational_schema(engine, require_phase_zero_facts=False)

    with engine.begin() as connection:
        connection.execute(
            sa.update(phase5_critical_alert_incidents)
            .where(phase5_critical_alert_incidents.c.incident_id == incident.incident_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(CriticalAlertConflict, match="canonical_payload"):
        verify_critical_alert_integrity(engine)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="critical-alert integrity",
    ):
        verify_operational_schema(engine, require_phase_zero_facts=False)


def test_0027_migration_is_additive_and_reversible_only_when_empty(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "migration.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = _alembic_config(database_url)
    alembic_command.upgrade(config, "0026_phase5_advanced_risk")
    engine = create_database_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())

    alembic_command.upgrade(config, "0027_phase5_critical_alerts")
    assert set(inspect(engine).get_table_names()) == prior_tables | ALERT_TABLE_NAMES
    assert tuple(
        column["name"] for column in inspect(engine).get_columns("phase5_critical_alert_incidents")
    ) == tuple(phase5_critical_alert_incidents.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase5_critical_alert_delivery_attempts")
    ) == tuple(phase5_critical_alert_delivery_attempts.c.keys())
    assert tuple(
        column["name"]
        for column in inspect(engine).get_columns("phase5_critical_alert_delivery_results")
    ) == tuple(phase5_critical_alert_delivery_results.c.keys())

    engine.dispose()
    alembic_command.downgrade(config, "0026_phase5_advanced_risk")
    engine = create_database_engine(database_url)
    assert set(inspect(engine).get_table_names()) == prior_tables

    engine.dispose()
    alembic_command.upgrade(config, "0027_phase5_critical_alerts")
    engine = create_database_engine(database_url)
    _repository(engine)
    engine.dispose()
    with pytest.raises(RuntimeError, match="nonempty critical-alert history"):
        alembic_command.downgrade(config, "0026_phase5_advanced_risk")
