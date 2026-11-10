from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from apps.api.backtest_views import LOCAL_SESSION_COOKIE
from apps.api.config import Settings
from apps.api.contracts import EnvironmentMode
from apps.api.main import create_app
from apps.api.operations_views import DurableLocalOperationsQuery
from packages.application.local_operations import (
    DatabaseOnlyOperationalControlService,
    LocalCoordinatorStatus,
    LocalOperationsSnapshotError,
)
from packages.domain.account_coordinator import AccountLease
from packages.domain.critical_alert import (
    CriticalAlertConflict,
    create_critical_alert_incident,
)
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlError,
    OperationalControlState,
)
from packages.persistence.account_coordinator import immutable_account_lease_values
from packages.persistence.critical_alert import SqlCriticalAlertRepository
from packages.persistence.database import (
    create_database_engine,
)
from packages.persistence.local_operations import SqlLocalOperationsSnapshotReader
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import (
    metadata,
    phase2_account_lease_heads,
    phase5_critical_alert_incidents,
    phase5_operational_control_heads,
)

BASE = datetime(2026, 7, 28, 18, 0, tzinfo=UTC)
ACCOUNT = "phase5f-composed-account"


@dataclass(slots=True)
class MutableClock:
    instant: datetime = BASE

    def now(self) -> datetime:
        return self.instant

    def __call__(self) -> datetime:
        return self.instant


def _engine(path: Path) -> sa.Engine:
    engine = create_database_engine(f"sqlite+pysqlite:///{path}")
    metadata.create_all(engine)
    return engine


def _active_lease(engine: sa.Engine) -> AccountLease:
    lease = AccountLease(
        account_id=ACCOUNT,
        owner_id="coordinator-process-1",
        lease_id="coordinator-lease-1",
        fencing_generation=1,
        revision_number=1,
        previous_lease_sha256=None,
        acquired_at=BASE,
        heartbeat_at=BASE,
        expires_at=BASE + timedelta(seconds=30),
        policy_sha256="a" * 64,
    )
    with engine.begin() as connection:
        connection.execute(
            sa.insert(
                next(
                    table
                    for table in metadata.tables.values()
                    if table.name == "phase2_account_leases"
                )
            ).values(**immutable_account_lease_values(lease))
        )
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=ACCOUNT,
                last_fencing_generation=1,
                current_fencing_generation=1,
                current_lease_sha256=lease.semantic_sha256,
                updated_at=BASE,
            )
        )
    return lease


def _initialize_control(
    engine: sa.Engine,
    clock: MutableClock,
) -> SqlOperationalControlRepository:
    repository = SqlOperationalControlRepository(engine=engine, clock=clock)
    repository.apply(
        OperationalControlCommand(
            scope_id=ACCOUNT,
            idempotency_key="initialize-control-0001",
            kind=OperationalControlCommandKind.INITIALIZE_HALTED,
            target_state=OperationalControlState.HALTED,
            actor=OperationalControlActor(
                actor_id="bootstrap",
                kind=OperationalControlActorKind.SYSTEM,
                authority_sha256="b" * 64,
                authenticated_at=None,
            ),
            reason_code="startup-fail-closed",
            reason_evidence_sha256="c" * 64,
            requested_at=BASE,
        )
    )
    return repository


def test_sql_overview_authenticates_allowlisted_facts_and_never_claims_ready(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "overview.sqlite")
    lease = _active_lease(engine)
    clock = MutableClock()
    _initialize_control(engine, clock)
    incident = create_critical_alert_incident(
        scope_id=ACCOUNT,
        source_id="strategy-supervisor",
        idempotency_key="critical-incident-0001",
        alert_code="strategy-process-failed",
        evidence_sha256="d" * 64,
        detected_at=BASE,
        recorded_at=BASE,
        correlation_sha256="e" * 64,
    )
    SqlCriticalAlertRepository(engine=engine, clock=clock).record_incident(incident)

    query = DurableLocalOperationsQuery(
        reader=SqlLocalOperationsSnapshotReader(engine),
        environment_name="Local durable operations",
        environment_mode=EnvironmentMode.LOCAL,
        loopback_only=True,
    )
    response = query.overview(ACCOUNT, as_of=BASE + timedelta(seconds=1))

    assert response.coordinator.owner_id == lease.owner_id
    assert response.coordinator.fencing_generation == 1
    assert response.control is not None
    assert response.control.effective_state is OperationalControlState.HALTED
    assert response.readiness.status.value == "halted"
    assert "authoritative reconciliation readiness is unavailable" in response.readiness.reasons
    assert response.current_risk_assignment is None
    assert response.current_risk_assessment is None
    assert len(response.active_alerts) == 1
    assert response.active_alerts[0].primary_delivery_state.value == "unknown"
    serialized = response.model_dump_json()
    for forbidden in (
        "canonical_payload",
        "evidence_sha256",
        "authority_sha256",
        "lease_id",
        "raw_payload",
        "provider_receipt",
    ):
        assert forbidden not in serialized


def test_sql_reader_reports_absence_without_creating_account_control(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "absent.sqlite")
    snapshot = SqlLocalOperationsSnapshotReader(engine).read(ACCOUNT, as_of=BASE)

    assert snapshot.coordinator_status is LocalCoordinatorStatus.ABSENT
    assert snapshot.current_lease is None
    assert snapshot.control is None
    assert snapshot.control_history == ()
    assert snapshot.active_alerts == ()
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_account_lease_heads))
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_operational_control_heads)
            )
            == 0
        )


def test_database_only_control_enforces_pause_halt_boundary_and_exact_retries(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "control.sqlite")
    _active_lease(engine)
    clock = MutableClock()
    repository = _initialize_control(engine, clock)
    clock.instant = BASE + timedelta(seconds=1)
    service = DatabaseOnlyOperationalControlService(
        repository=repository,
        actor_authority_sha256="f" * 64,
        clock=clock,
    )

    for unavailable in (
        OperationalControlCommandKind.DRAIN,
        OperationalControlCommandKind.FLATTEN,
        OperationalControlCommandKind.REARM,
    ):
        with pytest.raises(OperationalControlError, match="only PAUSE and HALT"):
            service.execute(
                account_id=ACCOUNT,
                operator_id="local-operator",
                idempotency_key=f"blocked-{unavailable.value}-0001",
                kind=unavailable,
                reason_code="operator-requested",
            )

    pause = service.execute(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="pause-control-0001",
        kind=OperationalControlCommandKind.PAUSE,
        reason_code="operator-requested",
    )
    retry = service.execute(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="pause-control-0001",
        kind=OperationalControlCommandKind.PAUSE,
        reason_code="operator-requested",
    )
    clock.instant = BASE + timedelta(seconds=2)
    halted = service.execute(
        account_id=ACCOUNT,
        operator_id="local-operator",
        idempotency_key="halt-control-0001",
        kind=OperationalControlCommandKind.HALT,
        reason_code="operator-requested",
    )

    assert retry == pause
    assert halted.sequence_number == pause.sequence_number + 1
    assert halted.effective_state is OperationalControlState.HALTED


def test_corrupt_alert_payload_fails_closed_instead_of_leaking_partial_view(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path / "corrupt.sqlite")
    clock = MutableClock()
    incident = create_critical_alert_incident(
        scope_id=ACCOUNT,
        source_id="risk-engine",
        idempotency_key="critical-incident-0002",
        alert_code="risk-trip",
        evidence_sha256="1" * 64,
        detected_at=BASE,
        recorded_at=BASE,
        correlation_sha256="2" * 64,
    )
    SqlCriticalAlertRepository(engine=engine, clock=clock).record_incident(incident)
    with engine.begin() as connection:
        connection.execute(
            sa.update(phase5_critical_alert_incidents)
            .where(phase5_critical_alert_incidents.c.incident_id == incident.incident_id)
            .values(canonical_payload='{"tampered":true}')
        )

    with pytest.raises(CriticalAlertConflict):
        SqlLocalOperationsSnapshotReader(engine).read(ACCOUNT, as_of=BASE)


def test_reader_rejects_future_retained_facts_and_non_utc_as_of(
    tmp_path: Path,
) -> None:
    lease_engine = _engine(tmp_path / "future-lease.sqlite")
    _active_lease(lease_engine)
    reader = SqlLocalOperationsSnapshotReader(lease_engine)
    with pytest.raises(LocalOperationsSnapshotError, match="later than the snapshot"):
        reader.read(ACCOUNT, as_of=BASE - timedelta(microseconds=1))
    with pytest.raises(LocalOperationsSnapshotError, match="must be UTC"):
        reader.read(
            ACCOUNT,
            as_of=BASE.astimezone(timezone(timedelta(hours=-4))),
        )

    absent_engine = _engine(tmp_path / "future-absent-coordinator.sqlite")
    with absent_engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=ACCOUNT,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=BASE + timedelta(microseconds=1),
            )
        )
    with pytest.raises(LocalOperationsSnapshotError, match="later than the snapshot"):
        SqlLocalOperationsSnapshotReader(absent_engine).read(
            ACCOUNT,
            as_of=BASE,
        )

    incident_engine = _engine(tmp_path / "future-incident.sqlite")
    incident = create_critical_alert_incident(
        scope_id=ACCOUNT,
        source_id="risk-engine",
        idempotency_key="critical-incident-0003",
        alert_code="future-risk-trip",
        evidence_sha256="3" * 64,
        detected_at=BASE,
        recorded_at=BASE,
        correlation_sha256="4" * 64,
    )
    SqlCriticalAlertRepository(
        engine=incident_engine,
        clock=MutableClock(),
    ).record_incident(incident)
    with pytest.raises(LocalOperationsSnapshotError, match="later than the snapshot"):
        SqlLocalOperationsSnapshotReader(incident_engine).read(
            ACCOUNT,
            as_of=BASE - timedelta(microseconds=1),
        )


def test_main_composes_only_durable_authenticated_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path / "main.sqlite")
    monkeypatch.setattr(
        "apps.api.main.verify_operational_schema",
        lambda *_args, **_kwargs: None,
    )
    app = create_app(Settings(), engine=engine)
    assert isinstance(app.state.operations_query, DurableLocalOperationsQuery)
    assert isinstance(
        app.state.operations_control,
        DatabaseOnlyOperationalControlService,
    )
    assert app.state.operations_query.runtime_store_identity == id(engine)
    assert app.state.operations_control.runtime_store_identity == id(engine)

    client = TestClient(app)
    bootstrap = client.get("/api/v1/ui/bootstrap")
    assert bootstrap.status_code == 200
    payload = bootstrap.json()
    assert payload["feature_flags"]["operations_query"] is True
    assert payload["feature_flags"]["operations_control"] is True
    assert payload["feature_flags"]["controls"] is False
    assert payload["feature_flags"]["control_pause"] is True
    assert payload["feature_flags"]["control_halt"] is True
    assert payload["feature_flags"]["control_drain"] is False
    assert payload["feature_flags"]["control_flatten"] is False
    assert payload["feature_flags"]["control_rearm"] is False

    csrf = payload["backtest_launch"]["csrf_token"]
    assert isinstance(csrf, str)
    assert client.cookies.get(LOCAL_SESSION_COOKIE) is not None
    overview = client.get(
        f"/api/v1/operations/accounts/{ACCOUNT}",
        headers={"X-CSRF-Token": csrf},
    )
    assert overview.status_code == 200
    assert overview.json()["coordinator"]["status"] == "absent"

    absent_halt = client.post(
        f"/api/v1/operations/accounts/{ACCOUNT}/control/halt",
        json={"reason_code": "operator-requested"},
        headers={
            "X-CSRF-Token": csrf,
            "Idempotency-Key": "halt-without-initialize-0001",
        },
    )
    assert absent_halt.status_code == 409
    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_account_lease_heads))
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase5_operational_control_heads)
            )
            == 0
        )
