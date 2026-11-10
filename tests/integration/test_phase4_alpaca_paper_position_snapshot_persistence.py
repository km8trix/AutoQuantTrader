from __future__ import annotations

import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    create_alpaca_paper_credential_envelope,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID,
    ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotRuntimePlan,
    AlpacaPaperPositionSnapshotTransportRequest,
    AlpacaPaperPositionSnapshotTransportResponse,
    _observe_authenticated_alpaca_paper_position_snapshot_with_transport,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_view_supervisor import (
    AlpacaPaperPositionSnapshotSupervisorSourceStage,
)
from packages.domain.account_coordinator import (
    AccountLeasePolicy,
    _account_fence_receipt,
)
from packages.domain.clock import FixedClock
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    AlpacaPaperPositionSnapshotPersistenceConflict,
    SqlAlpacaPaperPositionSnapshotRepository,
    verify_alpaca_paper_position_snapshot_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_position_snapshots,
)
from tests.integration.phase4_postgres_cleanup import (
    delete_phase4_postgres_account_facts,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    ACCOUNT_ID,
    API_KEY_ID,
    BASE,
    PROVIDER_ACCOUNT_ID,
    SECRET_KEY,
    RuntimeSystem,
    SequenceClock,
    _prepare_concurrent_postgres_evidence,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    _system as _account_system,
)

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


def _position(number: int) -> dict[str, object]:
    return {
        "asset_id": str(UUID(int=number)),
        "symbol": f"ASSET{number}",
        "exchange": "NYSE",
        "asset_class": "us_equity",
        "asset_marginable": True,
        "avg_entry_price": "10.00",
        "qty": "1",
        "side": "long",
        "market_value": "10.00",
        "cost_basis": "10.00",
        "unrealized_pl": "0.00",
        "unrealized_plpc": "0.00",
        "unrealized_intraday_pl": "0.00",
        "unrealized_intraday_plpc": "0.00",
        "current_price": "10.00",
        "lastday_price": "10.00",
        "change_today": "0.00",
    }


def _body(*positions: dict[str, object]) -> bytes:
    return json.dumps(positions, separators=(",", ":")).encode()


def _lease_policy() -> AccountLeasePolicy:
    return AccountLeasePolicy(
        policy_id="phase4g-binding-integration",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )


def _runtime_instants(capture_base: datetime) -> list[datetime]:
    return [
        capture_base,
        capture_base + timedelta(milliseconds=10),
        capture_base + timedelta(milliseconds=20),
        capture_base + timedelta(milliseconds=30),
        capture_base + timedelta(milliseconds=70),
        capture_base + timedelta(milliseconds=80),
        capture_base + timedelta(milliseconds=90),
        capture_base + timedelta(milliseconds=100),
        capture_base + timedelta(milliseconds=120),
        capture_base + timedelta(milliseconds=140),
    ]


class PositionSnapshotCredentialResolver:
    resolver_id = "phase4u-integration-secret-store"
    resolver_version = "v1"

    def __init__(self) -> None:
        self.materials: list[_AlpacaPaperCredentialMaterial] = []

    def _resolve_for_position_snapshot(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        del reference
        envelope = create_alpaca_paper_credential_envelope(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )
        assert type(envelope) is _AlpacaPaperCredentialMaterial
        self.materials.append(envelope)
        return envelope


class PositionSnapshotTransport:
    transport_id = ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_ID
    transport_version = ALPACA_PAPER_POSITION_SNAPSHOT_TRANSPORT_VERSION

    def __init__(self, response_body: bytes) -> None:
        self.response_body = response_body
        self.calls = 0

    def execute(
        self,
        request: AlpacaPaperPositionSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperPositionSnapshotTransportResponse:
        self.calls += 1
        assert tuple(headers)
        return AlpacaPaperPositionSnapshotTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=200,
            provider_request_id=(f"phase4u-integration-request-{self.calls:03d}"),
            media_type=ALPACA_PAPER_POSITION_SNAPSHOT_ACCEPT_MEDIA_TYPE,
            response_body=self.response_body,
        )


class ChangedCommitLease:
    def __init__(self, delegate: SqlAccountCoordinator) -> None:
        self.delegate = delegate

    def revalidate_for_commit_in_transaction(
        self,
        connection: sa.Connection,
        fence: object,
    ) -> object:
        receipt = self.delegate.revalidate_for_commit_in_transaction(
            connection,
            fence,  # type: ignore[arg-type]
        )
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256="f" * 64,
        )


@dataclass(slots=True)
class Phase4PositionSnapshotSystem:
    account: RuntimeSystem
    binding: AlpacaPaperAuthenticatedAccountBinding
    plan: AlpacaPaperPositionSnapshotRuntimePlan
    coordinator: SqlAccountCoordinator
    repository: SqlAlpacaPaperPositionSnapshotRepository
    resolver: PositionSnapshotCredentialResolver
    ingress: SqlBrokerIngressRepository
    capture_base: datetime

    def observe(self) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        return _observe_authenticated_alpaca_paper_position_snapshot_with_transport(
            plan=self.plan,
            credential_resolver=self.resolver,
            transport=PositionSnapshotTransport(_body(_position(1))),
            budget=SqlBrokerRequestBudgetRepository(
                engine=self.account.engine,
                clock=SequenceClock(
                    [
                        self.capture_base + timedelta(milliseconds=40),
                        self.capture_base + timedelta(milliseconds=60),
                    ]
                ),
            ),
            account_bindings=self.account.bindings,
            coordinator=self.coordinator,
            fence=self.account.fence,
            ingress_recorder=self.ingress,
            snapshot_runtime=self.repository,
            clock=SequenceClock(_runtime_instants(self.capture_base)),
        )


def _system(
    database_path: Path,
    *,
    capture_base: datetime = BASE + timedelta(seconds=1),
    commit_at: datetime | None = None,
) -> Phase4PositionSnapshotSystem:
    account = _account_system(
        database_path,
        run_count=3,
        migrated=True,
    )
    binding = account.observe("phase4u-source")
    reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )
    description = create_alpaca_paper_position_snapshot_description(
        account_id=ACCOUNT_ID,
        capture_idempotency_key="phase4u-position-capture-0001",
    )
    plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=description,
        reference=reference,
        account_binding=binding,
    )
    first_commit = capture_base + timedelta(milliseconds=150) if commit_at is None else commit_at
    fence_instants = (
        capture_base + timedelta(milliseconds=50),
        capture_base + timedelta(milliseconds=110),
        capture_base + timedelta(milliseconds=130),
        first_commit,
        first_commit + timedelta(milliseconds=10),
    )
    coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=account.engine,
            policy=_lease_policy(),
            clock=SequenceClock(
                [
                    instant
                    for checked_at in fence_instants
                    for instant in (
                        checked_at,
                        checked_at + timedelta(microseconds=1),
                    )
                ]
            ),
        ),
    )
    repository = SqlAlpacaPaperPositionSnapshotRepository(
        engine=account.engine,
        coordinator=coordinator,
    )
    return Phase4PositionSnapshotSystem(
        account=account,
        binding=binding,
        plan=plan,
        coordinator=coordinator,
        repository=repository,
        resolver=PositionSnapshotCredentialResolver(),
        ingress=SqlBrokerIngressRepository(account.engine),
        capture_base=capture_base,
    )


def _alembic_config(database_path: Path) -> Config:
    return _alembic_config_for_url(f"sqlite+pysqlite:///{database_path}")


def _alembic_config_for_url(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def phase4u_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4U tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    config = _alembic_config_for_url(database_url)
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def test_old_terminal_binding_can_claim_and_exact_receipt_round_trips(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4u-round-trip.sqlite",
        capture_base=BASE + timedelta(seconds=10),
    )
    assert system.binding.valid_until < system.capture_base
    assert system.repository.load(system.plan) is None
    absent = system.repository.load_state(system.plan)
    assert absent.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
    assert absent.preparation is None
    assert absent.receipt is None

    receipt = system.observe()
    restarted = SqlAlpacaPaperPositionSnapshotRepository(
        engine=system.account.engine,
        coordinator=system.coordinator,
    )

    assert restarted.load(system.plan) == receipt
    complete = restarted.load_state(system.plan)
    assert complete.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE
    assert complete.preparation == receipt.evidence.preparation
    assert complete.receipt == receipt
    assert receipt.persisted_snapshot.observation.position_count == 1
    assert receipt.persisted_snapshot.receipt.delivery.body == _body(_position(1))
    assert receipt.durable_authenticated_position_snapshot_established is True
    assert all(material.closed for material in system.resolver.materials)
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="stalled or complete",
    ):
        restarted.prepare(
            system.plan,
            checked_at=system.capture_base + timedelta(seconds=1),
        )
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="already complete",
    ):
        restarted.record(receipt.evidence)
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_position_snapshot_plans)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_position_snapshots)
            )
            == 1
        )
    verify_alpaca_paper_position_snapshot_integrity(system.account.engine)
    verify_operational_schema(
        system.account.engine,
        require_phase_zero_facts=False,
    )


def test_stalled_claim_and_changed_binding_cannot_reuse_capture(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4u-stalled.sqlite")
    preparation = system.repository.prepare(
        system.plan,
        checked_at=system.capture_base,
    )
    restarted = SqlAlpacaPaperPositionSnapshotRepository(
        engine=system.account.engine,
        coordinator=system.coordinator,
    )

    assert restarted.load(system.plan) is None
    stalled = restarted.load_state(system.plan)
    assert stalled.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED
    assert stalled.preparation == preparation
    assert stalled.receipt is None
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="stalled or complete",
    ):
        restarted.prepare(
            system.plan,
            checked_at=preparation.prepared_at + timedelta(milliseconds=1),
        )

    successor = system.account.observe("phase4u-successor")
    changed_plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=system.plan.description,
        reference=AlpacaPaperCredentialReference(
            account_id=successor.account_id,
            expected_provider_account_id=(successor.expected_provider_account_id),
            secret_ref=successor.secret_ref,
            secret_version=successor.secret_version,
        ),
        account_binding=successor,
    )
    assert changed_plan.plan_id != system.plan.plan_id
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="plan ID and capture ID disagree",
    ):
        restarted.prepare(
            changed_plan,
            checked_at=BASE + timedelta(seconds=3),
        )


def test_commit_revalidates_exact_lease_after_raw_persistence(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4u-commit-fence.sqlite")
    system.repository = SqlAlpacaPaperPositionSnapshotRepository(
        engine=system.account.engine,
        coordinator=ChangedCommitLease(system.coordinator),  # type: ignore[arg-type]
    )

    with pytest.raises(
        AlpacaPaperPositionSnapshotConflict,
        match="durable authenticated position-snapshot commit failed",
    ):
        system.observe()

    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_position_snapshot_plans)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_position_snapshots)
            )
            == 0
        )
    assert system.repository.load(system.plan) is None


def test_load_rejects_successor_qualified_between_prepare_and_commit(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4u-successor-before-commit.sqlite")
    receipt = system.observe()
    successor = system.account.observe("phase4u-historical-successor")
    assert (
        receipt.evidence.preparation.prepared_at
        < receipt.commit_fence_receipt.validated_at
        < successor.qualified_at
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_position_snapshots).values(
                commit_fence_validated_at=(successor.qualified_at + timedelta(milliseconds=1))
            )
        )

    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="account-binding source",
    ):
        system.repository.load(system.plan)


def test_load_and_readiness_fail_closed_on_identity_or_payload_corruption(
    tmp_path: Path,
) -> None:
    stalled = _system(tmp_path / "phase4u-plan-id-corruption.sqlite")
    stalled.repository.prepare(
        stalled.plan,
        checked_at=stalled.capture_base,
    )
    with stalled.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_position_snapshot_plans).values(plan_id=str(uuid4()))
        )
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="plan ID and capture ID disagree",
    ):
        stalled.repository.load(stalled.plan)

    complete = _system(tmp_path / "phase4u-payload-corruption.sqlite")
    complete.observe()
    with complete.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_position_snapshots).values(canonical_payload="[]")
        )
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="exact reconstruction",
    ):
        complete.repository.load(complete.plan)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="position-snapshot integrity",
    ):
        verify_operational_schema(
            complete.account.engine,
            require_phase_zero_facts=False,
        )


def test_readiness_requires_tables_and_downgrade_refuses_durable_claim(
    tmp_path: Path,
) -> None:
    missing = _system(tmp_path / "phase4u-missing-table.sqlite")
    with missing.account.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE phase4_alpaca_paper_position_snapshots")
    with pytest.raises(DatabaseSchemaNotReady):
        verify_operational_schema(
            missing.account.engine,
            require_phase_zero_facts=False,
        )

    database_path = tmp_path / "phase4u-downgrade.sqlite"
    durable = _system(database_path)
    durable.repository.prepare(
        durable.plan,
        checked_at=durable.capture_base,
    )
    durable.account.engine.dispose()
    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty authenticated position snapshot",
    ):
        command.downgrade(
            _alembic_config(database_path),
            "0020_phase4_order_view_cmp",
        )


def test_integrity_verifier_rejects_direct_sql_orphan_receipt(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4u-orphan.sqlite")
    system.observe()

    raw_connection = system.account.engine.raw_connection()
    try:
        cursor = raw_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = OFF")
        cursor.execute(
            "DELETE FROM phase4_alpaca_paper_position_snapshot_plans WHERE plan_id = ?",
            (system.plan.plan_id,),
        )
        raw_connection.commit()
        cursor.execute("PRAGMA foreign_keys = ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="without durable single-use claims",
    ):
        verify_alpaca_paper_position_snapshot_integrity(system.account.engine)


def test_postgresql_concurrent_prepare_allows_only_one_claim(
    phase4u_postgres_engine: Engine,
    request: pytest.FixtureRequest,
) -> None:
    engine = phase4u_postgres_engine
    account_id = f"phase4u-pg-position-{uuid4().hex[:20]}"
    request.addfinalizer(lambda: delete_phase4_postgres_account_facts(engine, account_id))
    evidence, _ = _prepare_concurrent_postgres_evidence(engine, account_id)
    binding = SqlAlpacaPaperAccountBindingRepository(engine).record(evidence)
    reference = AlpacaPaperCredentialReference(
        account_id=account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=binding.secret_ref,
        secret_version=binding.secret_version,
    )
    plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=account_id,
            capture_idempotency_key=f"phase4u-pg-capture-{uuid4()}",
        ),
        reference=reference,
        account_binding=binding,
    )
    coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase4u-postgres-preparation",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=FixedClock(datetime.now(tz=UTC)),
        ),
    )
    barrier = Barrier(2)

    def prepare() -> tuple[str, object]:
        barrier.wait(timeout=10)
        try:
            receipt = SqlAlpacaPaperPositionSnapshotRepository(
                engine=engine,
                coordinator=coordinator,
            ).prepare(plan, checked_at=binding.qualified_at)
            return ("claimed", receipt)
        except AlpacaPaperPositionSnapshotPersistenceConflict as error:
            return ("rejected", str(error))

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(prepare) for _ in range(2))
        results = tuple(future.result(timeout=20) for future in futures)

    assert sorted(status for status, _ in results) == ["claimed", "rejected"]
    assert "stalled or complete single-use claim" in next(
        str(value) for status, value in results if status == "rejected"
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_position_snapshot_plans)
                .where(phase4_alpaca_paper_position_snapshot_plans.c.plan_id == plan.plan_id)
            )
            == 1
        )
