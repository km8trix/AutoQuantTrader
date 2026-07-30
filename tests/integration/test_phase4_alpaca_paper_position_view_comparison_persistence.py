from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy import Engine, make_url
from sqlalchemy.engine import Connection

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    _observe_authenticated_alpaca_paper_position_snapshot_with_transport,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_snapshot_comparison import (
    AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    _alpaca_paper_authenticated_position_view_comparison_evidence,
    compare_and_record_authenticated_alpaca_paper_position_snapshots,
    create_authenticated_alpaca_paper_position_view_comparison_plan,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
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
    SqlAlpacaPaperPositionSnapshotRepository,
)
from packages.persistence.alpaca_paper_position_view_comparison import (
    AlpacaPaperPositionViewComparisonPersistenceConflict,
    SqlAlpacaPaperPositionViewComparisonRepository,
    verify_alpaca_paper_position_view_comparison_integrity,
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
    phase4_alpaca_paper_position_snapshots,
    phase4_alpaca_paper_position_view_comparison_heads,
    phase4_alpaca_paper_position_view_comparisons,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    BASE,
    PROVIDER_ACCOUNT_ID,
    SequenceClock,
    _prepare_concurrent_postgres_evidence,
)
from tests.integration.test_phase4_alpaca_paper_position_snapshot_persistence import (
    Phase4PositionSnapshotSystem,
    PositionSnapshotCredentialResolver,
    PositionSnapshotTransport,
    _alembic_config,
    _alembic_config_for_url,
    _body,
    _lease_policy,
    _position,
    _runtime_instants,
)
from tests.integration.test_phase4_alpaca_paper_position_snapshot_persistence import (
    _system as _position_system,
)

TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


def _snapshot_coordinator(
    engine: Engine,
    *,
    account_id: str,
    capture_base: datetime,
    policy: AccountLeasePolicy,
) -> SqlAccountCoordinator:
    first_commit = capture_base + timedelta(milliseconds=150)
    fence_instants = (
        capture_base + timedelta(milliseconds=50),
        capture_base + timedelta(milliseconds=110),
        capture_base + timedelta(milliseconds=130),
        first_commit,
        first_commit + timedelta(milliseconds=10),
    )
    return SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=policy,
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


def _observe_next(
    system: Phase4PositionSnapshotSystem,
    ordinal: int,
    *,
    capture_base: datetime,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    system.capture_base = capture_base
    system.plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=system.plan.description.account_id,
            capture_idempotency_key=f"phase4v-position-capture-{ordinal:04d}",
        ),
        reference=system.plan.reference,
        account_binding=system.plan.account_binding,
    )
    system.coordinator = _snapshot_coordinator(
        system.account.engine,
        account_id=system.plan.description.account_id,
        capture_base=capture_base,
        policy=_lease_policy(),
    )
    system.repository = SqlAlpacaPaperPositionSnapshotRepository(
        engine=system.account.engine,
        coordinator=system.coordinator,
    )
    return system.observe()


def _source_receipts(
    database_path: Path,
    *,
    count: int = 2,
) -> tuple[
    Phase4PositionSnapshotSystem,
    tuple[AlpacaPaperAuthenticatedPositionSnapshotReceipt, ...],
]:
    if count < 2:
        raise AssertionError("position-view comparison tests require at least two sources")
    system = _position_system(
        database_path,
        capture_base=BASE + timedelta(seconds=10),
    )
    receipts = [system.observe()]
    for ordinal in range(2, count + 1):
        receipts.append(
            _observe_next(
                system,
                ordinal,
                capture_base=BASE + timedelta(seconds=10 + (ordinal - 1) * 3),
            )
        )
    return system, tuple(receipts)


def _comparison_coordinator(
    system: Phase4PositionSnapshotSystem,
    *,
    checked_at: datetime,
) -> SqlAccountCoordinator:
    return SqlAccountCoordinator(
        account_id=system.plan.description.account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=system.account.engine,
            policy=_lease_policy(),
            clock=FixedClock(checked_at),
        ),
    )


def _repository(
    system: Phase4PositionSnapshotSystem,
    *,
    checked_at: datetime,
) -> SqlAlpacaPaperPositionViewComparisonRepository:
    return SqlAlpacaPaperPositionViewComparisonRepository(
        engine=system.account.engine,
        coordinator=_comparison_coordinator(system, checked_at=checked_at),
    )


def _evidence(
    earlier: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    later: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
) -> AlpacaPaperAuthenticatedPositionViewComparisonEvidence:
    return _alpaca_paper_authenticated_position_view_comparison_evidence(
        plan=create_authenticated_alpaca_paper_position_view_comparison_plan(
            earlier_plan=earlier.plan,
            later_plan=later.plan,
        ),
        earlier_receipt=earlier,
        later_receipt=later,
    )


class _CountingFenceValidator:
    def __init__(self, delegate: SqlAccountCoordinator) -> None:
        self.delegate = delegate
        self.calls = 0

    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        self.calls += 1
        return self.delegate.revalidate_for_commit_in_transaction(connection, fence)


class _ChangeSecondFenceValidator(_CountingFenceValidator):
    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        receipt = super().revalidate_for_commit_in_transaction(connection, fence)
        if self.calls == 1:
            return receipt
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256="f" * 64,
        )


class _SubstitutingFenceValidator:
    def __init__(self, receipt: AccountFenceReceipt) -> None:
        self.receipt = receipt

    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        del connection, fence
        return self.receipt


def test_round_trip_exact_sources_and_retry_preserves_historical_fence(
    tmp_path: Path,
) -> None:
    system, sources = _source_receipts(tmp_path / "phase4v-round-trip.sqlite")
    earlier, later = sources
    plan = create_authenticated_alpaca_paper_position_view_comparison_plan(
        earlier_plan=earlier.plan,
        later_plan=later.plan,
    )
    repository = _repository(
        system,
        checked_at=BASE + timedelta(seconds=20),
    )

    result = compare_and_record_authenticated_alpaca_paper_position_snapshots(
        plan,
        fence=system.account.fence,
        snapshot_loader=system.repository,
        comparison_repository=repository,
    )
    retry_validator = _CountingFenceValidator(
        _comparison_coordinator(
            system,
            checked_at=BASE + timedelta(seconds=21),
        )
    )
    retry_repository = SqlAlpacaPaperPositionViewComparisonRepository(
        engine=system.account.engine,
        coordinator=retry_validator,
    )
    repeated = retry_repository.record(
        result.receipt.evidence,
        fence=system.account.fence,
    )

    assert repeated == result.receipt
    assert repeated.commit_fence_receipt == result.receipt.commit_fence_receipt
    assert repeated.recorded_at == BASE + timedelta(seconds=20)
    assert retry_validator.calls == 1
    assert retry_repository.load(result.receipt.receipt_id) == result.receipt
    assert retry_repository.history(result.receipt.account_id) == (result.receipt,)
    assert result.receipt.durable_source_positions_authenticated is True
    assert result.receipt.comparison_durably_recorded is True
    assert result.receipt.trading_effect_authorized is False
    with system.account.engine.connect() as connection:
        row = (
            connection.execute(sa.select(phase4_alpaca_paper_position_view_comparisons))
            .mappings()
            .one()
        )
        assert row["expected_provider_account_id"] == PROVIDER_ACCOUNT_ID
        assert row["earlier_snapshot_receipt_id"] == earlier.receipt_id
        assert row["later_snapshot_receipt_id"] == later.receipt_id
        assert row["earlier_ingress_sequence"] < row["later_ingress_sequence"]
    verify_alpaca_paper_position_view_comparison_integrity(system.account.engine)
    verify_operational_schema(
        system.account.engine,
        require_phase_zero_facts=False,
    )


def test_exact_retry_reauthenticates_current_call_fence(
    tmp_path: Path,
) -> None:
    system, sources = _source_receipts(tmp_path / "phase4v-retry-fence.sqlite")
    evidence = _evidence(*sources)
    receipt = _repository(
        system,
        checked_at=BASE + timedelta(seconds=20),
    ).record(evidence, fence=system.account.fence)
    stale_fence = AccountFence(
        account_id=system.account.fence.account_id,
        owner_id=f"{system.account.fence.owner_id}-stale",
        lease_id=system.account.fence.lease_id,
        fencing_generation=system.account.fence.fencing_generation,
    )
    stale_repository = _repository(
        system,
        checked_at=BASE + timedelta(seconds=21),
    )
    with pytest.raises(
        AlpacaPaperPositionViewComparisonPersistenceConflict,
        match="current call fence validation failed",
    ):
        stale_repository.record(evidence, fence=stale_fence)

    substituted = _account_fence_receipt(
        fence=stale_fence,
        validated_at=receipt.recorded_at,
        valid_until=receipt.commit_fence_receipt.valid_until,
        policy_sha256=receipt.commit_fence_receipt.policy_sha256,
        lease_sha256=receipt.commit_fence_receipt.lease_sha256,
    )
    with pytest.raises(
        AlpacaPaperPositionViewComparisonPersistenceConflict,
        match="current call fence validation failed",
    ):
        SqlAlpacaPaperPositionViewComparisonRepository(
            engine=system.account.engine,
            coordinator=_SubstitutingFenceValidator(substituted),
        ).record(evidence, fence=system.account.fence)


def test_new_append_revalidates_fence_at_end_and_rolls_back_on_change(
    tmp_path: Path,
) -> None:
    system, sources = _source_receipts(tmp_path / "phase4v-final-fence.sqlite")
    validator = _ChangeSecondFenceValidator(
        _comparison_coordinator(
            system,
            checked_at=BASE + timedelta(seconds=20),
        )
    )
    repository = SqlAlpacaPaperPositionViewComparisonRepository(
        engine=system.account.engine,
        coordinator=validator,
    )

    with pytest.raises(
        AlpacaPaperPositionViewComparisonPersistenceConflict,
        match="fence changed before final commit",
    ):
        repository.record(_evidence(*sources), fence=system.account.fence)

    assert validator.calls == 2
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_view_comparisons
                )
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_view_comparison_heads
                )
            )
            == 0
        )


def test_source_tamper_and_orphan_head_fail_closed_for_load_and_readiness(
    tmp_path: Path,
) -> None:
    system, sources = _source_receipts(tmp_path / "phase4v-source-tamper.sqlite")
    repository = _repository(
        system,
        checked_at=BASE + timedelta(seconds=20),
    )
    receipt = repository.record(_evidence(*sources), fence=system.account.fence)
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_position_snapshots)
            .where(phase4_alpaca_paper_position_snapshots.c.receipt_id == sources[0].receipt_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        AlpacaPaperPositionViewComparisonPersistenceConflict,
        match="source failed durable authentication",
    ):
        repository.load(receipt.receipt_id)
    with pytest.raises(DatabaseSchemaNotReady):
        verify_operational_schema(
            system.account.engine,
            require_phase_zero_facts=False,
        )

    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute("DELETE FROM phase4_alpaca_paper_position_view_comparisons")
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperPositionViewComparisonPersistenceConflict,
        match="head exists without durable receipts",
    ):
        verify_alpaca_paper_position_view_comparison_integrity(system.account.engine)


def test_deleted_predecessor_is_rejected_and_downgrade_refuses_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4v-predecessor.sqlite"
    system, sources = _source_receipts(database_path, count=3)
    first_repository = _repository(
        system,
        checked_at=BASE + timedelta(seconds=20),
    )
    first = first_repository.record(
        _evidence(sources[0], sources[1]),
        fence=system.account.fence,
    )
    second = _repository(
        system,
        checked_at=BASE + timedelta(seconds=21),
    ).record(
        _evidence(sources[1], sources[2]),
        fence=system.account.fence,
    )
    assert second.account_sequence == 2
    assert second.previous_receipt_sha256 == first.semantic_sha256

    system.account.engine.dispose()
    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty authenticated position-view comparison history",
    ):
        command.downgrade(
            _alembic_config(database_path),
            "0021_phase4_position_snapshots",
        )

    engine = create_database_engine(f"sqlite+pysqlite:///{database_path}")
    raw_connection = engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute(
            "DELETE FROM phase4_alpaca_paper_position_view_comparisons WHERE receipt_id = ?",
            (first.receipt_id,),
        )
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()
    repository = SqlAlpacaPaperPositionViewComparisonRepository(
        engine=engine,
        coordinator=_comparison_coordinator(
            system,
            checked_at=BASE + timedelta(seconds=22),
        ),
    )
    with pytest.raises(
        AlpacaPaperPositionViewComparisonPersistenceConflict,
        match="history is discontinuous",
    ):
        repository.load(second.receipt_id)
    engine.dispose()


def test_migration_has_exact_composite_source_foreign_keys(
    tmp_path: Path,
) -> None:
    system = _position_system(tmp_path / "phase4v-schema.sqlite")
    source_columns = (
        "receipt_id",
        "plan_id",
        "capture_id",
        "account_id",
        "plan_sha256",
        "persisted_snapshot_sha256",
        "semantic_sha256",
        "ingress_receipt_id",
        "ingress_receipt_sha256",
        "ingress_sequence",
        "commit_fence_validated_at",
    )
    indexes = {
        item["name"]: item
        for item in sa.inspect(system.account.engine).get_indexes(
            "phase4_alpaca_paper_position_snapshots"
        )
    }
    exact_index = indexes["uq_phase4_position_snapshot_comparison_source"]
    assert exact_index["unique"]
    assert tuple(exact_index["column_names"]) == source_columns

    foreign_keys = {
        item["name"]: item
        for item in sa.inspect(system.account.engine).get_foreign_keys(
            "phase4_alpaca_paper_position_view_comparisons"
        )
    }
    for phase in ("earlier", "later"):
        foreign_key = foreign_keys[f"fk_phase4_position_view_cmp_{phase}_source"]
        assert tuple(foreign_key["referred_columns"]) == source_columns
        assert tuple(foreign_key["constrained_columns"]) == (
            f"{phase}_snapshot_receipt_id",
            f"{phase}_plan_id",
            f"{phase}_capture_id",
            "account_id",
            f"{phase}_plan_sha256",
            f"{phase}_persisted_snapshot_sha256",
            f"{phase}_snapshot_receipt_sha256",
            f"{phase}_ingress_receipt_id",
            f"{phase}_ingress_receipt_sha256",
            f"{phase}_ingress_sequence",
            f"{phase}_source_committed_at",
        )

    with system.account.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE phase4_alpaca_paper_position_view_comparison_heads")
    with pytest.raises(DatabaseSchemaNotReady):
        verify_operational_schema(
            system.account.engine,
            require_phase_zero_facts=False,
        )


@pytest.fixture
def phase4v_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4V tests")
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


def _postgres_sources(
    engine: Engine,
    account_id: str,
) -> tuple[
    AccountFence,
    AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    SqlAccountCoordinator,
]:
    binding_evidence, _ = _prepare_concurrent_postgres_evidence(engine, account_id)
    bindings = SqlAlpacaPaperAccountBindingRepository(engine)
    binding = bindings.record(binding_evidence)
    fence = binding_evidence.post_fence_receipt.fence
    reference = AlpacaPaperCredentialReference(
        account_id=account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=binding.secret_ref,
        secret_version=binding.secret_version,
    )
    ingress = SqlBrokerIngressRepository(engine)
    receipts = []
    for ordinal in (1, 2):
        capture_base = binding.qualified_at + timedelta(seconds=ordinal * 2)
        coordinator = _snapshot_coordinator(
            engine,
            account_id=account_id,
            capture_base=capture_base,
            policy=AccountLeasePolicy(
                policy_id="phase4g-postgres-binding-lock",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
        )
        repository = SqlAlpacaPaperPositionSnapshotRepository(
            engine=engine,
            coordinator=coordinator,
        )
        plan = create_alpaca_paper_position_snapshot_runtime_plan(
            description=create_alpaca_paper_position_snapshot_description(
                account_id=account_id,
                capture_idempotency_key=f"phase4v-pg-capture-{ordinal}-{uuid4()}",
            ),
            reference=reference,
            account_binding=binding,
        )
        receipts.append(
            _observe_authenticated_alpaca_paper_position_snapshot_with_transport(
                plan=plan,
                credential_resolver=PositionSnapshotCredentialResolver(),
                transport=PositionSnapshotTransport(_body(_position(ordinal))),
                budget=SqlBrokerRequestBudgetRepository(
                    engine=engine,
                    clock=SequenceClock(
                        [
                            capture_base + timedelta(milliseconds=40),
                            capture_base + timedelta(milliseconds=60),
                        ]
                    ),
                ),
                account_bindings=bindings,
                coordinator=coordinator,
                fence=fence,
                ingress_recorder=ingress,
                snapshot_runtime=repository,
                clock=SequenceClock(_runtime_instants(capture_base)),
            )
        )
    comparison_at = receipts[-1].commit_fence_receipt.validated_at + timedelta(seconds=1)
    comparison_coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase4g-postgres-binding-lock",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=FixedClock(comparison_at),
        ),
    )
    return fence, _evidence(*receipts), comparison_coordinator


def test_postgresql_concurrent_exact_retry_serializes_one_receipt_and_head(
    phase4v_postgres_engine: Engine,
) -> None:
    engine = phase4v_postgres_engine
    account_id = f"phase4v-pg-{uuid4().hex[:20]}"
    fence, evidence, coordinator = _postgres_sources(engine, account_id)
    barrier = Barrier(2)

    def record() -> object:
        barrier.wait(timeout=10)
        return SqlAlpacaPaperPositionViewComparisonRepository(
            engine=engine,
            coordinator=coordinator,
        ).record(evidence, fence=fence)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(record) for _ in range(2))
        # Keep the lock test bounded while allowing pooler latency under full-suite load.
        results = tuple(future.result(timeout=60) for future in futures)

    assert results[0] == results[1]
    history = SqlAlpacaPaperPositionViewComparisonRepository(
        engine=engine,
        coordinator=coordinator,
    ).history(account_id)
    assert history == (results[0],)
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_position_view_comparisons)
                .where(phase4_alpaca_paper_position_view_comparisons.c.account_id == account_id)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_position_view_comparison_heads)
                .where(
                    phase4_alpaca_paper_position_view_comparison_heads.c.account_id == account_id
                )
            )
            == 1
        )
