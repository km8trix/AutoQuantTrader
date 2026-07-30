from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
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
from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    AlpacaPaperOrderSnapshotComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPlan,
    create_alpaca_paper_order_snapshot_plan,
    start_alpaca_paper_order_snapshot,
)
from packages.application.alpaca_paper_order_snapshot_comparison import (
    AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
    _alpaca_paper_authenticated_order_view_comparison_evidence,
    compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLeasePolicy,
    _account_fence_receipt,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
)
from packages.persistence.alpaca_paper_order_snapshot import (
    SqlAlpacaPaperOrderSnapshotRepository,
)
from packages.persistence.alpaca_paper_order_view_comparison import (
    AlpacaPaperOrderViewComparisonPersistenceConflict,
    SqlAlpacaPaperOrderViewComparisonRepository,
    verify_alpaca_paper_order_view_comparison_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import create_database_engine, verify_operational_schema
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase4_alpaca_paper_order_snapshot_heads,
    phase4_alpaca_paper_order_view_comparison_heads,
    phase4_alpaca_paper_order_view_comparisons,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    ACCOUNT_ID,
    BASE,
    SequenceClock,
    _prepare_concurrent_postgres_evidence,
    _runtime_instants,
)
from tests.integration.test_phase4_alpaca_paper_order_snapshot_persistence import (
    OrderSnapshotCredentialResolver,
    OrderSnapshotTransport,
    Phase4OrderSnapshotSystem,
    _alembic_config,
    _first_page_runtime_instants,
    _second_page_runtime_instants,
    _system,
)
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order

TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


def _later_plan(
    ordinal: int,
    *,
    page_limit: int = 2,
    maximum_pages: int = 3,
) -> AlpacaPaperOrderSnapshotPlan:
    return create_alpaca_paper_order_snapshot_plan(
        account_id=ACCOUNT_ID,
        capture_idempotency_key=f"phase4p-integration-capture-{ordinal:04d}",
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )


def _observe_terminal(
    system: Phase4OrderSnapshotSystem,
    plan: AlpacaPaperOrderSnapshotPlan,
    *,
    response_body: bytes,
    later: bool,
    time_shift: timedelta = timedelta(),
) -> None:
    description = start_alpaca_paper_order_snapshot(plan).next_page_description
    assert description is not None
    system.observe(
        description,
        response_body=response_body,
        runtime_instants=[
            instant + time_shift
            for instant in (
                _second_page_runtime_instants() if later else _first_page_runtime_instants()
            )
        ],
        budget_instants=[
            instant + time_shift
            for instant in (
                (
                    BASE + timedelta(seconds=2, milliseconds=550),
                    BASE + timedelta(seconds=2, milliseconds=750),
                )
                if later
                else (
                    BASE + timedelta(seconds=1, milliseconds=40),
                    BASE + timedelta(seconds=2, milliseconds=10),
                )
            )
        ],
    )


def _terminal_pair(
    database_path: Path,
    *,
    bounded_truncation: bool = False,
) -> tuple[
    Phase4OrderSnapshotSystem,
    AlpacaPaperOrderSnapshotPlan,
    AlpacaPaperOrderSnapshotPlan,
]:
    page_limit = 1 if bounded_truncation else 2
    maximum_pages = 1 if bounded_truncation else 3
    system = _system(
        database_path,
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )
    earlier_plan = system.plan
    later_plan = _later_plan(
        2,
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )
    body = (
        _body(
            _order(
                1,
                submitted_at="2026-07-27T13:59:00.123456789Z",
            )
        )
        if bounded_truncation
        else b"[]"
    )
    _observe_terminal(
        system,
        earlier_plan,
        response_body=body,
        later=False,
    )
    _observe_terminal(
        system,
        later_plan,
        response_body=body,
        later=True,
    )
    return system, earlier_plan, later_plan


def _repository(
    system: Phase4OrderSnapshotSystem,
) -> SqlAlpacaPaperOrderViewComparisonRepository:
    return SqlAlpacaPaperOrderViewComparisonRepository(
        engine=system.account.engine,
        coordinator=system.account.coordinator,
    )


class _SubstitutingFenceValidator:
    def __init__(self, receipt: AccountFenceReceipt) -> None:
        self._receipt = receipt

    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        del connection, fence
        return self._receipt


def test_comparison_round_trips_exact_sources_fence_and_idempotent_retry(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(tmp_path / "phase4p-round-trip.sqlite")
    repository = _repository(system)
    assert repository.runtime_store_identity == system.repository.runtime_store_identity
    assert repository.runtime_store_identity == id(system.account.engine)

    receipt = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        prefix_loader=system.repository,
        comparison_repository=repository,
    )
    repeated = repository.record(
        receipt.evidence,
        fence=system.account.fence,
    )
    stale_fence = AccountFence(
        account_id=system.account.fence.account_id,
        owner_id=f"{system.account.fence.owner_id}-stale",
        lease_id=system.account.fence.lease_id,
        fencing_generation=system.account.fence.fencing_generation,
    )

    assert repeated == receipt
    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="commit fence validation failed",
    ):
        repository.record(receipt.evidence, fence=stale_fence)
    substituted_receipt = _account_fence_receipt(
        fence=stale_fence,
        validated_at=receipt.commit_fence_receipt.validated_at,
        valid_until=receipt.commit_fence_receipt.valid_until,
        policy_sha256=receipt.commit_fence_receipt.policy_sha256,
        lease_sha256=receipt.commit_fence_receipt.lease_sha256,
    )
    substituting_repository = SqlAlpacaPaperOrderViewComparisonRepository(
        engine=system.account.engine,
        coordinator=_SubstitutingFenceValidator(substituted_receipt),
    )
    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="commit fence validation failed",
    ):
        substituting_repository.record(
            receipt.evidence,
            fence=system.account.fence,
        )
    assert repository.load(receipt.receipt_id) == receipt
    assert repository.history(ACCOUNT_ID) == (receipt,)
    assert receipt.evidence.durable_source_positions_authenticated is False
    assert receipt.durable_source_positions_authenticated is True
    assert receipt.comparison_durably_recorded is True
    assert receipt.recorded_at == receipt.commit_fence_receipt.validated_at
    assert receipt.commit_fence_receipt.valid_until > receipt.recorded_at
    assert receipt.trading_effect_authorized is False
    with system.account.engine.connect() as connection:
        source_heads = {
            row["snapshot_id"]: row["semantic_sha256"]
            for row in connection.execute(
                sa.select(
                    phase4_alpaca_paper_order_snapshot_heads.c.snapshot_id,
                    phase4_alpaca_paper_order_snapshot_heads.c.semantic_sha256,
                ).where(
                    phase4_alpaca_paper_order_snapshot_heads.c.snapshot_id.in_(
                        (earlier_plan.snapshot_id, later_plan.snapshot_id)
                    )
                )
            ).mappings()
        }
        comparison_row = (
            connection.execute(sa.select(phase4_alpaca_paper_order_view_comparisons))
            .mappings()
            .one()
        )
        assert comparison_row["earlier_head_sha256"] == source_heads[earlier_plan.snapshot_id]
        assert comparison_row["later_head_sha256"] == source_heads[later_plan.snapshot_id]
        stored_valid_until = comparison_row["commit_fence_valid_until"]
        assert isinstance(stored_valid_until, datetime)
        assert as_aware_utc(stored_valid_until) == (receipt.commit_fence_receipt.valid_until)
    verify_alpaca_paper_order_view_comparison_integrity(system.account.engine)
    verify_operational_schema(
        system.account.engine,
        require_phase_zero_facts=False,
    )


def test_bounded_truncated_sources_are_retained_only_as_incomplete(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(
        tmp_path / "phase4p-bounded.sqlite",
        bounded_truncation=True,
    )
    earlier = system.repository.load_prefix(earlier_plan)
    later = system.repository.load_prefix(later_plan)
    assert earlier.capture.bounded_truncation is True
    assert later.capture.bounded_truncation is True
    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=later,
    )

    receipt = _repository(system).record(
        evidence,
        fence=system.account.fence,
    )

    assert (
        receipt.evidence.comparison.disposition
        is AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert receipt.evidence.bounded_traversal_incomplete is True
    assert receipt.reconciliation_complete is False


def test_read_and_startup_fail_closed_on_canonical_tamper_and_orphan_head(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(tmp_path / "phase4p-tamper.sqlite")
    repository = _repository(system)
    receipt = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        prefix_loader=system.repository,
        comparison_repository=repository,
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_order_view_comparisons).values(
                canonical_payload='{"tampered":true}'
            )
        )

    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="source reconstruction",
    ):
        repository.load(receipt.receipt_id)

    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute("DELETE FROM phase4_alpaca_paper_order_view_comparisons")
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="head exists without durable receipts",
    ):
        verify_alpaca_paper_order_view_comparison_integrity(system.account.engine)


def test_load_rejects_a_deleted_account_predecessor(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4p-deleted-predecessor.sqlite")
    first_plan = system.plan
    second_plan = _later_plan(2)
    third_plan = _later_plan(3)
    _observe_terminal(
        system,
        first_plan,
        response_body=b"[]",
        later=False,
    )
    _observe_terminal(
        system,
        second_plan,
        response_body=b"[]",
        later=True,
    )
    _observe_terminal(
        system,
        third_plan,
        response_body=b"[]",
        later=True,
        time_shift=timedelta(seconds=1, milliseconds=600),
    )
    system.account.coordinator = SqlAccountCoordinator(
        account_id=ACCOUNT_ID,
        authority=SqlAccountCoordinatorAuthority(
            engine=system.account.engine,
            policy=AccountLeasePolicy(
                policy_id="phase4g-binding-integration",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=SequenceClock(
                [
                    BASE + timedelta(seconds=5),
                    BASE + timedelta(seconds=5),
                    BASE + timedelta(seconds=5, milliseconds=100),
                    BASE + timedelta(seconds=5, milliseconds=100),
                ]
            ),
        ),
    )
    repository = _repository(system)
    first = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        first_plan,
        second_plan,
        fence=system.account.fence,
        prefix_loader=system.repository,
        comparison_repository=repository,
    )
    second = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        second_plan,
        third_plan,
        fence=system.account.fence,
        prefix_loader=system.repository,
        comparison_repository=repository,
    )
    assert second.account_sequence == 2
    assert second.previous_receipt_sha256 == first.semantic_sha256

    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute(
            "DELETE FROM phase4_alpaca_paper_order_view_comparisons WHERE receipt_id = ?",
            (first.receipt_id,),
        )
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="history is discontinuous",
    ):
        repository.load(second.receipt_id)


def test_startup_rejects_comparison_without_head_and_migration_refuses_data_loss(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4p-orphan-comparison.sqlite"
    system, earlier_plan, later_plan = _terminal_pair(database_path)
    repository = _repository(system)
    receipt = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        prefix_loader=system.repository,
        comparison_repository=repository,
    )
    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute("DELETE FROM phase4_alpaca_paper_order_view_comparison_heads")
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="head",
    ):
        repository.load(receipt.receipt_id)
    with pytest.raises(
        AlpacaPaperOrderViewComparisonPersistenceConflict,
        match="receipts exist without durable account heads",
    ):
        verify_alpaca_paper_order_view_comparison_integrity(system.account.engine)

    with system.account.engine.begin() as connection:
        connection.execute(
            sa.insert(phase4_alpaca_paper_order_view_comparison_heads).values(
                account_id=receipt.account_id,
                last_account_sequence=receipt.account_sequence,
                last_receipt_id=receipt.receipt_id,
                last_receipt_sha256=receipt.semantic_sha256,
                last_recorded_at=receipt.recorded_at,
                canonical_payload="[]",
                semantic_sha256="0" * 64,
            )
        )
    system.account.engine.dispose()
    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty authenticated order-view comparison history",
    ):
        command.downgrade(
            _alembic_config(f"sqlite+pysqlite:///{database_path}"),
            "0019_phase4_order_snapshots",
        )


@pytest.fixture
def phase4p_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4P tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    config = _alembic_config(database_url)
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def _postgres_comparison_sources(
    engine: Engine,
    account_id: str,
) -> tuple[
    SqlAlpacaPaperOrderSnapshotRepository,
    SqlAccountCoordinator,
    AccountFence,
    AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
]:
    binding_evidence, _ = _prepare_concurrent_postgres_evidence(
        engine,
        account_id,
    )
    bindings = SqlAlpacaPaperAccountBindingRepository(engine)
    binding = bindings.record(binding_evidence)
    coordinator = SqlAccountCoordinator(
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
            clock=SequenceClock(_runtime_instants(6)[13:]),
        ),
    )
    fence = binding_evidence.post_fence_receipt.fence
    reference = AlpacaPaperCredentialReference(
        account_id=account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=binding.secret_ref,
        secret_version=binding.secret_version,
    )
    repository = SqlAlpacaPaperOrderSnapshotRepository(
        engine=engine,
        coordinator=coordinator,
    )
    ingress = SqlBrokerIngressRepository(engine)
    resolver = OrderSnapshotCredentialResolver()
    plans = tuple(
        create_alpaca_paper_order_snapshot_plan(
            account_id=account_id,
            capture_idempotency_key=f"phase4p-pg-capture-{ordinal}-{uuid4()}",
            page_limit=2,
            maximum_pages=3,
        )
        for ordinal in (1, 2)
    )
    for plan, runtime_instants, budget_instants in zip(
        plans,
        (
            _first_page_runtime_instants(),
            _second_page_runtime_instants(),
        ),
        (
            (
                BASE + timedelta(seconds=1, milliseconds=40),
                BASE + timedelta(seconds=2, milliseconds=10),
            ),
            (
                BASE + timedelta(seconds=2, milliseconds=550),
                BASE + timedelta(seconds=2, milliseconds=750),
            ),
        ),
        strict=True,
    ):
        description = start_alpaca_paper_order_snapshot(plan).next_page_description
        assert description is not None
        _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport(
            reference=reference,
            account_binding=binding,
            description=description,
            credential_resolver=resolver,
            transport=OrderSnapshotTransport(b"[]"),
            budget=SqlBrokerRequestBudgetRepository(
                engine=engine,
                clock=SequenceClock(list(budget_instants)),
            ),
            account_bindings=bindings,
            coordinator=coordinator,
            fence=fence,
            ingress_recorder=ingress,
            page_runtime=repository,
            clock=SequenceClock(runtime_instants),
        )
    earlier = repository.load_prefix(plans[0])
    later = repository.load_prefix(plans[1])
    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=later,
    )
    return repository, coordinator, fence, evidence


def test_postgresql_concurrent_exact_retry_serializes_one_receipt_and_head(
    phase4p_postgres_engine: Engine,
) -> None:
    engine = phase4p_postgres_engine
    account_id = f"phase4p-pg-{uuid4()}"
    _, coordinator, fence, value = _postgres_comparison_sources(
        engine,
        account_id,
    )

    def record() -> object:
        return SqlAlpacaPaperOrderViewComparisonRepository(
            engine=engine,
            coordinator=coordinator,
        ).record(value, fence=fence)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _: record(), range(2)))

    assert results[0] == results[1]
    history = SqlAlpacaPaperOrderViewComparisonRepository(
        engine=engine,
        coordinator=coordinator,
    ).history(account_id)
    assert history == (results[0],)
    assert history[0].account_sequence == 1
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_order_view_comparisons)
                .where(phase4_alpaca_paper_order_view_comparisons.c.account_id == account_id)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_order_view_comparison_heads)
                .where(phase4_alpaca_paper_order_view_comparison_heads.c.account_id == account_id)
            )
            == 1
        )
