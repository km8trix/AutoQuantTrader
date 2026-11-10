from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.engine import Connection

from packages.adapters.broker.alpaca_paper_account_activities import (
    AlpacaPaperAccountActivityPlan,
    create_alpaca_paper_account_activity_plan,
    start_alpaca_paper_account_activity_capture,
)
from packages.adapters.broker.alpaca_paper_account_activity_comparison import (
    AlpacaPaperAccountActivityComparisonDisposition,
)
from packages.application.alpaca_paper_account_activity_comparison import (
    _alpaca_paper_authenticated_account_activity_comparison_evidence,
    compare_and_record_authenticated_alpaca_paper_account_activity_prefixes,
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
from packages.persistence.alpaca_paper_account_activity import (
    SqlAlpacaPaperAccountActivityRepository,
)
from packages.persistence.alpaca_paper_account_activity_comparison import (
    AlpacaPaperAccountActivityComparisonPersistenceConflict,
    SqlAlpacaPaperAccountActivityComparisonRepository,
    verify_alpaca_paper_account_activity_comparison_integrity,
)
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase4_alpaca_paper_account_activity_comparison_heads,
    phase4_alpaca_paper_account_activity_comparisons,
    phase4_alpaca_paper_account_activity_heads,
    phase4_broker_ingress_receipts,
)
from tests.integration.test_phase4_alpaca_paper_account_activity_persistence import (
    Phase4AccountActivitySystem,
    _first_page_runtime_instants,
    _second_page_runtime_instants,
    _system,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    ACCOUNT_ID,
    BASE,
    PROVIDER_ACCOUNT_ID,
    SequenceClock,
    _alembic_config,
)
from tests.unit.test_alpaca_paper_account_activities import _activity, _body

COMPARISON_TABLES = (
    phase4_alpaca_paper_account_activity_comparisons,
    phase4_alpaca_paper_account_activity_comparison_heads,
)


def _later_plan(
    ordinal: int,
    *,
    page_size: int = 2,
    maximum_pages: int = 3,
    maximum_items: int = 6,
) -> AlpacaPaperAccountActivityPlan:
    return create_alpaca_paper_account_activity_plan(
        account_id=ACCOUNT_ID,
        capture_idempotency_key=f"phase4ah-integration-capture-{ordinal:04d}",
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )


def _shifted(
    instants: list[datetime],
    shift: timedelta,
) -> list[datetime]:
    return [instant + shift for instant in instants]


def _observe_terminal(
    system: Phase4AccountActivitySystem,
    plan: AlpacaPaperAccountActivityPlan,
    *,
    response_body: bytes,
    later: bool,
    time_shift: timedelta = timedelta(),
) -> None:
    description = start_alpaca_paper_account_activity_capture(plan).next_page_description
    assert description is not None
    system.observe(
        description,
        response_body=response_body,
        runtime_instants=_shifted(
            (_second_page_runtime_instants() if later else _first_page_runtime_instants()),
            time_shift,
        ),
        budget_instants=_shifted(
            [
                (
                    BASE + timedelta(seconds=2, milliseconds=550)
                    if later
                    else BASE + timedelta(seconds=1, milliseconds=40)
                ),
                (
                    BASE + timedelta(seconds=2, milliseconds=750)
                    if later
                    else BASE + timedelta(seconds=2, milliseconds=10)
                ),
            ],
            time_shift,
        ),
    )


def _coordinator(
    system: Phase4AccountActivitySystem,
    *,
    instants: list[datetime],
) -> SqlAccountCoordinator:
    coordinator = SqlAccountCoordinator(
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
            clock=SequenceClock(instants),
        ),
    )
    system.account.coordinator = coordinator
    system.repository = SqlAlpacaPaperAccountActivityRepository(
        engine=system.account.engine,
        coordinator=coordinator,
    )
    return coordinator


def _comparison_coordinator(
    system: Phase4AccountActivitySystem,
    *,
    start_seconds: int = 10,
) -> SqlAccountCoordinator:
    return _coordinator(
        system,
        instants=[
            BASE
            + timedelta(
                seconds=start_seconds,
                milliseconds=ordinal * 10,
            )
            for ordinal in range(32)
        ],
    )


def _terminal_pair(
    database_path: Path,
    *,
    bounded_truncation: bool = False,
    migrated: bool = False,
) -> tuple[
    Phase4AccountActivitySystem,
    AlpacaPaperAccountActivityPlan,
    AlpacaPaperAccountActivityPlan,
]:
    page_size = 1 if bounded_truncation else 2
    maximum_pages = 1 if bounded_truncation else 3
    maximum_items = 1 if bounded_truncation else 6
    system = _system(
        database_path,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
        migrated=migrated,
    )
    earlier_plan = system.plan
    later_plan = _later_plan(
        2,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )
    body = (
        _body(
            _activity(
                1,
                transaction_time="2026-07-27T13:59:00.123456789Z",
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
    _comparison_coordinator(system)
    return system, earlier_plan, later_plan


def _repository(
    system: Phase4AccountActivitySystem,
) -> SqlAlpacaPaperAccountActivityComparisonRepository:
    return SqlAlpacaPaperAccountActivityComparisonRepository(
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


def test_0033_migration_is_additive_schema_exact_and_reversible(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4ah-migration.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = _alembic_config(database_url)

    command.upgrade(config, "0032_phase5_alert_fail_control")
    engine = sa.create_engine(database_url)
    prior_tables = set(sa.inspect(engine).get_table_names())

    command.upgrade(config, "0033_phase4_activity_comparison")

    assert set(sa.inspect(engine).get_table_names()) == prior_tables | {
        table.name for table in COMPARISON_TABLES
    }
    for table in COMPARISON_TABLES:
        assert tuple(
            column["name"] for column in sa.inspect(engine).get_columns(table.name)
        ) == tuple(table.c.keys())

    engine.dispose()
    command.downgrade(config, "0032_phase5_alert_fail_control")
    downgraded = sa.create_engine(database_url)
    assert set(sa.inspect(downgraded).get_table_names()) == prior_tables
    downgraded.dispose()


def test_comparison_round_trips_all_sources_fence_and_idempotent_retry(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(tmp_path / "phase4ah-round-trip.sqlite")
    repository = _repository(system)
    assert repository.runtime_store_identity == system.repository.runtime_store_identity
    assert repository.runtime_store_identity == id(system.account.engine)

    receipt = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        state_loader=system.repository,
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
        AlpacaPaperAccountActivityComparisonPersistenceConflict,
        match="current call fence validation failed",
    ):
        repository.record(receipt.evidence, fence=stale_fence)
    substituted_receipt = _account_fence_receipt(
        fence=stale_fence,
        validated_at=receipt.commit_fence_receipt.validated_at,
        valid_until=receipt.commit_fence_receipt.valid_until,
        policy_sha256=receipt.commit_fence_receipt.policy_sha256,
        lease_sha256=receipt.commit_fence_receipt.lease_sha256,
    )
    substituting_repository = SqlAlpacaPaperAccountActivityComparisonRepository(
        engine=system.account.engine,
        coordinator=_SubstitutingFenceValidator(substituted_receipt),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonPersistenceConflict,
        match="current call fence validation failed",
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
    assert receipt.provider_io_performed is False
    assert receipt.activity_history_complete is False
    assert receipt.canonical_execution_fact_authorized is False
    assert receipt.reconciliation_application_authorized is False
    assert receipt.trading_effect_authorized is False
    with system.account.engine.connect() as connection:
        source_heads = {
            row["capture_id"]: row["semantic_sha256"]
            for row in connection.execute(
                sa.select(
                    phase4_alpaca_paper_account_activity_heads.c.capture_id,
                    phase4_alpaca_paper_account_activity_heads.c.semantic_sha256,
                ).where(
                    phase4_alpaca_paper_account_activity_heads.c.capture_id.in_(
                        (earlier_plan.capture_id, later_plan.capture_id)
                    )
                )
            ).mappings()
        }
        row = (
            connection.execute(sa.select(phase4_alpaca_paper_account_activity_comparisons))
            .mappings()
            .one()
        )
        assert row["provider_account_id"] == PROVIDER_ACCOUNT_ID
        assert row["earlier_head_sha256"] == source_heads[earlier_plan.capture_id]
        assert row["later_head_sha256"] == source_heads[later_plan.capture_id]
        assert row["earlier_first_ingress_receipt_id"] == (
            receipt.evidence.earlier_prefix.page_receipts[0].persisted_page.receipt.receipt_id
        )
        assert row["later_tip_ingress_receipt_id"] == (
            receipt.evidence.later_prefix.page_receipts[-1].persisted_page.receipt.receipt_id
        )
        stored_valid_until = row["commit_fence_valid_until"]
        assert isinstance(stored_valid_until, datetime)
        assert as_aware_utc(stored_valid_until) == (receipt.commit_fence_receipt.valid_until)
    verify_alpaca_paper_account_activity_comparison_integrity(system.account.engine)


def test_concurrent_exact_retry_converges_on_one_receipt_and_head(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(tmp_path / "phase4ah-concurrent-retry.sqlite")
    earlier_state = system.repository.load_state(earlier_plan)
    later_state = system.repository.load_state(later_plan)
    assert earlier_state is not None
    assert later_state is not None
    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier_state,
        later_state=later_state,
    )
    coordinator = SqlAccountCoordinator(
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
            clock=FixedClock(BASE + timedelta(seconds=12)),
        ),
    )
    barrier = Barrier(2)

    def record() -> object:
        barrier.wait(timeout=10)
        return SqlAlpacaPaperAccountActivityComparisonRepository(
            engine=system.account.engine,
            coordinator=coordinator,
        ).record(
            evidence,
            fence=system.account.fence,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(record) for _ in range(2))
        results = tuple(future.result(timeout=30) for future in futures)

    assert results[0] == results[1]
    history = SqlAlpacaPaperAccountActivityComparisonRepository(
        engine=system.account.engine,
        coordinator=coordinator,
    ).history(ACCOUNT_ID)
    assert history == (results[0],)
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_account_activity_comparisons
                )
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_account_activity_comparison_heads
                )
            )
            == 1
        )


def test_bounded_sources_remain_explicitly_incomplete_and_non_authorizing(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(
        tmp_path / "phase4ah-bounded.sqlite",
        bounded_truncation=True,
    )

    receipt = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        state_loader=system.repository,
        comparison_repository=_repository(system),
    )

    assert receipt.evidence.comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert receipt.evidence.bounded_traversal_incomplete is True
    assert receipt.activity_history_complete is False
    assert receipt.converged is False
    assert receipt.reconciliation_complete is False


def test_record_reloads_and_reauthenticates_raw_sources_inside_transaction(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(tmp_path / "phase4ah-source-reauth.sqlite")
    earlier_state = system.repository.load_state(earlier_plan)
    later_state = system.repository.load_state(later_plan)
    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier_state,
        later_state=later_state,
    )
    earlier_ingress_id = earlier_state.prefix.page_receipts[0].persisted_page.receipt.receipt_id
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_ingress_receipts)
            .where(phase4_broker_ingress_receipts.c.receipt_id == earlier_ingress_id)
            .values(body=b"{}")
        )

    with pytest.raises(
        AlpacaPaperAccountActivityComparisonPersistenceConflict,
        match="source failed durable authentication",
    ):
        _repository(system).record(
            evidence,
            fence=system.account.fence,
        )
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_account_activity_comparisons
                )
            )
            == 0
        )


def test_read_and_startup_fail_closed_on_tamper_and_orphan_head(
    tmp_path: Path,
) -> None:
    system, earlier_plan, later_plan = _terminal_pair(tmp_path / "phase4ah-tamper.sqlite")
    repository = _repository(system)
    receipt = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        state_loader=system.repository,
        comparison_repository=repository,
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_account_activity_comparisons).values(
                canonical_payload='{"tampered":true}'
            )
        )

    with pytest.raises(
        AlpacaPaperAccountActivityComparisonPersistenceConflict,
        match="exact source reconstruction",
    ):
        repository.load(receipt.receipt_id)

    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute("DELETE FROM phase4_alpaca_paper_account_activity_comparisons")
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperAccountActivityComparisonPersistenceConflict,
        match="head exists without durable receipts",
    ):
        verify_alpaca_paper_account_activity_comparison_integrity(system.account.engine)


def test_deleted_predecessor_breaks_the_complete_account_chain(
    tmp_path: Path,
) -> None:
    system, first_plan, second_plan = _terminal_pair(tmp_path / "phase4ah-predecessor.sqlite")
    third_plan = _later_plan(3)
    _coordinator(
        system,
        instants=[
            BASE + timedelta(seconds=10, milliseconds=650),
            BASE + timedelta(seconds=10, milliseconds=650),
            BASE + timedelta(seconds=10, milliseconds=800),
            BASE + timedelta(seconds=10, milliseconds=800),
            BASE + timedelta(seconds=10, milliseconds=830),
            BASE + timedelta(seconds=10, milliseconds=830),
            BASE + timedelta(seconds=10, milliseconds=840),
            BASE + timedelta(seconds=10, milliseconds=840),
        ],
    )
    _observe_terminal(
        system,
        third_plan,
        response_body=b"[]",
        later=True,
        time_shift=timedelta(seconds=8),
    )
    _comparison_coordinator(system, start_seconds=12)
    repository = _repository(system)
    first = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        first_plan,
        second_plan,
        fence=system.account.fence,
        state_loader=system.repository,
        comparison_repository=repository,
    )
    second = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        second_plan,
        third_plan,
        fence=system.account.fence,
        state_loader=system.repository,
        comparison_repository=repository,
    )
    assert second.account_sequence == 2
    assert second.previous_receipt_sha256 == first.semantic_sha256

    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute(
            "DELETE FROM phase4_alpaca_paper_account_activity_comparisons WHERE receipt_id = ?",
            (first.receipt_id,),
        )
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperAccountActivityComparisonPersistenceConflict,
        match="history is discontinuous",
    ):
        repository.load(second.receipt_id)


def test_nonempty_0033_downgrade_is_guarded_against_data_loss(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4ah-downgrade.sqlite"
    system, earlier_plan, later_plan = _terminal_pair(
        database_path,
        migrated=True,
    )
    compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        earlier_plan,
        later_plan,
        fence=system.account.fence,
        state_loader=system.repository,
        comparison_repository=_repository(system),
    )
    system.account.engine.dispose()

    with pytest.raises(
        RuntimeError,
        match=("refusing to downgrade nonempty authenticated account-activity comparison history"),
    ):
        command.downgrade(
            _alembic_config(f"sqlite+pysqlite:///{database_path}"),
            "0032_phase5_alert_fail_control",
        )
