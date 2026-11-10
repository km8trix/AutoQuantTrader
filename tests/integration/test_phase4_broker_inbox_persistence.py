from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from packages.adapters.broker.alpaca_paper_inbox import (
    create_alpaca_paper_inbox_admission_request,
)
from packages.adapters.broker.alpaca_paper_reconciliation import (
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.application.broker_inbox_admission import (
    admit_authenticated_alpaca_paper_reconciliation_fact,
)
from packages.domain.broker_inbox import (
    BrokerInboxDisposition,
    BrokerInboxError,
)
from packages.domain.broker_reconciliation import BrokerReconciliationFact
from packages.persistence.broker_inbox import (
    BrokerInboxPersistenceConflict,
    BrokerInboxPersistenceError,
    SqlBrokerInboxRepository,
    verify_broker_inbox_integrity,
)
from packages.persistence.broker_reconciliation import (
    SqlBrokerReconciliationRepository,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase4_broker_inbox_application_receipts,
    phase4_broker_inbox_heads,
    phase4_broker_inbox_source_links,
    phase4_broker_normalized_facts,
)
from tests.integration.test_phase4_alpaca_paper_lookup_observation_persistence import (
    LookupPersistenceSystem,
    PreparedLookupPersistenceSystem,
    _run_lookup,
    _system,
)
from tests.integration.test_phase4_lookup_reconciliation_persistence import (
    _economic_rows,
    _stamp_current_schema_revision,
)
from tests.integration.test_phase4_lookup_reconciliation_persistence import (
    _repository as _reconciliation_repository,
)

ROOT = Path(__file__).resolve().parents[2]


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _prepared_inbox(
    database_path: Path,
) -> tuple[
    LookupPersistenceSystem,
    SqlBrokerInboxRepository,
    BrokerReconciliationFact,
]:
    system = _system(database_path)
    reconciliation = _reconciliation_repository(system)
    fact = reconciliation.record(
        normalize_authenticated_alpaca_paper_lookup(
            system.receipt,
            system.capture.evidence[0].persisted_observation,
        )
    )
    system.submission.coordinator_clock.instant = fact.normalized_at + timedelta(seconds=1)
    inbox = SqlBrokerInboxRepository(
        engine=system.submission.engine,
        clock=system.submission.coordinator_clock,
    )
    return system, inbox, fact


def _table_count(engine: Engine, table: sa.Table) -> int:
    with engine.connect() as connection:
        value = connection.scalar(sa.select(sa.func.count()).select_from(table))
    assert isinstance(value, int)
    return value


def test_application_admits_exact_source_without_phase2_economic_mutation(
    tmp_path: Path,
) -> None:
    system, inbox, fact = _prepared_inbox(tmp_path / "phase4l-application.sqlite")
    before = _economic_rows(system.submission.engine)
    reconciliation = SqlBrokerReconciliationRepository(
        engine=system.submission.engine,
        clock=system.submission.coordinator_clock,
    )

    decision = admit_authenticated_alpaca_paper_reconciliation_fact(
        fact.fact_id,
        reconciliation_loader=reconciliation,
        inbox_repository=inbox,
    )

    assert inbox.runtime_store_identity == id(system.submission.engine)
    assert decision.disposition is (BrokerInboxDisposition.WITHHELD_UNQUALIFIED_REVISION_IDENTITY)
    assert decision.application_withheld is True
    assert decision.provider_revision_identity_qualified is False
    assert decision.provider_deduplication_authorized is False
    assert decision.inbox_application_authorized is False
    assert decision.lifecycle_application_authorized is False
    assert decision.canonical_execution_fact_authorized is False
    assert decision.trading_effect_authorized is False
    assert inbox.load(decision.decision_id) == decision
    assert inbox.load_by_reconciliation_fact_id(fact.fact_id) == decision
    assert inbox.load_by_reconciliation_fact_id(fact.fact_id) == decision
    assert inbox.history(fact.evidence.account_id) == (decision,)
    assert _economic_rows(system.submission.engine) == before
    verify_broker_inbox_integrity(system.submission.engine)
    _stamp_current_schema_revision(system.submission.engine)
    verify_operational_schema(
        system.submission.engine,
        require_phase_zero_facts=False,
    )


def test_reconciliation_source_read_validates_exact_key_and_not_found(
    tmp_path: Path,
) -> None:
    _system, inbox, fact = _prepared_inbox(tmp_path / "phase4l-reconciliation-source-empty.sqlite")

    assert inbox.load_by_reconciliation_fact_id(fact.fact_id) is None
    for invalid in ("", "0" * 36, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"):
        with pytest.raises(
            BrokerInboxPersistenceError,
            match=r"canonical UUID|bounded trimmed text",
        ):
            inbox.load_by_reconciliation_fact_id(invalid)


def test_exact_retry_is_idempotent_and_does_not_read_clock_again(
    tmp_path: Path,
) -> None:
    system, inbox, fact = _prepared_inbox(tmp_path / "phase4l-retry.sqlite")
    request = create_alpaca_paper_inbox_admission_request(fact)
    first = inbox.record(request)
    system.submission.coordinator_clock.instant = fact.normalized_at - timedelta(seconds=1)

    replay = inbox.record(request)

    assert replay == first
    assert inbox.history(fact.evidence.account_id) == (first,)
    for table in (
        phase4_broker_normalized_facts,
        phase4_broker_inbox_source_links,
        phase4_broker_inbox_heads,
        phase4_broker_inbox_application_receipts,
    ):
        assert _table_count(system.submission.engine, table) == 1


def test_concurrent_exact_retry_commits_one_source_position(
    tmp_path: Path,
) -> None:
    system, inbox, fact = _prepared_inbox(tmp_path / "phase4l-concurrent.sqlite")
    request = create_alpaca_paper_inbox_admission_request(fact)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(inbox.record, request) for _ in range(2))
        decisions = tuple(future.result() for future in futures)

    assert decisions[0] == decisions[1]
    assert inbox.history(fact.evidence.account_id) == (decisions[0],)
    assert _table_count(system.submission.engine, phase4_broker_inbox_source_links) == 1


def test_distinct_sources_advance_gap_free_inbox_chain(
    tmp_path: Path,
) -> None:
    system, inbox, first_fact = _prepared_inbox(tmp_path / "phase4l-chain.sqlite")
    first = inbox.record(create_alpaca_paper_inbox_admission_request(first_fact))
    credential_reference = system.capture.evidence[0].security_reference.credential_reference
    second_receipt = _run_lookup(
        prepared=PreparedLookupPersistenceSystem(
            submission=system.submission,
            attempt=system.attempt,
            account_binding=system.account_binding,
            reference=credential_reference,
            repository=system.repository,
            capture=system.capture,
        ),
        provider_request_id="phase4l-second-provider-request",
        request_idempotency_key="phase4l-second-lookup-demand",
        delivery_idempotency_key="phase4l-second-lookup-delivery",
        lookup_at=first.decided_at + timedelta(seconds=1),
    )
    system.submission.coordinator_clock.instant = second_receipt.commit_checked_at + timedelta(
        seconds=1
    )
    reconciliation = SqlBrokerReconciliationRepository(
        engine=system.submission.engine,
        clock=system.submission.coordinator_clock,
    )
    second_fact = reconciliation.record(
        normalize_authenticated_alpaca_paper_lookup(
            second_receipt,
            system.capture.evidence[-1].persisted_observation,
        )
    )
    system.submission.coordinator_clock.instant = second_fact.normalized_at + timedelta(seconds=1)
    second = inbox.record(create_alpaca_paper_inbox_admission_request(second_fact))

    assert inbox.history(first_fact.evidence.account_id) == (first, second)
    with system.submission.engine.connect() as connection:
        rows = connection.execute(
            sa.select(phase4_broker_inbox_source_links).order_by(
                phase4_broker_inbox_source_links.c.account_sequence
            )
        ).mappings()
        links = tuple(rows)
    assert tuple(row["account_sequence"] for row in links) == (1, 2)
    assert links[0]["previous_link_sha256"] is None
    assert links[1]["previous_link_sha256"] == links[0]["semantic_sha256"]


@pytest.mark.parametrize(
    ("table", "column", "replacement"),
    (
        (
            phase4_broker_normalized_facts,
            "canonical_payload",
            "[]",
        ),
        (
            phase4_broker_inbox_source_links,
            "canonical_payload",
            "[]",
        ),
        (
            phase4_broker_inbox_application_receipts,
            "disposition",
            BrokerInboxDisposition.INCONCLUSIVE_NOT_VISIBLE.value,
        ),
    ),
)
def test_fact_link_and_decision_corruption_fail_reads_and_startup(
    tmp_path: Path,
    table: sa.Table,
    column: str,
    replacement: str,
) -> None:
    system, inbox, fact = _prepared_inbox(tmp_path / f"phase4l-corruption-{table.name}.sqlite")
    decision = inbox.record(create_alpaca_paper_inbox_admission_request(fact))
    with system.submission.engine.begin() as connection:
        connection.execute(sa.update(table).values({column: replacement}))

    with pytest.raises(BrokerInboxError):
        inbox.load(decision.decision_id)
    with pytest.raises(BrokerInboxError):
        inbox.load_by_reconciliation_fact_id(fact.fact_id)
    _stamp_current_schema_revision(system.submission.engine)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="broker-inbox integrity verification failed",
    ):
        verify_operational_schema(
            system.submission.engine,
            require_phase_zero_facts=False,
        )


def test_missing_head_and_orphan_normalized_fact_fail_integrity(
    tmp_path: Path,
) -> None:
    missing_head_system, missing_head_inbox, fact = _prepared_inbox(
        tmp_path / "phase4l-missing-head.sqlite"
    )
    missing_head_inbox.record(create_alpaca_paper_inbox_admission_request(fact))
    with missing_head_system.submission.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.execute(sa.delete(phase4_broker_inbox_heads))
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
    with pytest.raises(BrokerInboxError):
        verify_broker_inbox_integrity(missing_head_system.submission.engine)
    with pytest.raises(BrokerInboxPersistenceConflict):
        missing_head_inbox.load_by_reconciliation_fact_id(fact.fact_id)

    orphan_system, orphan_inbox, orphan_fact = _prepared_inbox(tmp_path / "phase4l-orphan.sqlite")
    orphan_inbox.record(create_alpaca_paper_inbox_admission_request(orphan_fact))
    with orphan_system.submission.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.execute(sa.delete(phase4_broker_inbox_application_receipts))
        connection.execute(sa.delete(phase4_broker_inbox_source_links))
        connection.execute(sa.delete(phase4_broker_inbox_heads))
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
    with pytest.raises(BrokerInboxError):
        verify_broker_inbox_integrity(orphan_system.submission.engine)


def test_phase4l_migration_is_additive_and_reversible_when_empty(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase4l-migration.sqlite'}"
    config = _alembic_config(database_url)
    command.upgrade(config, "0017_phase4_reconciliation")
    engine = sa.create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "0018_phase4_broker_inbox")

    assert set(inspect(engine).get_table_names()) == prior_tables | {
        "phase4_broker_normalized_facts",
        "phase4_broker_inbox_source_links",
        "phase4_broker_inbox_heads",
        "phase4_broker_inbox_application_receipts",
    }
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    engine.dispose()

    command.downgrade(config, "0017_phase4_reconciliation")
    downgraded = sa.create_engine(database_url)
    assert set(inspect(downgraded).get_table_names()) == prior_tables
    downgraded.dispose()


def test_phase4l_migration_refuses_nonempty_history_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4l-nonempty-downgrade.sqlite"
    system, inbox, fact = _prepared_inbox(database_path)
    inbox.record(create_alpaca_paper_inbox_admission_request(fact))
    _stamp_current_schema_revision(system.submission.engine)
    database_url = f"sqlite+pysqlite:///{database_path}"
    system.submission.engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty source-scoped broker inbox history",
    ):
        command.downgrade(
            _alembic_config(database_url),
            "0017_phase4_reconciliation",
        )

    preserved = sa.create_engine(database_url)
    assert _table_count(preserved, phase4_broker_inbox_source_links) == 1
    preserved.dispose()
