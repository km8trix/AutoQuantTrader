from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from packages.adapters.broker.alpaca_paper_reconciliation import (
    normalize_authenticated_alpaca_paper_lookup,
)
from packages.application.alpaca_paper_reconciliation_normalization import (
    normalize_and_record_authenticated_alpaca_paper_lookup,
)
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    UnknownSubmissionResolution,
    resolve_unknown_submission,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_reconciliation import (
    BrokerReconciliationPersistenceConflict,
    BrokerReconciliationPersistenceError,
    SqlBrokerReconciliationRepository,
    verify_broker_reconciliation_integrity,
)
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    DatabaseSchemaNotReady,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase2_batch_reservations,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_logical_orders,
    phase2_submission_attempt_events,
    phase2_submission_attempts,
    phase4_broker_ingress_receipts,
    phase4_broker_reconciliation_facts,
    phase4_broker_reconciliation_heads,
)
from packages.persistence.submission_attempt import _event_values
from tests.integration.test_phase4_alpaca_paper_lookup_observation_persistence import (
    LookupPersistenceSystem,
    PreparedLookupPersistenceSystem,
    _run_lookup,
    _system,
)

ROOT = Path(__file__).resolve().parents[2]
_PHASE2_ECONOMIC_TABLES = (
    phase2_batch_reservations,
    phase2_logical_orders,
    phase2_submission_attempts,
    phase2_submission_attempt_events,
    phase2_ledger_entries,
    phase2_ledger_postings,
)


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _stamp_current_schema_revision(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
        )
        connection.execute(
            sa.text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": EXPECTED_SCHEMA_REVISION},
        )


class _FixedAttemptLoader:
    def __init__(self, attempt: CanonicalSubmissionAttempt) -> None:
        self._attempt = attempt

    def get(self, attempt_id: str) -> CanonicalSubmissionAttempt | None:
        if attempt_id != self._attempt.attempt_id:
            return None
        return self._attempt


def _economic_rows(engine: Engine) -> dict[str, tuple[dict[str, object], ...]]:
    with engine.connect() as connection:
        return {
            table.name: tuple(
                dict(row)
                for row in connection.execute(
                    sa.select(table).order_by(*table.primary_key.columns)
                ).mappings()
            )
            for table in _PHASE2_ECONOMIC_TABLES
        }


def _repository(
    system: LookupPersistenceSystem,
) -> SqlBrokerReconciliationRepository:
    submission = system.submission
    submission.coordinator_clock.instant = system.receipt.commit_checked_at + timedelta(seconds=1)
    return SqlBrokerReconciliationRepository(
        engine=submission.engine,
        clock=submission.coordinator_clock,
    )


def test_application_normalizes_exact_sources_without_changing_phase2_economics(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-application.sqlite")
    before = _economic_rows(system.submission.engine)
    repository = _repository(system)

    fact = normalize_and_record_authenticated_alpaca_paper_lookup(
        system.receipt.receipt_id,
        lookup_loader=system.repository,
        attempt_loader=system.submission.repository,
        ingress_loader=SqlBrokerIngressRepository(system.submission.engine),
        reconciliation_repository=repository,
    )

    assert repository.runtime_store_identity == id(system.submission.engine)
    assert repository.load(fact.fact_id) == fact
    assert repository.load_by_lookup_receipt_id(system.receipt.receipt_id) == fact
    assert repository.load_by_lookup_receipt_id(system.receipt.receipt_id) == fact
    assert repository.history(fact.evidence.account_id) == (fact,)
    assert fact.evidence.source_lookup_receipt_id == system.receipt.receipt_id
    assert fact.lifecycle_application_authorized is False
    assert fact.reconciliation_application_authorized is False
    assert fact.unknown_resolution_authorized is False
    assert fact.reservation_release_authorized is False
    assert fact.canonical_execution_fact_authorized is False
    assert fact.trading_effect_authorized is False
    assert _economic_rows(system.submission.engine) == before
    verify_broker_reconciliation_integrity(system.submission.engine)
    _stamp_current_schema_revision(system.submission.engine)
    verify_operational_schema(
        system.submission.engine,
        require_phase_zero_facts=False,
    )


def test_lookup_source_read_validates_exact_key_and_not_found(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-lookup-source-empty.sqlite")
    repository = _repository(system)

    assert repository.load_by_lookup_receipt_id(system.receipt.receipt_id) is None
    for invalid in ("", "0" * 36, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"):
        with pytest.raises(
            BrokerReconciliationPersistenceError,
            match=r"canonical UUID|bounded trimmed text",
        ):
            repository.load_by_lookup_receipt_id(invalid)


def test_exact_replay_is_idempotent_and_does_not_read_clock_again(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-replay.sqlite")
    repository = _repository(system)
    source = system.capture.evidence[0].persisted_observation
    evidence = normalize_authenticated_alpaca_paper_lookup(
        system.receipt,
        source,
    )
    first = repository.record(evidence)
    system.submission.coordinator_clock.instant = first.normalized_at - timedelta(days=1)

    replay = repository.record(evidence)

    assert replay == first
    assert repository.history(evidence.account_id) == (first,)
    with system.submission.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_broker_reconciliation_facts)
            )
            == 1
        )


def test_concurrent_same_source_normalization_commits_one_fact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-concurrent.sqlite")
    repository = _repository(system)
    evidence = normalize_authenticated_alpaca_paper_lookup(
        system.receipt,
        system.capture.evidence[0].persisted_observation,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(repository.record, evidence) for _ in range(2))
        facts = tuple(future.result() for future in futures)

    assert facts[0] == facts[1]
    assert repository.history(evidence.account_id) == (facts[0],)


def test_distinct_lookup_sources_append_a_contiguous_account_chain(
    tmp_path: Path,
) -> None:
    prepared = _system(tmp_path / "phase4k-chain.sqlite")
    repository = _repository(prepared)
    first_evidence = normalize_authenticated_alpaca_paper_lookup(
        prepared.receipt,
        prepared.capture.evidence[0].persisted_observation,
    )
    first = repository.record(first_evidence)

    prepared.submission.coordinator_clock.instant = prepared.receipt.commit_checked_at + timedelta(
        seconds=2
    )
    second_receipt = _run_lookup(
        prepared=PreparedLookupPersistenceSystem(
            submission=prepared.submission,
            attempt=prepared.attempt,
            account_binding=prepared.account_binding,
            reference=(prepared.capture.evidence[0].security_reference.credential_reference),
            repository=prepared.repository,
            capture=prepared.capture,
        ),
        provider_request_id="phase4k-second-provider-request",
        request_idempotency_key="phase4k-second-lookup-demand",
        delivery_idempotency_key="phase4k-second-lookup-delivery",
        lookup_at=prepared.receipt.commit_checked_at + timedelta(seconds=2),
    )
    second_evidence = normalize_authenticated_alpaca_paper_lookup(
        second_receipt,
        prepared.capture.evidence[-1].persisted_observation,
    )
    prepared.submission.coordinator_clock.instant = second_receipt.commit_checked_at + timedelta(
        seconds=1
    )
    second = repository.record(second_evidence)

    assert second.account_sequence == 2
    assert second.previous_fact_sha256 == first.semantic_sha256
    assert repository.history(first.evidence.account_id) == (first, second)


def test_later_attempt_resolution_does_not_invalidate_historical_fact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-later-resolution.sqlite")
    repository = _repository(system)
    fact = normalize_and_record_authenticated_alpaca_paper_lookup(
        system.receipt.receipt_id,
        lookup_loader=system.repository,
        attempt_loader=system.submission.repository,
        ingress_loader=SqlBrokerIngressRepository(system.submission.engine),
        reconciliation_repository=repository,
    )
    resolved = resolve_unknown_submission(
        system.attempt,
        occurred_at=fact.normalized_at,
        recorded_at=fact.normalized_at,
        resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
        reconciliation_sha256="a" * 64,
    )
    successor = resolved.events[-1]
    with system.submission.engine.begin() as connection:
        visibility_sequence = connection.scalar(
            sa.select(phase2_submission_attempt_events.c.visible_after_observation_sequence).where(
                phase2_submission_attempt_events.c.event_id == system.attempt.events[-1].event_id
            )
        )
        assert isinstance(visibility_sequence, int)
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                **_event_values(
                    successor,
                    account_id=system.receipt.account_id,
                    visible_after_observation_sequence=visibility_sequence,
                )
            )
        )

    assert repository.load(fact.fact_id) == fact
    assert (
        normalize_and_record_authenticated_alpaca_paper_lookup(
            system.receipt.receipt_id,
            lookup_loader=system.repository,
            attempt_loader=_FixedAttemptLoader(resolved),
            ingress_loader=SqlBrokerIngressRepository(system.submission.engine),
            reconciliation_repository=repository,
        )
        == fact
    )


def test_source_corruption_fails_reads_and_startup_verification(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-source-corruption.sqlite")
    repository = _repository(system)
    fact = repository.record(
        normalize_authenticated_alpaca_paper_lookup(
            system.receipt,
            system.capture.evidence[0].persisted_observation,
        )
    )
    with system.submission.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_broker_ingress_receipts)
            .where(
                phase4_broker_ingress_receipts.c.receipt_id
                == fact.evidence.source_ingress_receipt_id
            )
            .values(body_sha256="f" * 64)
        )

    with pytest.raises(
        BrokerReconciliationPersistenceConflict,
        match=r"body_sha256|body digest|source",
    ):
        repository.load(fact.fact_id)
    with pytest.raises(
        BrokerReconciliationPersistenceConflict,
        match=r"body_sha256|body digest|source",
    ):
        repository.load_by_lookup_receipt_id(
            fact.evidence.source_lookup_receipt_id,
        )
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="broker-ingress integrity verification failed",
    ):
        _stamp_current_schema_revision(system.submission.engine)
        verify_operational_schema(
            system.submission.engine,
            require_phase_zero_facts=False,
        )


def test_missing_head_fails_integrity_and_operational_readiness(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4k-missing-head.sqlite")
    repository = _repository(system)
    fact = repository.record(
        normalize_authenticated_alpaca_paper_lookup(
            system.receipt,
            system.capture.evidence[0].persisted_observation,
        )
    )
    with system.submission.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
        connection.execute(
            sa.delete(phase4_broker_reconciliation_heads).where(
                phase4_broker_reconciliation_heads.c.account_id == fact.evidence.account_id
            )
        )
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")

    with pytest.raises(
        BrokerReconciliationPersistenceConflict,
        match="without durable heads",
    ):
        verify_broker_reconciliation_integrity(system.submission.engine)
    with pytest.raises(
        BrokerReconciliationPersistenceConflict,
        match=r"head|durable",
    ):
        repository.load_by_lookup_receipt_id(
            fact.evidence.source_lookup_receipt_id,
        )
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="broker-reconciliation integrity verification failed",
    ):
        _stamp_current_schema_revision(system.submission.engine)
        verify_operational_schema(
            system.submission.engine,
            require_phase_zero_facts=False,
        )


def test_phase4k_migration_is_additive_and_reversible_when_empty(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase4k-migration.sqlite'}"
    config = _alembic_config(database_url)
    command.upgrade(config, "0016_phase4_unknown_schedule")
    engine = sa.create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "0017_phase4_reconciliation")

    assert set(inspect(engine).get_table_names()) == prior_tables | {
        "phase4_broker_reconciliation_facts",
        "phase4_broker_reconciliation_heads",
    }
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    engine.dispose()

    command.downgrade(config, "0016_phase4_unknown_schedule")
    downgraded = sa.create_engine(database_url)
    assert set(inspect(downgraded).get_table_names()) == prior_tables
    downgraded.dispose()


def test_phase4k_migration_refuses_nonempty_history_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4k-nonempty-downgrade.sqlite"
    system = _system(database_path)
    repository = _repository(system)
    repository.record(
        normalize_authenticated_alpaca_paper_lookup(
            system.receipt,
            system.capture.evidence[0].persisted_observation,
        )
    )
    _stamp_current_schema_revision(system.submission.engine)
    database_url = f"sqlite+pysqlite:///{database_path}"
    system.submission.engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty broker reconciliation",
    ):
        command.downgrade(
            _alembic_config(database_url),
            "0016_phase4_unknown_schedule",
        )

    preserved = sa.create_engine(database_url)
    with preserved.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_broker_reconciliation_facts)
            )
            == 1
        )
    preserved.dispose()
