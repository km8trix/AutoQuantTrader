from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from packages.persistence.database import EXPECTED_SCHEMA_REVISION
from packages.persistence.schema import (
    metadata,
    phase2_ledger_entries,
    phase2_ledger_postings,
    phase2_order_events,
    phase2_reservation_release_events,
    phase2_simulation_horizon_facts,
    phase2_submission_attempt_events,
)

ROOT = Path(__file__).resolve().parents[2]
PHASE2_TABLE_NAMES = frozenset(
    {
        "phase2_account_lease_heads",
        "phase2_account_lease_releases",
        "phase2_account_leases",
        "phase2_authorization_consumptions",
        "phase2_backtest_audit_events",
        "phase2_backtest_fixtures",
        "phase2_backtest_job_events",
        "phase2_backtest_job_heads",
        "phase2_backtest_jobs",
        "phase2_backtest_reports",
        "phase2_backtest_run_manifests",
        "phase2_batch_authorizations",
        "phase2_batch_decisions",
        "phase2_batch_members",
        "phase2_batch_reservations",
        "phase2_ledger_entries",
        "phase2_ledger_postings",
        "phase2_logical_orders",
        "phase2_order_events",
        "phase2_reservation_release_events",
        "phase2_simulation_horizon_facts",
        "phase2_submission_attempt_events",
        "phase2_submission_attempts",
        "phase2_strategy_configurations",
        "phase2_strategy_versions",
    }
)


def test_operational_schema_can_be_created_without_postgresql() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")

    metadata.create_all(engine)

    assert set(inspect(engine).get_table_names()) == {
        "calendar_sessions",
        "calendar_versions",
        "corporate_action_revisions",
        "corporate_action_set_members",
        "corporate_action_sets",
        "data_objects",
        "data_quality_issues",
        "data_quality_runs",
        "dataset_manifest_partitions",
        "dataset_manifests",
        "dataset_partitions",
        "fills",
        "ingestion_jobs",
        "instrument_identifiers",
        "instruments",
        "ledger_entries",
        "ledger_postings",
        "market_data_admission_checks",
        "market_data_admission_profiles",
        "market_data_admission_runs",
        "market_data_entitlements",
        "market_data_sources",
        "orders",
        "partition_quarantines",
        "phase2_account_lease_heads",
        "phase2_account_lease_releases",
        "phase2_account_leases",
        "phase2_authorization_consumptions",
        "phase2_backtest_audit_events",
        "phase2_backtest_fixtures",
        "phase2_backtest_job_events",
        "phase2_backtest_job_heads",
        "phase2_backtest_jobs",
        "phase2_backtest_reports",
        "phase2_backtest_run_manifests",
        "phase2_batch_authorizations",
        "phase2_batch_decisions",
        "phase2_batch_members",
        "phase2_batch_reservations",
        "phase2_ledger_entries",
        "phase2_ledger_postings",
        "phase2_logical_orders",
        "phase2_order_events",
        "phase2_reservation_release_events",
        "phase2_simulation_horizon_facts",
        "phase2_submission_attempt_events",
        "phase2_submission_attempts",
        "phase2_strategy_configurations",
        "phase2_strategy_versions",
        "risk_account_guards",
        "risk_decisions",
        "risk_reservations",
        "replay_run_manifests",
        "submission_attempts",
        "universe_memberships",
        "universe_versions",
    }


def test_readiness_revision_pin_matches_the_single_alembic_head() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))

    assert ScriptDirectory.from_config(config).get_current_head() == EXPECTED_SCHEMA_REVISION


def test_index_backed_constraint_names_are_schema_wide_unique() -> None:
    """PostgreSQL places indexes for primary/unique constraints in one namespace."""

    owners: dict[str, list[str]] = {}
    for table in metadata.tables.values():
        index_backed = [
            constraint
            for constraint in table.constraints
            if isinstance(constraint, sa.PrimaryKeyConstraint | sa.UniqueConstraint)
        ]
        for schema_item in (*index_backed, *table.indexes):
            name = schema_item.name
            assert isinstance(name, str)
            owners.setdefault(name, []).append(table.name)

    assert {name: table_names for name, table_names in owners.items() if len(table_names) > 1} == {}


def test_simulation_horizon_schema_preserves_exact_proof_bindings() -> None:
    assert tuple(phase2_simulation_horizon_facts.c.keys()) == (
        "horizon_id",
        "horizon_reference",
        "horizon_source_sha256",
        "reservation_id",
        "parent_decision_id",
        "authorization_id",
        "attempt_id",
        "order_id",
        "final_order_event_id",
        "replay_run_id",
        "replay_manifest_sha256",
        "replay_event_count",
        "replay_watermark_count",
        "simulation_result_id",
        "horizon_at",
        "recorded_at",
        "canonical_payload",
        "semantic_sha256",
    )
    assert {
        tuple(column.target_fullname for column in constraint.elements)
        for constraint in phase2_simulation_horizon_facts.foreign_key_constraints
    } == {
        ("phase2_batch_reservations.reservation_id",),
        ("phase2_batch_decisions.decision_id",),
        ("phase2_batch_authorizations.authorization_id",),
        ("phase2_submission_attempts.attempt_id",),
        ("phase2_logical_orders.order_id",),
        ("phase2_order_events.event_id",),
        ("replay_run_manifests.run_id",),
        ("replay_run_manifests.manifest_sha256",),
    }
    assert {index.name for index in phase2_simulation_horizon_facts.indexes} == {
        "ix_phase2_simulation_horizon_facts_reservation_recorded"
    }


def test_phase2_durability_migration_is_additive_and_reversible(tmp_path: Path) -> None:
    database_path = tmp_path / "phase2-durability.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0006_replay_run_manifests")
    engine = create_engine(database_url)
    legacy_tables = set(inspect(engine).get_table_names())
    legacy_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in legacy_tables
    }

    command.upgrade(config, "head")

    upgraded_tables = set(inspect(engine).get_table_names())
    assert upgraded_tables == legacy_tables | PHASE2_TABLE_NAMES
    assert {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in legacy_tables
    } == legacy_columns

    engine.dispose()
    command.downgrade(config, "0006_replay_run_manifests")
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == legacy_tables
    downgraded_engine.dispose()


def test_phase2_durability_checks_reject_ambiguous_facts_and_allow_unit_postings() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata.create_all(engine)
    instant = datetime(2026, 7, 20, 14, 30, tzinfo=UTC)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="pending-not-first",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="pending",
                occurred_at=instant,
                recorded_at=instant,
                response_sha256=None,
                broker_order_id=None,
                error_class=None,
                canonical_payload="{}",
                semantic_sha256="a" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="in-flight-without-dispatch-receipt",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="in_flight",
                occurred_at=instant,
                recorded_at=instant,
                previous_event_sha256="a" * 64,
                canonical_payload="{}",
                semantic_sha256="b" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                event_id="abandoned-without-recovery-reason",
                attempt_id="attempt-not-required-for-check",
                sequence_number=2,
                state="abandoned",
                occurred_at=instant,
                recorded_at=instant,
                previous_event_sha256="a" * 64,
                canonical_payload="{}",
                semantic_sha256="c" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_order_events).values(
                event_id="accepted-with-execution-fields",
                order_id="order-not-required-for-check",
                broker_order_id="broker-order",
                broker_sequence=1,
                occurred_at=instant,
                received_at=instant,
                kind="accepted",
                reason=None,
                execution_id="unexpected-execution",
                execution_revision=1,
                supersedes_event_id=None,
                quantity=Decimal(1),
                price=Decimal(1),
                fee=Decimal(0),
                canonical_payload="{}",
                semantic_sha256="d" * 64,
            )
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_reservation_release_events).values(
                release_event_id="zero-release",
                reservation_id="reservation-not-required-for-check",
                authorization_id="authorization-not-required-for-check",
                order_id=None,
                attempt_id=None,
                order_event_id=None,
                reason="approval_expired_unsent",
                finality_reference="durably-never-dispatched",
                source_sha256="e" * 64,
                released_cash=Decimal(0),
                released_buy_exposure=Decimal(0),
                released_sell_quantity=Decimal(0),
                occurred_at=instant,
                recorded_at=instant,
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )

    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_ledger_entries).values(
                entry_id="split-entry",
                account_id="simulation-account",
                kind="stock_split",
                reference_id="split-reference",
                source_sha256="e" * 64,
                effective_at=instant,
                recorded_at=instant,
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )
        connection.execute(
            sa.insert(phase2_ledger_postings).values(
                entry_id="split-entry",
                line_number=1,
                account="security_units:instrument-a",
                currency="USD",
                debit=Decimal(0),
                credit=Decimal(0),
                units_delta=Decimal(5),
                instrument_id="instrument-a",
                semantic_sha256="1" * 64,
            )
        )

    with engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(phase2_ledger_postings)) == 1
        )


def test_phase_zero_database_upgrades_to_point_in_time_catalog(tmp_path: Path) -> None:
    database_path = tmp_path / "upgrade.sqlite"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")

    command.upgrade(config, "0003_submission_attempts")
    engine = create_engine(f"sqlite+pysqlite:///{database_path}")
    assert "dataset_manifests" not in inspect(engine).get_table_names()

    command.upgrade(config, "0004_point_in_time_data")

    assert "dataset_manifests" in inspect(engine).get_table_names()
    assert "market_data_admission_runs" not in inspect(engine).get_table_names()

    command.upgrade(config, "0005_market_data_admission")

    assert "market_data_admission_runs" in inspect(engine).get_table_names()
    assert "replay_run_manifests" not in inspect(engine).get_table_names()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO data_objects "
                "(object_id, object_key, byte_checksum, semantic_checksum, format, size_bytes, "
                "created_at) VALUES (:object_id, :object_key, :byte_checksum, "
                ":semantic_checksum, 'parquet', 1, :created_at)"
            ),
            {
                "object_id": "a" * 64,
                "object_key": f"normalized/sha256/aa/{'a' * 64}.parquet",
                "byte_checksum": "a" * 64,
                "semantic_checksum": "b" * 64,
                "created_at": "2026-07-18T00:00:00+00:00",
            },
        )
        connection.execute(
            text(
                "INSERT INTO dataset_partitions "
                "(partition_id, object_id, job_id, source_id, layer, status, schema_version, "
                "price_basis, row_count, event_time_start, event_time_end, available_at_start, "
                "available_at_end, semantic_checksum, created_at) VALUES "
                "(:partition_id, :object_id, :job_id, :source_id, 'normalized', 'published', "
                "'raw-bar-v1', 'raw', 1, :instant, :instant, :instant, :instant, "
                ":semantic_checksum, :instant)"
            ),
            {
                "partition_id": "c" * 64,
                "object_id": "a" * 64,
                "job_id": "d" * 64,
                "source_id": "legacy-fixture",
                "semantic_checksum": "b" * 64,
                "instant": "2026-07-18T00:00:00+00:00",
            },
        )
        connection.execute(
            text(
                "INSERT INTO calendar_versions "
                "(calendar_version, name, timezone, tzdata_version, content_hash, created_at) "
                "VALUES ('legacy-calendar', 'Legacy', 'UTC', '2026a', :hash, :created_at)"
            ),
            {"hash": "e" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO universe_versions "
                "(universe_version, name, effective_as_of, created_at, content_hash) "
                "VALUES ('legacy-universe', 'Legacy', :created_at, :created_at, :hash)"
            ),
            {"hash": "f" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )
        connection.execute(
            text(
                "INSERT INTO corporate_action_sets "
                "(corporate_action_version, name, content_hash, created_at) "
                "VALUES ('legacy-actions', 'Legacy', :hash, :created_at)"
            ),
            {"hash": "0" * 64, "created_at": "2026-07-18T00:00:00+00:00"},
        )

    command.upgrade(config, "head")

    assert "replay_run_manifests" in inspect(engine).get_table_names()
    assert "phase2_batch_members" in inspect(engine).get_table_names()
    assert "phase2_batch_reservations" in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
        assert (
            connection.scalar(text("SELECT semantic_checksum_version FROM data_objects"))
            == "input-v1"
        )
        assert (
            connection.scalar(text("SELECT semantic_checksum_version FROM dataset_partitions"))
            == "input-v1"
        )
        for table_name in (
            "calendar_versions",
            "universe_versions",
            "corporate_action_sets",
        ):
            assert (
                connection.scalar(text(f"SELECT content_hash_version FROM {table_name}"))
                == "input-v1"
            )
