from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text

from packages.persistence.database import EXPECTED_SCHEMA_REVISION
from packages.persistence.schema import metadata

ROOT = Path(__file__).resolve().parents[2]


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
