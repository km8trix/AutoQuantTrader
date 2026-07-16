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

    command.upgrade(config, "head")

    assert "market_data_admission_runs" in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
