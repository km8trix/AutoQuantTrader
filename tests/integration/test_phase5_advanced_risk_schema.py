"""Focused exit gates for the additive Phase 5B persistence schema."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from packages.persistence.schema import (
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_assignment_heads,
    phase5_advanced_risk_assignments,
    phase5_advanced_risk_batch_admissions,
    phase5_advanced_risk_batch_outcomes,
    phase5_advanced_risk_enforcement_heads,
    phase5_advanced_risk_evidence,
    phase5_advanced_risk_evidence_sources,
    phase5_advanced_risk_policies,
)

ROOT = Path(__file__).resolve().parents[2]
PRIOR_REVISION = "0025_phase5_operational_control"
REVISION = "0026_phase5_advanced_risk"
OUTCOME_PRIOR_REVISION = "0029_phase4_account_activities"
OUTCOME_REVISION = "0030_phase5_adv_outcomes"

PHASE5_ADVANCED_RISK_BASE_TABLES = (
    phase5_advanced_risk_policies,
    phase5_advanced_risk_assignments,
    phase5_advanced_risk_assignment_heads,
    phase5_advanced_risk_evidence,
    phase5_advanced_risk_evidence_sources,
    phase5_advanced_risk_assessments,
    phase5_advanced_risk_batch_admissions,
    phase5_advanced_risk_enforcement_heads,
)
PHASE5_ADVANCED_RISK_TABLES = (
    *PHASE5_ADVANCED_RISK_BASE_TABLES,
    phase5_advanced_risk_batch_outcomes,
)
PHASE5_ADVANCED_RISK_BASE_TABLE_NAMES = frozenset(
    table.name for table in PHASE5_ADVANCED_RISK_BASE_TABLES
)


def _migration_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _foreign_key_targets(table: sa.Table) -> set[tuple[str, ...]]:
    return {
        tuple(element.target_fullname for element in constraint.elements)
        for constraint in table.foreign_key_constraints
    }


def test_phase5_advanced_risk_metadata_compiles_and_binds_exact_sources() -> None:
    for table in PHASE5_ADVANCED_RISK_TABLES:
        assert str(CreateTable(table).compile(dialect=sqlite.dialect()))
        assert str(
            CreateTable(table).compile(
                dialect=postgresql.dialect()  # type: ignore[no-untyped-call]
            )
        )
        for constraint in table.constraints:
            assert isinstance(constraint.name, str)
            assert len(constraint.name) <= 63
        for index in table.indexes:
            assert isinstance(index.name, str)
            assert len(index.name) <= 63

    assert (
        "phase2_account_leases.account_id",
        "phase2_account_leases.fencing_generation",
        "phase2_account_leases.lease_sha256",
    ) in _foreign_key_targets(phase5_advanced_risk_assignments)
    assert (
        "phase5_operational_control_transitions.account_id",
        "phase5_operational_control_transitions.transition_id",
        "phase5_operational_control_transitions.semantic_sha256",
    ) in _foreign_key_targets(phase5_advanced_risk_assignments)
    assert (
        "phase5_advanced_risk_assignments.account_id",
        "phase5_advanced_risk_assignments.assignment_id",
        "phase5_advanced_risk_assignments.sequence_number",
        "phase5_advanced_risk_assignments.policy_sha256",
        "phase5_advanced_risk_assignments.semantic_sha256",
    ) in _foreign_key_targets(phase5_advanced_risk_evidence)
    assert (
        "phase5_advanced_risk_evidence.account_id",
        "phase5_advanced_risk_evidence.evidence_id",
        "phase5_advanced_risk_evidence.semantic_sha256",
    ) in _foreign_key_targets(phase5_advanced_risk_evidence_sources)
    assert (
        "phase2_batch_decisions.decision_id",
        "phase2_batch_decisions.account_id",
        "phase2_batch_decisions.fencing_generation",
    ) in _foreign_key_targets(phase5_advanced_risk_batch_admissions)
    assert {
        column.name for column in phase5_advanced_risk_batch_admissions.c if column.nullable
    } == {
        "assessment_id",
        "assessment_sha256",
        "assignment_id",
        "assignment_sequence_number",
        "assignment_sha256",
        "policy_sha256",
        "observation_watermark_sequence",
        "watermark_evidence_id",
        "watermark_evidence_sha256",
        "assessment_mode",
        "assessment_disposition",
    }
    assert "cutover_observation_sequence" in phase5_advanced_risk_enforcement_heads.c
    assert (
        "phase5_advanced_risk_batch_admissions.admission_id",
        "phase5_advanced_risk_batch_admissions.account_id",
        "phase5_advanced_risk_batch_admissions.phase2_decision_id",
        "phase5_advanced_risk_batch_admissions.semantic_sha256",
    ) in _foreign_key_targets(phase5_advanced_risk_batch_outcomes)


def test_phase5_advanced_risk_migration_is_additive_and_reversible(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5b-schema.sqlite'}"
    config = _migration_config(database_url)
    command.upgrade(config, PRIOR_REVISION)

    engine = create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }
    engine.dispose()

    command.upgrade(config, REVISION)
    engine = create_engine(database_url)
    migrated_inspector = inspect(engine)
    assert set(migrated_inspector.get_table_names()) == (
        prior_tables | PHASE5_ADVANCED_RISK_BASE_TABLE_NAMES
    )
    assert {
        table_name: tuple(column["name"] for column in migrated_inspector.get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    for table in PHASE5_ADVANCED_RISK_BASE_TABLES:
        migrated_columns = migrated_inspector.get_columns(table.name)
        assert tuple(column["name"] for column in migrated_columns) == tuple(table.c.keys())
        assert {column["name"]: column["nullable"] for column in migrated_columns} == {
            column.name: column.nullable for column in table.c
        }
    engine.dispose()

    command.downgrade(config, PRIOR_REVISION)
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase5_advanced_risk_outcome_migration_upgrades_existing_history(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5b-outcome-schema.sqlite'}"
    config = _migration_config(database_url)
    command.upgrade(config, OUTCOME_PRIOR_REVISION)

    engine = create_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspect(engine).get_columns(table_name))
        for table_name in prior_tables
    }
    engine.dispose()

    command.upgrade(config, OUTCOME_REVISION)
    engine = create_engine(database_url)
    migrated_inspector = inspect(engine)
    assert set(migrated_inspector.get_table_names()) == (
        prior_tables | {phase5_advanced_risk_batch_outcomes.name}
    )
    assert {
        table_name: tuple(column["name"] for column in migrated_inspector.get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    migrated_columns = migrated_inspector.get_columns(phase5_advanced_risk_batch_outcomes.name)
    assert tuple(column["name"] for column in migrated_columns) == tuple(
        phase5_advanced_risk_batch_outcomes.c.keys()
    )
    assert {column["name"]: column["nullable"] for column in migrated_columns} == {
        column.name: column.nullable for column in phase5_advanced_risk_batch_outcomes.c
    }
    engine.dispose()

    command.downgrade(config, OUTCOME_PRIOR_REVISION)
    downgraded_engine = create_engine(database_url)
    assert set(inspect(downgraded_engine).get_table_names()) == prior_tables
    downgraded_engine.dispose()


def test_phase5_advanced_risk_outcome_fresh_revision_upgrade_has_one_owner(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5b-fresh-head.sqlite'}"
    config = _migration_config(database_url)

    command.upgrade(config, OUTCOME_REVISION)

    engine = create_engine(database_url)
    inspector = inspect(engine)
    assert inspector.has_table(phase5_advanced_risk_batch_outcomes.name)
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            OUTCOME_REVISION
        )
    engine.dispose()


def test_phase5_advanced_risk_migration_refuses_nonempty_downgrade(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5b-nonempty.sqlite'}"
    config = _migration_config(database_url)
    command.upgrade(config, REVISION)
    engine = create_engine(database_url)
    approved_at = datetime(2026, 7, 28, 16, 0, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase5_advanced_risk_policies).values(
                policy_sha256="a" * 64,
                policy_id="phase5b-moderate-paper-rth-etf-v1",
                policy_version="1",
                environment="paper",
                scope_profile_id="paper-rth-etf",
                scope_profile_sha256="b" * 64,
                rule_count=1,
                pretrade_new_exposure_rule_count=1,
                runtime_rule_count=1,
                none_disposition_count=0,
                reject_disposition_count=1,
                pause_disposition_count=1,
                halt_disposition_count=1,
                rules_payload="{}",
                approval_evidence_sha256="d" * 64,
                approved_at=approved_at,
                canonical_payload="{}",
                semantic_sha256="e" * 64,
            )
        )
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty advanced-risk history",
    ):
        command.downgrade(config, PRIOR_REVISION)
