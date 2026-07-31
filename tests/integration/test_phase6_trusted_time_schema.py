from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from packages.domain.trusted_time import TRUSTED_TIME_POLICY
from packages.persistence.database import EXPECTED_SCHEMA_REVISION
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)

ROOT = Path(__file__).resolve().parents[2]
PHASE6_TABLE_NAMES = {
    "phase6_trusted_time_epoch_registrations",
    "phase6_trusted_time_host_heads",
    "phase6_trusted_time_probe_evaluations",
}
EPOCH_ID = "00000000-0000-0000-0000-000000000001"
BASE = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def _config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _foreign_keys(table: sa.Table) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    return {
        str(constraint.name): (
            tuple(element.parent.name for element in constraint.elements),
            tuple(element.target_fullname for element in constraint.elements),
        )
        for constraint in table.constraints
        if isinstance(constraint, sa.ForeignKeyConstraint)
    }


def test_phase6_trusted_time_schema_preserves_exact_durable_contract() -> None:
    assert tuple(phase6_trusted_time_epoch_registrations.c.keys()) == (
        "monitor_epoch_id",
        "host_id",
        "epoch_sequence",
        "previous_monitor_epoch_id",
        "previous_epoch_sha256",
        "previous_host_head_sha256",
        "source_id",
        "source_authority_sha256",
        "policy_sha256",
        "registered_at_utc",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase6_trusted_time_probe_evaluations.c.keys()) == (
        "evaluation_id",
        "host_id",
        "monitor_epoch_id",
        "epoch_sha256",
        "evaluation_sequence",
        "previous_evaluation_id",
        "previous_evaluation_sha256",
        "probe_status",
        "sample_sequence",
        "source_evidence_sha256",
        "probe_started_at_utc",
        "probe_completed_at_utc",
        "trusted_at_utc",
        "probe_started_monotonic_ns",
        "probe_completed_monotonic_ns",
        "sample_canonical_payload",
        "sample_sha256",
        "previous_state_sha256",
        "policy_sha256",
        "latest_sample_sha256",
        "sample_health",
        "health",
        "reason",
        "hard_failure_latched",
        "healthy_since_monotonic_ns",
        "clock_recovery_qualified",
        "evaluated_at_utc",
        "evaluated_at_monotonic_ns",
        "state_canonical_payload",
        "state_sha256",
        "evaluation_sha256",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase6_trusted_time_host_heads.c.keys()) == (
        "host_id",
        "epoch_sequence",
        "monitor_epoch_id",
        "epoch_sha256",
        "evaluation_sequence",
        "evaluation_id",
        "evaluation_record_sha256",
        "state_sha256",
        "health",
        "reason",
        "hard_failure_latched",
        "clock_recovery_qualified",
        "evaluated_at_utc",
        "evaluated_at_monotonic_ns",
        "canonical_payload",
        "semantic_sha256",
    )

    evaluation_foreign_keys = _foreign_keys(phase6_trusted_time_probe_evaluations)
    assert evaluation_foreign_keys["fk_phase6_trusted_time_eval_predecessor"] == (
        (
            "host_id",
            "monitor_epoch_id",
            "previous_evaluation_id",
            "previous_evaluation_sha256",
            "previous_state_sha256",
        ),
        (
            "phase6_trusted_time_probe_evaluations.host_id",
            "phase6_trusted_time_probe_evaluations.monitor_epoch_id",
            "phase6_trusted_time_probe_evaluations.evaluation_id",
            "phase6_trusted_time_probe_evaluations.semantic_sha256",
            "phase6_trusted_time_probe_evaluations.state_sha256",
        ),
    )
    head_foreign_keys = _foreign_keys(phase6_trusted_time_host_heads)
    assert head_foreign_keys["fk_phase6_trusted_time_head_epoch"][0] == (
        "host_id",
        "epoch_sequence",
        "monitor_epoch_id",
        "epoch_sha256",
    )
    assert head_foreign_keys["fk_phase6_trusted_time_head_tip"][0] == (
        "host_id",
        "monitor_epoch_id",
        "evaluation_sequence",
        "evaluation_id",
        "evaluation_record_sha256",
        "state_sha256",
        "health",
        "reason",
        "hard_failure_latched",
        "clock_recovery_qualified",
        "evaluated_at_utc",
        "evaluated_at_monotonic_ns",
    )


def test_phase6_trusted_time_schema_pins_policy_and_compiles_for_postgresql() -> None:
    policy_sha256 = TRUSTED_TIME_POLICY.semantic_sha256
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    assert policy_sha256 == ("e2ed2efe97b6a13764fba36976916001eec074773f1f2fcf37f759c80e474944")

    for table in (
        phase6_trusted_time_epoch_registrations,
        phase6_trusted_time_probe_evaluations,
        phase6_trusted_time_host_heads,
    ):
        sql = str(CreateTable(table).compile(dialect=dialect))
        assert table.name in sql
        assert "canonical_payload" in sql
        assert "semantic_sha256" in sql
    assert policy_sha256 in str(
        CreateTable(phase6_trusted_time_epoch_registrations).compile(dialect=dialect)
    )


def test_phase6_trusted_time_migration_is_additive_and_reversible(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-trusted-time.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "0033_phase4_activity_comparison")
    engine = sa.create_engine(database_url)
    inspector = sa.inspect(engine)
    prior_tables = set(inspector.get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspector.get_columns(table_name))
        for table_name in prior_tables
    }

    command.upgrade(config, "head")

    upgraded = sa.inspect(engine)
    assert set(upgraded.get_table_names()) == prior_tables | PHASE6_TABLE_NAMES
    assert {
        table_name: tuple(column["name"] for column in upgraded.get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    for table in (
        phase6_trusted_time_epoch_registrations,
        phase6_trusted_time_probe_evaluations,
        phase6_trusted_time_host_heads,
    ):
        assert tuple(column["name"] for column in upgraded.get_columns(table.name)) == tuple(
            table.c.keys()
        )
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )

    engine.dispose()
    command.downgrade(config, "0033_phase4_activity_comparison")
    downgraded = sa.create_engine(database_url)
    assert set(sa.inspect(downgraded).get_table_names()) == prior_tables
    downgraded.dispose()


def test_phase6_trusted_time_constraints_reject_partial_sample_shape(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-shape.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "head")
    engine = sa.create_engine(database_url)
    epoch_sha256 = "a" * 64
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_epoch_registrations).values(
                monitor_epoch_id=EPOCH_ID,
                host_id="paper-host-1",
                epoch_sequence=1,
                previous_monitor_epoch_id=None,
                previous_epoch_sha256=None,
                previous_host_head_sha256=None,
                source_id="injected-source",
                source_authority_sha256="b" * 64,
                policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
                registered_at_utc=BASE,
                canonical_payload="{}",
                semantic_sha256=epoch_sha256,
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_probe_evaluations).values(
                evaluation_id="00000000-0000-0000-0000-000000000002",
                host_id="paper-host-1",
                monitor_epoch_id=EPOCH_ID,
                epoch_sha256=epoch_sha256,
                evaluation_sequence=1,
                previous_evaluation_id=None,
                previous_evaluation_sha256=None,
                probe_status="recorded",
                sample_sequence=1,
                source_evidence_sha256=None,
                probe_started_at_utc=None,
                probe_completed_at_utc=None,
                trusted_at_utc=None,
                probe_started_monotonic_ns=None,
                probe_completed_monotonic_ns=None,
                sample_canonical_payload=None,
                sample_sha256=None,
                previous_state_sha256=None,
                policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
                latest_sample_sha256=None,
                sample_health="blocked",
                health="blocked",
                reason="startup_no_sample",
                hard_failure_latched=False,
                healthy_since_monotonic_ns=None,
                clock_recovery_qualified=False,
                evaluated_at_utc=BASE,
                evaluated_at_monotonic_ns=0,
                state_canonical_payload="{}",
                state_sha256="c" * 64,
                evaluation_sha256="d" * 64,
                canonical_payload="{}",
                semantic_sha256="e" * 64,
            )
        )
    engine.dispose()


def test_phase6_trusted_time_migration_refuses_nonempty_downgrade(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-nonempty.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "head")
    engine = sa.create_engine(database_url)
    epoch_sha256 = "a" * 64
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_epoch_registrations).values(
                monitor_epoch_id=EPOCH_ID,
                host_id="paper-host-1",
                epoch_sequence=1,
                previous_monitor_epoch_id=None,
                previous_epoch_sha256=None,
                previous_host_head_sha256=None,
                source_id="injected-source",
                source_authority_sha256="b" * 64,
                policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
                registered_at_utc=BASE,
                canonical_payload="{}",
                semantic_sha256=epoch_sha256,
            )
        )
        connection.execute(
            sa.insert(phase6_trusted_time_host_heads).values(
                host_id="paper-host-1",
                epoch_sequence=1,
                monitor_epoch_id=EPOCH_ID,
                epoch_sha256=epoch_sha256,
                evaluation_sequence=0,
                evaluation_id=None,
                evaluation_record_sha256=None,
                state_sha256=None,
                health=None,
                reason=None,
                hard_failure_latched=None,
                clock_recovery_qualified=None,
                evaluated_at_utc=None,
                evaluated_at_monotonic_ns=None,
                canonical_payload="{}",
                semantic_sha256="c" * 64,
            )
        )
    engine.dispose()

    with pytest.raises(RuntimeError, match="nonempty trusted-time history"):
        command.downgrade(config, "0033_phase4_activity_comparison")
