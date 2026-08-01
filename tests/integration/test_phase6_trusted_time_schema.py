from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
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
    phase6_trusted_time_head_anchor_intents,
    phase6_trusted_time_head_anchor_receipts,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.sqlite_config import enforce_sqlite_foreign_keys

ROOT = Path(__file__).resolve().parents[2]
PHASE6_TABLE_NAMES = {
    "phase6_trusted_time_epoch_registrations",
    "phase6_trusted_time_head_anchor_intents",
    "phase6_trusted_time_head_anchor_receipts",
    "phase6_trusted_time_host_heads",
    "phase6_trusted_time_probe_evaluations",
}
EPOCH_ID = "00000000-0000-0000-0000-000000000001"
ANCHOR_INTENT_ID = "00000000-0000-0000-0000-000000000003"
ANCHOR_RECEIPT_ID = "00000000-0000-0000-0000-000000000004"
PRINCIPAL_ID = "00000000-0000-0000-0000-000000000005"
BASE = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ENVELOPE_BYTES = b"{}"
ENVELOPE_SHA256 = hashlib.sha256(ENVELOPE_BYTES).hexdigest()
DEPLOYMENT_IDENTITY_SHA256 = "1" * 64
RUNTIME_DATABASE_IDENTITY_SHA256 = "2" * 64
ANCHOR_PROJECT_IDENTITY_SHA256 = "3" * 64
ANCHOR_PROJECT_REF = "abcdefghijklmnopqrst"
HOST_IDENTITY_SHA256 = "4" * 64


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


def _anchor_object_name(*, sequence: int, envelope_sha256: str) -> str:
    return (
        f"v1/{DEPLOYMENT_IDENTITY_SHA256}/{HOST_IDENTITY_SHA256}/"
        f"{sequence:020d}-{envelope_sha256}.json"
    )


def _genesis_epoch_values(*, epoch_sha256: str) -> dict[str, object]:
    return {
        "monitor_epoch_id": EPOCH_ID,
        "host_id": "paper-host-1",
        "epoch_sequence": 1,
        "previous_monitor_epoch_id": None,
        "previous_epoch_sha256": None,
        "previous_host_head_sha256": None,
        "source_id": "injected-source",
        "source_authority_sha256": "b" * 64,
        "policy_sha256": TRUSTED_TIME_POLICY.semantic_sha256,
        "registered_at_utc": BASE,
        "canonical_payload": "{}",
        "semantic_sha256": epoch_sha256,
    }


def _genesis_head_values(*, epoch_sha256: str, head_sha256: str) -> dict[str, object]:
    return {
        "host_id": "paper-host-1",
        "epoch_sequence": 1,
        "monitor_epoch_id": EPOCH_ID,
        "epoch_sha256": epoch_sha256,
        "evaluation_sequence": 0,
        "evaluation_id": None,
        "evaluation_record_sha256": None,
        "state_sha256": None,
        "health": None,
        "reason": None,
        "hard_failure_latched": None,
        "clock_recovery_qualified": None,
        "evaluated_at_utc": None,
        "evaluated_at_monotonic_ns": None,
        "canonical_payload": "{}",
        "semantic_sha256": head_sha256,
    }


def _anchor_intent_values(
    *,
    epoch_sha256: str,
    head_sha256: str,
    **overrides: object,
) -> dict[str, object]:
    values: dict[str, object] = {
        "anchor_intent_id": ANCHOR_INTENT_ID,
        "host_id": "paper-host-1",
        "anchor_sequence": 1,
        "previous_anchor_sha256": None,
        "previous_anchored_host_head_sha256": None,
        "checkpoint_reason": "enrollment",
        "checkpoint_interval_seconds": 300,
        "anchor_authority_sha256": "a" * 64,
        "deployment_identity_sha256": DEPLOYMENT_IDENTITY_SHA256,
        "runtime_database_identity_sha256": RUNTIME_DATABASE_IDENTITY_SHA256,
        "anchor_project_identity_sha256": ANCHOR_PROJECT_IDENTITY_SHA256,
        "anchor_project_ref": ANCHOR_PROJECT_REF,
        "bucket_name": "aqt-trusted-time-anchors-v1",
        "principal_id": PRINCIPAL_ID,
        "signing_key_id": "phase6d-anchor-key-v1",
        "signing_public_key_sha256": "5" * 64,
        "head_authenticated_at_utc": BASE,
        "source_id": "injected-source",
        "source_authority_sha256": "b" * 64,
        "policy_sha256": TRUSTED_TIME_POLICY.semantic_sha256,
        "persistence_contract_version": "phase6a-durable-trusted-time-persistence-v2",
        "epoch_sequence": 1,
        "monitor_epoch_id": EPOCH_ID,
        "epoch_sha256": epoch_sha256,
        "evaluation_sequence": 0,
        "evaluation_id": None,
        "evaluation_record_sha256": None,
        "state_sha256": None,
        "probe_status": None,
        "health": None,
        "reason": None,
        "hard_failure_latched": None,
        "clock_recovery_qualified": None,
        "evaluated_at_utc": None,
        "evaluated_at_monotonic_ns": None,
        "local_previous_host_head_sha256": None,
        "current_host_head_sha256": head_sha256,
        "host_identity_sha256": HOST_IDENTITY_SHA256,
        "object_name": _anchor_object_name(
            sequence=1,
            envelope_sha256=ENVELOPE_SHA256,
        ),
        "signed_envelope_bytes": ENVELOPE_BYTES,
        "signed_envelope_text": ENVELOPE_BYTES.decode("utf-8"),
        "signed_envelope_sha256": ENVELOPE_SHA256,
        "created_at_utc": BASE,
        "canonical_payload": "{}",
        "semantic_sha256": "f" * 64,
    }
    values.update(overrides)
    return values


def _anchor_receipt_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "anchor_receipt_id": ANCHOR_RECEIPT_ID,
        "anchor_intent_id": ANCHOR_INTENT_ID,
        "anchor_intent_sha256": "f" * 64,
        "signed_envelope_sha256": ENVELOPE_SHA256,
        "deployment_identity_sha256": DEPLOYMENT_IDENTITY_SHA256,
        "runtime_database_identity_sha256": RUNTIME_DATABASE_IDENTITY_SHA256,
        "anchor_project_identity_sha256": ANCHOR_PROJECT_IDENTITY_SHA256,
        "anchor_project_ref": ANCHOR_PROJECT_REF,
        "bucket_name": "aqt-trusted-time-anchors-v1",
        "principal_id": PRINCIPAL_ID,
        "object_name": _anchor_object_name(
            sequence=1,
            envelope_sha256=ENVELOPE_SHA256,
        ),
        "readback_bytes_sha256": ENVELOPE_SHA256,
        "observed_at_utc": BASE,
        "canonical_payload": "{}",
        "semantic_sha256": "9" * 64,
    }
    values.update(overrides)
    return values


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
        "source_uncertainty_milliseconds",
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
    assert tuple(phase6_trusted_time_head_anchor_intents.c.keys()) == (
        "anchor_intent_id",
        "host_id",
        "anchor_sequence",
        "previous_anchor_sha256",
        "previous_anchored_host_head_sha256",
        "checkpoint_reason",
        "checkpoint_interval_seconds",
        "anchor_authority_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "anchor_project_ref",
        "bucket_name",
        "principal_id",
        "signing_key_id",
        "signing_public_key_sha256",
        "head_authenticated_at_utc",
        "source_id",
        "source_authority_sha256",
        "policy_sha256",
        "persistence_contract_version",
        "epoch_sequence",
        "monitor_epoch_id",
        "epoch_sha256",
        "evaluation_sequence",
        "evaluation_id",
        "evaluation_record_sha256",
        "state_sha256",
        "probe_status",
        "health",
        "reason",
        "hard_failure_latched",
        "clock_recovery_qualified",
        "evaluated_at_utc",
        "evaluated_at_monotonic_ns",
        "local_previous_host_head_sha256",
        "current_host_head_sha256",
        "host_identity_sha256",
        "object_name",
        "signed_envelope_bytes",
        "signed_envelope_text",
        "signed_envelope_sha256",
        "created_at_utc",
        "canonical_payload",
        "semantic_sha256",
    )
    assert tuple(phase6_trusted_time_head_anchor_receipts.c.keys()) == (
        "anchor_receipt_id",
        "anchor_intent_id",
        "anchor_intent_sha256",
        "signed_envelope_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "anchor_project_ref",
        "bucket_name",
        "principal_id",
        "object_name",
        "readback_bytes_sha256",
        "observed_at_utc",
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
    intent_foreign_keys = _foreign_keys(phase6_trusted_time_head_anchor_intents)
    assert intent_foreign_keys["fk_phase6_anchor_intent_predecessor"] == (
        (
            "host_id",
            "previous_anchor_sha256",
            "previous_anchored_host_head_sha256",
        ),
        (
            "phase6_trusted_time_head_anchor_intents.host_id",
            "phase6_trusted_time_head_anchor_intents.signed_envelope_sha256",
            "phase6_trusted_time_head_anchor_intents.current_host_head_sha256",
        ),
    )
    assert intent_foreign_keys["fk_phase6_anchor_intent_epoch"][0] == (
        "host_id",
        "epoch_sequence",
        "monitor_epoch_id",
        "epoch_sha256",
    )
    assert intent_foreign_keys["fk_phase6_anchor_intent_evaluation"][0] == (
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
    receipt_foreign_keys = _foreign_keys(phase6_trusted_time_head_anchor_receipts)
    assert receipt_foreign_keys["fk_phase6_anchor_receipt_intent"][0] == (
        "anchor_intent_id",
        "anchor_intent_sha256",
        "signed_envelope_sha256",
        "deployment_identity_sha256",
        "runtime_database_identity_sha256",
        "anchor_project_identity_sha256",
        "anchor_project_ref",
        "bucket_name",
        "principal_id",
        "object_name",
    )


def test_phase6_trusted_time_schema_pins_policy_and_compiles_for_postgresql() -> None:
    policy_sha256 = TRUSTED_TIME_POLICY.semantic_sha256
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    assert policy_sha256 == ("64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c")

    for table in (
        phase6_trusted_time_epoch_registrations,
        phase6_trusted_time_probe_evaluations,
        phase6_trusted_time_host_heads,
        phase6_trusted_time_head_anchor_intents,
        phase6_trusted_time_head_anchor_receipts,
    ):
        sql = str(CreateTable(table).compile(dialect=dialect))
        assert table.name in sql
        assert "canonical_payload" in sql
        assert "semantic_sha256" in sql
    assert policy_sha256 in str(
        CreateTable(phase6_trusted_time_epoch_registrations).compile(dialect=dialect)
    )
    anchor_sql = str(CreateTable(phase6_trusted_time_head_anchor_intents).compile(dialect=dialect))
    assert "BYTEA" in anchor_sql
    assert "checkpoint_interval_seconds = 300" in anchor_sql
    assert "aqt-trusted-time-anchors-v1" in anchor_sql
    assert "BETWEEN 2 AND 4096" in anchor_sql


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
        phase6_trusted_time_head_anchor_intents,
        phase6_trusted_time_head_anchor_receipts,
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


def test_phase6_anchor_revision_is_the_operational_alembic_head() -> None:
    assert EXPECTED_SCHEMA_REVISION == "0036_phase6_time_anchors"


def test_phase6_anchor_upgrade_preserves_nonempty_0035_history_without_backfill(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-anchor-additive.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "0035_phase6_time_uncertainty")
    engine = enforce_sqlite_foreign_keys(sa.create_engine(database_url))
    epoch_sha256 = "a" * 64
    head_sha256 = "c" * 64
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_epoch_registrations).values(
                **_genesis_epoch_values(epoch_sha256=epoch_sha256)
            )
        )
        connection.execute(
            sa.insert(phase6_trusted_time_host_heads).values(
                **_genesis_head_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                )
            )
        )
    engine.dispose()

    command.upgrade(config, "head")

    upgraded = enforce_sqlite_foreign_keys(sa.create_engine(database_url))
    with upgraded.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_epoch_registrations)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_host_heads)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_intents)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase6_trusted_time_head_anchor_receipts)
            )
            == 0
        )
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            EXPECTED_SCHEMA_REVISION
        )
    upgraded.dispose()


def test_phase6_anchor_empty_downgrade_returns_to_0035(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-anchor-empty-down.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "head")

    command.downgrade(config, "0035_phase6_time_uncertainty")

    engine = sa.create_engine(database_url)
    inspector = sa.inspect(engine)
    assert "phase6_trusted_time_epoch_registrations" in inspector.get_table_names()
    assert "phase6_trusted_time_head_anchor_intents" not in inspector.get_table_names()
    assert "phase6_trusted_time_head_anchor_receipts" not in inspector.get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0035_phase6_time_uncertainty"
        )
    engine.dispose()


def test_phase6_anchor_constraints_bind_policy_object_and_exact_readback(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-anchor-shapes.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "head")
    engine = enforce_sqlite_foreign_keys(sa.create_engine(database_url))
    epoch_sha256 = "a" * 64
    head_sha256 = "c" * 64
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_epoch_registrations).values(
                **_genesis_epoch_values(epoch_sha256=epoch_sha256)
            )
        )
        connection.execute(
            sa.insert(phase6_trusted_time_host_heads).values(
                **_genesis_head_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                )
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                    checkpoint_interval_seconds=20,
                )
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                    anchor_project_ref="short",
                )
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                    object_name="v1/not-the-deterministic-object.json",
                )
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                    signed_envelope_bytes=b"x" * 4097,
                    signed_envelope_text="x" * 4097,
                )
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                    anchor_sequence=2,
                    checkpoint_reason="periodic",
                    object_name=_anchor_object_name(
                        sequence=2,
                        envelope_sha256=ENVELOPE_SHA256,
                    ),
                )
            )
        )

    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                )
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_receipts).values(
                **_anchor_receipt_values(readback_bytes_sha256="8" * 64)
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_receipts).values(
                **_anchor_receipt_values(anchor_project_identity_sha256="7" * 64)
            )
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_receipts).values(
                **_anchor_receipt_values(anchor_project_ref="bcdefghijklmnopqrstu")
            )
        )

    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_receipts).values(**_anchor_receipt_values())
        )

    with engine.begin() as connection, pytest.raises(sa.exc.IntegrityError):
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_receipts).values(
                **_anchor_receipt_values(
                    anchor_receipt_id="00000000-0000-0000-0000-000000000006",
                    semantic_sha256="8" * 64,
                )
            )
        )
    engine.dispose()


def test_phase6_anchor_downgrade_refuses_nonempty_anchor_history(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-anchor-nonempty.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "head")
    engine = enforce_sqlite_foreign_keys(sa.create_engine(database_url))
    epoch_sha256 = "a" * 64
    head_sha256 = "c" * 64
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase6_trusted_time_epoch_registrations).values(
                **_genesis_epoch_values(epoch_sha256=epoch_sha256)
            )
        )
        connection.execute(
            sa.insert(phase6_trusted_time_host_heads).values(
                **_genesis_head_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                )
            )
        )
        connection.execute(
            sa.insert(phase6_trusted_time_head_anchor_intents).values(
                **_anchor_intent_values(
                    epoch_sha256=epoch_sha256,
                    head_sha256=head_sha256,
                )
            )
        )
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty trusted-time anchor history",
    ):
        command.downgrade(config, "0035_phase6_time_uncertainty")


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
                source_uncertainty_milliseconds=None,
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


def test_phase6_trusted_time_constraints_pin_source_uncertainty_cap(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-uncertainty-cap.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "head")
    engine = sa.create_engine(database_url)
    epoch_sha256 = "a" * 64
    sample_sha256 = "c" * 64
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
                source_evidence_sha256="d" * 64,
                probe_started_at_utc=BASE,
                probe_completed_at_utc=BASE,
                trusted_at_utc=BASE,
                probe_started_monotonic_ns=0,
                probe_completed_monotonic_ns=0,
                sample_canonical_payload="{}",
                sample_sha256=sample_sha256,
                previous_state_sha256=None,
                policy_sha256=TRUSTED_TIME_POLICY.semantic_sha256,
                latest_sample_sha256=sample_sha256,
                sample_health="healthy",
                health="healthy",
                reason="startup_qualifying",
                hard_failure_latched=False,
                healthy_since_monotonic_ns=0,
                clock_recovery_qualified=False,
                evaluated_at_utc=BASE,
                evaluated_at_monotonic_ns=0,
                state_canonical_payload="{}",
                state_sha256="e" * 64,
                evaluation_sha256="f" * 64,
                canonical_payload="{}",
                semantic_sha256="1" * 64,
                source_uncertainty_milliseconds=Decimal("100.0000000001"),
            )
        )
    engine.dispose()


def test_phase6_uncertainty_upgrade_refuses_nonempty_v1_history(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase6-v1-nonempty.sqlite'}"
    config = _config(database_url)
    command.upgrade(config, "0034_phase6_trusted_time")
    engine = sa.create_engine(database_url)
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
                policy_sha256=("e2ed2efe97b6a13764fba36976916001eec074773f1f2fcf37f759c80e474944"),
                registered_at_utc=BASE,
                canonical_payload="{}",
                semantic_sha256="a" * 64,
            )
        )
    engine.dispose()

    with pytest.raises(RuntimeError, match="upgrade nonempty trusted-time history"):
        command.upgrade(config, "head")


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
