"""Focused migration gates for durable strategy invocation claims."""

import ast
import importlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from packages.persistence.schema import (
    phase5_strategy_invocation_claims,
    phase5_strategy_supervision_results,
)

ROOT = Path(__file__).resolve().parents[2]
PRIOR_REVISION = "0030_phase5_adv_outcomes"
REVISION = "0031_phase5_strategy_claims"
CLAIM_TABLE = "phase5_strategy_invocation_claims"
FINALIZATION_TABLE = "phase5_strategy_invocation_finalizations"
RESULT_TABLE = "phase5_strategy_supervision_results"
RECOVERY_INDEX = "ix_phase5_strategy_invocation_claim_recovery"
RESULT_LIFECYCLE_UNIQUE = "uq_phase5_strategy_supervision_lifecycle_result"
MIGRATION_PATH = ROOT / "migrations/versions/0031_phase5_strategy_invocation_claims.py"


def _migration_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _postgresql_lock_arguments(function_name: str) -> tuple[str, ...]:
    module = ast.parse(MIGRATION_PATH.read_text(encoding="utf-8"))
    function = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    call = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_lock_postgresql_tables"
    )
    names: list[str] = []
    for argument in call.args[1:]:
        assert isinstance(argument, ast.Name)
        names.append(argument.id)
    return tuple(names)


def test_strategy_invocation_migration_fixes_postgresql_lock_set_and_order() -> None:
    assert _postgresql_lock_arguments("upgrade") == ("_RESULT_TABLE",)
    assert _postgresql_lock_arguments("downgrade") == (
        "_RESULT_TABLE",
        "_CLAIM_TABLE",
        "_FINALIZATION_TABLE",
    )

    migration = importlib.import_module(
        "migrations.versions.0031_phase5_strategy_invocation_claims"
    )

    class _Dialect:
        name = "postgresql"

    class _Connection:
        dialect = _Dialect()

        def __init__(self) -> None:
            self.statements: list[str] = []

        def execute(self, statement: object) -> None:
            self.statements.append(str(statement))

    connection = _Connection()
    migration._lock_postgresql_tables(  # type: ignore[attr-defined]
        cast(Any, connection),
        RESULT_TABLE,
        CLAIM_TABLE,
        FINALIZATION_TABLE,
    )
    assert connection.statements == [
        "LOCK TABLE "
        f"{RESULT_TABLE}, {CLAIM_TABLE}, {FINALIZATION_TABLE} "
        "IN SHARE ROW EXCLUSIVE MODE"
    ]


def test_strategy_invocation_lifecycle_migration_is_empty_cutover_and_reversible(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'strategy-lifecycle-schema.sqlite'}"
    config = _migration_config(database_url)
    command.upgrade(config, PRIOR_REVISION)

    command.upgrade(config, REVISION)
    engine = create_engine(database_url)
    migrated = inspect(engine)
    assert migrated.has_table(CLAIM_TABLE)
    assert migrated.has_table(FINALIZATION_TABLE)
    claim_indexes = {
        index["name"]: tuple(index["column_names"]) for index in migrated.get_indexes(CLAIM_TABLE)
    }
    assert claim_indexes[RECOVERY_INDEX] == ("recoverable_at", "claim_id")
    result_unique_names = {
        constraint["name"] for constraint in migrated.get_unique_constraints(RESULT_TABLE)
    }
    assert RESULT_LIFECYCLE_UNIQUE in result_unique_names
    engine.dispose()

    command.downgrade(config, PRIOR_REVISION)
    downgraded_engine = create_engine(database_url)
    downgraded = inspect(downgraded_engine)
    assert not downgraded.has_table(CLAIM_TABLE)
    assert not downgraded.has_table(FINALIZATION_TABLE)
    assert RESULT_LIFECYCLE_UNIQUE not in {
        constraint["name"] for constraint in downgraded.get_unique_constraints(RESULT_TABLE)
    }
    downgraded_engine.dispose()


def test_strategy_invocation_lifecycle_upgrade_refuses_legacy_result_history(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'strategy-lifecycle-cutover.sqlite'}"
    config = _migration_config(database_url)
    command.upgrade(config, PRIOR_REVISION)
    engine = create_engine(database_url)
    observed_at = datetime(2026, 7, 28, 16, 0, tzinfo=UTC)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.insert(phase5_strategy_supervision_results).values(
                invocation_id="00000000-0000-0000-0000-000000000001",
                account_id="paper-account",
                invocation_sha256="a" * 64,
                environment="paper",
                market_batch_id="batch-1",
                market_batch_sha256="b" * 64,
                strategy_id="strategy-1",
                strategy_version="1",
                strategy_configuration_sha256="c" * 64,
                runtime_sha256="d" * 64,
                outcome="completed",
                started_at=observed_at,
                completed_at=observed_at,
                elapsed_microseconds=0,
                process_started=True,
                exit_code=0,
                stdout_bytes=2,
                stdout_sha256="e" * 64,
                stderr_bytes=0,
                stderr_sha256="f" * 64,
                detail_code="completed",
                response_sha256="1" * 64,
                response_result_sha256="2" * 64,
                response_result_json="{}",
                fencing_generation=1,
                lease_sha256="3" * 64,
                fence_sha256="4" * 64,
                pre_control_transition_id=("00000000-0000-0000-0000-000000000002"),
                pre_control_transition_sha256="5" * 64,
                final_control_transition_id=("00000000-0000-0000-0000-000000000002"),
                final_control_transition_sha256="5" * 64,
                critical_alert_incident_id=None,
                critical_alert_incident_sha256=None,
                recorded_at=observed_at,
                invocation_payload="{}",
                result_payload="{}",
                semantic_sha256="6" * 64,
            )
        )
        connection.commit()
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="cutover requires empty supervision history",
    ):
        command.upgrade(config, REVISION)

    retained_engine = create_engine(database_url)
    retained = inspect(retained_engine)
    assert not retained.has_table(CLAIM_TABLE)
    assert not retained.has_table(FINALIZATION_TABLE)
    retained_engine.dispose()


def test_strategy_invocation_lifecycle_downgrade_refuses_claim_history(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'strategy-lifecycle-downgrade.sqlite'}"
    config = _migration_config(database_url)
    command.upgrade(config, REVISION)
    engine = create_engine(database_url)
    claimed_at = datetime(2026, 7, 28, 16, 0, tzinfo=UTC)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.insert(phase5_strategy_invocation_claims).values(
                claim_id="00000000-0000-0000-0000-000000000003",
                account_id="paper-account",
                invocation_id="00000000-0000-0000-0000-000000000001",
                invocation_sha256="a" * 64,
                owner_id="worker-1",
                lease_id="lease-1",
                fencing_generation=1,
                lease_sha256="b" * 64,
                fence_sha256="c" * 64,
                fence_receipt_sha256="d" * 64,
                policy_sha256="e" * 64,
                claimed_at=claimed_at,
                claim_valid_until=claimed_at + timedelta(minutes=1),
                recoverable_at=claimed_at + timedelta(seconds=9),
                invocation_payload="{}",
                semantic_sha256="f" * 64,
            )
        )
        connection.commit()
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty strategy invocation lifecycle",
    ):
        command.downgrade(config, PRIOR_REVISION)

    retained_engine = create_engine(database_url)
    retained = inspect(retained_engine)
    assert retained.has_table(CLAIM_TABLE)
    assert retained.has_table(FINALIZATION_TABLE)
    retained_engine.dispose()
