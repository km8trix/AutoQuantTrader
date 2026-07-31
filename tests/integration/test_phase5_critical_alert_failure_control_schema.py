from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from packages.domain.critical_alert import (
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertIncident,
    CriticalAlertRoute,
    record_critical_alert_delivery_result,
)
from packages.persistence.critical_alert import SqlCriticalAlertRepository
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    phase5_critical_alert_delivery_results,
    phase5_critical_alert_failure_control_receipts,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 7, 28, 14, 0, tzinfo=UTC)
MIGRATION_PATH = ROOT / "migrations/versions/0032_phase5_critical_alert_failure_control.py"


@dataclass(slots=True)
class MutableClock:
    instant: datetime

    def now(self) -> datetime:
        return self.instant


def _config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _seed_history(engine: Engine) -> tuple[str, str]:
    clock = MutableClock(BASE)
    repository = SqlCriticalAlertRepository(engine=engine, clock=clock)
    incident = CriticalAlertIncident(
        scope_id="phase5-paper-account",
        source_id="strategy-supervisor",
        idempotency_key="schema-incident-0001",
        alert_code="strategy_deadline_exceeded",
        evidence_sha256="a" * 64,
        detected_at=BASE - timedelta(milliseconds=100),
        recorded_at=BASE,
        correlation_sha256="b" * 64,
    )
    repository.record_incident(incident)
    clock.instant = incident.primary_deadline
    attempt, created = repository.claim_delivery_attempt(
        CriticalAlertDeliveryCommand(
            incident_id=incident.incident_id,
            incident_sha256=incident.semantic_sha256,
            route=CriticalAlertRoute.ESCALATION,
            provider_id="fallback-provider",
            idempotency_key="schema-escalation-0001",
            request_sha256="c" * 64,
            requested_at=clock.instant,
        )
    )
    assert created is True
    clock.instant += timedelta(seconds=1)
    result = record_critical_alert_delivery_result(
        incident=incident,
        attempt=attempt,
        outcome=CriticalAlertDeliveryOutcome.ERROR,
        completed_at=clock.instant,
        elapsed_microseconds=1_000_000,
        failure_code="provider_error",
    )
    repository.record_delivery_result(result)
    return incident.incident_id, result.result_id


def test_metadata_binds_exact_alert_result_and_control_transitions() -> None:
    foreign_keys = {
        (
            tuple(element.parent.name for element in constraint.elements),
            tuple(element.target_fullname for element in constraint.elements),
        )
        for constraint in phase5_critical_alert_failure_control_receipts.foreign_key_constraints
    }
    assert (
        ("incident_id", "attempt_id", "result_id", "result_sha256"),
        (
            "phase5_critical_alert_delivery_results.incident_id",
            "phase5_critical_alert_delivery_results.attempt_id",
            "phase5_critical_alert_delivery_results.result_id",
            "phase5_critical_alert_delivery_results.semantic_sha256",
        ),
    ) in foreign_keys
    for prefix in ("pre", "final"):
        assert (
            (
                "account_id",
                f"{prefix}_control_transition_id",
                f"{prefix}_control_transition_sha256",
            ),
            (
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ),
        ) in foreign_keys
    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in phase5_critical_alert_delivery_results.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    }
    assert (
        "incident_id",
        "attempt_id",
        "result_id",
        "semantic_sha256",
    ) in unique_columns


def test_0032_downgrade_locks_guarded_tables_before_read_or_drop() -> None:
    module = ast.parse(
        MIGRATION_PATH.read_text(encoding="utf-8"),
        filename=str(MIGRATION_PATH),
    )
    functions = {
        node.name: node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    lock_helper = functions["_lock_postgresql_tables"]
    downgrade = functions["downgrade"]

    helper_literals = {
        node.value
        for node in ast.walk(lock_helper)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert {
        "postgresql",
        "LOCK TABLE ",
        ", ",
        " IN SHARE ROW EXCLUSIVE MODE",
    } <= helper_literals

    connection_assignment = next(
        node
        for node in downgrade.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "connection" for target in node.targets
        )
    )
    lock_call = next(
        node
        for node in downgrade.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_lock_postgresql_tables"
    )
    empty_receipt_guard = next(node for node in downgrade.body if isinstance(node, ast.If))
    lock_expression = lock_call.value
    assert isinstance(lock_expression, ast.Call)
    assert [ast.unparse(argument) for argument in lock_expression.args] == [
        "connection",
        "_RECEIPT_TABLE",
        "_RESULT_TABLE",
    ]

    destructive_lines = [
        node.lineno
        for node in ast.walk(downgrade)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"drop_constraint", "drop_index", "drop_table"}
    ]
    assert destructive_lines
    assert (
        connection_assignment.lineno
        < lock_call.lineno
        < empty_receipt_guard.lineno
        < min(destructive_lines)
    )


def test_0032_upgrade_and_empty_downgrade_preserve_delivery_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = _config(database_url)
    alembic_command.upgrade(config, "0031_phase5_strategy_claims")
    engine = create_database_engine(database_url)
    incident_id, result_id = _seed_history(engine)
    engine.dispose()

    alembic_command.upgrade(config, "0032_phase5_alert_fail_control")
    engine = create_database_engine(database_url)
    inspector = inspect(engine)
    assert "phase5_critical_alert_failure_control_receipts" in set(inspector.get_table_names())
    assert {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("phase5_critical_alert_delivery_results")
    } >= {("incident_id", "attempt_id", "result_id", "semantic_sha256")}
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase5_critical_alert_delivery_results)
                .where(
                    phase5_critical_alert_delivery_results.c.incident_id == incident_id,
                    phase5_critical_alert_delivery_results.c.result_id == result_id,
                )
            )
            == 1
        )
    engine.dispose()

    alembic_command.downgrade(config, "0031_phase5_strategy_claims")
    engine = create_database_engine(database_url)
    assert "phase5_critical_alert_failure_control_receipts" not in set(
        inspect(engine).get_table_names()
    )
    with engine.connect() as connection:
        result_table = sa.table(
            "phase5_critical_alert_delivery_results",
            sa.column("incident_id"),
            sa.column("result_id"),
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(result_table)
                .where(
                    result_table.c.incident_id == incident_id,
                    result_table.c.result_id == result_id,
                )
            )
            == 1
        )
