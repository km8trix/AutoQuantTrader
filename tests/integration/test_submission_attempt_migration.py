from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from packages.domain.identifiers import deterministic_id
from packages.persistence.database import create_database_engine
from packages.persistence.risk import submission_attempt_id
from packages.persistence.schema import (
    orders,
    risk_account_guards,
    risk_decisions,
    risk_reservations,
    submission_attempts,
)

ROOT = Path(__file__).resolve().parents[2]


def _migration_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def test_migration_backfills_recorded_and_interrupted_submission_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The migration config must select this isolated database even when a developer
    # shell has a normal application database configured.
    monkeypatch.delenv("AQT_DATABASE_URL", raising=False)
    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/backfill.sqlite")
    config = _migration_config(engine.url.render_as_string(hide_password=False))
    command.upgrade(config, "0002_risk_reservations")

    evaluated_at = datetime(2026, 7, 15, 13, 31, 1, tzinfo=UTC)
    consumed_at = evaluated_at + timedelta(seconds=1)
    account_id = "migration-account"
    snapshot_version = "cash-v1"
    recorded_decision_id = deterministic_id("risk", "recorded")
    recorded_intent_id = deterministic_id("intent", "recorded")
    interrupted_decision_id = deterministic_id("risk", "interrupted")
    interrupted_intent_id = deterministic_id("intent", "interrupted")
    order_id = deterministic_id("order", recorded_intent_id)
    with engine.begin() as connection:
        connection.execute(
            sa.insert(risk_account_guards).values(
                account_id=account_id,
                snapshot_version=snapshot_version,
                available_cash=Decimal("1000"),
                reserved_cash=Decimal("20"),
                updated_at=evaluated_at + timedelta(seconds=1),
            )
        )
        connection.execute(
            sa.insert(risk_decisions),
            [
                {
                    "decision_id": recorded_decision_id,
                    "intent_id": recorded_intent_id,
                    "intent_payload_hash": "a" * 64,
                    "policy_version": "migration-test",
                    "status": "approved",
                    "evaluated_at": evaluated_at,
                    "expires_at": evaluated_at + timedelta(minutes=1),
                    "reserved_cash": Decimal("10"),
                    "rules": [],
                    "consumed_at": consumed_at,
                },
                {
                    "decision_id": interrupted_decision_id,
                    "intent_id": interrupted_intent_id,
                    "intent_payload_hash": "b" * 64,
                    "policy_version": "migration-test",
                    "status": "approved",
                    "evaluated_at": evaluated_at + timedelta(seconds=1),
                    "expires_at": evaluated_at + timedelta(minutes=1),
                    "reserved_cash": Decimal("10"),
                    "rules": [],
                    "consumed_at": consumed_at + timedelta(seconds=1),
                },
            ],
        )
        connection.execute(
            sa.insert(risk_reservations),
            [
                {
                    "decision_id": recorded_decision_id,
                    "account_id": account_id,
                    "snapshot_version": snapshot_version,
                    "cash_amount": Decimal("10"),
                    "state": "consumed",
                    "expires_at": evaluated_at + timedelta(minutes=1),
                },
                {
                    "decision_id": interrupted_decision_id,
                    "account_id": account_id,
                    "snapshot_version": snapshot_version,
                    "cash_amount": Decimal("10"),
                    "state": "consumed",
                    "expires_at": evaluated_at + timedelta(minutes=1),
                },
            ],
        )
        connection.execute(
            sa.insert(orders).values(
                order_id=order_id,
                client_order_id="migration-order-recorded",
                intent_id=recorded_intent_id,
                risk_decision_id=recorded_decision_id,
                instrument_id="US-ETF-SPY",
                symbol="SPY",
                side="buy",
                quantity=Decimal("1"),
                filled_quantity=Decimal("0"),
                activation_after_event_time=evaluated_at - timedelta(seconds=1),
                submitted_at=consumed_at,
                status="working",
            )
        )

    command.upgrade(config, "0003_submission_attempts")

    with engine.connect() as connection:
        rows = {
            row["decision_id"]: row
            for row in connection.execute(sa.select(submission_attempts)).mappings()
        }
    recorded = rows[recorded_decision_id]
    assert recorded["attempt_id"] == submission_attempt_id(
        recorded_decision_id,
        recorded_intent_id,
    )
    assert recorded["state"] == "recorded"
    assert recorded["order_id"] == order_id
    interrupted = rows[interrupted_decision_id]
    assert interrupted["attempt_id"] == submission_attempt_id(
        interrupted_decision_id,
        interrupted_intent_id,
    )
    assert interrupted["state"] == "authorized"
    assert interrupted["order_id"] is None
