"""Record the durable risk-authorization to order-submission handoff.

Revision ID: 0003_submission_attempts
Revises: 0002_risk_reservations
Create Date: 2026-07-15
"""

from collections.abc import Sequence
from datetime import datetime
from uuid import NAMESPACE_URL, uuid5

import sqlalchemy as sa
from alembic import op

revision: str = "0003_submission_attempts"
down_revision: str | None = "0002_risk_reservations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _attempt_id(decision_id: str, intent_id: str) -> str:
    material = f"submission-attempt:{decision_id}:{intent_id}"
    return str(uuid5(NAMESPACE_URL, f"autoquant-trader:{material}"))


def _backfill_submission_attempts() -> None:
    """Represent every consumed authorization, including an interrupted handoff."""

    connection = op.get_bind()
    decisions = sa.table(
        "risk_decisions",
        sa.column("decision_id", sa.String(36)),
        sa.column("intent_id", sa.String(36)),
        sa.column("status", sa.String(16)),
        sa.column("consumed_at", sa.DateTime(timezone=True)),
    )
    order_table = sa.table(
        "orders",
        sa.column("order_id", sa.String(36)),
        sa.column("risk_decision_id", sa.String(36)),
        sa.column("intent_id", sa.String(36)),
        sa.column("submitted_at", sa.DateTime(timezone=True)),
    )
    attempt_table = sa.table(
        "submission_attempts",
        sa.column("attempt_id", sa.String(36)),
        sa.column("decision_id", sa.String(36)),
        sa.column("intent_id", sa.String(36)),
        sa.column("submitted_at", sa.DateTime(timezone=True)),
        sa.column("state", sa.String(16)),
        sa.column("order_id", sa.String(36)),
    )

    rows = (
        connection.execute(
            sa.select(
                decisions.c.decision_id,
                decisions.c.intent_id,
                decisions.c.status,
                decisions.c.consumed_at,
                order_table.c.order_id,
                order_table.c.intent_id.label("order_intent_id"),
                order_table.c.submitted_at.label("order_submitted_at"),
            )
            .select_from(
                decisions.outerjoin(
                    order_table,
                    decisions.c.decision_id == order_table.c.risk_decision_id,
                )
            )
            .where(decisions.c.consumed_at.is_not(None))
            .order_by(decisions.c.decision_id)
        )
        .mappings()
        .all()
    )
    attempts: list[dict[str, str | datetime | None]] = []
    for row in rows:
        decision_id = str(row["decision_id"])
        intent_id = str(row["intent_id"])
        consumed_at = row["consumed_at"]
        if row["status"] != "approved" or not isinstance(consumed_at, datetime):
            raise RuntimeError("only valid approved decisions may have been consumed")
        order_id = None if row["order_id"] is None else str(row["order_id"])
        if order_id is not None:
            if row["order_intent_id"] != intent_id:
                raise RuntimeError("existing order conflicts with its consumed risk intent")
            if row["order_submitted_at"] != consumed_at:
                raise RuntimeError("existing order conflicts with risk consumption time")
        attempts.append(
            {
                "attempt_id": _attempt_id(decision_id, intent_id),
                "decision_id": decision_id,
                "intent_id": intent_id,
                "submitted_at": consumed_at,
                "state": "recorded" if order_id is not None else "authorized",
                "order_id": order_id,
            }
        )
    if attempts:
        connection.execute(sa.insert(attempt_table), attempts)


def upgrade() -> None:
    op.create_table(
        "submission_attempts",
        sa.Column("attempt_id", sa.String(length=36), nullable=False),
        sa.Column("decision_id", sa.String(length=36), nullable=False),
        sa.Column("intent_id", sa.String(length=36), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("order_id", sa.String(length=36), nullable=True),
        sa.CheckConstraint(
            "(state = 'authorized' AND order_id IS NULL) "
            "OR (state = 'recorded' AND order_id IS NOT NULL)",
            name="ck_submission_attempts_submission_attempts_state_matches_order",
        ),
        sa.CheckConstraint(
            "state IN ('authorized', 'recorded')",
            name="ck_submission_attempts_submission_attempts_valid_state",
        ),
        sa.ForeignKeyConstraint(
            ["decision_id"],
            ["risk_decisions.decision_id"],
            name="fk_submission_attempts_decision_id_risk_decisions",
        ),
        sa.ForeignKeyConstraint(
            ["order_id"],
            ["orders.order_id"],
            name="fk_submission_attempts_order_id_orders",
        ),
        sa.PrimaryKeyConstraint("attempt_id", name="pk_submission_attempts"),
        sa.UniqueConstraint(
            "decision_id",
            name="uq_submission_attempts_decision_id",
        ),
        sa.UniqueConstraint("intent_id", name="uq_submission_attempts_intent_id"),
        sa.UniqueConstraint("order_id", name="uq_submission_attempts_order_id"),
    )
    _backfill_submission_attempts()


def downgrade() -> None:
    op.drop_table("submission_attempts")
