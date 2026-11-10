"""Add atomic account guards and single-use risk reservations.

Revision ID: 0002_risk_reservations
Revises: 0001_phase0
Create Date: 2026-07-15
"""

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal

import sqlalchemy as sa
from alembic import op

revision: str = "0002_risk_reservations"
down_revision: str | None = "0001_phase0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PHASE0_ACCOUNT_ID = "simulation-account-001"
PHASE0_SNAPSHOT_VERSION = "opening-balance-v1"
PHASE0_AVAILABLE_CASH = Decimal("100000.0000000000")


def _backfill_phase0_reservations() -> None:
    """Attach existing approved Phase-0 decisions to the fixed opening snapshot."""

    connection = op.get_bind()
    decisions = sa.table(
        "risk_decisions",
        sa.column("decision_id", sa.String(36)),
        sa.column("status", sa.String(16)),
        sa.column("evaluated_at", sa.DateTime(timezone=True)),
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("reserved_cash", sa.Numeric(28, 10)),
        sa.column("consumed_at", sa.DateTime(timezone=True)),
    )
    approved_rows = (
        connection.execute(
            sa.select(
                decisions.c.decision_id,
                decisions.c.evaluated_at,
                decisions.c.expires_at,
                decisions.c.reserved_cash,
                decisions.c.consumed_at,
            )
            .where(decisions.c.status == "approved")
            .order_by(decisions.c.decision_id)
        )
        .mappings()
        .all()
    )
    if not approved_rows:
        return

    reservations: list[dict[str, str | Decimal | datetime]] = []
    total_reserved_cash = Decimal("0")
    latest_evaluation: datetime | None = None
    for row in approved_rows:
        cash_amount = Decimal(str(row["reserved_cash"]))
        if cash_amount <= 0:
            raise RuntimeError("approved Phase-0 decisions must reserve positive cash")
        evaluated_at = row["evaluated_at"]
        expires_at = row["expires_at"]
        if not isinstance(evaluated_at, datetime) or not isinstance(expires_at, datetime):
            raise RuntimeError("existing Phase-0 risk timestamps are invalid")
        total_reserved_cash += cash_amount
        latest_evaluation = (
            evaluated_at
            if latest_evaluation is None or evaluated_at > latest_evaluation
            else latest_evaluation
        )
        reservations.append(
            {
                "decision_id": str(row["decision_id"]),
                "account_id": PHASE0_ACCOUNT_ID,
                "snapshot_version": PHASE0_SNAPSHOT_VERSION,
                "cash_amount": cash_amount,
                "state": "consumed" if row["consumed_at"] is not None else "approved",
                "expires_at": expires_at,
            }
        )

    if total_reserved_cash > PHASE0_AVAILABLE_CASH:
        raise RuntimeError("existing Phase-0 reservations exceed the known opening cash")
    if latest_evaluation is None:
        raise RuntimeError("existing Phase-0 risk decisions lack an evaluation timestamp")

    guards = sa.table(
        "risk_account_guards",
        sa.column("account_id", sa.String(64)),
        sa.column("snapshot_version", sa.String(64)),
        sa.column("available_cash", sa.Numeric(28, 10)),
        sa.column("reserved_cash", sa.Numeric(28, 10)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    reservation_table = sa.table(
        "risk_reservations",
        sa.column("decision_id", sa.String(36)),
        sa.column("account_id", sa.String(64)),
        sa.column("snapshot_version", sa.String(64)),
        sa.column("cash_amount", sa.Numeric(28, 10)),
        sa.column("state", sa.String(16)),
        sa.column("expires_at", sa.DateTime(timezone=True)),
    )
    connection.execute(
        sa.insert(guards).values(
            account_id=PHASE0_ACCOUNT_ID,
            snapshot_version=PHASE0_SNAPSHOT_VERSION,
            available_cash=PHASE0_AVAILABLE_CASH,
            reserved_cash=total_reserved_cash,
            updated_at=latest_evaluation,
        )
    )
    connection.execute(sa.insert(reservation_table), reservations)


def upgrade() -> None:
    op.create_table(
        "risk_account_guards",
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("snapshot_version", sa.String(length=64), nullable=False),
        sa.Column("available_cash", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column(
            "reserved_cash",
            sa.Numeric(precision=28, scale=10),
            server_default="0",
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "available_cash >= 0",
            name="ck_risk_account_guards_risk_account_guards_available_cash_non_negative",
        ),
        sa.CheckConstraint(
            "reserved_cash >= 0",
            name="ck_risk_account_guards_risk_account_guards_reserved_cash_non_negative",
        ),
        sa.CheckConstraint(
            "reserved_cash <= available_cash",
            name="ck_risk_account_guards_risk_account_guards_reserved_cash_within_capacity",
        ),
        sa.PrimaryKeyConstraint("account_id", name="pk_risk_account_guards"),
        sa.UniqueConstraint(
            "account_id",
            "snapshot_version",
            name="uq_risk_account_guards_account_snapshot",
        ),
    )
    op.create_table(
        "risk_reservations",
        sa.Column("decision_id", sa.String(length=36), nullable=False),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("snapshot_version", sa.String(length=64), nullable=False),
        sa.Column("cash_amount", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "cash_amount > 0",
            name="ck_risk_reservations_risk_reservations_cash_amount_positive",
        ),
        sa.CheckConstraint(
            "state IN ('approved', 'consumed', 'released')",
            name="ck_risk_reservations_risk_reservations_valid_state",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "snapshot_version"],
            ["risk_account_guards.account_id", "risk_account_guards.snapshot_version"],
            name="fk_risk_reservations_account_snapshot_risk_account_guards",
        ),
        sa.ForeignKeyConstraint(
            ["decision_id"],
            ["risk_decisions.decision_id"],
            name="fk_risk_reservations_decision_id_risk_decisions",
        ),
        sa.PrimaryKeyConstraint("decision_id", name="pk_risk_reservations"),
    )
    op.create_index(
        "ix_risk_reservations_account_state",
        "risk_reservations",
        ["account_id", "state"],
        unique=False,
    )
    op.create_index(
        "ix_risk_reservations_expires_at",
        "risk_reservations",
        ["expires_at"],
        unique=False,
    )
    _backfill_phase0_reservations()


def downgrade() -> None:
    op.drop_index("ix_risk_reservations_expires_at", table_name="risk_reservations")
    op.drop_index("ix_risk_reservations_account_state", table_name="risk_reservations")
    op.drop_table("risk_reservations")
    op.drop_table("risk_account_guards")
