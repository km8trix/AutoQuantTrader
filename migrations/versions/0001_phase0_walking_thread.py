"""Create the Phase 0 risk, order, fill, and ledger tables.

Revision ID: 0001_phase0
Revises:
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_phase0"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_decisions",
        sa.Column("decision_id", sa.String(length=36), nullable=False),
        sa.Column("intent_id", sa.String(length=36), nullable=False),
        sa.Column("intent_payload_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reserved_cash", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "expires_at > evaluated_at", name="ck_risk_decisions_risk_decisions_positive_ttl"
        ),
        sa.CheckConstraint(
            "reserved_cash >= 0",
            name="ck_risk_decisions_risk_decisions_reserved_cash_non_negative",
        ),
        sa.PrimaryKeyConstraint("decision_id", name="pk_risk_decisions"),
        sa.UniqueConstraint("intent_id", name="uq_risk_decisions_intent_id"),
    )
    op.create_table(
        "ledger_entries",
        sa.Column("entry_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("reference_id", sa.String(length=64), nullable=False),
        sa.Column("posted_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("entry_id", name="pk_ledger_entries"),
        sa.UniqueConstraint("reference_id", name="uq_ledger_entries_reference_id"),
    )
    op.create_table(
        "orders",
        sa.Column("order_id", sa.String(length=36), nullable=False),
        sa.Column("client_order_id", sa.String(length=64), nullable=False),
        sa.Column("intent_id", sa.String(length=36), nullable=False),
        sa.Column("risk_decision_id", sa.String(length=36), nullable=False),
        sa.Column("instrument_id", sa.String(length=64), nullable=False),
        sa.Column("symbol", sa.String(length=32), nullable=False),
        sa.Column("side", sa.String(length=8), nullable=False),
        sa.Column("quantity", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column(
            "filled_quantity",
            sa.Numeric(precision=28, scale=10),
            server_default="0",
            nullable=False,
        ),
        sa.Column("activation_after_event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.CheckConstraint(
            "filled_quantity >= 0 AND filled_quantity <= quantity",
            name="ck_orders_orders_filled_quantity_valid",
        ),
        sa.CheckConstraint("quantity > 0", name="ck_orders_orders_quantity_positive"),
        sa.CheckConstraint(
            "quantity = CAST(quantity AS BIGINT)",
            name="ck_orders_orders_quantity_whole_shares",
        ),
        sa.CheckConstraint(
            "filled_quantity = CAST(filled_quantity AS BIGINT)",
            name="ck_orders_orders_filled_quantity_whole_shares",
        ),
        sa.ForeignKeyConstraint(
            ["risk_decision_id"],
            ["risk_decisions.decision_id"],
            name="fk_orders_risk_decision_id_risk_decisions",
        ),
        sa.PrimaryKeyConstraint("order_id", name="pk_orders"),
        sa.UniqueConstraint("client_order_id", name="uq_orders_client_order_id"),
        sa.UniqueConstraint("intent_id", name="uq_orders_intent_id"),
        sa.UniqueConstraint("risk_decision_id", name="uq_orders_risk_decision_id"),
    )
    op.create_table(
        "ledger_postings",
        sa.Column(
            "posting_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("entry_id", sa.String(length=36), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("account", sa.String(length=128), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("debit", sa.Numeric(precision=28, scale=10), server_default="0", nullable=False),
        sa.Column("credit", sa.Numeric(precision=28, scale=10), server_default="0", nullable=False),
        sa.Column(
            "units_delta",
            sa.Numeric(precision=28, scale=10),
            server_default="0",
            nullable=False,
        ),
        sa.Column("instrument_id", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "debit >= 0 AND credit >= 0",
            name="ck_ledger_postings_ledger_postings_non_negative",
        ),
        sa.CheckConstraint(
            "(debit > 0 AND credit = 0) OR (credit > 0 AND debit = 0)",
            name="ck_ledger_postings_ledger_postings_single_side",
        ),
        sa.ForeignKeyConstraint(
            ["entry_id"],
            ["ledger_entries.entry_id"],
            name="fk_ledger_postings_entry_id_ledger_entries",
        ),
        sa.PrimaryKeyConstraint("posting_id", name="pk_ledger_postings"),
        sa.UniqueConstraint("entry_id", "line_number", name="uq_ledger_postings_entry_line"),
    )
    op.create_index("ix_ledger_postings_entry_id", "ledger_postings", ["entry_id"], unique=False)
    op.create_table(
        "fills",
        sa.Column("fill_id", sa.String(length=36), nullable=False),
        sa.Column("order_id", sa.String(length=36), nullable=False),
        sa.Column("instrument_id", sa.String(length=64), nullable=False),
        sa.Column("symbol", sa.String(length=32), nullable=False),
        sa.Column("side", sa.String(length=8), nullable=False),
        sa.Column("quantity", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("price", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("fee", sa.Numeric(precision=28, scale=10), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("fee >= 0", name="ck_fills_fills_fee_non_negative"),
        sa.CheckConstraint("price > 0", name="ck_fills_fills_price_positive"),
        sa.CheckConstraint("quantity > 0", name="ck_fills_fills_quantity_positive"),
        sa.CheckConstraint(
            "quantity = CAST(quantity AS BIGINT)",
            name="ck_fills_fills_quantity_whole_shares",
        ),
        sa.ForeignKeyConstraint(["order_id"], ["orders.order_id"], name="fk_fills_order_id_orders"),
        sa.PrimaryKeyConstraint("fill_id", name="pk_fills"),
    )
    op.create_index("ix_fills_order_id", "fills", ["order_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_fills_order_id", table_name="fills")
    op.drop_table("fills")
    op.drop_index("ix_ledger_postings_entry_id", table_name="ledger_postings")
    op.drop_table("ledger_postings")
    op.drop_table("orders")
    op.drop_table("ledger_entries")
    op.drop_table("risk_decisions")
