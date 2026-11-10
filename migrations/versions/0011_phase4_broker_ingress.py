"""Add the durable pre-decode Phase 4 broker ingress journal.

Revision ID: 0011_phase4_broker_ingress
Revises: 0010_phase3_governance
Create Date: 2026-07-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_phase4_broker_ingress"
down_revision: str | None = "0010_phase3_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE_NAME = "phase4_broker_ingress_receipts"
_HEAD_TABLE_NAME = "phase4_broker_ingress_heads"


def upgrade() -> None:
    op.create_table(
        _TABLE_NAME,
        sa.Column("receipt_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("delivery_idempotency_key", sa.String(128), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("adapter_version", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("channel", sa.String(128), nullable=False),
        sa.Column("operation", sa.String(128), nullable=False),
        sa.Column("correlation_sha256", sa.String(64), nullable=True),
        sa.Column("transport_status", sa.Integer(), nullable=True),
        sa.Column("provider_request_id", sa.String(256), nullable=True),
        sa.Column("media_type", sa.String(128), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("body", sa.LargeBinary(), nullable=False),
        sa.Column("body_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("body_sha256", sa.String(64), nullable=False),
        sa.Column("delivery_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(ingress_sequence = 1 AND previous_receipt_sha256 IS NULL) "
            "OR (ingress_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
            name=op.f("ck_phase4_broker_ingress_receipts_phase4_broker_ingress_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "transport_status IS NULL OR transport_status BETWEEN 100 AND 599",
            name=op.f("ck_phase4_broker_ingress_receipts_phase4_broker_ingress_transport_status"),
        ),
        sa.CheckConstraint(
            "recorded_at >= received_at",
            name=op.f("ck_phase4_broker_ingress_receipts_phase4_broker_ingress_time_order"),
        ),
        sa.CheckConstraint(
            "body_size_bytes BETWEEN 0 AND 1048576 AND length(body) = body_size_bytes",
            name=op.f("ck_phase4_broker_ingress_receipts_phase4_broker_ingress_body_size"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 64 "
            "AND (previous_receipt_sha256 IS NULL "
            "OR length(previous_receipt_sha256) = 64) "
            "AND (correlation_sha256 IS NULL OR length(correlation_sha256) = 64) "
            "AND length(body_sha256) = 64 "
            "AND length(delivery_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase4_broker_ingress_receipts_phase4_broker_ingress_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 8192",
            name=op.f(
                "ck_phase4_broker_ingress_receipts_phase4_broker_ingress_canonical_payload_size"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_ingress_account_head",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "previous_receipt_sha256"],
            [
                f"{_TABLE_NAME}.account_id",
                f"{_TABLE_NAME}.semantic_sha256",
            ],
            name="fk_phase4_broker_ingress_predecessor",
        ),
        sa.PrimaryKeyConstraint(
            "receipt_id",
            name=op.f(f"pk_{_TABLE_NAME}"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "ingress_sequence",
            name="uq_phase4_broker_ingress_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "delivery_idempotency_key",
            name="uq_phase4_broker_ingress_account_delivery_key",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_broker_ingress_account_semantic",
        ),
        sa.UniqueConstraint(
            "delivery_sha256",
            name=op.f("uq_phase4_broker_ingress_receipts_delivery_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase4_broker_ingress_receipts_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase4_broker_ingress_account_received",
        _TABLE_NAME,
        ["account_id", "received_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_broker_ingress_provider_request",
        _TABLE_NAME,
        ["provider_id", "provider_request_id"],
        unique=False,
    )
    op.create_table(
        _HEAD_TABLE_NAME,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("last_ingress_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_receipt_sha256", sa.String(64), nullable=True),
        sa.CheckConstraint(
            "(last_ingress_sequence = 0 AND last_receipt_sha256 IS NULL) "
            "OR (last_ingress_sequence > 0 AND last_receipt_sha256 IS NOT NULL "
            "AND length(last_receipt_sha256) = 64)",
            name=op.f("ck_phase4_broker_ingress_heads_phase4_broker_ingress_head_terminal_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_ingress_head_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "last_receipt_sha256"],
            [
                f"{_TABLE_NAME}.account_id",
                f"{_TABLE_NAME}.semantic_sha256",
            ],
            name="fk_phase4_broker_ingress_head_terminal_receipt",
        ),
        sa.PrimaryKeyConstraint(
            "account_id",
            name=op.f(f"pk_{_HEAD_TABLE_NAME}"),
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE phase4_broker_ingress_heads, "
            "phase4_broker_ingress_receipts IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    receipts = sa.table(
        _TABLE_NAME,
        sa.column("receipt_id", sa.String(length=64)),
    )
    if connection.scalar(sa.select(sa.func.count()).select_from(receipts)):
        raise RuntimeError(
            "cannot downgrade after durable broker ingress receipts have been persisted"
        )
    op.drop_table(_HEAD_TABLE_NAME)
    op.drop_index(
        "ix_phase4_broker_ingress_provider_request",
        table_name=_TABLE_NAME,
    )
    op.drop_index(
        "ix_phase4_broker_ingress_account_received",
        table_name=_TABLE_NAME,
    )
    op.drop_table(_TABLE_NAME)
