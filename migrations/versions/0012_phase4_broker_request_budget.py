"""Add durable Phase 4 broker request permits and account-local heads.

Revision ID: 0012_phase4_request_budget
Revises: 0011_phase4_broker_ingress
Create Date: 2026-07-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_phase4_request_budget"
down_revision: str | None = "0011_phase4_broker_ingress"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PERMIT_TABLE_NAME = "phase4_broker_request_permits"
_HEAD_TABLE_NAME = "phase4_broker_request_heads"


def upgrade() -> None:
    op.create_table(
        _PERMIT_TABLE_NAME,
        sa.Column("permit_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("previous_permit_sha256", sa.String(64), nullable=True),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=False),
        sa.Column("policy_version", sa.String(128), nullable=False),
        sa.Column("window_seconds", sa.BigInteger(), nullable=False),
        sa.Column("permit_ttl_seconds", sa.BigInteger(), nullable=False),
        sa.Column("submission_capacity", sa.BigInteger(), nullable=False),
        sa.Column("recovery_capacity", sa.BigInteger(), nullable=False),
        sa.Column("total_capacity", sa.BigInteger(), nullable=False),
        sa.Column("policy_payload", sa.Text(), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("demand_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("operation", sa.String(128), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("correlation_sha256", sa.String(64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("demand_payload", sa.Text(), nullable=False),
        sa.Column("demand_sha256", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_permit_count", sa.BigInteger(), nullable=False),
        sa.Column("admission_ceiling", sa.BigInteger(), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(sequence_number = 1 "
            "AND previous_sequence_number IS NULL "
            "AND previous_permit_sha256 IS NULL) "
            "OR (sequence_number > 1 "
            "AND previous_sequence_number = sequence_number - 1 "
            "AND previous_permit_sha256 IS NOT NULL)",
            name=op.f(
                "ck_phase4_broker_request_permits_phase4_broker_request_permit_predecessor_shape"
            ),
        ),
        sa.CheckConstraint(
            "window_seconds > 0 "
            "AND permit_ttl_seconds > 0 "
            "AND permit_ttl_seconds <= window_seconds",
            name=op.f(
                "ck_phase4_broker_request_permits_phase4_broker_request_permit_positive_durations"
            ),
        ),
        sa.CheckConstraint(
            "submission_capacity > 0 "
            "AND submission_capacity < recovery_capacity "
            "AND recovery_capacity < total_capacity",
            name=op.f(
                "ck_phase4_broker_request_permits_phase4_broker_request_permit_capacity_order"
            ),
        ),
        sa.CheckConstraint(
            "purpose IN ('submission', 'unknown_lookup', 'cancel', 'reconciliation')",
            name=op.f(
                "ck_phase4_broker_request_permits_phase4_broker_request_permit_valid_purpose"
            ),
        ),
        sa.CheckConstraint(
            "requested_at <= issued_at AND issued_at < expires_at",
            name=op.f("ck_phase4_broker_request_permits_phase4_broker_request_permit_time_order"),
        ),
        sa.CheckConstraint(
            "window_permit_count > 0 "
            "AND window_permit_count <= admission_ceiling "
            "AND admission_ceiling IN "
            "(submission_capacity, recovery_capacity, total_capacity)",
            name=op.f("ck_phase4_broker_request_permits_phase4_broker_request_permit_valid_counts"),
        ),
        sa.CheckConstraint(
            "length(permit_id) = 64 "
            "AND (previous_permit_sha256 IS NULL "
            "OR length(previous_permit_sha256) = 64) "
            "AND length(policy_sha256) = 64 "
            "AND length(demand_id) = 64 "
            "AND length(demand_sha256) = 64 "
            "AND length(correlation_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase4_broker_request_permits_phase4_broker_request_permit_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(policy_payload) BETWEEN 2 AND 8192 "
            "AND length(demand_payload) BETWEEN 2 AND 8192 "
            "AND length(canonical_payload) BETWEEN 2 AND 16384",
            name=op.f(
                "ck_phase4_broker_request_permits_phase4_broker_request_permit_payload_sizes"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_request_permits_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "previous_sequence_number",
                "previous_permit_sha256",
            ],
            [
                f"{_PERMIT_TABLE_NAME}.account_id",
                f"{_PERMIT_TABLE_NAME}.sequence_number",
                f"{_PERMIT_TABLE_NAME}.semantic_sha256",
            ],
            name="fk_phase4_broker_request_permits_predecessor",
        ),
        sa.PrimaryKeyConstraint(
            "permit_id",
            name=op.f(f"pk_{_PERMIT_TABLE_NAME}"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            name="uq_phase4_broker_request_permits_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "idempotency_key",
            name="uq_phase4_broker_request_permits_account_idempotency",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_broker_request_permits_account_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            "semantic_sha256",
            name="uq_phase4_broker_request_permits_account_sequence_semantic",
        ),
        sa.UniqueConstraint(
            "demand_id",
            name=op.f("uq_phase4_broker_request_permits_demand_id"),
        ),
        sa.UniqueConstraint(
            "demand_sha256",
            name=op.f("uq_phase4_broker_request_permits_demand_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase4_broker_request_permits_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase4_broker_request_permits_account_issued",
        _PERMIT_TABLE_NAME,
        ["account_id", "issued_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_broker_request_permits_policy_issued",
        _PERMIT_TABLE_NAME,
        ["policy_sha256", "issued_at"],
        unique=False,
    )
    op.create_table(
        _HEAD_TABLE_NAME,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("last_permit_sha256", sa.String(64), nullable=False),
        sa.Column("last_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "last_sequence_number > 0 AND length(last_permit_sha256) = 64",
            name=op.f("ck_phase4_broker_request_heads_phase4_broker_request_head_terminal_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_request_heads_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "last_sequence_number", "last_permit_sha256"],
            [
                f"{_PERMIT_TABLE_NAME}.account_id",
                f"{_PERMIT_TABLE_NAME}.sequence_number",
                f"{_PERMIT_TABLE_NAME}.semantic_sha256",
            ],
            name="fk_phase4_broker_request_heads_terminal_permit",
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
            "LOCK TABLE phase4_broker_request_heads, "
            "phase4_broker_request_permits IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    permits = sa.table(
        _PERMIT_TABLE_NAME,
        sa.column("permit_id", sa.String(length=64)),
    )
    heads = sa.table(
        _HEAD_TABLE_NAME,
        sa.column("account_id", sa.String(length=64)),
    )
    if connection.scalar(sa.select(sa.func.count()).select_from(permits)) or connection.scalar(
        sa.select(sa.func.count()).select_from(heads)
    ):
        raise RuntimeError(
            "cannot downgrade after durable broker request permits have been persisted"
        )
    op.drop_table(_HEAD_TABLE_NAME)
    op.drop_index(
        "ix_phase4_broker_request_permits_policy_issued",
        table_name=_PERMIT_TABLE_NAME,
    )
    op.drop_index(
        "ix_phase4_broker_request_permits_account_issued",
        table_name=_PERMIT_TABLE_NAME,
    )
    op.drop_table(_PERMIT_TABLE_NAME)
