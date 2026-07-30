"""Add non-applying lookup reconciliation evidence.

Revision ID: 0017_phase4_reconciliation
Revises: 0016_phase4_unknown_schedule
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_phase4_reconciliation"
down_revision: str | None = "0016_phase4_unknown_schedule"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FACT_TABLE = "phase4_broker_reconciliation_facts"
_HEAD_TABLE = "phase4_broker_reconciliation_heads"


def upgrade() -> None:
    op.create_table(
        _FACT_TABLE,
        sa.Column("fact_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_fact_sha256", sa.String(64), nullable=True),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("order_id", sa.String(64), nullable=False),
        sa.Column("client_order_id", sa.String(128), nullable=False),
        sa.Column("instrument_id", sa.String(64), nullable=False),
        sa.Column("symbol", sa.String(32), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
        sa.Column("provider_order_id", sa.String(128), nullable=True),
        sa.Column("provider_order_status", sa.String(64), nullable=True),
        sa.Column("provider_replaced_by", sa.String(128), nullable=True),
        sa.Column("provider_replaces", sa.String(128), nullable=True),
        sa.Column("observed_provider_asset_id", sa.String(36), nullable=True),
        sa.Column("mismatch_fields_payload", sa.Text(), nullable=False),
        sa.Column("provider_timestamps_payload", sa.Text(), nullable=False),
        sa.Column("requested_quantity", sa.String(64), nullable=True),
        sa.Column("requested_notional", sa.String(64), nullable=True),
        sa.Column("cumulative_filled_quantity", sa.String(64), nullable=True),
        sa.Column("cumulative_filled_average_price", sa.String(64), nullable=True),
        sa.Column("provider_source", sa.String(128), nullable=True),
        sa.Column("source_lookup_receipt_id", sa.String(36), nullable=False),
        sa.Column("source_lookup_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("source_ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_ingress_sequence", sa.BigInteger(), nullable=False),
        sa.Column("source_delivery_idempotency_key", sa.String(128), nullable=False),
        sa.Column("source_observation_sha256", sa.String(64), nullable=False),
        sa.Column("source_body_sha256", sa.String(64), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("provider_request_id", sa.String(256), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("fact_id", name=op.f(f"pk_{_FACT_TABLE}")),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_FACT_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            name="uq_phase4_broker_reconciliation_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_broker_reconciliation_account_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            "fact_id",
            "semantic_sha256",
            name="uq_phase4_broker_reconciliation_fact_exact",
        ),
        sa.UniqueConstraint(
            "source_lookup_receipt_id",
            name="uq_phase4_broker_reconciliation_lookup_source",
        ),
        sa.UniqueConstraint(
            "source_ingress_receipt_id",
            name="uq_phase4_broker_reconciliation_ingress_source",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_reconciliation_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "previous_fact_sha256"],
            [f"{_FACT_TABLE}.account_id", f"{_FACT_TABLE}.semantic_sha256"],
            name="fk_phase4_broker_reconciliation_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "attempt_id",
                "source_lookup_receipt_id",
                "source_lookup_receipt_sha256",
            ],
            [
                "phase4_alpaca_paper_lookup_observations.account_id",
                "phase4_alpaca_paper_lookup_observations.attempt_id",
                "phase4_alpaca_paper_lookup_observations.receipt_id",
                "phase4_alpaca_paper_lookup_observations.semantic_sha256",
            ],
            name="fk_phase4_broker_reconciliation_lookup_source",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "source_ingress_receipt_id",
                "source_ingress_receipt_sha256",
            ],
            [
                "phase4_broker_ingress_receipts.account_id",
                "phase4_broker_ingress_receipts.receipt_id",
                "phase4_broker_ingress_receipts.semantic_sha256",
            ],
            name="fk_phase4_broker_reconciliation_ingress_source",
        ),
        sa.CheckConstraint(
            "(account_sequence = 1 AND previous_fact_sha256 IS NULL) "
            "OR (account_sequence > 1 AND previous_fact_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "outcome IN "
            "('order_observed_candidate', 'quarantined_economic_mismatch', "
            "'quarantined_security_mismatch', 'inconclusive_not_visible')",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_outcome"),
        ),
        sa.CheckConstraint(
            "(http_status = 404 AND outcome = 'inconclusive_not_visible' "
            "AND provider_order_id IS NULL "
            "AND provider_order_status IS NULL "
            "AND provider_replaced_by IS NULL "
            "AND provider_replaces IS NULL "
            "AND observed_provider_asset_id IS NULL "
            "AND requested_quantity IS NULL "
            "AND requested_notional IS NULL "
            "AND cumulative_filled_quantity IS NULL "
            "AND cumulative_filled_average_price IS NULL "
            "AND provider_source IS NULL) "
            "OR (http_status = 200 "
            "AND outcome IN "
            "('order_observed_candidate', 'quarantined_economic_mismatch', "
            "'quarantined_security_mismatch') "
            "AND provider_order_id IS NOT NULL "
            "AND provider_order_status IS NOT NULL "
            "AND cumulative_filled_quantity IS NOT NULL)",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_observation_shape"),
        ),
        sa.CheckConstraint(
            "received_at <= raw_recorded_at "
            "AND raw_recorded_at <= authenticated_at "
            "AND authenticated_at <= source_committed_at "
            "AND source_committed_at <= normalized_at",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_time_order"),
        ),
        sa.CheckConstraint(
            "source_ingress_sequence > 0 AND account_sequence > 0",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_positive_sequences"),
        ),
        sa.CheckConstraint(
            "length(fact_id) = 36 "
            "AND (previous_fact_sha256 IS NULL "
            "OR length(previous_fact_sha256) = 64) "
            "AND length(source_lookup_receipt_sha256) = 64 "
            "AND length(source_ingress_receipt_id) = 64 "
            "AND length(source_ingress_receipt_sha256) = 64 "
            "AND length(source_observation_sha256) = 64 "
            "AND length(source_body_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(mismatch_fields_payload) BETWEEN 2 AND 4096 "
            "AND length(provider_timestamps_payload) BETWEEN 2 AND 8192 "
            "AND (requested_quantity IS NULL "
            "OR length(requested_quantity) BETWEEN 1 AND 64) "
            "AND (requested_notional IS NULL "
            "OR length(requested_notional) BETWEEN 1 AND 64) "
            "AND (cumulative_filled_quantity IS NULL "
            "OR length(cumulative_filled_quantity) BETWEEN 1 AND 64) "
            "AND (cumulative_filled_average_price IS NULL "
            "OR length(cumulative_filled_average_price) BETWEEN 1 AND 64) "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_FACT_TABLE}_phase4_broker_reconciliation_payload_sizes"),
        ),
    )
    op.create_index(
        "ix_phase4_broker_reconciliation_account_normalized",
        _FACT_TABLE,
        ["account_id", "normalized_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_broker_reconciliation_attempt",
        _FACT_TABLE,
        ["account_id", "attempt_id", "account_sequence"],
        unique=False,
    )
    op.create_table(
        _HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_fact_id", sa.String(36), nullable=False),
        sa.Column("last_fact_sha256", sa.String(64), nullable=False),
        sa.Column("last_normalized_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("account_id", name=op.f(f"pk_{_HEAD_TABLE}")),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_reconciliation_head_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "last_account_sequence",
                "last_fact_id",
                "last_fact_sha256",
            ],
            [
                f"{_FACT_TABLE}.account_id",
                f"{_FACT_TABLE}.account_sequence",
                f"{_FACT_TABLE}.fact_id",
                f"{_FACT_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_broker_reconciliation_head_fact",
        ),
        sa.CheckConstraint(
            "last_account_sequence > 0 "
            "AND length(last_fact_id) = 36 "
            "AND length(last_fact_sha256) = 64",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_broker_reconciliation_head_shape"),
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE phase4_broker_reconciliation_heads, "
            "phase4_broker_reconciliation_facts IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in (_HEAD_TABLE, _FACT_TABLE)
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty broker reconciliation evidence history")
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_broker_reconciliation_attempt",
        table_name=_FACT_TABLE,
    )
    op.drop_index(
        "ix_phase4_broker_reconciliation_account_normalized",
        table_name=_FACT_TABLE,
    )
    op.drop_table(_FACT_TABLE)
