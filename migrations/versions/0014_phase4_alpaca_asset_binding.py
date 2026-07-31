"""Add durable authenticated Alpaca paper asset bindings.

Revision ID: 0014_phase4_asset_binding
Revises: 0013_phase4_account_binding
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_phase4_asset_binding"
down_revision: str | None = "0013_phase4_account_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_BINDING_TABLE_NAME = "phase4_alpaca_paper_asset_bindings"
_HEAD_TABLE_NAME = "phase4_alpaca_paper_asset_binding_heads"
_ACCOUNT_BINDING_EXACT_INDEX = "ux_phase4_alpaca_account_binding_exact"


def upgrade() -> None:
    op.create_index(
        _ACCOUNT_BINDING_EXACT_INDEX,
        "phase4_alpaca_paper_account_bindings",
        [
            "account_id",
            "binding_id",
            "semantic_sha256",
            "expected_provider_account_id",
        ],
        unique=True,
    )
    op.create_table(
        _BINDING_TABLE_NAME,
        sa.Column("binding_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("instrument_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_binding_sha256", sa.String(64), nullable=True),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("symbol", sa.String(32), nullable=False),
        sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
        sa.Column("observed_provider_asset_id", sa.String(36), nullable=False),
        sa.Column("asset_class", sa.String(32), nullable=False),
        sa.Column("exchange", sa.String(16), nullable=False),
        sa.Column("asset_status", sa.String(16), nullable=False),
        sa.Column("tradable", sa.Boolean(), nullable=False),
        # Credential values are structurally absent. These are nonsecret
        # reference and proof fields only.
        sa.Column("secret_ref", sa.String(256), nullable=False),
        sa.Column("secret_version", sa.String(128), nullable=False),
        sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
        sa.Column("security_reference_sha256", sa.String(64), nullable=False),
        sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
        sa.Column("resolver_id", sa.String(128), nullable=False),
        sa.Column("resolver_version", sa.String(128), nullable=False),
        sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("account_binding_id", sa.String(36), nullable=False),
        sa.Column("account_binding_sha256", sa.String(64), nullable=False),
        sa.Column("pre_account_binding_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("post_account_binding_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("demand_id", sa.String(64), nullable=False),
        sa.Column("demand_sha256", sa.String(64), nullable=False),
        sa.Column("permit_id", sa.String(64), nullable=False),
        sa.Column("permit_sha256", sa.String(64), nullable=False),
        sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("observation_sha256", sa.String(64), nullable=False),
        sa.Column("transport_request_sha256", sa.String(64), nullable=False),
        sa.Column("transport_response_sha256", sa.String(64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_account_binding_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_account_binding_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("account_binding_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("qualified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(sequence_number = 1 AND previous_binding_sha256 IS NULL) "
            "OR (sequence_number > 1 AND previous_binding_sha256 IS NOT NULL)",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_"
                "phase4_alpaca_asset_binding_predecessor_shape"
            ),
        ),
        sa.CheckConstraint(
            "provider_id = 'alpaca-paper' AND environment = 'paper'",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_provider_scope"
            ),
        ),
        sa.CheckConstraint(
            "expected_provider_asset_id = observed_provider_asset_id "
            "AND length(expected_provider_asset_id) = 36 "
            "AND expected_provider_asset_id = lower(expected_provider_asset_id) "
            "AND substr(expected_provider_asset_id, 9, 1) = '-' "
            "AND substr(expected_provider_asset_id, 14, 1) = '-' "
            "AND substr(expected_provider_asset_id, 19, 1) = '-' "
            "AND substr(expected_provider_asset_id, 24, 1) = '-'",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_"
                "phase4_alpaca_asset_binding_provider_asset_uuid"
            ),
        ),
        sa.CheckConstraint(
            "length(expected_provider_account_id) = 36 "
            "AND expected_provider_account_id = lower(expected_provider_account_id) "
            "AND substr(expected_provider_account_id, 9, 1) = '-' "
            "AND substr(expected_provider_account_id, 14, 1) = '-' "
            "AND substr(expected_provider_account_id, 19, 1) = '-' "
            "AND substr(expected_provider_account_id, 24, 1) = '-'",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_"
                "phase4_alpaca_asset_binding_provider_account_uuid"
            ),
        ),
        sa.CheckConstraint(
            "length(symbol) BETWEEN 1 AND 32 AND symbol = upper(symbol)",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_symbol_shape"
            ),
        ),
        sa.CheckConstraint(
            "asset_class = 'us_equity' "
            "AND exchange IN ('AMEX', 'ARCA', 'BATS', 'NYSE', 'NASDAQ', 'NYSEARCA') "
            "AND asset_status = 'active' AND tradable",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_qualified_state"
            ),
        ),
        sa.CheckConstraint(
            "length(secret_ref) BETWEEN 16 AND 256 "
            "AND secret_ref LIKE 'secret://paper/%' "
            "AND length(secret_version) BETWEEN 1 AND 128",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_secret_reference"
            ),
        ),
        sa.CheckConstraint(
            "length(resolver_id) BETWEEN 1 AND 128 AND length(resolver_version) BETWEEN 1 AND 128",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_"
                "phase4_alpaca_asset_binding_resolver_identity"
            ),
        ),
        sa.CheckConstraint(
            "requested_at <= resolved_at "
            "AND resolved_at <= pre_fence_validated_at "
            "AND pre_fence_validated_at <= permit_checked_at "
            "AND permit_checked_at <= pre_account_binding_checked_at "
            "AND pre_account_binding_checked_at <= request_started_at "
            "AND request_started_at <= received_at "
            "AND received_at <= raw_recorded_at "
            "AND raw_recorded_at <= post_fence_validated_at "
            "AND post_fence_validated_at <= post_account_binding_checked_at "
            "AND post_account_binding_checked_at = qualified_at "
            "AND qualified_at < valid_until "
            "AND valid_until <= account_binding_valid_until "
            "AND valid_until <= post_fence_valid_until",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_time_order"
            ),
        ),
        sa.CheckConstraint(
            sa.extract("epoch", sa.column("valid_until"))
            - sa.extract("epoch", sa.column("qualified_at"))
            <= 5,
            name=op.f("ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_max_ttl"),
        ),
        sa.CheckConstraint(
            "length(binding_id) = 36 "
            "AND binding_id = lower(binding_id) "
            "AND substr(binding_id, 9, 1) = '-' "
            "AND substr(binding_id, 14, 1) = '-' "
            "AND substr(binding_id, 19, 1) = '-' "
            "AND substr(binding_id, 24, 1) = '-' "
            "AND length(account_binding_id) = 36",
            name=op.f("ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_id_shape"),
        ),
        sa.CheckConstraint(
            "(previous_binding_sha256 IS NULL "
            "OR length(previous_binding_sha256) = 64) "
            "AND length(credential_reference_sha256) = 64 "
            "AND length(security_reference_sha256) = 64 "
            "AND length(credential_resolution_sha256) = 64 "
            "AND length(capability_sha256) = 64 "
            "AND length(account_binding_sha256) = 64 "
            "AND length(pre_account_binding_freshness_sha256) = 64 "
            "AND length(post_account_binding_freshness_sha256) = 64 "
            "AND length(description_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(demand_id) = 64 "
            "AND length(demand_sha256) = 64 "
            "AND length(permit_id) = 64 "
            "AND length(permit_sha256) = 64 "
            "AND length(permit_freshness_sha256) = 64 "
            "AND length(pre_fence_receipt_sha256) = 64 "
            "AND length(post_fence_receipt_sha256) = 64 "
            "AND length(ingress_receipt_id) = 64 "
            "AND length(ingress_receipt_sha256) = 64 "
            "AND length(observation_sha256) = 64 "
            "AND length(transport_request_sha256) = 64 "
            "AND length(transport_response_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_hash_lengths"
            ),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_bindings_phase4_alpaca_asset_binding_payload_size"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_alpaca_asset_bindings_account",
        ),
        sa.ForeignKeyConstraint(
            ["instrument_id"],
            ["instruments.instrument_id"],
            name="fk_phase4_alpaca_asset_bindings_instrument",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "instrument_id",
                "expected_provider_asset_id",
                "previous_binding_sha256",
            ],
            [
                f"{_BINDING_TABLE_NAME}.account_id",
                f"{_BINDING_TABLE_NAME}.instrument_id",
                f"{_BINDING_TABLE_NAME}.expected_provider_asset_id",
                f"{_BINDING_TABLE_NAME}.semantic_sha256",
            ],
            name="fk_phase4_alpaca_asset_bindings_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "account_binding_id",
                "account_binding_sha256",
                "expected_provider_account_id",
            ],
            [
                "phase4_alpaca_paper_account_bindings.account_id",
                "phase4_alpaca_paper_account_bindings.binding_id",
                "phase4_alpaca_paper_account_bindings.semantic_sha256",
                "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
            ],
            name="fk_phase4_alpaca_asset_bindings_account_binding",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "permit_id", "permit_sha256"],
            [
                "phase4_broker_request_permits.account_id",
                "phase4_broker_request_permits.permit_id",
                "phase4_broker_request_permits.semantic_sha256",
            ],
            name="fk_phase4_alpaca_asset_bindings_permit",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
            [
                "phase4_broker_ingress_receipts.account_id",
                "phase4_broker_ingress_receipts.receipt_id",
                "phase4_broker_ingress_receipts.semantic_sha256",
            ],
            name="fk_phase4_alpaca_asset_bindings_ingress",
        ),
        sa.PrimaryKeyConstraint(
            "binding_id",
            name=op.f(f"pk_{_BINDING_TABLE_NAME}"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "instrument_id",
            "sequence_number",
            name="uq_phase4_alpaca_asset_bindings_instrument_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "instrument_id",
            "semantic_sha256",
            name="uq_phase4_alpaca_asset_bindings_instrument_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "instrument_id",
            "expected_provider_asset_id",
            "semantic_sha256",
            name="uq_phase4_alpaca_asset_bindings_predecessor_target",
        ),
        sa.UniqueConstraint(
            "account_id",
            "instrument_id",
            "sequence_number",
            "semantic_sha256",
            "expected_provider_asset_id",
            name="uq_phase4_alpaca_asset_bindings_terminal",
        ),
        sa.UniqueConstraint(
            "permit_id",
            name="uq_phase4_alpaca_asset_bindings_permit",
        ),
        sa.UniqueConstraint(
            "ingress_receipt_id",
            name="uq_phase4_alpaca_asset_bindings_ingress_receipt",
        ),
        sa.UniqueConstraint(
            "evidence_sha256",
            name=op.f("uq_phase4_alpaca_paper_asset_bindings_evidence_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase4_alpaca_paper_asset_bindings_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase4_alpaca_asset_bindings_instrument_qualified",
        _BINDING_TABLE_NAME,
        ["account_id", "instrument_id", "qualified_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_alpaca_asset_bindings_provider_asset",
        _BINDING_TABLE_NAME,
        ["provider_id", "environment", "expected_provider_asset_id"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_alpaca_asset_bindings_valid_until",
        _BINDING_TABLE_NAME,
        ["valid_until"],
        unique=False,
    )
    op.create_table(
        _HEAD_TABLE_NAME,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("instrument_id", sa.String(64), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("symbol", sa.String(32), nullable=False),
        sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
        sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("last_binding_sha256", sa.String(64), nullable=False),
        sa.Column("last_qualified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "provider_id = 'alpaca-paper' AND environment = 'paper'",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_binding_heads_"
                "phase4_alpaca_asset_binding_head_provider_scope"
            ),
        ),
        sa.CheckConstraint(
            "last_sequence_number > 0 "
            "AND length(last_binding_sha256) = 64 "
            "AND length(expected_provider_account_id) = 36 "
            "AND length(expected_provider_asset_id) = 36 "
            "AND length(symbol) BETWEEN 1 AND 32",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_binding_heads_"
                "phase4_alpaca_asset_binding_head_terminal_shape"
            ),
        ),
        sa.CheckConstraint(
            "last_qualified_at < last_valid_until",
            name=op.f(
                "ck_phase4_alpaca_paper_asset_binding_heads_"
                "phase4_alpaca_asset_binding_head_time_order"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_alpaca_asset_binding_heads_account",
        ),
        sa.ForeignKeyConstraint(
            ["instrument_id"],
            ["instruments.instrument_id"],
            name="fk_phase4_alpaca_asset_binding_heads_instrument",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "instrument_id",
                "last_sequence_number",
                "last_binding_sha256",
                "expected_provider_asset_id",
            ],
            [
                f"{_BINDING_TABLE_NAME}.account_id",
                f"{_BINDING_TABLE_NAME}.instrument_id",
                f"{_BINDING_TABLE_NAME}.sequence_number",
                f"{_BINDING_TABLE_NAME}.semantic_sha256",
                f"{_BINDING_TABLE_NAME}.expected_provider_asset_id",
            ],
            name="fk_phase4_alpaca_asset_binding_heads_terminal",
        ),
        sa.PrimaryKeyConstraint(
            "account_id",
            "instrument_id",
            name=op.f(f"pk_{_HEAD_TABLE_NAME}"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "expected_provider_asset_id",
            name="uq_phase4_alpaca_asset_binding_heads_provider_asset",
        ),
        sa.UniqueConstraint(
            "account_id",
            "symbol",
            name="uq_phase4_alpaca_asset_binding_heads_symbol",
        ),
    )
    op.create_index(
        "ix_phase4_alpaca_asset_binding_heads_valid_until",
        _HEAD_TABLE_NAME,
        ["last_valid_until"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE phase4_alpaca_paper_asset_binding_heads, "
            "phase4_alpaca_paper_asset_bindings, "
            "phase4_alpaca_paper_account_bindings, "
            "phase4_broker_request_permits, "
            "phase4_broker_ingress_receipts IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    bindings = sa.table(
        _BINDING_TABLE_NAME,
        sa.column("binding_id", sa.String(length=36)),
    )
    heads = sa.table(
        _HEAD_TABLE_NAME,
        sa.column("account_id", sa.String(length=64)),
    )
    if connection.scalar(sa.select(sa.func.count()).select_from(bindings)) or connection.scalar(
        sa.select(sa.func.count()).select_from(heads)
    ):
        raise RuntimeError(
            "cannot downgrade after durable Alpaca paper asset bindings have been persisted"
        )
    op.drop_index(
        "ix_phase4_alpaca_asset_binding_heads_valid_until",
        table_name=_HEAD_TABLE_NAME,
    )
    op.drop_table(_HEAD_TABLE_NAME)
    op.drop_index(
        "ix_phase4_alpaca_asset_bindings_valid_until",
        table_name=_BINDING_TABLE_NAME,
    )
    op.drop_index(
        "ix_phase4_alpaca_asset_bindings_provider_asset",
        table_name=_BINDING_TABLE_NAME,
    )
    op.drop_index(
        "ix_phase4_alpaca_asset_bindings_instrument_qualified",
        table_name=_BINDING_TABLE_NAME,
    )
    op.drop_table(_BINDING_TABLE_NAME)
    op.drop_index(
        _ACCOUNT_BINDING_EXACT_INDEX,
        table_name="phase4_alpaca_paper_account_bindings",
    )
