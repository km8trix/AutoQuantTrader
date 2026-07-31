"""Add single-use authenticated Alpaca paper position snapshots.

Revision ID: 0021_phase4_position_snapshots
Revises: 0020_phase4_order_view_cmp
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_phase4_position_snapshots"
down_revision: str | None = "0020_phase4_order_view_cmp"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLAN_TABLE = "phase4_alpaca_paper_position_snapshot_plans"
_SNAPSHOT_TABLE = "phase4_alpaca_paper_position_snapshots"


def upgrade() -> None:
    op.create_table(
        _PLAN_TABLE,
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("capture_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("secret_ref", sa.String(256), nullable=False),
        sa.Column("secret_version", sa.String(128), nullable=False),
        sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
        sa.Column("account_binding_id", sa.String(36), nullable=False),
        sa.Column("account_binding_sha256", sa.String(64), nullable=False),
        sa.Column("account_binding_sequence", sa.BigInteger(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("preparation_id", sa.String(36), nullable=False),
        sa.Column("preparation_sha256", sa.String(64), nullable=False),
        sa.Column("plan_canonical_payload", sa.Text(), nullable=False),
        sa.Column("preparation_canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("plan_id", name=op.f(f"pk_{_PLAN_TABLE}")),
        sa.UniqueConstraint(
            "capture_id",
            name=op.f(f"uq_{_PLAN_TABLE}_capture_id"),
        ),
        sa.UniqueConstraint(
            "preparation_id",
            name=op.f(f"uq_{_PLAN_TABLE}_preparation_id"),
        ),
        sa.UniqueConstraint(
            "preparation_sha256",
            name=op.f(f"uq_{_PLAN_TABLE}_preparation_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_PLAN_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "capture_idempotency_key",
            name="uq_phase4_position_snapshot_plan_account_key",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "capture_id",
            "account_id",
            "semantic_sha256",
            "preparation_sha256",
            name="uq_phase4_position_snapshot_plan_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_position_snapshot_plan_account",
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
            name="fk_phase4_position_snapshot_plan_account_binding",
        ),
        sa.CheckConstraint(
            "provider_id = 'alpaca-paper' AND environment = 'paper'",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_position_snapshot_plan_provider_scope"),
        ),
        sa.CheckConstraint(
            "account_binding_sequence > 0 "
            "AND length(plan_id) = 36 "
            "AND length(capture_id) = 36 "
            "AND length(preparation_id) = 36 "
            "AND length(expected_provider_account_id) = 36 "
            "AND length(account_binding_id) = 36",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_position_snapshot_plan_id_shape"),
        ),
        sa.CheckConstraint(
            "length(capture_idempotency_key) BETWEEN 8 AND 128 "
            "AND length(secret_ref) BETWEEN 1 AND 256 "
            "AND length(secret_version) BETWEEN 1 AND 128",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_position_snapshot_plan_text_bounds"),
        ),
        sa.CheckConstraint(
            "length(description_sha256) = 64 "
            "AND length(capability_sha256) = 64 "
            "AND length(credential_reference_sha256) = 64 "
            "AND length(account_binding_sha256) = 64 "
            "AND length(preparation_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_position_snapshot_plan_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(plan_canonical_payload) BETWEEN 2 AND 16384 "
            "AND length(preparation_canonical_payload) BETWEEN 2 AND 16384",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_position_snapshot_plan_payload_sizes"),
        ),
    )
    op.create_index(
        "ix_phase4_position_snapshot_plan_account_prepared",
        _PLAN_TABLE,
        ["account_id", "prepared_at"],
        unique=False,
    )

    snapshot_columns: list[sa.Column[object]] = [
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("capture_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("preparation_sha256", sa.String(64), nullable=False),
        sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
        sa.Column("resolver_id", sa.String(128), nullable=False),
        sa.Column("resolver_version", sa.String(128), nullable=False),
        sa.Column(
            "credential_resolution_started_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "credential_resolution_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
        sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
        sa.Column(
            "pre_account_identity_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "post_account_identity_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("demand_id", sa.String(64), nullable=False),
        sa.Column("demand_sha256", sa.String(64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_id", sa.String(64), nullable=False),
        sa.Column("permit_sha256", sa.String(64), nullable=False),
        sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("permit_issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("transport_request_sha256", sa.String(64), nullable=False),
        sa.Column("transport_response_sha256", sa.String(64), nullable=False),
        sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("provider_request_id", sa.String(256), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
        sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("response_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("response_body_sha256", sa.String(64), nullable=False),
        sa.Column("position_count", sa.BigInteger(), nullable=False),
        sa.Column("observation_sha256", sa.String(64), nullable=False),
        sa.Column("persisted_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("final_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("final_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("final_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("final_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
    ]
    op.create_table(
        _SNAPSHOT_TABLE,
        *snapshot_columns,
        sa.PrimaryKeyConstraint("receipt_id", name=op.f(f"pk_{_SNAPSHOT_TABLE}")),
        *(
            sa.UniqueConstraint(
                column,
                name=op.f(f"uq_{_SNAPSHOT_TABLE}_{column}"),
            )
            for column in (
                "evidence_id",
                "plan_id",
                "capture_id",
                "permit_id",
                "ingress_receipt_id",
                "evidence_sha256",
                "semantic_sha256",
            )
        ),
        sa.UniqueConstraint(
            "plan_id",
            "capture_id",
            "account_id",
            "plan_sha256",
            "preparation_sha256",
            name="uq_phase4_position_snapshot_source_exact",
        ),
        sa.ForeignKeyConstraint(
            [
                "plan_id",
                "capture_id",
                "account_id",
                "plan_sha256",
                "preparation_sha256",
            ],
            [
                f"{_PLAN_TABLE}.plan_id",
                f"{_PLAN_TABLE}.capture_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
                f"{_PLAN_TABLE}.preparation_sha256",
            ],
            name="fk_phase4_position_snapshot_plan",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "permit_id",
                "permit_sha256",
                "demand_id",
                "demand_sha256",
                "policy_sha256",
            ],
            [
                "phase4_broker_request_permits.account_id",
                "phase4_broker_request_permits.permit_id",
                "phase4_broker_request_permits.semantic_sha256",
                "phase4_broker_request_permits.demand_id",
                "phase4_broker_request_permits.demand_sha256",
                "phase4_broker_request_permits.policy_sha256",
            ],
            name="fk_phase4_position_snapshot_permit",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
            [
                "phase4_broker_ingress_receipts.account_id",
                "phase4_broker_ingress_receipts.receipt_id",
                "phase4_broker_ingress_receipts.semantic_sha256",
            ],
            name="fk_phase4_position_snapshot_ingress",
        ),
        *(
            sa.ForeignKeyConstraint(
                [
                    "account_id",
                    "fence_fencing_generation",
                    f"{phase}_fence_lease_sha256",
                ],
                [
                    "phase2_account_leases.account_id",
                    "phase2_account_leases.fencing_generation",
                    "phase2_account_leases.lease_sha256",
                ],
                name=f"fk_phase4_position_snapshot_{phase}_lease",
            )
            for phase in ("pre", "post", "final", "commit")
        ),
        sa.CheckConstraint(
            "http_status = 200 "
            "AND ingress_sequence > 0 "
            "AND fence_fencing_generation > 0 "
            "AND response_size_bytes BETWEEN 1 AND 1048576 "
            "AND position_count BETWEEN 0 AND 512",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_bounds"),
        ),
        sa.CheckConstraint(
            "pre_fence_lease_sha256 = post_fence_lease_sha256 "
            "AND post_fence_lease_sha256 = final_fence_lease_sha256 "
            "AND final_fence_lease_sha256 = commit_fence_lease_sha256 "
            "AND pre_fence_valid_until = post_fence_valid_until "
            "AND post_fence_valid_until = final_fence_valid_until "
            "AND final_fence_valid_until = commit_fence_valid_until",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_same_lease"),
        ),
        sa.CheckConstraint(
            "requested_at <= credential_resolution_started_at "
            "AND credential_resolution_started_at <= resolved_at "
            "AND resolved_at <= permit_issued_at "
            "AND permit_issued_at <= pre_fence_validated_at "
            "AND pre_fence_validated_at <= permit_checked_at "
            "AND permit_checked_at <= pre_account_identity_checked_at "
            "AND pre_account_identity_checked_at <= request_started_at "
            "AND request_started_at <= received_at "
            "AND received_at <= raw_recorded_at "
            "AND raw_recorded_at <= post_fence_validated_at "
            "AND post_fence_validated_at <= post_account_identity_checked_at "
            "AND post_account_identity_checked_at <= final_fence_validated_at "
            "AND final_fence_validated_at <= authenticated_at "
            "AND authenticated_at <= commit_fence_validated_at",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_time_order"),
        ),
        sa.CheckConstraint(
            "resolved_at < credential_resolution_valid_until "
            "AND request_started_at < credential_resolution_valid_until "
            "AND received_at < credential_resolution_valid_until "
            "AND permit_issued_at < permit_expires_at "
            "AND request_started_at < permit_expires_at "
            "AND received_at < permit_expires_at "
            "AND request_started_at < pre_fence_valid_until "
            "AND post_account_identity_checked_at < post_fence_valid_until "
            "AND authenticated_at < final_fence_valid_until "
            "AND commit_fence_validated_at < commit_fence_valid_until",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_validity_windows"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 36 "
            "AND length(evidence_id) = 36 "
            "AND length(plan_id) = 36 "
            "AND length(capture_id) = 36",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_id_lengths"),
        ),
        sa.CheckConstraint(
            "length(plan_sha256) = 64 "
            "AND length(preparation_sha256) = 64 "
            "AND length(credential_resolution_sha256) = 64 "
            "AND length(pre_account_identity_sha256) = 64 "
            "AND length(post_account_identity_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(demand_id) = 64 "
            "AND length(demand_sha256) = 64 "
            "AND length(permit_id) = 64 "
            "AND length(permit_sha256) = 64 "
            "AND length(permit_freshness_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(pre_fence_lease_sha256) = 64 "
            "AND length(pre_fence_receipt_sha256) = 64 "
            "AND length(transport_request_sha256) = 64 "
            "AND length(transport_response_sha256) = 64 "
            "AND length(ingress_receipt_id) = 64 "
            "AND length(ingress_receipt_sha256) = 64 "
            "AND length(response_body_sha256) = 64 "
            "AND length(observation_sha256) = 64 "
            "AND length(persisted_snapshot_sha256) = 64 "
            "AND length(post_fence_lease_sha256) = 64 "
            "AND length(post_fence_receipt_sha256) = 64 "
            "AND length(final_fence_lease_sha256) = 64 "
            "AND length(final_fence_receipt_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_SNAPSHOT_TABLE}_phase4_position_snapshot_payload_size"),
        ),
    )
    op.create_index(
        "ix_phase4_position_snapshot_account_authenticated",
        _SNAPSHOT_TABLE,
        ["account_id", "authenticated_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_position_snapshot_ingress_sequence",
        _SNAPSHOT_TABLE,
        ["account_id", "ingress_sequence"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    tables = (_SNAPSHOT_TABLE, _PLAN_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE")
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}")) for table_name in tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty authenticated position snapshot history")
    op.drop_index(
        "ix_phase4_position_snapshot_ingress_sequence",
        table_name=_SNAPSHOT_TABLE,
    )
    op.drop_index(
        "ix_phase4_position_snapshot_account_authenticated",
        table_name=_SNAPSHOT_TABLE,
    )
    op.drop_table(_SNAPSHOT_TABLE)
    op.drop_index(
        "ix_phase4_position_snapshot_plan_account_prepared",
        table_name=_PLAN_TABLE,
    )
    op.drop_table(_PLAN_TABLE)
