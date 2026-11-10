"""Add durable position-pair transition admission.

Revision ID: 0023_phase4_position_transition
Revises: 0022_phase4_position_view_cmp
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_phase4_position_transition"
down_revision: str | None = "0022_phase4_position_view_cmp"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLAN_TABLE = "phase4_alpaca_paper_position_snapshot_plans"
_PLAN_EXACT_INDEX = "uq_phase4_position_snapshot_plan_transition_source"
_MEMBER_TABLE = "phase4_alpaca_paper_position_transition_members"
_CLAIM_TABLE = "phase4_alpaca_paper_position_transition_claims"
_CONSUMPTION_TABLE = "phase4_alpaca_paper_position_transition_consumptions"


def upgrade() -> None:
    op.create_index(
        _PLAN_EXACT_INDEX,
        _PLAN_TABLE,
        [
            "plan_id",
            "capture_id",
            "account_id",
            "semantic_sha256",
            "preparation_id",
            "preparation_sha256",
            "prepared_at",
        ],
        unique=True,
    )

    op.create_table(
        _MEMBER_TABLE,
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("round_id", sa.String(36), nullable=False),
        sa.Column("member_role", sa.String(16), nullable=False),
        sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("capture_id", sa.String(36), nullable=False),
        sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("secret_ref", sa.String(256), nullable=False),
        sa.Column("secret_version", sa.String(128), nullable=False),
        sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
        sa.Column("account_binding_id", sa.String(36), nullable=False),
        sa.Column("account_binding_sha256", sa.String(64), nullable=False),
        sa.Column("account_binding_sequence", sa.BigInteger(), nullable=False),
        sa.Column("plan_canonical_payload", sa.Text(), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("member_id", name=op.f(f"pk_{_MEMBER_TABLE}")),
        *(
            sa.UniqueConstraint(
                column,
                name=op.f(f"uq_{_MEMBER_TABLE}_{column}"),
            )
            for column in (
                "plan_id",
                "capture_id",
                "plan_sha256",
                "semantic_sha256",
            )
        ),
        sa.UniqueConstraint(
            "round_id",
            "member_role",
            name="uq_phase4_position_transition_member_role",
        ),
        sa.UniqueConstraint(
            "account_id",
            "capture_idempotency_key",
            name="uq_phase4_position_transition_member_account_key",
        ),
        sa.UniqueConstraint(
            "member_id",
            "round_id",
            "member_role",
            "transition_plan_sha256",
            "account_id",
            "expected_provider_account_id",
            "plan_id",
            "capture_id",
            "plan_sha256",
            "semantic_sha256",
            name="uq_phase4_position_transition_member_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_position_transition_member_account",
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
            name="fk_phase4_position_transition_member_binding",
        ),
        sa.CheckConstraint(
            "member_role IN ('earlier', 'later') "
            "AND provider_id = 'alpaca-paper' "
            "AND environment = 'paper' "
            "AND account_binding_sequence > 0",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_position_transition_member_scope"),
        ),
        sa.CheckConstraint(
            "length(member_id) = 36 "
            "AND length(round_id) = 36 "
            "AND length(expected_provider_account_id) = 36 "
            "AND length(plan_id) = 36 "
            "AND length(capture_id) = 36 "
            "AND length(account_binding_id) = 36",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_position_transition_member_id_shape"),
        ),
        sa.CheckConstraint(
            "length(transition_plan_sha256) = 64 "
            "AND length(description_sha256) = 64 "
            "AND length(capability_sha256) = 64 "
            "AND length(credential_reference_sha256) = 64 "
            "AND length(account_binding_sha256) = 64 "
            "AND length(plan_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_position_transition_member_hashes"),
        ),
        sa.CheckConstraint(
            "length(capture_idempotency_key) BETWEEN 8 AND 128 "
            "AND length(secret_ref) BETWEEN 1 AND 256 "
            "AND length(secret_version) BETWEEN 1 AND 128 "
            "AND length(plan_canonical_payload) BETWEEN 2 AND 16384 "
            "AND length(canonical_payload) BETWEEN 2 AND 32768",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_position_transition_member_bounds"),
        ),
    )
    op.create_index(
        "ix_phase4_position_transition_member_account_round",
        _MEMBER_TABLE,
        ["account_id", "round_id"],
        unique=False,
    )

    op.create_table(
        _CLAIM_TABLE,
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("round_id", sa.String(36), nullable=False),
        sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
        sa.Column("selected_role", sa.String(16), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("earlier_member_id", sa.String(36), nullable=False),
        sa.Column("earlier_member_role", sa.String(16), nullable=False),
        sa.Column("earlier_member_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_plan_id", sa.String(36), nullable=False),
        sa.Column("earlier_capture_id", sa.String(36), nullable=False),
        sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
        sa.Column("later_member_id", sa.String(36), nullable=False),
        sa.Column("later_member_role", sa.String(16), nullable=False),
        sa.Column("later_member_sha256", sa.String(64), nullable=False),
        sa.Column("later_plan_id", sa.String(36), nullable=False),
        sa.Column("later_capture_id", sa.String(36), nullable=False),
        sa.Column("later_plan_sha256", sa.String(64), nullable=False),
        sa.Column("selected_member_id", sa.String(36), nullable=False),
        sa.Column("selected_plan_id", sa.String(36), nullable=False),
        sa.Column("selected_capture_id", sa.String(36), nullable=False),
        sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
        sa.Column("prior_snapshot_receipt_id", sa.String(36), nullable=True),
        sa.Column("prior_snapshot_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("prior_plan_id", sa.String(36), nullable=True),
        sa.Column("prior_capture_id", sa.String(36), nullable=True),
        sa.Column("prior_plan_sha256", sa.String(64), nullable=True),
        sa.Column("prior_persisted_snapshot_sha256", sa.String(64), nullable=True),
        sa.Column("prior_ingress_receipt_id", sa.String(64), nullable=True),
        sa.Column("prior_ingress_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("prior_ingress_sequence", sa.BigInteger(), nullable=True),
        sa.Column(
            "prior_source_committed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("eligible_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "commit_fence_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("transition_policy_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("claim_id", name=op.f(f"pk_{_CLAIM_TABLE}")),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_CLAIM_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "round_id",
            "selected_role",
            name="uq_phase4_position_transition_claim_role",
        ),
        sa.UniqueConstraint(
            "selected_member_id",
            name="uq_phase4_position_transition_claim_member",
        ),
        sa.UniqueConstraint(
            "claim_id",
            "semantic_sha256",
            "round_id",
            "selected_role",
            "selected_member_id",
            "selected_plan_id",
            "selected_capture_id",
            "selected_plan_sha256",
            "account_id",
            "fence_owner_id",
            "fence_lease_id",
            "fence_fencing_generation",
            "fence_sha256",
            "fence_policy_sha256",
            "commit_fence_lease_sha256",
            "commit_fence_receipt_sha256",
            "selected_at",
            "commit_fence_valid_until",
            name="uq_phase4_position_transition_claim_exact",
        ),
        sa.ForeignKeyConstraint(
            [
                "earlier_member_id",
                "round_id",
                "earlier_member_role",
                "transition_plan_sha256",
                "account_id",
                "expected_provider_account_id",
                "earlier_plan_id",
                "earlier_capture_id",
                "earlier_plan_sha256",
                "earlier_member_sha256",
            ],
            [
                f"{_MEMBER_TABLE}.member_id",
                f"{_MEMBER_TABLE}.round_id",
                f"{_MEMBER_TABLE}.member_role",
                f"{_MEMBER_TABLE}.transition_plan_sha256",
                f"{_MEMBER_TABLE}.account_id",
                f"{_MEMBER_TABLE}.expected_provider_account_id",
                f"{_MEMBER_TABLE}.plan_id",
                f"{_MEMBER_TABLE}.capture_id",
                f"{_MEMBER_TABLE}.plan_sha256",
                f"{_MEMBER_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_position_transition_claim_earlier",
        ),
        sa.ForeignKeyConstraint(
            [
                "later_member_id",
                "round_id",
                "later_member_role",
                "transition_plan_sha256",
                "account_id",
                "expected_provider_account_id",
                "later_plan_id",
                "later_capture_id",
                "later_plan_sha256",
                "later_member_sha256",
            ],
            [
                f"{_MEMBER_TABLE}.member_id",
                f"{_MEMBER_TABLE}.round_id",
                f"{_MEMBER_TABLE}.member_role",
                f"{_MEMBER_TABLE}.transition_plan_sha256",
                f"{_MEMBER_TABLE}.account_id",
                f"{_MEMBER_TABLE}.expected_provider_account_id",
                f"{_MEMBER_TABLE}.plan_id",
                f"{_MEMBER_TABLE}.capture_id",
                f"{_MEMBER_TABLE}.plan_sha256",
                f"{_MEMBER_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_position_transition_claim_later",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "fence_fencing_generation",
                "commit_fence_lease_sha256",
            ],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_position_transition_claim_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "prior_snapshot_receipt_id",
                "prior_plan_id",
                "prior_capture_id",
                "account_id",
                "prior_plan_sha256",
                "prior_persisted_snapshot_sha256",
                "prior_snapshot_receipt_sha256",
                "prior_ingress_receipt_id",
                "prior_ingress_receipt_sha256",
                "prior_ingress_sequence",
                "prior_source_committed_at",
            ],
            [
                "phase4_alpaca_paper_position_snapshots.receipt_id",
                "phase4_alpaca_paper_position_snapshots.plan_id",
                "phase4_alpaca_paper_position_snapshots.capture_id",
                "phase4_alpaca_paper_position_snapshots.account_id",
                "phase4_alpaca_paper_position_snapshots.plan_sha256",
                "phase4_alpaca_paper_position_snapshots.persisted_snapshot_sha256",
                "phase4_alpaca_paper_position_snapshots.semantic_sha256",
                "phase4_alpaca_paper_position_snapshots.ingress_receipt_id",
                "phase4_alpaca_paper_position_snapshots.ingress_receipt_sha256",
                "phase4_alpaca_paper_position_snapshots.ingress_sequence",
                "phase4_alpaca_paper_position_snapshots.commit_fence_validated_at",
            ],
            name="fk_phase4_position_transition_claim_prior",
        ),
        sa.CheckConstraint(
            "selected_role IN ('earlier', 'later') "
            "AND earlier_member_id <> later_member_id "
            "AND earlier_plan_id <> later_plan_id "
            "AND earlier_capture_id <> later_capture_id "
            "AND earlier_member_role = 'earlier' "
            "AND later_member_role = 'later'",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_position_transition_claim_scope"),
        ),
        sa.CheckConstraint(
            "(selected_role = 'earlier' "
            "AND selected_member_id = earlier_member_id "
            "AND selected_plan_id = earlier_plan_id "
            "AND selected_capture_id = earlier_capture_id "
            "AND selected_plan_sha256 = earlier_plan_sha256 "
            "AND prior_snapshot_receipt_id IS NULL "
            "AND prior_snapshot_receipt_sha256 IS NULL "
            "AND prior_plan_id IS NULL "
            "AND prior_capture_id IS NULL "
            "AND prior_plan_sha256 IS NULL "
            "AND prior_persisted_snapshot_sha256 IS NULL "
            "AND prior_ingress_receipt_id IS NULL "
            "AND prior_ingress_receipt_sha256 IS NULL "
            "AND prior_ingress_sequence IS NULL "
            "AND prior_source_committed_at IS NULL "
            "AND eligible_at IS NULL) "
            "OR (selected_role = 'later' "
            "AND selected_member_id = later_member_id "
            "AND selected_plan_id = later_plan_id "
            "AND selected_capture_id = later_capture_id "
            "AND selected_plan_sha256 = later_plan_sha256 "
            "AND prior_snapshot_receipt_id IS NOT NULL "
            "AND prior_snapshot_receipt_sha256 IS NOT NULL "
            "AND prior_plan_id = earlier_plan_id "
            "AND prior_capture_id = earlier_capture_id "
            "AND prior_plan_sha256 = earlier_plan_sha256 "
            "AND prior_persisted_snapshot_sha256 IS NOT NULL "
            "AND prior_ingress_receipt_id IS NOT NULL "
            "AND prior_ingress_receipt_sha256 IS NOT NULL "
            "AND prior_ingress_sequence > 0 "
            "AND prior_source_committed_at IS NOT NULL "
            "AND eligible_at IS NOT NULL "
            "AND selected_at >= eligible_at "
            "AND selected_at >= prior_source_committed_at)",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_position_transition_claim_role_shape"),
        ),
        sa.CheckConstraint(
            "fence_fencing_generation > 0 AND selected_at < commit_fence_valid_until",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_position_transition_claim_fence"),
        ),
        sa.CheckConstraint(
            "length(claim_id) = 36 "
            "AND length(round_id) = 36 "
            "AND length(expected_provider_account_id) = 36 "
            "AND length(earlier_member_id) = 36 "
            "AND length(later_member_id) = 36 "
            "AND length(selected_member_id) = 36 "
            "AND length(selected_plan_id) = 36 "
            "AND length(selected_capture_id) = 36",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_position_transition_claim_ids"),
        ),
        sa.CheckConstraint(
            "length(transition_plan_sha256) = 64 "
            "AND length(earlier_member_sha256) = 64 "
            "AND length(earlier_plan_sha256) = 64 "
            "AND length(later_member_sha256) = 64 "
            "AND length(later_plan_sha256) = 64 "
            "AND length(selected_plan_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(transition_policy_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_position_transition_claim_hashes"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_position_transition_claim_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_position_transition_claim_account_selected",
        _CLAIM_TABLE,
        ["account_id", "selected_at"],
        unique=False,
    )

    op.create_table(
        _CONSUMPTION_TABLE,
        sa.Column("consumption_id", sa.String(36), nullable=False),
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("claim_sha256", sa.String(64), nullable=False),
        sa.Column("round_id", sa.String(36), nullable=False),
        sa.Column("selected_role", sa.String(16), nullable=False),
        sa.Column("selected_member_id", sa.String(36), nullable=False),
        sa.Column("selected_plan_id", sa.String(36), nullable=False),
        sa.Column("selected_capture_id", sa.String(36), nullable=False),
        sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("preparation_id", sa.String(36), nullable=False),
        sa.Column("preparation_sha256", sa.String(64), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("claim_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("claim_selected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "commit_fence_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "consumption_id",
            name=op.f(f"pk_{_CONSUMPTION_TABLE}"),
        ),
        *(
            sa.UniqueConstraint(
                column,
                name=op.f(f"uq_{_CONSUMPTION_TABLE}_{column}"),
            )
            for column in (
                "claim_id",
                "claim_sha256",
                "selected_member_id",
                "selected_plan_id",
                "selected_capture_id",
                "preparation_id",
                "preparation_sha256",
                "semantic_sha256",
            )
        ),
        sa.ForeignKeyConstraint(
            [
                "claim_id",
                "claim_sha256",
                "round_id",
                "selected_role",
                "selected_member_id",
                "selected_plan_id",
                "selected_capture_id",
                "selected_plan_sha256",
                "account_id",
                "fence_owner_id",
                "fence_lease_id",
                "fence_fencing_generation",
                "fence_sha256",
                "fence_policy_sha256",
                "commit_fence_lease_sha256",
                "claim_fence_receipt_sha256",
                "claim_selected_at",
                "commit_fence_valid_until",
            ],
            [
                f"{_CLAIM_TABLE}.claim_id",
                f"{_CLAIM_TABLE}.semantic_sha256",
                f"{_CLAIM_TABLE}.round_id",
                f"{_CLAIM_TABLE}.selected_role",
                f"{_CLAIM_TABLE}.selected_member_id",
                f"{_CLAIM_TABLE}.selected_plan_id",
                f"{_CLAIM_TABLE}.selected_capture_id",
                f"{_CLAIM_TABLE}.selected_plan_sha256",
                f"{_CLAIM_TABLE}.account_id",
                f"{_CLAIM_TABLE}.fence_owner_id",
                f"{_CLAIM_TABLE}.fence_lease_id",
                f"{_CLAIM_TABLE}.fence_fencing_generation",
                f"{_CLAIM_TABLE}.fence_sha256",
                f"{_CLAIM_TABLE}.fence_policy_sha256",
                f"{_CLAIM_TABLE}.commit_fence_lease_sha256",
                f"{_CLAIM_TABLE}.commit_fence_receipt_sha256",
                f"{_CLAIM_TABLE}.selected_at",
                f"{_CLAIM_TABLE}.commit_fence_valid_until",
            ],
            name="fk_phase4_position_transition_consumption_claim",
        ),
        sa.ForeignKeyConstraint(
            [
                "selected_plan_id",
                "selected_capture_id",
                "account_id",
                "selected_plan_sha256",
                "preparation_id",
                "preparation_sha256",
                "prepared_at",
            ],
            [
                f"{_PLAN_TABLE}.plan_id",
                f"{_PLAN_TABLE}.capture_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
                f"{_PLAN_TABLE}.preparation_id",
                f"{_PLAN_TABLE}.preparation_sha256",
                f"{_PLAN_TABLE}.prepared_at",
            ],
            name="fk_phase4_position_transition_consumption_plan",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "fence_fencing_generation",
                "commit_fence_lease_sha256",
            ],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_position_transition_consumption_lease",
        ),
        sa.CheckConstraint(
            "selected_role IN ('earlier', 'later') "
            "AND fence_fencing_generation > 0 "
            "AND claim_selected_at <= prepared_at "
            "AND prepared_at <= consumed_at "
            "AND consumed_at < commit_fence_valid_until",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_position_transition_consumption_time"),
        ),
        sa.CheckConstraint(
            "length(consumption_id) = 36 "
            "AND length(claim_id) = 36 "
            "AND length(round_id) = 36 "
            "AND length(selected_member_id) = 36 "
            "AND length(selected_plan_id) = 36 "
            "AND length(selected_capture_id) = 36 "
            "AND length(preparation_id) = 36",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_position_transition_consumption_ids"),
        ),
        sa.CheckConstraint(
            "length(claim_sha256) = 64 "
            "AND length(selected_plan_sha256) = 64 "
            "AND length(preparation_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(claim_fence_receipt_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_position_transition_consumption_hashes"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_position_transition_consumption_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_position_transition_consumption_account_time",
        _CONSUMPTION_TABLE,
        ["account_id", "consumed_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    guarded_tables = (_CONSUMPTION_TABLE, _CLAIM_TABLE, _MEMBER_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE " + ", ".join((*guarded_tables, _PLAN_TABLE)) + " IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty position-view transition history")
    op.drop_index(
        "ix_phase4_position_transition_consumption_account_time",
        table_name=_CONSUMPTION_TABLE,
    )
    op.drop_table(_CONSUMPTION_TABLE)
    op.drop_index(
        "ix_phase4_position_transition_claim_account_selected",
        table_name=_CLAIM_TABLE,
    )
    op.drop_table(_CLAIM_TABLE)
    op.drop_index(
        "ix_phase4_position_transition_member_account_round",
        table_name=_MEMBER_TABLE,
    )
    op.drop_table(_MEMBER_TABLE)
    op.drop_index(_PLAN_EXACT_INDEX, table_name=_PLAN_TABLE)
