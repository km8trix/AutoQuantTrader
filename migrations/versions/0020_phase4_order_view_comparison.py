"""Add durable authenticated Alpaca paper order-view comparisons.

Revision ID: 0020_phase4_order_view_cmp
Revises: 0019_phase4_order_snapshots
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_phase4_order_view_cmp"
down_revision: str | None = "0019_phase4_order_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COMPARISON_TABLE = "phase4_alpaca_paper_order_view_comparisons"
_HEAD_TABLE = "phase4_alpaca_paper_order_view_comparison_heads"
_PLAN_TABLE = "phase4_alpaca_paper_order_snapshot_plans"
_PAGE_TABLE = "phase4_alpaca_paper_order_snapshot_pages"
_SNAPSHOT_HEAD_TABLE = "phase4_alpaca_paper_order_snapshot_heads"


def upgrade() -> None:
    op.create_table(
        _COMPARISON_TABLE,
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("comparison_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authentication_policy_sha256", sa.String(64), nullable=False),
        sa.Column("comparison_policy_sha256", sa.String(64), nullable=False),
        sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_snapshot_id", sa.String(36), nullable=False),
        sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_head_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_prefix_id", sa.String(36), nullable=False),
        sa.Column("earlier_prefix_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_capture_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_page_count", sa.BigInteger(), nullable=False),
        sa.Column("earlier_tip_receipt_id", sa.String(36), nullable=False),
        sa.Column("earlier_tip_receipt_sha256", sa.String(64), nullable=False),
        sa.Column(
            "earlier_tip_persisted_page_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("earlier_source_committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("earlier_window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("earlier_window_ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("earlier_view_sha256", sa.String(64), nullable=False),
        sa.Column("later_snapshot_id", sa.String(36), nullable=False),
        sa.Column("later_plan_sha256", sa.String(64), nullable=False),
        sa.Column("later_head_sha256", sa.String(64), nullable=False),
        sa.Column("later_prefix_id", sa.String(36), nullable=False),
        sa.Column("later_prefix_sha256", sa.String(64), nullable=False),
        sa.Column("later_capture_sha256", sa.String(64), nullable=False),
        sa.Column("later_page_count", sa.BigInteger(), nullable=False),
        sa.Column("later_tip_receipt_id", sa.String(36), nullable=False),
        sa.Column("later_tip_receipt_sha256", sa.String(64), nullable=False),
        sa.Column(
            "later_tip_persisted_page_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("later_source_committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("later_window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("later_window_ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("later_view_sha256", sa.String(64), nullable=False),
        sa.Column("observed_utc_separation_microseconds", sa.String(32), nullable=False),
        sa.Column("disposition", sa.String(64), nullable=False),
        sa.Column("added_provider_order_ids_payload", sa.Text(), nullable=False),
        sa.Column("removed_provider_order_ids_payload", sa.Text(), nullable=False),
        sa.Column("changed_provider_order_ids_payload", sa.Text(), nullable=False),
        sa.Column("added_count", sa.BigInteger(), nullable=False),
        sa.Column("removed_count", sa.BigInteger(), nullable=False),
        sa.Column("changed_count", sa.BigInteger(), nullable=False),
        sa.Column("comparison_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("receipt_id", name=op.f(f"pk_{_COMPARISON_TABLE}")),
        sa.UniqueConstraint(
            "evidence_id",
            name=op.f(f"uq_{_COMPARISON_TABLE}_evidence_id"),
        ),
        sa.UniqueConstraint(
            "comparison_id",
            name=op.f(f"uq_{_COMPARISON_TABLE}_comparison_id"),
        ),
        sa.UniqueConstraint(
            "evidence_sha256",
            name=op.f(f"uq_{_COMPARISON_TABLE}_evidence_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_COMPARISON_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            name="uq_phase4_order_view_cmp_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_order_view_cmp_account_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            "receipt_id",
            "semantic_sha256",
            "recorded_at",
            name="uq_phase4_order_view_cmp_exact",
        ),
        sa.UniqueConstraint(
            "earlier_snapshot_id",
            "later_snapshot_id",
            "authentication_policy_sha256",
            name="uq_phase4_order_view_cmp_source_pair",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_order_view_cmp_account",
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
            name="fk_phase4_order_view_cmp_commit_lease",
        ),
        sa.ForeignKeyConstraint(
            ["earlier_snapshot_id", "account_id", "earlier_plan_sha256"],
            [
                f"{_PLAN_TABLE}.snapshot_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_view_cmp_earlier_plan",
        ),
        sa.ForeignKeyConstraint(
            ["later_snapshot_id", "account_id", "later_plan_sha256"],
            [
                f"{_PLAN_TABLE}.snapshot_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_view_cmp_later_plan",
        ),
        sa.ForeignKeyConstraint(
            ["earlier_snapshot_id", "account_id", "earlier_head_sha256"],
            [
                f"{_SNAPSHOT_HEAD_TABLE}.snapshot_id",
                f"{_SNAPSHOT_HEAD_TABLE}.account_id",
                f"{_SNAPSHOT_HEAD_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_view_cmp_earlier_head",
        ),
        sa.ForeignKeyConstraint(
            ["later_snapshot_id", "account_id", "later_head_sha256"],
            [
                f"{_SNAPSHOT_HEAD_TABLE}.snapshot_id",
                f"{_SNAPSHOT_HEAD_TABLE}.account_id",
                f"{_SNAPSHOT_HEAD_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_view_cmp_later_head",
        ),
        sa.ForeignKeyConstraint(
            [
                "earlier_snapshot_id",
                "earlier_page_count",
                "earlier_tip_receipt_id",
                "earlier_tip_receipt_sha256",
                "earlier_tip_persisted_page_sha256",
            ],
            [
                f"{_PAGE_TABLE}.snapshot_id",
                f"{_PAGE_TABLE}.page_number",
                f"{_PAGE_TABLE}.receipt_id",
                f"{_PAGE_TABLE}.semantic_sha256",
                f"{_PAGE_TABLE}.persisted_page_sha256",
            ],
            name="fk_phase4_order_view_cmp_earlier_tip",
        ),
        sa.ForeignKeyConstraint(
            [
                "later_snapshot_id",
                "later_page_count",
                "later_tip_receipt_id",
                "later_tip_receipt_sha256",
                "later_tip_persisted_page_sha256",
            ],
            [
                f"{_PAGE_TABLE}.snapshot_id",
                f"{_PAGE_TABLE}.page_number",
                f"{_PAGE_TABLE}.receipt_id",
                f"{_PAGE_TABLE}.semantic_sha256",
                f"{_PAGE_TABLE}.persisted_page_sha256",
            ],
            name="fk_phase4_order_view_cmp_later_tip",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "previous_receipt_sha256"],
            [f"{_COMPARISON_TABLE}.account_id", f"{_COMPARISON_TABLE}.semantic_sha256"],
            name="fk_phase4_order_view_cmp_predecessor",
        ),
        sa.CheckConstraint(
            "(account_sequence = 1 AND previous_receipt_sha256 IS NULL) "
            "OR (account_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "fence_fencing_generation > 0 "
            "AND commit_fence_validated_at = recorded_at "
            "AND commit_fence_validated_at < commit_fence_valid_until",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_commit_fence"),
        ),
        sa.CheckConstraint(
            "earlier_snapshot_id <> later_snapshot_id "
            "AND earlier_prefix_id <> later_prefix_id "
            "AND earlier_tip_receipt_id <> later_tip_receipt_id",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_distinct_sources"),
        ),
        sa.CheckConstraint(
            "earlier_page_count BETWEEN 1 AND 8 "
            "AND later_page_count BETWEEN 1 AND 8 "
            "AND earlier_window_started_at <= earlier_window_ended_at "
            "AND later_window_started_at <= later_window_ended_at "
            "AND recorded_at >= earlier_source_committed_at "
            "AND recorded_at >= later_source_committed_at",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_time_bounds"),
        ),
        sa.CheckConstraint(
            "disposition IN ("
            "'exact_order_view_match_unqualified', "
            "'order_view_different', "
            "'waiting_minimum_separation', "
            "'bounded_traversal_incomplete')",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_disposition"),
        ),
        sa.CheckConstraint(
            "added_count >= 0 AND added_count <= 8000 "
            "AND removed_count >= 0 AND removed_count <= 8000 "
            "AND changed_count >= 0 AND changed_count <= 8000",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_difference_bounds"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 36 "
            "AND length(evidence_id) = 36 "
            "AND length(comparison_id) = 36 "
            "AND length(fence_owner_id) BETWEEN 1 AND 128 "
            "AND length(fence_lease_id) BETWEEN 1 AND 64 "
            "AND length(earlier_snapshot_id) = 36 "
            "AND length(earlier_prefix_id) = 36 "
            "AND length(earlier_tip_receipt_id) = 36 "
            "AND length(later_snapshot_id) = 36 "
            "AND length(later_prefix_id) = 36 "
            "AND length(later_tip_receipt_id) = 36",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_id_lengths"),
        ),
        sa.CheckConstraint(
            "(previous_receipt_sha256 IS NULL OR length(previous_receipt_sha256) = 64) "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(authentication_policy_sha256) = 64 "
            "AND length(comparison_policy_sha256) = 64 "
            "AND length(traversal_profile_sha256) = 64 "
            "AND length(earlier_plan_sha256) = 64 "
            "AND length(earlier_head_sha256) = 64 "
            "AND length(earlier_prefix_sha256) = 64 "
            "AND length(earlier_capture_sha256) = 64 "
            "AND length(earlier_tip_receipt_sha256) = 64 "
            "AND length(earlier_tip_persisted_page_sha256) = 64 "
            "AND length(earlier_view_sha256) = 64 "
            "AND length(later_plan_sha256) = 64 "
            "AND length(later_head_sha256) = 64 "
            "AND length(later_prefix_sha256) = 64 "
            "AND length(later_capture_sha256) = 64 "
            "AND length(later_tip_receipt_sha256) = 64 "
            "AND length(later_tip_persisted_page_sha256) = 64 "
            "AND length(later_view_sha256) = 64 "
            "AND length(comparison_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(observed_utc_separation_microseconds) BETWEEN 1 AND 32 "
            "AND length(added_provider_order_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(removed_provider_order_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(changed_provider_order_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(canonical_payload) BETWEEN 2 AND 1048576",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_order_view_cmp_payload_sizes"),
        ),
    )
    op.create_index(
        "ix_phase4_order_view_cmp_account_recorded",
        _COMPARISON_TABLE,
        ["account_id", "recorded_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_order_view_cmp_sources",
        _COMPARISON_TABLE,
        ["earlier_snapshot_id", "later_snapshot_id"],
        unique=False,
    )

    op.create_table(
        _HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_receipt_id", sa.String(36), nullable=False),
        sa.Column("last_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("last_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("account_id", name=op.f(f"pk_{_HEAD_TABLE}")),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_order_view_cmp_head_semantic",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_order_view_cmp_head_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "last_account_sequence",
                "last_receipt_id",
                "last_receipt_sha256",
                "last_recorded_at",
            ],
            [
                f"{_COMPARISON_TABLE}.account_id",
                f"{_COMPARISON_TABLE}.account_sequence",
                f"{_COMPARISON_TABLE}.receipt_id",
                f"{_COMPARISON_TABLE}.semantic_sha256",
                f"{_COMPARISON_TABLE}.recorded_at",
            ],
            name="fk_phase4_order_view_cmp_head_tip",
        ),
        sa.CheckConstraint(
            "last_account_sequence > 0 "
            "AND length(last_receipt_id) = 36 "
            "AND length(last_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_view_cmp_head_shape"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 16384",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_view_cmp_head_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_order_view_cmp_head_recorded",
        _HEAD_TABLE,
        ["last_recorded_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    tables = (_HEAD_TABLE, _COMPARISON_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE")
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}")) for table_name in tables
    )
    if any(counts):
        raise RuntimeError(
            "refusing to downgrade nonempty authenticated order-view comparison history"
        )
    op.drop_index(
        "ix_phase4_order_view_cmp_head_recorded",
        table_name=_HEAD_TABLE,
    )
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_order_view_cmp_sources",
        table_name=_COMPARISON_TABLE,
    )
    op.drop_index(
        "ix_phase4_order_view_cmp_account_recorded",
        table_name=_COMPARISON_TABLE,
    )
    op.drop_table(_COMPARISON_TABLE)
