"""Add durable authenticated Alpaca paper position-view comparisons.

Revision ID: 0022_phase4_position_view_cmp
Revises: 0021_phase4_position_snapshots
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_phase4_position_view_cmp"
down_revision: str | None = "0021_phase4_position_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SOURCE_TABLE = "phase4_alpaca_paper_position_snapshots"
_SOURCE_EXACT_INDEX = "uq_phase4_position_snapshot_comparison_source"
_COMPARISON_TABLE = "phase4_alpaca_paper_position_view_comparisons"
_HEAD_TABLE = "phase4_alpaca_paper_position_view_comparison_heads"

_SOURCE_EXACT_COLUMNS = (
    "receipt_id",
    "plan_id",
    "capture_id",
    "account_id",
    "plan_sha256",
    "persisted_snapshot_sha256",
    "semantic_sha256",
    "ingress_receipt_id",
    "ingress_receipt_sha256",
    "ingress_sequence",
    "commit_fence_validated_at",
)


def _source_columns(phase: str) -> tuple[str, ...]:
    return (
        f"{phase}_snapshot_receipt_id",
        f"{phase}_plan_id",
        f"{phase}_capture_id",
        "account_id",
        f"{phase}_plan_sha256",
        f"{phase}_persisted_snapshot_sha256",
        f"{phase}_snapshot_receipt_sha256",
        f"{phase}_ingress_receipt_id",
        f"{phase}_ingress_receipt_sha256",
        f"{phase}_ingress_sequence",
        f"{phase}_source_committed_at",
    )


def upgrade() -> None:
    op.create_index(
        _SOURCE_EXACT_INDEX,
        _SOURCE_TABLE,
        list(_SOURCE_EXACT_COLUMNS),
        unique=True,
    )

    columns: list[sa.Column[object]] = [
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("comparison_id", sa.String(36), nullable=False),
        sa.Column("comparison_plan_id", sa.String(36), nullable=False),
        sa.Column("comparison_plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column(
            "commit_fence_validated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "commit_fence_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("authentication_policy_sha256", sa.String(64), nullable=False),
        sa.Column("comparison_policy_sha256", sa.String(64), nullable=False),
        sa.Column("capture_profile_sha256", sa.String(64), nullable=False),
    ]
    for phase in ("earlier", "later"):
        columns.extend(
            (
                sa.Column(
                    f"{phase}_snapshot_receipt_id",
                    sa.String(36),
                    nullable=False,
                ),
                sa.Column(
                    f"{phase}_snapshot_receipt_sha256",
                    sa.String(64),
                    nullable=False,
                ),
                sa.Column(f"{phase}_plan_id", sa.String(36), nullable=False),
                sa.Column(f"{phase}_plan_sha256", sa.String(64), nullable=False),
                sa.Column(f"{phase}_capture_id", sa.String(36), nullable=False),
                sa.Column(
                    f"{phase}_persisted_snapshot_sha256",
                    sa.String(64),
                    nullable=False,
                ),
                sa.Column(
                    f"{phase}_ingress_receipt_id",
                    sa.String(64),
                    nullable=False,
                ),
                sa.Column(
                    f"{phase}_ingress_receipt_sha256",
                    sa.String(64),
                    nullable=False,
                ),
                sa.Column(
                    f"{phase}_ingress_sequence",
                    sa.BigInteger(),
                    nullable=False,
                ),
                sa.Column(
                    f"{phase}_source_committed_at",
                    sa.DateTime(timezone=True),
                    nullable=False,
                ),
                sa.Column(
                    f"{phase}_received_at",
                    sa.DateTime(timezone=True),
                    nullable=False,
                ),
                sa.Column(f"{phase}_view_sha256", sa.String(64), nullable=False),
            )
        )
    columns.extend(
        (
            sa.Column(
                "observed_utc_separation_microseconds",
                sa.String(32),
                nullable=False,
            ),
            sa.Column("disposition", sa.String(64), nullable=False),
            sa.Column("added_asset_ids_payload", sa.Text(), nullable=False),
            sa.Column("removed_asset_ids_payload", sa.Text(), nullable=False),
            sa.Column("changed_asset_ids_payload", sa.Text(), nullable=False),
            sa.Column("added_count", sa.BigInteger(), nullable=False),
            sa.Column("removed_count", sa.BigInteger(), nullable=False),
            sa.Column("changed_count", sa.BigInteger(), nullable=False),
            sa.Column("comparison_sha256", sa.String(64), nullable=False),
            sa.Column("evidence_sha256", sa.String(64), nullable=False),
            sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("canonical_payload", sa.Text(), nullable=False),
            sa.Column("semantic_sha256", sa.String(64), nullable=False),
        )
    )
    op.create_table(
        _COMPARISON_TABLE,
        *columns,
        sa.PrimaryKeyConstraint(
            "receipt_id",
            name=op.f(f"pk_{_COMPARISON_TABLE}"),
        ),
        *(
            sa.UniqueConstraint(
                column,
                name=op.f(f"uq_{_COMPARISON_TABLE}_{column}"),
            )
            for column in (
                "evidence_id",
                "comparison_id",
                "comparison_plan_id",
                "evidence_sha256",
                "semantic_sha256",
            )
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            name="uq_phase4_position_view_cmp_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_position_view_cmp_account_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            "receipt_id",
            "semantic_sha256",
            "recorded_at",
            name="uq_phase4_position_view_cmp_exact",
        ),
        sa.UniqueConstraint(
            "earlier_plan_id",
            "later_plan_id",
            "authentication_policy_sha256",
            name="uq_phase4_position_view_cmp_source_pair",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_position_view_cmp_account",
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
            name="fk_phase4_position_view_cmp_commit_lease",
        ),
        *(
            sa.ForeignKeyConstraint(
                _source_columns(phase),
                tuple(f"{_SOURCE_TABLE}.{column}" for column in _SOURCE_EXACT_COLUMNS),
                name=f"fk_phase4_position_view_cmp_{phase}_source",
            )
            for phase in ("earlier", "later")
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "previous_receipt_sha256"],
            [
                f"{_COMPARISON_TABLE}.account_id",
                f"{_COMPARISON_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_position_view_cmp_predecessor",
        ),
        sa.CheckConstraint(
            "(account_sequence = 1 AND previous_receipt_sha256 IS NULL) "
            "OR (account_sequence > 1 AND previous_receipt_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_predecessor"),
        ),
        sa.CheckConstraint(
            "fence_fencing_generation > 0 "
            "AND commit_fence_validated_at = recorded_at "
            "AND commit_fence_validated_at < commit_fence_valid_until",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_fence"),
        ),
        sa.CheckConstraint(
            "earlier_snapshot_receipt_id <> later_snapshot_receipt_id "
            "AND earlier_plan_id <> later_plan_id "
            "AND earlier_capture_id <> later_capture_id "
            "AND earlier_ingress_receipt_id <> later_ingress_receipt_id",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_distinct"),
        ),
        sa.CheckConstraint(
            "earlier_ingress_sequence > 0 "
            "AND later_ingress_sequence > earlier_ingress_sequence "
            "AND recorded_at >= earlier_source_committed_at "
            "AND recorded_at >= later_source_committed_at",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_order"),
        ),
        sa.CheckConstraint(
            "disposition IN ("
            "'exact_position_view_match_unqualified', "
            "'position_view_different', "
            "'waiting_minimum_separation')",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_disposition"),
        ),
        sa.CheckConstraint(
            "added_count BETWEEN 0 AND 512 "
            "AND removed_count BETWEEN 0 AND 512 "
            "AND changed_count BETWEEN 0 AND 512",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_differences"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 36 "
            "AND length(evidence_id) = 36 "
            "AND length(comparison_id) = 36 "
            "AND length(comparison_plan_id) = 36 "
            "AND length(expected_provider_account_id) = 36 "
            "AND length(fence_owner_id) BETWEEN 1 AND 128 "
            "AND length(fence_lease_id) BETWEEN 1 AND 64 "
            "AND length(earlier_snapshot_receipt_id) = 36 "
            "AND length(earlier_plan_id) = 36 "
            "AND length(earlier_capture_id) = 36 "
            "AND length(later_snapshot_receipt_id) = 36 "
            "AND length(later_plan_id) = 36 "
            "AND length(later_capture_id) = 36",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_ids"),
        ),
        sa.CheckConstraint(
            "(previous_receipt_sha256 IS NULL "
            "OR length(previous_receipt_sha256) = 64) "
            "AND length(comparison_plan_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(authentication_policy_sha256) = 64 "
            "AND length(comparison_policy_sha256) = 64 "
            "AND length(capture_profile_sha256) = 64 "
            "AND length(earlier_snapshot_receipt_sha256) = 64 "
            "AND length(earlier_plan_sha256) = 64 "
            "AND length(earlier_persisted_snapshot_sha256) = 64 "
            "AND length(earlier_ingress_receipt_id) = 64 "
            "AND length(earlier_ingress_receipt_sha256) = 64 "
            "AND length(earlier_view_sha256) = 64 "
            "AND length(later_snapshot_receipt_sha256) = 64 "
            "AND length(later_plan_sha256) = 64 "
            "AND length(later_persisted_snapshot_sha256) = 64 "
            "AND length(later_ingress_receipt_id) = 64 "
            "AND length(later_ingress_receipt_sha256) = 64 "
            "AND length(later_view_sha256) = 64 "
            "AND length(comparison_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_hashes"),
        ),
        sa.CheckConstraint(
            "length(observed_utc_separation_microseconds) BETWEEN 1 AND 32 "
            "AND length(added_asset_ids_payload) BETWEEN 2 AND 65536 "
            "AND length(removed_asset_ids_payload) BETWEEN 2 AND 65536 "
            "AND length(changed_asset_ids_payload) BETWEEN 2 AND 65536 "
            "AND length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f(f"ck_{_COMPARISON_TABLE}_phase4_position_view_cmp_payloads"),
        ),
    )
    op.create_index(
        "ix_phase4_position_view_cmp_account_recorded",
        _COMPARISON_TABLE,
        ["account_id", "recorded_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_position_view_cmp_sources",
        _COMPARISON_TABLE,
        ["earlier_plan_id", "later_plan_id"],
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
            name="uq_phase4_position_view_cmp_head_semantic",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_position_view_cmp_head_account",
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
            name="fk_phase4_position_view_cmp_head_tip",
        ),
        sa.CheckConstraint(
            "last_account_sequence > 0 "
            "AND length(last_receipt_id) = 36 "
            "AND length(last_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_position_view_cmp_head"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 16384",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_position_view_cmp_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_position_view_cmp_head_recorded",
        _HEAD_TABLE,
        ["last_recorded_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    guarded_tables = (_HEAD_TABLE, _COMPARISON_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE "
            + ", ".join((*guarded_tables, _SOURCE_TABLE))
            + " IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError(
            "refusing to downgrade nonempty authenticated position-view comparison history"
        )
    op.drop_index(
        "ix_phase4_position_view_cmp_head_recorded",
        table_name=_HEAD_TABLE,
    )
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_position_view_cmp_sources",
        table_name=_COMPARISON_TABLE,
    )
    op.drop_index(
        "ix_phase4_position_view_cmp_account_recorded",
        table_name=_COMPARISON_TABLE,
    )
    op.drop_table(_COMPARISON_TABLE)
    op.drop_index(_SOURCE_EXACT_INDEX, table_name=_SOURCE_TABLE)
