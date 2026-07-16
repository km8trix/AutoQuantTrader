"""Add fail-closed market-data admission evidence

Revision ID: 0005_market_data_admission
Revises: 0004_point_in_time_data
Create Date: 2026-07-15 15:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_market_data_admission"
down_revision: str | None = "0004_point_in_time_data"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "market_data_admission_profiles",
        sa.Column("profile_id", sa.String(length=64), nullable=False),
        sa.Column("source_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("adapter_type", sa.String(length=64), nullable=False),
        sa.Column("identifier_authority", sa.String(length=128), nullable=False),
        sa.Column("universe_version", sa.String(length=64), nullable=False),
        sa.Column("calendar_version", sa.String(length=64), nullable=False),
        sa.Column("corporate_action_version", sa.String(length=64), nullable=False),
        sa.Column("coverage_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("coverage_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("required_symbols", sa.JSON(), nullable=False),
        sa.Column("required_checks", sa.JSON(), nullable=False),
        sa.Column("specification_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "coverage_end >= coverage_start",
            name=op.f(
                "ck_market_data_admission_profiles_market_data_admission_profiles_valid_coverage"
            ),
        ),
        sa.CheckConstraint(
            "length(profile_id) = 64 AND length(specification_digest) = 64",
            name=op.f(
                "ck_market_data_admission_profiles_market_data_admission_profiles_hash_lengths"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["calendar_version"],
            ["calendar_versions.calendar_version"],
            name=op.f("fk_market_data_admission_profiles_calendar_version_calendar_versions"),
        ),
        sa.ForeignKeyConstraint(
            ["corporate_action_version"],
            ["corporate_action_sets.corporate_action_version"],
            name=op.f(
                "fk_market_data_admission_profiles_corporate_action_version_corporate_action_sets"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["market_data_sources.source_id"],
            name=op.f("fk_market_data_admission_profiles_source_id_market_data_sources"),
        ),
        sa.ForeignKeyConstraint(
            ["universe_version"],
            ["universe_versions.universe_version"],
            name=op.f("fk_market_data_admission_profiles_universe_version_universe_versions"),
        ),
        sa.PrimaryKeyConstraint("profile_id", name=op.f("pk_market_data_admission_profiles")),
        sa.UniqueConstraint(
            "specification_digest",
            name=op.f("uq_market_data_admission_profiles_specification_digest"),
        ),
    )
    op.create_index(
        op.f("ix_market_data_admission_profiles_source_id"),
        "market_data_admission_profiles",
        ["source_id"],
        unique=False,
    )
    op.create_table(
        "market_data_admission_runs",
        sa.Column("admission_run_id", sa.String(length=64), nullable=False),
        sa.Column("profile_id", sa.String(length=64), nullable=False),
        sa.Column("source_id", sa.String(length=64), nullable=False),
        sa.Column("manifest_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("executed_by", sa.String(length=128), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("review_decision", sa.String(length=16), nullable=True),
        sa.Column("evidence_digest", sa.String(length=64), nullable=False),
        sa.Column("report_digest", sa.String(length=64), nullable=False),
        sa.Column("passed_check_count", sa.Integer(), nullable=False),
        sa.Column("failed_check_count", sa.Integer(), nullable=False),
        sa.Column("pending_check_count", sa.Integer(), nullable=False),
        sa.Column("detail", sa.String(length=512), nullable=False),
        sa.CheckConstraint(
            "length(evidence_digest) = 64 AND length(report_digest) = 64",
            name=op.f("ck_market_data_admission_runs_market_data_admission_runs_hash_lengths"),
        ),
        sa.CheckConstraint(
            "passed_check_count >= 0 AND failed_check_count >= 0 AND pending_check_count >= 0",
            name=op.f(
                "ck_market_data_admission_runs_market_data_admission_runs_non_negative_counts"
            ),
        ),
        sa.CheckConstraint(
            "(reviewed_at IS NULL AND reviewed_by IS NULL AND review_decision IS NULL) OR "
            "(reviewed_at IS NOT NULL AND reviewed_by IS NOT NULL AND review_decision IS NOT NULL)",
            name=op.f("ck_market_data_admission_runs_market_data_admission_runs_complete_review"),
        ),
        sa.CheckConstraint(
            "review_decision IS NULL OR review_decision IN ('approved', 'rejected')",
            name=op.f(
                "ck_market_data_admission_runs_market_data_admission_runs_valid_review_decision"
            ),
        ),
        sa.CheckConstraint(
            "status IN ('blocked', 'review_pending', 'admitted', 'rejected')",
            name=op.f("ck_market_data_admission_runs_market_data_admission_runs_valid_status"),
        ),
        sa.CheckConstraint(
            "status <> 'admitted' OR review_decision = 'approved'",
            name=op.f(
                "ck_market_data_admission_runs_market_data_admission_runs_reviewed_final_status"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["manifest_id"],
            ["dataset_manifests.manifest_id"],
            name=op.f("fk_market_data_admission_runs_manifest_id_dataset_manifests"),
        ),
        sa.ForeignKeyConstraint(
            ["profile_id"],
            ["market_data_admission_profiles.profile_id"],
            name=op.f("fk_market_data_admission_runs_profile_id_market_data_admission_profiles"),
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["market_data_sources.source_id"],
            name=op.f("fk_market_data_admission_runs_source_id_market_data_sources"),
        ),
        sa.PrimaryKeyConstraint("admission_run_id", name=op.f("pk_market_data_admission_runs")),
        sa.UniqueConstraint(
            "report_digest", name=op.f("uq_market_data_admission_runs_report_digest")
        ),
    )
    op.create_index(
        op.f("ix_market_data_admission_runs_profile_id"),
        "market_data_admission_runs",
        ["profile_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_market_data_admission_runs_source_id"),
        "market_data_admission_runs",
        ["source_id"],
        unique=False,
    )
    op.create_table(
        "market_data_admission_checks",
        sa.Column("admission_run_id", sa.String(length=64), nullable=False),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("evidence_digest", sa.String(length=64), nullable=True),
        sa.Column("detail", sa.String(length=512), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "evidence_digest IS NULL OR length(evidence_digest) = 64",
            name=op.f("ck_market_data_admission_checks_market_data_admission_checks_digest_length"),
        ),
        sa.CheckConstraint(
            "status <> 'passed' OR evidence_digest IS NOT NULL",
            name=op.f(
                "ck_market_data_admission_checks_market_data_admission_checks_passed_evidence"
            ),
        ),
        sa.CheckConstraint(
            "status IN ('passed', 'failed', 'pending')",
            name=op.f("ck_market_data_admission_checks_market_data_admission_checks_valid_status"),
        ),
        sa.ForeignKeyConstraint(
            ["admission_run_id"],
            ["market_data_admission_runs.admission_run_id"],
            name=op.f(
                "fk_market_data_admission_checks_admission_run_id_market_data_admission_runs"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "admission_run_id",
            "code",
            name=op.f("pk_market_data_admission_checks"),
        ),
    )


def downgrade() -> None:
    op.drop_table("market_data_admission_checks")
    op.drop_index(
        op.f("ix_market_data_admission_runs_source_id"),
        table_name="market_data_admission_runs",
    )
    op.drop_index(
        op.f("ix_market_data_admission_runs_profile_id"),
        table_name="market_data_admission_runs",
    )
    op.drop_table("market_data_admission_runs")
    op.drop_index(
        op.f("ix_market_data_admission_profiles_source_id"),
        table_name="market_data_admission_profiles",
    )
    op.drop_table("market_data_admission_profiles")
