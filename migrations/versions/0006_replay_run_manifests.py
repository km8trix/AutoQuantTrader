"""Add sealed-success replay run manifests

Revision ID: 0006_replay_run_manifests
Revises: 0005_market_data_admission
Create Date: 2026-07-18 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_replay_run_manifests"
down_revision: str | None = "0005_market_data_admission"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    legacy_version = sa.text("'input-v1'")
    op.add_column(
        "data_objects",
        sa.Column(
            "semantic_checksum_version",
            sa.String(length=32),
            nullable=False,
            server_default=legacy_version,
        ),
    )
    op.add_column(
        "dataset_partitions",
        sa.Column(
            "semantic_checksum_version",
            sa.String(length=32),
            nullable=False,
            server_default=legacy_version,
        ),
    )
    for table_name in ("calendar_versions", "universe_versions", "corporate_action_sets"):
        op.add_column(
            table_name,
            sa.Column(
                "content_hash_version",
                sa.String(length=32),
                nullable=False,
                server_default=legacy_version,
            ),
        )

    op.create_table(
        "replay_run_manifests",
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("dataset_manifest_id", sa.String(length=64), nullable=False),
        sa.Column("dataset_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("manifest_payload", sa.Text(), nullable=False),
        sa.Column("tape_sha256", sa.String(length=64), nullable=False),
        sa.Column("replay_semantic_sha256", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_event_count", sa.Integer(), nullable=False),
        sa.Column("batch_count", sa.Integer(), nullable=False),
        sa.Column("complete_batch_count", sa.Integer(), nullable=False),
        sa.Column("skipped_batch_count", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "run_id = manifest_sha256",
            name=op.f("ck_replay_run_manifests_replay_run_manifests_content_addressed"),
        ),
        sa.CheckConstraint(
            "length(run_id) = 64 "
            "AND length(idempotency_key) = 64 "
            "AND length(dataset_manifest_id) = 64 "
            "AND length(dataset_manifest_hash) = 64 "
            "AND length(manifest_sha256) = 64 "
            "AND length(tape_sha256) = 64 "
            "AND length(replay_semantic_sha256) = 64",
            name=op.f("ck_replay_run_manifests_replay_run_manifests_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(manifest_payload) <= 65536",
            name=op.f("ck_replay_run_manifests_replay_run_manifests_payload_size"),
        ),
        sa.CheckConstraint(
            "completed_at >= started_at",
            name=op.f("ck_replay_run_manifests_replay_run_manifests_valid_time_range"),
        ),
        sa.CheckConstraint(
            "processed_event_count >= 0 "
            "AND batch_count > 0 "
            "AND complete_batch_count >= 0 "
            "AND skipped_batch_count >= 0",
            name=op.f("ck_replay_run_manifests_replay_run_manifests_valid_counts"),
        ),
        sa.CheckConstraint(
            "complete_batch_count + skipped_batch_count = batch_count",
            name=op.f("ck_replay_run_manifests_replay_run_manifests_reconciled_batch_counts"),
        ),
        sa.ForeignKeyConstraint(
            ["dataset_manifest_id"],
            ["dataset_manifests.manifest_id"],
            name=op.f("fk_replay_run_manifests_dataset_manifest_id_dataset_manifests"),
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_replay_run_manifests")),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_replay_run_manifests_idempotency_key"),
        ),
        sa.UniqueConstraint(
            "manifest_sha256",
            name=op.f("uq_replay_run_manifests_manifest_sha256"),
        ),
    )
    op.create_index(
        op.f("ix_replay_run_manifests_dataset_manifest_id"),
        "replay_run_manifests",
        ["dataset_manifest_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_replay_run_manifests_dataset_manifest_id"),
        table_name="replay_run_manifests",
    )
    op.drop_table("replay_run_manifests")
    for table_name in ("corporate_action_sets", "universe_versions", "calendar_versions"):
        op.drop_column(table_name, "content_hash_version")
    op.drop_column("dataset_partitions", "semantic_checksum_version")
    op.drop_column("data_objects", "semantic_checksum_version")
