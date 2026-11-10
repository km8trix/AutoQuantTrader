"""Add the bounded Phase 3F fixture-segment worker.

Revision ID: 0037_phase3_fixture_worker
Revises: 0036_phase6_time_anchors
Create Date: 2026-08-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0037_phase3_fixture_worker"
down_revision: str | None = "0036_phase6_time_anchors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ARTIFACTS = "phase3_fixture_segment_transcript_artifacts"
_JOBS = "phase3_fixture_segment_jobs"
_EVENTS = "phase3_fixture_segment_job_events"
_HEADS = "phase3_fixture_segment_job_heads"


def upgrade() -> None:
    op.create_table(
        _ARTIFACTS,
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("artifact_kind", sa.String(16), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("segment_kind", sa.String(16), nullable=False),
        sa.Column("segment_sha256", sa.String(64), nullable=False),
        sa.Column("source_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=True),
        sa.Column("certification_sha256", sa.String(64), nullable=False),
        sa.Column("parity_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("transcript_sha256", sa.String(64), nullable=False),
        sa.Column("step_count", sa.Integer(), nullable=False),
        sa.Column("output_count", sa.Integer(), nullable=False),
        sa.Column("transcript_payload", sa.Text(), nullable=False),
        sa.Column("transcript_payload_sha256", sa.String(64), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("artifact_sha256", name=op.f(f"pk_{_ARTIFACTS}")),
        sa.ForeignKeyConstraint(
            ["attempt_id", "family_id"],
            ["phase3_experiment_attempts.attempt_id", "phase3_experiment_attempts.family_id"],
            name="fk_phase3_fixture_artifacts_attempt_family",
        ),
        sa.UniqueConstraint("semantic_sha256", name=op.f(f"uq_{_ARTIFACTS}_semantic_sha256")),
        sa.UniqueConstraint(
            "attempt_id", "artifact_kind", name="uq_phase3_fixture_artifacts_attempt_kind"
        ),
        sa.CheckConstraint(
            "artifact_kind IN ('feature', 'target') "
            "AND segment_kind IN ('train', 'validation', 'test') "
            "AND ((artifact_kind = 'feature' AND configuration_sha256 IS NULL) "
            "OR (artifact_kind = 'target' AND configuration_sha256 IS NOT NULL))",
            name="phase3_fixture_artifact_kind_shape",
        ),
        sa.CheckConstraint(
            "step_count BETWEEN 1 AND 100000 AND output_count BETWEEN 0 AND 5000000",
            name="phase3_fixture_artifact_count_bounds",
        ),
        sa.CheckConstraint(
            "length(artifact_sha256) = 64 AND length(family_id) = 64 "
            "AND length(attempt_id) = 64 AND length(segment_sha256) = 64 "
            "AND length(source_evidence_sha256) = 64 "
            "AND (configuration_sha256 IS NULL OR length(configuration_sha256) = 64) "
            "AND length(certification_sha256) = 64 AND length(parity_receipt_sha256) = 64 "
            "AND length(transcript_sha256) = 64 "
            "AND length(transcript_payload_sha256) = 64 AND length(semantic_sha256) = 64",
            name="phase3_fixture_artifact_hash_lengths",
        ),
        sa.CheckConstraint(
            "length(transcript_payload) BETWEEN 2 AND 8388608",
            name="phase3_fixture_artifact_payload_bound",
        ),
    )
    op.create_index(
        "ix_phase3_fixture_artifacts_family_attempt",
        _ARTIFACTS,
        ["family_id", "attempt_id"],
        unique=False,
    )

    op.create_table(
        _JOBS,
        sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("configuration_validation_sha256", sa.String(64), nullable=False),
        sa.Column("segment_kind", sa.String(16), nullable=False),
        sa.Column("segment_sha256", sa.String(64), nullable=False),
        sa.Column("source_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("queued_governance_event_sha256", sa.String(64), nullable=False),
        sa.Column("feature_certification_sha256", sa.String(64), nullable=False),
        sa.Column("feature_transcript_artifact_sha256", sa.String(64), nullable=False),
        sa.Column("governed_actor_id", sa.String(96), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requested_by", sa.String(128), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("job_id", name=op.f(f"pk_{_JOBS}")),
        sa.ForeignKeyConstraint(
            ["attempt_id", "family_id"],
            ["phase3_experiment_attempts.attempt_id", "phase3_experiment_attempts.family_id"],
            name="fk_phase3_fixture_jobs_attempt_family",
        ),
        sa.ForeignKeyConstraint(
            ["queued_governance_event_sha256"],
            ["phase3_experiment_attempt_events.event_sha256"],
            name="fk_phase3_fixture_jobs_queued_event",
        ),
        sa.ForeignKeyConstraint(
            ["feature_transcript_artifact_sha256"],
            [f"{_ARTIFACTS}.artifact_sha256"],
            name="fk_phase3_fixture_jobs_feature_artifact",
        ),
        sa.UniqueConstraint("attempt_id", name=op.f(f"uq_{_JOBS}_attempt_id")),
        sa.UniqueConstraint(
            "queued_governance_event_sha256",
            name=op.f(f"uq_{_JOBS}_queued_governance_event_sha256"),
        ),
        sa.UniqueConstraint(
            "feature_transcript_artifact_sha256",
            name=op.f(f"uq_{_JOBS}_feature_transcript_artifact_sha256"),
        ),
        sa.UniqueConstraint("governed_actor_id", name=op.f(f"uq_{_JOBS}_governed_actor_id")),
        sa.UniqueConstraint("semantic_sha256", name=op.f(f"uq_{_JOBS}_semantic_sha256")),
        sa.CheckConstraint(
            "segment_kind IN ('train', 'validation', 'test') "
            "AND length(requested_by) BETWEEN 1 AND 128 "
            "AND length(governed_actor_id) BETWEEN 1 AND 96",
            name="phase3_fixture_job_text_shape",
        ),
        sa.CheckConstraint(
            "length(job_id) = 64 AND length(family_id) = 64 AND length(attempt_id) = 64 "
            "AND length(configuration_sha256) = 64 "
            "AND length(configuration_validation_sha256) = 64 "
            "AND length(segment_sha256) = 64 AND length(source_evidence_sha256) = 64 "
            "AND length(queued_governance_event_sha256) = 64 "
            "AND length(feature_certification_sha256) = 64 "
            "AND length(feature_transcript_artifact_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name="phase3_fixture_job_hash_lengths",
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144",
            name="phase3_fixture_job_payload_bound",
        ),
    )
    op.create_index(
        "ix_phase3_fixture_jobs_requested",
        _JOBS,
        ["requested_at", "job_id"],
        unique=False,
    )

    op.create_table(
        _EVENTS,
        sa.Column("event_sha256", sa.String(64), nullable=False),
        sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("previous_event_sha256", sa.String(64), nullable=True),
        sa.Column("worker_id", sa.String(128), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("governance_event_sha256", sa.String(64), nullable=False),
        sa.Column("feature_artifact_sha256", sa.String(64), nullable=False),
        sa.Column("target_artifact_sha256", sa.String(64), nullable=True),
        sa.Column("completion_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("terminal_reason_code", sa.String(64), nullable=True),
        sa.Column("terminal_reason_sha256", sa.String(64), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("event_sha256", name=op.f(f"pk_{_EVENTS}")),
        sa.ForeignKeyConstraint(
            ["job_id"], [f"{_JOBS}.job_id"], name="fk_phase3_fixture_events_job"
        ),
        sa.ForeignKeyConstraint(
            ["previous_event_sha256"],
            [f"{_EVENTS}.event_sha256"],
            name="fk_phase3_fixture_events_predecessor",
        ),
        sa.ForeignKeyConstraint(
            ["governance_event_sha256"],
            ["phase3_experiment_attempt_events.event_sha256"],
            name="fk_phase3_fixture_events_governance_event",
        ),
        sa.ForeignKeyConstraint(
            ["feature_artifact_sha256"],
            [f"{_ARTIFACTS}.artifact_sha256"],
            name="fk_phase3_fixture_events_feature_artifact",
        ),
        sa.ForeignKeyConstraint(
            ["target_artifact_sha256"],
            [f"{_ARTIFACTS}.artifact_sha256"],
            name="fk_phase3_fixture_events_target_artifact",
        ),
        sa.UniqueConstraint(
            "job_id", "sequence_number", name="uq_phase3_fixture_events_job_sequence"
        ),
        sa.UniqueConstraint("semantic_sha256", name=op.f(f"uq_{_EVENTS}_semantic_sha256")),
        sa.CheckConstraint(
            "(sequence_number = 0 AND previous_event_sha256 IS NULL) "
            "OR (sequence_number > 0 AND previous_event_sha256 IS NOT NULL)",
            name="phase3_fixture_event_predecessor_shape",
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed') "
            "AND attempt_number >= 0 AND length(actor_id) BETWEEN 1 AND 128 "
            "AND (worker_id IS NULL OR length(worker_id) BETWEEN 1 AND 128)",
            name="phase3_fixture_event_status_shape",
        ),
        sa.CheckConstraint(
            "(status = 'queued' AND sequence_number = 0 AND attempt_number = 0 "
            "AND worker_id IS NULL AND claim_expires_at IS NULL "
            "AND target_artifact_sha256 IS NULL AND completion_receipt_sha256 IS NULL "
            "AND terminal_reason_code IS NULL AND terminal_reason_sha256 IS NULL) "
            "OR (status = 'running' AND attempt_number > 0 AND worker_id IS NOT NULL "
            "AND claim_expires_at IS NOT NULL AND target_artifact_sha256 IS NULL "
            "AND completion_receipt_sha256 IS NULL AND terminal_reason_code IS NULL "
            "AND terminal_reason_sha256 IS NULL) "
            "OR (status = 'completed' AND attempt_number > 0 AND worker_id IS NOT NULL "
            "AND claim_expires_at IS NULL AND target_artifact_sha256 IS NOT NULL "
            "AND completion_receipt_sha256 IS NOT NULL AND terminal_reason_code IS NULL "
            "AND terminal_reason_sha256 IS NULL) "
            "OR (status = 'failed' AND attempt_number > 0 AND worker_id IS NOT NULL "
            "AND claim_expires_at IS NULL AND target_artifact_sha256 IS NULL "
            "AND completion_receipt_sha256 IS NULL AND terminal_reason_code IS NOT NULL "
            "AND terminal_reason_sha256 IS NOT NULL)",
            name="phase3_fixture_event_evidence_shape",
        ),
        sa.CheckConstraint(
            "length(event_sha256) = 64 AND length(job_id) = 64 "
            "AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
            "AND length(governance_event_sha256) = 64 "
            "AND length(feature_artifact_sha256) = 64 "
            "AND (target_artifact_sha256 IS NULL OR length(target_artifact_sha256) = 64) "
            "AND (completion_receipt_sha256 IS NULL OR length(completion_receipt_sha256) = 64) "
            "AND (terminal_reason_sha256 IS NULL OR length(terminal_reason_sha256) = 64) "
            "AND length(semantic_sha256) = 64",
            name="phase3_fixture_event_hash_lengths",
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144",
            name="phase3_fixture_event_payload_bound",
        ),
    )
    op.create_index(
        "ix_phase3_fixture_events_job_occurred",
        _EVENTS,
        ["job_id", "occurred_at"],
        unique=False,
    )

    op.create_table(
        _HEADS,
        sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("latest_sequence_number", sa.Integer(), nullable=False),
        sa.Column("latest_event_sha256", sa.String(64), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(128), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("job_id", name=op.f(f"pk_{_HEADS}")),
        sa.ForeignKeyConstraint(
            ["job_id"], [f"{_JOBS}.job_id"], name="fk_phase3_fixture_heads_job"
        ),
        sa.ForeignKeyConstraint(
            ["latest_event_sha256"],
            [f"{_EVENTS}.event_sha256"],
            name="fk_phase3_fixture_heads_latest_event",
        ),
        sa.UniqueConstraint("latest_event_sha256", name=op.f(f"uq_{_HEADS}_latest_event_sha256")),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed') "
            "AND latest_sequence_number >= 0 AND attempt_number >= 0 "
            "AND ((status = 'running' AND worker_id IS NOT NULL "
            "AND claim_expires_at IS NOT NULL) OR (status <> 'running' "
            "AND worker_id IS NULL AND claim_expires_at IS NULL))",
            name="phase3_fixture_head_shape",
        ),
        sa.CheckConstraint(
            "length(job_id) = 64 AND length(latest_event_sha256) = 64 "
            "AND (worker_id IS NULL OR length(worker_id) BETWEEN 1 AND 128)",
            name="phase3_fixture_head_identity",
        ),
    )
    op.create_index(
        "ix_phase3_fixture_heads_claimable",
        _HEADS,
        ["status", "claim_expires_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    guarded_tables = (_HEADS, _EVENTS, _JOBS, _ARTIFACTS)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE " + ", ".join(guarded_tables) + " IN ACCESS EXCLUSIVE MODE"
        )
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty fixture-segment history")
    op.drop_index("ix_phase3_fixture_heads_claimable", table_name=_HEADS)
    op.drop_table(_HEADS)
    op.drop_index("ix_phase3_fixture_events_job_occurred", table_name=_EVENTS)
    op.drop_table(_EVENTS)
    op.drop_index("ix_phase3_fixture_jobs_requested", table_name=_JOBS)
    op.drop_table(_JOBS)
    op.drop_index("ix_phase3_fixture_artifacts_family_attempt", table_name=_ARTIFACTS)
    op.drop_table(_ARTIFACTS)
