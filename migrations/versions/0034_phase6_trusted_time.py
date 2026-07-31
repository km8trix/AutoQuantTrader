"""Add durable provider-neutral trusted-time evidence.

Revision ID: 0034_phase6_trusted_time
Revises: 0033_phase4_activity_comparison
Create Date: 2026-07-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034_phase6_trusted_time"
down_revision: str | None = "0033_phase4_activity_comparison"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EPOCH_TABLE = "phase6_trusted_time_epoch_registrations"
_EVALUATION_TABLE = "phase6_trusted_time_probe_evaluations"
_HEAD_TABLE = "phase6_trusted_time_host_heads"
_POLICY_SHA256 = "e2ed2efe97b6a13764fba36976916001eec074773f1f2fcf37f759c80e474944"


def upgrade() -> None:
    op.create_table(
        _EPOCH_TABLE,
        sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("epoch_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_monitor_epoch_id", sa.String(36), nullable=True),
        sa.Column("previous_epoch_sha256", sa.String(64), nullable=True),
        sa.Column("previous_host_head_sha256", sa.String(64), nullable=True),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("source_authority_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("registered_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "monitor_epoch_id",
            name=op.f(f"pk_{_EPOCH_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_EPOCH_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "host_id",
            "epoch_sequence",
            name="uq_phase6_trusted_time_epoch_host_sequence",
        ),
        sa.UniqueConstraint(
            "host_id",
            "monitor_epoch_id",
            "semantic_sha256",
            name="uq_phase6_trusted_time_epoch_exact",
        ),
        sa.UniqueConstraint(
            "host_id",
            "epoch_sequence",
            "monitor_epoch_id",
            "semantic_sha256",
            name="uq_phase6_trusted_time_epoch_tip",
        ),
        sa.ForeignKeyConstraint(
            [
                "host_id",
                "previous_monitor_epoch_id",
                "previous_epoch_sha256",
            ],
            [
                f"{_EPOCH_TABLE}.host_id",
                f"{_EPOCH_TABLE}.monitor_epoch_id",
                f"{_EPOCH_TABLE}.semantic_sha256",
            ],
            name="fk_phase6_trusted_time_epoch_predecessor",
        ),
        sa.CheckConstraint(
            "(epoch_sequence = 1 "
            "AND previous_monitor_epoch_id IS NULL "
            "AND previous_epoch_sha256 IS NULL "
            "AND previous_host_head_sha256 IS NULL) "
            "OR (epoch_sequence > 1 "
            "AND previous_monitor_epoch_id IS NOT NULL "
            "AND previous_epoch_sha256 IS NOT NULL "
            "AND previous_host_head_sha256 IS NOT NULL)",
            name="phase6_trusted_time_epoch_predecessor_shape",
        ),
        sa.CheckConstraint(
            "length(monitor_epoch_id) = 36 "
            "AND length(host_id) BETWEEN 1 AND 128 "
            "AND length(source_id) BETWEEN 1 AND 128 "
            "AND length(source_authority_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            f"AND policy_sha256 = '{_POLICY_SHA256}' "
            "AND length(semantic_sha256) = 64 "
            "AND (previous_monitor_epoch_id IS NULL "
            "OR length(previous_monitor_epoch_id) = 36) "
            "AND (previous_epoch_sha256 IS NULL "
            "OR length(previous_epoch_sha256) = 64) "
            "AND (previous_host_head_sha256 IS NULL "
            "OR length(previous_host_head_sha256) = 64)",
            name="phase6_trusted_time_epoch_identity",
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name="phase6_trusted_time_epoch_payload",
        ),
    )
    op.create_index(
        "ix_phase6_trusted_time_epoch_host_registered",
        _EPOCH_TABLE,
        ["host_id", "registered_at_utc"],
        unique=False,
    )

    op.create_table(
        _EVALUATION_TABLE,
        sa.Column("evaluation_id", sa.String(36), nullable=False),
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
        sa.Column("epoch_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_evaluation_id", sa.String(36), nullable=True),
        sa.Column("previous_evaluation_sha256", sa.String(64), nullable=True),
        sa.Column("probe_status", sa.String(32), nullable=False),
        sa.Column("sample_sequence", sa.BigInteger(), nullable=True),
        sa.Column("source_evidence_sha256", sa.String(64), nullable=True),
        sa.Column("probe_started_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("probe_completed_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trusted_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("probe_started_monotonic_ns", sa.BigInteger(), nullable=True),
        sa.Column("probe_completed_monotonic_ns", sa.BigInteger(), nullable=True),
        sa.Column("sample_canonical_payload", sa.Text(), nullable=True),
        sa.Column("sample_sha256", sa.String(64), nullable=True),
        sa.Column("previous_state_sha256", sa.String(64), nullable=True),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("latest_sample_sha256", sa.String(64), nullable=True),
        sa.Column("sample_health", sa.String(16), nullable=False),
        sa.Column("health", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(32), nullable=False),
        sa.Column("hard_failure_latched", sa.Boolean(), nullable=False),
        sa.Column("healthy_since_monotonic_ns", sa.BigInteger(), nullable=True),
        sa.Column("clock_recovery_qualified", sa.Boolean(), nullable=False),
        sa.Column("evaluated_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluated_at_monotonic_ns", sa.BigInteger(), nullable=False),
        sa.Column("state_canonical_payload", sa.Text(), nullable=False),
        sa.Column("state_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "evaluation_id",
            name=op.f(f"pk_{_EVALUATION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_EVALUATION_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "host_id",
            "monitor_epoch_id",
            "evaluation_sequence",
            name="uq_phase6_trusted_time_eval_epoch_sequence",
        ),
        sa.UniqueConstraint(
            "host_id",
            "monitor_epoch_id",
            "evaluation_id",
            "semantic_sha256",
            "state_sha256",
            name="uq_phase6_trusted_time_eval_exact",
        ),
        sa.UniqueConstraint(
            "host_id",
            "monitor_epoch_id",
            "evaluation_sequence",
            "evaluation_id",
            "semantic_sha256",
            "state_sha256",
            "health",
            "reason",
            "hard_failure_latched",
            "clock_recovery_qualified",
            "evaluated_at_utc",
            "evaluated_at_monotonic_ns",
            name="uq_phase6_trusted_time_eval_tip",
        ),
        sa.ForeignKeyConstraint(
            ["host_id", "monitor_epoch_id", "epoch_sha256"],
            [
                f"{_EPOCH_TABLE}.host_id",
                f"{_EPOCH_TABLE}.monitor_epoch_id",
                f"{_EPOCH_TABLE}.semantic_sha256",
            ],
            name="fk_phase6_trusted_time_eval_epoch",
        ),
        sa.ForeignKeyConstraint(
            [
                "host_id",
                "monitor_epoch_id",
                "previous_evaluation_id",
                "previous_evaluation_sha256",
                "previous_state_sha256",
            ],
            [
                f"{_EVALUATION_TABLE}.host_id",
                f"{_EVALUATION_TABLE}.monitor_epoch_id",
                f"{_EVALUATION_TABLE}.evaluation_id",
                f"{_EVALUATION_TABLE}.semantic_sha256",
                f"{_EVALUATION_TABLE}.state_sha256",
            ],
            name="fk_phase6_trusted_time_eval_predecessor",
        ),
        sa.CheckConstraint(
            "(evaluation_sequence = 1 "
            "AND previous_evaluation_id IS NULL "
            "AND previous_evaluation_sha256 IS NULL "
            "AND previous_state_sha256 IS NULL) "
            "OR (evaluation_sequence > 1 "
            "AND previous_evaluation_id IS NOT NULL "
            "AND previous_evaluation_sha256 IS NOT NULL "
            "AND previous_state_sha256 IS NOT NULL)",
            name="phase6_trusted_time_eval_predecessor_shape",
        ),
        sa.CheckConstraint(
            "probe_status IN ("
            "'recorded', "
            "'source_unavailable', "
            "'source_identity_mismatch', "
            "'invalid_reading')",
            name="phase6_trusted_time_eval_probe_status",
        ),
        sa.CheckConstraint(
            "(probe_status = 'recorded' "
            "AND sample_sequence IS NOT NULL "
            "AND source_evidence_sha256 IS NOT NULL "
            "AND probe_started_at_utc IS NOT NULL "
            "AND probe_completed_at_utc IS NOT NULL "
            "AND trusted_at_utc IS NOT NULL "
            "AND probe_started_monotonic_ns IS NOT NULL "
            "AND probe_completed_monotonic_ns IS NOT NULL "
            "AND sample_canonical_payload IS NOT NULL "
            "AND sample_sha256 IS NOT NULL) "
            "OR (probe_status <> 'recorded' "
            "AND sample_sequence IS NULL "
            "AND source_evidence_sha256 IS NULL "
            "AND probe_started_at_utc IS NULL "
            "AND probe_completed_at_utc IS NULL "
            "AND trusted_at_utc IS NULL "
            "AND probe_started_monotonic_ns IS NULL "
            "AND probe_completed_monotonic_ns IS NULL "
            "AND sample_canonical_payload IS NULL "
            "AND sample_sha256 IS NULL)",
            name="phase6_trusted_time_eval_sample_shape",
        ),
        sa.CheckConstraint(
            "(sample_sequence IS NULL OR sample_sequence > 0) "
            "AND (probe_started_monotonic_ns IS NULL "
            "OR probe_started_monotonic_ns >= 0) "
            "AND (probe_completed_monotonic_ns IS NULL "
            "OR probe_completed_monotonic_ns >= probe_started_monotonic_ns) "
            "AND (probe_started_at_utc IS NULL "
            "OR probe_started_at_utc <= probe_completed_at_utc) "
            "AND (probe_completed_at_utc IS NULL "
            "OR probe_completed_at_utc <= evaluated_at_utc) "
            "AND (probe_completed_monotonic_ns IS NULL "
            "OR probe_completed_monotonic_ns <= evaluated_at_monotonic_ns)",
            name="phase6_trusted_time_eval_sample_order",
        ),
        sa.CheckConstraint(
            "sample_health IN ('healthy', 'warning', 'blocked') "
            "AND health IN ('healthy', 'warning', 'blocked') "
            "AND reason IN ("
            "'within_limit', "
            "'startup_no_sample', "
            "'startup_qualifying', "
            "'source_unavailable', "
            "'warning_offset', "
            "'hard_offset', "
            "'hard_offset_latched', "
            "'sample_stale', "
            "'identity_changed', "
            "'sequence_discontinuity', "
            "'cadence_gap', "
            "'utc_regression', "
            "'monotonic_regression')",
            name="phase6_trusted_time_eval_outcome",
        ),
        sa.CheckConstraint(
            "evaluation_sequence > 0 "
            "AND evaluated_at_monotonic_ns >= 0 "
            "AND (healthy_since_monotonic_ns IS NULL "
            "OR (healthy_since_monotonic_ns >= 0 "
            "AND healthy_since_monotonic_ns <= evaluated_at_monotonic_ns)) "
            "AND (NOT clock_recovery_qualified "
            "OR healthy_since_monotonic_ns IS NOT NULL)",
            name="phase6_trusted_time_eval_state_bounds",
        ),
        sa.CheckConstraint(
            "length(evaluation_id) = 36 "
            "AND length(host_id) BETWEEN 1 AND 128 "
            "AND length(monitor_epoch_id) = 36 "
            "AND length(epoch_sha256) = 64 "
            "AND (previous_evaluation_id IS NULL "
            "OR length(previous_evaluation_id) = 36) "
            "AND (previous_evaluation_sha256 IS NULL "
            "OR length(previous_evaluation_sha256) = 64) "
            "AND (source_evidence_sha256 IS NULL "
            "OR length(source_evidence_sha256) = 64) "
            "AND (sample_sha256 IS NULL OR length(sample_sha256) = 64) "
            "AND (previous_state_sha256 IS NULL "
            "OR length(previous_state_sha256) = 64) "
            "AND length(policy_sha256) = 64 "
            f"AND policy_sha256 = '{_POLICY_SHA256}' "
            "AND (latest_sample_sha256 IS NULL "
            "OR length(latest_sample_sha256) = 64) "
            "AND length(state_sha256) = 64 "
            "AND length(evaluation_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name="phase6_trusted_time_eval_identity",
        ),
        sa.CheckConstraint(
            "(sample_canonical_payload IS NULL "
            "OR length(sample_canonical_payload) BETWEEN 2 AND 65536) "
            "AND length(state_canonical_payload) BETWEEN 2 AND 65536 "
            "AND length(canonical_payload) BETWEEN 2 AND 262144",
            name="phase6_trusted_time_eval_payload",
        ),
    )
    op.create_index(
        "ix_phase6_trusted_time_eval_host_time",
        _EVALUATION_TABLE,
        ["host_id", "evaluated_at_utc"],
        unique=False,
    )

    op.create_table(
        _HEAD_TABLE,
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("epoch_sequence", sa.BigInteger(), nullable=False),
        sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
        sa.Column("epoch_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_sequence", sa.BigInteger(), nullable=False),
        sa.Column("evaluation_id", sa.String(36), nullable=True),
        sa.Column("evaluation_record_sha256", sa.String(64), nullable=True),
        sa.Column("state_sha256", sa.String(64), nullable=True),
        sa.Column("health", sa.String(16), nullable=True),
        sa.Column("reason", sa.String(32), nullable=True),
        sa.Column("hard_failure_latched", sa.Boolean(), nullable=True),
        sa.Column("clock_recovery_qualified", sa.Boolean(), nullable=True),
        sa.Column("evaluated_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_at_monotonic_ns", sa.BigInteger(), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "host_id",
            name=op.f(f"pk_{_HEAD_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_HEAD_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            [
                "host_id",
                "epoch_sequence",
                "monitor_epoch_id",
                "epoch_sha256",
            ],
            [
                f"{_EPOCH_TABLE}.host_id",
                f"{_EPOCH_TABLE}.epoch_sequence",
                f"{_EPOCH_TABLE}.monitor_epoch_id",
                f"{_EPOCH_TABLE}.semantic_sha256",
            ],
            name="fk_phase6_trusted_time_head_epoch",
        ),
        sa.ForeignKeyConstraint(
            [
                "host_id",
                "monitor_epoch_id",
                "evaluation_sequence",
                "evaluation_id",
                "evaluation_record_sha256",
                "state_sha256",
                "health",
                "reason",
                "hard_failure_latched",
                "clock_recovery_qualified",
                "evaluated_at_utc",
                "evaluated_at_monotonic_ns",
            ],
            [
                f"{_EVALUATION_TABLE}.host_id",
                f"{_EVALUATION_TABLE}.monitor_epoch_id",
                f"{_EVALUATION_TABLE}.evaluation_sequence",
                f"{_EVALUATION_TABLE}.evaluation_id",
                f"{_EVALUATION_TABLE}.semantic_sha256",
                f"{_EVALUATION_TABLE}.state_sha256",
                f"{_EVALUATION_TABLE}.health",
                f"{_EVALUATION_TABLE}.reason",
                f"{_EVALUATION_TABLE}.hard_failure_latched",
                f"{_EVALUATION_TABLE}.clock_recovery_qualified",
                f"{_EVALUATION_TABLE}.evaluated_at_utc",
                f"{_EVALUATION_TABLE}.evaluated_at_monotonic_ns",
            ],
            name="fk_phase6_trusted_time_head_tip",
        ),
        sa.CheckConstraint(
            "(evaluation_sequence = 0 "
            "AND evaluation_id IS NULL "
            "AND evaluation_record_sha256 IS NULL "
            "AND state_sha256 IS NULL "
            "AND health IS NULL "
            "AND reason IS NULL "
            "AND hard_failure_latched IS NULL "
            "AND clock_recovery_qualified IS NULL "
            "AND evaluated_at_utc IS NULL "
            "AND evaluated_at_monotonic_ns IS NULL) "
            "OR (evaluation_sequence > 0 "
            "AND evaluation_id IS NOT NULL "
            "AND evaluation_record_sha256 IS NOT NULL "
            "AND state_sha256 IS NOT NULL "
            "AND health IS NOT NULL "
            "AND reason IS NOT NULL "
            "AND hard_failure_latched IS NOT NULL "
            "AND clock_recovery_qualified IS NOT NULL "
            "AND evaluated_at_utc IS NOT NULL "
            "AND evaluated_at_monotonic_ns IS NOT NULL)",
            name="phase6_trusted_time_head_evaluation_shape",
        ),
        sa.CheckConstraint(
            "epoch_sequence > 0 "
            "AND evaluation_sequence >= 0 "
            "AND (evaluated_at_monotonic_ns IS NULL "
            "OR evaluated_at_monotonic_ns >= 0) "
            "AND (health IS NULL OR health IN ('healthy', 'warning', 'blocked')) "
            "AND (reason IS NULL OR reason IN ("
            "'within_limit', "
            "'startup_no_sample', "
            "'startup_qualifying', "
            "'source_unavailable', "
            "'warning_offset', "
            "'hard_offset', "
            "'hard_offset_latched', "
            "'sample_stale', "
            "'identity_changed', "
            "'sequence_discontinuity', "
            "'cadence_gap', "
            "'utc_regression', "
            "'monotonic_regression'))",
            name="phase6_trusted_time_head_state",
        ),
        sa.CheckConstraint(
            "length(host_id) BETWEEN 1 AND 128 "
            "AND length(monitor_epoch_id) = 36 "
            "AND length(epoch_sha256) = 64 "
            "AND (evaluation_id IS NULL OR length(evaluation_id) = 36) "
            "AND (evaluation_record_sha256 IS NULL "
            "OR length(evaluation_record_sha256) = 64) "
            "AND (state_sha256 IS NULL OR length(state_sha256) = 64) "
            "AND length(semantic_sha256) = 64",
            name="phase6_trusted_time_head_identity",
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name="phase6_trusted_time_head_payload",
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    guarded_tables = (_HEAD_TABLE, _EVALUATION_TABLE, _EPOCH_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE " + ", ".join(guarded_tables) + " IN ACCESS EXCLUSIVE MODE"
        )
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty trusted-time history")
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase6_trusted_time_eval_host_time",
        table_name=_EVALUATION_TABLE,
    )
    op.drop_table(_EVALUATION_TABLE)
    op.drop_index(
        "ix_phase6_trusted_time_epoch_host_registered",
        table_name=_EPOCH_TABLE,
    )
    op.drop_table(_EPOCH_TABLE)
