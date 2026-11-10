"""Add immutable external trusted-time head anchor evidence.

Revision ID: 0036_phase6_time_anchors
Revises: 0035_phase6_time_uncertainty
Create Date: 2026-08-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036_phase6_time_anchors"
down_revision: str | None = "0035_phase6_time_uncertainty"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INTENT_TABLE = "phase6_trusted_time_head_anchor_intents"
_RECEIPT_TABLE = "phase6_trusted_time_head_anchor_receipts"
_EPOCH_TABLE = "phase6_trusted_time_epoch_registrations"
_EVALUATION_TABLE = "phase6_trusted_time_probe_evaluations"
_POLICY_SHA256 = "64b826c9300e02a5f1543dfb5e1d7684e32317777fb12ab96b95da834f3f697c"


def upgrade() -> None:
    # This migration is deliberately additive. Existing trusted-time history is
    # not projected into an external anchor: enrollment must be an explicit,
    # authenticated runtime act after the schema is present.
    op.create_table(
        _INTENT_TABLE,
        sa.Column("anchor_intent_id", sa.String(36), nullable=False),
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("anchor_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_anchor_sha256", sa.String(64), nullable=True),
        sa.Column(
            "previous_anchored_host_head_sha256",
            sa.String(64),
            nullable=True,
        ),
        sa.Column("checkpoint_reason", sa.String(32), nullable=False),
        sa.Column("checkpoint_interval_seconds", sa.BigInteger(), nullable=False),
        sa.Column("anchor_authority_sha256", sa.String(64), nullable=False),
        sa.Column("deployment_identity_sha256", sa.String(64), nullable=False),
        sa.Column("runtime_database_identity_sha256", sa.String(64), nullable=False),
        sa.Column("anchor_project_identity_sha256", sa.String(64), nullable=False),
        sa.Column("anchor_project_ref", sa.String(20), nullable=False),
        sa.Column("bucket_name", sa.String(128), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("signing_key_id", sa.String(128), nullable=False),
        sa.Column("signing_public_key_sha256", sa.String(64), nullable=False),
        sa.Column("head_authenticated_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("source_authority_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("persistence_contract_version", sa.String(64), nullable=False),
        sa.Column("epoch_sequence", sa.BigInteger(), nullable=False),
        sa.Column("monitor_epoch_id", sa.String(36), nullable=False),
        sa.Column("epoch_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_sequence", sa.BigInteger(), nullable=False),
        sa.Column("evaluation_id", sa.String(36), nullable=True),
        sa.Column("evaluation_record_sha256", sa.String(64), nullable=True),
        sa.Column("state_sha256", sa.String(64), nullable=True),
        sa.Column("probe_status", sa.String(32), nullable=True),
        sa.Column("health", sa.String(16), nullable=True),
        sa.Column("reason", sa.String(32), nullable=True),
        sa.Column("hard_failure_latched", sa.Boolean(), nullable=True),
        sa.Column("clock_recovery_qualified", sa.Boolean(), nullable=True),
        sa.Column("evaluated_at_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evaluated_at_monotonic_ns", sa.BigInteger(), nullable=True),
        sa.Column("local_previous_host_head_sha256", sa.String(64), nullable=True),
        sa.Column("current_host_head_sha256", sa.String(64), nullable=False),
        sa.Column("host_identity_sha256", sa.String(64), nullable=False),
        sa.Column("object_name", sa.String(512), nullable=False),
        sa.Column("signed_envelope_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("signed_envelope_text", sa.Text(), nullable=False),
        sa.Column("signed_envelope_sha256", sa.String(64), nullable=False),
        sa.Column("created_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "anchor_intent_id",
            name=op.f(f"pk_{_INTENT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name="uq_phase6_anchor_intent_semantic",
        ),
        sa.UniqueConstraint(
            "signed_envelope_sha256",
            name="uq_phase6_anchor_intent_envelope",
        ),
        sa.UniqueConstraint(
            "host_id",
            "anchor_sequence",
            name="uq_phase6_anchor_intent_host_sequence",
        ),
        sa.UniqueConstraint(
            "host_id",
            "current_host_head_sha256",
            name="uq_phase6_anchor_intent_host_head",
        ),
        sa.UniqueConstraint(
            "host_id",
            "signed_envelope_sha256",
            "current_host_head_sha256",
            name="uq_phase6_anchor_intent_predecessor_target",
        ),
        sa.UniqueConstraint(
            "anchor_project_identity_sha256",
            "anchor_project_ref",
            "bucket_name",
            "object_name",
            name="uq_phase6_anchor_intent_object",
        ),
        sa.UniqueConstraint(
            "anchor_intent_id",
            "semantic_sha256",
            "signed_envelope_sha256",
            "deployment_identity_sha256",
            "runtime_database_identity_sha256",
            "anchor_project_identity_sha256",
            "anchor_project_ref",
            "bucket_name",
            "principal_id",
            "object_name",
            name="uq_phase6_anchor_intent_receipt_binding",
        ),
        sa.ForeignKeyConstraint(
            [
                "host_id",
                "previous_anchor_sha256",
                "previous_anchored_host_head_sha256",
            ],
            [
                f"{_INTENT_TABLE}.host_id",
                f"{_INTENT_TABLE}.signed_envelope_sha256",
                f"{_INTENT_TABLE}.current_host_head_sha256",
            ],
            name="fk_phase6_anchor_intent_predecessor",
        ),
        sa.ForeignKeyConstraint(
            ["host_id", "epoch_sequence", "monitor_epoch_id", "epoch_sha256"],
            [
                f"{_EPOCH_TABLE}.host_id",
                f"{_EPOCH_TABLE}.epoch_sequence",
                f"{_EPOCH_TABLE}.monitor_epoch_id",
                f"{_EPOCH_TABLE}.semantic_sha256",
            ],
            name="fk_phase6_anchor_intent_epoch",
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
            name="fk_phase6_anchor_intent_evaluation",
        ),
        sa.CheckConstraint(
            "(anchor_sequence = 1 "
            "AND previous_anchor_sha256 IS NULL "
            "AND previous_anchored_host_head_sha256 IS NULL "
            "AND checkpoint_reason = 'enrollment') "
            "OR (anchor_sequence > 1 "
            "AND previous_anchor_sha256 IS NOT NULL "
            "AND previous_anchored_host_head_sha256 IS NOT NULL "
            "AND checkpoint_reason <> 'enrollment')",
            name="phase6_anchor_intent_predecessor_shape",
        ),
        sa.CheckConstraint(
            "checkpoint_reason IN ("
            "'enrollment', "
            "'epoch_rotation', "
            "'periodic', "
            "'hard_failure', "
            "'health_transition', "
            "'recovery_transition', "
            "'clean_stop', "
            "'on_demand') "
            "AND checkpoint_interval_seconds = 300",
            name="phase6_anchor_intent_checkpoint_policy",
        ),
        sa.CheckConstraint(
            "(evaluation_sequence = 0 "
            "AND evaluation_id IS NULL "
            "AND evaluation_record_sha256 IS NULL "
            "AND state_sha256 IS NULL "
            "AND probe_status IS NULL "
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
            "AND probe_status IS NOT NULL "
            "AND health IS NOT NULL "
            "AND reason IS NOT NULL "
            "AND hard_failure_latched IS NOT NULL "
            "AND clock_recovery_qualified IS NOT NULL "
            "AND evaluated_at_utc IS NOT NULL "
            "AND evaluated_at_monotonic_ns IS NOT NULL)",
            name="phase6_anchor_intent_evaluation_shape",
        ),
        sa.CheckConstraint(
            "((epoch_sequence = 1 AND evaluation_sequence = 0) "
            "AND local_previous_host_head_sha256 IS NULL) "
            "OR ((epoch_sequence > 1 OR evaluation_sequence > 0) "
            "AND local_previous_host_head_sha256 IS NOT NULL)",
            name="phase6_anchor_intent_local_head_shape",
        ),
        sa.CheckConstraint(
            "anchor_sequence > 0 "
            "AND epoch_sequence > 0 "
            "AND evaluation_sequence >= 0 "
            "AND length(anchor_intent_id) = 36 "
            "AND length(host_id) BETWEEN 1 AND 128 "
            "AND (previous_anchor_sha256 IS NULL "
            "OR length(previous_anchor_sha256) = 64) "
            "AND (previous_anchored_host_head_sha256 IS NULL "
            "OR length(previous_anchored_host_head_sha256) = 64) "
            "AND length(anchor_authority_sha256) = 64 "
            "AND length(deployment_identity_sha256) = 64 "
            "AND length(runtime_database_identity_sha256) = 64 "
            "AND length(anchor_project_identity_sha256) = 64 "
            "AND length(anchor_project_ref) = 20 "
            "AND length(bucket_name) BETWEEN 1 AND 128 "
            "AND bucket_name = 'aqt-trusted-time-anchors-v1' "
            "AND length(principal_id) = 36 "
            "AND length(signing_key_id) BETWEEN 1 AND 128 "
            "AND length(signing_public_key_sha256) = 64 "
            "AND length(source_id) BETWEEN 1 AND 128 "
            "AND length(source_authority_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            f"AND policy_sha256 = '{_POLICY_SHA256}' "
            "AND persistence_contract_version = "
            "'phase6a-durable-trusted-time-persistence-v2' "
            "AND length(monitor_epoch_id) = 36 "
            "AND length(epoch_sha256) = 64 "
            "AND (evaluation_id IS NULL OR length(evaluation_id) = 36) "
            "AND (evaluation_record_sha256 IS NULL "
            "OR length(evaluation_record_sha256) = 64) "
            "AND (state_sha256 IS NULL OR length(state_sha256) = 64) "
            "AND (probe_status IS NULL OR probe_status IN ("
            "'recorded', "
            "'source_unavailable', "
            "'source_identity_mismatch', "
            "'invalid_reading')) "
            "AND (health IS NULL OR health IN ('healthy', 'warning', 'blocked')) "
            "AND (local_previous_host_head_sha256 IS NULL "
            "OR length(local_previous_host_head_sha256) = 64) "
            "AND length(current_host_head_sha256) = 64 "
            "AND (local_previous_host_head_sha256 IS NULL "
            "OR local_previous_host_head_sha256 <> current_host_head_sha256) "
            "AND (previous_anchored_host_head_sha256 IS NULL "
            "OR previous_anchored_host_head_sha256 <> current_host_head_sha256) "
            "AND length(host_identity_sha256) = 64 "
            "AND length(signed_envelope_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND (evaluated_at_utc IS NULL "
            "OR evaluated_at_utc = head_authenticated_at_utc) "
            "AND (evaluated_at_monotonic_ns IS NULL "
            "OR evaluated_at_monotonic_ns >= 0)",
            name="phase6_anchor_intent_identity",
        ),
        sa.CheckConstraint(
            "length(object_name) = 223 "
            "AND substr(object_name, 1, 133) = 'v1/' "
            "|| deployment_identity_sha256 || '/' "
            "|| host_identity_sha256 || '/' "
            "AND substr(object_name, 134, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 135, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 136, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 137, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 138, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 139, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 140, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 141, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 142, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 143, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 144, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 145, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 146, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 147, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 148, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 149, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 150, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 151, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 152, 1) BETWEEN '0' AND '9' "
            "AND substr(object_name, 153, 1) BETWEEN '0' AND '9' "
            "AND CAST(substr(object_name, 134, 20) AS BIGINT) = anchor_sequence "
            "AND substr(object_name, 154, 70) = '-' "
            "|| signed_envelope_sha256 || '.json'",
            name="phase6_anchor_intent_object_name",
        ),
        sa.CheckConstraint(
            "length(signed_envelope_bytes) BETWEEN 2 AND 4096 "
            "AND length(signed_envelope_text) BETWEEN 2 AND 4096 "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name="phase6_anchor_intent_payload",
        ),
    )
    op.create_index(
        "ix_phase6_anchor_intent_host_created",
        _INTENT_TABLE,
        ["host_id", "created_at_utc"],
        unique=False,
    )

    op.create_table(
        _RECEIPT_TABLE,
        sa.Column("anchor_receipt_id", sa.String(36), nullable=False),
        sa.Column("anchor_intent_id", sa.String(36), nullable=False),
        sa.Column("anchor_intent_sha256", sa.String(64), nullable=False),
        sa.Column("signed_envelope_sha256", sa.String(64), nullable=False),
        sa.Column("deployment_identity_sha256", sa.String(64), nullable=False),
        sa.Column("runtime_database_identity_sha256", sa.String(64), nullable=False),
        sa.Column("anchor_project_identity_sha256", sa.String(64), nullable=False),
        sa.Column("anchor_project_ref", sa.String(20), nullable=False),
        sa.Column("bucket_name", sa.String(128), nullable=False),
        sa.Column("principal_id", sa.String(36), nullable=False),
        sa.Column("object_name", sa.String(512), nullable=False),
        sa.Column("readback_bytes_sha256", sa.String(64), nullable=False),
        sa.Column("observed_at_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "anchor_receipt_id",
            name=op.f(f"pk_{_RECEIPT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "anchor_intent_id",
            name="uq_phase6_anchor_receipt_intent",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name="uq_phase6_anchor_receipt_semantic",
        ),
        sa.ForeignKeyConstraint(
            [
                "anchor_intent_id",
                "anchor_intent_sha256",
                "signed_envelope_sha256",
                "deployment_identity_sha256",
                "runtime_database_identity_sha256",
                "anchor_project_identity_sha256",
                "anchor_project_ref",
                "bucket_name",
                "principal_id",
                "object_name",
            ],
            [
                f"{_INTENT_TABLE}.anchor_intent_id",
                f"{_INTENT_TABLE}.semantic_sha256",
                f"{_INTENT_TABLE}.signed_envelope_sha256",
                f"{_INTENT_TABLE}.deployment_identity_sha256",
                f"{_INTENT_TABLE}.runtime_database_identity_sha256",
                f"{_INTENT_TABLE}.anchor_project_identity_sha256",
                f"{_INTENT_TABLE}.anchor_project_ref",
                f"{_INTENT_TABLE}.bucket_name",
                f"{_INTENT_TABLE}.principal_id",
                f"{_INTENT_TABLE}.object_name",
            ],
            name="fk_phase6_anchor_receipt_intent",
        ),
        sa.CheckConstraint(
            "length(anchor_receipt_id) = 36 "
            "AND length(anchor_intent_id) = 36 "
            "AND length(anchor_intent_sha256) = 64 "
            "AND length(signed_envelope_sha256) = 64 "
            "AND length(deployment_identity_sha256) = 64 "
            "AND length(runtime_database_identity_sha256) = 64 "
            "AND length(anchor_project_identity_sha256) = 64 "
            "AND length(anchor_project_ref) = 20 "
            "AND length(bucket_name) BETWEEN 1 AND 128 "
            "AND bucket_name = 'aqt-trusted-time-anchors-v1' "
            "AND length(principal_id) = 36 "
            "AND length(object_name) BETWEEN 1 AND 512 "
            "AND length(readback_bytes_sha256) = 64 "
            "AND readback_bytes_sha256 = signed_envelope_sha256 "
            "AND length(semantic_sha256) = 64",
            name="phase6_anchor_receipt_identity",
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name="phase6_anchor_receipt_payload",
        ),
    )
    op.create_index(
        "ix_phase6_anchor_receipt_observed",
        _RECEIPT_TABLE,
        ["observed_at_utc"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    guarded_tables = (_RECEIPT_TABLE, _INTENT_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE " + ", ".join(guarded_tables) + " IN ACCESS EXCLUSIVE MODE"
        )
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in guarded_tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty trusted-time anchor history")
    op.drop_index(
        "ix_phase6_anchor_receipt_observed",
        table_name=_RECEIPT_TABLE,
    )
    op.drop_table(_RECEIPT_TABLE)
    op.drop_index(
        "ix_phase6_anchor_intent_host_created",
        table_name=_INTENT_TABLE,
    )
    op.drop_table(_INTENT_TABLE)
