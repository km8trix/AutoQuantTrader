"""Add durable bounded Phase 3 experiment governance.

Revision ID: 0010_phase3_governance
Revises: 0009_lease_revision_chain
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_phase3_governance"
down_revision: str | None = "0009_lease_revision_chain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "phase3_experiment_families",
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("family_name", sa.String(128), nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=False),
        sa.Column("strategy_version_id", sa.String(64), nullable=False),
        sa.Column("dataset_replay_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_plan_sha256", sa.String(64), nullable=False),
        sa.Column("promotion_criteria_sha256", sa.String(64), nullable=False),
        sa.Column("holdout_commitment_sha256", sa.String(64), nullable=False),
        sa.Column("holdout_content_commitment_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("evidence_payload", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "length(family_id) = 64 AND length(strategy_version_id) = 64 "
            "AND length(dataset_replay_sha256) = 64 "
            "AND length(evaluation_plan_sha256) = 64 "
            "AND length(promotion_criteria_sha256) = 64 "
            "AND length(holdout_commitment_sha256) = 64 "
            "AND length(holdout_content_commitment_sha256) = 64 "
            "AND length(evidence_sha256) = 64 AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_experiment_families_phase3_family_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 524288 "
            "AND length(evidence_payload) BETWEEN 2 AND 1048576",
            name=op.f("ck_phase3_experiment_families_phase3_family_payload_sizes"),
        ),
        sa.ForeignKeyConstraint(
            ["strategy_version_id"],
            ["phase2_strategy_versions.strategy_version_id"],
            name="fk_phase3_families_strategy_version",
        ),
        sa.PrimaryKeyConstraint(
            "family_id",
            name=op.f("pk_phase3_experiment_families"),
        ),
        sa.UniqueConstraint(
            "evidence_sha256",
            name=op.f("uq_phase3_experiment_families_evidence_sha256"),
        ),
        sa.UniqueConstraint(
            "holdout_commitment_sha256",
            name=op.f("uq_phase3_experiment_families_holdout_commitment_sha256"),
        ),
        sa.UniqueConstraint(
            "holdout_content_commitment_sha256",
            name=op.f("uq_phase3_experiment_families_holdout_content_commitment_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_experiment_families_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase3_experiment_families_created_at",
        "phase3_experiment_families",
        ["created_at"],
        unique=False,
    )

    op.create_table(
        "phase3_experiment_tape_policies",
        sa.Column("tape_content_sha256", sa.String(64), nullable=False),
        sa.Column("source_tape_sha256", sa.String(64), nullable=False),
        sa.Column("usage_class", sa.String(16), nullable=False),
        sa.Column("holdout_family_id", sa.String(64), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(usage_class = 'exploratory' AND holdout_family_id IS NULL) "
            "OR (usage_class = 'holdout' AND holdout_family_id IS NOT NULL)",
            name=op.f("ck_phase3_experiment_tape_policies_phase3_tape_policy_usage_shape"),
        ),
        sa.CheckConstraint(
            "length(tape_content_sha256) = 64 "
            "AND length(source_tape_sha256) = 64 "
            "AND (holdout_family_id IS NULL OR length(holdout_family_id) = 64) "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_experiment_tape_policies_phase3_tape_policy_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 4096",
            name=op.f("ck_phase3_experiment_tape_policies_phase3_tape_policy_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["holdout_family_id"],
            ["phase3_experiment_families.family_id"],
            name="fk_phase3_tape_policies_holdout_family",
        ),
        sa.PrimaryKeyConstraint(
            "tape_content_sha256",
            name=op.f("pk_phase3_experiment_tape_policies"),
        ),
        sa.UniqueConstraint(
            "holdout_family_id",
            name=op.f("uq_phase3_experiment_tape_policies_holdout_family_id"),
        ),
        sa.UniqueConstraint(
            "tape_content_sha256",
            "source_tape_sha256",
            "usage_class",
            name="uq_phase3_tape_policies_identity_usage",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_experiment_tape_policies_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "source_tape_sha256",
            name=op.f("uq_phase3_experiment_tape_policies_source_tape_sha256"),
        ),
    )

    op.create_table(
        "phase3_experiment_tape_claims",
        sa.Column("claim_sha256", sa.String(64), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("segment_kind", sa.String(16), nullable=False),
        sa.Column("segment_sha256", sa.String(64), nullable=False),
        sa.Column("source_tape_sha256", sa.String(64), nullable=False),
        sa.Column("tape_content_sha256", sa.String(64), nullable=False),
        sa.Column("usage_class", sa.String(16), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(segment_kind IN ('train', 'validation') "
            "AND usage_class = 'exploratory') "
            "OR (segment_kind = 'test' AND usage_class = 'holdout')",
            name=op.f("ck_phase3_experiment_tape_claims_phase3_tape_claim_role_usage"),
        ),
        sa.CheckConstraint(
            "length(claim_sha256) = 64 "
            "AND length(family_id) = 64 "
            "AND length(segment_sha256) = 64 "
            "AND length(source_tape_sha256) = 64 "
            "AND length(tape_content_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_experiment_tape_claims_phase3_tape_claim_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 4096",
            name=op.f("ck_phase3_experiment_tape_claims_phase3_tape_claim_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["family_id"],
            ["phase3_experiment_families.family_id"],
            name="fk_phase3_tape_claims_family",
        ),
        sa.ForeignKeyConstraint(
            ["tape_content_sha256", "source_tape_sha256", "usage_class"],
            [
                "phase3_experiment_tape_policies.tape_content_sha256",
                "phase3_experiment_tape_policies.source_tape_sha256",
                "phase3_experiment_tape_policies.usage_class",
            ],
            name="fk_phase3_tape_claims_policy",
        ),
        sa.PrimaryKeyConstraint(
            "claim_sha256",
            name=op.f("pk_phase3_experiment_tape_claims"),
        ),
        sa.UniqueConstraint(
            "family_id",
            "segment_kind",
            name="uq_phase3_tape_claims_family_segment_kind",
        ),
        sa.UniqueConstraint(
            "family_id",
            "segment_sha256",
            name="uq_phase3_tape_claims_family_segment",
        ),
        sa.UniqueConstraint(
            "family_id",
            "source_tape_sha256",
            name="uq_phase3_tape_claims_family_source_tape",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_experiment_tape_claims_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase3_experiment_tape_claims_family",
        "phase3_experiment_tape_claims",
        ["family_id"],
        unique=False,
    )

    op.create_table(
        "phase3_experiment_attempts",
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("configuration_sha256", sa.String(64), nullable=False),
        sa.Column("configuration_validation_sha256", sa.String(64), nullable=False),
        sa.Column("segment_kind", sa.String(16), nullable=False),
        sa.Column("segment_sha256", sa.String(64), nullable=False),
        sa.Column("holdout_reveal_sha256", sa.String(64), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "sequence_number >= 0 AND attempt_number = sequence_number + 1",
            name=op.f("ck_phase3_experiment_attempts_phase3_attempt_contiguous_number"),
        ),
        sa.CheckConstraint(
            "segment_kind IN ('train', 'validation', 'test')",
            name=op.f("ck_phase3_experiment_attempts_phase3_attempt_valid_segment_kind"),
        ),
        sa.CheckConstraint(
            "(segment_kind = 'test' AND holdout_reveal_sha256 IS NOT NULL) "
            "OR (segment_kind <> 'test' AND holdout_reveal_sha256 IS NULL)",
            name=op.f("ck_phase3_experiment_attempts_phase3_attempt_holdout_binding"),
        ),
        sa.CheckConstraint(
            "length(attempt_id) = 64 AND length(family_id) = 64 "
            "AND length(configuration_sha256) = 64 "
            "AND length(configuration_validation_sha256) = 64 "
            "AND length(segment_sha256) = 64 "
            "AND (holdout_reveal_sha256 IS NULL OR length(holdout_reveal_sha256) = 64) "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_experiment_attempts_phase3_attempt_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f("ck_phase3_experiment_attempts_phase3_attempt_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["configuration_sha256"],
            ["phase2_strategy_configurations.configuration_sha256"],
            name="fk_phase3_attempts_configuration",
        ),
        sa.ForeignKeyConstraint(
            ["family_id"],
            ["phase3_experiment_families.family_id"],
            name="fk_phase3_attempts_family",
        ),
        sa.PrimaryKeyConstraint(
            "attempt_id",
            name=op.f("pk_phase3_experiment_attempts"),
        ),
        sa.UniqueConstraint(
            "attempt_id",
            "family_id",
            name="uq_phase3_attempts_identity_family",
        ),
        sa.UniqueConstraint(
            "family_id",
            "attempt_number",
            name="uq_phase3_attempts_family_attempt_number",
        ),
        sa.UniqueConstraint(
            "family_id",
            "sequence_number",
            name="uq_phase3_attempts_family_sequence",
        ),
        sa.UniqueConstraint(
            "holdout_reveal_sha256",
            name=op.f("uq_phase3_experiment_attempts_holdout_reveal_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_experiment_attempts_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase3_experiment_attempts_family_requested",
        "phase3_experiment_attempts",
        ["family_id", "requested_at"],
        unique=False,
    )

    op.create_table(
        "phase3_experiment_attempt_events",
        sa.Column("event_sha256", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("global_sequence_number", sa.Integer(), nullable=False),
        sa.Column("attempt_sequence_number", sa.Integer(), nullable=False),
        sa.Column("previous_entry_sha256", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("terminal_evidence_sha256", sa.String(64), nullable=True),
        sa.Column("terminal_evidence_payload", sa.Text(), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "(global_sequence_number = 0 AND previous_entry_sha256 IS NULL) "
            "OR (global_sequence_number > 0 AND previous_entry_sha256 IS NOT NULL)",
            name=op.f("ck_phase3_experiment_attempt_events_phase3_attempt_event_initial_shape"),
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'canceled', 'abandoned')",
            name=op.f("ck_phase3_experiment_attempt_events_phase3_attempt_event_valid_status"),
        ),
        sa.CheckConstraint(
            "(status IN ('queued', 'running') "
            "AND terminal_evidence_sha256 IS NULL AND terminal_evidence_payload IS NULL) "
            "OR (status IN ('completed', 'failed', 'canceled', 'abandoned') "
            "AND terminal_evidence_sha256 IS NOT NULL "
            "AND terminal_evidence_payload IS NOT NULL)",
            name=op.f("ck_phase3_experiment_attempt_events_phase3_attempt_event_evidence_shape"),
        ),
        sa.CheckConstraint(
            "length(event_sha256) = 64 AND length(attempt_id) = 64 "
            "AND length(family_id) = 64 "
            "AND (previous_entry_sha256 IS NULL OR length(previous_entry_sha256) = 64) "
            "AND (terminal_evidence_sha256 IS NULL "
            "OR length(terminal_evidence_sha256) = 64) "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_experiment_attempt_events_phase3_attempt_event_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(actor_id) BETWEEN 1 AND 128",
            name=op.f("ck_phase3_experiment_attempt_events_phase3_attempt_event_actor_size"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144 "
            "AND (terminal_evidence_payload IS NULL "
            "OR length(terminal_evidence_payload) BETWEEN 2 AND 262144)",
            name=op.f("ck_phase3_experiment_attempt_events_phase3_attempt_event_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id", "family_id"],
            [
                "phase3_experiment_attempts.attempt_id",
                "phase3_experiment_attempts.family_id",
            ],
            name="fk_phase3_attempt_events_attempt_family",
        ),
        sa.PrimaryKeyConstraint(
            "event_sha256",
            name=op.f("pk_phase3_experiment_attempt_events"),
        ),
        sa.UniqueConstraint(
            "attempt_id",
            "attempt_sequence_number",
            name="uq_phase3_attempt_events_attempt_sequence",
        ),
        sa.UniqueConstraint(
            "attempt_id",
            "event_sha256",
            name="uq_phase3_attempt_events_attempt_event",
        ),
        sa.UniqueConstraint(
            "family_id",
            "global_sequence_number",
            name="uq_phase3_attempt_events_family_global_sequence",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_experiment_attempt_events_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase3_attempt_events_family_occurred",
        "phase3_experiment_attempt_events",
        ["family_id", "occurred_at"],
        unique=False,
    )

    op.create_table(
        "phase3_holdout_reveals",
        sa.Column("reveal_id", sa.String(64), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("holdout_commitment_sha256", sa.String(64), nullable=False),
        sa.Column("holdout_content_commitment_sha256", sa.String(64), nullable=False),
        sa.Column("global_sequence_number", sa.Integer(), nullable=False),
        sa.Column("previous_entry_sha256", sa.String(64), nullable=False),
        sa.Column("promotion_criteria_sha256", sa.String(64), nullable=False),
        sa.Column("selected_configuration_sha256", sa.String(64), nullable=False),
        sa.Column("pre_reveal_attempt_count", sa.Integer(), nullable=False),
        sa.Column("pre_reveal_attempts_sha256", sa.String(64), nullable=False),
        sa.Column("pre_reveal_registry_sha256", sa.String(64), nullable=False),
        sa.Column("authorization_sha256", sa.String(64), nullable=False),
        sa.Column("revealed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revealed_by", sa.String(128), nullable=False),
        sa.Column("access_reason", sa.String(1024), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "global_sequence_number >= 1 AND pre_reveal_attempt_count >= 1",
            name=op.f("ck_phase3_holdout_reveals_phase3_holdout_reveal_non_negative_attempt_count"),
        ),
        sa.CheckConstraint(
            "length(reveal_id) = 64 AND length(holdout_commitment_sha256) = 64 "
            "AND length(holdout_content_commitment_sha256) = 64 "
            "AND length(previous_entry_sha256) = 64 "
            "AND length(promotion_criteria_sha256) = 64 "
            "AND length(selected_configuration_sha256) = 64 "
            "AND length(pre_reveal_attempts_sha256) = 64 "
            "AND length(pre_reveal_registry_sha256) = 64 "
            "AND length(authorization_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_holdout_reveals_phase3_holdout_reveal_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f("ck_phase3_holdout_reveals_phase3_holdout_reveal_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["family_id"],
            ["phase3_experiment_families.family_id"],
            name="fk_phase3_holdout_reveals_family",
        ),
        sa.ForeignKeyConstraint(
            ["selected_configuration_sha256"],
            ["phase2_strategy_configurations.configuration_sha256"],
            name="fk_phase3_holdout_reveals_configuration",
        ),
        sa.PrimaryKeyConstraint(
            "reveal_id",
            name=op.f("pk_phase3_holdout_reveals"),
        ),
        sa.UniqueConstraint(
            "authorization_sha256",
            name=op.f("uq_phase3_holdout_reveals_authorization_sha256"),
        ),
        sa.UniqueConstraint(
            "family_id",
            name=op.f("uq_phase3_holdout_reveals_family_id"),
        ),
        sa.UniqueConstraint(
            "holdout_commitment_sha256",
            name=op.f("uq_phase3_holdout_reveals_holdout_commitment_sha256"),
        ),
        sa.UniqueConstraint(
            "holdout_content_commitment_sha256",
            name=op.f("uq_phase3_holdout_reveals_holdout_content_commitment_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_holdout_reveals_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase3_holdout_reveals_revealed_at",
        "phase3_holdout_reveals",
        ["revealed_at"],
        unique=False,
    )

    op.create_table(
        "phase3_experiment_audit_events",
        sa.Column("audit_sha256", sa.String(64), nullable=False),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("expected_registry_sha256", sa.String(64), nullable=False),
        sa.Column("result_registry_sha256", sa.String(64), nullable=False),
        sa.Column("resource_sha256", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "action IN ('register_family', 'record_attempt', "
            "'transition_attempt', 'reveal_holdout')",
            name=op.f("ck_phase3_experiment_audit_events_phase3_experiment_audit_valid_action"),
        ),
        sa.CheckConstraint(
            "length(audit_sha256) = 64 AND length(request_sha256) = 64 "
            "AND length(expected_registry_sha256) = 64 "
            "AND length(result_registry_sha256) = 64 "
            "AND length(resource_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f("ck_phase3_experiment_audit_events_phase3_experiment_audit_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f("ck_phase3_experiment_audit_events_phase3_experiment_audit_payload_size"),
        ),
        sa.ForeignKeyConstraint(
            ["family_id"],
            ["phase3_experiment_families.family_id"],
            name="fk_phase3_experiment_audits_family",
        ),
        sa.PrimaryKeyConstraint(
            "audit_sha256",
            name=op.f("pk_phase3_experiment_audit_events"),
        ),
        sa.UniqueConstraint(
            "actor_id",
            "idempotency_key",
            name="uq_phase3_experiment_audits_actor_idempotency",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f("uq_phase3_experiment_audit_events_semantic_sha256"),
        ),
    )
    op.create_index(
        "ix_phase3_experiment_audits_family_occurred",
        "phase3_experiment_audit_events",
        ["family_id", "occurred_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_phase3_experiment_audits_family_occurred",
        table_name="phase3_experiment_audit_events",
    )
    op.drop_table("phase3_experiment_audit_events")
    op.drop_index(
        "ix_phase3_holdout_reveals_revealed_at",
        table_name="phase3_holdout_reveals",
    )
    op.drop_table("phase3_holdout_reveals")
    op.drop_index(
        "ix_phase3_attempt_events_family_occurred",
        table_name="phase3_experiment_attempt_events",
    )
    op.drop_table("phase3_experiment_attempt_events")
    op.drop_index(
        "ix_phase3_experiment_attempts_family_requested",
        table_name="phase3_experiment_attempts",
    )
    op.drop_table("phase3_experiment_attempts")
    op.drop_index(
        "ix_phase3_experiment_tape_claims_family",
        table_name="phase3_experiment_tape_claims",
    )
    op.drop_table("phase3_experiment_tape_claims")
    op.drop_table("phase3_experiment_tape_policies")
    op.drop_index(
        "ix_phase3_experiment_families_created_at",
        table_name="phase3_experiment_families",
    )
    op.drop_table("phase3_experiment_families")
