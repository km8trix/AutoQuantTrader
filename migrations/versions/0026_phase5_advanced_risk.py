"""Add durable Phase 5B advanced-risk policy and evidence bindings.

Revision ID: 0026_phase5_advanced_risk
Revises: 0025_phase5_operational_control
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026_phase5_advanced_risk"
down_revision: str | None = "0025_phase5_operational_control"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY_TABLE = "phase5_advanced_risk_policies"
_ASSIGNMENT_TABLE = "phase5_advanced_risk_assignments"
_ASSIGNMENT_HEAD_TABLE = "phase5_advanced_risk_assignment_heads"
_EVIDENCE_TABLE = "phase5_advanced_risk_evidence"
_SOURCE_TABLE = "phase5_advanced_risk_evidence_sources"
_ASSESSMENT_TABLE = "phase5_advanced_risk_assessments"
_ADMISSION_TABLE = "phase5_advanced_risk_batch_admissions"
_ENFORCEMENT_HEAD_TABLE = "phase5_advanced_risk_enforcement_heads"


def upgrade() -> None:
    op.create_table(
        _POLICY_TABLE,
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("scope_profile_id", sa.String(128), nullable=False),
        sa.Column("scope_profile_sha256", sa.String(64), nullable=False),
        sa.Column("rule_count", sa.Integer(), nullable=False),
        sa.Column("pretrade_new_exposure_rule_count", sa.Integer(), nullable=False),
        sa.Column("runtime_rule_count", sa.Integer(), nullable=False),
        sa.Column("none_disposition_count", sa.Integer(), nullable=False),
        sa.Column("reject_disposition_count", sa.Integer(), nullable=False),
        sa.Column("pause_disposition_count", sa.Integer(), nullable=False),
        sa.Column("halt_disposition_count", sa.Integer(), nullable=False),
        sa.Column("rules_payload", sa.Text(), nullable=False),
        # Provenance only; assignment commands carry actor authority.
        sa.Column("approval_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "policy_sha256",
            name=op.f(f"pk_{_POLICY_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_POLICY_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "policy_id",
            "policy_version",
            "environment",
            name="uq_phase5_adv_policy_version_scope",
        ),
        sa.UniqueConstraint(
            "policy_sha256",
            "policy_id",
            "environment",
            "semantic_sha256",
            name="uq_phase5_adv_policy_exact",
        ),
        sa.CheckConstraint(
            "rule_count BETWEEN 1 AND 64 "
            "AND pretrade_new_exposure_rule_count BETWEEN 1 AND rule_count "
            "AND runtime_rule_count BETWEEN 1 AND rule_count "
            "AND none_disposition_count BETWEEN 0 AND rule_count "
            "AND reject_disposition_count BETWEEN 0 AND rule_count "
            "AND pause_disposition_count BETWEEN 0 AND rule_count "
            "AND halt_disposition_count BETWEEN 0 AND rule_count",
            name=op.f(f"ck_{_POLICY_TABLE}_counts"),
        ),
        sa.CheckConstraint(
            "length(policy_sha256) = 64 "
            "AND length(scope_profile_sha256) = 64 "
            "AND length(approval_evidence_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_POLICY_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "length(policy_id) BETWEEN 1 AND 128 "
            "AND length(policy_version) BETWEEN 1 AND 64 "
            "AND length(environment) BETWEEN 1 AND 32 "
            "AND length(scope_profile_id) BETWEEN 1 AND 128 "
            "AND length(rules_payload) BETWEEN 2 AND 1048576 "
            "AND length(canonical_payload) BETWEEN 2 AND 2097152",
            name=op.f(f"ck_{_POLICY_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_policy_scope",
        _POLICY_TABLE,
        ["environment", "policy_id"],
        unique=False,
    )

    op.create_table(
        _ASSIGNMENT_TABLE,
        sa.Column("assignment_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("previous_assignment_id", sa.String(36), nullable=True),
        sa.Column("previous_assignment_sha256", sa.String(64), nullable=True),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=False),
        sa.Column("policy_semantic_sha256", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("command_id", sa.String(36), nullable=False),
        sa.Column("command_sha256", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("actor_authority_sha256", sa.String(64), nullable=False),
        sa.Column("actor_authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("operational_transition_id", sa.String(36), nullable=False),
        sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "assignment_id",
            name=op.f(f"pk_{_ASSIGNMENT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_ASSIGNMENT_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            name="uq_phase5_adv_assignment_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "command_id",
            name="uq_phase5_adv_assignment_command",
        ),
        sa.UniqueConstraint(
            "account_id",
            "assignment_id",
            "semantic_sha256",
            name="uq_phase5_adv_assignment_id_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            "assignment_id",
            "semantic_sha256",
            name="uq_phase5_adv_assignment_chain_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "assignment_id",
            "sequence_number",
            "policy_sha256",
            "semantic_sha256",
            name="uq_phase5_adv_assignment_policy_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_adv_assignment_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_adv_assignment_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "policy_sha256",
                "policy_id",
                "environment",
                "policy_semantic_sha256",
            ],
            [
                f"{_POLICY_TABLE}.policy_sha256",
                f"{_POLICY_TABLE}.policy_id",
                f"{_POLICY_TABLE}.environment",
                f"{_POLICY_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_assignment_policy",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "previous_sequence_number",
                "previous_assignment_id",
                "previous_assignment_sha256",
            ],
            [
                f"{_ASSIGNMENT_TABLE}.account_id",
                f"{_ASSIGNMENT_TABLE}.sequence_number",
                f"{_ASSIGNMENT_TABLE}.assignment_id",
                f"{_ASSIGNMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_assignment_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "operational_transition_id",
                "operational_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_assignment_control",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 "
            "AND previous_sequence_number IS NULL "
            "AND previous_assignment_id IS NULL "
            "AND previous_assignment_sha256 IS NULL) "
            "OR (sequence_number > 1 "
            "AND previous_sequence_number = sequence_number - 1 "
            "AND previous_assignment_id IS NOT NULL "
            "AND previous_assignment_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_ASSIGNMENT_TABLE}_predecessor"),
        ),
        sa.CheckConstraint(
            "fencing_generation > 0",
            name=op.f(f"ck_{_ASSIGNMENT_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(assignment_id) = 36 "
            "AND (previous_assignment_id IS NULL "
            "OR length(previous_assignment_id) = 36) "
            "AND (previous_assignment_sha256 IS NULL "
            "OR length(previous_assignment_sha256) = 64) "
            "AND length(policy_sha256) = 64 "
            "AND length(policy_semantic_sha256) = 64 "
            "AND length(command_id) = 36 "
            "AND length(command_sha256) = 64 "
            "AND length(actor_authority_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(operational_transition_id) = 36 "
            "AND length(operational_transition_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_ASSIGNMENT_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "length(account_id) BETWEEN 1 AND 64 "
            "AND length(environment) BETWEEN 1 AND 32 "
            "AND length(policy_id) BETWEEN 1 AND 128 "
            "AND length(actor_id) BETWEEN 1 AND 128 "
            "AND length(canonical_payload) BETWEEN 2 AND 524288",
            name=op.f(f"ck_{_ASSIGNMENT_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_assignment_account_time",
        _ASSIGNMENT_TABLE,
        ["account_id", "assigned_at"],
        unique=False,
    )

    op.create_table(
        _ASSIGNMENT_HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("assignment_id", sa.String(36), nullable=False),
        sa.Column("assignment_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "account_id",
            name=op.f(f"pk_{_ASSIGNMENT_HEAD_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_ASSIGNMENT_HEAD_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_adv_assignment_head_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "assignment_id",
                "sequence_number",
                "policy_sha256",
                "assignment_sha256",
            ],
            [
                f"{_ASSIGNMENT_TABLE}.account_id",
                f"{_ASSIGNMENT_TABLE}.assignment_id",
                f"{_ASSIGNMENT_TABLE}.sequence_number",
                f"{_ASSIGNMENT_TABLE}.policy_sha256",
                f"{_ASSIGNMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_assignment_head_tip",
        ),
        sa.CheckConstraint(
            "sequence_number > 0 AND assigned_at <= updated_at",
            name=op.f(f"ck_{_ASSIGNMENT_HEAD_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(assignment_id) = 36 "
            "AND length(assignment_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(environment) BETWEEN 1 AND 32 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 524288",
            name=op.f(f"ck_{_ASSIGNMENT_HEAD_TABLE}_identity"),
        ),
    )

    op.create_table(
        _EVIDENCE_TABLE,
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("observation_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_observation_sequence", sa.BigInteger(), nullable=True),
        sa.Column("previous_evidence_id", sa.String(36), nullable=True),
        sa.Column("previous_evidence_sha256", sa.String(64), nullable=True),
        sa.Column("assignment_id", sa.String(36), nullable=False),
        sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("assignment_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_kind", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(128), nullable=False),
        sa.Column("rule_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_mode", sa.String(32), nullable=False),
        sa.Column("breach_disposition", sa.String(16), nullable=False),
        sa.Column("producer_id", sa.String(128), nullable=False),
        sa.Column("producer_version", sa.String(64), nullable=False),
        sa.Column("producer_authority_sha256", sa.String(64), nullable=False),
        sa.Column("source_authority_sha256", sa.String(64), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_ended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completeness", sa.String(16), nullable=False),
        sa.Column("value", sa.Numeric(28, 10), nullable=True),
        sa.Column("incomplete_reason", sa.String(512), nullable=True),
        sa.Column("sample_count", sa.BigInteger(), nullable=False),
        sa.Column("qualifying_count", sa.BigInteger(), nullable=False),
        sa.Column("source_count", sa.BigInteger(), nullable=False),
        sa.Column("retained_source_count", sa.Integer(), nullable=False),
        sa.Column("source_set_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("operational_transition_id", sa.String(36), nullable=False),
        sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "evidence_id",
            name=op.f(f"pk_{_EVIDENCE_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_EVIDENCE_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "observation_sequence",
            name="uq_phase5_adv_evidence_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "producer_id",
            "idempotency_key",
            name="uq_phase5_adv_evidence_producer_key",
        ),
        sa.UniqueConstraint(
            "account_id",
            "evidence_id",
            "semantic_sha256",
            name="uq_phase5_adv_evidence_id_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "observation_sequence",
            "evidence_id",
            "semantic_sha256",
            name="uq_phase5_adv_evidence_chain_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "evidence_id",
            "observation_sequence",
            "assignment_id",
            "policy_sha256",
            "semantic_sha256",
            name="uq_phase5_adv_evidence_watermark_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_adv_evidence_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_adv_evidence_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "assignment_id",
                "assignment_sequence_number",
                "policy_sha256",
                "assignment_sha256",
            ],
            [
                f"{_ASSIGNMENT_TABLE}.account_id",
                f"{_ASSIGNMENT_TABLE}.assignment_id",
                f"{_ASSIGNMENT_TABLE}.sequence_number",
                f"{_ASSIGNMENT_TABLE}.policy_sha256",
                f"{_ASSIGNMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_evidence_assignment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "previous_observation_sequence",
                "previous_evidence_id",
                "previous_evidence_sha256",
            ],
            [
                f"{_EVIDENCE_TABLE}.account_id",
                f"{_EVIDENCE_TABLE}.observation_sequence",
                f"{_EVIDENCE_TABLE}.evidence_id",
                f"{_EVIDENCE_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_evidence_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "operational_transition_id",
                "operational_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_evidence_control",
        ),
        sa.CheckConstraint(
            "(observation_sequence = 1 "
            "AND previous_observation_sequence IS NULL "
            "AND previous_evidence_id IS NULL "
            "AND previous_evidence_sha256 IS NULL) "
            "OR (observation_sequence > 1 "
            "AND previous_observation_sequence = observation_sequence - 1 "
            "AND previous_evidence_id IS NOT NULL "
            "AND previous_evidence_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_EVIDENCE_TABLE}_predecessor"),
        ),
        sa.CheckConstraint(
            "rule_kind IN "
            "('session_loss', 'session_drawdown', 'concentration', 'leverage', "
            "'volatility', 'spread', 'slippage', 'broker_reject_rate', "
            "'broker_rate_limit', 'clock_health', 'data_health', "
            "'unknown_duration', 'reconciliation_duration') "
            "AND evaluation_mode IN ('pretrade_new_exposure', 'runtime') "
            "AND breach_disposition IN ('none', 'reject', 'pause', 'halt')",
            name=op.f(f"ck_{_EVIDENCE_TABLE}_rule"),
        ),
        sa.CheckConstraint(
            "window_started_at < window_ended_at "
            "AND window_ended_at <= observed_at "
            "AND observed_at <= recorded_at",
            name=op.f(f"ck_{_EVIDENCE_TABLE}_chronology"),
        ),
        sa.CheckConstraint(
            "completeness IN "
            "('complete', 'insufficient', 'unavailable', 'overflowed') "
            "AND sample_count >= 0 "
            "AND qualifying_count BETWEEN 0 AND sample_count "
            "AND source_count >= 0 "
            "AND retained_source_count BETWEEN 0 AND 2048 "
            "AND ("
            "(completeness = 'complete' "
            "AND value IS NOT NULL "
            "AND incomplete_reason IS NULL "
            "AND source_count = retained_source_count "
            "AND retained_source_count > 0) "
            "OR (completeness = 'overflowed' "
            "AND value IS NULL "
            "AND incomplete_reason IS NOT NULL "
            "AND retained_source_count = 2048 "
            "AND source_count > retained_source_count) "
            "OR (completeness IN ('insufficient', 'unavailable') "
            "AND value IS NULL "
            "AND incomplete_reason IS NOT NULL "
            "AND source_count = retained_source_count))",
            name=op.f(f"ck_{_EVIDENCE_TABLE}_completeness"),
        ),
        sa.CheckConstraint(
            "fencing_generation > 0 "
            "AND assignment_sequence_number > 0 "
            "AND length(evidence_id) = 36 "
            "AND (previous_evidence_id IS NULL "
            "OR length(previous_evidence_id) = 36) "
            "AND (previous_evidence_sha256 IS NULL "
            "OR length(previous_evidence_sha256) = 64) "
            "AND length(assignment_id) = 36 "
            "AND length(assignment_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(rule_sha256) = 64 "
            "AND length(producer_authority_sha256) = 64 "
            "AND length(source_authority_sha256) = 64 "
            "AND length(source_set_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(operational_transition_id) = 36 "
            "AND length(operational_transition_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_EVIDENCE_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "length(account_id) BETWEEN 1 AND 64 "
            "AND length(environment) BETWEEN 1 AND 32 "
            "AND length(idempotency_key) BETWEEN 8 AND 128 "
            "AND length(rule_id) BETWEEN 1 AND 128 "
            "AND length(subject_id) BETWEEN 1 AND 128 "
            "AND length(producer_id) BETWEEN 1 AND 128 "
            "AND length(producer_version) BETWEEN 1 AND 64 "
            "AND (incomplete_reason IS NULL "
            "OR length(incomplete_reason) BETWEEN 1 AND 512) "
            "AND length(canonical_payload) BETWEEN 2 AND 2097152",
            name=op.f(f"ck_{_EVIDENCE_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_evidence_account_time",
        _EVIDENCE_TABLE,
        ["account_id", "recorded_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase5_adv_evidence_rule_time",
        _EVIDENCE_TABLE,
        ["rule_kind", "recorded_at"],
        unique=False,
    )

    op.create_table(
        _SOURCE_TABLE,
        sa.Column("evidence_id", sa.String(36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("source_kind", sa.String(64), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "evidence_id",
            "ordinal",
            name=op.f(f"pk_{_SOURCE_TABLE}"),
        ),
        sa.UniqueConstraint(
            "evidence_id",
            "source_kind",
            "source_id",
            name="uq_phase5_adv_evidence_source_identity",
        ),
        sa.UniqueConstraint(
            "evidence_id",
            "semantic_sha256",
            name="uq_phase5_adv_evidence_source_semantic",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "evidence_id", "evidence_sha256"],
            [
                f"{_EVIDENCE_TABLE}.account_id",
                f"{_EVIDENCE_TABLE}.evidence_id",
                f"{_EVIDENCE_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_evidence_source_parent",
        ),
        sa.CheckConstraint(
            "ordinal BETWEEN 0 AND 2047 AND effective_at <= available_at",
            name=op.f(f"ck_{_SOURCE_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(evidence_id) = 36 "
            "AND length(evidence_sha256) = 64 "
            "AND length(source_kind) BETWEEN 1 AND 64 "
            "AND length(source_id) BETWEEN 1 AND 128 "
            "AND length(source_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_SOURCE_TABLE}_identity"),
        ),
    )

    op.create_table(
        _ASSESSMENT_TABLE,
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("previous_assessment_id", sa.String(36), nullable=True),
        sa.Column("previous_assessment_sha256", sa.String(64), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("assignment_id", sa.String(36), nullable=False),
        sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("assignment_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("observation_watermark_sequence", sa.BigInteger(), nullable=False),
        sa.Column("watermark_evidence_id", sa.String(36), nullable=False),
        sa.Column("watermark_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("evaluation_mode", sa.String(32), nullable=False),
        sa.Column("disposition", sa.String(16), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False),
        sa.Column("complete_result_count", sa.Integer(), nullable=False),
        sa.Column("incomplete_result_count", sa.Integer(), nullable=False),
        sa.Column("breached_rule_count", sa.Integer(), nullable=False),
        sa.Column("results_payload", sa.Text(), nullable=False),
        sa.Column("results_sha256", sa.String(64), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("operational_transition_id", sa.String(36), nullable=False),
        sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_through", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "assessment_id",
            name=op.f(f"pk_{_ASSESSMENT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_ASSESSMENT_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            name="uq_phase5_adv_assessment_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "idempotency_key",
            name="uq_phase5_adv_assessment_account_key",
        ),
        sa.UniqueConstraint(
            "account_id",
            "assessment_id",
            "semantic_sha256",
            name="uq_phase5_adv_assessment_id_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            "assessment_id",
            "semantic_sha256",
            name="uq_phase5_adv_assessment_chain_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_adv_assessment_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_adv_assessment_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "previous_sequence_number",
                "previous_assessment_id",
                "previous_assessment_sha256",
            ],
            [
                f"{_ASSESSMENT_TABLE}.account_id",
                f"{_ASSESSMENT_TABLE}.sequence_number",
                f"{_ASSESSMENT_TABLE}.assessment_id",
                f"{_ASSESSMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_assessment_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "assignment_id",
                "assignment_sequence_number",
                "policy_sha256",
                "assignment_sha256",
            ],
            [
                f"{_ASSIGNMENT_TABLE}.account_id",
                f"{_ASSIGNMENT_TABLE}.assignment_id",
                f"{_ASSIGNMENT_TABLE}.sequence_number",
                f"{_ASSIGNMENT_TABLE}.policy_sha256",
                f"{_ASSIGNMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_assessment_assignment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "watermark_evidence_id",
                "observation_watermark_sequence",
                "assignment_id",
                "policy_sha256",
                "watermark_evidence_sha256",
            ],
            [
                f"{_EVIDENCE_TABLE}.account_id",
                f"{_EVIDENCE_TABLE}.evidence_id",
                f"{_EVIDENCE_TABLE}.observation_sequence",
                f"{_EVIDENCE_TABLE}.assignment_id",
                f"{_EVIDENCE_TABLE}.policy_sha256",
                f"{_EVIDENCE_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_assessment_watermark",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "operational_transition_id",
                "operational_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_assessment_control",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 "
            "AND previous_sequence_number IS NULL "
            "AND previous_assessment_id IS NULL "
            "AND previous_assessment_sha256 IS NULL) "
            "OR (sequence_number > 1 "
            "AND previous_sequence_number = sequence_number - 1 "
            "AND previous_assessment_id IS NOT NULL "
            "AND previous_assessment_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_ASSESSMENT_TABLE}_predecessor"),
        ),
        sa.CheckConstraint(
            "evaluation_mode IN ('pretrade_new_exposure', 'runtime') "
            "AND disposition IN ('none', 'reject', 'pause', 'halt')",
            name=op.f(f"ck_{_ASSESSMENT_TABLE}_outcome"),
        ),
        sa.CheckConstraint(
            "result_count BETWEEN 1 AND 64 "
            "AND complete_result_count BETWEEN 0 AND result_count "
            "AND incomplete_result_count = result_count - complete_result_count "
            "AND breached_rule_count BETWEEN 0 AND complete_result_count",
            name=op.f(f"ck_{_ASSESSMENT_TABLE}_counts"),
        ),
        sa.CheckConstraint(
            "fencing_generation > 0 "
            "AND assignment_sequence_number > 0 "
            "AND observation_watermark_sequence > 0 "
            "AND assessed_at < valid_through",
            name=op.f(f"ck_{_ASSESSMENT_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(assessment_id) = 36 "
            "AND (previous_assessment_id IS NULL "
            "OR length(previous_assessment_id) = 36) "
            "AND (previous_assessment_sha256 IS NULL "
            "OR length(previous_assessment_sha256) = 64) "
            "AND length(assignment_id) = 36 "
            "AND length(assignment_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(watermark_evidence_id) = 36 "
            "AND length(watermark_evidence_sha256) = 64 "
            "AND length(results_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(operational_transition_id) = 36 "
            "AND length(operational_transition_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_ASSESSMENT_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 8 AND 128 "
            "AND length(environment) BETWEEN 1 AND 32 "
            "AND length(results_payload) BETWEEN 2 AND 2097152 "
            "AND length(canonical_payload) BETWEEN 2 AND 4194304",
            name=op.f(f"ck_{_ASSESSMENT_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_assessment_account_time",
        _ASSESSMENT_TABLE,
        ["account_id", "assessed_at"],
        unique=False,
    )

    op.create_table(
        _ADMISSION_TABLE,
        sa.Column("admission_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("phase2_decision_id", sa.String(64), nullable=False),
        sa.Column("phase2_decision_sha256", sa.String(64), nullable=False),
        sa.Column("phase2_decision_status", sa.String(16), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("assessment_id", sa.String(36), nullable=True),
        sa.Column("assessment_sha256", sa.String(64), nullable=True),
        sa.Column("assignment_id", sa.String(36), nullable=True),
        sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=True),
        sa.Column("assignment_sha256", sa.String(64), nullable=True),
        sa.Column("policy_sha256", sa.String(64), nullable=True),
        sa.Column("observation_watermark_sequence", sa.BigInteger(), nullable=True),
        sa.Column("watermark_evidence_id", sa.String(36), nullable=True),
        sa.Column("watermark_evidence_sha256", sa.String(64), nullable=True),
        sa.Column("operational_transition_id", sa.String(36), nullable=False),
        sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
        sa.Column("assessment_mode", sa.String(32), nullable=True),
        sa.Column("assessment_disposition", sa.String(16), nullable=True),
        sa.Column("admitted", sa.Boolean(), nullable=False),
        sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "admission_id",
            name=op.f(f"pk_{_ADMISSION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "phase2_decision_id",
            name=op.f(f"uq_{_ADMISSION_TABLE}_phase2_decision_id"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_ADMISSION_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["phase2_decision_id", "account_id", "fencing_generation"],
            [
                "phase2_batch_decisions.decision_id",
                "phase2_batch_decisions.account_id",
                "phase2_batch_decisions.fencing_generation",
            ],
            name="fk_phase5_adv_admission_phase2_decision",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_adv_admission_lease",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "assessment_id", "assessment_sha256"],
            [
                f"{_ASSESSMENT_TABLE}.account_id",
                f"{_ASSESSMENT_TABLE}.assessment_id",
                f"{_ASSESSMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_admission_assessment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "assignment_id",
                "assignment_sequence_number",
                "policy_sha256",
                "assignment_sha256",
            ],
            [
                f"{_ASSIGNMENT_TABLE}.account_id",
                f"{_ASSIGNMENT_TABLE}.assignment_id",
                f"{_ASSIGNMENT_TABLE}.sequence_number",
                f"{_ASSIGNMENT_TABLE}.policy_sha256",
                f"{_ASSIGNMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_admission_assignment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "watermark_evidence_id",
                "observation_watermark_sequence",
                "assignment_id",
                "policy_sha256",
                "watermark_evidence_sha256",
            ],
            [
                f"{_EVIDENCE_TABLE}.account_id",
                f"{_EVIDENCE_TABLE}.evidence_id",
                f"{_EVIDENCE_TABLE}.observation_sequence",
                f"{_EVIDENCE_TABLE}.assignment_id",
                f"{_EVIDENCE_TABLE}.policy_sha256",
                f"{_EVIDENCE_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_admission_watermark",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "operational_transition_id",
                "operational_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_admission_control",
        ),
        sa.CheckConstraint(
            "(phase2_decision_status = 'no_action' "
            "AND NOT admitted "
            "AND assessment_id IS NULL "
            "AND assessment_sha256 IS NULL "
            "AND assignment_id IS NULL "
            "AND assignment_sequence_number IS NULL "
            "AND assignment_sha256 IS NULL "
            "AND policy_sha256 IS NULL "
            "AND observation_watermark_sequence IS NULL "
            "AND watermark_evidence_id IS NULL "
            "AND watermark_evidence_sha256 IS NULL "
            "AND assessment_mode IS NULL "
            "AND assessment_disposition IS NULL) "
            "OR (phase2_decision_status IN ('approved', 'rejected') "
            "AND assessment_id IS NOT NULL "
            "AND assessment_sha256 IS NOT NULL "
            "AND assignment_id IS NOT NULL "
            "AND assignment_sequence_number IS NOT NULL "
            "AND assignment_sha256 IS NOT NULL "
            "AND policy_sha256 IS NOT NULL "
            "AND observation_watermark_sequence IS NOT NULL "
            "AND watermark_evidence_id IS NOT NULL "
            "AND watermark_evidence_sha256 IS NOT NULL "
            "AND assessment_mode = 'pretrade_new_exposure' "
            "AND assessment_disposition IN ('none', 'reject', 'pause', 'halt') "
            "AND ((admitted "
            "AND phase2_decision_status = 'approved' "
            "AND assessment_disposition = 'none') "
            "OR (NOT admitted "
            "AND (phase2_decision_status = 'rejected' "
            "OR assessment_disposition <> 'none'))))",
            name=op.f(f"ck_{_ADMISSION_TABLE}_outcome"),
        ),
        sa.CheckConstraint(
            "fencing_generation > 0 "
            "AND (assignment_sequence_number IS NULL "
            "OR assignment_sequence_number > 0) "
            "AND (observation_watermark_sequence IS NULL "
            "OR observation_watermark_sequence > 0) "
            "AND bound_at < expires_at",
            name=op.f(f"ck_{_ADMISSION_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(admission_id) = 36 "
            "AND length(phase2_decision_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND (assessment_id IS NULL OR length(assessment_id) = 36) "
            "AND (assessment_sha256 IS NULL OR length(assessment_sha256) = 64) "
            "AND (assignment_id IS NULL OR length(assignment_id) = 36) "
            "AND (assignment_sha256 IS NULL OR length(assignment_sha256) = 64) "
            "AND (policy_sha256 IS NULL OR length(policy_sha256) = 64) "
            "AND (watermark_evidence_id IS NULL "
            "OR length(watermark_evidence_id) = 36) "
            "AND (watermark_evidence_sha256 IS NULL "
            "OR length(watermark_evidence_sha256) = 64) "
            "AND length(operational_transition_id) = 36 "
            "AND length(operational_transition_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 2097152",
            name=op.f(f"ck_{_ADMISSION_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_admission_account_time",
        _ADMISSION_TABLE,
        ["account_id", "bound_at"],
        unique=False,
    )

    op.create_table(
        _ENFORCEMENT_HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("cutover_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("assignment_id", sa.String(36), nullable=False),
        sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("assignment_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("assessment_sha256", sa.String(64), nullable=False),
        sa.Column("cutover_observation_sequence", sa.BigInteger(), nullable=False),
        sa.Column("cutover_evidence_id", sa.String(36), nullable=False),
        sa.Column("cutover_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("operational_transition_id", sa.String(36), nullable=False),
        sa.Column("operational_transition_sha256", sa.String(64), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("enforcement_enabled", sa.Boolean(), nullable=False),
        sa.Column("assessment_disposition", sa.String(16), nullable=False),
        sa.Column("cutover_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assessment_valid_through", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "account_id",
            name=op.f(f"pk_{_ENFORCEMENT_HEAD_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_ENFORCEMENT_HEAD_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_adv_enforcement_head_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_adv_enforcement_head_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "assignment_id",
                "assignment_sequence_number",
                "policy_sha256",
                "assignment_sha256",
            ],
            [
                f"{_ASSIGNMENT_TABLE}.account_id",
                f"{_ASSIGNMENT_TABLE}.assignment_id",
                f"{_ASSIGNMENT_TABLE}.sequence_number",
                f"{_ASSIGNMENT_TABLE}.policy_sha256",
                f"{_ASSIGNMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_enforcement_head_assignment",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "assessment_id", "assessment_sha256"],
            [
                f"{_ASSESSMENT_TABLE}.account_id",
                f"{_ASSESSMENT_TABLE}.assessment_id",
                f"{_ASSESSMENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_enforcement_head_assessment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "cutover_evidence_id",
                "cutover_observation_sequence",
                "assignment_id",
                "policy_sha256",
                "cutover_evidence_sha256",
            ],
            [
                f"{_EVIDENCE_TABLE}.account_id",
                f"{_EVIDENCE_TABLE}.evidence_id",
                f"{_EVIDENCE_TABLE}.observation_sequence",
                f"{_EVIDENCE_TABLE}.assignment_id",
                f"{_EVIDENCE_TABLE}.policy_sha256",
                f"{_EVIDENCE_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_adv_enforcement_head_watermark",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "operational_transition_id",
                "operational_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_enforcement_head_control",
        ),
        sa.CheckConstraint(
            "cutover_sequence_number > 0 "
            "AND assignment_sequence_number > 0 "
            "AND cutover_observation_sequence > 0 "
            "AND fencing_generation > 0 "
            "AND assessment_disposition IN ('none', 'reject', 'pause', 'halt') "
            "AND cutover_at < assessment_valid_through "
            "AND cutover_at <= updated_at",
            name=op.f(f"ck_{_ENFORCEMENT_HEAD_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(assignment_id) = 36 "
            "AND length(assignment_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(assessment_id) = 36 "
            "AND length(assessment_sha256) = 64 "
            "AND length(cutover_evidence_id) = 36 "
            "AND length(cutover_evidence_sha256) = 64 "
            "AND length(operational_transition_id) = 36 "
            "AND length(operational_transition_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 2097152",
            name=op.f(f"ck_{_ENFORCEMENT_HEAD_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_enforcement_head_time",
        _ENFORCEMENT_HEAD_TABLE,
        ["updated_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    table_names = (
        _ENFORCEMENT_HEAD_TABLE,
        _ADMISSION_TABLE,
        _ASSESSMENT_TABLE,
        _SOURCE_TABLE,
        _EVIDENCE_TABLE,
        _ASSIGNMENT_HEAD_TABLE,
        _ASSIGNMENT_TABLE,
        _POLICY_TABLE,
    )
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("LOCK TABLE " + ", ".join(table_names) + " IN SHARE ROW EXCLUSIVE MODE")
        )
    for table_name in table_names:
        table = sa.table(table_name)
        if int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0):
            raise RuntimeError("refusing to downgrade nonempty advanced-risk history")

    op.drop_index(
        "ix_phase5_adv_enforcement_head_time",
        table_name=_ENFORCEMENT_HEAD_TABLE,
    )
    op.drop_table(_ENFORCEMENT_HEAD_TABLE)
    op.drop_index(
        "ix_phase5_adv_admission_account_time",
        table_name=_ADMISSION_TABLE,
    )
    op.drop_table(_ADMISSION_TABLE)
    op.drop_index(
        "ix_phase5_adv_assessment_account_time",
        table_name=_ASSESSMENT_TABLE,
    )
    op.drop_table(_ASSESSMENT_TABLE)
    op.drop_table(_SOURCE_TABLE)
    op.drop_index(
        "ix_phase5_adv_evidence_rule_time",
        table_name=_EVIDENCE_TABLE,
    )
    op.drop_index(
        "ix_phase5_adv_evidence_account_time",
        table_name=_EVIDENCE_TABLE,
    )
    op.drop_table(_EVIDENCE_TABLE)
    op.drop_table(_ASSIGNMENT_HEAD_TABLE)
    op.drop_index(
        "ix_phase5_adv_assignment_account_time",
        table_name=_ASSIGNMENT_TABLE,
    )
    op.drop_table(_ASSIGNMENT_TABLE)
    op.drop_index(
        "ix_phase5_adv_policy_scope",
        table_name=_POLICY_TABLE,
    )
    op.drop_table(_POLICY_TABLE)
