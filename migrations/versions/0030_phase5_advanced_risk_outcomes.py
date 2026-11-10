"""Add restart-safe atomic Phase 5B batch outcome receipts.

Revision ID: 0030_phase5_adv_outcomes
Revises: 0029_phase4_account_activities
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030_phase5_adv_outcomes"
down_revision: str | None = "0029_phase4_account_activities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OUTCOME_TABLE = "phase5_advanced_risk_batch_outcomes"
_DECISION_EXACT_UNIQUE = "decision_account_generation_exact"
_ADMISSION_EXACT_UNIQUE = "uq_phase5_adv_admission_exact"


def upgrade() -> None:
    with op.batch_alter_table("phase2_batch_decisions") as batch_op:
        batch_op.create_unique_constraint(
            _DECISION_EXACT_UNIQUE,
            [
                "decision_id",
                "account_id",
                "fencing_generation",
                "semantic_sha256",
            ],
        )
    with op.batch_alter_table("phase5_advanced_risk_batch_admissions") as batch_op:
        batch_op.create_unique_constraint(
            _ADMISSION_EXACT_UNIQUE,
            [
                "admission_id",
                "account_id",
                "phase2_decision_id",
                "semantic_sha256",
            ],
        )

    op.create_table(
        _OUTCOME_TABLE,
        sa.Column("outcome_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("intent_batch_id", sa.String(64), nullable=False),
        sa.Column("intent_batch_sha256", sa.String(64), nullable=False),
        sa.Column("watermark_id", sa.String(36), nullable=False),
        sa.Column("watermark_sha256", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("target_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_version", sa.String(128), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("active_capacity_sha256", sa.String(64), nullable=False),
        sa.Column("phase2_policy_sha256", sa.String(64), nullable=False),
        sa.Column("advanced_risk_policy_sha256", sa.String(64), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("runtime_instrument_ids_payload", sa.Text(), nullable=False),
        sa.Column("pretrade_instrument_ids_payload", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assignment_id", sa.String(36), nullable=False),
        sa.Column("assignment_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("assignment_sha256", sa.String(64), nullable=False),
        sa.Column("runtime_assessment_id", sa.String(36), nullable=False),
        sa.Column("runtime_assessment_sha256", sa.String(64), nullable=False),
        sa.Column("pretrade_assessment_id", sa.String(36), nullable=True),
        sa.Column("pretrade_assessment_sha256", sa.String(64), nullable=True),
        sa.Column("pre_control_transition_id", sa.String(36), nullable=False),
        sa.Column("pre_control_transition_sha256", sa.String(64), nullable=False),
        sa.Column("final_control_transition_id", sa.String(36), nullable=False),
        sa.Column("final_control_transition_sha256", sa.String(64), nullable=False),
        sa.Column("final_control_state", sa.String(16), nullable=False),
        sa.Column("phase2_decision_id", sa.String(64), nullable=True),
        sa.Column("phase2_decision_sha256", sa.String(64), nullable=True),
        sa.Column("admission_id", sa.String(36), nullable=True),
        sa.Column("admission_sha256", sa.String(64), nullable=True),
        sa.Column("outcome_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("outcome_id", name=op.f(f"pk_{_OUTCOME_TABLE}")),
        sa.UniqueConstraint(
            "intent_batch_id",
            name=op.f(f"uq_{_OUTCOME_TABLE}_intent_batch_id"),
        ),
        sa.UniqueConstraint(
            "watermark_id",
            name=op.f(f"uq_{_OUTCOME_TABLE}_watermark_id"),
        ),
        sa.UniqueConstraint(
            "watermark_sha256",
            name=op.f(f"uq_{_OUTCOME_TABLE}_watermark_sha256"),
        ),
        sa.UniqueConstraint(
            "outcome_sha256",
            name=op.f(f"uq_{_OUTCOME_TABLE}_outcome_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_OUTCOME_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_adv_outcome_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_adv_outcome_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "assignment_id",
                "assignment_sequence_number",
                "advanced_risk_policy_sha256",
                "assignment_sha256",
            ],
            [
                "phase5_advanced_risk_assignments.account_id",
                "phase5_advanced_risk_assignments.assignment_id",
                "phase5_advanced_risk_assignments.sequence_number",
                "phase5_advanced_risk_assignments.policy_sha256",
                "phase5_advanced_risk_assignments.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_assignment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "runtime_assessment_id",
                "runtime_assessment_sha256",
            ],
            [
                "phase5_advanced_risk_assessments.account_id",
                "phase5_advanced_risk_assessments.assessment_id",
                "phase5_advanced_risk_assessments.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_runtime_assessment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "pretrade_assessment_id",
                "pretrade_assessment_sha256",
            ],
            [
                "phase5_advanced_risk_assessments.account_id",
                "phase5_advanced_risk_assessments.assessment_id",
                "phase5_advanced_risk_assessments.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_pretrade_assessment",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "pre_control_transition_id",
                "pre_control_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_pre_control",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "final_control_transition_id",
                "final_control_transition_sha256",
            ],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_final_control",
        ),
        sa.ForeignKeyConstraint(
            [
                "phase2_decision_id",
                "account_id",
                "fencing_generation",
                "phase2_decision_sha256",
            ],
            [
                "phase2_batch_decisions.decision_id",
                "phase2_batch_decisions.account_id",
                "phase2_batch_decisions.fencing_generation",
                "phase2_batch_decisions.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_phase2_decision",
        ),
        sa.ForeignKeyConstraint(
            [
                "admission_id",
                "account_id",
                "phase2_decision_id",
                "admission_sha256",
            ],
            [
                "phase5_advanced_risk_batch_admissions.admission_id",
                "phase5_advanced_risk_batch_admissions.account_id",
                "phase5_advanced_risk_batch_admissions.phase2_decision_id",
                "phase5_advanced_risk_batch_admissions.semantic_sha256",
            ],
            name="fk_phase5_adv_outcome_admission",
        ),
        sa.CheckConstraint(
            "fencing_generation > 0 "
            "AND assignment_sequence_number > 0 "
            "AND final_control_state IN "
            "('running', 'paused', 'draining', 'flattening', 'halted')",
            name=op.f(f"ck_{_OUTCOME_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "(pretrade_assessment_id IS NULL "
            "AND pretrade_assessment_sha256 IS NULL) "
            "OR (pretrade_assessment_id IS NOT NULL "
            "AND pretrade_assessment_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_OUTCOME_TABLE}_pretrade_shape"),
        ),
        sa.CheckConstraint(
            "(phase2_decision_id IS NULL "
            "AND phase2_decision_sha256 IS NULL "
            "AND admission_id IS NULL "
            "AND admission_sha256 IS NULL) "
            "OR (phase2_decision_id IS NOT NULL "
            "AND phase2_decision_sha256 IS NOT NULL "
            "AND admission_id IS NOT NULL "
            "AND admission_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_OUTCOME_TABLE}_decision_shape"),
        ),
        sa.CheckConstraint(
            "length(outcome_id) = 36 "
            "AND length(intent_batch_sha256) = 64 "
            "AND length(watermark_id) = 36 "
            "AND length(watermark_sha256) = 64 "
            "AND length(target_sha256) = 64 "
            "AND length(snapshot_sha256) = 64 "
            "AND length(active_capacity_sha256) = 64 "
            "AND length(phase2_policy_sha256) = 64 "
            "AND length(advanced_risk_policy_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(assignment_id) = 36 "
            "AND length(assignment_sha256) = 64 "
            "AND length(runtime_assessment_id) = 36 "
            "AND length(runtime_assessment_sha256) = 64 "
            "AND (pretrade_assessment_id IS NULL "
            "OR length(pretrade_assessment_id) = 36) "
            "AND (pretrade_assessment_sha256 IS NULL "
            "OR length(pretrade_assessment_sha256) = 64) "
            "AND length(pre_control_transition_id) = 36 "
            "AND length(pre_control_transition_sha256) = 64 "
            "AND length(final_control_transition_id) = 36 "
            "AND length(final_control_transition_sha256) = 64 "
            "AND (phase2_decision_sha256 IS NULL "
            "OR length(phase2_decision_sha256) = 64) "
            "AND (admission_id IS NULL OR length(admission_id) = 36) "
            "AND (admission_sha256 IS NULL OR length(admission_sha256) = 64) "
            "AND length(outcome_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_OUTCOME_TABLE}_identity"),
        ),
        sa.CheckConstraint(
            "length(account_id) BETWEEN 1 AND 64 "
            "AND length(intent_batch_id) BETWEEN 1 AND 64 "
            "AND length(target_id) BETWEEN 1 AND 64 "
            "AND length(snapshot_version) BETWEEN 1 AND 128 "
            "AND length(runtime_instrument_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(pretrade_instrument_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(canonical_payload) BETWEEN 2 AND 4194304",
            name=op.f(f"ck_{_OUTCOME_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_adv_outcome_account_time",
        _OUTCOME_TABLE,
        ["account_id", "evaluated_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.scalar(
        sa.select(sa.func.count()).select_from(sa.table(_OUTCOME_TABLE, sa.column("outcome_id")))
    ):
        raise RuntimeError("refusing to downgrade nonempty advanced-risk outcome history")
    op.drop_index(
        "ix_phase5_adv_outcome_account_time",
        table_name=_OUTCOME_TABLE,
    )
    op.drop_table(_OUTCOME_TABLE)
    with op.batch_alter_table("phase5_advanced_risk_batch_admissions") as batch_op:
        batch_op.drop_constraint(_ADMISSION_EXACT_UNIQUE, type_="unique")
    with op.batch_alter_table("phase2_batch_decisions") as batch_op:
        batch_op.drop_constraint(_DECISION_EXACT_UNIQUE, type_="unique")
