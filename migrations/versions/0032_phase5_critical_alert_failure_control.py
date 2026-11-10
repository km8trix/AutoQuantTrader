"""Add local atomic critical-alert total-failure control receipts.

Revision ID: 0032_phase5_alert_fail_control
Revises: 0031_phase5_strategy_claims
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032_phase5_alert_fail_control"
down_revision: str | None = "0031_phase5_strategy_claims"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RECEIPT_TABLE = "phase5_critical_alert_failure_control_receipts"
_RESULT_TABLE = "phase5_critical_alert_delivery_results"
_RESULT_EXACT_UNIQUE = "uq_phase5_critical_alert_result_exact"


def _lock_postgresql_tables(
    connection: sa.Connection,
    *table_names: str,
) -> None:
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("LOCK TABLE " + ", ".join(table_names) + " IN SHARE ROW EXCLUSIVE MODE")
        )


def upgrade() -> None:
    with op.batch_alter_table(_RESULT_TABLE) as batch_op:
        batch_op.create_unique_constraint(
            _RESULT_EXACT_UNIQUE,
            ["incident_id", "attempt_id", "result_id", "semantic_sha256"],
        )

    op.create_table(
        _RECEIPT_TABLE,
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("incident_sha256", sa.String(64), nullable=False),
        sa.Column("route_plan_id", sa.String(128), nullable=False),
        sa.Column("route_plan_version", sa.String(128), nullable=False),
        sa.Column("route_plan_sha256", sa.String(64), nullable=False),
        sa.Column("primary_provider_id", sa.String(128), nullable=False),
        sa.Column("primary_destination_sha256", sa.String(64), nullable=False),
        sa.Column("primary_recipient_set_sha256", sa.String(64), nullable=False),
        sa.Column("escalation_provider_id", sa.String(128), nullable=False),
        sa.Column("escalation_destination_sha256", sa.String(64), nullable=False),
        sa.Column("escalation_recipient_set_sha256", sa.String(64), nullable=False),
        sa.Column("supervisor_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("supervisor_disposition", sa.String(32), nullable=False),
        sa.Column("supervisor_reason", sa.String(64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("selected_route", sa.String(24), nullable=False),
        sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("attempt_sha256", sa.String(64), nullable=False),
        sa.Column("result_id", sa.String(36), nullable=True),
        sa.Column("result_sha256", sa.String(64), nullable=True),
        sa.Column("provider_called", sa.Boolean(), nullable=False),
        sa.Column("unresolved_claim", sa.Boolean(), nullable=False),
        sa.Column("actor_authority_sha256", sa.String(64), nullable=False),
        sa.Column("control_policy_sha256", sa.String(64), nullable=False),
        sa.Column("control_command_id", sa.String(36), nullable=False),
        sa.Column("control_command_sha256", sa.String(64), nullable=False),
        sa.Column("pre_control_transition_id", sa.String(36), nullable=False),
        sa.Column("pre_control_transition_sha256", sa.String(64), nullable=False),
        sa.Column("pre_control_state", sa.String(24), nullable=False),
        sa.Column("final_control_transition_id", sa.String(36), nullable=False),
        sa.Column("final_control_transition_sha256", sa.String(64), nullable=False),
        sa.Column("final_control_state", sa.String(24), nullable=False),
        sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("receipt_id", name=op.f(f"pk_{_RECEIPT_TABLE}")),
        sa.UniqueConstraint(
            "incident_id",
            name=op.f(f"uq_{_RECEIPT_TABLE}_incident_id"),
        ),
        sa.UniqueConstraint(
            "supervisor_evidence_sha256",
            name=op.f(f"uq_{_RECEIPT_TABLE}_supervisor_evidence_sha256"),
        ),
        sa.UniqueConstraint(
            "control_command_id",
            name=op.f(f"uq_{_RECEIPT_TABLE}_control_command_id"),
        ),
        sa.UniqueConstraint(
            "control_command_sha256",
            name=op.f(f"uq_{_RECEIPT_TABLE}_control_command_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_RECEIPT_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_alert_failure_control_account",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "incident_sha256"],
            [
                "phase5_critical_alert_incidents.incident_id",
                "phase5_critical_alert_incidents.semantic_sha256",
            ],
            name="fk_phase5_alert_failure_control_incident",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "attempt_id", "attempt_sha256"],
            [
                "phase5_critical_alert_delivery_attempts.incident_id",
                "phase5_critical_alert_delivery_attempts.attempt_id",
                "phase5_critical_alert_delivery_attempts.semantic_sha256",
            ],
            name="fk_phase5_alert_failure_control_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "attempt_id", "result_id", "result_sha256"],
            [
                "phase5_critical_alert_delivery_results.incident_id",
                "phase5_critical_alert_delivery_results.attempt_id",
                "phase5_critical_alert_delivery_results.result_id",
                "phase5_critical_alert_delivery_results.semantic_sha256",
            ],
            name="fk_phase5_alert_failure_control_result",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "pre_control_transition_id", "pre_control_transition_sha256"],
            [
                "phase5_operational_control_transitions.account_id",
                "phase5_operational_control_transitions.transition_id",
                "phase5_operational_control_transitions.semantic_sha256",
            ],
            name="fk_phase5_alert_failure_control_pre_control",
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
            name="fk_phase5_alert_failure_control_final_control",
        ),
        sa.CheckConstraint(
            "supervisor_disposition = 'total_delivery_failure' "
            "AND selected_route = 'escalation' AND bound_at >= observed_at",
            name=op.f(f"ck_{_RECEIPT_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "(unresolved_claim "
            "AND supervisor_reason = 'escalation_deadline_unresolved' "
            "AND result_id IS NULL AND result_sha256 IS NULL) "
            "OR (NOT unresolved_claim "
            "AND supervisor_reason = 'escalation_attempt_failed' "
            "AND result_id IS NOT NULL AND result_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_RECEIPT_TABLE}_failure_shape"),
        ),
        sa.CheckConstraint(
            "(pre_control_state = 'running' AND final_control_state = 'paused') "
            "OR (pre_control_state = 'paused' AND final_control_state = 'paused') "
            "OR (pre_control_state = 'draining' AND final_control_state = 'draining') "
            "OR (pre_control_state = 'flattening' "
            "AND final_control_state = 'flattening') "
            "OR (pre_control_state = 'halted' AND final_control_state = 'halted')",
            name=op.f(f"ck_{_RECEIPT_TABLE}_severity"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 36 "
            "AND length(account_id) BETWEEN 1 AND 64 "
            "AND length(incident_id) = 36 "
            "AND length(incident_sha256) = 64 "
            "AND length(route_plan_id) BETWEEN 1 AND 128 "
            "AND length(route_plan_version) BETWEEN 1 AND 128 "
            "AND length(route_plan_sha256) = 64 "
            "AND length(primary_provider_id) BETWEEN 1 AND 128 "
            "AND length(primary_destination_sha256) = 64 "
            "AND length(primary_recipient_set_sha256) = 64 "
            "AND length(escalation_provider_id) BETWEEN 1 AND 128 "
            "AND length(escalation_destination_sha256) = 64 "
            "AND length(escalation_recipient_set_sha256) = 64 "
            "AND length(supervisor_evidence_sha256) = 64 "
            "AND length(attempt_id) = 36 "
            "AND length(attempt_sha256) = 64 "
            "AND (result_id IS NULL OR length(result_id) = 36) "
            "AND (result_sha256 IS NULL OR length(result_sha256) = 64) "
            "AND length(actor_authority_sha256) = 64 "
            "AND length(control_policy_sha256) = 64 "
            "AND length(control_command_id) = 36 "
            "AND length(control_command_sha256) = 64 "
            "AND length(pre_control_transition_id) = 36 "
            "AND length(pre_control_transition_sha256) = 64 "
            "AND length(final_control_transition_id) = 36 "
            "AND length(final_control_transition_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f(f"ck_{_RECEIPT_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_alert_failure_control_account_time",
        _RECEIPT_TABLE,
        ["account_id", "bound_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    _lock_postgresql_tables(
        connection,
        _RECEIPT_TABLE,
        _RESULT_TABLE,
    )
    if connection.scalar(
        sa.select(sa.func.count()).select_from(sa.table(_RECEIPT_TABLE, sa.column("receipt_id")))
    ):
        raise RuntimeError("refusing to downgrade nonempty critical-alert failure-control history")
    op.drop_index(
        "ix_phase5_alert_failure_control_account_time",
        table_name=_RECEIPT_TABLE,
    )
    op.drop_table(_RECEIPT_TABLE)
    with op.batch_alter_table(_RESULT_TABLE) as batch_op:
        batch_op.drop_constraint(_RESULT_EXACT_UNIQUE, type_="unique")
