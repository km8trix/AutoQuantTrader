"""Add durable Phase 5C strategy-supervision results.

Revision ID: 0028_phase5_strategy_supervision
Revises: 0027_phase5_critical_alerts
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028_phase5_strategy_supervision"
down_revision: str | None = "0027_phase5_critical_alerts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "phase5_strategy_supervision_results"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("invocation_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("invocation_sha256", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("market_batch_id", sa.String(128), nullable=False),
        sa.Column("market_batch_sha256", sa.String(64), nullable=False),
        sa.Column("strategy_id", sa.String(128), nullable=False),
        sa.Column("strategy_version", sa.String(64), nullable=False),
        sa.Column("strategy_configuration_sha256", sa.String(64), nullable=False),
        sa.Column("runtime_sha256", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("elapsed_microseconds", sa.BigInteger(), nullable=False),
        sa.Column("process_started", sa.Boolean(), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout_bytes", sa.BigInteger(), nullable=False),
        sa.Column("stdout_sha256", sa.String(64), nullable=False),
        sa.Column("stderr_bytes", sa.BigInteger(), nullable=False),
        sa.Column("stderr_sha256", sa.String(64), nullable=False),
        sa.Column("detail_code", sa.String(128), nullable=False),
        sa.Column("response_sha256", sa.String(64), nullable=True),
        sa.Column("response_result_sha256", sa.String(64), nullable=True),
        sa.Column("response_result_json", sa.Text(), nullable=True),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("pre_control_transition_id", sa.String(36), nullable=False),
        sa.Column("pre_control_transition_sha256", sa.String(64), nullable=False),
        sa.Column("final_control_transition_id", sa.String(36), nullable=False),
        sa.Column("final_control_transition_sha256", sa.String(64), nullable=False),
        sa.Column("critical_alert_incident_id", sa.String(36), nullable=True),
        sa.Column("critical_alert_incident_sha256", sa.String(64), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invocation_payload", sa.Text(), nullable=False),
        sa.Column("result_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("invocation_id", name=op.f(f"pk_{_TABLE}")),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "invocation_id",
            "invocation_sha256",
            name="uq_phase5_strategy_supervision_exact_invocation",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_strategy_supervision_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_strategy_supervision_lease",
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
            name="fk_phase5_strategy_supervision_pre_control",
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
            name="fk_phase5_strategy_supervision_final_control",
        ),
        sa.ForeignKeyConstraint(
            ["critical_alert_incident_id"],
            ["phase5_critical_alert_incidents.incident_id"],
            name="fk_phase5_strategy_supervision_critical_alert",
        ),
        sa.CheckConstraint(
            "outcome IN "
            "('completed', 'timeout', 'crash', 'protocol_error', 'resource_exceeded') "
            "AND started_at <= completed_at "
            "AND completed_at <= recorded_at "
            "AND elapsed_microseconds >= 0 "
            "AND stdout_bytes BETWEEN 0 AND 262145 "
            "AND stderr_bytes BETWEEN 0 AND 65537 "
            "AND fencing_generation > 0",
            name=op.f(f"ck_{_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "process_started OR exit_code IS NULL",
            name=op.f(f"ck_{_TABLE}_process_shape"),
        ),
        sa.CheckConstraint(
            "(outcome = 'completed' "
            "AND process_started AND exit_code = 0 "
            "AND response_sha256 IS NOT NULL "
            "AND response_result_sha256 IS NOT NULL "
            "AND response_result_json IS NOT NULL "
            "AND pre_control_transition_id = final_control_transition_id "
            "AND pre_control_transition_sha256 = final_control_transition_sha256 "
            "AND critical_alert_incident_id IS NULL "
            "AND critical_alert_incident_sha256 IS NULL) "
            "OR (outcome <> 'completed' "
            "AND response_sha256 IS NULL "
            "AND response_result_sha256 IS NULL "
            "AND response_result_json IS NULL "
            "AND critical_alert_incident_id IS NOT NULL "
            "AND critical_alert_incident_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_TABLE}_outcome_shape"),
        ),
        sa.CheckConstraint(
            "length(invocation_id) = 36 "
            "AND length(invocation_sha256) = 64 "
            "AND length(market_batch_sha256) = 64 "
            "AND length(strategy_configuration_sha256) = 64 "
            "AND length(runtime_sha256) = 64 "
            "AND length(stdout_sha256) = 64 "
            "AND length(stderr_sha256) = 64 "
            "AND (response_sha256 IS NULL OR length(response_sha256) = 64) "
            "AND (response_result_sha256 IS NULL "
            "OR length(response_result_sha256) = 64) "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(pre_control_transition_id) = 36 "
            "AND length(pre_control_transition_sha256) = 64 "
            "AND length(final_control_transition_id) = 36 "
            "AND length(final_control_transition_sha256) = 64 "
            "AND (critical_alert_incident_id IS NULL "
            "OR length(critical_alert_incident_id) = 36) "
            "AND (critical_alert_incident_sha256 IS NULL "
            "OR length(critical_alert_incident_sha256) = 64) "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "length(environment) BETWEEN 1 AND 32 "
            "AND length(market_batch_id) BETWEEN 1 AND 128 "
            "AND length(strategy_id) BETWEEN 1 AND 128 "
            "AND length(strategy_version) BETWEEN 1 AND 64 "
            "AND length(detail_code) BETWEEN 1 AND 128 "
            "AND (response_result_json IS NULL "
            "OR length(response_result_json) BETWEEN 1 AND 262144) "
            "AND length(invocation_payload) BETWEEN 2 AND 1048576 "
            "AND length(result_payload) BETWEEN 2 AND 1048576",
            name=op.f(f"ck_{_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_strategy_supervision_account_time",
        _TABLE,
        ["account_id", "completed_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.execute(sa.text(f"LOCK TABLE {_TABLE} IN SHARE ROW EXCLUSIVE MODE"))
    table = sa.table(_TABLE)
    if int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0):
        raise RuntimeError("refusing to downgrade nonempty strategy-supervision history")
    op.drop_index(
        "ix_phase5_strategy_supervision_account_time",
        table_name=_TABLE,
    )
    op.drop_table(_TABLE)
