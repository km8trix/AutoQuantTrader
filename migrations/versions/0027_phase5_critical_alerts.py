"""Add durable Phase 5D critical-alert delivery evidence.

Revision ID: 0027_phase5_critical_alerts
Revises: 0026_phase5_advanced_risk
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027_phase5_critical_alerts"
down_revision: str | None = "0026_phase5_advanced_risk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INCIDENT_TABLE = "phase5_critical_alert_incidents"
_ATTEMPT_TABLE = "phase5_critical_alert_delivery_attempts"
_RESULT_TABLE = "phase5_critical_alert_delivery_results"


def upgrade() -> None:
    op.create_table(
        _INCIDENT_TABLE,
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(128), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("alert_code", sa.String(128), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "incident_id",
            name=op.f(f"pk_{_INCIDENT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "scope_id",
            "source_id",
            "idempotency_key",
            name="uq_phase5_critical_alert_source_key",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name="uq_phase5_critical_alert_incident_semantic",
        ),
        sa.UniqueConstraint(
            "incident_id",
            "semantic_sha256",
            name="uq_phase5_critical_alert_incident_exact",
        ),
        sa.CheckConstraint(
            "recorded_at >= detected_at",
            name=op.f(f"ck_{_INCIDENT_TABLE}_time"),
        ),
        sa.CheckConstraint(
            "length(incident_id) = 36 "
            "AND length(scope_id) BETWEEN 1 AND 128 "
            "AND length(source_id) BETWEEN 1 AND 128 "
            "AND length(idempotency_key) BETWEEN 8 AND 128 "
            "AND length(alert_code) BETWEEN 1 AND 128 "
            "AND length(evidence_sha256) = 64 "
            "AND length(correlation_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_INCIDENT_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_critical_alert_incident_recorded",
        _INCIDENT_TABLE,
        ["recorded_at", "incident_id"],
        unique=False,
    )

    op.create_table(
        _ATTEMPT_TABLE,
        sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("incident_sha256", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("previous_attempt_id", sa.String(36), nullable=True),
        sa.Column("previous_attempt_sha256", sa.String(64), nullable=True),
        sa.Column("route", sa.String(24), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("command_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "attempt_id",
            name=op.f(f"pk_{_ATTEMPT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "incident_id",
            "sequence_number",
            name="uq_phase5_critical_alert_attempt_sequence",
        ),
        sa.UniqueConstraint(
            "incident_id",
            "provider_id",
            "idempotency_key",
            name="uq_phase5_critical_alert_attempt_provider_key",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name="uq_phase5_critical_alert_attempt_semantic",
        ),
        sa.UniqueConstraint(
            "incident_id",
            "attempt_id",
            "semantic_sha256",
            name="uq_phase5_critical_alert_attempt_exact",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "incident_sha256"],
            [
                f"{_INCIDENT_TABLE}.incident_id",
                f"{_INCIDENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_critical_alert_attempt_incident",
        ),
        sa.ForeignKeyConstraint(
            [
                "incident_id",
                "previous_attempt_id",
                "previous_attempt_sha256",
            ],
            [
                f"{_ATTEMPT_TABLE}.incident_id",
                f"{_ATTEMPT_TABLE}.attempt_id",
                f"{_ATTEMPT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_critical_alert_attempt_predecessor",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND previous_attempt_id IS NULL "
            "AND previous_attempt_sha256 IS NULL) "
            "OR (sequence_number > 1 AND previous_attempt_id IS NOT NULL "
            "AND previous_attempt_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_ATTEMPT_TABLE}_predecessor"),
        ),
        sa.CheckConstraint(
            "sequence_number BETWEEN 1 AND 1024 "
            "AND claimed_at >= requested_at "
            "AND route IN ('primary', 'escalation')",
            name=op.f(f"ck_{_ATTEMPT_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "length(attempt_id) = 36 "
            "AND length(incident_id) = 36 "
            "AND length(incident_sha256) = 64 "
            "AND (previous_attempt_id IS NULL "
            "OR length(previous_attempt_id) = 36) "
            "AND (previous_attempt_sha256 IS NULL "
            "OR length(previous_attempt_sha256) = 64) "
            "AND length(provider_id) BETWEEN 1 AND 128 "
            "AND length(idempotency_key) BETWEEN 8 AND 128 "
            "AND length(request_sha256) = 64 "
            "AND length(command_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_ATTEMPT_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_critical_alert_attempt_incident",
        _ATTEMPT_TABLE,
        ["incident_id", "sequence_number"],
        unique=False,
    )

    op.create_table(
        _RESULT_TABLE,
        sa.Column("result_id", sa.String(36), nullable=False),
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("incident_sha256", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("attempt_sha256", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("elapsed_microseconds", sa.BigInteger(), nullable=False),
        sa.Column("provider_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("failure_code", sa.String(128), nullable=True),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "result_id",
            name=op.f(f"pk_{_RESULT_TABLE}"),
        ),
        sa.UniqueConstraint(
            "attempt_id",
            name="uq_phase5_critical_alert_result_attempt",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name="uq_phase5_critical_alert_result_semantic",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "incident_sha256"],
            [
                f"{_INCIDENT_TABLE}.incident_id",
                f"{_INCIDENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_critical_alert_result_incident",
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "attempt_id", "attempt_sha256"],
            [
                f"{_ATTEMPT_TABLE}.incident_id",
                f"{_ATTEMPT_TABLE}.attempt_id",
                f"{_ATTEMPT_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_critical_alert_result_attempt",
        ),
        sa.CheckConstraint(
            "elapsed_microseconds >= 0 "
            "AND outcome IN ('confirmed', 'timeout', 'error') "
            "AND ((outcome = 'confirmed' "
            "AND provider_receipt_sha256 IS NOT NULL "
            "AND failure_code IS NULL) "
            "OR (outcome <> 'confirmed' "
            "AND provider_receipt_sha256 IS NULL "
            "AND failure_code IS NOT NULL))",
            name=op.f(f"ck_{_RESULT_TABLE}_outcome"),
        ),
        sa.CheckConstraint(
            "length(result_id) = 36 "
            "AND length(incident_id) = 36 "
            "AND length(incident_sha256) = 64 "
            "AND length(attempt_id) = 36 "
            "AND length(attempt_sha256) = 64 "
            "AND (provider_receipt_sha256 IS NULL "
            "OR length(provider_receipt_sha256) = 64) "
            "AND (failure_code IS NULL "
            "OR length(failure_code) BETWEEN 1 AND 128) "
            "AND length(semantic_sha256) = 64 "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_RESULT_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_critical_alert_result_completed",
        _RESULT_TABLE,
        ["completed_at", "result_id"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    table_names = (
        _RESULT_TABLE,
        _ATTEMPT_TABLE,
        _INCIDENT_TABLE,
    )
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("LOCK TABLE " + ", ".join(table_names) + " IN SHARE ROW EXCLUSIVE MODE")
        )
    for table_name in table_names:
        table = sa.table(table_name)
        if int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0):
            raise RuntimeError("refusing to downgrade nonempty critical-alert history")

    op.drop_index(
        "ix_phase5_critical_alert_result_completed",
        table_name=_RESULT_TABLE,
    )
    op.drop_table(_RESULT_TABLE)
    op.drop_index(
        "ix_phase5_critical_alert_attempt_incident",
        table_name=_ATTEMPT_TABLE,
    )
    op.drop_table(_ATTEMPT_TABLE)
    op.drop_index(
        "ix_phase5_critical_alert_incident_recorded",
        table_name=_INCIDENT_TABLE,
    )
    op.drop_table(_INCIDENT_TABLE)
