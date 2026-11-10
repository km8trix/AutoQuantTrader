"""Add durable bounded UNKNOWN lookup scheduling.

Revision ID: 0016_phase4_unknown_schedule
Revises: 0015_phase4_lookup_observation
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_phase4_unknown_schedule"
down_revision: str | None = "0015_phase4_lookup_observation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLAN_TABLE = "phase4_unknown_lookup_recovery_plans"
_EVENT_TABLE = "phase4_unknown_lookup_recovery_events"
_HEAD_TABLE = "phase4_unknown_lookup_recovery_heads"
_ATTEMPT_SOURCE_INDEX = "ux_phase2_submission_attempt_recovery_source"
_LOOKUP_EXACT_INDEX = "ux_phase4_lookup_observation_recovery_exact"


def upgrade() -> None:
    op.create_index(
        _ATTEMPT_SOURCE_INDEX,
        "phase2_submission_attempts",
        ["account_id", "attempt_id", "client_order_id"],
        unique=True,
    )
    op.create_index(
        _LOOKUP_EXACT_INDEX,
        "phase4_alpaca_paper_lookup_observations",
        ["account_id", "attempt_id", "receipt_id", "semantic_sha256"],
        unique=True,
    )
    op.create_table(
        _PLAN_TABLE,
        sa.Column("plan_id", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("attempt_sha256", sa.String(64), nullable=False),
        sa.Column("client_order_id", sa.String(128), nullable=False),
        sa.Column("lookup_correlation_sha256", sa.String(64), nullable=False),
        sa.Column("in_flight_event_id", sa.String(64), nullable=False),
        sa.Column("in_flight_event_sha256", sa.String(64), nullable=False),
        sa.Column("in_flight_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("in_flight_occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("in_flight_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("unknown_event_id", sa.String(64), nullable=False),
        sa.Column("unknown_event_sha256", sa.String(64), nullable=False),
        sa.Column("unknown_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("unknown_occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("unknown_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recovery_deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("slot_count", sa.Integer(), nullable=False),
        sa.Column("slots_payload", sa.Text(), nullable=False),
        sa.Column("slots_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("plan_id", name=op.f(f"pk_{_PLAN_TABLE}")),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_PLAN_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "attempt_id",
            "unknown_event_id",
            name="uq_phase4_unknown_recovery_attempt_event",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "account_id",
            "attempt_id",
            "semantic_sha256",
            name="uq_phase4_unknown_recovery_plan_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_unknown_recovery_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "attempt_id", "client_order_id"],
            [
                "phase2_submission_attempts.account_id",
                "phase2_submission_attempts.attempt_id",
                "phase2_submission_attempts.client_order_id",
            ],
            name="fk_phase4_unknown_recovery_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id", "in_flight_event_id", "in_flight_event_sha256"],
            [
                "phase2_submission_attempt_events.attempt_id",
                "phase2_submission_attempt_events.event_id",
                "phase2_submission_attempt_events.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_in_flight",
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id", "unknown_event_id", "unknown_event_sha256"],
            [
                "phase2_submission_attempt_events.attempt_id",
                "phase2_submission_attempt_events.event_id",
                "phase2_submission_attempt_events.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_unknown",
        ),
        sa.CheckConstraint(
            "in_flight_sequence_number = 2 AND unknown_sequence_number = 3",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_unknown_recovery_source_sequence"),
        ),
        sa.CheckConstraint(
            "in_flight_occurred_at <= in_flight_recorded_at "
            "AND in_flight_occurred_at <= unknown_occurred_at "
            "AND in_flight_recorded_at <= unknown_recorded_at "
            "AND unknown_occurred_at <= unknown_recorded_at",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_unknown_recovery_source_time"),
        ),
        sa.CheckConstraint(
            "slot_count BETWEEN 0 AND 6",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_unknown_recovery_slot_count"),
        ),
        sa.CheckConstraint(
            "length(plan_id) = 64 "
            "AND length(attempt_sha256) = 64 "
            "AND length(lookup_correlation_sha256) = 64 "
            "AND length(in_flight_event_sha256) = 64 "
            "AND length(unknown_event_sha256) = 64 "
            "AND length(slots_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_unknown_recovery_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(slots_payload) BETWEEN 2 AND 32768 "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_unknown_recovery_payload_sizes"),
        ),
    )
    op.create_index(
        "ix_phase4_unknown_recovery_account_deadline",
        _PLAN_TABLE,
        ["account_id", "recovery_deadline_at"],
        unique=False,
    )
    op.create_table(
        _EVENT_TABLE,
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("plan_id", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("previous_event_sha256", sa.String(64), nullable=True),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluation_id", sa.String(64), nullable=True),
        sa.Column("evaluation_sha256", sa.String(64), nullable=True),
        sa.Column("evaluation_payload", sa.Text(), nullable=True),
        sa.Column("consumed_slot_ids_payload", sa.Text(), nullable=False),
        sa.Column("coalesced_slot_ids_payload", sa.Text(), nullable=False),
        sa.Column("selected_slot_ordinal", sa.Integer(), nullable=True),
        sa.Column("selected_slot_id", sa.String(64), nullable=True),
        sa.Column("selected_slot_sha256", sa.String(64), nullable=True),
        sa.Column("selected_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ticket_id", sa.String(64), nullable=True),
        sa.Column("ticket_sha256", sa.String(64), nullable=True),
        sa.Column("claim_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_dispatch_event_id", sa.String(64), nullable=True),
        sa.Column("source_dispatch_event_sha256", sa.String(64), nullable=True),
        sa.Column("lookup_receipt_id", sa.String(36), nullable=True),
        sa.Column("lookup_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("event_id", name=op.f(f"pk_{_EVENT_TABLE}")),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_EVENT_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "plan_id",
            "sequence_number",
            name="uq_phase4_unknown_recovery_event_sequence",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "semantic_sha256",
            name="uq_phase4_unknown_recovery_event_semantic",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "account_id",
            "attempt_id",
            "event_id",
            "semantic_sha256",
            name="uq_phase4_unknown_recovery_dispatch_exact",
        ),
        sa.UniqueConstraint(
            "plan_id",
            "account_id",
            "attempt_id",
            "sequence_number",
            "event_id",
            "semantic_sha256",
            name="uq_phase4_unknown_recovery_event_exact",
        ),
        sa.UniqueConstraint("ticket_id", name="uq_phase4_unknown_recovery_ticket"),
        sa.UniqueConstraint(
            "source_dispatch_event_id",
            name="uq_phase4_unknown_recovery_observed_dispatch",
        ),
        sa.UniqueConstraint(
            "lookup_receipt_id",
            name="uq_phase4_unknown_recovery_lookup_receipt",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id", "account_id", "attempt_id", "plan_sha256"],
            [
                f"{_PLAN_TABLE}.plan_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.attempt_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_event_plan",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fence_fencing_generation", "fence_lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_unknown_recovery_event_lease",
        ),
        sa.ForeignKeyConstraint(
            ["plan_id", "previous_event_sha256"],
            [f"{_EVENT_TABLE}.plan_id", f"{_EVENT_TABLE}.semantic_sha256"],
            name="fk_phase4_unknown_recovery_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "plan_id",
                "account_id",
                "attempt_id",
                "source_dispatch_event_id",
                "source_dispatch_event_sha256",
            ],
            [
                f"{_EVENT_TABLE}.plan_id",
                f"{_EVENT_TABLE}.account_id",
                f"{_EVENT_TABLE}.attempt_id",
                f"{_EVENT_TABLE}.event_id",
                f"{_EVENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_dispatch",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "attempt_id",
                "lookup_receipt_id",
                "lookup_receipt_sha256",
            ],
            [
                "phase4_alpaca_paper_lookup_observations.account_id",
                "phase4_alpaca_paper_lookup_observations.attempt_id",
                "phase4_alpaca_paper_lookup_observations.receipt_id",
                "phase4_alpaca_paper_lookup_observations.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_receipt",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND previous_event_sha256 IS NULL) "
            "OR (sequence_number > 1 AND previous_event_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_event_predecessor"),
        ),
        sa.CheckConstraint(
            "kind IN ('dispatch', 'observation', 'exhausted')",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_event_kind"),
        ),
        sa.CheckConstraint(
            "(kind = 'dispatch' "
            "AND evaluation_id IS NOT NULL AND evaluation_sha256 IS NOT NULL "
            "AND evaluation_payload IS NOT NULL "
            "AND selected_slot_ordinal IS NOT NULL "
            "AND selected_slot_id IS NOT NULL AND selected_slot_sha256 IS NOT NULL "
            "AND selected_scheduled_at IS NOT NULL "
            "AND ticket_id IS NOT NULL AND ticket_sha256 IS NOT NULL "
            "AND claim_issued_at IS NOT NULL AND claim_valid_until IS NOT NULL "
            "AND source_dispatch_event_id IS NULL "
            "AND source_dispatch_event_sha256 IS NULL "
            "AND lookup_receipt_id IS NULL AND lookup_receipt_sha256 IS NULL) "
            "OR (kind = 'observation' "
            "AND evaluation_id IS NULL AND evaluation_sha256 IS NULL "
            "AND evaluation_payload IS NULL "
            "AND selected_slot_ordinal IS NULL "
            "AND selected_slot_id IS NULL AND selected_slot_sha256 IS NULL "
            "AND selected_scheduled_at IS NULL "
            "AND ticket_id IS NULL AND ticket_sha256 IS NULL "
            "AND claim_issued_at IS NULL AND claim_valid_until IS NULL "
            "AND source_dispatch_event_id IS NOT NULL "
            "AND source_dispatch_event_sha256 IS NOT NULL "
            "AND lookup_receipt_id IS NOT NULL AND lookup_receipt_sha256 IS NOT NULL) "
            "OR (kind = 'exhausted' "
            "AND evaluation_id IS NOT NULL AND evaluation_sha256 IS NOT NULL "
            "AND evaluation_payload IS NOT NULL "
            "AND selected_slot_ordinal IS NULL "
            "AND selected_slot_id IS NULL AND selected_slot_sha256 IS NULL "
            "AND selected_scheduled_at IS NULL "
            "AND ticket_id IS NULL AND ticket_sha256 IS NULL "
            "AND claim_issued_at IS NULL AND claim_valid_until IS NULL "
            "AND source_dispatch_event_id IS NULL "
            "AND source_dispatch_event_sha256 IS NULL "
            "AND lookup_receipt_id IS NULL AND lookup_receipt_sha256 IS NULL)",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_event_shape"),
        ),
        sa.CheckConstraint(
            "(kind <> 'dispatch') "
            "OR (selected_slot_ordinal BETWEEN 1 AND 6 "
            "AND selected_scheduled_at <= claim_issued_at "
            "AND claim_issued_at < claim_valid_until "
            "AND committed_at = claim_issued_at)",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_claim_time"),
        ),
        sa.CheckConstraint(
            "committed_at < fence_valid_until "
            "AND fence_fencing_generation > 0 "
            "AND sequence_number > 0",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_event_time"),
        ),
        sa.CheckConstraint(
            "length(event_id) = 64 "
            "AND length(plan_id) = 64 "
            "AND length(plan_sha256) = 64 "
            "AND (previous_event_sha256 IS NULL OR length(previous_event_sha256) = 64) "
            "AND (evaluation_id IS NULL OR length(evaluation_id) = 64) "
            "AND (evaluation_sha256 IS NULL OR length(evaluation_sha256) = 64) "
            "AND (selected_slot_id IS NULL OR length(selected_slot_id) = 64) "
            "AND (selected_slot_sha256 IS NULL OR length(selected_slot_sha256) = 64) "
            "AND (ticket_id IS NULL OR length(ticket_id) = 64) "
            "AND (ticket_sha256 IS NULL OR length(ticket_sha256) = 64) "
            "AND (source_dispatch_event_sha256 IS NULL "
            "OR length(source_dispatch_event_sha256) = 64) "
            "AND (lookup_receipt_sha256 IS NULL "
            "OR length(lookup_receipt_sha256) = 64) "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(fence_lease_sha256) = 64 "
            "AND length(fence_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_event_hashes"),
        ),
        sa.CheckConstraint(
            "length(consumed_slot_ids_payload) BETWEEN 2 AND 4096 "
            "AND length(coalesced_slot_ids_payload) BETWEEN 2 AND 4096 "
            "AND (evaluation_payload IS NULL "
            "OR length(evaluation_payload) BETWEEN 2 AND 32768) "
            "AND length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_EVENT_TABLE}_phase4_unknown_recovery_event_payloads"),
        ),
    )
    op.create_index(
        "ix_phase4_unknown_recovery_event_plan_time",
        _EVENT_TABLE,
        ["plan_id", "committed_at"],
        unique=False,
    )
    op.create_table(
        _HEAD_TABLE,
        sa.Column("plan_id", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("last_event_id", sa.String(64), nullable=False),
        sa.Column("last_event_sha256", sa.String(64), nullable=False),
        sa.Column("last_committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_slot_ids_payload", sa.Text(), nullable=False),
        sa.Column("consumed_slot_count", sa.Integer(), nullable=False),
        sa.Column("issuance_status", sa.String(32), nullable=False),
        sa.PrimaryKeyConstraint("plan_id", name=op.f(f"pk_{_HEAD_TABLE}")),
        sa.ForeignKeyConstraint(
            ["plan_id", "account_id", "attempt_id", "plan_sha256"],
            [
                f"{_PLAN_TABLE}.plan_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.attempt_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_head_plan",
        ),
        sa.ForeignKeyConstraint(
            [
                "plan_id",
                "account_id",
                "attempt_id",
                "last_sequence_number",
                "last_event_id",
                "last_event_sha256",
            ],
            [
                f"{_EVENT_TABLE}.plan_id",
                f"{_EVENT_TABLE}.account_id",
                f"{_EVENT_TABLE}.attempt_id",
                f"{_EVENT_TABLE}.sequence_number",
                f"{_EVENT_TABLE}.event_id",
                f"{_EVENT_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_unknown_recovery_head_event",
        ),
        sa.CheckConstraint(
            "last_sequence_number > 0 "
            "AND consumed_slot_count BETWEEN 0 AND 6 "
            "AND issuance_status IN "
            "('active', 'exhausted', 'reconciliation_required', 'blocked_mismatch')",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_unknown_recovery_head_state"),
        ),
        sa.CheckConstraint(
            "length(plan_id) = 64 "
            "AND length(plan_sha256) = 64 "
            "AND length(last_event_id) = 64 "
            "AND length(last_event_sha256) = 64 "
            "AND length(consumed_slot_ids_payload) BETWEEN 2 AND 4096",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_unknown_recovery_head_shape"),
        ),
    )
    op.create_index(
        "ix_phase4_unknown_recovery_head_account_status",
        _HEAD_TABLE,
        ["account_id", "issuance_status"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE phase4_unknown_lookup_recovery_heads, "
            "phase4_unknown_lookup_recovery_events, "
            "phase4_unknown_lookup_recovery_plans, "
            "phase4_alpaca_paper_lookup_observations, "
            "phase2_submission_attempts IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}"))
        for table_name in (_HEAD_TABLE, _EVENT_TABLE, _PLAN_TABLE)
    )
    if any(counts):
        raise RuntimeError(
            "refusing to downgrade nonempty UNKNOWN lookup recovery schedule history"
        )
    op.drop_index(
        "ix_phase4_unknown_recovery_head_account_status",
        table_name=_HEAD_TABLE,
    )
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_unknown_recovery_event_plan_time",
        table_name=_EVENT_TABLE,
    )
    op.drop_table(_EVENT_TABLE)
    op.drop_index(
        "ix_phase4_unknown_recovery_account_deadline",
        table_name=_PLAN_TABLE,
    )
    op.drop_table(_PLAN_TABLE)
    op.drop_index(
        _LOOKUP_EXACT_INDEX,
        table_name="phase4_alpaca_paper_lookup_observations",
    )
    op.drop_index(
        _ATTEMPT_SOURCE_INDEX,
        table_name="phase2_submission_attempts",
    )
