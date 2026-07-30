"""Add the durable Phase 5 operational-control spine.

Revision ID: 0025_phase5_operational_control
Revises: 0024_phase4_order_transition
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_phase5_operational_control"
down_revision: str | None = "0024_phase4_order_transition"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRANSITION_TABLE = "phase5_operational_control_transitions"
_HEAD_TABLE = "phase5_operational_control_heads"
_COMPLETION_TABLE = "phase5_operational_control_completions"


def upgrade() -> None:
    op.create_table(
        _TRANSITION_TABLE,
        sa.Column("transition_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_transition_id", sa.String(36), nullable=True),
        sa.Column("previous_transition_sha256", sa.String(64), nullable=True),
        sa.Column("command_id", sa.String(36), nullable=False),
        sa.Column("actor_kind", sa.String(24), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("actor_authority_sha256", sa.String(64), nullable=False),
        sa.Column("actor_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("command_kind", sa.String(32), nullable=False),
        sa.Column("target_state", sa.String(24), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason_code", sa.String(128), nullable=False),
        sa.Column("reason_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("rearm_evidence_sha256", sa.String(64), nullable=True),
        sa.Column("trip_rule_id", sa.String(128), nullable=True),
        sa.Column("trip_policy_sha256", sa.String(64), nullable=True),
        sa.Column("trip_observation_sha256", sa.String(64), nullable=True),
        sa.Column("command_canonical_payload", sa.Text(), nullable=False),
        sa.Column("command_sha256", sa.String(64), nullable=False),
        sa.Column("prior_state", sa.String(24), nullable=True),
        sa.Column("effective_state", sa.String(24), nullable=False),
        sa.Column("state_changed", sa.Boolean(), nullable=False),
        sa.Column("state_epoch_id", sa.String(36), nullable=False),
        sa.Column("blocking_event_count", sa.BigInteger(), nullable=False),
        sa.Column("blocking_event_ids_payload", sa.Text(), nullable=False),
        sa.Column("blocking_event_ids_sha256", sa.String(64), nullable=False),
        sa.Column("blocker_overflowed", sa.Boolean(), nullable=False),
        sa.Column("active_operation_attempt_id", sa.String(36), nullable=True),
        sa.Column("active_operation_kind", sa.String(24), nullable=True),
        sa.Column("active_operation_state_epoch_id", sa.String(36), nullable=True),
        sa.Column("active_operation_opened_by_command_id", sa.String(36), nullable=True),
        sa.Column("active_operation_opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active_operation_sha256", sa.String(64), nullable=True),
        sa.Column("operation_started", sa.Boolean(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "transition_id",
            name=op.f(f"pk_{_TRANSITION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_TRANSITION_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "sequence_number",
            name="uq_phase5_control_transition_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase5_control_transition_account_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "transition_id",
            "semantic_sha256",
            name="uq_phase5_control_transition_account_id_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "actor_kind",
            "actor_id",
            "idempotency_key",
            name="uq_phase5_control_transition_actor_key",
        ),
        sa.UniqueConstraint(
            "account_id",
            "transition_id",
            "sequence_number",
            "effective_state",
            "state_epoch_id",
            "blocking_event_count",
            "blocking_event_ids_sha256",
            "blocker_overflowed",
            "semantic_sha256",
            name="uq_phase5_control_transition_tip_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "transition_id",
            "sequence_number",
            "state_epoch_id",
            "active_operation_attempt_id",
            "active_operation_kind",
            "active_operation_state_epoch_id",
            "active_operation_opened_by_command_id",
            "active_operation_opened_at",
            "active_operation_sha256",
            "semantic_sha256",
            name="uq_phase5_control_transition_operation_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "transition_id",
            "sequence_number",
            "state_epoch_id",
            "active_operation_attempt_id",
            "active_operation_kind",
            "active_operation_state_epoch_id",
            "active_operation_opened_by_command_id",
            "active_operation_opened_at",
            "active_operation_sha256",
            "operation_started",
            "semantic_sha256",
            name="uq_phase5_control_transition_opener_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_operational_control_transition_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "previous_transition_id",
                "previous_transition_sha256",
            ],
            [
                f"{_TRANSITION_TABLE}.account_id",
                f"{_TRANSITION_TABLE}.transition_id",
                f"{_TRANSITION_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_operational_control_transition_predecessor",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND previous_transition_id IS NULL "
            "AND previous_transition_sha256 IS NULL AND prior_state IS NULL "
            "AND command_kind = 'initialize_halted' "
            "AND effective_state = 'halted' AND target_state = 'halted' "
            "AND state_changed AND state_epoch_id = transition_id) "
            "OR (sequence_number > 1 AND previous_transition_id IS NOT NULL "
            "AND previous_transition_sha256 IS NOT NULL AND prior_state IS NOT NULL "
            "AND command_kind <> 'initialize_halted')",
            name=op.f(f"ck_{_TRANSITION_TABLE}_predecessor"),
        ),
        sa.CheckConstraint(
            "effective_state IN "
            "('running', 'paused', 'draining', 'flattening', 'halted') "
            "AND (prior_state IS NULL OR prior_state IN "
            "('running', 'paused', 'draining', 'flattening', 'halted')) "
            "AND target_state IN "
            "('running', 'paused', 'draining', 'flattening', 'halted')",
            name=op.f(f"ck_{_TRANSITION_TABLE}_states"),
        ),
        sa.CheckConstraint(
            "sequence_number > 0 AND length(state_epoch_id) = 36",
            name=op.f(f"ck_{_TRANSITION_TABLE}_sequence"),
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND state_changed) "
            "OR (sequence_number > 1 AND "
            "((state_changed AND prior_state <> effective_state "
            "AND state_epoch_id = transition_id) "
            "OR (NOT state_changed AND prior_state = effective_state)))",
            name=op.f(f"ck_{_TRANSITION_TABLE}_state_change"),
        ),
        sa.CheckConstraint(
            "(effective_state IN ('draining', 'flattening') "
            "AND active_operation_attempt_id IS NOT NULL "
            "AND active_operation_sha256 IS NOT NULL "
            "AND active_operation_kind = "
            "CASE effective_state WHEN 'draining' THEN 'drain' ELSE 'flatten' END "
            "AND active_operation_state_epoch_id = state_epoch_id "
            "AND active_operation_opened_by_command_id IS NOT NULL "
            "AND active_operation_opened_at IS NOT NULL) "
            "OR (effective_state NOT IN ('draining', 'flattening') "
            "AND active_operation_attempt_id IS NULL "
            "AND active_operation_sha256 IS NULL "
            "AND active_operation_kind IS NULL "
            "AND active_operation_state_epoch_id IS NULL "
            "AND active_operation_opened_by_command_id IS NULL "
            "AND active_operation_opened_at IS NULL "
            "AND NOT operation_started)",
            name=op.f(f"ck_{_TRANSITION_TABLE}_operation"),
        ),
        sa.CheckConstraint(
            "NOT operation_started OR "
            "(active_operation_opened_by_command_id = command_id "
            "AND active_operation_opened_at = decided_at)",
            name=op.f(f"ck_{_TRANSITION_TABLE}_operation_opener"),
        ),
        sa.CheckConstraint(
            "actor_kind IN ('human', 'system', 'circuit_breaker') "
            "AND command_kind IN "
            "('initialize_halted', 'pause', 'drain', 'flatten', 'halt', 'trip', 'rearm') "
            "AND ("
            "(command_kind = 'trip' "
            "AND actor_kind IN ('system', 'circuit_breaker') "
            "AND target_state IN ('paused', 'halted') "
            "AND trip_rule_id IS NOT NULL "
            "AND trip_policy_sha256 IS NOT NULL "
            "AND trip_observation_sha256 IS NOT NULL) "
            "OR (command_kind <> 'trip' "
            "AND trip_rule_id IS NULL "
            "AND trip_policy_sha256 IS NULL "
            "AND trip_observation_sha256 IS NULL)) "
            "AND (command_kind <> 'initialize_halted' OR actor_kind = 'system') "
            "AND ((command_kind = 'rearm' AND actor_kind = 'human' "
            "AND target_state = 'running' AND rearm_evidence_sha256 IS NOT NULL) "
            "OR (command_kind <> 'rearm' AND rearm_evidence_sha256 IS NULL)) "
            "AND (command_kind <> 'pause' OR target_state = 'paused') "
            "AND (command_kind <> 'drain' OR target_state = 'draining') "
            "AND (command_kind <> 'flatten' OR target_state = 'flattening') "
            "AND (command_kind <> 'halt' OR target_state = 'halted')",
            name=op.f(f"ck_{_TRANSITION_TABLE}_command"),
        ),
        sa.CheckConstraint(
            "(actor_kind = 'human' AND actor_authenticated_at IS NOT NULL) "
            "OR (actor_kind <> 'human' AND actor_authenticated_at IS NULL)",
            name=op.f(f"ck_{_TRANSITION_TABLE}_actor_authentication"),
        ),
        sa.CheckConstraint(
            "length(transition_id) = 36 "
            "AND length(command_id) = 36 "
            "AND length(account_id) BETWEEN 1 AND 64 "
            "AND length(actor_kind) BETWEEN 1 AND 24 "
            "AND length(actor_id) BETWEEN 1 AND 128 "
            "AND length(idempotency_key) BETWEEN 8 AND 128 "
            "AND length(command_kind) BETWEEN 1 AND 32 "
            "AND length(reason_code) BETWEEN 1 AND 128",
            name=op.f(f"ck_{_TRANSITION_TABLE}_identity"),
        ),
        sa.CheckConstraint(
            "length(command_sha256) = 64 "
            "AND length(actor_authority_sha256) = 64 "
            "AND length(reason_evidence_sha256) = 64 "
            "AND (rearm_evidence_sha256 IS NULL "
            "OR length(rearm_evidence_sha256) = 64) "
            "AND length(blocking_event_ids_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND (previous_transition_id IS NULL "
            "OR length(previous_transition_id) = 36) "
            "AND (previous_transition_sha256 IS NULL "
            "OR length(previous_transition_sha256) = 64) "
            "AND (trip_policy_sha256 IS NULL OR length(trip_policy_sha256) = 64) "
            "AND (trip_observation_sha256 IS NULL "
            "OR length(trip_observation_sha256) = 64) "
            "AND (active_operation_attempt_id IS NULL "
            "OR length(active_operation_attempt_id) = 36) "
            "AND (active_operation_sha256 IS NULL "
            "OR length(active_operation_sha256) = 64) "
            "AND (active_operation_state_epoch_id IS NULL "
            "OR length(active_operation_state_epoch_id) = 36) "
            "AND (active_operation_opened_by_command_id IS NULL "
            "OR length(active_operation_opened_by_command_id) = 36)",
            name=op.f(f"ck_{_TRANSITION_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "blocking_event_count BETWEEN 0 AND 2048 "
            "AND ((effective_state = 'running' AND blocking_event_count = 0 "
            "AND NOT blocker_overflowed) "
            "OR (effective_state <> 'running' AND blocking_event_count > 0)) "
            "AND (NOT blocker_overflowed OR blocking_event_count = 2048) "
            "AND length(command_canonical_payload) BETWEEN 2 AND 131072 "
            "AND length(blocking_event_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(canonical_payload) BETWEEN 2 AND 2097152",
            name=op.f(f"ck_{_TRANSITION_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_operational_control_transition_account_time",
        _TRANSITION_TABLE,
        ["account_id", "decided_at"],
        unique=False,
    )

    op.create_table(
        _HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("transition_id", sa.String(36), nullable=False),
        sa.Column("transition_sha256", sa.String(64), nullable=False),
        sa.Column("effective_state", sa.String(24), nullable=False),
        sa.Column("state_epoch_id", sa.String(36), nullable=False),
        sa.Column("blocking_event_count", sa.BigInteger(), nullable=False),
        sa.Column("blocking_event_ids_payload", sa.Text(), nullable=False),
        sa.Column("blocking_event_ids_sha256", sa.String(64), nullable=False),
        sa.Column("blocker_overflowed", sa.Boolean(), nullable=False),
        sa.Column("active_operation_attempt_id", sa.String(36), nullable=True),
        sa.Column("active_operation_kind", sa.String(24), nullable=True),
        sa.Column("active_operation_state_epoch_id", sa.String(36), nullable=True),
        sa.Column("active_operation_opened_by_command_id", sa.String(36), nullable=True),
        sa.Column("active_operation_opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active_operation_sha256", sa.String(64), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "account_id",
            name=op.f(f"pk_{_HEAD_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_HEAD_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_operational_control_head_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "transition_id",
                "sequence_number",
                "effective_state",
                "state_epoch_id",
                "blocking_event_count",
                "blocking_event_ids_sha256",
                "blocker_overflowed",
                "transition_sha256",
            ],
            [
                f"{_TRANSITION_TABLE}.account_id",
                f"{_TRANSITION_TABLE}.transition_id",
                f"{_TRANSITION_TABLE}.sequence_number",
                f"{_TRANSITION_TABLE}.effective_state",
                f"{_TRANSITION_TABLE}.state_epoch_id",
                f"{_TRANSITION_TABLE}.blocking_event_count",
                f"{_TRANSITION_TABLE}.blocking_event_ids_sha256",
                f"{_TRANSITION_TABLE}.blocker_overflowed",
                f"{_TRANSITION_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_control_head_tip",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "transition_id",
                "sequence_number",
                "state_epoch_id",
                "active_operation_attempt_id",
                "active_operation_kind",
                "active_operation_state_epoch_id",
                "active_operation_opened_by_command_id",
                "active_operation_opened_at",
                "active_operation_sha256",
                "transition_sha256",
            ],
            [
                f"{_TRANSITION_TABLE}.account_id",
                f"{_TRANSITION_TABLE}.transition_id",
                f"{_TRANSITION_TABLE}.sequence_number",
                f"{_TRANSITION_TABLE}.state_epoch_id",
                f"{_TRANSITION_TABLE}.active_operation_attempt_id",
                f"{_TRANSITION_TABLE}.active_operation_kind",
                f"{_TRANSITION_TABLE}.active_operation_state_epoch_id",
                f"{_TRANSITION_TABLE}.active_operation_opened_by_command_id",
                f"{_TRANSITION_TABLE}.active_operation_opened_at",
                f"{_TRANSITION_TABLE}.active_operation_sha256",
                f"{_TRANSITION_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_control_head_operation_tip",
        ),
        sa.CheckConstraint(
            "sequence_number > 0 AND length(state_epoch_id) = 36 "
            "AND effective_state IN "
            "('running', 'paused', 'draining', 'flattening', 'halted')",
            name=op.f(f"ck_{_HEAD_TABLE}_state"),
        ),
        sa.CheckConstraint(
            "(effective_state IN ('draining', 'flattening') "
            "AND active_operation_attempt_id IS NOT NULL "
            "AND active_operation_sha256 IS NOT NULL "
            "AND active_operation_kind = "
            "CASE effective_state WHEN 'draining' THEN 'drain' ELSE 'flatten' END "
            "AND active_operation_state_epoch_id = state_epoch_id "
            "AND active_operation_opened_by_command_id IS NOT NULL "
            "AND active_operation_opened_at IS NOT NULL) "
            "OR (effective_state NOT IN ('draining', 'flattening') "
            "AND active_operation_attempt_id IS NULL "
            "AND active_operation_sha256 IS NULL "
            "AND active_operation_kind IS NULL "
            "AND active_operation_state_epoch_id IS NULL "
            "AND active_operation_opened_by_command_id IS NULL "
            "AND active_operation_opened_at IS NULL)",
            name=op.f(f"ck_{_HEAD_TABLE}_operation"),
        ),
        sa.CheckConstraint(
            "length(transition_id) = 36 "
            "AND length(transition_sha256) = 64 "
            "AND length(blocking_event_ids_sha256) = 64 "
            "AND length(semantic_sha256) = 64 "
            "AND blocking_event_count BETWEEN 0 AND 2048 "
            "AND ((effective_state = 'running' AND blocking_event_count = 0 "
            "AND NOT blocker_overflowed) "
            "OR (effective_state <> 'running' AND blocking_event_count > 0)) "
            "AND (NOT blocker_overflowed OR blocking_event_count = 2048) "
            "AND (active_operation_attempt_id IS NULL "
            "OR length(active_operation_attempt_id) = 36) "
            "AND (active_operation_sha256 IS NULL "
            "OR length(active_operation_sha256) = 64) "
            "AND (active_operation_state_epoch_id IS NULL "
            "OR length(active_operation_state_epoch_id) = 36) "
            "AND (active_operation_opened_by_command_id IS NULL "
            "OR length(active_operation_opened_by_command_id) = 36) "
            "AND length(blocking_event_ids_payload) BETWEEN 2 AND 262144 "
            "AND length(canonical_payload) BETWEEN 2 AND 262144",
            name=op.f(f"ck_{_HEAD_TABLE}_identity"),
        ),
    )
    op.create_index(
        "ix_phase5_operational_control_head_time",
        _HEAD_TABLE,
        ["decided_at"],
        unique=False,
    )

    op.create_table(
        _COMPLETION_TABLE,
        sa.Column("completion_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("operation_attempt_id", sa.String(36), nullable=False),
        sa.Column("operation_kind", sa.String(24), nullable=False),
        sa.Column("state_epoch_id", sa.String(36), nullable=False),
        sa.Column("operation_state_epoch_id", sa.String(36), nullable=False),
        sa.Column("operation_attempt_sha256", sa.String(64), nullable=False),
        sa.Column("operation_opened_by_command_id", sa.String(36), nullable=False),
        sa.Column("operation_opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opener_transition_id", sa.String(36), nullable=False),
        sa.Column("opener_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("opener_transition_sha256", sa.String(64), nullable=False),
        sa.Column("opener_operation_started", sa.Boolean(), nullable=False),
        sa.Column("head_transition_id", sa.String(36), nullable=False),
        sa.Column("head_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("head_transition_sha256", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("terminal_order_count", sa.BigInteger(), nullable=False),
        sa.Column("working_order_count", sa.BigInteger(), nullable=False),
        sa.Column("working_order_ids_payload", sa.Text(), nullable=False),
        sa.Column("working_order_ids_sha256", sa.String(64), nullable=False),
        sa.Column("unknown_order_count", sa.BigInteger(), nullable=False),
        sa.Column("unknown_order_ids_payload", sa.Text(), nullable=False),
        sa.Column("unknown_order_ids_sha256", sa.String(64), nullable=False),
        sa.Column("pending_cancel_order_count", sa.BigInteger(), nullable=False),
        sa.Column("pending_cancel_order_ids_payload", sa.Text(), nullable=False),
        sa.Column("pending_cancel_order_ids_sha256", sa.String(64), nullable=False),
        sa.Column("reconciliation_clean", sa.Boolean(), nullable=False),
        sa.Column("source_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("incomplete_reason", sa.String(256), nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("residual_position_count", sa.BigInteger(), nullable=False),
        sa.Column("residual_gross_exposure", sa.Numeric(32, 10), nullable=False),
        sa.Column("residual_positions_payload", sa.Text(), nullable=False),
        sa.Column("residual_positions_sha256", sa.String(64), nullable=False),
        sa.Column("residual_facts_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "completion_id",
            name=op.f(f"pk_{_COMPLETION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_COMPLETION_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "operation_attempt_id",
            name="uq_phase5_control_completion_account_attempt",
        ),
        sa.UniqueConstraint(
            "account_id",
            "idempotency_key",
            name="uq_phase5_control_completion_account_key",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "opener_transition_id",
                "opener_sequence_number",
                "state_epoch_id",
                "operation_attempt_id",
                "operation_kind",
                "operation_state_epoch_id",
                "operation_opened_by_command_id",
                "operation_opened_at",
                "operation_attempt_sha256",
                "opener_operation_started",
                "opener_transition_sha256",
            ],
            [
                f"{_TRANSITION_TABLE}.account_id",
                f"{_TRANSITION_TABLE}.transition_id",
                f"{_TRANSITION_TABLE}.sequence_number",
                f"{_TRANSITION_TABLE}.state_epoch_id",
                f"{_TRANSITION_TABLE}.active_operation_attempt_id",
                f"{_TRANSITION_TABLE}.active_operation_kind",
                f"{_TRANSITION_TABLE}.active_operation_state_epoch_id",
                f"{_TRANSITION_TABLE}.active_operation_opened_by_command_id",
                f"{_TRANSITION_TABLE}.active_operation_opened_at",
                f"{_TRANSITION_TABLE}.active_operation_sha256",
                f"{_TRANSITION_TABLE}.operation_started",
                f"{_TRANSITION_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_control_completion_opener",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "head_transition_id",
                "head_sequence_number",
                "state_epoch_id",
                "operation_attempt_id",
                "operation_kind",
                "operation_state_epoch_id",
                "operation_opened_by_command_id",
                "operation_opened_at",
                "operation_attempt_sha256",
                "head_transition_sha256",
            ],
            [
                f"{_TRANSITION_TABLE}.account_id",
                f"{_TRANSITION_TABLE}.transition_id",
                f"{_TRANSITION_TABLE}.sequence_number",
                f"{_TRANSITION_TABLE}.state_epoch_id",
                f"{_TRANSITION_TABLE}.active_operation_attempt_id",
                f"{_TRANSITION_TABLE}.active_operation_kind",
                f"{_TRANSITION_TABLE}.active_operation_state_epoch_id",
                f"{_TRANSITION_TABLE}.active_operation_opened_by_command_id",
                f"{_TRANSITION_TABLE}.active_operation_opened_at",
                f"{_TRANSITION_TABLE}.active_operation_sha256",
                f"{_TRANSITION_TABLE}.semantic_sha256",
            ],
            name="fk_phase5_control_completion_head",
        ),
        sa.CheckConstraint(
            "operation_kind IN ('drain', 'flatten') "
            "AND length(state_epoch_id) = 36 "
            "AND operation_state_epoch_id = state_epoch_id "
            "AND opener_sequence_number > 0 "
            "AND head_sequence_number >= opener_sequence_number "
            "AND opener_operation_started "
            "AND terminal_order_count >= 0 "
            "AND working_order_count >= 0 "
            "AND unknown_order_count >= 0 "
            "AND pending_cancel_order_count >= 0 "
            "AND residual_position_count >= 0 "
            "AND residual_gross_exposure >= 0 "
            "AND observed_at >= operation_opened_at "
            "AND (deadline_at IS NULL OR deadline_at >= operation_opened_at)",
            name=op.f(f"ck_{_COMPLETION_TABLE}_scope"),
        ),
        sa.CheckConstraint(
            "outcome IN ('completed', 'incomplete', 'deadline_exceeded') "
            "AND ("
            "(outcome = 'completed' "
            "AND incomplete_reason IS NULL "
            "AND working_order_count = 0 "
            "AND unknown_order_count = 0 "
            "AND pending_cancel_order_count = 0 "
            "AND reconciliation_clean "
            "AND (operation_kind <> 'flatten' "
            "OR (residual_position_count = 0 AND residual_gross_exposure = 0))) "
            "OR (outcome IN ('incomplete', 'deadline_exceeded') "
            "AND incomplete_reason IS NOT NULL "
            "AND (working_order_count > 0 "
            "OR unknown_order_count > 0 "
            "OR pending_cancel_order_count > 0 "
            "OR residual_position_count > 0 "
            "OR NOT reconciliation_clean))) "
            "AND (outcome <> 'deadline_exceeded' "
            "OR (deadline_at IS NOT NULL AND deadline_at <= observed_at))",
            name=op.f(f"ck_{_COMPLETION_TABLE}_outcome"),
        ),
        sa.CheckConstraint(
            "length(completion_id) = 36 "
            "AND length(idempotency_key) BETWEEN 8 AND 128 "
            "AND length(operation_attempt_id) = 36 "
            "AND length(operation_attempt_sha256) = 64 "
            "AND length(operation_opened_by_command_id) = 36 "
            "AND length(opener_transition_id) = 36 "
            "AND length(opener_transition_sha256) = 64 "
            "AND length(head_transition_id) = 36 "
            "AND length(head_transition_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(source_evidence_sha256) = 64 "
            "AND length(working_order_ids_sha256) = 64 "
            "AND length(unknown_order_ids_sha256) = 64 "
            "AND length(pending_cancel_order_ids_sha256) = 64 "
            "AND length(residual_positions_sha256) = 64 "
            "AND length(residual_facts_sha256) = 64 "
            "AND length(outcome) BETWEEN 1 AND 32 "
            "AND (incomplete_reason IS NULL "
            "OR length(incomplete_reason) BETWEEN 1 AND 256) "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_COMPLETION_TABLE}_identity"),
        ),
        sa.CheckConstraint(
            "length(working_order_ids_payload) BETWEEN 2 AND 4194304 "
            "AND length(unknown_order_ids_payload) BETWEEN 2 AND 4194304 "
            "AND length(pending_cancel_order_ids_payload) BETWEEN 2 AND 4194304 "
            "AND length(residual_positions_payload) BETWEEN 2 AND 2097152 "
            "AND length(canonical_payload) BETWEEN 2 AND 524288",
            name=op.f(f"ck_{_COMPLETION_TABLE}_payloads"),
        ),
    )
    op.create_index(
        "ix_phase5_operational_control_completion_account_time",
        _COMPLETION_TABLE,
        ["account_id", "observed_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text(
                "LOCK TABLE "
                f"{_COMPLETION_TABLE}, {_HEAD_TABLE}, {_TRANSITION_TABLE} "
                "IN SHARE ROW EXCLUSIVE MODE"
            )
        )
    for table_name in (_COMPLETION_TABLE, _HEAD_TABLE, _TRANSITION_TABLE):
        table = sa.table(table_name)
        if int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0):
            raise RuntimeError("refusing to downgrade nonempty operational-control history")
    op.drop_index(
        "ix_phase5_operational_control_completion_account_time",
        table_name=_COMPLETION_TABLE,
    )
    op.drop_table(_COMPLETION_TABLE)
    op.drop_index(
        "ix_phase5_operational_control_head_time",
        table_name=_HEAD_TABLE,
    )
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase5_operational_control_transition_account_time",
        table_name=_TRANSITION_TABLE,
    )
    op.drop_table(_TRANSITION_TABLE)
