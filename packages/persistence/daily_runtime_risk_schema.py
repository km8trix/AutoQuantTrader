"""Additive daily simulation risk rows; schema activation is root-owned."""

from typing import Any

import sqlalchemy as sa

from packages.persistence.schema import metadata


def _payload() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("payload", sa.LargeBinary, nullable=False),
    )


daily_runtime_assignments = sa.Table(
    "daily_runtime_assignments",
    metadata,
    sa.Column(
        "account_id",
        sa.String(128),
        sa.ForeignKey("phase2_account_lease_heads.account_id"),
        primary_key=True,
    ),
    sa.Column("generation", sa.BigInteger, primary_key=True),
    sa.Column("command_id", sa.String(128), nullable=False),
    sa.Column("command_sha256", sa.String(64), nullable=False),
    sa.Column("command_payload", sa.LargeBinary, nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("previous_sha256", sa.String(64)),
    *_payload(),
    sa.UniqueConstraint("account_id", "command_id", name="uq_daily_assign_command"),
    sa.UniqueConstraint(
        "account_id", "generation", "semantic_sha256", name="uq_daily_assign_generation_digest"
    ),
    sa.CheckConstraint("generation > 0", name="daily_assignment_generation"),
    sa.CheckConstraint("length(payload) <= 1048576", name="daily_assignment_bound"),
    sa.CheckConstraint("length(command_payload) <= 1048576", name="daily_assignment_command_bound"),
)
daily_runtime_assignment_heads = sa.Table(
    "daily_runtime_assignment_heads",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("generation", sa.BigInteger, nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "generation", "semantic_sha256"],
        [
            "daily_runtime_assignments.account_id",
            "daily_runtime_assignments.generation",
            "daily_runtime_assignments.semantic_sha256",
        ],
    ),
)
daily_runtime_admissions = sa.Table(
    "daily_runtime_admissions",
    metadata,
    sa.Column("admission_id", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(128), nullable=False),
    sa.Column("command_id", sa.String(128), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("batch_sha256", sa.String(64), nullable=False),
    sa.Column("assignment_generation", sa.BigInteger, nullable=False),
    sa.Column("assignment_sha256", sa.String(64), nullable=False),
    sa.Column("approved", sa.Boolean, nullable=False),
    *_payload(),
    sa.UniqueConstraint("account_id", "command_id", name="uq_daily_admission_command"),
    sa.UniqueConstraint("account_id", "admission_id", name="uq_daily_admission_account_id"),
    sa.ForeignKeyConstraint(
        ["account_id", "assignment_generation", "assignment_sha256"],
        [
            "daily_runtime_assignments.account_id",
            "daily_runtime_assignments.generation",
            "daily_runtime_assignments.semantic_sha256",
        ],
    ),
    sa.CheckConstraint("length(payload) <= 1048576", name="daily_admission_bound"),
)
daily_runtime_hold_events = sa.Table(
    "daily_runtime_hold_events",
    metadata,
    sa.Column("hold_id", sa.String(64), primary_key=True),
    sa.Column("revision", sa.BigInteger, primary_key=True),
    sa.Column("account_id", sa.String(128), nullable=False),
    sa.Column("admission_id", sa.String(64), nullable=False),
    sa.Column("intent_id", sa.String(128), nullable=False),
    sa.Column("execution_session", sa.Date, nullable=False),
    sa.Column("previous_sha256", sa.String(64)),
    *_payload(),
    sa.UniqueConstraint(
        "account_id", "hold_id", "revision", "semantic_sha256", name="uq_daily_hold_revision_digest"
    ),
    sa.UniqueConstraint(
        "account_id", "intent_id", "revision", name="uq_daily_hold_intent_revision"
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "admission_id"],
        [
            "daily_runtime_admissions.account_id",
            "daily_runtime_admissions.admission_id",
        ],
    ),
    sa.CheckConstraint("revision > 0", name="daily_hold_revision"),
    sa.CheckConstraint("length(payload) <= 1048576", name="daily_hold_bound"),
    sa.Index("ix_daily_hold_session", "account_id", "execution_session", "revision"),
)
daily_runtime_hold_heads = sa.Table(
    "daily_runtime_hold_heads",
    metadata,
    sa.Column("hold_id", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(128), nullable=False),
    sa.Column("revision", sa.BigInteger, nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint("account_id", "hold_id"),
    sa.ForeignKeyConstraint(
        ["account_id", "hold_id", "revision", "semantic_sha256"],
        [
            "daily_runtime_hold_events.account_id",
            "daily_runtime_hold_events.hold_id",
            "daily_runtime_hold_events.revision",
            "daily_runtime_hold_events.semantic_sha256",
        ],
    ),
)
daily_runtime_consumptions = sa.Table(
    "daily_runtime_consumptions",
    metadata,
    sa.Column("admission_id", sa.String(64), primary_key=True),
    sa.Column("intent_id", sa.String(128), primary_key=True),
    sa.Column("account_id", sa.String(128), nullable=False),
    sa.Column("hold_id", sa.String(64), nullable=False),
    sa.Column("attempt_id", sa.String(128), nullable=False),
    *_payload(),
    sa.UniqueConstraint("attempt_id", name="uq_daily_consumption_attempt"),
    sa.UniqueConstraint("account_id", "attempt_id", name="uq_daily_consumption_account_attempt"),
    sa.UniqueConstraint(
        "account_id",
        "attempt_id",
        "admission_id",
        "intent_id",
        "hold_id",
        name="uq_daily_consumption_exact_binding",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "hold_id"],
        ["daily_runtime_hold_heads.account_id", "daily_runtime_hold_heads.hold_id"],
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "admission_id"],
        [
            "daily_runtime_admissions.account_id",
            "daily_runtime_admissions.admission_id",
        ],
    ),
    sa.CheckConstraint("length(payload) <= 1048576", name="daily_consumption_bound"),
)
daily_runtime_outbound = sa.Table(
    "daily_runtime_outbound",
    metadata,
    sa.Column("outbound_id", sa.String(64), primary_key=True),
    sa.Column("account_id", sa.String(128), nullable=False),
    sa.Column("admission_id", sa.String(64), nullable=False),
    sa.Column("intent_id", sa.String(128), nullable=False),
    sa.Column("hold_id", sa.String(64), nullable=False),
    sa.Column("request_sha256", sa.String(64), nullable=False),
    sa.Column("binding_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint("admission_id", "intent_id"),
    sa.ForeignKeyConstraint(
        ["account_id", "hold_id"],
        ["daily_runtime_hold_heads.account_id", "daily_runtime_hold_heads.hold_id"],
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "admission_id"],
        [
            "daily_runtime_admissions.account_id",
            "daily_runtime_admissions.admission_id",
        ],
    ),
)
daily_runtime_attempt_events = sa.Table(
    "daily_runtime_attempt_events",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("attempt_id", sa.String(128), primary_key=True),
    sa.Column("sequence", sa.BigInteger, primary_key=True),
    sa.Column("event_id", sa.String(128), nullable=False),
    sa.Column("event_sha256", sa.String(64), nullable=False),
    sa.Column("previous_event_sha256", sa.String(64)),
    sa.Column("state", sa.String(16), nullable=False),
    sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("admission_id", sa.String(64), nullable=False),
    sa.Column("intent_id", sa.String(128), nullable=False),
    sa.Column("hold_id", sa.String(64), nullable=False),
    sa.Column("coordinator_command_id", sa.String(128), nullable=False),
    sa.Column("coordinator_sequence", sa.BigInteger, nullable=False),
    *_payload(),
    sa.UniqueConstraint("account_id", "event_id", name="uq_daily_attempt_event_id"),
    sa.UniqueConstraint(
        "account_id",
        "attempt_id",
        "sequence",
        "event_sha256",
        name="uq_daily_attempt_event_sequence_digest",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "attempt_id", "admission_id", "intent_id", "hold_id"],
        [
            "daily_runtime_consumptions.account_id",
            "daily_runtime_consumptions.attempt_id",
            "daily_runtime_consumptions.admission_id",
            "daily_runtime_consumptions.intent_id",
            "daily_runtime_consumptions.hold_id",
        ],
        name="fk_daily_attempt_original_consumption",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "coordinator_command_id", "coordinator_sequence"],
        [
            "personal_continuous_account_commits.account_id",
            "personal_continuous_account_commits.command_id",
            "personal_continuous_account_commits.sequence",
        ],
        name="fk_daily_attempt_parent_command",
        deferrable=True,
        initially="DEFERRED",
    ),
    sa.CheckConstraint("sequence >= 1 AND sequence <= 64", name="daily_attempt_sequence"),
    sa.CheckConstraint("coordinator_sequence > 0", name="daily_attempt_account_sequence"),
    sa.CheckConstraint(
        "state IN ('pending','in_flight','confirmed','unknown','resolved','abandoned')",
        name="daily_attempt_state",
    ),
    sa.CheckConstraint(
        "(sequence = 1 AND previous_event_sha256 IS NULL) OR "
        "(sequence > 1 AND previous_event_sha256 IS NOT NULL)",
        name="daily_attempt_predecessor",
    ),
    sa.CheckConstraint(
        "length(payload) > 0 AND length(payload) <= 1048576", name="daily_attempt_bound"
    ),
    sa.Index("ix_daily_attempt_parent_command", "account_id", "coordinator_command_id", "sequence"),
)
daily_runtime_attempt_heads = sa.Table(
    "daily_runtime_attempt_heads",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("attempt_id", sa.String(128), primary_key=True),
    sa.Column("sequence", sa.BigInteger, nullable=False),
    sa.Column("event_sha256", sa.String(64), nullable=False),
    sa.Column("attempt_sha256", sa.String(64), nullable=False),
    sa.Column("state", sa.String(16), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "attempt_id", "sequence", "event_sha256"],
        [
            "daily_runtime_attempt_events.account_id",
            "daily_runtime_attempt_events.attempt_id",
            "daily_runtime_attempt_events.sequence",
            "daily_runtime_attempt_events.event_sha256",
        ],
        name="fk_daily_attempt_exact_head_event",
    ),
    sa.CheckConstraint("sequence >= 1 AND sequence <= 64", name="daily_attempt_head_sequence"),
    sa.CheckConstraint(
        "state IN ('pending','in_flight','confirmed','unknown','resolved','abandoned')",
        name="daily_attempt_head_state",
    ),
)
daily_runtime_observed_hold_groups = sa.Table(
    "daily_runtime_observed_hold_groups",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("coordinator_sequence", sa.BigInteger, primary_key=True),
    sa.Column("coordinator_command_id", sa.String(128), nullable=False),
    sa.Column("source_sha256", sa.String(64), nullable=False),
    sa.Column("before_inventory_sha256", sa.String(64), nullable=False),
    sa.Column("after_inventory_sha256", sa.String(64), nullable=False),
    sa.Column("applied_at", sa.DateTime(timezone=True), nullable=False),
    *_payload(),
    sa.UniqueConstraint("account_id", "coordinator_command_id", name="uq_daily_observed_parent"),
    sa.ForeignKeyConstraint(
        ["account_id", "coordinator_command_id", "coordinator_sequence"],
        [
            "personal_continuous_account_commits.account_id",
            "personal_continuous_account_commits.command_id",
            "personal_continuous_account_commits.sequence",
        ],
        name="fk_daily_observed_parent_command",
        deferrable=True,
        initially="DEFERRED",
    ),
    sa.CheckConstraint("coordinator_sequence > 0", name="daily_observed_sequence"),
    sa.CheckConstraint("length(payload) <= 1048576", name="daily_observed_payload_bound"),
)

DAILY_RUNTIME_TABLES = (
    daily_runtime_assignments,
    daily_runtime_assignment_heads,
    daily_runtime_admissions,
    daily_runtime_hold_events,
    daily_runtime_hold_heads,
    daily_runtime_consumptions,
    daily_runtime_outbound,
    daily_runtime_attempt_events,
    daily_runtime_attempt_heads,
    daily_runtime_observed_hold_groups,
)
