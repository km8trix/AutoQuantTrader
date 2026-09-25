"""Add continuous simulation journals, reconciliation and daily account state.

Revision ID: 0040_personal_continuous
Revises: 0039_personal_research

Frozen DDL only. Existing account/lease tables are referenced, never replaced.
Nonempty W4 history cannot be downgraded.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0040_personal_continuous"
down_revision: str | None = "0039_personal_research"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

metadata = sa.MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)


# Minimal frozen FK targets resolve DDL only; upgrade/downgrade never create/drop them.
sa.Table(
    "phase2_account_lease_heads",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
)
sa.Table(
    "phase2_account_leases", metadata, sa.Column("lease_sha256", sa.String(64), primary_key=True)
)


journal_streams = sa.Table(
    "personal_journal_streams",
    metadata,
    sa.Column("key_sha256", sa.String(64), primary_key=True),
    sa.Column("key_payload", sa.LargeBinary, nullable=False),
    sa.Column("last_sequence", sa.BigInteger, nullable=False),
    sa.Column("last_entry_sha256", sa.String(64), nullable=False),
    sa.CheckConstraint("last_sequence >= 0", name="personal_journal_head_sequence"),
)

journal_appends = sa.Table(
    "personal_journal_appends",
    metadata,
    sa.Column(
        "key_sha256",
        sa.String(64),
        sa.ForeignKey("personal_journal_streams.key_sha256"),
        primary_key=True,
    ),
    sa.Column("command_id", sa.String(128), primary_key=True),
    sa.Column("command_sha256", sa.String(64), nullable=False),
    sa.Column("append_sha256", sa.String(64), nullable=False),
    sa.Column("previous_sequence", sa.BigInteger, nullable=False),
    sa.Column("previous_entry_sha256", sa.String(64), nullable=False),
    sa.Column("last_sequence", sa.BigInteger, nullable=False),
    sa.Column("last_entry_sha256", sa.String(64), nullable=False),
    sa.Column("receipt_sha256", sa.String(64), nullable=False),
    sa.CheckConstraint(
        "previous_sequence >= 0 AND last_sequence > previous_sequence "
        "AND last_sequence <= previous_sequence + 64",
        name="personal_journal_append_range",
    ),
)

journal_entries = sa.Table(
    "personal_journal_entries",
    metadata,
    sa.Column("key_sha256", sa.String(64), primary_key=True),
    sa.Column("sequence", sa.BigInteger, primary_key=True),
    sa.Column("command_id", sa.String(128), nullable=False),
    sa.Column("record_id", sa.String(128), nullable=False),
    sa.Column("schema_id", sa.String(128), nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    sa.Column("payload_sha256", sa.String(64), nullable=False),
    sa.Column("previous_entry_sha256", sa.String(64), nullable=False),
    sa.Column("entry_sha256", sa.String(64), nullable=False),
    sa.ForeignKeyConstraint(
        ["key_sha256", "command_id"],
        ["personal_journal_appends.key_sha256", "personal_journal_appends.command_id"],
    ),
    sa.UniqueConstraint("key_sha256", "record_id", name="uq_personal_journal_record_id"),
    sa.UniqueConstraint(
        "key_sha256", "sequence", "entry_sha256", name="uq_personal_journal_entry_identity"
    ),
    sa.CheckConstraint("sequence > 0", name="personal_journal_entry_sequence"),
)

JOURNAL_TABLES = (journal_streams, journal_appends, journal_entries)

applied_reconciliation_commits = sa.Table(
    "personal_reconciliation_commits",
    metadata,
    sa.Column("scope_sha256", sa.String(64), primary_key=True),
    sa.Column("command_id", sa.String(128), primary_key=True),
    sa.Column("sequence", sa.BigInteger, nullable=False),
    sa.Column("commit_sha256", sa.String(64), nullable=False),
    sa.Column("previous_commit_sha256", sa.String(64), nullable=True),
    sa.Column("journal_key_sha256", sa.String(64), nullable=False),
    sa.Column("journal_command_id", sa.String(128), nullable=False),
    sa.Column("journal_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("first_journal_sequence", sa.BigInteger, nullable=False),
    sa.Column("last_journal_sequence", sa.BigInteger, nullable=False),
    sa.Column("canonical_payload", sa.LargeBinary, nullable=False),
    sa.UniqueConstraint("scope_sha256", "sequence", name="uq_reconciliation_scope_sequence"),
    sa.UniqueConstraint("scope_sha256", "commit_sha256", name="uq_reconciliation_scope_commit"),
    sa.ForeignKeyConstraint(
        ["journal_key_sha256", "journal_command_id"],
        ["personal_journal_appends.key_sha256", "personal_journal_appends.command_id"],
    ),
    sa.CheckConstraint("sequence > 0", name="personal_reconciliation_sequence_positive"),
    sa.CheckConstraint(
        "first_journal_sequence = last_journal_sequence AND sequence = last_journal_sequence",
        name="personal_reconciliation_single_record",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) > 0 AND length(canonical_payload) <= 16384",
        name="personal_reconciliation_compact_bytes",
    ),
)

APPLIED_RECONCILIATION_TABLES = (applied_reconciliation_commits,)


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

continuous_account_commits = sa.Table(
    "personal_continuous_account_commits",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("command_id", sa.String(128), primary_key=True),
    sa.Column("scope_sha256", sa.String(64), nullable=False),
    sa.Column("sequence", sa.BigInteger, nullable=False),
    sa.Column("commit_sha256", sa.String(64), nullable=False),
    sa.Column("previous_commit_sha256", sa.String(64)),
    sa.Column("checkpoint_sha256", sa.String(64), nullable=False),
    sa.Column("journal_key_sha256", sa.String(64), nullable=False),
    sa.Column("journal_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("canonical_payload", sa.LargeBinary, nullable=False),
    sa.Column("recorded_at", sa.String(32), nullable=False),
    sa.Column("owner_id", sa.String(128), nullable=False),
    sa.Column("lease_id", sa.String(128), nullable=False),
    sa.Column("fencing_generation", sa.BigInteger, nullable=False),
    sa.Column("lease_sha256", sa.String(64), nullable=False),
    sa.Column("policy_sha256", sa.String(64), nullable=False),
    sa.Column("valid_until", sa.String(32), nullable=False),
    sa.Column("receipt_sha256", sa.String(64), nullable=False),
    sa.UniqueConstraint("account_id", "sequence", name="uq_continuous_account_sequence"),
    sa.UniqueConstraint("account_id", "commit_sha256", name="uq_continuous_account_commit_sha"),
    sa.UniqueConstraint(
        "account_id", "command_id", "sequence", name="uq_continuous_account_command_sequence"
    ),
    sa.ForeignKeyConstraint(
        ["journal_key_sha256", "command_id"],
        ["personal_journal_appends.key_sha256", "personal_journal_appends.command_id"],
    ),
    sa.ForeignKeyConstraint(["lease_sha256"], ["phase2_account_leases.lease_sha256"]),
    sa.CheckConstraint("sequence > 0 AND fencing_generation > 0", name="continuous_positive"),
    sa.CheckConstraint(
        "length(canonical_payload) > 0 AND length(canonical_payload) <= 16384",
        name="continuous_compact_bytes",
    ),
)

continuous_account_heads = sa.Table(
    "personal_continuous_account_heads",
    metadata,
    sa.Column("account_id", sa.String(128), primary_key=True),
    sa.Column("scope_sha256", sa.String(64), nullable=False),
    sa.Column("command_id", sa.String(128), nullable=False),
    sa.Column("sequence", sa.BigInteger, nullable=False),
    sa.Column("commit_sha256", sa.String(64), nullable=False),
    sa.Column("checkpoint_sha256", sa.String(64), nullable=False),
    sa.ForeignKeyConstraint(
        ["account_id", "command_id"],
        [
            "personal_continuous_account_commits.account_id",
            "personal_continuous_account_commits.command_id",
        ],
    ),
    sa.CheckConstraint("sequence > 0", name="continuous_head_positive"),
)

CONTINUOUS_ACCOUNT_TABLES = (continuous_account_commits, continuous_account_heads)

_TABLES = (
    *JOURNAL_TABLES,
    *APPLIED_RECONCILIATION_TABLES,
    *DAILY_RUNTIME_TABLES,
    *CONTINUOUS_ACCOUNT_TABLES,
)

# The attempt parent FK is deferred for writes, but PostgreSQL still requires its
# referenced table to exist when CREATE TABLE executes.
_CREATION_TABLES = (
    *JOURNAL_TABLES,
    *APPLIED_RECONCILIATION_TABLES,
    *DAILY_RUNTIME_TABLES[:7],
    *CONTINUOUS_ACCOUNT_TABLES,
    *DAILY_RUNTIME_TABLES[7:],
)


def upgrade() -> None:
    connection = op.get_bind()
    for table in _CREATION_TABLES:
        table.create(connection, checkfirst=False)


def downgrade() -> None:
    if op.get_context().as_sql:
        raise RuntimeError("continuous downgrade requires online locked history verification")
    connection = op.get_bind()
    names = tuple(table.name for table in _TABLES)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE " + ", ".join(names) + " IN ACCESS EXCLUSIVE MODE")
    elif connection.dialect.name == "sqlite":
        # Obtain the transaction write lock even when the stream inventory is empty.
        connection.exec_driver_sql(
            "UPDATE personal_journal_streams SET key_sha256 = key_sha256 WHERE 0"
        )
    else:
        raise RuntimeError("unsupported continuous downgrade database")
    if any(
        connection.execute(sa.select(sa.literal(1)).select_from(t).limit(1)).first() is not None
        for t in _TABLES
    ):
        raise RuntimeError("refusing to downgrade nonempty personal continuous history")
    for table in reversed(_CREATION_TABLES):
        table.drop(connection, checkfirst=False)
