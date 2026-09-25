"""Immutable reconciliation provenance index; root owns schema registration."""

import sqlalchemy as sa

from packages.persistence.schema import metadata

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
