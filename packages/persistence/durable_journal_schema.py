"""Shared W4 journal tables; registration/migrations belong to composition."""

import sqlalchemy as sa

from packages.persistence.schema import metadata

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
