"""Account-scoped checkpoint metadata; root owns migration/registration."""

import sqlalchemy as sa

from packages.persistence.schema import metadata

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
