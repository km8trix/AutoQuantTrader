"""Add durable pre-run strategy invocation claims.

Revision ID: 0031_phase5_strategy_claims
Revises: 0030_phase5_adv_outcomes
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031_phase5_strategy_claims"
down_revision: str | None = "0030_phase5_adv_outcomes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RESULT_TABLE = "phase5_strategy_supervision_results"
_CLAIM_TABLE = "phase5_strategy_invocation_claims"
_FINALIZATION_TABLE = "phase5_strategy_invocation_finalizations"
_RESULT_EXACT_UNIQUE = "uq_phase5_strategy_supervision_lifecycle_result"


def _lock_postgresql_tables(
    connection: sa.Connection,
    *table_names: str,
) -> None:
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("LOCK TABLE " + ", ".join(table_names) + " IN SHARE ROW EXCLUSIVE MODE")
        )


def upgrade() -> None:
    connection = op.get_bind()
    _lock_postgresql_tables(connection, _RESULT_TABLE)
    result_table = sa.table(_RESULT_TABLE)
    if int(connection.scalar(sa.select(sa.func.count()).select_from(result_table)) or 0):
        raise RuntimeError("strategy invocation claim cutover requires empty supervision history")

    with op.batch_alter_table(_RESULT_TABLE) as batch_op:
        batch_op.create_unique_constraint(
            _RESULT_EXACT_UNIQUE,
            [
                "account_id",
                "invocation_id",
                "invocation_sha256",
                "semantic_sha256",
            ],
        )

    op.create_table(
        _CLAIM_TABLE,
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("invocation_id", sa.String(36), nullable=False),
        sa.Column("invocation_sha256", sa.String(64), nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=False),
        sa.Column("lease_id", sa.String(64), nullable=False),
        sa.Column("fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("lease_sha256", sa.String(64), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claim_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recoverable_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invocation_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("claim_id", name=op.f(f"pk_{_CLAIM_TABLE}")),
        sa.UniqueConstraint(
            "invocation_id",
            name=op.f(f"uq_{_CLAIM_TABLE}_invocation_id"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_CLAIM_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "claim_id",
            "semantic_sha256",
            "account_id",
            "invocation_id",
            "invocation_sha256",
            name="uq_phase5_strategy_invocation_claim_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase5_strategy_invocation_claim_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fencing_generation", "lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase5_strategy_invocation_claim_lease",
        ),
        sa.CheckConstraint(
            "fencing_generation > 0 "
            "AND claimed_at < recoverable_at "
            "AND recoverable_at < claim_valid_until",
            name=op.f(f"ck_{_CLAIM_TABLE}_window"),
        ),
        sa.CheckConstraint(
            "length(claim_id) = 36 "
            "AND length(invocation_id) = 36 "
            "AND length(account_id) BETWEEN 1 AND 64 "
            "AND length(owner_id) BETWEEN 1 AND 128 "
            "AND length(lease_id) BETWEEN 1 AND 64",
            name=op.f(f"ck_{_CLAIM_TABLE}_identities"),
        ),
        sa.CheckConstraint(
            "length(invocation_sha256) = 64 "
            "AND length(lease_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_receipt_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_CLAIM_TABLE}_hashes"),
        ),
        sa.CheckConstraint(
            "length(invocation_payload) BETWEEN 2 AND 1048576",
            name=op.f(f"ck_{_CLAIM_TABLE}_payload"),
        ),
    )
    op.create_index(
        "ix_phase5_strategy_invocation_claim_account_time",
        _CLAIM_TABLE,
        ["account_id", "claimed_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase5_strategy_invocation_claim_recovery",
        _CLAIM_TABLE,
        ["recoverable_at", "claim_id"],
        unique=False,
    )

    op.create_table(
        _FINALIZATION_TABLE,
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("claim_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("invocation_id", sa.String(36), nullable=False),
        sa.Column("invocation_sha256", sa.String(64), nullable=False),
        sa.Column("result_record_sha256", sa.String(64), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "claim_id",
            name=op.f(f"pk_{_FINALIZATION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "invocation_id",
            name=op.f(f"uq_{_FINALIZATION_TABLE}_invocation_id"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_FINALIZATION_TABLE}_semantic_sha256"),
        ),
        sa.ForeignKeyConstraint(
            [
                "claim_id",
                "claim_sha256",
                "account_id",
                "invocation_id",
                "invocation_sha256",
            ],
            [
                "phase5_strategy_invocation_claims.claim_id",
                "phase5_strategy_invocation_claims.semantic_sha256",
                "phase5_strategy_invocation_claims.account_id",
                "phase5_strategy_invocation_claims.invocation_id",
                "phase5_strategy_invocation_claims.invocation_sha256",
            ],
            name="fk_phase5_strategy_invocation_finalization_claim",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "invocation_id",
                "invocation_sha256",
                "result_record_sha256",
            ],
            [
                "phase5_strategy_supervision_results.account_id",
                "phase5_strategy_supervision_results.invocation_id",
                "phase5_strategy_supervision_results.invocation_sha256",
                "phase5_strategy_supervision_results.semantic_sha256",
            ],
            name="fk_phase5_strategy_invocation_finalization_result",
        ),
        sa.CheckConstraint(
            "length(claim_id) = 36 "
            "AND length(invocation_id) = 36 "
            "AND length(account_id) BETWEEN 1 AND 64",
            name=op.f(f"ck_{_FINALIZATION_TABLE}_identities"),
        ),
        sa.CheckConstraint(
            "length(claim_sha256) = 64 "
            "AND length(invocation_sha256) = 64 "
            "AND length(result_record_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_FINALIZATION_TABLE}_hashes"),
        ),
    )
    op.create_index(
        "ix_phase5_strategy_invocation_finalization_account_time",
        _FINALIZATION_TABLE,
        ["account_id", "finalized_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    _lock_postgresql_tables(
        connection,
        _RESULT_TABLE,
        _CLAIM_TABLE,
        _FINALIZATION_TABLE,
    )
    for table_name in (_FINALIZATION_TABLE, _CLAIM_TABLE):
        table = sa.table(table_name)
        if int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0):
            raise RuntimeError("refusing to downgrade nonempty strategy invocation lifecycle")

    op.drop_index(
        "ix_phase5_strategy_invocation_finalization_account_time",
        table_name=_FINALIZATION_TABLE,
    )
    op.drop_table(_FINALIZATION_TABLE)
    op.drop_index(
        "ix_phase5_strategy_invocation_claim_recovery",
        table_name=_CLAIM_TABLE,
    )
    op.drop_index(
        "ix_phase5_strategy_invocation_claim_account_time",
        table_name=_CLAIM_TABLE,
    )
    op.drop_table(_CLAIM_TABLE)
    with op.batch_alter_table(_RESULT_TABLE) as batch_op:
        batch_op.drop_constraint(
            _RESULT_EXACT_UNIQUE,
            type_="unique",
        )
