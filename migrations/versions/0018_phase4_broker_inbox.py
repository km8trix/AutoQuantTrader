"""Add source-scoped broker inbox admission evidence.

Revision ID: 0018_phase4_broker_inbox
Revises: 0017_phase4_reconciliation
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_phase4_broker_inbox"
down_revision: str | None = "0017_phase4_reconciliation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NORMALIZED_TABLE = "phase4_broker_normalized_facts"
_LINK_TABLE = "phase4_broker_inbox_source_links"
_HEAD_TABLE = "phase4_broker_inbox_heads"
_APPLICATION_TABLE = "phase4_broker_inbox_application_receipts"


def upgrade() -> None:
    op.create_table(
        _NORMALIZED_TABLE,
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("source_kind", sa.String(64), nullable=False),
        sa.Column("identity_profile_id", sa.String(128), nullable=False),
        sa.Column("identity_profile_sha256", sa.String(64), nullable=False),
        sa.Column("identity_sha256", sa.String(64), nullable=False),
        sa.Column("source_reconciliation_fact_id", sa.String(36), nullable=False),
        sa.Column("source_reconciliation_fact_sha256", sa.String(64), nullable=False),
        sa.Column("source_reconciliation_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("source_reconciliation_account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("source_fact_normalized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_lookup_receipt_id", sa.String(36), nullable=False),
        sa.Column("source_lookup_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("source_ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_observation_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "request_id",
            name=op.f(f"pk_{_NORMALIZED_TABLE}"),
        ),
        sa.UniqueConstraint(
            "observation_id",
            name=op.f(f"uq_{_NORMALIZED_TABLE}_observation_id"),
        ),
        sa.UniqueConstraint(
            "identity_sha256",
            name=op.f(f"uq_{_NORMALIZED_TABLE}_identity_sha256"),
        ),
        sa.UniqueConstraint(
            "source_reconciliation_fact_id",
            name=op.f(f"uq_{_NORMALIZED_TABLE}_source_reconciliation_fact_id"),
        ),
        sa.UniqueConstraint(
            "source_lookup_receipt_id",
            name=op.f(f"uq_{_NORMALIZED_TABLE}_source_lookup_receipt_id"),
        ),
        sa.UniqueConstraint(
            "source_ingress_receipt_id",
            name=op.f(f"uq_{_NORMALIZED_TABLE}_source_ingress_receipt_id"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_NORMALIZED_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "request_id",
            "account_id",
            "observation_id",
            "semantic_sha256",
            name="uq_phase4_broker_normalized_fact_exact",
        ),
        sa.UniqueConstraint(
            "request_id",
            "account_id",
            "observation_id",
            "source_reconciliation_fact_id",
            "source_reconciliation_fact_sha256",
            "source_ingress_receipt_id",
            "source_ingress_receipt_sha256",
            "semantic_sha256",
            name="uq_phase4_broker_normalized_source_exact",
        ),
        sa.CheckConstraint(
            "source_kind = 'authenticated_client_order_lookup'",
            name=op.f(f"ck_{_NORMALIZED_TABLE}_phase4_broker_normalized_source_kind"),
        ),
        sa.CheckConstraint(
            "source_reconciliation_account_sequence > 0",
            name=op.f(f"ck_{_NORMALIZED_TABLE}_phase4_broker_normalized_positive_sequence"),
        ),
        sa.CheckConstraint(
            "length(request_id) = 36 "
            "AND length(observation_id) = 36 "
            "AND length(identity_profile_sha256) = 64 "
            "AND length(identity_sha256) = 64 "
            "AND length(source_reconciliation_fact_id) = 36 "
            "AND length(source_reconciliation_fact_sha256) = 64 "
            "AND length(source_reconciliation_evidence_sha256) = 64 "
            "AND length(source_lookup_receipt_id) = 36 "
            "AND length(source_lookup_receipt_sha256) = 64 "
            "AND length(source_ingress_receipt_id) = 64 "
            "AND length(source_ingress_receipt_sha256) = 64 "
            "AND length(source_observation_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_NORMALIZED_TABLE}_phase4_broker_normalized_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_NORMALIZED_TABLE}_phase4_broker_normalized_payload_size"),
        ),
    )
    op.create_index(
        "ix_phase4_broker_normalized_account_source_time",
        _NORMALIZED_TABLE,
        ["account_id", "source_fact_normalized_at"],
        unique=False,
    )

    op.create_table(
        _LINK_TABLE,
        sa.Column("link_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("previous_link_sha256", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("source_reconciliation_fact_id", sa.String(36), nullable=False),
        sa.Column("source_reconciliation_fact_sha256", sa.String(64), nullable=False),
        sa.Column("source_reconciliation_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("source_reconciliation_account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("source_lookup_receipt_id", sa.String(36), nullable=False),
        sa.Column("source_lookup_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("source_ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("source_observation_sha256", sa.String(64), nullable=False),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("link_id", name=op.f(f"pk_{_LINK_TABLE}")),
        sa.UniqueConstraint(
            "request_id",
            name=op.f(f"uq_{_LINK_TABLE}_request_id"),
        ),
        sa.UniqueConstraint(
            "observation_id",
            name=op.f(f"uq_{_LINK_TABLE}_observation_id"),
        ),
        sa.UniqueConstraint(
            "source_reconciliation_fact_id",
            name=op.f(f"uq_{_LINK_TABLE}_source_reconciliation_fact_id"),
        ),
        sa.UniqueConstraint(
            "source_lookup_receipt_id",
            name=op.f(f"uq_{_LINK_TABLE}_source_lookup_receipt_id"),
        ),
        sa.UniqueConstraint(
            "source_ingress_receipt_id",
            name=op.f(f"uq_{_LINK_TABLE}_source_ingress_receipt_id"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_LINK_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            name="uq_phase4_broker_inbox_link_account_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "semantic_sha256",
            name="uq_phase4_broker_inbox_link_account_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            "link_id",
            "semantic_sha256",
            name="uq_phase4_broker_inbox_link_head_exact",
        ),
        sa.UniqueConstraint(
            "account_id",
            "account_sequence",
            "link_id",
            "request_id",
            "semantic_sha256",
            name="uq_phase4_broker_inbox_link_exact",
        ),
        sa.UniqueConstraint(
            "link_id",
            "account_id",
            "request_id",
            "semantic_sha256",
            name="uq_phase4_broker_inbox_link_receipt_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_inbox_link_account",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "previous_link_sha256"],
            [f"{_LINK_TABLE}.account_id", f"{_LINK_TABLE}.semantic_sha256"],
            name="fk_phase4_broker_inbox_link_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "request_id",
                "account_id",
                "observation_id",
                "source_reconciliation_fact_id",
                "source_reconciliation_fact_sha256",
                "source_ingress_receipt_id",
                "source_ingress_receipt_sha256",
                "request_sha256",
            ],
            [
                f"{_NORMALIZED_TABLE}.request_id",
                f"{_NORMALIZED_TABLE}.account_id",
                f"{_NORMALIZED_TABLE}.observation_id",
                f"{_NORMALIZED_TABLE}.source_reconciliation_fact_id",
                f"{_NORMALIZED_TABLE}.source_reconciliation_fact_sha256",
                f"{_NORMALIZED_TABLE}.source_ingress_receipt_id",
                f"{_NORMALIZED_TABLE}.source_ingress_receipt_sha256",
                f"{_NORMALIZED_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_broker_inbox_link_normalized_fact",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "source_reconciliation_account_sequence",
                "source_reconciliation_fact_id",
                "source_reconciliation_fact_sha256",
            ],
            [
                "phase4_broker_reconciliation_facts.account_id",
                "phase4_broker_reconciliation_facts.account_sequence",
                "phase4_broker_reconciliation_facts.fact_id",
                "phase4_broker_reconciliation_facts.semantic_sha256",
            ],
            name="fk_phase4_broker_inbox_link_reconciliation",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "source_ingress_receipt_id",
                "source_ingress_receipt_sha256",
            ],
            [
                "phase4_broker_ingress_receipts.account_id",
                "phase4_broker_ingress_receipts.receipt_id",
                "phase4_broker_ingress_receipts.semantic_sha256",
            ],
            name="fk_phase4_broker_inbox_link_ingress",
        ),
        sa.CheckConstraint(
            "(account_sequence = 1 AND previous_link_sha256 IS NULL) "
            "OR (account_sequence > 1 AND previous_link_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_LINK_TABLE}_phase4_broker_inbox_link_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "source_reconciliation_account_sequence > 0 AND account_sequence > 0",
            name=op.f(f"ck_{_LINK_TABLE}_phase4_broker_inbox_link_positive_sequences"),
        ),
        sa.CheckConstraint(
            "length(link_id) = 36 "
            "AND length(request_id) = 36 "
            "AND length(request_sha256) = 64 "
            "AND length(observation_id) = 36 "
            "AND (previous_link_sha256 IS NULL "
            "OR length(previous_link_sha256) = 64) "
            "AND length(source_reconciliation_fact_id) = 36 "
            "AND length(source_reconciliation_fact_sha256) = 64 "
            "AND length(source_reconciliation_evidence_sha256) = 64 "
            "AND length(source_lookup_receipt_id) = 36 "
            "AND length(source_lookup_receipt_sha256) = 64 "
            "AND length(source_ingress_receipt_id) = 64 "
            "AND length(source_ingress_receipt_sha256) = 64 "
            "AND length(source_observation_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_LINK_TABLE}_phase4_broker_inbox_link_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_LINK_TABLE}_phase4_broker_inbox_link_payload_size"),
        ),
    )
    op.create_index(
        "ix_phase4_broker_inbox_link_account_time",
        _LINK_TABLE,
        ["account_id", "linked_at"],
        unique=False,
    )

    op.create_table(
        _HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("last_account_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_link_id", sa.String(36), nullable=False),
        sa.Column("last_link_sha256", sa.String(64), nullable=False),
        sa.Column("last_linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("account_id", name=op.f(f"pk_{_HEAD_TABLE}")),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_broker_inbox_head_account",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "last_account_sequence",
                "last_link_id",
                "last_link_sha256",
            ],
            [
                f"{_LINK_TABLE}.account_id",
                f"{_LINK_TABLE}.account_sequence",
                f"{_LINK_TABLE}.link_id",
                f"{_LINK_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_broker_inbox_head_link",
        ),
        sa.CheckConstraint(
            "last_account_sequence > 0 "
            "AND length(last_link_id) = 36 "
            "AND length(last_link_sha256) = 64",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_broker_inbox_head_shape"),
        ),
    )

    op.create_table(
        _APPLICATION_TABLE,
        sa.Column("decision_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("observation_id", sa.String(36), nullable=False),
        sa.Column("source_link_id", sa.String(36), nullable=False),
        sa.Column("source_link_sha256", sa.String(64), nullable=False),
        sa.Column("disposition", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "decision_id",
            name=op.f(f"pk_{_APPLICATION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "request_id",
            name=op.f(f"uq_{_APPLICATION_TABLE}_request_id"),
        ),
        sa.UniqueConstraint(
            "observation_id",
            name=op.f(f"uq_{_APPLICATION_TABLE}_observation_id"),
        ),
        sa.UniqueConstraint(
            "source_link_id",
            name=op.f(f"uq_{_APPLICATION_TABLE}_source_link_id"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_APPLICATION_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "decision_id",
            "account_id",
            "request_id",
            "semantic_sha256",
            name="uq_phase4_broker_inbox_application_exact",
        ),
        sa.ForeignKeyConstraint(
            ["request_id", "account_id", "observation_id", "request_sha256"],
            [
                f"{_NORMALIZED_TABLE}.request_id",
                f"{_NORMALIZED_TABLE}.account_id",
                f"{_NORMALIZED_TABLE}.observation_id",
                f"{_NORMALIZED_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_broker_inbox_application_request",
        ),
        sa.ForeignKeyConstraint(
            [
                "source_link_id",
                "account_id",
                "request_id",
                "source_link_sha256",
            ],
            [
                f"{_LINK_TABLE}.link_id",
                f"{_LINK_TABLE}.account_id",
                f"{_LINK_TABLE}.request_id",
                f"{_LINK_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_broker_inbox_application_link",
        ),
        sa.CheckConstraint(
            "disposition IN "
            "('withheld_unqualified_revision_identity', "
            "'quarantined_economic_mismatch', "
            "'quarantined_security_mismatch', "
            "'inconclusive_not_visible')",
            name=op.f(f"ck_{_APPLICATION_TABLE}_phase4_broker_inbox_application_disposition"),
        ),
        sa.CheckConstraint(
            "decided_at <= recorded_at",
            name=op.f(f"ck_{_APPLICATION_TABLE}_phase4_broker_inbox_application_time_order"),
        ),
        sa.CheckConstraint(
            "length(decision_id) = 36 "
            "AND length(request_id) = 36 "
            "AND length(request_sha256) = 64 "
            "AND length(observation_id) = 36 "
            "AND length(source_link_id) = 36 "
            "AND length(source_link_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_APPLICATION_TABLE}_phase4_broker_inbox_application_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 65536",
            name=op.f(f"ck_{_APPLICATION_TABLE}_phase4_broker_inbox_application_payload_size"),
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    tables = (
        _APPLICATION_TABLE,
        _HEAD_TABLE,
        _LINK_TABLE,
        _NORMALIZED_TABLE,
    )
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE")
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}")) for table_name in tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty source-scoped broker inbox history")
    op.drop_table(_APPLICATION_TABLE)
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_broker_inbox_link_account_time",
        table_name=_LINK_TABLE,
    )
    op.drop_table(_LINK_TABLE)
    op.drop_index(
        "ix_phase4_broker_normalized_account_source_time",
        table_name=_NORMALIZED_TABLE,
    )
    op.drop_table(_NORMALIZED_TABLE)
