"""Add gap-free lease revisions and authenticated capacity ordering.

Revision ID: 0009_lease_revision_chain
Revises: 0008_phase2_research
Create Date: 2026-07-21
"""

import hashlib
import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_lease_revision_chain"
down_revision: str | None = "0008_phase2_research"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE_NAME = "phase2_account_leases"
_INDEX_NAME = "ix_phase2_account_leases_account_generation"
_HASH_CHECK = "ck_phase2_account_leases_hash_lengths"
_POSITIVE_REVISION_CHECK = "ck_phase2_account_leases_positive_revision"
_PREDECESSOR_SHAPE_CHECK = "ck_phase2_account_leases_revision_predecessor_shape"
_REVISION_UNIQUE = "account_generation_revision"
_PREDECESSOR_FOREIGN_KEY = "previous_lease_revision"
_LEGACY_LEASE_CONTRACT_VERSION = "phase2-account-coordinator-v1"
_CURRENT_LEASE_CONTRACT_VERSION = "phase2-account-lease-v2"
_LEGACY_CAPACITY_OBSERVATION_CONTRACT = "phase2-capacity-observation-v3"
_CURRENT_CAPACITY_OBSERVATION_CONTRACT = "phase2-capacity-observation-v4"
_CAPACITY_DECISION_TABLE = "phase2_batch_decisions"
_CAPACITY_MUTATION_TABLES = (
    "phase2_submission_attempt_events",
    "phase2_order_events",
    "phase2_reservation_release_events",
)
_CAPACITY_CONTRACT_CHECK = "ck_phase2_batch_decisions_valid_capacity_observation_contract"
_CAPACITY_VISIBILITY_CHECK = "valid_capacity_visibility_binding"


def _lease_history_table() -> sa.TableClause:
    return sa.table(
        _TABLE_NAME,
        sa.column("lease_sha256", sa.String(length=64)),
        sa.column("account_id", sa.String(length=64)),
        sa.column("fencing_generation", sa.BigInteger()),
        sa.column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.column("expires_at", sa.DateTime(timezone=True)),
        sa.column("revision_number", sa.BigInteger()),
        sa.column("previous_lease_sha256", sa.String(length=64)),
    )


def _backfill_revision_chain() -> None:
    """Number each pre-existing generation by its canonical historical order."""

    connection = op.get_bind()
    leases = _lease_history_table()
    rows = (
        connection.execute(
            sa.select(
                leases.c.lease_sha256,
                leases.c.account_id,
                leases.c.fencing_generation,
            ).order_by(
                leases.c.account_id,
                leases.c.fencing_generation,
                leases.c.heartbeat_at,
                leases.c.expires_at,
                leases.c.lease_sha256,
            )
        )
        .mappings()
        .all()
    )

    prior_history: tuple[str, int] | None = None
    prior_digest: str | None = None
    revision_number = 0
    for row in rows:
        history = (str(row["account_id"]), int(row["fencing_generation"]))
        if history != prior_history:
            prior_history = history
            prior_digest = None
            revision_number = 1
        else:
            revision_number += 1
        lease_sha256 = str(row["lease_sha256"])
        result = connection.execute(
            sa.update(leases)
            .where(leases.c.lease_sha256 == lease_sha256)
            .values(
                revision_number=revision_number,
                previous_lease_sha256=prior_digest,
            )
        )
        if result.rowcount != 1:
            raise RuntimeError("account lease revision backfill did not update exactly one row")
        prior_digest = lease_sha256


def _require_legacy_only_downgrade() -> None:
    """Refuse to erase revision or capacity ordering required by current facts."""

    connection = op.get_bind()
    leases = sa.table(
        _TABLE_NAME,
        sa.column("lease_sha256", sa.String(length=64)),
        sa.column("canonical_payload", sa.Text()),
    )
    rows = connection.execute(
        sa.select(leases.c.lease_sha256, leases.c.canonical_payload).order_by(leases.c.lease_sha256)
    ).mappings()
    for row in rows:
        canonical_payload = row["canonical_payload"]
        lease_sha256 = row["lease_sha256"]
        if not isinstance(canonical_payload, str) or not isinstance(lease_sha256, str):
            raise RuntimeError(
                "cannot downgrade account lease history with an unauthenticated contract"
            )
        try:
            payload = json.loads(canonical_payload)
        except (TypeError, ValueError) as error:
            raise RuntimeError(
                "cannot downgrade account lease history with an unauthenticated contract"
            ) from error
        if hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest() != lease_sha256:
            raise RuntimeError(
                "cannot downgrade account lease history with an unauthenticated contract"
            )
        contract: object | None = None
        if (
            isinstance(payload, dict)
            and set(payload) == {"type", "value"}
            and payload["type"] == "tuple"
            and isinstance(payload["value"], list)
            and payload["value"]
        ):
            first_value = payload["value"][0]
            if (
                isinstance(first_value, dict)
                and set(first_value) == {"type", "value"}
                and first_value["type"] == "string"
            ):
                contract = first_value["value"]
        if contract != _LEGACY_LEASE_CONTRACT_VERSION:
            if contract == _CURRENT_LEASE_CONTRACT_VERSION:
                raise RuntimeError(
                    "cannot downgrade after a v2 account lease revision has been persisted"
                )
            raise RuntimeError(
                "cannot downgrade account lease history with an unauthenticated contract"
            )

    decisions = sa.table(
        _CAPACITY_DECISION_TABLE,
        sa.column("capacity_observation_contract", sa.String(length=64)),
    )
    current_decisions = connection.scalar(
        sa.select(sa.func.count())
        .select_from(decisions)
        .where(decisions.c.capacity_observation_contract == _CURRENT_CAPACITY_OBSERVATION_CONTRACT)
    )
    if current_decisions:
        raise RuntimeError(
            "cannot downgrade after sequence-ordered capacity observations have been persisted"
        )
    for table_name in _CAPACITY_MUTATION_TABLES:
        mutations = sa.table(
            table_name,
            sa.column("visible_after_observation_sequence", sa.BigInteger()),
        )
        if connection.scalar(
            sa.select(sa.func.count())
            .select_from(mutations)
            .where(mutations.c.visible_after_observation_sequence > 0)
        ):
            raise RuntimeError(
                "cannot downgrade after sequence-ordered capacity mutations have been persisted"
            )


def _upgrade_capacity_observation_ordering() -> None:
    op.add_column(
        _CAPACITY_DECISION_TABLE,
        sa.Column("capacity_observation_contract", sa.String(length=64), nullable=True),
    )
    decisions = sa.table(
        _CAPACITY_DECISION_TABLE,
        sa.column("capacity_observation_contract", sa.String(length=64)),
    )
    op.get_bind().execute(
        sa.update(decisions).values(
            capacity_observation_contract=_LEGACY_CAPACITY_OBSERVATION_CONTRACT
        )
    )
    with op.batch_alter_table(_CAPACITY_DECISION_TABLE) as batch_op:
        batch_op.alter_column(
            "capacity_observation_contract",
            existing_type=sa.String(length=64),
            nullable=False,
        )
        batch_op.create_check_constraint(
            op.f(_CAPACITY_CONTRACT_CHECK),
            "capacity_observation_contract IN "
            "('phase2-capacity-observation-v3', 'phase2-capacity-observation-v4')",
        )

    for table_name in _CAPACITY_MUTATION_TABLES:
        op.add_column(
            table_name,
            sa.Column(
                "visible_after_observation_sequence",
                sa.BigInteger(),
                nullable=False,
                server_default="0",
            ),
        )
        op.add_column(
            table_name,
            sa.Column("capacity_visibility_sha256", sa.String(length=64), nullable=True),
        )
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.create_check_constraint(
                op.f(_CAPACITY_VISIBILITY_CHECK),
                "(visible_after_observation_sequence = 0 "
                "AND capacity_visibility_sha256 IS NULL) "
                "OR (visible_after_observation_sequence > 0 "
                "AND length(capacity_visibility_sha256) = 64)",
            )
            batch_op.alter_column(
                "visible_after_observation_sequence",
                existing_type=sa.BigInteger(),
                server_default=None,
            )


def _downgrade_capacity_observation_ordering() -> None:
    for table_name in reversed(_CAPACITY_MUTATION_TABLES):
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.drop_constraint(op.f(_CAPACITY_VISIBILITY_CHECK), type_="check")
            batch_op.drop_column("capacity_visibility_sha256")
            batch_op.drop_column("visible_after_observation_sequence")
    with op.batch_alter_table(_CAPACITY_DECISION_TABLE) as batch_op:
        batch_op.drop_constraint(op.f(_CAPACITY_CONTRACT_CHECK), type_="check")
        batch_op.drop_column("capacity_observation_contract")


def upgrade() -> None:
    op.add_column(
        _TABLE_NAME,
        sa.Column("revision_number", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        _TABLE_NAME,
        sa.Column("previous_lease_sha256", sa.String(length=64), nullable=True),
    )
    _backfill_revision_chain()

    op.drop_index(_INDEX_NAME, table_name=_TABLE_NAME)
    with op.batch_alter_table(_TABLE_NAME) as batch_op:
        batch_op.alter_column(
            "revision_number",
            existing_type=sa.BigInteger(),
            nullable=False,
        )
        batch_op.drop_constraint(op.f(_HASH_CHECK), type_="check")
        batch_op.create_check_constraint(
            op.f(_HASH_CHECK),
            "length(lease_sha256) = 64 AND length(policy_sha256) = 64 "
            "AND (previous_lease_sha256 IS NULL OR length(previous_lease_sha256) = 64)",
        )
        batch_op.create_check_constraint(
            op.f(_POSITIVE_REVISION_CHECK),
            "revision_number > 0",
        )
        batch_op.create_check_constraint(
            op.f(_PREDECESSOR_SHAPE_CHECK),
            "(revision_number = 1 AND previous_lease_sha256 IS NULL) "
            "OR (revision_number > 1 AND previous_lease_sha256 IS NOT NULL "
            "AND previous_lease_sha256 <> lease_sha256)",
        )
        batch_op.create_unique_constraint(
            _REVISION_UNIQUE,
            ["account_id", "fencing_generation", "revision_number"],
        )
        batch_op.create_foreign_key(
            _PREDECESSOR_FOREIGN_KEY,
            _TABLE_NAME,
            ["account_id", "fencing_generation", "previous_lease_sha256"],
            ["account_id", "fencing_generation", "lease_sha256"],
        )
    op.create_index(
        _INDEX_NAME,
        _TABLE_NAME,
        ["account_id", "fencing_generation", "revision_number"],
        unique=False,
    )
    _upgrade_capacity_observation_ordering()


def downgrade() -> None:
    _require_legacy_only_downgrade()
    _downgrade_capacity_observation_ordering()
    op.drop_index(_INDEX_NAME, table_name=_TABLE_NAME)
    with op.batch_alter_table(_TABLE_NAME) as batch_op:
        batch_op.drop_constraint(_PREDECESSOR_FOREIGN_KEY, type_="foreignkey")
        batch_op.drop_constraint(_REVISION_UNIQUE, type_="unique")
        batch_op.drop_constraint(op.f(_PREDECESSOR_SHAPE_CHECK), type_="check")
        batch_op.drop_constraint(op.f(_POSITIVE_REVISION_CHECK), type_="check")
        batch_op.drop_constraint(op.f(_HASH_CHECK), type_="check")
        batch_op.create_check_constraint(
            op.f(_HASH_CHECK),
            "length(lease_sha256) = 64 AND length(policy_sha256) = 64",
        )
        batch_op.drop_column("previous_lease_sha256")
        batch_op.drop_column("revision_number")
    op.create_index(
        _INDEX_NAME,
        _TABLE_NAME,
        ["account_id", "fencing_generation"],
        unique=False,
    )
