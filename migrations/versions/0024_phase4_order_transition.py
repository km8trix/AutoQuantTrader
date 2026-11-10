"""Add durable order-pair page transition admission.

Revision ID: 0024_phase4_order_transition
Revises: 0023_phase4_position_transition
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_phase4_order_transition"
down_revision: str | None = "0023_phase4_position_transition"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLAN_TABLE = "phase4_alpaca_paper_order_snapshot_plans"
_PAGE_TABLE = "phase4_alpaca_paper_order_snapshot_pages"
_HEAD_TABLE = "phase4_alpaca_paper_order_snapshot_heads"
_PREPARATION_TABLE = "phase4_alpaca_paper_order_snapshot_preparations"
_PAGE_PREPARATION_INDEX = "uq_phase4_order_snapshot_page_preparation"
_HEAD_PREPARATION_INDEX = "uq_phase4_order_snapshot_head_preparation"
_MEMBER_TABLE = "phase4_alpaca_paper_order_transition_members"
_CLAIM_TABLE = "phase4_alpaca_paper_order_transition_claims"
_CONSUMPTION_TABLE = "phase4_alpaca_paper_order_transition_consumptions"

_PREPARATION_FIELDS = (
    "preparation_sha256",
    "snapshot_id",
    "account_id",
    "page_number",
    "plan_sha256",
    "before_order_id",
    "description_sha256",
    "prefix_capture_sha256",
    "prefix_page_count",
    "previous_page_receipt_id",
    "previous_page_receipt_sha256",
    "previous_persisted_page_sha256",
    "prepared_at",
)


def _preparation_table() -> sa.TableClause:
    return sa.table(
        _PREPARATION_TABLE,
        sa.column("preparation_sha256", sa.String(64)),
        sa.column("snapshot_id", sa.String(36)),
        sa.column("account_id", sa.String(64)),
        sa.column("page_number", sa.BigInteger()),
        sa.column("plan_sha256", sa.String(64)),
        sa.column("before_order_id", sa.String(36)),
        sa.column("description_sha256", sa.String(64)),
        sa.column("prefix_capture_sha256", sa.String(64)),
        sa.column("prefix_page_count", sa.BigInteger()),
        sa.column("previous_page_receipt_id", sa.String(36)),
        sa.column("previous_page_receipt_sha256", sa.String(64)),
        sa.column("previous_persisted_page_sha256", sa.String(64)),
        sa.column("prepared_at", sa.DateTime(timezone=True)),
    )


def _lock_order_snapshot_projection(connection: sa.Connection) -> None:
    """Exclude Phase 4O writers while the migration projects immutable facts."""

    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text(
                "LOCK TABLE "
                f"{_PLAN_TABLE}, {_PAGE_TABLE}, {_HEAD_TABLE} "
                "IN SHARE ROW EXCLUSIVE MODE"
            )
        )


def _projected_preparations() -> sa.Subquery:
    pages = sa.table(
        _PAGE_TABLE,
        sa.column("preparation_sha256"),
        sa.column("snapshot_id"),
        sa.column("account_id"),
        sa.column("page_number"),
        sa.column("plan_sha256"),
        sa.column("before_order_id"),
        sa.column("description_sha256"),
        sa.column("prefix_capture_sha256"),
        sa.column("prefix_page_count"),
        sa.column("preparation_previous_page_receipt_id"),
        sa.column("preparation_previous_page_receipt_sha256"),
        sa.column("previous_persisted_page_sha256"),
        sa.column("prepared_at"),
    )
    heads = sa.table(
        _HEAD_TABLE,
        sa.column("preparation_sha256"),
        sa.column("snapshot_id"),
        sa.column("account_id"),
        sa.column("next_page_number"),
        sa.column("plan_sha256"),
        sa.column("next_before_order_id"),
        sa.column("prepared_description_sha256"),
        sa.column("prepared_prefix_capture_sha256"),
        sa.column("prepared_prefix_page_count"),
        sa.column("prepared_previous_page_receipt_id"),
        sa.column("prepared_previous_page_receipt_sha256"),
        sa.column("next_previous_page_sha256"),
        sa.column("prepared_at"),
        sa.column("state"),
    )
    page_projection = sa.select(
        pages.c.preparation_sha256,
        pages.c.snapshot_id,
        pages.c.account_id,
        pages.c.page_number,
        pages.c.plan_sha256,
        pages.c.before_order_id,
        pages.c.description_sha256,
        pages.c.prefix_capture_sha256,
        pages.c.prefix_page_count,
        pages.c.preparation_previous_page_receipt_id.label("previous_page_receipt_id"),
        pages.c.preparation_previous_page_receipt_sha256.label("previous_page_receipt_sha256"),
        pages.c.previous_persisted_page_sha256,
        pages.c.prepared_at,
    )
    head_projection = sa.select(
        heads.c.preparation_sha256,
        heads.c.snapshot_id,
        heads.c.account_id,
        heads.c.next_page_number.label("page_number"),
        heads.c.plan_sha256,
        heads.c.next_before_order_id.label("before_order_id"),
        heads.c.prepared_description_sha256.label("description_sha256"),
        heads.c.prepared_prefix_capture_sha256.label("prefix_capture_sha256"),
        heads.c.prepared_prefix_page_count.label("prefix_page_count"),
        heads.c.prepared_previous_page_receipt_id.label("previous_page_receipt_id"),
        heads.c.prepared_previous_page_receipt_sha256.label("previous_page_receipt_sha256"),
        heads.c.next_previous_page_sha256.label("previous_persisted_page_sha256"),
        heads.c.prepared_at,
    ).where(heads.c.state == "stalled")
    return sa.union_all(page_projection, head_projection).subquery()


def _validate_preparation_projection(connection: sa.Connection) -> None:
    """Require exact bidirectional equality with the Phase 4O projection."""

    projected = _projected_preparations()
    preparations = _preparation_table()
    projected_select = sa.select(*(projected.c[name] for name in _PREPARATION_FIELDS))
    preparation_select = sa.select(*(preparations.c[name] for name in _PREPARATION_FIELDS))
    projected_count = int(connection.scalar(sa.select(sa.func.count()).select_from(projected)) or 0)
    preparation_count = int(
        connection.scalar(sa.select(sa.func.count()).select_from(preparations)) or 0
    )
    missing = connection.scalar(
        sa.select(sa.literal(1))
        .select_from(sa.except_(projected_select, preparation_select).subquery())
        .limit(1)
    )
    extra = connection.scalar(
        sa.select(sa.literal(1))
        .select_from(sa.except_(preparation_select, projected_select).subquery())
        .limit(1)
    )
    if projected_count != preparation_count or missing is not None or extra is not None:
        raise RuntimeError(
            "order snapshot preparation facts do not exactly match their Phase 4O projection"
        )


def _backfill_preparations() -> None:
    """Project existing committed and unresolved Phase 4O preparations."""

    connection = op.get_bind()
    preparations = _preparation_table()
    pages = sa.table(
        _PAGE_TABLE,
        sa.column("preparation_sha256", sa.String(64)),
        sa.column("snapshot_id", sa.String(36)),
        sa.column("account_id", sa.String(64)),
        sa.column("page_number", sa.BigInteger()),
        sa.column("plan_sha256", sa.String(64)),
        sa.column("before_order_id", sa.String(36)),
        sa.column("description_sha256", sa.String(64)),
        sa.column("prefix_capture_sha256", sa.String(64)),
        sa.column("prefix_page_count", sa.BigInteger()),
        sa.column("preparation_previous_page_receipt_id", sa.String(36)),
        sa.column("preparation_previous_page_receipt_sha256", sa.String(64)),
        sa.column("previous_persisted_page_sha256", sa.String(64)),
        sa.column("prepared_at", sa.DateTime(timezone=True)),
    )
    heads = sa.table(
        _HEAD_TABLE,
        sa.column("preparation_sha256", sa.String(64)),
        sa.column("snapshot_id", sa.String(36)),
        sa.column("account_id", sa.String(64)),
        sa.column("next_page_number", sa.BigInteger()),
        sa.column("plan_sha256", sa.String(64)),
        sa.column("next_before_order_id", sa.String(36)),
        sa.column("prepared_description_sha256", sa.String(64)),
        sa.column("prepared_prefix_capture_sha256", sa.String(64)),
        sa.column("prepared_prefix_page_count", sa.BigInteger()),
        sa.column("prepared_previous_page_receipt_id", sa.String(36)),
        sa.column("prepared_previous_page_receipt_sha256", sa.String(64)),
        sa.column("next_previous_page_sha256", sa.String(64)),
        sa.column("prepared_at", sa.DateTime(timezone=True)),
        sa.column("state", sa.String(32)),
    )
    fields = (
        "preparation_sha256",
        "snapshot_id",
        "account_id",
        "page_number",
        "plan_sha256",
        "before_order_id",
        "description_sha256",
        "prefix_capture_sha256",
        "prefix_page_count",
        "previous_page_receipt_id",
        "previous_page_receipt_sha256",
        "previous_persisted_page_sha256",
        "prepared_at",
    )
    page_count = int(connection.scalar(sa.select(sa.func.count()).select_from(pages)) or 0)
    stalled_count = int(
        connection.scalar(
            sa.select(sa.func.count()).select_from(heads).where(heads.c.state == "stalled")
        )
        or 0
    )
    connection.execute(
        sa.insert(preparations).from_select(
            fields,
            sa.select(
                pages.c.preparation_sha256,
                pages.c.snapshot_id,
                pages.c.account_id,
                pages.c.page_number,
                pages.c.plan_sha256,
                pages.c.before_order_id,
                pages.c.description_sha256,
                pages.c.prefix_capture_sha256,
                pages.c.prefix_page_count,
                pages.c.preparation_previous_page_receipt_id,
                pages.c.preparation_previous_page_receipt_sha256,
                pages.c.previous_persisted_page_sha256,
                pages.c.prepared_at,
            ).order_by(pages.c.snapshot_id, pages.c.page_number),
        )
    )
    connection.execute(
        sa.insert(preparations).from_select(
            fields,
            sa.select(
                heads.c.preparation_sha256,
                heads.c.snapshot_id,
                heads.c.account_id,
                heads.c.next_page_number,
                heads.c.plan_sha256,
                heads.c.next_before_order_id,
                heads.c.prepared_description_sha256,
                heads.c.prepared_prefix_capture_sha256,
                heads.c.prepared_prefix_page_count,
                heads.c.prepared_previous_page_receipt_id,
                heads.c.prepared_previous_page_receipt_sha256,
                heads.c.next_previous_page_sha256,
                heads.c.prepared_at,
            )
            .where(heads.c.state == "stalled")
            .order_by(heads.c.snapshot_id),
        )
    )
    actual_count = int(connection.scalar(sa.select(sa.func.count()).select_from(preparations)) or 0)
    if actual_count != page_count + stalled_count:
        raise RuntimeError("order snapshot preparation backfill did not preserve every exact claim")


def _create_transition_tables() -> None:
    op.create_table(
        _MEMBER_TABLE,
        sa.Column("member_id", sa.String(36), nullable=False),
        sa.Column("round_id", sa.String(36), nullable=False),
        sa.Column("member_role", sa.String(16), nullable=False),
        sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
        sa.Column("page_limit", sa.BigInteger(), nullable=False),
        sa.Column("maximum_pages", sa.BigInteger(), nullable=False),
        sa.Column("plan_canonical_payload", sa.Text(), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("member_id", name=op.f(f"pk_{_MEMBER_TABLE}")),
        *(
            sa.UniqueConstraint(column, name=op.f(f"uq_{_MEMBER_TABLE}_{column}"))
            for column in ("snapshot_id", "plan_sha256", "semantic_sha256")
        ),
        sa.UniqueConstraint(
            "round_id",
            "member_role",
            name="uq_phase4_order_transition_member_role",
        ),
        sa.UniqueConstraint(
            "account_id",
            "capture_idempotency_key",
            name="uq_phase4_order_transition_member_account_key",
        ),
        sa.UniqueConstraint(
            "member_id",
            "round_id",
            "member_role",
            "transition_plan_sha256",
            "account_id",
            "snapshot_id",
            "plan_sha256",
            "semantic_sha256",
            name="uq_phase4_order_transition_member_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_order_transition_member_account",
        ),
        sa.CheckConstraint(
            "member_role IN ('earlier', 'later') "
            "AND page_limit BETWEEN 1 AND 500 "
            "AND maximum_pages BETWEEN 1 AND 8",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_order_transition_member_scope"),
        ),
        sa.CheckConstraint(
            "length(member_id) = 36 "
            "AND length(round_id) = 36 "
            "AND length(snapshot_id) = 36 "
            "AND length(transition_plan_sha256) = 64 "
            "AND length(plan_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_order_transition_member_identity"),
        ),
        sa.CheckConstraint(
            "length(capture_idempotency_key) BETWEEN 8 AND 128 "
            "AND length(plan_canonical_payload) BETWEEN 2 AND 16384 "
            "AND length(canonical_payload) BETWEEN 2 AND 32768",
            name=op.f(f"ck_{_MEMBER_TABLE}_phase4_order_transition_member_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_order_transition_member_account_round",
        _MEMBER_TABLE,
        ["account_id", "round_id"],
        unique=False,
    )

    op.create_table(
        _CLAIM_TABLE,
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("round_id", sa.String(36), nullable=False),
        sa.Column("transition_plan_sha256", sa.String(64), nullable=False),
        sa.Column("selected_role", sa.String(16), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("earlier_member_id", sa.String(36), nullable=False),
        sa.Column("earlier_member_role", sa.String(16), nullable=False),
        sa.Column("earlier_member_sha256", sa.String(64), nullable=False),
        sa.Column("earlier_snapshot_id", sa.String(36), nullable=False),
        sa.Column("earlier_plan_sha256", sa.String(64), nullable=False),
        sa.Column("later_member_id", sa.String(36), nullable=False),
        sa.Column("later_member_role", sa.String(16), nullable=False),
        sa.Column("later_member_sha256", sa.String(64), nullable=False),
        sa.Column("later_snapshot_id", sa.String(36), nullable=False),
        sa.Column("later_plan_sha256", sa.String(64), nullable=False),
        sa.Column("selected_member_id", sa.String(36), nullable=False),
        sa.Column("selected_snapshot_id", sa.String(36), nullable=False),
        sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
        sa.Column("page_number", sa.BigInteger(), nullable=False),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("before_order_id", sa.String(36), nullable=True),
        sa.Column("prefix_id", sa.String(36), nullable=False),
        sa.Column("prefix_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
        sa.Column("previous_page_receipt_id", sa.String(36), nullable=True),
        sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
        sa.Column("previous_claim_id", sa.String(36), nullable=True),
        sa.Column("previous_claim_sha256", sa.String(64), nullable=True),
        sa.Column("prior_earlier_prefix_id", sa.String(36), nullable=True),
        sa.Column("prior_earlier_prefix_sha256", sa.String(64), nullable=True),
        sa.Column("prior_earlier_source_head_sha256", sa.String(64), nullable=True),
        sa.Column("prior_earlier_tip_receipt_id", sa.String(36), nullable=True),
        sa.Column("prior_earlier_tip_receipt_sha256", sa.String(64), nullable=True),
        sa.Column(
            "prior_earlier_tip_received_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("eligible_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "commit_fence_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("transition_policy_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("claim_id", name=op.f(f"pk_{_CLAIM_TABLE}")),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_CLAIM_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "round_id",
            "selected_role",
            "page_number",
            name="uq_phase4_order_transition_claim_page",
        ),
        sa.UniqueConstraint(
            "claim_id",
            "semantic_sha256",
            name="uq_phase4_order_transition_claim_identity",
        ),
        sa.UniqueConstraint(
            "claim_id",
            "semantic_sha256",
            "round_id",
            "selected_role",
            "selected_member_id",
            "selected_snapshot_id",
            "selected_plan_sha256",
            "page_number",
            "description_sha256",
            "fence_owner_id",
            "fence_lease_id",
            "fence_fencing_generation",
            "fence_sha256",
            "fence_policy_sha256",
            "commit_fence_lease_sha256",
            "commit_fence_receipt_sha256",
            "selected_at",
            "commit_fence_valid_until",
            name="uq_phase4_order_transition_claim_exact",
        ),
        sa.ForeignKeyConstraint(
            [
                "earlier_member_id",
                "round_id",
                "earlier_member_role",
                "transition_plan_sha256",
                "account_id",
                "earlier_snapshot_id",
                "earlier_plan_sha256",
                "earlier_member_sha256",
            ],
            [
                f"{_MEMBER_TABLE}.member_id",
                f"{_MEMBER_TABLE}.round_id",
                f"{_MEMBER_TABLE}.member_role",
                f"{_MEMBER_TABLE}.transition_plan_sha256",
                f"{_MEMBER_TABLE}.account_id",
                f"{_MEMBER_TABLE}.snapshot_id",
                f"{_MEMBER_TABLE}.plan_sha256",
                f"{_MEMBER_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_transition_claim_earlier",
        ),
        sa.ForeignKeyConstraint(
            [
                "later_member_id",
                "round_id",
                "later_member_role",
                "transition_plan_sha256",
                "account_id",
                "later_snapshot_id",
                "later_plan_sha256",
                "later_member_sha256",
            ],
            [
                f"{_MEMBER_TABLE}.member_id",
                f"{_MEMBER_TABLE}.round_id",
                f"{_MEMBER_TABLE}.member_role",
                f"{_MEMBER_TABLE}.transition_plan_sha256",
                f"{_MEMBER_TABLE}.account_id",
                f"{_MEMBER_TABLE}.snapshot_id",
                f"{_MEMBER_TABLE}.plan_sha256",
                f"{_MEMBER_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_transition_claim_later",
        ),
        sa.ForeignKeyConstraint(
            ["previous_claim_id", "previous_claim_sha256"],
            [f"{_CLAIM_TABLE}.claim_id", f"{_CLAIM_TABLE}.semantic_sha256"],
            name="fk_phase4_order_transition_claim_predecessor",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_order_transition_claim_lease",
        ),
        sa.CheckConstraint(
            "selected_role IN ('earlier', 'later') "
            "AND earlier_member_role = 'earlier' "
            "AND later_member_role = 'later' "
            "AND earlier_member_id <> later_member_id "
            "AND earlier_snapshot_id <> later_snapshot_id",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_order_transition_claim_scope"),
        ),
        sa.CheckConstraint(
            "(selected_role = 'earlier' "
            "AND selected_member_id = earlier_member_id "
            "AND selected_snapshot_id = earlier_snapshot_id "
            "AND selected_plan_sha256 = earlier_plan_sha256 "
            "AND prior_earlier_prefix_id IS NULL "
            "AND prior_earlier_prefix_sha256 IS NULL "
            "AND prior_earlier_source_head_sha256 IS NULL "
            "AND prior_earlier_tip_receipt_id IS NULL "
            "AND prior_earlier_tip_receipt_sha256 IS NULL "
            "AND prior_earlier_tip_received_at IS NULL "
            "AND eligible_at IS NULL) "
            "OR (selected_role = 'later' "
            "AND selected_member_id = later_member_id "
            "AND selected_snapshot_id = later_snapshot_id "
            "AND selected_plan_sha256 = later_plan_sha256 "
            "AND prior_earlier_prefix_id IS NOT NULL "
            "AND prior_earlier_prefix_sha256 IS NOT NULL "
            "AND prior_earlier_source_head_sha256 IS NOT NULL "
            "AND prior_earlier_tip_receipt_id IS NOT NULL "
            "AND prior_earlier_tip_receipt_sha256 IS NOT NULL "
            "AND prior_earlier_tip_received_at IS NOT NULL "
            "AND eligible_at IS NOT NULL "
            "AND selected_at >= eligible_at)",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_order_transition_claim_role_shape"),
        ),
        sa.CheckConstraint(
            "(page_number = 1 "
            "AND prefix_page_count = 0 "
            "AND before_order_id IS NULL "
            "AND previous_page_receipt_id IS NULL "
            "AND previous_page_receipt_sha256 IS NULL "
            "AND previous_persisted_page_sha256 IS NULL "
            "AND previous_claim_id IS NULL "
            "AND previous_claim_sha256 IS NULL) "
            "OR (page_number > 1 "
            "AND prefix_page_count = page_number - 1 "
            "AND before_order_id IS NOT NULL "
            "AND previous_page_receipt_id IS NOT NULL "
            "AND previous_page_receipt_sha256 IS NOT NULL "
            "AND previous_persisted_page_sha256 IS NOT NULL "
            "AND previous_claim_id IS NOT NULL "
            "AND previous_claim_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_order_transition_claim_page_shape"),
        ),
        sa.CheckConstraint(
            "page_number BETWEEN 1 AND 8 "
            "AND fence_fencing_generation > 0 "
            "AND selected_at < commit_fence_valid_until",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_order_transition_claim_bounds"),
        ),
        sa.CheckConstraint(
            "length(claim_id) = 36 "
            "AND length(round_id) = 36 "
            "AND length(prefix_id) = 36 "
            "AND length(transition_plan_sha256) = 64 "
            "AND length(description_sha256) = 64 "
            "AND length(prefix_sha256) = 64 "
            "AND length(prefix_capture_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(transition_policy_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_order_transition_claim_identity"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_CLAIM_TABLE}_phase4_order_transition_claim_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_order_transition_claim_account_selected",
        _CLAIM_TABLE,
        ["account_id", "selected_at"],
        unique=False,
    )

    op.create_table(
        _CONSUMPTION_TABLE,
        sa.Column("consumption_id", sa.String(36), nullable=False),
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("claim_sha256", sa.String(64), nullable=False),
        sa.Column("round_id", sa.String(36), nullable=False),
        sa.Column("selected_role", sa.String(16), nullable=False),
        sa.Column("selected_member_id", sa.String(36), nullable=False),
        sa.Column("selected_snapshot_id", sa.String(36), nullable=False),
        sa.Column("selected_plan_sha256", sa.String(64), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("page_number", sa.BigInteger(), nullable=False),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("preparation_id", sa.String(36), nullable=False),
        sa.Column("preparation_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("claim_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("claim_selected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "commit_fence_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint(
            "consumption_id",
            name=op.f(f"pk_{_CONSUMPTION_TABLE}"),
        ),
        *(
            sa.UniqueConstraint(
                column,
                name=op.f(f"uq_{_CONSUMPTION_TABLE}_{column}"),
            )
            for column in (
                "claim_id",
                "claim_sha256",
                "preparation_id",
                "preparation_sha256",
                "semantic_sha256",
            )
        ),
        sa.ForeignKeyConstraint(
            [
                "claim_id",
                "claim_sha256",
                "round_id",
                "selected_role",
                "selected_member_id",
                "selected_snapshot_id",
                "selected_plan_sha256",
                "page_number",
                "description_sha256",
                "fence_owner_id",
                "fence_lease_id",
                "fence_fencing_generation",
                "fence_sha256",
                "fence_policy_sha256",
                "commit_fence_lease_sha256",
                "claim_fence_receipt_sha256",
                "claim_selected_at",
                "commit_fence_valid_until",
            ],
            [
                f"{_CLAIM_TABLE}.claim_id",
                f"{_CLAIM_TABLE}.semantic_sha256",
                f"{_CLAIM_TABLE}.round_id",
                f"{_CLAIM_TABLE}.selected_role",
                f"{_CLAIM_TABLE}.selected_member_id",
                f"{_CLAIM_TABLE}.selected_snapshot_id",
                f"{_CLAIM_TABLE}.selected_plan_sha256",
                f"{_CLAIM_TABLE}.page_number",
                f"{_CLAIM_TABLE}.description_sha256",
                f"{_CLAIM_TABLE}.fence_owner_id",
                f"{_CLAIM_TABLE}.fence_lease_id",
                f"{_CLAIM_TABLE}.fence_fencing_generation",
                f"{_CLAIM_TABLE}.fence_sha256",
                f"{_CLAIM_TABLE}.fence_policy_sha256",
                f"{_CLAIM_TABLE}.commit_fence_lease_sha256",
                f"{_CLAIM_TABLE}.commit_fence_receipt_sha256",
                f"{_CLAIM_TABLE}.selected_at",
                f"{_CLAIM_TABLE}.commit_fence_valid_until",
            ],
            name="fk_phase4_order_transition_consumption_claim",
        ),
        sa.ForeignKeyConstraint(
            [
                "preparation_sha256",
                "selected_snapshot_id",
                "account_id",
                "page_number",
                "selected_plan_sha256",
                "description_sha256",
                "prefix_capture_sha256",
                "prefix_page_count",
                "prepared_at",
            ],
            [
                f"{_PREPARATION_TABLE}.preparation_sha256",
                f"{_PREPARATION_TABLE}.snapshot_id",
                f"{_PREPARATION_TABLE}.account_id",
                f"{_PREPARATION_TABLE}.page_number",
                f"{_PREPARATION_TABLE}.plan_sha256",
                f"{_PREPARATION_TABLE}.description_sha256",
                f"{_PREPARATION_TABLE}.prefix_capture_sha256",
                f"{_PREPARATION_TABLE}.prefix_page_count",
                f"{_PREPARATION_TABLE}.prepared_at",
            ],
            name="fk_phase4_order_transition_consumption_preparation",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_order_transition_consumption_lease",
        ),
        sa.CheckConstraint(
            "selected_role IN ('earlier', 'later') "
            "AND page_number BETWEEN 1 AND 8 "
            "AND prefix_page_count = page_number - 1 "
            "AND fence_fencing_generation > 0 "
            "AND claim_selected_at <= prepared_at "
            "AND prepared_at <= consumed_at "
            "AND consumed_at < commit_fence_valid_until",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_order_transition_consumption_time"),
        ),
        sa.CheckConstraint(
            "length(consumption_id) = 36 "
            "AND length(claim_id) = 36 "
            "AND length(round_id) = 36 "
            "AND length(selected_member_id) = 36 "
            "AND length(selected_snapshot_id) = 36 "
            "AND length(preparation_id) = 36 "
            "AND length(claim_sha256) = 64 "
            "AND length(selected_plan_sha256) = 64 "
            "AND length(description_sha256) = 64 "
            "AND length(preparation_sha256) = 64 "
            "AND length(prefix_capture_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(claim_fence_receipt_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_order_transition_consumption_identity"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_CONSUMPTION_TABLE}_phase4_order_transition_consumption_payload"),
        ),
    )
    op.create_index(
        "ix_phase4_order_transition_consumption_account_time",
        _CONSUMPTION_TABLE,
        ["account_id", "consumed_at"],
        unique=False,
    )


def upgrade() -> None:
    connection = op.get_bind()
    _lock_order_snapshot_projection(connection)
    op.create_table(
        _PREPARATION_TABLE,
        sa.Column("preparation_sha256", sa.String(64), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("page_number", sa.BigInteger(), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("before_order_id", sa.String(36), nullable=True),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
        sa.Column("previous_page_receipt_id", sa.String(36), nullable=True),
        sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "preparation_sha256",
            name=op.f(f"pk_{_PREPARATION_TABLE}"),
        ),
        sa.UniqueConstraint(
            "snapshot_id",
            "page_number",
            name="uq_phase4_order_snapshot_preparation_page",
        ),
        sa.UniqueConstraint(
            "preparation_sha256",
            "snapshot_id",
            "account_id",
            "page_number",
            "plan_sha256",
            "description_sha256",
            "prefix_capture_sha256",
            "prefix_page_count",
            "prepared_at",
            name="uq_phase4_order_snapshot_preparation_exact",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id", "account_id", "plan_sha256"],
            [
                f"{_PLAN_TABLE}.snapshot_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_snapshot_preparation_plan",
        ),
        sa.ForeignKeyConstraint(
            [
                "snapshot_id",
                "prefix_page_count",
                "previous_page_receipt_id",
                "previous_page_receipt_sha256",
                "previous_persisted_page_sha256",
            ],
            [
                f"{_PAGE_TABLE}.snapshot_id",
                f"{_PAGE_TABLE}.page_number",
                f"{_PAGE_TABLE}.receipt_id",
                f"{_PAGE_TABLE}.semantic_sha256",
                f"{_PAGE_TABLE}.persisted_page_sha256",
            ],
            name="fk_phase4_order_snapshot_preparation_predecessor",
        ),
        sa.CheckConstraint(
            "(page_number = 1 "
            "AND before_order_id IS NULL "
            "AND prefix_page_count = 0 "
            "AND previous_page_receipt_id IS NULL "
            "AND previous_page_receipt_sha256 IS NULL "
            "AND previous_persisted_page_sha256 IS NULL) "
            "OR (page_number > 1 "
            "AND before_order_id IS NOT NULL "
            "AND prefix_page_count = page_number - 1 "
            "AND previous_page_receipt_id IS NOT NULL "
            "AND previous_page_receipt_sha256 IS NOT NULL "
            "AND previous_persisted_page_sha256 IS NOT NULL)",
            name=op.f(
                f"ck_{_PREPARATION_TABLE}_phase4_order_snapshot_preparation_predecessor_shape"
            ),
        ),
        sa.CheckConstraint(
            "page_number BETWEEN 1 AND 8",
            name=op.f(f"ck_{_PREPARATION_TABLE}_phase4_order_snapshot_preparation_page_bounds"),
        ),
        sa.CheckConstraint(
            "length(preparation_sha256) = 64 "
            "AND length(snapshot_id) = 36 "
            "AND (before_order_id IS NULL OR length(before_order_id) = 36) "
            "AND (previous_page_receipt_id IS NULL "
            "OR length(previous_page_receipt_id) = 36) "
            "AND length(plan_sha256) = 64 "
            "AND length(description_sha256) = 64 "
            "AND length(prefix_capture_sha256) = 64 "
            "AND (previous_page_receipt_sha256 IS NULL "
            "OR length(previous_page_receipt_sha256) = 64) "
            "AND (previous_persisted_page_sha256 IS NULL "
            "OR length(previous_persisted_page_sha256) = 64)",
            name=op.f(
                f"ck_{_PREPARATION_TABLE}_phase4_order_snapshot_preparation_identity_lengths"
            ),
        ),
    )
    op.create_index(
        "ix_phase4_order_snapshot_preparation_account_time",
        _PREPARATION_TABLE,
        ["account_id", "prepared_at"],
        unique=False,
    )
    _backfill_preparations()
    _validate_preparation_projection(connection)
    op.create_index(
        _PAGE_PREPARATION_INDEX,
        _PAGE_TABLE,
        ["preparation_sha256"],
        unique=True,
    )
    op.create_index(
        _HEAD_PREPARATION_INDEX,
        _HEAD_TABLE,
        ["preparation_sha256"],
        unique=True,
    )
    _create_transition_tables()


def downgrade() -> None:
    connection = op.get_bind()
    _lock_order_snapshot_projection(connection)
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text(
                "LOCK TABLE "
                f"{_CONSUMPTION_TABLE}, {_CLAIM_TABLE}, {_MEMBER_TABLE} "
                "IN SHARE ROW EXCLUSIVE MODE"
            )
        )
    for table_name in (_CONSUMPTION_TABLE, _CLAIM_TABLE, _MEMBER_TABLE):
        table = sa.table(table_name)
        if int(connection.scalar(sa.select(sa.func.count()).select_from(table)) or 0):
            raise RuntimeError("refusing to downgrade nonempty order-view transition history")
    _validate_preparation_projection(connection)
    op.drop_index(
        "ix_phase4_order_transition_consumption_account_time",
        table_name=_CONSUMPTION_TABLE,
    )
    op.drop_table(_CONSUMPTION_TABLE)
    op.drop_index(
        "ix_phase4_order_transition_claim_account_selected",
        table_name=_CLAIM_TABLE,
    )
    op.drop_table(_CLAIM_TABLE)
    op.drop_index(
        "ix_phase4_order_transition_member_account_round",
        table_name=_MEMBER_TABLE,
    )
    op.drop_table(_MEMBER_TABLE)
    op.drop_index(_HEAD_PREPARATION_INDEX, table_name=_HEAD_TABLE)
    op.drop_index(_PAGE_PREPARATION_INDEX, table_name=_PAGE_TABLE)
    op.drop_index(
        "ix_phase4_order_snapshot_preparation_account_time",
        table_name=_PREPARATION_TABLE,
    )
    op.drop_table(_PREPARATION_TABLE)
