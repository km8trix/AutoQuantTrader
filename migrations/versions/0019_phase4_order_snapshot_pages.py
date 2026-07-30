"""Add restart-safe authenticated Alpaca paper order snapshot pages.

Revision ID: 0019_phase4_order_snapshots
Revises: 0018_phase4_broker_inbox
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_phase4_order_snapshots"
down_revision: str | None = "0018_phase4_broker_inbox"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLAN_TABLE = "phase4_alpaca_paper_order_snapshot_plans"
_PAGE_TABLE = "phase4_alpaca_paper_order_snapshot_pages"
_HEAD_TABLE = "phase4_alpaca_paper_order_snapshot_heads"
_PERMIT_EXACT_INDEX = "ux_phase4_order_snapshot_permit_exact"


def upgrade() -> None:
    op.create_index(
        _PERMIT_EXACT_INDEX,
        "phase4_broker_request_permits",
        [
            "account_id",
            "permit_id",
            "semantic_sha256",
            "demand_id",
            "demand_sha256",
            "policy_sha256",
        ],
        unique=True,
    )
    op.create_table(
        _PLAN_TABLE,
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
        sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
        sa.Column("page_limit", sa.BigInteger(), nullable=False),
        sa.Column("maximum_pages", sa.BigInteger(), nullable=False),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id", name=op.f(f"pk_{_PLAN_TABLE}")),
        sa.UniqueConstraint(
            "account_id",
            "capture_idempotency_key",
            name="uq_phase4_order_snapshot_plan_account_key",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_PLAN_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "snapshot_id",
            "account_id",
            "semantic_sha256",
            name="uq_phase4_order_snapshot_plan_exact",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_order_snapshot_plan_account",
        ),
        sa.CheckConstraint(
            "length(snapshot_id) = 36 "
            "AND snapshot_id = lower(snapshot_id) "
            "AND substr(snapshot_id, 9, 1) = '-' "
            "AND substr(snapshot_id, 14, 1) = '-' "
            "AND substr(snapshot_id, 19, 1) = '-' "
            "AND substr(snapshot_id, 24, 1) = '-'",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_order_snapshot_plan_id_shape"),
        ),
        sa.CheckConstraint(
            "length(capture_idempotency_key) BETWEEN 8 AND 128",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_order_snapshot_plan_key_size"),
        ),
        sa.CheckConstraint(
            "page_limit BETWEEN 1 AND 500 AND maximum_pages BETWEEN 1 AND 8",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_order_snapshot_plan_bounds"),
        ),
        sa.CheckConstraint(
            "length(capability_sha256) = 64 "
            "AND length(traversal_profile_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_order_snapshot_plan_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 16384",
            name=op.f(f"ck_{_PLAN_TABLE}_phase4_order_snapshot_plan_payload_size"),
        ),
    )
    op.create_index(
        "ix_phase4_order_snapshot_plan_account_prepared",
        _PLAN_TABLE,
        ["account_id", "prepared_at"],
        unique=False,
    )

    op.create_table(
        _PAGE_TABLE,
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("page_number", sa.BigInteger(), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("preparation_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
        sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
        sa.Column("preparation_previous_page_receipt_id", sa.String(36), nullable=True),
        sa.Column(
            "preparation_previous_page_receipt_sha256",
            sa.String(64),
            nullable=True,
        ),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("secret_ref", sa.String(256), nullable=False),
        sa.Column("secret_version", sa.String(128), nullable=False),
        sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
        sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
        sa.Column("resolver_id", sa.String(128), nullable=False),
        sa.Column("resolver_version", sa.String(128), nullable=False),
        sa.Column(
            "credential_resolution_started_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "credential_resolution_valid_until",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("account_binding_id", sa.String(36), nullable=False),
        sa.Column("account_binding_sha256", sa.String(64), nullable=False),
        sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
        sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
        sa.Column(
            "pre_account_identity_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "post_account_identity_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("demand_id", sa.String(64), nullable=False),
        sa.Column("demand_sha256", sa.String(64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("permit_id", sa.String(64), nullable=False),
        sa.Column("permit_sha256", sa.String(64), nullable=False),
        sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("transport_request_sha256", sa.String(64), nullable=False),
        sa.Column("transport_response_sha256", sa.String(64), nullable=False),
        sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("provider_request_id", sa.String(256), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("ingress_sequence", sa.BigInteger(), nullable=False),
        sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_sha256", sa.String(64), nullable=False),
        sa.Column("persisted_page_sha256", sa.String(64), nullable=False),
        sa.Column("before_order_id", sa.String(36), nullable=True),
        sa.Column("next_before_order_id", sa.String(36), nullable=True),
        sa.Column("terminal_page", sa.Boolean(), nullable=False),
        sa.Column("bounded_truncation", sa.Boolean(), nullable=False),
        sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("receipt_id", name=op.f(f"pk_{_PAGE_TABLE}")),
        sa.UniqueConstraint(
            "snapshot_id",
            "page_number",
            name="uq_phase4_order_snapshot_page_number",
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_PAGE_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "evidence_sha256",
            name=op.f(f"uq_{_PAGE_TABLE}_evidence_sha256"),
        ),
        sa.UniqueConstraint(
            "permit_id",
            name=op.f(f"uq_{_PAGE_TABLE}_permit_id"),
        ),
        sa.UniqueConstraint(
            "ingress_receipt_id",
            name=op.f(f"uq_{_PAGE_TABLE}_ingress_receipt_id"),
        ),
        sa.UniqueConstraint(
            "snapshot_id",
            "semantic_sha256",
            name="uq_phase4_order_snapshot_page_predecessor",
        ),
        sa.UniqueConstraint(
            "snapshot_id",
            "page_number",
            "receipt_id",
            "semantic_sha256",
            "persisted_page_sha256",
            name="uq_phase4_order_snapshot_page_exact",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id", "account_id", "plan_sha256"],
            [
                f"{_PLAN_TABLE}.snapshot_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_snapshot_page_plan",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id", "previous_page_receipt_sha256"],
            [f"{_PAGE_TABLE}.snapshot_id", f"{_PAGE_TABLE}.semantic_sha256"],
            name="fk_phase4_order_snapshot_page_predecessor",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "account_binding_id",
                "account_binding_sha256",
                "expected_provider_account_id",
            ],
            [
                "phase4_alpaca_paper_account_bindings.account_id",
                "phase4_alpaca_paper_account_bindings.binding_id",
                "phase4_alpaca_paper_account_bindings.semantic_sha256",
                "phase4_alpaca_paper_account_bindings.expected_provider_account_id",
            ],
            name="fk_phase4_order_snapshot_page_account_binding",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "permit_id",
                "permit_sha256",
                "demand_id",
                "demand_sha256",
                "policy_sha256",
            ],
            [
                "phase4_broker_request_permits.account_id",
                "phase4_broker_request_permits.permit_id",
                "phase4_broker_request_permits.semantic_sha256",
                "phase4_broker_request_permits.demand_id",
                "phase4_broker_request_permits.demand_sha256",
                "phase4_broker_request_permits.policy_sha256",
            ],
            name="fk_phase4_order_snapshot_page_permit",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
            [
                "phase4_broker_ingress_receipts.account_id",
                "phase4_broker_ingress_receipts.receipt_id",
                "phase4_broker_ingress_receipts.semantic_sha256",
            ],
            name="fk_phase4_order_snapshot_page_ingress",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "fence_fencing_generation",
                "pre_fence_lease_sha256",
            ],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_order_snapshot_page_pre_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "fence_fencing_generation",
                "post_fence_lease_sha256",
            ],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_order_snapshot_page_post_lease",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "fence_fencing_generation",
                "commit_fence_lease_sha256",
            ],
            [
                "phase2_account_leases.account_id",
                "phase2_account_leases.fencing_generation",
                "phase2_account_leases.lease_sha256",
            ],
            name="fk_phase4_order_snapshot_page_commit_lease",
        ),
        sa.CheckConstraint(
            "(page_number = 1 "
            "AND previous_page_receipt_sha256 IS NULL "
            "AND previous_persisted_page_sha256 IS NULL "
            "AND before_order_id IS NULL "
            "AND prefix_page_count = 0 "
            "AND preparation_previous_page_receipt_id IS NULL "
            "AND preparation_previous_page_receipt_sha256 IS NULL) "
            "OR (page_number > 1 "
            "AND previous_page_receipt_sha256 IS NOT NULL "
            "AND previous_persisted_page_sha256 IS NOT NULL "
            "AND before_order_id IS NOT NULL "
            "AND prefix_page_count = page_number - 1 "
            "AND preparation_previous_page_receipt_id IS NOT NULL "
            "AND preparation_previous_page_receipt_sha256 = previous_page_receipt_sha256)",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "provider_id = 'alpaca-paper' AND environment = 'paper'",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_provider_scope"),
        ),
        sa.CheckConstraint(
            "page_number BETWEEN 1 AND 8 "
            "AND prefix_page_count = page_number - 1 "
            "AND ingress_sequence > 0 "
            "AND fence_fencing_generation > 0",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_positive_counts"),
        ),
        sa.CheckConstraint(
            "http_status = 200",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_http_status"),
        ),
        sa.CheckConstraint(
            "(terminal_page AND next_before_order_id IS NULL AND NOT bounded_truncation) "
            "OR (NOT terminal_page AND next_before_order_id IS NOT NULL)",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_cursor_shape"),
        ),
        sa.CheckConstraint(
            "prepared_at <= requested_at "
            "AND requested_at <= credential_resolution_started_at "
            "AND credential_resolution_started_at <= resolved_at "
            "AND resolved_at <= pre_fence_validated_at "
            "AND pre_fence_validated_at <= permit_checked_at "
            "AND permit_checked_at <= pre_account_identity_checked_at "
            "AND pre_account_identity_checked_at <= request_started_at "
            "AND request_started_at <= received_at "
            "AND received_at <= raw_recorded_at "
            "AND raw_recorded_at <= post_fence_validated_at "
            "AND post_fence_validated_at <= post_account_identity_checked_at "
            "AND post_account_identity_checked_at <= authenticated_at "
            "AND authenticated_at <= commit_fence_validated_at",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_time_order"),
        ),
        sa.CheckConstraint(
            "resolved_at < credential_resolution_valid_until "
            "AND request_started_at < credential_resolution_valid_until "
            "AND received_at < credential_resolution_valid_until "
            "AND pre_fence_validated_at < pre_fence_valid_until "
            "AND received_at < pre_fence_valid_until "
            "AND post_fence_validated_at < post_fence_valid_until "
            "AND commit_fence_validated_at < commit_fence_valid_until",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_validity_windows"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 36 "
            "AND length(snapshot_id) = 36 "
            "AND length(expected_provider_account_id) = 36 "
            "AND length(account_binding_id) = 36 "
            "AND (before_order_id IS NULL OR length(before_order_id) = 36) "
            "AND (next_before_order_id IS NULL OR length(next_before_order_id) = 36) "
            "AND (preparation_previous_page_receipt_id IS NULL "
            "OR length(preparation_previous_page_receipt_id) = 36)",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_id_lengths"),
        ),
        sa.CheckConstraint(
            "length(plan_sha256) = 64 "
            "AND (previous_page_receipt_sha256 IS NULL "
            "OR length(previous_page_receipt_sha256) = 64) "
            "AND (previous_persisted_page_sha256 IS NULL "
            "OR length(previous_persisted_page_sha256) = 64) "
            "AND length(description_sha256) = 64 "
            "AND length(preparation_sha256) = 64 "
            "AND length(prefix_capture_sha256) = 64 "
            "AND (preparation_previous_page_receipt_sha256 IS NULL "
            "OR length(preparation_previous_page_receipt_sha256) = 64) "
            "AND length(capability_sha256) = 64 "
            "AND length(credential_reference_sha256) = 64 "
            "AND length(credential_resolution_sha256) = 64 "
            "AND length(account_binding_sha256) = 64 "
            "AND length(pre_account_identity_sha256) = 64 "
            "AND length(post_account_identity_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(demand_id) = 64 "
            "AND length(demand_sha256) = 64 "
            "AND length(permit_id) = 64 "
            "AND length(permit_sha256) = 64 "
            "AND length(permit_freshness_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(pre_fence_lease_sha256) = 64 "
            "AND length(pre_fence_receipt_sha256) = 64 "
            "AND length(transport_request_sha256) = 64 "
            "AND length(transport_response_sha256) = 64 "
            "AND length(ingress_receipt_id) = 64 "
            "AND length(ingress_receipt_sha256) = 64 "
            "AND length(observation_sha256) = 64 "
            "AND length(persisted_page_sha256) = 64 "
            "AND length(post_fence_lease_sha256) = 64 "
            "AND length(post_fence_receipt_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(commit_fence_lease_sha256) = 64 "
            "AND length(commit_fence_receipt_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_PAGE_TABLE}_phase4_order_snapshot_page_payload_size"),
        ),
    )
    op.create_index(
        "ix_phase4_order_snapshot_page_account_authenticated",
        _PAGE_TABLE,
        ["account_id", "authenticated_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_order_snapshot_page_ingress_sequence",
        _PAGE_TABLE,
        ["account_id", "ingress_sequence"],
        unique=False,
    )

    op.create_table(
        _HEAD_TABLE,
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("committed_page_count", sa.BigInteger(), nullable=False),
        sa.Column("last_page_receipt_id", sa.String(36), nullable=True),
        sa.Column("last_page_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("last_persisted_page_sha256", sa.String(64), nullable=True),
        sa.Column("next_page_number", sa.BigInteger(), nullable=True),
        sa.Column("next_before_order_id", sa.String(36), nullable=True),
        sa.Column("next_previous_page_sha256", sa.String(64), nullable=True),
        sa.Column("prepared_description_sha256", sa.String(64), nullable=True),
        sa.Column("prepared_prefix_capture_sha256", sa.String(64), nullable=True),
        sa.Column("prepared_prefix_page_count", sa.BigInteger(), nullable=True),
        sa.Column("prepared_previous_page_receipt_id", sa.String(36), nullable=True),
        sa.Column("prepared_previous_page_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("preparation_sha256", sa.String(64), nullable=True),
        sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id", name=op.f(f"pk_{_HEAD_TABLE}")),
        sa.UniqueConstraint(
            "snapshot_id",
            "account_id",
            "semantic_sha256",
            name="uq_phase4_order_snapshot_head_exact",
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id", "account_id", "plan_sha256"],
            [
                f"{_PLAN_TABLE}.snapshot_id",
                f"{_PLAN_TABLE}.account_id",
                f"{_PLAN_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_order_snapshot_head_plan",
        ),
        sa.ForeignKeyConstraint(
            [
                "snapshot_id",
                "committed_page_count",
                "last_page_receipt_id",
                "last_page_receipt_sha256",
                "last_persisted_page_sha256",
            ],
            [
                f"{_PAGE_TABLE}.snapshot_id",
                f"{_PAGE_TABLE}.page_number",
                f"{_PAGE_TABLE}.receipt_id",
                f"{_PAGE_TABLE}.semantic_sha256",
                f"{_PAGE_TABLE}.persisted_page_sha256",
            ],
            name="fk_phase4_order_snapshot_head_terminal_page",
        ),
        sa.CheckConstraint(
            "(committed_page_count = 0 "
            "AND last_page_receipt_id IS NULL "
            "AND last_page_receipt_sha256 IS NULL "
            "AND last_persisted_page_sha256 IS NULL) "
            "OR (committed_page_count > 0 "
            "AND last_page_receipt_id IS NOT NULL "
            "AND last_page_receipt_sha256 IS NOT NULL "
            "AND last_persisted_page_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_tip_shape"),
        ),
        sa.CheckConstraint(
            "state IN ('active', 'cursor_exhausted_unisolated', 'bounded_truncated', 'stalled')",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_state"),
        ),
        sa.CheckConstraint(
            "(state IN ('active', 'stalled') "
            "AND next_page_number = committed_page_count + 1 "
            "AND next_page_number BETWEEN 1 AND 8 "
            "AND ((next_page_number = 1 "
            "AND next_before_order_id IS NULL "
            "AND next_previous_page_sha256 IS NULL) "
            "OR (next_page_number > 1 "
            "AND next_before_order_id IS NOT NULL "
            "AND next_previous_page_sha256 = last_persisted_page_sha256))) "
            "OR (state IN ('cursor_exhausted_unisolated', 'bounded_truncated') "
            "AND next_page_number IS NULL "
            "AND next_before_order_id IS NULL "
            "AND next_previous_page_sha256 IS NULL)",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_next_shape"),
        ),
        sa.CheckConstraint(
            "(state <> 'stalled' "
            "AND prepared_description_sha256 IS NULL "
            "AND prepared_prefix_capture_sha256 IS NULL "
            "AND prepared_prefix_page_count IS NULL "
            "AND prepared_previous_page_receipt_id IS NULL "
            "AND prepared_previous_page_receipt_sha256 IS NULL "
            "AND preparation_sha256 IS NULL "
            "AND prepared_at IS NULL) "
            "OR (state = 'stalled' "
            "AND prepared_description_sha256 IS NOT NULL "
            "AND prepared_prefix_capture_sha256 IS NOT NULL "
            "AND prepared_prefix_page_count = committed_page_count "
            "AND preparation_sha256 IS NOT NULL "
            "AND prepared_at IS NOT NULL "
            "AND ((committed_page_count = 0 "
            "AND prepared_previous_page_receipt_id IS NULL "
            "AND prepared_previous_page_receipt_sha256 IS NULL) "
            "OR (committed_page_count > 0 "
            "AND prepared_previous_page_receipt_id = last_page_receipt_id "
            "AND prepared_previous_page_receipt_sha256 = last_page_receipt_sha256)))",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_preparation_shape"),
        ),
        sa.CheckConstraint(
            "committed_page_count BETWEEN 0 AND 8",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_page_bound"),
        ),
        sa.CheckConstraint(
            "length(plan_sha256) = 64 "
            "AND (last_page_receipt_sha256 IS NULL "
            "OR length(last_page_receipt_sha256) = 64) "
            "AND (last_persisted_page_sha256 IS NULL "
            "OR length(last_persisted_page_sha256) = 64) "
            "AND (next_previous_page_sha256 IS NULL "
            "OR length(next_previous_page_sha256) = 64) "
            "AND (prepared_description_sha256 IS NULL "
            "OR length(prepared_description_sha256) = 64) "
            "AND (prepared_prefix_capture_sha256 IS NULL "
            "OR length(prepared_prefix_capture_sha256) = 64) "
            "AND (prepared_previous_page_receipt_sha256 IS NULL "
            "OR length(prepared_previous_page_receipt_sha256) = 64) "
            "AND (preparation_sha256 IS NULL OR length(preparation_sha256) = 64) "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(canonical_payload) BETWEEN 2 AND 16384",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_order_snapshot_head_payload_size"),
        ),
    )
    op.create_index(
        "ix_phase4_order_snapshot_head_account_state",
        _HEAD_TABLE,
        ["account_id", "state", "updated_at"],
        unique=False,
    )


def downgrade() -> None:
    connection = op.get_bind()
    tables = (_HEAD_TABLE, _PAGE_TABLE, _PLAN_TABLE)
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("LOCK TABLE " + ", ".join(tables) + " IN ACCESS EXCLUSIVE MODE")
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    counts = tuple(
        connection.scalar(sa.text(f"SELECT COUNT(*) FROM {table_name}")) for table_name in tables
    )
    if any(counts):
        raise RuntimeError("refusing to downgrade nonempty authenticated order snapshot history")
    op.drop_index(
        "ix_phase4_order_snapshot_head_account_state",
        table_name=_HEAD_TABLE,
    )
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_order_snapshot_page_ingress_sequence",
        table_name=_PAGE_TABLE,
    )
    op.drop_index(
        "ix_phase4_order_snapshot_page_account_authenticated",
        table_name=_PAGE_TABLE,
    )
    op.drop_table(_PAGE_TABLE)
    op.drop_index(
        "ix_phase4_order_snapshot_plan_account_prepared",
        table_name=_PLAN_TABLE,
    )
    op.drop_table(_PLAN_TABLE)
    op.drop_index(
        _PERMIT_EXACT_INDEX,
        table_name="phase4_broker_request_permits",
    )
