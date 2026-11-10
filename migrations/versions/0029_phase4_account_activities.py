"""Add authenticated durable Alpaca paper account-activity traversal.

Revision ID: 0029_phase4_account_activities
Revises: 0028_phase5_strategy_supervision
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029_phase4_account_activities"
down_revision: str | None = "0028_phase5_strategy_supervision"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
_metadata = sa.MetaData(naming_convention=_NAMING_CONVENTION)

sa.Table(
    "phase2_account_lease_heads",
    _metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
)
sa.Table(
    "phase4_alpaca_paper_account_bindings",
    _metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("binding_id", sa.String(36), primary_key=True),
    sa.Column("semantic_sha256", sa.String(64), primary_key=True),
    sa.Column("expected_provider_account_id", sa.String(36), primary_key=True),
)
sa.Table(
    "phase4_broker_request_permits",
    _metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("permit_id", sa.String(64), primary_key=True),
    sa.Column("semantic_sha256", sa.String(64), primary_key=True),
    sa.Column("demand_id", sa.String(64), primary_key=True),
    sa.Column("demand_sha256", sa.String(64), primary_key=True),
    sa.Column("policy_sha256", sa.String(64), primary_key=True),
)
sa.Table(
    "phase4_broker_ingress_receipts",
    _metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("receipt_id", sa.String(64), primary_key=True),
    sa.Column("semantic_sha256", sa.String(64), primary_key=True),
)
sa.Table(
    "phase2_account_leases",
    _metadata,
    sa.Column("account_id", sa.String(64), primary_key=True),
    sa.Column("fencing_generation", sa.BigInteger(), primary_key=True),
    sa.Column("lease_sha256", sa.String(64), primary_key=True),
)

phase4_alpaca_paper_account_activity_plans = sa.Table(
    "phase4_alpaca_paper_account_activity_plans",
    _metadata,
    sa.Column("capture_id", sa.String(36), primary_key=True),
    sa.Column(
        "account_id",
        sa.String(64),
        sa.ForeignKey(
            "phase2_account_lease_heads.account_id",
            name="fk_phase4_account_activity_plan_account",
        ),
        nullable=False,
    ),
    sa.Column("capture_idempotency_key", sa.String(128), nullable=False),
    sa.Column("capability_sha256", sa.String(64), nullable=False),
    sa.Column("traversal_profile_sha256", sa.String(64), nullable=False),
    sa.Column("page_size", sa.BigInteger(), nullable=False),
    sa.Column("maximum_pages", sa.BigInteger(), nullable=False),
    sa.Column("maximum_items", sa.BigInteger(), nullable=False),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "account_id",
        "capture_idempotency_key",
        name="uq_phase4_account_activity_plan_account_key",
    ),
    sa.UniqueConstraint(
        "capture_id",
        "account_id",
        "semantic_sha256",
        name="uq_phase4_account_activity_plan_exact",
    ),
    sa.CheckConstraint(
        "length(capture_id) = 36 "
        "AND capture_id = lower(capture_id) "
        "AND substr(capture_id, 9, 1) = '-' "
        "AND substr(capture_id, 14, 1) = '-' "
        "AND substr(capture_id, 19, 1) = '-' "
        "AND substr(capture_id, 24, 1) = '-'",
        name="phase4_account_activity_plan_id_shape",
    ),
    sa.CheckConstraint(
        "length(capture_idempotency_key) BETWEEN 8 AND 128",
        name="phase4_account_activity_plan_key_size",
    ),
    sa.CheckConstraint(
        "page_size BETWEEN 1 AND 100 "
        "AND maximum_pages BETWEEN 1 AND 8 "
        "AND maximum_items BETWEEN 1 AND 800",
        name="phase4_account_activity_plan_bounds",
    ),
    sa.CheckConstraint(
        "length(capability_sha256) = 64 "
        "AND length(traversal_profile_sha256) = 64 "
        "AND length(semantic_sha256) = 64",
        name="phase4_account_activity_plan_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_account_activity_plan_payload_size",
    ),
)
sa.Index(
    "ix_phase4_account_activity_plan_account_prepared",
    phase4_alpaca_paper_account_activity_plans.c.account_id,
    phase4_alpaca_paper_account_activity_plans.c.prepared_at,
)

phase4_alpaca_paper_account_activity_pages = sa.Table(
    "phase4_alpaca_paper_account_activity_pages",
    _metadata,
    sa.Column("receipt_id", sa.String(36), primary_key=True),
    sa.Column("capture_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("page_size", sa.BigInteger(), nullable=False),
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
    sa.Column("page_token", sa.String(256), nullable=True),
    sa.Column("next_page_token", sa.String(256), nullable=True),
    sa.Column("activity_count", sa.BigInteger(), nullable=False),
    sa.Column("terminal_page", sa.Boolean(), nullable=False),
    sa.Column("bounded_truncation", sa.Boolean(), nullable=False),
    sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("evidence_sha256", sa.String(64), nullable=False, unique=True),
    sa.Column("commit_fence_lease_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_receipt_sha256", sa.String(64), nullable=False),
    sa.Column("commit_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("commit_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
    sa.Column("canonical_payload", sa.Text(), nullable=False),
    sa.Column("semantic_sha256", sa.String(64), nullable=False, unique=True),
    sa.UniqueConstraint(
        "capture_id",
        "page_number",
        name="uq_phase4_account_activity_page_number",
    ),
    sa.UniqueConstraint(
        "permit_id",
        name="uq_phase4_alpaca_paper_account_activity_pages_permit_id",
    ),
    sa.UniqueConstraint(
        "ingress_receipt_id",
        name="uq_phase4_alpaca_paper_account_activity_pages_ingress_receipt",
    ),
    sa.UniqueConstraint(
        "capture_id",
        "semantic_sha256",
        name="uq_phase4_account_activity_page_predecessor",
    ),
    sa.UniqueConstraint(
        "capture_id",
        "page_number",
        "receipt_id",
        "semantic_sha256",
        "persisted_page_sha256",
        name="uq_phase4_account_activity_page_exact",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_account_activity_page_plan",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "previous_page_receipt_sha256"],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
        ],
        name="fk_phase4_account_activity_page_predecessor",
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
        name="fk_phase4_account_activity_page_account_binding",
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
        name="fk_phase4_account_activity_page_permit",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
        [
            "phase4_broker_ingress_receipts.account_id",
            "phase4_broker_ingress_receipts.receipt_id",
            "phase4_broker_ingress_receipts.semantic_sha256",
        ],
        name="fk_phase4_account_activity_page_ingress",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "pre_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_account_activity_page_pre_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "post_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_account_activity_page_post_lease",
    ),
    sa.ForeignKeyConstraint(
        ["account_id", "fence_fencing_generation", "commit_fence_lease_sha256"],
        [
            "phase2_account_leases.account_id",
            "phase2_account_leases.fencing_generation",
            "phase2_account_leases.lease_sha256",
        ],
        name="fk_phase4_account_activity_page_commit_lease",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL "
        "AND page_token IS NULL "
        "AND prefix_page_count = 0 "
        "AND preparation_previous_page_receipt_id IS NULL "
        "AND preparation_previous_page_receipt_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL "
        "AND page_token IS NOT NULL "
        "AND prefix_page_count = page_number - 1 "
        "AND preparation_previous_page_receipt_id IS NOT NULL "
        "AND preparation_previous_page_receipt_sha256 = previous_page_receipt_sha256)",
        name="phase4_account_activity_page_predecessor_shape",
    ),
    sa.CheckConstraint(
        "provider_id = 'alpaca-paper' AND environment = 'paper'",
        name="phase4_account_activity_page_provider_scope",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8 "
        "AND page_size BETWEEN 1 AND 100 "
        "AND activity_count BETWEEN 0 AND page_size "
        "AND prefix_page_count = page_number - 1 "
        "AND ingress_sequence > 0 "
        "AND fence_fencing_generation > 0",
        name="phase4_account_activity_page_positive_counts",
    ),
    sa.CheckConstraint(
        "http_status = 200",
        name="phase4_account_activity_page_http_status",
    ),
    sa.CheckConstraint(
        "(terminal_page AND next_page_token IS NULL AND NOT bounded_truncation) "
        "OR (NOT terminal_page AND next_page_token IS NOT NULL)",
        name="phase4_account_activity_page_cursor_shape",
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
        name="phase4_account_activity_page_time_order",
    ),
    sa.CheckConstraint(
        "resolved_at < credential_resolution_valid_until "
        "AND request_started_at < credential_resolution_valid_until "
        "AND received_at < credential_resolution_valid_until "
        "AND pre_fence_validated_at < pre_fence_valid_until "
        "AND received_at < pre_fence_valid_until "
        "AND post_fence_validated_at < post_fence_valid_until "
        "AND commit_fence_validated_at < commit_fence_valid_until",
        name="phase4_account_activity_page_validity_windows",
    ),
    sa.CheckConstraint(
        "length(receipt_id) = 36 "
        "AND length(capture_id) = 36 "
        "AND length(expected_provider_account_id) = 36 "
        "AND length(account_binding_id) = 36 "
        "AND (page_token IS NULL OR length(page_token) BETWEEN 1 AND 256) "
        "AND (next_page_token IS NULL "
        "OR length(next_page_token) BETWEEN 1 AND 256) "
        "AND (preparation_previous_page_receipt_id IS NULL "
        "OR length(preparation_previous_page_receipt_id) = 36)",
        name="phase4_account_activity_page_id_lengths",
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
        name="phase4_account_activity_page_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 131072",
        name="phase4_account_activity_page_payload_size",
    ),
)
sa.Index(
    "ix_phase4_account_activity_page_account_authenticated",
    phase4_alpaca_paper_account_activity_pages.c.account_id,
    phase4_alpaca_paper_account_activity_pages.c.authenticated_at,
)
sa.Index(
    "ix_phase4_account_activity_page_ingress_sequence",
    phase4_alpaca_paper_account_activity_pages.c.account_id,
    phase4_alpaca_paper_account_activity_pages.c.ingress_sequence,
)
sa.Index(
    "uq_phase4_account_activity_page_preparation",
    phase4_alpaca_paper_account_activity_pages.c.preparation_sha256,
    unique=True,
)

# Phase 4AA normalizes every Phase 4O single-use page preparation into an
# immutable fact.  Existing committed pages and the sole stalled head retain
# every source field needed to backfill these rows without inventing evidence.
# The mutable head remains a cache/pointer; loaders authenticate it against the
# fact and completed pages retain the fact after the head advances.
phase4_alpaca_paper_account_activity_preparations = sa.Table(
    "phase4_alpaca_paper_account_activity_preparations",
    _metadata,
    sa.Column("preparation_sha256", sa.String(64), primary_key=True),
    sa.Column("capture_id", sa.String(36), nullable=False),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("page_number", sa.BigInteger(), nullable=False),
    sa.Column("page_size", sa.BigInteger(), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("page_token", sa.String(256), nullable=True),
    sa.Column("description_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_capture_sha256", sa.String(64), nullable=False),
    sa.Column("prefix_page_count", sa.BigInteger(), nullable=False),
    sa.Column("previous_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("previous_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("previous_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("prepared_at", sa.DateTime(timezone=True), nullable=False),
    sa.UniqueConstraint(
        "capture_id",
        "page_number",
        name="uq_phase4_account_activity_preparation_page",
    ),
    sa.UniqueConstraint(
        "preparation_sha256",
        "capture_id",
        "account_id",
        "page_number",
        "plan_sha256",
        "description_sha256",
        "prefix_capture_sha256",
        "prefix_page_count",
        "prepared_at",
        name="uq_phase4_account_activity_preparation_exact",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_account_activity_preparation_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "capture_id",
            "prefix_page_count",
            "previous_page_receipt_id",
            "previous_page_receipt_sha256",
            "previous_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_account_activity_preparation_predecessor",
    ),
    sa.CheckConstraint(
        "(page_number = 1 "
        "AND page_token IS NULL "
        "AND prefix_page_count = 0 "
        "AND previous_page_receipt_id IS NULL "
        "AND previous_page_receipt_sha256 IS NULL "
        "AND previous_persisted_page_sha256 IS NULL) "
        "OR (page_number > 1 "
        "AND page_token IS NOT NULL "
        "AND prefix_page_count = page_number - 1 "
        "AND previous_page_receipt_id IS NOT NULL "
        "AND previous_page_receipt_sha256 IS NOT NULL "
        "AND previous_persisted_page_sha256 IS NOT NULL)",
        name="phase4_account_activity_preparation_predecessor_shape",
    ),
    sa.CheckConstraint(
        "page_number BETWEEN 1 AND 8 AND page_size BETWEEN 1 AND 100",
        name="phase4_account_activity_preparation_page_bounds",
    ),
    sa.CheckConstraint(
        "length(preparation_sha256) = 64 "
        "AND length(capture_id) = 36 "
        "AND (page_token IS NULL OR length(page_token) BETWEEN 1 AND 256) "
        "AND (previous_page_receipt_id IS NULL "
        "OR length(previous_page_receipt_id) = 36) "
        "AND length(plan_sha256) = 64 "
        "AND length(description_sha256) = 64 "
        "AND length(prefix_capture_sha256) = 64 "
        "AND (previous_page_receipt_sha256 IS NULL "
        "OR length(previous_page_receipt_sha256) = 64) "
        "AND (previous_persisted_page_sha256 IS NULL "
        "OR length(previous_persisted_page_sha256) = 64)",
        name="phase4_account_activity_preparation_identity_lengths",
    ),
)
sa.Index(
    "ix_phase4_account_activity_preparation_account_time",
    phase4_alpaca_paper_account_activity_preparations.c.account_id,
    phase4_alpaca_paper_account_activity_preparations.c.prepared_at,
)

phase4_alpaca_paper_account_activity_heads = sa.Table(
    "phase4_alpaca_paper_account_activity_heads",
    _metadata,
    sa.Column("capture_id", sa.String(36), primary_key=True),
    sa.Column("account_id", sa.String(64), nullable=False),
    sa.Column("plan_sha256", sa.String(64), nullable=False),
    sa.Column("committed_page_count", sa.BigInteger(), nullable=False),
    sa.Column("committed_activity_count", sa.BigInteger(), nullable=False),
    sa.Column("last_page_receipt_id", sa.String(36), nullable=True),
    sa.Column("last_page_receipt_sha256", sa.String(64), nullable=True),
    sa.Column("last_persisted_page_sha256", sa.String(64), nullable=True),
    sa.Column("next_page_number", sa.BigInteger(), nullable=True),
    sa.Column("next_page_size", sa.BigInteger(), nullable=True),
    sa.Column("next_page_token", sa.String(256), nullable=True),
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
    sa.UniqueConstraint(
        "capture_id",
        "account_id",
        "semantic_sha256",
        name="uq_phase4_account_activity_head_exact",
    ),
    sa.ForeignKeyConstraint(
        ["capture_id", "account_id", "plan_sha256"],
        [
            "phase4_alpaca_paper_account_activity_plans.capture_id",
            "phase4_alpaca_paper_account_activity_plans.account_id",
            "phase4_alpaca_paper_account_activity_plans.semantic_sha256",
        ],
        name="fk_phase4_account_activity_head_plan",
    ),
    sa.ForeignKeyConstraint(
        [
            "capture_id",
            "committed_page_count",
            "last_page_receipt_id",
            "last_page_receipt_sha256",
            "last_persisted_page_sha256",
        ],
        [
            "phase4_alpaca_paper_account_activity_pages.capture_id",
            "phase4_alpaca_paper_account_activity_pages.page_number",
            "phase4_alpaca_paper_account_activity_pages.receipt_id",
            "phase4_alpaca_paper_account_activity_pages.semantic_sha256",
            "phase4_alpaca_paper_account_activity_pages.persisted_page_sha256",
        ],
        name="fk_phase4_account_activity_head_terminal_page",
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
        name="phase4_account_activity_head_tip_shape",
    ),
    sa.CheckConstraint(
        "state IN ('active', 'cursor_exhausted_unisolated', 'bounded_truncated', 'stalled')",
        name="phase4_account_activity_head_state",
    ),
    sa.CheckConstraint(
        "(state IN ('active', 'stalled') "
        "AND next_page_number = committed_page_count + 1 "
        "AND next_page_number BETWEEN 1 AND 8 "
        "AND next_page_size BETWEEN 1 AND 100 "
        "AND ((next_page_number = 1 "
        "AND next_page_token IS NULL "
        "AND next_previous_page_sha256 IS NULL) "
        "OR (next_page_number > 1 "
        "AND next_page_token IS NOT NULL "
        "AND next_previous_page_sha256 = last_persisted_page_sha256))) "
        "OR (state IN ('cursor_exhausted_unisolated', 'bounded_truncated') "
        "AND next_page_number IS NULL "
        "AND next_page_size IS NULL "
        "AND next_page_token IS NULL "
        "AND next_previous_page_sha256 IS NULL)",
        name="phase4_account_activity_head_next_shape",
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
        name="phase4_account_activity_head_preparation_shape",
    ),
    sa.CheckConstraint(
        "committed_page_count BETWEEN 0 AND 8 AND committed_activity_count BETWEEN 0 AND 800",
        name="phase4_account_activity_head_page_bound",
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
        name="phase4_account_activity_head_hash_lengths",
    ),
    sa.CheckConstraint(
        "length(canonical_payload) BETWEEN 2 AND 16384",
        name="phase4_account_activity_head_payload_size",
    ),
)
sa.Index(
    "ix_phase4_account_activity_head_account_state",
    phase4_alpaca_paper_account_activity_heads.c.account_id,
    phase4_alpaca_paper_account_activity_heads.c.state,
    phase4_alpaca_paper_account_activity_heads.c.updated_at,
)
sa.Index(
    "uq_phase4_account_activity_head_preparation",
    phase4_alpaca_paper_account_activity_heads.c.preparation_sha256,
    unique=True,
)

# Phase 4AA reserves one exact ordered pair before either order traversal is
# prepared.  Claims are page-granular immutable facts and consumptions bind


_ACTIVITY_TABLES = (
    phase4_alpaca_paper_account_activity_plans,
    phase4_alpaca_paper_account_activity_pages,
    phase4_alpaca_paper_account_activity_preparations,
    phase4_alpaca_paper_account_activity_heads,
)


def upgrade() -> None:
    bind = op.get_bind()
    for table in _ACTIVITY_TABLES:
        table.create(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        names = ", ".join(table.name for table in reversed(_ACTIVITY_TABLES))
        bind.execute(sa.text(f"LOCK TABLE {names} IN SHARE ROW EXCLUSIVE MODE"))
    for table in reversed(_ACTIVITY_TABLES):
        count = int(bind.scalar(sa.select(sa.func.count()).select_from(table)) or 0)
        if count:
            raise RuntimeError("refusing to downgrade nonempty account-activity traversal history")
    for table in reversed(_ACTIVITY_TABLES):
        table.drop(bind)
