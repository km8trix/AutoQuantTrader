"""Add authenticated Alpaca paper UNKNOWN lookup observations.

Revision ID: 0015_phase4_lookup_observation
Revises: 0014_phase4_asset_binding
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_phase4_lookup_observation"
down_revision: str | None = "0014_phase4_asset_binding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OBSERVATION_TABLE = "phase4_alpaca_paper_lookup_observations"
_HEAD_TABLE = "phase4_alpaca_paper_lookup_observation_heads"
_EVENT_EXACT_INDEX = "ux_phase2_submission_attempt_event_exact"


def upgrade() -> None:
    op.create_index(
        _EVENT_EXACT_INDEX,
        "phase2_submission_attempt_events",
        ["attempt_id", "event_id", "semantic_sha256"],
        unique=True,
    )
    op.create_table(
        _OBSERVATION_TABLE,
        sa.Column("receipt_id", sa.String(36), nullable=False),
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("provider_id", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(32), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("attempt_sha256", sa.String(64), nullable=False),
        sa.Column("terminal_event_id", sa.String(64), nullable=False),
        sa.Column("terminal_event_sha256", sa.String(64), nullable=False),
        sa.Column("terminal_event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("parent_decision_id", sa.String(64), nullable=False),
        sa.Column("reservation_id", sa.String(64), nullable=False),
        sa.Column("order_id", sa.String(64), nullable=False),
        sa.Column("client_order_id", sa.String(64), nullable=False),
        sa.Column("instrument_id", sa.String(64), nullable=False),
        sa.Column("symbol", sa.String(32), nullable=False),
        sa.Column("expected_provider_account_id", sa.String(36), nullable=False),
        sa.Column("expected_provider_asset_id", sa.String(36), nullable=False),
        sa.Column("outcome", sa.String(64), nullable=False),
        sa.Column("provider_order_id", sa.String(128), nullable=True),
        sa.Column("provider_order_status", sa.String(64), nullable=True),
        sa.Column("observed_provider_asset_id", sa.String(36), nullable=True),
        sa.Column("mismatch_fields_payload", sa.Text(), nullable=False),
        sa.Column("secret_ref", sa.String(256), nullable=False),
        sa.Column("secret_version", sa.String(128), nullable=False),
        sa.Column("credential_reference_sha256", sa.String(64), nullable=False),
        sa.Column("security_reference_sha256", sa.String(64), nullable=False),
        sa.Column("credential_resolution_sha256", sa.String(64), nullable=False),
        sa.Column("resolver_id", sa.String(128), nullable=False),
        sa.Column("resolver_version", sa.String(128), nullable=False),
        sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("account_binding_id", sa.String(36), nullable=False),
        sa.Column("account_binding_sha256", sa.String(64), nullable=False),
        sa.Column("pre_attempt_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("post_attempt_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("pre_account_identity_sha256", sa.String(64), nullable=False),
        sa.Column("post_account_identity_sha256", sa.String(64), nullable=False),
        sa.Column("description_sha256", sa.String(64), nullable=False),
        sa.Column("submission_sha256", sa.String(64), nullable=False),
        sa.Column("policy_sha256", sa.String(64), nullable=False),
        sa.Column("demand_id", sa.String(64), nullable=False),
        sa.Column("demand_sha256", sa.String(64), nullable=False),
        sa.Column("permit_id", sa.String(64), nullable=False),
        sa.Column("permit_sha256", sa.String(64), nullable=False),
        sa.Column("permit_freshness_sha256", sa.String(64), nullable=False),
        sa.Column("fence_owner_id", sa.String(128), nullable=False),
        sa.Column("fence_lease_id", sa.String(64), nullable=False),
        sa.Column("fence_fencing_generation", sa.BigInteger(), nullable=False),
        sa.Column("fence_sha256", sa.String(64), nullable=False),
        sa.Column("fence_policy_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_lease_sha256", sa.String(64), nullable=False),
        sa.Column("pre_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("post_fence_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("ingress_receipt_id", sa.String(64), nullable=False),
        sa.Column("ingress_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("observation_sha256", sa.String(64), nullable=False),
        sa.Column("transport_request_sha256", sa.String(64), nullable=False),
        sa.Column("transport_response_sha256", sa.String(64), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=False),
        sa.Column("provider_request_id", sa.String(256), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.Column("permit_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pre_attempt_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "pre_account_identity_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("request_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_fence_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_fence_valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("post_attempt_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "post_account_identity_checked_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("commit_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("previous_receipt_sha256", sa.String(64), nullable=True),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("canonical_payload", sa.Text(), nullable=False),
        sa.Column("semantic_sha256", sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint("receipt_id", name=op.f(f"pk_{_OBSERVATION_TABLE}")),
        sa.UniqueConstraint(
            "evidence_sha256",
            name=op.f(f"uq_{_OBSERVATION_TABLE}_evidence_sha256"),
        ),
        sa.UniqueConstraint(
            "semantic_sha256",
            name=op.f(f"uq_{_OBSERVATION_TABLE}_semantic_sha256"),
        ),
        sa.UniqueConstraint(
            "account_id",
            "attempt_id",
            "sequence_number",
            name="uq_phase4_alpaca_lookup_attempt_sequence",
        ),
        sa.UniqueConstraint(
            "account_id",
            "attempt_id",
            "semantic_sha256",
            name="uq_phase4_alpaca_lookup_attempt_semantic",
        ),
        sa.UniqueConstraint(
            "account_id",
            "attempt_id",
            "sequence_number",
            "semantic_sha256",
            "terminal_event_id",
            "terminal_event_sha256",
            name="uq_phase4_alpaca_lookup_terminal",
        ),
        sa.UniqueConstraint(
            "permit_id",
            name="uq_phase4_alpaca_lookup_permit",
        ),
        sa.UniqueConstraint(
            "ingress_receipt_id",
            name="uq_phase4_alpaca_lookup_ingress",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_alpaca_lookup_account",
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id"],
            ["phase2_submission_attempts.attempt_id"],
            name="fk_phase4_alpaca_lookup_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id", "terminal_event_id", "terminal_event_sha256"],
            [
                "phase2_submission_attempt_events.attempt_id",
                "phase2_submission_attempt_events.event_id",
                "phase2_submission_attempt_events.semantic_sha256",
            ],
            name="fk_phase4_alpaca_lookup_unknown_event",
        ),
        sa.ForeignKeyConstraint(
            ["instrument_id"],
            ["instruments.instrument_id"],
            name="fk_phase4_alpaca_lookup_instrument",
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
            name="fk_phase4_alpaca_lookup_account_binding",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "permit_id", "permit_sha256"],
            [
                "phase4_broker_request_permits.account_id",
                "phase4_broker_request_permits.permit_id",
                "phase4_broker_request_permits.semantic_sha256",
            ],
            name="fk_phase4_alpaca_lookup_permit",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "ingress_receipt_id", "ingress_receipt_sha256"],
            [
                "phase4_broker_ingress_receipts.account_id",
                "phase4_broker_ingress_receipts.receipt_id",
                "phase4_broker_ingress_receipts.semantic_sha256",
            ],
            name="fk_phase4_alpaca_lookup_ingress",
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
            name="fk_phase4_alpaca_lookup_pre_fence_lease",
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
            name="fk_phase4_alpaca_lookup_post_fence_lease",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "attempt_id", "previous_receipt_sha256"],
            [
                f"{_OBSERVATION_TABLE}.account_id",
                f"{_OBSERVATION_TABLE}.attempt_id",
                f"{_OBSERVATION_TABLE}.semantic_sha256",
            ],
            name="fk_phase4_alpaca_lookup_predecessor",
        ),
        sa.CheckConstraint(
            "(sequence_number = 1 AND previous_receipt_sha256 IS NULL) "
            "OR (sequence_number > 1 AND previous_receipt_sha256 IS NOT NULL)",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_predecessor_shape"),
        ),
        sa.CheckConstraint(
            "provider_id = 'alpaca-paper' AND environment = 'paper'",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_provider_scope"),
        ),
        sa.CheckConstraint(
            "outcome IN ('found_matched', 'found_mismatch', "
            "'security_identity_mismatch', "
            "'not_visible_inconclusive')",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_outcome"),
        ),
        sa.CheckConstraint(
            "(http_status = 404 AND outcome = 'not_visible_inconclusive' "
            "AND provider_order_id IS NULL "
            "AND provider_order_status IS NULL "
            "AND observed_provider_asset_id IS NULL "
            'AND mismatch_fields_payload = \'{"type":"tuple","value":[]}\') '
            "OR (http_status = 200 AND outcome = 'found_matched' "
            "AND provider_order_id IS NOT NULL "
            "AND provider_order_status IS NOT NULL "
            "AND observed_provider_asset_id IS NOT NULL "
            "AND observed_provider_asset_id = expected_provider_asset_id "
            'AND mismatch_fields_payload = \'{"type":"tuple","value":[]}\') '
            "OR (http_status = 200 AND outcome = 'found_mismatch' "
            "AND provider_order_id IS NOT NULL "
            "AND provider_order_status IS NOT NULL "
            "AND observed_provider_asset_id IS NOT NULL "
            "AND observed_provider_asset_id = expected_provider_asset_id "
            'AND mismatch_fields_payload <> \'{"type":"tuple","value":[]}\') '
            "OR (http_status = 200 AND outcome = 'security_identity_mismatch' "
            "AND provider_order_id IS NOT NULL "
            "AND provider_order_status IS NOT NULL "
            "AND (observed_provider_asset_id IS NULL "
            "OR observed_provider_asset_id <> expected_provider_asset_id))",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_http_shape"),
        ),
        sa.CheckConstraint(
            "terminal_event_sequence > 0 AND fence_fencing_generation > 0 AND sequence_number > 0",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_positive_sequences"),
        ),
        sa.CheckConstraint(
            "length(symbol) BETWEEN 1 AND 32 AND symbol = upper(symbol)",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_symbol"),
        ),
        sa.CheckConstraint(
            "length(secret_ref) BETWEEN 16 AND 256 "
            "AND secret_ref LIKE 'secret://paper/%' "
            "AND length(secret_version) BETWEEN 1 AND 128 "
            "AND length(resolver_id) BETWEEN 1 AND 128 "
            "AND length(resolver_version) BETWEEN 1 AND 128",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_reference_shape"),
        ),
        sa.CheckConstraint(
            "length(receipt_id) = 36 "
            "AND receipt_id = lower(receipt_id) "
            "AND length(expected_provider_account_id) = 36 "
            "AND expected_provider_account_id = lower(expected_provider_account_id) "
            "AND length(expected_provider_asset_id) = 36 "
            "AND expected_provider_asset_id = lower(expected_provider_asset_id) "
            "AND (observed_provider_asset_id IS NULL "
            "OR (length(observed_provider_asset_id) = 36 "
            "AND observed_provider_asset_id = lower(observed_provider_asset_id))) "
            "AND length(account_binding_id) = 36",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_uuid_shape"),
        ),
        sa.CheckConstraint(
            "requested_at <= credential_resolution_started_at "
            "AND credential_resolution_started_at <= resolved_at "
            "AND resolved_at < credential_resolution_valid_until "
            "AND resolved_at <= pre_fence_validated_at "
            "AND pre_fence_validated_at < pre_fence_valid_until "
            "AND pre_fence_validated_at <= permit_checked_at "
            "AND permit_checked_at <= pre_attempt_checked_at "
            "AND pre_attempt_checked_at <= pre_account_identity_checked_at "
            "AND pre_account_identity_checked_at <= request_started_at "
            "AND request_started_at < credential_resolution_valid_until "
            "AND request_started_at <= received_at "
            "AND received_at < credential_resolution_valid_until "
            "AND received_at < pre_fence_valid_until "
            "AND received_at <= raw_recorded_at "
            "AND raw_recorded_at <= post_fence_validated_at "
            "AND post_fence_validated_at < post_fence_valid_until "
            "AND post_fence_validated_at <= post_attempt_checked_at "
            "AND post_attempt_checked_at <= post_account_identity_checked_at "
            "AND post_account_identity_checked_at = authenticated_at "
            "AND authenticated_at <= commit_checked_at "
            "AND commit_checked_at < post_fence_valid_until",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_time_order"),
        ),
        sa.CheckConstraint(
            "(previous_receipt_sha256 IS NULL "
            "OR length(previous_receipt_sha256) = 64) "
            "AND length(attempt_sha256) = 64 "
            "AND length(terminal_event_sha256) = 64 "
            "AND length(credential_reference_sha256) = 64 "
            "AND length(security_reference_sha256) = 64 "
            "AND length(credential_resolution_sha256) = 64 "
            "AND length(capability_sha256) = 64 "
            "AND length(account_binding_sha256) = 64 "
            "AND length(pre_attempt_freshness_sha256) = 64 "
            "AND length(post_attempt_freshness_sha256) = 64 "
            "AND length(pre_account_identity_sha256) = 64 "
            "AND length(post_account_identity_sha256) = 64 "
            "AND length(description_sha256) = 64 "
            "AND length(submission_sha256) = 64 "
            "AND length(policy_sha256) = 64 "
            "AND length(demand_id) = 64 "
            "AND length(demand_sha256) = 64 "
            "AND length(permit_id) = 64 "
            "AND length(permit_sha256) = 64 "
            "AND length(permit_freshness_sha256) = 64 "
            "AND length(fence_sha256) = 64 "
            "AND length(fence_policy_sha256) = 64 "
            "AND length(pre_fence_lease_sha256) = 64 "
            "AND length(post_fence_lease_sha256) = 64 "
            "AND length(pre_fence_receipt_sha256) = 64 "
            "AND length(post_fence_receipt_sha256) = 64 "
            "AND length(ingress_receipt_id) = 64 "
            "AND length(ingress_receipt_sha256) = 64 "
            "AND length(observation_sha256) = 64 "
            "AND length(transport_request_sha256) = 64 "
            "AND length(transport_response_sha256) = 64 "
            "AND length(evidence_sha256) = 64 "
            "AND length(semantic_sha256) = 64",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_hash_lengths"),
        ),
        sa.CheckConstraint(
            "length(mismatch_fields_payload) BETWEEN 2 AND 4096 "
            "AND length(canonical_payload) BETWEEN 2 AND 131072",
            name=op.f(f"ck_{_OBSERVATION_TABLE}_phase4_alpaca_lookup_payload_sizes"),
        ),
    )
    op.create_index(
        "ix_phase4_alpaca_lookup_attempt_authenticated",
        _OBSERVATION_TABLE,
        ["account_id", "attempt_id", "authenticated_at"],
        unique=False,
    )
    op.create_index(
        "ix_phase4_alpaca_lookup_provider_order",
        _OBSERVATION_TABLE,
        ["provider_id", "environment", "provider_order_id"],
        unique=False,
    )
    op.create_table(
        _HEAD_TABLE,
        sa.Column("account_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(64), nullable=False),
        sa.Column("terminal_event_id", sa.String(64), nullable=False),
        sa.Column("terminal_event_sha256", sa.String(64), nullable=False),
        sa.Column("last_sequence_number", sa.BigInteger(), nullable=False),
        sa.Column("last_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint(
            "account_id",
            "attempt_id",
            name=op.f(f"pk_{_HEAD_TABLE}"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["phase2_account_lease_heads.account_id"],
            name="fk_phase4_alpaca_lookup_heads_account",
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id"],
            ["phase2_submission_attempts.attempt_id"],
            name="fk_phase4_alpaca_lookup_heads_attempt",
        ),
        sa.ForeignKeyConstraint(
            [
                "account_id",
                "attempt_id",
                "last_sequence_number",
                "last_receipt_sha256",
                "terminal_event_id",
                "terminal_event_sha256",
            ],
            [
                f"{_OBSERVATION_TABLE}.account_id",
                f"{_OBSERVATION_TABLE}.attempt_id",
                f"{_OBSERVATION_TABLE}.sequence_number",
                f"{_OBSERVATION_TABLE}.semantic_sha256",
                f"{_OBSERVATION_TABLE}.terminal_event_id",
                f"{_OBSERVATION_TABLE}.terminal_event_sha256",
            ],
            name="fk_phase4_alpaca_lookup_heads_terminal",
        ),
        sa.CheckConstraint(
            "last_sequence_number > 0 "
            "AND length(last_receipt_sha256) = 64 "
            "AND length(terminal_event_sha256) = 64",
            name=op.f(f"ck_{_HEAD_TABLE}_phase4_alpaca_lookup_head_shape"),
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "LOCK TABLE phase4_alpaca_paper_lookup_observation_heads, "
            "phase4_alpaca_paper_lookup_observations, "
            "phase2_submission_attempt_events IN ACCESS EXCLUSIVE MODE"
        )
    elif connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN EXCLUSIVE")
    observation_count = connection.scalar(sa.text(f"SELECT COUNT(*) FROM {_OBSERVATION_TABLE}"))
    head_count = connection.scalar(sa.text(f"SELECT COUNT(*) FROM {_HEAD_TABLE}"))
    if observation_count or head_count:
        raise RuntimeError(
            "refusing to downgrade nonempty authenticated lookup observation history"
        )
    op.drop_table(_HEAD_TABLE)
    op.drop_index(
        "ix_phase4_alpaca_lookup_provider_order",
        table_name=_OBSERVATION_TABLE,
    )
    op.drop_index(
        "ix_phase4_alpaca_lookup_attempt_authenticated",
        table_name=_OBSERVATION_TABLE,
    )
    op.drop_table(_OBSERVATION_TABLE)
    op.drop_index(
        _EVENT_EXACT_INDEX,
        table_name="phase2_submission_attempt_events",
    )
