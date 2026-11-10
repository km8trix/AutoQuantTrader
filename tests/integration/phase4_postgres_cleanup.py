"""Exact reverse-FK cleanup for per-account Phase 4 PostgreSQL test facts."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import Engine

from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_alpaca_paper_order_snapshot_heads,
    phase4_alpaca_paper_order_snapshot_pages,
    phase4_alpaca_paper_order_snapshot_plans,
    phase4_alpaca_paper_order_snapshot_preparations,
    phase4_alpaca_paper_order_transition_claims,
    phase4_alpaca_paper_order_transition_consumptions,
    phase4_alpaca_paper_order_transition_members,
    phase4_alpaca_paper_order_view_comparison_heads,
    phase4_alpaca_paper_order_view_comparisons,
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_position_snapshots,
    phase4_alpaca_paper_position_transition_claims,
    phase4_alpaca_paper_position_transition_consumptions,
    phase4_alpaca_paper_position_transition_members,
    phase4_alpaca_paper_position_view_comparison_heads,
    phase4_alpaca_paper_position_view_comparisons,
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_request_heads,
    phase4_broker_request_permits,
)

_REVERSE_FOREIGN_KEY_ORDER = (
    phase4_alpaca_paper_order_transition_consumptions,
    phase4_alpaca_paper_order_transition_claims,
    phase4_alpaca_paper_order_transition_members,
    phase4_alpaca_paper_position_transition_consumptions,
    phase4_alpaca_paper_position_transition_claims,
    phase4_alpaca_paper_position_transition_members,
    phase4_alpaca_paper_order_view_comparison_heads,
    phase4_alpaca_paper_order_view_comparisons,
    phase4_alpaca_paper_position_view_comparison_heads,
    phase4_alpaca_paper_position_view_comparisons,
    phase4_alpaca_paper_order_snapshot_heads,
    phase4_alpaca_paper_order_snapshot_preparations,
    phase4_alpaca_paper_order_snapshot_pages,
    phase4_alpaca_paper_order_snapshot_plans,
    phase4_alpaca_paper_position_snapshots,
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_broker_ingress_heads,
    phase4_broker_request_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_request_permits,
    phase2_account_lease_releases,
    phase2_account_lease_heads,
    phase2_account_leases,
)


def delete_phase4_postgres_account_facts(engine: Engine, account_id: str) -> None:
    """Delete one generated test account atomically, including partial runs."""

    with engine.begin() as connection:
        for table in _REVERSE_FOREIGN_KEY_ORDER:
            connection.execute(sa.delete(table).where(table.c.account_id == account_id))
