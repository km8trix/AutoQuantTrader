from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    _alpaca_paper_authenticated_order_snapshot_prefix,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    create_alpaca_paper_order_snapshot_plan,
)
from packages.application.alpaca_paper_order_view_transition import (
    ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION,
    ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256,
    AlpacaPaperOrderViewTransitionClaim,
    AlpacaPaperOrderViewTransitionConflict,
    AlpacaPaperOrderViewTransitionConsumption,
    AlpacaPaperOrderViewTransitionPlan,
    AlpacaPaperOrderViewTransitionRole,
    _alpaca_paper_order_view_transition_claim,
    _alpaca_paper_order_view_transition_consumption,
    create_alpaca_paper_order_view_transition_plan,
)
from packages.domain.account_coordinator import AccountFenceReceipt
from tests.unit.test_alpaca_paper_order_snapshot_comparison_application import (
    _terminal_pair,
)
from tests.unit.test_alpaca_paper_order_snapshot_runtime import BASE, VALID_UNTIL
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order
from tests.unit.test_submission_attempt import fence_receipt

EARLIER_HEAD = "a" * 64


def _prefix_at(
    terminal: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    page_count: int,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    return _alpaca_paper_authenticated_order_snapshot_prefix(
        terminal.plan,
        page_receipts=terminal.page_receipts[:page_count],
    )


def _transition() -> tuple[
    AlpacaPaperOrderViewTransitionPlan,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
]:
    earlier, later = _terminal_pair(
        earlier_bodies=(
            _body(_order(2), _order(1)),
            b"[]",
        ),
        later_bodies=(b"[]",),
    )
    return (
        create_alpaca_paper_order_view_transition_plan(
            earlier_plan=earlier.plan,
            later_plan=later.plan,
        ),
        earlier,
        later,
    )


def _empty(
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    return _prefix_at(prefix, 0)


def _claim_fence(
    account_id: str,
    *,
    validated_at: datetime = BASE - timedelta(milliseconds=1),
) -> AccountFenceReceipt:
    return fence_receipt(
        account_id=account_id,
        validated_at=validated_at,
        valid_until=VALID_UNTIL,
    )


def _first_earlier_claim(
    transition: AlpacaPaperOrderViewTransitionPlan,
    earlier: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
) -> AlpacaPaperOrderViewTransitionClaim:
    return _alpaca_paper_order_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
        selected_prefix=_empty(earlier),
        previous_claim=None,
        prior_earlier_prefix=None,
        prior_earlier_source_head_sha256=None,
        commit_fence_receipt=_claim_fence(transition.account_id),
    )


def _assert_no_higher_authority(value: object) -> None:
    for name in (
        "authenticated_provider_evidence",
        "request_budget_enforced",
        "raw_response_persisted",
        "runtime_current",
        "capture_authenticated",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "monotonic_timing_qualified",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "reconciliation_complete",
        "unknown_resolution_authorized",
        "resubmission_authorized",
        "reservation_release_authorized",
        "canonical_execution_fact_authorized",
        "readiness_transition_authorized",
        "reconciliation_ready",
        "transport_submission_ready",
        "submission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
        "converged",
    ):
        assert getattr(value, name) is False


def test_transition_plan_is_one_stable_exact_non_authorizing_pair() -> None:
    transition, earlier, later = _transition()

    assert ALPACA_PAPER_ORDER_VIEW_TRANSITION_CONTRACT_VERSION.startswith("phase4aa-")
    assert ALPACA_PAPER_ORDER_VIEW_TRANSITION_POLICY_SHA256 == (
        "c584c1296a3bb5d39fabbf0b16e6d59fdcf034364f42ce06170785b7b43eeb70"
    )
    assert transition.round_id == _transition()[0].round_id
    assert transition.earlier_plan == earlier.plan
    assert transition.later_plan == later.plan
    assert transition.earlier_plan.snapshot_id != transition.later_plan.snapshot_id
    assert len(transition.canonical_json) < 4096
    _assert_no_higher_authority(transition)


def test_transition_plan_rejects_reuse_cross_account_and_profile_mismatch() -> None:
    transition, earlier, later = _transition()

    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="two distinct plans",
    ):
        create_alpaca_paper_order_view_transition_plan(
            earlier_plan=earlier.plan,
            later_plan=earlier.plan,
        )

    cross_account = create_alpaca_paper_order_snapshot_plan(
        account_id="another-paper-account",
        capture_idempotency_key="phase4aa-cross-account",
        page_limit=earlier.plan.page_limit,
        maximum_pages=earlier.plan.maximum_pages,
    )
    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="cross account",
    ):
        create_alpaca_paper_order_view_transition_plan(
            earlier_plan=earlier.plan,
            later_plan=cross_account,
        )

    another_profile = create_alpaca_paper_order_snapshot_plan(
        account_id=transition.account_id,
        capture_idempotency_key="phase4aa-another-profile",
        page_limit=earlier.plan.page_limit + 1,
        maximum_pages=earlier.plan.maximum_pages,
    )
    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="different traversal profiles",
    ):
        create_alpaca_paper_order_view_transition_plan(
            earlier_plan=earlier.plan,
            later_plan=another_profile,
        )
    assert later.plan.account_id == transition.account_id


def test_claims_are_repository_only_and_form_one_exact_gap_free_page_chain() -> None:
    transition, earlier, later = _transition()
    first = _first_earlier_claim(transition, earlier)
    active = _prefix_at(earlier, 1)
    second = _alpaca_paper_order_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
        selected_prefix=active,
        previous_claim=first,
        prior_earlier_prefix=None,
        prior_earlier_source_head_sha256=None,
        commit_fence_receipt=_claim_fence(
            transition.account_id,
            validated_at=BASE + timedelta(seconds=1),
        ),
    )

    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperOrderViewTransitionClaim()
    assert first.description.page_number == 1
    assert first.previous_page_receipt_id is None
    assert second.description.page_number == 2
    assert second.previous_page_receipt_id == active.page_receipts[-1].receipt_id
    assert second.previous_page_receipt_sha256 == active.page_receipts[-1].semantic_sha256
    assert second.previous_persisted_page_sha256 == (
        active.page_receipts[-1].persisted_page.semantic_sha256
    )
    assert first.claim_id != second.claim_id
    assert len(second.canonical_json) < 8192
    _assert_no_higher_authority(second)

    third_plan = create_alpaca_paper_order_snapshot_plan(
        account_id=transition.account_id,
        capture_idempotency_key="phase4aa-third-plan",
        page_limit=transition.earlier_plan.page_limit,
        maximum_pages=transition.earlier_plan.maximum_pages,
    )
    other_transition = create_alpaca_paper_order_view_transition_plan(
        earlier_plan=later.plan,
        later_plan=third_plan,
    )
    other_first = _first_earlier_claim(other_transition, later)
    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="predecessor chain",
    ):
        _alpaca_paper_order_view_transition_claim(
            plan=transition,
            selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
            selected_prefix=active,
            previous_claim=other_first,
            prior_earlier_prefix=None,
            prior_earlier_source_head_sha256=None,
            commit_fence_receipt=_claim_fence(
                transition.account_id,
                validated_at=BASE + timedelta(seconds=1),
            ),
        )


def test_later_claim_requires_exact_terminal_source_head_and_receive_gate() -> None:
    transition, earlier, later = _transition()
    later_empty = _empty(later)
    eligible_at = earlier.page_receipts[-1].persisted_page.observation.received_at + timedelta(
        seconds=2
    )

    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="before its terminal-source boundary",
    ):
        _alpaca_paper_order_view_transition_claim(
            plan=transition,
            selected_role=AlpacaPaperOrderViewTransitionRole.LATER,
            selected_prefix=later_empty,
            previous_claim=None,
            prior_earlier_prefix=earlier,
            prior_earlier_source_head_sha256=EARLIER_HEAD,
            commit_fence_receipt=_claim_fence(
                transition.account_id,
                validated_at=eligible_at - timedelta(microseconds=1),
            ),
        )

    claim = _alpaca_paper_order_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.LATER,
        selected_prefix=later_empty,
        previous_claim=None,
        prior_earlier_prefix=earlier,
        prior_earlier_source_head_sha256=EARLIER_HEAD,
        commit_fence_receipt=_claim_fence(
            transition.account_id,
            validated_at=eligible_at,
        ),
    )

    assert claim.eligible_at == eligible_at
    assert claim.selected_plan == transition.later_plan
    assert claim.prior_earlier_prefix == earlier
    _assert_no_higher_authority(claim)

    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="terminal earlier prefix",
    ):
        _alpaca_paper_order_view_transition_claim(
            plan=transition,
            selected_role=AlpacaPaperOrderViewTransitionRole.LATER,
            selected_prefix=later_empty,
            previous_claim=None,
            prior_earlier_prefix=_prefix_at(earlier, 1),
            prior_earlier_source_head_sha256=EARLIER_HEAD,
            commit_fence_receipt=_claim_fence(
                transition.account_id,
                validated_at=eligible_at,
            ),
        )


def test_consumption_binds_unchanged_preparation_and_exact_claim_lease() -> None:
    transition, earlier, later = _transition()
    claim = _first_earlier_claim(transition, earlier)
    preparation = earlier.page_receipts[0].evidence.preparation
    consumption = _alpaca_paper_order_view_transition_consumption(
        claim=claim,
        preparation=preparation,
        commit_fence_receipt=_claim_fence(
            transition.account_id,
            validated_at=BASE + timedelta(milliseconds=200),
        ),
    )

    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperOrderViewTransitionConsumption()
    assert consumption.preparation == preparation
    assert consumption.claim == claim
    assert consumption.consumed_at == BASE + timedelta(milliseconds=200)
    assert len(consumption.canonical_json) < 8192
    _assert_no_higher_authority(consumption)

    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="another page or prefix",
    ):
        _alpaca_paper_order_view_transition_consumption(
            claim=claim,
            preparation=later.page_receipts[0].evidence.preparation,
            commit_fence_receipt=_claim_fence(
                transition.account_id,
                validated_at=BASE + timedelta(milliseconds=200),
            ),
        )

    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="fence conflicts",
    ):
        _alpaca_paper_order_view_transition_consumption(
            claim=claim,
            preparation=preparation,
            commit_fence_receipt=fence_receipt(
                account_id=transition.account_id,
                validated_at=BASE + timedelta(milliseconds=200),
                valid_until=VALID_UNTIL,
                fencing_generation=2,
            ),
        )
