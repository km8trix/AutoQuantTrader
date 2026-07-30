from __future__ import annotations

from datetime import timedelta

import pytest

import tests.unit.test_alpaca_paper_position_snapshot_runtime as runtime_fixtures
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperPositionSnapshotRuntimePlan,
    _alpaca_paper_position_snapshot_preparation_receipt,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_view_transition import (
    ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
    ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
    AlpacaPaperPositionViewTransitionClaim,
    AlpacaPaperPositionViewTransitionConflict,
    AlpacaPaperPositionViewTransitionConsumption,
    AlpacaPaperPositionViewTransitionPlan,
    AlpacaPaperPositionViewTransitionRole,
    _alpaca_paper_position_view_transition_claim,
    _alpaca_paper_position_view_transition_consumption,
    create_alpaca_paper_position_view_transition_plan,
)
from tests.unit.test_alpaca_paper_position_snapshot_runtime import BASE, _scenario
from tests.unit.test_submission_attempt import fence_receipt


def _plan(
    source: AlpacaPaperPositionSnapshotRuntimePlan,
    key: str,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    return create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=source.description.account_id,
            capture_idempotency_key=key,
        ),
        reference=source.reference,
        account_binding=source.account_binding,
    )


def _transition() -> AlpacaPaperPositionViewTransitionPlan:
    source = _scenario().plan
    return create_alpaca_paper_position_view_transition_plan(
        earlier_plan=_plan(source, "phase4x-unit-earlier"),
        later_plan=_plan(source, "phase4x-unit-later"),
    )


def test_transition_plan_registers_one_exact_non_authorizing_pair() -> None:
    transition = _transition()

    assert ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION.startswith("phase4x-")
    assert len(ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256) == 64
    assert transition.earlier_plan.plan_id != transition.later_plan.plan_id
    assert transition.round_id == _transition().round_id
    assert transition.runtime_current is False
    assert transition.provider_io_performed is False
    assert transition.submission_authorized is False
    assert transition.trading_effect_authorized is False


def test_claims_are_repository_only_and_enforce_later_receive_boundary() -> None:
    transition = _transition()
    earlier_scenario = _scenario()
    earlier_scenario.plan = transition.earlier_plan
    earlier = earlier_scenario.run()
    eligible_at = earlier.persisted_snapshot.observation.received_at + timedelta(seconds=2)

    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperPositionViewTransitionClaim()
    with pytest.raises(
        AlpacaPaperPositionViewTransitionConflict,
        match="receive-time boundary",
    ):
        _alpaca_paper_position_view_transition_claim(
            plan=transition,
            selected_role=AlpacaPaperPositionViewTransitionRole.LATER,
            prior_earlier_receipt=earlier,
            commit_fence_receipt=fence_receipt(
                account_id=transition.account_id,
                validated_at=eligible_at - timedelta(microseconds=1),
                valid_until=eligible_at + timedelta(seconds=10),
            ),
        )

    claim = _alpaca_paper_position_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.LATER,
        prior_earlier_receipt=earlier,
        commit_fence_receipt=fence_receipt(
            account_id=transition.account_id,
            validated_at=eligible_at,
            valid_until=eligible_at + timedelta(seconds=10),
        ),
    )

    assert claim.eligible_at == eligible_at
    assert claim.selected_plan == transition.later_plan
    assert claim.runtime_current is False
    assert claim.broker_call_authorized is False


def test_consumption_requires_exact_nonregressing_claim_lease() -> None:
    transition = _transition()
    selected_at = BASE + timedelta(seconds=1)
    valid_until = BASE + timedelta(seconds=20)
    claim = _alpaca_paper_position_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        prior_earlier_receipt=None,
        commit_fence_receipt=fence_receipt(
            account_id=transition.account_id,
            validated_at=selected_at,
            valid_until=valid_until,
        ),
    )
    preparation = _alpaca_paper_position_snapshot_preparation_receipt(
        transition.earlier_plan,
        prepared_at=selected_at + timedelta(milliseconds=1),
    )
    consumption_fence = fence_receipt(
        account_id=transition.account_id,
        validated_at=selected_at + timedelta(milliseconds=2),
        valid_until=valid_until,
    )
    consumption = _alpaca_paper_position_view_transition_consumption(
        claim=claim,
        preparation=preparation,
        commit_fence_receipt=consumption_fence,
    )

    assert consumption.preparation == preparation
    assert consumption.trading_effect_authorized is False
    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperPositionViewTransitionConsumption()
    with pytest.raises(
        AlpacaPaperPositionViewTransitionConflict,
        match="conflicts with its preparation",
    ):
        _alpaca_paper_position_view_transition_consumption(
            claim=claim,
            preparation=preparation,
            commit_fence_receipt=fence_receipt(
                account_id=transition.account_id,
                validated_at=selected_at + timedelta(milliseconds=2),
                valid_until=valid_until,
                fencing_generation=2,
            ),
        )


def test_pair_rejects_reused_member() -> None:
    source = _scenario().plan
    plan = _plan(source, "phase4x-unit-reused")
    with pytest.raises(
        AlpacaPaperPositionViewTransitionConflict,
        match="two distinct plans",
    ):
        create_alpaca_paper_position_view_transition_plan(
            earlier_plan=plan,
            later_plan=plan,
        )


def test_fixture_clock_is_restored() -> None:
    # Guard the mutable runtime fixture used by neighboring supervisor tests.
    assert runtime_fixtures.BASE == BASE
