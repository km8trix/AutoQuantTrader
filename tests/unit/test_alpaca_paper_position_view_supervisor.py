from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta

import pytest

import tests.unit.test_alpaca_paper_position_snapshot_runtime as runtime_fixtures
from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    AlpacaPaperPositionSnapshotComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
    _alpaca_paper_position_snapshot_preparation_receipt,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_snapshot_comparison import (
    AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
    _alpaca_paper_authenticated_position_view_comparison_receipt,
)
from packages.application.alpaca_paper_position_view_supervisor import (
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID,
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256,
    ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION,
    AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
    AlpacaPaperAuthenticatedPositionViewSupervisorResult,
    AlpacaPaperAuthenticatedPositionViewSupervisorStalled,
    AlpacaPaperPositionSnapshotSupervisorSourceStage,
    AlpacaPaperPositionViewSupervisorStage,
    _alpaca_paper_authenticated_position_snapshot_supervisor_state,
    alpaca_paper_position_view_supervisor_round_id,
    supervise_authenticated_alpaca_paper_position_views_once,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from tests.unit.test_alpaca_paper_position_snapshot_runtime import (
    BASE,
    VALID_UNTIL,
    SnapshotRuntime,
    Transport,
    _body,
    _position,
    _scenario,
)
from tests.unit.test_submission_attempt import fence_receipt


def _runtime_plan(
    source: AlpacaPaperPositionSnapshotRuntimePlan,
    capture_key: str,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    return create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=source.description.account_id,
            capture_idempotency_key=capture_key,
        ),
        reference=source.reference,
        account_binding=source.account_binding,
    )


def _separated_receipts(
    suffix: str,
) -> tuple[
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
]:
    earlier_scenario = _scenario(body=_body(_position(1)))
    earlier_scenario.plan = _runtime_plan(
        earlier_scenario.plan,
        f"phase4w-{suffix}-earlier",
    )
    earlier = earlier_scenario.run()

    original_base = runtime_fixtures.BASE
    try:
        runtime_fixtures.BASE = original_base + timedelta(seconds=3)
        later_scenario = _scenario(body=_body(_position(1)))
        later_scenario.plan = create_alpaca_paper_position_snapshot_runtime_plan(
            description=create_alpaca_paper_position_snapshot_description(
                account_id=earlier.account_id,
                capture_idempotency_key=f"phase4w-{suffix}-later",
            ),
            reference=earlier.plan.reference,
            account_binding=earlier.plan.account_binding,
        )
        later_scenario.ingress = earlier_scenario.ingress
        later_scenario.snapshots = SnapshotRuntime(later_scenario.events)
        later_scenario.transport = Transport(
            later_scenario.events,
            body=_body(_position(1)),
            request_id=f"phase4w-{suffix}-later-request",
        )
        later = later_scenario.run()
    finally:
        runtime_fixtures.BASE = original_base

    assert earlier.persisted_snapshot.receipt.ingress_sequence == 1
    assert later.persisted_snapshot.receipt.ingress_sequence == 2
    assert later.evidence.preparation.prepared_at >= (
        earlier.persisted_snapshot.observation.received_at
        + ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION
    )
    return earlier, later


def _state(
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None = None,
    stalled: bool = False,
) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
    if receipt is not None:
        return _alpaca_paper_authenticated_position_snapshot_supervisor_state(
            stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE,
            plan=plan,
            preparation=receipt.evidence.preparation,
            receipt=receipt,
        )
    if stalled:
        return _alpaca_paper_authenticated_position_snapshot_supervisor_state(
            stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED,
            plan=plan,
            preparation=_alpaca_paper_position_snapshot_preparation_receipt(
                plan,
                prepared_at=BASE,
            ),
            receipt=None,
        )
    return _alpaca_paper_authenticated_position_snapshot_supervisor_state(
        stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT,
        plan=plan,
        preparation=None,
        receipt=None,
    )


class _StateLoader:
    def __init__(
        self,
        *states: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
        runtime_store_identity: int = 1,
    ) -> None:
        self.states = {state.plan.plan_id: state for state in states}
        self.state_calls: list[AlpacaPaperPositionSnapshotRuntimePlan] = []
        self.load_calls: list[AlpacaPaperPositionSnapshotRuntimePlan] = []
        self.runtime_store_identity = runtime_store_identity

    def load_state(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
        self.state_calls.append(plan)
        return self.states[plan.plan_id]

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        self.load_calls.append(plan)
        return self.states[plan.plan_id].receipt


class _CaptureWorkflow:
    def __init__(
        self,
        loader: _StateLoader,
        receipts: tuple[
            AlpacaPaperAuthenticatedPositionSnapshotReceipt,
            ...,
        ],
    ) -> None:
        self.loader = loader
        self.receipts = {receipt.plan.plan_id: receipt for receipt in receipts}
        self.calls: list[tuple[AlpacaPaperPositionSnapshotRuntimePlan, AccountFence]] = []
        self.unselected_mutation: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState | None = (
            None
        )

    @property
    def runtime_store_identity(self) -> int:
        return self.loader.runtime_store_identity

    def capture_once(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        self.calls.append((plan, fence))
        receipt = self.receipts[plan.plan_id]
        self.loader.states[plan.plan_id] = _state(plan, receipt=receipt)
        if self.unselected_mutation is not None:
            mutation = self.unselected_mutation
            self.loader.states[mutation.plan.plan_id] = mutation
        return receipt


class _ComparisonRepository:
    def __init__(
        self,
        commit_fence: AccountFenceReceipt,
        *,
        runtime_store_identity: int = 1,
    ) -> None:
        self.commit_fence = commit_fence
        self.runtime_store_identity = runtime_store_identity
        self.record_calls: list[
            tuple[AlpacaPaperAuthenticatedPositionViewComparisonEvidence, AccountFence]
        ] = []
        self.load_calls: list[str] = []
        self.receipt: AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None = None
        self.return_none_on_load = False

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        self.record_calls.append((evidence, fence))
        if self.receipt is None:
            self.receipt = _alpaca_paper_authenticated_position_view_comparison_receipt(
                evidence,
                commit_fence_receipt=self.commit_fence,
                account_sequence=1,
                previous_receipt_sha256=None,
            )
        else:
            assert self.receipt.evidence == evidence
        return self.receipt

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None:
        self.load_calls.append(receipt_id)
        if self.return_none_on_load:
            return None
        assert self.receipt is not None
        assert self.receipt.receipt_id == receipt_id
        return self.receipt


class _Clock:
    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.instant


def _commit_fence(account_id: str) -> AccountFenceReceipt:
    return fence_receipt(
        account_id=account_id,
        validated_at=BASE + timedelta(seconds=4),
        valid_until=VALID_UNTIL,
    )


def _assert_no_higher_authority(value: object) -> None:
    for name in (
        "runtime_current",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
        "monotonic_timing_qualified",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "canonical_position_fact_authorized",
        "canonical_execution_fact_authorized",
        "canonical_account_fact_authorized",
        "canonical_cash_fact_authorized",
        "canonical_ledger_fact_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "reconciliation_complete",
        "readiness_transition_authorized",
        "reconciliation_ready",
        "dispatch_preflight_ready",
        "paper_startup_ready",
        "unknown_resolution_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "transport_submission_ready",
        "submission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
        "converged",
    ):
        assert getattr(value, name) is False


def test_restart_round_advances_once_waits_advances_once_then_compares() -> None:
    earlier, later = _separated_receipts("round")
    loader = _StateLoader(_state(earlier.plan), _state(later.plan))
    workflow = _CaptureWorkflow(loader, (earlier, later))
    commit_fence = _commit_fence(earlier.account_id)
    repository = _ComparisonRepository(commit_fence)
    eligible_at = (
        earlier.persisted_snapshot.observation.received_at
        + ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION
    )

    first = supervise_authenticated_alpaca_paper_position_views_once(
        earlier.plan,
        later.plan,
        fence=commit_fence.fence,
        clock=_Clock(BASE),
        state_loader=loader,
        capture_workflow=workflow,
        comparison_repository=repository,
    )
    assert first.stage is AlpacaPaperPositionViewSupervisorStage.EARLIER_CAPTURE_RECORDED
    assert first.value == earlier
    assert len(workflow.calls) == 1
    assert repository.record_calls == []

    waiting_clock = _Clock(eligible_at - timedelta(microseconds=1))
    waiting = supervise_authenticated_alpaca_paper_position_views_once(
        earlier.plan,
        later.plan,
        fence=commit_fence.fence,
        clock=waiting_clock,
        state_loader=loader,
        capture_workflow=workflow,
        comparison_repository=repository,
    )
    assert waiting.stage is AlpacaPaperPositionViewSupervisorStage.WAITING_MINIMUM_SEPARATION
    assert waiting.checked_at == eligible_at - timedelta(microseconds=1)
    assert waiting.eligible_at == eligible_at
    assert waiting.value is None
    assert waiting_clock.calls == 1
    assert len(workflow.calls) == 1

    later_clock = _Clock(eligible_at)
    second = supervise_authenticated_alpaca_paper_position_views_once(
        earlier.plan,
        later.plan,
        fence=commit_fence.fence,
        clock=later_clock,
        state_loader=loader,
        capture_workflow=workflow,
        comparison_repository=repository,
    )
    assert second.stage is AlpacaPaperPositionViewSupervisorStage.LATER_CAPTURE_RECORDED
    assert second.value == later
    assert len(workflow.calls) == 2
    assert repository.record_calls == []

    no_clock = _Clock(BASE)
    compared = supervise_authenticated_alpaca_paper_position_views_once(
        earlier.plan,
        later.plan,
        fence=commit_fence.fence,
        clock=no_clock,
        state_loader=loader,
        capture_workflow=workflow,
        comparison_repository=repository,
    )
    assert ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION == (
        "phase4w-bounded-authenticated-position-view-supervisor-v1"
    )
    assert ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID == (
        "phase4w-one-durable-transition-position-supervisor-policy-v1"
    )
    assert len(ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256) == 64
    assert compared.stage is AlpacaPaperPositionViewSupervisorStage.COMPARISON_RECORDED
    assert compared.value == repository.receipt
    assert compared.value is not None
    assert compared.value.evidence.comparison.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.EXACT_POSITION_VIEW_MATCH_UNQUALIFIED
    )
    assert len(repository.record_calls) == 1
    assert repository.load_calls == [compared.value.receipt_id]
    assert no_clock.calls == 0
    assert len(workflow.calls) == 2
    assert compared.round_id == alpaca_paper_position_view_supervisor_round_id(
        earlier.plan,
        later.plan,
    )
    for value in (
        first,
        waiting,
        second,
        compared,
        compared.earlier_state,
        compared.later_state,
    ):
        _assert_no_higher_authority(value)


@pytest.mark.parametrize("stalled_role", ["earlier", "later"])
def test_stalled_single_use_claim_fails_before_clock_capture_or_comparison(
    stalled_role: str,
) -> None:
    earlier, later = _separated_receipts(f"stalled-{stalled_role}")
    earlier_state = _state(earlier.plan, stalled=stalled_role == "earlier")
    later_state = _state(later.plan, stalled=stalled_role == "later")
    loader = _StateLoader(earlier_state, later_state)
    workflow = _CaptureWorkflow(loader, (earlier, later))
    clock = _Clock(BASE + timedelta(seconds=20))
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorStalled,
        match="conservatively stalled",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=clock,
            state_loader=loader,
            capture_workflow=workflow,
            comparison_repository=repository,
        )

    assert clock.calls == 0
    assert workflow.calls == []
    assert repository.record_calls == []


def test_mismatched_runtime_store_fails_before_clock_capture_or_comparison() -> None:
    earlier, later = _separated_receipts("miswired-store")
    loader = _StateLoader(_state(earlier.plan), _state(later.plan))
    workflow = _CaptureWorkflow(loader, (earlier, later))
    clock = _Clock(BASE + timedelta(seconds=20))
    repository = _ComparisonRepository(
        _commit_fence(earlier.account_id),
        runtime_store_identity=2,
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="do not share one runtime durable store",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=clock,
            state_loader=loader,
            capture_workflow=workflow,
            comparison_repository=repository,
        )

    assert loader.state_calls == []
    assert clock.calls == 0
    assert workflow.calls == []
    assert repository.record_calls == []


def test_later_source_cannot_complete_before_earlier_source() -> None:
    earlier, later = _separated_receipts("later-first")
    loader = _StateLoader(_state(earlier.plan), _state(later.plan, receipt=later))
    workflow = _CaptureWorkflow(loader, (earlier, later))
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="completed before the earlier",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=_Clock(BASE),
            state_loader=loader,
            capture_workflow=workflow,
            comparison_repository=repository,
        )
    assert workflow.calls == []
    assert repository.record_calls == []


def test_existing_later_source_must_prove_authenticated_start_gate() -> None:
    earlier_scenario = _scenario(body=_body(_position(1)))
    earlier_scenario.plan = _runtime_plan(
        earlier_scenario.plan,
        "phase4w-ungated-earlier",
    )
    earlier = earlier_scenario.run()
    later_scenario = _scenario(body=_body(_position(1)))
    later_scenario.plan = _runtime_plan(
        earlier.plan,
        "phase4w-ungated-later",
    )
    later_scenario.ingress = earlier_scenario.ingress
    later_scenario.snapshots = SnapshotRuntime(later_scenario.events)
    later = later_scenario.run()
    loader = _StateLoader(
        _state(earlier.plan, receipt=earlier),
        _state(later.plan, receipt=later),
    )
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="gate-separated start evidence",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=_Clock(BASE + timedelta(seconds=20)),
            state_loader=loader,
            capture_workflow=_CaptureWorkflow(loader, (earlier, later)),
            comparison_repository=repository,
        )
    assert repository.record_calls == []


def test_new_later_capture_cannot_predate_this_calls_selection_check() -> None:
    earlier, later = _separated_receipts("selection-check")
    loader = _StateLoader(
        _state(earlier.plan, receipt=earlier),
        _state(later.plan),
    )
    workflow = _CaptureWorkflow(loader, (earlier, later))
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))
    selected_at = later.evidence.preparation.prepared_at + timedelta(microseconds=1)

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="gate-separated start evidence",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=_Clock(selected_at),
            state_loader=loader,
            capture_workflow=workflow,
            comparison_repository=repository,
        )
    assert len(workflow.calls) == 1
    assert repository.record_calls == []


def test_selected_capture_rejects_concurrent_unselected_source_change() -> None:
    earlier, later = _separated_receipts("unselected-mutation")
    loader = _StateLoader(_state(earlier.plan), _state(later.plan))
    workflow = _CaptureWorkflow(loader, (earlier, later))
    workflow.unselected_mutation = _state(later.plan, receipt=later)
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="unselected later position source changed",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=_Clock(BASE),
            state_loader=loader,
            capture_workflow=workflow,
            comparison_repository=repository,
        )
    assert len(workflow.calls) == 1
    assert repository.record_calls == []


def test_concurrently_stalled_unselected_source_is_detected_after_bounded_capture() -> None:
    earlier, later = _separated_receipts("unselected-stall")
    loader = _StateLoader(_state(earlier.plan), _state(later.plan))
    workflow = _CaptureWorkflow(loader, (earlier, later))
    workflow.unselected_mutation = _state(later.plan, stalled=True)
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="unselected later position source changed",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=_Clock(BASE),
            state_loader=loader,
            capture_workflow=workflow,
            comparison_repository=repository,
        )
    # Phase 4W has no pair-wide durable CAS.  It bounds this race to one selected
    # capture and rejects the result; deployed exclusive pair coordination is pending.
    assert len(workflow.calls) == 1
    assert loader.states[later.plan.plan_id].stage is (
        AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED
    )
    assert repository.record_calls == []


def test_comparison_must_reload_exact_repository_receipt() -> None:
    earlier, later = _separated_receipts("comparison-reload")
    loader = _StateLoader(
        _state(earlier.plan, receipt=earlier),
        _state(later.plan, receipt=later),
    )
    repository = _ComparisonRepository(_commit_fence(earlier.account_id))
    repository.return_none_on_load = True

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="non-canonical receipt",
    ):
        supervise_authenticated_alpaca_paper_position_views_once(
            earlier.plan,
            later.plan,
            fence=repository.commit_fence.fence,
            clock=_Clock(BASE),
            state_loader=loader,
            capture_workflow=_CaptureWorkflow(loader, (earlier, later)),
            comparison_repository=repository,
        )
    assert len(repository.record_calls) == 1
    assert len(repository.load_calls) == 1


def test_supervisor_values_are_proof_constructed_and_immutable() -> None:
    earlier, later = _separated_receipts("proofs")
    state = _state(earlier.plan, receipt=earlier)

    with pytest.raises(TypeError):
        AlpacaPaperAuthenticatedPositionSnapshotSupervisorState()
    with pytest.raises(TypeError):
        AlpacaPaperAuthenticatedPositionViewSupervisorResult()
    with pytest.raises(FrozenInstanceError):
        state.stage = AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT  # type: ignore[misc]
    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewSupervisorConflict,
        match="distinct plans",
    ):
        alpaca_paper_position_view_supervisor_round_id(
            earlier.plan,
            earlier.plan,
        )
    assert alpaca_paper_position_view_supervisor_round_id(
        earlier.plan,
        later.plan,
    )
