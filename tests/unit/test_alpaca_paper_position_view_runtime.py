from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from threading import Barrier, Lock

import pytest

from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
    AlpacaPaperPositionSnapshotTransportRequest,
    AlpacaPaperPositionSnapshotTransportResponse,
    _alpaca_paper_authenticated_position_snapshot_evidence,
    _alpaca_paper_authenticated_position_snapshot_receipt,
    _alpaca_paper_position_snapshot_preparation_receipt,
)
from packages.application.alpaca_paper_position_view_runtime import (
    ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_CONTRACT_VERSION,
    ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_SHA256,
    AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
    AlpacaPaperPairAdmittedPositionViewRuntimeResult,
    _pair_admitted_position_view_runtime_result,
    supervise_pair_admitted_alpaca_paper_position_views_once,
)
from packages.application.alpaca_paper_position_view_supervisor import (
    AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    AlpacaPaperAuthenticatedPositionViewSupervisorStalled,
    AlpacaPaperPositionSnapshotSupervisorSourceStage,
    AlpacaPaperPositionViewSupervisorStage,
    _alpaca_paper_authenticated_position_snapshot_supervisor_state,
    _alpaca_paper_authenticated_position_view_supervisor_result,
)
from packages.application.alpaca_paper_position_view_transition import (
    AlpacaPaperPositionViewTransitionClaim,
    AlpacaPaperPositionViewTransitionConsumption,
    AlpacaPaperPositionViewTransitionPlan,
    AlpacaPaperPositionViewTransitionRole,
    _alpaca_paper_position_view_transition_claim,
    _alpaca_paper_position_view_transition_consumption,
    create_alpaca_paper_position_view_transition_plan,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from tests.unit.test_alpaca_paper_position_snapshot_runtime import BASE, VALID_UNTIL
from tests.unit.test_alpaca_paper_position_view_supervisor import (
    _Clock,
    _commit_fence,
    _ComparisonRepository,
    _separated_receipts,
    _state,
)
from tests.unit.test_submission_attempt import fence_receipt


class _SnapshotRuntime:
    def __init__(
        self,
        earlier: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
        later: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
        *,
        runtime_store_identity: int = 1,
    ) -> None:
        self.runtime_store_identity = runtime_store_identity
        self.expected = {
            earlier.plan.plan_id: earlier,
            later.plan.plan_id: later,
        }
        self.states = {
            earlier.plan.plan_id: _state(earlier.plan),
            later.plan.plan_id: _state(later.plan),
        }
        self.state_calls: list[AlpacaPaperPositionSnapshotRuntimePlan] = []
        self.record_calls: list[AlpacaPaperAuthenticatedPositionSnapshotEvidence] = []
        self.load_calls: list[AlpacaPaperPositionSnapshotRuntimePlan] = []

    def mark_prepared(
        self,
        preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
    ) -> None:
        self.states[preparation.plan.plan_id] = (
            _alpaca_paper_authenticated_position_snapshot_supervisor_state(
                stage=AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED,
                plan=preparation.plan,
                preparation=preparation,
                receipt=None,
            )
        )

    def load_state(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
        self.state_calls.append(plan)
        return self.states[plan.plan_id]

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt:
        del plan, checked_at
        raise AssertionError("Phase 4Y must not call unscoped Phase 4U prepare")

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        self.record_calls.append(evidence)
        receipt = self.expected[evidence.plan.plan_id]
        assert receipt.evidence == evidence
        self.states[evidence.plan.plan_id] = _state(
            evidence.plan,
            receipt=receipt,
        )
        return receipt

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        self.load_calls.append(plan)
        return self.states[plan.plan_id].receipt


class _TransitionRepository:
    def __init__(
        self,
        runtime: _SnapshotRuntime,
        *,
        runtime_store_identity: int = 1,
    ) -> None:
        self.runtime_store_identity = runtime_store_identity
        self.runtime = runtime
        self.claims: dict[str, AlpacaPaperPositionViewTransitionClaim] = {}
        self.consumptions: dict[str, AlpacaPaperPositionViewTransitionConsumption] = {}
        self.claim_calls: list[AlpacaPaperPositionViewTransitionRole] = []
        self.prepare_calls: list[str] = []
        self.substituted_claim: AlpacaPaperPositionViewTransitionClaim | None = None
        self.claim_barrier: Barrier | None = None
        self._lock = Lock()

    def claim(
        self,
        transition: AlpacaPaperPositionViewTransitionPlan,
        *,
        selected_role: AlpacaPaperPositionViewTransitionRole,
        fence: AccountFence,
    ) -> AlpacaPaperPositionViewTransitionClaim:
        self.claim_calls.append(selected_role)
        if self.claim_barrier is not None:
            self.claim_barrier.wait()
        selected = transition.selected_plan(selected_role)
        expected = self.runtime.expected[selected.plan_id]
        prior = (
            None
            if selected_role is AlpacaPaperPositionViewTransitionRole.EARLIER
            else self.runtime.states[transition.earlier_plan.plan_id].receipt
        )
        claim = _alpaca_paper_position_view_transition_claim(
            plan=transition,
            selected_role=selected_role,
            prior_earlier_receipt=prior,
            commit_fence_receipt=fence_receipt(
                account_id=transition.account_id,
                validated_at=expected.evidence.preparation.prepared_at,
                valid_until=VALID_UNTIL,
            ),
        )
        assert claim.commit_fence_receipt.fence == fence
        with self._lock:
            existing = self.claims.setdefault(claim.claim_id, claim)
        assert existing == claim
        return existing

    def prepare_claimed(
        self,
        claim: AlpacaPaperPositionViewTransitionClaim,
        *,
        checked_at: datetime,
        fence: AccountFence,
    ) -> AlpacaPaperPositionViewTransitionConsumption:
        self.prepare_calls.append(claim.claim_id)
        with self._lock:
            if any(value.claim == claim for value in self.consumptions.values()):
                raise RuntimeError("claim already consumed")
            assert fence == claim.commit_fence_receipt.fence
            preparation = _alpaca_paper_position_snapshot_preparation_receipt(
                claim.selected_plan,
                prepared_at=checked_at,
            )
            consumption = _alpaca_paper_position_view_transition_consumption(
                claim=claim,
                preparation=preparation,
                commit_fence_receipt=fence_receipt(
                    account_id=claim.plan.account_id,
                    validated_at=checked_at,
                    valid_until=VALID_UNTIL,
                ),
            )
            self.consumptions[consumption.consumption_id] = consumption
            self.runtime.mark_prepared(preparation)
        return consumption

    def load_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperPositionViewTransitionClaim | None:
        if self.substituted_claim is not None:
            return self.substituted_claim
        return self.claims.get(claim_id)

    def load_consumption(
        self,
        consumption_id: str,
    ) -> AlpacaPaperPositionViewTransitionConsumption | None:
        return self.consumptions.get(consumption_id)

    def load_consumption_for_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperPositionViewTransitionConsumption | None:
        values = [value for value in self.consumptions.values() if value.claim.claim_id == claim_id]
        assert len(values) <= 1
        return None if not values else values[0]


class _Coordinator:
    def __init__(
        self,
        receipts: tuple[AccountFenceReceipt, ...],
        *,
        runtime_store_identity: int = 1,
        changed_lease_call: int | None = None,
    ) -> None:
        self.account_id = receipts[0].fence.account_id
        self.runtime_store_identity = runtime_store_identity
        self.receipts = receipts
        self.changed_lease_call = changed_lease_call
        self.calls = 0

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        self.calls += 1
        receipt = self.receipts[self.calls - 1]
        assert receipt.fence == fence
        if self.calls != self.changed_lease_call:
            return receipt
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256="e" * 64,
        )


class _CaptureWorkflow:
    def __init__(
        self,
        receipts: tuple[
            AlpacaPaperAuthenticatedPositionSnapshotReceipt,
            AlpacaPaperAuthenticatedPositionSnapshotReceipt,
        ],
        *,
        runtime_store_identity: int = 1,
        crash_after_prepare: bool = False,
    ) -> None:
        self.runtime_store_identity = runtime_store_identity
        self.receipts = {receipt.plan.plan_id: receipt for receipt in receipts}
        self.crash_after_prepare = crash_after_prepare
        self.calls: list[AlpacaPaperPositionSnapshotRuntimePlan] = []
        self.events: list[str] = []

    def capture_once(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        fence: AccountFence,
        snapshot_runtime: object,
        coordinator: object,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        self.calls.append(plan)
        receipt = self.receipts[plan.plan_id]
        preparation = snapshot_runtime.prepare(  # type: ignore[attr-defined]
            plan,
            checked_at=receipt.evidence.preparation.prepared_at,
        )
        assert preparation == receipt.evidence.preparation
        self.events.append("prepared")
        if self.crash_after_prepare:
            raise RuntimeError("simulated crash after atomic consumption")
        pre = coordinator.revalidate(fence)  # type: ignore[attr-defined]
        assert pre == receipt.evidence.pre_fence_receipt
        self.events.append("transport")
        post = coordinator.revalidate(fence)  # type: ignore[attr-defined]
        assert post == receipt.evidence.post_fence_receipt
        final = coordinator.revalidate(fence)  # type: ignore[attr-defined]
        assert final == receipt.evidence.final_fence_receipt
        recorded = snapshot_runtime.record(receipt.evidence)  # type: ignore[attr-defined]
        assert recorded == receipt
        loaded = snapshot_runtime.load(plan)  # type: ignore[attr-defined]
        assert loaded == receipt
        return receipt


def _fixture(
    suffix: str,
    *,
    coordinator_store_identity: int = 1,
    changed_lease_call: int | None = None,
    crash_after_prepare: bool = False,
) -> tuple[
    AlpacaPaperPositionViewTransitionPlan,
    _SnapshotRuntime,
    _TransitionRepository,
    _Coordinator,
    _CaptureWorkflow,
    _ComparisonRepository,
]:
    earlier, later = _separated_receipts(f"phase4y-{suffix}")
    transition = create_alpaca_paper_position_view_transition_plan(
        earlier_plan=earlier.plan,
        later_plan=later.plan,
    )
    runtime = _SnapshotRuntime(earlier, later)
    transitions = _TransitionRepository(runtime)
    coordinator = _Coordinator(
        (
            earlier.evidence.pre_fence_receipt,
            earlier.evidence.post_fence_receipt,
            earlier.evidence.final_fence_receipt,
            later.evidence.pre_fence_receipt,
            later.evidence.post_fence_receipt,
            later.evidence.final_fence_receipt,
        ),
        runtime_store_identity=coordinator_store_identity,
        changed_lease_call=changed_lease_call,
    )
    capture = _CaptureWorkflow(
        (earlier, later),
        crash_after_prepare=crash_after_prepare,
    )
    comparison = _ComparisonRepository(_commit_fence(earlier.account_id))
    return transition, runtime, transitions, coordinator, capture, comparison


def _run(
    transition: AlpacaPaperPositionViewTransitionPlan,
    runtime: _SnapshotRuntime,
    transitions: _TransitionRepository,
    coordinator: _Coordinator,
    capture: _CaptureWorkflow,
    comparison: _ComparisonRepository,
    *,
    checked_at: datetime,
) -> AlpacaPaperPairAdmittedPositionViewRuntimeResult:
    return supervise_pair_admitted_alpaca_paper_position_views_once(
        transition,
        fence=comparison.commit_fence.fence,
        clock=_Clock(checked_at),
        transition_repository=transitions,
        snapshot_runtime=runtime,
        capture_workflow=capture,
        coordinator=coordinator,  # type: ignore[arg-type]
        comparison_repository=comparison,
    )


def _receipt_under_lease(
    source: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    *,
    lease_sha256: str,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    def changed_fence(receipt: AccountFenceReceipt) -> AccountFenceReceipt:
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256=lease_sha256,
        )

    original = source.evidence
    pre_fence = changed_fence(original.pre_fence_receipt)
    post_fence = changed_fence(original.post_fence_receipt)
    final_fence = changed_fence(original.final_fence_receipt)
    request = AlpacaPaperPositionSnapshotTransportRequest(
        plan=original.request.plan,
        preparation_sha256=original.request.preparation_sha256,
        pre_account_identity_sha256=original.request.pre_account_identity_sha256,
        demand_sha256=original.request.demand_sha256,
        permit_sha256=original.request.permit_sha256,
        permit_freshness_sha256=original.request.permit_freshness_sha256,
        pre_fence_receipt_sha256=pre_fence.semantic_sha256,
        started_at=original.request.started_at,
        httpx_phase_timeout=original.request.httpx_phase_timeout,
    )
    response = AlpacaPaperPositionSnapshotTransportResponse(
        request_sha256=request.semantic_sha256,
        transport_id=original.response.transport_id,
        transport_version=original.response.transport_version,
        http_status=original.response.http_status,
        provider_request_id=original.response.provider_request_id,
        media_type=original.response.media_type,
        response_body=original.response.response_body,
        tls_verified=original.response.tls_verified,
        redirects_followed=original.response.redirects_followed,
    )
    evidence = _alpaca_paper_authenticated_position_snapshot_evidence(
        plan=original.plan,
        preparation=original.preparation,
        credential_receipt=original.credential_receipt,
        pre_account_identity=original.pre_account_identity,
        policy=original.policy,
        demand=original.demand,
        permit=original.permit,
        permit_freshness=original.permit_freshness,
        pre_fence_receipt=pre_fence,
        request=request,
        response=response,
        persisted_snapshot=original.persisted_snapshot,
        post_fence_receipt=post_fence,
        post_account_identity=original.post_account_identity,
        final_fence_receipt=final_fence,
        authenticated_at=original.authenticated_at,
    )
    return _alpaca_paper_authenticated_position_snapshot_receipt(
        evidence,
        commit_fence_receipt=changed_fence(source.commit_fence_receipt),
    )


def test_pair_admitted_round_captures_once_waits_captures_once_then_compares() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("round")
    earlier = runtime.expected[transition.earlier_plan.plan_id]
    eligible_at = earlier.persisted_snapshot.observation.received_at + timedelta(seconds=2)

    first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )
    assert first.stage is AlpacaPaperPositionViewSupervisorStage.EARLIER_CAPTURE_RECORDED
    assert first.value == earlier
    assert first.earlier_consumption.preparation == earlier.evidence.preparation
    assert first.later_claim is None
    assert transitions.claim_calls == [AlpacaPaperPositionViewTransitionRole.EARLIER]
    assert len(capture.calls) == 1
    assert capture.events == ["prepared", "transport"]
    assert coordinator.calls == 3

    waiting = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=eligible_at - timedelta(microseconds=1),
    )
    assert waiting.stage is AlpacaPaperPositionViewSupervisorStage.WAITING_MINIMUM_SEPARATION
    assert waiting.value is None
    assert len(capture.calls) == 1
    assert coordinator.calls == 3
    assert comparison.record_calls == []

    second = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=eligible_at,
    )
    assert second.stage is AlpacaPaperPositionViewSupervisorStage.LATER_CAPTURE_RECORDED
    assert second.later_consumption is not None
    assert len(capture.calls) == 2
    assert capture.events == ["prepared", "transport", "prepared", "transport"]
    assert coordinator.calls == 6

    compared = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )
    assert ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_CONTRACT_VERSION.startswith("phase4y-")
    assert len(ALPACA_PAPER_PAIR_ADMITTED_POSITION_VIEW_RUNTIME_POLICY_SHA256) == 64
    assert compared.stage is AlpacaPaperPositionViewSupervisorStage.COMPARISON_RECORDED
    assert compared.earlier_claim == first.earlier_claim
    assert compared.later_claim == second.later_claim
    assert len(capture.calls) == 2
    assert coordinator.calls == 6
    assert len(comparison.record_calls) == 1
    assert compared.runtime_current is False
    assert compared.converged is False
    assert compared.trading_effect_authorized is False


def test_direct_unscoped_complete_source_fails_before_claim_clock_or_comparison() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("direct-complete")
    earlier = runtime.expected[transition.earlier_plan.plan_id]
    runtime.states[earlier.plan.plan_id] = _state(earlier.plan, receipt=earlier)

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="lacks its exact pair admission",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert transitions.claim_calls == []
    assert capture.calls == []
    assert coordinator.calls == 0
    assert comparison.record_calls == []


def test_absent_source_with_consumption_is_rejected_before_effects() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("absent-consumed")
    claim = transitions.claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=comparison.commit_fence.fence,
    )
    expected = runtime.expected[transition.earlier_plan.plan_id]
    transitions.prepare_claimed(
        claim,
        checked_at=expected.evidence.preparation.prepared_at,
        fence=comparison.commit_fence.fence,
    )
    runtime.states[transition.earlier_plan.plan_id] = _state(transition.earlier_plan)
    transitions.claim_calls.clear()

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="absent position source has a consumed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert transitions.claim_calls == []
    assert capture.calls == []
    assert coordinator.calls == 0


def test_stale_claim_lease_fails_on_first_pretransport_check() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture(
        "stale-lease",
        changed_lease_call=1,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="account lease changed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert capture.events == ["prepared"]
    assert runtime.record_calls == []
    assert coordinator.calls == 1
    assert runtime.states[transition.earlier_plan.plan_id].stage is (
        AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED
    )


def test_midcapture_lease_change_allows_one_raw_read_but_no_phase4u_commit() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture(
        "mid-lease",
        changed_lease_call=2,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="account lease changed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert capture.events == ["prepared", "transport"]
    assert runtime.record_calls == []
    assert coordinator.calls == 2
    assert len(capture.calls) == 1


def test_crash_after_consumption_is_stalled_and_never_resends() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture(
        "crash",
        crash_after_prepare=True,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="capture workflow failed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )
    assert capture.events == ["prepared"]
    assert len(capture.calls) == 1

    capture.crash_after_prepare = False
    with pytest.raises(AlpacaPaperAuthenticatedPositionViewSupervisorStalled):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE + timedelta(seconds=10),
        )
    assert len(capture.calls) == 1
    assert coordinator.calls == 0


def test_store_mismatch_fails_before_state_claim_or_effect() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture(
        "store-mismatch",
        coordinator_store_identity=2,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="do not share one durable store",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert runtime.state_calls == []
    assert transitions.claim_calls == []
    assert capture.calls == []
    assert coordinator.calls == 0


def test_substituted_role_claim_fails_before_comparison() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("substitution")
    earlier = runtime.expected[transition.earlier_plan.plan_id]
    eligible_at = earlier.persisted_snapshot.observation.received_at + timedelta(seconds=2)
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=eligible_at,
    )
    transitions.substituted_claim = next(
        claim
        for claim in transitions.claims.values()
        if claim.selected_role is AlpacaPaperPositionViewTransitionRole.EARLIER
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="substituted another role or pair",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert comparison.record_calls == []


def test_claim_only_same_lease_restart_consumes_then_captures() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("claim-restart")
    historical = transitions.claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=comparison.commit_fence.fence,
    )
    transitions.claim_calls.clear()

    result = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )

    assert result.stage is AlpacaPaperPositionViewSupervisorStage.EARLIER_CAPTURE_RECORDED
    assert result.earlier_claim == historical
    assert len(transitions.consumptions) == 1
    assert capture.events == ["prepared", "transport"]


def test_concurrent_same_role_callers_perform_at_most_one_provider_read() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("concurrent")
    transitions.claim_barrier = Barrier(2)

    def invoke() -> AlpacaPaperPairAdmittedPositionViewRuntimeResult:
        return _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (executor.submit(invoke), executor.submit(invoke))
        outcomes: list[object] = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except Exception as error:
                outcomes.append(error)

    assert (
        sum(type(value) is AlpacaPaperPairAdmittedPositionViewRuntimeResult for value in outcomes)
        == 1
    )
    assert sum(isinstance(value, Exception) for value in outcomes) == 1
    assert capture.events.count("transport") == 1
    assert len(runtime.record_calls) == 1
    assert len(transitions.consumptions) == 1


def test_restarted_complete_receipt_must_share_consumption_lease() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture(
        "restarted-wrong-lease"
    )
    earlier = runtime.expected[transition.earlier_plan.plan_id]
    earlier_claim = transitions.claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=comparison.commit_fence.fence,
    )
    transitions.prepare_claimed(
        earlier_claim,
        checked_at=earlier.evidence.preparation.prepared_at,
        fence=comparison.commit_fence.fence,
    )
    wrong_earlier = _receipt_under_lease(earlier, lease_sha256="e" * 64)
    runtime.states[earlier.plan.plan_id] = _state(
        earlier.plan,
        receipt=wrong_earlier,
    )
    later = runtime.expected[transition.later_plan.plan_id]
    later_claim = transitions.claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.LATER,
        fence=comparison.commit_fence.fence,
    )
    transitions.prepare_claimed(
        later_claim,
        checked_at=later.evidence.preparation.prepared_at,
        fence=comparison.commit_fence.fence,
    )
    runtime.states[later.plan.plan_id] = _state(
        later.plan,
        receipt=_receipt_under_lease(later, lease_sha256="e" * 64),
    )
    comparison.record_calls.clear()

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="escaped its consumed pair-claim lease",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            capture,
            comparison,
            checked_at=BASE,
        )

    assert capture.calls == []
    assert comparison.record_calls == []


def test_standalone_result_rejects_complete_receipt_under_another_lease() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("result-lease")
    first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )
    supervisor = first.supervisor_result
    earlier = runtime.expected[transition.earlier_plan.plan_id]
    changed = _receipt_under_lease(earlier, lease_sha256="e" * 64)
    changed_supervisor = _alpaca_paper_authenticated_position_view_supervisor_result(
        stage=supervisor.stage,
        prior_earlier_state=supervisor.prior_earlier_state,
        prior_later_state=supervisor.prior_later_state,
        earlier_state=_state(earlier.plan, receipt=changed),
        later_state=supervisor.later_state,
        fence=supervisor.fence,
        checked_at=supervisor.checked_at,
        eligible_at=supervisor.eligible_at,
        value=changed,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="escaped its consumed pair-claim lease",
    ):
        _pair_admitted_position_view_runtime_result(
            transition=transition,
            supervisor_result=changed_supervisor,
            earlier_claim=first.earlier_claim,
            earlier_consumption=first.earlier_consumption,
            later_claim=first.later_claim,
            later_consumption=first.later_consumption,
        )


def test_standalone_result_rejects_later_claim_with_another_earlier_receipt() -> None:
    transition, runtime, transitions, coordinator, capture, comparison = _fixture("result-prior")
    earlier = runtime.expected[transition.earlier_plan.plan_id]
    eligible_at = earlier.persisted_snapshot.observation.received_at + timedelta(seconds=2)
    first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=eligible_at,
    )
    compared = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        capture,
        comparison,
        checked_at=BASE,
    )
    assert compared.later_claim is not None
    assert compared.later_consumption is not None
    forged_later_claim = _alpaca_paper_position_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.LATER,
        prior_earlier_receipt=_receipt_under_lease(earlier, lease_sha256="e" * 64),
        commit_fence_receipt=compared.later_claim.commit_fence_receipt,
    )
    forged_later_consumption = _alpaca_paper_position_view_transition_consumption(
        claim=forged_later_claim,
        preparation=compared.later_consumption.preparation,
        commit_fence_receipt=compared.later_consumption.commit_fence_receipt,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedPositionViewRuntimeConflict,
        match="another role, pair, or source",
    ):
        _pair_admitted_position_view_runtime_result(
            transition=transition,
            supervisor_result=compared.supervisor_result,
            earlier_claim=first.earlier_claim,
            earlier_consumption=first.earlier_consumption,
            later_claim=forged_later_claim,
            later_consumption=forged_later_consumption,
        )


def test_result_is_proof_constructed() -> None:
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperPairAdmittedPositionViewRuntimeResult()
