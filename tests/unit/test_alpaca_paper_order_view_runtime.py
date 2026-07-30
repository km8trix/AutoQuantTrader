from __future__ import annotations

from datetime import datetime, timedelta

import pytest

import tests.unit.test_alpaca_paper_order_snapshot_comparison_application as comparison_fixtures
import tests.unit.test_alpaca_paper_order_snapshot_runtime as runtime_fixtures
import tests.unit.test_alpaca_paper_order_view_supervisor as supervisor_fixtures
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotPagePreparationReceipt,
    _alpaca_paper_authenticated_order_snapshot_prefix,
    _alpaca_paper_order_snapshot_page_preparation_receipt,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
)
from packages.application.alpaca_paper_order_view_runtime import (
    ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_CONTRACT_VERSION,
    ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_SHA256,
    AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
    AlpacaPaperPairAdmittedOrderViewRuntimeResult,
    _pair_admitted_order_view_runtime_result,
    supervise_pair_admitted_alpaca_paper_order_views_once,
)
from packages.application.alpaca_paper_order_view_supervisor import (
    AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    AlpacaPaperAuthenticatedOrderViewSupervisorStalled,
    AlpacaPaperOrderSnapshotSupervisorSourceStage,
    AlpacaPaperOrderViewSupervisorStage,
    _alpaca_paper_authenticated_order_snapshot_supervisor_state,
)
from packages.application.alpaca_paper_order_view_transition import (
    AlpacaPaperOrderViewTransitionClaim,
    AlpacaPaperOrderViewTransitionConsumption,
    AlpacaPaperOrderViewTransitionPlan,
    AlpacaPaperOrderViewTransitionRole,
    _alpaca_paper_order_view_transition_claim,
    _alpaca_paper_order_view_transition_consumption,
    create_alpaca_paper_order_view_transition_plan,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from tests.unit.test_alpaca_paper_order_snapshot_runtime import BASE
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order
from tests.unit.test_alpaca_paper_order_view_supervisor import (
    _Clock,
    _ComparisonRepository,
    _fence,
    _prefix_at,
    _separated_terminal_pair,
    _source_state,
)

_STALLED_HEAD = "f" * 64


class _SnapshotRuntime:
    def __init__(
        self,
        earlier: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
        later: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
        *,
        runtime_store_identity: int = 1,
    ) -> None:
        self.runtime_store_identity = runtime_store_identity
        self.terminals = {
            earlier.plan.snapshot_id: earlier,
            later.plan.snapshot_id: later,
        }
        self.head_starts = {
            earlier.plan.snapshot_id: 1,
            later.plan.snapshot_id: 8,
        }
        self.states = {
            terminal.plan.snapshot_id: _source_state(
                _prefix_at(terminal, 0),
                source_head_sha256=None,
            )
            for terminal in (earlier, later)
        }
        self.state_calls: list[AlpacaPaperOrderSnapshotPlan] = []
        self.prefix_calls: list[AlpacaPaperOrderSnapshotPlan] = []
        self.record_calls: list[AlpacaPaperAuthenticatedOrderSnapshotPageEvidence] = []
        self.unscoped_prepare_calls: list[AlpacaPaperOrderSnapshotPageDescription] = []

    def source_head(
        self,
        prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    ) -> str:
        assert prefix.page_count > 0
        digit = self.head_starts[prefix.plan.snapshot_id] + prefix.page_count - 1
        return f"{digit:x}" * 64

    def expected_receipt(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        terminal = self.terminals[description.plan.snapshot_id]
        return terminal.page_receipts[description.page_number - 1]

    def load_state(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
        self.state_calls.append(plan)
        return self.states[plan.snapshot_id]

    def prepare_next(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperOrderSnapshotPagePreparationReceipt:
        del checked_at
        self.unscoped_prepare_calls.append(description)
        raise AssertionError("Phase 4AB must not call unscoped Phase 4O preparation")

    def mark_prepared(
        self,
        preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
    ) -> None:
        plan = preparation.description.plan
        prior = self.states[plan.snapshot_id]
        self.states[plan.snapshot_id] = _alpaca_paper_authenticated_order_snapshot_supervisor_state(
            stage=AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED,
            prefix=prior.prefix,
            preparation=preparation,
            source_head_sha256=_STALLED_HEAD,
        )

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        self.record_calls.append(evidence)
        expected = self.expected_receipt(evidence.description)
        assert evidence == expected.evidence
        prior = self.states[evidence.description.plan.snapshot_id].prefix
        assert prior.next_page_description == evidence.description
        prefix = _alpaca_paper_authenticated_order_snapshot_prefix(
            evidence.description.plan,
            page_receipts=(*prior.page_receipts, expected),
        )
        self.states[evidence.description.plan.snapshot_id] = _source_state(
            prefix,
            source_head_sha256=self.source_head(prefix),
        )
        return expected

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        self.prefix_calls.append(plan)
        return self.states[plan.snapshot_id].prefix


class _TransitionRepository:
    def __init__(
        self,
        runtime: _SnapshotRuntime,
        *,
        runtime_store_identity: int = 1,
    ) -> None:
        self.runtime_store_identity = runtime_store_identity
        self.runtime = runtime
        self.claims: dict[str, AlpacaPaperOrderViewTransitionClaim] = {}
        self.consumptions: dict[str, AlpacaPaperOrderViewTransitionConsumption] = {}
        self.claim_calls: list[
            tuple[
                AlpacaPaperOrderViewTransitionRole,
                AlpacaPaperAuthenticatedOrderSnapshotPrefix,
                str | None,
            ]
        ] = []
        self.prepare_calls: list[str] = []
        self.hide_consumptions = False

    def _prior_claim(
        self,
        transition: AlpacaPaperOrderViewTransitionPlan,
        role: AlpacaPaperOrderViewTransitionRole,
        prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    ) -> AlpacaPaperOrderViewTransitionClaim | None:
        if not prefix.page_receipts:
            return None
        candidates = [
            claim
            for claim in self.claims.values()
            if claim.plan == transition
            and claim.selected_role is role
            and claim.selected_prefix.page_receipts == prefix.page_receipts[:-1]
        ]
        assert len(candidates) == 1
        return candidates[0]

    def claim(
        self,
        transition: AlpacaPaperOrderViewTransitionPlan,
        *,
        selected_role: AlpacaPaperOrderViewTransitionRole,
        selected_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
        selected_source_head_sha256: str | None,
        fence: AccountFence,
    ) -> AlpacaPaperOrderViewTransitionClaim:
        self.claim_calls.append((selected_role, selected_prefix, selected_source_head_sha256))
        selected_state = self.runtime.states[transition.selected_plan(selected_role).snapshot_id]
        if (
            selected_state.prefix != selected_prefix
            or selected_state.source_head_sha256 != selected_source_head_sha256
        ):
            raise RuntimeError("selected source changed before admission")
        expected = self.runtime.expected_receipt(selected_prefix.next_page_description)
        earlier_state = self.runtime.states[transition.earlier_plan.snapshot_id]
        page_authority = expected.evidence.pre_fence_receipt
        claim = _alpaca_paper_order_view_transition_claim(
            plan=transition,
            selected_role=selected_role,
            selected_prefix=selected_prefix,
            previous_claim=self._prior_claim(
                transition,
                selected_role,
                selected_prefix,
            ),
            prior_earlier_prefix=(
                None
                if selected_role is AlpacaPaperOrderViewTransitionRole.EARLIER
                else earlier_state.prefix
            ),
            prior_earlier_source_head_sha256=(
                None
                if selected_role is AlpacaPaperOrderViewTransitionRole.EARLIER
                else earlier_state.source_head_sha256
            ),
            commit_fence_receipt=_account_fence_receipt(
                fence=fence,
                validated_at=expected.evidence.preparation.prepared_at,
                valid_until=page_authority.valid_until,
                policy_sha256=page_authority.policy_sha256,
                lease_sha256=page_authority.lease_sha256,
            ),
        )
        assert claim.commit_fence_receipt.fence == fence
        stored = self.claims.setdefault(claim.claim_id, claim)
        assert stored == claim
        return stored

    def prepare_claimed(
        self,
        claim: AlpacaPaperOrderViewTransitionClaim,
        *,
        checked_at: datetime,
        fence: AccountFence,
    ) -> AlpacaPaperOrderViewTransitionConsumption:
        self.prepare_calls.append(claim.claim_id)
        if any(value.claim == claim for value in self.consumptions.values()):
            raise RuntimeError("page claim was already consumed")
        assert fence == claim.commit_fence_receipt.fence
        previous = (
            None
            if not claim.selected_prefix.page_receipts
            else claim.selected_prefix.page_receipts[-1]
        )
        preparation = _alpaca_paper_order_snapshot_page_preparation_receipt(
            claim.description,
            prefix_capture_sha256=claim.selected_prefix.capture.semantic_sha256,
            prefix_page_count=claim.selected_prefix.page_count,
            previous_page_receipt_id=(None if previous is None else previous.receipt_id),
            previous_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
            prepared_at=checked_at,
        )
        consumption = _alpaca_paper_order_view_transition_consumption(
            claim=claim,
            preparation=preparation,
            commit_fence_receipt=_account_fence_receipt(
                fence=fence,
                validated_at=checked_at,
                valid_until=claim.commit_fence_receipt.valid_until,
                policy_sha256=claim.commit_fence_receipt.policy_sha256,
                lease_sha256=claim.commit_fence_receipt.lease_sha256,
            ),
        )
        self.consumptions[consumption.consumption_id] = consumption
        self.runtime.mark_prepared(preparation)
        return consumption

    def load_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperOrderViewTransitionClaim | None:
        return self.claims.get(claim_id)

    def load_consumption(
        self,
        consumption_id: str,
    ) -> AlpacaPaperOrderViewTransitionConsumption | None:
        if self.hide_consumptions:
            return None
        return self.consumptions.get(consumption_id)

    def load_consumption_for_claim(
        self,
        claim_id: str,
    ) -> AlpacaPaperOrderViewTransitionConsumption | None:
        if self.hide_consumptions:
            return None
        values = [value for value in self.consumptions.values() if value.claim.claim_id == claim_id]
        assert len(values) <= 1
        return None if not values else values[0]


class _Coordinator:
    def __init__(
        self,
        *,
        runtime_store_identity: int = 1,
        changed_lease_call: int | None = None,
    ) -> None:
        self.account_id = _fence().account_id
        self.runtime_store_identity = runtime_store_identity
        self.changed_lease_call = changed_lease_call
        self.calls = 0
        self._receipts: tuple[AccountFenceReceipt, AccountFenceReceipt] | None = None
        self._page_call = 0

    def begin(
        self,
        receipt: AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    ) -> None:
        self._receipts = (
            receipt.evidence.pre_fence_receipt,
            receipt.evidence.post_fence_receipt,
        )
        self._page_call = 0

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        assert self._receipts is not None
        receipt = self._receipts[self._page_call]
        self._page_call += 1
        self.calls += 1
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


class _PageWorkflow:
    def __init__(
        self,
        runtime: _SnapshotRuntime,
        coordinator: _Coordinator,
        *,
        runtime_store_identity: int = 1,
        crash_after_prepare: bool = False,
    ) -> None:
        self.runtime_store_identity = runtime_store_identity
        self.runtime = runtime
        self.coordinator = coordinator
        self.crash_after_prepare = crash_after_prepare
        self.calls: list[AlpacaPaperOrderSnapshotPageDescription] = []
        self.events: list[str] = []

    def advance_one_page(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        fence: AccountFence,
        page_runtime: object,
        coordinator: object,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        self.calls.append(description)
        expected = self.runtime.expected_receipt(description)
        preparation = page_runtime.prepare_next(  # type: ignore[attr-defined]
            description,
            checked_at=expected.evidence.preparation.prepared_at,
        )
        assert preparation == expected.evidence.preparation
        self.events.append("prepared")
        prefix = page_runtime.load_prefix(description.plan)  # type: ignore[attr-defined]
        assert prefix.next_page_description == description
        assert prefix.page_count == description.page_number - 1
        if self.crash_after_prepare:
            raise RuntimeError("simulated crash after atomic claim consumption")
        self.coordinator.begin(expected)
        pre = coordinator.revalidate(fence)  # type: ignore[attr-defined]
        assert pre == expected.evidence.pre_fence_receipt
        self.events.append("transport")
        post = coordinator.revalidate(fence)  # type: ignore[attr-defined]
        assert post == expected.evidence.post_fence_receipt
        recorded = page_runtime.record(expected.evidence)  # type: ignore[attr-defined]
        assert recorded == expected
        return recorded


def _fixture(
    suffix: str,
    *,
    coordinator_store_identity: int = 1,
    changed_lease_call: int | None = None,
    crash_after_prepare: bool = False,
) -> tuple[
    AlpacaPaperOrderViewTransitionPlan,
    _SnapshotRuntime,
    _TransitionRepository,
    _Coordinator,
    _PageWorkflow,
    _ComparisonRepository,
]:
    earlier, later = _separated_terminal_pair()
    transition = create_alpaca_paper_order_view_transition_plan(
        earlier_plan=earlier.plan,
        later_plan=later.plan,
    )
    runtime = _SnapshotRuntime(earlier, later)
    transitions = _TransitionRepository(runtime)
    coordinator = _Coordinator(
        runtime_store_identity=coordinator_store_identity,
        changed_lease_call=changed_lease_call,
    )
    workflow = _PageWorkflow(
        runtime,
        coordinator,
        crash_after_prepare=crash_after_prepare,
    )
    comparison = _ComparisonRepository(runtime)
    assert suffix
    return transition, runtime, transitions, coordinator, workflow, comparison


class _ProgressiveFixtureCoordinator(runtime_fixtures.Coordinator):
    _lease_digests: tuple[str, ...] = ()
    _next_lease = 0

    @classmethod
    def reset(cls, lease_digests: tuple[str, ...]) -> None:
        cls._lease_digests = lease_digests
        cls._next_lease = 0

    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self._lease_sha256 = self._lease_digests[self._next_lease]
        type(self)._next_lease += 1

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        receipt = super().revalidate(fence)
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256=self._lease_sha256,
        )


def _monotonic_terminal_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
]:
    original_clock = comparison_fixtures._clock
    original_base = runtime_fixtures.BASE
    shifts = iter(
        (
            timedelta(),
            timedelta(seconds=1),
            timedelta(seconds=4),
            timedelta(seconds=5),
        )
    )
    _ProgressiveFixtureCoordinator.reset(
        tuple(character * 64 for character in ("a", "b", "c", "d"))
    )

    def shifted_clock() -> object:
        monkeypatch.setattr(runtime_fixtures, "BASE", original_base + next(shifts))
        return original_clock()

    monkeypatch.setattr(comparison_fixtures, "_clock", shifted_clock)
    monkeypatch.setattr(
        comparison_fixtures,
        "Coordinator",
        _ProgressiveFixtureCoordinator,
    )
    earlier, ingress, account_source = comparison_fixtures._authenticated_prefix(
        capture_key="phase4ab-monotonic-earlier",
        bodies=(
            _body(_order(2), _order(1)),
            _body(),
        ),
    )
    later, _, _ = comparison_fixtures._authenticated_prefix(
        capture_key="phase4ab-monotonic-later",
        bodies=(
            _body(_order(4), _order(3)),
            _body(),
        ),
        ingress=ingress,
        account_source=account_source,
    )
    monkeypatch.setattr(runtime_fixtures, "BASE", original_base)
    return earlier, later


def _run(
    transition: AlpacaPaperOrderViewTransitionPlan,
    runtime: _SnapshotRuntime,
    transitions: _TransitionRepository,
    coordinator: _Coordinator,
    workflow: _PageWorkflow,
    comparison: _ComparisonRepository,
    *,
    checked_at: datetime,
) -> AlpacaPaperPairAdmittedOrderViewRuntimeResult:
    return supervise_pair_admitted_alpaca_paper_order_views_once(
        transition,
        fence=_fence(),
        clock=_Clock(checked_at),
        transition_repository=transitions,
        snapshot_runtime=runtime,
        page_workflow=workflow,  # type: ignore[arg-type]
        coordinator=coordinator,  # type: ignore[arg-type]
        comparison_repository=comparison,
    )


def _set_complete(
    runtime: _SnapshotRuntime,
    terminal: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
) -> None:
    runtime.states[terminal.plan.snapshot_id] = _source_state(
        terminal,
        source_head_sha256=runtime.source_head(terminal),
    )


def _assert_non_authorizing(value: object) -> None:
    for name in (
        "authenticated_provider_evidence",
        "request_budget_enforced",
        "raw_response_persisted",
        "runtime_current",
        "capture_authenticated",
        "durable_source_positions_authenticated",
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


def test_pair_admitted_round_advances_waits_advances_then_compares() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture("round")
    earlier = runtime.terminals[transition.earlier_plan.snapshot_id]
    eligible_at = earlier.page_receipts[-1].persisted_page.observation.received_at + timedelta(
        seconds=2
    )

    first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE,
    )
    assert first.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED
    assert first.value == earlier.page_receipts[-1]
    assert len(first.earlier_claims) == len(first.earlier_consumptions) == 1
    assert first.selected_pair == (
        first.earlier_claims[-1],
        first.earlier_consumptions[-1],
    )
    assert first.later_claims == first.later_consumptions == ()

    claim_count = len(transitions.claims)
    waiting = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at - timedelta(microseconds=1),
    )
    assert waiting.stage is AlpacaPaperOrderViewSupervisorStage.WAITING_MINIMUM_SEPARATION
    assert waiting.selected_pair is None
    assert len(transitions.claims) == claim_count
    assert len(workflow.calls) == 1

    later = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    assert later.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED
    assert len(later.earlier_claims) == len(later.later_claims) == 1
    assert later.selected_pair == (
        later.later_claims[-1],
        later.later_consumptions[-1],
    )

    claim_count = len(transitions.claims)
    compared = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    assert ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_CONTRACT_VERSION.startswith("phase4ab-")
    assert ALPACA_PAPER_PAIR_ADMITTED_ORDER_VIEW_RUNTIME_POLICY_SHA256 == (
        "d41feadbcd50d762190c2ae4ded32e2066f25517ea83fc85a5ba7401de34c221"
    )
    assert compared.stage is AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED
    assert compared.earlier_claims == first.earlier_claims
    assert compared.later_claims == later.later_claims
    assert compared.selected_pair is None
    assert len(transitions.claims) == claim_count
    assert len(workflow.calls) == 2
    assert coordinator.calls == 4
    assert len(comparison.record_calls) == 1
    _assert_non_authorizing(compared)


def test_multi_page_source_returns_gap_free_claim_and_consumption_chains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    earlier, later = _monotonic_terminal_pair(monkeypatch)
    transition = create_alpaca_paper_order_view_transition_plan(
        earlier_plan=earlier.plan,
        later_plan=later.plan,
    )
    runtime = _SnapshotRuntime(earlier, later)
    transitions = _TransitionRepository(runtime)
    coordinator = _Coordinator()
    workflow = _PageWorkflow(runtime, coordinator)
    comparison = _ComparisonRepository(runtime)

    first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE,
    )
    second = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE + timedelta(seconds=1),
    )
    eligible_at = earlier.page_receipts[-1].persisted_page.observation.received_at + timedelta(
        seconds=2
    )
    waiting = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at - timedelta(microseconds=1),
    )
    later_first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    later_second = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE + timedelta(seconds=5),
    )
    monkeypatch.setattr(supervisor_fixtures, "BASE", BASE + timedelta(seconds=1))
    compared = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE + timedelta(seconds=5),
    )

    assert first.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED
    assert second.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED
    assert waiting.stage is AlpacaPaperOrderViewSupervisorStage.WAITING_MINIMUM_SEPARATION
    assert later_first.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED
    assert later_second.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED
    assert compared.stage is AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED
    assert len(second.earlier_claims) == len(second.earlier_consumptions) == 2
    assert second.earlier_claims[1].previous_claim == second.earlier_claims[0]
    assert (
        second.earlier_consumptions[0].claim,
        second.earlier_consumptions[1].claim,
    ) == second.earlier_claims
    assert tuple(consumption.preparation for consumption in second.earlier_consumptions) == tuple(
        receipt.evidence.preparation for receipt in earlier.page_receipts
    )
    assert len(later_second.later_claims) == len(later_second.later_consumptions) == 2
    assert later_second.later_claims[1].previous_claim == later_second.later_claims[0]
    assert (
        later_second.later_consumptions[0].claim,
        later_second.later_consumptions[1].claim,
    ) == later_second.later_claims
    assert tuple(
        consumption.preparation for consumption in later_second.later_consumptions
    ) == tuple(receipt.evidence.preparation for receipt in later.page_receipts)
    assert tuple(
        consumption.commit_fence_receipt.lease_sha256
        for consumption in (
            *compared.earlier_consumptions,
            *compared.later_consumptions,
        )
    ) == tuple(character * 64 for character in ("a", "b", "c", "d"))


def test_nonadmitted_existing_source_fails_before_claim_clock_or_effect() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture("direct")
    _set_complete(
        runtime,
        runtime.terminals[transition.earlier_plan.snapshot_id],
    )
    clock = _Clock(BASE)

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="lacks its exact pair claim",
    ):
        supervise_pair_admitted_alpaca_paper_order_views_once(
            transition,
            fence=_fence(),
            clock=clock,
            transition_repository=transitions,
            snapshot_runtime=runtime,
            page_workflow=workflow,  # type: ignore[arg-type]
            coordinator=coordinator,  # type: ignore[arg-type]
            comparison_repository=comparison,
        )

    assert transitions.claim_calls == []
    assert workflow.calls == []
    assert coordinator.calls == 0
    assert comparison.record_calls == []
    assert clock.calls == 0


def test_committed_source_with_missing_consumption_fails_before_effects() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture(
        "missing-consumption"
    )
    selected = runtime.states[transition.earlier_plan.snapshot_id]
    transitions.claim(
        transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
        selected_prefix=selected.prefix,
        selected_source_head_sha256=selected.source_head_sha256,
        fence=_fence(),
    )
    _set_complete(
        runtime,
        runtime.terminals[transition.earlier_plan.snapshot_id],
    )
    transitions.claim_calls.clear()

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="consumption loader returned a non-canonical",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            workflow,
            comparison,
            checked_at=BASE,
        )

    assert transitions.claim_calls == []
    assert workflow.calls == []
    assert coordinator.calls == 0


def test_claim_only_same_lease_restart_consumes_and_advances() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture("claim-restart")
    selected = runtime.states[transition.earlier_plan.snapshot_id]
    historical = transitions.claim(
        transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
        selected_prefix=selected.prefix,
        selected_source_head_sha256=selected.source_head_sha256,
        fence=_fence(),
    )
    transitions.claim_calls.clear()

    result = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE,
    )

    assert result.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED
    assert result.selected_claim == historical
    assert result.selected_consumption is not None
    assert len(transitions.claims) == len(transitions.consumptions) == 1
    assert workflow.events == ["prepared", "transport"]


def test_substituted_later_earlier_source_fails_before_io_and_in_result() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture(
        "later-source-substitution"
    )
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE,
    )
    earlier_state = runtime.states[transition.earlier_plan.snapshot_id]
    later_state = runtime.states[transition.later_plan.snapshot_id]
    expected = runtime.expected_receipt(later_state.prefix.next_page_description)
    authority = expected.evidence.pre_fence_receipt
    forged_current = _alpaca_paper_order_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.LATER,
        selected_prefix=later_state.prefix,
        previous_claim=None,
        prior_earlier_prefix=earlier_state.prefix,
        prior_earlier_source_head_sha256="e" * 64,
        commit_fence_receipt=_account_fence_receipt(
            fence=_fence(),
            validated_at=expected.evidence.preparation.prepared_at,
            valid_until=authority.valid_until,
            policy_sha256=authority.policy_sha256,
            lease_sha256=authority.lease_sha256,
        ),
    )
    transitions.claims[forged_current.claim_id] = forged_current
    eligible_at = earlier_state.prefix.page_receipts[
        -1
    ].persisted_page.observation.received_at + timedelta(seconds=2)
    workflow_call_count = len(workflow.calls)
    record_count = len(runtime.record_calls)

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="does not bind the exact authenticated terminal earlier source",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            workflow,
            comparison,
            checked_at=eligible_at,
        )

    assert len(workflow.calls) == workflow_call_count
    assert len(runtime.record_calls) == record_count
    assert len(transitions.consumptions) == 1

    del transitions.claims[forged_current.claim_id]
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    compared = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    genuine_claim = compared.later_claims[0]
    genuine_consumption = compared.later_consumptions[0]
    forged_completed = _alpaca_paper_order_view_transition_claim(
        plan=transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.LATER,
        selected_prefix=genuine_claim.selected_prefix,
        previous_claim=genuine_claim.previous_claim,
        prior_earlier_prefix=genuine_claim.prior_earlier_prefix,
        prior_earlier_source_head_sha256="e" * 64,
        commit_fence_receipt=genuine_claim.commit_fence_receipt,
    )
    forged_consumption = _alpaca_paper_order_view_transition_consumption(
        claim=forged_completed,
        preparation=genuine_consumption.preparation,
        commit_fence_receipt=genuine_consumption.commit_fence_receipt,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="does not bind the exact authenticated terminal earlier source",
    ):
        _pair_admitted_order_view_runtime_result(
            transition=transition,
            supervisor_result=compared.supervisor_result,
            earlier_claims=compared.earlier_claims,
            earlier_consumptions=compared.earlier_consumptions,
            later_claims=(forged_completed,),
            later_consumptions=(forged_consumption,),
            selected_claim=None,
            selected_consumption=None,
        )


def test_crash_after_consumption_is_stalled_and_never_resends() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture(
        "crash",
        crash_after_prepare=True,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="claim-bound Phase 4O page workflow failed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            workflow,
            comparison,
            checked_at=BASE,
        )
    assert workflow.events == ["prepared"]
    assert len(workflow.calls) == 1
    assert len(transitions.consumptions) == 1

    workflow.crash_after_prepare = False
    with pytest.raises(AlpacaPaperAuthenticatedOrderViewSupervisorStalled):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            workflow,
            comparison,
            checked_at=BASE + timedelta(seconds=10),
        )
    assert len(workflow.calls) == 1
    assert runtime.record_calls == []
    assert coordinator.calls == 0


def test_changed_lease_before_transport_leaves_stalled_without_provider_read() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture(
        "pretransport-lease",
        changed_lease_call=1,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="account lease changed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            workflow,
            comparison,
            checked_at=BASE,
        )

    assert workflow.events == ["prepared"]
    assert runtime.record_calls == []
    assert coordinator.calls == 1
    assert runtime.states[transition.earlier_plan.snapshot_id].stage is (
        AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
    )


def test_changed_lease_after_transport_blocks_page_commit() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture(
        "posttransport-lease",
        changed_lease_call=2,
    )

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="account lease changed",
    ):
        _run(
            transition,
            runtime,
            transitions,
            coordinator,
            workflow,
            comparison,
            checked_at=BASE,
        )

    assert workflow.events == ["prepared", "transport"]
    assert runtime.record_calls == []
    assert coordinator.calls == 2


def test_store_mismatch_fails_before_source_or_clock_access() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture(
        "store-mismatch",
        coordinator_store_identity=2,
    )
    clock = _Clock(BASE)

    with pytest.raises(
        AlpacaPaperPairAdmittedOrderViewRuntimeConflict,
        match="do not share one durable store",
    ):
        supervise_pair_admitted_alpaca_paper_order_views_once(
            transition,
            fence=_fence(),
            clock=clock,
            transition_repository=transitions,
            snapshot_runtime=runtime,
            page_workflow=workflow,  # type: ignore[arg-type]
            coordinator=coordinator,  # type: ignore[arg-type]
            comparison_repository=comparison,
        )

    assert runtime.state_calls == []
    assert transitions.claim_calls == []
    assert workflow.calls == []
    assert clock.calls == 0


def test_proof_only_result_is_deterministic_and_non_authorizing() -> None:
    transition, runtime, transitions, coordinator, workflow, comparison = _fixture("proof")
    earlier = runtime.terminals[transition.earlier_plan.snapshot_id]
    eligible_at = earlier.page_receipts[-1].persisted_page.observation.received_at + timedelta(
        seconds=2
    )
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=BASE,
    )
    _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    first = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )
    second = _run(
        transition,
        runtime,
        transitions,
        coordinator,
        workflow,
        comparison,
        checked_at=eligible_at,
    )

    assert first.result_id == second.result_id
    assert first.semantic_sha256 == second.semantic_sha256
    assert first.canonical_json == second.canonical_json
    _assert_non_authorizing(first)
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperPairAdmittedOrderViewRuntimeResult()
