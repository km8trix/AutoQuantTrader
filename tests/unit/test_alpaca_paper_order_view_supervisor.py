from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta

import pytest

import tests.unit.test_alpaca_paper_order_snapshot_runtime as runtime_fixtures
from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION,
    AlpacaPaperOrderSnapshotComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotConflict,
    _alpaca_paper_authenticated_order_snapshot_prefix,
    _alpaca_paper_order_snapshot_page_preparation_receipt,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
    create_alpaca_paper_order_snapshot_plan,
)
from packages.application.alpaca_paper_order_snapshot_comparison import (
    AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
    AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
    _alpaca_paper_authenticated_order_view_comparison_receipt,
)
from packages.application.alpaca_paper_order_view_supervisor import (
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID,
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
    ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION,
    AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
    AlpacaPaperAuthenticatedOrderViewSupervisorResult,
    AlpacaPaperAuthenticatedOrderViewSupervisorStalled,
    AlpacaPaperOrderSnapshotSupervisorSourceStage,
    AlpacaPaperOrderViewSupervisorStage,
    _alpaca_paper_authenticated_order_snapshot_supervisor_state,
    alpaca_paper_order_view_supervisor_round_id,
    supervise_authenticated_alpaca_paper_order_views_once,
)
from packages.domain.account_coordinator import AccountFence
from tests.unit.test_alpaca_paper_order_snapshot_comparison_application import (
    _authenticated_prefix,
    _terminal_pair,
)
from tests.unit.test_alpaca_paper_order_snapshot_runtime import BASE, VALID_UNTIL
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order
from tests.unit.test_submission_attempt import fence_receipt

HEAD_1 = "1" * 64
HEAD_2 = "2" * 64
HEAD_3 = "3" * 64
HEAD_4 = "4" * 64


def _prefix_at(
    terminal: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    page_count: int,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    return _alpaca_paper_authenticated_order_snapshot_prefix(
        terminal.plan,
        page_receipts=terminal.page_receipts[:page_count],
    )


def _source_state(
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    *,
    source_head_sha256: str | None,
) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
    capture = prefix.capture
    if not prefix.page_receipts:
        stage = AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT
    elif capture.pagination_exhausted:
        stage = AlpacaPaperOrderSnapshotSupervisorSourceStage.CURSOR_EXHAUSTED
    elif capture.bounded_truncation:
        stage = AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED
    else:
        stage = AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE
    return _alpaca_paper_authenticated_order_snapshot_supervisor_state(
        stage=stage,
        prefix=prefix,
        preparation=None,
        source_head_sha256=source_head_sha256,
    )


def _stalled_state(
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    *,
    source_head_sha256: str,
) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
    description = prefix.next_page_description
    assert description is not None
    previous = None if not prefix.page_receipts else prefix.page_receipts[-1]
    preparation = _alpaca_paper_order_snapshot_page_preparation_receipt(
        description,
        prefix_capture_sha256=prefix.capture.semantic_sha256,
        prefix_page_count=prefix.page_count,
        previous_page_receipt_id=(None if previous is None else previous.receipt_id),
        previous_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
        prepared_at=BASE + timedelta(milliseconds=200),
    )
    return _alpaca_paper_authenticated_order_snapshot_supervisor_state(
        stage=AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED,
        prefix=prefix,
        preparation=preparation,
        source_head_sha256=source_head_sha256,
    )


def _two_page_earlier_pair() -> tuple[
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
]:
    return _separated_terminal_pair(
        earlier_bodies=(
            _body(_order(2), _order(1)),
            _body(),
        ),
        later_bodies=(_body(),),
    )


def _separated_terminal_pair(
    *,
    earlier_bodies: tuple[bytes, ...] = (_body(),),
    later_bodies: tuple[bytes, ...] = (_body(),),
    later_preparation_offset: timedelta | None = None,
) -> tuple[
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
]:
    earlier, ingress, account_source = _authenticated_prefix(
        capture_key="phase4q-separated-earlier",
        bodies=earlier_bodies,
    )
    original_base = runtime_fixtures.BASE
    later_shift = timedelta(seconds=3)
    if later_preparation_offset is not None:
        eligible_at = (
            earlier.capture.pages[-1].observation.received_at
            + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
        )
        later_shift = eligible_at - original_base + later_preparation_offset
    try:
        runtime_fixtures.BASE = original_base + later_shift
        later, _, _ = _authenticated_prefix(
            capture_key="phase4q-separated-later",
            bodies=later_bodies,
            ingress=ingress,
            account_source=account_source,
        )
    finally:
        runtime_fixtures.BASE = original_base
    return earlier, later


class _StateLoader:
    def __init__(
        self,
        *states: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
        runtime_store_identity: int = 1,
    ) -> None:
        self.states = {state.prefix.plan.snapshot_id: state for state in states}
        self.state_calls: list[AlpacaPaperOrderSnapshotPlan] = []
        self.prefix_calls: list[AlpacaPaperOrderSnapshotPlan] = []
        self.runtime_store_identity = runtime_store_identity

    def load_state(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
        self.state_calls.append(plan)
        return self.states[plan.snapshot_id]

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        self.prefix_calls.append(plan)
        return self.states[plan.snapshot_id].prefix


class _PageWorkflow:
    def __init__(
        self,
        loader: _StateLoader,
        transitions: dict[
            tuple[str, int],
            AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
        ],
        *,
        runtime_store_identity: int = 1,
    ) -> None:
        self.loader = loader
        self.transitions = transitions
        self.runtime_store_identity = runtime_store_identity
        self.calls: list[tuple[AlpacaPaperOrderSnapshotPageDescription, AccountFence]] = []
        self.unselected_mutation: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState | None = None

    def advance_one_page(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        self.calls.append((description, fence))
        before = self.loader.states[description.plan.snapshot_id]
        assert before.prefix.next_page_description == description
        after = self.transitions[(description.plan.snapshot_id, len(before.prefix.page_receipts))]
        self.loader.states[description.plan.snapshot_id] = after
        if self.unselected_mutation is not None:
            mutation = self.unselected_mutation
            self.loader.states[mutation.prefix.plan.snapshot_id] = mutation
        return after.prefix.page_receipts[-1]


class _Clock:
    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.instant


class _ComparisonRepository:
    def __init__(
        self,
        loader: _StateLoader,
        *,
        commit_fence_generation: int = 1,
        runtime_store_identity: int = 1,
    ) -> None:
        self.loader = loader
        self.commit_fence_generation = commit_fence_generation
        self.runtime_store_identity = runtime_store_identity
        self.record_calls: list[
            tuple[AlpacaPaperAuthenticatedOrderViewComparisonEvidence, AccountFence]
        ] = []
        self.load_calls: list[str] = []
        self.receipt: AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None = None
        self.return_wrong_heads = False
        self.return_none_on_load = False

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        self.record_calls.append((evidence, fence))
        if self.receipt is not None:
            assert self.receipt.evidence == evidence
            return self.receipt
        earlier = self.loader.states[evidence.earlier_plan_id]
        later = self.loader.states[evidence.later_plan_id]
        assert earlier.source_head_sha256 is not None
        assert later.source_head_sha256 is not None
        self.receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256=(
                HEAD_4 if self.return_wrong_heads else earlier.source_head_sha256
            ),
            later_source_head_sha256=later.source_head_sha256,
            commit_fence_receipt=fence_receipt(
                account_id=evidence.account_id,
                validated_at=BASE + timedelta(seconds=5),
                valid_until=VALID_UNTIL,
                fencing_generation=self.commit_fence_generation,
            ),
            account_sequence=1,
            previous_receipt_sha256=None,
        )
        return self.receipt

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None:
        self.load_calls.append(receipt_id)
        if self.return_none_on_load:
            return None
        assert self.receipt is not None
        assert self.receipt.receipt_id == receipt_id
        return self.receipt


def _fence(*, generation: int = 1) -> AccountFence:
    return fence_receipt(
        validated_at=BASE - timedelta(seconds=1),
        valid_until=VALID_UNTIL,
        fencing_generation=generation,
    ).fence


def _assert_non_authorizing(value: object) -> None:
    for property_name in (
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
        assert getattr(value, property_name) is False


def test_one_step_supervisor_advances_earlier_waits_advances_later_then_compares() -> None:
    earlier_terminal, later_terminal = _two_page_earlier_pair()
    earlier_absent = _source_state(
        _prefix_at(earlier_terminal, 0),
        source_head_sha256=None,
    )
    earlier_active = _source_state(
        _prefix_at(earlier_terminal, 1),
        source_head_sha256=HEAD_1,
    )
    earlier_done = _source_state(
        earlier_terminal,
        source_head_sha256=HEAD_2,
    )
    later_absent = _source_state(
        _prefix_at(later_terminal, 0),
        source_head_sha256=None,
    )
    later_done = _source_state(
        later_terminal,
        source_head_sha256=HEAD_3,
    )
    loader = _StateLoader(earlier_absent, later_absent)
    page_workflow = _PageWorkflow(
        loader,
        {
            (earlier_terminal.plan.snapshot_id, 0): earlier_active,
            (earlier_terminal.plan.snapshot_id, 1): earlier_done,
            (later_terminal.plan.snapshot_id, 0): later_done,
        },
    )
    comparison_repository = _ComparisonRepository(loader)
    fence = _fence()
    eligible_at = (
        earlier_terminal.capture.pages[-1].observation.received_at
        + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
    )

    first = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=fence,
        clock=_Clock(BASE),
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=comparison_repository,
    )
    second = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=fence,
        clock=_Clock(BASE),
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=comparison_repository,
    )
    waiting_clock = _Clock(eligible_at - timedelta(microseconds=1))
    waiting = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=fence,
        clock=waiting_clock,
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=comparison_repository,
    )
    eligible_clock = _Clock(eligible_at)
    later = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=fence,
        clock=eligible_clock,
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=comparison_repository,
    )
    compared = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=fence,
        clock=_Clock(eligible_at),
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=comparison_repository,
    )

    assert first.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED
    assert first.prior_earlier_state == earlier_absent
    assert first.earlier_state == earlier_active
    assert second.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED
    assert second.prior_earlier_state == earlier_active
    assert second.earlier_state == earlier_done
    assert waiting.stage is AlpacaPaperOrderViewSupervisorStage.WAITING_MINIMUM_SEPARATION
    assert waiting.value is None
    assert waiting.checked_at == eligible_at - timedelta(microseconds=1)
    assert waiting.eligible_at == eligible_at
    assert waiting_clock.calls == 1
    assert later.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED
    assert later.prior_later_state == later_absent
    assert later.later_state == later_done
    assert eligible_clock.calls == 1
    assert compared.stage is AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED
    assert type(compared.value) is AlpacaPaperAuthenticatedOrderViewComparisonReceipt
    assert compared.value.evidence.comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.ORDER_VIEW_DIFFERENT
    )
    assert len(page_workflow.calls) == 3
    assert all(call_fence == fence for _, call_fence in page_workflow.calls)
    assert len(comparison_repository.record_calls) == 1
    assert len(comparison_repository.load_calls) == 1
    assert {result.round_id for result in (first, second, waiting, later, compared)} == {
        alpaca_paper_order_view_supervisor_round_id(
            earlier_terminal.plan,
            later_terminal.plan,
        )
    }
    assert first.semantic_sha256 == first.semantic_sha256
    assert compared.semantic_sha256 == compared.semantic_sha256
    _assert_non_authorizing(first)
    _assert_non_authorizing(waiting)
    _assert_non_authorizing(compared)
    for nested_value in (first.value, later.value, compared.value):
        assert nested_value is not None
        assert nested_value.lifecycle_application_authorized is False
        assert nested_value.readiness_transition_authorized is False
        assert nested_value.broker_call_authorized is False
        assert nested_value.trading_effect_authorized is False
        assert nested_value.converged is False


@pytest.mark.parametrize("stalled_source", ("earlier", "later"))
def test_any_stalled_source_fails_before_page_or_comparison(
    stalled_source: str,
) -> None:
    earlier_terminal, later_terminal = _terminal_pair()
    earlier_absent = _source_state(
        _prefix_at(earlier_terminal, 0),
        source_head_sha256=None,
    )
    later_absent = _source_state(
        _prefix_at(later_terminal, 0),
        source_head_sha256=None,
    )
    earlier = (
        _stalled_state(earlier_absent.prefix, source_head_sha256=HEAD_1)
        if stalled_source == "earlier"
        else earlier_absent
    )
    later = (
        _stalled_state(later_absent.prefix, source_head_sha256=HEAD_2)
        if stalled_source == "later"
        else later_absent
    )
    loader = _StateLoader(earlier, later)
    page_workflow = _PageWorkflow(loader, {})
    comparison_repository = _ComparisonRepository(loader)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorStalled,
        match="conservatively stalled",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=comparison_repository,
        )

    assert page_workflow.calls == []
    assert comparison_repository.record_calls == []


def test_absent_and_active_are_distinct_and_later_cannot_start_first() -> None:
    earlier_terminal, later_terminal = _terminal_pair(
        earlier_bodies=(_body(),),
        later_bodies=(
            _body(_order(2), _order(1)),
            _body(),
        ),
    )
    earlier_absent = _source_state(
        _prefix_at(earlier_terminal, 0),
        source_head_sha256=None,
    )
    later_active = _source_state(
        _prefix_at(later_terminal, 1),
        source_head_sha256=HEAD_1,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match=r"active.*durable prefix",
    ):
        _alpaca_paper_authenticated_order_snapshot_supervisor_state(
            stage=AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE,
            prefix=earlier_absent.prefix,
            preparation=None,
            source_head_sha256=HEAD_1,
        )

    loader = _StateLoader(earlier_absent, later_active)
    page_workflow = _PageWorkflow(loader, {})
    comparison_repository = _ComparisonRepository(loader)
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="later source advanced",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=comparison_repository,
        )
    assert page_workflow.calls == []


def test_page_result_rejects_double_advance_and_unselected_head_change() -> None:
    earlier_terminal, later_terminal = _two_page_earlier_pair()
    earlier_absent = _source_state(
        _prefix_at(earlier_terminal, 0),
        source_head_sha256=None,
    )
    later_absent = _source_state(
        _prefix_at(later_terminal, 0),
        source_head_sha256=None,
    )
    loader = _StateLoader(earlier_absent, later_absent)
    double_workflow = _PageWorkflow(
        loader,
        {
            (earlier_terminal.plan.snapshot_id, 0): _source_state(
                earlier_terminal,
                source_head_sha256=HEAD_2,
            )
        },
    )
    repository = _ComparisonRepository(loader)
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="one exact same-fence append",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=double_workflow,
            comparison_repository=repository,
        )

    loader.states[earlier_terminal.plan.snapshot_id] = earlier_absent
    earlier_active = _source_state(
        _prefix_at(earlier_terminal, 1),
        source_head_sha256=HEAD_1,
    )
    changing_workflow = _PageWorkflow(
        loader,
        {(earlier_terminal.plan.snapshot_id, 0): earlier_active},
    )
    changing_workflow.unselected_mutation = _stalled_state(
        later_absent.prefix,
        source_head_sha256=HEAD_4,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="unselected later source changed",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=changing_workflow,
            comparison_repository=repository,
        )


def test_page_receipt_must_bind_the_exact_supplied_fence() -> None:
    earlier_terminal, later_terminal = _terminal_pair()
    earlier_absent = _source_state(
        _prefix_at(earlier_terminal, 0),
        source_head_sha256=None,
    )
    earlier_done = _source_state(
        earlier_terminal,
        source_head_sha256=HEAD_1,
    )
    later_absent = _source_state(
        _prefix_at(later_terminal, 0),
        source_head_sha256=None,
    )
    loader = _StateLoader(earlier_absent, later_absent)
    page_workflow = _PageWorkflow(
        loader,
        {(earlier_terminal.plan.snapshot_id, 0): earlier_done},
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="same-fence append",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(generation=2),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=_ComparisonRepository(loader),
        )
    assert page_workflow.calls[0][1].fencing_generation == 2


def test_existing_later_ingress_inversion_fails_before_another_page() -> None:
    earlier_terminal, _, account_source = _authenticated_prefix(
        capture_key="phase4q-ingress-earlier",
        bodies=(_body(),),
    )
    later_terminal, _, _ = _authenticated_prefix(
        capture_key="phase4q-ingress-later",
        bodies=(
            _body(_order(2), _order(1)),
            _body(),
        ),
        account_source=account_source,
    )
    earlier_done = _source_state(
        earlier_terminal,
        source_head_sha256=HEAD_1,
    )
    later_active = _source_state(
        _prefix_at(later_terminal, 1),
        source_head_sha256=HEAD_2,
    )
    later_done = _source_state(
        later_terminal,
        source_head_sha256=HEAD_3,
    )
    loader = _StateLoader(earlier_done, later_active)
    page_workflow = _PageWorkflow(
        loader,
        {(later_terminal.plan.snapshot_id, 1): later_done},
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="strictly follow",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE + timedelta(seconds=10)),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=_ComparisonRepository(loader),
        )
    assert page_workflow.calls == []


@pytest.mark.parametrize("later_terminal_state", (False, True))
def test_preexisting_later_without_observed_separation_fails_before_io(
    later_terminal_state: bool,
) -> None:
    earlier_terminal, later_terminal = _terminal_pair(
        earlier_bodies=(_body(),),
        later_bodies=(
            _body(_order(2), _order(1)),
            _body(),
        ),
    )
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later_active = _source_state(
        _prefix_at(later_terminal, 1),
        source_head_sha256=HEAD_2,
    )
    later_done = _source_state(later_terminal, source_head_sha256=HEAD_3)
    later = later_done if later_terminal_state else later_active
    loader = _StateLoader(earlier, later)
    page_workflow = _PageWorkflow(
        loader,
        {(later_terminal.plan.snapshot_id, 1): later_done},
    )
    repository = _ComparisonRepository(loader)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="gate-separated start evidence",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE + timedelta(seconds=10)),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=repository,
        )

    assert page_workflow.calls == []
    assert repository.record_calls == []


def test_new_later_page_with_early_observation_is_retained_but_round_fails() -> None:
    earlier_terminal, later_terminal = _terminal_pair()
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later_absent = _source_state(
        _prefix_at(later_terminal, 0),
        source_head_sha256=None,
    )
    later_done = _source_state(later_terminal, source_head_sha256=HEAD_2)
    loader = _StateLoader(earlier, later_absent)
    page_workflow = _PageWorkflow(
        loader,
        {(later_terminal.plan.snapshot_id, 0): later_done},
    )
    repository = _ComparisonRepository(loader)
    eligible_at = (
        earlier_terminal.capture.pages[-1].observation.received_at
        + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="gate-separated start evidence",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(eligible_at),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=repository,
        )

    assert len(page_workflow.calls) == 1
    assert loader.states[later_terminal.plan.snapshot_id] == later_done
    assert repository.record_calls == []


@pytest.mark.parametrize(
    ("preparation_offset", "accepted"),
    (
        (timedelta(microseconds=-1), False),
        (timedelta(), True),
    ),
)
def test_authenticated_first_preparation_enforces_exact_gate_boundary(
    preparation_offset: timedelta,
    accepted: bool,
) -> None:
    earlier_terminal, later_terminal = _separated_terminal_pair(
        later_preparation_offset=preparation_offset,
    )
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later = _source_state(later_terminal, source_head_sha256=HEAD_2)
    loader = _StateLoader(earlier, later)
    page_workflow = _PageWorkflow(loader, {})
    repository = _ComparisonRepository(loader)
    eligible_at = (
        earlier_terminal.capture.pages[-1].observation.received_at
        + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
    )
    assert (
        later_terminal.page_receipts[0].evidence.preparation.prepared_at
        == eligible_at + preparation_offset
    )

    if not accepted:
        with pytest.raises(
            AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
            match="gate-separated start evidence",
        ):
            supervise_authenticated_alpaca_paper_order_views_once(
                earlier_terminal.plan,
                later_terminal.plan,
                fence=_fence(),
                clock=_Clock(eligible_at),
                state_loader=loader,
                page_workflow=page_workflow,
                comparison_repository=repository,
            )
        assert repository.record_calls == []
        return

    result = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=_fence(),
        clock=_Clock(eligible_at),
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=repository,
    )
    assert result.stage is AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED
    assert len(repository.record_calls) == 1


def test_phase4p_source_binding_and_reload_are_reauthenticated() -> None:
    earlier_terminal, later_terminal = _separated_terminal_pair()
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later = _source_state(later_terminal, source_head_sha256=HEAD_2)
    loader = _StateLoader(earlier, later)
    page_workflow = _PageWorkflow(loader, {})
    repository = _ComparisonRepository(loader)
    repository.return_wrong_heads = True

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="terminal source bindings",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=repository,
        )

    repository = _ComparisonRepository(loader)
    repository.return_none_on_load = True
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="non-canonical receipt",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier_terminal.plan,
            later_terminal.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=page_workflow,
            comparison_repository=repository,
        )


def test_bounded_truncation_compares_only_as_incomplete() -> None:
    full_pages = (
        _body(_order(6), _order(5)),
        _body(_order(4), _order(3)),
        _body(_order(2), _order(1)),
    )
    earlier_terminal, later_terminal = _separated_terminal_pair(
        earlier_bodies=full_pages,
        later_bodies=full_pages,
    )
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later = _source_state(later_terminal, source_head_sha256=HEAD_2)
    assert earlier.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED
    assert later.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED
    loader = _StateLoader(earlier, later)
    page_workflow = _PageWorkflow(loader, {})

    result = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=_fence(),
        clock=_Clock(BASE),
        state_loader=loader,
        page_workflow=page_workflow,
        comparison_repository=_ComparisonRepository(loader),
    )

    assert result.stage is AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED
    assert type(result.value) is AlpacaPaperAuthenticatedOrderViewComparisonReceipt
    assert result.value.evidence.comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert result.value.provider_snapshot_complete is False
    assert result.value.converged is False
    assert page_workflow.calls == []


def test_exact_comparison_retry_accepts_original_historical_fence() -> None:
    earlier_terminal, later_terminal = _separated_terminal_pair()
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later = _source_state(later_terminal, source_head_sha256=HEAD_2)
    loader = _StateLoader(earlier, later)
    repository = _ComparisonRepository(loader, commit_fence_generation=1)
    workflow = _PageWorkflow(loader, {})

    first = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=_fence(generation=1),
        clock=_Clock(BASE),
        state_loader=loader,
        page_workflow=workflow,
        comparison_repository=repository,
    )
    retry = supervise_authenticated_alpaca_paper_order_views_once(
        earlier_terminal.plan,
        later_terminal.plan,
        fence=_fence(generation=2),
        clock=_Clock(BASE),
        state_loader=loader,
        page_workflow=workflow,
        comparison_repository=repository,
    )

    assert retry.value == first.value
    assert type(retry.value) is AlpacaPaperAuthenticatedOrderViewComparisonReceipt
    assert retry.value.commit_fence_receipt.fence.fencing_generation == 1
    assert repository.record_calls[-1][1].fencing_generation == 2


def test_round_identity_is_ordered_and_result_objects_are_non_forgeable() -> None:
    earlier, later = _terminal_pair()
    forward = alpaca_paper_order_view_supervisor_round_id(
        earlier.plan,
        later.plan,
    )
    reverse = alpaca_paper_order_view_supervisor_round_id(
        later.plan,
        earlier.plan,
    )

    assert ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION == (
        "phase4q-bounded-authenticated-order-view-supervisor-v2"
    )
    assert ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID == (
        "phase4q-one-durable-transition-supervisor-policy-v2"
    )
    assert ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256 == (
        "a445d2e1ce064970ebc39b41e8b5f3995b67ed24818977c4cd6919a29c74dcf7"
    )
    assert (
        ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
        is ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION
    )
    assert forward != reverse
    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperAuthenticatedOrderSnapshotSupervisorState()
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAuthenticatedOrderViewSupervisorResult()

    state = _source_state(earlier, source_head_sha256=HEAD_1)
    with pytest.raises(FrozenInstanceError):
        state.source_head_sha256 = HEAD_2  # type: ignore[misc]


def test_invalid_exact_fence_is_wrapped_before_state_or_page_access() -> None:
    earlier, later = _terminal_pair()
    earlier_state = _source_state(earlier, source_head_sha256=HEAD_1)
    later_state = _source_state(later, source_head_sha256=HEAD_2)
    loader = _StateLoader(earlier_state, later_state)
    invalid_fence = _fence()
    object.__setattr__(invalid_fence, "fencing_generation", 0)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="fence is invalid",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier.plan,
            later.plan,
            fence=invalid_fence,
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=_PageWorkflow(loader, {}),
            comparison_repository=_ComparisonRepository(loader),
        )

    assert loader.state_calls == []


@pytest.mark.parametrize(
    ("loader_identity", "workflow_identity", "repository_identity"),
    (
        (2, 1, 1),
        (1, 2, 1),
        (1, 1, 2),
        (0, 1, 1),
        (-1, 1, 1),
        (True, 1, 1),
    ),
)
def test_runtime_store_identity_must_be_one_exact_positive_int_before_access(
    loader_identity: int,
    workflow_identity: int,
    repository_identity: int,
) -> None:
    earlier, later = _terminal_pair()
    loader = _StateLoader(
        _source_state(earlier, source_head_sha256=HEAD_1),
        _source_state(later, source_head_sha256=HEAD_2),
        runtime_store_identity=loader_identity,
    )
    workflow = _PageWorkflow(
        loader,
        {},
        runtime_store_identity=workflow_identity,
    )
    repository = _ComparisonRepository(
        loader,
        runtime_store_identity=repository_identity,
    )
    clock = _Clock(BASE + timedelta(seconds=20))

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="do not share one runtime durable store",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier.plan,
            later.plan,
            fence=_fence(),
            clock=clock,
            state_loader=loader,
            page_workflow=workflow,
            comparison_repository=repository,
        )

    assert loader.state_calls == []
    assert loader.prefix_calls == []
    assert clock.calls == 0
    assert workflow.calls == []
    assert repository.record_calls == []
    assert repository.load_calls == []


def test_missing_runtime_store_identity_fails_before_access() -> None:
    earlier, later = _terminal_pair()
    loader = _StateLoader(
        _source_state(earlier, source_head_sha256=HEAD_1),
        _source_state(later, source_head_sha256=HEAD_2),
    )
    workflow = _PageWorkflow(loader, {})
    repository = _ComparisonRepository(loader)
    clock = _Clock(BASE + timedelta(seconds=20))
    del repository.runtime_store_identity

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="do not share one runtime durable store",
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier.plan,
            later.plan,
            fence=_fence(),
            clock=clock,
            state_loader=loader,
            page_workflow=workflow,
            comparison_repository=repository,
        )

    assert loader.state_calls == []
    assert loader.prefix_calls == []
    assert clock.calls == 0
    assert workflow.calls == []
    assert repository.record_calls == []
    assert repository.load_calls == []


def test_runtime_store_identity_failure_is_wrapped_before_access() -> None:
    earlier, later = _terminal_pair()
    loader = _StateLoader(
        _source_state(earlier, source_head_sha256=HEAD_1),
        _source_state(later, source_head_sha256=HEAD_2),
    )
    workflow = _PageWorkflow(loader, {})
    repository = _ComparisonRepository(loader)
    clock = _Clock(BASE + timedelta(seconds=20))

    class _BrokenIdentityRepository:
        @property
        def runtime_store_identity(self) -> int:
            raise RuntimeError("store unavailable")

        def record(
            self,
            evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
            *,
            fence: AccountFence,
        ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
            del evidence, fence
            raise AssertionError("record must not be called")

        def load(
            self,
            receipt_id: str,
        ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None:
            del receipt_id
            raise AssertionError("load must not be called")

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="could not identify their runtime durable store",
    ) as captured:
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier.plan,
            later.plan,
            fence=_fence(),
            clock=clock,
            state_loader=loader,
            page_workflow=workflow,
            comparison_repository=_BrokenIdentityRepository(),
        )

    assert type(captured.value.__cause__) is RuntimeError
    assert loader.state_calls == []
    assert loader.prefix_calls == []
    assert clock.calls == 0
    assert workflow.calls == []
    assert repository.record_calls == []
    assert repository.load_calls == []


def test_runtime_store_identity_is_not_canonical_result_material() -> None:
    earlier_terminal, later_terminal = _terminal_pair()
    earlier = _source_state(earlier_terminal, source_head_sha256=HEAD_1)
    later = _source_state(
        _prefix_at(later_terminal, 0),
        source_head_sha256=None,
    )
    eligible_at = (
        earlier_terminal.capture.pages[-1].observation.received_at
        + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
    )
    checked_at = eligible_at - timedelta(microseconds=1)
    results: list[AlpacaPaperAuthenticatedOrderViewSupervisorResult] = []

    for identity in (1, 99):
        loader = _StateLoader(
            earlier,
            later,
            runtime_store_identity=identity,
        )
        results.append(
            supervise_authenticated_alpaca_paper_order_views_once(
                earlier_terminal.plan,
                later_terminal.plan,
                fence=_fence(),
                clock=_Clock(checked_at),
                state_loader=loader,
                page_workflow=_PageWorkflow(
                    loader,
                    {},
                    runtime_store_identity=identity,
                ),
                comparison_repository=_ComparisonRepository(
                    loader,
                    runtime_store_identity=identity,
                ),
            )
        )

    assert results[0] == results[1]
    assert results[0].result_id == results[1].result_id
    assert results[0].semantic_sha256 == results[1].semantic_sha256


@pytest.mark.parametrize(
    ("later_kind", "message"),
    (
        ("same", "distinct plans"),
        ("account", "cross account"),
        ("profile", "traversal profiles"),
    ),
)
def test_plan_pair_binding_fails_before_durable_state_access(
    later_kind: str,
    message: str,
) -> None:
    earlier, later = _terminal_pair()
    later_plan = later.plan
    if later_kind == "same":
        later_plan = earlier.plan
    elif later_kind == "account":
        later_plan = create_alpaca_paper_order_snapshot_plan(
            account_id="another-paper-account",
            capture_idempotency_key="phase4q-cross-account-plan",
            page_limit=earlier.plan.page_limit,
            maximum_pages=earlier.plan.maximum_pages,
        )
    elif later_kind == "profile":
        later_plan = create_alpaca_paper_order_snapshot_plan(
            account_id=earlier.plan.account_id,
            capture_idempotency_key="phase4q-other-profile-plan",
            page_limit=1,
            maximum_pages=earlier.plan.maximum_pages,
        )
    loader = _StateLoader(
        _source_state(earlier, source_head_sha256=HEAD_1),
        _source_state(later, source_head_sha256=HEAD_2),
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match=message,
    ):
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier.plan,
            later_plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=_PageWorkflow(loader, {}),
            comparison_repository=_ComparisonRepository(loader),
        )

    assert loader.state_calls == []


def test_phase4o_conflict_is_wrapped_in_supervisor_taxonomy() -> None:
    earlier, later = _terminal_pair()
    earlier_absent = _source_state(
        _prefix_at(earlier, 0),
        source_head_sha256=None,
    )
    later_absent = _source_state(
        _prefix_at(later, 0),
        source_head_sha256=None,
    )
    loader = _StateLoader(earlier_absent, later_absent)

    class _ConflictingPageWorkflow:
        @property
        def runtime_store_identity(self) -> int:
            return loader.runtime_store_identity

        def advance_one_page(
            self,
            description: AlpacaPaperOrderSnapshotPageDescription,
            *,
            fence: AccountFence,
        ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
            del description, fence
            raise AlpacaPaperOrderSnapshotConflict("pre-existing stalled claim")

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewSupervisorConflict,
        match="Phase 4O page workflow failed",
    ) as captured:
        supervise_authenticated_alpaca_paper_order_views_once(
            earlier.plan,
            later.plan,
            fence=_fence(),
            clock=_Clock(BASE),
            state_loader=loader,
            page_workflow=_ConflictingPageWorkflow(),
            comparison_repository=_ComparisonRepository(loader),
        )

    assert type(captured.value.__cause__) is AlpacaPaperOrderSnapshotConflict
