from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, replace
from datetime import datetime, timedelta
from typing import Any

import pytest

from packages.adapters.broker.alpaca_paper_account_activities import (
    AlpacaPaperAccountActivityPageDescription,
    AlpacaPaperAccountActivityPlan,
    create_alpaca_paper_account_activity_plan,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    AlpacaPaperAuthenticatedAccountActivityPrefix,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
    _alpaca_paper_account_activity_page_preparation_receipt,
    _alpaca_paper_authenticated_account_activity_prefix,
    _alpaca_paper_authenticated_account_activity_traversal_state,
)
from packages.application.alpaca_paper_account_activity_comparison import (
    AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    _alpaca_paper_authenticated_account_activity_comparison_receipt,
)
from packages.application.alpaca_paper_account_activity_supervisor import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_SUPERVISOR_MINIMUM_START_SEPARATION,
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_ID,
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256,
    AlpacaPaperAccountActivitySupervisorAction,
    AlpacaPaperAccountActivitySupervisorReason,
    AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
    AlpacaPaperAuthenticatedAccountActivitySupervisorResult,
    AlpacaPaperAuthenticatedAccountActivitySupervisorStalled,
    alpaca_paper_account_activity_supervisor_round_id,
    supervise_authenticated_alpaca_paper_account_activities_once,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from tests.unit.test_alpaca_paper_account_activities import _activity, _body
from tests.unit.test_alpaca_paper_account_activity_comparison_application import (
    _authenticated_prefix,
    _commit_fence,
)
from tests.unit.test_alpaca_paper_account_activity_runtime import BASE

HEAD_EARLIER_ACTIVE = "1" * 64
HEAD_LATER_ACTIVE = "2" * 64
HEAD_EARLIER_TERMINAL = "a" * 64
HEAD_LATER_TERMINAL = "b" * 64
SECRET_MARKER = "unsafe-phase4ai-secret"


def _prefix_slice(
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    count: int,
) -> AlpacaPaperAuthenticatedAccountActivityPrefix:
    return _alpaca_paper_authenticated_account_activity_prefix(
        prefix.plan,
        page_receipts=prefix.page_receipts[:count],
    )


def _absent_state(
    plan: AlpacaPaperAccountActivityPlan,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    prefix = _alpaca_paper_authenticated_account_activity_prefix(
        plan,
        page_receipts=(),
    )
    return _alpaca_paper_authenticated_account_activity_traversal_state(
        stage=AlpacaPaperAccountActivityTraversalStage.ABSENT,
        prefix=prefix,
        preparation=None,
        source_head_sha256=None,
    )


def _active_state(
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    *,
    head: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    return _alpaca_paper_authenticated_account_activity_traversal_state(
        stage=AlpacaPaperAccountActivityTraversalStage.ACTIVE,
        prefix=prefix,
        preparation=None,
        source_head_sha256=head,
    )


def _terminal_state(
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    *,
    head: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    return _alpaca_paper_authenticated_account_activity_traversal_state(
        stage=(
            AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED
            if prefix.capture.pagination_exhausted
            else AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED
        ),
        prefix=prefix,
        preparation=None,
        source_head_sha256=head,
    )


def _stalled_state(
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    *,
    head: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    description = prefix.next_page_description
    assert description is not None
    previous = prefix.page_receipts[-1] if prefix.page_receipts else None
    preparation = _alpaca_paper_account_activity_page_preparation_receipt(
        description,
        prefix_capture_sha256=prefix.capture.semantic_sha256,
        prefix_page_count=prefix.page_count,
        previous_page_receipt_id=(None if previous is None else previous.receipt_id),
        previous_page_receipt_sha256=(None if previous is None else previous.semantic_sha256),
        prepared_at=BASE + timedelta(milliseconds=1),
    )
    return _alpaca_paper_authenticated_account_activity_traversal_state(
        stage=AlpacaPaperAccountActivityTraversalStage.STALLED,
        prefix=prefix,
        preparation=preparation,
        source_head_sha256=head,
    )


@dataclass(frozen=True, slots=True)
class _World:
    earlier_absent: AlpacaPaperAuthenticatedAccountActivityTraversalState
    earlier_active: AlpacaPaperAuthenticatedAccountActivityTraversalState
    earlier_terminal: AlpacaPaperAuthenticatedAccountActivityTraversalState
    later_absent: AlpacaPaperAuthenticatedAccountActivityTraversalState
    later_active: AlpacaPaperAuthenticatedAccountActivityTraversalState
    later_terminal: AlpacaPaperAuthenticatedAccountActivityTraversalState
    earlier_receipts: tuple[
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    ]
    later_receipts: tuple[
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
        AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    ]
    commit_fence: AccountFenceReceipt
    eligible_at: datetime


@pytest.fixture(scope="module")
def world() -> _World:
    earlier_prefix, ingress, account_source = _authenticated_prefix(
        capture_key="phase4ai-earlier-capture",
        bodies=(
            _body(_activity(1), _activity(2)),
            _body(),
        ),
        page_size=2,
        maximum_pages=3,
        maximum_items=6,
    )
    later_prefix, _, _ = _authenticated_prefix(
        capture_key="phase4ai-later-capture",
        bodies=(
            _body(_activity(1), _activity(2)),
            _body(),
        ),
        page_size=2,
        maximum_pages=3,
        maximum_items=6,
        window_offset=timedelta(seconds=4),
        ingress=ingress,
        account_source=account_source,
    )
    earlier_absent = _absent_state(earlier_prefix.plan)
    earlier_active = _active_state(
        _prefix_slice(earlier_prefix, 1),
        head=HEAD_EARLIER_ACTIVE,
    )
    earlier_terminal = _terminal_state(
        earlier_prefix,
        head=HEAD_EARLIER_TERMINAL,
    )
    later_absent = _absent_state(later_prefix.plan)
    later_active = _active_state(
        _prefix_slice(later_prefix, 1),
        head=HEAD_LATER_ACTIVE,
    )
    later_terminal = _terminal_state(
        later_prefix,
        head=HEAD_LATER_TERMINAL,
    )
    eligible_at = (
        earlier_prefix.capture.pages[-1].observation.received_at
        + ALPACA_PAPER_ACCOUNT_ACTIVITY_SUPERVISOR_MINIMUM_START_SEPARATION
    )
    return _World(
        earlier_absent=earlier_absent,
        earlier_active=earlier_active,
        earlier_terminal=earlier_terminal,
        later_absent=later_absent,
        later_active=later_active,
        later_terminal=later_terminal,
        earlier_receipts=(
            earlier_prefix.page_receipts[0],
            earlier_prefix.page_receipts[1],
        ),
        later_receipts=(
            later_prefix.page_receipts[0],
            later_prefix.page_receipts[1],
        ),
        commit_fence=_commit_fence(earlier_prefix.plan.account_id),
        eligible_at=eligible_at,
    )


class _StateLoader:
    def __init__(
        self,
        *states: AlpacaPaperAuthenticatedAccountActivityTraversalState,
        events: list[str] | None = None,
        runtime_store_identity: object = 1,
        fail: bool = False,
    ) -> None:
        self.states = {state.prefix.plan.capture_id: state for state in states}
        self.events = [] if events is None else events
        self.identity = runtime_store_identity
        self.fail = fail
        self.calls: list[AlpacaPaperAccountActivityPlan] = []

    @property
    def runtime_store_identity(self) -> Any:
        self.events.append("loader-identity")
        return self.identity

    def load_state(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityTraversalState | None:
        self.events.append(f"load-{plan.capture_id}")
        self.calls.append(plan)
        if self.fail:
            raise RuntimeError(SECRET_MARKER)
        return self.states.get(plan.capture_id)


class _PageRuntime:
    def __init__(
        self,
        loader: _StateLoader,
        world: _World,
        *,
        events: list[str] | None = None,
        runtime_store_identity: object = 1,
        fail: bool = False,
        no_update: bool = False,
        double_advance: bool = False,
        return_value: object | None = None,
    ) -> None:
        self.loader = loader
        self.world = world
        self.events = [] if events is None else events
        self.identity = runtime_store_identity
        self.fail = fail
        self.no_update = no_update
        self.double_advance = double_advance
        self.return_value = return_value
        self.calls: list[tuple[AlpacaPaperAccountActivityPageDescription, AccountFence]] = []

    @property
    def runtime_store_identity(self) -> Any:
        self.events.append("runtime-identity")
        return self.identity

    def advance_one_page(
        self,
        description: AlpacaPaperAccountActivityPageDescription,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        self.events.append(f"page-{description.plan.capture_id}-{description.page_number}")
        self.calls.append((description, fence))
        if self.fail:
            raise RuntimeError(SECRET_MARKER)
        if description.plan == self.world.earlier_absent.prefix.plan:
            if description.page_number == 1:
                receipt = self.world.earlier_receipts[0]
                after = (
                    self.world.earlier_terminal
                    if self.double_advance
                    else self.world.earlier_active
                )
            else:
                receipt = self.world.earlier_receipts[1]
                after = self.world.earlier_terminal
        else:
            if description.page_number == 1:
                receipt = self.world.later_receipts[0]
                after = self.world.later_active
            else:
                receipt = self.world.later_receipts[1]
                after = self.world.later_terminal
        if not self.no_update:
            self.loader.states[description.plan.capture_id] = after
        if self.return_value is not None:
            return self.return_value  # type: ignore[return-value]
        return receipt


class _ComparisonRepository:
    def __init__(
        self,
        commit_fence: AccountFenceReceipt,
        *,
        events: list[str] | None = None,
        runtime_store_identity: object = 1,
        fail: bool = False,
        forge: bool = False,
    ) -> None:
        self.commit_fence = commit_fence
        self.events = [] if events is None else events
        self.identity = runtime_store_identity
        self.fail = fail
        self.forge = forge
        self.calls: list[
            tuple[
                AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
                AccountFence,
            ]
        ] = []

    @property
    def runtime_store_identity(self) -> Any:
        self.events.append("repository-identity")
        return self.identity

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        self.events.append("append")
        self.calls.append((evidence, fence))
        if self.fail:
            raise RuntimeError(SECRET_MARKER)
        receipt = _alpaca_paper_authenticated_account_activity_comparison_receipt(
            evidence,
            earlier_source_head_sha256=(evidence.earlier_source_head_sha256),
            later_source_head_sha256=evidence.later_source_head_sha256,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )
        if self.forge:
            object.__setattr__(
                receipt,
                "later_source_head_sha256",
                "0" * 64,
            )
        return receipt


class _Clock:
    def __init__(
        self,
        *instants: datetime,
        events: list[str] | None = None,
        fail: bool = False,
    ) -> None:
        self.instants = list(instants)
        self.events = [] if events is None else events
        self.fail = fail
        self.calls = 0

    def now(self) -> datetime:
        self.events.append("clock")
        self.calls += 1
        if self.fail:
            raise RuntimeError(SECRET_MARKER)
        if not self.instants:
            raise AssertionError("unexpected clock read")
        return self.instants.pop(0)


def _ports(
    world: _World,
    *,
    earlier: AlpacaPaperAuthenticatedAccountActivityTraversalState | None = None,
    later: AlpacaPaperAuthenticatedAccountActivityTraversalState | None = None,
    events: list[str] | None = None,
    identity: object = 1,
) -> tuple[_StateLoader, _PageRuntime, _ComparisonRepository]:
    loader = _StateLoader(
        world.earlier_absent if earlier is None else earlier,
        world.later_absent if later is None else later,
        events=events,
        runtime_store_identity=identity,
    )
    runtime = _PageRuntime(
        loader,
        world,
        events=events,
        runtime_store_identity=identity,
    )
    repository = _ComparisonRepository(
        world.commit_fence,
        events=events,
        runtime_store_identity=identity,
    )
    return loader, runtime, repository


def _supervise(
    world: _World,
    *,
    clock: _Clock,
    loader: object,
    runtime: object,
    repository: object,
    earlier_plan: AlpacaPaperAccountActivityPlan | None = None,
    later_plan: AlpacaPaperAccountActivityPlan | None = None,
    fence: AccountFence | None = None,
) -> AlpacaPaperAuthenticatedAccountActivitySupervisorResult:
    return supervise_authenticated_alpaca_paper_account_activities_once(
        world.earlier_absent.prefix.plan if earlier_plan is None else earlier_plan,
        world.later_absent.prefix.plan if later_plan is None else later_plan,
        fence=world.commit_fence.fence if fence is None else fence,
        clock=clock,
        state_loader=loader,  # type: ignore[arg-type]
        page_runtime=runtime,  # type: ignore[arg-type]
        comparison_repository=repository,  # type: ignore[arg-type]
    )


def _assert_no_authority(value: object) -> None:
    for property_name in (
        "request_budget_enforced",
        "authenticated_provider_evidence",
        "raw_response_persisted",
        "provider_io_performed",
        "runtime_current",
        "account_status_current",
        "provider_account_status_current",
        "capture_authenticated",
        "durable_source_positions_authenticated",
        "comparison_durably_recorded",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
        "activity_history_complete",
        "activity_history_consistent",
        "converged",
        "monotonic_timing_qualified",
        "provider_activity_identity_qualified",
        "provider_activity_sequence_identity_qualified",
        "provider_activity_revision_identity_qualified",
        "provider_execution_identity_qualified",
        "canonical_execution_identity_qualified",
        "provider_revision_identity_qualified",
        "execution_revision_identity_qualified",
        "provider_deduplication_identity_qualified",
        "provider_bust_identity_qualified",
        "provider_correction_identity_qualified",
        "provider_deduplication_authorized",
        "canonical_execution_fact_authorized",
        "canonical_execution_revision_authorized",
        "canonical_account_fact_authorized",
        "canonical_ledger_fact_authorized",
        "canonical_cash_fact_authorized",
        "execution_application_authorized",
        "bust_application_authorized",
        "correction_application_authorized",
        "manual_activity_application_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_completion_authorized",
        "reconciliation_complete",
        "unknown_resolution_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "readiness_transition_authorized",
        "activity_snapshot_pagination_ready",
        "decode_quarantine_ready",
        "reconciliation_ready",
        "dispatch_preflight_ready",
        "paper_startup_ready",
        "transport_submission_ready",
        "submission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(value, property_name) is False


def test_restart_safe_lifecycle_advances_one_effect_per_invocation(
    world: _World,
) -> None:
    loader, runtime, repository = _ports(world)
    clock = _Clock(
        world.eligible_at - timedelta(microseconds=1),
        world.eligible_at,
    )

    first = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert first.action is (AlpacaPaperAccountActivitySupervisorAction.EARLIER_PAGE_ADVANCED)
    assert first.reason is (
        AlpacaPaperAccountActivitySupervisorReason.EARLIER_TRAVERSAL_REQUIRES_PAGE
    )
    assert first.earlier_state.stage is AlpacaPaperAccountActivityTraversalStage.ACTIVE
    assert first.next_eligible_at is None
    assert len(runtime.calls) == 1
    assert repository.calls == []
    assert clock.calls == 0

    second = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert second.action is (AlpacaPaperAccountActivitySupervisorAction.EARLIER_PAGE_ADVANCED)
    assert second.earlier_state.stage is (AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED)
    assert second.next_eligible_at == world.eligible_at
    assert len(runtime.calls) == 2
    assert repository.calls == []
    assert clock.calls == 0

    waiting = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert waiting.action is (AlpacaPaperAccountActivitySupervisorAction.WAITING_MINIMUM_SEPARATION)
    assert waiting.reason is (
        AlpacaPaperAccountActivitySupervisorReason.LATER_START_GATE_NOT_REACHED
    )
    assert waiting.next_eligible_at == world.eligible_at
    assert waiting.checked_at == world.eligible_at - timedelta(microseconds=1)
    assert waiting.value is None
    assert len(runtime.calls) == 2
    assert repository.calls == []
    assert clock.calls == 1

    later = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert later.action is (AlpacaPaperAccountActivitySupervisorAction.LATER_PAGE_ADVANCED)
    assert later.reason is (
        AlpacaPaperAccountActivitySupervisorReason.LATER_TRAVERSAL_REQUIRES_PAGE
    )
    assert later.checked_at == world.eligible_at
    assert later.next_eligible_at is None
    assert later.later_state.stage is (AlpacaPaperAccountActivityTraversalStage.ACTIVE)
    assert len(runtime.calls) == 3
    assert repository.calls == []
    assert clock.calls == 2

    later_terminal = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert later_terminal.action is (AlpacaPaperAccountActivitySupervisorAction.LATER_PAGE_ADVANCED)
    assert later_terminal.checked_at is None
    assert later_terminal.later_state.stage is (
        AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED
    )
    assert len(runtime.calls) == 4
    assert repository.calls == []
    assert clock.calls == 2

    compared = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert compared.action is (AlpacaPaperAccountActivitySupervisorAction.COMPARISON_RECORDED)
    assert compared.reason is (AlpacaPaperAccountActivitySupervisorReason.TERMINAL_PAIR_READY)
    assert type(compared.value) is (AlpacaPaperAuthenticatedAccountActivityComparisonReceipt)
    assert len(runtime.calls) == 4
    assert len(repository.calls) == 1
    assert clock.calls == 2
    assert loader.calls.count(world.earlier_absent.prefix.plan) >= 6
    assert loader.calls.count(world.later_absent.prefix.plan) >= 6
    assert compared.additional_reconciliation_required is True
    _assert_no_authority(compared)


def test_two_second_boundary_is_closed_and_wait_is_no_effect(
    world: _World,
) -> None:
    loader, runtime, repository = _ports(
        world,
        earlier=world.earlier_terminal,
    )
    clock = _Clock(
        world.eligible_at - timedelta(microseconds=1),
        world.eligible_at,
    )

    waiting = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert waiting.stage is (AlpacaPaperAccountActivitySupervisorAction.WAITING_MINIMUM_SEPARATION)
    assert runtime.calls == []
    assert repository.calls == []

    exact = _supervise(
        world,
        clock=clock,
        loader=loader,
        runtime=runtime,
        repository=repository,
    )
    assert exact.action is (AlpacaPaperAccountActivitySupervisorAction.LATER_PAGE_ADVANCED)
    assert len(runtime.calls) == 1
    assert repository.calls == []


@pytest.mark.parametrize("stalled_source", ("earlier", "later"))
def test_stalled_claims_never_resend(
    world: _World,
    stalled_source: str,
) -> None:
    earlier = (
        _stalled_state(
            world.earlier_absent.prefix,
            head="c" * 64,
        )
        if stalled_source == "earlier"
        else world.earlier_terminal
    )
    later = (
        _stalled_state(
            world.later_absent.prefix,
            head="d" * 64,
        )
        if stalled_source == "later"
        else world.later_absent
    )
    loader, runtime, repository = _ports(
        world,
        earlier=earlier,
        later=later,
    )
    clock = _Clock(world.eligible_at)

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorStalled,
        match=stalled_source,
    ):
        _supervise(
            world,
            clock=clock,
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert len(loader.calls) == 2
    assert runtime.calls == []
    assert repository.calls == []
    assert clock.calls == 0


def test_active_later_source_before_earlier_terminal_fails_closed(
    world: _World,
) -> None:
    loader, runtime, repository = _ports(
        world,
        earlier=world.earlier_active,
        later=world.later_active,
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="advanced before earlier termination",
    ):
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert runtime.calls == []
    assert repository.calls == []


def test_runtime_store_preflight_precedes_load_clock_and_effect(
    world: _World,
) -> None:
    events: list[str] = []
    loader, runtime, repository = _ports(
        world,
        events=events,
        identity=7,
    )
    _supervise(
        world,
        clock=_Clock(events=events),
        loader=loader,
        runtime=runtime,
        repository=repository,
    )

    assert events[:3] == [
        "loader-identity",
        "runtime-identity",
        "repository-identity",
    ]
    assert events[3].startswith("load-")


def test_split_runtime_store_fails_before_load_clock_or_effect(
    world: _World,
) -> None:
    events: list[str] = []
    loader, runtime, repository = _ports(world, events=events)
    runtime.identity = 2
    clock = _Clock(world.eligible_at, events=events)

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="do not share one process-local runtime store",
    ):
        _supervise(
            world,
            clock=clock,
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert events == [
        "loader-identity",
        "runtime-identity",
        "repository-identity",
    ]
    assert loader.calls == []
    assert runtime.calls == []
    assert repository.calls == []
    assert clock.calls == 0


@pytest.mark.parametrize("port_name", ("loader", "runtime", "repository"))
@pytest.mark.parametrize("invalid_identity", (None, 0, -1, True, "1"))
def test_missing_or_invalid_runtime_store_identity_fails_before_access(
    world: _World,
    port_name: str,
    invalid_identity: object,
) -> None:
    events: list[str] = []
    loader, runtime, repository = _ports(world, events=events)
    if port_name == "loader":
        loader.identity = invalid_identity
    elif port_name == "runtime":
        runtime.identity = invalid_identity
    else:
        repository.identity = invalid_identity
    clock = _Clock(world.eligible_at, events=events)

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="runtime-store identity",
    ):
        _supervise(
            world,
            clock=clock,
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert loader.calls == []
    assert runtime.calls == []
    assert repository.calls == []
    assert clock.calls == 0

    missing = object()
    values = {
        "loader": missing if port_name == "loader" else loader,
        "runtime": missing if port_name == "runtime" else runtime,
        "repository": missing if port_name == "repository" else repository,
    }
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="runtime-store identity is unavailable",
    ):
        _supervise(
            world,
            clock=clock,
            loader=values["loader"],
            runtime=values["runtime"],
            repository=values["repository"],
        )


def test_ordered_pair_account_and_traversal_conflicts_precede_state_access(
    world: _World,
) -> None:
    cases = (
        (
            world.earlier_absent.prefix.plan,
            world.earlier_absent.prefix.plan,
            "distinct ordered plans",
        ),
        (
            world.earlier_absent.prefix.plan,
            create_alpaca_paper_account_activity_plan(
                account_id="different-account",
                capture_idempotency_key="phase4ai-other-account",
                page_size=2,
                maximum_pages=3,
                maximum_items=6,
            ),
            "cross account identities",
        ),
        (
            world.earlier_absent.prefix.plan,
            replace(
                world.later_absent.prefix.plan,
                page_size=3,
            ),
            "different traversal profiles",
        ),
    )
    for earlier_plan, later_plan, message in cases:
        loader, runtime, repository = _ports(world)
        with pytest.raises(
            AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
            match=message,
        ):
            _supervise(
                world,
                clock=_Clock(),
                loader=loader,
                runtime=runtime,
                repository=repository,
                earlier_plan=earlier_plan,
                later_plan=later_plan,
            )
        assert loader.calls == []
        assert runtime.calls == []
        assert repository.calls == []

    forward = alpaca_paper_account_activity_supervisor_round_id(
        world.earlier_absent.prefix.plan,
        world.later_absent.prefix.plan,
    )
    reverse = alpaca_paper_account_activity_supervisor_round_id(
        world.later_absent.prefix.plan,
        world.earlier_absent.prefix.plan,
    )
    assert forward != reverse


def test_clock_rollback_is_rejected_without_effect(world: _World) -> None:
    loader, runtime, repository = _ports(
        world,
        earlier=world.earlier_terminal,
    )
    earlier_received_at = world.earlier_terminal.prefix.capture.pages[-1].observation.received_at
    clock = _Clock(earlier_received_at - timedelta(microseconds=1))

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="clock regressed",
    ):
        _supervise(
            world,
            clock=clock,
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert runtime.calls == []
    assert repository.calls == []
    assert clock.calls == 1


@pytest.mark.parametrize(
    ("mode", "message"),
    (
        ("no_update", "executable Phase 4AE transition"),
        ("double_advance", "one exact same-fence append"),
        ("wrong_value", "non-canonical receipt"),
    ),
)
def test_forged_page_workflow_or_receipt_fails_closed(
    world: _World,
    mode: str,
    message: str,
) -> None:
    loader, _, repository = _ports(world)
    runtime = _PageRuntime(
        loader,
        world,
        no_update=mode == "no_update",
        double_advance=mode == "double_advance",
        return_value=object() if mode == "wrong_value" else None,
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match=message,
    ):
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert len(runtime.calls) == 1
    assert repository.calls == []


def test_forged_comparison_receipt_and_append_failure_are_sanitized(
    world: _World,
) -> None:
    loader, runtime, _ = _ports(
        world,
        earlier=world.earlier_terminal,
        later=world.later_terminal,
    )
    forged = _ComparisonRepository(
        world.commit_fence,
        forge=True,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="Phase 4AG comparison workflow failed",
    ):
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=runtime,
            repository=forged,
        )
    assert len(forged.calls) == 1
    assert runtime.calls == []

    loader, runtime, _ = _ports(
        world,
        earlier=world.earlier_terminal,
        later=world.later_terminal,
    )
    failing = _ComparisonRepository(
        world.commit_fence,
        fail=True,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="Phase 4AG comparison workflow failed",
    ) as captured:
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=runtime,
            repository=failing,
        )
    assert SECRET_MARKER not in str(captured.value)
    assert len(failing.calls) == 1
    assert runtime.calls == []


def test_clock_and_page_failures_do_not_expose_internal_details(
    world: _World,
) -> None:
    loader, runtime, repository = _ports(
        world,
        earlier=world.earlier_terminal,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="clock failed",
    ) as clock_failure:
        _supervise(
            world,
            clock=_Clock(fail=True),
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
    assert SECRET_MARKER not in str(clock_failure.value)

    loader, _, repository = _ports(world)
    failing_runtime = _PageRuntime(loader, world, fail=True)
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="one-page runtime failed",
    ) as runtime_failure:
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=failing_runtime,
            repository=repository,
        )
    assert SECRET_MARKER not in str(runtime_failure.value)


def test_result_is_deterministic_immutable_and_non_forgeable(
    world: _World,
) -> None:
    first_ports = _ports(
        world,
        earlier=world.earlier_terminal,
        identity=11,
    )
    second_ports = _ports(
        world,
        earlier=world.earlier_terminal,
        identity=29,
    )
    checked_at = world.eligible_at - timedelta(microseconds=1)
    first = _supervise(
        world,
        clock=_Clock(checked_at),
        loader=first_ports[0],
        runtime=first_ports[1],
        repository=first_ports[2],
    )
    second = _supervise(
        world,
        clock=_Clock(checked_at),
        loader=second_ports[0],
        runtime=second_ports[1],
        repository=second_ports[2],
    )

    assert (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_CONTRACT_VERSION
        == "phase4ai-bounded-authenticated-account-activity-supervisor-v1"
    )
    assert (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_ID
        == "phase4ai-one-effect-account-activity-supervisor-policy-v1"
    )
    assert len(ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256) == 64
    assert first == second
    assert first.result_id == second.result_id
    assert first.semantic_sha256 == second.semantic_sha256
    assert first.canonical_json == second.canonical_json
    assert SECRET_MARKER not in first.canonical_json
    _assert_no_authority(first)

    with pytest.raises(TypeError):
        AlpacaPaperAuthenticatedAccountActivitySupervisorResult()
    with pytest.raises(FrozenInstanceError):
        first.action = (  # type: ignore[misc]
            AlpacaPaperAccountActivitySupervisorAction.COMPARISON_RECORDED
        )
    object.__setattr__(
        first,
        "reason",
        AlpacaPaperAccountActivitySupervisorReason.TERMINAL_PAIR_READY,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="waiting result",
    ):
        _ = first.semantic_sha256


def test_missing_or_substituted_state_is_sanitized(world: _World) -> None:
    loader, runtime, repository = _ports(world)
    loader.states.pop(world.earlier_absent.prefix.plan.capture_id)
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="no explicit Phase 4AE state",
    ):
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=runtime,
            repository=repository,
        )

    loader, runtime, repository = _ports(world)
    loader.states[world.earlier_absent.prefix.plan.capture_id] = world.later_absent
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivitySupervisorConflict,
        match="substituted another plan",
    ):
        _supervise(
            world,
            clock=_Clock(),
            loader=loader,
            runtime=runtime,
            repository=repository,
        )
