from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import timedelta
from typing import Any

import pytest

from packages.adapters.broker.alpaca_paper_account_activities import (
    AlpacaPaperAccountActivityPlan,
    create_alpaca_paper_account_activity_plan,
)
from packages.adapters.broker.alpaca_paper_account_activity_comparison import (
    AlpacaPaperAccountActivityComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPrefix,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
    _alpaca_paper_authenticated_account_activity_prefix,
    _alpaca_paper_authenticated_account_activity_traversal_state,
)
from packages.application.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID,
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
    AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing,
    _alpaca_paper_authenticated_account_activity_comparison_evidence,
    _alpaca_paper_authenticated_account_activity_comparison_receipt,
    _materialize_authenticated_comparison_evidence,
    _materialize_authenticated_comparison_receipt,
    compare_and_record_authenticated_alpaca_paper_account_activity_prefixes,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from packages.domain.broker_request_budget import (
    BrokerRequestDemand,
    BrokerRequestPermit,
    _broker_request_permit_freshness_receipt,
    issue_broker_request_permit,
)
from tests.unit.test_alpaca_paper_account_activities import _activity, _body
from tests.unit.test_alpaca_paper_account_activity_runtime import (
    BASE,
    VALID_UNTIL,
    Budget,
    Coordinator,
    Identities,
    InMemoryIngress,
    PageRuntime,
    Resolver,
    Transport,
    _clock,
    _scenario,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    FixedTransport,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    _scenario as account_scenario,
)
from tests.unit.test_submission_attempt import fence_receipt

HEAD_A = "a" * 64
HEAD_B = "b" * 64
PROVIDER_ACCOUNT_B = "00000000-0000-4000-8000-000000000002"
SECRET_MARKER = "unsafe-repository-secret"


class _ShiftedBudget(Budget):
    def __init__(self, events: list[str], *, offset: timedelta) -> None:
        super().__init__(events)
        self.offset = offset

    def issue_new(
        self,
        *,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> BrokerRequestPermit:
        self.events.append("permit")
        self.demands.append(demand)
        permit = issue_broker_request_permit(
            policy=policy,  # type: ignore[arg-type]
            demand=demand,
            issued_at=BASE + self.offset + timedelta(milliseconds=40),
            active_permits=(),
            previous_permit=None,
            previous_policy=None,
        )
        self.permits.append(permit)
        return permit

    def authenticate_fresh(
        self,
        *,
        permit: BrokerRequestPermit,
        policy: object,
        demand: BrokerRequestDemand,
    ) -> object:
        self.events.append("permit-fresh")
        return _broker_request_permit_freshness_receipt(
            permit=permit,
            policy=policy,  # type: ignore[arg-type]
            demand=demand,
            checked_at=BASE + self.offset + timedelta(milliseconds=60),
        )


class _ShiftedCoordinator(Coordinator):
    def __init__(self, events: list[str], *, offset: timedelta) -> None:
        super().__init__(events)
        self.offset = offset

    def revalidate(self, fence: AccountFence) -> AccountFenceReceipt:
        del fence
        self.calls += 1
        self.events.append(f"fence-{self.calls}")
        return fence_receipt(
            validated_at=(
                BASE + self.offset + timedelta(milliseconds=50 if self.calls == 1 else 110)
            ),
            valid_until=VALID_UNTIL,
        )


def _shifted_clock(offset: timedelta) -> object:
    clock = _clock()
    clock.instants = [instant + offset for instant in clock.instants]
    return clock


def _alternate_account_source() -> tuple[object, object]:
    body = json.loads(FixedTransport().body)
    assert type(body) is dict
    body["id"] = PROVIDER_ACCOUNT_B
    scenario = account_scenario(
        expected_provider_account_id=PROVIDER_ACCOUNT_B,
        transport=FixedTransport(
            body=json.dumps(
                body,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ),
    )
    return scenario.reference, scenario.run()


def _authenticated_prefix(
    *,
    capture_key: str,
    bodies: tuple[bytes, ...],
    page_size: int = 2,
    maximum_pages: int = 3,
    maximum_items: int = 6,
    window_offset: timedelta = timedelta(),
    ingress: InMemoryIngress | None = None,
    account_source: tuple[object, object] | None = None,
) -> tuple[
    AlpacaPaperAuthenticatedAccountActivityPrefix,
    InMemoryIngress,
    tuple[object, object],
]:
    seed = _scenario(body=bodies[0], page_size=page_size)
    if account_source is not None:
        seed.reference = account_source[0]  # type: ignore[assignment]
        seed.binding = account_source[1]  # type: ignore[assignment]
    source = (seed.reference, seed.binding)
    plan = create_alpaca_paper_account_activity_plan(
        account_id=seed.reference.account_id,
        capture_idempotency_key=capture_key,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )
    events: list[str] = []
    pages = PageRuntime(events)
    raw = ingress or InMemoryIngress(events)
    prefix = pages.load_prefix(plan)
    for page_index, body in enumerate(bodies):
        description = prefix.next_page_description
        assert description is not None
        offset = window_offset + timedelta(seconds=page_index)
        seed.description = description
        seed.resolver = Resolver(events)
        seed.transport = Transport(
            events,
            body=body,
            request_id=(f"phase4ag-provider-request-{capture_key}-{page_index + 1}"),
        )
        seed.budget = _ShiftedBudget(events, offset=offset)
        seed.identities = Identities(events)
        seed.coordinator = _ShiftedCoordinator(events, offset=offset)
        seed.ingress = raw
        seed.pages = pages
        seed.clock = _shifted_clock(offset)  # type: ignore[assignment]
        seed.events = events
        seed.run()
        prefix = pages.load_prefix(plan)
    return prefix, raw, source


def _state(
    prefix: AlpacaPaperAuthenticatedAccountActivityPrefix,
    *,
    source_head_sha256: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    capture = prefix.capture
    stage = (
        AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED
        if capture.pagination_exhausted
        else (
            AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED
            if capture.bounded_truncation
            else AlpacaPaperAccountActivityTraversalStage.ACTIVE
        )
    )
    return _alpaca_paper_authenticated_account_activity_traversal_state(
        stage=stage,
        prefix=prefix,
        preparation=None,
        source_head_sha256=source_head_sha256,
    )


def _terminal_pair(
    *,
    earlier_bodies: tuple[bytes, ...] | None = None,
    later_bodies: tuple[bytes, ...] | None = None,
    later_offset: timedelta = timedelta(seconds=3),
    page_size: int = 2,
    maximum_pages: int = 3,
    maximum_items: int = 6,
) -> tuple[
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
]:
    default = (_body(_activity(1)),)
    earlier_prefix, ingress, account_source = _authenticated_prefix(
        capture_key="phase4ag-earlier-capture",
        bodies=default if earlier_bodies is None else earlier_bodies,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )
    later_prefix, _, _ = _authenticated_prefix(
        capture_key="phase4ag-later-capture",
        bodies=default if later_bodies is None else later_bodies,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
        window_offset=later_offset,
        ingress=ingress,
        account_source=account_source,
    )
    return (
        _state(earlier_prefix, source_head_sha256=HEAD_A),
        _state(later_prefix, source_head_sha256=HEAD_B),
    )


class _StateLoader:
    def __init__(
        self,
        *states: AlpacaPaperAuthenticatedAccountActivityTraversalState,
        events: list[str] | None = None,
        runtime_store_identity: int = 1,
    ) -> None:
        self.states = {state.prefix.plan.capture_id: state for state in states}
        self.events = [] if events is None else events
        self.identity = runtime_store_identity
        self.calls: list[AlpacaPaperAccountActivityPlan] = []

    @property
    def runtime_store_identity(self) -> int:
        self.events.append("loader-identity")
        return self.identity

    def load_state(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityTraversalState | None:
        self.events.append(f"load-{plan.capture_id}")
        self.calls.append(plan)
        return self.states.get(plan.capture_id)


class _ComparisonRepository:
    def __init__(
        self,
        commit_fence: AccountFenceReceipt,
        *,
        events: list[str] | None = None,
        runtime_store_identity: int = 1,
        fail: bool = False,
    ) -> None:
        self.commit_fence = commit_fence
        self.events = [] if events is None else events
        self.identity = runtime_store_identity
        self.fail = fail
        self.calls: list[
            tuple[
                AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
                AccountFence,
            ]
        ] = []

    @property
    def runtime_store_identity(self) -> int:
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
        return _alpaca_paper_authenticated_account_activity_comparison_receipt(
            evidence,
            earlier_source_head_sha256=evidence.earlier_source_head_sha256,
            later_source_head_sha256=evidence.later_source_head_sha256,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


class _SubstitutingRepository(_ComparisonRepository):
    def __init__(
        self,
        substitute: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
        commit_fence: AccountFenceReceipt,
    ) -> None:
        super().__init__(commit_fence)
        self.substitute = substitute

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        del evidence
        self.events.append("append")
        return _alpaca_paper_authenticated_account_activity_comparison_receipt(
            self.substitute,
            earlier_source_head_sha256=(self.substitute.earlier_source_head_sha256),
            later_source_head_sha256=self.substitute.later_source_head_sha256,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


def _commit_fence(account_id: str) -> AccountFenceReceipt:
    return fence_receipt(
        account_id=account_id,
        validated_at=BASE + timedelta(seconds=10),
        valid_until=VALID_UNTIL,
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


def test_workflow_authenticates_sources_before_exact_fenced_append() -> None:
    earlier, later = _terminal_pair()
    events: list[str] = []
    loader = _StateLoader(earlier, later, events=events)
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)
    repository = _ComparisonRepository(commit_fence, events=events)

    receipt = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        earlier.prefix.plan,
        later.prefix.plan,
        fence=commit_fence.fence,
        state_loader=loader,
        comparison_repository=repository,
    )
    repeated = compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
        earlier.prefix.plan,
        later.prefix.plan,
        fence=commit_fence.fence,
        state_loader=loader,
        comparison_repository=repository,
    )

    assert (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION
        == "phase4ag-source-authenticated-account-activity-comparison-v1"
    )
    assert (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID
        == "phase4ag-exact-source-authenticated-account-activity-comparison-policy-v1"
    )
    assert len(ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256) == 64
    assert events[:4] == [
        "loader-identity",
        "repository-identity",
        f"load-{earlier.prefix.plan.capture_id}",
        f"load-{later.prefix.plan.capture_id}",
    ]
    assert events[4] == "append"
    assert receipt == repeated
    assert receipt.evidence.earlier_prefix == earlier.prefix
    assert receipt.evidence.later_prefix == later.prefix
    assert receipt.evidence.earlier_source_head_sha256 == HEAD_A
    assert receipt.evidence.later_source_head_sha256 == HEAD_B
    assert receipt.earlier_source_head_sha256 == HEAD_A
    assert receipt.later_source_head_sha256 == HEAD_B
    assert receipt.evidence.source_request_budgets_authenticated is True
    assert receipt.evidence.source_provider_evidence_authenticated is True
    assert receipt.evidence.source_raw_responses_authenticated is True
    assert receipt.evidence.source_account_identity_authenticated is True
    assert receipt.evidence.source_terminal_heads_authenticated is True
    assert receipt.evidence.captures_authenticated is True
    assert receipt.evidence.historical_provider_account_identity_authenticated is True
    assert receipt.evidence.durable_source_positions_authenticated is False
    assert receipt.evidence.comparison_durably_recorded is False
    assert receipt.durable_source_positions_authenticated is True
    assert receipt.comparison_durably_recorded is True
    assert receipt.commit_fence_receipt == commit_fence
    assert receipt.account_sequence == 1
    assert receipt.previous_receipt_sha256 is None
    _assert_no_authority(receipt.evidence)
    _assert_no_authority(receipt)


def test_split_store_fails_before_any_source_load_or_append() -> None:
    earlier, later = _terminal_pair()
    events: list[str] = []
    loader = _StateLoader(
        earlier,
        later,
        events=events,
        runtime_store_identity=1,
    )
    repository = _ComparisonRepository(
        _commit_fence(earlier.prefix.plan.account_id),
        events=events,
        runtime_store_identity=2,
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="do not share one process-local runtime store",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=repository.commit_fence.fence,
            state_loader=loader,
            comparison_repository=repository,
        )

    assert events == ["loader-identity", "repository-identity"]
    assert loader.calls == []
    assert repository.calls == []


@pytest.mark.parametrize("invalid_identity", (0, -1, True, "1", None))
def test_runtime_store_identity_must_be_a_positive_exact_integer(
    invalid_identity: object,
) -> None:
    earlier, later = _terminal_pair()
    loader = _StateLoader(earlier, later)
    loader.identity = invalid_identity  # type: ignore[assignment]
    repository = _ComparisonRepository(_commit_fence(earlier.prefix.plan.account_id))

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="runtime-store identity is invalid",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=repository.commit_fence.fence,
            state_loader=loader,
            comparison_repository=repository,
        )
    assert loader.calls == []
    assert repository.calls == []


def test_missing_active_and_empty_prefixes_fail_before_append() -> None:
    earlier, later = _terminal_pair()
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)
    repository = _ComparisonRepository(commit_fence)

    missing_loader = _StateLoader(earlier)
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing,
        match="absent",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=missing_loader,
            comparison_repository=repository,
        )

    active_prefix, _, _ = _authenticated_prefix(
        capture_key="phase4ag-active-capture",
        bodies=(_body(_activity(1), _activity(2)),),
        page_size=2,
        maximum_pages=3,
        maximum_items=6,
    )
    active = _state(active_prefix, source_head_sha256="c" * 64)
    assert active.stage is AlpacaPaperAccountActivityTraversalStage.ACTIVE
    active_loader = _StateLoader(active, later)
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing,
        match="not terminal",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            active.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=active_loader,
            comparison_repository=repository,
        )

    empty_plan = create_alpaca_paper_account_activity_plan(
        account_id=earlier.prefix.plan.account_id,
        capture_idempotency_key="phase4ag-empty-prefix-plan",
        page_size=2,
        maximum_pages=3,
        maximum_items=6,
    )
    empty_prefix = _alpaca_paper_authenticated_account_activity_prefix(
        empty_plan,
        page_receipts=(),
    )
    empty = _alpaca_paper_authenticated_account_activity_traversal_state(
        stage=AlpacaPaperAccountActivityTraversalStage.ABSENT,
        prefix=empty_prefix,
        preparation=None,
        source_head_sha256=None,
    )
    empty_loader = _StateLoader(earlier, empty)
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceMissing,
        match="no committed page",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            empty_plan,
            fence=commit_fence.fence,
            state_loader=empty_loader,
            comparison_repository=repository,
        )
    assert repository.calls == []


def test_cross_account_and_cross_provider_uuid_sources_fail_closed() -> None:
    earlier_prefix, ingress, account_source = _authenticated_prefix(
        capture_key="phase4ag-earlier-capture",
        bodies=(_body(_activity(1)),),
    )
    earlier = _state(earlier_prefix, source_head_sha256=HEAD_A)
    later_prefix, _, _ = _authenticated_prefix(
        capture_key="phase4ag-later-capture",
        bodies=(_body(_activity(1)),),
        window_offset=timedelta(seconds=3),
        ingress=ingress,
        account_source=account_source,
    )
    later = _state(later_prefix, source_head_sha256=HEAD_B)
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)

    wrong_fence = AccountFence(
        account_id="different-account",
        owner_id=commit_fence.fence.owner_id,
        lease_id="different-account-lease",
        fencing_generation=commit_fence.fence.fencing_generation,
    )
    loader = _StateLoader(earlier, later)
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="crosses account identities",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=wrong_fence,
            state_loader=loader,
            comparison_repository=_ComparisonRepository(commit_fence),
        )
    assert loader.calls == []

    alternate_source = _alternate_account_source()
    alternate_prefix, _, _ = _authenticated_prefix(
        capture_key="phase4ag-alternate-provider-capture",
        bodies=(_body(_activity(1)),),
        window_offset=timedelta(seconds=3),
        ingress=ingress,
        account_source=alternate_source,
    )
    alternate = _state(
        alternate_prefix,
        source_head_sha256="d" * 64,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="different provider-account UUIDs",
    ):
        _alpaca_paper_authenticated_account_activity_comparison_evidence(
            earlier_state=earlier,
            later_state=alternate,
        )


def test_corrupted_page_substituted_source_and_corrupted_head_fail_closed() -> None:
    earlier, later = _terminal_pair()
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)
    repository = _ComparisonRepository(commit_fence)

    substituted = _StateLoader(earlier, later)
    substituted.states[earlier.prefix.plan.capture_id] = later
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="another plan",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=substituted,
            comparison_repository=repository,
        )

    object.__setattr__(earlier, "source_head_sha256", "not-a-head")
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="failed exact authenticated reconstruction",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=_StateLoader(earlier, later),
            comparison_repository=repository,
        )

    clean_earlier, clean_later = _terminal_pair()
    observation = clean_earlier.prefix.page_receipts[0].persisted_page.observation
    object.__setattr__(observation, "response_body", b"[]")
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="failed exact authenticated reconstruction",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            clean_earlier.prefix.plan,
            clean_later.prefix.plan,
            fence=_commit_fence(clean_earlier.prefix.plan.account_id).fence,
            state_loader=_StateLoader(clean_earlier, clean_later),
            comparison_repository=_ComparisonRepository(
                _commit_fence(clean_earlier.prefix.plan.account_id)
            ),
        )


def test_malformed_empty_prefix_probe_is_sanitized_as_source_conflict() -> None:
    earlier, later = _terminal_pair()
    earlier_plan = earlier.prefix.plan
    commit_fence = _commit_fence(earlier_plan.account_id)
    object.__setattr__(earlier.prefix, "page_receipts", object())

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="failed exact authenticated reconstruction",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier_plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=_StateLoader(earlier, later),
            comparison_repository=_ComparisonRepository(commit_fence),
        )


@pytest.mark.parametrize(
    ("kind", "expected"),
    (
        (
            "match",
            AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED,
        ),
        (
            "waiting",
            AlpacaPaperAccountActivityComparisonDisposition.WAITING_MINIMUM_SEPARATION,
        ),
        (
            "different",
            AlpacaPaperAccountActivityComparisonDisposition.ACTIVITY_VIEW_DIFFERENT,
        ),
        (
            "truncated",
            AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE,
        ),
    ),
)
def test_exact_phase4af_dispositions_are_preserved_in_evidence(
    kind: str,
    expected: AlpacaPaperAccountActivityComparisonDisposition,
) -> None:
    if kind == "waiting":
        earlier, later = _terminal_pair(later_offset=timedelta(seconds=1))
    elif kind == "different":
        earlier, later = _terminal_pair(
            later_bodies=(_body(_activity(1, price="402.0000")),),
        )
    elif kind == "truncated":
        full = (_body(_activity(1)),)
        earlier, later = _terminal_pair(
            earlier_bodies=full,
            later_bodies=full,
            page_size=1,
            maximum_pages=1,
            maximum_items=3,
        )
    else:
        earlier, later = _terminal_pair()

    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier,
        later_state=later,
    )

    assert evidence.comparison.disposition is expected
    assert evidence.bounded_traversal_incomplete is (
        expected is AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert evidence.account_status_current is False
    assert evidence.activity_history_complete is False
    assert evidence.additional_reconciliation_required is True


def test_receipt_binds_exact_heads_account_chain_and_commit_fence() -> None:
    earlier, later = _terminal_pair()
    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier,
        later_state=later,
    )
    commit_fence = _commit_fence(evidence.account_id)
    receipt = _alpaca_paper_authenticated_account_activity_comparison_receipt(
        evidence,
        earlier_source_head_sha256=HEAD_A,
        later_source_head_sha256=HEAD_B,
        commit_fence_receipt=commit_fence,
        account_sequence=2,
        previous_receipt_sha256="c" * 64,
    )

    assert HEAD_A in receipt.canonical_json
    assert HEAD_B in receipt.canonical_json
    assert commit_fence.semantic_sha256 in receipt.canonical_json
    assert receipt.previous_receipt_sha256 == "c" * 64

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="changed an exact source head",
    ):
        _alpaca_paper_authenticated_account_activity_comparison_receipt(
            evidence,
            earlier_source_head_sha256="d" * 64,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match=r"first.*predecessor",
    ):
        _alpaca_paper_authenticated_account_activity_comparison_receipt(
            evidence,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=commit_fence,
            account_sequence=1,
            previous_receipt_sha256="c" * 64,
        )
    stale = fence_receipt(
        account_id=evidence.account_id,
        validated_at=BASE,
        valid_until=VALID_UNTIL,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="predates a source commit",
    ):
        _alpaca_paper_authenticated_account_activity_comparison_receipt(
            evidence,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=stale,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


def test_validate_once_materialization_is_byte_stable_and_fail_closed() -> None:
    earlier, later = _terminal_pair()
    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier,
        later_state=later,
    )
    receipt = _alpaca_paper_authenticated_account_activity_comparison_receipt(
        evidence,
        earlier_source_head_sha256=HEAD_A,
        later_source_head_sha256=HEAD_B,
        commit_fence_receipt=_commit_fence(evidence.account_id),
        account_sequence=2,
        previous_receipt_sha256="c" * 64,
    )
    evidence_material = _materialize_authenticated_comparison_evidence(evidence)
    receipt_material = _materialize_authenticated_comparison_receipt(receipt)

    assert evidence_material.evidence_id == ("6d352819-ef4f-58d4-a613-5ac243f860f6")
    assert evidence_material.semantic_sha256 == (
        "bd059445d5259814c30feed3a79cf12978a1703f892360bc3a9f59f845184ce2"
    )
    assert receipt_material.receipt_id == ("43a3c61b-eef3-54c0-a16a-ba2a22172c96")
    assert receipt_material.semantic_sha256 == (
        "40c31c9d0bc3dc98e1c7b32a60f72ec50f1321b39260accbe591399b3d4c05ef"
    )
    assert evidence.canonical_json == evidence_material.canonical_json
    assert receipt.canonical_json == receipt_material.canonical_json

    object.__setattr__(
        evidence.comparison,
        "added_provider_activity_ids",
        ("forged-opaque-key",),
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="conflicts with exact sources",
    ):
        _ = receipt.semantic_sha256


def test_repository_cannot_change_evidence_heads_or_exact_fence() -> None:
    earlier, later = _terminal_pair()
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)
    substitute_earlier, substitute_later = _terminal_pair(
        later_bodies=(_body(_activity(2)),),
    )
    substitute = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=substitute_earlier,
        later_state=substitute_later,
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="changed authenticated evidence",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=_StateLoader(earlier, later),
            comparison_repository=_SubstitutingRepository(
                substitute,
                commit_fence,
            ),
        )

    wrong_fence = fence_receipt(
        account_id=earlier.prefix.plan.account_id,
        validated_at=BASE + timedelta(seconds=10),
        valid_until=VALID_UNTIL,
        fencing_generation=2,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="changed the exact account fence",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=_StateLoader(earlier, later),
            comparison_repository=_ComparisonRepository(wrong_fence),
        )


def test_append_failure_is_sanitized_without_changing_sources() -> None:
    earlier, later = _terminal_pair()
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)
    repository = _ComparisonRepository(commit_fence, fail=True)

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="append failed",
    ) as raised:
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=_StateLoader(earlier, later),
            comparison_repository=repository,
        )

    assert SECRET_MARKER not in str(raised.value)
    assert raised.value.__cause__ is None
    assert len(repository.calls) == 1


def test_proof_objects_are_immutable_and_reject_public_construction() -> None:
    earlier, later = _terminal_pair()
    evidence = _alpaca_paper_authenticated_account_activity_comparison_evidence(
        earlier_state=earlier,
        later_state=later,
    )
    receipt = _alpaca_paper_authenticated_account_activity_comparison_receipt(
        evidence,
        earlier_source_head_sha256=HEAD_A,
        later_source_head_sha256=HEAD_B,
        commit_fence_receipt=_commit_fence(evidence.account_id),
        account_sequence=1,
        previous_receipt_sha256=None,
    )

    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAuthenticatedAccountActivityComparisonEvidence()
    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperAuthenticatedAccountActivityComparisonReceipt()
    mutable_evidence: Any = evidence
    with pytest.raises(FrozenInstanceError):
        mutable_evidence.comparison = evidence.comparison
    mutable_receipt: Any = receipt
    with pytest.raises(FrozenInstanceError):
        mutable_receipt.account_sequence = 2


def test_same_plan_and_noncanonical_loader_results_fail_closed() -> None:
    earlier, later = _terminal_pair()
    commit_fence = _commit_fence(earlier.prefix.plan.account_id)
    loader = _StateLoader(earlier, later)
    repository = _ComparisonRepository(commit_fence)

    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="distinct plans",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            earlier.prefix.plan,
            fence=commit_fence.fence,
            state_loader=loader,
            comparison_repository=repository,
        )
    assert loader.calls == []

    loader.states[earlier.prefix.plan.capture_id] = object()  # type: ignore[assignment]
    with pytest.raises(
        AlpacaPaperAuthenticatedAccountActivityComparisonSourceConflict,
        match="exact Phase 4AE traversal state",
    ):
        compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
            earlier.prefix.plan,
            later.prefix.plan,
            fence=commit_fence.fence,
            state_loader=loader,
            comparison_repository=repository,
        )
