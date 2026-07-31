from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import timedelta
from time import perf_counter

import pytest

import packages.application.alpaca_paper_order_snapshot_comparison as comparison_application
from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    AlpacaPaperOrderSnapshotComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    _alpaca_paper_authenticated_order_snapshot_prefix,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPlan,
    create_alpaca_paper_order_snapshot_plan,
)
from packages.application.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_ID,
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
    AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
    AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
    AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing,
    _alpaca_paper_authenticated_order_view_comparison_evidence,
    _alpaca_paper_authenticated_order_view_comparison_receipt,
    compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from tests.unit.test_alpaca_paper_order_snapshot_runtime import (
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
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order
from tests.unit.test_submission_attempt import fence_receipt

HEAD_A = "a" * 64
HEAD_B = "b" * 64


def _authenticated_prefix(
    *,
    capture_key: str,
    bodies: tuple[bytes, ...],
    page_limit: int = 2,
    maximum_pages: int = 3,
    ingress: InMemoryIngress | None = None,
    account_source: tuple[object, object] | None = None,
) -> tuple[
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    InMemoryIngress,
    tuple[object, object],
]:
    scenario = _scenario(body=bodies[0], page_limit=page_limit)
    if account_source is not None:
        scenario.reference = account_source[0]  # type: ignore[assignment]
        scenario.binding = account_source[1]  # type: ignore[assignment]
    source = (scenario.reference, scenario.binding)
    plan = create_alpaca_paper_order_snapshot_plan(
        account_id=scenario.reference.account_id,
        capture_idempotency_key=capture_key,
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )
    events: list[str] = []
    pages = PageRuntime(events)
    raw = ingress or InMemoryIngress(events)
    prefix = pages.load_prefix(plan)
    for page_number, body in enumerate(bodies, start=1):
        description = prefix.next_page_description
        assert description is not None
        scenario.description = description
        scenario.resolver = Resolver(events)
        scenario.transport = Transport(
            events,
            body=body,
            request_id=f"phase4p-provider-request-{capture_key}-{page_number}",
        )
        scenario.budget = Budget(events)
        scenario.identities = Identities(events)
        scenario.coordinator = Coordinator(events)
        scenario.ingress = raw
        scenario.pages = pages
        scenario.clock = _clock()
        scenario.events = events
        scenario.run()
        prefix = pages.load_prefix(plan)
    return prefix, raw, source


def _terminal_pair(
    *,
    earlier_bodies: tuple[bytes, ...] | None = None,
    later_bodies: tuple[bytes, ...] | None = None,
    page_limit: int = 2,
    maximum_pages: int = 3,
) -> tuple[
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
]:
    earlier, ingress, account_source = _authenticated_prefix(
        capture_key="phase4p-earlier-capture",
        bodies=earlier_bodies or (_body(_order(1)),),
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )
    later, _, _ = _authenticated_prefix(
        capture_key="phase4p-later-capture",
        bodies=later_bodies or (_body(_order(1)),),
        page_limit=page_limit,
        maximum_pages=maximum_pages,
        ingress=ingress,
        account_source=account_source,
    )
    return earlier, later


class _PrefixLoader:
    def __init__(
        self,
        *prefixes: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    ) -> None:
        self.prefixes = {prefix.plan.snapshot_id: prefix for prefix in prefixes}
        self.calls: list[AlpacaPaperOrderSnapshotPlan] = []

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        self.calls.append(plan)
        return self.prefixes.get(
            plan.snapshot_id,
            _alpaca_paper_authenticated_order_snapshot_prefix(
                plan,
                page_receipts=(),
            ),
        )


class _ComparisonRepository:
    def __init__(self, commit_fence: AccountFenceReceipt) -> None:
        self.commit_fence = commit_fence
        self.calls: list[
            tuple[AlpacaPaperAuthenticatedOrderViewComparisonEvidence, AccountFence]
        ] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        self.calls.append((evidence, fence))
        assert fence == self.commit_fence.fence
        return _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


class _SubstitutingComparisonRepository:
    def __init__(
        self,
        substitute: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        commit_fence: AccountFenceReceipt,
    ) -> None:
        self.substitute = substitute
        self.commit_fence = commit_fence

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        del evidence
        assert fence == self.commit_fence.fence
        return _alpaca_paper_authenticated_order_view_comparison_receipt(
            self.substitute,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


def _commit_fence(account_id: str) -> AccountFenceReceipt:
    return fence_receipt(
        account_id=account_id,
        validated_at=BASE + timedelta(seconds=1),
        valid_until=VALID_UNTIL,
    )


def _assert_no_higher_authority(value: object) -> None:
    for property_name in (
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
        assert getattr(value, property_name) is False


def test_workflow_reloads_exact_sources_derives_and_records_one_pair() -> None:
    earlier, later = _terminal_pair()
    loader = _PrefixLoader(earlier, later)
    commit_fence = _commit_fence(earlier.plan.account_id)
    repository = _ComparisonRepository(commit_fence)

    receipt = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        earlier.plan,
        later.plan,
        fence=commit_fence.fence,
        prefix_loader=loader,
        comparison_repository=repository,
    )
    repeated = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
        earlier.plan,
        later.plan,
        fence=commit_fence.fence,
        prefix_loader=loader,
        comparison_repository=repository,
    )

    assert ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION == (
        "phase4p-durable-authenticated-order-view-comparison-v1"
    )
    assert ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_ID == (
        "phase4p-exact-authenticated-order-view-comparison-policy-v1"
    )
    assert ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256 == (
        "376473078cb8e515ce18f1cdb78b0166c1a1f2b0f7e14b0be644ddad56914b0c"
    )
    assert loader.calls == [earlier.plan, later.plan, earlier.plan, later.plan]
    assert len(repository.calls) == 2
    assert receipt == repeated
    assert receipt.receipt_id == repeated.receipt_id
    assert receipt.semantic_sha256 == repeated.semantic_sha256
    assert receipt.evidence.comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert receipt.evidence.earlier_plan_id == earlier.plan.snapshot_id
    assert receipt.evidence.later_plan_id == later.plan.snapshot_id
    assert receipt.evidence.earlier_prefix_sha256 == earlier.semantic_sha256
    assert receipt.evidence.later_prefix_sha256 == later.semantic_sha256
    assert receipt.evidence.earlier_terminal_page_receipt_id == (
        earlier.page_receipts[-1].receipt_id
    )
    assert receipt.evidence.later_terminal_page_receipt_sha256 == (
        later.page_receipts[-1].semantic_sha256
    )
    assert receipt.evidence.source_request_budgets_authenticated is True
    assert receipt.evidence.source_raw_responses_authenticated is True
    assert receipt.evidence.captures_authenticated is True
    assert receipt.evidence.durable_source_positions_authenticated is False
    assert receipt.evidence.comparison_durably_recorded is False
    assert receipt.earlier_source_head_sha256 == HEAD_A
    assert receipt.later_source_head_sha256 == HEAD_B
    assert receipt.durable_source_positions_authenticated is True
    assert receipt.comparison_durably_recorded is True
    assert receipt.recorded_at == commit_fence.validated_at
    assert receipt.account_sequence == 1
    assert receipt.previous_receipt_sha256 is None
    _assert_no_higher_authority(receipt.evidence)
    _assert_no_higher_authority(receipt)


def test_bounded_truncation_is_retained_only_as_incomplete_evidence() -> None:
    full_pages = (
        _body(_order(6), _order(5)),
        _body(_order(4), _order(3)),
        _body(_order(2), _order(1)),
    )
    earlier, later = _terminal_pair(
        earlier_bodies=full_pages,
        later_bodies=full_pages,
        page_limit=2,
        maximum_pages=3,
    )

    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=later,
    )

    assert earlier.capture.bounded_truncation is True
    assert later.capture.bounded_truncation is True
    assert evidence.bounded_traversal_incomplete is True
    assert evidence.comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert evidence.comparison.order_views_equal is True
    assert evidence.provider_snapshot_complete is False
    assert evidence.converged is False
    assert evidence.readiness_transition_authorized is False
    assert evidence.reconciliation_completion_authorized is False


def test_active_or_absent_prefix_fails_before_durable_append() -> None:
    earlier, ingress, account_source = _authenticated_prefix(
        capture_key="phase4p-active-capture",
        bodies=(_body(_order(2), _order(1)),),
        page_limit=2,
        maximum_pages=3,
    )
    assert earlier.capture.next_page_description is not None
    later, _, _ = _authenticated_prefix(
        capture_key="phase4p-terminal-after-active",
        bodies=(_body(_order(1)),),
        ingress=ingress,
        account_source=account_source,
    )
    loader = _PrefixLoader(earlier, later)
    commit_fence = _commit_fence(earlier.plan.account_id)
    repository = _ComparisonRepository(commit_fence)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing,
        match="not terminal",
    ):
        compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            earlier.plan,
            later.plan,
            fence=commit_fence.fence,
            prefix_loader=loader,
            comparison_repository=repository,
        )

    assert repository.calls == []

    missing_plan = create_alpaca_paper_order_snapshot_plan(
        account_id=later.plan.account_id,
        capture_idempotency_key="phase4p-missing-capture",
        page_limit=later.plan.page_limit,
        maximum_pages=later.plan.maximum_pages,
    )
    missing_loader = _PrefixLoader(later)
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing,
        match="no committed page",
    ):
        compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            later.plan,
            missing_plan,
            fence=commit_fence.fence,
            prefix_loader=missing_loader,
            comparison_repository=repository,
        )
    assert repository.calls == []


def test_loader_cannot_substitute_another_terminal_plan() -> None:
    earlier, later = _terminal_pair()
    loader = _PrefixLoader(earlier, later)
    loader.prefixes[earlier.plan.snapshot_id] = later
    commit_fence = _commit_fence(earlier.plan.account_id)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="another plan",
    ):
        compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            earlier.plan,
            later.plan,
            fence=commit_fence.fence,
            prefix_loader=loader,
            comparison_repository=_ComparisonRepository(commit_fence),
        )


def test_workflow_rejects_same_plan_and_cross_account_fence_before_loading() -> None:
    earlier, later = _terminal_pair()
    loader = _PrefixLoader(earlier, later)
    commit_fence = _commit_fence(earlier.plan.account_id)
    repository = _ComparisonRepository(commit_fence)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="distinct plans",
    ):
        compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            earlier.plan,
            earlier.plan,
            fence=commit_fence.fence,
            prefix_loader=loader,
            comparison_repository=repository,
        )
    assert loader.calls == []

    wrong_fence = AccountFence(
        account_id="another-paper-account",
        owner_id=commit_fence.fence.owner_id,
        lease_id="lease-another-paper-account",
        fencing_generation=commit_fence.fence.fencing_generation,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="crosses account",
    ):
        compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            earlier.plan,
            later.plan,
            fence=wrong_fence,
            prefix_loader=loader,
            comparison_repository=repository,
        )
    assert loader.calls == []


def test_receipt_binds_distinct_heads_fence_time_and_account_chain() -> None:
    earlier, later = _terminal_pair()
    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=later,
    )
    commit_fence = _commit_fence(earlier.plan.account_id)

    receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
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

    changed_head_receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
        evidence,
        earlier_source_head_sha256="d" * 64,
        later_source_head_sha256=HEAD_B,
        commit_fence_receipt=commit_fence,
        account_sequence=2,
        previous_receipt_sha256="c" * 64,
    )
    assert changed_head_receipt.receipt_id == receipt.receipt_id
    assert changed_head_receipt.semantic_sha256 != receipt.semantic_sha256

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="distinct durable heads",
    ):
        _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_A,
            commit_fence_receipt=commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="lowercase SHA-256",
    ):
        _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256="not-a-head-digest",
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match=r"first.*predecessor",
    ):
        _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=commit_fence,
            account_sequence=1,
            previous_receipt_sha256="c" * 64,
        )
    stale_commit_fence = fence_receipt(
        account_id=earlier.plan.account_id,
        validated_at=BASE,
        valid_until=VALID_UNTIL,
    )
    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="predates",
    ):
        _alpaca_paper_authenticated_order_view_comparison_receipt(
            evidence,
            earlier_source_head_sha256=HEAD_A,
            later_source_head_sha256=HEAD_B,
            commit_fence_receipt=stale_commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


def test_receipt_digest_keeps_authenticated_source_validation_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    earlier, later = _terminal_pair()
    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=later,
    )
    receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
        evidence,
        earlier_source_head_sha256=HEAD_A,
        later_source_head_sha256=HEAD_B,
        commit_fence_receipt=_commit_fence(earlier.plan.account_id),
        account_sequence=1,
        previous_receipt_sha256=None,
    )
    original_terminal_prefix = comparison_application._terminal_prefix
    terminal_prefix_calls = 0

    def counted_terminal_prefix(
        value: object,
        *,
        field_name: str,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        nonlocal terminal_prefix_calls
        terminal_prefix_calls += 1
        return original_terminal_prefix(value, field_name=field_name)

    monkeypatch.setattr(
        comparison_application,
        "_terminal_prefix",
        counted_terminal_prefix,
    )

    started_at = perf_counter()
    digest = receipt.semantic_sha256
    elapsed = perf_counter() - started_at

    assert len(digest) == 64
    assert 2 <= terminal_prefix_calls <= 4
    assert elapsed < 1.0


def test_repository_cannot_substitute_other_authenticated_evidence() -> None:
    earlier, ingress, account_source = _authenticated_prefix(
        capture_key="phase4p-substitution-earlier",
        bodies=(_body(_order(1)),),
    )
    later, ingress, _ = _authenticated_prefix(
        capture_key="phase4p-substitution-later",
        bodies=(_body(_order(1)),),
        ingress=ingress,
        account_source=account_source,
    )
    substitute_later, _, _ = _authenticated_prefix(
        capture_key="phase4p-substitution-other-later",
        bodies=(_body(_order(2)),),
        ingress=ingress,
        account_source=account_source,
    )
    substitute = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=substitute_later,
    )
    commit_fence = _commit_fence(earlier.plan.account_id)

    with pytest.raises(
        AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict,
        match="changed authenticated evidence",
    ):
        compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            earlier.plan,
            later.plan,
            fence=commit_fence.fence,
            prefix_loader=_PrefixLoader(earlier, later),
            comparison_repository=_SubstitutingComparisonRepository(
                substitute,
                commit_fence,
            ),
        )


def test_proof_objects_reject_public_construction_and_mutation() -> None:
    earlier, later = _terminal_pair()
    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier,
        later_prefix=later,
    )
    receipt = _alpaca_paper_authenticated_order_view_comparison_receipt(
        evidence,
        earlier_source_head_sha256=HEAD_A,
        later_source_head_sha256=HEAD_B,
        commit_fence_receipt=_commit_fence(earlier.plan.account_id),
        account_sequence=1,
        previous_receipt_sha256=None,
    )

    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAuthenticatedOrderViewComparisonEvidence()
    with pytest.raises(TypeError, match="repository-produced"):
        AlpacaPaperAuthenticatedOrderViewComparisonReceipt()
    with pytest.raises(FrozenInstanceError):
        evidence.comparison = evidence.comparison  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        receipt.account_sequence = 2  # type: ignore[misc]
