from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import timedelta
from uuid import UUID

import pytest

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    AlpacaPaperPositionSnapshotComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID,
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    AlpacaPaperAuthenticatedPositionViewComparisonPlan,
    AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
    AlpacaPaperAuthenticatedPositionViewComparisonResult,
    AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
    AlpacaPaperAuthenticatedPositionViewComparisonSourceMissing,
    _alpaca_paper_authenticated_position_view_comparison_evidence,
    _alpaca_paper_authenticated_position_view_comparison_receipt,
    compare_and_record_authenticated_alpaca_paper_position_snapshots,
    create_authenticated_alpaca_paper_position_view_comparison_plan,
)
from packages.domain.account_coordinator import AccountFence, AccountFenceReceipt
from tests.unit.test_alpaca_paper_account_asset_ingress import _account_body
from tests.unit.test_alpaca_paper_account_runtime import (
    FixedTransport as AccountTransport,
)
from tests.unit.test_alpaca_paper_account_runtime import (
    _scenario as account_scenario,
)
from tests.unit.test_alpaca_paper_position_snapshot_runtime import (
    BASE,
    VALID_UNTIL,
    SnapshotRuntime,
    Transport,
    _body,
    _clock_with_response_at,
    _position,
    _scenario,
)
from tests.unit.test_submission_attempt import fence_receipt


def _receipt_pair(
    suffix: str,
    *,
    later_received_at_offset: timedelta = timedelta(milliseconds=90),
    earlier_body: bytes | None = None,
    later_body: bytes | None = None,
) -> tuple[
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
]:
    earlier_scenario = _scenario(body=earlier_body or _body(_position(1)))
    earlier_scenario.plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=earlier_scenario.plan.description.account_id,
            capture_idempotency_key=f"phase4v-{suffix}-earlier-capture",
        ),
        reference=earlier_scenario.plan.reference,
        account_binding=earlier_scenario.plan.account_binding,
    )
    earlier = earlier_scenario.run()

    later_scenario = _scenario(body=later_body or _body(_position(1)))
    later_scenario.plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=earlier.account_id,
            capture_idempotency_key=f"phase4v-{suffix}-later-capture",
        ),
        reference=earlier.plan.reference,
        account_binding=earlier.plan.account_binding,
    )
    later_scenario.ingress = earlier_scenario.ingress
    later_scenario.snapshots = SnapshotRuntime(later_scenario.events)
    later_scenario.transport = Transport(
        later_scenario.events,
        body=later_body or _body(_position(1)),
        request_id=f"phase4v-{suffix}-later-request",
    )
    later_scenario.clock = _clock_with_response_at(BASE + later_received_at_offset)
    later = later_scenario.run()

    assert earlier.persisted_snapshot.receipt.ingress_sequence == 1
    assert later.persisted_snapshot.receipt.ingress_sequence == 2
    return earlier, later


class _Loader:
    def __init__(
        self,
        *receipts: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    ) -> None:
        self.receipts = {receipt.plan.plan_id: receipt for receipt in receipts}
        self.calls: list[AlpacaPaperPositionSnapshotRuntimePlan] = []

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        self.calls.append(plan)
        return self.receipts.get(plan.plan_id)


class _Repository:
    def __init__(self, commit_fence: AccountFenceReceipt) -> None:
        self.commit_fence = commit_fence
        self.calls: list[
            tuple[AlpacaPaperAuthenticatedPositionViewComparisonEvidence, AccountFence]
        ] = []

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        self.calls.append((evidence, fence))
        assert fence == self.commit_fence.fence
        return _alpaca_paper_authenticated_position_view_comparison_receipt(
            evidence,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


class _SubstitutingRepository:
    def __init__(
        self,
        substitute: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        commit_fence: AccountFenceReceipt,
    ) -> None:
        self.substitute = substitute
        self.commit_fence = commit_fence

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        del evidence
        assert fence == self.commit_fence.fence
        return _alpaca_paper_authenticated_position_view_comparison_receipt(
            self.substitute,
            commit_fence_receipt=self.commit_fence,
            account_sequence=1,
            previous_receipt_sha256=None,
        )


def _comparison_plan(
    earlier: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    later: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
) -> AlpacaPaperAuthenticatedPositionViewComparisonPlan:
    return create_authenticated_alpaca_paper_position_view_comparison_plan(
        earlier_plan=earlier.plan,
        later_plan=later.plan,
    )


def _commit_fence(account_id: str) -> AccountFenceReceipt:
    return fence_receipt(
        account_id=account_id,
        validated_at=BASE + timedelta(seconds=1),
        valid_until=VALID_UNTIL,
    )


def _assert_no_higher_authority(value: object) -> None:
    for property_name in (
        "request_budget_enforced",
        "authenticated_provider_evidence",
        "raw_response_persisted",
        "provider_io_performed",
        "runtime_current",
        "capture_authenticated",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
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
        "reservation_release_authorized",
        "resubmission_authorized",
        "canonical_position_fact_authorized",
        "canonical_execution_fact_authorized",
        "canonical_account_fact_authorized",
        "canonical_ledger_fact_authorized",
        "canonical_cash_fact_authorized",
        "readiness_transition_authorized",
        "reconciliation_ready",
        "dispatch_preflight_ready",
        "paper_startup_ready",
        "transport_submission_ready",
        "submission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
        "converged",
    ):
        assert getattr(value, property_name) is False


def test_typed_workflow_reloads_roles_derives_and_records_exact_sources() -> None:
    earlier, later = _receipt_pair("happy")
    plan = _comparison_plan(earlier, later)
    loader = _Loader(earlier, later)
    commit_fence = _commit_fence(plan.account_id)
    repository = _Repository(commit_fence)

    result = compare_and_record_authenticated_alpaca_paper_position_snapshots(
        plan,
        fence=commit_fence.fence,
        snapshot_loader=loader,
        comparison_repository=repository,
    )

    assert ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION == (
        "phase4v-durable-authenticated-position-view-comparison-v1"
    )
    assert ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID == (
        "phase4v-exact-authenticated-position-view-comparison-policy-v1"
    )
    assert len(ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256) == 64
    assert loader.calls == [earlier.plan, later.plan]
    assert len(repository.calls) == 1
    assert result.plan == plan
    assert result.receipt.evidence.earlier_receipt == earlier
    assert result.receipt.evidence.later_receipt == later
    assert result.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert result.durable_source_positions_authenticated is True
    assert result.comparison_durably_recorded is True
    assert result.receipt.source_request_budgets_authenticated is True
    assert result.receipt.source_provider_evidence_authenticated is True
    assert result.receipt.source_raw_responses_authenticated is True
    assert result.receipt.captures_authenticated is True


def test_raw_ingress_order_allows_negative_signed_receive_separation() -> None:
    earlier, later = _receipt_pair(
        "negative-separation",
        later_received_at_offset=timedelta(milliseconds=85),
    )
    plan = _comparison_plan(earlier, later)
    commit_fence = _commit_fence(plan.account_id)

    result = compare_and_record_authenticated_alpaca_paper_position_snapshots(
        plan,
        fence=commit_fence.fence,
        snapshot_loader=_Loader(earlier, later),
        comparison_repository=_Repository(commit_fence),
    )

    assert later.persisted_snapshot.observation.received_at < (
        earlier.persisted_snapshot.observation.received_at
    )
    assert result.comparison.observed_utc_separation_microseconds == -5_000
    assert result.disposition is (
        AlpacaPaperPositionSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert result.comparison.monotonic_timing_qualified is False


def test_plan_roles_do_not_claim_chronology_and_phase4s_rejects_swap() -> None:
    earlier, later = _receipt_pair("swapped")
    swapped = create_authenticated_alpaca_paper_position_view_comparison_plan(
        earlier_plan=later.plan,
        later_plan=earlier.plan,
    )
    commit_fence = _commit_fence(swapped.account_id)

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        match="cannot be compared exactly",
    ):
        compare_and_record_authenticated_alpaca_paper_position_snapshots(
            swapped,
            fence=commit_fence.fence,
            snapshot_loader=_Loader(earlier, later),
            comparison_repository=_Repository(commit_fence),
        )


def test_plan_rejects_distinct_provider_account_identities() -> None:
    earlier, _ = _receipt_pair("provider-identity")
    other_provider_account_id = str(UUID(int=42))
    account_payload = json.loads(_account_body())
    assert type(account_payload) is dict
    account_payload["id"] = other_provider_account_id
    other_account = account_scenario(
        expected_provider_account_id=other_provider_account_id,
        transport=AccountTransport(
            body=json.dumps(account_payload, separators=(",", ":")).encode(),
        ),
    )
    other_binding = other_account.run()
    other_plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=earlier.account_id,
            capture_idempotency_key="phase4v-cross-provider-capture",
        ),
        reference=other_account.reference,
        account_binding=other_binding,
    )

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        match="different provider account identities",
    ):
        create_authenticated_alpaca_paper_position_view_comparison_plan(
            earlier_plan=earlier.plan,
            later_plan=other_plan,
        )


def test_plan_allows_credential_rotation_within_same_provider_account() -> None:
    earlier, _ = _receipt_pair("credential-rotation")
    rotated_account = account_scenario()
    rotated_account.reference = AlpacaPaperCredentialReference(
        account_id=earlier.account_id,
        expected_provider_account_id=(earlier.plan.reference.expected_provider_account_id),
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-002",
    )
    rotated_binding = rotated_account.run()
    rotated_plan = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=earlier.account_id,
            capture_idempotency_key="phase4v-rotated-credential-capture",
        ),
        reference=rotated_account.reference,
        account_binding=rotated_binding,
    )

    plan = create_authenticated_alpaca_paper_position_view_comparison_plan(
        earlier_plan=earlier.plan,
        later_plan=rotated_plan,
    )

    assert plan.earlier_plan.account_binding != plan.later_plan.account_binding
    assert plan.earlier_plan.reference.secret_version != plan.later_plan.reference.secret_version
    assert plan.expected_provider_account_id == (
        earlier.plan.reference.expected_provider_account_id
    )


def test_absent_or_substituted_source_fails_before_append() -> None:
    earlier, later = _receipt_pair("source-failure")
    plan = _comparison_plan(earlier, later)
    commit_fence = _commit_fence(plan.account_id)
    repository = _Repository(commit_fence)

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceMissing,
        match="absent or stalled",
    ):
        compare_and_record_authenticated_alpaca_paper_position_snapshots(
            plan,
            fence=commit_fence.fence,
            snapshot_loader=_Loader(earlier),
            comparison_repository=repository,
        )
    assert repository.calls == []

    substituting_loader = _Loader(earlier, later)
    substituting_loader.receipts[earlier.plan.plan_id] = later
    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        match="another plan",
    ):
        compare_and_record_authenticated_alpaca_paper_position_snapshots(
            plan,
            fence=commit_fence.fence,
            snapshot_loader=substituting_loader,
            comparison_repository=repository,
        )
    assert repository.calls == []


def test_repository_cannot_substitute_other_authenticated_evidence() -> None:
    earlier, later = _receipt_pair("requested")
    substitute_earlier, substitute_later = _receipt_pair("substitute")
    plan = _comparison_plan(earlier, later)
    substitute_plan = _comparison_plan(substitute_earlier, substitute_later)
    substitute = _alpaca_paper_authenticated_position_view_comparison_evidence(
        plan=substitute_plan,
        earlier_receipt=substitute_earlier,
        later_receipt=substitute_later,
    )
    commit_fence = _commit_fence(plan.account_id)

    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        match="changed authenticated evidence",
    ):
        compare_and_record_authenticated_alpaca_paper_position_snapshots(
            plan,
            fence=commit_fence.fence,
            snapshot_loader=_Loader(earlier, later),
            comparison_repository=_SubstitutingRepository(
                substitute,
                commit_fence,
            ),
        )


def test_proof_construction_distinct_plan_and_account_fence_fail_closed() -> None:
    earlier, later = _receipt_pair("proofs")
    plan = _comparison_plan(earlier, later)
    commit_fence = _commit_fence(plan.account_id)
    result = compare_and_record_authenticated_alpaca_paper_position_snapshots(
        plan,
        fence=commit_fence.fence,
        snapshot_loader=_Loader(earlier, later),
        comparison_repository=_Repository(commit_fence),
    )

    with pytest.raises(TypeError):
        AlpacaPaperAuthenticatedPositionViewComparisonEvidence()
    with pytest.raises(TypeError):
        AlpacaPaperAuthenticatedPositionViewComparisonReceipt()
    with pytest.raises(TypeError):
        AlpacaPaperAuthenticatedPositionViewComparisonResult()
    with pytest.raises(FrozenInstanceError):
        plan.earlier_plan = later.plan  # type: ignore[misc]
    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        match="distinct plans",
    ):
        AlpacaPaperAuthenticatedPositionViewComparisonPlan(
            earlier_plan=earlier.plan,
            later_plan=earlier.plan,
        )
    with pytest.raises(
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        match="crosses account identities",
    ):
        compare_and_record_authenticated_alpaca_paper_position_snapshots(
            plan,
            fence=fence_receipt(
                account_id="another-account",
                validated_at=BASE + timedelta(seconds=1),
                valid_until=VALID_UNTIL,
            ).fence,
            snapshot_loader=_Loader(earlier, later),
            comparison_repository=_Repository(commit_fence),
        )

    for value in (
        plan,
        result.receipt.evidence,
        result.receipt,
        result,
    ):
        _assert_no_higher_authority(value)
    assert result.receipt.evidence.durable_source_positions_authenticated is False
    assert result.receipt.evidence.comparison_durably_recorded is False
    assert result.receipt.durable_source_positions_authenticated is True
    assert result.receipt.comparison_durably_recorded is True
