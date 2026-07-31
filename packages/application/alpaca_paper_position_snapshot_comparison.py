"""Durable authenticated comparison of two Alpaca paper position views.

Phase 4V accepts only an ordered pair of exact Phase 4T runtime plans.  The
roles in that plan are labels, not chronology: both durable Phase 4U receipts
are reloaded and Phase 4S must prove their strict raw-ingress order before a
comparison can be derived.  The result is historical, non-authorizing
evidence.  It performs no provider I/O and establishes neither snapshot
isolation, convergence, canonical positions, readiness, nor trading authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256,
    AlpacaPaperPositionSnapshotComparison,
    AlpacaPaperPositionSnapshotComparisonDisposition,
    AlpacaPaperPositionSnapshotComparisonError,
    _capture_profile_sha256,
    compare_alpaca_paper_position_snapshots,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotRuntimePlan,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION = (
    "phase4v-durable-authenticated-position-view-comparison-v1"
)
ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID = (
    "phase4v-exact-authenticated-position-view-comparison-policy-v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
        "comparison_policy",
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID,
        ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
        ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256,
        "ordered_pair_of_exact_runtime_plans_only",
        "roles_are_not_chronology",
        "same_expected_provider_account_identity",
        "credential_rotation_within_provider_account_is_allowed",
        "two_exact_durable_authenticated_position_receipts",
        "phase4s_proves_raw_ingress_order_and_derives_signed_receive_time_separation",
        "exact_phase4s_recomputation",
        "transaction_internal_current_account_fence_for_append_or_retry",
        "historical_receipt_fence_is_never_rewritten",
        "historical_non_authorizing_evidence",
    )
)


class AlpacaPaperAuthenticatedPositionViewComparisonError(RuntimeError):
    """Phase 4V could not derive or append exact authenticated evidence."""


class AlpacaPaperAuthenticatedPositionViewComparisonSourceMissing(
    AlpacaPaperAuthenticatedPositionViewComparisonError
):
    """A requested Phase 4U receipt is absent or its one-shot capture stalled."""


class AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
    AlpacaPaperAuthenticatedPositionViewComparisonError
):
    """Loaded sources, derived evidence, or a durable result conflict."""


class _NoAuthenticatedPositionViewComparisonAuthority:
    __slots__ = ()

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def provider_io_performed(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def capture_authenticated(self) -> bool:
        return False

    @property
    def durable_source_positions_authenticated(self) -> bool:
        return False

    @property
    def comparison_durably_recorded(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
        return False

    @property
    def snapshot_complete(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def reconciliation_complete(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def canonical_position_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_ledger_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_cash_fact_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
        return False

    @property
    def transport_submission_ready(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_runtime_plan(
    value: object,
    field_name: str,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    if type(value) is not AlpacaPaperPositionSnapshotRuntimePlan:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} must be an exact Phase 4T runtime plan"
        )
    try:
        value.__post_init__()
    except Exception:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} is invalid"
        ) from None
    return value


def _require_source_receipt(
    value: object,
    *,
    field_name: str,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    if type(value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} must be an exact Phase 4U receipt"
        )
    try:
        value._validate()
    except Exception:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} failed authenticated reconstruction"
        ) from None
    return value


@dataclass(frozen=True, slots=True)
class AlpacaPaperAuthenticatedPositionViewComparisonPlan(
    _NoAuthenticatedPositionViewComparisonAuthority
):
    """Ordered source roles for one Phase 4V application attempt.

    This object does not claim chronological order.  Only Phase 4S, after both
    Phase 4U receipts have been reloaded, may prove that the later source
    follows the earlier raw-ingress source.
    """

    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan

    def __post_init__(self) -> None:
        earlier = _require_runtime_plan(
            self.earlier_plan,
            "earlier position-view runtime plan",
        )
        later = _require_runtime_plan(
            self.later_plan,
            "later position-view runtime plan",
        )
        if earlier.description.account_id != later.description.account_id:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "position-view comparison plans belong to different accounts"
            )
        if (
            earlier.reference.expected_provider_account_id
            != later.reference.expected_provider_account_id
        ):
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "position-view comparison plans name different provider account identities"
            )
        if (
            earlier.plan_id == later.plan_id
            or earlier.description.capture_id == later.description.capture_id
        ):
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "authenticated position-view comparison requires distinct plans"
            )

    @property
    def account_id(self) -> str:
        self.__post_init__()
        return self.earlier_plan.description.account_id

    @property
    def comparison_plan_id(self) -> str:
        self.__post_init__()
        return canonical_id(
            "alpaca-paper-authenticated-position-view-comparison-plan",
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
            self.earlier_plan.plan_id,
            self.earlier_plan.semantic_sha256,
            self.later_plan.plan_id,
            self.later_plan.semantic_sha256,
        )

    @property
    def expected_provider_account_id(self) -> str:
        self.__post_init__()
        return self.earlier_plan.reference.expected_provider_account_id

    def _semantic_material(self) -> tuple[object, ...]:
        self.__post_init__()
        return (
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
            "authenticated_position_view_comparison_plan",
            self.comparison_plan_id,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
            self.account_id,
            self.expected_provider_account_id,
            self.earlier_plan.plan_id,
            self.earlier_plan.semantic_sha256,
            self.earlier_plan.description.capture_id,
            self.later_plan.plan_id,
            self.later_plan.semantic_sha256,
            self.later_plan.description.capture_id,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def create_authenticated_alpaca_paper_position_view_comparison_plan(
    *,
    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan,
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan,
) -> AlpacaPaperAuthenticatedPositionViewComparisonPlan:
    """Label two exact runtime plans without claiming their chronology."""

    return AlpacaPaperAuthenticatedPositionViewComparisonPlan(
        earlier_plan=earlier_plan,
        later_plan=later_plan,
    )


def _source_material(
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
) -> tuple[object, ...]:
    persisted = receipt.persisted_snapshot
    ingress = persisted.receipt
    return (
        receipt.plan.plan_id,
        receipt.plan.semantic_sha256,
        receipt.capture_id,
        receipt.receipt_id,
        receipt.semantic_sha256,
        persisted.semantic_sha256,
        ingress.receipt_id,
        ingress.semantic_sha256,
        ingress.ingress_sequence,
        persisted.observation.received_at,
        receipt.commit_fence_receipt.receipt_id,
        receipt.commit_fence_receipt.semantic_sha256,
        receipt.commit_fence_receipt.validated_at,
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionViewComparisonEvidence(
    _NoAuthenticatedPositionViewComparisonAuthority
):
    """Phase 4S result derived only from two authenticated Phase 4U receipts."""

    plan: AlpacaPaperAuthenticatedPositionViewComparisonPlan
    earlier_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt
    later_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt
    comparison: AlpacaPaperPositionSnapshotComparison

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionViewComparisonEvidence must be proof-constructed"
        )

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperAuthenticatedPositionViewComparisonPlan:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "authenticated position-view evidence requires an exact application plan"
            )
        self.plan.__post_init__()
        earlier = _require_source_receipt(
            self.earlier_receipt,
            field_name="earlier authenticated position-view receipt",
        )
        later = _require_source_receipt(
            self.later_receipt,
            field_name="later authenticated position-view receipt",
        )
        if earlier.plan != self.plan.earlier_plan or later.plan != self.plan.later_plan:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "authenticated position-view receipts conflict with the application plan"
            )
        if type(self.comparison) is not AlpacaPaperPositionSnapshotComparison:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "authenticated position-view evidence requires an exact Phase 4S comparison"
            )
        try:
            self.comparison._validate()
            expected = compare_alpaca_paper_position_snapshots(
                earlier.persisted_snapshot,
                later.persisted_snapshot,
            )
        except (
            AlpacaPaperPositionSnapshotComparisonError,
            AlpacaPaperPositionSnapshotConflict,
            TypeError,
            ValueError,
        ):
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "authenticated position-view sources cannot be compared exactly"
            ) from None
        if self.comparison != expected:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "authenticated position-view comparison conflicts with exact sources"
            )

    @property
    def account_id(self) -> str:
        self._validate()
        return self.plan.account_id

    @property
    def capture_profile_sha256(self) -> str:
        self._validate()
        return _capture_profile_sha256(self.earlier_receipt.persisted_snapshot)

    @property
    def expected_provider_account_id(self) -> str:
        self._validate()
        return self.plan.expected_provider_account_id

    @property
    def latest_source_committed_at(self) -> datetime:
        self._validate()
        return max(
            self.earlier_receipt.commit_fence_receipt.validated_at,
            self.later_receipt.commit_fence_receipt.validated_at,
        )

    @property
    def source_request_budgets_authenticated(self) -> bool:
        self._validate()
        return all(
            receipt.request_budget_enforced
            for receipt in (self.earlier_receipt, self.later_receipt)
        )

    @property
    def source_provider_evidence_authenticated(self) -> bool:
        self._validate()
        return all(
            receipt.authenticated_provider_evidence
            for receipt in (self.earlier_receipt, self.later_receipt)
        )

    @property
    def source_raw_responses_authenticated(self) -> bool:
        self._validate()
        return all(
            receipt.raw_response_persisted for receipt in (self.earlier_receipt, self.later_receipt)
        )

    @property
    def captures_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def evidence_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-authenticated-position-view-comparison-evidence",
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
            self.plan.comparison_plan_id,
            self.plan.semantic_sha256,
            self.earlier_receipt.receipt_id,
            self.earlier_receipt.semantic_sha256,
            self.later_receipt.receipt_id,
            self.later_receipt.semantic_sha256,
            self.comparison.semantic_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        comparison = self.comparison
        return (
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
            "authenticated_position_view_comparison_evidence",
            self.evidence_id,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
            self.plan.comparison_plan_id,
            self.plan.semantic_sha256,
            self.account_id,
            self.expected_provider_account_id,
            self.capture_profile_sha256,
            _source_material(self.earlier_receipt),
            _source_material(self.later_receipt),
            comparison.comparison_id,
            comparison.semantic_sha256,
            comparison.disposition,
            comparison.earlier_view_sha256,
            comparison.later_view_sha256,
            comparison.observed_utc_separation_microseconds,
            comparison.added_asset_ids,
            comparison.removed_asset_ids,
            comparison.changed_asset_ids,
            self.source_request_budgets_authenticated,
            self.source_provider_evidence_authenticated,
            self.source_raw_responses_authenticated,
            self.captures_authenticated,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _alpaca_paper_authenticated_position_view_comparison_evidence(
    *,
    plan: AlpacaPaperAuthenticatedPositionViewComparisonPlan,
    earlier_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    later_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
) -> AlpacaPaperAuthenticatedPositionViewComparisonEvidence:
    """Construct evidence only after exact Phase 4U receipt authentication."""

    if type(plan) is not AlpacaPaperAuthenticatedPositionViewComparisonPlan:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "position-view evidence requires an exact application plan"
        )
    plan.__post_init__()
    earlier = _require_source_receipt(
        earlier_receipt,
        field_name="earlier authenticated position-view receipt",
    )
    later = _require_source_receipt(
        later_receipt,
        field_name="later authenticated position-view receipt",
    )
    try:
        comparison = compare_alpaca_paper_position_snapshots(
            earlier.persisted_snapshot,
            later.persisted_snapshot,
        )
    except (AlpacaPaperPositionSnapshotComparisonError, TypeError, ValueError):
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "authenticated position-view sources cannot be compared exactly"
        ) from None
    evidence = object.__new__(AlpacaPaperAuthenticatedPositionViewComparisonEvidence)
    object.__setattr__(evidence, "plan", plan)
    object.__setattr__(evidence, "earlier_receipt", earlier)
    object.__setattr__(evidence, "later_receipt", later)
    object.__setattr__(evidence, "comparison", comparison)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionViewComparisonReceipt(
    _NoAuthenticatedPositionViewComparisonAuthority
):
    """Repository-produced append proof for one exact position-view pair."""

    evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence
    commit_fence_receipt: AccountFenceReceipt
    account_sequence: int
    previous_receipt_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionViewComparisonReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.evidence) is not AlpacaPaperAuthenticatedPositionViewComparisonEvidence:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "durable position-view comparison requires exact Phase 4V evidence"
            )
        self.evidence._validate()
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "durable position-view comparison requires an exact commit fence"
            )
        try:
            self.commit_fence_receipt._validate()
        except (AccountCoordinatorError, TypeError, ValueError):
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "durable position-view comparison commit fence is invalid"
            ) from None
        if self.commit_fence_receipt.fence.account_id != self.evidence.account_id:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "durable position-view comparison fence crosses account identities"
            )
        if self.commit_fence_receipt.validated_at < self.evidence.latest_source_committed_at:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "durable position-view comparison predates a source commit"
            )
        if type(self.account_sequence) is not int or self.account_sequence <= 0:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "durable position-view comparison sequence must be positive"
            )
        if self.account_sequence == 1:
            if self.previous_receipt_sha256 is not None:
                raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                    "first durable position-view comparison cannot name a predecessor"
                )
        else:
            _require_sha256(
                self.previous_receipt_sha256,
                "durable position-view comparison predecessor",
            )

    @property
    def account_id(self) -> str:
        self._validate()
        return self.evidence.account_id

    @property
    def recorded_at(self) -> datetime:
        self._validate()
        return self.commit_fence_receipt.validated_at

    @property
    def committed_at(self) -> datetime:
        return self.recorded_at

    @property
    def receipt_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-authenticated-position-view-comparison",
            self.evidence.evidence_id,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        return (
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
            "authenticated_position_view_comparison_receipt",
            self.receipt_id,
            self.evidence.evidence_id,
            self.evidence.semantic_sha256,
            self.commit_fence_receipt.receipt_id,
            self.commit_fence_receipt.semantic_sha256,
            self.recorded_at,
            self.account_sequence,
            self.previous_receipt_sha256,
            self.source_request_budgets_authenticated,
            self.source_provider_evidence_authenticated,
            self.source_raw_responses_authenticated,
            self.captures_authenticated,
            True,
            True,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())

    @property
    def source_request_budgets_authenticated(self) -> bool:
        self._validate()
        return self.evidence.source_request_budgets_authenticated

    @property
    def source_provider_evidence_authenticated(self) -> bool:
        self._validate()
        return self.evidence.source_provider_evidence_authenticated

    @property
    def source_raw_responses_authenticated(self) -> bool:
        self._validate()
        return self.evidence.source_raw_responses_authenticated

    @property
    def captures_authenticated(self) -> bool:
        self._validate()
        return self.evidence.captures_authenticated

    @property
    def durable_source_positions_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def comparison_durably_recorded(self) -> bool:
        self._validate()
        return True


def _alpaca_paper_authenticated_position_view_comparison_receipt(
    evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    *,
    commit_fence_receipt: AccountFenceReceipt,
    account_sequence: int,
    previous_receipt_sha256: str | None,
) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
    """Construct exactly the value a durable repository appended."""

    receipt = object.__new__(AlpacaPaperAuthenticatedPositionViewComparisonReceipt)
    for field_name, value in (
        ("evidence", evidence),
        ("commit_fence_receipt", commit_fence_receipt),
        ("account_sequence", account_sequence),
        ("previous_receipt_sha256", previous_receipt_sha256),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionViewComparisonResult(
    _NoAuthenticatedPositionViewComparisonAuthority
):
    """Typed application result binding the requested roles to durable proof."""

    plan: AlpacaPaperAuthenticatedPositionViewComparisonPlan
    receipt: AlpacaPaperAuthenticatedPositionViewComparisonReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionViewComparisonResult must be workflow-produced"
        )

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperAuthenticatedPositionViewComparisonPlan:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "position-view result requires an exact application plan"
            )
        if type(self.receipt) is not AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "position-view result requires an exact durable receipt"
            )
        self.plan.__post_init__()
        self.receipt._validate()
        if self.receipt.evidence.plan != self.plan:
            raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
                "position-view result receipt conflicts with the requested plan"
            )

    @property
    def result_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-authenticated-position-view-comparison-result",
            self.plan.comparison_plan_id,
            self.plan.semantic_sha256,
            self.receipt.receipt_id,
            self.receipt.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
                "authenticated_position_view_comparison_result",
                self.result_id,
                self.plan.semantic_sha256,
                self.receipt.semantic_sha256,
                self.durable_source_positions_authenticated,
                self.comparison_durably_recorded,
                False,
                False,
                False,
                False,
            )
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
                "authenticated_position_view_comparison_result",
                self.result_id,
                self.plan.semantic_sha256,
                self.receipt.semantic_sha256,
                self.durable_source_positions_authenticated,
                self.comparison_durably_recorded,
                False,
                False,
                False,
                False,
            )
        )

    @property
    def comparison(self) -> AlpacaPaperPositionSnapshotComparison:
        self._validate()
        return self.receipt.evidence.comparison

    @property
    def disposition(self) -> AlpacaPaperPositionSnapshotComparisonDisposition:
        return self.comparison.disposition

    @property
    def durable_source_positions_authenticated(self) -> bool:
        self._validate()
        return self.receipt.durable_source_positions_authenticated

    @property
    def comparison_durably_recorded(self) -> bool:
        self._validate()
        return self.receipt.comparison_durably_recorded


def _alpaca_paper_authenticated_position_view_comparison_result(
    plan: AlpacaPaperAuthenticatedPositionViewComparisonPlan,
    receipt: AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
) -> AlpacaPaperAuthenticatedPositionViewComparisonResult:
    result = object.__new__(AlpacaPaperAuthenticatedPositionViewComparisonResult)
    object.__setattr__(result, "plan", plan)
    object.__setattr__(result, "receipt", receipt)
    result._validate()
    return result


class AlpacaPaperPositionSnapshotReceiptLoader(Protocol):
    """Reload and authenticate one exact durable Phase 4U receipt."""

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None: ...


class AlpacaPaperPositionViewComparisonRepository(Protocol):
    """Append one derived comparison under the current account fence."""

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt: ...


def _load_exact_receipt(
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    loader: AlpacaPaperPositionSnapshotReceiptLoader,
    field_name: str,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    try:
        value = loader.load(plan)
    except AlpacaPaperAuthenticatedPositionViewComparisonError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} could not be reloaded and authenticated"
        ) from None
    if value is None:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceMissing(
            f"{field_name} is absent or stalled"
        )
    receipt = _require_source_receipt(value, field_name=field_name)
    if receipt.plan != plan:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            f"{field_name} loader returned another plan"
        )
    return receipt


def compare_and_record_authenticated_alpaca_paper_position_snapshots(
    plan: AlpacaPaperAuthenticatedPositionViewComparisonPlan,
    *,
    fence: AccountFence,
    snapshot_loader: AlpacaPaperPositionSnapshotReceiptLoader,
    comparison_repository: AlpacaPaperPositionViewComparisonRepository,
) -> AlpacaPaperAuthenticatedPositionViewComparisonResult:
    """Reload, derive, and durably append one exact authenticated pair."""

    if type(plan) is not AlpacaPaperAuthenticatedPositionViewComparisonPlan:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "authenticated position-view comparison requires an exact application plan"
        )
    plan.__post_init__()
    if type(fence) is not AccountFence:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "authenticated position-view comparison requires an exact account fence"
        )
    try:
        fence.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError):
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "authenticated position-view comparison fence is invalid"
        ) from None
    if fence.account_id != plan.account_id:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "authenticated position-view comparison fence crosses account identities"
        )
    if not callable(getattr(snapshot_loader, "load", None)):
        raise AlpacaPaperAuthenticatedPositionViewComparisonError(
            "position-snapshot loader does not implement load"
        )
    if not callable(getattr(comparison_repository, "record", None)):
        raise AlpacaPaperAuthenticatedPositionViewComparisonError(
            "position-view comparison repository does not implement record"
        )

    earlier_receipt = _load_exact_receipt(
        plan.earlier_plan,
        loader=snapshot_loader,
        field_name="earlier authenticated position-view receipt",
    )
    later_receipt = _load_exact_receipt(
        plan.later_plan,
        loader=snapshot_loader,
        field_name="later authenticated position-view receipt",
    )
    evidence = _alpaca_paper_authenticated_position_view_comparison_evidence(
        plan=plan,
        earlier_receipt=earlier_receipt,
        later_receipt=later_receipt,
    )
    try:
        receipt = comparison_repository.record(evidence, fence=fence)
    except AlpacaPaperAuthenticatedPositionViewComparisonError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "authenticated position-view comparison append failed"
        ) from None
    if type(receipt) is not AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "position-view comparison repository returned a non-canonical receipt"
        )
    try:
        receipt._validate()
    except (
        AlpacaPaperAuthenticatedPositionViewComparisonError,
        TypeError,
        ValueError,
    ):
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "position-view comparison repository returned invalid durable evidence"
        ) from None
    if receipt.evidence != evidence:
        raise AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict(
            "position-view comparison repository changed authenticated evidence"
        )
    return _alpaca_paper_authenticated_position_view_comparison_result(
        plan,
        receipt,
    )


__all__ = [
    "ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION",
    "ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_ID",
    "ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256",
    "AlpacaPaperAuthenticatedPositionViewComparisonError",
    "AlpacaPaperAuthenticatedPositionViewComparisonEvidence",
    "AlpacaPaperAuthenticatedPositionViewComparisonPlan",
    "AlpacaPaperAuthenticatedPositionViewComparisonReceipt",
    "AlpacaPaperAuthenticatedPositionViewComparisonResult",
    "AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict",
    "AlpacaPaperAuthenticatedPositionViewComparisonSourceMissing",
    "AlpacaPaperPositionSnapshotReceiptLoader",
    "AlpacaPaperPositionViewComparisonRepository",
    "compare_and_record_authenticated_alpaca_paper_position_snapshots",
    "create_authenticated_alpaca_paper_position_view_comparison_plan",
]
