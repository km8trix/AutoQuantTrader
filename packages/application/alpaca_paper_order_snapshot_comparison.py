"""Durable, authenticated comparison of two Alpaca paper order views.

Phase 4P reloads two exact terminal Phase 4O prefixes, derives the Phase 4N
comparison from those authenticated values, and asks a repository to append
the resulting evidence under an account fence.  The comparison remains
historical and non-authorizing: durable provenance is not provider snapshot
isolation, trusted timing, convergence, lifecycle application, or trading
authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
    AlpacaPaperOrderSnapshotComparison,
    AlpacaPaperOrderSnapshotComparisonDisposition,
    AlpacaPaperOrderSnapshotComparisonError,
    _timedelta_microseconds,
    _traversal_profile_sha256,
    _utc_separation,
    _view_sha256,
    compare_alpaca_paper_order_snapshot_captures,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotConflict,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotCapture,
    AlpacaPaperOrderSnapshotPlan,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION = (
    "phase4p-durable-authenticated-order-view-comparison-v1"
)
ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_ID = (
    "phase4p-exact-authenticated-order-view-comparison-policy-v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION,
        "comparison_policy",
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_ID,
        ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
        ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
        "two_exact_terminal_authenticated_prefixes",
        "cursor_exhaustion_or_bounded_truncation",
        "same_account_and_traversal_profile",
        "distinct_capture_and_raw_ingress_sources",
        "strict_account_local_raw_ingress_order",
        "exact_phase4n_recomputation",
        "transaction_internal_account_fence_for_append_only",
        "historical_non_authorizing_evidence",
    )
)


class AlpacaPaperAuthenticatedOrderViewComparisonError(RuntimeError):
    """Phase 4P could not derive or append exact authenticated evidence."""


class AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing(
    AlpacaPaperAuthenticatedOrderViewComparisonError
):
    """A requested terminal Phase 4O prefix is absent or still active."""


class AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
    AlpacaPaperAuthenticatedOrderViewComparisonError
):
    """Loaded sources, derived comparison, or durable result conflict."""


class _NoAuthenticatedOrderViewComparisonAuthority:
    __slots__ = ()

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
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
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
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
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
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
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_plan(value: object, field_name: str) -> AlpacaPaperOrderSnapshotPlan:
    if type(value) is not AlpacaPaperOrderSnapshotPlan:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} must be an exact Phase 4M plan"
        )
    try:
        value.__post_init__()
    except (TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} is invalid"
        ) from error
    return value


def _terminal_prefix(
    value: object,
    *,
    field_name: str,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    if type(value) is not AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} must be an exact Phase 4O prefix"
        )
    try:
        capture = value.capture
    except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} failed authenticated reconstruction"
        ) from error
    if not value.page_receipts:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing(
            f"{field_name} has no committed page"
        )
    if not (capture.pagination_exhausted or capture.bounded_truncation):
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing(
            f"{field_name} is not terminal"
        )
    if capture.next_page_description is not None:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} terminal state still exposes a next page"
        )
    terminal = value.page_receipts[-1]
    if type(terminal) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} has an invalid terminal page receipt"
        )
    return value


def _source_material(
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    *,
    capture: AlpacaPaperOrderSnapshotCapture,
    capture_sha256: str,
    prefix_sha256: str,
) -> tuple[object, ...]:
    terminal = prefix.page_receipts[-1]
    return (
        prefix.plan.snapshot_id,
        prefix.plan.semantic_sha256,
        canonical_id(
            "alpaca-paper-authenticated-order-snapshot-prefix",
            prefix_sha256,
        ),
        prefix_sha256,
        capture_sha256,
        len(prefix.page_receipts),
        tuple(
            (
                receipt.receipt_id,
                receipt.semantic_sha256,
                receipt.persisted_page.receipt.receipt_id,
                receipt.persisted_page.receipt.semantic_sha256,
                receipt.persisted_page.receipt.ingress_sequence,
            )
            for receipt in prefix.page_receipts
        ),
        terminal.receipt_id,
        terminal.semantic_sha256,
        capture.pagination_exhausted,
        capture.bounded_truncation,
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedOrderViewComparisonEvidence(
    _NoAuthenticatedOrderViewComparisonAuthority
):
    """Exact Phase 4N result derived from two authenticated Phase 4O prefixes."""

    earlier_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix
    later_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix
    comparison: AlpacaPaperOrderSnapshotComparison

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedOrderViewComparisonEvidence must be proof-constructed"
        )

    def _validate(self) -> None:
        earlier = _terminal_prefix(
            self.earlier_prefix,
            field_name="earlier authenticated order-view prefix",
        )
        later = _terminal_prefix(
            self.later_prefix,
            field_name="later authenticated order-view prefix",
        )
        if type(self.comparison) is not AlpacaPaperOrderSnapshotComparison:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "authenticated order-view evidence requires an exact Phase 4N comparison"
            )
        try:
            self.comparison._validate()
            expected = compare_alpaca_paper_order_snapshot_captures(
                earlier.capture,
                later.capture,
            )
        except (
            AlpacaPaperOrderSnapshotComparisonError,
            AlpacaPaperOrderSnapshotConflict,
            TypeError,
            ValueError,
        ) as error:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "authenticated order-view sources cannot be compared exactly"
            ) from error
        if self.comparison != expected:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "authenticated order-view comparison conflicts with exact sources"
            )

    @property
    def account_id(self) -> str:
        self._validate()
        return self.comparison.account_id

    @property
    def traversal_profile_sha256(self) -> str:
        self._validate()
        return self.comparison.traversal_profile_sha256

    @property
    def earlier_plan_id(self) -> str:
        return self.earlier_prefix.plan.snapshot_id

    @property
    def earlier_plan_sha256(self) -> str:
        return self.earlier_prefix.plan.semantic_sha256

    @property
    def later_plan_id(self) -> str:
        return self.later_prefix.plan.snapshot_id

    @property
    def later_plan_sha256(self) -> str:
        return self.later_prefix.plan.semantic_sha256

    @property
    def earlier_prefix_id(self) -> str:
        self._validate()
        return self.earlier_prefix.prefix_id

    @property
    def later_prefix_id(self) -> str:
        self._validate()
        return self.later_prefix.prefix_id

    @property
    def earlier_terminal_page_receipt(self) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        self._validate()
        return self.earlier_prefix.page_receipts[-1]

    @property
    def later_terminal_page_receipt(self) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        self._validate()
        return self.later_prefix.page_receipts[-1]

    @property
    def earlier_terminal_page_receipt_id(self) -> str:
        return self.earlier_terminal_page_receipt.receipt_id

    @property
    def earlier_terminal_page_receipt_sha256(self) -> str:
        return self.earlier_terminal_page_receipt.semantic_sha256

    @property
    def later_terminal_page_receipt_id(self) -> str:
        return self.later_terminal_page_receipt.receipt_id

    @property
    def later_terminal_page_receipt_sha256(self) -> str:
        return self.later_terminal_page_receipt.semantic_sha256

    @property
    def earlier_capture_sha256(self) -> str:
        self._validate()
        return self.earlier_prefix.capture.semantic_sha256

    @property
    def later_capture_sha256(self) -> str:
        self._validate()
        return self.later_prefix.capture.semantic_sha256

    @property
    def earlier_prefix_sha256(self) -> str:
        self._validate()
        return self.earlier_prefix.semantic_sha256

    @property
    def later_prefix_sha256(self) -> str:
        self._validate()
        return self.later_prefix.semantic_sha256

    @property
    def earlier_page_count(self) -> int:
        self._validate()
        return self.earlier_prefix.page_count

    @property
    def later_page_count(self) -> int:
        self._validate()
        return self.later_prefix.page_count

    @property
    def earlier_window_started_at(self) -> datetime:
        self._validate()
        return self.comparison.earlier_window_started_at

    @property
    def earlier_window_ended_at(self) -> datetime:
        self._validate()
        return self.comparison.earlier_window_ended_at

    @property
    def later_window_started_at(self) -> datetime:
        self._validate()
        return self.comparison.later_window_started_at

    @property
    def later_window_ended_at(self) -> datetime:
        self._validate()
        return self.comparison.later_window_ended_at

    @property
    def latest_source_committed_at(self) -> datetime:
        self._validate()
        return max(
            receipt.commit_fence_receipt.validated_at
            for prefix in (self.earlier_prefix, self.later_prefix)
            for receipt in prefix.page_receipts
        )

    @property
    def bounded_traversal_incomplete(self) -> bool:
        self._validate()
        return (
            self.comparison.disposition
            is AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
        )

    @property
    def source_request_budgets_authenticated(self) -> bool:
        self._validate()
        return all(
            receipt.request_budget_enforced
            for prefix in (self.earlier_prefix, self.later_prefix)
            for receipt in prefix.page_receipts
        )

    @property
    def source_raw_responses_authenticated(self) -> bool:
        self._validate()
        return all(
            receipt.raw_response_persisted
            for prefix in (self.earlier_prefix, self.later_prefix)
            for receipt in prefix.page_receipts
        )

    @property
    def captures_authenticated(self) -> bool:
        self._validate()
        return True

    @property
    def comparison_durably_recorded(self) -> bool:
        return False

    @property
    def evidence_id(self) -> str:
        self._validate()
        earlier_prefix_sha256 = self.earlier_prefix.semantic_sha256
        later_prefix_sha256 = self.later_prefix.semantic_sha256
        return canonical_id(
            "alpaca-paper-authenticated-order-view-comparison-evidence",
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
            self.earlier_prefix.plan.snapshot_id,
            earlier_prefix_sha256,
            self.later_prefix.plan.snapshot_id,
            later_prefix_sha256,
            self.comparison.semantic_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        earlier = self.earlier_prefix
        later = self.later_prefix
        comparison = self.comparison
        earlier_capture = earlier.capture
        later_capture = later.capture
        earlier_capture_sha256 = earlier_capture.semantic_sha256
        later_capture_sha256 = later_capture.semantic_sha256
        earlier_prefix_sha256 = earlier.semantic_sha256
        later_prefix_sha256 = later.semantic_sha256
        comparison_sha256 = comparison.semantic_sha256
        evidence_id = canonical_id(
            "alpaca-paper-authenticated-order-view-comparison-evidence",
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
            earlier.plan.snapshot_id,
            earlier_prefix_sha256,
            later.plan.snapshot_id,
            later_prefix_sha256,
            comparison_sha256,
        )
        source_request_budgets_authenticated = all(
            receipt.request_budget_enforced
            for prefix in (earlier, later)
            for receipt in prefix.page_receipts
        )
        source_raw_responses_authenticated = all(
            receipt.raw_response_persisted
            for prefix in (earlier, later)
            for receipt in prefix.page_receipts
        )
        return (
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION,
            "authenticated_order_view_comparison_evidence",
            evidence_id,
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
            earlier.plan.account_id,
            _traversal_profile_sha256(earlier_capture),
            _source_material(
                earlier,
                capture=earlier_capture,
                capture_sha256=earlier_capture_sha256,
                prefix_sha256=earlier_prefix_sha256,
            ),
            _source_material(
                later,
                capture=later_capture,
                capture_sha256=later_capture_sha256,
                prefix_sha256=later_prefix_sha256,
            ),
            earlier_capture.pages[0].observation.received_at,
            earlier_capture.pages[-1].observation.received_at,
            later_capture.pages[0].observation.received_at,
            later_capture.pages[-1].observation.received_at,
            canonical_id(
                "alpaca-paper-order-view-comparison",
                ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
                earlier.plan.snapshot_id,
                earlier_capture_sha256,
                later.plan.snapshot_id,
                later_capture_sha256,
            ),
            comparison_sha256,
            comparison.disposition,
            _view_sha256(earlier_capture),
            _view_sha256(later_capture),
            _timedelta_microseconds(
                _utc_separation(
                    earlier_capture,
                    later_capture,
                )
            ),
            comparison.added_provider_order_ids,
            comparison.removed_provider_order_ids,
            comparison.changed_provider_order_ids,
            source_request_budgets_authenticated,
            source_raw_responses_authenticated,
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
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _alpaca_paper_authenticated_order_view_comparison_evidence(
    *,
    earlier_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    later_prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
) -> AlpacaPaperAuthenticatedOrderViewComparisonEvidence:
    """Construct evidence only after exact Phase 4O source authentication."""

    earlier = _terminal_prefix(
        earlier_prefix,
        field_name="earlier authenticated order-view prefix",
    )
    later = _terminal_prefix(
        later_prefix,
        field_name="later authenticated order-view prefix",
    )
    try:
        comparison = compare_alpaca_paper_order_snapshot_captures(
            earlier.capture,
            later.capture,
        )
    except (AlpacaPaperOrderSnapshotComparisonError, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "authenticated order-view sources cannot be compared exactly"
        ) from error
    evidence = object.__new__(AlpacaPaperAuthenticatedOrderViewComparisonEvidence)
    object.__setattr__(evidence, "earlier_prefix", earlier)
    object.__setattr__(evidence, "later_prefix", later)
    object.__setattr__(evidence, "comparison", comparison)
    evidence._validate()
    return evidence


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedOrderViewComparisonReceipt(
    _NoAuthenticatedOrderViewComparisonAuthority
):
    """Repository-produced append proof for one exact comparison evidence pair."""

    evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence
    earlier_source_head_sha256: str
    later_source_head_sha256: str
    commit_fence_receipt: AccountFenceReceipt
    account_sequence: int
    previous_receipt_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedOrderViewComparisonReceipt must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.evidence) is not AlpacaPaperAuthenticatedOrderViewComparisonEvidence:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "durable comparison receipt requires exact Phase 4P evidence"
            )
        self.evidence._validate()
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "durable comparison receipt requires an exact commit fence"
            )
        _require_sha256(
            self.earlier_source_head_sha256,
            "earlier durable order-view source head",
        )
        _require_sha256(
            self.later_source_head_sha256,
            "later durable order-view source head",
        )
        if self.earlier_source_head_sha256 == self.later_source_head_sha256:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "distinct order-view sources require distinct durable heads"
            )
        try:
            self.commit_fence_receipt._validate()
        except (AccountCoordinatorError, TypeError, ValueError) as error:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "durable comparison commit fence is invalid"
            ) from error
        if (
            self.commit_fence_receipt.fence.account_id
            != self.evidence.earlier_prefix.plan.account_id
        ):
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "durable comparison commit fence crosses account identities"
            )
        latest_source_committed_at = max(
            receipt.commit_fence_receipt.validated_at
            for prefix in (
                self.evidence.earlier_prefix,
                self.evidence.later_prefix,
            )
            for receipt in prefix.page_receipts
        )
        if self.commit_fence_receipt.validated_at < latest_source_committed_at:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "durable comparison append predates an authenticated source commit"
            )
        if type(self.account_sequence) is not int or self.account_sequence <= 0:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "durable comparison account sequence must be positive"
            )
        if self.account_sequence == 1:
            if self.previous_receipt_sha256 is not None:
                raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                    "first durable comparison receipt cannot name a predecessor"
                )
        else:
            _require_sha256(
                self.previous_receipt_sha256,
                "durable comparison predecessor",
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
            "alpaca-paper-authenticated-order-view-comparison",
            self.evidence.evidence_id,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        evidence = self.evidence
        evidence_material = evidence._semantic_material()
        evidence_id = evidence_material[2]
        if type(evidence_id) is not str:
            raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
                "authenticated evidence identity is malformed"
            )
        evidence_sha256 = _semantic_sha256(evidence_material)
        receipt_id = canonical_id(
            "alpaca-paper-authenticated-order-view-comparison",
            evidence_id,
        )
        source_request_budgets_authenticated = all(
            receipt.request_budget_enforced
            for prefix in (evidence.earlier_prefix, evidence.later_prefix)
            for receipt in prefix.page_receipts
        )
        source_raw_responses_authenticated = all(
            receipt.raw_response_persisted
            for prefix in (evidence.earlier_prefix, evidence.later_prefix)
            for receipt in prefix.page_receipts
        )
        recorded_at = self.commit_fence_receipt.validated_at
        return (
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION,
            "authenticated_order_view_comparison_receipt",
            receipt_id,
            evidence_id,
            evidence_sha256,
            self.earlier_source_head_sha256,
            self.later_source_head_sha256,
            self.commit_fence_receipt.receipt_id,
            self.commit_fence_receipt.semantic_sha256,
            recorded_at,
            self.account_sequence,
            self.previous_receipt_sha256,
            source_request_budgets_authenticated,
            source_raw_responses_authenticated,
            True,
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


def _alpaca_paper_authenticated_order_view_comparison_receipt(
    evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
    *,
    earlier_source_head_sha256: str,
    later_source_head_sha256: str,
    commit_fence_receipt: AccountFenceReceipt,
    account_sequence: int,
    previous_receipt_sha256: str | None,
) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
    """Construct the exact value a durable repository appended."""

    receipt = object.__new__(AlpacaPaperAuthenticatedOrderViewComparisonReceipt)
    for field_name, value in (
        ("evidence", evidence),
        ("earlier_source_head_sha256", earlier_source_head_sha256),
        ("later_source_head_sha256", later_source_head_sha256),
        ("commit_fence_receipt", commit_fence_receipt),
        ("account_sequence", account_sequence),
        ("previous_receipt_sha256", previous_receipt_sha256),
    ):
        object.__setattr__(receipt, field_name, value)
    receipt._validate()
    return receipt


class AlpacaPaperOrderSnapshotPrefixLoader(Protocol):
    """Reload and authenticate one exact durable Phase 4O prefix."""

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix: ...


class AlpacaPaperOrderViewComparisonRepository(Protocol):
    """Append one authenticated comparison under the current account fence."""

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt: ...


def _load_exact_terminal_prefix(
    plan: AlpacaPaperOrderSnapshotPlan,
    *,
    loader: AlpacaPaperOrderSnapshotPrefixLoader,
    field_name: str,
) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
    try:
        value = loader.load_prefix(plan)
    except AlpacaPaperAuthenticatedOrderViewComparisonError:
        raise
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} could not be reloaded and authenticated"
        ) from error
    prefix = _terminal_prefix(value, field_name=field_name)
    if prefix.plan != plan:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            f"{field_name} loader returned another plan"
        )
    return prefix


def compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
    earlier_plan: AlpacaPaperOrderSnapshotPlan,
    later_plan: AlpacaPaperOrderSnapshotPlan,
    *,
    fence: AccountFence,
    prefix_loader: AlpacaPaperOrderSnapshotPrefixLoader,
    comparison_repository: AlpacaPaperOrderViewComparisonRepository,
) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
    """Reload, compare, and durably append one exact authenticated pair."""

    earlier_plan = _require_plan(earlier_plan, "earlier order-view plan")
    later_plan = _require_plan(later_plan, "later order-view plan")
    if earlier_plan.snapshot_id == later_plan.snapshot_id:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "authenticated order-view comparison requires distinct plans"
        )
    if type(fence) is not AccountFence:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "authenticated order-view comparison requires an exact account fence"
        )
    try:
        fence.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "authenticated order-view comparison fence is invalid"
        ) from error
    if fence.account_id != earlier_plan.account_id or fence.account_id != later_plan.account_id:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "authenticated order-view comparison fence crosses account identities"
        )
    if not callable(getattr(prefix_loader, "load_prefix", None)):
        raise AlpacaPaperAuthenticatedOrderViewComparisonError(
            "order-view prefix loader does not implement load_prefix"
        )
    if not callable(getattr(comparison_repository, "record", None)):
        raise AlpacaPaperAuthenticatedOrderViewComparisonError(
            "order-view comparison repository does not implement record"
        )

    earlier_prefix = _load_exact_terminal_prefix(
        earlier_plan,
        loader=prefix_loader,
        field_name="earlier authenticated order-view prefix",
    )
    later_prefix = _load_exact_terminal_prefix(
        later_plan,
        loader=prefix_loader,
        field_name="later authenticated order-view prefix",
    )
    evidence = _alpaca_paper_authenticated_order_view_comparison_evidence(
        earlier_prefix=earlier_prefix,
        later_prefix=later_prefix,
    )
    try:
        receipt = comparison_repository.record(evidence, fence=fence)
    except AlpacaPaperAuthenticatedOrderViewComparisonError:
        raise
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "authenticated order-view comparison append failed"
        ) from error
    if type(receipt) is not AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "comparison repository returned a non-canonical receipt"
        )
    try:
        receipt._validate()
    except (
        AlpacaPaperAuthenticatedOrderViewComparisonError,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "comparison repository returned an invalid durable receipt"
        ) from error
    if receipt.evidence != evidence:
        raise AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict(
            "comparison repository changed authenticated evidence"
        )
    return receipt


__all__ = [
    "ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION",
    "ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_ID",
    "ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256",
    "AlpacaPaperAuthenticatedOrderViewComparisonError",
    "AlpacaPaperAuthenticatedOrderViewComparisonEvidence",
    "AlpacaPaperAuthenticatedOrderViewComparisonReceipt",
    "AlpacaPaperAuthenticatedOrderViewComparisonSourceConflict",
    "AlpacaPaperAuthenticatedOrderViewComparisonSourceMissing",
    "AlpacaPaperOrderSnapshotPrefixLoader",
    "AlpacaPaperOrderViewComparisonRepository",
    "compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes",
]
