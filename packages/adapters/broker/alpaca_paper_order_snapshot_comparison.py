"""Bounded, non-authorizing comparison of two Alpaca paper order traversals.

Phase 4M retains one bounded descending order traversal without claiming
snapshot isolation.  This module compares two distinct, sequential traversals
and records exact decoded-order differences.  Even an exact match remains
unqualified: UTC receipt spacing is not trusted monotonic timing, order pages
are not an isolated account snapshot, and no other account or stream evidence
is present.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from packages.adapters.broker.alpaca_paper import ALPACA_PAPER_CAPABILITIES
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
    AlpacaPaperOrderSnapshotCapture,
    AlpacaPaperOrderSnapshotError,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION = "phase4n-bounded-order-view-comparison-v1"
ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_ID = "phase4n-exact-order-view-comparison-policy-v1"
ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION = timedelta(seconds=2)


class AlpacaPaperOrderSnapshotComparisonError(AlpacaPaperOrderSnapshotError):
    """Two order snapshot traversals cannot be compared under the frozen contract."""


class AlpacaPaperOrderSnapshotComparisonConflict(AlpacaPaperOrderSnapshotComparisonError):
    """Comparison inputs or claimed results conflict with exact source evidence."""


class AlpacaPaperOrderSnapshotComparisonDisposition(StrEnum):
    """Closed meanings for one bounded pair comparison."""

    EXACT_ORDER_VIEW_MATCH_UNQUALIFIED = "exact_order_view_match_unqualified"
    ORDER_VIEW_DIFFERENT = "order_view_different"
    WAITING_MINIMUM_SEPARATION = "waiting_minimum_separation"
    BOUNDED_TRAVERSAL_INCOMPLETE = "bounded_traversal_incomplete"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _timedelta_microseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
        "comparison_policy",
        ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_ID,
        _timedelta_microseconds(ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION),
        tuple(AlpacaPaperOrderSnapshotComparisonDisposition),
        "same_account_and_traversal_profile",
        "distinct_capture_and_raw_source",
        "strict_account_local_ingress_order",
        "page_boundary_independent_exact_order_semantics",
        "no_snapshot_isolation_or_reconciliation_authority",
    )
)


class _NoOrderSnapshotComparisonAuthority:
    __slots__ = ()

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
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


def _capture_has_ended(capture: AlpacaPaperOrderSnapshotCapture) -> bool:
    return capture.pagination_exhausted or capture.bounded_truncation


def _traversal_profile_sha256(capture: AlpacaPaperOrderSnapshotCapture) -> str:
    return _semantic_sha256(
        (
            ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
            "traversal_profile",
            ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
            ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            capture.plan.page_limit,
            capture.plan.maximum_pages,
            "all",
            "desc",
            False,
            "us_equity",
            "before_order_id",
        )
    )


def _ordered_view(
    capture: AlpacaPaperOrderSnapshotCapture,
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (
                order.provider_order_id,
                order.semantic_sha256,
            )
            for page in capture.pages
            for order in page.observation.orders
        )
    )


def _view_sha256(
    capture: AlpacaPaperOrderSnapshotCapture,
) -> str:
    return _semantic_sha256(
        (
            ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
            "exact_decoded_order_view",
            capture.plan.account_id,
            _traversal_profile_sha256(capture),
            _ordered_view(capture),
        )
    )


def _capture_receipt_ids(
    capture: AlpacaPaperOrderSnapshotCapture,
) -> frozenset[str]:
    return frozenset(page.receipt.receipt_id for page in capture.pages)


def _validate_pair(
    earlier_capture: object,
    later_capture: object,
) -> tuple[AlpacaPaperOrderSnapshotCapture, AlpacaPaperOrderSnapshotCapture]:
    if type(earlier_capture) is not AlpacaPaperOrderSnapshotCapture:
        raise AlpacaPaperOrderSnapshotComparisonError(
            "earlier order view must be an exact Phase 4M capture"
        )
    if type(later_capture) is not AlpacaPaperOrderSnapshotCapture:
        raise AlpacaPaperOrderSnapshotComparisonError(
            "later order view must be an exact Phase 4M capture"
        )
    earlier_capture.__post_init__()
    later_capture.__post_init__()
    if not _capture_has_ended(earlier_capture) or not _capture_has_ended(later_capture):
        raise AlpacaPaperOrderSnapshotComparisonError(
            "order view comparison requires two ended bounded traversals"
        )
    if earlier_capture.plan.account_id != later_capture.plan.account_id:
        raise AlpacaPaperOrderSnapshotComparisonConflict(
            "order view captures belong to different accounts"
        )
    overlapping_receipts = _capture_receipt_ids(earlier_capture) & _capture_receipt_ids(
        later_capture
    )
    if overlapping_receipts:
        raise AlpacaPaperOrderSnapshotComparisonConflict(
            "order view captures reuse a raw ingress source"
        )
    if earlier_capture.plan.snapshot_id == later_capture.plan.snapshot_id:
        raise AlpacaPaperOrderSnapshotComparisonConflict(
            "order view comparison requires distinct capture identities"
        )
    if _traversal_profile_sha256(earlier_capture) != _traversal_profile_sha256(later_capture):
        raise AlpacaPaperOrderSnapshotComparisonConflict(
            "order view captures use different traversal profiles"
        )
    if (
        earlier_capture.pages[-1].receipt.ingress_sequence
        >= later_capture.pages[0].receipt.ingress_sequence
    ):
        raise AlpacaPaperOrderSnapshotComparisonConflict(
            "later order view does not follow the earlier raw ingress sources"
        )
    return earlier_capture, later_capture


def _differences(
    earlier_capture: AlpacaPaperOrderSnapshotCapture,
    later_capture: AlpacaPaperOrderSnapshotCapture,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    earlier = dict(_ordered_view(earlier_capture))
    later = dict(_ordered_view(later_capture))
    added = tuple(sorted(later.keys() - earlier.keys()))
    removed = tuple(sorted(earlier.keys() - later.keys()))
    changed = tuple(
        sorted(
            provider_order_id
            for provider_order_id in earlier.keys() & later.keys()
            if earlier[provider_order_id] != later[provider_order_id]
        )
    )
    return added, removed, changed


def _utc_separation(
    earlier_capture: AlpacaPaperOrderSnapshotCapture,
    later_capture: AlpacaPaperOrderSnapshotCapture,
) -> timedelta:
    return (
        later_capture.pages[0].observation.received_at
        - earlier_capture.pages[-1].observation.received_at
    )


def _disposition(
    earlier_capture: AlpacaPaperOrderSnapshotCapture,
    later_capture: AlpacaPaperOrderSnapshotCapture,
    *,
    added_provider_order_ids: tuple[str, ...],
    removed_provider_order_ids: tuple[str, ...],
    changed_provider_order_ids: tuple[str, ...],
) -> AlpacaPaperOrderSnapshotComparisonDisposition:
    if earlier_capture.bounded_truncation or later_capture.bounded_truncation:
        return AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    if (
        _utc_separation(earlier_capture, later_capture)
        < ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION
    ):
        return AlpacaPaperOrderSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    if added_provider_order_ids or removed_provider_order_ids or changed_provider_order_ids:
        return AlpacaPaperOrderSnapshotComparisonDisposition.ORDER_VIEW_DIFFERENT
    return AlpacaPaperOrderSnapshotComparisonDisposition.EXACT_ORDER_VIEW_MATCH_UNQUALIFIED


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperOrderSnapshotComparison(_NoOrderSnapshotComparisonAuthority):
    """Proof-constructed exact comparison of two bounded traversal sources."""

    earlier_capture: AlpacaPaperOrderSnapshotCapture
    later_capture: AlpacaPaperOrderSnapshotCapture
    disposition: AlpacaPaperOrderSnapshotComparisonDisposition
    added_provider_order_ids: tuple[str, ...]
    removed_provider_order_ids: tuple[str, ...]
    changed_provider_order_ids: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperOrderSnapshotComparison must be proof-constructed")

    def _validate(self) -> None:
        earlier, later = _validate_pair(self.earlier_capture, self.later_capture)
        expected_added, expected_removed, expected_changed = _differences(
            earlier,
            later,
        )
        if (
            self.added_provider_order_ids != expected_added
            or self.removed_provider_order_ids != expected_removed
            or self.changed_provider_order_ids != expected_changed
        ):
            raise AlpacaPaperOrderSnapshotComparisonConflict(
                "order view comparison differences conflict with exact captures"
            )
        expected_disposition = _disposition(
            earlier,
            later,
            added_provider_order_ids=expected_added,
            removed_provider_order_ids=expected_removed,
            changed_provider_order_ids=expected_changed,
        )
        if (
            type(self.disposition) is not AlpacaPaperOrderSnapshotComparisonDisposition
            or self.disposition is not expected_disposition
        ):
            raise AlpacaPaperOrderSnapshotComparisonConflict(
                "order view comparison disposition conflicts with exact captures"
            )

    @property
    def account_id(self) -> str:
        self._validate()
        return self.earlier_capture.plan.account_id

    @property
    def traversal_profile_sha256(self) -> str:
        self._validate()
        return _traversal_profile_sha256(self.earlier_capture)

    @property
    def earlier_window_started_at(self) -> datetime:
        self._validate()
        return self.earlier_capture.pages[0].observation.received_at

    @property
    def earlier_window_ended_at(self) -> datetime:
        self._validate()
        return self.earlier_capture.pages[-1].observation.received_at

    @property
    def later_window_started_at(self) -> datetime:
        self._validate()
        return self.later_capture.pages[0].observation.received_at

    @property
    def later_window_ended_at(self) -> datetime:
        self._validate()
        return self.later_capture.pages[-1].observation.received_at

    @property
    def observed_utc_separation(self) -> timedelta:
        self._validate()
        return _utc_separation(self.earlier_capture, self.later_capture)

    @property
    def observed_utc_separation_microseconds(self) -> int:
        return _timedelta_microseconds(self.observed_utc_separation)

    @property
    def capture_windows_non_overlapping(self) -> bool:
        return self.observed_utc_separation >= timedelta()

    @property
    def minimum_utc_separation_observed(self) -> bool:
        return self.observed_utc_separation >= ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION

    @property
    def earlier_view_sha256(self) -> str:
        self._validate()
        return _view_sha256(self.earlier_capture)

    @property
    def later_view_sha256(self) -> str:
        self._validate()
        return _view_sha256(self.later_capture)

    @property
    def order_views_equal(self) -> bool:
        self._validate()
        return not (
            self.added_provider_order_ids
            or self.removed_provider_order_ids
            or self.changed_provider_order_ids
        )

    @property
    def exact_order_view_match_unqualified(self) -> bool:
        self._validate()
        return (
            self.disposition
            is AlpacaPaperOrderSnapshotComparisonDisposition.EXACT_ORDER_VIEW_MATCH_UNQUALIFIED
        )

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def comparison_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-order-view-comparison",
            ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
            self.earlier_capture.plan.snapshot_id,
            self.earlier_capture.semantic_sha256,
            self.later_capture.plan.snapshot_id,
            self.later_capture.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
                "order_view_comparison",
                self.comparison_id,
                ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_ID,
                ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
                self.account_id,
                self.traversal_profile_sha256,
                self.earlier_capture.plan.snapshot_id,
                self.earlier_capture.semantic_sha256,
                tuple(
                    (
                        page.receipt.receipt_id,
                        page.receipt.semantic_sha256,
                    )
                    for page in self.earlier_capture.pages
                ),
                self.earlier_window_started_at,
                self.earlier_window_ended_at,
                self.earlier_view_sha256,
                self.later_capture.plan.snapshot_id,
                self.later_capture.semantic_sha256,
                tuple(
                    (
                        page.receipt.receipt_id,
                        page.receipt.semantic_sha256,
                    )
                    for page in self.later_capture.pages
                ),
                self.later_window_started_at,
                self.later_window_ended_at,
                self.later_view_sha256,
                self.observed_utc_separation_microseconds,
                self.added_provider_order_ids,
                self.removed_provider_order_ids,
                self.changed_provider_order_ids,
                self.disposition,
                self.request_budget_enforced,
                self.authenticated_provider_evidence,
                self.runtime_current,
                self.capture_authenticated,
                self.durable_source_positions_authenticated,
                self.snapshot_isolation_qualified,
                self.provider_snapshot_complete,
                self.monotonic_timing_qualified,
                self.provider_revision_identity_qualified,
                self.provider_deduplication_authorized,
                self.normalized_fact_authorized,
                self.inbox_application_authorized,
                self.lifecycle_application_authorized,
                self.reconciliation_application_authorized,
                self.reconciliation_completion_authorized,
                self.reconciliation_complete,
                self.unknown_resolution_authorized,
                self.resubmission_authorized,
                self.reservation_release_authorized,
                self.canonical_execution_fact_authorized,
                self.readiness_transition_authorized,
                self.transport_authorized,
                self.broker_call_authorized,
                self.trading_effect_authorized,
                self.converged,
            )
        )


def compare_alpaca_paper_order_snapshot_captures(
    earlier_capture: AlpacaPaperOrderSnapshotCapture,
    later_capture: AlpacaPaperOrderSnapshotCapture,
) -> AlpacaPaperOrderSnapshotComparison:
    """Compare exact bounded traversal values without declaring convergence."""

    earlier, later = _validate_pair(earlier_capture, later_capture)
    added, removed, changed = _differences(earlier, later)
    comparison = object.__new__(AlpacaPaperOrderSnapshotComparison)
    object.__setattr__(comparison, "earlier_capture", earlier)
    object.__setattr__(comparison, "later_capture", later)
    object.__setattr__(
        comparison,
        "disposition",
        _disposition(
            earlier,
            later,
            added_provider_order_ids=added,
            removed_provider_order_ids=removed,
            changed_provider_order_ids=changed,
        ),
    )
    object.__setattr__(comparison, "added_provider_order_ids", added)
    object.__setattr__(comparison, "removed_provider_order_ids", removed)
    object.__setattr__(comparison, "changed_provider_order_ids", changed)
    comparison._validate()
    return comparison


__all__ = [
    "ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION",
    "ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_ID",
    "ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256",
    "ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION",
    "AlpacaPaperOrderSnapshotComparison",
    "AlpacaPaperOrderSnapshotComparisonConflict",
    "AlpacaPaperOrderSnapshotComparisonDisposition",
    "AlpacaPaperOrderSnapshotComparisonError",
    "compare_alpaca_paper_order_snapshot_captures",
]
