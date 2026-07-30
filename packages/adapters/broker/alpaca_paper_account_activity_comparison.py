"""Pure, non-authorizing comparison of two Alpaca account-activity captures.

Phase 4AD retains one bounded, ascending account-activity traversal without
snapshot isolation or complete-history authority.  This module compares two
distinct ended traversals by exact decoded activity semantics.  Provider
activity IDs are used only as opaque set keys; their text and ordering never
become execution, sequence, revision, correction, bust, or deduplication
identity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from packages.adapters.broker.alpaca_paper import (
    ALPACA_ACCOUNT_ACTIVITIES_PATH,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_TRADING_BASE_URL,
)
from packages.adapters.broker.alpaca_paper_account_activities import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES,
    AlpacaPaperAccountActivityCapture,
    AlpacaPaperAccountActivityError,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION = (
    "phase4af-exact-account-activity-view-comparison-v1"
)
ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID = (
    "phase4af-exact-account-activity-view-comparison-policy-v1"
)
ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION = timedelta(seconds=2)


class AlpacaPaperAccountActivityComparisonError(AlpacaPaperAccountActivityError):
    """Two activity captures cannot be compared under the frozen contract."""


class AlpacaPaperAccountActivityComparisonConflict(AlpacaPaperAccountActivityComparisonError):
    """Comparison inputs or claimed results conflict with exact source evidence."""


class AlpacaPaperAccountActivityComparisonDisposition(StrEnum):
    """Closed meanings for one bounded activity-view comparison."""

    EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED = "exact_activity_view_match_unqualified"
    ACTIVITY_VIEW_DIFFERENT = "activity_view_different"
    WAITING_MINIMUM_SEPARATION = "waiting_minimum_separation"
    BOUNDED_TRAVERSAL_INCOMPLETE = "bounded_traversal_incomplete"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _timedelta_microseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
        "comparison_policy",
        ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID,
        _timedelta_microseconds(ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION),
        tuple(AlpacaPaperAccountActivityComparisonDisposition),
        "same_account_and_traversal_profile",
        "distinct_ended_capture_identity",
        "disjoint_raw_ingress_receipts",
        "strict_account_local_ingress_order",
        "provider_activity_id_to_exact_activity_semantic_digest",
        "provider_activity_ids_are_opaque_set_keys_only",
        "bounded_truncation_precedes_timing_and_difference_dispositions",
        "no_snapshot_history_convergence_or_application_authority",
    )
)


class _NoAccountActivityComparisonAuthority:
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
    def snapshot_complete(self) -> bool:
        return False

    @property
    def activity_history_complete(self) -> bool:
        return False

    @property
    def activity_history_consistent(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_activity_identity_qualified(self) -> bool:
        return False

    @property
    def provider_activity_sequence_identity_qualified(self) -> bool:
        return False

    @property
    def provider_activity_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_execution_identity_qualified(self) -> bool:
        return False

    @property
    def canonical_execution_identity_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def execution_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_identity_qualified(self) -> bool:
        return False

    @property
    def provider_bust_identity_qualified(self) -> bool:
        return False

    @property
    def provider_correction_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_revision_authorized(self) -> bool:
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
    def execution_application_authorized(self) -> bool:
        return False

    @property
    def bust_application_authorized(self) -> bool:
        return False

    @property
    def correction_application_authorized(self) -> bool:
        return False

    @property
    def manual_activity_application_authorized(self) -> bool:
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
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def activity_snapshot_pagination_ready(self) -> bool:
        return False

    @property
    def decode_quarantine_ready(self) -> bool:
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
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def _capture_has_ended(capture: AlpacaPaperAccountActivityCapture) -> bool:
    return capture.pagination_exhausted or capture.bounded_truncation


def _traversal_profile_sha256(
    capture: AlpacaPaperAccountActivityCapture,
) -> str:
    return _semantic_sha256(
        (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
            "account_activity_traversal_profile",
            ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
            ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            "GET",
            ALPACA_PAPER_TRADING_BASE_URL,
            ALPACA_ACCOUNT_ACTIVITIES_PATH,
            capture.plan.page_size,
            capture.plan.maximum_pages,
            capture.plan.maximum_items,
            capture.plan.activity_types,
            capture.plan.direction,
            "last_activity_id",
            ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES,
            "strict_legacy_trade_activity_fill",
            "provider_activity_id_opaque_set_key_only",
        )
    )


def _deterministic_view(
    capture: AlpacaPaperAccountActivityCapture,
) -> tuple[tuple[str, str], ...]:
    # Sorting is only canonical set serialization. It assigns no provider order
    # or sequence meaning to the opaque activity-ID text.
    return tuple(
        sorted(
            (
                activity.provider_activity_id,
                activity.semantic_sha256,
            )
            for page in capture.pages
            for activity in page.observation.activities
        )
    )


def _view_sha256(capture: AlpacaPaperAccountActivityCapture) -> str:
    return _semantic_sha256(
        (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
            "exact_decoded_account_activity_view",
            capture.plan.account_id,
            _traversal_profile_sha256(capture),
            _deterministic_view(capture),
        )
    )


def _capture_receipt_ids(
    capture: AlpacaPaperAccountActivityCapture,
) -> frozenset[str]:
    return frozenset(page.receipt.receipt_id for page in capture.pages)


def _validate_pair(
    earlier_capture: object,
    later_capture: object,
) -> tuple[AlpacaPaperAccountActivityCapture, AlpacaPaperAccountActivityCapture]:
    if type(earlier_capture) is not AlpacaPaperAccountActivityCapture:
        raise AlpacaPaperAccountActivityComparisonError(
            "earlier activity view must be an exact Phase 4AD capture"
        )
    if type(later_capture) is not AlpacaPaperAccountActivityCapture:
        raise AlpacaPaperAccountActivityComparisonError(
            "later activity view must be an exact Phase 4AD capture"
        )
    earlier_capture.__post_init__()
    later_capture.__post_init__()
    if not _capture_has_ended(earlier_capture) or not _capture_has_ended(later_capture):
        raise AlpacaPaperAccountActivityComparisonError(
            "account-activity comparison requires two ended bounded traversals"
        )
    if earlier_capture.plan.account_id != later_capture.plan.account_id:
        raise AlpacaPaperAccountActivityComparisonConflict(
            "account-activity captures belong to different accounts"
        )
    if _traversal_profile_sha256(earlier_capture) != _traversal_profile_sha256(later_capture):
        raise AlpacaPaperAccountActivityComparisonConflict(
            "account-activity captures use different traversal profiles"
        )
    if earlier_capture.plan.capture_id == later_capture.plan.capture_id:
        raise AlpacaPaperAccountActivityComparisonConflict(
            "account-activity comparison requires distinct capture identities"
        )
    if _capture_receipt_ids(earlier_capture) & _capture_receipt_ids(later_capture):
        raise AlpacaPaperAccountActivityComparisonConflict(
            "account-activity captures reuse a raw ingress receipt"
        )
    if (
        earlier_capture.pages[-1].receipt.ingress_sequence
        >= later_capture.pages[0].receipt.ingress_sequence
    ):
        raise AlpacaPaperAccountActivityComparisonConflict(
            "later account-activity capture does not follow the earlier raw ingress sources"
        )
    return earlier_capture, later_capture


def _differences(
    earlier_capture: AlpacaPaperAccountActivityCapture,
    later_capture: AlpacaPaperAccountActivityCapture,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    earlier = dict(_deterministic_view(earlier_capture))
    later = dict(_deterministic_view(later_capture))
    added = tuple(sorted(later.keys() - earlier.keys()))
    removed = tuple(sorted(earlier.keys() - later.keys()))
    changed = tuple(
        sorted(
            provider_activity_id
            for provider_activity_id in earlier.keys() & later.keys()
            if earlier[provider_activity_id] != later[provider_activity_id]
        )
    )
    return added, removed, changed


def _utc_separation(
    earlier_capture: AlpacaPaperAccountActivityCapture,
    later_capture: AlpacaPaperAccountActivityCapture,
) -> timedelta:
    return (
        later_capture.pages[0].observation.received_at
        - earlier_capture.pages[-1].observation.received_at
    )


def _disposition(
    earlier_capture: AlpacaPaperAccountActivityCapture,
    later_capture: AlpacaPaperAccountActivityCapture,
    *,
    added_provider_activity_ids: tuple[str, ...],
    removed_provider_activity_ids: tuple[str, ...],
    changed_provider_activity_ids: tuple[str, ...],
) -> AlpacaPaperAccountActivityComparisonDisposition:
    if earlier_capture.bounded_truncation or later_capture.bounded_truncation:
        return AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    if (
        _utc_separation(earlier_capture, later_capture)
        < ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION
    ):
        return AlpacaPaperAccountActivityComparisonDisposition.WAITING_MINIMUM_SEPARATION
    if (
        added_provider_activity_ids
        or removed_provider_activity_ids
        or changed_provider_activity_ids
    ):
        return AlpacaPaperAccountActivityComparisonDisposition.ACTIVITY_VIEW_DIFFERENT
    return AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAccountActivityComparison(_NoAccountActivityComparisonAuthority):
    """Proof-constructed exact comparison of two bounded activity captures."""

    earlier_capture: AlpacaPaperAccountActivityCapture
    later_capture: AlpacaPaperAccountActivityCapture
    disposition: AlpacaPaperAccountActivityComparisonDisposition
    added_provider_activity_ids: tuple[str, ...]
    removed_provider_activity_ids: tuple[str, ...]
    changed_provider_activity_ids: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperAccountActivityComparison must be proof-constructed")

    def _validate(self) -> None:
        earlier, later = _validate_pair(self.earlier_capture, self.later_capture)
        expected_added, expected_removed, expected_changed = _differences(
            earlier,
            later,
        )
        if (
            self.added_provider_activity_ids != expected_added
            or self.removed_provider_activity_ids != expected_removed
            or self.changed_provider_activity_ids != expected_changed
        ):
            raise AlpacaPaperAccountActivityComparisonConflict(
                "account-activity comparison differences conflict with exact captures"
            )
        expected_disposition = _disposition(
            earlier,
            later,
            added_provider_activity_ids=expected_added,
            removed_provider_activity_ids=expected_removed,
            changed_provider_activity_ids=expected_changed,
        )
        if (
            type(self.disposition) is not AlpacaPaperAccountActivityComparisonDisposition
            or self.disposition is not expected_disposition
        ):
            raise AlpacaPaperAccountActivityComparisonConflict(
                "account-activity comparison disposition conflicts with exact captures"
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
        return self.observed_utc_separation >= ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION

    @property
    def provider_activity_ids_are_opaque_set_keys(self) -> bool:
        return True

    @property
    def earlier_view(self) -> tuple[tuple[str, str], ...]:
        self._validate()
        return _deterministic_view(self.earlier_capture)

    @property
    def later_view(self) -> tuple[tuple[str, str], ...]:
        self._validate()
        return _deterministic_view(self.later_capture)

    @property
    def earlier_view_sha256(self) -> str:
        self._validate()
        return _view_sha256(self.earlier_capture)

    @property
    def later_view_sha256(self) -> str:
        self._validate()
        return _view_sha256(self.later_capture)

    @property
    def activity_views_equal(self) -> bool:
        self._validate()
        return not (
            self.added_provider_activity_ids
            or self.removed_provider_activity_ids
            or self.changed_provider_activity_ids
        )

    @property
    def exact_activity_view_match_unqualified(self) -> bool:
        self._validate()
        return self.disposition is (
            AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED
        )

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def comparison_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-account-activity-view-comparison",
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
            self.earlier_capture.plan.capture_id,
            self.earlier_capture.semantic_sha256,
            self.later_capture.plan.capture_id,
            self.later_capture.semantic_sha256,
        )

    def _semantic_material(
        self,
        *,
        authenticate: bool = True,
    ) -> tuple[object, ...]:
        if authenticate:
            self._validate()
        earlier = self.earlier_capture
        later = self.later_capture
        earlier_capture_sha256 = earlier.semantic_sha256
        later_capture_sha256 = later.semantic_sha256
        comparison_id = canonical_id(
            "alpaca-paper-account-activity-view-comparison",
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
            earlier.plan.capture_id,
            earlier_capture_sha256,
            later.plan.capture_id,
            later_capture_sha256,
        )
        return (
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
            "account_activity_capture_comparison",
            comparison_id,
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID,
            ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
            earlier.plan.account_id,
            _traversal_profile_sha256(earlier),
            earlier.plan.capture_id,
            earlier_capture_sha256,
            tuple(
                (page.receipt.receipt_id, page.receipt.semantic_sha256) for page in earlier.pages
            ),
            earlier.pages[0].observation.received_at,
            earlier.pages[-1].observation.received_at,
            _view_sha256(earlier),
            later.plan.capture_id,
            later_capture_sha256,
            tuple((page.receipt.receipt_id, page.receipt.semantic_sha256) for page in later.pages),
            later.pages[0].observation.received_at,
            later.pages[-1].observation.received_at,
            _view_sha256(later),
            _timedelta_microseconds(_utc_separation(earlier, later)),
            True,
            self.added_provider_activity_ids,
            self.removed_provider_activity_ids,
            self.changed_provider_activity_ids,
            self.disposition,
            self.request_budget_enforced,
            self.authenticated_provider_evidence,
            self.runtime_current,
            self.capture_authenticated,
            self.durable_source_positions_authenticated,
            self.snapshot_isolation_qualified,
            self.provider_snapshot_complete,
            self.snapshot_complete,
            self.activity_history_complete,
            self.activity_history_consistent,
            self.converged,
            self.monotonic_timing_qualified,
            self.provider_activity_identity_qualified,
            self.provider_activity_sequence_identity_qualified,
            self.provider_activity_revision_identity_qualified,
            self.provider_execution_identity_qualified,
            self.canonical_execution_identity_qualified,
            self.provider_revision_identity_qualified,
            self.execution_revision_identity_qualified,
            self.provider_deduplication_identity_qualified,
            self.provider_bust_identity_qualified,
            self.provider_correction_identity_qualified,
            self.provider_deduplication_authorized,
            self.canonical_execution_fact_authorized,
            self.canonical_execution_revision_authorized,
            self.canonical_account_fact_authorized,
            self.canonical_ledger_fact_authorized,
            self.canonical_cash_fact_authorized,
            self.execution_application_authorized,
            self.bust_application_authorized,
            self.correction_application_authorized,
            self.manual_activity_application_authorized,
            self.normalized_fact_authorized,
            self.inbox_application_authorized,
            self.lifecycle_application_authorized,
            self.reconciliation_application_authorized,
            self.reconciliation_completion_authorized,
            self.reconciliation_complete,
            self.unknown_resolution_authorized,
            self.reservation_release_authorized,
            self.resubmission_authorized,
            self.readiness_transition_authorized,
            self.activity_snapshot_pagination_ready,
            self.decode_quarantine_ready,
            self.reconciliation_ready,
            self.dispatch_preflight_ready,
            self.paper_startup_ready,
            self.transport_authorized,
            self.broker_call_authorized,
            self.trading_effect_authorized,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())


def compare_alpaca_paper_account_activity_captures(
    earlier_capture: AlpacaPaperAccountActivityCapture,
    later_capture: AlpacaPaperAccountActivityCapture,
) -> AlpacaPaperAccountActivityComparison:
    """Compare two exact bounded captures without declaring history convergence."""

    earlier, later = _validate_pair(earlier_capture, later_capture)
    added, removed, changed = _differences(earlier, later)
    comparison = object.__new__(AlpacaPaperAccountActivityComparison)
    object.__setattr__(comparison, "earlier_capture", earlier)
    object.__setattr__(comparison, "later_capture", later)
    object.__setattr__(
        comparison,
        "disposition",
        _disposition(
            earlier,
            later,
            added_provider_activity_ids=added,
            removed_provider_activity_ids=removed,
            changed_provider_activity_ids=changed,
        ),
    )
    object.__setattr__(comparison, "added_provider_activity_ids", added)
    object.__setattr__(comparison, "removed_provider_activity_ids", removed)
    object.__setattr__(comparison, "changed_provider_activity_ids", changed)
    comparison._validate()
    return comparison


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256",
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION",
    "AlpacaPaperAccountActivityComparison",
    "AlpacaPaperAccountActivityComparisonConflict",
    "AlpacaPaperAccountActivityComparisonDisposition",
    "AlpacaPaperAccountActivityComparisonError",
    "compare_alpaca_paper_account_activity_captures",
]
