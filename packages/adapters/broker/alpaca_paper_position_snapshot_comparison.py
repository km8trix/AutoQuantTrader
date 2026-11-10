"""Pure, non-authorizing comparison of two Alpaca paper position captures.

Phase 4R retains and strictly decodes one bounded ``GET /v2/positions``
response.  This module compares two distinct account-local captures by stable
asset identity.  Equal views remain explicitly unqualified: UTC receive-time
spacing is local evidence, not provider snapshot isolation, a revision token,
convergence, or reconciliation authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_POSITIONS_PATH,
)
from packages.adapters.broker.alpaca_paper_positions import (
    ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
    ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS,
    ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES,
    ALPACA_PAPER_POSITION_SNAPSHOT_REVIEWED_ON,
    AlpacaPaperPositionSnapshotError,
    PersistedAlpacaPaperPositionSnapshot,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION = (
    "phase4s-exact-position-view-comparison-v1"
)
ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_ID = (
    "phase4s-exact-position-view-comparison-policy-v1"
)
ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION = timedelta(seconds=2)


class AlpacaPaperPositionSnapshotComparisonError(AlpacaPaperPositionSnapshotError):
    """Two position captures cannot be compared under the frozen contract."""


class AlpacaPaperPositionSnapshotComparisonConflict(AlpacaPaperPositionSnapshotComparisonError):
    """Comparison inputs or claimed results conflict with exact source evidence."""


class AlpacaPaperPositionSnapshotComparisonDisposition(StrEnum):
    """Closed meanings for one exact position-view comparison."""

    EXACT_POSITION_VIEW_MATCH_UNQUALIFIED = "exact_position_view_match_unqualified"
    POSITION_VIEW_DIFFERENT = "position_view_different"
    WAITING_MINIMUM_SEPARATION = "waiting_minimum_separation"


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _timedelta_microseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
        "comparison_policy",
        ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_ID,
        _timedelta_microseconds(ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION),
        tuple(AlpacaPaperPositionSnapshotComparisonDisposition),
        "same_account_and_position_wire_profile",
        "distinct_capture_identity",
        "disjoint_raw_ingress_receipts",
        "strict_account_local_ingress_order",
        "asset_id_sorted_exact_position_semantics",
        "exact_provider_decimal_lexemes_are_semantic",
        "no_snapshot_isolation_revision_convergence_or_reconciliation_authority",
    )
)


class _NoPositionSnapshotComparisonAuthority:
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


def _capture_profile_sha256(
    capture: PersistedAlpacaPaperPositionSnapshot,
) -> str:
    return _semantic_sha256(
        (
            ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
            "position_capture_profile",
            ALPACA_PAPER_POSITION_SNAPSHOT_CONTRACT_VERSION,
            ALPACA_PAPER_POSITION_SNAPSHOT_REVIEWED_ON,
            ALPACA_PAPER_CAPABILITIES.semantic_sha256,
            capture.observation.description.method,
            capture.observation.description.base_url,
            ALPACA_POSITIONS_PATH,
            tuple(capture.observation.description.query.items()),
            ALPACA_PAPER_POSITION_SNAPSHOT_MAX_RESPONSE_BYTES,
            ALPACA_PAPER_POSITION_SNAPSHOT_MAX_POSITIONS,
            "strict_us_equity_position_object",
            "exact_decimal_lexeme_semantics",
        )
    )


def _ordered_view(
    capture: PersistedAlpacaPaperPositionSnapshot,
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (
                position.asset_id,
                position.semantic_sha256,
            )
            for position in capture.observation.positions
        )
    )


def _view_sha256(
    capture: PersistedAlpacaPaperPositionSnapshot,
) -> str:
    return _semantic_sha256(
        (
            ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
            "exact_decoded_position_view",
            capture.observation.description.account_id,
            _capture_profile_sha256(capture),
            _ordered_view(capture),
        )
    )


def _validate_pair(
    earlier_capture: object,
    later_capture: object,
) -> tuple[
    PersistedAlpacaPaperPositionSnapshot,
    PersistedAlpacaPaperPositionSnapshot,
]:
    if type(earlier_capture) is not PersistedAlpacaPaperPositionSnapshot:
        raise AlpacaPaperPositionSnapshotComparisonError(
            "earlier position view must be an exact Phase 4R persisted capture"
        )
    if type(later_capture) is not PersistedAlpacaPaperPositionSnapshot:
        raise AlpacaPaperPositionSnapshotComparisonError(
            "later position view must be an exact Phase 4R persisted capture"
        )
    earlier_capture.__post_init__()
    later_capture.__post_init__()
    if (
        earlier_capture.observation.description.account_id
        != later_capture.observation.description.account_id
    ):
        raise AlpacaPaperPositionSnapshotComparisonConflict(
            "position captures belong to different accounts"
        )
    if _capture_profile_sha256(earlier_capture) != _capture_profile_sha256(later_capture):
        raise AlpacaPaperPositionSnapshotComparisonConflict(
            "position captures use different wire profiles"
        )
    if earlier_capture.capture_id == later_capture.capture_id:
        raise AlpacaPaperPositionSnapshotComparisonConflict(
            "position comparison requires distinct capture identities"
        )
    if earlier_capture.receipt.receipt_id == later_capture.receipt.receipt_id:
        raise AlpacaPaperPositionSnapshotComparisonConflict(
            "position captures reuse a raw ingress receipt"
        )
    if earlier_capture.receipt.ingress_sequence >= later_capture.receipt.ingress_sequence:
        raise AlpacaPaperPositionSnapshotComparisonConflict(
            "later position capture does not follow the earlier raw ingress source"
        )
    return earlier_capture, later_capture


def _differences(
    earlier_capture: PersistedAlpacaPaperPositionSnapshot,
    later_capture: PersistedAlpacaPaperPositionSnapshot,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    earlier = dict(_ordered_view(earlier_capture))
    later = dict(_ordered_view(later_capture))
    added = tuple(sorted(later.keys() - earlier.keys()))
    removed = tuple(sorted(earlier.keys() - later.keys()))
    changed = tuple(
        sorted(
            asset_id
            for asset_id in earlier.keys() & later.keys()
            if earlier[asset_id] != later[asset_id]
        )
    )
    return added, removed, changed


def _utc_separation(
    earlier_capture: PersistedAlpacaPaperPositionSnapshot,
    later_capture: PersistedAlpacaPaperPositionSnapshot,
) -> timedelta:
    return later_capture.observation.received_at - earlier_capture.observation.received_at


def _disposition(
    earlier_capture: PersistedAlpacaPaperPositionSnapshot,
    later_capture: PersistedAlpacaPaperPositionSnapshot,
    *,
    added_asset_ids: tuple[str, ...],
    removed_asset_ids: tuple[str, ...],
    changed_asset_ids: tuple[str, ...],
) -> AlpacaPaperPositionSnapshotComparisonDisposition:
    if (
        _utc_separation(earlier_capture, later_capture)
        < ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION
    ):
        return AlpacaPaperPositionSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    if added_asset_ids or removed_asset_ids or changed_asset_ids:
        return AlpacaPaperPositionSnapshotComparisonDisposition.POSITION_VIEW_DIFFERENT
    return AlpacaPaperPositionSnapshotComparisonDisposition.EXACT_POSITION_VIEW_MATCH_UNQUALIFIED


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionSnapshotComparison(_NoPositionSnapshotComparisonAuthority):
    """Proof-constructed exact comparison of two raw-first position captures."""

    earlier_capture: PersistedAlpacaPaperPositionSnapshot
    later_capture: PersistedAlpacaPaperPositionSnapshot
    disposition: AlpacaPaperPositionSnapshotComparisonDisposition
    added_asset_ids: tuple[str, ...]
    removed_asset_ids: tuple[str, ...]
    changed_asset_ids: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperPositionSnapshotComparison must be proof-constructed")

    def _validate(self) -> None:
        earlier, later = _validate_pair(
            self.earlier_capture,
            self.later_capture,
        )
        expected_added, expected_removed, expected_changed = _differences(
            earlier,
            later,
        )
        if (
            self.added_asset_ids != expected_added
            or self.removed_asset_ids != expected_removed
            or self.changed_asset_ids != expected_changed
        ):
            raise AlpacaPaperPositionSnapshotComparisonConflict(
                "position comparison differences conflict with exact captures"
            )
        expected_disposition = _disposition(
            earlier,
            later,
            added_asset_ids=expected_added,
            removed_asset_ids=expected_removed,
            changed_asset_ids=expected_changed,
        )
        if (
            type(self.disposition) is not AlpacaPaperPositionSnapshotComparisonDisposition
            or self.disposition is not expected_disposition
        ):
            raise AlpacaPaperPositionSnapshotComparisonConflict(
                "position comparison disposition conflicts with exact captures"
            )

    @property
    def account_id(self) -> str:
        self._validate()
        return self.earlier_capture.observation.description.account_id

    @property
    def capture_profile_sha256(self) -> str:
        self._validate()
        return _capture_profile_sha256(self.earlier_capture)

    @property
    def earlier_received_at(self) -> datetime:
        self._validate()
        return self.earlier_capture.observation.received_at

    @property
    def later_received_at(self) -> datetime:
        self._validate()
        return self.later_capture.observation.received_at

    @property
    def observed_utc_separation(self) -> timedelta:
        self._validate()
        return _utc_separation(self.earlier_capture, self.later_capture)

    @property
    def observed_utc_separation_microseconds(self) -> int:
        return _timedelta_microseconds(self.observed_utc_separation)

    @property
    def receive_windows_non_overlapping(self) -> bool:
        return self.observed_utc_separation >= timedelta()

    @property
    def minimum_utc_separation_observed(self) -> bool:
        return self.observed_utc_separation >= ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION

    @property
    def earlier_view(self) -> tuple[tuple[str, str], ...]:
        self._validate()
        return _ordered_view(self.earlier_capture)

    @property
    def later_view(self) -> tuple[tuple[str, str], ...]:
        self._validate()
        return _ordered_view(self.later_capture)

    @property
    def earlier_view_sha256(self) -> str:
        self._validate()
        return _view_sha256(self.earlier_capture)

    @property
    def later_view_sha256(self) -> str:
        self._validate()
        return _view_sha256(self.later_capture)

    @property
    def position_views_equal(self) -> bool:
        self._validate()
        return not (self.added_asset_ids or self.removed_asset_ids or self.changed_asset_ids)

    @property
    def exact_position_view_match_unqualified(self) -> bool:
        self._validate()
        return self.disposition is (
            AlpacaPaperPositionSnapshotComparisonDisposition.EXACT_POSITION_VIEW_MATCH_UNQUALIFIED
        )

    @property
    def additional_reconciliation_required(self) -> bool:
        return True

    @property
    def comparison_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-position-view-comparison",
            ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256,
            self.earlier_capture.capture_id,
            self.earlier_capture.semantic_sha256,
            self.later_capture.capture_id,
            self.later_capture.semantic_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        self._validate()
        return _semantic_sha256(
            (
                ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
                "position_snapshot_comparison",
                self.comparison_id,
                ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_ID,
                ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256,
                self.account_id,
                self.capture_profile_sha256,
                self.earlier_capture.capture_id,
                self.earlier_capture.receipt.receipt_id,
                self.earlier_capture.receipt.semantic_sha256,
                self.earlier_capture.semantic_sha256,
                self.earlier_received_at,
                self.earlier_view_sha256,
                self.later_capture.capture_id,
                self.later_capture.receipt.receipt_id,
                self.later_capture.receipt.semantic_sha256,
                self.later_capture.semantic_sha256,
                self.later_received_at,
                self.later_view_sha256,
                self.observed_utc_separation_microseconds,
                self.added_asset_ids,
                self.removed_asset_ids,
                self.changed_asset_ids,
                self.disposition,
                self.request_budget_enforced,
                self.authenticated_provider_evidence,
                self.runtime_current,
                self.capture_authenticated,
                self.durable_source_positions_authenticated,
                self.snapshot_isolation_qualified,
                self.provider_snapshot_complete,
                self.snapshot_complete,
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
                self.reservation_release_authorized,
                self.resubmission_authorized,
                self.canonical_position_fact_authorized,
                self.canonical_execution_fact_authorized,
                self.canonical_account_fact_authorized,
                self.canonical_ledger_fact_authorized,
                self.canonical_cash_fact_authorized,
                self.readiness_transition_authorized,
                self.reconciliation_ready,
                self.dispatch_preflight_ready,
                self.paper_startup_ready,
                self.transport_authorized,
                self.broker_call_authorized,
                self.trading_effect_authorized,
                self.converged,
            )
        )


def compare_alpaca_paper_position_snapshots(
    earlier_capture: PersistedAlpacaPaperPositionSnapshot,
    later_capture: PersistedAlpacaPaperPositionSnapshot,
) -> AlpacaPaperPositionSnapshotComparison:
    """Compare two exact captures without declaring provider convergence."""

    earlier, later = _validate_pair(earlier_capture, later_capture)
    added, removed, changed = _differences(earlier, later)
    comparison = object.__new__(AlpacaPaperPositionSnapshotComparison)
    object.__setattr__(comparison, "earlier_capture", earlier)
    object.__setattr__(comparison, "later_capture", later)
    object.__setattr__(
        comparison,
        "disposition",
        _disposition(
            earlier,
            later,
            added_asset_ids=added,
            removed_asset_ids=removed,
            changed_asset_ids=changed,
        ),
    )
    object.__setattr__(comparison, "added_asset_ids", added)
    object.__setattr__(comparison, "removed_asset_ids", removed)
    object.__setattr__(comparison, "changed_asset_ids", changed)
    comparison._validate()
    return comparison


__all__ = [
    "ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_CONTRACT_VERSION",
    "ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_ID",
    "ALPACA_PAPER_POSITION_SNAPSHOT_COMPARISON_POLICY_SHA256",
    "ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION",
    "AlpacaPaperPositionSnapshotComparison",
    "AlpacaPaperPositionSnapshotComparisonConflict",
    "AlpacaPaperPositionSnapshotComparisonDisposition",
    "AlpacaPaperPositionSnapshotComparisonError",
    "compare_alpaca_paper_position_snapshots",
]
