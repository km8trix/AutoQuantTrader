from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import pytest

from packages.adapters import broker as broker_exports
from packages.adapters.broker.alpaca_paper_account_activities import (
    AlpacaPaperAccountActivityCapture,
    AlpacaPaperAccountActivityPageDescription,
    append_alpaca_paper_account_activity_page,
    create_alpaca_paper_account_activity_plan,
    persist_then_decode_alpaca_paper_account_activity_page,
    start_alpaca_paper_account_activity_capture,
)
from packages.adapters.broker.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION,
    AlpacaPaperAccountActivityComparison,
    AlpacaPaperAccountActivityComparisonConflict,
    AlpacaPaperAccountActivityComparisonDisposition,
    AlpacaPaperAccountActivityComparisonError,
    compare_alpaca_paper_account_activity_captures,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressReceipt,
)

ACCOUNT_ID = "paper-account-activity-comparison"
BASE = datetime(2026, 7, 28, 19, 0, tzinfo=UTC)


def _activity(
    number: int,
    *,
    activity_id: str | None = None,
    transaction_time: str | None = None,
    price: str = "401.2300",
    quantity: str = "1.0000",
) -> dict[str, object]:
    return {
        "activity_type": "FILL",
        "cum_qty": "3.0000",
        "id": (f"opaque-activity-{number:04d}" if activity_id is None else activity_id),
        "leaves_qty": "7.0000",
        "order_id": str(UUID(int=number)),
        "price": price,
        "qty": quantity,
        "side": "buy",
        "symbol": "SPY",
        "transaction_time": (
            f"2026-07-28T14:58:{number:02d}Z" if transaction_time is None else transaction_time
        ),
        "type": "fill",
    }


def _body(
    activities: tuple[dict[str, object], ...],
    *,
    pretty: bool = False,
) -> bytes:
    if pretty:
        return json.dumps(
            activities,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    return json.dumps(
        activities,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _Recorder:
    def __init__(self) -> None:
        self.receipts: list[BrokerIngressReceipt] = []

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=len(self.receipts) + 1,
            previous_receipt_sha256=(
                None if not self.receipts else self.receipts[-1].semantic_sha256
            ),
        )
        self.receipts.append(receipt)
        return receipt


def _append_page(
    recorder: _Recorder,
    capture: AlpacaPaperAccountActivityCapture,
    *,
    source_key: str,
    activities: tuple[dict[str, object], ...],
    received_at: datetime,
    pretty: bool = False,
) -> AlpacaPaperAccountActivityCapture:
    description = capture.next_page_description
    assert type(description) is AlpacaPaperAccountActivityPageDescription
    page = persist_then_decode_alpaca_paper_account_activity_page(
        recorder,
        description,
        delivery_idempotency_key=(
            f"activity-comparison-delivery-{source_key}-{description.page_number:02d}"
        ),
        http_status=200,
        provider_request_id=(
            f"activity-comparison-request-{source_key}-{description.page_number:02d}"
        ),
        response_body=_body(activities, pretty=pretty),
        received_at=received_at,
        recorded_at=received_at + timedelta(milliseconds=1),
    )
    return append_alpaca_paper_account_activity_page(capture, page)


def _capture(
    recorder: _Recorder,
    *,
    capture_key: str,
    received_at: datetime,
    activities: tuple[dict[str, object], ...] = (),
    source_key: str | None = None,
    account_id: str = ACCOUNT_ID,
    page_size: int = 4,
    maximum_pages: int = 3,
    maximum_items: int = 12,
    pretty: bool = False,
) -> AlpacaPaperAccountActivityCapture:
    plan = create_alpaca_paper_account_activity_plan(
        account_id=account_id,
        capture_idempotency_key=capture_key,
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )
    capture = start_alpaca_paper_account_activity_capture(plan)
    return _append_page(
        recorder,
        capture,
        source_key=capture_key if source_key is None else source_key,
        activities=activities,
        received_at=received_at,
        pretty=pretty,
    )


def _pair(
    *,
    later_offset: timedelta = timedelta(seconds=2),
    earlier_activities: tuple[dict[str, object], ...] | None = None,
    later_activities: tuple[dict[str, object], ...] | None = None,
) -> tuple[AlpacaPaperAccountActivityCapture, AlpacaPaperAccountActivityCapture]:
    recorder = _Recorder()
    default = (_activity(1), _activity(2))
    earlier = _capture(
        recorder,
        capture_key="activity-comparison-capture-earlier",
        source_key="pair-earlier",
        received_at=BASE,
        activities=default if earlier_activities is None else earlier_activities,
    )
    later = _capture(
        recorder,
        capture_key="activity-comparison-capture-later",
        source_key="pair-later",
        received_at=BASE + later_offset,
        activities=default if later_activities is None else later_activities,
    )
    return earlier, later


def _two_page_capture(
    recorder: _Recorder,
    *,
    capture_key: str,
    source_key: str,
    window_started_at: datetime,
) -> AlpacaPaperAccountActivityCapture:
    plan = create_alpaca_paper_account_activity_plan(
        account_id=ACCOUNT_ID,
        capture_idempotency_key=capture_key,
        page_size=2,
        maximum_pages=3,
        maximum_items=6,
    )
    capture = start_alpaca_paper_account_activity_capture(plan)
    for page_index, activities in enumerate(
        (
            (_activity(1), _activity(2)),
            (_activity(3),),
        )
    ):
        capture = _append_page(
            recorder,
            capture,
            source_key=source_key,
            activities=activities,
            received_at=window_started_at + timedelta(seconds=page_index),
        )
    assert capture.pagination_exhausted is True
    return capture


def _assert_no_authority(value: object) -> None:
    for property_name in (
        "request_budget_enforced",
        "authenticated_provider_evidence",
        "runtime_current",
        "capture_authenticated",
        "durable_source_positions_authenticated",
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
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(value, property_name) is False


def test_exact_two_second_equal_view_is_stable_and_explicitly_unqualified() -> None:
    earlier, later = _pair()

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)
    repeated = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION == (
        "phase4af-exact-account-activity-view-comparison-v1"
    )
    assert ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_ID == (
        "phase4af-exact-account-activity-view-comparison-policy-v1"
    )
    assert len(ALPACA_PAPER_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256) == 64
    assert timedelta(seconds=2) == (ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION)
    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.account_id == ACCOUNT_ID
    assert len(comparison.traversal_profile_sha256) == 64
    assert comparison.earlier_window_started_at == BASE
    assert comparison.earlier_window_ended_at == BASE
    assert comparison.later_window_started_at == BASE + timedelta(seconds=2)
    assert comparison.later_window_ended_at == BASE + timedelta(seconds=2)
    assert comparison.observed_utc_separation == timedelta(seconds=2)
    assert comparison.observed_utc_separation_microseconds == 2_000_000
    assert comparison.capture_windows_non_overlapping is True
    assert comparison.minimum_utc_separation_observed is True
    assert comparison.provider_activity_ids_are_opaque_set_keys is True
    assert comparison.activity_views_equal is True
    assert comparison.exact_activity_view_match_unqualified is True
    assert comparison.earlier_view == comparison.later_view
    assert comparison.earlier_view_sha256 == comparison.later_view_sha256
    assert comparison.added_provider_activity_ids == ()
    assert comparison.removed_provider_activity_ids == ()
    assert comparison.changed_provider_activity_ids == ()
    assert comparison.additional_reconciliation_required is True
    assert comparison == repeated
    assert comparison.semantic_sha256 == repeated.semantic_sha256
    assert str(UUID(comparison.comparison_id)) == comparison.comparison_id
    assert (
        broker_exports.compare_alpaca_paper_account_activity_captures
        is compare_alpaca_paper_account_activity_captures
    )
    _assert_no_authority(comparison)


@pytest.mark.parametrize(
    ("later_offset", "non_overlapping"),
    (
        (timedelta(seconds=2, microseconds=-1), True),
        (timedelta(microseconds=-1), False),
    ),
)
def test_too_close_waits_before_differences_without_qualifying_time(
    later_offset: timedelta,
    non_overlapping: bool,
) -> None:
    earlier, later = _pair(
        later_offset=later_offset,
        later_activities=(_activity(1, price="402.0000"), _activity(2)),
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert comparison.capture_windows_non_overlapping is non_overlapping
    assert comparison.minimum_utc_separation_observed is False
    assert comparison.activity_views_equal is False
    assert comparison.changed_provider_activity_ids == ("opaque-activity-0001",)
    assert comparison.exact_activity_view_match_unqualified is False
    assert comparison.monotonic_timing_qualified is False
    assert comparison.converged is False


def test_added_removed_and_changed_activity_ids_are_exact_and_sorted() -> None:
    earlier, later = _pair(
        later_offset=timedelta(seconds=3),
        earlier_activities=(_activity(1), _activity(2), _activity(3)),
        later_activities=(
            _activity(2, quantity="1.00"),
            _activity(3),
            _activity(4),
        ),
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.ACTIVITY_VIEW_DIFFERENT
    )
    assert comparison.added_provider_activity_ids == ("opaque-activity-0004",)
    assert comparison.removed_provider_activity_ids == ("opaque-activity-0001",)
    assert comparison.changed_provider_activity_ids == ("opaque-activity-0002",)
    assert comparison.activity_views_equal is False
    assert comparison.earlier_view_sha256 != comparison.later_view_sha256
    assert comparison.canonical_execution_fact_authorized is False
    assert comparison.correction_application_authorized is False
    assert comparison.bust_application_authorized is False


def test_provider_ids_are_only_opaque_set_keys_not_order_or_revision_tokens() -> None:
    same_instant = "2026-07-28T14:58:00Z"
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="activity-comparison-opaque-earlier",
        source_key="opaque-earlier",
        received_at=BASE,
        activities=(
            _activity(1, activity_id="z-opaque-key", transaction_time=same_instant),
            _activity(2, activity_id="a-opaque-key", transaction_time=same_instant),
        ),
    )
    later = _capture(
        recorder,
        capture_key="activity-comparison-opaque-later",
        source_key="opaque-later",
        received_at=BASE + timedelta(seconds=3),
        activities=(
            _activity(2, activity_id="a-opaque-key", transaction_time=same_instant),
            _activity(1, activity_id="z-opaque-key", transaction_time=same_instant),
        ),
        pretty=True,
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert tuple(provider_id for provider_id, _ in comparison.earlier_view) == (
        "a-opaque-key",
        "z-opaque-key",
    )
    assert comparison.earlier_view == comparison.later_view
    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.provider_activity_ids_are_opaque_set_keys is True
    assert comparison.provider_activity_identity_qualified is False
    assert comparison.provider_activity_sequence_identity_qualified is False
    assert comparison.provider_activity_revision_identity_qualified is False
    assert comparison.provider_deduplication_identity_qualified is False


def test_activity_id_substitution_is_added_and_removed_not_changed() -> None:
    earlier, later = _pair(
        earlier_activities=(_activity(5, activity_id="old-opaque-key"),),
        later_activities=(_activity(5, activity_id="new-opaque-key"),),
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert comparison.added_provider_activity_ids == ("new-opaque-key",)
    assert comparison.removed_provider_activity_ids == ("old-opaque-key",)
    assert comparison.changed_provider_activity_ids == ()


def test_raw_format_capture_identity_and_source_identity_do_not_change_view() -> None:
    recorder = _Recorder()
    activities = (_activity(1), _activity(2))
    earlier = _capture(
        recorder,
        capture_key="activity-comparison-format-earlier",
        source_key="format-earlier",
        received_at=BASE,
        activities=activities,
    )
    later = _capture(
        recorder,
        capture_key="activity-comparison-format-later",
        source_key="format-later",
        received_at=BASE + timedelta(seconds=3),
        activities=activities,
        pretty=True,
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert earlier.plan.capture_id != later.plan.capture_id
    assert earlier.pages[0].observation.response_sha256 != (
        later.pages[0].observation.response_sha256
    )
    assert earlier.semantic_sha256 != later.semantic_sha256
    assert comparison.earlier_view == comparison.later_view
    assert comparison.earlier_view_sha256 == comparison.later_view_sha256
    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED
    )


def test_multi_page_windows_use_exact_earlier_final_to_later_first_spacing() -> None:
    recorder = _Recorder()
    earlier = _two_page_capture(
        recorder,
        capture_key="activity-comparison-multipage-earlier",
        source_key="multipage-earlier",
        window_started_at=BASE,
    )
    later = _two_page_capture(
        recorder,
        capture_key="activity-comparison-multipage-later",
        source_key="multipage-later",
        window_started_at=BASE + timedelta(seconds=3),
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert comparison.earlier_window_started_at == BASE
    assert comparison.earlier_window_ended_at == BASE + timedelta(seconds=1)
    assert comparison.later_window_started_at == BASE + timedelta(seconds=3)
    assert comparison.later_window_ended_at == BASE + timedelta(seconds=4)
    assert comparison.observed_utc_separation == timedelta(seconds=2)
    assert earlier.pages[-1].receipt.ingress_sequence == 2
    assert later.pages[0].receipt.ingress_sequence == 3
    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED
    )


def test_two_empty_exhausted_views_match_without_history_or_reconciliation_claims() -> None:
    earlier, later = _pair(earlier_activities=(), later_activities=())

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert earlier.pagination_exhausted is True
    assert later.pagination_exhausted is True
    assert comparison.earlier_view == ()
    assert comparison.later_view == ()
    assert comparison.activity_views_equal is True
    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.EXACT_ACTIVITY_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.activity_history_complete is False
    assert comparison.reconciliation_complete is False
    assert comparison.paper_startup_ready is False


def test_bounded_truncation_precedes_timing_differences_and_equal_views() -> None:
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="activity-comparison-truncated-earlier",
        source_key="truncated-earlier",
        received_at=BASE,
        activities=(_activity(1),),
        page_size=1,
        maximum_pages=1,
        maximum_items=4,
    )
    later = _capture(
        recorder,
        capture_key="activity-comparison-truncated-later",
        source_key="truncated-later",
        received_at=BASE + timedelta(seconds=1),
        activities=(_activity(2),),
        page_size=1,
        maximum_pages=1,
        maximum_items=4,
    )

    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    assert earlier.bounded_truncation is True
    assert later.bounded_truncation is True
    assert comparison.activity_views_equal is False
    assert comparison.minimum_utc_separation_observed is False
    assert comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert comparison.exact_activity_view_match_unqualified is False

    equal_later = _capture(
        recorder,
        capture_key="activity-comparison-truncated-equal-later",
        source_key="truncated-equal-later",
        received_at=BASE + timedelta(seconds=4),
        activities=(_activity(1),),
        page_size=1,
        maximum_pages=1,
        maximum_items=4,
    )
    equal_comparison = compare_alpaca_paper_account_activity_captures(
        earlier,
        equal_later,
    )
    assert equal_comparison.activity_views_equal is True
    assert equal_comparison.minimum_utc_separation_observed is True
    assert equal_comparison.disposition is (
        AlpacaPaperAccountActivityComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )


def test_in_progress_capture_cannot_be_compared() -> None:
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="activity-comparison-in-progress-earlier",
        source_key="in-progress-earlier",
        received_at=BASE,
        activities=(_activity(1),),
        page_size=1,
        maximum_pages=2,
        maximum_items=4,
    )
    later = _capture(
        recorder,
        capture_key="activity-comparison-in-progress-later",
        source_key="in-progress-later",
        received_at=BASE + timedelta(seconds=3),
        activities=(_activity(1),),
        page_size=1,
        maximum_pages=2,
        maximum_items=4,
    )

    assert earlier.next_page_description is not None
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonError,
        match="ended bounded traversals",
    ):
        compare_alpaca_paper_account_activity_captures(earlier, later)


def test_same_account_profile_distinct_identity_and_disjoint_sources_are_required() -> None:
    different_account_recorder = _Recorder()
    first_account = _capture(
        different_account_recorder,
        capture_key="activity-comparison-account-earlier",
        source_key="account-earlier",
        received_at=BASE,
    )
    second_account = _capture(
        different_account_recorder,
        capture_key="activity-comparison-account-later",
        source_key="account-later",
        received_at=BASE + timedelta(seconds=3),
        account_id="different-paper-account",
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="different accounts",
    ):
        compare_alpaca_paper_account_activity_captures(
            first_account,
            second_account,
        )

    recorder = _Recorder()
    first_profile = _capture(
        recorder,
        capture_key="activity-comparison-profile-earlier",
        source_key="profile-earlier",
        received_at=BASE,
        page_size=3,
    )
    second_profile = _capture(
        recorder,
        capture_key="activity-comparison-profile-later",
        source_key="profile-later",
        received_at=BASE + timedelta(seconds=3),
        page_size=4,
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="different traversal profiles",
    ):
        compare_alpaca_paper_account_activity_captures(
            first_profile,
            second_profile,
        )

    same_identity_first = _capture(
        recorder,
        capture_key="activity-comparison-same-identity",
        source_key="same-identity-first",
        received_at=BASE + timedelta(seconds=10),
    )
    same_identity_second = _capture(
        recorder,
        capture_key="activity-comparison-same-identity",
        source_key="same-identity-second",
        received_at=BASE + timedelta(seconds=13),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="distinct capture identities",
    ):
        compare_alpaca_paper_account_activity_captures(
            same_identity_first,
            same_identity_second,
        )

    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="distinct capture identities",
    ):
        compare_alpaca_paper_account_activity_captures(
            same_identity_first,
            same_identity_first,
        )

    shared_receipt_first = _capture(
        recorder,
        capture_key="activity-comparison-shared-receipt-earlier",
        source_key="shared-receipt-source",
        received_at=BASE + timedelta(seconds=20),
    )
    shared_receipt_second = _capture(
        recorder,
        capture_key="activity-comparison-shared-receipt-later",
        source_key="shared-receipt-source",
        received_at=BASE + timedelta(seconds=23),
    )
    assert (
        shared_receipt_first.pages[0].receipt.receipt_id
        == shared_receipt_second.pages[0].receipt.receipt_id
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="reuse a raw ingress receipt",
    ):
        compare_alpaca_paper_account_activity_captures(
            shared_receipt_first,
            shared_receipt_second,
        )


def test_strict_raw_source_order_rejects_reversal_and_independent_sequences() -> None:
    earlier, later = _pair(later_offset=timedelta(seconds=3))
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="does not follow",
    ):
        compare_alpaca_paper_account_activity_captures(later, earlier)

    independent_earlier = _capture(
        _Recorder(),
        capture_key="activity-comparison-independent-earlier",
        source_key="independent-earlier",
        received_at=BASE,
    )
    independent_later = _capture(
        _Recorder(),
        capture_key="activity-comparison-independent-later",
        source_key="independent-later",
        received_at=BASE + timedelta(seconds=3),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="does not follow",
    ):
        compare_alpaca_paper_account_activity_captures(
            independent_earlier,
            independent_later,
        )


def test_result_is_proof_constructed_frozen_and_rejects_forged_claims() -> None:
    earlier, later = _pair()
    comparison = compare_alpaca_paper_account_activity_captures(earlier, later)

    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAccountActivityComparison()
    mutable: Any = comparison
    with pytest.raises(FrozenInstanceError):
        mutable.disposition = (
            AlpacaPaperAccountActivityComparisonDisposition.ACTIVITY_VIEW_DIFFERENT
        )

    forged_differences = object.__new__(AlpacaPaperAccountActivityComparison)
    object.__setattr__(forged_differences, "earlier_capture", earlier)
    object.__setattr__(forged_differences, "later_capture", later)
    object.__setattr__(
        forged_differences,
        "disposition",
        AlpacaPaperAccountActivityComparisonDisposition.ACTIVITY_VIEW_DIFFERENT,
    )
    object.__setattr__(
        forged_differences,
        "added_provider_activity_ids",
        ("forged-opaque-key",),
    )
    object.__setattr__(forged_differences, "removed_provider_activity_ids", ())
    object.__setattr__(forged_differences, "changed_provider_activity_ids", ())
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="differences conflict",
    ):
        _ = forged_differences.semantic_sha256

    forged_disposition = object.__new__(AlpacaPaperAccountActivityComparison)
    object.__setattr__(forged_disposition, "earlier_capture", earlier)
    object.__setattr__(forged_disposition, "later_capture", later)
    object.__setattr__(
        forged_disposition,
        "disposition",
        AlpacaPaperAccountActivityComparisonDisposition.ACTIVITY_VIEW_DIFFERENT,
    )
    object.__setattr__(forged_disposition, "added_provider_activity_ids", ())
    object.__setattr__(forged_disposition, "removed_provider_activity_ids", ())
    object.__setattr__(forged_disposition, "changed_provider_activity_ids", ())
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="disposition conflicts",
    ):
        _ = forged_disposition.semantic_sha256


def test_validate_once_semantic_material_is_byte_stable_and_fail_closed() -> None:
    earlier, later = _pair()
    comparison = compare_alpaca_paper_account_activity_captures(
        earlier,
        later,
    )

    assert comparison.comparison_id == "0a6d778e-5709-5a7e-8e07-dfbfa28772c6"
    assert comparison.semantic_sha256 == (
        "df5ebf0948727322af090111a45a0caf80fd3012acdacedcf06ec3cddfa7bb59"
    )

    object.__setattr__(
        comparison,
        "added_provider_activity_ids",
        ("forged-opaque-key",),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonConflict,
        match="differences conflict",
    ):
        _ = comparison.semantic_sha256


def test_exact_types_are_required() -> None:
    earlier, later = _pair()

    with pytest.raises(
        AlpacaPaperAccountActivityComparisonError,
        match="earlier activity view",
    ):
        compare_alpaca_paper_account_activity_captures(
            cast(Any, object()),
            later,
        )
    with pytest.raises(
        AlpacaPaperAccountActivityComparisonError,
        match="later activity view",
    ):
        compare_alpaca_paper_account_activity_captures(
            earlier,
            cast(Any, object()),
        )
