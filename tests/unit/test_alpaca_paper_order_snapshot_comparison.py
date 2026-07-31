from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest

from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_ID,
    ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256,
    ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION,
    AlpacaPaperOrderSnapshotComparison,
    AlpacaPaperOrderSnapshotComparisonConflict,
    AlpacaPaperOrderSnapshotComparisonDisposition,
    AlpacaPaperOrderSnapshotComparisonError,
    compare_alpaca_paper_order_snapshot_captures,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotCapture,
    append_alpaca_paper_order_snapshot_page,
    create_alpaca_paper_order_snapshot_plan,
    persist_then_decode_alpaca_paper_order_snapshot_page,
    start_alpaca_paper_order_snapshot,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressReceipt,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/broker/alpaca_paper/lookup_found.json"
BASE = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)


def _base_order() -> dict[str, Any]:
    value = json.loads(FIXTURE.read_bytes())
    assert type(value) is dict
    return value


def _order(
    number: int,
    *,
    updated_at: str = "2026-07-28T14:59:00.123456789Z",
    subtag: str | None = None,
) -> dict[str, Any]:
    value = _base_order()
    value["id"] = str(UUID(int=number))
    value["client_order_id"] = f"comparison-client-order-{number:04d}"
    value["created_at"] = "2026-07-28T14:58:00.123456789Z"
    value["submitted_at"] = "2026-07-28T14:58:30.123456789Z"
    value["updated_at"] = updated_at
    value["subtag"] = subtag
    return value


def _body(
    *orders: dict[str, Any],
    pretty: bool = False,
) -> bytes:
    if pretty:
        return json.dumps(
            orders,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    return json.dumps(
        orders,
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


def _capture(
    recorder: _Recorder,
    *,
    capture_key: str,
    request_suffix: str,
    received_at: datetime,
    orders: tuple[dict[str, Any], ...] = (),
    account_id: str = "paper-account-comparison",
    page_limit: int = 8,
    maximum_pages: int = 3,
    pretty: bool = False,
) -> AlpacaPaperOrderSnapshotCapture:
    plan = create_alpaca_paper_order_snapshot_plan(
        account_id=account_id,
        capture_idempotency_key=capture_key,
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )
    capture = start_alpaca_paper_order_snapshot(plan)
    description = capture.next_page_description
    assert description is not None
    page = persist_then_decode_alpaca_paper_order_snapshot_page(
        recorder,
        description,
        delivery_idempotency_key=f"comparison-delivery-{request_suffix}",
        http_status=200,
        provider_request_id=f"comparison-provider-request-{request_suffix}",
        response_body=_body(*orders, pretty=pretty),
        received_at=received_at,
        recorded_at=received_at + timedelta(milliseconds=1),
    )
    return append_alpaca_paper_order_snapshot_page(capture, page)


def _pair(
    *,
    later_offset: timedelta = timedelta(seconds=2),
    earlier_orders: tuple[dict[str, Any], ...] | None = None,
    later_orders: tuple[dict[str, Any], ...] | None = None,
) -> tuple[AlpacaPaperOrderSnapshotCapture, AlpacaPaperOrderSnapshotCapture]:
    recorder = _Recorder()
    default_orders = (_order(1), _order(2))
    earlier = _capture(
        recorder,
        capture_key="comparison-capture-earlier",
        request_suffix="earlier",
        received_at=BASE,
        orders=default_orders if earlier_orders is None else earlier_orders,
    )
    later = _capture(
        recorder,
        capture_key="comparison-capture-later",
        request_suffix="later",
        received_at=BASE + later_offset,
        orders=default_orders if later_orders is None else later_orders,
    )
    return earlier, later


def _two_page_capture(
    recorder: _Recorder,
    *,
    capture_key: str,
    request_suffix: str,
    window_started_at: datetime,
) -> AlpacaPaperOrderSnapshotCapture:
    plan = create_alpaca_paper_order_snapshot_plan(
        account_id="paper-account-comparison",
        capture_idempotency_key=capture_key,
        page_limit=2,
        maximum_pages=3,
    )
    capture = start_alpaca_paper_order_snapshot(plan)
    for page_index, orders in enumerate(
        (
            (_order(1), _order(2)),
            (_order(3),),
        )
    ):
        description = capture.next_page_description
        assert description is not None
        received_at = window_started_at + timedelta(seconds=page_index)
        page = persist_then_decode_alpaca_paper_order_snapshot_page(
            recorder,
            description,
            delivery_idempotency_key=(f"comparison-delivery-{request_suffix}-{page_index + 1}"),
            http_status=200,
            provider_request_id=(f"comparison-provider-request-{request_suffix}-{page_index + 1}"),
            response_body=_body(*orders),
            received_at=received_at,
            recorded_at=received_at + timedelta(milliseconds=1),
        )
        capture = append_alpaca_paper_order_snapshot_page(capture, page)
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
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
        "converged",
    ):
        assert getattr(value, property_name) is False


def test_exact_two_second_equal_view_is_explicitly_unqualified() -> None:
    earlier, later = _pair()

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)
    repeated = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_CONTRACT_VERSION == (
        "phase4n-bounded-order-view-comparison-v1"
    )
    assert ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_ID == (
        "phase4n-exact-order-view-comparison-policy-v1"
    )
    assert ALPACA_PAPER_ORDER_SNAPSHOT_COMPARISON_POLICY_SHA256 == (
        "6015d0d1ff97d1de6dc3feece5efbb1360f8b9a5a994a638ec537ee1348e2823"
    )
    assert timedelta(seconds=2) == ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION
    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.EXACT_ORDER_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.observed_utc_separation == timedelta(seconds=2)
    assert comparison.observed_utc_separation_microseconds == 2_000_000
    assert comparison.capture_windows_non_overlapping is True
    assert comparison.minimum_utc_separation_observed is True
    assert comparison.order_views_equal is True
    assert comparison.exact_order_view_match_unqualified is True
    assert comparison.earlier_view_sha256 == comparison.later_view_sha256
    assert comparison.added_provider_order_ids == ()
    assert comparison.removed_provider_order_ids == ()
    assert comparison.changed_provider_order_ids == ()
    assert comparison.additional_reconciliation_required is True
    assert comparison == repeated
    assert comparison.semantic_sha256 == repeated.semantic_sha256
    assert len(comparison.comparison_id) == 36
    _assert_no_authority(comparison)


def test_equal_view_before_two_seconds_waits_without_claiming_monotonic_time() -> None:
    earlier, later = _pair(
        later_offset=timedelta(seconds=2, microseconds=-1),
    )

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert comparison.observed_utc_separation_microseconds == 1_999_999
    assert comparison.capture_windows_non_overlapping is True
    assert comparison.minimum_utc_separation_observed is False
    assert comparison.order_views_equal is True
    assert comparison.exact_order_view_match_unqualified is False
    assert comparison.monotonic_timing_qualified is False
    assert comparison.converged is False


def test_capture_window_overlap_is_waiting_even_when_decoded_views_match() -> None:
    earlier, later = _pair(later_offset=timedelta(microseconds=-1))

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )
    assert comparison.observed_utc_separation_microseconds == -1
    assert comparison.capture_windows_non_overlapping is False
    assert comparison.order_views_equal is True


def test_added_removed_and_changed_orders_are_exact_and_sorted() -> None:
    earlier_orders = (_order(3), _order(1), _order(2))
    changed_order = _order(
        2,
        updated_at="2026-07-28T14:59:00.123456790Z",
    )
    later_orders = (_order(4), changed_order, _order(3))
    earlier, later = _pair(
        later_offset=timedelta(seconds=3),
        earlier_orders=earlier_orders,
        later_orders=later_orders,
    )

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.ORDER_VIEW_DIFFERENT
    )
    assert comparison.added_provider_order_ids == (str(UUID(int=4)),)
    assert comparison.removed_provider_order_ids == (str(UUID(int=1)),)
    assert comparison.changed_provider_order_ids == (str(UUID(int=2)),)
    assert comparison.order_views_equal is False
    assert comparison.earlier_view_sha256 != comparison.later_view_sha256
    assert comparison.canonical_execution_fact_authorized is False


def test_raw_format_and_request_identity_do_not_change_exact_decoded_view() -> None:
    recorder = _Recorder()
    orders = (_order(1, subtag="retained"),)
    earlier = _capture(
        recorder,
        capture_key="comparison-format-earlier",
        request_suffix="format-earlier",
        received_at=BASE,
        orders=orders,
    )
    later = _capture(
        recorder,
        capture_key="comparison-format-later",
        request_suffix="format-later",
        received_at=BASE + timedelta(seconds=3),
        orders=orders,
        pretty=True,
    )

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert earlier.pages[0].observation.response_sha256 != (
        later.pages[0].observation.response_sha256
    )
    assert earlier.semantic_sha256 != later.semantic_sha256
    assert comparison.earlier_view_sha256 == comparison.later_view_sha256
    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.EXACT_ORDER_VIEW_MATCH_UNQUALIFIED
    )


def test_multi_page_windows_use_exact_end_to_start_ordering_and_separation() -> None:
    recorder = _Recorder()
    earlier = _two_page_capture(
        recorder,
        capture_key="comparison-multi-page-earlier",
        request_suffix="multi-page-earlier",
        window_started_at=BASE,
    )
    later = _two_page_capture(
        recorder,
        capture_key="comparison-multi-page-later",
        request_suffix="multi-page-later",
        window_started_at=BASE + timedelta(seconds=3),
    )

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert comparison.earlier_window_started_at == BASE
    assert comparison.earlier_window_ended_at == BASE + timedelta(seconds=1)
    assert comparison.later_window_started_at == BASE + timedelta(seconds=3)
    assert comparison.later_window_ended_at == BASE + timedelta(seconds=4)
    assert comparison.observed_utc_separation == timedelta(seconds=2)
    assert earlier.pages[-1].receipt.ingress_sequence == 2
    assert later.pages[0].receipt.ingress_sequence == 3
    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.EXACT_ORDER_VIEW_MATCH_UNQUALIFIED
    )

    overlapping_history_earlier = _two_page_capture(
        _Recorder(),
        capture_key="comparison-overlap-history-earlier",
        request_suffix="overlap-history-earlier",
        window_started_at=BASE,
    )
    overlapping_history_later = _two_page_capture(
        _Recorder(),
        capture_key="comparison-overlap-history-later",
        request_suffix="overlap-history-later",
        window_started_at=BASE + timedelta(seconds=3),
    )
    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="does not follow",
    ):
        compare_alpaca_paper_order_snapshot_captures(
            overlapping_history_earlier,
            overlapping_history_later,
        )


def test_two_empty_cursor_exhausted_views_match_but_cannot_reconcile() -> None:
    earlier, later = _pair(earlier_orders=(), later_orders=())

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert earlier.pagination_exhausted is True
    assert later.pagination_exhausted is True
    assert comparison.order_views_equal is True
    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.EXACT_ORDER_VIEW_MATCH_UNQUALIFIED
    )
    assert comparison.reconciliation_completion_authorized is False
    assert comparison.readiness_transition_authorized is False


def test_bounded_truncation_takes_precedence_over_equal_values_and_time() -> None:
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="comparison-truncated-earlier",
        request_suffix="truncated-earlier",
        received_at=BASE,
        orders=(_order(1),),
        page_limit=1,
        maximum_pages=1,
    )
    later = _capture(
        recorder,
        capture_key="comparison-truncated-later",
        request_suffix="truncated-later",
        received_at=BASE + timedelta(seconds=3),
        orders=(_order(1),),
        page_limit=1,
        maximum_pages=1,
    )

    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    assert earlier.bounded_truncation is True
    assert later.bounded_truncation is True
    assert comparison.order_views_equal is True
    assert comparison.minimum_utc_separation_observed is True
    assert comparison.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )
    assert comparison.exact_order_view_match_unqualified is False


def test_waiting_and_truncation_take_precedence_over_view_differences() -> None:
    waiting_earlier, waiting_later = _pair(
        later_offset=timedelta(seconds=1),
        earlier_orders=(_order(1),),
        later_orders=(_order(2),),
    )
    waiting = compare_alpaca_paper_order_snapshot_captures(
        waiting_earlier,
        waiting_later,
    )

    assert waiting.order_views_equal is False
    assert waiting.added_provider_order_ids == (str(UUID(int=2)),)
    assert waiting.removed_provider_order_ids == (str(UUID(int=1)),)
    assert waiting.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    )

    recorder = _Recorder()
    truncated_earlier = _capture(
        recorder,
        capture_key="comparison-precedence-truncated-earlier",
        request_suffix="precedence-truncated-earlier",
        received_at=BASE,
        orders=(_order(1),),
        page_limit=1,
        maximum_pages=1,
    )
    truncated_later = _capture(
        recorder,
        capture_key="comparison-precedence-truncated-later",
        request_suffix="precedence-truncated-later",
        received_at=BASE + timedelta(seconds=1),
        orders=(_order(2),),
        page_limit=1,
        maximum_pages=1,
    )
    truncated = compare_alpaca_paper_order_snapshot_captures(
        truncated_earlier,
        truncated_later,
    )

    assert truncated.order_views_equal is False
    assert truncated.minimum_utc_separation_observed is False
    assert truncated.disposition is (
        AlpacaPaperOrderSnapshotComparisonDisposition.BOUNDED_TRAVERSAL_INCOMPLETE
    )


def test_in_progress_traversal_cannot_be_compared() -> None:
    recorder = _Recorder()
    earlier = _capture(
        recorder,
        capture_key="comparison-in-progress-earlier",
        request_suffix="in-progress-earlier",
        received_at=BASE,
        orders=(_order(1),),
        page_limit=1,
        maximum_pages=2,
    )
    later = _capture(
        recorder,
        capture_key="comparison-in-progress-later",
        request_suffix="in-progress-later",
        received_at=BASE + timedelta(seconds=3),
        orders=(_order(1),),
        page_limit=1,
        maximum_pages=2,
    )

    assert earlier.next_page_description is not None
    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonError,
        match="ended bounded traversals",
    ):
        compare_alpaca_paper_order_snapshot_captures(earlier, later)


def test_cross_account_and_profile_drift_fail_as_conflicts() -> None:
    first_recorder = _Recorder()
    second_recorder = _Recorder()
    first_account = _capture(
        first_recorder,
        capture_key="comparison-account-earlier",
        request_suffix="account-earlier",
        received_at=BASE,
        account_id="paper-account-first",
    )
    second_account = _capture(
        second_recorder,
        capture_key="comparison-account-later",
        request_suffix="account-later",
        received_at=BASE + timedelta(seconds=3),
        account_id="paper-account-second",
    )

    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="different accounts",
    ):
        compare_alpaca_paper_order_snapshot_captures(
            first_account,
            second_account,
        )

    recorder = _Recorder()
    first_profile = _capture(
        recorder,
        capture_key="comparison-profile-earlier",
        request_suffix="profile-earlier",
        received_at=BASE,
        page_limit=4,
    )
    second_profile = _capture(
        recorder,
        capture_key="comparison-profile-later",
        request_suffix="profile-later",
        received_at=BASE + timedelta(seconds=3),
        page_limit=5,
    )

    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="different traversal profiles",
    ):
        compare_alpaca_paper_order_snapshot_captures(
            first_profile,
            second_profile,
        )


def test_same_capture_identity_and_shared_source_cannot_form_two_views() -> None:
    recorder = _Recorder()
    first = _capture(
        recorder,
        capture_key="comparison-reused-identity",
        request_suffix="identity-first",
        received_at=BASE,
    )
    second = _capture(
        recorder,
        capture_key="comparison-reused-identity",
        request_suffix="identity-second",
        received_at=BASE + timedelta(seconds=3),
    )

    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="distinct capture identities",
    ):
        compare_alpaca_paper_order_snapshot_captures(first, second)
    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="reuse a raw ingress source",
    ):
        compare_alpaca_paper_order_snapshot_captures(first, first)


def test_reversed_raw_source_order_fails_even_when_utc_times_are_reversed_too() -> None:
    earlier, later = _pair(later_offset=timedelta(seconds=3))

    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="does not follow",
    ):
        compare_alpaca_paper_order_snapshot_captures(later, earlier)


def test_result_is_proof_constructed_frozen_and_rejects_forged_differences() -> None:
    earlier, later = _pair()
    comparison = compare_alpaca_paper_order_snapshot_captures(earlier, later)

    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperOrderSnapshotComparison()
    mutable: Any = comparison
    with pytest.raises(FrozenInstanceError):
        mutable.disposition = AlpacaPaperOrderSnapshotComparisonDisposition.ORDER_VIEW_DIFFERENT

    forged = object.__new__(AlpacaPaperOrderSnapshotComparison)
    object.__setattr__(forged, "earlier_capture", earlier)
    object.__setattr__(forged, "later_capture", later)
    object.__setattr__(
        forged,
        "disposition",
        AlpacaPaperOrderSnapshotComparisonDisposition.ORDER_VIEW_DIFFERENT,
    )
    object.__setattr__(forged, "added_provider_order_ids", (str(UUID(int=9)),))
    object.__setattr__(forged, "removed_provider_order_ids", ())
    object.__setattr__(forged, "changed_provider_order_ids", ())
    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="differences conflict",
    ):
        _ = forged.semantic_sha256

    wrong_disposition = object.__new__(AlpacaPaperOrderSnapshotComparison)
    object.__setattr__(wrong_disposition, "earlier_capture", earlier)
    object.__setattr__(wrong_disposition, "later_capture", later)
    object.__setattr__(
        wrong_disposition,
        "disposition",
        AlpacaPaperOrderSnapshotComparisonDisposition.ORDER_VIEW_DIFFERENT,
    )
    object.__setattr__(wrong_disposition, "added_provider_order_ids", ())
    object.__setattr__(wrong_disposition, "removed_provider_order_ids", ())
    object.__setattr__(wrong_disposition, "changed_provider_order_ids", ())
    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonConflict,
        match="disposition conflicts",
    ):
        _ = wrong_disposition.semantic_sha256


def test_comparison_identity_binds_distinct_sources_with_equal_value_views() -> None:
    recorder = _Recorder()
    first_earlier = _capture(
        recorder,
        capture_key="comparison-source-pair-one-earlier",
        request_suffix="source-pair-one-earlier",
        received_at=BASE,
        orders=(_order(1),),
    )
    first_later = _capture(
        recorder,
        capture_key="comparison-source-pair-one-later",
        request_suffix="source-pair-one-later",
        received_at=BASE + timedelta(seconds=2),
        orders=(_order(1),),
    )
    second_earlier = _capture(
        recorder,
        capture_key="comparison-source-pair-two-earlier",
        request_suffix="source-pair-two-earlier",
        received_at=BASE + timedelta(seconds=10),
        orders=(_order(1),),
    )
    second_later = _capture(
        recorder,
        capture_key="comparison-source-pair-two-later",
        request_suffix="source-pair-two-later",
        received_at=BASE + timedelta(seconds=12),
        orders=(_order(1),),
    )

    first = compare_alpaca_paper_order_snapshot_captures(
        first_earlier,
        first_later,
    )
    second = compare_alpaca_paper_order_snapshot_captures(
        second_earlier,
        second_later,
    )

    assert first.earlier_view_sha256 == second.earlier_view_sha256
    assert first.later_view_sha256 == second.later_view_sha256
    assert first.comparison_id != second.comparison_id
    assert first.semantic_sha256 != second.semantic_sha256


def test_exact_types_are_required() -> None:
    earlier, later = _pair()

    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonError,
        match="earlier order view",
    ):
        compare_alpaca_paper_order_snapshot_captures(
            cast(Any, object()),
            later,
        )
    with pytest.raises(
        AlpacaPaperOrderSnapshotComparisonError,
        match="later order view",
    ):
        compare_alpaca_paper_order_snapshot_captures(
            earlier,
            cast(Any, object()),
        )
