from __future__ import annotations

import json
import tomllib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from packages.adapters.broker.alpaca_paper_account_activities import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_CHANNEL,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_OPERATION,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES,
    AlpacaPaperAccountActivityDecimal,
    AlpacaPaperAccountActivityError,
    AlpacaPaperAccountActivityPageDescription,
    AlpacaPaperAccountActivityPageObservation,
    AlpacaPaperAccountActivityPlan,
    AlpacaPaperAccountActivityTimestamp,
    AlpacaPaperTradeActivity,
    AlpacaPaperTradeActivitySide,
    AlpacaPaperTradeActivityType,
    PersistedAlpacaPaperAccountActivityPage,
    append_alpaca_paper_account_activity_page,
    create_alpaca_paper_account_activity_page_demand,
    create_alpaca_paper_account_activity_plan,
    decode_alpaca_paper_account_activity_page,
    persist_then_decode_alpaca_paper_account_activity_page,
    start_alpaca_paper_account_activity_capture,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressReceipt,
)
from packages.domain.broker_request_budget import BrokerRequestPurpose

REPOSITORY = Path(__file__).resolve().parents[2]
BASE = datetime(2026, 7, 28, 15, 0, tzinfo=UTC)


def _activity(
    number: int,
    *,
    transaction_time: str = "2026-07-28T14:59:00.123456789Z",
    activity_id: str | None = None,
    activity_type: str = "FILL",
    cumulative_quantity: str = "3.0000",
    leaves_quantity: str = "7.0000",
    price: str = "401.2300",
    quantity: str = "1.0000",
    side: str = "buy",
    symbol: str = "SPY",
    trade_type: str = "fill",
) -> dict[str, Any]:
    return {
        "activity_type": activity_type,
        "cum_qty": cumulative_quantity,
        "id": (
            activity_id
            if activity_id is not None
            else f"20260728145900123456789::activity-{number:04d}"
        ),
        "leaves_qty": leaves_quantity,
        "order_id": str(UUID(int=number)),
        "price": price,
        "qty": quantity,
        "side": side,
        "symbol": symbol,
        "transaction_time": transaction_time,
        "type": trade_type,
    }


def _body(*activities: dict[str, Any]) -> bytes:
    return json.dumps(
        activities,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _Recorder:
    def __init__(self) -> None:
        self.deliveries: list[BrokerIngressDelivery] = []
        self.receipts: list[BrokerIngressReceipt] = []

    def record(self, delivery: BrokerIngressDelivery) -> BrokerIngressReceipt:
        self.deliveries.append(delivery)
        receipt = BrokerIngressReceipt(
            delivery=delivery,
            ingress_sequence=len(self.receipts) + 1,
            previous_receipt_sha256=(
                None if not self.receipts else self.receipts[-1].semantic_sha256
            ),
        )
        self.receipts.append(receipt)
        return receipt


def _plan(
    *,
    page_size: int = 2,
    maximum_pages: int = 3,
    maximum_items: int = 6,
) -> AlpacaPaperAccountActivityPlan:
    return create_alpaca_paper_account_activity_plan(
        account_id="paper-account-activities",
        capture_idempotency_key="activity-capture-0001",
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )


def _persist(
    recorder: _Recorder,
    description: AlpacaPaperAccountActivityPageDescription,
    body: bytes,
    *,
    request_suffix: str,
    received_at: datetime,
) -> PersistedAlpacaPaperAccountActivityPage:
    return persist_then_decode_alpaca_paper_account_activity_page(
        recorder,
        description,
        delivery_idempotency_key=f"activity-delivery-{request_suffix}",
        http_status=200,
        provider_request_id=f"activity-provider-request-{request_suffix}",
        response_body=body,
        received_at=received_at,
        recorded_at=received_at + timedelta(milliseconds=1),
    )


def _assert_no_authority(value: object) -> None:
    for property_name in (
        "request_budget_enforced",
        "authenticated_provider_evidence",
        "runtime_current",
        "snapshot_isolation_qualified",
        "provider_snapshot_complete",
        "snapshot_complete",
        "activity_history_complete",
        "converged",
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


def test_plan_first_page_and_budget_demand_are_frozen_and_non_authorizing() -> None:
    plan = _plan()
    capture = start_alpaca_paper_account_activity_capture(plan)
    description = capture.next_page_description

    assert type(description) is AlpacaPaperAccountActivityPageDescription
    assert description.page_number == 1
    assert description.page_token is None
    assert description.previous_page_sha256 is None
    assert description.method == "GET"
    assert description.base_url == "https://paper-api.alpaca.markets"
    assert description.path == "/v2/account/activities"
    assert dict(description.query) == {
        "activity_types": "FILL",
        "direction": "asc",
        "page_size": "2",
    }
    assert description.request_target == (
        "/v2/account/activities?activity_types=FILL&direction=asc&page_size=2"
    )
    assert plan.activity_types == "FILL"
    assert plan.direction == "asc"
    assert plan.maximum_request_count == 3
    assert plan.budget_purpose is BrokerRequestPurpose.RECONCILIATION

    demand = create_alpaca_paper_account_activity_page_demand(
        description,
        requested_at=BASE,
    )
    assert demand.account_id == plan.account_id
    assert demand.purpose is BrokerRequestPurpose.RECONCILIATION
    assert demand.operation == "reconcile_account"
    assert demand.correlation_sha256 == description.semantic_sha256

    for value in (plan, description, capture):
        _assert_no_authority(value)
    mutable: Any = plan
    with pytest.raises(FrozenInstanceError):
        mutable.page_size = 100


def test_raw_first_short_page_retains_exact_fill_lexemes_and_exhausts_cursor() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(_plan())
    description = capture.next_page_description
    assert description is not None
    source = _activity(
        1,
        transaction_time="2026-07-28T10:59:00.123456789-04:00",
        cumulative_quantity="3.0000",
        leaves_quantity="7.0000",
        price="401.2300",
        quantity="1.0000",
        trade_type="partial_fill",
    )
    response_body = _body(source)
    page = _persist(
        recorder,
        description,
        response_body,
        request_suffix="0001",
        received_at=BASE,
    )

    assert len(recorder.deliveries) == 1
    assert page.receipt == recorder.receipts[0]
    assert page.receipt.delivery.channel == ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_CHANNEL
    assert page.receipt.delivery.operation == (ALPACA_PAPER_ACCOUNT_ACTIVITY_INGRESS_OPERATION)
    assert page.receipt.delivery.correlation_sha256 == description.semantic_sha256
    assert page.observation.response_body == response_body
    assert page.observation.terminal_page is True
    assert page.observation.next_page_token is None

    activity = page.observation.activities[0]
    assert activity.activity_type == "FILL"
    assert activity.provider_activity_id == source["id"]
    assert activity.id == source["id"]
    assert activity.provider_order_id == source["order_id"]
    assert activity.order_id == source["order_id"]
    assert activity.cumulative_quantity.raw == "3.0000"
    assert activity.cumulative_quantity.value == Decimal("3")
    assert activity.cum_qty is activity.cumulative_quantity
    assert activity.leaves_quantity.raw == "7.0000"
    assert activity.leaves_qty is activity.leaves_quantity
    assert activity.price.raw == "401.2300"
    assert activity.price.value == Decimal("401.23")
    assert activity.quantity.raw == "1.0000"
    assert activity.qty is activity.quantity
    assert activity.side is AlpacaPaperTradeActivitySide.BUY
    assert activity.trade_type is AlpacaPaperTradeActivityType.PARTIAL_FILL
    assert activity.type is activity.trade_type
    assert activity.transaction_time.raw == source["transaction_time"]
    assert activity.transaction_time.normalized_utc == "2026-07-28T14:59:00.123456789Z"

    completed = append_alpaca_paper_account_activity_page(capture, page)
    assert completed.page_count == 1
    assert completed.activity_count == 1
    assert completed.response_size_bytes == len(response_body)
    assert completed.pagination_exhausted is True
    assert completed.bounded_truncation is False
    assert completed.next_page_description is None
    assert completed.additional_reconciliation_required is True
    for value in (activity, page.observation, page, completed):
        _assert_no_authority(value)


def test_full_page_uses_exact_last_activity_id_as_token_and_demand_is_distinct() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(_plan(maximum_items=10))
    first_description = capture.next_page_description
    assert first_description is not None
    first_page = _persist(
        recorder,
        first_description,
        _body(
            _activity(1, transaction_time="2026-07-28T14:58:00Z"),
            _activity(2, transaction_time="2026-07-28T14:59:00Z"),
        ),
        request_suffix="0001",
        received_at=BASE,
    )
    after_first = append_alpaca_paper_account_activity_page(capture, first_page)
    second_description = after_first.next_page_description

    expected_token = _activity(2)["id"]
    assert type(second_description) is AlpacaPaperAccountActivityPageDescription
    assert second_description.page_number == 2
    assert second_description.page_size == 2
    assert second_description.page_token == expected_token
    assert second_description.previous_page_sha256 == first_page.semantic_sha256
    assert dict(second_description.query)["page_token"] == expected_token
    assert second_description.request_target.endswith(f"&page_token={expected_token}")

    first_demand = create_alpaca_paper_account_activity_page_demand(
        first_description,
        requested_at=BASE,
    )
    second_demand = create_alpaca_paper_account_activity_page_demand(
        second_description,
        requested_at=BASE + timedelta(seconds=1),
    )
    assert first_demand.demand_id != second_demand.demand_id
    assert first_demand.idempotency_key != second_demand.idempotency_key

    second_page = _persist(
        recorder,
        second_description,
        _body(_activity(3, transaction_time="2026-07-28T15:00:00Z")),
        request_suffix="0002",
        received_at=BASE + timedelta(seconds=1),
    )
    completed = append_alpaca_paper_account_activity_page(
        after_first,
        second_page,
    )
    assert completed.page_count == 2
    assert completed.activity_count == 3
    assert completed.pagination_exhausted is True
    assert completed.bounded_truncation is False
    assert completed.next_page_description is None
    assert completed.semantic_sha256 == replace(completed).semantic_sha256


def test_item_bound_shrinks_final_request_and_marks_explicit_truncation() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(
        _plan(page_size=2, maximum_pages=3, maximum_items=3)
    )
    first_description = capture.next_page_description
    assert first_description is not None
    first_page = _persist(
        recorder,
        first_description,
        _body(
            _activity(1, transaction_time="2026-07-28T14:58:00Z"),
            _activity(2, transaction_time="2026-07-28T14:59:00Z"),
        ),
        request_suffix="0001",
        received_at=BASE,
    )
    capture = append_alpaca_paper_account_activity_page(capture, first_page)
    final_description = capture.next_page_description

    assert final_description is not None
    assert final_description.page_size == 1
    assert dict(final_description.query)["page_size"] == "1"
    final_page = _persist(
        recorder,
        final_description,
        _body(_activity(3, transaction_time="2026-07-28T15:00:00Z")),
        request_suffix="0002",
        received_at=BASE + timedelta(seconds=1),
    )
    capture = append_alpaca_paper_account_activity_page(capture, final_page)

    assert capture.activity_count == 3
    assert capture.pagination_exhausted is False
    assert capture.bounded_truncation is True
    assert capture.activity_history_complete is False
    assert capture.next_page_description is None
    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="remaining page authority",
    ):
        append_alpaca_paper_account_activity_page(capture, final_page)


def test_full_final_page_hits_page_bound_as_truncation_not_exhaustion() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(
        _plan(page_size=1, maximum_pages=2, maximum_items=10)
    )
    for number in (1, 2):
        description = capture.next_page_description
        assert description is not None
        page = _persist(
            recorder,
            description,
            _body(
                _activity(
                    number,
                    transaction_time=f"2026-07-28T14:59:0{number}Z",
                )
            ),
            request_suffix=f"{number:04d}",
            received_at=BASE + timedelta(seconds=number),
        )
        capture = append_alpaca_paper_account_activity_page(capture, page)

    assert capture.pagination_exhausted is False
    assert capture.bounded_truncation is True
    assert capture.provider_snapshot_complete is False
    assert capture.converged is False
    assert capture.next_page_description is None


def test_empty_page_is_cursor_exhaustion_but_not_complete_execution_history() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(_plan())
    description = capture.next_page_description
    assert description is not None
    page = _persist(
        recorder,
        description,
        _body(),
        request_suffix="empty",
        received_at=BASE,
    )
    completed = append_alpaca_paper_account_activity_page(capture, page)

    assert page.observation.activities == ()
    assert completed.pagination_exhausted is True
    assert completed.activity_history_complete is False
    assert completed.canonical_execution_fact_authorized is False
    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="remaining page authority",
    ):
        append_alpaca_paper_account_activity_page(completed, page)


@pytest.mark.parametrize(
    ("http_status", "provider_request_id", "response_body"),
    (
        (200, None, b"[]"),
        (500, "activity-request-status", b"[]"),
        (200, "activity-request-json", b"{}"),
        (200, "activity-request-utf8", b"\xff"),
        (
            200,
            "activity-request-duplicate",
            (
                b'[{"activity_type":"FILL","activity_type":"FILL",'
                b'"cum_qty":"1","id":"activity-0001","leaves_qty":"0",'
                b'"order_id":"00000000-0000-0000-0000-000000000001",'
                b'"price":"1","qty":"1","side":"buy","symbol":"SPY",'
                b'"transaction_time":"2026-07-28T14:59:00Z","type":"fill"}]'
            ),
        ),
    ),
)
def test_raw_receipt_precedes_request_id_status_and_decode_qualification(
    http_status: int,
    provider_request_id: str | None,
    response_body: bytes,
) -> None:
    recorder = _Recorder()
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None

    with pytest.raises(AlpacaPaperAccountActivityError):
        persist_then_decode_alpaca_paper_account_activity_page(
            recorder,
            description,
            delivery_idempotency_key=(
                f"activity-delivery-raw-first-{len(response_body)}-{http_status}"
            ),
            http_status=http_status,
            provider_request_id=provider_request_id,
            response_body=response_body,
            received_at=BASE,
            recorded_at=BASE,
        )

    assert len(recorder.receipts) == 1
    assert recorder.receipts[0].delivery.body == response_body
    assert recorder.receipts[0].delivery.transport_status == http_status
    assert recorder.receipts[0].delivery.provider_request_id == provider_request_id


def test_persisted_page_rejects_forged_raw_receipt_bindings() -> None:
    recorder = _Recorder()
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None
    page = _persist(
        recorder,
        description,
        _body(_activity(1)),
        request_suffix="binding",
        received_at=BASE,
    )

    forged_deliveries = (
        replace(page.receipt.delivery, account_id="different-account"),
        replace(page.receipt.delivery, correlation_sha256="0" * 64),
        replace(
            page.receipt.delivery,
            provider_request_id="different-request-id",
        ),
        replace(page.receipt.delivery, body=_body(_activity(2))),
    )
    for forged_delivery in forged_deliveries:
        forged_receipt = replace(page.receipt, delivery=forged_delivery)
        with pytest.raises(
            AlpacaPaperAccountActivityError,
            match="raw receipt",
        ):
            PersistedAlpacaPaperAccountActivityPage(
                receipt=forged_receipt,
                observation=page.observation,
            )


@pytest.mark.parametrize(
    "response_body",
    (
        b"",
        b"{}",
        b"[null]",
        b"[NaN]",
        b"\xff",
        b'[{"id":"first","id":"second"}]',
    ),
)
def test_malformed_page_bytes_fail_closed(response_body: bytes) -> None:
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None

    with pytest.raises(AlpacaPaperAccountActivityError):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-malformed",
            response_body=response_body,
            received_at=BASE,
        )


def test_size_item_count_status_request_id_and_receive_time_fail_closed() -> None:
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None

    with pytest.raises(AlpacaPaperAccountActivityError, match="size"):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-oversize",
            response_body=(b" " * (ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_RESPONSE_BYTES + 1)),
            received_at=BASE,
        )
    with pytest.raises(AlpacaPaperAccountActivityError, match="page_size"):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-too-many",
            response_body=_body(_activity(1), _activity(2), _activity(3)),
            received_at=BASE,
        )

    for invalid_status, request_id, received_at in (
        (500, "activity-provider-request-status", BASE),
        (200, "", BASE),
        (200, "activity-provider-request-time", BASE.replace(tzinfo=None)),
    ):
        with pytest.raises(AlpacaPaperAccountActivityError):
            decode_alpaca_paper_account_activity_page(
                description,
                http_status=invalid_status,
                provider_request_id=request_id,
                response_body=_body(),
                received_at=received_at,
            )


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("extra", "schema-drift"),
        ("activity_type", "DIV"),
        ("type", "FILL"),
        ("side", "BUY"),
        ("symbol", "spy"),
        ("order_id", "not-a-uuid"),
        ("cum_qty", "0"),
        ("cum_qty", "01"),
        ("qty", "0"),
        ("leaves_qty", "-1"),
        ("price", "0"),
        ("transaction_time", "2026-07-28T14:59:00-00:00"),
        ("transaction_time", "2026-07-28 14:59:00Z"),
        ("id", "unsafe activity id"),
    ),
)
def test_strict_flat_fill_schema_and_values_fail_closed(
    mutation: str,
    value: str,
) -> None:
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None
    activity = _activity(1)
    activity[mutation] = value

    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="frozen FILL profile",
    ):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-profile",
            response_body=_body(activity),
            received_at=BASE,
        )

    nested = _activity(1)
    nested["price"] = {"raw": "1"}
    with pytest.raises(AlpacaPaperAccountActivityError):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-nested",
            response_body=_body(nested),
            received_at=BASE,
        )


def test_duplicate_ids_and_descending_transaction_times_fail_closed() -> None:
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None
    duplicate = _activity(1)
    with pytest.raises(AlpacaPaperAccountActivityError, match="repeats"):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-duplicates",
            response_body=_body(duplicate, duplicate),
            received_at=BASE,
        )

    later = _activity(1, transaction_time="2026-07-28T14:59:00Z")
    earlier = _activity(2, transaction_time="2026-07-28T14:58:00Z")
    with pytest.raises(AlpacaPaperAccountActivityError, match="ascending"):
        decode_alpaca_paper_account_activity_page(
            description,
            http_status=200,
            provider_request_id="activity-provider-request-ordering",
            response_body=_body(later, earlier),
            received_at=BASE,
        )


def test_wrong_token_overlap_and_cross_page_regressions_reject_chain() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(_plan(maximum_items=10))
    first_description = capture.next_page_description
    assert first_description is not None
    first_page = _persist(
        recorder,
        first_description,
        _body(
            _activity(1, transaction_time="2026-07-28T14:58:00Z"),
            _activity(2, transaction_time="2026-07-28T14:59:00Z"),
        ),
        request_suffix="0001",
        received_at=BASE,
    )
    after_first = append_alpaca_paper_account_activity_page(
        capture,
        first_page,
    )
    expected_second = after_first.next_page_description
    assert expected_second is not None

    wrong_description = replace(
        expected_second,
        page_token="different-activity-token",
    )
    wrong_page = _persist(
        recorder,
        wrong_description,
        _body(_activity(3, transaction_time="2026-07-28T15:00:00Z")),
        request_suffix="wrong",
        received_at=BASE + timedelta(seconds=1),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="different page description",
    ):
        append_alpaca_paper_account_activity_page(after_first, wrong_page)

    overlap_page = _persist(
        recorder,
        expected_second,
        _body(_activity(2, transaction_time="2026-07-28T14:59:00Z")),
        request_suffix="overlap",
        received_at=BASE + timedelta(seconds=1),
    )
    with pytest.raises(AlpacaPaperAccountActivityError, match="overlap"):
        append_alpaca_paper_account_activity_page(after_first, overlap_page)

    regressed_receive_page = _persist(
        recorder,
        expected_second,
        _body(_activity(3, transaction_time="2026-07-28T15:00:00Z")),
        request_suffix="receive-regression",
        received_at=BASE - timedelta(seconds=1),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="receive time regressed",
    ):
        append_alpaca_paper_account_activity_page(
            after_first,
            regressed_receive_page,
        )

    regressed_time_page = _persist(
        recorder,
        expected_second,
        _body(_activity(4, transaction_time="2026-07-28T14:57:00Z")),
        request_suffix="time-regression",
        received_at=BASE + timedelta(seconds=2),
    )
    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="ascending transaction",
    ):
        append_alpaca_paper_account_activity_page(
            after_first,
            regressed_time_page,
        )


def test_plan_and_page_descriptions_reject_unbounded_or_malformed_values() -> None:
    for page_size, maximum_pages, maximum_items in (
        (0, 1, 1),
        (101, 1, 1),
        (1, 0, 1),
        (1, ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_PAGES + 1, 1),
        (1, 1, 0),
        (1, 1, ALPACA_PAPER_ACCOUNT_ACTIVITY_MAX_ITEMS + 1),
    ):
        with pytest.raises(AlpacaPaperAccountActivityError):
            create_alpaca_paper_account_activity_plan(
                account_id="paper-account-activities",
                capture_idempotency_key="activity-capture-bounds",
                page_size=page_size,
                maximum_pages=maximum_pages,
                maximum_items=maximum_items,
            )

    plan = _plan()
    with pytest.raises(AlpacaPaperAccountActivityError, match="first"):
        AlpacaPaperAccountActivityPageDescription(
            plan=plan,
            page_number=1,
            page_size=plan.page_size,
            page_token="activity-token-0001",
            previous_page_sha256=None,
        )
    with pytest.raises(AlpacaPaperAccountActivityError, match="cursor"):
        AlpacaPaperAccountActivityPageDescription(
            plan=plan,
            page_number=2,
            page_size=plan.page_size,
            page_token="unsafe token",
            previous_page_sha256="0" * 64,
        )
    with pytest.raises(AlpacaPaperAccountActivityError, match="SHA-256"):
        AlpacaPaperAccountActivityPageDescription(
            plan=plan,
            page_number=2,
            page_size=plan.page_size,
            page_token="activity-token-0001",
            previous_page_sha256="not-a-digest",
        )


def test_raw_derived_types_are_constructor_closed_and_capture_requires_receipt() -> None:
    description = start_alpaca_paper_account_activity_capture(_plan()).next_page_description
    assert description is not None
    decoded_only = decode_alpaca_paper_account_activity_page(
        description,
        http_status=200,
        provider_request_id="activity-provider-request-decoded-only",
        response_body=_body(_activity(1)),
        received_at=BASE,
    )
    activity = decoded_only.activities[0]

    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAccountActivityDecimal()
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAccountActivityTimestamp()
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperTradeActivity()
    with pytest.raises(TypeError, match="proof-constructed"):
        AlpacaPaperAccountActivityPageObservation()
    with pytest.raises(TypeError, match="proof-constructed"):
        replace(activity, provider_activity_id="forged-activity-id")

    capture = start_alpaca_paper_account_activity_capture(_plan())
    with pytest.raises(
        AlpacaPaperAccountActivityError,
        match="persisted page",
    ):
        append_alpaca_paper_account_activity_page(
            capture,
            decoded_only,  # type: ignore[arg-type]
        )


def test_activity_values_do_not_claim_execution_identity_or_leak_raw_body() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_account_activity_capture(_plan())
    description = capture.next_page_description
    assert description is not None
    response_body = _body(_activity(1))
    page = _persist(
        recorder,
        description,
        response_body,
        request_suffix="opaque",
        received_at=BASE,
    )
    activity = page.observation.activities[0]
    rendered = f"{activity!r}\n{page.observation!r}\n{page!r}"

    assert not hasattr(activity, "execution_id")
    assert not hasattr(activity, "revision_id")
    assert not hasattr(activity, "deduplication_key")
    assert activity.provider_execution_identity_qualified is False
    assert activity.provider_revision_identity_qualified is False
    assert activity.provider_deduplication_identity_qualified is False
    assert activity.canonical_execution_fact_authorized is False
    assert response_body.decode("utf-8") not in rendered
    assert "APCA-API-KEY-ID" not in rendered
    assert "APCA-API-SECRET-KEY" not in rendered


def test_account_activity_module_is_enrolled_in_side_effect_free_boundary() -> None:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as config_file:
        config = tomllib.load(config_file)

    assert "packages/adapters/broker/alpaca_paper_account_activities.py" in set(
        config["scan"]["side_effect_free_roots"]
    )
