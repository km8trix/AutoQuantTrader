from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from packages.adapters.broker.alpaca_paper_order_snapshots import (
    ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_CHANNEL,
    ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_OPERATION,
    ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES,
    ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES,
    AlpacaPaperOrderSnapshotCapture,
    AlpacaPaperOrderSnapshotError,
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
    PersistedAlpacaPaperOrderSnapshotPage,
    append_alpaca_paper_order_snapshot_page,
    create_alpaca_paper_order_snapshot_page_demand,
    create_alpaca_paper_order_snapshot_plan,
    decode_alpaca_paper_order_snapshot_page,
    persist_then_decode_alpaca_paper_order_snapshot_page,
    start_alpaca_paper_order_snapshot,
)
from packages.domain.broker_ingress import (
    BrokerIngressDelivery,
    BrokerIngressReceipt,
)
from packages.domain.broker_request_budget import BrokerRequestPurpose

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
    submitted_at: str = "2026-07-28T14:59:00.123456789Z",
) -> dict[str, Any]:
    value = _base_order()
    value["id"] = str(UUID(int=number))
    value["client_order_id"] = f"snapshot-client-order-{number:04d}"
    value["created_at"] = submitted_at
    value["submitted_at"] = submitted_at
    value["updated_at"] = submitted_at
    return value


def _body(*orders: dict[str, Any]) -> bytes:
    return json.dumps(
        orders,
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
    page_limit: int = 2,
    maximum_pages: int = 3,
) -> AlpacaPaperOrderSnapshotPlan:
    return create_alpaca_paper_order_snapshot_plan(
        account_id="paper-account-snapshot",
        capture_idempotency_key="snapshot-capture-0001",
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )


def _persist(
    recorder: _Recorder,
    description: AlpacaPaperOrderSnapshotPageDescription,
    body: bytes,
    *,
    request_suffix: str,
    received_at: datetime,
) -> PersistedAlpacaPaperOrderSnapshotPage:
    return persist_then_decode_alpaca_paper_order_snapshot_page(
        recorder,
        description,
        delivery_idempotency_key=f"snapshot-delivery-{request_suffix}",
        http_status=200,
        provider_request_id=f"snapshot-provider-request-{request_suffix}",
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
        "converged",
        "provider_revision_identity_qualified",
        "provider_deduplication_authorized",
        "normalized_fact_authorized",
        "inbox_application_authorized",
        "lifecycle_application_authorized",
        "reconciliation_application_authorized",
        "reconciliation_complete",
        "unknown_resolution_authorized",
        "canonical_execution_fact_authorized",
        "reservation_release_authorized",
        "resubmission_authorized",
        "transport_authorized",
        "broker_call_authorized",
        "trading_effect_authorized",
    ):
        assert getattr(value, property_name) is False


def test_plan_first_page_and_budget_demand_are_frozen_and_non_authorizing() -> None:
    plan = _plan()
    capture = start_alpaca_paper_order_snapshot(plan)
    description = capture.next_page_description

    assert type(description) is AlpacaPaperOrderSnapshotPageDescription
    assert description.page_number == 1
    assert description.before_order_id is None
    assert description.previous_page_sha256 is None
    assert description.method == "GET"
    assert description.base_url == "https://paper-api.alpaca.markets"
    assert description.path == "/v2/orders"
    assert dict(description.query) == {
        "asset_class": "us_equity",
        "direction": "desc",
        "limit": "2",
        "nested": "false",
        "status": "all",
    }
    assert description.request_target == (
        "/v2/orders?status=all&limit=2&direction=desc&nested=false&asset_class=us_equity"
    )
    assert plan.maximum_request_count == 3
    assert plan.budget_purpose is BrokerRequestPurpose.RECONCILIATION
    demand = create_alpaca_paper_order_snapshot_page_demand(
        description,
        requested_at=BASE,
    )
    assert demand.account_id == plan.account_id
    assert demand.purpose is BrokerRequestPurpose.RECONCILIATION
    assert demand.operation == "reconcile_account"
    assert demand.correlation_sha256 == description.semantic_sha256

    for value in (plan, description, capture):
        _assert_no_authority(value)
    mutable_view: Any = plan
    with pytest.raises(FrozenInstanceError):
        mutable_view.page_limit = 500


def test_raw_first_short_page_exhausts_only_the_cursor_chain() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_order_snapshot(_plan())
    description = capture.next_page_description
    assert description is not None
    page = _persist(
        recorder,
        description,
        _body(_order(1)),
        request_suffix="0001",
        received_at=BASE,
    )

    assert len(recorder.deliveries) == 1
    assert page.receipt == recorder.receipts[0]
    assert page.receipt.delivery.channel == ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_CHANNEL
    assert page.receipt.delivery.operation == (ALPACA_PAPER_ORDER_SNAPSHOT_INGRESS_OPERATION)
    assert page.receipt.delivery.correlation_sha256 == description.semantic_sha256
    assert page.observation.terminal_page is True
    assert page.observation.next_before_order_id is None
    assert page.observation.response_body == _body(_order(1))
    assert page.observation.orders[0].provider_order_id == str(UUID(int=1))

    completed = append_alpaca_paper_order_snapshot_page(capture, page)
    assert completed.page_count == 1
    assert completed.order_count == 1
    assert completed.pagination_exhausted is True
    assert completed.bounded_truncation is False
    assert completed.next_page_description is None
    assert completed.additional_reconciliation_required is True
    for value in (page.observation, page, completed):
        _assert_no_authority(value)


def test_full_page_derives_exclusive_cursor_and_short_second_page_terminates() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_order_snapshot(_plan())
    first_description = capture.next_page_description
    assert first_description is not None
    first_page = _persist(
        recorder,
        first_description,
        _body(_order(1), _order(2)),
        request_suffix="0001",
        received_at=BASE,
    )
    after_first = append_alpaca_paper_order_snapshot_page(capture, first_page)
    second_description = after_first.next_page_description

    assert type(second_description) is AlpacaPaperOrderSnapshotPageDescription
    assert second_description.page_number == 2
    assert second_description.before_order_id == str(UUID(int=2))
    assert second_description.previous_page_sha256 == first_page.semantic_sha256
    assert dict(second_description.query)["before_order_id"] == str(UUID(int=2))
    assert second_description.request_target.endswith(f"&before_order_id={UUID(int=2)}")
    second_demand = create_alpaca_paper_order_snapshot_page_demand(
        second_description,
        requested_at=BASE + timedelta(seconds=1),
    )
    first_demand = create_alpaca_paper_order_snapshot_page_demand(
        first_description,
        requested_at=BASE,
    )
    assert second_demand.demand_id != first_demand.demand_id

    second_page = _persist(
        recorder,
        second_description,
        _body(_order(3)),
        request_suffix="0002",
        received_at=BASE + timedelta(seconds=1),
    )
    completed = append_alpaca_paper_order_snapshot_page(after_first, second_page)

    assert completed.page_count == 2
    assert completed.order_count == 3
    assert completed.pagination_exhausted is True
    assert completed.next_page_description is None
    assert completed.semantic_sha256 == replace(completed).semantic_sha256


def test_full_final_page_is_bounded_truncation_not_exhaustion() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_order_snapshot(_plan(page_limit=1, maximum_pages=2))
    for number in (1, 2):
        description = capture.next_page_description
        assert description is not None
        page = _persist(
            recorder,
            description,
            _body(_order(number)),
            request_suffix=f"{number:04d}",
            received_at=BASE + timedelta(seconds=number),
        )
        capture = append_alpaca_paper_order_snapshot_page(capture, page)

    assert capture.pagination_exhausted is False
    assert capture.bounded_truncation is True
    assert capture.next_page_description is None
    assert capture.converged is False
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="remaining page authority"):
        append_alpaca_paper_order_snapshot_page(capture, capture.pages[-1])


def test_empty_terminal_page_is_valid_but_cannot_be_extended() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_order_snapshot(_plan())
    description = capture.next_page_description
    assert description is not None
    page = _persist(
        recorder,
        description,
        _body(),
        request_suffix="empty",
        received_at=BASE,
    )
    completed = append_alpaca_paper_order_snapshot_page(capture, page)

    assert page.observation.orders == ()
    assert completed.pagination_exhausted is True
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="remaining page authority"):
        append_alpaca_paper_order_snapshot_page(completed, page)


def test_raw_receipt_survives_missing_request_id_and_decoder_failure() -> None:
    description = start_alpaca_paper_order_snapshot(_plan()).next_page_description
    assert description is not None
    missing_request_id_recorder = _Recorder()

    with pytest.raises(AlpacaPaperOrderSnapshotError, match="after raw persistence"):
        persist_then_decode_alpaca_paper_order_snapshot_page(
            missing_request_id_recorder,
            description,
            delivery_idempotency_key="snapshot-delivery-missing-id",
            http_status=200,
            provider_request_id=None,
            response_body=_body(),
            received_at=BASE,
            recorded_at=BASE,
        )
    assert len(missing_request_id_recorder.receipts) == 1

    malformed_recorder = _Recorder()
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="JSON array"):
        persist_then_decode_alpaca_paper_order_snapshot_page(
            malformed_recorder,
            description,
            delivery_idempotency_key="snapshot-delivery-malformed",
            http_status=200,
            provider_request_id="snapshot-provider-request-malformed",
            response_body=b"{}",
            received_at=BASE,
            recorded_at=BASE,
        )
    assert len(malformed_recorder.receipts) == 1
    assert malformed_recorder.receipts[0].delivery.body == b"{}"


def test_persisted_page_rejects_forged_raw_receipt_bindings() -> None:
    recorder = _Recorder()
    description = start_alpaca_paper_order_snapshot(_plan()).next_page_description
    assert description is not None
    page = _persist(
        recorder,
        description,
        _body(_order(1)),
        request_suffix="binding",
        received_at=BASE,
    )

    forged_deliveries = (
        replace(page.receipt.delivery, correlation_sha256="0" * 64),
        replace(page.receipt.delivery, provider_request_id="different-request-id"),
        replace(page.receipt.delivery, body=_body(_order(2))),
    )
    for forged_delivery in forged_deliveries:
        forged_receipt = replace(page.receipt, delivery=forged_delivery)
        with pytest.raises(AlpacaPaperOrderSnapshotError, match="raw receipt"):
            PersistedAlpacaPaperOrderSnapshotPage(
                receipt=forged_receipt,
                observation=page.observation,
            )


@pytest.mark.parametrize(
    "response_body",
    (
        b"",
        b"{}",
        b"[null]",
        b'[{"id":"first","id":"second"}]',
        b"[NaN]",
        b"\xff",
    ),
)
def test_malformed_page_bytes_fail_closed(response_body: bytes) -> None:
    description = start_alpaca_paper_order_snapshot(_plan()).next_page_description
    assert description is not None

    with pytest.raises(AlpacaPaperOrderSnapshotError):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-malformed",
            response_body=response_body,
            received_at=BASE,
        )


def test_size_item_count_schema_status_and_time_bounds_fail_closed() -> None:
    description = start_alpaca_paper_order_snapshot(_plan()).next_page_description
    assert description is not None

    with pytest.raises(AlpacaPaperOrderSnapshotError, match="size"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-oversize",
            response_body=b" " * (ALPACA_PAPER_ORDER_SNAPSHOT_MAX_RESPONSE_BYTES + 1),
            received_at=BASE,
        )
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="item limit"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-too-many",
            response_body=_body(_order(1), _order(2), _order(3)),
            received_at=BASE,
        )

    drifted = _order(1)
    drifted["unexpected"] = "schema-drift"
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="frozen order profile"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-drift",
            response_body=_body(drifted),
            received_at=BASE,
        )

    unknown_status = _order(1)
    unknown_status["status"] = "provider_new_status"
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="frozen order profile"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-status",
            response_body=_body(unknown_status),
            received_at=BASE,
        )

    wrong_asset_class = _order(1)
    wrong_asset_class["asset_class"] = "crypto"
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="fixed us_equity"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-asset-class",
            response_body=_body(wrong_asset_class),
            received_at=BASE,
        )

    for invalid_status, request_id, received_at in (
        (500, "snapshot-provider-request-status", BASE),
        (200, "", BASE),
        (200, "snapshot-provider-request-time", BASE.replace(tzinfo=None)),
    ):
        with pytest.raises(AlpacaPaperOrderSnapshotError):
            decode_alpaca_paper_order_snapshot_page(
                description,
                http_status=invalid_status,
                provider_request_id=request_id,
                response_body=_body(),
                received_at=received_at,
            )


def test_duplicate_order_ids_and_ascending_submission_times_fail_closed() -> None:
    description = start_alpaca_paper_order_snapshot(_plan()).next_page_description
    assert description is not None
    duplicate = _order(1)
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="repeats"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-duplicates",
            response_body=_body(duplicate, duplicate),
            received_at=BASE,
        )

    older = _order(1, submitted_at="2026-07-28T14:58:00Z")
    newer = _order(2, submitted_at="2026-07-28T14:59:00Z")
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="descending"):
        decode_alpaca_paper_order_snapshot_page(
            description,
            http_status=200,
            provider_request_id="snapshot-provider-request-ordering",
            response_body=_body(older, newer),
            received_at=BASE,
        )


def test_wrong_cursor_overlap_and_receive_time_regression_reject_chain() -> None:
    recorder = _Recorder()
    capture = start_alpaca_paper_order_snapshot(_plan())
    first_description = capture.next_page_description
    assert first_description is not None
    first_page = _persist(
        recorder,
        first_description,
        _body(_order(1), _order(2)),
        request_suffix="0001",
        received_at=BASE,
    )
    after_first = append_alpaca_paper_order_snapshot_page(capture, first_page)
    expected_second = after_first.next_page_description
    assert expected_second is not None

    wrong_description = replace(
        expected_second,
        before_order_id=str(UUID(int=99)),
    )
    wrong_page = _persist(
        recorder,
        wrong_description,
        _body(_order(3)),
        request_suffix="wrong",
        received_at=BASE + timedelta(seconds=1),
    )
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="different page description"):
        append_alpaca_paper_order_snapshot_page(after_first, wrong_page)

    overlap_page = _persist(
        recorder,
        expected_second,
        _body(_order(2)),
        request_suffix="overlap",
        received_at=BASE + timedelta(seconds=1),
    )
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="overlap"):
        append_alpaca_paper_order_snapshot_page(after_first, overlap_page)

    regressed_page = _persist(
        recorder,
        expected_second,
        _body(_order(3)),
        request_suffix="regressed",
        received_at=BASE - timedelta(seconds=1),
    )
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="receive time regressed"):
        append_alpaca_paper_order_snapshot_page(after_first, regressed_page)

    boundary_regression_page = _persist(
        recorder,
        expected_second,
        _body(
            _order(
                4,
                submitted_at="2026-07-28T14:59:30Z",
            )
        ),
        request_suffix="boundary-regression",
        received_at=BASE + timedelta(seconds=2),
    )
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="descending submission"):
        append_alpaca_paper_order_snapshot_page(
            after_first,
            boundary_regression_page,
        )


def test_plan_rejects_unbounded_or_malformed_traversals() -> None:
    for page_limit, maximum_pages in (
        (0, 1),
        (501, 1),
        (1, 0),
        (1, ALPACA_PAPER_ORDER_SNAPSHOT_MAX_PAGES + 1),
    ):
        with pytest.raises(AlpacaPaperOrderSnapshotError):
            create_alpaca_paper_order_snapshot_plan(
                account_id="paper-account-snapshot",
                capture_idempotency_key="snapshot-capture-bounds",
                page_limit=page_limit,
                maximum_pages=maximum_pages,
            )

    plan = _plan()
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="first"):
        AlpacaPaperOrderSnapshotPageDescription(
            plan=plan,
            page_number=1,
            before_order_id=str(UUID(int=1)),
            previous_page_sha256=None,
        )
    with pytest.raises(AlpacaPaperOrderSnapshotError, match="canonical UUID"):
        AlpacaPaperOrderSnapshotPageDescription(
            plan=plan,
            page_number=2,
            before_order_id="not-a-cursor",
            previous_page_sha256="0" * 64,
        )


def test_capture_requires_raw_first_page_type() -> None:
    capture = start_alpaca_paper_order_snapshot(_plan())
    description = capture.next_page_description
    assert description is not None
    decoded_only = decode_alpaca_paper_order_snapshot_page(
        description,
        http_status=200,
        provider_request_id="snapshot-provider-request-decoded-only",
        response_body=_body(),
        received_at=BASE,
    )

    with pytest.raises(AlpacaPaperOrderSnapshotError, match="persisted page"):
        append_alpaca_paper_order_snapshot_page(
            capture,
            decoded_only,  # type: ignore[arg-type]
        )
    assert type(capture) is AlpacaPaperOrderSnapshotCapture
