from __future__ import annotations

import tomllib
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_ORDER_STATUS_DISPOSITIONS,
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CANDIDATE_INSTRUMENTS,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
    AlpacaOrderDisposition,
    AlpacaOrderStatus,
    AlpacaPaperCapabilityMatrix,
    AlpacaPaperContractError,
    AlpacaPaperSubmissionDescription,
    classify_alpaca_order_status,
    create_alpaca_paper_submission_description,
    create_alpaca_paper_submission_request,
)
from packages.domain.models import OrderIntent, Side
from packages.domain.submission_attempt import BrokerSubmissionRequest
from packages.domain.walking_thread import WalkingThread

CAPABILITY_SHA256 = "9192707b7dcd29de5510f5fa4b42262767e5344878dfe282ed337cf212cd8ab2"
SPY_REQUEST_SHA256 = "b9326033a329279206bf26540581b54a5a15c94b0845aff7efa0ea97dd3a3393"
SPY_DESCRIPTION_SHA256 = "4361a76064ccf8b48bd08c5971a45d45181281bf2bc0367c04a815317c4a6128"


def intent() -> OrderIntent:
    return WalkingThread.run().intent


def copy_request(
    source: BrokerSubmissionRequest,
    *,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    operation: str | None = None,
    client_order_id: str | None = None,
    payload: dict[str, object] | None = None,
) -> BrokerSubmissionRequest:
    return BrokerSubmissionRequest(
        adapter_id=adapter_id or source.adapter_id,
        adapter_version=adapter_version or source.adapter_version,
        operation=operation or source.operation,
        order_id=source.order_id,
        client_order_id=client_order_id or source.client_order_id,
        intent_payload_sha256=source.intent_payload_sha256,
        payload=payload or dict(source.payload),
    )


def test_capability_matrix_freezes_provider_breadth_and_local_subset() -> None:
    capability = ALPACA_PAPER_CAPABILITIES

    assert type(capability) is AlpacaPaperCapabilityMatrix
    assert capability.environment == "paper"
    assert capability.trading_base_url == "https://paper-api.alpaca.markets"
    assert capability.trading_websocket_url == "wss://paper-api.alpaca.markets/stream"
    assert capability.create_order_path == "/v2/orders"
    assert capability.order_by_client_id_path == "/v2/orders:by_client_order_id"
    assert capability.account_path == "/v2/account"
    assert capability.positions_path == "/v2/positions"
    assert capability.orders_path == "/v2/orders"
    assert capability.account_activities_path == "/v2/account/activities"
    assert capability.auth_header_names == (
        "APCA-API-KEY-ID",
        "APCA-API-SECRET-KEY",
    )
    assert capability.candidate_instrument_symbols == ALPACA_PAPER_CANDIDATE_INSTRUMENTS
    assert capability.provider_order_types == (
        "limit",
        "market",
        "stop",
        "stop_limit",
        "trailing_stop",
    )
    assert capability.provider_time_in_force == ("cls", "day", "fok", "gtc", "ioc", "opg")
    assert capability.enabled_order_types == ("market",)
    assert capability.enabled_time_in_force == ("day",)
    assert capability.enabled_order_classes == ("simple",)
    assert capability.required_dispatch_session == "exchange_regular_session"
    assert not hasattr(capability, "regular_session_open")
    assert not hasattr(capability, "regular_session_close")
    assert capability.extended_hours_enabled is False
    assert capability.whole_share_only is True
    assert capability.fractional_quantity_enabled is False
    assert capability.notional_quantity_enabled is False
    assert capability.buy_shape_enabled is True
    assert capability.sell_shape_enabled is True
    assert capability.reduce_only_required_at_dispatch is True
    assert capability.short_exposure_authorized is False
    assert capability.price_fields_enabled is False
    assert capability.replacement_enabled is False
    assert capability.maximum_client_order_id_length == 128
    assert capability.orders_default_page_limit == 50
    assert capability.orders_max_page_limit == 500
    assert capability.orders_status_filters == ("all", "closed", "open")
    assert capability.orders_time_cursor_fields == ("after", "until")
    assert capability.orders_order_id_cursor_fields == (
        "after_order_id",
        "before_order_id",
    )
    assert capability.orders_directions == ("asc", "desc")
    assert capability.orders_order_id_cursors_mutually_exclusive is True
    assert capability.orders_cursor_families_mutually_exclusive is True
    assert capability.activities_min_page_size == 1
    assert capability.activities_default_page_size == 100
    assert capability.activities_max_page_size == 100
    assert capability.activities_page_token_field == "page_token"
    assert capability.activities_page_token_semantics == "last_activity_id"
    assert capability.activities_directions == ("asc", "desc")
    assert capability.documented_trading_requests_per_minute == 200
    assert capability.selected_market_data_feed is None
    assert capability.semantic_sha256 == CAPABILITY_SHA256


def test_capability_matrix_closes_every_runtime_and_trading_gate() -> None:
    capability = ALPACA_PAPER_CAPABILITIES

    assert capability.offline_contract_only is True
    assert capability.runtime_readiness
    assert set(capability.runtime_readiness.values()) == {False}
    assert {
        "exchange_calendar_binding_ready",
        "session_validation_ready",
        "security_mapping_ready",
        "asset_tradability_validation_ready",
        "reduce_only_validation_ready",
    } <= set(capability.runtime_readiness)
    assert capability.trading_effect_authorized is False
    with pytest.raises(TypeError):
        capability.runtime_readiness["transport_submission_ready"] = True  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        capability.environment = "live"  # type: ignore[misc]
    with pytest.raises(AlpacaPaperContractError, match="trading_base_url"):
        replace(capability, trading_base_url="https://api.alpaca.markets")
    with pytest.raises(AlpacaPaperContractError, match="transport_submission_ready"):
        replace(capability, transport_submission_ready=True)
    with pytest.raises(AlpacaPaperContractError, match="reconciliation_ready"):
        replace(capability, reconciliation_ready=True)
    with pytest.raises(AlpacaPaperContractError, match="coordinator_dispatch_ready"):
        replace(capability, coordinator_dispatch_ready=True)
    with pytest.raises(AlpacaPaperContractError, match="candidate_instrument_symbols"):
        replace(capability, candidate_instrument_symbols=(("US-ETF-SPY", "SPY"),))


def test_translation_is_deterministic_and_exact() -> None:
    first = create_alpaca_paper_submission_description(intent())
    second = create_alpaca_paper_submission_description(intent())

    assert first == second
    assert first.request == create_alpaca_paper_submission_request(intent())
    assert type(first.request) is BrokerSubmissionRequest
    assert first.request.adapter_id == ALPACA_PAPER_ADAPTER_ID
    assert first.request.adapter_version == ALPACA_PAPER_ADAPTER_VERSION
    assert first.request.operation == "submit_order"
    assert first.request.client_order_id == "aqt-36a481835bf952369f6de607"
    assert len(first.request.client_order_id) <= 128
    assert first.request.payload == {
        "capability_sha256": CAPABILITY_SHA256,
        "contract_version": ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
        "extended_hours": False,
        "instrument_id": "US-ETF-SPY",
        "qty": "10",
        "required_asset_class": "us_equity",
        "required_dispatch_session": "exchange_regular_session",
        "required_order_class": "simple",
        "side": "buy",
        "symbol": "SPY",
        "time_in_force": "day",
        "type": "market",
    }
    assert first.method == "POST"
    assert first.base_url == "https://paper-api.alpaca.markets"
    assert first.path == "/v2/orders"
    assert first.url == "https://paper-api.alpaca.markets/v2/orders"
    assert first.body == {
        "client_order_id": first.request.client_order_id,
        "extended_hours": False,
        "qty": "10",
        "side": "buy",
        "symbol": "SPY",
        "time_in_force": "day",
        "type": "market",
    }
    assert first.to_json_bytes() == (
        b'{"client_order_id":"aqt-36a481835bf952369f6de607",'
        b'"extended_hours":false,"qty":"10","side":"buy","symbol":"SPY",'
        b'"time_in_force":"day","type":"market"}'
    )
    assert first.request.semantic_sha256 == SPY_REQUEST_SHA256
    assert first.semantic_sha256 == SPY_DESCRIPTION_SHA256
    assert first.trading_effect_authorized is False


def test_decimal_scale_does_not_change_translation_identity() -> None:
    base = intent()
    scaled = replace(base, quantity=Decimal("10.0"))

    assert create_alpaca_paper_submission_description(scaled) == (
        create_alpaca_paper_submission_description(base)
    )


@pytest.mark.parametrize(("instrument_id", "symbol"), ALPACA_PAPER_CANDIDATE_INSTRUMENTS)
@pytest.mark.parametrize("side", (Side.BUY, Side.SELL))
def test_translation_accepts_each_exact_allowlist_pair_and_side(
    instrument_id: str,
    symbol: str,
    side: Side,
) -> None:
    translated = create_alpaca_paper_submission_description(
        replace(
            intent(),
            intent_id=f"fixture-{instrument_id}-{side.value}",
            instrument_id=instrument_id,
            symbol=symbol,
            side=side,
        )
    )

    assert translated.body["symbol"] == symbol
    assert translated.body["side"] == side.value
    assert translated.body["type"] == "market"
    assert translated.body["time_in_force"] == "day"
    assert translated.body["extended_hours"] is False


def test_translation_rejects_unknown_or_mismatched_instruments() -> None:
    with pytest.raises(AlpacaPaperContractError, match="outside"):
        create_alpaca_paper_submission_description(
            replace(intent(), instrument_id="US-ETF-VTI", symbol="VTI")
        )
    with pytest.raises(AlpacaPaperContractError, match="do not match"):
        create_alpaca_paper_submission_description(replace(intent(), symbol="QQQ"))
    with pytest.raises(AlpacaPaperContractError, match="exact OrderIntent"):
        create_alpaca_paper_submission_description(object())  # type: ignore[arg-type]


def test_description_and_request_evidence_are_immutable() -> None:
    description = create_alpaca_paper_submission_description(intent())

    with pytest.raises(TypeError):
        description.body["symbol"] = "QQQ"  # type: ignore[index]
    with pytest.raises(TypeError):
        description.request.payload["symbol"] = "QQQ"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        description.capability_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(AlpacaPaperContractError, match="capability digest"):
        replace(description, capability_sha256="0" * 64)

    caller_payload = dict(description.request.payload)
    copied_request = copy_request(description.request, payload=caller_payload)
    copied_description = AlpacaPaperSubmissionDescription(
        intent=description.intent,
        request=copied_request,
        capability_sha256=CAPABILITY_SHA256,
    )
    caller_payload["symbol"] = "QQQ"
    assert copied_description.body["symbol"] == "SPY"


@pytest.mark.parametrize(
    ("request_change", "message"),
    (
        ({"adapter_id": "other-broker"}, "adapter ID"),
        ({"adapter_version": "2.0.0"}, "adapter version"),
        ({"operation": "replace_order"}, "operation"),
        ({"client_order_id": "aqt-tampered"}, "client order ID"),
    ),
)
def test_description_rejects_tampered_request_identity(
    request_change: dict[str, str],
    message: str,
) -> None:
    description = create_alpaca_paper_submission_description(intent())
    altered = copy_request(description.request, **request_change)  # type: ignore[arg-type]

    with pytest.raises(AlpacaPaperContractError, match=message):
        AlpacaPaperSubmissionDescription(
            intent=description.intent,
            request=altered,
            capability_sha256=CAPABILITY_SHA256,
        )


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("type", "limit"),
        ("time_in_force", "gtc"),
        ("extended_hours", True),
        ("qty", "10.5"),
        ("required_order_class", "bracket"),
        ("required_dispatch_session", "extended_hours"),
        ("instrument_id", "US-ETF-QQQ"),
        ("symbol", "VTI"),
    ),
)
def test_description_rejects_tampered_or_expanded_payload(
    key: str,
    value: object,
) -> None:
    description = create_alpaca_paper_submission_description(intent())
    payload = dict(description.request.payload)
    payload[key] = value
    altered = copy_request(description.request, payload=payload)

    with pytest.raises(AlpacaPaperContractError):
        AlpacaPaperSubmissionDescription(
            intent=description.intent,
            request=altered,
            capability_sha256=CAPABILITY_SHA256,
        )


@pytest.mark.parametrize(
    "payload_changes",
    (
        {"qty": "11"},
        {"side": "sell"},
        {"instrument_id": "US-ETF-QQQ", "symbol": "QQQ"},
    ),
)
def test_description_binds_valid_looking_request_fields_to_the_exact_intent(
    payload_changes: dict[str, object],
) -> None:
    description = create_alpaca_paper_submission_description(intent())
    payload = dict(description.request.payload)
    payload.update(payload_changes)
    altered = copy_request(description.request, payload=payload)

    with pytest.raises(AlpacaPaperContractError, match="exact canonical intent"):
        AlpacaPaperSubmissionDescription(
            intent=description.intent,
            request=altered,
            capability_sha256=CAPABILITY_SHA256,
        )

    other_intent = replace(
        description.intent,
        intent_id="fixture-other-intent",
        instrument_id="US-ETF-QQQ",
        symbol="QQQ",
    )
    with pytest.raises(AlpacaPaperContractError, match="exact canonical intent"):
        replace(description, intent=other_intent)


EXPECTED_STATUS_DISPOSITIONS = {
    AlpacaOrderStatus.ACCEPTED: AlpacaOrderDisposition.ACKNOWLEDGED,
    AlpacaOrderStatus.PENDING_NEW: AlpacaOrderDisposition.ACKNOWLEDGED,
    AlpacaOrderStatus.ACCEPTED_FOR_BIDDING: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.NEW: AlpacaOrderDisposition.WORKING,
    AlpacaOrderStatus.HELD: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.STOPPED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.PARTIALLY_FILLED: AlpacaOrderDisposition.PARTIALLY_FILLED,
    AlpacaOrderStatus.FILLED: AlpacaOrderDisposition.FILLED,
    AlpacaOrderStatus.DONE_FOR_DAY: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.CANCELED: AlpacaOrderDisposition.CANCELED,
    AlpacaOrderStatus.EXPIRED: AlpacaOrderDisposition.EXPIRED,
    AlpacaOrderStatus.REPLACED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.PENDING_CANCEL: AlpacaOrderDisposition.PENDING_CANCEL,
    AlpacaOrderStatus.PENDING_REPLACE: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.PENDING_REVIEW: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.REJECTED: AlpacaOrderDisposition.REJECTED,
    AlpacaOrderStatus.SUSPENDED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
    AlpacaOrderStatus.CALCULATED: AlpacaOrderDisposition.RECONCILIATION_REQUIRED,
}


def test_order_status_classification_is_closed_and_exhaustive() -> None:
    assert set(EXPECTED_STATUS_DISPOSITIONS) == set(AlpacaOrderStatus)
    assert dict(ALPACA_ORDER_STATUS_DISPOSITIONS) == EXPECTED_STATUS_DISPOSITIONS

    for status, disposition in EXPECTED_STATUS_DISPOSITIONS.items():
        assert classify_alpaca_order_status(status.value) is disposition


def test_order_status_vocabulary_covers_the_reviewed_official_sdk_enum() -> None:
    reviewed_sdk_statuses = {
        "accepted",
        "accepted_for_bidding",
        "calculated",
        "canceled",
        "done_for_day",
        "expired",
        "filled",
        "held",
        "new",
        "partially_filled",
        "pending_cancel",
        "pending_new",
        "pending_replace",
        "pending_review",
        "rejected",
        "replaced",
        "stopped",
        "suspended",
    }

    assert {status.value for status in AlpacaOrderStatus} == reviewed_sdk_statuses


@pytest.mark.parametrize(
    "raw_status",
    ("", " new", "new ", "NEW", "cancelled", "unknown", None),
)
def test_order_status_classification_rejects_malformed_or_unknown_values(
    raw_status: str | None,
) -> None:
    with pytest.raises(AlpacaPaperContractError):
        classify_alpaca_order_status(raw_status)  # type: ignore[arg-type]


def test_pure_contract_is_enrolled_in_the_architecture_boundary() -> None:
    repository = Path(__file__).resolve().parents[2]
    with (repository / "infra/architecture-boundaries.toml").open("rb") as config_file:
        config = tomllib.load(config_file)

    assert {
        "packages/adapters/broker/__init__.py",
        "packages/adapters/broker/alpaca_paper.py",
    } <= set(config["scan"]["side_effect_free_roots"])
