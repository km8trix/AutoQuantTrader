from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_CAPABILITIES,
    AlpacaOrderDisposition,
    AlpacaOrderStatus,
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_observations import (
    ALPACA_PAPER_MAX_LOOKUP_RESPONSE_BYTES,
    ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION,
    AlpacaClientOrderLookupDescription,
    AlpacaClientOrderLookupObservation,
    AlpacaClientOrderLookupOutcome,
    AlpacaOrderObservation,
    AlpacaPaperObservationError,
    AlpacaProviderTimestamp,
    create_alpaca_client_order_lookup_description,
    decode_alpaca_client_order_lookup_response,
)
from packages.domain.order_reducer import BrokerOrderEvent
from packages.domain.submission_attempt import UnknownSubmissionResolution
from packages.domain.walking_thread import WalkingThread

REPOSITORY = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPOSITORY / "tests/fixtures/broker/alpaca_paper"
RECEIVED_AT = datetime(2026, 7, 15, 13, 31, 1, tzinfo=UTC)
FOUND_RESPONSE_SHA256 = "125225a48a0a6e9429865b02eee91943de4d45fcdb18207747413885bddc2836"
NOT_FOUND_RESPONSE_SHA256 = "e7471ba0c3327f18cd614ff50eecbbabe60745657cafffa0c7c6191d99e81ee5"
LOOKUP_DESCRIPTION_SHA256 = "fc7f96b41772c0038f5bf12d45acf607a02b94fccd22434bc71a8fccb5defa53"
FOUND_OBSERVATION_SHA256 = "d61d95d0284ed7eefcbbee114750c2a14cabd997c86d0c4171bfcaaa5a09f261"
NOT_FOUND_OBSERVATION_SHA256 = "cf4cd002bb58f715a2feec6a252d0f64820ead41e7742566222bb199df5780fc"
ORDER_OBSERVATION_SHA256 = "2e09113d377f1fdf764249bd1cc4e7b6bce4cb046cd32527d865b1c5028dd5a5"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURE_ROOT / name).read_bytes()


def fixture_object(name: str = "lookup_found.json") -> dict[str, Any]:
    value = json.loads(fixture_bytes(name))
    assert type(value) is dict
    return value


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def lookup_description() -> AlpacaClientOrderLookupDescription:
    submission = create_alpaca_paper_submission_description(WalkingThread.run().intent)
    return create_alpaca_client_order_lookup_description(
        account_id="paper-account-fixture",
        submission=submission,
    )


def decode_found(
    payload: bytes | None = None,
    *,
    provider_request_id: str = "fixture-request-found-0001",
) -> AlpacaClientOrderLookupObservation:
    return decode_alpaca_client_order_lookup_response(
        lookup_description(),
        http_status=200,
        provider_request_id=provider_request_id,
        response_body=fixture_bytes("lookup_found.json") if payload is None else payload,
        received_at=RECEIVED_AT,
    )


def decode_not_found(
    payload: bytes | None = None,
    *,
    provider_request_id: str = "fixture-request-not-found-0001",
) -> AlpacaClientOrderLookupObservation:
    return decode_alpaca_client_order_lookup_response(
        lookup_description(),
        http_status=404,
        provider_request_id=provider_request_id,
        response_body=fixture_bytes("lookup_not_found.json") if payload is None else payload,
        received_at=RECEIVED_AT,
    )


def test_fixture_manifest_is_truthful_and_pins_exact_bytes() -> None:
    manifest = fixture_object("manifest.json")

    assert manifest["contract_version"] == ALPACA_PAPER_OBSERVATION_CONTRACT_VERSION
    assert manifest["reviewed_on"] == "2026-07-26"
    assert manifest["fixtures"] == {
        "lookup_found.json": {
            "provenance": "documentation_derived_synthetic",
            "sha256": FOUND_RESPONSE_SHA256,
        },
        "lookup_not_found.json": {
            "provenance": "unqualified_synthetic_error_example",
            "sha256": NOT_FOUND_RESPONSE_SHA256,
        },
    }
    assert all("authenticated" not in item["provenance"] for item in manifest["fixtures"].values())
    assert any("not authenticated" in note for note in manifest["notes"])
    assert any("not-found code and message" in note for note in manifest["notes"])
    assert {
        name: hashlib.sha256(fixture_bytes(name)).hexdigest() for name in manifest["fixtures"]
    } == {
        "lookup_found.json": FOUND_RESPONSE_SHA256,
        "lookup_not_found.json": NOT_FOUND_RESPONSE_SHA256,
    }
    assert set(manifest["sources"]) == {
        "https://docs.alpaca.markets/us/v1.4.2/reference/getorderbyclientorderid",
        "https://docs.alpaca.markets/us/docs/alpaca-api-platform",
        "https://docs.alpaca.markets/us/docs/getting-started-with-trading-api",
        "https://docs.alpaca.markets/us/docs/orders-at-alpaca",
        "https://docs.alpaca.markets/us/openapi/trading-api.json",
        "https://docs.alpaca.markets/us/v1.1/changelog/2026-06-24-trading-api-00bf221",
        "https://raw.githubusercontent.com/alpacahq/alpaca-py/bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/enums.py",
        "https://raw.githubusercontent.com/alpacahq/alpaca-py/bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f/alpaca/trading/models.py",
    }
    assert manifest["source_artifacts"] == {
        "alpaca_py_enums": {
            "commit": "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f",
            "sha256": "08a7d06d9ae6ce4ad6251c5628d74eaeef8d62a001784951dc24b90df0e5cc30",
        },
        "alpaca_py_models": {
            "commit": "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f",
            "sha256": "0a4296847ea46c434de3fe08ef6bb82519d9442705e59b4671127ffffad3855f",
        },
        "trading_openapi": {
            "retrieved_on": "2026-07-26",
            "sha256": "fd4f33cf6a5f21416cd1abe27eff19fa858425bdc9569a9e6937086d752e55d1",
        },
    }


def test_lookup_description_is_bound_to_the_exact_prior_submission() -> None:
    description = lookup_description()
    submission = description.submission

    assert description.account_id == "paper-account-fixture"
    assert description.method == "GET"
    assert description.base_url == "https://paper-api.alpaca.markets"
    assert description.path == "/v2/orders:by_client_order_id"
    assert dict(description.query) == {"client_order_id": submission.request.client_order_id}
    assert description.request_target == (
        f"/v2/orders:by_client_order_id?client_order_id={submission.request.client_order_id}"
    )
    assert description.semantic_sha256 == LOOKUP_DESCRIPTION_SHA256
    assert description.transport_authorized is False
    assert description.trading_effect_authorized is False
    assert ALPACA_PAPER_CAPABILITIES.runtime_readiness
    assert set(ALPACA_PAPER_CAPABILITIES.runtime_readiness.values()) == {False}

    with pytest.raises(AlpacaPaperObservationError, match="exact"):
        create_alpaca_client_order_lookup_description(
            account_id="paper-account-fixture",
            submission=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(AlpacaPaperObservationError, match="bounded"):
        create_alpaca_client_order_lookup_description(
            account_id="x" * 65,
            submission=submission,
        )


def test_found_lookup_retains_exact_bytes_and_matches_submission_shape() -> None:
    observation = decode_found()

    assert type(observation) is AlpacaClientOrderLookupObservation
    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.http_status == 200
    assert observation.provider_request_id == "fixture-request-found-0001"
    assert observation.received_at == RECEIVED_AT
    assert observation.response_body == fixture_bytes("lookup_found.json")
    assert observation.response_size_bytes == len(fixture_bytes("lookup_found.json"))
    assert observation.response_sha256 == FOUND_RESPONSE_SHA256
    assert observation.mismatch_fields == ()
    assert observation.not_found_code is None
    assert observation.not_found_message is None
    assert observation.inconclusive is False
    assert observation.semantic_sha256 == FOUND_OBSERVATION_SHA256

    order = observation.order
    assert type(order) is AlpacaOrderObservation
    assert order.provider_order_id == "61e69015-8549-4bfd-b9c3-01e75843f47d"
    assert order.client_order_id == observation.description.submission.request.client_order_id
    assert order.asset_id == "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415"
    assert order.asset_class == "us_equity"
    assert order.symbol == "SPY"
    assert order.quantity == Decimal(10)
    assert order.notional is None
    assert order.filled_quantity == Decimal(0)
    assert order.filled_average_price is None
    assert order.order_class == "simple"
    assert order.order_type == "market"
    assert order.type == "market"
    assert order.side == "buy"
    assert order.time_in_force == "day"
    assert order.status is AlpacaOrderStatus.NEW
    assert order.disposition is AlpacaOrderDisposition.WORKING
    assert order.extended_hours is False
    assert order.expires_at is None
    assert order.source is None
    assert order.subtag is None
    assert order.semantic_sha256 == ORDER_OBSERVATION_SHA256


def test_provider_timestamps_preserve_nanoseconds_and_normalize_offsets() -> None:
    observation = decode_found()
    assert observation.order is not None
    created_at = observation.order.created_at
    submitted_at = observation.order.submitted_at

    assert type(created_at) is AlpacaProviderTimestamp
    assert created_at.raw == "2026-07-15T09:31:00.123456789-04:00"
    assert created_at.utc_second == datetime(2026, 7, 15, 13, 31, tzinfo=UTC)
    assert created_at.nanosecond == 123_456_789
    assert created_at.normalized_utc == "2026-07-15T13:31:00.123456789Z"
    assert submitted_at is not None
    assert submitted_at.normalized_utc == "2026-07-15T13:30:59.999999999Z"
    assert submitted_at.utc_second < created_at.utc_second


def test_provider_timestamp_rejects_the_rfc3339_unknown_offset_marker() -> None:
    with pytest.raises(AlpacaPaperObservationError, match="unknown-offset"):
        AlpacaProviderTimestamp("2026-07-15T13:31:00-00:00")


@pytest.mark.parametrize("status", tuple(AlpacaOrderStatus))
def test_every_frozen_order_status_uses_the_closed_classifier(
    status: AlpacaOrderStatus,
) -> None:
    payload = fixture_object()
    payload["status"] = status.value
    if status is AlpacaOrderStatus.PARTIALLY_FILLED:
        payload["filled_qty"] = "4"
        payload["filled_avg_price"] = "100.25"
    elif status is AlpacaOrderStatus.FILLED:
        payload["filled_qty"] = "10"
        payload["filled_avg_price"] = "100.25"
        payload["filled_at"] = "2026-07-15T13:31:00.999999999Z"

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.order is not None
    assert observation.order.status is status
    assert observation.order.disposition is not None


@pytest.mark.parametrize("deprecated_order_type", (None, ""))
def test_deprecated_optional_order_type_does_not_create_a_false_mismatch(
    deprecated_order_type: str | None,
) -> None:
    payload = fixture_object()
    payload["order_type"] = deprecated_order_type

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.order is not None
    assert observation.order.order_type == deprecated_order_type


def test_conflicting_nonempty_deprecated_order_type_is_retained_as_mismatch() -> None:
    payload = fixture_object()
    payload["order_type"] = "limit"

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    assert observation.mismatch_fields == ("order_type",)


def test_documented_zero_average_price_and_trailing_zero_lexemes_are_retained() -> None:
    payload = fixture_object()
    payload["filled_avg_price"] = "0.0"
    payload["filled_qty"] = "0.000"
    payload["qty"] = "10.000000000"

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.order is not None
    assert observation.order.filled_average_price == Decimal(0)
    assert observation.order.filled_quantity == Decimal(0)
    assert observation.order.quantity == Decimal(10)


def test_documented_legacy_example_shape_can_omit_new_optional_fields() -> None:
    payload = fixture_object()
    payload.pop("expires_at")
    payload.pop("position_intent")
    payload.pop("ratio_qty")
    reviewed_official_equity_example_keys = {
        "asset_class",
        "asset_id",
        "canceled_at",
        "client_order_id",
        "created_at",
        "expired_at",
        "extended_hours",
        "failed_at",
        "filled_at",
        "filled_avg_price",
        "filled_qty",
        "hwm",
        "id",
        "legs",
        "limit_price",
        "notional",
        "order_class",
        "order_type",
        "qty",
        "replaced_at",
        "replaced_by",
        "replaces",
        "side",
        "source",
        "status",
        "stop_price",
        "submitted_at",
        "subtag",
        "symbol",
        "time_in_force",
        "trail_percent",
        "trail_price",
        "type",
        "updated_at",
    }

    assert set(payload) == reviewed_official_equity_example_keys
    observation = decode_found(json_bytes(payload))
    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.order is not None
    assert observation.order.expires_at is None
    assert observation.order.position_intent is None
    assert observation.order.ratio_quantity is None


def test_nullable_update_and_submission_times_are_an_intentional_local_profile() -> None:
    payload = fixture_object()
    payload["updated_at"] = None
    payload["submitted_at"] = None

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.order is not None
    assert observation.order.updated_at is None
    assert observation.order.submitted_at is None


def test_same_client_id_with_different_economics_is_retained_as_mismatch() -> None:
    payload = fixture_object()
    payload.update(
        {
            "asset_class": "crypto",
            "extended_hours": True,
            "hwm": "101",
            "legs": [{"id": "opaque-unsupported-leg"}],
            "limit_price": "100",
            "order_class": "bracket",
            "order_type": "limit",
            "position_intent": "sell_to_open",
            "qty": "11",
            "ratio_qty": "1",
            "replaced_at": "2026-07-15T13:31:00.5Z",
            "replaced_by": "71e69015-8549-4bfd-b9c3-01e75843f47d",
            "side": "sell",
            "stop_price": "99",
            "symbol": "QQQ",
            "time_in_force": "gtc",
            "trail_percent": "2.5",
            "trail_price": "2",
            "type": "limit",
        }
    )

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    assert observation.order is not None
    expected_client_order_id = lookup_description().submission.request.client_order_id
    assert observation.order.client_order_id == expected_client_order_id
    assert observation.mismatch_fields == (
        "asset_class",
        "symbol",
        "quantity",
        "side",
        "order_type",
        "type",
        "time_in_force",
        "order_class",
        "extended_hours",
        "limit_price",
        "stop_price",
        "trail_percent",
        "trail_price",
        "high_water_mark",
        "legs",
        "position_intent",
        "ratio_quantity",
        "replacement_chain",
    )
    assert observation.additional_reconciliation_required is True
    assert observation.unknown_submission_resolution_authorized is False


def test_notional_order_is_observable_but_never_matches_the_local_quantity() -> None:
    payload = fixture_object()
    payload["qty"] = None
    payload["notional"] = "1000"

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    assert observation.order is not None
    assert observation.order.notional == Decimal(1000)
    assert observation.order.quantity is None
    assert observation.mismatch_fields == ("quantity", "notional")


@pytest.mark.parametrize("status", ("partially_filled", "filled"))
def test_filled_notional_collision_is_retained_as_mismatch(status: str) -> None:
    payload = fixture_object()
    payload.update(
        {
            "filled_at": ("2026-07-15T13:31:00.999999999Z" if status == "filled" else None),
            "filled_avg_price": "105.00",
            "filled_qty": "9.500",
            "notional": "1000.00",
            "qty": None,
            "status": status,
        }
    )

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    assert observation.order is not None
    assert observation.order.notional == Decimal(1000)
    assert observation.order.filled_quantity == Decimal("9.5")
    assert observation.mismatch_fields == ("quantity", "notional")


def test_documented_empty_mleg_identity_is_retained_as_a_mismatch() -> None:
    payload = fixture_object()
    payload.update(
        {
            "asset_class": "",
            "asset_id": "",
            "legs": [{"id": "opaque-leg-retained-by-digest"}],
            "order_class": "mleg",
            "order_type": "",
            "side": "",
            "symbol": "",
            "type": "",
        }
    )

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MISMATCH
    assert observation.order is not None
    assert observation.order.asset_id == ""
    assert observation.order.legs_sha256 is not None


def test_request_economics_match_does_not_claim_security_identity_validation() -> None:
    payload = fixture_object()
    payload["asset_id"] = None

    observation = decode_found(json_bytes(payload))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.FOUND_MATCHED
    assert observation.order is not None
    assert observation.order.asset_id is None
    assert ALPACA_PAPER_CAPABILITIES.security_mapping_ready is False
    assert ALPACA_PAPER_CAPABILITIES.asset_tradability_validation_ready is False


def test_lookup_rejects_a_different_returned_client_order_id() -> None:
    payload = fixture_object()
    payload["client_order_id"] = "aqt-unrelated-client-id"

    with pytest.raises(AlpacaPaperObservationError, match="different client_order_id"):
        decode_found(json_bytes(payload))


def test_404_is_repeatably_inconclusive_and_never_proves_not_submitted() -> None:
    first = decode_not_found()
    second = decode_not_found()

    assert first == second
    assert first.outcome is AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE
    assert first.http_status == 404
    assert first.response_sha256 == NOT_FOUND_RESPONSE_SHA256
    assert first.not_found_code == 40_410_000
    assert first.not_found_message == "order not found"
    assert first.order is None
    assert first.mismatch_fields == ()
    assert first.inconclusive is True
    assert first.additional_reconciliation_required is True
    assert first.unknown_submission_resolution_authorized is False
    assert first.semantic_sha256 == NOT_FOUND_OBSERVATION_SHA256
    assert not hasattr(first, "resolution")


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (lambda payload: payload.update({"unexpected": None}), "wire profile"),
        (lambda payload: payload.pop("status"), "wire profile"),
        (lambda payload: payload.update({"qty": True}), "exact string"),
        (lambda payload: payload.update({"qty": "01"}), "plain decimal"),
        (
            lambda payload: payload.update({"created_at": "2026-07-15T13:31:00.1234567890Z"}),
            "at most 9",
        ),
        (lambda payload: payload.update({"status": "future_status"}), "unsupported"),
        (lambda payload: payload.update({"filled_qty": "11"}), "exceeds"),
        (
            lambda payload: payload.update({"status": "partially_filled", "filled_qty": "0"}),
            "partially-filled",
        ),
        (
            lambda payload: payload.update(
                {"status": "filled", "filled_qty": "10", "filled_avg_price": "100"}
            ),
            "filled_at",
        ),
    ),
)
def test_lookup_rejects_schema_type_decimal_time_and_economic_drift(
    mutate: Any,
    match: str,
) -> None:
    payload = fixture_object()
    mutate(payload)

    with pytest.raises(AlpacaPaperObservationError, match=match):
        decode_found(json_bytes(payload))


@pytest.mark.parametrize(
    ("payload", "match"),
    (
        (b'{"id":"one","id":"two"}', "duplicate"),
        (b"[]", "one JSON object"),
        (b'{"value":NaN}', "non-standard"),
        (b"\xff", "UTF-8"),
    ),
)
def test_lookup_rejects_ambiguous_or_nonstandard_json(
    payload: bytes,
    match: str,
) -> None:
    with pytest.raises(AlpacaPaperObservationError, match=match):
        decode_found(payload)


def test_lookup_rejects_excessively_nested_json_as_a_contract_error() -> None:
    payload = b'{"value":' + (b"[" * 10_000) + b"0" + (b"]" * 10_000) + b"}"

    with pytest.raises(AlpacaPaperObservationError, match="invalid JSON"):
        decode_found(payload)


def test_lookup_enforces_exact_byte_type_and_response_bound() -> None:
    with pytest.raises(AlpacaPaperObservationError, match="exact bytes"):
        decode_alpaca_client_order_lookup_response(
            lookup_description(),
            http_status=200,
            provider_request_id="fixture-request",
            response_body=bytearray(b"{}"),  # type: ignore[arg-type]
            received_at=RECEIVED_AT,
        )

    with pytest.raises(AlpacaPaperObservationError, match="size"):
        decode_found(b"")

    with pytest.raises(AlpacaPaperObservationError, match="size"):
        decode_found(b" " * (ALPACA_PAPER_MAX_LOOKUP_RESPONSE_BYTES + 1))


@pytest.mark.parametrize(
    "payload",
    (
        b'{"code":40410000,"message":"order not found","extra":true}',
        b'{"code":"40410000","message":"order not found"}',
        b'{"code":true,"message":"order not found"}',
        b'{"code":0,"message":"order not found"}',
        b'{"code":-1,"message":"order not found"}',
        b'{"code":2147483648,"message":"order not found"}',
        b'{"code":40410000,"message":""}',
    ),
)
def test_not_found_error_shape_is_closed(payload: bytes) -> None:
    with pytest.raises(AlpacaPaperObservationError):
        decode_not_found(payload)


@pytest.mark.parametrize("code", (1, 40_410_000, 40_410_001, 2_147_483_647))
def test_any_bounded_404_error_code_remains_inconclusive(code: int) -> None:
    observation = decode_not_found(json_bytes({"code": code, "message": "bounded provider error"}))

    assert observation.outcome is AlpacaClientOrderLookupOutcome.NOT_VISIBLE_INCONCLUSIVE
    assert observation.not_found_code == code
    assert observation.not_found_message == "bounded provider error"
    assert observation.unknown_submission_resolution_authorized is False


@pytest.mark.parametrize("http_status", (0, 201, 400, 429, 500))
def test_other_http_statuses_do_not_gain_a_lookup_meaning(http_status: int) -> None:
    with pytest.raises(AlpacaPaperObservationError, match="only"):
        decode_alpaca_client_order_lookup_response(
            lookup_description(),
            http_status=http_status,
            provider_request_id="fixture-request",
            response_body=fixture_bytes("lookup_not_found.json"),
            received_at=RECEIVED_AT,
        )


def test_observation_authenticates_immutable_fields_against_retained_bytes() -> None:
    observation = decode_found()

    with pytest.raises(FrozenInstanceError):
        observation.http_status = 404  # type: ignore[misc]
    with pytest.raises(AlpacaPaperObservationError, match="does not match"):
        replace(
            observation,
            outcome=AlpacaClientOrderLookupOutcome.FOUND_MISMATCH,
            mismatch_fields=("symbol",),
        )
    with pytest.raises(AlpacaPaperObservationError):
        replace(observation, response_body=fixture_bytes("lookup_not_found.json"))
    assert observation.order is not None
    with pytest.raises(FrozenInstanceError):
        observation.order.symbol = "QQQ"  # type: ignore[misc]


def test_direct_construction_rejects_mutable_or_equality_spoofed_derived_fields() -> None:
    found = decode_found()
    not_found = decode_not_found()

    class EqualitySpoof:
        semantic_sha256 = "0" * 64

        def __eq__(self, other: object) -> bool:
            return True

    with pytest.raises(AlpacaPaperObservationError, match="exact AlpacaOrderObservation"):
        replace(found, order=EqualitySpoof())  # type: ignore[arg-type]
    with pytest.raises(AlpacaPaperObservationError, match="unique closed tuple"):
        replace(not_found, mismatch_fields=[])  # type: ignore[arg-type]
    with pytest.raises(AlpacaPaperObservationError, match="unique closed tuple"):
        replace(not_found, mismatch_fields=("future_field",))
    with pytest.raises(AlpacaPaperObservationError, match="exact integer"):
        replace(not_found, not_found_code=True)


def test_rest_observation_cannot_be_mistaken_for_resolution_or_execution() -> None:
    for observation in (decode_found(), decode_not_found()):
        opaque_observation: object = observation
        assert observation.trading_effect_authorized is False
        assert observation.canonical_execution_fact_authorized is False
        assert observation.unknown_submission_resolution_authorized is False
        assert observation.additional_reconciliation_required is True
        assert not isinstance(opaque_observation, BrokerOrderEvent)
        assert not isinstance(opaque_observation, UnknownSubmissionResolution)
        assert not hasattr(observation, "broker_sequence")
        assert not hasattr(observation, "execution_id")
        if observation.order is not None:
            assert observation.order.trading_effect_authorized is False
            assert observation.order.canonical_execution_fact_authorized is False


def test_lookup_values_do_not_retain_credentials_or_authentication_headers() -> None:
    description = lookup_description()
    observation = decode_found()
    rendered = f"{description!r}\n{observation!r}"

    assert "APCA-API-KEY-ID" not in rendered
    assert "APCA-API-SECRET-KEY" not in rendered
    assert fixture_bytes("lookup_found.json").decode("utf-8") not in rendered


def test_observation_module_is_enrolled_in_the_side_effect_free_boundary() -> None:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as config_file:
        config = tomllib.load(config_file)

    assert {
        "packages/adapters/broker/alpaca_paper.py",
        "packages/adapters/broker/alpaca_paper_observations.py",
    } <= set(config["scan"]["side_effect_free_roots"])
