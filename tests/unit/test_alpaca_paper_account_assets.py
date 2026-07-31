from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CANDIDATE_INSTRUMENTS,
    ALPACA_PAPER_CAPABILITIES,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION,
    ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION,
    ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON,
    ALPACA_PAPER_MAX_ACCOUNT_ASSET_RESPONSE_BYTES,
    ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES,
    ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT,
    AlpacaAccountObservation,
    AlpacaAccountObservationOutcome,
    AlpacaAccountStatus,
    AlpacaAssetAttribute,
    AlpacaAssetClass,
    AlpacaAssetExchange,
    AlpacaAssetObservation,
    AlpacaAssetObservationOutcome,
    AlpacaAssetStatus,
    AlpacaPaperAccountAssetObservationError,
    AlpacaPaperAccountObservationDescription,
    AlpacaPaperAssetObservationDescription,
    create_alpaca_account_observation_description,
    create_alpaca_asset_observation_description,
    decode_alpaca_account_observation_response,
    decode_alpaca_asset_observation_response,
)

RECEIVED_AT = datetime(2026, 7, 27, 14, 30, 1, 123456, tzinfo=UTC)
ACCOUNT_ID = "paper-account-fixture"


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def account_payload() -> dict[str, Any]:
    return {
        "account_blocked": False,
        "account_number": "PA3APERFIXTURE",
        "buying_power": "200000.00",
        "cash": "100000.00",
        "created_at": "2026-07-01T09:30:00.123456789-04:00",
        "currency": "USD",
        "id": "8d56e1e8-0cda-4f67-b5eb-7dedd1cbf28f",
        "pattern_day_trader": False,
        "portfolio_value": "100000.00",
        "shorting_enabled": True,
        "status": "ACTIVE",
        "trade_suspended_by_user": False,
        "trading_blocked": False,
        "transfers_blocked": False,
    }


def asset_payload() -> dict[str, Any]:
    return {
        "attributes": [],
        "class": "us_equity",
        "easy_to_borrow": True,
        "exchange": "ARCA",
        "fractionable": True,
        "id": "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415",
        "maintenance_margin_requirement": 30,
        "marginable": True,
        "name": "SPDR S&P 500 ETF Trust",
        "shortable": True,
        "status": "active",
        "symbol": "SPY",
        "tradable": True,
    }


def account_description() -> AlpacaPaperAccountObservationDescription:
    return create_alpaca_account_observation_description(account_id=ACCOUNT_ID)


def asset_description(
    instrument_id: str = "US-ETF-SPY",
    symbol: str = "SPY",
) -> AlpacaPaperAssetObservationDescription:
    return create_alpaca_asset_observation_description(
        account_id=ACCOUNT_ID,
        instrument_id=instrument_id,
        symbol=symbol,
    )


def decode_account(
    payload: dict[str, Any] | None = None,
    *,
    response_body: bytes | None = None,
) -> AlpacaAccountObservation:
    body = (
        json_bytes(account_payload() if payload is None else payload)
        if response_body is None
        else response_body
    )
    return decode_alpaca_account_observation_response(
        account_description(),
        http_status=200,
        provider_request_id="account-request-0001",
        response_body=body,
        received_at=RECEIVED_AT,
    )


def decode_asset(
    payload: dict[str, Any] | None = None,
    *,
    response_body: bytes | None = None,
    http_status: int = 200,
) -> AlpacaAssetObservation:
    body = (
        json_bytes(asset_payload() if payload is None else payload)
        if response_body is None
        else response_body
    )
    return decode_alpaca_asset_observation_response(
        asset_description(),
        http_status=http_status,
        provider_request_id="asset-request-0001",
        response_body=body,
        received_at=RECEIVED_AT,
    )


def test_account_description_is_deterministic_and_paper_bound() -> None:
    description = account_description()

    assert description.contract_version == ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION
    assert ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON == "2026-07-30"
    assert description.reviewed_on == ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON
    assert description.provider_model_commit == ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT
    assert ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT == ("bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f")
    assert description.account_id == ACCOUNT_ID
    assert description.adapter_id == ALPACA_PAPER_ADAPTER_ID
    assert description.adapter_version == ALPACA_PAPER_ADAPTER_VERSION
    assert description.capability_sha256 == ALPACA_PAPER_CAPABILITIES.semantic_sha256
    assert description.environment == "paper"
    assert description.candidate_instrument_symbols == ALPACA_PAPER_CANDIDATE_INSTRUMENTS
    assert description.method == "GET"
    assert description.base_url == "https://paper-api.alpaca.markets"
    assert description.path == "/v2/account"
    assert description.request_target == "/v2/account"
    assert description.url == "https://paper-api.alpaca.markets/v2/account"
    assert dict(description.query) == {}
    assert description.semantic_sha256 == account_description().semantic_sha256
    assert description.credential_resolution_authorized is False
    assert description.transport_authorized is False
    assert description.runtime_request_ready is False
    assert description.trading_effect_authorized is False

    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="bounded"):
        create_alpaca_account_observation_description(account_id="x" * 65)
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="exact string"):
        create_alpaca_account_observation_description(account_id=1)  # type: ignore[arg-type]


@pytest.mark.parametrize(("instrument_id", "symbol"), ALPACA_PAPER_CANDIDATE_INSTRUMENTS)
def test_asset_descriptions_are_exactly_candidate_bound(
    instrument_id: str,
    symbol: str,
) -> None:
    description = asset_description(instrument_id, symbol)

    assert description.account_id == ACCOUNT_ID
    assert description.instrument_id == instrument_id
    assert description.symbol == symbol
    assert description.capability_sha256 == ALPACA_PAPER_CAPABILITIES.semantic_sha256
    assert description.reviewed_on == ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON
    assert description.provider_model_commit == ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT
    assert description.environment == "paper"
    assert description.candidate_instrument_symbols == ALPACA_PAPER_CANDIDATE_INSTRUMENTS
    assert description.method == "GET"
    assert description.path == f"/v2/assets/{symbol}"
    assert description.request_target == f"/v2/assets/{symbol}"
    assert description.url == f"https://paper-api.alpaca.markets/v2/assets/{symbol}"
    assert dict(description.query) == {}
    assert (
        description.semantic_sha256
        == asset_description(
            instrument_id,
            symbol,
        ).semantic_sha256
    )
    assert description.credential_resolution_authorized is False
    assert description.transport_authorized is False
    assert description.runtime_request_ready is False
    assert description.trading_effect_authorized is False


@pytest.mark.parametrize(
    ("instrument_id", "symbol"),
    (
        ("US-ETF-SPY", "QQQ"),
        ("US-ETF-UNKNOWN", "SPY"),
        ("US-ETF-SPY", "spy"),
    ),
)
def test_asset_description_rejects_any_candidate_map_drift(
    instrument_id: str,
    symbol: str,
) -> None:
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match=r"candidate map|canonical"):
        asset_description(instrument_id, symbol)


def test_account_observation_retains_exact_identity_flags_and_raw_bytes() -> None:
    body = json_bytes(account_payload())
    observation = decode_account(response_body=body)

    assert type(observation) is AlpacaAccountObservation
    assert observation.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert observation.http_status == 200
    assert observation.provider_request_id == "account-request-0001"
    assert observation.received_at == RECEIVED_AT
    assert observation.response_body is body
    assert observation.response_size_bytes == len(body)
    assert observation.response_sha256 == hashlib.sha256(body).hexdigest()
    assert observation.provider_account_id == "8d56e1e8-0cda-4f67-b5eb-7dedd1cbf28f"
    assert observation.status is AlpacaAccountStatus.ACTIVE
    assert observation.currency == "USD"
    assert observation.account_blocked is False
    assert observation.trading_blocked is False
    assert observation.transfers_blocked is False
    assert observation.trade_suspended_by_user is False
    assert observation.shorting_enabled is True
    assert observation.pattern_day_trader is False
    assert observation.created_at == "2026-07-01T09:30:00.123456789-04:00"
    assert observation.qualification_failures == ()
    assert observation.validated_noncanonical_economic_fields == (
        "buying_power",
        "cash",
        "portfolio_value",
    )
    assert not hasattr(observation, "buying_power")
    assert not hasattr(observation, "cash")
    assert not hasattr(observation, "portfolio_value")
    assert observation.environment == "paper"
    assert observation.evidence_qualification == (ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION)
    assert observation.semantic_sha256 == decode_account(response_body=body).semantic_sha256


@pytest.mark.parametrize(
    ("changes", "outcome", "failures"),
    (
        (
            {"currency": "EUR"},
            AlpacaAccountObservationOutcome.CURRENCY_MISMATCH,
            ("currency",),
        ),
        (
            {"status": "ACCOUNT_UPDATED"},
            AlpacaAccountObservationOutcome.INACTIVE,
            ("account_status",),
        ),
        (
            {"status": "INACTIVE"},
            AlpacaAccountObservationOutcome.INACTIVE,
            ("account_status",),
        ),
        (
            {"account_blocked": True},
            AlpacaAccountObservationOutcome.BLOCKED,
            ("account_blocked",),
        ),
        (
            {"trading_blocked": True},
            AlpacaAccountObservationOutcome.BLOCKED,
            ("trading_blocked",),
        ),
        (
            {"transfers_blocked": True},
            AlpacaAccountObservationOutcome.BLOCKED,
            ("transfers_blocked",),
        ),
        (
            {"trade_suspended_by_user": True},
            AlpacaAccountObservationOutcome.BLOCKED,
            ("trade_suspended_by_user",),
        ),
        (
            {
                "currency": "EUR",
                "status": "REJECTED",
                "account_blocked": True,
                "trading_blocked": True,
            },
            AlpacaAccountObservationOutcome.CURRENCY_MISMATCH,
            ("currency", "account_status", "account_blocked", "trading_blocked"),
        ),
    ),
)
def test_account_qualification_is_explicit_and_fail_closed(
    changes: dict[str, Any],
    outcome: AlpacaAccountObservationOutcome,
    failures: tuple[str, ...],
) -> None:
    payload = account_payload()
    payload.update(changes)

    observation = decode_account(payload)

    assert observation.outcome is outcome
    assert observation.qualification_failures == failures
    assert observation.runtime_current is False
    assert observation.dispatch_preflight_ready is False


@pytest.mark.parametrize("legacy_value", (None, False, True))
def test_retired_pattern_day_trader_is_retained_but_never_qualifies_current_state(
    legacy_value: bool | None,
) -> None:
    payload = account_payload()
    payload["pattern_day_trader"] = legacy_value

    observation = decode_account(payload)

    assert observation.pattern_day_trader is legacy_value
    assert observation.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert observation.qualification_failures == ()


@pytest.mark.parametrize(
    "field_name",
    (
        "currency",
        "account_blocked",
        "trading_blocked",
        "transfers_blocked",
        "trade_suspended_by_user",
    ),
)
@pytest.mark.parametrize("representation", ("absent", "null"))
def test_missing_current_account_qualification_fields_are_incomplete(
    field_name: str,
    representation: str,
) -> None:
    payload = account_payload()
    if representation == "absent":
        del payload[field_name]
    else:
        payload[field_name] = None

    observation = decode_account(payload)

    assert observation.outcome is AlpacaAccountObservationOutcome.INCOMPLETE
    assert field_name in observation.qualification_failures
    assert observation.dispatch_preflight_ready is False


@pytest.mark.parametrize(
    "status",
    tuple(status for status in AlpacaAccountStatus if status is not AlpacaAccountStatus.ACTIVE),
)
def test_every_reviewed_non_active_account_status_is_inactive(
    status: AlpacaAccountStatus,
) -> None:
    payload = account_payload()
    payload["status"] = status.value

    observation = decode_account(payload)

    assert observation.status is status
    assert observation.outcome is AlpacaAccountObservationOutcome.INACTIVE
    assert observation.qualification_failures == ("account_status",)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("id", "not-a-uuid", "canonical UUID"),
        ("id", "8D56E1E8-0CDA-4F67-B5EB-7DEDD1CBF28F", "lowercase UUID"),
        ("status", "UNREVIEWED", "unsupported Alpaca account status"),
        ("currency", "usd", "uppercase"),
        ("account_blocked", 0, "exact boolean"),
        ("pattern_day_trader", 1, "exact boolean"),
        ("created_at", "2026-02-30T10:00:00Z", "valid instant"),
        ("created_at", "2026-07-01T09:30:00-00:00", "unknown-offset"),
        ("buying_power", "1e5", "plain decimal"),
        ("cash", "01.00", "plain decimal"),
        ("portfolio_value", "NaN", "plain decimal"),
    ),
)
def test_account_profile_rejects_wrong_types_and_malformed_values(
    field_name: str,
    value: object,
    message: str,
) -> None:
    payload = account_payload()
    payload[field_name] = value

    with pytest.raises(AlpacaPaperAccountAssetObservationError, match=message):
        decode_account(payload)


def test_account_profile_accepts_and_strictly_validates_reviewed_optional_fields() -> None:
    payload = account_payload()
    payload.update(
        {
            "accrued_fees": "0",
            "crypto_status": "ACTIVE",
            "daytrade_count": 0,
            "daytrading_buying_power": "262113.632",
            "equity": "103820.56",
            "initial_margin": "63480.38",
            "last_equity": "103529.24",
            "last_maintenance_margin": "38000.832",
            "long_market_value": "126960.76",
            "maintenance_margin": "38088.228",
            "multiplier": "4",
            "non_marginable_buying_power": "7386.56",
            "options_approved_level": 3,
            "options_buying_power": "7500.25",
            "options_trading_level": 2,
            "pending_transfer_in": "0",
            "pending_transfer_out": "0",
            "regt_buying_power": "80680.36",
            "short_market_value": "0",
            "sma": "0",
        }
    )

    observation = decode_account(payload)

    assert observation.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert observation.validated_noncanonical_economic_fields == (
        "accrued_fees",
        "buying_power",
        "cash",
        "daytrading_buying_power",
        "equity",
        "initial_margin",
        "last_equity",
        "last_maintenance_margin",
        "long_market_value",
        "maintenance_margin",
        "multiplier",
        "non_marginable_buying_power",
        "options_buying_power",
        "pending_transfer_in",
        "pending_transfer_out",
        "portfolio_value",
        "regt_buying_power",
        "short_market_value",
        "sma",
    )
    assert not hasattr(observation, "equity")
    assert not hasattr(observation, "daytrade_count")
    assert not hasattr(observation, "crypto_status")

    for field_name, value, message in (
        ("crypto_status", "UNKNOWN", "crypto account status"),
        ("daytrade_count", "0", "non-negative integer"),
        ("daytrade_count", -1, "non-negative integer"),
        ("equity", "1e5", "plain decimal"),
        ("options_buying_power", 100, "exact string"),
        ("options_approved_level", True, "integer from 0 through 3"),
        ("options_approved_level", 4, "integer from 0 through 3"),
        ("options_trading_level", -1, "integer from 0 through 3"),
        ("options_trading_level", "2", "integer from 0 through 3"),
    ):
        drifted = payload.copy()
        drifted[field_name] = value
        with pytest.raises(AlpacaPaperAccountAssetObservationError, match=message):
            decode_account(drifted)

    nullable = payload.copy()
    nullable.update(
        {
            "crypto_status": None,
            "daytrade_count": None,
            "daytrading_buying_power": None,
            "options_approved_level": None,
            "options_buying_power": None,
            "options_trading_level": None,
            "pattern_day_trader": None,
        }
    )
    assert decode_account(nullable).outcome is (
        AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    )


def test_current_account_response_accepts_reviewed_raw_only_fields() -> None:
    payload = account_payload()
    payload.update(
        {
            "admin_configurations": {},
            "balance_asof": "2026-07-30",
            "crypto_tier": 1,
            "effective_buying_power": "200000.00",
            "intraday_adjustments": "0",
            "pending_reg_taf_fees": "1.25",
            "position_market_value": "100000.00",
            "user_configurations": {},
        }
    )

    observation = decode_account(payload)

    assert observation.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    reviewed_economic_fields = (
        "effective_buying_power",
        "intraday_adjustments",
        "pending_reg_taf_fees",
        "position_market_value",
    )
    assert (
        tuple(
            field_name
            for field_name in observation.validated_noncanonical_economic_fields
            if field_name in reviewed_economic_fields
        )
        == reviewed_economic_fields
    )
    for field_name in payload.keys() & {
        "admin_configurations",
        "balance_asof",
        "crypto_tier",
        *reviewed_economic_fields,
        "user_configurations",
    }:
        assert not hasattr(observation, field_name)


@pytest.mark.parametrize(
    "balance_asof",
    (
        "2026-02-30",
        "2026-7-30",
        "2026/07/30",
    ),
)
def test_account_balance_asof_rejects_impossible_or_wrong_shape_dates(
    balance_asof: str,
) -> None:
    payload = account_payload()
    payload["balance_asof"] = balance_asof

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="exact valid YYYY-MM-DD date",
    ):
        decode_account(payload)


@pytest.mark.parametrize("crypto_tier", (True, "1", -1, 101))
def test_account_crypto_tier_rejects_noncanonical_or_out_of_range_values(
    crypto_tier: object,
) -> None:
    payload = account_payload()
    payload["crypto_tier"] = crypto_tier

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="exact integer from 0 through 100 or null",
    ):
        decode_account(payload)


@pytest.mark.parametrize("field_name", ("admin_configurations", "user_configurations"))
@pytest.mark.parametrize("configuration", (None, {}))
def test_account_configurations_accept_only_null_or_empty_objects(
    field_name: str,
    configuration: object,
) -> None:
    payload = account_payload()
    payload[field_name] = configuration

    assert decode_account(payload).outcome is (
        AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    )


@pytest.mark.parametrize("field_name", ("admin_configurations", "user_configurations"))
@pytest.mark.parametrize(
    "configuration",
    (
        {"enabled": True},
        [],
        "{}",
        False,
    ),
)
def test_account_configurations_reject_populated_objects_and_wrong_types(
    field_name: str,
    configuration: object,
) -> None:
    payload = account_payload()
    payload[field_name] = configuration

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="null or an exact empty object",
    ):
        decode_account(payload)


def test_current_account_review_still_rejects_unrelated_top_level_fields() -> None:
    payload = account_payload()
    payload.update(
        {
            "admin_configurations": None,
            "balance_asof": "2026-07-30",
            "crypto_tier": 1,
            "effective_buying_power": "200000.00",
            "intraday_adjustments": "0",
            "pending_reg_taf_fees": "1.25",
            "position_market_value": "100000.00",
            "unreviewed_provider_field": None,
            "user_configurations": {},
        }
    )

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="reviewed wire profile",
    ):
        decode_account(payload)


def test_current_account_shape_omits_all_retired_pdt_fields() -> None:
    payload = account_payload()
    del payload["pattern_day_trader"]
    payload.update(
        {
            "options_approved_level": 1,
            "options_buying_power": "1000",
            "options_trading_level": 1,
        }
    )

    observation = decode_account(payload)

    assert observation.pattern_day_trader is None
    assert observation.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert "daytrade_count" not in observation.validated_noncanonical_economic_fields
    assert "daytrading_buying_power" not in observation.validated_noncanonical_economic_fields


def test_stale_account_shape_accepts_only_exact_legacy_pdt_types() -> None:
    payload = account_payload()
    payload.update(
        {
            "daytrade_count": 2,
            "daytrading_buying_power": "12000.50",
            "pattern_day_trader": True,
        }
    )

    observation = decode_account(payload)

    assert observation.pattern_day_trader is True
    assert observation.outcome is AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert "daytrading_buying_power" in (observation.validated_noncanonical_economic_fields)

    for field_name, invalid in (
        ("daytrade_count", "2"),
        ("daytrading_buying_power", 12000),
        ("pattern_day_trader", 1),
    ):
        drifted = payload.copy()
        drifted[field_name] = invalid
        with pytest.raises(AlpacaPaperAccountAssetObservationError):
            decode_account(drifted)


@pytest.mark.parametrize("mutator", ("missing", "unknown", "environment"))
def test_account_profile_rejects_missing_unknown_and_response_environment(
    mutator: str,
) -> None:
    payload = account_payload()
    if mutator == "missing":
        del payload["account_number"]
    elif mutator == "unknown":
        payload["new_provider_field"] = "drift"
    else:
        payload["environment"] = "paper"

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="reviewed wire profile",
    ):
        decode_account(payload)


def test_account_decoder_rejects_duplicate_keys_non_utf8_and_bounds() -> None:
    duplicate = (
        b'{"account_blocked":false,"account_blocked":true,"account_number":"x",'
        b'"buying_power":"1","cash":"1","created_at":"2026-07-01T00:00:00Z",'
        b'"currency":"USD","id":"8d56e1e8-0cda-4f67-b5eb-7dedd1cbf28f",'
        b'"pattern_day_trader":false,"portfolio_value":"1","shorting_enabled":true,'
        b'"status":"ACTIVE","trade_suspended_by_user":false,"trading_blocked":false,'
        b'"transfers_blocked":false}'
    )
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="duplicate JSON key"):
        decode_account(response_body=duplicate)
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="UTF-8"):
        decode_account(response_body=b"\xff")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="size"):
        decode_account(response_body=b"")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="size"):
        decode_account(
            response_body=b"{" + b" " * ALPACA_PAPER_MAX_ACCOUNT_ASSET_RESPONSE_BYTES + b"}"
        )
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="invalid JSON"):
        decode_account(response_body=b"{")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="one JSON object"):
        decode_account(response_body=b"[]")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="non-standard"):
        decode_account(response_body=b'{"value":NaN}')


def test_account_decoder_rejects_unqualified_envelope_metadata() -> None:
    body = json_bytes(account_payload())
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="successful"):
        decode_alpaca_account_observation_response(
            account_description(),
            http_status=403,
            provider_request_id="account-request-0001",
            response_body=body,
            received_at=RECEIVED_AT,
        )
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="bounded"):
        decode_alpaca_account_observation_response(
            account_description(),
            http_status=200,
            provider_request_id=" request ",
            response_body=body,
            received_at=RECEIVED_AT,
        )
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="must be UTC"):
        decode_alpaca_account_observation_response(
            account_description(),
            http_status=200,
            provider_request_id="account-request-0001",
            response_body=body,
            received_at=datetime(
                2026,
                7,
                27,
                10,
                30,
                tzinfo=timezone(timedelta(hours=-4)),
            ),
        )


def test_account_observation_cannot_be_tampered_or_mutated() -> None:
    observation = decode_account()

    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="exact response bytes"):
        replace(observation, provider_account_id="2dfe1e09-e8e4-40f0-bea2-c2eafb9ff0fd")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="exact response bytes"):
        replace(observation, account_blocked=True)
    with pytest.raises(FrozenInstanceError):
        observation.currency = "EUR"  # type: ignore[misc]


def test_account_evidence_never_grants_authority_or_runtime_readiness() -> None:
    observation = decode_account()

    assert observation.runtime_current is False
    assert observation.authenticated_provider_evidence is False
    assert observation.economics_canonicalized is False
    assert observation.durable_account_binding_authorized is False
    assert observation.canonical_account_fact_authorized is False
    assert observation.dispatch_preflight_ready is False
    assert observation.trading_effect_authorized is False


def test_asset_observation_retains_exact_profile_and_raw_bytes() -> None:
    body = json_bytes(asset_payload())
    observation = decode_asset(response_body=body)

    assert type(observation) is AlpacaAssetObservation
    assert observation.outcome is AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert observation.http_status == 200
    assert observation.provider_request_id == "asset-request-0001"
    assert observation.received_at == RECEIVED_AT
    assert observation.response_body is body
    assert observation.response_size_bytes == len(body)
    assert observation.response_sha256 == hashlib.sha256(body).hexdigest()
    assert observation.provider_asset_id == "b0b6dd9d-8b9b-48a9-ba46-b9d54906e415"
    assert observation.asset_class is AlpacaAssetClass.US_EQUITY
    assert observation.exchange is AlpacaAssetExchange.ARCA
    assert observation.symbol == "SPY"
    assert observation.name == "SPDR S&P 500 ETF Trust"
    assert observation.status is AlpacaAssetStatus.ACTIVE
    assert observation.tradable is True
    assert observation.marginable is True
    assert observation.maintenance_margin_requirement == Decimal(30)
    assert observation.shortable is True
    assert observation.easy_to_borrow is True
    assert observation.fractionable is True
    assert observation.attributes == ()
    assert observation.qualification_failures == ()
    assert observation.attribute_review_required is False
    assert observation.validated_raw_only_numeric_fields == ()
    assert observation.not_found_code is None
    assert observation.not_found_message is None
    assert observation.inconclusive is False
    assert observation.environment == "paper"
    assert observation.evidence_qualification == (ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION)
    assert observation.semantic_sha256 == decode_asset(response_body=body).semantic_sha256


@pytest.mark.parametrize(
    ("changes", "outcome", "failures"),
    (
        (
            {"symbol": "QQQ"},
            AlpacaAssetObservationOutcome.IDENTITY_MISMATCH,
            ("symbol",),
        ),
        (
            {"class": "crypto"},
            AlpacaAssetObservationOutcome.ASSET_CLASS_MISMATCH,
            ("asset_class",),
        ),
        (
            {"status": "inactive"},
            AlpacaAssetObservationOutcome.INACTIVE,
            ("asset_status",),
        ),
        (
            {"tradable": False},
            AlpacaAssetObservationOutcome.NOT_TRADABLE,
            ("tradable",),
        ),
        (
            {
                "symbol": "QQQ",
                "class": "crypto",
                "status": "inactive",
                "tradable": False,
            },
            AlpacaAssetObservationOutcome.IDENTITY_MISMATCH,
            ("symbol", "asset_class", "asset_status", "tradable"),
        ),
    ),
)
def test_asset_qualification_has_explicit_fail_closed_outcomes(
    changes: dict[str, Any],
    outcome: AlpacaAssetObservationOutcome,
    failures: tuple[str, ...],
) -> None:
    payload = asset_payload()
    payload.update(changes)

    observation = decode_asset(payload)

    assert observation.outcome is outcome
    assert observation.qualification_failures == failures
    assert observation.runtime_current is False
    assert observation.security_mapping_ready is False
    assert observation.asset_tradability_validation_ready is False


@pytest.mark.parametrize("exchange", ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES)
def test_only_explicit_listed_us_exchanges_are_v1_candidates(
    exchange: AlpacaAssetExchange,
) -> None:
    payload = asset_payload()
    payload["exchange"] = exchange.value

    observation = decode_asset(payload)

    assert observation.exchange is exchange
    assert observation.outcome is AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE


@pytest.mark.parametrize(
    "exchange",
    tuple(
        exchange
        for exchange in AlpacaAssetExchange
        if exchange not in ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES
    ),
)
def test_recognized_nonlisted_or_non_equity_exchanges_are_explicitly_ineligible(
    exchange: AlpacaAssetExchange,
) -> None:
    payload = asset_payload()
    payload["exchange"] = exchange.value

    observation = decode_asset(payload)

    assert observation.exchange is exchange
    assert observation.outcome is AlpacaAssetObservationOutcome.EXCHANGE_INELIGIBLE
    assert observation.qualification_failures == ("exchange",)
    assert observation.asset_tradability_validation_ready is False


@pytest.mark.parametrize("attribute", tuple(AlpacaAssetAttribute))
def test_known_nonempty_asset_attributes_require_explicit_review(
    attribute: AlpacaAssetAttribute,
) -> None:
    payload = asset_payload()
    payload["attributes"] = [attribute.value]

    observation = decode_asset(payload)

    assert observation.attributes == (attribute,)
    assert observation.outcome is AlpacaAssetObservationOutcome.ATTRIBUTE_REVIEW_REQUIRED
    assert observation.qualification_failures == ("attributes",)
    assert observation.attribute_review_required is True
    assert observation.dispatch_preflight_ready is False


def test_unknown_asset_exchange_and_attribute_are_rejected() -> None:
    for field_name, value, message in (
        ("exchange", "UNKNOWN", "unsupported Alpaca asset exchange"),
        ("attributes", ["ipo"], "unsupported Alpaca asset attribute"),
    ):
        payload = asset_payload()
        payload[field_name] = value
        with pytest.raises(AlpacaPaperAccountAssetObservationError, match=message):
            decode_asset(payload)


def test_fractionable_and_shortable_never_expand_the_local_execution_surface() -> None:
    observation = decode_asset()

    assert observation.fractionable is True
    assert observation.shortable is True
    assert ALPACA_PAPER_CAPABILITIES.whole_share_only is True
    assert ALPACA_PAPER_CAPABILITIES.fractional_quantity_enabled is False
    assert ALPACA_PAPER_CAPABILITIES.short_exposure_authorized is False
    assert observation.fractional_quantity_authorized is False
    assert observation.short_exposure_authorized is False


def test_asset_404_is_exact_and_inconclusive() -> None:
    body = b'{"code":40410000,"message":"asset not found"}'
    observation = decode_asset(response_body=body, http_status=404)

    assert observation.outcome is AlpacaAssetObservationOutcome.NOT_VISIBLE_INCONCLUSIVE
    assert observation.http_status == 404
    assert observation.response_body is body
    assert observation.response_sha256 == hashlib.sha256(body).hexdigest()
    assert observation.inconclusive is True
    assert observation.provider_asset_id is None
    assert observation.asset_class is None
    assert observation.exchange is None
    assert observation.symbol is None
    assert observation.status is None
    assert observation.tradable is None
    assert observation.attributes == ()
    assert observation.qualification_failures == ()
    assert observation.not_found_code == 40410000
    assert observation.not_found_message == "asset not found"
    assert observation.runtime_current is False


@pytest.mark.parametrize(
    ("body", "message"),
    (
        (b'{"code":0,"message":"asset not found"}', "positive integer"),
        (b'{"code":"40410000","message":"asset not found"}', "positive integer"),
        (b'{"code":40410000,"message":""}', "bounded"),
        (b'{"code":40410000,"message":"asset not found","status":404}', "wire profile"),
    ),
)
def test_asset_404_rejects_any_error_shape_drift(body: bytes, message: str) -> None:
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match=message):
        decode_asset(response_body=body, http_status=404)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("id", "not-a-uuid", "canonical UUID"),
        ("class", "US_EQUITY", "unsupported Alpaca asset class"),
        ("exchange", "nyse", "unsupported Alpaca asset exchange"),
        ("symbol", "spy", "canonical"),
        ("name", "", "bounded"),
        ("status", "delisted", "unsupported Alpaca asset status"),
        ("tradable", 1, "exact boolean"),
        ("marginable", "true", "exact boolean"),
        ("maintenance_margin_requirement", "30", "exact JSON number"),
        ("maintenance_margin_requirement", -1, "outside the reviewed non-negative bound"),
        ("shortable", None, "exact boolean"),
        ("easy_to_borrow", 0, "exact boolean"),
        ("fractionable", 1, "exact boolean"),
        ("attributes", "ptp_no_exception", "bounded array"),
        (
            "attributes",
            ["ptp_no_exception", "ptp_no_exception"],
            "must not contain duplicates",
        ),
    ),
)
def test_asset_profile_rejects_wrong_types_and_malformed_values(
    field_name: str,
    value: object,
    message: str,
) -> None:
    payload = asset_payload()
    payload[field_name] = value

    with pytest.raises(AlpacaPaperAccountAssetObservationError, match=message):
        decode_asset(payload)


@pytest.mark.parametrize(
    "field_name",
    ("name", "maintenance_margin_requirement", "attributes"),
)
@pytest.mark.parametrize("representation", ("absent", "null"))
def test_asset_sdk_optional_fields_accept_absent_or_null(
    field_name: str,
    representation: str,
) -> None:
    payload = asset_payload()
    if representation == "absent":
        del payload[field_name]
    else:
        payload[field_name] = None

    observation = decode_asset(payload)

    assert observation.outcome is AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
    if field_name == "name":
        assert observation.name is None
    elif field_name == "maintenance_margin_requirement":
        assert observation.maintenance_margin_requirement is None
    else:
        assert observation.attributes == ()


def test_asset_increment_fields_are_validated_but_remain_raw_only() -> None:
    payload = asset_payload()
    payload.update(
        {
            "min_order_size": 1,
            "min_trade_increment": 0.0001,
            "price_increment": None,
        }
    )

    observation = decode_asset(payload)

    assert observation.outcome is AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE
    assert observation.validated_raw_only_numeric_fields == (
        "min_order_size",
        "min_trade_increment",
        "price_increment",
    )
    assert not hasattr(observation, "min_order_size")
    assert not hasattr(observation, "min_trade_increment")
    assert not hasattr(observation, "price_increment")

    for field_name, invalid in (
        ("min_order_size", -1),
        ("min_trade_increment", "0.0001"),
        ("price_increment", True),
    ):
        drifted = payload.copy()
        drifted[field_name] = invalid
        with pytest.raises(AlpacaPaperAccountAssetObservationError):
            decode_asset(drifted)


@pytest.mark.parametrize("mutator", ("missing", "unknown", "environment"))
def test_asset_profile_rejects_missing_unknown_and_response_environment(
    mutator: str,
) -> None:
    payload = asset_payload()
    if mutator == "missing":
        del payload["exchange"]
    elif mutator == "unknown":
        payload["new_provider_field"] = "drift"
    else:
        payload["environment"] = "paper"

    with pytest.raises(
        AlpacaPaperAccountAssetObservationError,
        match="reviewed wire profile",
    ):
        decode_asset(payload)


def test_asset_decoder_rejects_duplicate_keys_non_utf8_and_unsupported_status() -> None:
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="duplicate JSON key"):
        decode_asset(response_body=b'{"id":"a","id":"b"}')
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="UTF-8"):
        decode_asset(response_body=b"\xff")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="not-visible"):
        decode_alpaca_asset_observation_response(
            asset_description(),
            http_status=500,
            provider_request_id="asset-request-0001",
            response_body=json_bytes(asset_payload()),
            received_at=RECEIVED_AT,
        )


def test_asset_observation_cannot_be_tampered_or_mutated() -> None:
    observation = decode_asset()

    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="exact response bytes"):
        replace(observation, symbol="QQQ")
    with pytest.raises(AlpacaPaperAccountAssetObservationError, match="exact response bytes"):
        replace(observation, fractionable=False)
    with pytest.raises(FrozenInstanceError):
        observation.exchange = AlpacaAssetExchange.NASDAQ  # type: ignore[misc]


def test_asset_evidence_never_grants_authority_or_runtime_readiness() -> None:
    observation = decode_asset()

    assert observation.runtime_current is False
    assert observation.authenticated_provider_evidence is False
    assert observation.durable_security_identity_binding_authorized is False
    assert observation.security_mapping_ready is False
    assert observation.asset_tradability_validation_ready is False
    assert observation.fractional_quantity_authorized is False
    assert observation.short_exposure_authorized is False
    assert observation.dispatch_preflight_ready is False
    assert observation.trading_effect_authorized is False
