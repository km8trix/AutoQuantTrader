"""Strict, offline Alpaca paper account and asset observations.

The descriptions in this module are deterministic request evidence only.  The
decoders accept deliberately narrow, reviewed wire profiles and retain the
exact response bytes, but they do not perform I/O, authenticate evidence,
establish provider identity, qualify freshness, or authorize trading.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from packages.adapters.broker.alpaca_paper import (
    ALPACA_ACCOUNT_PATH,
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_CANDIDATE_INSTRUMENTS,
    ALPACA_PAPER_CAPABILITIES,
    ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
    ALPACA_PAPER_TRADING_BASE_URL,
    AlpacaPaperContractError,
)
from packages.domain.canonical import canonical_decimal, canonical_json_bytes
from packages.domain.models import require_utc

ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION = (
    "phase4e-alpaca-paper-account-asset-observation-v1"
)
ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON = "2026-07-27"
ALPACA_PAPER_ASSET_PATH_TEMPLATE = "/v2/assets/{symbol_or_asset_id}"
ALPACA_PAPER_MAX_ACCOUNT_ASSET_RESPONSE_BYTES = 262_144
ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION = "unqualified_offline_bytes"
ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT = "bd1fa9ea2fc3194914be9d47f7f5822a18a05b5f"

_ALPACA_ACCOUNT_REQUIRED_RESPONSE_KEYS = frozenset(
    {
        "account_number",
        "id",
        "status",
    }
)
_ALPACA_ACCOUNT_OPTIONAL_RESPONSE_KEYS = frozenset(
    {
        "account_blocked",
        "accrued_fees",
        "buying_power",
        "cash",
        "created_at",
        "crypto_status",
        "currency",
        "daytrade_count",
        "daytrading_buying_power",
        "equity",
        "initial_margin",
        "last_equity",
        "last_maintenance_margin",
        "long_market_value",
        "maintenance_margin",
        "multiplier",
        "non_marginable_buying_power",
        "options_approved_level",
        "options_buying_power",
        "options_trading_level",
        "pattern_day_trader",
        "pending_transfer_in",
        "pending_transfer_out",
        "portfolio_value",
        "regt_buying_power",
        "shorting_enabled",
        "short_market_value",
        "sma",
        "trade_suspended_by_user",
        "trading_blocked",
        "transfers_blocked",
    }
)
_ALPACA_ACCOUNT_RESPONSE_KEYS = (
    _ALPACA_ACCOUNT_REQUIRED_RESPONSE_KEYS | _ALPACA_ACCOUNT_OPTIONAL_RESPONSE_KEYS
)
_ALPACA_ACCOUNT_NONCANONICAL_ECONOMIC_FIELDS = (
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
_ALPACA_ASSET_REQUIRED_RESPONSE_KEYS = frozenset(
    {
        "class",
        "easy_to_borrow",
        "exchange",
        "fractionable",
        "id",
        "marginable",
        "shortable",
        "status",
        "symbol",
        "tradable",
    }
)
_ALPACA_ASSET_OPTIONAL_RESPONSE_KEYS = frozenset(
    {
        "attributes",
        "maintenance_margin_requirement",
        "min_order_size",
        "min_trade_increment",
        "name",
        "price_increment",
    }
)
_ALPACA_ASSET_RESPONSE_KEYS = (
    _ALPACA_ASSET_REQUIRED_RESPONSE_KEYS | _ALPACA_ASSET_OPTIONAL_RESPONSE_KEYS
)
_ALPACA_ASSET_RAW_ONLY_NUMERIC_FIELDS = (
    "min_order_size",
    "min_trade_increment",
    "price_increment",
)
_ALPACA_NOT_FOUND_RESPONSE_KEYS = frozenset({"code", "message"})
_ALPACA_PAPER_MAX_ERROR_CODE = 2_147_483_647
_ACCOUNT_FAILURE_NAMES = frozenset(
    {
        "account_blocked",
        "account_status",
        "currency",
        "trade_suspended_by_user",
        "trading_blocked",
        "transfers_blocked",
    }
)
_ASSET_FAILURE_NAMES = frozenset(
    {"asset_class", "asset_status", "attributes", "exchange", "symbol", "tradable"}
)
_DECIMAL_TEXT_PATTERN = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?")
_CURRENCY_PATTERN = re.compile(r"[A-Z]{3}")
_SYMBOL_PATTERN = re.compile(r"[A-Z][A-Z0-9./-]{0,31}")
_TIMESTAMP_PATTERN = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})"
)


class AlpacaPaperAccountAssetObservationError(AlpacaPaperContractError):
    """An account/asset description or retained response violated the contract."""


class AlpacaAccountStatus(StrEnum):
    """Account states pinned to the reviewed alpaca-py revision."""

    ACCOUNT_CLOSED = "ACCOUNT_CLOSED"
    ACCOUNT_UPDATED = "ACCOUNT_UPDATED"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    ACTIVE = "ACTIVE"
    AML_REVIEW = "AML_REVIEW"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    DISABLED = "DISABLED"
    DISABLE_PENDING = "DISABLE_PENDING"
    EDITED = "EDITED"
    INACTIVE = "INACTIVE"
    KYC_SUBMITTED = "KYC_SUBMITTED"
    LIMITED = "LIMITED"
    ONBOARDING = "ONBOARDING"
    PAPER_ONLY = "PAPER_ONLY"
    REAPPROVAL_PENDING = "REAPPROVAL_PENDING"
    REJECTED = "REJECTED"
    RESUBMITTED = "RESUBMITTED"
    SIGNED_UP = "SIGNED_UP"
    SUBMISSION_FAILED = "SUBMISSION_FAILED"
    SUBMITTED = "SUBMITTED"


class AlpacaAssetClass(StrEnum):
    """Asset classes pinned to the reviewed alpaca-py revision."""

    US_EQUITY = "us_equity"
    US_OPTION = "us_option"
    CRYPTO = "crypto"
    CRYPTO_PERP = "crypto_perp"


class AlpacaAssetStatus(StrEnum):
    """Reviewed asset states used by the narrow local wire profile."""

    ACTIVE = "active"
    INACTIVE = "inactive"


class AlpacaAssetExchange(StrEnum):
    """Asset exchanges pinned to the reviewed alpaca-py revision."""

    AMEX = "AMEX"
    ARCA = "ARCA"
    ASCX = "ASCX"
    BATS = "BATS"
    NYSE = "NYSE"
    NASDAQ = "NASDAQ"
    NYSEARCA = "NYSEARCA"
    FTXU = "FTXU"
    CBSE = "CBSE"
    GNSS = "GNSS"
    ERSX = "ERSX"
    OTC = "OTC"
    CRYPTO = "CRYPTO"
    EMPTY = ""


class AlpacaAssetAttribute(StrEnum):
    """Asset attributes supported by the pinned SDK model."""

    PTP_NO_EXCEPTION = "ptp_no_exception"
    PTP_WITH_EXCEPTION = "ptp_with_exception"


ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES = (
    AlpacaAssetExchange.AMEX,
    AlpacaAssetExchange.ARCA,
    AlpacaAssetExchange.BATS,
    AlpacaAssetExchange.NYSE,
    AlpacaAssetExchange.NASDAQ,
    AlpacaAssetExchange.NYSEARCA,
)


class AlpacaAccountObservationOutcome(StrEnum):
    """Conservative meaning of one decoded account response."""

    OBSERVED_USABLE_CANDIDATE = "observed_usable_candidate"
    BLOCKED = "blocked"
    INACTIVE = "inactive"
    CURRENCY_MISMATCH = "currency_mismatch"
    INCOMPLETE = "incomplete"


class AlpacaAssetObservationOutcome(StrEnum):
    """Conservative meaning of one decoded asset response."""

    OBSERVED_USABLE_CANDIDATE = "observed_usable_candidate"
    IDENTITY_MISMATCH = "identity_mismatch"
    ASSET_CLASS_MISMATCH = "asset_class_mismatch"
    EXCHANGE_INELIGIBLE = "exchange_ineligible"
    INACTIVE = "inactive"
    NOT_TRADABLE = "not_tradable"
    ATTRIBUTE_REVIEW_REQUIRED = "attribute_review_required"
    NOT_VISIBLE_INCONCLUSIVE = "not_visible_inconclusive"


def _require_text(
    value: object,
    field_name: str,
    *,
    maximum_length: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str:
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be an exact string")
    if (
        len(value) > maximum_length
        or (not allow_empty and not value)
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be bounded, trimmed text without control characters"
        )
    return value


def _require_uuid(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum_length=36)
    try:
        parsed = UUID(raw)
    except (TypeError, ValueError, AttributeError) as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be a canonical UUID"
        ) from error
    if str(parsed) != raw:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be a canonical lowercase UUID"
        )
    return raw


def _require_exact_boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be an exact boolean")
    return value


def _require_optional_boolean(value: object, field_name: str) -> bool | None:
    if value is None:
        return None
    return _require_exact_boolean(value, field_name)


def _require_optional_text(
    value: object,
    field_name: str,
    *,
    maximum_length: int,
    allow_empty: bool = False,
) -> str | None:
    if value is None:
        return None
    return _require_text(
        value,
        field_name,
        maximum_length=maximum_length,
        allow_empty=allow_empty,
    )


def _require_timestamp_text(value: object, field_name: str) -> str:
    raw = _require_text(value, field_name, maximum_length=40)
    matched = _TIMESTAMP_PATTERN.fullmatch(raw)
    if matched is None:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be an exact ISO-8601 timestamp with at most 9 fractional digits"
        )
    zone = matched.group("zone")
    if zone == "-00:00":
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must not use the RFC 3339 unknown-offset marker"
        )
    seconds = f"{matched.group('date')}T{matched.group('time')}"
    seconds += "+00:00" if zone == "Z" else zone
    try:
        parsed = datetime.fromisoformat(seconds)
    except ValueError as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} is not a valid instant"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must include an offset")
    return raw


def _require_optional_timestamp_text(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_timestamp_text(value, field_name)


def _require_decimal_text(value: object, field_name: str) -> None:
    raw = _require_text(value, field_name, maximum_length=64)
    if _DECIMAL_TEXT_PATTERN.fullmatch(raw) is None:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be a bounded plain decimal string"
        )
    integer = raw.removeprefix("-").partition(".")[0]
    if len(integer) > 18:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} exceeds the reviewed decimal bound"
        )
    try:
        parsed = Decimal(raw)
    except InvalidOperation as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be a finite decimal"
        ) from error
    if not parsed.is_finite():
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be a finite decimal")


def _require_optional_decimal_text(value: object, field_name: str) -> None:
    if value is not None:
        _require_decimal_text(value, field_name)


def _require_nonnegative_json_number(
    value: object,
    field_name: str,
    *,
    maximum: Decimal | None = None,
) -> Decimal:
    if type(value) is int:
        parsed = Decimal(value)
    elif type(value) is Decimal:
        parsed = value
    else:
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be an exact JSON number")
    try:
        result = canonical_decimal(parsed)
    except (InvalidOperation, ValueError) as error:
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be finite") from error
    _, digits, exponent = result.as_tuple()
    adjusted_exponent = len(digits) + int(exponent) - 1
    if (
        result < 0
        or (maximum is not None and result > maximum)
        or len(digits) > 18
        or int(exponent) < -18
        or adjusted_exponent > 18
    ):
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} is outside the reviewed non-negative bound"
        )
    return result


def _require_optional_nonnegative_json_number(
    value: object,
    field_name: str,
    *,
    maximum: Decimal | None = None,
) -> Decimal | None:
    if value is None:
        return None
    return _require_nonnegative_json_number(value, field_name, maximum=maximum)


def _require_optional_level(value: object, field_name: str) -> None:
    if value is not None and (type(value) is not int or not 0 <= value <= 3):
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} must be an exact integer from 0 through 3 or null"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AlpacaPaperAccountAssetObservationError(
                f"Alpaca account/asset response contains duplicate JSON key {key!r}"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise AlpacaPaperAccountAssetObservationError(
        f"Alpaca account/asset response contains non-standard JSON constant {value!r}"
    )


def _decode_response_object(response_body: bytes) -> dict[str, Any]:
    if type(response_body) is not bytes:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account/asset response must be exact bytes"
        )
    if not 1 <= len(response_body) <= ALPACA_PAPER_MAX_ACCOUNT_ASSET_RESPONSE_BYTES:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account/asset response size is outside the bound"
        )
    try:
        text = response_body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account/asset response must be UTF-8"
        ) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=Decimal,
            parse_constant=_reject_json_constant,
        )
    except AlpacaPaperAccountAssetObservationError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account/asset response is invalid JSON"
        ) from error
    if type(value) is not dict:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account/asset response must be one JSON object"
        )
    return cast(dict[str, Any], value)


def _require_exact_keys(
    value: Mapping[str, Any],
    expected_keys: frozenset[str],
    field_name: str,
) -> None:
    actual = frozenset(value)
    if actual != expected_keys:
        missing = tuple(sorted(expected_keys - actual))
        extra = tuple(sorted(actual - expected_keys))
        raise AlpacaPaperAccountAssetObservationError(
            f"{field_name} is outside the reviewed wire profile; "
            f"missing={missing!r}, extra={extra!r}"
        )


def _require_account_response_keys(value: Mapping[str, Any]) -> None:
    actual = frozenset(value)
    missing = tuple(sorted(_ALPACA_ACCOUNT_REQUIRED_RESPONSE_KEYS - actual))
    extra = tuple(sorted(actual - _ALPACA_ACCOUNT_RESPONSE_KEYS))
    if missing or extra:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account response is outside the reviewed wire profile; "
            f"missing={missing!r}, extra={extra!r}"
        )


def _require_asset_response_keys(value: Mapping[str, Any]) -> None:
    actual = frozenset(value)
    missing = tuple(sorted(_ALPACA_ASSET_REQUIRED_RESPONSE_KEYS - actual))
    extra = tuple(sorted(actual - _ALPACA_ASSET_RESPONSE_KEYS))
    if missing or extra:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca asset response is outside the reviewed wire profile; "
            f"missing={missing!r}, extra={extra!r}"
        )


def _require_received_at(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be an exact datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAccountAssetObservationError(str(error)) from error
    return value


def _require_closed_failures(
    value: object,
    *,
    field_name: str,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    if (
        type(value) is not tuple
        or any(type(item) is not str for item in value)
        or len(frozenset(value)) != len(value)
        or not frozenset(value) <= allowed
    ):
        raise AlpacaPaperAccountAssetObservationError(f"{field_name} must be a unique closed tuple")
    return cast(tuple[str, ...], value)


@dataclass(frozen=True, slots=True)
class AlpacaPaperAccountObservationDescription:
    """A deterministic, non-I/O ``GET /v2/account`` description."""

    account_id: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "account observation account ID", maximum_length=64)
        ALPACA_PAPER_CAPABILITIES.__post_init__()

    @property
    def contract_version(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION

    @property
    def reviewed_on(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON

    @property
    def provider_model_commit(self) -> str:
        return ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT

    @property
    def adapter_id(self) -> str:
        return ALPACA_PAPER_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        return ALPACA_PAPER_ADAPTER_VERSION

    @property
    def capability_sha256(self) -> str:
        return ALPACA_PAPER_CAPABILITIES.semantic_sha256

    @property
    def environment(self) -> str:
        return "paper"

    @property
    def candidate_instrument_symbols(self) -> tuple[tuple[str, str], ...]:
        return ALPACA_PAPER_CANDIDATE_INSTRUMENTS

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_ACCOUNT_PATH

    @property
    def query(self) -> Mapping[str, str]:
        return MappingProxyType({})

    @property
    def request_target(self) -> str:
        return self.path

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    self.contract_version,
                    self.reviewed_on,
                    self.provider_model_commit,
                    ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
                    "account_observation_description",
                    self.adapter_id,
                    self.adapter_version,
                    self.capability_sha256,
                    self.environment,
                    self.account_id,
                    self.candidate_instrument_symbols,
                    self.method,
                    self.base_url,
                    self.path,
                    tuple(self.query.items()),
                )
            )
        ).hexdigest()

    @property
    def credential_resolution_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def runtime_request_ready(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class AlpacaPaperAssetObservationDescription:
    """A deterministic, candidate-bound, non-I/O asset GET description."""

    account_id: str
    instrument_id: str
    symbol: str

    def __post_init__(self) -> None:
        _require_text(self.account_id, "asset observation account ID", maximum_length=64)
        _require_text(self.instrument_id, "asset observation instrument ID", maximum_length=64)
        symbol = _require_text(
            self.symbol,
            "asset observation symbol",
            maximum_length=32,
        )
        if _SYMBOL_PATTERN.fullmatch(symbol) is None:
            raise AlpacaPaperAccountAssetObservationError(
                "asset observation symbol is not canonical"
            )
        expected_symbol = dict(ALPACA_PAPER_CANDIDATE_INSTRUMENTS).get(self.instrument_id)
        if expected_symbol is None or symbol != expected_symbol:
            raise AlpacaPaperAccountAssetObservationError(
                "asset observation identity must match the exact fixed candidate map"
            )
        ALPACA_PAPER_CAPABILITIES.__post_init__()

    @property
    def contract_version(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION

    @property
    def reviewed_on(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON

    @property
    def provider_model_commit(self) -> str:
        return ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT

    @property
    def adapter_id(self) -> str:
        return ALPACA_PAPER_ADAPTER_ID

    @property
    def adapter_version(self) -> str:
        return ALPACA_PAPER_ADAPTER_VERSION

    @property
    def capability_sha256(self) -> str:
        return ALPACA_PAPER_CAPABILITIES.semantic_sha256

    @property
    def environment(self) -> str:
        return "paper"

    @property
    def candidate_instrument_symbols(self) -> tuple[tuple[str, str], ...]:
        return ALPACA_PAPER_CANDIDATE_INSTRUMENTS

    @property
    def method(self) -> str:
        return "GET"

    @property
    def base_url(self) -> str:
        return ALPACA_PAPER_TRADING_BASE_URL

    @property
    def path(self) -> str:
        return ALPACA_PAPER_ASSET_PATH_TEMPLATE.format(symbol_or_asset_id=self.symbol)

    @property
    def query(self) -> Mapping[str, str]:
        return MappingProxyType({})

    @property
    def request_target(self) -> str:
        return self.path

    @property
    def url(self) -> str:
        return f"{self.base_url}{self.path}"

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    self.contract_version,
                    self.reviewed_on,
                    self.provider_model_commit,
                    ALPACA_PAPER_CAPABILITY_CONTRACT_VERSION,
                    "asset_observation_description",
                    self.adapter_id,
                    self.adapter_version,
                    self.capability_sha256,
                    self.environment,
                    self.account_id,
                    self.candidate_instrument_symbols,
                    self.instrument_id,
                    self.symbol,
                    self.method,
                    self.base_url,
                    self.path,
                    tuple(self.query.items()),
                )
            )
        ).hexdigest()

    @property
    def credential_resolution_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def runtime_request_ready(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def create_alpaca_account_observation_description(
    *,
    account_id: str,
) -> AlpacaPaperAccountObservationDescription:
    """Describe an account observation request without acquiring I/O authority."""

    return AlpacaPaperAccountObservationDescription(account_id=account_id)


def create_alpaca_asset_observation_description(
    *,
    account_id: str,
    instrument_id: str,
    symbol: str,
) -> AlpacaPaperAssetObservationDescription:
    """Describe one fixed-candidate asset request without acquiring I/O authority."""

    return AlpacaPaperAssetObservationDescription(
        account_id=account_id,
        instrument_id=instrument_id,
        symbol=symbol,
    )


@dataclass(frozen=True, slots=True)
class _DecodedAccount:
    provider_account_id: str
    status: AlpacaAccountStatus
    currency: str | None
    account_blocked: bool | None
    trading_blocked: bool | None
    transfers_blocked: bool | None
    trade_suspended_by_user: bool | None
    shorting_enabled: bool | None
    pattern_day_trader: bool | None
    created_at: str | None


def _decode_account_wire(value: Mapping[str, Any]) -> _DecodedAccount:
    _require_account_response_keys(value)
    raw_status = _require_text(value["status"], "Alpaca account status", maximum_length=32)
    try:
        status = AlpacaAccountStatus(raw_status)
    except ValueError as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"unsupported Alpaca account status: {raw_status!r}"
        ) from error
    currency = _require_optional_text(
        value.get("currency"),
        "Alpaca account currency",
        maximum_length=3,
    )
    if currency is not None and _CURRENCY_PATTERN.fullmatch(currency) is None:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca account currency must be an exact uppercase ISO-style code"
        )
    _require_text(value["account_number"], "Alpaca account number", maximum_length=64)
    for field_name in _ALPACA_ACCOUNT_NONCANONICAL_ECONOMIC_FIELDS:
        if field_name in value:
            _require_optional_decimal_text(
                value[field_name],
                f"Alpaca account {field_name}",
            )
    if "crypto_status" in value and value["crypto_status"] is not None:
        raw_crypto_status = _require_text(
            value["crypto_status"],
            "Alpaca crypto account status",
            maximum_length=32,
        )
        try:
            AlpacaAccountStatus(raw_crypto_status)
        except ValueError as error:
            raise AlpacaPaperAccountAssetObservationError(
                f"unsupported Alpaca crypto account status: {raw_crypto_status!r}"
            ) from error
    if "daytrade_count" in value and value["daytrade_count"] is not None:
        daytrade_count = value["daytrade_count"]
        if type(daytrade_count) is not int or not 0 <= daytrade_count <= 1_000_000:
            raise AlpacaPaperAccountAssetObservationError(
                "Alpaca retired daytrade_count must be a bounded non-negative integer or null"
            )
    _require_optional_level(
        value.get("options_approved_level"),
        "Alpaca options_approved_level",
    )
    _require_optional_level(
        value.get("options_trading_level"),
        "Alpaca options_trading_level",
    )
    return _DecodedAccount(
        provider_account_id=_require_uuid(value["id"], "Alpaca provider account ID"),
        status=status,
        currency=currency,
        account_blocked=_require_optional_boolean(
            value.get("account_blocked"),
            "Alpaca account_blocked",
        ),
        trading_blocked=_require_optional_boolean(
            value.get("trading_blocked"),
            "Alpaca trading_blocked",
        ),
        transfers_blocked=_require_optional_boolean(
            value.get("transfers_blocked"),
            "Alpaca transfers_blocked",
        ),
        trade_suspended_by_user=_require_optional_boolean(
            value.get("trade_suspended_by_user"),
            "Alpaca trade_suspended_by_user",
        ),
        shorting_enabled=_require_optional_boolean(
            value.get("shorting_enabled"),
            "Alpaca shorting_enabled",
        ),
        pattern_day_trader=_require_optional_boolean(
            value.get("pattern_day_trader"),
            "Alpaca retired pattern_day_trader",
        ),
        created_at=_require_optional_timestamp_text(
            value.get("created_at"),
            "Alpaca account created_at",
        ),
    )


def _account_failures(account: _DecodedAccount) -> tuple[str, ...]:
    failures: list[str] = []
    if account.currency != "USD":
        failures.append("currency")
    if account.status is not AlpacaAccountStatus.ACTIVE:
        failures.append("account_status")
    for field_name in (
        "account_blocked",
        "trading_blocked",
        "transfers_blocked",
        "trade_suspended_by_user",
    ):
        if getattr(account, field_name) is not False:
            failures.append(field_name)
    return tuple(failures)


def _account_outcome(
    account: _DecodedAccount,
    failures: tuple[str, ...],
) -> AlpacaAccountObservationOutcome:
    if account.currency is not None and account.currency != "USD":
        return AlpacaAccountObservationOutcome.CURRENCY_MISMATCH
    if account.status is not AlpacaAccountStatus.ACTIVE:
        return AlpacaAccountObservationOutcome.INACTIVE
    blockers = (
        account.account_blocked,
        account.trading_blocked,
        account.transfers_blocked,
        account.trade_suspended_by_user,
    )
    if any(blocker is True for blocker in blockers):
        return AlpacaAccountObservationOutcome.BLOCKED
    if account.currency is None or any(blocker is None for blocker in blockers):
        return AlpacaAccountObservationOutcome.INCOMPLETE
    return AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE


@dataclass(frozen=True, slots=True)
class AlpacaAccountObservation:
    """Exact retained account bytes plus a non-authorizing qualification."""

    description: AlpacaPaperAccountObservationDescription
    outcome: AlpacaAccountObservationOutcome
    http_status: int
    provider_request_id: str
    received_at: datetime
    response_body: bytes = field(repr=False)
    provider_account_id: str
    status: AlpacaAccountStatus
    currency: str | None
    account_blocked: bool | None
    trading_blocked: bool | None
    transfers_blocked: bool | None
    trade_suspended_by_user: bool | None
    shorting_enabled: bool | None
    pattern_day_trader: bool | None
    created_at: str | None
    qualification_failures: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperAccountObservationDescription:
            raise AlpacaPaperAccountAssetObservationError(
                "account observation requires an exact account description"
            )
        self.description.__post_init__()
        if type(self.outcome) is not AlpacaAccountObservationOutcome:
            raise AlpacaPaperAccountAssetObservationError(
                "account observation outcome is unsupported"
            )
        if type(self.http_status) is not int or self.http_status != 200:
            raise AlpacaPaperAccountAssetObservationError(
                "account observation supports only HTTP 200"
            )
        _require_text(
            self.provider_request_id,
            "Alpaca X-Request-ID",
            maximum_length=256,
        )
        _require_received_at(self.received_at, "account observation received_at")
        _require_closed_failures(
            self.qualification_failures,
            field_name="account qualification failures",
            allowed=_ACCOUNT_FAILURE_NAMES,
        )
        decoded = _decode_account_wire(_decode_response_object(self.response_body))
        expected_failures = _account_failures(decoded)
        expected_outcome = _account_outcome(decoded, expected_failures)
        expected_values = (
            ("provider_account_id", decoded.provider_account_id),
            ("status", decoded.status),
            ("currency", decoded.currency),
            ("account_blocked", decoded.account_blocked),
            ("trading_blocked", decoded.trading_blocked),
            ("transfers_blocked", decoded.transfers_blocked),
            ("trade_suspended_by_user", decoded.trade_suspended_by_user),
            ("shorting_enabled", decoded.shorting_enabled),
            ("pattern_day_trader", decoded.pattern_day_trader),
            ("created_at", decoded.created_at),
            ("qualification_failures", expected_failures),
            ("outcome", expected_outcome),
        )
        for field_name, expected in expected_values:
            actual = getattr(self, field_name)
            if type(actual) is not type(expected) or actual != expected:
                raise AlpacaPaperAccountAssetObservationError(
                    f"account observation {field_name} does not match exact response bytes"
                )

    @property
    def environment(self) -> str:
        return self.description.environment

    @property
    def evidence_qualification(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def response_size_bytes(self) -> int:
        return len(self.response_body)

    @property
    def validated_noncanonical_economic_fields(self) -> tuple[str, ...]:
        decoded = _decode_response_object(self.response_body)
        return tuple(
            field_name
            for field_name in _ALPACA_ACCOUNT_NONCANONICAL_ECONOMIC_FIELDS
            if field_name in decoded
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION,
                    "account_observation",
                    self.description.semantic_sha256,
                    self.outcome,
                    self.http_status,
                    self.provider_request_id,
                    self.received_at,
                    self.response_size_bytes,
                    self.response_sha256,
                    self.provider_account_id,
                    self.status,
                    self.currency,
                    self.account_blocked,
                    self.trading_blocked,
                    self.transfers_blocked,
                    self.trade_suspended_by_user,
                    self.shorting_enabled,
                    self.pattern_day_trader,
                    self.created_at,
                    self.qualification_failures,
                    self.validated_noncanonical_economic_fields,
                )
            )
        ).hexdigest()

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def economics_canonicalized(self) -> bool:
        return False

    @property
    def durable_account_binding_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def decode_alpaca_account_observation_response(
    description: AlpacaPaperAccountObservationDescription,
    *,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
) -> AlpacaAccountObservation:
    """Decode retained account bytes without qualifying identity or freshness."""

    if type(description) is not AlpacaPaperAccountObservationDescription:
        raise AlpacaPaperAccountAssetObservationError(
            "account decoding requires an exact account description"
        )
    if type(http_status) is not int or http_status != 200:
        raise AlpacaPaperAccountAssetObservationError(
            "account decoding supports only successful responses"
        )
    decoded = _decode_account_wire(_decode_response_object(response_body))
    failures = _account_failures(decoded)
    return AlpacaAccountObservation(
        description=description,
        outcome=_account_outcome(decoded, failures),
        http_status=http_status,
        provider_request_id=provider_request_id,
        received_at=received_at,
        response_body=response_body,
        provider_account_id=decoded.provider_account_id,
        status=decoded.status,
        currency=decoded.currency,
        account_blocked=decoded.account_blocked,
        trading_blocked=decoded.trading_blocked,
        transfers_blocked=decoded.transfers_blocked,
        trade_suspended_by_user=decoded.trade_suspended_by_user,
        shorting_enabled=decoded.shorting_enabled,
        pattern_day_trader=decoded.pattern_day_trader,
        created_at=decoded.created_at,
        qualification_failures=failures,
    )


@dataclass(frozen=True, slots=True)
class _DecodedAsset:
    provider_asset_id: str
    asset_class: AlpacaAssetClass
    exchange: AlpacaAssetExchange
    symbol: str
    name: str | None
    status: AlpacaAssetStatus
    tradable: bool
    marginable: bool
    maintenance_margin_requirement: Decimal | None
    shortable: bool
    easy_to_borrow: bool
    fractionable: bool
    attributes: tuple[AlpacaAssetAttribute, ...]


def _require_attributes(value: object) -> tuple[AlpacaAssetAttribute, ...]:
    if value is None:
        return ()
    if type(value) is not list or len(value) > len(AlpacaAssetAttribute):
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca asset attributes must be a bounded array"
        )
    result: list[AlpacaAssetAttribute] = []
    for item in value:
        raw = _require_text(item, "Alpaca asset attribute", maximum_length=64)
        try:
            result.append(AlpacaAssetAttribute(raw))
        except ValueError as error:
            raise AlpacaPaperAccountAssetObservationError(
                f"unsupported Alpaca asset attribute: {raw!r}"
            ) from error
    if len(frozenset(result)) != len(result):
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca asset attributes must not contain duplicates"
        )
    return tuple(result)


def _decode_asset_wire(value: Mapping[str, Any]) -> _DecodedAsset:
    _require_asset_response_keys(value)
    raw_asset_class = _require_text(
        value["class"],
        "Alpaca asset class",
        maximum_length=32,
    )
    try:
        asset_class = AlpacaAssetClass(raw_asset_class)
    except ValueError as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"unsupported Alpaca asset class: {raw_asset_class!r}"
        ) from error
    raw_exchange = _require_text(
        value["exchange"],
        "Alpaca asset exchange",
        maximum_length=16,
        allow_empty=True,
    )
    try:
        exchange = AlpacaAssetExchange(raw_exchange)
    except ValueError as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"unsupported Alpaca asset exchange: {raw_exchange!r}"
        ) from error
    symbol = _require_text(value["symbol"], "Alpaca asset symbol", maximum_length=32)
    if _SYMBOL_PATTERN.fullmatch(symbol) is None:
        raise AlpacaPaperAccountAssetObservationError("Alpaca asset symbol must be canonical")
    raw_status = _require_text(value["status"], "Alpaca asset status", maximum_length=16)
    try:
        status = AlpacaAssetStatus(raw_status)
    except ValueError as error:
        raise AlpacaPaperAccountAssetObservationError(
            f"unsupported Alpaca asset status: {raw_status!r}"
        ) from error
    for field_name in _ALPACA_ASSET_RAW_ONLY_NUMERIC_FIELDS:
        if field_name in value:
            _require_optional_nonnegative_json_number(
                value[field_name],
                f"Alpaca asset {field_name}",
            )
    return _DecodedAsset(
        provider_asset_id=_require_uuid(value["id"], "Alpaca provider asset ID"),
        asset_class=asset_class,
        exchange=exchange,
        symbol=symbol,
        name=_require_optional_text(
            value.get("name"),
            "Alpaca asset name",
            maximum_length=256,
        ),
        status=status,
        tradable=_require_exact_boolean(value["tradable"], "Alpaca asset tradable"),
        marginable=_require_exact_boolean(value["marginable"], "Alpaca asset marginable"),
        maintenance_margin_requirement=_require_optional_nonnegative_json_number(
            value.get("maintenance_margin_requirement"),
            "Alpaca maintenance_margin_requirement",
            maximum=Decimal(10_000),
        ),
        shortable=_require_exact_boolean(value["shortable"], "Alpaca asset shortable"),
        easy_to_borrow=_require_exact_boolean(
            value["easy_to_borrow"], "Alpaca asset easy_to_borrow"
        ),
        fractionable=_require_exact_boolean(value["fractionable"], "Alpaca asset fractionable"),
        attributes=_require_attributes(value.get("attributes")),
    )


def _asset_failures(
    description: AlpacaPaperAssetObservationDescription,
    asset: _DecodedAsset,
) -> tuple[str, ...]:
    failures: list[str] = []
    if asset.symbol != description.symbol:
        failures.append("symbol")
    if asset.asset_class is not AlpacaAssetClass.US_EQUITY:
        failures.append("asset_class")
    if asset.exchange not in ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES:
        failures.append("exchange")
    if asset.status is not AlpacaAssetStatus.ACTIVE:
        failures.append("asset_status")
    if not asset.tradable:
        failures.append("tradable")
    if asset.attributes:
        failures.append("attributes")
    return tuple(failures)


def _asset_outcome(
    failures: tuple[str, ...],
) -> AlpacaAssetObservationOutcome:
    if "symbol" in failures:
        return AlpacaAssetObservationOutcome.IDENTITY_MISMATCH
    if "asset_class" in failures:
        return AlpacaAssetObservationOutcome.ASSET_CLASS_MISMATCH
    if "exchange" in failures:
        return AlpacaAssetObservationOutcome.EXCHANGE_INELIGIBLE
    if "asset_status" in failures:
        return AlpacaAssetObservationOutcome.INACTIVE
    if "tradable" in failures:
        return AlpacaAssetObservationOutcome.NOT_TRADABLE
    if "attributes" in failures:
        return AlpacaAssetObservationOutcome.ATTRIBUTE_REVIEW_REQUIRED
    return AlpacaAssetObservationOutcome.OBSERVED_USABLE_CANDIDATE


def _not_found_details(value: Mapping[str, Any]) -> tuple[int, str]:
    _require_exact_keys(
        value,
        _ALPACA_NOT_FOUND_RESPONSE_KEYS,
        "Alpaca asset not-found response",
    )
    code = value["code"]
    if type(code) is not int or not 1 <= code <= _ALPACA_PAPER_MAX_ERROR_CODE:
        raise AlpacaPaperAccountAssetObservationError(
            "Alpaca asset not-found code must be a bounded positive integer"
        )
    message = _require_text(
        value["message"],
        "Alpaca asset not-found message",
        maximum_length=512,
    )
    return code, message


@dataclass(frozen=True, slots=True)
class AlpacaAssetObservation:
    """Exact retained asset bytes plus a conservative candidate classification."""

    description: AlpacaPaperAssetObservationDescription
    outcome: AlpacaAssetObservationOutcome
    http_status: int
    provider_request_id: str
    received_at: datetime
    response_body: bytes = field(repr=False)
    provider_asset_id: str | None = None
    asset_class: AlpacaAssetClass | None = None
    exchange: AlpacaAssetExchange | None = None
    symbol: str | None = None
    name: str | None = None
    status: AlpacaAssetStatus | None = None
    tradable: bool | None = None
    marginable: bool | None = None
    maintenance_margin_requirement: Decimal | None = None
    shortable: bool | None = None
    easy_to_borrow: bool | None = None
    fractionable: bool | None = None
    attributes: tuple[AlpacaAssetAttribute, ...] = ()
    qualification_failures: tuple[str, ...] = ()
    not_found_code: int | None = None
    not_found_message: str | None = None

    def __post_init__(self) -> None:
        if type(self.description) is not AlpacaPaperAssetObservationDescription:
            raise AlpacaPaperAccountAssetObservationError(
                "asset observation requires an exact asset description"
            )
        self.description.__post_init__()
        if type(self.outcome) is not AlpacaAssetObservationOutcome:
            raise AlpacaPaperAccountAssetObservationError(
                "asset observation outcome is unsupported"
            )
        if type(self.http_status) is not int or self.http_status not in (200, 404):
            raise AlpacaPaperAccountAssetObservationError(
                "asset observation supports only HTTP 200 or 404"
            )
        _require_text(
            self.provider_request_id,
            "Alpaca X-Request-ID",
            maximum_length=256,
        )
        _require_received_at(self.received_at, "asset observation received_at")
        _require_closed_failures(
            self.qualification_failures,
            field_name="asset qualification failures",
            allowed=_ASSET_FAILURE_NAMES,
        )
        decoded_response = _decode_response_object(self.response_body)
        if self.http_status == 404:
            code, message = _not_found_details(decoded_response)
            normalized_values = (
                self.provider_asset_id,
                self.asset_class,
                self.exchange,
                self.symbol,
                self.name,
                self.status,
                self.tradable,
                self.marginable,
                self.maintenance_margin_requirement,
                self.shortable,
                self.easy_to_borrow,
                self.fractionable,
            )
            if (
                self.outcome is not AlpacaAssetObservationOutcome.NOT_VISIBLE_INCONCLUSIVE
                or any(value is not None for value in normalized_values)
                or self.attributes
                or self.qualification_failures
                or self.not_found_code != code
                or self.not_found_message != message
            ):
                raise AlpacaPaperAccountAssetObservationError(
                    "HTTP 404 must remain an exact inconclusive not-visible observation"
                )
            return

        asset = _decode_asset_wire(decoded_response)
        failures = _asset_failures(self.description, asset)
        expected_outcome = _asset_outcome(failures)
        expected_values = (
            ("provider_asset_id", asset.provider_asset_id),
            ("asset_class", asset.asset_class),
            ("exchange", asset.exchange),
            ("symbol", asset.symbol),
            ("name", asset.name),
            ("status", asset.status),
            ("tradable", asset.tradable),
            ("marginable", asset.marginable),
            ("maintenance_margin_requirement", asset.maintenance_margin_requirement),
            ("shortable", asset.shortable),
            ("easy_to_borrow", asset.easy_to_borrow),
            ("fractionable", asset.fractionable),
            ("attributes", asset.attributes),
            ("qualification_failures", failures),
            ("outcome", expected_outcome),
            ("not_found_code", None),
            ("not_found_message", None),
        )
        for field_name, expected in expected_values:
            actual = getattr(self, field_name)
            if type(actual) is not type(expected) or actual != expected:
                raise AlpacaPaperAccountAssetObservationError(
                    f"asset observation {field_name} does not match exact response bytes"
                )

    @property
    def environment(self) -> str:
        return self.description.environment

    @property
    def evidence_qualification(self) -> str:
        return ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION

    @property
    def response_sha256(self) -> str:
        return hashlib.sha256(self.response_body).hexdigest()

    @property
    def response_size_bytes(self) -> int:
        return len(self.response_body)

    @property
    def validated_raw_only_numeric_fields(self) -> tuple[str, ...]:
        decoded = _decode_response_object(self.response_body)
        return tuple(
            field_name
            for field_name in _ALPACA_ASSET_RAW_ONLY_NUMERIC_FIELDS
            if field_name in decoded
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                (
                    ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION,
                    "asset_observation",
                    self.description.semantic_sha256,
                    self.outcome,
                    self.http_status,
                    self.provider_request_id,
                    self.received_at,
                    self.response_size_bytes,
                    self.response_sha256,
                    self.provider_asset_id,
                    self.asset_class,
                    self.exchange,
                    self.symbol,
                    self.name,
                    self.status,
                    self.tradable,
                    self.marginable,
                    self.maintenance_margin_requirement,
                    self.shortable,
                    self.easy_to_borrow,
                    self.fractionable,
                    self.attributes,
                    self.qualification_failures,
                    self.not_found_code,
                    self.not_found_message,
                    self.validated_raw_only_numeric_fields,
                )
            )
        ).hexdigest()

    @property
    def inconclusive(self) -> bool:
        return self.outcome is AlpacaAssetObservationOutcome.NOT_VISIBLE_INCONCLUSIVE

    @property
    def attribute_review_required(self) -> bool:
        return self.outcome is AlpacaAssetObservationOutcome.ATTRIBUTE_REVIEW_REQUIRED

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def durable_security_identity_binding_authorized(self) -> bool:
        return False

    @property
    def security_mapping_ready(self) -> bool:
        return False

    @property
    def asset_tradability_validation_ready(self) -> bool:
        return False

    @property
    def fractional_quantity_authorized(self) -> bool:
        return False

    @property
    def short_exposure_authorized(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


def decode_alpaca_asset_observation_response(
    description: AlpacaPaperAssetObservationDescription,
    *,
    http_status: int,
    provider_request_id: str,
    response_body: bytes,
    received_at: datetime,
) -> AlpacaAssetObservation:
    """Decode retained asset bytes without qualifying identity or freshness."""

    if type(description) is not AlpacaPaperAssetObservationDescription:
        raise AlpacaPaperAccountAssetObservationError(
            "asset decoding requires an exact asset description"
        )
    if type(http_status) is not int:
        raise AlpacaPaperAccountAssetObservationError("asset HTTP status must be an exact integer")
    decoded_response = _decode_response_object(response_body)
    if http_status == 404:
        code, message = _not_found_details(decoded_response)
        return AlpacaAssetObservation(
            description=description,
            outcome=AlpacaAssetObservationOutcome.NOT_VISIBLE_INCONCLUSIVE,
            http_status=http_status,
            provider_request_id=provider_request_id,
            received_at=received_at,
            response_body=response_body,
            not_found_code=code,
            not_found_message=message,
        )
    if http_status != 200:
        raise AlpacaPaperAccountAssetObservationError(
            "asset decoding supports only successful or not-visible responses"
        )
    asset = _decode_asset_wire(decoded_response)
    failures = _asset_failures(description, asset)
    return AlpacaAssetObservation(
        description=description,
        outcome=_asset_outcome(failures),
        http_status=http_status,
        provider_request_id=provider_request_id,
        received_at=received_at,
        response_body=response_body,
        provider_asset_id=asset.provider_asset_id,
        asset_class=asset.asset_class,
        exchange=asset.exchange,
        symbol=asset.symbol,
        name=asset.name,
        status=asset.status,
        tradable=asset.tradable,
        marginable=asset.marginable,
        maintenance_margin_requirement=asset.maintenance_margin_requirement,
        shortable=asset.shortable,
        easy_to_borrow=asset.easy_to_borrow,
        fractionable=asset.fractionable,
        attributes=asset.attributes,
        qualification_failures=failures,
    )


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ASSET_EVIDENCE_QUALIFICATION",
    "ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_CONTRACT_VERSION",
    "ALPACA_PAPER_ACCOUNT_ASSET_OBSERVATION_REVIEWED_ON",
    "ALPACA_PAPER_ASSET_PATH_TEMPLATE",
    "ALPACA_PAPER_MAX_ACCOUNT_ASSET_RESPONSE_BYTES",
    "ALPACA_PAPER_V1_ELIGIBLE_ASSET_EXCHANGES",
    "ALPACA_PY_ACCOUNT_ASSET_MODEL_COMMIT",
    "AlpacaAccountObservation",
    "AlpacaAccountObservationOutcome",
    "AlpacaAccountStatus",
    "AlpacaAssetAttribute",
    "AlpacaAssetClass",
    "AlpacaAssetExchange",
    "AlpacaAssetObservation",
    "AlpacaAssetObservationOutcome",
    "AlpacaAssetStatus",
    "AlpacaPaperAccountAssetObservationError",
    "AlpacaPaperAccountObservationDescription",
    "AlpacaPaperAssetObservationDescription",
    "create_alpaca_account_observation_description",
    "create_alpaca_asset_observation_description",
    "decode_alpaca_account_observation_response",
    "decode_alpaca_asset_observation_response",
]
