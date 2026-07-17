"""Strict, offline qualification for Tiingo end-of-day response observations.

Tiingo documents separate raw and adjusted OHLCV fields. Its EOD rows do not,
however, include a row publication timestamp, revision number, or historical
vintage. This module therefore qualifies economic and calendar semantics while
deliberately refusing conversion to canonical execution bars.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import NoReturn, cast

from packages.market_data import BarInterval, ExchangeCalendar, ExchangeSession
from packages.market_data.models import (
    require_digest,
    require_positive_decimal,
    require_text,
    require_utc,
)

TIINGO_PROVIDER = "tiingo"
TIINGO_DATASET = "end-of-day"
TIINGO_QUALIFICATION_SCHEMA_VERSION = "tiingo-eod-qualification-v1"
TIINGO_ACQUISITION_PROFILE_SCHEMA_VERSION = "tiingo-eod-acquisition-profile-v1"
TIINGO_CAPTURE_AUTHORIZATION_SCHEMA_VERSION = "tiingo-eod-capture-authorization-v1"
TIINGO_CAPTURE_SCHEMA_VERSION = "tiingo-eod-capture-v2"
TIINGO_EOD_SOURCE_ID = "tiingo-eod-rest"
TIINGO_EOD_ADAPTER_VERSION = "tiingo-eod-capture-v2"
TIINGO_EOD_ENDPOINT_TEMPLATE = "https://api.tiingo.com/tiingo/daily/{symbol}/prices"
TIINGO_EOD_FIELDS = (
    "date",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "adjOpen",
    "adjHigh",
    "adjLow",
    "adjClose",
    "adjVolume",
    "divCash",
    "splitFactor",
)
PHASE1_TIINGO_SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")
MAX_TIINGO_RESPONSE_BYTES = 4_194_304
MAX_TIINGO_PROFILE_BYTES = 1_048_576
MAX_TIINGO_AUTHORIZATION_BYTES = 1_048_576
MAX_TIINGO_MANIFEST_BYTES = 1_048_576
MAX_INT64 = 9_223_372_036_854_775_807

_SYMBOL = re.compile(r"^[A-Z][A-Z0-9.-]{0,14}$")
_FIELD_CONTRACT = (
    ("date", "utc-midnight-or-iso-date"),
    ("open", "positive-decimal-raw"),
    ("high", "positive-decimal-raw"),
    ("low", "positive-decimal-raw"),
    ("close", "positive-decimal-raw"),
    ("volume", "non-negative-int64-raw"),
    ("adjOpen", "positive-decimal-split-dividend-adjusted"),
    ("adjHigh", "positive-decimal-split-dividend-adjusted"),
    ("adjLow", "positive-decimal-split-dividend-adjusted"),
    ("adjClose", "positive-decimal-split-dividend-adjusted"),
    ("adjVolume", "non-negative-int64-split-dividend-adjusted"),
    ("divCash", "non-negative-decimal-ex-date"),
    ("splitFactor", "positive-decimal"),
)


class TiingoEodError(ValueError):
    """A Tiingo response or qualification invariant failed closed."""


class TiingoEodAdjustedBasis(StrEnum):
    SPLIT_DIVIDEND_ADJUSTED = "split_dividend_adjusted"


class TiingoEodRawBasis(StrEnum):
    DOCUMENTED_RAW_CANDIDATE = "documented_raw_candidate"


class TiingoEodQualificationKind(StrEnum):
    SYNTHETIC_CONTRACT_ONLY = "synthetic_contract_only"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


TIINGO_EOD_SCHEMA_SHA256 = _digest(_FIELD_CONTRACT)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TiingoEodError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> NoReturn:
    raise TiingoEodError(f"non-finite JSON number is not permitted: {value}")


def _json(payload_bytes: bytes) -> object:
    try:
        return cast(
            object,
            json.loads(
                payload_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_float=Decimal,
                parse_int=int,
                parse_constant=_reject_constant,
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TiingoEodError("response is not valid unambiguous UTF-8 JSON") from error


def _object(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TiingoEodError(f"{field_name} must be a JSON object")
    return cast(dict[str, object], value)


def _text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise TiingoEodError(f"{field_name} must be a string")
    try:
        require_text(value, field_name)
    except ValueError as error:
        raise TiingoEodError(str(error)) from error
    return value


def _boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise TiingoEodError(f"{field_name} must be boolean")
    return value


def _date(value: object, field_name: str) -> date:
    if not isinstance(value, str):
        raise TiingoEodError(f"{field_name} must be an ISO date string")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise TiingoEodError(f"{field_name} must be an ISO date string") from error


def _optional_date(value: object, field_name: str) -> date | None:
    return None if value is None else _date(value, field_name)


def _datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise TiingoEodError(f"{field_name} must be an ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(result, field_name)
    except ValueError as error:
        raise TiingoEodError(f"{field_name} must be an ISO-8601 UTC timestamp") from error
    return result


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _fields(value: dict[str, object], expected: set[str], field_name: str) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown or missing:
        details: list[str] = []
        if unknown:
            details.append(f"unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            details.append(f"missing fields: {', '.join(sorted(missing))}")
        raise TiingoEodError(f"{field_name} has {'; '.join(details)}")


def _decimal(value: object, field_name: str, *, allow_zero: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise TiingoEodError(f"{field_name} must be a JSON number")
    result = Decimal(value)
    if not result.is_finite() or result < 0 or (not allow_zero and result == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise TiingoEodError(f"{field_name} must be a finite {qualifier} decimal")
    return result


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_INT64:
        raise TiingoEodError(f"{field_name} must be a non-negative int64")
    return value


def _trading_date(value: object, field_name: str) -> date:
    if not isinstance(value, str):
        raise TiingoEodError(f"{field_name} must be an ISO date or UTC timestamp")
    if len(value) == 10:
        try:
            return date.fromisoformat(value)
        except ValueError as error:
            raise TiingoEodError(f"{field_name} must be an ISO date") from error
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require_utc(timestamp, field_name)
    except ValueError as error:
        raise TiingoEodError(f"{field_name} must be an ISO UTC timestamp") from error
    if timestamp.timetz().replace(tzinfo=None) != time(0):
        raise TiingoEodError(f"{field_name} timestamp must identify midnight UTC")
    return timestamp.date()


@dataclass(frozen=True, slots=True)
class TiingoEodScope:
    symbols: tuple[str, ...]
    start_date: date
    end_date: date

    def __post_init__(self) -> None:
        if self.symbols != tuple(sorted(set(self.symbols))) or not self.symbols:
            raise ValueError("symbols must be a non-empty, unique, sorted tuple")
        if any(_SYMBOL.fullmatch(symbol) is None for symbol in self.symbols):
            raise ValueError("symbols must use canonical uppercase market notation")
        if self.end_date < self.start_date:
            raise ValueError("end_date cannot precede start_date")
        if (self.end_date - self.start_date).days > 365:
            raise ValueError("a Tiingo qualification scope is limited to 366 inclusive dates")

    def to_dict(self) -> dict[str, object]:
        return {
            "end_date": self.end_date.isoformat(),
            "start_date": self.start_date.isoformat(),
            "symbols": list(self.symbols),
        }

    @classmethod
    def from_dict(cls, value: object) -> TiingoEodScope:
        payload = _object(value, "scope")
        _fields(payload, {"symbols", "start_date", "end_date"}, "scope")
        symbols = payload["symbols"]
        if not isinstance(symbols, list) or not all(isinstance(item, str) for item in symbols):
            raise TiingoEodError("scope.symbols must be an array of strings")
        try:
            return cls(
                symbols=tuple(symbols),
                start_date=_date(payload["start_date"], "scope.start_date"),
                end_date=_date(payload["end_date"], "scope.end_date"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(str(error)) from error


@dataclass(frozen=True, slots=True)
class TiingoEodAcquisitionProfile:
    """Frozen request and interpretation boundary reviewed before capture."""

    scope: TiingoEodScope
    profile_id: str
    approved: bool
    reviewer_id: str
    reviewed_at: datetime
    source_id: str
    adapter_version: str
    market_provenance: str
    identifier_authority: str
    calendar_authority: str
    corporate_action_authority: str
    correction_policy: str
    endpoint_template: str = TIINGO_EOD_ENDPOINT_TEMPLATE
    schema_sha256: str = TIINGO_EOD_SCHEMA_SHA256
    schema_version: str = TIINGO_ACQUISITION_PROFILE_SCHEMA_VERSION
    provider: str = TIINGO_PROVIDER
    dataset: str = TIINGO_DATASET

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.profile_id, "profile_id"),
            (self.reviewer_id, "reviewer_id"),
            (self.source_id, "source_id"),
            (self.adapter_version, "adapter_version"),
            (self.market_provenance, "market_provenance"),
            (self.identifier_authority, "identifier_authority"),
            (self.calendar_authority, "calendar_authority"),
            (self.corporate_action_authority, "corporate_action_authority"),
            (self.correction_policy, "correction_policy"),
        ):
            require_text(value, field_name)
        if type(self.approved) is not bool:
            raise ValueError("approved must be boolean")
        require_utc(self.reviewed_at, "reviewed_at")
        if self.source_id != TIINGO_EOD_SOURCE_ID:
            raise ValueError("acquisition profile source_id does not identify Tiingo EOD")
        if self.adapter_version != TIINGO_EOD_ADAPTER_VERSION:
            raise ValueError("acquisition profile adapter_version is unsupported")
        if self.endpoint_template != TIINGO_EOD_ENDPOINT_TEMPLATE:
            raise ValueError("acquisition profile endpoint is not the frozen Tiingo EOD endpoint")
        if self.schema_sha256 != TIINGO_EOD_SCHEMA_SHA256:
            raise ValueError("acquisition profile schema digest is not the frozen field contract")
        if self.schema_version != TIINGO_ACQUISITION_PROFILE_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD acquisition profile schema")
        if self.provider != TIINGO_PROVIDER or self.dataset != TIINGO_DATASET:
            raise ValueError("acquisition profile does not identify Tiingo EOD")
        if not set(self.scope.symbols).issubset(PHASE1_TIINGO_SYMBOLS):
            raise ValueError("acquisition profile exceeds the Phase 1 Tiingo symbol allow-list")

    @property
    def contract_sha256(self) -> str:
        """Digest the normalized profile contract, not its presentation bytes."""

        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_version": self.adapter_version,
            "approved": self.approved,
            "calendar_authority": self.calendar_authority,
            "corporate_action_authority": self.corporate_action_authority,
            "correction_policy": self.correction_policy,
            "dataset": self.dataset,
            "endpoint_template": self.endpoint_template,
            "identifier_authority": self.identifier_authority,
            "market_provenance": self.market_provenance,
            "provider": self.provider,
            "profile_id": self.profile_id,
            "reviewed_at": _timestamp(self.reviewed_at),
            "reviewer_id": self.reviewer_id,
            "schema_sha256": self.schema_sha256,
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "source_id": self.source_id,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_dict(cls, value: object) -> TiingoEodAcquisitionProfile:
        payload = _object(value, "profile")
        expected = {
            "adapter_version",
            "approved",
            "calendar_authority",
            "corporate_action_authority",
            "correction_policy",
            "dataset",
            "endpoint_template",
            "identifier_authority",
            "market_provenance",
            "provider",
            "profile_id",
            "reviewed_at",
            "reviewer_id",
            "schema_sha256",
            "schema_version",
            "scope",
            "source_id",
        }
        _fields(payload, expected, "profile")
        try:
            return cls(
                scope=TiingoEodScope.from_dict(payload["scope"]),
                profile_id=_text(payload["profile_id"], "profile_id"),
                approved=_boolean(payload["approved"], "approved"),
                reviewer_id=_text(payload["reviewer_id"], "reviewer_id"),
                reviewed_at=_datetime(payload["reviewed_at"], "reviewed_at"),
                source_id=_text(payload["source_id"], "source_id"),
                adapter_version=_text(payload["adapter_version"], "adapter_version"),
                market_provenance=_text(payload["market_provenance"], "market_provenance"),
                identifier_authority=_text(payload["identifier_authority"], "identifier_authority"),
                calendar_authority=_text(payload["calendar_authority"], "calendar_authority"),
                corporate_action_authority=_text(
                    payload["corporate_action_authority"],
                    "corporate_action_authority",
                ),
                correction_policy=_text(payload["correction_policy"], "correction_policy"),
                endpoint_template=_text(payload["endpoint_template"], "endpoint_template"),
                schema_sha256=_text(payload["schema_sha256"], "schema_sha256"),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                dataset=_text(payload["dataset"], "dataset"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(str(error)) from error

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> TiingoEodAcquisitionProfile:
        if type(payload_bytes) is not bytes or not payload_bytes:
            raise TiingoEodError("acquisition profile must be non-empty immutable bytes")
        if len(payload_bytes) > MAX_TIINGO_PROFILE_BYTES:
            raise TiingoEodError("acquisition profile exceeds the size limit")
        return cls.from_dict(_json(payload_bytes))


@dataclass(frozen=True, slots=True)
class TiingoEodCaptureAuthorization:
    """Reviewed permission for one digest-bound acquisition profile."""

    authorization_id: str
    reviewer_id: str
    reviewed_at: datetime
    terms_sha256: str
    profile_contract_sha256: str
    effective_from: date
    effective_through: date | None
    permits_local_snapshot_storage: bool
    permits_research_use: bool
    schema_version: str = TIINGO_CAPTURE_AUTHORIZATION_SCHEMA_VERSION
    provider: str = TIINGO_PROVIDER
    dataset: str = TIINGO_DATASET

    def __post_init__(self) -> None:
        require_text(self.authorization_id, "authorization_id")
        require_text(self.reviewer_id, "reviewer_id")
        require_utc(self.reviewed_at, "reviewed_at")
        require_digest(self.terms_sha256, "terms_sha256")
        require_digest(self.profile_contract_sha256, "profile_contract_sha256")
        if self.terms_sha256 == "0" * 64:
            raise ValueError("terms_sha256 must identify the reviewed terms artifact")
        if self.profile_contract_sha256 == "0" * 64:
            raise ValueError(
                "profile_contract_sha256 must identify the reviewed acquisition profile"
            )
        if self.effective_through is not None and self.effective_through < self.effective_from:
            raise ValueError("effective_through cannot precede effective_from")
        if type(self.permits_local_snapshot_storage) is not bool:
            raise ValueError("permits_local_snapshot_storage must be boolean")
        if type(self.permits_research_use) is not bool:
            raise ValueError("permits_research_use must be boolean")
        if self.schema_version != TIINGO_CAPTURE_AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD capture authorization schema")
        if self.provider != TIINGO_PROVIDER or self.dataset != TIINGO_DATASET:
            raise ValueError("authorization does not identify Tiingo EOD")

    def authorize(
        self,
        profile: TiingoEodAcquisitionProfile,
        *,
        requested_at: datetime,
    ) -> None:
        require_utc(requested_at, "requested_at")
        if not profile.approved:
            raise ValueError("acquisition profile has not been approved")
        if profile.reviewed_at > requested_at:
            raise ValueError("acquisition profile has not yet been reviewed")
        if self.reviewed_at > requested_at:
            raise ValueError("capture authorization has not yet been reviewed")
        if self.reviewed_at < profile.reviewed_at:
            raise ValueError("capture authorization predates the reviewed acquisition profile")
        if self.profile_contract_sha256 != profile.contract_sha256:
            raise ValueError("capture authorization does not bind the acquisition profile")
        if not self.permits_local_snapshot_storage or not self.permits_research_use:
            raise ValueError("capture authorization does not permit local research storage")
        if profile.scope.start_date < self.effective_from:
            raise ValueError("capture scope predates its storage authorization")
        if self.effective_through is not None and profile.scope.end_date > self.effective_through:
            raise ValueError("capture scope exceeds its storage authorization")

    def to_dict(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "dataset": self.dataset,
            "effective_from": self.effective_from.isoformat(),
            "effective_through": (
                None if self.effective_through is None else self.effective_through.isoformat()
            ),
            "permits_local_snapshot_storage": self.permits_local_snapshot_storage,
            "permits_research_use": self.permits_research_use,
            "profile_contract_sha256": self.profile_contract_sha256,
            "provider": self.provider,
            "reviewed_at": _timestamp(self.reviewed_at),
            "reviewer_id": self.reviewer_id,
            "schema_version": self.schema_version,
            "terms_sha256": self.terms_sha256,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> TiingoEodCaptureAuthorization:
        if type(payload_bytes) is not bytes or not payload_bytes:
            raise TiingoEodError("capture authorization must be non-empty immutable bytes")
        if len(payload_bytes) > MAX_TIINGO_AUTHORIZATION_BYTES:
            raise TiingoEodError("capture authorization exceeds the size limit")
        payload = _object(_json(payload_bytes), "authorization")
        expected = {
            "authorization_id",
            "dataset",
            "effective_from",
            "effective_through",
            "permits_local_snapshot_storage",
            "permits_research_use",
            "profile_contract_sha256",
            "provider",
            "reviewed_at",
            "reviewer_id",
            "schema_version",
            "terms_sha256",
        }
        _fields(payload, expected, "authorization")
        try:
            return cls(
                authorization_id=_text(payload["authorization_id"], "authorization_id"),
                reviewer_id=_text(payload["reviewer_id"], "reviewer_id"),
                reviewed_at=_datetime(payload["reviewed_at"], "reviewed_at"),
                terms_sha256=_text(payload["terms_sha256"], "terms_sha256"),
                profile_contract_sha256=_text(
                    payload["profile_contract_sha256"],
                    "profile_contract_sha256",
                ),
                effective_from=_date(payload["effective_from"], "effective_from"),
                effective_through=_optional_date(payload["effective_through"], "effective_through"),
                permits_local_snapshot_storage=_boolean(
                    payload["permits_local_snapshot_storage"],
                    "permits_local_snapshot_storage",
                ),
                permits_research_use=_boolean(
                    payload["permits_research_use"], "permits_research_use"
                ),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                dataset=_text(payload["dataset"], "dataset"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(str(error)) from error


@dataclass(frozen=True, slots=True)
class TiingoEodCaptureReceipt:
    symbol: str
    object_path: str
    sha256: str
    byte_count: int
    requested_at: datetime
    received_at: datetime

    def __post_init__(self) -> None:
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("symbol must use canonical uppercase market notation")
        require_digest(self.sha256, "sha256")
        if (
            type(self.byte_count) is not int
            or not 1 <= self.byte_count <= MAX_TIINGO_RESPONSE_BYTES
        ):
            raise ValueError("response byte_count must be within the capture limit")
        path = PurePosixPath(self.object_path)
        if (
            path.is_absolute()
            or tuple(path.parts) != ("objects", f"{self.sha256}.json")
            or "\\" in self.object_path
        ):
            raise ValueError("object_path must be the content-addressed response path")
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.received_at < self.requested_at:
            raise ValueError("received_at cannot precede requested_at")

    def to_dict(self) -> dict[str, object]:
        return {
            "byte_count": self.byte_count,
            "object_path": self.object_path,
            "received_at": _timestamp(self.received_at),
            "requested_at": _timestamp(self.requested_at),
            "sha256": self.sha256,
            "symbol": self.symbol,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> TiingoEodCaptureReceipt:
        payload = _object(value, f"responses[{index}]")
        expected = {
            "byte_count",
            "object_path",
            "received_at",
            "requested_at",
            "sha256",
            "symbol",
        }
        _fields(payload, expected, f"responses[{index}]")
        byte_count = payload["byte_count"]
        if type(byte_count) is not int:
            raise TiingoEodError("byte_count must be an integer")
        try:
            return cls(
                symbol=_text(payload["symbol"], "symbol"),
                object_path=_text(payload["object_path"], "object_path"),
                sha256=_text(payload["sha256"], "sha256"),
                byte_count=byte_count,
                requested_at=_datetime(payload["requested_at"], "requested_at"),
                received_at=_datetime(payload["received_at"], "received_at"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(str(error)) from error


@dataclass(frozen=True, slots=True)
class TiingoEodCaptureManifest:
    profile: TiingoEodAcquisitionProfile
    profile_contract_sha256: str
    responses: tuple[TiingoEodCaptureReceipt, ...]
    requested_at: datetime
    received_at: datetime
    authorization_sha256: str
    calendar_artifact_sha256: str
    terms_sha256: str
    schema_version: str = TIINGO_CAPTURE_SCHEMA_VERSION
    provider: str = TIINGO_PROVIDER
    dataset: str = TIINGO_DATASET

    def __post_init__(self) -> None:
        require_digest(self.profile_contract_sha256, "profile_contract_sha256")
        require_digest(self.authorization_sha256, "authorization_sha256")
        require_digest(self.calendar_artifact_sha256, "calendar_artifact_sha256")
        require_digest(self.terms_sha256, "terms_sha256")
        if self.authorization_sha256 == "0" * 64:
            raise ValueError("authorization_sha256 must identify the reviewed artifact")
        if self.calendar_artifact_sha256 == "0" * 64:
            raise ValueError("calendar_artifact_sha256 must identify the reviewed artifact")
        if self.terms_sha256 == "0" * 64:
            raise ValueError("terms_sha256 must identify the reviewed terms artifact")
        if self.profile_contract_sha256 != self.profile.contract_sha256:
            raise ValueError("manifest profile digest does not match its acquisition profile")
        if self.schema_version != TIINGO_CAPTURE_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD capture schema")
        if self.provider != TIINGO_PROVIDER or self.dataset != TIINGO_DATASET:
            raise ValueError("capture manifest does not identify Tiingo EOD")
        if type(self.responses) is not tuple or not self.responses:
            raise ValueError("capture manifest requires an immutable response tuple")
        symbols = tuple(receipt.symbol for receipt in self.responses)
        if symbols != self.profile.scope.symbols:
            raise ValueError("capture responses must exactly match sorted profile symbols")
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.requested_at != self.responses[0].requested_at:
            raise ValueError("manifest requested_at must equal the first response request")
        if self.received_at != self.responses[-1].received_at:
            raise ValueError("manifest received_at must equal the final response receipt")
        previous: TiingoEodCaptureReceipt | None = None
        for receipt in self.responses:
            if previous is not None and receipt.requested_at < previous.received_at:
                raise ValueError("capture response timestamps are not monotonic")
            previous = receipt

    def to_dict(self) -> dict[str, object]:
        return {
            "authorization_sha256": self.authorization_sha256,
            "calendar_artifact_sha256": self.calendar_artifact_sha256,
            "dataset": self.dataset,
            "profile": self.profile.to_dict(),
            "profile_contract_sha256": self.profile_contract_sha256,
            "provider": self.provider,
            "received_at": _timestamp(self.received_at),
            "requested_at": _timestamp(self.requested_at),
            "responses": [response.to_dict() for response in self.responses],
            "schema_version": self.schema_version,
            "terms_sha256": self.terms_sha256,
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload_bytes: bytes) -> TiingoEodCaptureManifest:
        if type(payload_bytes) is not bytes or not payload_bytes:
            raise TiingoEodError("capture manifest must be non-empty immutable bytes")
        if len(payload_bytes) > MAX_TIINGO_MANIFEST_BYTES:
            raise TiingoEodError("capture manifest exceeds the size limit")
        payload = _object(_json(payload_bytes), "manifest")
        expected = {
            "authorization_sha256",
            "calendar_artifact_sha256",
            "dataset",
            "profile",
            "profile_contract_sha256",
            "provider",
            "received_at",
            "requested_at",
            "responses",
            "schema_version",
            "terms_sha256",
        }
        _fields(payload, expected, "manifest")
        responses = payload["responses"]
        if not isinstance(responses, list):
            raise TiingoEodError("manifest.responses must be an array")
        try:
            return cls(
                profile=TiingoEodAcquisitionProfile.from_dict(payload["profile"]),
                profile_contract_sha256=_text(
                    payload["profile_contract_sha256"],
                    "profile_contract_sha256",
                ),
                responses=tuple(
                    TiingoEodCaptureReceipt.from_dict(response, index)
                    for index, response in enumerate(responses)
                ),
                requested_at=_datetime(payload["requested_at"], "requested_at"),
                received_at=_datetime(payload["received_at"], "received_at"),
                authorization_sha256=_text(payload["authorization_sha256"], "authorization_sha256"),
                calendar_artifact_sha256=_text(
                    payload["calendar_artifact_sha256"],
                    "calendar_artifact_sha256",
                ),
                terms_sha256=_text(payload["terms_sha256"], "terms_sha256"),
                schema_version=_text(payload["schema_version"], "schema_version"),
                provider=_text(payload["provider"], "provider"),
                dataset=_text(payload["dataset"], "dataset"),
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(str(error)) from error


@dataclass(frozen=True, slots=True)
class TiingoEodResponseObservation:
    symbol: str
    requested_at: datetime
    received_at: datetime
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("symbol must use canonical uppercase market notation")
        require_utc(self.requested_at, "requested_at")
        require_utc(self.received_at, "received_at")
        if self.received_at < self.requested_at:
            raise ValueError("received_at cannot precede requested_at")
        if type(self.payload) is not bytes or not self.payload:
            raise ValueError("payload must be non-empty immutable bytes")
        if len(self.payload) > MAX_TIINGO_RESPONSE_BYTES:
            raise ValueError("Tiingo response exceeds the qualification size limit")


@dataclass(frozen=True, slots=True)
class TiingoEodResponseContract:
    """Secret-free structural identity of one exact provider response."""

    response_sha256: str
    schema_sha256: str
    byte_count: int
    session_dates: tuple[date, ...]

    def __post_init__(self) -> None:
        require_digest(self.response_sha256, "response_sha256")
        require_digest(self.schema_sha256, "schema_sha256")
        if self.schema_sha256 != TIINGO_EOD_SCHEMA_SHA256:
            raise ValueError("response contract does not use the frozen Tiingo field schema")
        if (
            type(self.byte_count) is not int
            or not 1 <= self.byte_count <= MAX_TIINGO_RESPONSE_BYTES
        ):
            raise ValueError("response byte_count must be within the capture limit")
        if (
            type(self.session_dates) is not tuple
            or not self.session_dates
            or self.session_dates != tuple(sorted(set(self.session_dates)))
        ):
            raise ValueError("response session dates must be a non-empty sorted unique tuple")


@dataclass(frozen=True, slots=True)
class _TiingoEodContractRow:
    trading_date: date
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: int
    adjusted_open_price: Decimal
    adjusted_high_price: Decimal
    adjusted_low_price: Decimal
    adjusted_close_price: Decimal
    adjusted_volume: int
    div_cash: Decimal
    split_factor: Decimal


def _validate_ohlc(
    open_price: Decimal,
    high_price: Decimal,
    low_price: Decimal,
    close_price: Decimal,
    *,
    basis: str,
) -> None:
    if low_price > min(open_price, close_price):
        raise TiingoEodError(f"{basis} low cannot exceed {basis} open or close")
    if high_price < max(open_price, close_price):
        raise TiingoEodError(f"{basis} high cannot be below {basis} open or close")
    if low_price > high_price:
        raise TiingoEodError(f"{basis} low cannot exceed {basis} high")


def _contract_rows(
    payload_bytes: bytes,
    *,
    scope: TiingoEodScope,
) -> tuple[_TiingoEodContractRow, ...]:
    if type(payload_bytes) is not bytes or not payload_bytes:
        raise TiingoEodError("Tiingo EOD response must be non-empty immutable bytes")
    if len(payload_bytes) > MAX_TIINGO_RESPONSE_BYTES:
        raise TiingoEodError("Tiingo EOD response exceeds the capture size limit")
    decoded = _json(payload_bytes)
    if not isinstance(decoded, list) or not decoded:
        raise TiingoEodError("Tiingo EOD response must be a non-empty JSON array")
    rows: list[_TiingoEodContractRow] = []
    seen_dates: set[date] = set()
    for index, value in enumerate(decoded):
        payload = _object(value, f"rows[{index}]")
        _fields(payload, set(TIINGO_EOD_FIELDS), f"rows[{index}]")
        trading_date = _trading_date(payload["date"], f"rows[{index}].date")
        if trading_date in seen_dates:
            raise TiingoEodError("Tiingo response contains a duplicate session date")
        seen_dates.add(trading_date)
        if not scope.start_date <= trading_date <= scope.end_date:
            raise TiingoEodError(f"rows[{index}] is outside the requested date scope")
        row = _TiingoEodContractRow(
            trading_date=trading_date,
            open_price=_decimal(payload["open"], "open"),
            high_price=_decimal(payload["high"], "high"),
            low_price=_decimal(payload["low"], "low"),
            close_price=_decimal(payload["close"], "close"),
            volume=_integer(payload["volume"], "volume"),
            adjusted_open_price=_decimal(payload["adjOpen"], "adjOpen"),
            adjusted_high_price=_decimal(payload["adjHigh"], "adjHigh"),
            adjusted_low_price=_decimal(payload["adjLow"], "adjLow"),
            adjusted_close_price=_decimal(payload["adjClose"], "adjClose"),
            adjusted_volume=_integer(payload["adjVolume"], "adjVolume"),
            div_cash=_decimal(payload["divCash"], "divCash", allow_zero=True),
            split_factor=_decimal(payload["splitFactor"], "splitFactor"),
        )
        _validate_ohlc(
            row.open_price,
            row.high_price,
            row.low_price,
            row.close_price,
            basis="raw",
        )
        _validate_ohlc(
            row.adjusted_open_price,
            row.adjusted_high_price,
            row.adjusted_low_price,
            row.adjusted_close_price,
            basis="adjusted",
        )
        rows.append(row)
    return tuple(rows)


def tiingo_eod_response_contract(
    payload_bytes: bytes,
    *,
    scope: TiingoEodScope,
) -> TiingoEodResponseContract:
    """Validate one exact response without assigning calendar or trading authority."""

    rows = _contract_rows(payload_bytes, scope=scope)
    return TiingoEodResponseContract(
        response_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        schema_sha256=TIINGO_EOD_SCHEMA_SHA256,
        byte_count=len(payload_bytes),
        session_dates=tuple(sorted(row.trading_date for row in rows)),
    )


@dataclass(frozen=True, slots=True)
class TiingoEodRow:
    symbol: str
    session_label: date
    interval_start: datetime
    interval_end: datetime
    observed_at: datetime
    open_price: Decimal
    high_price: Decimal
    low_price: Decimal
    close_price: Decimal
    volume: int
    adjusted_open_price: Decimal
    adjusted_high_price: Decimal
    adjusted_low_price: Decimal
    adjusted_close_price: Decimal
    adjusted_volume: int
    div_cash: Decimal
    split_factor: Decimal
    response_sha256: str
    interval: BarInterval = BarInterval.ONE_DAY
    raw_price_basis: TiingoEodRawBasis = TiingoEodRawBasis.DOCUMENTED_RAW_CANDIDATE
    adjusted_price_basis: TiingoEodAdjustedBasis = TiingoEodAdjustedBasis.SPLIT_DIVIDEND_ADJUSTED

    def __post_init__(self) -> None:
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("symbol must use canonical uppercase market notation")
        require_utc(self.interval_start, "interval_start")
        require_utc(self.interval_end, "interval_end")
        require_utc(self.observed_at, "observed_at")
        if self.observed_at < self.interval_end:
            raise ValueError("a completed EOD row cannot be observed before session close")
        if not self.interval.has_valid_span(self.interval_start, self.interval_end):
            raise ValueError("daily row has invalid local interval bounds")
        for value, field_name in (
            (self.open_price, "open_price"),
            (self.high_price, "high_price"),
            (self.low_price, "low_price"),
            (self.close_price, "close_price"),
            (self.adjusted_open_price, "adjusted_open_price"),
            (self.adjusted_high_price, "adjusted_high_price"),
            (self.adjusted_low_price, "adjusted_low_price"),
            (self.adjusted_close_price, "adjusted_close_price"),
        ):
            require_positive_decimal(value, field_name)
        if type(self.volume) is not int or not 0 <= self.volume <= MAX_INT64:
            raise ValueError("volume must be a non-negative int64")
        if type(self.adjusted_volume) is not int or not 0 <= self.adjusted_volume <= MAX_INT64:
            raise ValueError("adjusted_volume must be a non-negative int64")
        if not self.div_cash.is_finite() or self.div_cash < 0:
            raise ValueError("div_cash must be a finite non-negative decimal")
        require_positive_decimal(self.split_factor, "split_factor")
        if self.low_price > min(self.open_price, self.close_price):
            raise ValueError("raw low cannot exceed raw open or close")
        if self.high_price < max(self.open_price, self.close_price):
            raise ValueError("raw high cannot be below raw open or close")
        if self.low_price > self.high_price:
            raise ValueError("raw low cannot exceed raw high")
        if self.adjusted_low_price > min(
            self.adjusted_open_price,
            self.adjusted_close_price,
        ):
            raise ValueError("adjusted low cannot exceed adjusted open or close")
        if self.adjusted_high_price < max(
            self.adjusted_open_price,
            self.adjusted_close_price,
        ):
            raise ValueError("adjusted high cannot be below adjusted open or close")
        if self.adjusted_low_price > self.adjusted_high_price:
            raise ValueError("adjusted low cannot exceed adjusted high")
        require_digest(self.response_sha256, "response_sha256")
        if self.interval is not BarInterval.ONE_DAY:
            raise ValueError("Tiingo EOD rows require the session-defined daily interval")
        if self.raw_price_basis is not TiingoEodRawBasis.DOCUMENTED_RAW_CANDIDATE:
            raise ValueError("Tiingo raw-candidate OHLCV basis must remain explicit")
        if self.adjusted_price_basis is not TiingoEodAdjustedBasis.SPLIT_DIVIDEND_ADJUSTED:
            raise ValueError("Tiingo adjusted OHLCV basis must remain explicit")


@dataclass(frozen=True, slots=True)
class TiingoEodDataset:
    scope: TiingoEodScope
    response_sha256: str
    schema_sha256: str
    calendar_id: str
    calendar_version: str
    calendar_sha256: str
    semantic_sha256: str
    rows: tuple[TiingoEodRow, ...]
    schema_version: str = TIINGO_QUALIFICATION_SCHEMA_VERSION
    qualification_kind: TiingoEodQualificationKind = (
        TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY
    )

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.response_sha256, "response_sha256"),
            (self.schema_sha256, "schema_sha256"),
            (self.calendar_sha256, "calendar_sha256"),
            (self.semantic_sha256, "semantic_sha256"),
        ):
            require_digest(value, field_name)
        require_text(self.calendar_id, "calendar_id")
        require_text(self.calendar_version, "calendar_version")
        if self.schema_version != TIINGO_QUALIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported Tiingo EOD qualification schema")
        if self.qualification_kind is not TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY:
            raise ValueError("Tiingo EOD qualification is synthetic-contract-only")
        if type(self.rows) is not tuple or not self.rows:
            raise ValueError("Tiingo EOD qualification requires immutable non-empty rows")
        expected = tuple(sorted(self.rows, key=lambda row: (row.symbol, row.session_label)))
        if self.rows != expected:
            raise ValueError("Tiingo EOD rows must use deterministic symbol/session order")

    def raw_bar_records(self) -> NoReturn:
        """Refuse canonical conversion until publication and revision lineage exist."""

        raise TiingoEodError(
            "Tiingo EOD rows contain documented raw-candidate OHLCV but no row "
            "publication timestamp or historical vintage. Immutable authorized captures, "
            "local revision lineage, and venue/identity authority are required before "
            "VendorBarRecord emission."
        )

    def admission_evidence(self) -> NoReturn:
        """Refuse use of a synthetic contract result as provider evidence."""

        raise TiingoEodError(
            "synthetic Tiingo contract qualification is not licensed provider "
            "evidence and has no admission or trading effect"
        )


def _calendar_binding(
    calendar: ExchangeCalendar,
    scope: TiingoEodScope,
) -> tuple[tuple[ExchangeSession, ...], str]:
    if (
        calendar.sessions[0].session_label > scope.start_date
        or calendar.sessions[-1].session_label < scope.end_date
    ):
        raise TiingoEodError("pinned calendar does not cover the complete qualification scope")
    sessions = tuple(
        session
        for session in calendar.sessions
        if scope.start_date <= session.session_label <= scope.end_date
    )
    if not sessions:
        raise TiingoEodError("qualification scope contains no pinned exchange sessions")
    material = {
        "calendar_id": calendar.calendar_id,
        "sessions": [
            {
                "closes_at": session.closes_at.isoformat(),
                "kind": session.kind.value,
                "opens_at": session.opens_at.isoformat(),
                "session_label": session.session_label.isoformat(),
                "venue": session.venue,
            }
            for session in sessions
        ],
        "timezone": calendar.timezone,
        "venue": calendar.venue,
        "version": calendar.version,
    }
    return sessions, _digest(material)


def _parse_response(
    observation: TiingoEodResponseObservation,
    *,
    scope: TiingoEodScope,
    calendar: ExchangeCalendar,
) -> tuple[TiingoEodRow, ...]:
    response_sha256 = hashlib.sha256(observation.payload).hexdigest()
    rows: list[TiingoEodRow] = []
    for index, contract_row in enumerate(_contract_rows(observation.payload, scope=scope)):
        session = calendar.session_for_label(contract_row.trading_date)
        if session is None:
            raise TiingoEodError(f"rows[{index}] has no pinned exchange session")
        try:
            rows.append(
                TiingoEodRow(
                    symbol=observation.symbol,
                    session_label=contract_row.trading_date,
                    interval_start=session.opens_at,
                    interval_end=session.closes_at,
                    observed_at=observation.received_at,
                    open_price=contract_row.open_price,
                    high_price=contract_row.high_price,
                    low_price=contract_row.low_price,
                    close_price=contract_row.close_price,
                    volume=contract_row.volume,
                    adjusted_open_price=contract_row.adjusted_open_price,
                    adjusted_high_price=contract_row.adjusted_high_price,
                    adjusted_low_price=contract_row.adjusted_low_price,
                    adjusted_close_price=contract_row.adjusted_close_price,
                    adjusted_volume=contract_row.adjusted_volume,
                    div_cash=contract_row.div_cash,
                    split_factor=contract_row.split_factor,
                    response_sha256=response_sha256,
                )
            )
        except ValueError as error:
            if isinstance(error, TiingoEodError):
                raise
            raise TiingoEodError(f"rows[{index}] is invalid: {error}") from error
    return tuple(rows)


def qualify_tiingo_eod(
    responses: tuple[TiingoEodResponseObservation, ...],
    *,
    scope: TiingoEodScope,
    calendar: ExchangeCalendar,
    allowed_symbols: tuple[str, ...] = PHASE1_TIINGO_SYMBOLS,
) -> TiingoEodDataset:
    """Qualify synthetic contract observations without retaining their payloads.

    Every result is permanently marked synthetic-contract-only. A future
    authorized capture must use a separate API and evidence type.
    """

    if type(responses) is not tuple or not responses:
        raise TiingoEodError("qualification requires an immutable non-empty response tuple")
    if not set(scope.symbols).issubset(allowed_symbols):
        raise TiingoEodError("Tiingo qualification scope exceeds the configured allow-list")
    ordered = tuple(sorted(responses, key=lambda response: response.symbol))
    observed_symbols = tuple(response.symbol for response in ordered)
    if len(observed_symbols) != len(set(observed_symbols)):
        raise TiingoEodError("qualification contains duplicate symbol responses")
    if observed_symbols != scope.symbols:
        missing = sorted(set(scope.symbols) - set(observed_symbols))
        unknown = sorted(set(observed_symbols) - set(scope.symbols))
        details: list[str] = []
        if missing:
            details.append(f"missing symbols: {', '.join(missing)}")
        if unknown:
            details.append(f"out-of-scope symbols: {', '.join(unknown)}")
        raise TiingoEodError(f"response symbols do not match scope: {'; '.join(details)}")

    sessions, calendar_sha256 = _calendar_binding(calendar, scope)
    rows: list[TiingoEodRow] = []
    keys: set[tuple[str, date]] = set()
    response_material: list[dict[str, object]] = []
    for observation in ordered:
        payload_sha256 = hashlib.sha256(observation.payload).hexdigest()
        response_material.append(
            {
                "byte_count": len(observation.payload),
                "payload_sha256": payload_sha256,
                "received_at": observation.received_at.isoformat(),
                "requested_at": observation.requested_at.isoformat(),
                "symbol": observation.symbol,
            }
        )
        for row in _parse_response(observation, scope=scope, calendar=calendar):
            key = (row.symbol, row.session_label)
            if key in keys:
                raise TiingoEodError("qualification contains a duplicate symbol/session row")
            keys.add(key)
            rows.append(row)

    expected_keys = {
        (symbol, session.session_label) for symbol in scope.symbols for session in sessions
    }
    missing_keys = sorted(expected_keys - keys)
    if missing_keys:
        first_symbol, first_date = missing_keys[0]
        raise TiingoEodError(
            "Tiingo qualification is missing required session coverage: "
            f"{len(missing_keys)} rows; first {first_symbol}/{first_date.isoformat()}"
        )

    rows.sort(key=lambda row: (row.symbol, row.session_label))
    response_sha256 = _digest(response_material)
    schema_sha256 = TIINGO_EOD_SCHEMA_SHA256
    semantic_sha256 = _digest(
        {
            "calendar_sha256": calendar_sha256,
            "dataset": TIINGO_DATASET,
            "provider": TIINGO_PROVIDER,
            "qualification_kind": (TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY.value),
            "response_sha256": response_sha256,
            "schema_sha256": schema_sha256,
            "schema_version": TIINGO_QUALIFICATION_SCHEMA_VERSION,
            "scope": {
                "end_date": scope.end_date.isoformat(),
                "start_date": scope.start_date.isoformat(),
                "symbols": list(scope.symbols),
            },
        }
    )
    return TiingoEodDataset(
        scope=scope,
        response_sha256=response_sha256,
        schema_sha256=schema_sha256,
        calendar_id=calendar.calendar_id,
        calendar_version=calendar.version,
        calendar_sha256=calendar_sha256,
        semantic_sha256=semantic_sha256,
        rows=tuple(rows),
    )
