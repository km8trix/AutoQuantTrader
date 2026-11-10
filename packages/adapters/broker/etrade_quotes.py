"""Strict offline ALL-quote normalization; no OAuth, transport or provider defaults."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Literal
from zoneinfo import ZoneInfo

from packages.domain.forward_capture_contracts import MAX_CAPTURE_BYTES, ForwardCaptureRequest
from packages.domain.forward_contracts import ForwardQuote


class EtradeQuoteError(ValueError):
    """Static diagnostic; no provider fields are interpolated."""


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in values:
        if key in result or any(
            word in key.lower()
            for word in ("oauth", "authorization", "password", "secret", "token")
        ):
            raise EtradeQuoteError("QUOTE_DUPLICATE_OR_SECRET_FIELD")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise EtradeQuoteError("QUOTE_NONFINITE_NUMBER")


def _side_time(value: object) -> datetime | None:
    if type(value) is not str or len(value) > 40:
        return None
    match = re.fullmatch(r"(\d{2}:\d{2}:\d{2}) (EST|EDT|PST|PDT) (\d{2}-\d{2}-\d{4})", value)
    if match is None:
        return None
    clock, zone, day = match.groups()
    offsets = {"EST": -5, "EDT": -4, "PST": -8, "PDT": -7}
    try:
        local = datetime.strptime(day + " " + clock, "%m-%d-%Y %H:%M:%S").replace(
            tzinfo=timezone(timedelta(hours=offsets[zone]))
        )
        instant = local.astimezone(UTC)
        region = "America/New_York" if zone in ("EST", "EDT") else "America/Los_Angeles"
        return instant if instant.astimezone(ZoneInfo(region)).tzname() == zone else None
    except ValueError:
        return None


def _price(value: object) -> Decimal | None:
    if value is None:
        return None
    if type(value) is not int and type(value) is not Decimal:
        raise EtradeQuoteError("QUOTE_PRICE_TYPE_INVALID")
    result = Decimal(value)
    # Zero is a documented-unavailable side for this conservative profile.
    return None if result == 0 else result


def parse_etrade_quotes(body: bytes, request: ForwardCaptureRequest) -> tuple[ForwardQuote, ...]:
    """Product/ALL schema only. Currency comes from verified request metadata."""
    try:
        if (
            type(body) is not bytes
            or not 0 < len(body) <= min(request.max_response_bytes, MAX_CAPTURE_BYTES)
            or request.kind != "quote"
        ):
            raise EtradeQuoteError("QUOTE_SCOPE_OR_SIZE_INVALID")
        document = json.loads(
            body, object_pairs_hook=_pairs, parse_float=Decimal, parse_constant=_constant
        )
        if type(document) is not dict or set(document) != {"QuoteResponse"}:
            raise EtradeQuoteError("QUOTE_ENVELOPE_UNSUPPORTED")
        response = document["QuoteResponse"]
        if type(response) is not dict or set(response) != {"QuoteData"}:
            raise EtradeQuoteError("QUOTE_COVERAGE_OR_MESSAGES_UNAVAILABLE")
        rows = response["QuoteData"]
        if type(rows) is not list or len(rows) != len(request.instruments):
            raise EtradeQuoteError("QUOTE_COVERAGE_DIFFERS")
        by_symbol = {}
        for row in rows:
            if (
                type(row) is not dict
                or type(row.get("Product")) is not dict
                or type(row.get("All")) is not dict
            ):
                raise EtradeQuoteError("QUOTE_SCHEMA_UNSUPPORTED")
            product = row["Product"]
            symbol = product.get("symbol")
            if (
                type(symbol) is not str
                or product.get("securityType") != "EQ"
                or symbol in by_symbol
            ):
                raise EtradeQuoteError("QUOTE_PRODUCT_IDENTITY_DIFFERS")
            by_symbol[symbol] = row
        if set(by_symbol) != {i.symbol for i in request.instruments}:
            raise EtradeQuoteError("QUOTE_PRODUCT_COVERAGE_DIFFERS")
        result = []
        for instrument in request.instruments:
            row = by_symbol[instrument.symbol]
            sides = row["All"]
            bid_at, ask_at = _side_time(sides.get("bidTime")), _side_time(sides.get("askTime"))
            raw_at = row.get("dateTimeUTC")
            source_at = (
                datetime.fromtimestamp(raw_at, UTC)
                if type(raw_at) is int and 0 <= raw_at < 253402300800
                else None
            )
            status = row.get("quoteStatus")
            delay: Literal["realtime", "delayed", "unknown"] = (
                "realtime"
                if status == "REALTIME"
                else "delayed"
                if status == "DELAYED"
                else "unknown"
            )
            result.append(
                ForwardQuote(
                    instrument.instrument_id,
                    instrument.symbol,
                    request.session,
                    _price(sides.get("bid")),
                    _price(sides.get("ask")),
                    source_at,
                    instrument.currency,
                    delay,
                    bid_at,
                    ask_at,
                    "documented_side_times"
                    if bid_at is not None and ask_at is not None
                    else "unknown",
                )
            )
        return tuple(result)
    except EtradeQuoteError:
        raise
    except (ValueError, TypeError, OverflowError, OSError, RecursionError, KeyError):
        raise EtradeQuoteError("QUOTE_NORMALIZATION_FAILED") from None
