"""Pure provider-shaped capture scenarios, never evidence of actual provider access.

All identity, rights, entitlement, currency and clock declarations are synthetic
models. Provider names/environment select existing parsers, not network authority.
The caller supplies pins and separately wires the existing capture collector.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Literal, cast
from zoneinfo import ZoneInfo

from packages.domain.canonical import canonical_decimal_text, canonical_persisted_decimal
from packages.domain.durable_journal_contracts import JournalKey
from packages.domain.engine_contracts import DailyPrice
from packages.domain.forward_capture_contracts import (
    CaptureClockSample,
    CaptureInstrument,
    ForwardCaptureRequest,
)
from packages.domain.forward_contracts import ForwardDataState, ForwardSource
from packages.domain.personal_contracts import (
    VersionPin,
    content_digest,
    require_amount,
    require_text,
    require_utc,
)
from packages.domain.research_dataset import ResearchSession, modeled_daily_availability

type _Symbol = Literal["DIA", "IWM", "QQQ", "SPY"]
type _Kind = Literal["daily", "quote"]

_ASSUMPTIONS = (
    "SYNTHETIC_IDENTITY_RIGHTS_ENTITLEMENT_AND_USD_CURRENCY_MODELS",
    "SYNTHETIC_CLOCK_SAMPLES_NOT_HOST_MEASUREMENTS",
    "PROVIDER_ENVIRONMENT_IS_PARSER_SHAPE_NOT_ACTUAL_SOURCE_PROOF",
    "CALLER_PINS_ARE_DECLARATIONS_NOT_PROVIDER_QUALIFICATION",
    "RECORDED_STATE_RETAINS_SYNTHETIC_OBSERVATIONS_ONLY",
    "NO_NETWORK_OR_EXECUTION_AUTHORITY",
)


@dataclass(frozen=True, slots=True)
class SyntheticCaptureScenario:
    request: ForwardCaptureRequest
    state: ForwardDataState
    clock_samples: tuple[CaptureClockSample, ...]
    body: bytes
    assumptions: tuple[str, ...]


def _number(value: Decimal) -> str:
    require_amount(value, "synthetic price", positive=True)
    return canonical_decimal_text(canonical_persisted_decimal(value, "synthetic price"))


def _samples(start: datetime) -> tuple[CaptureClockSample, ...]:
    return tuple(
        CaptureClockSample(
            start + timedelta(milliseconds=n),
            1_000_000_000 + n * 1_000_000,
            "synthetic-capture-clock-model/1",
        )
        for n in (0, 100, 200)
    )


def _request(
    *,
    kind: _Kind,
    instrument_id: str,
    symbol: str,
    session: ResearchSession,
    capture_id: str,
    account_scope: str,
    calendar_pin: VersionPin,
    producer_pin: VersionPin,
    evidence_class: str,
    window_end: datetime,
) -> ForwardCaptureRequest:
    if type(evidence_class) is not str or evidence_class != "synthetic_fixture":
        raise ValueError("scenario requires synthetic_fixture evidence")
    if type(session) is not ResearchSession:
        raise ValueError("scenario requires an exact synthetic research session")
    session.__post_init__()
    if session.venue != "SYNTHETIC":
        raise ValueError("scenario requires an explicitly synthetic calendar")
    if type(symbol) is not str or symbol not in ("DIA", "IWM", "QQQ", "SPY"):
        raise ValueError("scenario instrument exceeds the personal universe")
    require_text(instrument_id, "synthetic instrument")
    require_text(account_scope, "synthetic account scope")
    for pin in (calendar_pin, producer_pin):
        if type(pin) is not VersionPin:
            raise ValueError("scenario requires explicit calendar and producer pins")
        pin.__post_init__()
    identity = content_digest(
        ("synthetic-capture-identity/1", account_scope, instrument_id, symbol)
    )
    source = ForwardSource(
        source_id=f"synthetic-capture-{kind}-" + identity,
        provider="tiingo" if kind == "daily" else "etrade",
        environment="production",
        account_scope=account_scope,
        identity_reference="synthetic-identity-model/1:" + identity,
        rights_status="allowed",
        rights_reference="synthetic-rights-model/1:not-provider-permission",
        entitlement_status="not_required" if kind == "daily" else "realtime",
        entitlement_reference="synthetic-entitlement-model/1:not-provider-entitlement",
    )
    return ForwardCaptureRequest(
        capture_id=capture_id,
        source=source,
        kind=kind,
        instruments=(
            CaptureInstrument(
                instrument_id,
                cast(_Symbol, symbol),
                "USD",
                "synthetic-instrument-USD-model/1:" + identity,
            ),
        ),
        session=session.session_label,
        session_open=session.opens_at,
        session_close=session.closes_at,
        window_start=session.closes_at if kind == "daily" else session.opens_at,
        window_end=window_end,
        calendar=calendar_pin,
        producer=producer_pin,
        journal_key=JournalKey(
            "capture",
            f"synthetic-capture-{kind}/1",
            account_scope,
            source.provider,
            source.environment,
            source.semantic_sha256,
        ),
        evidence_class="synthetic_fixture",
    )


def _scenario(
    request: ForwardCaptureRequest,
    samples: tuple[CaptureClockSample, ...],
    body: bytes,
    assumptions: tuple[str, ...],
) -> SyntheticCaptureScenario:
    if not 0 < len(body) <= request.max_response_bytes:
        raise ValueError("synthetic response exceeds the capture byte bound")
    if not request.window_start <= samples[0].at <= samples[-1].at < request.window_end:
        raise ValueError("synthetic samples exceed the capture window")
    return SyntheticCaptureScenario(
        request,
        ForwardDataState((request.source,), "recorded"),
        samples,
        body,
        _ASSUMPTIONS + assumptions,
    )


def synthetic_daily_capture_scenario(
    *,
    price: DailyPrice,
    session: ResearchSession,
    capture_id: str,
    account_scope: str,
    calendar_pin: VersionPin,
    producer_pin: VersionPin,
    evidence_class: Literal["synthetic_fixture"],
) -> SyntheticCaptureScenario:
    """Declare modeled receipt stages ending at the existing daily availability time.

    High/low are synthetic open/close bounds and volumes are zero. Only S3.1's
    unadjusted, action-free first observations are supported; no adjustment or
    historical revision model is inferred.
    """
    if type(price) is not DailyPrice or type(session) is not ResearchSession:
        raise ValueError("daily scenario requires exact price and research session values")
    price.__post_init__()
    if price.session != session.session_label:
        raise ValueError("synthetic daily price and calendar session differ")
    if price.adjusted_close != price.close_price or price.revision != 1:
        raise ValueError("synthetic daily scenario has no action or revision model")
    available = modeled_daily_availability(session.session_label)
    request = _request(
        kind="daily",
        instrument_id=price.instrument_id,
        symbol=price.symbol,
        session=session,
        capture_id=capture_id,
        account_scope=account_scope,
        calendar_pin=calendar_pin,
        producer_pin=producer_pin,
        evidence_class=evidence_class,
        window_end=available + timedelta(seconds=1),
    )
    high, low = max(price.open_price, price.close_price), min(price.open_price, price.close_price)
    fields = ['"date":' + json.dumps(price.session.isoformat() + "T00:00:00.000Z")]
    fields.extend(
        f'"{name}":{_number(value)}'
        for name, value in (
            ("open", price.open_price),
            ("high", high),
            ("low", low),
            ("close", price.close_price),
            ("adjOpen", price.open_price),
            ("adjHigh", high),
            ("adjLow", low),
            ("adjClose", price.close_price),
        )
    )
    fields.extend(('"volume":0', '"adjVolume":0', '"divCash":0', '"splitFactor":1'))
    body = ("[{" + ",".join(fields) + "}]").encode("ascii")
    return _scenario(
        request,
        _samples(available - timedelta(milliseconds=200)),
        body,
        (
            "DAILY_SYNTHETIC_HIGH_LOW_OPEN_CLOSE_BOUNDS_ZERO_VOLUME_NO_ACTIONS",
            "DAILY_MODELED_RECEIPT_STAGES_END_AT_MODELED_AVAILABILITY",
        ),
    )


def synthetic_quote_capture_scenario(
    *,
    instrument_id: str,
    symbol: _Symbol,
    session: ResearchSession,
    at: datetime,
    bid: Decimal,
    ask: Decimal,
    capture_id: str,
    account_scope: str,
    calendar_pin: VersionPin,
    producer_pin: VersionPin,
    evidence_class: Literal["synthetic_fixture"],
) -> SyntheticCaptureScenario:
    """Declare an in-session, whole-second source quote and three modeled receipt stages."""
    if type(session) is not ResearchSession:
        raise ValueError("quote scenario requires an exact synthetic research session")
    require_utc(at, "synthetic quote source time")
    if at.microsecond or at < datetime(1970, 1, 1, tzinfo=UTC):
        raise ValueError("synthetic quote time requires whole UTC seconds since 1970")
    bid_text, ask_text = _number(bid), _number(ask)
    if bid > ask:
        raise ValueError("synthetic quote bid exceeds ask")
    request = _request(
        kind="quote",
        instrument_id=instrument_id,
        symbol=symbol,
        session=session,
        capture_id=capture_id,
        account_scope=account_scope,
        calendar_pin=calendar_pin,
        producer_pin=producer_pin,
        evidence_class=evidence_class,
        window_end=session.closes_at,
    )
    samples = _samples(at)
    epoch = (at - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(seconds=1)
    stamp = at.astimezone(ZoneInfo("America/New_York")).strftime("%H:%M:%S %Z %m-%d-%Y")
    body = (
        '{"QuoteResponse":{"QuoteData":[{"Product":{"symbol":'
        + json.dumps(symbol)
        + ',"securityType":"EQ"},"dateTimeUTC":'
        + str(epoch)
        + ',"quoteStatus":"REALTIME","All":{"bid":'
        + bid_text
        + ',"ask":'
        + ask_text
        + ',"bidTime":'
        + json.dumps(stamp)
        + ',"askTime":'
        + json.dumps(stamp)
        + "}}]}}"
    ).encode("ascii")
    return _scenario(
        request,
        samples,
        body,
        ("QUOTE_PRICES_AND_REALTIME_STATUS_ARE_EXPLICIT_SYNTHETIC_MODELS",),
    )
