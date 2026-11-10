from __future__ import annotations

import json
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from packages.adapters.market_data.tiingo_eod import (
    TiingoEodError,
    TiingoEodQualificationKind,
    TiingoEodRawBasis,
    TiingoEodResponseObservation,
    TiingoEodScope,
    qualify_tiingo_eod,
)
from packages.market_data import (
    BarInterval,
    ExchangeCalendar,
    ExchangeSession,
    SessionKind,
    VendorBarRecord,
)

PRE_DST_DATE = date(2026, 3, 6)
POST_DST_DATE = date(2026, 3, 9)
HALF_DAY_DATE = date(2026, 11, 27)

PRE_DST_OPEN = datetime(2026, 3, 6, 14, 30, tzinfo=UTC)
PRE_DST_CLOSE = datetime(2026, 3, 6, 21, 0, tzinfo=UTC)
POST_DST_OPEN = datetime(2026, 3, 9, 13, 30, tzinfo=UTC)
POST_DST_CLOSE = datetime(2026, 3, 9, 20, 0, tzinfo=UTC)
HALF_DAY_OPEN = datetime(2026, 11, 27, 14, 30, tzinfo=UTC)
HALF_DAY_CLOSE = datetime(2026, 11, 27, 18, 0, tzinfo=UTC)

REQUESTED_AT = datetime(2026, 11, 30, 14, 0, tzinfo=UTC)
DIA_RECEIVED_AT = datetime(2026, 11, 30, 14, 0, 1, tzinfo=UTC)
SPY_RECEIVED_AT = datetime(2026, 11, 30, 14, 0, 2, tzinfo=UTC)


def calendar(
    *,
    version: str = "test-v1",
    half_day_close: datetime = HALF_DAY_CLOSE,
) -> ExchangeCalendar:
    return ExchangeCalendar(
        calendar_id="US-EQUITIES-test",
        version=version,
        venue="US-EQUITIES",
        timezone="America/New_York",
        sessions=(
            ExchangeSession(
                venue="US-EQUITIES",
                session_label=PRE_DST_DATE,
                opens_at=PRE_DST_OPEN,
                closes_at=PRE_DST_CLOSE,
            ),
            ExchangeSession(
                venue="US-EQUITIES",
                session_label=POST_DST_DATE,
                opens_at=POST_DST_OPEN,
                closes_at=POST_DST_CLOSE,
            ),
            ExchangeSession(
                venue="US-EQUITIES",
                session_label=HALF_DAY_DATE,
                opens_at=HALF_DAY_OPEN,
                closes_at=half_day_close,
                kind=SessionKind.HALF_DAY,
            ),
        ),
    )


def scope(*, symbols: tuple[str, ...] = ("DIA", "SPY")) -> TiingoEodScope:
    return TiingoEodScope(
        symbols=symbols,
        start_date=PRE_DST_DATE,
        end_date=HALF_DAY_DATE,
    )


def provider_row(
    session_label: date,
    *,
    open_price: object = 101.125,
    volume: object = 1_000_001,
) -> dict[str, object]:
    return {
        "date": f"{session_label.isoformat()}T00:00:00.000Z",
        "close": 102.375,
        "high": 103.5,
        "low": 99.875,
        "open": open_price,
        "volume": volume,
        "adjClose": 51.1875,
        "adjHigh": 51.75,
        "adjLow": 49.9375,
        "adjOpen": 50.5625,
        "adjVolume": 2_000_002,
        "divCash": 0.25,
        "splitFactor": 2.0,
    }


def payload(rows: list[dict[str, object]]) -> bytes:
    return json.dumps(rows, separators=(",", ":")).encode("utf-8")


def receipt(
    symbol: str,
    *,
    rows: list[dict[str, object]] | None = None,
    received_at: datetime | None = None,
) -> TiingoEodResponseObservation:
    response_rows = (
        [provider_row(PRE_DST_DATE), provider_row(POST_DST_DATE), provider_row(HALF_DAY_DATE)]
        if rows is None
        else rows
    )
    return TiingoEodResponseObservation(
        symbol=symbol,
        requested_at=REQUESTED_AT,
        received_at=received_at or (DIA_RECEIVED_AT if symbol == "DIA" else SPY_RECEIVED_AT),
        payload=payload(response_rows),
    )


def complete_responses() -> tuple[TiingoEodResponseObservation, ...]:
    return (receipt("DIA"), receipt("SPY"))


def test_response_receipt_hides_paid_payload_from_repr() -> None:
    response = receipt("SPY", rows=[provider_row(PRE_DST_DATE, open_price=987.654321)])

    assert "payload" not in repr(response)
    assert "987.654321" not in repr(response)


def test_qualification_preserves_raw_and_adjusted_fields_without_float_rounding() -> None:
    dataset = qualify_tiingo_eod(
        complete_responses(),
        scope=scope(),
        calendar=calendar(),
    )
    row = next(
        item for item in dataset.rows if item.symbol == "DIA" and item.session_label == PRE_DST_DATE
    )

    assert row.open_price == Decimal("101.125")
    assert row.high_price == Decimal("103.5")
    assert row.low_price == Decimal("99.875")
    assert row.close_price == Decimal("102.375")
    assert row.volume == 1_000_001
    assert row.adjusted_open_price == Decimal("50.5625")
    assert row.adjusted_high_price == Decimal("51.75")
    assert row.adjusted_low_price == Decimal("49.9375")
    assert row.adjusted_close_price == Decimal("51.1875")
    assert row.adjusted_volume == 2_000_002
    assert row.div_cash == Decimal("0.25")
    assert row.split_factor == Decimal("2.0")
    assert row.raw_price_basis is TiingoEodRawBasis.DOCUMENTED_RAW_CANDIDATE
    assert dataset.qualification_kind is TiingoEodQualificationKind.SYNTHETIC_CONTRACT_ONLY


def test_qualification_rejects_duplicate_json_keys() -> None:
    original = payload([provider_row(PRE_DST_DATE)])
    duplicated = original.replace(
        b'"open":101.125',
        b'"open":101.125,"open":999.0',
        1,
    )
    response = TiingoEodResponseObservation(
        symbol="SPY",
        requested_at=REQUESTED_AT,
        received_at=SPY_RECEIVED_AT,
        payload=duplicated,
    )

    with pytest.raises(TiingoEodError, match="duplicate JSON key"):
        qualify_tiingo_eod(
            (response,),
            scope=TiingoEodScope(
                symbols=("SPY",),
                start_date=PRE_DST_DATE,
                end_date=PRE_DST_DATE,
            ),
            calendar=ExchangeCalendar(
                calendar_id="US-EQUITIES-test",
                version="test-v1",
                venue="US-EQUITIES",
                timezone="America/New_York",
                sessions=calendar().sessions[:1],
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "missing fields"),
        ("unknown", "unknown fields"),
    ],
)
def test_qualification_requires_the_exact_tiingo_eod_fields(
    mutation: str,
    message: str,
) -> None:
    row = provider_row(PRE_DST_DATE)
    if mutation == "missing":
        del row["adjClose"]
    else:
        row["providerSurprise"] = 1

    with pytest.raises(TiingoEodError, match=message):
        qualify_tiingo_eod(
            (receipt("SPY", rows=[row]),),
            scope=TiingoEodScope(
                symbols=("SPY",),
                start_date=PRE_DST_DATE,
                end_date=PRE_DST_DATE,
            ),
            calendar=ExchangeCalendar(
                calendar_id="US-EQUITIES-test",
                version="test-v1",
                venue="US-EQUITIES",
                timezone="America/New_York",
                sessions=calendar().sessions[:1],
            ),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("open", "101.125", "open"),
        ("open", None, "open"),
        ("open", float("inf"), r"open|finite|JSON"),
        ("volume", 1_000_001.0, "volume"),
        ("volume", True, "volume"),
        ("volume", 9_223_372_036_854_775_808, "volume"),
        ("adjVolume", 2_000_002.0, "adjVolume"),
        ("adjVolume", "2000002", "adjVolume"),
        ("adjVolume", 9_223_372_036_854_775_808, "adjVolume"),
        ("divCash", -0.01, "divCash"),
        ("splitFactor", 0.0, "splitFactor"),
    ],
)
def test_qualification_validates_decimal_and_integer_fields_strictly(
    field: str,
    value: object,
    message: str,
) -> None:
    row = provider_row(PRE_DST_DATE)
    row[field] = value

    with pytest.raises(TiingoEodError, match=message):
        qualify_tiingo_eod(
            (receipt("SPY", rows=[row]),),
            scope=TiingoEodScope(
                symbols=("SPY",),
                start_date=PRE_DST_DATE,
                end_date=PRE_DST_DATE,
            ),
            calendar=ExchangeCalendar(
                calendar_id="US-EQUITIES-test",
                version="test-v1",
                venue="US-EQUITIES",
                timezone="America/New_York",
                sessions=calendar().sessions[:1],
            ),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("low", 101.5, "low"),
        ("high", 101.0, "high"),
        ("adjLow", 51.0, "adjusted low"),
        ("adjHigh", 50.0, "adjusted high"),
    ],
)
def test_qualification_validates_raw_and_adjusted_ohlc_relationships(
    field: str,
    value: object,
    message: str,
) -> None:
    row = provider_row(PRE_DST_DATE)
    row[field] = value

    with pytest.raises(TiingoEodError, match=message):
        qualify_tiingo_eod(
            (receipt("SPY", rows=[row]),),
            scope=TiingoEodScope(
                symbols=("SPY",),
                start_date=PRE_DST_DATE,
                end_date=PRE_DST_DATE,
            ),
            calendar=ExchangeCalendar(
                calendar_id="US-EQUITIES-test",
                version="test-v1",
                venue="US-EQUITIES",
                timezone="America/New_York",
                sessions=calendar().sessions[:1],
            ),
        )


def test_qualification_requires_every_symbol_for_every_scoped_session() -> None:
    incomplete_spy = receipt(
        "SPY",
        rows=[provider_row(PRE_DST_DATE), provider_row(HALF_DAY_DATE)],
    )

    with pytest.raises(
        TiingoEodError,
        match=r"coverage.*SPY.*2026-03-09",
    ):
        qualify_tiingo_eod(
            (receipt("DIA"), incomplete_spy),
            scope=scope(),
            calendar=calendar(),
        )


def test_qualification_maps_dates_to_regular_half_day_and_dst_session_bounds() -> None:
    dataset = qualify_tiingo_eod(
        complete_responses(),
        scope=scope(),
        calendar=calendar(),
    )
    spy = {row.session_label: row for row in dataset.rows if row.symbol == "SPY"}

    assert spy[PRE_DST_DATE].interval is BarInterval.ONE_DAY
    assert (spy[PRE_DST_DATE].interval_start, spy[PRE_DST_DATE].interval_end) == (
        PRE_DST_OPEN,
        PRE_DST_CLOSE,
    )
    assert (spy[POST_DST_DATE].interval_start, spy[POST_DST_DATE].interval_end) == (
        POST_DST_OPEN,
        POST_DST_CLOSE,
    )
    assert (spy[HALF_DAY_DATE].interval_start, spy[HALF_DAY_DATE].interval_end) == (
        HALF_DAY_OPEN,
        HALF_DAY_CLOSE,
    )
    assert all(row.observed_at == SPY_RECEIVED_AT for row in spy.values())


def test_calendar_version_and_bounds_are_bound_into_the_semantic_digest() -> None:
    responses = complete_responses()
    baseline = qualify_tiingo_eod(responses, scope=scope(), calendar=calendar())
    changed_version = qualify_tiingo_eod(
        responses,
        scope=scope(),
        calendar=calendar(version="test-v2"),
    )
    changed_bounds = qualify_tiingo_eod(
        responses,
        scope=scope(),
        calendar=calendar(half_day_close=datetime(2026, 11, 27, 17, 0, tzinfo=UTC)),
    )

    assert baseline.response_sha256 == changed_version.response_sha256
    assert baseline.response_sha256 == changed_bounds.response_sha256
    assert baseline.schema_sha256 == changed_version.schema_sha256
    assert baseline.calendar_sha256 != changed_version.calendar_sha256
    assert baseline.calendar_sha256 != changed_bounds.calendar_sha256
    assert baseline.semantic_sha256 != changed_version.semantic_sha256
    assert baseline.semantic_sha256 != changed_bounds.semantic_sha256


def test_non_session_scope_boundaries_are_bound_into_the_semantic_digest() -> None:
    responses = (receipt("SPY", rows=[provider_row(POST_DST_DATE)]),)
    saturday_scope = TiingoEodScope(
        symbols=("SPY",),
        start_date=date(2026, 3, 7),
        end_date=POST_DST_DATE,
    )
    sunday_scope = TiingoEodScope(
        symbols=("SPY",),
        start_date=date(2026, 3, 8),
        end_date=POST_DST_DATE,
    )

    saturday = qualify_tiingo_eod(responses, scope=saturday_scope, calendar=calendar())
    sunday = qualify_tiingo_eod(responses, scope=sunday_scope, calendar=calendar())

    assert saturday.response_sha256 == sunday.response_sha256
    assert saturday.calendar_sha256 == sunday.calendar_sha256
    assert saturday.semantic_sha256 != sunday.semantic_sha256


def test_qualification_order_and_digests_are_deterministic() -> None:
    responses = complete_responses()

    first = qualify_tiingo_eod(responses, scope=scope(), calendar=calendar())
    second = qualify_tiingo_eod(tuple(reversed(responses)), scope=scope(), calendar=calendar())

    expected_keys = tuple(
        (symbol, session_label)
        for symbol in ("DIA", "SPY")
        for session_label in (PRE_DST_DATE, POST_DST_DATE, HALF_DAY_DATE)
    )
    assert tuple((row.symbol, row.session_label) for row in first.rows) == expected_keys
    assert first.rows == second.rows
    assert first.response_sha256 == second.response_sha256
    assert first.schema_sha256 == second.schema_sha256
    assert first.calendar_sha256 == second.calendar_sha256
    assert first.semantic_sha256 == second.semantic_sha256
    assert all(
        len(digest) == 64
        for digest in (
            first.response_sha256,
            first.schema_sha256,
            first.calendar_sha256,
            first.semantic_sha256,
        )
    )


def test_qualification_cannot_emit_execution_lane_records() -> None:
    dataset = qualify_tiingo_eod(
        complete_responses(),
        scope=scope(),
        calendar=calendar(),
    )

    assert all(not isinstance(row, VendorBarRecord) for row in dataset.rows)
    with pytest.raises(TiingoEodError, match=r"publication|revision|VendorBarRecord"):
        dataset.raw_bar_records()
    with pytest.raises(TiingoEodError, match=r"synthetic|admission|trading"):
        dataset.admission_evidence()


def test_qualification_rejects_duplicate_and_out_of_scope_session_dates() -> None:
    duplicate = receipt(
        "SPY",
        rows=[provider_row(PRE_DST_DATE), provider_row(PRE_DST_DATE)],
    )
    one_day_scope = TiingoEodScope(
        symbols=("SPY",),
        start_date=PRE_DST_DATE,
        end_date=PRE_DST_DATE,
    )
    one_day_calendar = ExchangeCalendar(
        calendar_id="US-EQUITIES-test",
        version="test-v1",
        venue="US-EQUITIES",
        timezone="America/New_York",
        sessions=calendar().sessions[:1],
    )

    with pytest.raises(TiingoEodError, match="duplicate session date"):
        qualify_tiingo_eod((duplicate,), scope=one_day_scope, calendar=one_day_calendar)

    outside = receipt("SPY", rows=[provider_row(POST_DST_DATE)])
    with pytest.raises(TiingoEodError, match="outside the requested date scope"):
        qualify_tiingo_eod((outside,), scope=one_day_scope, calendar=calendar())


@pytest.mark.parametrize(
    "provider_date",
    [
        "2026-03-06T01:00:00Z",
        "2026-03-06T00:00:00-05:00",
        "not-a-date",
    ],
)
def test_qualification_rejects_ambiguous_provider_dates(provider_date: str) -> None:
    row = provider_row(PRE_DST_DATE)
    row["date"] = provider_date

    with pytest.raises(TiingoEodError, match=r"date|midnight|UTC"):
        qualify_tiingo_eod(
            (receipt("SPY", rows=[row]),),
            scope=TiingoEodScope(
                symbols=("SPY",),
                start_date=PRE_DST_DATE,
                end_date=PRE_DST_DATE,
            ),
            calendar=ExchangeCalendar(
                calendar_id="US-EQUITIES-test",
                version="test-v1",
                venue="US-EQUITIES",
                timezone="America/New_York",
                sessions=calendar().sessions[:1],
            ),
        )


def test_qualification_rejects_receipt_before_session_close() -> None:
    response = TiingoEodResponseObservation(
        symbol="SPY",
        requested_at=datetime(2026, 3, 6, 20, 58, tzinfo=UTC),
        received_at=datetime(2026, 3, 6, 20, 59, tzinfo=UTC),
        payload=payload([provider_row(PRE_DST_DATE)]),
    )

    with pytest.raises(TiingoEodError, match="before session close"):
        qualify_tiingo_eod(
            (response,),
            scope=TiingoEodScope(
                symbols=("SPY",),
                start_date=PRE_DST_DATE,
                end_date=PRE_DST_DATE,
            ),
            calendar=ExchangeCalendar(
                calendar_id="US-EQUITIES-test",
                version="test-v1",
                venue="US-EQUITIES",
                timezone="America/New_York",
                sessions=calendar().sessions[:1],
            ),
        )
