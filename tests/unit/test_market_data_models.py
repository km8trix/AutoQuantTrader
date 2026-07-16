from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

import pytest

from packages.market_data import (
    AmbiguousSecurityError,
    AssetClass,
    BarInterval,
    CaptureMode,
    CashDividendTerms,
    CorporateActionRevision,
    CorporateActionType,
    DelistingTerms,
    EntitlementLevel,
    ExchangeCalendar,
    ExchangeSession,
    FeedEntitlement,
    NonTradableSecurityError,
    PriceBasis,
    QualityCode,
    RawBar,
    RevisionConflictError,
    RevisionPolicy,
    Security,
    SecurityIdentifier,
    SecurityMaster,
    SessionKind,
    SplitTerms,
    UniverseMembership,
    UnknownSecurityError,
    VendorBarRecord,
    check_quality,
    normalize_records,
    select_as_of,
)

SESSION_LABEL = date(2026, 7, 15)
SESSION_OPEN = datetime(2026, 7, 15, 13, 30, tzinfo=UTC)


def short_calendar(*, minutes: int = 4) -> ExchangeCalendar:
    return ExchangeCalendar(
        calendar_id="XNYS-test",
        version="2026a-test-v1",
        venue="XNYS",
        timezone="America/New_York",
        sessions=(
            ExchangeSession(
                venue="XNYS",
                session_label=SESSION_LABEL,
                opens_at=SESSION_OPEN,
                closes_at=SESSION_OPEN + timedelta(minutes=minutes),
            ),
        ),
    )


def identifier(
    *,
    observation_id: str = "identifier-spy",
    event_revision_id: str = "identifier-spy-r1",
    security_id: str = "security-spy",
    symbol: str = "SPY",
    venue: str = "XNYS",
    effective_from: datetime = datetime(2020, 1, 1, tzinfo=UTC),
    effective_to: datetime | None = None,
    available_at: datetime = datetime(2020, 1, 1, tzinfo=UTC),
    tradable: bool = True,
    revision: int = 1,
    supersedes_event_revision_id: str | None = None,
) -> SecurityIdentifier:
    return SecurityIdentifier(
        observation_id=observation_id,
        event_revision_id=event_revision_id,
        security_id=security_id,
        source_id="security-master-fixture",
        symbol=symbol,
        venue=venue,
        effective_from=effective_from,
        effective_to=effective_to,
        available_at=available_at,
        tradable=tradable,
        revision=revision,
        supersedes_event_revision_id=supersedes_event_revision_id,
    )


def security_master(
    *,
    identifiers: tuple[SecurityIdentifier, ...] | None = None,
    memberships: tuple[UniverseMembership, ...] = (),
) -> SecurityMaster:
    return SecurityMaster(
        securities=(
            Security(
                security_id="security-spy",
                asset_class=AssetClass.ETF,
                currency="USD",
                name="SPDR S&P 500 ETF Trust",
            ),
        ),
        identifiers=identifiers if identifiers is not None else (identifier(),),
        memberships=memberships,
    )


def vendor_record(
    minute: int = 0,
    *,
    symbol: str = "SPY",
    source_record_id: str | None = None,
    open_price: Decimal = Decimal("100"),
    high_price: Decimal = Decimal("101"),
    low_price: Decimal = Decimal("99"),
    close_price: Decimal = Decimal("100.5"),
    revision: int = 1,
    available_at: datetime | None = None,
    vendor_published_at: datetime | None = None,
    received_at: datetime | None = None,
    ingested_at: datetime | None = None,
    interval_start: datetime | None = None,
    declared_session_label: date | None = SESSION_LABEL,
    observation_key: str | None = None,
) -> VendorBarRecord:
    start = interval_start or SESSION_OPEN + timedelta(minutes=minute)
    end = start + timedelta(minutes=1)
    published = vendor_published_at or end + timedelta(seconds=1)
    received = received_at or published + timedelta(seconds=1)
    ingested = ingested_at or received + timedelta(seconds=1)
    return VendorBarRecord(
        source_id="fixture-feed",
        source_record_id=source_record_id or f"SPY-{minute}-r{revision}",
        source_sequence=minute * 10 + revision,
        symbol=symbol,
        venue="XNYS",
        interval=BarInterval.ONE_MINUTE,
        interval_start=start,
        interval_end=end,
        vendor_published_at=published,
        received_at=received,
        available_at=available_at,
        ingested_at=ingested,
        declared_session_label=declared_session_label,
        observation_key=observation_key,
        open_price=open_price,
        high_price=high_price,
        low_price=low_price,
        close_price=close_price,
        volume=1_000,
        trade_count=100,
        revision=revision,
    )


def normalized_bars(
    *records: VendorBarRecord,
    mode: CaptureMode = CaptureMode.HISTORICAL,
) -> tuple[RawBar, ...]:
    result = normalize_records(
        list(records),
        calendar=short_calendar(),
        security_master=security_master(),
        capture_mode=mode,
    )
    assert result.issues == ()
    return result.bars


def test_exchange_calendar_explicitly_represents_dst_and_half_days() -> None:
    new_york = ZoneInfo("America/New_York")
    calendar = ExchangeCalendar(
        calendar_id="XNYS-2026-sample",
        version="tzdata-2026a",
        venue="XNYS",
        timezone="America/New_York",
        sessions=(
            ExchangeSession(
                venue="XNYS",
                session_label=date(2026, 3, 6),
                opens_at=datetime(2026, 3, 6, 14, 30, tzinfo=UTC),
                closes_at=datetime(2026, 3, 6, 21, 0, tzinfo=UTC),
            ),
            ExchangeSession(
                venue="XNYS",
                session_label=date(2026, 3, 9),
                opens_at=datetime(2026, 3, 9, 13, 30, tzinfo=UTC),
                closes_at=datetime(2026, 3, 9, 20, 0, tzinfo=UTC),
            ),
            ExchangeSession(
                venue="XNYS",
                session_label=date(2026, 7, 3),
                opens_at=datetime(2026, 7, 3, 13, 30, tzinfo=UTC),
                closes_at=datetime(2026, 7, 3, 17, 0, tzinfo=UTC),
                kind=SessionKind.HALF_DAY,
            ),
        ),
    )

    assert calendar.sessions[0].opens_at.astimezone(new_york).hour == 9
    assert calendar.sessions[1].opens_at.astimezone(new_york).hour == 9
    assert calendar.sessions[0].opens_at.hour == 14
    assert calendar.sessions[1].opens_at.hour == 13
    assert len(calendar.sessions[2].expected_starts(BarInterval.ONE_MINUTE)) == 210


def test_calendar_rejects_wrong_local_session_label_and_overlaps() -> None:
    wrong_label = ExchangeSession(
        venue="XNYS",
        session_label=date(2026, 7, 14),
        opens_at=SESSION_OPEN,
        closes_at=SESSION_OPEN + timedelta(minutes=1),
    )
    with pytest.raises(ValueError, match="exchange-local open date"):
        ExchangeCalendar(
            calendar_id="wrong-label",
            version="v1",
            venue="XNYS",
            timezone="America/New_York",
            sessions=(wrong_label,),
        )


def test_raw_bar_is_frozen_utc_raw_and_ohlc_validated() -> None:
    (bar,) = normalized_bars(vendor_record())

    assert bar.price_basis is PriceBasis.RAW
    assert bar.event_time == bar.interval_end
    assert bar.interval_start.tzinfo is UTC
    with pytest.raises(FrozenInstanceError):
        bar.close_price = Decimal("0")  # type: ignore[misc]
    with pytest.raises(ValueError, match="high_price"):
        replace(bar, high_price=Decimal("99.5"))


def test_corporate_action_can_be_known_before_its_future_effective_time() -> None:
    action = CorporateActionRevision(
        observation_id="action-spy-split",
        event_revision_id="action-spy-split-r1",
        security_id="security-spy",
        source_id="fixture-actions",
        source_record_id="split-001",
        action_type=CorporateActionType.SPLIT,
        announced_at=datetime(2026, 7, 1, 12, 0, tzinfo=UTC),
        effective_at=datetime(2026, 7, 20, 13, 30, tzinfo=UTC),
        vendor_published_at=datetime(2026, 7, 1, 12, 1, tzinfo=UTC),
        available_at=datetime(2026, 7, 1, 12, 1, 1, tzinfo=UTC),
        ingested_at=datetime(2026, 7, 1, 12, 2, tzinfo=UTC),
        revision=1,
        terms=SplitTerms(numerator=Decimal("2"), denominator=Decimal("1")),
    )

    assert action.available_at < action.event_time
    with pytest.raises(ValueError, match="type and terms"):
        replace(
            action,
            action_type=CorporateActionType.CASH_DIVIDEND,
            terms=DelistingTerms(reason="test"),
        )
    dividend = replace(
        action,
        observation_id="action-dividend",
        event_revision_id="action-dividend-r1",
        action_type=CorporateActionType.CASH_DIVIDEND,
        terms=CashDividendTerms(amount=Decimal("1.25"), currency="USD"),
    )
    assert isinstance(dividend.terms, CashDividendTerms)
    assert dividend.terms.amount == Decimal("1.25")


def test_feed_entitlement_is_effective_dated_and_digest_pinned() -> None:
    entitlement = FeedEntitlement(
        entitlement_id="entitlement-sip-historical",
        source_id="fixture-feed",
        feed="SIP",
        level=EntitlementLevel.HISTORICAL,
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=datetime(2027, 1, 1, tzinfo=UTC),
        recorded_at=datetime(2026, 1, 1, tzinfo=UTC),
        terms_sha256="a" * 64,
    )

    assert entitlement.is_effective_at(datetime(2026, 7, 15, tzinfo=UTC))
    assert not entitlement.is_effective_at(datetime(2027, 1, 1, tzinfo=UTC))


def test_security_resolution_uses_effective_and_knowledge_time() -> None:
    old = identifier(
        observation_id="identifier-old-symbol",
        event_revision_id="identifier-old-symbol-r1",
        symbol="OLD",
        effective_to=datetime(2026, 7, 1, tzinfo=UTC),
    )
    new = identifier(
        observation_id="identifier-new-symbol",
        event_revision_id="identifier-new-symbol-r1",
        symbol="SPY",
        effective_from=datetime(2026, 7, 1, tzinfo=UTC),
        available_at=datetime(2026, 6, 15, tzinfo=UTC),
    )
    master = security_master(identifiers=(old, new))

    historical = master.resolve_security(
        symbol="OLD",
        venue="XNYS",
        effective_at=datetime(2026, 6, 30, 15, 0, tzinfo=UTC),
        as_of=datetime(2026, 6, 30, 15, 0, tzinfo=UTC),
    )
    current = master.resolve_security(
        symbol="SPY",
        venue="XNYS",
        effective_at=datetime(2026, 7, 1, 15, 0, tzinfo=UTC),
        as_of=datetime(2026, 7, 1, 15, 0, tzinfo=UTC),
    )

    assert historical.security_id == current.security_id == "security-spy"
    with pytest.raises(UnknownSecurityError):
        master.resolve_security(
            symbol="OLD",
            venue="XNYS",
            effective_at=datetime(2026, 7, 1, 15, 0, tzinfo=UTC),
            as_of=datetime(2026, 7, 1, 15, 0, tzinfo=UTC),
        )


def test_security_identifier_correction_is_applied_only_when_available() -> None:
    first_seen = identifier()
    corrected = identifier(
        event_revision_id="identifier-spy-r2",
        available_at=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        tradable=False,
        revision=2,
        supersedes_event_revision_id=first_seen.event_revision_id,
    )
    master = security_master(identifiers=(first_seen, corrected))

    assert (
        master.resolve_security(
            symbol="SPY",
            venue="XNYS",
            effective_at=SESSION_OPEN,
            as_of=datetime(2026, 7, 15, 13, 31, tzinfo=UTC),
        ).security_id
        == "security-spy"
    )
    with pytest.raises(NonTradableSecurityError):
        master.resolve_security(
            symbol="SPY",
            venue="XNYS",
            effective_at=SESSION_OPEN,
            as_of=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        )
    assert (
        master.resolve_security(
            symbol="SPY",
            venue="XNYS",
            effective_at=SESSION_OPEN,
            as_of=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
            policy=RevisionPolicy.FIRST_SEEN,
        ).security_id
        == "security-spy"
    )


def test_delisted_and_nontradable_security_remains_historically_resolvable() -> None:
    delisted_at = datetime(2026, 7, 10, tzinfo=UTC)
    listed = identifier(effective_to=delisted_at)
    nontradable = identifier(
        observation_id="identifier-spy-nontradable",
        event_revision_id="identifier-spy-nontradable-r1",
        effective_from=delisted_at,
        tradable=False,
    )
    master = security_master(identifiers=(listed, nontradable))

    assert (
        master.resolve_security(
            symbol="SPY",
            venue="XNYS",
            effective_at=datetime(2026, 7, 9, 15, 0, tzinfo=UTC),
            as_of=datetime(2026, 7, 9, 15, 0, tzinfo=UTC),
        ).security_id
        == "security-spy"
    )
    with pytest.raises(NonTradableSecurityError):
        master.resolve_security(
            symbol="SPY",
            venue="XNYS",
            effective_at=datetime(2026, 7, 10, 15, 0, tzinfo=UTC),
            as_of=datetime(2026, 7, 10, 15, 0, tzinfo=UTC),
        )


def test_universe_membership_is_point_in_time_and_survivorship_safe() -> None:
    removed_at = datetime(2026, 7, 10, tzinfo=UTC)
    membership = UniverseMembership(
        observation_id="membership-liquid-etfs-spy",
        event_revision_id="membership-liquid-etfs-spy-r1",
        universe_id="liquid-etfs",
        security_id="security-spy",
        effective_from=datetime(2020, 1, 1, tzinfo=UTC),
        effective_to=removed_at,
        available_at=datetime(2020, 1, 1, tzinfo=UTC),
        included=True,
        revision=1,
    )
    master = security_master(memberships=(membership,))

    before = master.universe_members(
        universe_id="liquid-etfs",
        effective_at=datetime(2026, 7, 9, tzinfo=UTC),
        as_of=datetime(2026, 7, 9, tzinfo=UTC),
    )
    after = master.universe_members(
        universe_id="liquid-etfs",
        effective_at=datetime(2026, 7, 10, tzinfo=UTC),
        as_of=datetime(2026, 7, 10, tzinfo=UTC),
    )

    assert [security.security_id for security in before] == ["security-spy"]
    assert after == ()


def test_security_resolution_fails_closed_on_ambiguous_active_mappings() -> None:
    duplicate = identifier(
        observation_id="duplicate-identifier",
        event_revision_id="duplicate-identifier-r1",
    )
    master = security_master(identifiers=(identifier(), duplicate))

    with pytest.raises(AmbiguousSecurityError):
        master.resolve_security(
            symbol="SPY",
            venue="XNYS",
            effective_at=SESSION_OPEN,
            as_of=SESSION_OPEN,
        )


def test_normalization_converts_aware_source_times_to_utc_and_is_deterministic() -> None:
    new_york = ZoneInfo("America/New_York")
    local_start = SESSION_OPEN.astimezone(new_york)
    record = vendor_record(
        interval_start=local_start,
        vendor_published_at=(local_start + timedelta(minutes=1, seconds=1)),
        received_at=(local_start + timedelta(minutes=1, seconds=2)),
        ingested_at=(local_start + timedelta(minutes=1, seconds=3)),
    )
    assert record.received_at is not None
    assert record.ingested_at is not None
    retry_record = replace(
        record,
        received_at=record.received_at + timedelta(seconds=5),
        ingested_at=record.ingested_at + timedelta(seconds=5),
    )

    first = normalize_records(
        [record],
        calendar=short_calendar(),
        security_master=security_master(),
    )
    retry = normalize_records(
        [retry_record],
        calendar=short_calendar(),
        security_master=security_master(),
    )

    assert first.publishable
    assert first.bars[0].interval_start == SESSION_OPEN
    assert first.bars[0].interval_start.tzinfo is UTC
    assert first.bars[0].event_revision_id == retry.bars[0].event_revision_id
    assert first.bars[0].payload_sha256 == retry.bars[0].payload_sha256


def test_live_normalization_uses_receipt_time_as_causal_availability() -> None:
    record = vendor_record()
    result = normalize_records(
        [record],
        calendar=short_calendar(),
        security_master=security_master(),
        capture_mode=CaptureMode.LIVE,
    )

    assert result.bars[0].available_at == record.received_at
    assert result.bars[0].capture_mode is CaptureMode.LIVE


@pytest.mark.parametrize(
    ("record", "expected_code"),
    [
        (
            vendor_record(interval_start=datetime(2026, 7, 15, 9, 30)),
            QualityCode.TIMEZONE_INVALID,
        ),
        (
            vendor_record(high_price=Decimal("99")),
            QualityCode.OHLC_INVALID,
        ),
        (
            vendor_record(interval_start=SESSION_OPEN - timedelta(minutes=1)),
            QualityCode.SESSION_MISMATCH,
        ),
        (
            vendor_record(declared_session_label=date(2026, 7, 14)),
            QualityCode.SESSION_MISMATCH,
        ),
    ],
)
def test_normalization_quarantines_structurally_invalid_records(
    record: VendorBarRecord,
    expected_code: QualityCode,
) -> None:
    result = normalize_records(
        [record],
        calendar=short_calendar(),
        security_master=security_master(),
    )

    assert result.bars == ()
    assert result.rejected_records == 1
    assert not result.publishable
    assert {issue.code for issue in result.issues} == {expected_code}


def test_normalization_rejects_unknown_and_nontradable_identifiers() -> None:
    unknown = normalize_records(
        [vendor_record(symbol="QQQ")],
        calendar=short_calendar(),
        security_master=security_master(),
    )
    nontradable = normalize_records(
        [vendor_record()],
        calendar=short_calendar(),
        security_master=security_master(
            identifiers=(identifier(tradable=False),),
        ),
    )

    assert [issue.code for issue in unknown.issues] == [QualityCode.UNKNOWN_SECURITY]
    assert [issue.code for issue in nontradable.issues] == [QualityCode.NON_TRADABLE]


def test_correction_is_invisible_before_availability_and_first_seen_never_changes() -> None:
    first_record = vendor_record(
        observation_key="spy-09:30",
        available_at=datetime(2026, 7, 15, 13, 31, 1, tzinfo=UTC),
    )
    correction = vendor_record(
        source_record_id="SPY-0-correction",
        observation_key="spy-09:30",
        revision=2,
        close_price=Decimal("100.75"),
        vendor_published_at=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        available_at=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        received_at=datetime(2026, 7, 15, 13, 32, 1, tzinfo=UTC),
        ingested_at=datetime(2026, 7, 15, 13, 32, 2, tzinfo=UTC),
    )
    first, revised = normalized_bars(first_record, correction)

    before = select_as_of(
        (first, revised),
        as_of=datetime(2026, 7, 15, 13, 31, 59, tzinfo=UTC),
        policy=RevisionPolicy.REVISED_AS_OF,
    )
    at_boundary = select_as_of(
        (first, revised),
        as_of=datetime(2026, 7, 15, 13, 32, tzinfo=UTC),
        policy=RevisionPolicy.REVISED_AS_OF,
    )
    first_seen = select_as_of(
        (first, revised),
        as_of=datetime(2026, 7, 15, 14, 0, tzinfo=UTC),
        policy=RevisionPolicy.FIRST_SEEN,
    )

    assert before == (first,)
    assert at_boundary == (revised,)
    assert first_seen == (first,)
    assert revised.supersedes_event_revision_id == first.event_revision_id


def test_causal_selection_fails_closed_on_same_revision_conflict() -> None:
    (bar,) = normalized_bars(vendor_record())
    conflict = replace(
        bar,
        event_revision_id="conflicting-event-revision",
        payload_sha256="b" * 64,
    )

    with pytest.raises(RevisionConflictError):
        select_as_of(
            (bar, conflict),
            as_of=bar.available_at,
            policy=RevisionPolicy.REVISED_AS_OF,
        )


def test_quality_detects_partial_range_gaps_without_requiring_full_session() -> None:
    bars = normalized_bars(vendor_record(0), vendor_record(2), vendor_record(3))

    issues = check_quality(
        bars,
        calendar=short_calendar(),
        as_of=bars[-1].available_at,
        stale_after=timedelta(minutes=30),
    )

    gaps = [issue for issue in issues if issue.code is QualityCode.GAP]
    assert len(gaps) == 1
    assert dict(gaps[0].details)["count"] == "1"


def test_explicit_session_scope_detects_trailing_bars_and_wholly_missing_session() -> None:
    (bar,) = normalized_bars(vendor_record(0))

    issues = check_quality(
        (bar,),
        calendar=short_calendar(),
        as_of=bar.available_at,
        stale_after=timedelta(minutes=30),
        expected_session_labels=(SESSION_LABEL,),
    )

    gap = next(issue for issue in issues if issue.code is QualityCode.GAP)
    assert dict(gap.details)["count"] == "3"


def test_explicit_session_scope_detects_an_entire_missing_session() -> None:
    next_label = date(2026, 7, 16)
    next_open = datetime(2026, 7, 16, 13, 30, tzinfo=UTC)
    calendar = ExchangeCalendar(
        calendar_id="XNYS-two-days",
        version="v1",
        venue="XNYS",
        timezone="America/New_York",
        sessions=(
            short_calendar().sessions[0],
            ExchangeSession(
                venue="XNYS",
                session_label=next_label,
                opens_at=next_open,
                closes_at=next_open + timedelta(minutes=4),
            ),
        ),
    )
    (bar,) = normalized_bars(vendor_record(0))

    issues = check_quality(
        (bar,),
        calendar=calendar,
        as_of=bar.available_at,
        stale_after=timedelta(minutes=30),
        expected_session_labels=(next_label,),
    )

    gap = next(
        issue
        for issue in issues
        if issue.code is QualityCode.GAP and issue.session_label == next_label
    )
    assert gap.session_label == next_label
    assert dict(gap.details)["count"] == "4"


def test_quality_detects_duplicates_staleness_extreme_returns_and_revision_errors() -> None:
    first, extreme = normalized_bars(
        vendor_record(0),
        vendor_record(
            1,
            open_price=Decimal("100"),
            high_price=Decimal("201"),
            low_price=Decimal("99"),
            close_price=Decimal("200"),
        ),
    )
    skipped_revision = replace(
        first,
        event_revision_id="skipped-revision-r3",
        payload_sha256="c" * 64,
        revision=3,
        supersedes_event_revision_id="missing-r2",
        available_at=first.available_at + timedelta(seconds=1),
    )
    conflict = replace(
        first,
        event_revision_id="same-revision-conflict",
        payload_sha256="d" * 64,
    )

    issues = check_quality(
        (first, first, conflict, skipped_revision, extreme),
        calendar=short_calendar(),
        as_of=extreme.available_at + timedelta(minutes=10),
        stale_after=timedelta(minutes=5),
        extreme_return_threshold=Decimal("0.25"),
    )
    codes = {issue.code for issue in issues}

    assert QualityCode.DUPLICATE in codes
    assert QualityCode.REVISION_CONFLICT in codes
    assert QualityCode.REVISION_SEQUENCE in codes
    assert QualityCode.STALE in codes
    assert QualityCode.EXTREME_RETURN in codes


def test_quality_reports_bar_against_wrong_calendar_session() -> None:
    (bar,) = normalized_bars(vendor_record())
    shifted_calendar = ExchangeCalendar(
        calendar_id="XNYS-shifted",
        version="v1",
        venue="XNYS",
        timezone="America/New_York",
        sessions=(
            ExchangeSession(
                venue="XNYS",
                session_label=SESSION_LABEL,
                opens_at=SESSION_OPEN + timedelta(minutes=1),
                closes_at=SESSION_OPEN + timedelta(minutes=5),
            ),
        ),
    )

    issues = check_quality(
        (bar,),
        calendar=shifted_calendar,
        as_of=bar.available_at,
        stale_after=timedelta(minutes=30),
    )

    assert QualityCode.SESSION_MISMATCH in {issue.code for issue in issues}
