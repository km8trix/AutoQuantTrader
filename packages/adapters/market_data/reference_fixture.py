"""Synthetic Phase 1 reference data used to admit the local ingestion contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal

from packages.domain.identifiers import deterministic_id
from packages.market_data import (
    AssetClass,
    CashDividendTerms,
    CorporateActionRevision,
    CorporateActionType,
    DelistingTerms,
    EntitlementLevel,
    EntitlementStatus,
    ExchangeCalendar,
    ExchangeSession,
    FeedEntitlement,
    HistoricalAdmissionProfile,
    Security,
    SecurityIdentifier,
    SecurityMaster,
    SessionKind,
    SourceKind,
    SplitTerms,
    SymbolChangeTerms,
    UniverseMembership,
)

SOURCE_ID = "synthetic-pit-bars-v1"
SPY_SECURITY_ID = "aqt-security-spy"
RENAMED_SECURITY_ID = "aqt-security-ticker-change"
DELISTED_SECURITY_ID = "aqt-security-delisted"
UNIVERSE_ID = "fixture-liquid-etf-v1"
UNIVERSE_VERSION = "fixture-liquid-etf-2026a"
CALENDAR_VERSION = "xnys-fixture-2026a"
CORPORATE_ACTION_VERSION = "fixture-actions-2026a"
FIXTURE_CAPTURED_AT = datetime(2026, 7, 15, 14, 0, tzinfo=UTC)


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _identifier(
    *,
    security_id: str,
    symbol: str,
    effective_from: str,
    effective_to: str | None,
    available_at: str,
    tradable: bool,
) -> SecurityIdentifier:
    observation_id = deterministic_id(
        "security-identifier",
        SOURCE_ID,
        security_id,
        symbol,
        effective_from,
    )
    return SecurityIdentifier(
        observation_id=observation_id,
        event_revision_id=deterministic_id("security-identifier-revision", observation_id, 1),
        security_id=security_id,
        source_id=SOURCE_ID,
        symbol=symbol,
        venue="XNYS",
        effective_from=_at(effective_from),
        effective_to=None if effective_to is None else _at(effective_to),
        available_at=_at(available_at),
        tradable=tradable,
        revision=1,
    )


def securities() -> tuple[Security, ...]:
    return (
        Security(SPY_SECURITY_ID, AssetClass.ETF, "USD", "Synthetic SPY fixture"),
        Security(
            RENAMED_SECURITY_ID,
            AssetClass.EQUITY,
            "USD",
            "Synthetic ticker-change fixture",
        ),
        Security(
            DELISTED_SECURITY_ID,
            AssetClass.EQUITY,
            "USD",
            "Synthetic delisted fixture",
        ),
    )


def identifiers() -> tuple[SecurityIdentifier, ...]:
    return (
        _identifier(
            security_id=SPY_SECURITY_ID,
            symbol="SPY",
            effective_from="1993-01-29T14:30:00Z",
            effective_to=None,
            available_at="1993-01-29T14:00:00Z",
            tradable=True,
        ),
        _identifier(
            security_id=RENAMED_SECURITY_ID,
            symbol="OLD",
            effective_from="2024-01-02T14:30:00Z",
            effective_to="2025-01-02T14:30:00Z",
            available_at="2024-01-01T12:00:00Z",
            tradable=True,
        ),
        _identifier(
            security_id=RENAMED_SECURITY_ID,
            symbol="NEW",
            effective_from="2025-01-02T14:30:00Z",
            effective_to=None,
            available_at="2024-12-20T12:00:00Z",
            tradable=True,
        ),
        _identifier(
            security_id=DELISTED_SECURITY_ID,
            symbol="DEAD",
            effective_from="2020-01-02T14:30:00Z",
            effective_to="2025-06-30T20:00:00Z",
            available_at="2020-01-01T12:00:00Z",
            tradable=True,
        ),
        _identifier(
            security_id=DELISTED_SECURITY_ID,
            symbol="DEAD",
            effective_from="2025-06-30T20:00:00Z",
            effective_to=None,
            available_at="2025-06-20T12:00:00Z",
            tradable=False,
        ),
    )


def memberships() -> tuple[UniverseMembership, ...]:
    observation_id = deterministic_id("universe-membership", UNIVERSE_ID, SPY_SECURITY_ID)
    return (
        UniverseMembership(
            observation_id=observation_id,
            event_revision_id=deterministic_id("universe-membership-revision", observation_id, 1),
            universe_id=UNIVERSE_ID,
            security_id=SPY_SECURITY_ID,
            effective_from=_at("2026-01-02T14:30:00Z"),
            effective_to=None,
            available_at=_at("2025-12-20T12:00:00Z"),
            included=True,
            revision=1,
        ),
    )


def security_master() -> SecurityMaster:
    return SecurityMaster(
        securities=securities(),
        identifiers=identifiers(),
        memberships=memberships(),
    )


def calendar() -> ExchangeCalendar:
    return ExchangeCalendar(
        calendar_id="XNYS",
        version=CALENDAR_VERSION,
        venue="XNYS",
        timezone="America/New_York",
        sessions=(
            ExchangeSession(
                venue="XNYS",
                session_label=date(2025, 11, 28),
                opens_at=_at("2025-11-28T14:30:00Z"),
                closes_at=_at("2025-11-28T18:00:00Z"),
                kind=SessionKind.HALF_DAY,
            ),
            ExchangeSession(
                venue="XNYS",
                session_label=date(2026, 3, 6),
                opens_at=_at("2026-03-06T14:30:00Z"),
                closes_at=_at("2026-03-06T21:00:00Z"),
            ),
            ExchangeSession(
                venue="XNYS",
                session_label=date(2026, 3, 9),
                opens_at=_at("2026-03-09T13:30:00Z"),
                closes_at=_at("2026-03-09T20:00:00Z"),
            ),
            ExchangeSession(
                venue="XNYS",
                session_label=date(2026, 7, 15),
                opens_at=_at("2026-07-15T13:30:00Z"),
                closes_at=_at("2026-07-15T20:00:00Z"),
            ),
        ),
    )


def _action(
    *,
    action_id: str,
    security_id: str,
    action_type: CorporateActionType,
    announced_at: str,
    effective_at: str,
    terms: object,
) -> CorporateActionRevision:
    observation_id = deterministic_id("corporate-action", SOURCE_ID, action_id)
    return CorporateActionRevision(
        observation_id=observation_id,
        event_revision_id=deterministic_id("corporate-action-revision", observation_id, 1),
        security_id=security_id,
        source_id=SOURCE_ID,
        source_record_id=action_id,
        action_type=action_type,
        announced_at=_at(announced_at),
        effective_at=_at(effective_at),
        vendor_published_at=_at(announced_at),
        available_at=_at(announced_at),
        ingested_at=FIXTURE_CAPTURED_AT,
        revision=1,
        terms=terms,  # type: ignore[arg-type]
    )


def corporate_actions() -> tuple[CorporateActionRevision, ...]:
    return (
        _action(
            action_id="fixture-split",
            security_id=RENAMED_SECURITY_ID,
            action_type=CorporateActionType.SPLIT,
            announced_at="2025-02-14T12:00:00Z",
            effective_at="2025-03-03T14:30:00Z",
            terms=SplitTerms(Decimal("2"), Decimal("1")),
        ),
        _action(
            action_id="fixture-dividend",
            security_id=SPY_SECURITY_ID,
            action_type=CorporateActionType.CASH_DIVIDEND,
            announced_at="2026-06-15T12:00:00Z",
            effective_at="2026-06-30T13:30:00Z",
            terms=CashDividendTerms(Decimal("1.25"), "USD"),
        ),
        _action(
            action_id="fixture-symbol-change",
            security_id=RENAMED_SECURITY_ID,
            action_type=CorporateActionType.SYMBOL_CHANGE,
            announced_at="2024-12-20T12:00:00Z",
            effective_at="2025-01-02T14:30:00Z",
            terms=SymbolChangeTerms("NEW", "XNYS"),
        ),
        _action(
            action_id="fixture-delisting",
            security_id=DELISTED_SECURITY_ID,
            action_type=CorporateActionType.DELISTING,
            announced_at="2025-06-20T12:00:00Z",
            effective_at="2025-06-30T20:00:00Z",
            terms=DelistingTerms("Synthetic lifecycle fixture"),
        ),
    )


def entitlement() -> FeedEntitlement:
    return FeedEntitlement(
        entitlement_id="fixture-entitlement-v1",
        source_id=SOURCE_ID,
        feed="synthetic-recorded-jsonl",
        level=EntitlementLevel.HISTORICAL,
        effective_from=_at("2026-01-01T00:00:00Z"),
        effective_to=None,
        recorded_at=FIXTURE_CAPTURED_AT,
        terms_sha256="9be3c2453ee4f8097d23edb773b14e4fe3ce5dc296b5888fd66ac8c83f2b2c0f",
    )


def admission_profile() -> HistoricalAdmissionProfile:
    """Permanent unqualified metadata for the repository-owned fixture."""

    return HistoricalAdmissionProfile(
        source_id=SOURCE_ID,
        source_name="Synthetic point-in-time bars",
        provider="AutoQuantTrader",
        dataset="phase1-contract-fixture",
        feed="recorded-jsonl",
        adapter_type="recorded_jsonl",
        identifier_authority="autoquant-synthetic-v1",
        kind=SourceKind.SYNTHETIC_FIXTURE,
        licensed=False,
        detail="Checked-in synthetic admission data; not licensed or live market data.",
        captured_at=FIXTURE_CAPTURED_AT,
        coverage_start=_at("2026-07-15T13:30:00Z"),
        coverage_end=_at("2026-07-15T13:34:00Z"),
        required_symbols=("SPY",),
        manifest_name="Synthetic SPY point-in-time fixture",
        universe_version=UNIVERSE_VERSION,
        universe_name="Synthetic liquid ETF fixture",
        corporate_action_version=CORPORATE_ACTION_VERSION,
        corporate_action_set_name="Synthetic corporate-action fixture",
        tzdata_version="system-zoneinfo-2026a-fixture",
        entitlement_status=EntitlementStatus.FIXTURE_ONLY,
        entitlement_scope="Synthetic records for local contract testing only",
    )


@dataclass(frozen=True, slots=True)
class ReferenceFixture:
    security_master: SecurityMaster
    calendar: ExchangeCalendar
    corporate_actions: tuple[CorporateActionRevision, ...]
    entitlement: FeedEntitlement


def reference_fixture() -> ReferenceFixture:
    return ReferenceFixture(
        security_master=security_master(),
        calendar=calendar(),
        corporate_actions=corporate_actions(),
        entitlement=entitlement(),
    )
