"""Bounded offline admission of owner-supplied Tiingo daily JSON exports."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_RESPONSE_BYTES,
    TiingoEodError,
    TiingoEodScope,
    _boolean,
    _contract_rows,
    _datetime,
    _fields,
    _json,
    _object,
    _text,
)
from packages.adapters.market_data.tiingo_eod_calendar import _array
from packages.domain.research_dataset import (
    DailyResearchBar,
    ResearchCalendar,
    ResearchDataset,
    ResearchDatasetManifest,
    ResearchRawObject,
    ResearchSession,
    modeled_daily_availability,
)
from packages.market_data import ExchangeCalendar

IMPORT_DECLARATION_VERSION = "tiingo-eod-owner-import-declaration-v1"


@dataclass(frozen=True, slots=True)
class TiingoImportDeclaration:
    """Owner review bound to exact input bytes; no requested output-class switch."""

    source_kind: str
    rights_reference: str
    provenance_reference: str
    reviewer_id: str
    reviewed_at: datetime
    identity_reference: str
    calendar_reference: str
    tzdata_version: str
    scope: TiingoEodScope
    instruments: tuple[tuple[str, str], ...]
    raw_object_hashes: tuple[tuple[str, str], ...]
    local_research_permitted: bool
    captures: tuple[tuple[str, datetime | None, str | None], ...]

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> TiingoImportDeclaration:
        if len(payload) > 1_048_576:
            raise TiingoEodError("declaration exceeds the 1 MiB limit")
        return cls.from_dict(_json(payload))

    @classmethod
    def from_dict(cls, value: object) -> TiingoImportDeclaration:
        payload = _object(value, "declaration")
        _fields(
            payload,
            {
                "schema_version",
                "source_kind",
                "rights_reference",
                "provenance_reference",
                "reviewer_id",
                "reviewed_at",
                "identity_reference",
                "calendar_reference",
                "tzdata_version",
                "scope",
                "instruments",
                "local_research_permitted",
            },
            "declaration",
        )
        if payload["schema_version"] != IMPORT_DECLARATION_VERSION:
            raise TiingoEodError("unsupported import declaration version")
        instruments: list[tuple[str, str]] = []
        hashes: list[tuple[str, str]] = []
        captures: list[tuple[str, datetime | None, str | None]] = []
        for item in _array(payload["instruments"], "instruments"):
            instrument = _object(item, "instrument")
            _fields(
                instrument,
                {
                    "symbol",
                    "instrument_id",
                    "source_sha256",
                    "observed_available_at",
                    "capture_reference",
                },
                "instrument",
            )
            symbol = _text(instrument["symbol"], "symbol")
            instruments.append((symbol, _text(instrument["instrument_id"], "instrument_id")))
            hashes.append((symbol, _text(instrument["source_sha256"], "source_sha256")))
            captured_at = instrument["observed_available_at"]
            reference = instrument["capture_reference"]
            captures.append(
                (
                    symbol,
                    None
                    if captured_at is None
                    else _datetime(captured_at, "observed_available_at"),
                    None if reference is None else _text(reference, "capture_reference"),
                )
            )
        return cls(
            source_kind=_text(payload["source_kind"], "source_kind"),
            rights_reference=_text(payload["rights_reference"], "rights_reference"),
            provenance_reference=_text(payload["provenance_reference"], "provenance_reference"),
            reviewer_id=_text(payload["reviewer_id"], "reviewer_id"),
            reviewed_at=_datetime(payload["reviewed_at"], "reviewed_at"),
            identity_reference=_text(payload["identity_reference"], "identity_reference"),
            calendar_reference=_text(payload["calendar_reference"], "calendar_reference"),
            tzdata_version=_text(payload["tzdata_version"], "tzdata_version"),
            scope=TiingoEodScope.from_dict(payload["scope"]),
            instruments=tuple(instruments),
            raw_object_hashes=tuple(hashes),
            local_research_permitted=_boolean(
                payload["local_research_permitted"], "local_research_permitted"
            ),
            captures=tuple(captures),
        )

    def __post_init__(self) -> None:
        if self.local_research_permitted is not True:
            raise TiingoEodError("local research rights require an explicit owner declaration")
        if (
            tuple(symbol for symbol, _ in self.instruments) != self.scope.symbols
            or tuple(symbol for symbol, _ in self.raw_object_hashes) != self.scope.symbols
        ):
            raise TiingoEodError("reviewed identities and hashes must exactly cover sorted scope")
        if tuple(symbol for symbol, _, _ in self.captures) != self.scope.symbols:
            raise TiingoEodError("capture declarations must exactly cover sorted scope")


def parse_tiingo_research_dataset(
    *,
    declaration: TiingoImportDeclaration,
    calendar: ExchangeCalendar,
    raw_objects: tuple[ResearchRawObject, ...],
    imported_at: datetime,
) -> ResearchDataset:
    """Reuse the strict Tiingo economics parser without inventing a capture receipt."""

    if tuple((raw.symbol, raw.sha256) for raw in raw_objects) != declaration.raw_object_hashes:
        raise TiingoEodError("source bytes do not match the owner-reviewed hash bindings")
    if (
        tuple((raw.symbol, raw.observed_available_at, raw.capture_reference) for raw in raw_objects)
        != declaration.captures
    ):
        raise TiingoEodError("source receipt metadata differs from its reviewed declaration")
    identities = dict(declaration.instruments)
    sessions = {session.session_label: session for session in calendar.sessions}
    rows: list[DailyResearchBar] = []
    for raw in raw_objects:
        for parsed in _contract_rows(raw.payload, scope=declaration.scope):
            session = sessions.get(parsed.trading_date)
            if session is None:
                raise TiingoEodError("source row has no declared calendar session")
            if parsed.split_factor != 1:
                raise TiingoEodError(
                    "split-affected scope excluded: fractional cash-in-lieu is unsupported"
                )
            rows.append(
                DailyResearchBar(
                    instrument_id=identities[raw.symbol],
                    symbol=raw.symbol,
                    session_label=parsed.trading_date,
                    interval_start=session.opens_at,
                    interval_end=session.closes_at,
                    open_price=parsed.open_price,
                    high_price=parsed.high_price,
                    low_price=parsed.low_price,
                    close_price=parsed.close_price,
                    volume=parsed.volume,
                    adjusted_open_price=parsed.adjusted_open_price,
                    adjusted_high_price=parsed.adjusted_high_price,
                    adjusted_low_price=parsed.adjusted_low_price,
                    adjusted_close_price=parsed.adjusted_close_price,
                    adjusted_volume=parsed.adjusted_volume,
                    div_cash=parsed.div_cash,
                    split_factor=parsed.split_factor,
                    raw_object_sha256=raw.sha256,
                    simulated_available_at=modeled_daily_availability(parsed.trading_date),
                    observed_available_at=raw.observed_available_at,
                    observation_evidence_reference=raw.capture_reference,
                    factual_time_unknown_reason=(
                        "tiingo-row-has-no-vendor-publication;local-receipt-in-capture-reference"
                        if raw.observed_available_at is not None
                        else "owner-export-has-no-publication-or-capture-evidence"
                    ),
                )
            )
    exclusions = {
        "no-historical-pit",
        "no-execution-time-quotes",
        "fixed-universe-selection-bias",
        "adjusted-series-not-executable",
        "owner-review-not-provider-qualification",
    }
    if any(row.div_cash for row in rows):
        exclusions.add("cash-dividend-payable-date-unavailable")
    manifest = ResearchDatasetManifest(
        source_kind=declaration.source_kind,
        rights_reference=declaration.rights_reference,
        provenance_reference=declaration.provenance_reference,
        reviewer_id=declaration.reviewer_id,
        reviewed_at=declaration.reviewed_at,
        identity_reference=declaration.identity_reference,
        calendar_reference=declaration.calendar_reference,
        tzdata_version=declaration.tzdata_version,
        instruments=declaration.instruments,
        start_date=declaration.scope.start_date,
        end_date=declaration.scope.end_date,
        calendar=ResearchCalendar(
            calendar_id=calendar.calendar_id,
            version=calendar.version,
            venue=calendar.venue,
            timezone=calendar.timezone,
            sessions=tuple(
                ResearchSession(
                    venue=session.venue,
                    session_label=session.session_label,
                    opens_at=session.opens_at,
                    closes_at=session.closes_at,
                    kind=session.kind.value,
                )
                for session in calendar.sessions
            ),
        ),
        raw_object_hashes=declaration.raw_object_hashes,
        exclusions=tuple(sorted(exclusions)),
    )
    return ResearchDataset(
        manifest=manifest,
        rows=tuple(sorted(rows, key=lambda row: (row.session_label, row.symbol))),
        raw_objects=raw_objects,
        imported_at=imported_at,
    )


class OwnerImportedTiingoSource:
    def __init__(
        self,
        *,
        paths: Mapping[str, Path],
        declaration: TiingoImportDeclaration,
        calendar: ExchangeCalendar,
        imported_at: datetime,
    ) -> None:
        self._paths = dict(paths)
        self._declaration = declaration
        self._calendar = calendar
        self._imported_at = imported_at

    def load(self) -> ResearchDataset:
        if tuple(sorted(self._paths)) != self._declaration.scope.symbols:
            raise TiingoEodError("explicit source paths must exactly cover the declared universe")
        objects: list[ResearchRawObject] = []
        hashes = dict(self._declaration.raw_object_hashes)
        captures = {
            symbol: (instant, reference)
            for symbol, instant, reference in self._declaration.captures
        }
        for symbol in self._declaration.scope.symbols:
            try:
                with self._paths[symbol].open("rb") as source:
                    payload = source.read(MAX_TIINGO_RESPONSE_BYTES + 1)
            except OSError as error:
                raise TiingoEodError(f"cannot read explicit source for {symbol}") from error
            if len(payload) > MAX_TIINGO_RESPONSE_BYTES:
                raise TiingoEodError("source exceeds the 4 MiB per-symbol limit")
            if hashlib.sha256(payload).hexdigest() != hashes[symbol]:
                raise TiingoEodError(f"source checksum differs from owner review for {symbol}")
            instant, reference = captures[symbol]
            objects.append(ResearchRawObject(symbol, hashes[symbol], payload, instant, reference))
        return parse_tiingo_research_dataset(
            declaration=self._declaration,
            calendar=self._calendar,
            raw_objects=tuple(objects),
            imported_at=self._imported_at,
        )
