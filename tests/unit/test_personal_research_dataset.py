from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from packages.adapters.market_data.tiingo_eod_calendar import _calendar_to_dict
from packages.adapters.market_data.tiingo_eod_import import (
    IMPORT_DECLARATION_VERSION,
    OwnerImportedTiingoSource,
    TiingoImportDeclaration,
)
from packages.application.research_dataset import (
    import_research_dataset,
    replay_research_dataset,
    research_dataset_from_json_bytes,
    research_dataset_to_json_bytes,
)
from packages.domain.research_dataset import ResearchDataClass, ResearchDataset
from packages.market_data import ExchangeCalendar, ExchangeSession
from scripts.import_personal_dataset import main

START = date(2025, 2, 3)
END = date(2025, 2, 7)
IMPORTED = datetime(2025, 2, 10, 16, tzinfo=UTC)


def _row(day: date) -> dict[str, object]:
    return {
        "date": day.isoformat(),
        "open": 100.125,
        "high": 103.5,
        "low": 99.875,
        "close": 102.375,
        "volume": 1_000_001,
        "adjOpen": 50.0625,
        "adjHigh": 51.75,
        "adjLow": 49.9375,
        "adjClose": 51.1875,
        "adjVolume": 2_000_002,
        "divCash": 0.25 if day == END else 0,
        "splitFactor": 1,
    }


def _inputs(tmp_path: Path) -> tuple[dict[str, Path], dict[str, Any], ExchangeCalendar]:
    dates = tuple(START + timedelta(days=index) for index in range(5))
    calendar = ExchangeCalendar(
        calendar_id="synthetic-US-session-grid",
        version="fixture-v1",
        venue="US-EQUITIES",
        timezone="America/New_York",
        sessions=tuple(
            ExchangeSession(
                venue="US-EQUITIES",
                session_label=day,
                opens_at=datetime(day.year, day.month, day.day, 14, 30, tzinfo=UTC),
                closes_at=datetime(day.year, day.month, day.day, 21, tzinfo=UTC),
            )
            for day in dates
        ),
    )
    paths: dict[str, Path] = {}
    instruments = []
    for symbol in ("DIA", "SPY"):
        path = tmp_path / f"{symbol}.json"
        path.write_text(json.dumps([_row(day) for day in dates]))
        paths[symbol] = path
        instruments.append(
            {
                "symbol": symbol,
                "instrument_id": f"fixture-{symbol}",
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "observed_available_at": None,
                "capture_reference": None,
            }
        )
    declaration: dict[str, Any] = {
        "schema_version": IMPORT_DECLARATION_VERSION,
        "source_kind": "synthetic_fixture",
        "rights_reference": "synthetic-fixture-no-provider-rights",
        "provenance_reference": "generated-in-test",
        "reviewer_id": "fixture-reviewer",
        "reviewed_at": "2025-02-10T15:00:00+00:00",
        "identity_reference": "fixture-identities-v1",
        "calendar_reference": "fixture-five-session-calendar",
        "tzdata_version": "fixture-pin",
        "scope": {
            "symbols": ["DIA", "SPY"],
            "start_date": START.isoformat(),
            "end_date": END.isoformat(),
        },
        "instruments": instruments,
        "local_research_permitted": True,
    }
    return paths, declaration, calendar


def _load(
    paths: dict[str, Path], declaration: dict[str, Any], calendar: ExchangeCalendar
) -> ResearchDataset:
    return import_research_dataset(
        OwnerImportedTiingoSource(
            paths=paths,
            declaration=TiingoImportDeclaration.from_dict(declaration),
            calendar=calendar,
            imported_at=IMPORTED,
        )
    )


def _edit_source(paths: dict[str, Path], declaration: dict[str, Any], transform: Any) -> None:
    rows = json.loads(paths["SPY"].read_bytes())
    transform(rows)
    paths["SPY"].write_text(json.dumps(rows))
    declaration["instruments"][1]["source_sha256"] = hashlib.sha256(
        paths["SPY"].read_bytes()
    ).hexdigest()


def test_offline_import_preserves_bases_actions_and_unknown_factual_times(tmp_path: Path) -> None:
    dataset = _load(*_inputs(tmp_path))
    assert dataset.manifest.data_class is ResearchDataClass.SYNTHETIC_FIXTURE
    assert len(dataset.rows) == 10
    assert dataset.rows[0].open_price == Decimal("100.125")
    assert dataset.rows[0].adjusted_open_price == Decimal("50.0625")
    assert dataset.rows[-1].div_cash == Decimal("0.25")
    assert "cash-dividend-payable-date-unavailable" in dataset.manifest.exclusions
    assert all(
        row.vendor_published_at is None and row.observed_available_at is None
        for row in dataset.rows
    )
    assert dataset.rows[0].simulated_available_at == datetime(2025, 2, 4, 1, tzinfo=UTC)
    assert dataset.imported_at == IMPORTED


def test_archive_roundtrip_replays_only_complete_available_selected_sessions(
    tmp_path: Path,
) -> None:
    dataset = _load(*_inputs(tmp_path))
    restored = research_dataset_from_json_bytes(research_dataset_to_json_bytes(dataset))
    assert restored == dataset
    batches = replay_research_dataset(
        restored,
        symbols=("SPY",),
        start_date=START,
        end_date=END,
        as_of=datetime(2025, 2, 6, 1, tzinfo=UTC),
    )
    assert tuple(batch.session_label for batch in batches) == (
        START,
        START + timedelta(days=1),
        START + timedelta(days=2),
    )
    assert all(len(batch.rows) == 1 and batch.rows[0].symbol == "SPY" for batch in batches)
    assert all(batch.data_class is ResearchDataClass.SYNTHETIC_FIXTURE for batch in batches)
    assert all(batch.dataset_id == dataset.dataset_id for batch in batches)


def test_later_row_change_changes_dataset_identity_but_not_earlier_prices(tmp_path: Path) -> None:
    paths, declaration, calendar = _inputs(tmp_path)
    before = _load(paths, declaration, calendar)
    _edit_source(paths, declaration, lambda rows: rows[-1].update(close=103))
    after = _load(paths, declaration, calendar)
    assert before.dataset_id != after.dataset_id

    def earlier(dataset: ResearchDataset) -> tuple[Decimal, ...]:
        return tuple(
            row.close_price
            for batch in replay_research_dataset(
                dataset,
                symbols=("SPY",),
                start_date=START,
                end_date=END,
                as_of=datetime(2025, 2, 6, 1, tzinfo=UTC),
            )
            for row in batch.rows
        )

    assert earlier(before) == earlier(after)
    assert (
        replace(before, imported_at=IMPORTED + timedelta(hours=1)).dataset_id == before.dataset_id
    )


@pytest.mark.parametrize(
    "change,reason",
    [
        (lambda rows: rows.pop(), "exactly cover"),
        (lambda rows: rows.append(rows[0]), "duplicate session"),
        (lambda rows: rows[0].update(splitFactor=0.5), "split-affected"),
        (lambda rows: rows[0].update(open=float("nan")), "non-finite"),
        (lambda rows: rows[0].update(low=104), "raw low"),
        (lambda rows: rows[0].update(date="2025-02-08"), "outside"),
    ],
)
def test_bad_or_unsupported_scope_is_rejected(tmp_path: Path, change: Any, reason: str) -> None:
    paths, declaration, calendar = _inputs(tmp_path)
    _edit_source(paths, declaration, change)
    with pytest.raises(ValueError, match=reason):
        _load(paths, declaration, calendar)


def test_source_hash_and_rights_review_are_required(tmp_path: Path) -> None:
    paths, declaration, calendar = _inputs(tmp_path)
    paths["SPY"].write_bytes(paths["SPY"].read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        _load(paths, declaration, calendar)
    declaration["local_research_permitted"] = False
    with pytest.raises(ValueError, match="rights"):
        _load(paths, declaration, calendar)


def test_archive_cannot_promote_fixture_or_rewrite_summary(tmp_path: Path) -> None:
    dataset = _load(*_inputs(tmp_path))
    archive = json.loads(research_dataset_to_json_bytes(dataset))
    archive["summary"]["data_class"] = "validated_current_vintage"
    with pytest.raises(ValueError, match="summary"):
        research_dataset_from_json_bytes(json.dumps(archive).encode())
    paths, declaration, calendar = _inputs(tmp_path)
    declaration["data_class"] = "validated_current_vintage"
    with pytest.raises(ValueError, match="unknown fields"):
        _load(paths, declaration, calendar)


def test_recorded_receipt_is_current_and_kept_separate_from_historical_assumption(
    tmp_path: Path,
) -> None:
    paths, declaration, calendar = _inputs(tmp_path)
    for item in declaration["instruments"]:
        item["observed_available_at"] = "2025-02-10T14:00:00+00:00"
        item["capture_reference"] = "synthetic-receipt-fixture"
    dataset = _load(paths, declaration, calendar)
    assert dataset.rows[0].observed_available_at == datetime(2025, 2, 10, 14, tzinfo=UTC)
    assert dataset.rows[0].simulated_available_at == datetime(2025, 2, 4, 1, tzinfo=UTC)
    assert dataset.rows[0].vendor_published_at is None
    assert research_dataset_from_json_bytes(research_dataset_to_json_bytes(dataset)) == dataset
    declaration["instruments"][0]["observed_available_at"] = "2025-02-01T14:00:00+00:00"
    with pytest.raises(ValueError, match="precede"):
        _load(paths, declaration, calendar)


def test_cli_writes_private_archive_and_preserves_existing_output(tmp_path: Path) -> None:
    paths, declaration, calendar = _inputs(tmp_path)
    declaration_path = tmp_path / "declaration.json"
    declaration_path.write_text(json.dumps(declaration))
    calendar_path = tmp_path / "calendar.json"
    calendar_path.write_text(json.dumps(_calendar_to_dict(calendar)))
    output = tmp_path / "dataset.json"
    args = [
        "--declaration",
        str(declaration_path),
        "--calendar",
        str(calendar_path),
        "--source",
        f"DIA={paths['DIA']}",
        "--source",
        f"SPY={paths['SPY']}",
        "--output",
        str(output),
    ]
    assert main(args) == 0
    first = output.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600
    assert (
        research_dataset_from_json_bytes(first).manifest.data_class
        is ResearchDataClass.SYNTHETIC_FIXTURE
    )
    assert main(args) == 2
    assert output.read_bytes() == first


@pytest.mark.parametrize(
    "instant",
    [
        datetime(2025, 2, 3, tzinfo=UTC),
        datetime(2025, 2, 10),
    ],
)
def test_invalid_import_receipt_is_rejected(tmp_path: Path, instant: datetime) -> None:
    paths, declaration, calendar = _inputs(tmp_path)
    with pytest.raises(ValueError):
        OwnerImportedTiingoSource(
            paths=paths,
            declaration=TiingoImportDeclaration.from_dict(declaration),
            calendar=calendar,
            imported_at=instant,
        ).load()
