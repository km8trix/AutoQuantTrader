"""Offline dataset admission, portable archives and availability-limited replay."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import date, datetime

from packages.adapters.market_data.tiingo_eod import (
    TiingoEodError,
    _datetime,
    _fields,
    _json,
    _object,
    _text,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    _array,
    _calendar_from_dict,
)
from packages.adapters.market_data.tiingo_eod_import import (
    IMPORT_DECLARATION_VERSION,
    TiingoImportDeclaration,
    parse_tiingo_research_dataset,
)
from packages.domain.research_dataset import (
    RESEARCH_DATASET_VERSION,
    DailyResearchBar,
    ResearchDataClass,
    ResearchDataset,
    ResearchDatasetSource,
    ResearchRawObject,
)
from packages.market_data.models import require_utc

MAX_RESEARCH_ARCHIVE_BYTES = 32 * 1024 * 1024


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def import_research_dataset(source: ResearchDatasetSource) -> ResearchDataset:
    """Admit through the new versioned port without modifying legacy manifests."""
    return source.load()


def _archive_dict(dataset: ResearchDataset) -> dict[str, object]:
    manifest = dataset.manifest
    hashes = dict(manifest.raw_object_hashes)
    observations = {raw.symbol: raw for raw in dataset.raw_objects}
    return {
        "schema_version": RESEARCH_DATASET_VERSION,
        "dataset_id": dataset.dataset_id,
        "imported_at": dataset.imported_at.isoformat(),
        "declaration": {
            "schema_version": IMPORT_DECLARATION_VERSION,
            "source_kind": manifest.source_kind,
            "rights_reference": manifest.rights_reference,
            "provenance_reference": manifest.provenance_reference,
            "reviewer_id": manifest.reviewer_id,
            "reviewed_at": manifest.reviewed_at.isoformat(),
            "identity_reference": manifest.identity_reference,
            "calendar_reference": manifest.calendar_reference,
            "tzdata_version": manifest.tzdata_version,
            "scope": {
                "symbols": list(manifest.symbols),
                "start_date": manifest.start_date.isoformat(),
                "end_date": manifest.end_date.isoformat(),
            },
            "instruments": [
                {
                    "symbol": symbol,
                    "instrument_id": instrument_id,
                    "source_sha256": hashes[symbol],
                    "observed_available_at": _optional_timestamp(
                        observations[symbol].observed_available_at
                    ),
                    "capture_reference": observations[symbol].capture_reference,
                }
                for symbol, instrument_id in manifest.instruments
            ],
            "local_research_permitted": True,
        },
        "calendar": {
            "calendar_id": manifest.calendar.calendar_id,
            "version": manifest.calendar.version,
            "venue": manifest.calendar.venue,
            "timezone": manifest.calendar.timezone,
            "sessions": [
                {
                    "session_label": session.session_label.isoformat(),
                    "venue": session.venue,
                    "opens_at": session.opens_at.isoformat(),
                    "closes_at": session.closes_at.isoformat(),
                    "kind": session.kind,
                }
                for session in manifest.calendar.sessions
            ],
        },
        "sources": [
            {
                "symbol": raw.symbol,
                "sha256": raw.sha256,
                "payload_base64": base64.b64encode(raw.payload).decode("ascii"),
                "observed_available_at": _optional_timestamp(raw.observed_available_at),
                "capture_reference": raw.capture_reference,
            }
            for raw in dataset.raw_objects
        ],
        "summary": {
            "data_class": manifest.data_class.value,
            "admission_decision": manifest.admission_decision,
            "parser_version": manifest.parser_version,
            "availability_policy_id": manifest.availability_policy_id,
            "action_policy_id": manifest.action_policy_id,
            "calendar_sha256": manifest.calendar_sha256,
            "exclusions": list(manifest.exclusions),
            "quality_checks": list(manifest.quality_checks),
            "row_count": len(dataset.rows),
            "raw_price_basis": "tiingo-documented-raw",
            "adjusted_price_basis": "tiingo-split-dividend-adjusted",
            "dividend_candidate_count": sum(row.div_cash != 0 for row in dataset.rows),
            "vendor_published_at": None,
            "factual_receipt_coverage": (
                "all-symbols"
                if all(raw.observed_available_at is not None for raw in dataset.raw_objects)
                else "incomplete-or-unknown"
            ),
        },
    }


def research_dataset_to_json_bytes(dataset: ResearchDataset) -> bytes:
    """Archive exact source bytes and enough pinned inputs to reproduce every row."""
    payload = (json.dumps(_archive_dict(dataset), sort_keys=True, indent=2) + "\n").encode()
    if len(payload) > MAX_RESEARCH_ARCHIVE_BYTES:
        raise ValueError("research archive exceeds the 32 MiB limit")
    return payload


def research_dataset_from_json_bytes(payload: bytes) -> ResearchDataset:
    if type(payload) is not bytes or not payload or len(payload) > MAX_RESEARCH_ARCHIVE_BYTES:
        raise ValueError("research archive must be nonempty bytes within the 32 MiB limit")
    archive = _object(_json(payload), "archive")
    _fields(
        archive,
        {
            "schema_version",
            "dataset_id",
            "imported_at",
            "declaration",
            "calendar",
            "sources",
            "summary",
        },
        "archive",
    )
    if archive["schema_version"] != RESEARCH_DATASET_VERSION:
        raise ValueError("unsupported research archive version")
    raw_objects: list[ResearchRawObject] = []
    for item in _array(archive["sources"], "sources"):
        raw = _object(item, "source")
        _fields(
            raw,
            {"symbol", "sha256", "payload_base64", "observed_available_at", "capture_reference"},
            "source",
        )
        try:
            body = base64.b64decode(_text(raw["payload_base64"], "payload_base64"), validate=True)
        except (ValueError, binascii.Error) as error:
            raise TiingoEodError("invalid archived source encoding") from error
        raw_objects.append(
            ResearchRawObject(
                _text(raw["symbol"], "symbol"),
                _text(raw["sha256"], "sha256"),
                body,
                None
                if raw["observed_available_at"] is None
                else _datetime(raw["observed_available_at"], "observed_available_at"),
                None
                if raw["capture_reference"] is None
                else _text(raw["capture_reference"], "capture_reference"),
            )
        )
    dataset = parse_tiingo_research_dataset(
        declaration=TiingoImportDeclaration.from_dict(archive["declaration"]),
        calendar=_calendar_from_dict(archive["calendar"], "calendar"),
        raw_objects=tuple(raw_objects),
        imported_at=_datetime(archive["imported_at"], "imported_at"),
    )
    if archive != _archive_dict(dataset):
        raise ValueError("archive identity or declared summary differs from its validated contents")
    return dataset


@dataclass(frozen=True, slots=True)
class ResearchReplayBatch:
    dataset_id: str
    data_class: ResearchDataClass
    session_label: date
    simulated_available_at: datetime
    rows: tuple[DailyResearchBar, ...]


def replay_research_dataset(
    dataset: ResearchDataset,
    *,
    symbols: tuple[str, ...],
    start_date: date,
    end_date: date,
    as_of: datetime,
) -> tuple[ResearchReplayBatch, ...]:
    """Select complete daily batches at or before a modeled knowledge frontier.

    This is a historical research input port, with no fills, economics, or
    conversion of modeled availability into factual timestamps.
    """
    require_utc(as_of, "as_of")
    if (
        not symbols
        or symbols != tuple(sorted(set(symbols)))
        or not set(symbols).issubset(dataset.manifest.symbols)
    ):
        raise ValueError("selection must be a nonempty sorted subset of the admitted universe")
    if not dataset.manifest.start_date <= start_date <= end_date <= dataset.manifest.end_date:
        raise ValueError("selection falls outside admitted coverage")
    batches: dict[date, list[DailyResearchBar]] = {}
    for row in dataset.rows:
        if (
            row.symbol in symbols
            and start_date <= row.session_label <= end_date
            and row.simulated_available_at <= as_of
        ):
            batches.setdefault(row.session_label, []).append(row)
    dataset_id = dataset.dataset_id
    return tuple(
        ResearchReplayBatch(
            dataset_id=dataset_id,
            data_class=dataset.manifest.data_class,
            session_label=session,
            simulated_available_at=rows[0].simulated_available_at,
            rows=tuple(rows),
        )
        for session, rows in batches.items()
    )
