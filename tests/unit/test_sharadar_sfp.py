from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from packages.adapters.market_data.sharadar_sfp import (
    PHASE1_SFP_SYMBOLS,
    SFP_COLUMNS,
    RecordedSharadarSfpSnapshot,
    SfpCaptureAuthorization,
    SfpCaptureManifest,
    SfpCaptureScope,
    SfpPageReceipt,
    SfpPriceBasis,
    SharadarSfpError,
    sfp_page_contract,
)
from packages.adapters.market_data.sharadar_sfp_capture import (
    SfpApiRequest,
    SfpApiResponse,
    SharadarSfpCaptureError,
    capture_sharadar_sfp,
)
from packages.market_data import BarInterval, ExchangeCalendar, ExchangeSession

SESSION_DATE = date(2026, 7, 14)
SESSION_OPEN = datetime(2026, 7, 14, 13, 30, tzinfo=UTC)
SESSION_CLOSE = datetime(2026, 7, 14, 20, 0, tzinfo=UTC)
REQUESTED_AT = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
RECEIVED_AT = datetime(2026, 7, 16, 12, 0, 1, tzinfo=UTC)
SECOND_SESSION_DATE = date(2026, 7, 15)
SECOND_SESSION_OPEN = datetime(2026, 7, 15, 13, 30, tzinfo=UTC)
SECOND_SESSION_CLOSE = datetime(2026, 7, 15, 20, 0, tzinfo=UTC)
TERMS_SHA256 = hashlib.sha256(b"reviewed Sharadar terms fixture").hexdigest()

TYPE_BY_COLUMN = {
    "ticker": "String",
    "date": "Date",
    "open": "BigDecimal",
    "high": "BigDecimal",
    "low": "BigDecimal",
    "close": "BigDecimal",
    "volume": "BigDecimal",
    "closeadj": "BigDecimal",
    "closeunadj": "BigDecimal",
    "lastupdated": "Date",
}


def calendar(
    *,
    version: str = "test-v1",
    closes_at: datetime = SESSION_CLOSE,
    include_second_session: bool = False,
) -> ExchangeCalendar:
    sessions = [
        ExchangeSession(
            venue="US-EQUITIES",
            session_label=SESSION_DATE,
            opens_at=SESSION_OPEN,
            closes_at=closes_at,
        )
    ]
    if include_second_session:
        sessions.append(
            ExchangeSession(
                venue="US-EQUITIES",
                session_label=SECOND_SESSION_DATE,
                opens_at=SECOND_SESSION_OPEN,
                closes_at=SECOND_SESSION_CLOSE,
            )
        )
    return ExchangeCalendar(
        calendar_id="US-EQUITIES-test",
        version=version,
        venue="US-EQUITIES",
        timezone="America/New_York",
        sessions=tuple(sessions),
    )


def authorization(
    *,
    permits_local_snapshot_storage: bool = True,
    permits_research_use: bool = True,
) -> SfpCaptureAuthorization:
    return SfpCaptureAuthorization(
        authorization_id="test-reviewed-authorization",
        reviewer_id="test-reviewer",
        reviewed_at=datetime(2026, 7, 1, tzinfo=UTC),
        terms_sha256=TERMS_SHA256,
        effective_from=date(2026, 1, 1),
        effective_through=date(2026, 12, 31),
        permits_local_snapshot_storage=permits_local_snapshot_storage,
        permits_research_use=permits_research_use,
    )


def authorization_json_bytes(
    *,
    duplicate_reviewer_id: bool = False,
    permits_local_snapshot_storage: bool = True,
    permits_research_use: bool = True,
) -> bytes:
    value = authorization(
        permits_local_snapshot_storage=permits_local_snapshot_storage,
        permits_research_use=permits_research_use,
    )
    payload = {
        "authorization_id": value.authorization_id,
        "effective_from": value.effective_from.isoformat(),
        "effective_through": (
            None if value.effective_through is None else value.effective_through.isoformat()
        ),
        "permits_local_snapshot_storage": value.permits_local_snapshot_storage,
        "permits_research_use": value.permits_research_use,
        "provider": value.provider,
        "reviewed_at": value.reviewed_at.isoformat().replace("+00:00", "Z"),
        "reviewer_id": value.reviewer_id,
        "schema_version": value.schema_version,
        "table": value.table,
        "terms_sha256": value.terms_sha256,
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    if duplicate_reviewer_id:
        field = b'"reviewer_id":"test-reviewer"'
        return encoded.replace(field, field + b',"reviewer_id":"other-reviewer"', 1)
    return encoded


def authorization_sha256(payload: bytes | None = None) -> str:
    artifact = authorization_json_bytes() if payload is None else payload
    return hashlib.sha256(artifact).hexdigest()


def capture_root(repository_root: Path) -> Path:
    return repository_root / ".local" / "vendor-snapshots" / "sharadar-sfp"


def economic_row(
    symbol: str,
    *,
    trading_date: date = SESSION_DATE,
) -> dict[str, object]:
    return {
        "ticker": symbol,
        "date": trading_date.isoformat(),
        "open": "100.00",
        "high": "102.00",
        "low": "99.00",
        "close": "101.00",
        "volume": "1000000.5",
        "closeadj": "101.25",
        "closeunadj": "100.75",
        "lastupdated": max(trading_date, SECOND_SESSION_DATE).isoformat(),
    }


def page_bytes(
    rows: list[dict[str, object]],
    *,
    columns: tuple[str, ...] = tuple(reversed(SFP_COLUMNS)),
    next_cursor_id: str | None = None,
    types: dict[str, str] | None = None,
) -> bytes:
    column_types = TYPE_BY_COLUMN if types is None else types
    payload = {
        "datatable": {
            "columns": [{"name": column, "type": column_types[column]} for column in columns],
            "data": [[row[column] for column in columns] for row in rows],
        },
        "meta": {"next_cursor_id": next_cursor_id},
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def write_owner_only(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_bytes(payload)
    path.chmod(0o600)


def page_schema_sha256(payload: bytes | None = None) -> str:
    _, digest = sfp_page_contract(page_bytes([]) if payload is None else payload)
    return digest


def write_snapshot(
    root: Path,
    payload: bytes,
    *,
    scope: SfpCaptureScope | None = None,
    receipt_digest: str | None = None,
    object_path: str = "objects/page.json",
    column_schema_sha256: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    digest = hashlib.sha256(payload).hexdigest()
    target = root / object_path
    write_owner_only(target, payload)
    receipt = SfpPageReceipt(
        object_path=object_path,
        sha256=receipt_digest or digest,
        byte_count=len(payload),
        cursor_id=None,
        next_cursor_id=None,
        requested_at=REQUESTED_AT,
        received_at=RECEIVED_AT,
    )
    manifest = SfpCaptureManifest(
        scope=scope
        or SfpCaptureScope(
            symbols=PHASE1_SFP_SYMBOLS,
            start_date=SESSION_DATE,
            end_date=SESSION_DATE,
        ),
        pages=(receipt,),
        requested_at=REQUESTED_AT,
        received_at=RECEIVED_AT,
        authorization_sha256=authorization_sha256(),
        terms_sha256=TERMS_SHA256,
        column_schema_sha256=column_schema_sha256 or page_schema_sha256(),
    )
    manifest_path = root / "manifest.json"
    write_owner_only(manifest_path, manifest.to_json_bytes())
    return manifest_path


def all_rows() -> list[dict[str, object]]:
    return [economic_row(symbol) for symbol in reversed(PHASE1_SFP_SYMBOLS)]


def test_capture_authorization_json_parses_valid_document() -> None:
    parsed = SfpCaptureAuthorization.from_json_bytes(authorization_json_bytes())

    assert parsed.authorization_id == "test-reviewed-authorization"
    assert parsed.terms_sha256 == TERMS_SHA256


def test_recorded_snapshot_is_deterministic_session_daily_and_research_only(
    tmp_path: Path,
) -> None:
    payload = page_bytes(all_rows())
    manifest_path = write_snapshot(tmp_path, payload)

    dataset = RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()

    assert tuple(row.ticker for row in dataset.rows) == PHASE1_SFP_SYMBOLS
    assert dataset.rows[0].interval is BarInterval.ONE_DAY
    assert dataset.rows[0].interval_start == SESSION_OPEN
    assert dataset.rows[0].interval_end == SESSION_CLOSE
    assert dataset.rows[0].observed_at == RECEIVED_AT
    assert dataset.rows[0].ohlcv_basis is SfpPriceBasis.SPLIT_STOCK_DIVIDEND_ADJUSTED
    assert dataset.rows[0].close_unadjusted_basis is SfpPriceBasis.UNADJUSTED_CLOSE
    assert dataset.rows[0].volume.as_tuple().exponent == -1
    assert dataset.capture_sha256 == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with pytest.raises(SharadarSfpError, match="only closeunadj is raw"):
        dataset.raw_bar_records()


def test_snapshot_accepts_parameterized_big_decimal_schema(tmp_path: Path) -> None:
    types = dict(TYPE_BY_COLUMN)
    for column in (
        "open",
        "high",
        "low",
        "close",
        "volume",
        "closeadj",
        "closeunadj",
    ):
        types[column] = "BigDecimal(20,6)"
    payload = page_bytes(all_rows(), types=types)
    manifest_path = write_snapshot(
        tmp_path,
        payload,
        column_schema_sha256=page_schema_sha256(payload),
    )

    dataset = RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()

    assert len(dataset.rows) == len(PHASE1_SFP_SYMBOLS)


@pytest.mark.parametrize("target", ["authorization", "manifest", "response"])
def test_sfp_json_documents_reject_duplicate_keys(
    tmp_path: Path,
    target: str,
) -> None:
    if target == "authorization":
        with pytest.raises(SharadarSfpError, match="duplicate JSON key"):
            SfpCaptureAuthorization.from_json_bytes(
                authorization_json_bytes(duplicate_reviewer_id=True)
            )
        return

    payload = page_bytes(all_rows())
    manifest_path = write_snapshot(tmp_path, payload)
    if target == "manifest":
        manifest_bytes = manifest_path.read_bytes()
        field = b'"provider": "nasdaq-data-link",'
        assert field in manifest_bytes
        write_owner_only(manifest_path, manifest_bytes.replace(field, field + field, 1))
    else:
        duplicate_cursor = b'"next_cursor_id":null,"next_cursor_id":null'
        duplicated = payload.replace(b'"next_cursor_id":null', duplicate_cursor, 1)
        write_owner_only(tmp_path / "objects" / "page.json", duplicated)
        manifest = SfpCaptureManifest.from_json_bytes(manifest_path.read_bytes())
        receipt = manifest.pages[0]
        corrected_receipt = SfpPageReceipt(
            object_path=receipt.object_path,
            sha256=hashlib.sha256(duplicated).hexdigest(),
            byte_count=len(duplicated),
            cursor_id=receipt.cursor_id,
            next_cursor_id=receipt.next_cursor_id,
            requested_at=receipt.requested_at,
            received_at=receipt.received_at,
        )
        corrected_manifest = SfpCaptureManifest(
            scope=manifest.scope,
            pages=(corrected_receipt,),
            requested_at=manifest.requested_at,
            received_at=manifest.received_at,
            authorization_sha256=manifest.authorization_sha256,
            terms_sha256=manifest.terms_sha256,
            column_schema_sha256=manifest.column_schema_sha256,
        )
        write_owner_only(manifest_path, corrected_manifest.to_json_bytes())

    with pytest.raises(SharadarSfpError, match="duplicate JSON key"):
        RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            page_bytes(all_rows(), columns=SFP_COLUMNS[:-1]),
            "missing required columns",
        ),
        (
            page_bytes([economic_row("SPY"), economic_row("SPY")]),
            "duplicate ticker/date",
        ),
        (
            page_bytes([economic_row("SPY")]),
            "missing required symbol coverage",
        ),
    ],
)
def test_snapshot_fails_closed_on_schema_duplicates_and_coverage(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    manifest_path = write_snapshot(tmp_path, payload)

    with pytest.raises(SharadarSfpError, match=message):
        RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()


def test_snapshot_requires_every_symbol_for_every_scoped_session(
    tmp_path: Path,
) -> None:
    rows = all_rows()
    rows.extend(
        economic_row(symbol, trading_date=SECOND_SESSION_DATE)
        for symbol in PHASE1_SFP_SYMBOLS
        if symbol != "SPY"
    )
    scope = SfpCaptureScope(
        symbols=PHASE1_SFP_SYMBOLS,
        start_date=SESSION_DATE,
        end_date=SECOND_SESSION_DATE,
    )
    manifest_path = write_snapshot(tmp_path, page_bytes(rows), scope=scope)

    with pytest.raises(
        SharadarSfpError,
        match=r"missing required session coverage: 1 rows; first SPY/2026-07-15",
    ):
        RecordedSharadarSfpSnapshot(
            manifest_path,
            calendar=calendar(include_second_session=True),
        ).load()


def test_semantic_digest_binds_calendar_version_and_session_bounds(
    tmp_path: Path,
) -> None:
    manifest_path = write_snapshot(tmp_path, page_bytes(all_rows()))

    baseline = RecordedSharadarSfpSnapshot(
        manifest_path,
        calendar=calendar(),
    ).load()
    changed_version = RecordedSharadarSfpSnapshot(
        manifest_path,
        calendar=calendar(version="test-v2"),
    ).load()
    changed_bounds = RecordedSharadarSfpSnapshot(
        manifest_path,
        calendar=calendar(closes_at=datetime(2026, 7, 14, 19, 0, tzinfo=UTC)),
    ).load()

    assert baseline.capture_sha256 == changed_version.capture_sha256
    assert baseline.capture_sha256 == changed_bounds.capture_sha256
    assert baseline.calendar_sha256 != changed_version.calendar_sha256
    assert baseline.calendar_sha256 != changed_bounds.calendar_sha256
    assert baseline.semantic_sha256 != changed_version.semantic_sha256
    assert baseline.semantic_sha256 != changed_bounds.semantic_sha256
    assert changed_bounds.rows[0].interval_end != baseline.rows[0].interval_end


def test_snapshot_rejects_digest_mismatch_and_broad_permissions(tmp_path: Path) -> None:
    payload = page_bytes(all_rows())
    mismatched = write_snapshot(tmp_path / "digest", payload, receipt_digest="0" * 64)
    broad = write_snapshot(tmp_path / "mode", payload)
    broad.chmod(0o644)

    with pytest.raises(SharadarSfpError, match="digest"):
        RecordedSharadarSfpSnapshot(mismatched, calendar=calendar()).load()
    with pytest.raises(SharadarSfpError, match="permissions must be owner-only"):
        RecordedSharadarSfpSnapshot(broad, calendar=calendar()).load()


def test_snapshot_rejects_out_of_allow_list_and_unknown_session(tmp_path: Path) -> None:
    outside_scope = SfpCaptureScope(
        symbols=("AAPL",),
        start_date=SESSION_DATE,
        end_date=SESSION_DATE,
    )
    outside = write_snapshot(
        tmp_path / "outside",
        page_bytes([economic_row("AAPL")]),
        scope=outside_scope,
    )
    wrong_date_row = economic_row("SPY")
    wrong_date_row["date"] = "2026-07-13"
    wrong_date_row["lastupdated"] = "2026-07-13"
    wrong_scope = SfpCaptureScope(
        symbols=("SPY",),
        start_date=date(2026, 7, 13),
        end_date=date(2026, 7, 13),
    )
    unknown_session = write_snapshot(
        tmp_path / "calendar",
        page_bytes([wrong_date_row]),
        scope=wrong_scope,
    )

    with pytest.raises(SharadarSfpError, match="allow-list"):
        RecordedSharadarSfpSnapshot(outside, calendar=calendar()).load()
    with pytest.raises(
        SharadarSfpError,
        match=r"complete capture scope|no session",
    ):
        RecordedSharadarSfpSnapshot(unknown_session, calendar=calendar()).load()


def test_snapshot_rejects_symlinked_page(tmp_path: Path) -> None:
    payload = page_bytes(all_rows())
    root = tmp_path / "capture"
    target = root / "target.json"
    write_owner_only(target, payload)
    link = root / "objects" / "page.json"
    link.parent.mkdir()
    link.symlink_to(target)
    manifest_path = write_snapshot(root, payload)
    (root / "objects" / "page.json").unlink()
    (root / "objects" / "page.json").symlink_to(target)

    with pytest.raises(SharadarSfpError, match=r"symlink|cannot read"):
        RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()


def test_snapshot_rejects_symlinked_intermediate_page_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "capture"
    manifest_path = write_snapshot(root, page_bytes(all_rows()))
    objects = root / "objects"
    real_objects = root / "real-objects"
    objects.rename(real_objects)
    objects.symlink_to(real_objects.name, target_is_directory=True)

    with pytest.raises(SharadarSfpError, match=r"symlink|cannot read|directory"):
        RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()


def test_snapshot_rejects_symlinked_capture_directory(tmp_path: Path) -> None:
    real_root = tmp_path / "real-capture"
    write_snapshot(real_root, page_bytes(all_rows()))
    alias = tmp_path / "capture-alias"
    alias.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(SharadarSfpError, match=r"symlink|cannot read|directory"):
        RecordedSharadarSfpSnapshot(
            alias / "manifest.json",
            calendar=calendar(),
        ).load()


def test_capture_rejects_output_outside_fixed_repository_root_before_transport(
    tmp_path: Path,
) -> None:
    called = False

    def transport(request: SfpApiRequest, *, timeout_seconds: float) -> SfpApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    arbitrary_root = tmp_path / "captures"
    with pytest.raises(
        SharadarSfpCaptureError,
        match="fixed ignored SFP snapshot root",
    ):
        capture_sharadar_sfp(
            arbitrary_root,
            repository_root=tmp_path,
            api_key="top-secret",
            scope=SfpCaptureScope(
                symbols=("SPY",),
                start_date=SESSION_DATE,
                end_date=SESSION_DATE,
            ),
            authorization_bytes=authorization_json_bytes(),
            transport=transport,
            clock=lambda: REQUESTED_AT,
        )

    assert called is False
    assert not arbitrary_root.exists()


def test_capture_rejects_unauthorized_storage_before_transport_or_writes(
    tmp_path: Path,
) -> None:
    called = False

    def transport(request: SfpApiRequest, *, timeout_seconds: float) -> SfpApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    root = capture_root(tmp_path)
    with pytest.raises(
        SharadarSfpCaptureError,
        match="does not permit local research storage",
    ):
        capture_sharadar_sfp(
            root,
            repository_root=tmp_path,
            api_key="top-secret",
            scope=SfpCaptureScope(
                symbols=("SPY",),
                start_date=SESSION_DATE,
                end_date=SESSION_DATE,
            ),
            authorization_bytes=authorization_json_bytes(permits_local_snapshot_storage=False),
            transport=transport,
            clock=lambda: REQUESTED_AT,
        )

    assert called is False
    assert not root.exists()


def test_capture_archives_complete_cursor_chain_without_exposing_api_key(
    tmp_path: Path,
) -> None:
    responses = [
        page_bytes([economic_row("DIA"), economic_row("IWM")], next_cursor_id="cursor-2"),
        page_bytes([economic_row("QQQ"), economic_row("SPY")]),
    ]
    seen: list[SfpApiRequest] = []
    times = iter(
        (
            REQUESTED_AT,
            RECEIVED_AT,
            RECEIVED_AT.replace(second=2),
            RECEIVED_AT.replace(second=3),
        )
    )

    def transport(request: SfpApiRequest, *, timeout_seconds: float) -> SfpApiResponse:
        seen.append(request)
        assert timeout_seconds == 15.0
        return SfpApiResponse(status=200, payload=responses[len(seen) - 1])

    root = capture_root(tmp_path)
    manifest_path = capture_sharadar_sfp(
        root,
        repository_root=tmp_path,
        api_key="top-secret",
        scope=SfpCaptureScope(
            symbols=PHASE1_SFP_SYMBOLS,
            start_date=SESSION_DATE,
            end_date=SESSION_DATE,
        ),
        authorization_bytes=authorization_json_bytes(),
        transport=transport,
        clock=lambda: next(times),
    )
    dataset = RecordedSharadarSfpSnapshot(manifest_path, calendar=calendar()).load()

    assert len(dataset.rows) == 4
    assert dataset.manifest.authorization_sha256 == authorization_sha256()
    assert len(seen) == 2
    assert seen[0].cursor_id is None
    assert seen[1].cursor_id == "cursor-2"
    assert repr(seen[0]) == "SfpApiRequest(table='SHARADAR/SFP', redacted=True)"
    assert "top-secret" not in str(manifest_path)
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o400
    assert stat.S_IMODE(manifest_path.parent.stat().st_mode) == 0o500


def test_capture_http_failure_is_sanitized_and_writes_nothing(tmp_path: Path) -> None:
    def transport(request: SfpApiRequest, *, timeout_seconds: float) -> SfpApiResponse:
        assert "top-secret" in request.url
        return SfpApiResponse(status=403, payload=b'{"error":"top-secret detail"}')

    root = capture_root(tmp_path)
    with pytest.raises(SharadarSfpCaptureError) as captured:
        capture_sharadar_sfp(
            root,
            repository_root=tmp_path,
            api_key="top-secret",
            scope=SfpCaptureScope(
                symbols=("SPY",),
                start_date=SESSION_DATE,
                end_date=SESSION_DATE,
            ),
            authorization_bytes=authorization_json_bytes(),
            transport=transport,
            clock=lambda: REQUESTED_AT,
        )

    assert "top-secret" not in str(captured.value)
    assert not root.exists()
