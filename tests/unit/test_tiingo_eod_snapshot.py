from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

import packages.adapters.market_data.tiingo_eod_lineage as lineage_module
import packages.adapters.market_data.tiingo_eod_retained_fields as retained_fields_module
import packages.adapters.market_data.tiingo_eod_snapshot as snapshot_module
from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_MANIFEST_BYTES,
    MAX_TIINGO_RESPONSE_BYTES,
    TIINGO_EOD_FIELD_CONTRACT,
    TIINGO_EOD_FIELDS,
    TIINGO_EOD_SCHEMA_SHA256,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodCaptureManifest,
    TiingoEodCaptureReceipt,
    TiingoEodError,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    TiingoEodPinnedCalendar,
    TiingoEodPinnedCalendarArtifact,
)
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodApiResponse,
    capture_tiingo_eod,
)
from packages.adapters.market_data.tiingo_eod_capture_identity import (
    tiingo_eod_capture_name,
)
from packages.adapters.market_data.tiingo_eod_lineage import (
    TiingoEodLocalRevision,
    TiingoEodReceiptComparison,
    TiingoEodReceiptDisposition,
    TiingoEodReceiptTimeLineage,
    derive_tiingo_eod_receipt_lineage,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    TIINGO_EOD_RETAINED_FIELD_BINDINGS,
    TIINGO_EOD_RETAINED_FIELD_CHECK_IDS,
    TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256,
    TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION,
    TiingoEodRetainedFieldBinding,
    TiingoEodRetainedFieldQualification,
    TiingoEodRetainedFieldQualificationKind,
    TiingoEodRetainedFieldRole,
    qualify_tiingo_eod_retained_fields,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    RecordedTiingoEodResearchSnapshot,
    TiingoEodVerifiedResearchSnapshot,
    verify_tiingo_eod_capture,
)
from packages.market_data import ExchangeCalendar, ExchangeSession, HistoricalBarSource

SESSION_DATE = date(2026, 7, 14)
SECOND_SESSION_DATE = date(2026, 7, 15)
PROFILE_REVIEWED_AT = datetime(2026, 6, 30, 16, 0, tzinfo=UTC)
AUTHORIZATION_REVIEWED_AT = datetime(2026, 7, 1, 16, 0, tzinfo=UTC)
CALENDAR_REVIEWED_AT = datetime(2026, 7, 2, 16, 0, tzinfo=UTC)
CAPTURE_REQUESTED_AT = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
CALENDAR_AUTHORITY = "test-per-symbol-calendar-authority-v1"
TERMS_SHA256 = hashlib.sha256(b"reviewed Tiingo terms fixture").hexdigest()
SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")
VENUE_BY_SYMBOL = {
    "DIA": "ARCX",
    "IWM": "BATS",
    "QQQ": "XNAS",
    "SPY": "XNYS",
}


def scope(
    *,
    symbols: tuple[str, ...] = SYMBOLS,
    start_date: date = SESSION_DATE,
    end_date: date = SESSION_DATE,
) -> TiingoEodScope:
    return TiingoEodScope(
        symbols=symbols,
        start_date=start_date,
        end_date=end_date,
    )


def profile(
    *,
    capture_scope: TiingoEodScope | None = None,
    calendar_authority: str = CALENDAR_AUTHORITY,
    market_provenance: str = "tiingo-eod-us-consolidated-market-v1",
    reviewed_at: datetime = PROFILE_REVIEWED_AT,
) -> TiingoEodAcquisitionProfile:
    return TiingoEodAcquisitionProfile(
        scope=capture_scope or scope(),
        profile_id="test-reviewed-tiingo-profile",
        approved=True,
        reviewer_id="test-profile-reviewer",
        reviewed_at=reviewed_at,
        source_id="tiingo-eod-rest",
        adapter_version="tiingo-eod-capture-v2",
        market_provenance=market_provenance,
        identifier_authority="tiingo-ticker-mapping-v1",
        calendar_authority=calendar_authority,
        corporate_action_authority="tiingo-eod-actions-v1",
        correction_policy="first-observed-local-revisions-v1",
    )


def authorization(
    selected_profile: TiingoEodAcquisitionProfile,
    *,
    authorization_id: str = "test-reviewed-tiingo-authorization",
    reviewed_at: datetime = AUTHORIZATION_REVIEWED_AT,
    terms_sha256: str = TERMS_SHA256,
    profile_contract_sha256: str | None = None,
    effective_from: date = date(2026, 1, 1),
    effective_through: date | None = date(2026, 12, 31),
    permits_local_snapshot_storage: bool = True,
    permits_research_use: bool = True,
) -> bytes:
    return TiingoEodCaptureAuthorization(
        authorization_id=authorization_id,
        reviewer_id="test-authorization-reviewer",
        reviewed_at=reviewed_at,
        terms_sha256=terms_sha256,
        profile_contract_sha256=(profile_contract_sha256 or selected_profile.contract_sha256),
        effective_from=effective_from,
        effective_through=effective_through,
        permits_local_snapshot_storage=permits_local_snapshot_storage,
        permits_research_use=permits_research_use,
    ).to_json_bytes()


def economic_row(
    trading_date: date,
    *,
    volume: int = 1_000_001,
) -> dict[str, object]:
    return {
        "date": f"{trading_date.isoformat()}T00:00:00.000Z",
        "close": 102.375,
        "high": 103.5,
        "low": 99.875,
        "open": 101.125,
        "volume": volume,
        "adjClose": 51.1875,
        "adjHigh": 51.75,
        "adjLow": 49.9375,
        "adjOpen": 50.5625,
        "adjVolume": volume * 2,
        "divCash": 0.25,
        "splitFactor": 2.0,
    }


def response_bytes(
    *dates: date,
    volume: int = 1_000_001,
) -> bytes:
    selected_dates = dates or (SESSION_DATE,)
    return json.dumps(
        [
            economic_row(trading_date, volume=volume + index)
            for index, trading_date in enumerate(selected_dates)
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def calendar(
    symbol: str,
    *,
    session_dates: tuple[date, ...] = (SESSION_DATE,),
    calendar_id: str | None = None,
    version: str | None = None,
    venue: str | None = None,
    close_hour: int = 20,
) -> ExchangeCalendar:
    selected_venue = venue or VENUE_BY_SYMBOL[symbol]
    return ExchangeCalendar(
        calendar_id=calendar_id or f"{symbol}-CALENDAR",
        version=version or f"{symbol.lower()}-2026a",
        venue=selected_venue,
        timezone="America/New_York",
        sessions=tuple(
            ExchangeSession(
                venue=selected_venue,
                session_label=session_date,
                opens_at=datetime.combine(
                    session_date,
                    datetime.min.time(),
                    tzinfo=UTC,
                ).replace(hour=13, minute=30),
                closes_at=datetime.combine(
                    session_date,
                    datetime.min.time(),
                    tzinfo=UTC,
                ).replace(hour=close_hour),
            )
            for session_date in session_dates
        ),
    )


def calendars(
    *,
    symbols: tuple[str, ...] = SYMBOLS,
    session_dates: tuple[date, ...] = (SESSION_DATE,),
) -> dict[str, ExchangeCalendar]:
    return {
        symbol: calendar(
            symbol,
            session_dates=session_dates,
            close_hour=19 + index,
        )
        for index, symbol in enumerate(symbols)
    }


def pinned_calendar_artifact(
    selected_profile: TiingoEodAcquisitionProfile,
    *,
    selected_calendars: Mapping[str, ExchangeCalendar] | None = None,
    approved: bool = True,
    reviewed_at: datetime = CALENDAR_REVIEWED_AT,
    calendar_authority: str | None = None,
    profile_contract_sha256: str | None = None,
) -> bytes:
    calendar_values = selected_calendars or calendars(symbols=selected_profile.scope.symbols)
    return TiingoEodPinnedCalendarArtifact(
        artifact_id="test-reviewed-tiingo-calendar",
        approved=approved,
        reviewer_id="test-calendar-reviewer",
        reviewed_at=reviewed_at,
        profile_contract_sha256=(profile_contract_sha256 or selected_profile.contract_sha256),
        calendar_authority=(calendar_authority or selected_profile.calendar_authority),
        tzdata_version="2026a",
        scope=selected_profile.scope,
        calendars=tuple(
            TiingoEodPinnedCalendar(symbol=symbol, calendar=calendar_values[symbol])
            for symbol in selected_profile.scope.symbols
        ),
    ).to_json_bytes()


@dataclass(frozen=True, slots=True)
class SyntheticCapture:
    repository_root: Path
    capture_name: str
    capture_directory: Path
    manifest_path: Path
    manifest: TiingoEodCaptureManifest
    profile: TiingoEodAcquisitionProfile
    authorization_bytes: bytes
    calendar_artifact_bytes: bytes
    calendars_by_symbol: dict[str, ExchangeCalendar]

    @property
    def object_paths(self) -> tuple[Path, ...]:
        return tuple(
            self.capture_directory / object_path
            for object_path in sorted(
                {response.object_path for response in self.manifest.responses}
            )
        )


def _mkdir_owner_only(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def write_capture(
    repository_root: Path,
    *,
    selected_profile: TiingoEodAcquisitionProfile | None = None,
    authorization_bytes: bytes | None = None,
    calendar_artifact_bytes: bytes | None = None,
    payloads: Mapping[str, bytes] | None = None,
    selected_calendars: dict[str, ExchangeCalendar] | None = None,
    capture_requested_at: datetime = CAPTURE_REQUESTED_AT,
) -> SyntheticCapture:
    selected_profile = selected_profile or profile()
    authorization_bytes = authorization_bytes or authorization(selected_profile)
    selected_calendars = selected_calendars or calendars(symbols=selected_profile.scope.symbols)
    calendar_artifact_bytes = calendar_artifact_bytes or pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    payloads = payloads or {
        symbol: response_bytes(volume=1_000_000 + index)
        for index, symbol in enumerate(selected_profile.scope.symbols)
    }
    receipts: list[TiingoEodCaptureReceipt] = []
    objects: dict[str, bytes] = {}
    for index, symbol in enumerate(selected_profile.scope.symbols):
        payload = payloads[symbol]
        digest = hashlib.sha256(payload).hexdigest()
        objects.setdefault(digest, payload)
        requested_at = capture_requested_at + timedelta(seconds=index * 2)
        received_at = requested_at + timedelta(seconds=1)
        receipts.append(
            TiingoEodCaptureReceipt(
                symbol=symbol,
                object_path=f"objects/{digest}.json",
                sha256=digest,
                byte_count=len(payload),
                requested_at=requested_at,
                received_at=received_at,
            )
        )

    parsed_authorization = TiingoEodCaptureAuthorization.from_json_bytes(authorization_bytes)
    manifest = TiingoEodCaptureManifest(
        profile=selected_profile,
        profile_contract_sha256=selected_profile.contract_sha256,
        responses=tuple(receipts),
        requested_at=receipts[0].requested_at,
        received_at=receipts[-1].received_at,
        authorization_sha256=hashlib.sha256(authorization_bytes).hexdigest(),
        calendar_artifact_sha256=hashlib.sha256(calendar_artifact_bytes).hexdigest(),
        terms_sha256=parsed_authorization.terms_sha256,
    )
    manifest_bytes = manifest.to_json_bytes()
    capture_name = tiingo_eod_capture_name(manifest_bytes)
    capture_root = repository_root
    for part in (".local", "vendor-snapshots", "tiingo-eod"):
        capture_root = capture_root / part
        _mkdir_owner_only(capture_root)
    capture_directory = capture_root / capture_name
    _mkdir_owner_only(capture_directory)
    objects_directory = capture_directory / "objects"
    _mkdir_owner_only(objects_directory)
    for digest, payload in objects.items():
        object_path = objects_directory / f"{digest}.json"
        object_path.write_bytes(payload)
        object_path.chmod(0o400)
    manifest_path = capture_directory / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    manifest_path.chmod(0o400)
    objects_directory.chmod(0o500)
    capture_directory.chmod(0o500)
    return SyntheticCapture(
        repository_root=repository_root,
        capture_name=capture_name,
        capture_directory=capture_directory,
        manifest_path=manifest_path,
        manifest=manifest,
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_artifact_bytes,
        calendars_by_symbol=selected_calendars,
    )


def replace_file(path: Path, payload: bytes) -> None:
    path.parent.chmod(0o700)
    if path.exists() and not path.is_symlink():
        path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)
    path.parent.chmod(0o500)


def rewrite_manifest(
    capture: SyntheticCapture,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    payload = cast(dict[str, Any], json.loads(capture.manifest_path.read_bytes()))
    mutate(payload)
    rewritten = (json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    replace_file(capture.manifest_path, rewritten)
    try:
        rebound_name = tiingo_eod_capture_name(rewritten)
    except (TypeError, ValueError):
        return
    rebound_directory = capture.capture_directory.parent / rebound_name
    capture.capture_directory.rename(rebound_directory)
    object.__setattr__(capture, "capture_name", rebound_name)
    object.__setattr__(capture, "capture_directory", rebound_directory)
    object.__setattr__(capture, "manifest_path", rebound_directory / "manifest.json")


def bind_authorization(capture: SyntheticCapture, artifact: bytes) -> None:
    rewrite_manifest(
        capture,
        lambda payload: payload.__setitem__(
            "authorization_sha256",
            hashlib.sha256(artifact).hexdigest(),
        ),
    )


def verify(
    capture: SyntheticCapture,
    *,
    repository_root: Path | None = None,
    capture_name: str | None = None,
    expected_profile: TiingoEodAcquisitionProfile | None = None,
    authorization_bytes: bytes | None = None,
    calendar_artifact_bytes: bytes | None = None,
) -> TiingoEodVerifiedResearchSnapshot:
    return verify_tiingo_eod_capture(
        repository_root=repository_root or capture.repository_root,
        capture_name=(capture.capture_name if capture_name is None else capture_name),
        expected_profile=expected_profile or capture.profile,
        authorization_bytes=(
            capture.authorization_bytes if authorization_bytes is None else authorization_bytes
        ),
        calendar_artifact_bytes=(
            capture.calendar_artifact_bytes
            if calendar_artifact_bytes is None
            else calendar_artifact_bytes
        ),
    )


def test_verified_capture_is_deterministic_heterogeneous_and_research_only(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)

    first = verify(capture)
    second = verify(capture)

    assert first == second
    assert first.manifest == capture.manifest
    assert first.manifest_sha256 == hashlib.sha256(capture.manifest_path.read_bytes()).hexdigest()
    assert capture.capture_name.endswith(first.manifest_sha256)
    assert len(first.capture_sha256) == 64
    assert first.schema_version == "tiingo-eod-verified-research-v2"
    assert (
        first.calendar_artifact_sha256
        == hashlib.sha256(capture.calendar_artifact_bytes).hexdigest()
    )
    assert len(first.semantic_sha256) == 64
    assert tuple(observation.symbol for observation in first.observations) == SYMBOLS
    assert tuple(row.symbol for row in first.rows) == SYMBOLS
    assert tuple(binding.symbol for binding in first.calendar_bindings) == SYMBOLS
    assert {
        binding.symbol: (
            binding.calendar_id,
            binding.calendar_version,
            binding.venue,
        )
        for binding in first.calendar_bindings
    } == {
        symbol: (
            capture.calendars_by_symbol[symbol].calendar_id,
            capture.calendars_by_symbol[symbol].version,
            capture.calendars_by_symbol[symbol].venue,
        )
        for symbol in SYMBOLS
    }
    assert {row.symbol: row.interval_end.hour for row in first.rows} == {
        symbol: 19 + index for index, symbol in enumerate(SYMBOLS)
    }

    for operation in (
        first.raw_bar_records,
        first.canonical_bar_records,
        first.historical_bar_source,
        first.admission_evidence,
        first.revision_lineage,
    ):
        with pytest.raises(TiingoEodError):
            operation()


def test_recorded_snapshot_wrapper_has_the_same_strict_result(tmp_path: Path) -> None:
    capture = write_capture(tmp_path)

    direct = verify(capture)
    recorded = RecordedTiingoEodResearchSnapshot(
        capture.repository_root,
        capture.capture_name,
        expected_profile=capture.profile,
        authorization_bytes=capture.authorization_bytes,
        calendar_artifact_bytes=capture.calendar_artifact_bytes,
    )
    wrapped = recorded.verify()

    assert not isinstance(recorded, HistoricalBarSource)
    assert not hasattr(recorded, "load")
    assert wrapped == direct


def test_verified_snapshot_cannot_be_directly_constructed_or_replaced(
    tmp_path: Path,
) -> None:
    snapshot = verify(write_capture(tmp_path))

    with pytest.raises(TypeError, match="only be created by the verifier"):
        TiingoEodVerifiedResearchSnapshot(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact_sha256=snapshot.calendar_artifact_sha256,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256=snapshot.semantic_sha256,
            observations=snapshot.observations,
            rows=snapshot.rows,
        )
    with pytest.raises(TypeError, match="only be created by the verifier"):
        replace(snapshot, capture_sha256="0" * 64)


def test_verified_snapshot_factory_recomputes_capture_and_semantic_digests(
    tmp_path: Path,
) -> None:
    snapshot = verify(write_capture(tmp_path))

    with pytest.raises(ValueError, match="capture digest"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256="0" * 64,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256=snapshot.semantic_sha256,
            observations=snapshot.observations,
            rows=snapshot.rows,
        )
    mismatched_artifact = replace(
        snapshot.calendar_artifact,
        reviewed_at=snapshot.calendar_artifact.reviewed_at + timedelta(seconds=1),
    )
    with pytest.raises(ValueError, match="calendar artifact digest"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact=mismatched_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256=snapshot.semantic_sha256,
            observations=snapshot.observations,
            rows=snapshot.rows,
        )
    with pytest.raises(ValueError, match="semantic digest"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256="0" * 64,
            observations=snapshot.observations,
            rows=snapshot.rows,
        )
    with pytest.raises(ValueError, match="unsupported verified Tiingo EOD research schema"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256=snapshot.semantic_sha256,
            observations=snapshot.observations,
            rows=snapshot.rows,
            schema_version="tiingo-eod-verified-research-v1",
        )


def test_verified_snapshot_rows_are_bound_to_the_exact_observation_payloads(
    tmp_path: Path,
) -> None:
    snapshot = verify(write_capture(tmp_path))
    forged_row = replace(snapshot.rows[0], volume=snapshot.rows[0].volume + 1)
    forged_rows = (forged_row, *snapshot.rows[1:])

    with pytest.raises(ValueError, match="exactly derived"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256=snapshot.semantic_sha256,
            observations=snapshot.observations,
            rows=forged_rows,
        )

    original = snapshot.observations[0]
    forged_payload = original.payload.replace(b'"close":102.375', b'"close":102.374')
    assert len(forged_payload) == len(original.payload) and forged_payload != original.payload
    forged_observation = replace(original, payload=forged_payload)
    forged_observations = (forged_observation, *snapshot.observations[1:])
    with pytest.raises(ValueError, match="manifest receipt"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=snapshot.calendar_bindings,
            semantic_sha256=snapshot.semantic_sha256,
            observations=forged_observations,
            rows=snapshot.rows,
        )


def test_verified_snapshot_bindings_are_derived_from_the_exact_calendar_artifact(
    tmp_path: Path,
) -> None:
    snapshot = verify(write_capture(tmp_path))
    original = snapshot.calendar_bindings[0]
    forged_calendar = ExchangeCalendar(
        calendar_id=f"{original.calendar_id}-FORGED",
        version=original.calendar_version,
        venue=original.venue,
        timezone=original.timezone,
        sessions=original.sessions,
    )
    forged_binding = snapshot_module._calendar_binding(
        symbol=original.symbol,
        authority=original.authority,
        calendar=forged_calendar,
    )[0]
    forged_bindings = (forged_binding, *snapshot.calendar_bindings[1:])
    forged_semantic_sha256 = snapshot_module._verified_research_semantic_sha256(
        manifest=snapshot.manifest,
        capture_sha256=snapshot.capture_sha256,
        calendar_artifact_sha256=snapshot.calendar_artifact_sha256,
        calendar_bindings=forged_bindings,
    )

    with pytest.raises(ValueError, match="not exactly derived from the pinned artifact"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=snapshot.manifest,
            capture_sha256=snapshot.capture_sha256,
            calendar_artifact=snapshot.calendar_artifact,
            calendar_bindings=forged_bindings,
            semantic_sha256=forged_semantic_sha256,
            observations=snapshot.observations,
            rows=snapshot.rows,
        )


def test_verified_snapshot_rows_are_bound_to_exact_calendar_session_metadata(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)
    snapshot = verify(capture)
    binding = snapshot.calendar_bindings[0]
    changed_session = replace(
        binding.sessions[0],
        closes_at=binding.sessions[0].closes_at - timedelta(minutes=1),
    )

    with pytest.raises(ValueError, match="calendar binding digest"):
        replace(binding, sessions=(changed_session, *binding.sessions[1:]))

    changed_calendars = dict(capture.calendars_by_symbol)
    changed_calendars[binding.symbol] = calendar(binding.symbol, close_hour=18)
    changed_snapshot = verify(
        write_capture(
            tmp_path / "changed-calendar",
            selected_profile=capture.profile,
            authorization_bytes=capture.authorization_bytes,
            selected_calendars=changed_calendars,
        )
    )
    with pytest.raises(ValueError, match="exactly derived"):
        TiingoEodVerifiedResearchSnapshot._from_verified_components(
            manifest=changed_snapshot.manifest,
            capture_sha256=changed_snapshot.capture_sha256,
            calendar_artifact=changed_snapshot.calendar_artifact,
            calendar_bindings=changed_snapshot.calendar_bindings,
            semantic_sha256=changed_snapshot.semantic_sha256,
            observations=changed_snapshot.observations,
            rows=snapshot.rows,
        )


def test_content_addressed_object_may_be_shared_by_multiple_symbol_receipts(
    tmp_path: Path,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("DIA", "SPY")))
    shared_payload = response_bytes()
    capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        payloads={"DIA": shared_payload, "SPY": shared_payload},
    )

    snapshot = verify(capture)

    assert len(tuple((capture.capture_directory / "objects").iterdir())) == 1
    assert len(snapshot.observations) == 2
    assert {observation.payload for observation in snapshot.observations} == {shared_payload}


def test_calendar_artifact_requires_exact_manifest_bound_canonical_bytes(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)
    presentation_change = json.dumps(
        json.loads(capture.calendar_artifact_bytes),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert presentation_change != capture.calendar_artifact_bytes
    substituted = pinned_calendar_artifact(
        capture.profile,
        selected_calendars=capture.calendars_by_symbol,
        reviewed_at=CALENDAR_REVIEWED_AT + timedelta(seconds=1),
    )

    for artifact_bytes in (presentation_change, substituted):
        with pytest.raises(TiingoEodError, match=r"calendar|canonical|digest"):
            verify(capture, calendar_artifact_bytes=artifact_bytes)


@pytest.mark.parametrize("mismatch", ["authority", "profile", "review_order", "approval"])
def test_calendar_artifact_is_reauthorized_against_the_manifest_profile(
    tmp_path: Path,
    mismatch: str,
) -> None:
    selected_profile = profile()
    selected_calendars = calendars()
    kwargs: dict[str, object] = {"selected_calendars": selected_calendars}
    if mismatch == "authority":
        kwargs["calendar_authority"] = "another-calendar-authority"
    elif mismatch == "profile":
        kwargs["profile_contract_sha256"] = profile(
            market_provenance="different-market-provenance"
        ).contract_sha256
    elif mismatch == "review_order":
        kwargs["reviewed_at"] = PROFILE_REVIEWED_AT - timedelta(seconds=1)
    else:
        kwargs["approved"] = False
    artifact_bytes = pinned_calendar_artifact(selected_profile, **kwargs)
    capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        calendar_artifact_bytes=artifact_bytes,
        selected_calendars=selected_calendars,
    )

    with pytest.raises(TiingoEodError, match=r"calendar|profile|approved|predates"):
        verify(capture)


def test_semantic_identity_binds_each_calendar_identity_and_session_bounds(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path / "baseline")
    baseline = verify(capture)

    changed_version = dict(capture.calendars_by_symbol)
    changed_version["QQQ"] = calendar("QQQ", version="qqq-2026b", close_hour=21)
    changed_bounds = dict(capture.calendars_by_symbol)
    changed_bounds["DIA"] = calendar("DIA", close_hour=18)

    version_snapshot = verify(
        write_capture(
            tmp_path / "version",
            selected_profile=capture.profile,
            authorization_bytes=capture.authorization_bytes,
            selected_calendars=changed_version,
        )
    )
    bounds_snapshot = verify(
        write_capture(
            tmp_path / "bounds",
            selected_profile=capture.profile,
            authorization_bytes=capture.authorization_bytes,
            selected_calendars=changed_bounds,
        )
    )

    assert baseline.capture_sha256 != version_snapshot.capture_sha256
    assert baseline.capture_sha256 != bounds_snapshot.capture_sha256
    assert baseline.calendar_artifact_sha256 != version_snapshot.calendar_artifact_sha256
    assert baseline.calendar_artifact_sha256 != bounds_snapshot.calendar_artifact_sha256
    assert baseline.semantic_sha256 != version_snapshot.semantic_sha256
    assert baseline.semantic_sha256 != bounds_snapshot.semantic_sha256
    assert bounds_snapshot.rows[0].interval_end != baseline.rows[0].interval_end


def test_reviewed_calendar_may_mark_scope_boundaries_as_non_sessions(tmp_path: Path) -> None:
    selected_scope = scope(
        start_date=SESSION_DATE - timedelta(days=2),
        end_date=SECOND_SESSION_DATE + timedelta(days=3),
    )
    selected_profile = profile(capture_scope=selected_scope)
    payloads = {
        symbol: response_bytes(SESSION_DATE, SECOND_SESSION_DATE, volume=1_000_000 + index)
        for index, symbol in enumerate(SYMBOLS)
    }
    capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        payloads=payloads,
        selected_calendars=calendars(
            symbols=SYMBOLS,
            session_dates=(SESSION_DATE, SECOND_SESSION_DATE),
        ),
    )
    assert len(verify(capture).rows) == len(SYMBOLS) * 2


def test_every_symbol_requires_every_calendar_session(tmp_path: Path) -> None:
    selected_scope = scope(start_date=SESSION_DATE, end_date=SECOND_SESSION_DATE)
    selected_profile = profile(capture_scope=selected_scope)
    payloads = {
        symbol: response_bytes(SESSION_DATE, SECOND_SESSION_DATE, volume=1_000_000 + index)
        for index, symbol in enumerate(SYMBOLS)
    }
    payloads["QQQ"] = response_bytes(SESSION_DATE)
    capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        payloads=payloads,
        selected_calendars=calendars(
            symbols=SYMBOLS,
            session_dates=(SESSION_DATE, SECOND_SESSION_DATE),
        ),
    )

    with pytest.raises(
        TiingoEodError,
        match=r"missing|required session|coverage|response dates",
    ):
        verify(capture)


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "/tmp/capture",
        "../capture",
        "capture/manifest.json",
        r"capture\manifest.json",
        ".staging-capture-deadbeef",
        ".publish-capture.lock",
    ],
)
def test_capture_name_is_a_strict_final_single_component(
    tmp_path: Path,
    value: str,
) -> None:
    capture = write_capture(tmp_path)

    with pytest.raises(TiingoEodError):
        verify(capture, capture_name=value)


def test_capture_must_exist_under_the_fixed_repository_root(tmp_path: Path) -> None:
    capture = write_capture(tmp_path / "real")
    unrelated_repository = tmp_path / "other"
    unrelated_repository.mkdir()

    with pytest.raises(TiingoEodError):
        verify(capture, repository_root=unrelated_repository)


def test_final_capture_name_is_recomputed_from_the_manifest(tmp_path: Path) -> None:
    capture = write_capture(tmp_path)
    wrong_name = f"{capture.capture_name[:-64]}{'0' * 64}"
    if wrong_name == capture.capture_name:
        wrong_name = f"{capture.capture_name[:-64]}{'1' * 64}"
    capture.capture_directory.rename(capture.capture_directory.parent / wrong_name)

    with pytest.raises(TiingoEodError, match=r"name|identity"):
        verify(capture, capture_name=wrong_name)


def test_unrelated_hidden_crash_residue_does_not_invalidate_a_final_capture(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)
    root = capture.capture_directory.parent
    staging = root / ".staging-unrelated-deadbeef"
    staging.mkdir()
    staging.chmod(0o700)
    lock = root / ".publish-unrelated.lock"
    lock.write_bytes(b"")
    lock.chmod(0o400)

    assert verify(capture).manifest == capture.manifest


def test_capture_producer_and_offline_verifier_share_full_manifest_identity(
    tmp_path: Path,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    artifact = authorization(selected_profile)
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars={"SPY": calendar("SPY")},
    )
    payload = response_bytes()
    clock_values = iter(
        (
            CAPTURE_REQUESTED_AT,
            CAPTURE_REQUESTED_AT + timedelta(seconds=1),
        )
    )

    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token="synthetic-test-token",
        profile=selected_profile,
        authorization_bytes=artifact,
        calendar_artifact_bytes=calendar_bytes,
        transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
            status=200,
            payload=payload,
        ),
        clock=lambda: next(clock_values),
    )
    manifest_bytes = manifest_path.read_bytes()

    verified = verify_tiingo_eod_capture(
        repository_root=tmp_path,
        capture_name=manifest_path.parent.name,
        expected_profile=selected_profile,
        authorization_bytes=artifact,
        calendar_artifact_bytes=calendar_bytes,
    )

    assert manifest_path.parent.name == tiingo_eod_capture_name(manifest_bytes)
    assert manifest_path.parent.name.endswith(hashlib.sha256(manifest_bytes).hexdigest())
    assert verified.manifest_sha256 == hashlib.sha256(manifest_bytes).hexdigest()
    assert verified.calendar_artifact_sha256 == hashlib.sha256(calendar_bytes).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    ["final_capture_swap", "objects_swap", "capture_mode", "post_list_entry"],
)
def test_directory_races_after_initial_entry_lists_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    capture = write_capture(tmp_path)
    objects = capture.capture_directory / "objects"
    replacement = tmp_path / f"replacement-{mutation}"
    if mutation == "final_capture_swap":
        shutil.copytree(capture.capture_directory, replacement, copy_function=shutil.copy2)
    elif mutation == "objects_swap":
        shutil.copytree(objects, replacement, copy_function=shutil.copy2)

    original_listdir = os.listdir
    list_calls = 0
    raced = False

    def racing_listdir(path: int) -> list[str]:
        nonlocal list_calls, raced
        entries = original_listdir(path)
        list_calls += 1
        if list_calls != 2:
            return entries
        raced = True
        if mutation == "final_capture_swap":
            displaced = capture.capture_directory.parent / ".race-original-capture"
            capture.capture_directory.rename(displaced)
            replacement.rename(capture.capture_directory)
        elif mutation == "objects_swap":
            displaced = capture.capture_directory / ".race-original-objects"
            capture.capture_directory.chmod(0o700)
            objects.rename(displaced)
            replacement.rename(objects)
            capture.capture_directory.chmod(0o500)
        elif mutation == "capture_mode":
            capture.capture_directory.chmod(0o700)
        else:
            objects.chmod(0o700)
            extra = objects / "post-list-entry.json"
            extra.write_bytes(b"{}")
            extra.chmod(0o400)
            objects.chmod(0o500)
        return entries

    monkeypatch.setattr(os, "listdir", racing_listdir)

    with pytest.raises(TiingoEodError, match=r"changed|directory|entries|identifies"):
        verify(capture)
    assert raced is True


@pytest.mark.parametrize(
    "mutation",
    ["manifest_swap", "object_swap", "manifest_mode", "object_mode", "fixed_root_swap"],
)
def test_final_revalidation_detects_post_read_file_and_root_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    capture = write_capture(tmp_path)
    object_path = capture.object_paths[0]
    target = capture.manifest_path if mutation.startswith("manifest") else object_path
    replacement = tmp_path / f"replacement-{target.name}"
    if mutation.endswith("swap") and mutation != "fixed_root_swap":
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o400)
    if mutation == "fixed_root_swap":
        replacement.mkdir(mode=0o700)

    original_revalidate = snapshot_module._revalidate_capture_tree
    raced = False

    def racing_revalidate(**kwargs: Any) -> None:
        nonlocal raced
        raced = True
        if mutation == "manifest_swap":
            displaced = tmp_path / "displaced-manifest.json"
            capture.capture_directory.chmod(0o700)
            capture.manifest_path.rename(displaced)
            replacement.rename(capture.manifest_path)
            capture.capture_directory.chmod(0o500)
        elif mutation == "object_swap":
            displaced = tmp_path / "displaced-object.json"
            object_path.parent.chmod(0o700)
            object_path.rename(displaced)
            replacement.rename(object_path)
            object_path.parent.chmod(0o500)
        elif mutation == "manifest_mode":
            capture.manifest_path.chmod(0o600)
        elif mutation == "object_mode":
            object_path.chmod(0o600)
        else:
            capture_root = capture.capture_directory.parent
            displaced = capture_root.parent / ".race-original-tiingo-root"
            capture_root.rename(displaced)
            replacement.rename(capture_root)
        original_revalidate(**kwargs)

    monkeypatch.setattr(snapshot_module, "_revalidate_capture_tree", racing_revalidate)

    with pytest.raises(TiingoEodError, match=r"changed|metadata|root|identifies"):
        verify(capture)
    assert raced is True


@pytest.mark.parametrize("target", ["repository", "capture", "objects", "manifest", "object"])
def test_loader_never_follows_path_component_or_file_symlinks(
    tmp_path: Path,
    target: str,
) -> None:
    capture = write_capture(tmp_path / "repository")
    repository_root = capture.repository_root
    symlink_path: Path | None = None
    relocated_path: Path | None = None
    if target == "repository":
        alias = tmp_path / "repository-alias"
        alias.symlink_to(repository_root, target_is_directory=True)
        repository_root = alias
        symlink_path = alias
    elif target == "capture":
        real_capture = tmp_path / "real-capture"
        capture.capture_directory.chmod(0o700)
        capture.capture_directory.rename(real_capture)
        capture.capture_directory.symlink_to(real_capture, target_is_directory=True)
        symlink_path = capture.capture_directory
        relocated_path = real_capture
    elif target == "objects":
        objects = capture.capture_directory / "objects"
        real_objects = tmp_path / "real-objects"
        capture.capture_directory.chmod(0o700)
        objects.chmod(0o700)
        objects.rename(real_objects)
        objects.symlink_to(real_objects, target_is_directory=True)
        capture.capture_directory.chmod(0o500)
        symlink_path = objects
        relocated_path = real_objects
    elif target == "manifest":
        real_manifest = tmp_path / "real-manifest.json"
        capture.capture_directory.chmod(0o700)
        capture.manifest_path.rename(real_manifest)
        capture.manifest_path.symlink_to(real_manifest)
        capture.capture_directory.chmod(0o500)
        symlink_path = capture.manifest_path
        relocated_path = real_manifest
    else:
        object_path = capture.object_paths[0]
        real_object = tmp_path / "real-object.json"
        object_path.parent.chmod(0o700)
        object_path.rename(real_object)
        object_path.symlink_to(real_object)
        object_path.parent.chmod(0o500)
        symlink_path = object_path
        relocated_path = real_object

    try:
        with pytest.raises(
            TiingoEodError,
            match=r"symlink|path|read|directory|file|finalized|unsafe",
        ):
            verify(capture, repository_root=repository_root)
    finally:
        if symlink_path is not None and symlink_path.is_symlink():
            symlink_path.parent.chmod(0o700)
            symlink_path.unlink()
        for directory in (
            relocated_path / "objects" if relocated_path is not None else None,
            relocated_path,
            capture.capture_directory / "objects",
            capture.capture_directory,
        ):
            if directory is not None and not directory.is_symlink() and directory.is_dir():
                directory.chmod(0o700)
                for child in directory.iterdir():
                    if child.is_file() and not child.is_symlink():
                        child.chmod(0o600)
        if relocated_path is not None and relocated_path.is_file():
            relocated_path.chmod(0o600)


@pytest.mark.parametrize(
    ("target", "mode"),
    [
        ("capture", 0o700),
        ("capture", 0o555),
        ("objects", 0o700),
        ("objects", 0o555),
        ("manifest", 0o600),
        ("manifest", 0o440),
        ("object", 0o600),
        ("object", 0o440),
    ],
)
def test_final_directories_and_files_require_exact_0500_and_0400_modes(
    tmp_path: Path,
    target: str,
    mode: int,
) -> None:
    capture = write_capture(tmp_path)
    paths = {
        "capture": capture.capture_directory,
        "objects": capture.capture_directory / "objects",
        "manifest": capture.manifest_path,
        "object": capture.object_paths[0],
    }
    paths[target].chmod(mode)

    with pytest.raises(TiingoEodError, match=r"mode|permission|owner-only|immutable"):
        verify(capture)


@pytest.mark.parametrize("target", ["manifest", "object"])
def test_manifest_and_objects_must_be_single_link_files(
    tmp_path: Path,
    target: str,
) -> None:
    capture = write_capture(tmp_path)
    source = capture.manifest_path if target == "manifest" else capture.object_paths[0]
    os.link(source, tmp_path / f"{target}-hard-link")

    with pytest.raises(TiingoEodError, match=r"link|regular file"):
        verify(capture)


@pytest.mark.parametrize("target", ["manifest", "object"])
def test_loader_rejects_fifo_without_blocking(tmp_path: Path, target: str) -> None:
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    file_flags = vars(snapshot_module)["_FILE_FLAGS"]
    assert nonblocking and isinstance(file_flags, int) and file_flags & nonblocking
    capture = write_capture(tmp_path)
    path = capture.manifest_path if target == "manifest" else capture.object_paths[0]
    path.parent.chmod(0o700)
    path.unlink()
    os.mkfifo(path, mode=0o400)
    path.parent.chmod(0o500)

    with pytest.raises(TiingoEodError, match="regular file"):
        verify(capture)


@pytest.mark.parametrize(
    ("target", "limit"),
    [
        ("manifest", MAX_TIINGO_MANIFEST_BYTES),
        ("object", MAX_TIINGO_RESPONSE_BYTES),
    ],
)
def test_manifest_and_objects_are_read_with_strict_size_limits(
    tmp_path: Path,
    target: str,
    limit: int,
) -> None:
    capture = write_capture(tmp_path)
    path = capture.manifest_path if target == "manifest" else capture.object_paths[0]
    path.parent.chmod(0o700)
    path.chmod(0o600)
    with path.open("r+b") as stream:
        stream.truncate(limit + 1)
    path.chmod(0o400)
    path.parent.chmod(0o500)

    with pytest.raises(TiingoEodError, match=r"size|limit"):
        verify(capture)


def test_capture_entries_must_be_owned_by_the_current_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = write_capture(tmp_path)
    actual_uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(TiingoEodError, match=r"owner|current user"):
        verify(capture)


@pytest.mark.parametrize(
    "mutation",
    ["missing_manifest", "missing_object", "extra_file", "extra_object"],
)
def test_capture_tree_must_exactly_match_the_manifest(
    tmp_path: Path,
    mutation: str,
) -> None:
    capture = write_capture(tmp_path)
    if mutation == "missing_manifest":
        capture.capture_directory.chmod(0o700)
        capture.manifest_path.unlink()
        capture.capture_directory.chmod(0o500)
    elif mutation == "missing_object":
        object_path = capture.object_paths[0]
        object_path.parent.chmod(0o700)
        object_path.unlink()
        object_path.parent.chmod(0o500)
    elif mutation == "extra_file":
        capture.capture_directory.chmod(0o700)
        extra = capture.capture_directory / "notes.txt"
        extra.write_bytes(b"unrecognized")
        extra.chmod(0o400)
        capture.capture_directory.chmod(0o500)
    else:
        objects = capture.capture_directory / "objects"
        objects.chmod(0o700)
        extra = objects / f"{'f' * 64}.json"
        extra.write_bytes(response_bytes())
        extra.chmod(0o400)
        objects.chmod(0o500)

    with pytest.raises(TiingoEodError):
        verify(capture)


@pytest.mark.parametrize("mutation", ["missing", "unknown", "duplicate", "response_unknown"])
def test_capture_manifest_json_is_strict(tmp_path: Path, mutation: str) -> None:
    capture = write_capture(tmp_path)
    if mutation == "missing":
        rewrite_manifest(capture, lambda payload: payload.pop("provider"))
    elif mutation == "unknown":
        rewrite_manifest(capture, lambda payload: payload.__setitem__("admitted", True))
    elif mutation == "response_unknown":
        rewrite_manifest(
            capture,
            lambda payload: cast(list[dict[str, Any]], payload["responses"])[0].__setitem__(
                "revision", 1
            ),
        )
    else:
        manifest_bytes = capture.manifest_path.read_bytes()
        field = b'"provider": "tiingo",'
        assert field in manifest_bytes
        replace_file(
            capture.manifest_path,
            manifest_bytes.replace(field, field + b'\n  "provider": "tiingo",', 1),
        )

    with pytest.raises(TiingoEodError):
        verify(capture)


@pytest.mark.parametrize(
    "object_path",
    ["../escape.json", "/tmp/escape.json", r"objects\escape.json"],
)
def test_manifest_object_paths_are_strict_descriptor_relative_paths(
    tmp_path: Path,
    object_path: str,
) -> None:
    capture = write_capture(tmp_path)
    rewrite_manifest(
        capture,
        lambda payload: cast(list[dict[str, Any]], payload["responses"])[0].__setitem__(
            "object_path", object_path
        ),
    )

    with pytest.raises(TiingoEodError, match=r"path|content-addressed"):
        verify(capture)


def test_response_byte_count_must_match_the_exact_object(tmp_path: Path) -> None:
    capture = write_capture(tmp_path)
    rewrite_manifest(
        capture,
        lambda payload: cast(list[dict[str, Any]], payload["responses"])[0].__setitem__(
            "byte_count",
            cast(list[dict[str, Any]], payload["responses"])[0]["byte_count"] + 1,
        ),
    )

    with pytest.raises(TiingoEodError, match=r"byte count|size"):
        verify(capture)


def test_swapped_object_bytes_fail_the_receipt_digest(tmp_path: Path) -> None:
    capture = write_capture(tmp_path)
    object_path = capture.object_paths[0]
    original = object_path.read_bytes()
    swapped = original.replace(b"102.375", b"102.374", 1)
    assert len(swapped) == len(original) and swapped != original
    replace_file(object_path, swapped)

    with pytest.raises(TiingoEodError, match="digest"):
        verify(capture)


def test_object_swap_between_metadata_check_and_open_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = write_capture(tmp_path)
    object_path = capture.object_paths[0]
    original_payload = object_path.read_bytes()
    swapped_payload = original_payload.replace(b"102.375", b"102.374", 1)
    assert len(swapped_payload) == len(original_payload)
    original_open = os.open
    swapped = False

    def swapping_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        name = os.fsdecode(path)
        if not swapped and name == object_path.name and dir_fd is not None:
            swapped = True
            os.chmod(name, 0o600, dir_fd=dir_fd, follow_symlinks=False)
            writer = original_open(
                name,
                os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=dir_fd,
            )
            try:
                os.write(writer, swapped_payload)
                os.fchmod(writer, 0o400)
            finally:
                os.close(writer)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swapping_open)

    with pytest.raises(TiingoEodError, match="digest"):
        verify(capture)
    assert swapped is True


@pytest.mark.parametrize("mismatch", ["contract", "symbols", "dates"])
def test_expected_profile_must_exactly_match_the_manifest(
    tmp_path: Path,
    mismatch: str,
) -> None:
    capture = write_capture(tmp_path)
    if mismatch == "contract":
        expected = profile(market_provenance="different-market-provenance")
    elif mismatch == "symbols":
        expected = profile(capture_scope=scope(symbols=("DIA", "IWM", "QQQ")))
    else:
        expected = profile(
            capture_scope=scope(
                start_date=SECOND_SESSION_DATE,
                end_date=SECOND_SESSION_DATE,
            )
        )

    with pytest.raises(TiingoEodError, match=r"expected profile|profile"):
        verify(capture, expected_profile=expected)


def test_authorization_requires_the_exact_artifact_bytes_not_semantic_json(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)
    compact = json.dumps(
        json.loads(capture.authorization_bytes),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    assert compact != capture.authorization_bytes
    assert TiingoEodCaptureAuthorization.from_json_bytes(compact) == (
        TiingoEodCaptureAuthorization.from_json_bytes(capture.authorization_bytes)
    )

    with pytest.raises(
        TiingoEodError,
        match=r"authorization.*(?:bytes|digest)|artifact",
    ):
        verify(capture, authorization_bytes=compact)


@pytest.mark.parametrize("artifact", [b"{}", b"[]", b"not-json"])
def test_manifest_self_asserted_authorization_digest_is_not_authorization(
    tmp_path: Path,
    artifact: bytes,
) -> None:
    capture = write_capture(tmp_path)
    rewrite_manifest(
        capture,
        lambda payload: payload.__setitem__(
            "authorization_sha256", hashlib.sha256(artifact).hexdigest()
        ),
    )

    with pytest.raises(TiingoEodError, match="authorization"):
        verify(capture, authorization_bytes=artifact)


def test_authorization_terms_must_match_the_manifest(tmp_path: Path) -> None:
    capture = write_capture(tmp_path)
    other_terms = hashlib.sha256(b"different reviewed terms").hexdigest()
    artifact = authorization(capture.profile, terms_sha256=other_terms)
    bind_authorization(capture, artifact)

    with pytest.raises(TiingoEodError, match="terms"):
        verify(capture, authorization_bytes=artifact)


@pytest.mark.parametrize(
    "gate",
    ["profile", "review_order", "storage", "research", "effective_window"],
)
def test_exact_authorization_artifact_is_revalidated_against_capture(
    tmp_path: Path,
    gate: str,
) -> None:
    capture = write_capture(tmp_path)
    if gate == "profile":
        different_profile = profile(market_provenance="different-market-provenance")
        artifact = authorization(
            capture.profile,
            profile_contract_sha256=different_profile.contract_sha256,
        )
    elif gate == "review_order":
        artifact = authorization(
            capture.profile,
            reviewed_at=PROFILE_REVIEWED_AT - timedelta(seconds=1),
        )
    elif gate == "storage":
        artifact = authorization(
            capture.profile,
            permits_local_snapshot_storage=False,
        )
    elif gate == "research":
        artifact = authorization(capture.profile, permits_research_use=False)
    else:
        artifact = authorization(
            capture.profile,
            effective_through=SESSION_DATE - timedelta(days=1),
        )
    bind_authorization(capture, artifact)

    with pytest.raises(TiingoEodError, match=r"authorization|profile|permit|scope"):
        verify(capture, authorization_bytes=artifact)


def test_manifest_authorization_digest_must_match_caller_supplied_bytes(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)
    rewrite_manifest(
        capture,
        lambda payload: payload.__setitem__("authorization_sha256", "1" * 64),
    )

    with pytest.raises(
        TiingoEodError,
        match=r"authorization.*(?:bytes|digest)|artifact",
    ):
        verify(capture)


def test_receipt_lineage_preserves_occurrences_and_collapses_unchanged_economics(
    tmp_path: Path,
) -> None:
    selected_profile = profile()
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars()
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    baseline_payloads = {
        symbol: response_bytes(volume=1_000_000 + index) for index, symbol in enumerate(SYMBOLS)
    }
    presentation_changed_payloads = {
        symbol: (
            json.dumps(
                json.loads(payload),
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        for symbol, payload in baseline_payloads.items()
    }
    first_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads=baseline_payloads,
    )
    second_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads=presentation_changed_payloads,
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )
    snapshots = (verify(first_capture), verify(second_capture))

    first = derive_tiingo_eod_receipt_lineage(snapshots)
    second = derive_tiingo_eod_receipt_lineage(snapshots)

    assert first == second
    assert len(first.revisions) == len(SYMBOLS)
    assert len(first.comparisons) == len(SYMBOLS) * 2
    assert tuple(comparison.disposition for comparison in first.comparisons) == (
        *(TiingoEodReceiptDisposition.INITIAL for _ in SYMBOLS),
        *(TiingoEodReceiptDisposition.UNCHANGED for _ in SYMBOLS),
    )
    for initial, unchanged in zip(
        first.comparisons[: len(SYMBOLS)],
        first.comparisons[len(SYMBOLS) :],
        strict=True,
    ):
        assert initial.response_sha256 != unchanged.response_sha256
        assert initial.economics_sha256 == unchanged.economics_sha256
        assert initial.effective_revision_sha256 == unchanged.effective_revision_sha256
        assert unchanged.effective_local_revision == 1
        revision = next(
            value
            for value in first.revisions
            if value.local_observation_id == initial.local_observation_id
        )
        assert revision.observed_at == initial.observed_at


def test_receipt_lineage_decimal_identity_is_compact_and_value_canonical(
    tmp_path: Path,
) -> None:
    assert lineage_module._decimal_text(Decimal("102.3750")) == (
        lineage_module._decimal_text(Decimal("1.02375e2"))
    )
    assert len(lineage_module._decimal_text(Decimal("1e100000"))) < 32

    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(symbols=("SPY",))
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    baseline_payload = response_bytes()
    equivalent_payload = baseline_payload.replace(
        b'"close":102.375',
        b'"close":1.023750e2',
    ).replace(
        b'"divCash":0.25',
        b'"divCash":2.500e-1',
    )
    assert equivalent_payload != baseline_payload
    first_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": baseline_payload},
    )
    second_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": equivalent_payload},
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )

    lineage = derive_tiingo_eod_receipt_lineage((verify(first_capture), verify(second_capture)))

    assert len(lineage.revisions) == 1
    assert lineage.comparisons[-1].disposition is TiingoEodReceiptDisposition.UNCHANGED
    assert lineage.comparisons[0].response_sha256 != lineage.comparisons[1].response_sha256
    assert lineage.comparisons[0].economics_sha256 == lineage.comparisons[1].economics_sha256


def test_receipt_lineage_ignores_response_wide_row_order(tmp_path: Path) -> None:
    selected_scope = scope(
        symbols=("SPY",),
        start_date=SESSION_DATE,
        end_date=SECOND_SESSION_DATE,
    )
    selected_profile = profile(capture_scope=selected_scope)
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(
        symbols=("SPY",),
        session_dates=(SESSION_DATE, SECOND_SESSION_DATE),
    )
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    ordered_payload = response_bytes(SESSION_DATE, SECOND_SESSION_DATE)
    reversed_payload = json.dumps(
        list(reversed(cast(list[dict[str, object]], json.loads(ordered_payload)))),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    first_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": ordered_payload},
    )
    second_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": reversed_payload},
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )

    lineage = derive_tiingo_eod_receipt_lineage((verify(first_capture), verify(second_capture)))

    assert len(lineage.revisions) == 2
    assert [comparison.disposition for comparison in lineage.comparisons] == [
        TiingoEodReceiptDisposition.INITIAL,
        TiingoEodReceiptDisposition.INITIAL,
        TiingoEodReceiptDisposition.UNCHANGED,
        TiingoEodReceiptDisposition.UNCHANGED,
    ]


def test_changed_then_unchanged_creates_only_two_local_revisions(tmp_path: Path) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(symbols=("SPY",))
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    payload_a = {"SPY": response_bytes(volume=1_000_001)}
    payload_b = {"SPY": response_bytes(volume=1_000_111)}
    captures = tuple(
        write_capture(
            tmp_path,
            selected_profile=selected_profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_bytes,
            selected_calendars=selected_calendars,
            payloads=payloads,
            capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=index),
        )
        for index, payloads in enumerate((payload_a, payload_b, payload_b))
    )

    lineage = derive_tiingo_eod_receipt_lineage(tuple(verify(capture) for capture in captures))

    assert [revision.local_revision for revision in lineage.revisions] == [1, 2]
    assert [comparison.disposition for comparison in lineage.comparisons] == [
        TiingoEodReceiptDisposition.INITIAL,
        TiingoEodReceiptDisposition.CHANGED,
        TiingoEodReceiptDisposition.UNCHANGED,
    ]
    assert (
        lineage.comparisons[-1].effective_revision_sha256 == lineage.revisions[-1].revision_sha256
    )
    assert lineage.revisions[-1].supersedes_revision_sha256 == lineage.revisions[0].revision_sha256


def test_changed_then_reverted_creates_a_third_local_revision(tmp_path: Path) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(symbols=("SPY",))
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    payload_a = {"SPY": response_bytes(volume=1_000_001)}
    payload_b = {"SPY": response_bytes(volume=1_000_111)}
    captures = tuple(
        write_capture(
            tmp_path,
            selected_profile=selected_profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_bytes,
            selected_calendars=selected_calendars,
            payloads=payloads,
            capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=index),
        )
        for index, payloads in enumerate((payload_a, payload_b, payload_a))
    )

    lineage = derive_tiingo_eod_receipt_lineage(tuple(verify(capture) for capture in captures))

    assert [revision.local_revision for revision in lineage.revisions] == [1, 2, 3]
    assert [comparison.disposition for comparison in lineage.comparisons] == [
        TiingoEodReceiptDisposition.INITIAL,
        TiingoEodReceiptDisposition.CHANGED,
        TiingoEodReceiptDisposition.CHANGED,
    ]
    assert lineage.revisions[0].economics_sha256 == lineage.revisions[2].economics_sha256
    assert lineage.revisions[0].revision_sha256 != lineage.revisions[2].revision_sha256
    assert lineage.revisions[2].supersedes_revision_sha256 == lineage.revisions[1].revision_sha256


@pytest.mark.parametrize(
    ("field_name", "changed_value"),
    [
        ("open", 101.25),
        ("high", 103.75),
        ("low", 99.75),
        ("close", 102.5),
        ("volume", 1_000_002),
        ("adjOpen", 50.625),
        ("adjHigh", 51.875),
        ("adjLow", 49.875),
        ("adjClose", 51.25),
        ("adjVolume", 2_000_003),
        ("divCash", 0.375),
        ("splitFactor", 1.5),
    ],
)
def test_every_economic_field_participates_in_local_revision_identity(
    tmp_path: Path,
    field_name: str,
    changed_value: object,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(symbols=("SPY",))
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    baseline_row = economic_row(SESSION_DATE)
    changed_row = dict(baseline_row)
    changed_row[field_name] = changed_value
    payloads = tuple(
        {"SPY": json.dumps([row], ensure_ascii=True, separators=(",", ":")).encode("utf-8")}
        for row in (baseline_row, changed_row)
    )
    captures = tuple(
        write_capture(
            tmp_path,
            selected_profile=selected_profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_bytes,
            selected_calendars=selected_calendars,
            payloads=payload,
            capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=index),
        )
        for index, payload in enumerate(payloads)
    )

    lineage = derive_tiingo_eod_receipt_lineage(tuple(verify(capture) for capture in captures))

    assert len(lineage.revisions) == 2
    assert lineage.comparisons[-1].disposition is TiingoEodReceiptDisposition.CHANGED
    assert lineage.revisions[0].economics_sha256 != lineage.revisions[1].economics_sha256


def test_multi_session_lineage_revises_only_the_changed_row(tmp_path: Path) -> None:
    selected_scope = scope(
        symbols=("SPY",),
        start_date=SESSION_DATE,
        end_date=SECOND_SESSION_DATE,
    )
    selected_profile = profile(capture_scope=selected_scope)
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(
        symbols=("SPY",),
        session_dates=(SESSION_DATE, SECOND_SESSION_DATE),
    )
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    first_payload = json.dumps(
        [
            economic_row(SESSION_DATE, volume=1_000_001),
            economic_row(SECOND_SESSION_DATE, volume=1_000_002),
        ],
        separators=(",", ":"),
    ).encode("utf-8")
    second_payload = json.dumps(
        [
            economic_row(SESSION_DATE, volume=1_000_001),
            economic_row(SECOND_SESSION_DATE, volume=1_000_222),
        ],
        separators=(",", ":"),
    ).encode("utf-8")
    first_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": first_payload},
    )
    second_capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": second_payload},
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )

    lineage = derive_tiingo_eod_receipt_lineage((verify(first_capture), verify(second_capture)))

    assert len(lineage.revisions) == 3
    revisions_by_date = {
        session_label: [
            revision.local_revision
            for revision in lineage.revisions
            if revision.session_label == session_label
        ]
        for session_label in (SESSION_DATE, SECOND_SESSION_DATE)
    }
    assert revisions_by_date == {SESSION_DATE: [1], SECOND_SESSION_DATE: [1, 2]}
    assert [comparison.disposition for comparison in lineage.comparisons[2:]] == [
        TiingoEodReceiptDisposition.UNCHANGED,
        TiingoEodReceiptDisposition.CHANGED,
    ]


def test_incomplete_later_capture_is_rejected_without_tombstone_or_carry_forward(
    tmp_path: Path,
) -> None:
    selected_scope = scope(
        symbols=("SPY",),
        start_date=SESSION_DATE,
        end_date=SECOND_SESSION_DATE,
    )
    selected_profile = profile(capture_scope=selected_scope)
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(
        symbols=("SPY",),
        session_dates=(SESSION_DATE, SECOND_SESSION_DATE),
    )
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )
    complete = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": response_bytes(SESSION_DATE, SECOND_SESSION_DATE)},
    )
    incomplete = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        selected_calendars=selected_calendars,
        payloads={"SPY": response_bytes(SESSION_DATE)},
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )

    assert verify(complete).rows
    with pytest.raises(TiingoEodError, match=r"missing|required session|coverage|response dates"):
        verify(incomplete)
    assert not hasattr(TiingoEodReceiptDisposition, "MISSING")


@pytest.mark.parametrize("narrower_dimension", ["symbols", "dates"])
def test_receipt_lineage_rejects_individually_valid_narrower_scopes(
    tmp_path: Path,
    narrower_dimension: str,
) -> None:
    def verified_scope_capture(
        root: Path,
        selected_scope: TiingoEodScope,
        *,
        requested_at: datetime,
    ) -> TiingoEodVerifiedResearchSnapshot:
        selected_profile = profile(capture_scope=selected_scope)
        authorization_bytes = authorization(selected_profile)
        session_dates = tuple(
            session_date
            for session_date in (SESSION_DATE, SECOND_SESSION_DATE)
            if selected_scope.start_date <= session_date <= selected_scope.end_date
        )
        selected_calendars = calendars(
            symbols=selected_scope.symbols,
            session_dates=session_dates,
        )
        calendar_bytes = pinned_calendar_artifact(
            selected_profile,
            selected_calendars=selected_calendars,
        )
        payloads = {
            symbol: response_bytes(*session_dates, volume=1_000_000 + index)
            for index, symbol in enumerate(selected_scope.symbols)
        }
        return verify(
            write_capture(
                root,
                selected_profile=selected_profile,
                authorization_bytes=authorization_bytes,
                calendar_artifact_bytes=calendar_bytes,
                selected_calendars=selected_calendars,
                payloads=payloads,
                capture_requested_at=requested_at,
            )
        )

    broad_scope = scope(
        symbols=("DIA", "SPY"),
        start_date=SESSION_DATE,
        end_date=SECOND_SESSION_DATE,
    )
    narrow_scope = (
        scope(
            symbols=("SPY",),
            start_date=SESSION_DATE,
            end_date=SECOND_SESSION_DATE,
        )
        if narrower_dimension == "symbols"
        else scope(
            symbols=("DIA", "SPY"),
            start_date=SESSION_DATE,
            end_date=SESSION_DATE,
        )
    )
    broad = verified_scope_capture(
        tmp_path / "broad",
        broad_scope,
        requested_at=CAPTURE_REQUESTED_AT,
    )
    narrow = verified_scope_capture(
        tmp_path / "narrow",
        narrow_scope,
        requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )

    with pytest.raises(TiingoEodError, match="exact profile"):
        derive_tiingo_eod_receipt_lineage((broad, narrow))


def test_receipt_lineage_rejects_duplicate_reversed_and_overlapping_captures(
    tmp_path: Path,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    authorization_bytes = authorization(selected_profile)
    selected_calendars = calendars(symbols=("SPY",))
    calendar_bytes = pinned_calendar_artifact(
        selected_profile,
        selected_calendars=selected_calendars,
    )

    def snapshot_at(offset: timedelta) -> TiingoEodVerifiedResearchSnapshot:
        return verify(
            write_capture(
                tmp_path,
                selected_profile=selected_profile,
                authorization_bytes=authorization_bytes,
                calendar_artifact_bytes=calendar_bytes,
                selected_calendars=selected_calendars,
                capture_requested_at=CAPTURE_REQUESTED_AT + offset,
            )
        )

    first = snapshot_at(timedelta())
    second = snapshot_at(timedelta(minutes=1))
    overlapping = snapshot_at(timedelta(seconds=1))

    with pytest.raises(TiingoEodError, match="duplicate capture"):
        derive_tiingo_eod_receipt_lineage((first, first))
    with pytest.raises(TiingoEodError, match="chronological"):
        derive_tiingo_eod_receipt_lineage((second, first))
    with pytest.raises(TiingoEodError, match="non-overlapping"):
        derive_tiingo_eod_receipt_lineage((first, overlapping))


def test_receipt_lineage_rejects_profile_calendar_and_policy_mismatches(tmp_path: Path) -> None:
    first_capture = write_capture(tmp_path / "first")
    first = verify(first_capture)

    other_profile = profile(market_provenance="different-market-provenance")
    other_profile_capture = write_capture(
        tmp_path / "profile",
        selected_profile=other_profile,
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )
    with pytest.raises(TiingoEodError, match="exact profile"):
        derive_tiingo_eod_receipt_lineage((first, verify(other_profile_capture)))

    changed_calendars = calendars()
    changed_calendars["SPY"] = calendar("SPY", version="spy-2026b", close_hour=22)
    changed_calendar_capture = write_capture(
        tmp_path / "calendar",
        selected_profile=first_capture.profile,
        authorization_bytes=first_capture.authorization_bytes,
        selected_calendars=changed_calendars,
        capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
    )
    with pytest.raises(TiingoEodError, match="exact calendar"):
        derive_tiingo_eod_receipt_lineage((first, verify(changed_calendar_capture)))

    unsupported_profile = replace(
        profile(),
        correction_policy="vendor-latest-is-not-a-local-lineage-policy",
    )
    unsupported_authorization = authorization(unsupported_profile)
    unsupported_calendars = calendars()
    unsupported_calendar_bytes = pinned_calendar_artifact(
        unsupported_profile,
        selected_calendars=unsupported_calendars,
    )
    unsupported_captures = tuple(
        write_capture(
            tmp_path / "unsupported",
            selected_profile=unsupported_profile,
            authorization_bytes=unsupported_authorization,
            calendar_artifact_bytes=unsupported_calendar_bytes,
            selected_calendars=unsupported_calendars,
            capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=index),
        )
        for index in range(2)
    )
    with pytest.raises(TiingoEodError, match="unsupported local lineage policy"):
        derive_tiingo_eod_receipt_lineage(
            tuple(verify(capture) for capture in unsupported_captures)
        )


def test_receipt_lineage_revalidates_proofs_and_requires_multiple_exact_snapshots(
    tmp_path: Path,
) -> None:
    first = verify(write_capture(tmp_path / "first"))
    second = verify(
        write_capture(
            tmp_path / "second",
            capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
        )
    )

    with pytest.raises(TiingoEodError, match="at least two"):
        derive_tiingo_eod_receipt_lineage((first,))
    with pytest.raises(TiingoEodError, match="exact tuple"):
        derive_tiingo_eod_receipt_lineage(cast(Any, [first, second]))

    object.__setattr__(second, "rows", second.rows[:-1])
    with pytest.raises(TiingoEodError, match=r"verified snapshot proof|rows"):
        derive_tiingo_eod_receipt_lineage((first, second))


def test_receipt_lineage_is_proof_constructed_secret_safe_and_research_only(
    tmp_path: Path,
) -> None:
    first = verify(write_capture(tmp_path))
    second = verify(
        write_capture(
            tmp_path,
            capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
        )
    )
    lineage = derive_tiingo_eod_receipt_lineage((first, second))

    with pytest.raises(TypeError, match="only be created from verified proofs"):
        TiingoEodReceiptTimeLineage()
    with pytest.raises(TypeError, match="only be created from verified proofs"):
        replace(lineage, lineage_sha256="0" * 64)
    with pytest.raises(TypeError, match="only be derived from verified proofs"):
        TiingoEodLocalRevision()
    with pytest.raises(TypeError, match="only be derived from verified proofs"):
        replace(lineage.revisions[0], revision_sha256="f" * 64)
    with pytest.raises(TypeError, match="only be derived from verified proofs"):
        TiingoEodReceiptComparison()
    with pytest.raises(TypeError, match="only be derived from verified proofs"):
        replace(lineage.comparisons[0], effective_revision_sha256="f" * 64)
    assert not isinstance(lineage, HistoricalBarSource)
    assert not hasattr(lineage, "load")
    assert "102.375" not in repr(lineage)
    assert "adjClose" not in repr(lineage)
    for operation in (
        lineage.raw_bar_records,
        lineage.canonical_bar_records,
        lineage.admission_evidence,
        lineage.historical_bar_source,
    ):
        with pytest.raises(TiingoEodError):
            operation()


def test_retained_field_contract_has_exact_thirteen_source_to_row_bindings() -> None:
    expected = (
        (
            "date",
            "session_label",
            "utc-midnight-or-iso-date",
            TiingoEodRetainedFieldRole.SESSION_IDENTITY,
        ),
        (
            "open",
            "open_price",
            "positive-decimal-raw",
            TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE,
        ),
        (
            "high",
            "high_price",
            "positive-decimal-raw",
            TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE,
        ),
        (
            "low",
            "low_price",
            "positive-decimal-raw",
            TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE,
        ),
        (
            "close",
            "close_price",
            "positive-decimal-raw",
            TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE,
        ),
        (
            "volume",
            "volume",
            "non-negative-int64-raw",
            TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE,
        ),
        (
            "adjOpen",
            "adjusted_open_price",
            "positive-decimal-split-dividend-adjusted",
            TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH,
        ),
        (
            "adjHigh",
            "adjusted_high_price",
            "positive-decimal-split-dividend-adjusted",
            TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH,
        ),
        (
            "adjLow",
            "adjusted_low_price",
            "positive-decimal-split-dividend-adjusted",
            TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH,
        ),
        (
            "adjClose",
            "adjusted_close_price",
            "positive-decimal-split-dividend-adjusted",
            TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH,
        ),
        (
            "adjVolume",
            "adjusted_volume",
            "non-negative-int64-split-dividend-adjusted",
            TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH,
        ),
        (
            "divCash",
            "div_cash",
            "non-negative-decimal-ex-date",
            TiingoEodRetainedFieldRole.CORPORATE_ACTION_CANDIDATE,
        ),
        (
            "splitFactor",
            "split_factor",
            "positive-decimal",
            TiingoEodRetainedFieldRole.CORPORATE_ACTION_CANDIDATE,
        ),
    )

    actual = tuple(
        (
            binding.field_name,
            binding.row_attribute,
            binding.source_schema_constraint_id,
            binding.role,
        )
        for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS
    )
    assert actual == expected
    assert tuple(binding.field_name for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS) == (
        TIINGO_EOD_FIELDS
    )
    assert (
        tuple(
            (binding.field_name, binding.source_schema_constraint_id)
            for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS
        )
        == TIINGO_EOD_FIELD_CONTRACT
    )
    assert len(TIINGO_EOD_RETAINED_FIELD_BINDINGS) == 13
    assert {
        role: sum(binding.role is role for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS)
        for role in TiingoEodRetainedFieldRole
    } == {
        TiingoEodRetainedFieldRole.SESSION_IDENTITY: 1,
        TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE: 5,
        TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH: 5,
        TiingoEodRetainedFieldRole.CORPORATE_ACTION_CANDIDATE: 2,
    }
    assert TIINGO_EOD_RETAINED_FIELD_CHECK_IDS == (
        "exact-thirteen-field-contract-v1",
        "duplicate-missing-unknown-field-rejection-v1",
        "finite-numeric-domain-v1",
        "documented-raw-candidate-lane-routing-v1",
        "adjusted-research-lane-routing-v1",
        "corporate-action-candidate-lane-routing-v1",
        "independent-raw-and-adjusted-ohlc-ordering-v1",
        "scope-calendar-session-coverage-v1",
        "receipt-response-row-binding-v1",
    )
    assert len(TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256) == 64


def test_retained_field_binding_rejects_constraint_role_and_target_drift() -> None:
    binding = TIINGO_EOD_RETAINED_FIELD_BINDINGS[1]

    with pytest.raises(ValueError, match="frozen Tiingo contract"):
        TiingoEodRetainedFieldBinding(
            field_name="open",
            row_attribute="open_price",
            source_schema_constraint_id="invented-raw-constraint",
            role=TiingoEodRetainedFieldRole.DOCUMENTED_RAW_CANDIDATE,
        )
    with pytest.raises(ValueError, match="role"):
        replace(binding, role=TiingoEodRetainedFieldRole.ADJUSTED_RESEARCH)
    with pytest.raises(ValueError, match="target"):
        replace(binding, row_attribute="adjusted_open_price")


def test_retained_field_qualification_proves_actual_style_four_by_one_shape(
    tmp_path: Path,
) -> None:
    capture = write_capture(tmp_path)
    snapshot = verify(capture)

    first = qualify_tiingo_eod_retained_fields(snapshot)
    second = qualify_tiingo_eod_retained_fields(snapshot)

    assert first == second
    assert first.snapshot is snapshot
    assert first.scope == capture.profile.scope
    assert first.profile_contract_sha256 == capture.profile.contract_sha256
    assert first.calendar_artifact_sha256 == snapshot.calendar_artifact_sha256
    assert first.manifest_sha256 == snapshot.manifest_sha256
    assert first.snapshot_semantic_sha256 == snapshot.semantic_sha256
    assert first.requested_at == capture.manifest.requested_at
    assert first.received_at == capture.manifest.received_at
    assert first.field_contract_sha256 == TIINGO_EOD_SCHEMA_SHA256
    assert first.role_contract_sha256 == TIINGO_EOD_RETAINED_FIELD_ROLE_CONTRACT_SHA256
    assert first.field_bindings == TIINGO_EOD_RETAINED_FIELD_BINDINGS
    assert first.check_ids == TIINGO_EOD_RETAINED_FIELD_CHECK_IDS
    assert first.observation_count == 4
    assert first.row_count == 4
    assert first.session_count == 1
    assert first.field_occurrence_count == 52
    assert first.schema_version == TIINGO_EOD_RETAINED_FIELD_SCHEMA_VERSION
    assert (
        first.qualification_kind
        is TiingoEodRetainedFieldQualificationKind.EXACT_RETAINED_FIELD_CONTRACT_ONLY
    )
    assert len(first.qualification_sha256) == 64
    assert first.qualification_sha256 == second.qualification_sha256

    later = qualify_tiingo_eod_retained_fields(
        verify(
            write_capture(
                tmp_path,
                capture_requested_at=CAPTURE_REQUESTED_AT + timedelta(minutes=1),
            )
        )
    )
    assert later.qualification_sha256 != first.qualification_sha256


def test_retained_field_qualification_allows_equal_raw_and_adjusted_values(
    tmp_path: Path,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    row = economic_row(SESSION_DATE)
    row.update(
        {
            "adjOpen": row["open"],
            "adjHigh": row["high"],
            "adjLow": row["low"],
            "adjClose": row["close"],
            "adjVolume": row["volume"],
        }
    )
    payload = json.dumps([row], ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    capture = write_capture(
        tmp_path,
        selected_profile=selected_profile,
        payloads={"SPY": payload},
    )

    qualification = qualify_tiingo_eod_retained_fields(verify(capture))

    assert qualification.observation_count == 1
    assert qualification.row_count == 1
    assert qualification.session_count == 1
    assert qualification.field_occurrence_count == 13


def test_retained_field_qualification_never_accepts_malformed_upstream_payloads(
    tmp_path: Path,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    missing = economic_row(SESSION_DATE)
    missing.pop("adjClose")
    unknown = economic_row(SESSION_DATE)
    unknown["unexpected"] = 1
    invalid_action = economic_row(SESSION_DATE)
    invalid_action["splitFactor"] = 0
    duplicate = response_bytes().replace(
        b'"open":101.125',
        b'"open":101.125,"open":101.125',
        1,
    )
    malformed_payloads = (
        json.dumps([missing], ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
        json.dumps([unknown], ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
        json.dumps([invalid_action], ensure_ascii=True, separators=(",", ":")).encode("utf-8"),
        duplicate,
    )

    for index, payload in enumerate(malformed_payloads):
        capture = write_capture(
            tmp_path / str(index),
            selected_profile=selected_profile,
            payloads={"SPY": payload},
        )
        with pytest.raises(TiingoEodError):
            verify(capture)


def test_retained_field_qualification_rejects_substitution_and_snapshot_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = verify(write_capture(tmp_path / "substitution"))
    source_value = retained_fields_module._source_value
    adjusted_open = next(
        binding for binding in TIINGO_EOD_RETAINED_FIELD_BINDINGS if binding.field_name == "adjOpen"
    )

    def substitute_open(
        payload: dict[str, object],
        binding: TiingoEodRetainedFieldBinding,
        *,
        row_label: str,
    ) -> object:
        selected_binding = adjusted_open if binding.field_name == "open" else binding
        return source_value(payload, selected_binding, row_label=row_label)

    monkeypatch.setattr(retained_fields_module, "_source_value", substitute_open)
    with pytest.raises(TiingoEodError, match="not routed"):
        qualify_tiingo_eod_retained_fields(snapshot)

    monkeypatch.setattr(retained_fields_module, "_source_value", source_value)
    tampered = verify(write_capture(tmp_path / "tamper"))
    object.__setattr__(tampered.rows[0], "open_price", tampered.rows[0].adjusted_open_price)
    with pytest.raises(TiingoEodError, match=r"verified snapshot proof|exactly derived"):
        qualify_tiingo_eod_retained_fields(tampered)

    invalid_payload = verify(write_capture(tmp_path / "invalid-payload"))
    object.__setattr__(invalid_payload.observations[0], "payload", None)
    with pytest.raises(TiingoEodError, match="verified snapshot proof"):
        qualify_tiingo_eod_retained_fields(invalid_payload)


def test_retained_field_qualification_is_exact_proof_constructed_and_non_authorizing(
    tmp_path: Path,
) -> None:
    qualification = qualify_tiingo_eod_retained_fields(verify(write_capture(tmp_path)))

    with pytest.raises(TiingoEodError, match="exact verified snapshot proof"):
        qualify_tiingo_eod_retained_fields(cast(Any, object()))
    with pytest.raises(TypeError, match="only be derived from verified proofs"):
        TiingoEodRetainedFieldQualification()
    with pytest.raises(TypeError, match="only be derived from verified proofs"):
        replace(qualification, qualification_sha256="0" * 64)
    assert not isinstance(qualification, HistoricalBarSource)
    assert not hasattr(qualification, "load")
    representation = repr(qualification)
    for retained_value in ("102.375", "101.125", "51.1875", "1000001"):
        assert retained_value not in representation
    for operation in (
        qualification.raw_bar_records,
        qualification.canonical_bar_records,
        qualification.corporate_action_records,
        qualification.admission_evidence,
        qualification.historical_bar_source,
    ):
        with pytest.raises(TiingoEodError):
            operation()
