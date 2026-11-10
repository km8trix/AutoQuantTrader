from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

import packages.adapters.market_data.tiingo_eod_capture as capture_module
from packages.adapters.market_data.tiingo_eod import (
    MAX_TIINGO_RESPONSE_BYTES,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodCaptureManifest,
    TiingoEodCaptureReceipt,
    TiingoEodError,
    TiingoEodScope,
)
from packages.adapters.market_data.tiingo_eod_calendar import (
    MAX_TIINGO_CALENDAR_ARTIFACT_BYTES,
    TiingoEodPinnedCalendar,
    TiingoEodPinnedCalendarArtifact,
)
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodApiRequest,
    TiingoEodApiResponse,
    TiingoEodCaptureError,
    capture_tiingo_eod,
)
from packages.market_data import ExchangeCalendar, ExchangeSession

SESSION_DATE = date(2026, 7, 14)
REQUESTED_AT = datetime(2026, 7, 16, 12, 0, tzinfo=UTC)
FIRST_RECEIVED_AT = datetime(2026, 7, 16, 12, 0, 1, tzinfo=UTC)
SECOND_REQUESTED_AT = datetime(2026, 7, 16, 12, 0, 2, tzinfo=UTC)
SECOND_RECEIVED_AT = datetime(2026, 7, 16, 12, 0, 3, tzinfo=UTC)
TERMS_SHA256 = hashlib.sha256(b"reviewed Tiingo terms fixture").hexdigest()
TOKEN = "test-token-must-remain-secret"


def scope(*, symbols: tuple[str, ...] = ("DIA", "SPY")) -> TiingoEodScope:
    return TiingoEodScope(
        symbols=symbols,
        start_date=SESSION_DATE,
        end_date=SESSION_DATE,
    )


def profile(
    *,
    capture_scope: TiingoEodScope | None = None,
    market_provenance: str = "tiingo-eod-us-market",
    approved: bool = True,
    reviewed_at: datetime = datetime(2026, 6, 30, tzinfo=UTC),
) -> TiingoEodAcquisitionProfile:
    return TiingoEodAcquisitionProfile(
        scope=capture_scope or scope(),
        profile_id="test-reviewed-tiingo-profile",
        approved=approved,
        reviewer_id="test-profile-reviewer",
        reviewed_at=reviewed_at,
        source_id="tiingo-eod-rest",
        adapter_version="tiingo-eod-capture-v2",
        market_provenance=market_provenance,
        identifier_authority="tiingo-ticker-mapping-v1",
        calendar_authority="us-equities-calendar-v1",
        corporate_action_authority="tiingo-eod-actions-v1",
        correction_policy="first-observed-local-revisions-v1",
    )


def authorization(
    acquisition_profile: TiingoEodAcquisitionProfile | None = None,
    *,
    permits_local_snapshot_storage: bool = True,
    permits_research_use: bool = True,
    reviewed_at: datetime = datetime(2026, 7, 1, tzinfo=UTC),
    effective_from: date = date(2026, 1, 1),
    effective_through: date | None = date(2026, 12, 31),
) -> TiingoEodCaptureAuthorization:
    selected_profile = acquisition_profile or profile()
    return TiingoEodCaptureAuthorization(
        authorization_id="test-reviewed-tiingo-authorization",
        reviewer_id="test-reviewer",
        reviewed_at=reviewed_at,
        terms_sha256=TERMS_SHA256,
        profile_contract_sha256=selected_profile.contract_sha256,
        effective_from=effective_from,
        effective_through=effective_through,
        permits_local_snapshot_storage=permits_local_snapshot_storage,
        permits_research_use=permits_research_use,
    )


def authorization_bytes(
    acquisition_profile: TiingoEodAcquisitionProfile | None = None,
    *,
    permits_local_snapshot_storage: bool = True,
    permits_research_use: bool = True,
    reviewed_at: datetime = datetime(2026, 7, 1, tzinfo=UTC),
    effective_from: date = date(2026, 1, 1),
    effective_through: date | None = date(2026, 12, 31),
) -> bytes:
    return authorization(
        acquisition_profile,
        permits_local_snapshot_storage=permits_local_snapshot_storage,
        permits_research_use=permits_research_use,
        reviewed_at=reviewed_at,
        effective_from=effective_from,
        effective_through=effective_through,
    ).to_json_bytes()


def calendar_artifact(
    acquisition_profile: TiingoEodAcquisitionProfile | None = None,
    *,
    approved: bool = True,
    reviewed_at: datetime = datetime(2026, 7, 2, tzinfo=UTC),
    profile_contract_sha256: str | None = None,
    calendar_authority: str | None = None,
    artifact_scope: TiingoEodScope | None = None,
) -> TiingoEodPinnedCalendarArtifact:
    selected_profile = acquisition_profile or profile()
    selected_scope = artifact_scope or selected_profile.scope
    return TiingoEodPinnedCalendarArtifact(
        artifact_id="test-reviewed-tiingo-calendar-artifact",
        approved=approved,
        reviewer_id="test-calendar-reviewer",
        reviewed_at=reviewed_at,
        profile_contract_sha256=(profile_contract_sha256 or selected_profile.contract_sha256),
        calendar_authority=calendar_authority or selected_profile.calendar_authority,
        tzdata_version="2026a",
        scope=selected_scope,
        calendars=tuple(
            TiingoEodPinnedCalendar(
                symbol=symbol,
                calendar=ExchangeCalendar(
                    calendar_id=f"{symbol}-CALENDAR",
                    version="2026a",
                    venue="XNYS",
                    timezone="America/New_York",
                    sessions=(
                        ExchangeSession(
                            venue="XNYS",
                            session_label=SESSION_DATE,
                            opens_at=datetime(2026, 7, 14, 13, 30, tzinfo=UTC),
                            closes_at=datetime(2026, 7, 14, 20, 0, tzinfo=UTC),
                        ),
                    ),
                ),
            )
            for symbol in selected_scope.symbols
        ),
    )


def calendar_artifact_bytes(
    acquisition_profile: TiingoEodAcquisitionProfile | None = None,
    *,
    approved: bool = True,
    reviewed_at: datetime = datetime(2026, 7, 2, tzinfo=UTC),
    profile_contract_sha256: str | None = None,
    calendar_authority: str | None = None,
    artifact_scope: TiingoEodScope | None = None,
) -> bytes:
    return calendar_artifact(
        acquisition_profile,
        approved=approved,
        reviewed_at=reviewed_at,
        profile_contract_sha256=profile_contract_sha256,
        calendar_authority=calendar_authority,
        artifact_scope=artifact_scope,
    ).to_json_bytes()


def economic_row(
    *,
    trading_date: date = SESSION_DATE,
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
        "adjVolume": 2_000_002,
        "divCash": 0.25,
        "splitFactor": 2.0,
    }


def response_bytes(
    *,
    trading_date: date = SESSION_DATE,
    volume: int = 1_000_001,
) -> bytes:
    return json.dumps(
        [economic_row(trading_date=trading_date, volume=volume)],
        separators=(",", ":"),
    ).encode("utf-8")


def capture_root(repository_root: Path) -> Path:
    return repository_root / ".local" / "vendor-snapshots" / "tiingo-eod"


def clock_values(*values: datetime) -> Callable[[], datetime]:
    iterator = iter(values)

    def clock() -> datetime:
        return next(iterator)

    return clock


def capture_tree_snapshot(root: Path) -> tuple[tuple[str, int, bytes | None], ...]:
    paths = (root, *sorted(root.rglob("*")))
    return tuple(
        (
            path.relative_to(root).as_posix(),
            stat.S_IMODE(path.lstat().st_mode),
            path.read_bytes() if path.is_file() else None,
        )
        for path in paths
    )


def install_storage_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> Callable[[], bool]:
    raised = False

    def did_raise() -> bool:
        return raised

    if fault in {"object_write", "manifest_write"}:
        original_write = capture_module._write_exclusive
        target_manifest = fault == "manifest_write"

        def failing_write(directory_descriptor: int, name: str, payload: bytes) -> None:
            nonlocal raised
            original_write(directory_descriptor, name, payload)
            if not raised and (name == "manifest.json") is target_manifest:
                raised = True
                raise OSError("synthetic immutable-write fault")

        monkeypatch.setattr(capture_module, "_write_exclusive", failing_write)
        return did_raise

    if fault == "chmod":
        original_fchmod = os.fchmod

        def failing_fchmod(descriptor: int, mode: int) -> None:
            nonlocal raised
            original_fchmod(descriptor, mode)
            if not raised:
                raised = True
                raise OSError("synthetic chmod fault")

        monkeypatch.setattr(os, "fchmod", failing_fchmod)
        return did_raise

    if fault == "fsync":
        original_fsync = os.fsync

        def failing_fsync(descriptor: int) -> None:
            nonlocal raised
            original_fsync(descriptor)
            if not raised and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raised = True
                raise OSError("synthetic directory-fsync fault")

        monkeypatch.setattr(os, "fsync", failing_fsync)
        return did_raise

    if fault == "rename":

        def failing_rename(
            source: str,
            destination: str,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
        ) -> None:
            nonlocal raised
            del source, destination, src_dir_fd, dst_dir_fd
            raised = True
            raise OSError("synthetic final-rename fault")

        monkeypatch.setattr(os, "rename", failing_rename)
        return did_raise

    raise AssertionError(f"unknown storage fault: {fault}")


def test_acquisition_profile_roundtrip_is_strict_and_digest_bound() -> None:
    baseline = profile()
    changed = profile(market_provenance="tiingo-eod-us-market-v2")

    assert TiingoEodAcquisitionProfile.from_dict(baseline.to_dict()) == baseline
    assert baseline.contract_sha256 != changed.contract_sha256
    assert len(baseline.contract_sha256) == 64

    for field in ("source_id", "market_provenance", "correction_policy"):
        missing = baseline.to_dict()
        del missing[field]
        with pytest.raises(TiingoEodError, match="missing fields"):
            TiingoEodAcquisitionProfile.from_dict(missing)

    unknown = baseline.to_dict()
    unknown["unreviewed"] = True
    with pytest.raises(TiingoEodError, match="unknown fields"):
        TiingoEodAcquisitionProfile.from_dict(unknown)

    encoded = baseline.to_json_bytes()
    encoded_field = b'"source_id": "tiingo-eod-rest"'
    assert encoded_field in encoded
    with pytest.raises(TiingoEodError, match="duplicate JSON key"):
        TiingoEodAcquisitionProfile.from_json_bytes(
            encoded.replace(
                encoded_field,
                encoded_field + b', "source_id": "other"',
                1,
            )
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_id", "other-source"),
        ("adapter_version", "other-adapter"),
        ("endpoint_template", "https://example.invalid/{symbol}"),
        ("schema_sha256", "0" * 64),
        ("provider", "other-provider"),
        ("dataset", "other-dataset"),
    ],
)
def test_acquisition_profile_rejects_unfrozen_identity_fields(
    field: str,
    value: str,
) -> None:
    payload = profile().to_dict()
    payload[field] = value

    with pytest.raises(TiingoEodError):
        TiingoEodAcquisitionProfile.from_dict(payload)


@pytest.mark.parametrize("mutation", ["missing", "unknown", "duplicate"])
def test_capture_authorization_json_is_strict(mutation: str) -> None:
    encoded = authorization_bytes()
    if mutation == "duplicate":
        field = b'"reviewer_id": "test-reviewer",'
        assert field in encoded
        encoded = encoded.replace(field, field + field, 1)
    else:
        decoded = json.loads(encoded)
        if mutation == "missing":
            del decoded["profile_contract_sha256"]
        else:
            decoded["unreviewed"] = True
        encoded = json.dumps(decoded, separators=(",", ":")).encode()

    with pytest.raises(TiingoEodError, match=r"missing fields|unknown fields|duplicate JSON key"):
        TiingoEodCaptureAuthorization.from_json_bytes(encoded)


def test_capture_authorization_roundtrip_binds_exact_profile() -> None:
    selected_profile = profile()
    artifact = authorization_bytes(selected_profile)

    parsed = TiingoEodCaptureAuthorization.from_json_bytes(artifact)

    assert parsed == authorization(selected_profile)
    assert parsed.profile_contract_sha256 == selected_profile.contract_sha256
    assert parsed.terms_sha256 == TERMS_SHA256


@pytest.mark.parametrize(
    "artifact",
    [
        authorization_bytes(permits_local_snapshot_storage=False),
        authorization_bytes(permits_research_use=False),
        authorization_bytes(effective_from=date(2026, 7, 15)),
        authorization_bytes(effective_through=date(2026, 7, 13)),
        authorization_bytes(reviewed_at=datetime(2026, 7, 17, tzinfo=UTC)),
        authorization_bytes(profile(market_provenance="tiingo-eod-us-market-v2")),
    ],
)
def test_authorization_and_profile_gates_run_before_transport_or_writes(
    tmp_path: Path,
    artifact: bytes,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=profile(),
            authorization_bytes=artifact,
            calendar_artifact_bytes=calendar_artifact_bytes(),
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    ("selected_profile", "authorization_reviewed_at"),
    [
        (profile(approved=False), datetime(2026, 7, 1, tzinfo=UTC)),
        (
            profile(reviewed_at=datetime(2026, 7, 17, tzinfo=UTC)),
            datetime(2026, 7, 18, tzinfo=UTC),
        ),
        (
            profile(reviewed_at=datetime(2026, 7, 2, tzinfo=UTC)),
            datetime(2026, 7, 1, tzinfo=UTC),
        ),
    ],
)
def test_reviewed_profile_gates_run_before_transport_or_writes(
    tmp_path: Path,
    selected_profile: TiingoEodAcquisitionProfile,
    authorization_reviewed_at: datetime,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=selected_profile,
            authorization_bytes=authorization_bytes(
                selected_profile,
                reviewed_at=authorization_reviewed_at,
            ),
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize("artifact", [b"{", b"{}", b"[]"])
def test_malformed_authorization_fails_before_transport_or_writes(
    tmp_path: Path,
    artifact: bytes,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError, match="authorization artifact is invalid"):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=profile(),
            authorization_bytes=artifact,
            calendar_artifact_bytes=calendar_artifact_bytes(),
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    "artifact",
    [
        b"{",
        b"{}",
        b"[]",
        b" " * (MAX_TIINGO_CALENDAR_ARTIFACT_BYTES + 1),
    ],
)
def test_malformed_calendar_artifact_fails_before_token_transport_or_writes(
    tmp_path: Path,
    artifact: bytes,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError, match="calendar artifact is invalid") as error:
        capture_tiingo_eod(
            repository_root=tmp_path,
            token="",
            profile=profile(),
            authorization_bytes=authorization_bytes(),
            calendar_artifact_bytes=artifact,
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert TOKEN not in str(error.value)
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    "artifact",
    [
        calendar_artifact_bytes(approved=False),
        calendar_artifact_bytes(profile_contract_sha256="1" * 64),
        calendar_artifact_bytes(calendar_authority="different-calendar-authority"),
        calendar_artifact_bytes(artifact_scope=scope(symbols=("SPY",))),
        calendar_artifact_bytes(reviewed_at=datetime(2026, 6, 29, tzinfo=UTC)),
        calendar_artifact_bytes(reviewed_at=datetime(2026, 7, 17, tzinfo=UTC)),
    ],
)
def test_calendar_authority_gates_run_before_token_transport_or_writes(
    tmp_path: Path,
    artifact: bytes,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(
        TiingoEodCaptureError,
        match="calendar artifact is not authorized",
    ) as error:
        capture_tiingo_eod(
            repository_root=tmp_path,
            token="",
            profile=profile(),
            authorization_bytes=authorization_bytes(),
            calendar_artifact_bytes=artifact,
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert TOKEN not in str(error.value)
    assert not capture_root(tmp_path).exists()


def test_invalid_profile_type_fails_before_transport_or_writes(tmp_path: Path) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError, match="profile is invalid"):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=cast(TiingoEodAcquisitionProfile, object()),
            authorization_bytes=authorization_bytes(),
            calendar_artifact_bytes=calendar_artifact_bytes(),
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    ("token", "timeout_seconds", "selected_profile", "message"),
    [
        ("", 15.0, profile(), "not configured"),
        (TOKEN, 0.0, profile(), "timeout"),
        (TOKEN, 31.0, profile(), "timeout"),
        (TOKEN, float("inf"), profile(), "timeout"),
        (TOKEN, float("nan"), profile(), "timeout"),
    ],
)
def test_capture_preflight_rejects_configuration_before_transport(
    tmp_path: Path,
    token: str,
    timeout_seconds: float,
    selected_profile: TiingoEodAcquisitionProfile,
    message: str,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError, match=message):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=token,
            profile=selected_profile,
            authorization_bytes=authorization_bytes(selected_profile),
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            timeout_seconds=timeout_seconds,
            transport=transport,
            clock=clock_values(REQUESTED_AT),
        )

    assert called is False
    assert not capture_root(tmp_path).exists()


def test_acquisition_profile_rejects_out_of_allow_list_scope() -> None:
    with pytest.raises(ValueError, match="allow-list"):
        profile(capture_scope=scope(symbols=("AAPL",)))


def test_capture_archives_one_exact_response_per_sorted_symbol_without_secret_leakage(
    tmp_path: Path,
) -> None:
    selected_profile = profile()
    artifact = authorization_bytes(selected_profile)
    pinned_calendar_bytes = calendar_artifact_bytes(selected_profile)
    payloads = {
        "DIA": response_bytes(volume=1_000_001),
        "SPY": response_bytes(volume=1_000_002),
    }
    seen: list[TiingoEodApiRequest] = []

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        seen.append(request)
        assert timeout_seconds == 15.0
        assert TOKEN in request.headers["Authorization"]
        assert TOKEN not in request.url
        assert request.symbol in request.url
        assert SESSION_DATE.isoformat() in request.url
        assert TOKEN not in repr(request)
        return TiingoEodApiResponse(status=200, payload=payloads[request.symbol])

    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token=TOKEN,
        profile=selected_profile,
        authorization_bytes=artifact,
        calendar_artifact_bytes=pinned_calendar_bytes,
        transport=transport,
        clock=clock_values(
            REQUESTED_AT,
            FIRST_RECEIVED_AT,
            SECOND_REQUESTED_AT,
            SECOND_RECEIVED_AT,
        ),
    )
    manifest_bytes = manifest_path.read_bytes()
    manifest = TiingoEodCaptureManifest.from_json_bytes(manifest_bytes)

    assert [request.symbol for request in seen] == ["DIA", "SPY"]
    assert [receipt.symbol for receipt in manifest.responses] == ["DIA", "SPY"]
    assert manifest.profile == selected_profile
    assert manifest.profile_contract_sha256 == selected_profile.contract_sha256
    assert manifest.authorization_sha256 == hashlib.sha256(artifact).hexdigest()
    assert manifest.calendar_artifact_sha256 == hashlib.sha256(pinned_calendar_bytes).hexdigest()
    assert manifest.schema_version == "tiingo-eod-capture-v2"
    assert manifest.terms_sha256 == TERMS_SHA256
    assert manifest.requested_at == REQUESTED_AT
    assert manifest.received_at == SECOND_RECEIVED_AT
    assert manifest_path.parent.parent == capture_root(tmp_path)
    assert manifest_path.parent.name == (
        f"{REQUESTED_AT.strftime('%Y%m%dT%H%M%S%fZ')}-{hashlib.sha256(manifest_bytes).hexdigest()}"
    )
    assert TiingoEodCaptureManifest.from_json_bytes(manifest.to_json_bytes()) == manifest

    expected_times = (
        (REQUESTED_AT, FIRST_RECEIVED_AT),
        (SECOND_REQUESTED_AT, SECOND_RECEIVED_AT),
    )
    for receipt, expected_time in zip(manifest.responses, expected_times, strict=True):
        object_path = manifest_path.parent / receipt.object_path
        expected_payload = payloads[receipt.symbol]
        assert object_path.read_bytes() == expected_payload
        assert receipt.sha256 == hashlib.sha256(expected_payload).hexdigest()
        assert receipt.byte_count == len(expected_payload)
        assert (receipt.requested_at, receipt.received_at) == expected_time
        assert stat.S_IMODE(object_path.stat().st_mode) == 0o400
        assert stat.S_IMODE(object_path.parent.stat().st_mode) == 0o500

    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o400
    assert stat.S_IMODE(manifest_path.parent.stat().st_mode) == 0o500
    assert stat.S_IMODE(capture_root(tmp_path).stat().st_mode) == 0o700
    assert TOKEN.encode() not in manifest_bytes
    for path in manifest_path.parent.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes()


def test_request_and_response_repr_hide_sensitive_transport_material(
    tmp_path: Path,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    seen: list[TiingoEodApiRequest] = []

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        seen.append(request)
        response = TiingoEodApiResponse(status=200, payload=response_bytes())
        assert "101.125" not in repr(response)
        return response

    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token=TOKEN,
        profile=selected_profile,
        authorization_bytes=authorization_bytes(selected_profile),
        calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
        transport=transport,
        clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
    )

    assert manifest_path.is_file()
    assert len(seen) == 1
    assert TOKEN not in repr(seen[0])
    assert "Authorization" not in repr(seen[0])


def invalid_payloads() -> tuple[tuple[bytes, str], ...]:
    valid = response_bytes()
    duplicate = valid.replace(
        b'"open":101.125',
        b'"open":101.125,"open":999.0',
        1,
    )
    return (
        (b"{", "invalid EOD response"),
        (duplicate, "invalid EOD response"),
        (response_bytes(trading_date=date(2026, 7, 13)), "invalid EOD response"),
        (b"[" + b" " * MAX_TIINGO_RESPONSE_BYTES + b"]", "invalid EOD response"),
    )


@pytest.mark.parametrize(("bad_payload", "message"), invalid_payloads())
def test_all_responses_are_validated_before_any_capture_output_is_written(
    tmp_path: Path,
    bad_payload: bytes,
    message: str,
) -> None:
    seen: list[str] = []

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        seen.append(request.symbol)
        payload = response_bytes() if request.symbol == "DIA" else bad_payload
        return TiingoEodApiResponse(status=200, payload=payload)

    with pytest.raises(TiingoEodCaptureError, match=message):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=profile(),
            authorization_bytes=authorization_bytes(),
            calendar_artifact_bytes=calendar_artifact_bytes(),
            transport=transport,
            clock=clock_values(
                REQUESTED_AT,
                FIRST_RECEIVED_AT,
                SECOND_REQUESTED_AT,
                SECOND_RECEIVED_AT,
            ),
        )

    assert seen == ["DIA", "SPY"]
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize("failure", ["http", "transport"])
def test_partial_capture_failure_is_sanitized_and_writes_nothing(
    tmp_path: Path,
    failure: str,
) -> None:
    seen: list[str] = []

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        seen.append(request.symbol)
        if request.symbol == "DIA":
            return TiingoEodApiResponse(status=200, payload=response_bytes())
        if failure == "http":
            return TiingoEodApiResponse(
                status=403,
                payload=f'{{"error":"{TOKEN}"}}'.encode(),
            )
        raise OSError(f"synthetic transport detail: {TOKEN}")

    with pytest.raises(TiingoEodCaptureError) as captured:
        times = (
            REQUESTED_AT,
            FIRST_RECEIVED_AT,
            SECOND_REQUESTED_AT,
            *(() if failure == "transport" else (SECOND_RECEIVED_AT,)),
        )
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=profile(),
            authorization_bytes=authorization_bytes(),
            calendar_artifact_bytes=calendar_artifact_bytes(),
            transport=transport,
            clock=clock_values(*times),
        )

    assert seen == ["DIA", "SPY"]
    assert TOKEN not in str(captured.value)
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    "fault",
    ["object_write", "manifest_write", "chmod", "fsync", "rename"],
)
def test_atomic_publication_cleans_storage_faults_preserves_existing_capture_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    artifact = authorization_bytes(selected_profile)

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        assert request.symbol == "SPY"
        assert timeout_seconds == 15.0
        return TiingoEodApiResponse(status=200, payload=response_bytes())

    existing_manifest = capture_tiingo_eod(
        repository_root=tmp_path,
        token=TOKEN,
        profile=selected_profile,
        authorization_bytes=artifact,
        calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
        transport=transport,
        clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
    )
    existing_capture = existing_manifest.parent
    existing_snapshot = capture_tree_snapshot(existing_capture)
    root = capture_root(tmp_path)

    with monkeypatch.context() as fault_patch:
        did_raise = install_storage_fault(fault_patch, fault)
        with pytest.raises(TiingoEodCaptureError, match=r"publish|capture object"):
            capture_tiingo_eod(
                repository_root=tmp_path,
                token=TOKEN,
                profile=selected_profile,
                authorization_bytes=artifact,
                calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
                transport=transport,
                clock=clock_values(SECOND_REQUESTED_AT, SECOND_RECEIVED_AT),
            )
        assert did_raise()

    assert {path.name for path in root.iterdir()} == {existing_capture.name}
    assert capture_tree_snapshot(existing_capture) == existing_snapshot

    retried_manifest = capture_tiingo_eod(
        repository_root=tmp_path,
        token=TOKEN,
        profile=selected_profile,
        authorization_bytes=artifact,
        calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
        transport=transport,
        clock=clock_values(SECOND_REQUESTED_AT, SECOND_RECEIVED_AT),
    )

    captures = tuple(root.iterdir())
    assert retried_manifest.is_file()
    assert retried_manifest.parent != existing_capture
    assert len(captures) == 2
    assert all(path.is_dir() and not path.name.startswith(".staging-") for path in captures)


def test_publish_lock_rejects_overlapping_same_name_capture_without_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    artifact = authorization_bytes(selected_profile)
    overlap_errors: list[TiingoEodCaptureError] = []

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        assert request.symbol == "SPY"
        assert timeout_seconds == 15.0
        return TiingoEodApiResponse(status=200, payload=response_bytes())

    original_write = capture_module._write_exclusive
    overlap_attempted = False

    def overlapping_write(directory_descriptor: int, name: str, payload: bytes) -> None:
        nonlocal overlap_attempted
        if not overlap_attempted:
            overlap_attempted = True
            with pytest.raises(TiingoEodCaptureError, match="final-name reservation") as captured:
                capture_tiingo_eod(
                    repository_root=tmp_path,
                    token=TOKEN,
                    profile=selected_profile,
                    authorization_bytes=artifact,
                    calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
                    transport=transport,
                    clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
                )
            overlap_errors.append(captured.value)
        original_write(directory_descriptor, name, payload)

    with monkeypatch.context() as overlap_patch:
        overlap_patch.setattr(capture_module, "_write_exclusive", overlapping_write)
        manifest_path = capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=selected_profile,
            authorization_bytes=artifact,
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            transport=transport,
            clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
        )

    root = capture_root(tmp_path)
    published_snapshot = capture_tree_snapshot(manifest_path.parent)
    assert overlap_attempted
    assert len(overlap_errors) == 1
    assert tuple(root.iterdir()) == (manifest_path.parent,)
    assert manifest_path.is_file()

    with pytest.raises(TiingoEodCaptureError, match="already uses the final name"):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=selected_profile,
            authorization_bytes=artifact,
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            transport=transport,
            clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
        )

    assert tuple(root.iterdir()) == (manifest_path.parent,)
    assert capture_tree_snapshot(manifest_path.parent) == published_snapshot


def test_post_commit_root_fsync_failure_returns_the_published_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    artifact = authorization_bytes(selected_profile)
    original_rename = os.rename
    original_fsync = os.fsync
    renamed = False
    post_commit_fsync_failed = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        assert request.symbol == "SPY"
        assert timeout_seconds == 15.0
        return TiingoEodApiResponse(status=200, payload=response_bytes())

    def tracking_rename(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal renamed
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        renamed = True

    def failing_post_commit_fsync(descriptor: int) -> None:
        nonlocal post_commit_fsync_failed
        original_fsync(descriptor)
        if renamed and not post_commit_fsync_failed:
            post_commit_fsync_failed = True
            raise OSError("synthetic post-commit root-fsync fault")

    with monkeypatch.context() as post_commit_patch:
        post_commit_patch.setattr(os, "rename", tracking_rename)
        post_commit_patch.setattr(os, "fsync", failing_post_commit_fsync)
        manifest_path = capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=selected_profile,
            authorization_bytes=artifact,
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            transport=transport,
            clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
        )

    assert renamed
    assert post_commit_fsync_failed
    assert manifest_path.is_file()
    assert tuple(capture_root(tmp_path).iterdir()) == (manifest_path.parent,)


@pytest.mark.parametrize("interrupt_at", ["write", "fsync"])
def test_publication_interrupt_cleans_owned_staging_and_reservation_then_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupt_at: str,
) -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    artifact = authorization_bytes(selected_profile)
    interrupted = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        assert request.symbol == "SPY"
        assert timeout_seconds == 15.0
        return TiingoEodApiResponse(status=200, payload=response_bytes())

    with monkeypatch.context() as interrupt_patch:
        if interrupt_at == "write":
            original_write = capture_module._write_exclusive

            def interrupting_write(
                directory_descriptor: int,
                name: str,
                payload: bytes,
            ) -> None:
                nonlocal interrupted
                original_write(directory_descriptor, name, payload)
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt

            interrupt_patch.setattr(capture_module, "_write_exclusive", interrupting_write)
        else:
            original_fsync = os.fsync

            def interrupting_fsync(descriptor: int) -> None:
                nonlocal interrupted
                original_fsync(descriptor)
                if not interrupted and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    interrupted = True
                    raise KeyboardInterrupt

            interrupt_patch.setattr(os, "fsync", interrupting_fsync)

        with pytest.raises(KeyboardInterrupt):
            capture_tiingo_eod(
                repository_root=tmp_path,
                token=TOKEN,
                profile=selected_profile,
                authorization_bytes=artifact,
                calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
                transport=transport,
                clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
            )

    root = capture_root(tmp_path)
    assert interrupted
    assert tuple(root.iterdir()) == ()

    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token=TOKEN,
        profile=selected_profile,
        authorization_bytes=artifact,
        calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
        transport=transport,
        clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
    )

    assert manifest_path.is_file()
    assert tuple(root.iterdir()) == (manifest_path.parent,)


def test_capture_rejects_non_utc_clock_before_transport_or_writes(
    tmp_path: Path,
) -> None:
    called = False

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        nonlocal called
        called = True
        raise AssertionError((request, timeout_seconds))

    with pytest.raises(TiingoEodCaptureError, match="clock"):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=profile(capture_scope=scope(symbols=("SPY",))),
            authorization_bytes=authorization_bytes(profile(capture_scope=scope(symbols=("SPY",)))),
            calendar_artifact_bytes=calendar_artifact_bytes(
                profile(capture_scope=scope(symbols=("SPY",)))
            ),
            transport=transport,
            clock=clock_values(REQUESTED_AT.replace(tzinfo=None)),
        )

    assert called is False
    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    "times",
    [
        (
            REQUESTED_AT,
            REQUESTED_AT - timedelta(seconds=1),
        ),
        (
            REQUESTED_AT,
            FIRST_RECEIVED_AT,
            REQUESTED_AT,
            SECOND_RECEIVED_AT,
        ),
    ],
)
def test_capture_rejects_non_monotonic_clock_without_writes(
    tmp_path: Path,
    times: tuple[datetime, ...],
) -> None:
    selected_profile = (
        profile(capture_scope=scope(symbols=("SPY",))) if len(times) == 2 else profile()
    )

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        return TiingoEodApiResponse(status=200, payload=response_bytes())

    with pytest.raises(TiingoEodCaptureError, match=r"clock|timestamp|monotonic"):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=selected_profile,
            authorization_bytes=authorization_bytes(selected_profile),
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            transport=transport,
            clock=clock_values(*times),
        )

    assert not capture_root(tmp_path).exists()


@pytest.mark.parametrize(
    "object_path",
    ["../escape.json", "/tmp/escape.json", "objects\\escape.json", "./escape.json"],
)
def test_capture_receipt_rejects_unsafe_object_paths(object_path: str) -> None:
    payload = response_bytes()

    with pytest.raises(ValueError, match="content-addressed response path"):
        TiingoEodCaptureReceipt(
            symbol="SPY",
            object_path=object_path,
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_count=len(payload),
            requested_at=REQUESTED_AT,
            received_at=FIRST_RECEIVED_AT,
        )


def test_manifest_roundtrip_rejects_duplicate_keys_and_profile_digest_mismatch() -> None:
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))
    payload = response_bytes()
    receipt = TiingoEodCaptureReceipt(
        symbol="SPY",
        object_path=f"objects/{hashlib.sha256(payload).hexdigest()}.json",
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
        requested_at=REQUESTED_AT,
        received_at=FIRST_RECEIVED_AT,
    )
    manifest = TiingoEodCaptureManifest(
        profile=selected_profile,
        profile_contract_sha256=selected_profile.contract_sha256,
        responses=(receipt,),
        requested_at=REQUESTED_AT,
        received_at=FIRST_RECEIVED_AT,
        authorization_sha256=hashlib.sha256(authorization_bytes(selected_profile)).hexdigest(),
        calendar_artifact_sha256=hashlib.sha256(
            calendar_artifact_bytes(selected_profile)
        ).hexdigest(),
        terms_sha256=TERMS_SHA256,
    )
    encoded = manifest.to_json_bytes()

    assert TiingoEodCaptureManifest.from_json_bytes(encoded) == manifest
    field = b'"provider": "tiingo",'
    assert field in encoded
    with pytest.raises(TiingoEodError, match="duplicate JSON key"):
        TiingoEodCaptureManifest.from_json_bytes(encoded.replace(field, field + field, 1))
    missing_calendar_digest = json.loads(encoded)
    del missing_calendar_digest["calendar_artifact_sha256"]
    with pytest.raises(TiingoEodError, match="missing fields"):
        TiingoEodCaptureManifest.from_json_bytes(
            json.dumps(missing_calendar_digest, separators=(",", ":")).encode()
        )
    v1_manifest = json.loads(encoded)
    v1_manifest["schema_version"] = "tiingo-eod-capture-v1"
    with pytest.raises(TiingoEodError, match="unsupported Tiingo EOD capture schema"):
        TiingoEodCaptureManifest.from_json_bytes(
            (json.dumps(v1_manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
        )
    with pytest.raises(ValueError, match="profile"):
        TiingoEodCaptureManifest(
            profile=selected_profile,
            profile_contract_sha256="0" * 64,
            responses=(receipt,),
            requested_at=REQUESTED_AT,
            received_at=FIRST_RECEIVED_AT,
            authorization_sha256=hashlib.sha256(authorization_bytes(selected_profile)).hexdigest(),
            calendar_artifact_sha256=hashlib.sha256(
                calendar_artifact_bytes(selected_profile)
            ).hexdigest(),
            terms_sha256=TERMS_SHA256,
        )
    with pytest.raises(ValueError, match="calendar_artifact_sha256"):
        TiingoEodCaptureManifest(
            profile=selected_profile,
            profile_contract_sha256=selected_profile.contract_sha256,
            responses=(receipt,),
            requested_at=REQUESTED_AT,
            received_at=FIRST_RECEIVED_AT,
            authorization_sha256=hashlib.sha256(authorization_bytes(selected_profile)).hexdigest(),
            calendar_artifact_sha256="0" * 64,
            terms_sha256=TERMS_SHA256,
        )


def test_capture_rejects_symlinked_fixed_root_without_writing_outside(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".local").symlink_to(outside, target_is_directory=True)
    selected_profile = profile(capture_scope=scope(symbols=("SPY",)))

    def transport(
        request: TiingoEodApiRequest,
        *,
        timeout_seconds: float,
    ) -> TiingoEodApiResponse:
        return TiingoEodApiResponse(status=200, payload=response_bytes())

    with pytest.raises(TiingoEodCaptureError, match=r"symlink|directory|capture root"):
        capture_tiingo_eod(
            repository_root=tmp_path,
            token=TOKEN,
            profile=selected_profile,
            authorization_bytes=authorization_bytes(selected_profile),
            calendar_artifact_bytes=calendar_artifact_bytes(selected_profile),
            transport=transport,
            clock=clock_values(REQUESTED_AT, FIRST_RECEIVED_AT),
        )

    assert list(outside.iterdir()) == []
