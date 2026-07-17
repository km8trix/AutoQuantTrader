from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import NoReturn

import pytest

import scripts.capture_tiingo_eod as capture_cli
import scripts.derive_tiingo_eod_lineage as lineage_cli
import scripts.inspect_tiingo_eod_profile as inspect_cli
import scripts.qualify_tiingo_eod_identity_lifecycle as identity_lifecycle_cli
import scripts.qualify_tiingo_eod_retained_fields as retained_fields_cli
import scripts.verify_tiingo_eod_capture as verify_cli
from packages.adapters.market_data.tiingo_eod import (
    TIINGO_EOD_FIELD_CONTRACT,
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
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
from packages.adapters.market_data.tiingo_eod_identity_lifecycle import (
    TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS,
    TiingoEodIdentityLifecycleArtifactKind,
)
from packages.market_data import ExchangeCalendar, ExchangeSession
from tests.unit.test_tiingo_eod_identity_lifecycle import _artifact
from tests.unit.test_tiingo_eod_snapshot import VENUE_BY_SYMBOL

SESSION_DATE = date(2026, 7, 14)
REQUESTED_AT = datetime(2026, 7, 16, 12, tzinfo=UTC)
TERMS_SHA256 = hashlib.sha256(b"reviewed Tiingo terms fixture").hexdigest()
TOKEN = "test-token-must-never-be-printed"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def profile(
    *,
    approved: bool = True,
    symbols: tuple[str, ...] = ("SPY",),
    market_provenance: str = "tiingo-eod-us-market",
) -> TiingoEodAcquisitionProfile:
    return TiingoEodAcquisitionProfile(
        scope=TiingoEodScope(
            symbols=symbols,
            start_date=SESSION_DATE,
            end_date=SESSION_DATE,
        ),
        profile_id="test-reviewed-tiingo-profile",
        approved=approved,
        reviewer_id="test-profile-reviewer",
        reviewed_at=datetime(2026, 6, 30, tzinfo=UTC),
        source_id="tiingo-eod-rest",
        adapter_version="tiingo-eod-capture-v2",
        market_provenance=market_provenance,
        identifier_authority="tiingo-ticker-mapping-v1",
        calendar_authority="us-equities-calendar-v1",
        corporate_action_authority="tiingo-eod-actions-v1",
        correction_policy="first-observed-local-revisions-v1",
    )


def authorization(acquisition_profile: TiingoEodAcquisitionProfile) -> bytes:
    return TiingoEodCaptureAuthorization(
        authorization_id="test-reviewed-tiingo-authorization",
        reviewer_id="test-authorization-reviewer",
        reviewed_at=datetime(2026, 7, 1, tzinfo=UTC),
        terms_sha256=TERMS_SHA256,
        profile_contract_sha256=acquisition_profile.contract_sha256,
        effective_from=date(2026, 1, 1),
        effective_through=date(2026, 12, 31),
        permits_local_snapshot_storage=True,
        permits_research_use=True,
    ).to_json_bytes()


def pinned_calendar(symbol: str = "SPY", *, venue: str = "XNYS") -> ExchangeCalendar:
    return ExchangeCalendar(
        calendar_id=f"{symbol}-CALENDAR",
        version="test-2026a",
        venue=venue,
        timezone="America/New_York",
        sessions=(
            ExchangeSession(
                venue=venue,
                session_label=SESSION_DATE,
                opens_at=datetime(2026, 7, 14, 13, 30, tzinfo=UTC),
                closes_at=datetime(2026, 7, 14, 20, 0, tzinfo=UTC),
            ),
        ),
    )


def calendar_artifact(
    acquisition_profile: TiingoEodAcquisitionProfile,
    *,
    venues: Mapping[str, str] | None = None,
) -> bytes:
    return TiingoEodPinnedCalendarArtifact(
        artifact_id="test-reviewed-tiingo-calendar",
        approved=True,
        reviewer_id="test-calendar-reviewer",
        reviewed_at=datetime(2026, 7, 2, tzinfo=UTC),
        profile_contract_sha256=acquisition_profile.contract_sha256,
        calendar_authority=acquisition_profile.calendar_authority,
        tzdata_version="2026a",
        scope=acquisition_profile.scope,
        calendars=tuple(
            TiingoEodPinnedCalendar(
                symbol=symbol,
                calendar=pinned_calendar(
                    symbol,
                    venue=venues[symbol] if venues is not None else "XNYS",
                ),
            )
            for symbol in acquisition_profile.scope.symbols
        ),
    ).to_json_bytes()


def write_artifact(path: Path, payload: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def capture_argv(
    profile_path: Path,
    authorization_path: Path,
    calendar_path: Path,
    *,
    symbol: str = "SPY",
) -> list[str]:
    return [
        "capture_tiingo_eod.py",
        "--start-date",
        SESSION_DATE.isoformat(),
        "--symbol",
        symbol,
        "--profile-file",
        str(profile_path),
        "--authorization-file",
        str(authorization_path),
        "--calendar-file",
        str(calendar_path),
    ]


def identity_lifecycle_argv(
    *,
    capture_name: str,
    profile_path: Path,
    authorization_path: Path,
    calendar_path: Path,
    identity_lifecycle_path: Path,
) -> list[str]:
    return [
        "qualify_tiingo_eod_identity_lifecycle.py",
        "--capture-name",
        capture_name,
        "--profile-file",
        str(profile_path),
        "--authorization-file",
        str(authorization_path),
        "--calendar-file",
        str(calendar_path),
        "--identity-lifecycle-file",
        str(identity_lifecycle_path),
    ]


def forbidden(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError((args, kwargs))


def tree_snapshot(root: Path) -> tuple[tuple[str, int, bytes | None], ...]:
    return tuple(
        (
            str(path.relative_to(root)),
            path.stat().st_mode,
            path.read_bytes() if path.is_file() else None,
        )
        for path in sorted(root.rglob("*"))
    )


def response_bytes() -> bytes:
    return json.dumps(
        [
            {
                "adjClose": 51.1875,
                "adjHigh": 51.75,
                "adjLow": 49.9375,
                "adjOpen": 50.5625,
                "adjVolume": 2_000_002,
                "close": 102.375,
                "date": f"{SESSION_DATE.isoformat()}T00:00:00.000Z",
                "divCash": 0.25,
                "high": 103.5,
                "low": 99.875,
                "open": 101.125,
                "splitFactor": 2.0,
                "volume": 1_000_001,
            }
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("malformed-profile", "missing fields"),
        ("scope-mismatch", "requested scope"),
        ("malformed-authorization", "missing fields"),
        ("malformed-calendar", "missing fields"),
        ("unapproved-profile", "has not been approved"),
        ("authorization-profile-mismatch", "does not bind"),
        ("calendar-profile-mismatch", "does not bind"),
    ],
)
def test_capture_cli_validates_profile_authorization_and_scope_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    selected_profile = profile(approved=case != "unapproved-profile")
    profile_bytes = selected_profile.to_json_bytes()
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile)
    symbol = "SPY"

    if case == "malformed-profile":
        profile_bytes = b"{}"
    elif case == "scope-mismatch":
        symbol = "QQQ"
    elif case == "malformed-authorization":
        authorization_bytes = b"{}"
    elif case == "malformed-calendar":
        calendar_bytes = b"{}"
    elif case == "authorization-profile-mismatch":
        authorization_bytes = authorization(profile(market_provenance="tiingo-eod-us-market-v2"))
    elif case == "calendar-profile-mismatch":
        calendar_bytes = calendar_artifact(profile(market_provenance="tiingo-eod-us-market-v2"))

    profile_path = write_artifact(tmp_path / "profile.json", profile_bytes)
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization_bytes,
    )
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)
    monkeypatch.setattr(
        sys,
        "argv",
        capture_argv(profile_path, authorization_path, calendar_path, symbol=symbol),
    )
    monkeypatch.setattr(capture_cli, "load_owner_only_environment", forbidden)
    monkeypatch.setattr(capture_cli, "capture_tiingo_eod", forbidden)

    with pytest.raises(SystemExit, match=message):
        capture_cli.main()


def test_capture_cli_uses_contract_digest_and_keeps_secret_out_of_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected_profile = profile()
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_bytes = authorization(selected_profile)
    authorization_path = write_artifact(tmp_path / "authorization.json", authorization_bytes)
    calendar_bytes = calendar_artifact(selected_profile)
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)
    manifest_path = (
        capture_cli.REPOSITORY_ROOT / ".local/vendor-snapshots/tiingo-eod/test/manifest.json"
    )

    def load_environment(
        path: Path | None,
        *,
        variables: tuple[str, ...],
    ) -> Mapping[str, str]:
        assert path is None
        assert variables == ("TIINGO_TOKEN",)
        return {"TIINGO_TOKEN": TOKEN}

    def capture(**kwargs: object) -> Path:
        assert kwargs["repository_root"] == capture_cli.REPOSITORY_ROOT
        assert kwargs["token"] == TOKEN
        assert kwargs["profile"] == selected_profile
        assert kwargs["authorization_bytes"] == authorization_bytes
        assert kwargs["calendar_artifact_bytes"] == calendar_bytes
        return manifest_path

    monkeypatch.setattr(
        sys,
        "argv",
        capture_argv(profile_path, authorization_path, calendar_path),
    )
    monkeypatch.setattr(capture_cli, "load_owner_only_environment", load_environment)
    monkeypatch.setattr(capture_cli, "capture_tiingo_eod", capture)

    assert capture_cli.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["profile_contract_sha256"] == selected_profile.contract_sha256
    assert result["authorization_sha256"] == hashlib.sha256(authorization_bytes).hexdigest()
    assert result["calendar_artifact_sha256"] == hashlib.sha256(calendar_bytes).hexdigest()
    assert result["admission_effect"] == "none"
    assert result["trading_effect"] == "none"
    assert TOKEN not in output


@pytest.mark.parametrize("restricted_artifact", ["profile", "authorization", "calendar"])
def test_capture_cli_requires_owner_only_artifacts_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restricted_artifact: str,
) -> None:
    selected_profile = profile()
    profile_path = write_artifact(
        tmp_path / "profile.json",
        selected_profile.to_json_bytes(),
        mode=0o644 if restricted_artifact == "profile" else 0o600,
    )
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization(selected_profile),
        mode=0o644 if restricted_artifact == "authorization" else 0o600,
    )
    calendar_path = write_artifact(
        tmp_path / "calendar.json",
        calendar_artifact(selected_profile),
        mode=0o644 if restricted_artifact == "calendar" else 0o600,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        capture_argv(profile_path, authorization_path, calendar_path),
    )
    monkeypatch.setattr(capture_cli, "load_owner_only_environment", forbidden)
    monkeypatch.setattr(capture_cli, "capture_tiingo_eod", forbidden)

    with pytest.raises(SystemExit, match="permissions must be owner-only"):
        capture_cli.main()


@pytest.mark.parametrize("symlink_kind", ["file", "directory"])
def test_profile_inspector_rejects_symlinked_artifact_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    symlink_kind: str,
) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    profile_path = write_artifact(real_directory / "profile.json", profile().to_json_bytes())
    if symlink_kind == "file":
        unsafe_path = tmp_path / "profile-link.json"
        unsafe_path.symlink_to(profile_path)
    else:
        linked_directory = tmp_path / "linked"
        linked_directory.symlink_to(real_directory, target_is_directory=True)
        unsafe_path = linked_directory / "profile.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["inspect_tiingo_eod_profile.py", "--profile-file", str(unsafe_path)],
    )

    with pytest.raises(SystemExit, match="non-symlinked"):
        inspect_cli.main()


def test_profile_inspector_prints_normalized_digest_without_credentials_or_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected_profile = profile()
    presentation_bytes = json.dumps(
        selected_profile.to_dict(),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    profile_path = write_artifact(tmp_path / "profile.json", presentation_bytes)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(capture_cli, "load_owner_only_environment", forbidden)
    monkeypatch.setattr(capture_cli, "capture_tiingo_eod", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        ["inspect_tiingo_eod_profile.py", "--profile-file", str(profile_path)],
    )

    assert inspect_cli.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["profile_contract_sha256"] == selected_profile.contract_sha256
    assert result["profile_contract_sha256"] != hashlib.sha256(presentation_bytes).hexdigest()
    assert result["approved"] is True
    assert result["scope"] == selected_profile.scope.to_dict()
    assert TOKEN not in output


def test_verify_cli_is_credential_free_and_emits_only_research_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected_profile = profile()
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile)
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(tmp_path / "authorization.json", authorization_bytes)
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)
    clock_values = iter((REQUESTED_AT, REQUESTED_AT.replace(second=1)))
    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token="synthetic-capture-token",
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
            status=200,
            payload=response_bytes(),
        ),
        clock=lambda: next(clock_values),
    )
    monkeypatch.setattr(verify_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_tiingo_eod_capture.py",
            "--capture-name",
            manifest_path.parent.name,
            "--profile-file",
            str(profile_path),
            "--authorization-file",
            str(authorization_path),
            "--calendar-file",
            str(calendar_path),
        ],
    )

    assert verify_cli.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["capture_name"] == manifest_path.parent.name
    assert result["manifest_sha256"] == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert result["calendar_artifact_sha256"] == hashlib.sha256(calendar_bytes).hexdigest()
    assert result["profile_contract_sha256"] == selected_profile.contract_sha256
    assert result["observation_count"] == 1
    assert result["row_count"] == 1
    assert len(result["calendar_bindings"]) == 1
    binding = dict(result["calendar_bindings"][0])
    calendar_sha256 = binding.pop("calendar_sha256")
    assert len(calendar_sha256) == 64
    assert binding == {
        "authority": selected_profile.calendar_authority,
        "calendar_id": "SPY-CALENDAR",
        "calendar_version": "test-2026a",
        "session_count": 1,
        "symbol": "SPY",
        "timezone": "America/New_York",
        "venue": "XNYS",
    }
    assert len(result["semantic_sha256"]) == 64
    assert result["admission_effect"] == "none"
    assert result["trading_effect"] == "none"
    assert TOKEN not in output
    assert "synthetic-capture-token" not in output
    assert "102.375" not in output
    assert "adjClose" not in output


def test_lineage_cli_is_offline_and_emits_only_local_version_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected_profile = profile()
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile)
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(tmp_path / "authorization.json", authorization_bytes)
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)

    def capture_at(requested_at: datetime) -> Path:
        clock_values = iter((requested_at, requested_at + timedelta(seconds=1)))
        return capture_tiingo_eod(
            repository_root=tmp_path,
            token="synthetic-capture-token",
            profile=selected_profile,
            authorization_bytes=authorization_bytes,
            calendar_artifact_bytes=calendar_bytes,
            transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
                status=200,
                payload=response_bytes(),
            ),
            clock=lambda: next(clock_values),
        )

    first_manifest = capture_at(REQUESTED_AT)
    second_manifest = capture_at(REQUESTED_AT + timedelta(minutes=1))
    monkeypatch.setattr(lineage_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive_tiingo_eod_lineage.py",
            "--capture-name",
            first_manifest.parent.name,
            "--capture-name",
            second_manifest.parent.name,
            "--profile-file",
            str(profile_path),
            "--authorization-file",
            str(authorization_path),
            "--calendar-file",
            str(calendar_path),
        ],
    )

    assert lineage_cli.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["capture_count"] == 2
    assert result["comparison_count"] == 2
    assert result["local_observation_count"] == 1
    assert result["local_revision_count"] == 1
    assert result["disposition_counts"] == {
        "changed": 0,
        "initial": 1,
        "unchanged": 1,
    }
    assert result["schema_version"] == "tiingo-eod-receipt-lineage-v1"
    assert len(result["lineage_sha256"]) == 64
    assert result["admission_effect"] == "none"
    assert result["trading_effect"] == "none"
    assert TOKEN not in output
    assert "synthetic-capture-token" not in output
    assert "102.375" not in output
    assert "101.125" not in output
    assert "adjClose" not in output
    assert "divCash" not in output
    assert not hasattr(lineage_cli, "load_owner_only_environment")
    assert not hasattr(lineage_cli, "capture_tiingo_eod")


def test_lineage_cli_requires_two_capture_names_before_reading_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lineage_cli, "read_owner_only_artifact", forbidden)
    monkeypatch.setattr(lineage_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive_tiingo_eod_lineage.py",
            "--capture-name",
            f"20260716T120000000000Z-{'a' * 64}",
            "--profile-file",
            str(tmp_path / "profile.json"),
            "--authorization-file",
            str(tmp_path / "authorization.json"),
            "--calendar-file",
            str(tmp_path / "calendar.json"),
        ],
    )

    with pytest.raises(SystemExit, match="at least two capture names"):
        lineage_cli.main()


@pytest.mark.parametrize("unsafe_artifact", ["profile", "authorization", "calendar"])
def test_lineage_cli_rejects_symlinked_review_artifacts_before_capture_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_artifact: str,
) -> None:
    selected_profile = profile()
    paths = {
        "profile": write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes()),
        "authorization": write_artifact(
            tmp_path / "authorization.json",
            authorization(selected_profile),
        ),
        "calendar": write_artifact(
            tmp_path / "calendar.json",
            calendar_artifact(selected_profile),
        ),
    }
    unsafe_path = tmp_path / f"{unsafe_artifact}-link.json"
    unsafe_path.symlink_to(paths[unsafe_artifact])
    paths[unsafe_artifact] = unsafe_path
    monkeypatch.setattr(lineage_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive_tiingo_eod_lineage.py",
            "--capture-name",
            f"20260716T120000000000Z-{'a' * 64}",
            "--capture-name",
            f"20260716T120100000000Z-{'b' * 64}",
            "--profile-file",
            str(paths["profile"]),
            "--authorization-file",
            str(paths["authorization"]),
            "--calendar-file",
            str(paths["calendar"]),
        ],
    )

    with pytest.raises(SystemExit, match="non-symlinked"):
        lineage_cli.main()


@pytest.mark.parametrize(
    "capture_name",
    ["../capture", "/tmp/capture", ".staging-capture", "capture/manifest.json"],
)
def test_lineage_cli_rejects_unsafe_capture_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capture_name: str,
) -> None:
    selected_profile = profile()
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization(selected_profile),
    )
    calendar_path = write_artifact(
        tmp_path / "calendar.json",
        calendar_artifact(selected_profile),
    )
    monkeypatch.setattr(lineage_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "derive_tiingo_eod_lineage.py",
            "--capture-name",
            capture_name,
            "--capture-name",
            f"20260716T120100000000Z-{'b' * 64}",
            "--profile-file",
            str(profile_path),
            "--authorization-file",
            str(authorization_path),
            "--calendar-file",
            str(calendar_path),
        ],
    )

    with pytest.raises(SystemExit, match="finalized Tiingo capture"):
        lineage_cli.main()


def test_retained_field_cli_is_offline_no_write_and_value_free_for_four_by_one_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    symbols = ("DIA", "IWM", "QQQ", "SPY")
    selected_profile = profile(symbols=symbols)
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile)
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization_bytes,
    )
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)
    clock_values = iter(
        REQUESTED_AT + timedelta(seconds=index) for index in range(len(symbols) * 2)
    )
    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token="synthetic-capture-token",
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
            status=200,
            payload=response_bytes(),
        ),
        clock=lambda: next(clock_values),
    )
    before = tree_snapshot(manifest_path.parent)

    monkeypatch.setattr(retained_fields_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_tiingo_eod_retained_fields.py",
            "--capture-name",
            manifest_path.parent.name,
            "--profile-file",
            str(profile_path),
            "--authorization-file",
            str(authorization_path),
            "--calendar-file",
            str(calendar_path),
        ],
    )

    assert retained_fields_cli.main() == 0

    captured = capsys.readouterr()
    output = captured.out
    result = json.loads(output)
    assert captured.err == ""
    assert set(result) == {
        "admission_effect",
        "calendar_artifact_sha256",
        "capture_name",
        "check_ids",
        "corporate_action_effect",
        "field_bindings",
        "field_contract_sha256",
        "field_count",
        "field_occurrence_count",
        "field_occurrence_counts",
        "manifest_sha256",
        "note",
        "observation_count",
        "profile_contract_sha256",
        "qualification_kind",
        "qualification_sha256",
        "raw_execution_effect",
        "received_at",
        "requested_at",
        "role_contract_sha256",
        "role_field_counts",
        "row_count",
        "schema_version",
        "scope",
        "session_count",
        "snapshot_semantic_sha256",
        "trading_effect",
    }
    assert result["capture_name"] == manifest_path.parent.name
    assert result["profile_contract_sha256"] == selected_profile.contract_sha256
    assert result["calendar_artifact_sha256"] == hashlib.sha256(calendar_bytes).hexdigest()
    assert result["manifest_sha256"] == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert result["scope"] == selected_profile.scope.to_dict()
    assert result["observation_count"] == 4
    assert result["row_count"] == 4
    assert result["session_count"] == 1
    assert result["field_count"] == 13
    assert result["field_occurrence_count"] == 52
    assert result["field_occurrence_counts"] == [
        {"count": 4, "field_name": field_name} for field_name, _ in TIINGO_EOD_FIELD_CONTRACT
    ]
    assert all(
        set(binding) == {"field_name", "role", "row_attribute", "source_schema_constraint_id"}
        for binding in result["field_bindings"]
    )
    assert [
        (binding["field_name"], binding["source_schema_constraint_id"])
        for binding in result["field_bindings"]
    ] == list(TIINGO_EOD_FIELD_CONTRACT)
    assert result["role_field_counts"] == {
        "adjusted_research": 5,
        "corporate_action_candidate": 2,
        "documented_raw_candidate": 5,
        "session_identity": 1,
    }
    assert result["schema_version"] == "tiingo-eod-retained-field-qualification-v1"
    assert result["qualification_kind"] == "exact_retained_field_contract_only"
    assert len(result["field_contract_sha256"]) == 64
    assert len(result["role_contract_sha256"]) == 64
    assert len(result["snapshot_semantic_sha256"]) == 64
    assert len(result["qualification_sha256"]) == 64
    for effect in (
        "admission_effect",
        "corporate_action_effect",
        "raw_execution_effect",
        "trading_effect",
    ):
        assert result[effect] == "none"
    for prohibited in (
        TOKEN,
        "synthetic-capture-token",
        TERMS_SHA256,
        "102.375",
        "101.125",
        "51.1875",
        "50.5625",
        "2000002",
        str(tmp_path),
        "test-profile-reviewer",
        "test-authorization-reviewer",
    ):
        assert prohibited not in output
    assert tree_snapshot(manifest_path.parent) == before
    assert not hasattr(retained_fields_cli, "load_owner_only_environment")
    assert not hasattr(retained_fields_cli, "capture_tiingo_eod")


@pytest.mark.parametrize("unsafe_artifact", ["profile", "authorization", "calendar"])
def test_retained_field_cli_rejects_symlinked_review_artifacts_before_capture_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_artifact: str,
) -> None:
    selected_profile = profile()
    paths = {
        "profile": write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes()),
        "authorization": write_artifact(
            tmp_path / "authorization.json",
            authorization(selected_profile),
        ),
        "calendar": write_artifact(
            tmp_path / "calendar.json",
            calendar_artifact(selected_profile),
        ),
    }
    unsafe_path = tmp_path / f"{unsafe_artifact}-link.json"
    unsafe_path.symlink_to(paths[unsafe_artifact])
    paths[unsafe_artifact] = unsafe_path
    monkeypatch.setattr(retained_fields_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_tiingo_eod_retained_fields.py",
            "--capture-name",
            f"20260716T120000000000Z-{'a' * 64}",
            "--profile-file",
            str(paths["profile"]),
            "--authorization-file",
            str(paths["authorization"]),
            "--calendar-file",
            str(paths["calendar"]),
        ],
    )

    with pytest.raises(SystemExit, match="non-symlinked"):
        retained_fields_cli.main()


@pytest.mark.parametrize("restricted_artifact", ["profile", "authorization", "calendar"])
def test_retained_field_cli_requires_owner_only_review_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restricted_artifact: str,
) -> None:
    selected_profile = profile()
    paths = {
        "profile": write_artifact(
            tmp_path / "profile.json",
            selected_profile.to_json_bytes(),
            mode=0o644 if restricted_artifact == "profile" else 0o600,
        ),
        "authorization": write_artifact(
            tmp_path / "authorization.json",
            authorization(selected_profile),
            mode=0o644 if restricted_artifact == "authorization" else 0o600,
        ),
        "calendar": write_artifact(
            tmp_path / "calendar.json",
            calendar_artifact(selected_profile),
            mode=0o644 if restricted_artifact == "calendar" else 0o600,
        ),
    }
    monkeypatch.setattr(retained_fields_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_tiingo_eod_retained_fields.py",
            "--capture-name",
            f"20260716T120000000000Z-{'a' * 64}",
            "--profile-file",
            str(paths["profile"]),
            "--authorization-file",
            str(paths["authorization"]),
            "--calendar-file",
            str(paths["calendar"]),
        ],
    )

    with pytest.raises(SystemExit, match="permissions must be owner-only"):
        retained_fields_cli.main()


@pytest.mark.parametrize(
    "capture_name",
    ["../capture", "/tmp/capture", ".staging-capture", "capture/manifest.json"],
)
def test_retained_field_cli_rejects_unsafe_capture_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capture_name: str,
) -> None:
    selected_profile = profile()
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization(selected_profile),
    )
    calendar_path = write_artifact(
        tmp_path / "calendar.json",
        calendar_artifact(selected_profile),
    )
    monkeypatch.setattr(retained_fields_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_tiingo_eod_retained_fields.py",
            "--capture-name",
            capture_name,
            "--profile-file",
            str(profile_path),
            "--authorization-file",
            str(authorization_path),
            "--calendar-file",
            str(calendar_path),
        ],
    )

    with pytest.raises(SystemExit, match="finalized Tiingo capture"):
        retained_fields_cli.main()


def test_identity_lifecycle_cli_is_offline_no_write_and_value_free_for_exact_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    symbols = ("DIA", "IWM", "QQQ", "SPY")
    selected_profile = profile(symbols=symbols)
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL)
    identity_lifecycle = _artifact(
        selected_profile.contract_sha256,
        kind=TiingoEodIdentityLifecycleArtifactKind.REVIEWED_REFERENCE,
    )
    identity_lifecycle_bytes = identity_lifecycle.to_json_bytes()
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization_bytes,
    )
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)
    identity_lifecycle_path = write_artifact(
        tmp_path / "identity-lifecycle.json",
        identity_lifecycle_bytes,
    )
    payload = response_bytes()
    clock_values = iter(
        REQUESTED_AT + timedelta(seconds=index) for index in range(len(symbols) * 2)
    )
    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token="synthetic-capture-token",
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
            status=200,
            payload=payload,
        ),
        clock=lambda: next(clock_values),
    )
    before = tree_snapshot(manifest_path.parent)

    monkeypatch.setattr(identity_lifecycle_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(capture_cli, "load_owner_only_environment", forbidden)
    monkeypatch.setattr(capture_cli, "capture_tiingo_eod", forbidden)
    for operation in ("chmod", "mkdir", "rename", "replace", "touch", "unlink", "write_bytes"):
        monkeypatch.setattr(Path, operation, forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        identity_lifecycle_argv(
            capture_name=manifest_path.parent.name,
            profile_path=profile_path,
            authorization_path=authorization_path,
            calendar_path=calendar_path,
            identity_lifecycle_path=identity_lifecycle_path,
        ),
    )

    assert identity_lifecycle_cli.main() == 0

    captured = capsys.readouterr()
    output = captured.out
    result = json.loads(output)
    assert captured.err == ""
    assert set(result) == {
        "admission_effect",
        "artifact_kind",
        "artifact_sha256",
        "calendar_artifact_sha256",
        "canonical_bar_effect",
        "capture_name",
        "check_ids",
        "corporate_action_effect",
        "delisting_case_count",
        "historical_source_effect",
        "identifier_count",
        "lifecycle_calendar_effect",
        "mapping_count",
        "membership_count",
        "note",
        "production_identity_effect",
        "profile_contract_sha256",
        "qualification_kind",
        "qualification_sha256",
        "raw_execution_effect",
        "retained_field_qualification_sha256",
        "schema_version",
        "scope",
        "security_count",
        "session_mapping_count",
        "snapshot_semantic_sha256",
        "symbol_change_case_count",
        "trade_symbol_count",
        "trading_effect",
    }
    assert result["capture_name"] == manifest_path.parent.name
    assert result["artifact_kind"] == "reviewed_reference"
    assert result["artifact_sha256"] == hashlib.sha256(identity_lifecycle_bytes).hexdigest()
    assert result["profile_contract_sha256"] == selected_profile.contract_sha256
    assert result["calendar_artifact_sha256"] == hashlib.sha256(calendar_bytes).hexdigest()
    assert result["scope"] == selected_profile.scope.to_dict()
    assert result["check_ids"] == list(TIINGO_EOD_IDENTITY_LIFECYCLE_CHECK_IDS)
    assert result["qualification_kind"] == "identity_lifecycle_contract_only"
    assert result["schema_version"] == "tiingo-eod-identity-lifecycle-qualification-v1"
    assert result["security_count"] == 6
    assert result["identifier_count"] == 8
    assert result["membership_count"] == 4
    assert result["mapping_count"] == 4
    assert result["session_mapping_count"] == 4
    assert result["trade_symbol_count"] == 4
    assert result["symbol_change_case_count"] == 1
    assert result["delisting_case_count"] == 1
    for digest_name in (
        "artifact_sha256",
        "calendar_artifact_sha256",
        "profile_contract_sha256",
        "qualification_sha256",
        "retained_field_qualification_sha256",
        "snapshot_semantic_sha256",
    ):
        assert len(result[digest_name]) == 64
    for effect in (
        "admission_effect",
        "canonical_bar_effect",
        "corporate_action_effect",
        "historical_source_effect",
        "lifecycle_calendar_effect",
        "production_identity_effect",
        "raw_execution_effect",
        "trading_effect",
    ):
        assert result[effect] == "none"

    assert identity_lifecycle.reviewer_id is not None
    for prohibited in (
        TOKEN,
        "synthetic-capture-token",
        TERMS_SHA256,
        payload.decode("utf-8"),
        hashlib.sha256(payload).hexdigest(),
        "102.375",
        "101.125",
        "51.1875",
        "50.5625",
        "2000002",
        str(tmp_path),
        str(profile_path),
        str(authorization_path),
        str(calendar_path),
        str(identity_lifecycle_path),
        "test-profile-reviewer",
        "test-authorization-reviewer",
        "test-calendar-reviewer",
        identity_lifecycle.reviewer_id,
        identity_lifecycle.executor_id,
        identity_lifecycle.identifier_evidence_sha256,
        identity_lifecycle.lifecycle_evidence_sha256,
        identity_lifecycle.identity_source_id,
    ):
        assert prohibited not in output
    for security in identity_lifecycle.securities:
        assert security.security_id not in output
        assert security.name not in output
    assert tree_snapshot(manifest_path.parent) == before
    assert not hasattr(identity_lifecycle_cli, "load_owner_only_environment")
    assert not hasattr(identity_lifecycle_cli, "capture_tiingo_eod")


def test_identity_lifecycle_cli_session_gap_fails_without_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    symbols = ("DIA", "IWM", "QQQ", "SPY")
    selected_profile = profile(symbols=symbols)
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL)
    artifact = _artifact(selected_profile.contract_sha256)
    gap_end = datetime(2026, 7, 14, 13, 30, tzinfo=UTC) + timedelta(microseconds=1)
    gapped_artifact = replace(
        artifact,
        identifiers=tuple(
            replace(value, effective_to=gap_end) if value.symbol == "DIA" else value
            for value in artifact.identifiers
        ),
    )
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization_bytes,
    )
    calendar_path = write_artifact(tmp_path / "calendar.json", calendar_bytes)
    identity_lifecycle_path = write_artifact(
        tmp_path / "identity-lifecycle-private.json",
        gapped_artifact.to_json_bytes(),
    )
    clock_values = iter(
        REQUESTED_AT + timedelta(seconds=index) for index in range(len(symbols) * 2)
    )
    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token="session-gap-private-token",
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
            status=200,
            payload=response_bytes(),
        ),
        clock=lambda: next(clock_values),
    )
    monkeypatch.setattr(identity_lifecycle_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        identity_lifecycle_argv(
            capture_name=manifest_path.parent.name,
            profile_path=profile_path,
            authorization_path=authorization_path,
            calendar_path=calendar_path,
            identity_lifecycle_path=identity_lifecycle_path,
        ),
    )

    with pytest.raises(SystemExit) as failure:
        identity_lifecycle_cli.main()

    message = str(failure.value)
    captured = capsys.readouterr()
    assert message == identity_lifecycle_cli.QUALIFICATION_FAILURE_MESSAGE
    assert captured.out == captured.err == ""
    for prohibited in (
        "Traceback",
        str(tmp_path),
        str(identity_lifecycle_path),
        "session-gap-private-token",
        "security-dia",
    ):
        assert prohibited not in message


@pytest.mark.parametrize(
    "unsafe_artifact",
    ["profile", "authorization", "calendar", "identity_lifecycle"],
)
def test_identity_lifecycle_cli_rejects_symlinked_artifacts_before_capture_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_artifact: str,
) -> None:
    selected_profile = profile(symbols=("DIA", "IWM", "QQQ", "SPY"))
    paths = {
        "profile": write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes()),
        "authorization": write_artifact(
            tmp_path / "authorization.json",
            authorization(selected_profile),
        ),
        "calendar": write_artifact(
            tmp_path / "calendar.json",
            calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL),
        ),
        "identity_lifecycle": write_artifact(
            tmp_path / "identity-lifecycle.json",
            _artifact(selected_profile.contract_sha256).to_json_bytes(),
        ),
    }
    unsafe_path = tmp_path / f"{unsafe_artifact}-link.json"
    unsafe_path.symlink_to(paths[unsafe_artifact])
    paths[unsafe_artifact] = unsafe_path
    monkeypatch.setattr(identity_lifecycle_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        identity_lifecycle_argv(
            capture_name=f"20260716T120000000000Z-{'a' * 64}",
            profile_path=paths["profile"],
            authorization_path=paths["authorization"],
            calendar_path=paths["calendar"],
            identity_lifecycle_path=paths["identity_lifecycle"],
        ),
    )

    with pytest.raises(SystemExit, match="non-symlinked"):
        identity_lifecycle_cli.main()


@pytest.mark.parametrize(
    "restricted_artifact",
    ["profile", "authorization", "calendar", "identity_lifecycle"],
)
def test_identity_lifecycle_cli_requires_owner_only_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restricted_artifact: str,
) -> None:
    selected_profile = profile(symbols=("DIA", "IWM", "QQQ", "SPY"))
    payloads = {
        "profile": selected_profile.to_json_bytes(),
        "authorization": authorization(selected_profile),
        "calendar": calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL),
        "identity_lifecycle": _artifact(selected_profile.contract_sha256).to_json_bytes(),
    }
    paths = {
        name: write_artifact(
            tmp_path / f"{name}.json",
            payload,
            mode=0o644 if name == restricted_artifact else 0o600,
        )
        for name, payload in payloads.items()
    }
    monkeypatch.setattr(identity_lifecycle_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        identity_lifecycle_argv(
            capture_name=f"20260716T120000000000Z-{'a' * 64}",
            profile_path=paths["profile"],
            authorization_path=paths["authorization"],
            calendar_path=paths["calendar"],
            identity_lifecycle_path=paths["identity_lifecycle"],
        ),
    )

    with pytest.raises(SystemExit, match="permissions must be owner-only"):
        identity_lifecycle_cli.main()


@pytest.mark.parametrize(
    "artifact_case",
    ["noncanonical", "template", "private_enum", "private_field"],
)
def test_identity_lifecycle_cli_rejects_invalid_artifact_before_capture_qualification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_case: str,
) -> None:
    selected_profile = profile(symbols=("DIA", "IWM", "QQQ", "SPY"))
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization(selected_profile),
    )
    calendar_path = write_artifact(
        tmp_path / "calendar.json",
        calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL),
    )
    private_marker = "PRIVATE-IDENTITY-ARTIFACT-CONTENT"
    if artifact_case == "noncanonical":
        canonical = _artifact(selected_profile.contract_sha256).to_json_bytes()
        identity_lifecycle_bytes = json.dumps(json.loads(canonical)).encode("utf-8")
    elif artifact_case == "template":
        identity_lifecycle_bytes = (
            REPOSITORY_ROOT / "docs/admission/tiingo-eod-identity-lifecycle.template.json"
        ).read_bytes()
    else:
        payload = json.loads(_artifact(selected_profile.contract_sha256).to_json_bytes())
        if artifact_case == "private_enum":
            payload["securities"][0]["asset_class"] = private_marker
        else:
            payload["securities"][0][private_marker] = True
        identity_lifecycle_bytes = (
            json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode()
    identity_lifecycle_path = write_artifact(
        tmp_path / "identity-lifecycle.json",
        identity_lifecycle_bytes,
    )
    monkeypatch.setattr(identity_lifecycle_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(identity_lifecycle_cli, "qualify_tiingo_eod_retained_fields", forbidden)
    monkeypatch.setattr(identity_lifecycle_cli, "qualify_tiingo_eod_identity_lifecycle", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        identity_lifecycle_argv(
            capture_name=f"20260716T120000000000Z-{'a' * 64}",
            profile_path=profile_path,
            authorization_path=authorization_path,
            calendar_path=calendar_path,
            identity_lifecycle_path=identity_lifecycle_path,
        ),
    )

    with pytest.raises(SystemExit) as failure:
        identity_lifecycle_cli.main()

    message = str(failure.value)
    assert message == identity_lifecycle_cli.QUALIFICATION_FAILURE_MESSAGE
    assert private_marker not in message
    assert str(tmp_path) not in message


def test_identity_lifecycle_make_target_expands_to_strict_offline_command() -> None:
    result = subprocess.run(
        [
            "make",
            "-n",
            "tiingo-eod-identity-qualify",
            "CAPTURE=final-capture",
            "PROFILE=profile.json",
            "AUTHORIZATION=authorization.json",
            "CALENDAR=calendar.json",
            "IDENTITY_LIFECYCLE=identity-lifecycle.json",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stderr == ""
    assert "uv run --offline --frozen --no-sync --no-env-file python -B" in result.stdout
    assert "scripts/qualify_tiingo_eod_identity_lifecycle.py" in result.stdout
    assert '--capture-name "final-capture"' in result.stdout
    assert '--identity-lifecycle-file "identity-lifecycle.json"' in result.stdout


@pytest.mark.parametrize("unsafe_artifact", ["profile", "authorization", "calendar"])
def test_verify_cli_rejects_symlinked_review_artifacts_before_capture_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_artifact: str,
) -> None:
    selected_profile = profile()
    paths = {
        "profile": write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes()),
        "authorization": write_artifact(
            tmp_path / "authorization.json",
            authorization(selected_profile),
        ),
        "calendar": write_artifact(
            tmp_path / "calendar.json",
            calendar_artifact(selected_profile),
        ),
    }
    unsafe_path = tmp_path / f"{unsafe_artifact}-link.json"
    unsafe_path.symlink_to(paths[unsafe_artifact])
    paths[unsafe_artifact] = unsafe_path
    monkeypatch.setattr(verify_cli, "verify_tiingo_eod_capture", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_tiingo_eod_capture.py",
            "--capture-name",
            f"20260716T120000000000Z-{'a' * 64}",
            "--profile-file",
            str(paths["profile"]),
            "--authorization-file",
            str(paths["authorization"]),
            "--calendar-file",
            str(paths["calendar"]),
        ],
    )

    with pytest.raises(SystemExit, match="non-symlinked"):
        verify_cli.main()


@pytest.mark.parametrize(
    "capture_name",
    ["../capture", "/tmp/capture", ".staging-capture", "capture/manifest.json"],
)
def test_verify_cli_rejects_unsafe_capture_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capture_name: str,
) -> None:
    selected_profile = profile()
    profile_path = write_artifact(tmp_path / "profile.json", selected_profile.to_json_bytes())
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization(selected_profile),
    )
    calendar_path = write_artifact(
        tmp_path / "calendar.json",
        calendar_artifact(selected_profile),
    )
    monkeypatch.setattr(verify_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_tiingo_eod_capture.py",
            "--capture-name",
            capture_name,
            "--profile-file",
            str(profile_path),
            "--authorization-file",
            str(authorization_path),
            "--calendar-file",
            str(calendar_path),
        ],
    )

    with pytest.raises(SystemExit, match="finalized Tiingo capture"):
        verify_cli.main()


def test_checked_in_templates_remain_non_authorizing() -> None:
    profile_bytes = (
        REPOSITORY_ROOT / "docs/admission/tiingo-eod-acquisition-profile.template.json"
    ).read_bytes()
    authorization_bytes = (
        REPOSITORY_ROOT / "docs/admission/tiingo-eod-capture-authorization.template.json"
    ).read_bytes()
    calendar_bytes = (
        REPOSITORY_ROOT / "docs/admission/tiingo-eod-pinned-calendar.template.json"
    ).read_bytes()
    selected_profile = TiingoEodAcquisitionProfile.from_json_bytes(profile_bytes)
    selected_calendar = TiingoEodPinnedCalendarArtifact.from_json_bytes(calendar_bytes)

    assert selected_profile.approved is False
    assert selected_calendar.approved is False
    assert selected_calendar.profile_contract_sha256 != selected_profile.contract_sha256
    with pytest.raises(TiingoEodError, match="terms_sha256"):
        TiingoEodCaptureAuthorization.from_json_bytes(authorization_bytes)

    approved_profile = replace(selected_profile, approved=True)
    authorization_payload = json.loads(authorization_bytes)
    authorization_payload["terms_sha256"] = TERMS_SHA256
    authorization_payload["profile_contract_sha256"] = approved_profile.contract_sha256
    false_by_default_authorization = TiingoEodCaptureAuthorization.from_json_bytes(
        json.dumps(authorization_payload, separators=(",", ":")).encode("utf-8")
    )
    with pytest.raises(ValueError, match="does not permit local research storage"):
        false_by_default_authorization.authorize(
            approved_profile,
            requested_at=REQUESTED_AT,
        )
    with pytest.raises(ValueError, match="has not been approved"):
        selected_calendar.authorize(approved_profile, requested_at=REQUESTED_AT)
