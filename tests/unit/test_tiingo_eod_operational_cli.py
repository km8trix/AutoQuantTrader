from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn

import pytest

import scripts.capture_tiingo_eod as capture_cli
import scripts.inspect_tiingo_eod_profile as inspect_cli
from packages.adapters.market_data.tiingo_eod import (
    TiingoEodAcquisitionProfile,
    TiingoEodCaptureAuthorization,
    TiingoEodError,
    TiingoEodScope,
)

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
        adapter_version="tiingo-eod-capture-v1",
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


def write_artifact(path: Path, payload: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(payload)
    path.chmod(mode)
    return path


def capture_argv(
    profile_path: Path,
    authorization_path: Path,
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
    ]


def forbidden(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError((args, kwargs))


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("malformed-profile", "missing fields"),
        ("scope-mismatch", "requested scope"),
        ("malformed-authorization", "missing fields"),
        ("unapproved-profile", "has not been approved"),
        ("authorization-profile-mismatch", "does not bind"),
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
    symbol = "SPY"

    if case == "malformed-profile":
        profile_bytes = b"{}"
    elif case == "scope-mismatch":
        symbol = "QQQ"
    elif case == "malformed-authorization":
        authorization_bytes = b"{}"
    elif case == "authorization-profile-mismatch":
        authorization_bytes = authorization(profile(market_provenance="tiingo-eod-us-market-v2"))

    profile_path = write_artifact(tmp_path / "profile.json", profile_bytes)
    authorization_path = write_artifact(
        tmp_path / "authorization.json",
        authorization_bytes,
    )
    monkeypatch.setattr(sys, "argv", capture_argv(profile_path, authorization_path, symbol=symbol))
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
        return manifest_path

    monkeypatch.setattr(sys, "argv", capture_argv(profile_path, authorization_path))
    monkeypatch.setattr(capture_cli, "load_owner_only_environment", load_environment)
    monkeypatch.setattr(capture_cli, "capture_tiingo_eod", capture)

    assert capture_cli.main() == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["profile_contract_sha256"] == selected_profile.contract_sha256
    assert result["authorization_sha256"] == hashlib.sha256(authorization_bytes).hexdigest()
    assert result["admission_effect"] == "none"
    assert result["trading_effect"] == "none"
    assert TOKEN not in output


@pytest.mark.parametrize("restricted_artifact", ["profile", "authorization"])
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
    monkeypatch.setattr(sys, "argv", capture_argv(profile_path, authorization_path))
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


def test_checked_in_templates_remain_non_authorizing() -> None:
    profile_bytes = (
        REPOSITORY_ROOT / "docs/admission/tiingo-eod-acquisition-profile.template.json"
    ).read_bytes()
    authorization_bytes = (
        REPOSITORY_ROOT / "docs/admission/tiingo-eod-capture-authorization.template.json"
    ).read_bytes()
    selected_profile = TiingoEodAcquisitionProfile.from_json_bytes(profile_bytes)

    assert selected_profile.approved is False
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
