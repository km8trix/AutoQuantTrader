from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn, cast

import pytest

import scripts.qualify_tiingo_eod_market_semantics as semantics_cli
from packages.adapters.market_data.tiingo_eod import TiingoEodAcquisitionProfile
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodApiResponse,
    capture_tiingo_eod,
)
from packages.adapters.market_data.tiingo_eod_identity_lifecycle import (
    TiingoEodIdentityLifecycleArtifact,
    TiingoEodIdentityLifecycleArtifactKind,
    TiingoEodIdentityLifecycleQualification,
    qualify_tiingo_eod_identity_lifecycle,
)
from packages.adapters.market_data.tiingo_eod_market_semantics import (
    TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS,
    TiingoEodMarketSemanticsArtifact,
)
from packages.adapters.market_data.tiingo_eod_retained_fields import (
    qualify_tiingo_eod_retained_fields,
)
from packages.adapters.market_data.tiingo_eod_snapshot import (
    verify_tiingo_eod_capture,
)
from tests.unit.test_tiingo_eod_identity_lifecycle import _artifact as identity_artifact
from tests.unit.test_tiingo_eod_market_semantics import (
    _canonical_json,
    _semantics_payload,
)
from tests.unit.test_tiingo_eod_operational_cli import (
    REQUESTED_AT,
    TERMS_SHA256,
    TOKEN,
    authorization,
    calendar_artifact,
    profile,
    response_bytes,
    tree_snapshot,
    write_artifact,
)
from tests.unit.test_tiingo_eod_snapshot import VENUE_BY_SYMBOL

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SYMBOLS = ("DIA", "IWM", "QQQ", "SPY")
MARKET_PROVENANCE = "tiingo-eod-us-consolidated-market-v1"
MARKET_SEMANTICS_SOURCE_ID = "test-reviewed-market-semantics-source-v1"
CAPTURE_TOKEN = "private-synthetic-capture-token"


@dataclass(frozen=True, slots=True)
class _Scenario:
    profile: TiingoEodAcquisitionProfile
    authorization_bytes: bytes
    calendar_bytes: bytes
    identity_artifact: TiingoEodIdentityLifecycleArtifact
    identity_qualification: TiingoEodIdentityLifecycleQualification
    identity_bytes: bytes
    semantics_artifact: TiingoEodMarketSemanticsArtifact
    semantics_bytes: bytes
    response_payload: bytes
    manifest_path: Path
    paths: dict[str, Path]


def _forbidden(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError((args, kwargs))


def _market_semantics_bytes(
    *,
    profile_contract_sha256: str,
    identity_lifecycle_qualification_sha256: str,
    kind: str = "synthetic_contract",
    source_id: str = MARKET_SEMANTICS_SOURCE_ID,
) -> bytes:
    payload = _semantics_payload(
        profile_contract_sha256=profile_contract_sha256,
        identity_lifecycle_qualification_sha256=(identity_lifecycle_qualification_sha256),
        kind=kind,
    )
    payload["market_semantics_source_id"] = source_id
    return _canonical_json(payload)


def _argv(*, capture_name: str, paths: dict[str, Path]) -> list[str]:
    return [
        "qualify_tiingo_eod_market_semantics.py",
        "--capture-name",
        capture_name,
        "--profile-file",
        str(paths["profile"]),
        "--authorization-file",
        str(paths["authorization"]),
        "--calendar-file",
        str(paths["calendar"]),
        "--identity-lifecycle-file",
        str(paths["identity_lifecycle"]),
        "--market-semantics-file",
        str(paths["market_semantics"]),
    ]


def _reviewed_scenario(tmp_path: Path) -> _Scenario:
    selected_profile = profile(
        symbols=SYMBOLS,
        market_provenance=MARKET_PROVENANCE,
    )
    authorization_bytes = authorization(selected_profile)
    calendar_bytes = calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL)
    selected_identity_artifact = identity_artifact(
        selected_profile.contract_sha256,
        kind=TiingoEodIdentityLifecycleArtifactKind.REVIEWED_REFERENCE,
    )
    identity_bytes = selected_identity_artifact.to_json_bytes()
    paths = {
        "profile": write_artifact(
            tmp_path / "profile.json",
            selected_profile.to_json_bytes(),
        ),
        "authorization": write_artifact(
            tmp_path / "authorization.json",
            authorization_bytes,
        ),
        "calendar": write_artifact(tmp_path / "calendar.json", calendar_bytes),
        "identity_lifecycle": write_artifact(
            tmp_path / "identity-lifecycle.json",
            identity_bytes,
        ),
    }
    payload = response_bytes()
    clock_values = iter(
        REQUESTED_AT + timedelta(seconds=index) for index in range(len(SYMBOLS) * 2)
    )
    manifest_path = capture_tiingo_eod(
        repository_root=tmp_path,
        token=CAPTURE_TOKEN,
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
        transport=lambda request, *, timeout_seconds: TiingoEodApiResponse(
            status=200,
            payload=payload,
        ),
        clock=lambda: next(clock_values),
    )
    snapshot = verify_tiingo_eod_capture(
        repository_root=tmp_path,
        capture_name=manifest_path.parent.name,
        expected_profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_artifact_bytes=calendar_bytes,
    )
    retained_fields = qualify_tiingo_eod_retained_fields(snapshot)
    identity_qualification = qualify_tiingo_eod_identity_lifecycle(
        snapshot=snapshot,
        retained_fields=retained_fields,
        artifact_bytes=identity_bytes,
    )
    semantics_bytes = _market_semantics_bytes(
        profile_contract_sha256=selected_profile.contract_sha256,
        identity_lifecycle_qualification_sha256=(identity_qualification.qualification_sha256),
        kind="reviewed_reference",
    )
    paths["market_semantics"] = write_artifact(
        tmp_path / "market-semantics.json",
        semantics_bytes,
    )
    return _Scenario(
        profile=selected_profile,
        authorization_bytes=authorization_bytes,
        calendar_bytes=calendar_bytes,
        identity_artifact=selected_identity_artifact,
        identity_qualification=identity_qualification,
        identity_bytes=identity_bytes,
        semantics_artifact=TiingoEodMarketSemanticsArtifact.from_json_bytes(semantics_bytes),
        semantics_bytes=semantics_bytes,
        response_payload=payload,
        manifest_path=manifest_path,
        paths=paths,
    )


def _read_gate_paths(tmp_path: Path) -> dict[str, Path]:
    selected_profile = profile(
        symbols=SYMBOLS,
        market_provenance=MARKET_PROVENANCE,
    )
    identity_bytes = identity_artifact(selected_profile.contract_sha256).to_json_bytes()
    payloads = {
        "profile": selected_profile.to_json_bytes(),
        "authorization": authorization(selected_profile),
        "calendar": calendar_artifact(selected_profile, venues=VENUE_BY_SYMBOL),
        "identity_lifecycle": identity_bytes,
        "market_semantics": _market_semantics_bytes(
            profile_contract_sha256=selected_profile.contract_sha256,
            identity_lifecycle_qualification_sha256="a" * 64,
        ),
    }
    return {
        name: write_artifact(tmp_path / f"{name}.json", payload)
        for name, payload in payloads.items()
    }


def test_market_semantics_cli_is_offline_no_write_and_value_free_for_exact_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scenario = _reviewed_scenario(tmp_path)
    before = tree_snapshot(tmp_path)

    monkeypatch.setattr(semantics_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    for operation in ("chmod", "mkdir", "rename", "replace", "touch", "unlink", "write_bytes"):
        monkeypatch.setattr(Path, operation, _forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        _argv(capture_name=scenario.manifest_path.parent.name, paths=scenario.paths),
    )

    assert semantics_cli.main() == 0

    captured = capsys.readouterr()
    output = captured.out
    result = json.loads(output)
    assert captured.err == ""
    assert set(result) == {
        "action_candidate_contract_sha256",
        "adjustment_methodology_effect",
        "admission_effect",
        "artifact_kind",
        "artifact_sha256",
        "calendar_artifact_sha256",
        "candidate_field_count",
        "candidate_occurrence_count",
        "canonical_bar_effect",
        "capture_name",
        "check_ids",
        "corporate_action_effect",
        "correction_effect",
        "field_semantics_contract_sha256",
        "genuine_raw_effect",
        "historical_source_effect",
        "identity_lifecycle_qualification_sha256",
        "market_provenance_effect",
        "note",
        "profile_contract_sha256",
        "qualification_kind",
        "qualification_sha256",
        "retained_field_qualification_sha256",
        "row_count",
        "schema_version",
        "scope",
        "stable_id_count",
        "synthetic_case_contract_sha256",
        "synthetic_case_count",
        "trading_effect",
        "vendor_publication_effect",
    }
    assert result["capture_name"] == scenario.manifest_path.parent.name
    assert result["artifact_kind"] == "reviewed_reference"
    assert result["artifact_sha256"] == hashlib.sha256(scenario.semantics_bytes).hexdigest()
    assert result["calendar_artifact_sha256"] == hashlib.sha256(scenario.calendar_bytes).hexdigest()
    assert result["profile_contract_sha256"] == scenario.profile.contract_sha256
    assert result["identity_lifecycle_qualification_sha256"] == (
        scenario.identity_qualification.qualification_sha256
    )
    assert result["scope"] == scenario.profile.scope.to_dict()
    assert result["check_ids"] == list(TIINGO_EOD_MARKET_SEMANTICS_CHECK_IDS)
    assert result["qualification_kind"] == "market_semantics_contract_only"
    assert result["schema_version"] == "tiingo-eod-market-semantics-qualification-v1"
    assert result["row_count"] == 4
    assert result["stable_id_count"] == 4
    assert result["candidate_field_count"] == 2
    assert result["candidate_occurrence_count"] == 8
    assert result["synthetic_case_count"] == 5
    for digest_name in (
        "action_candidate_contract_sha256",
        "artifact_sha256",
        "calendar_artifact_sha256",
        "field_semantics_contract_sha256",
        "identity_lifecycle_qualification_sha256",
        "profile_contract_sha256",
        "qualification_sha256",
        "retained_field_qualification_sha256",
        "synthetic_case_contract_sha256",
    ):
        assert len(result[digest_name]) == 64
    for effect in (
        "adjustment_methodology_effect",
        "admission_effect",
        "canonical_bar_effect",
        "corporate_action_effect",
        "correction_effect",
        "genuine_raw_effect",
        "historical_source_effect",
        "market_provenance_effect",
        "trading_effect",
        "vendor_publication_effect",
    ):
        assert result[effect] == "none"

    artifact = scenario.semantics_artifact
    for prohibited in (
        TOKEN,
        CAPTURE_TOKEN,
        TERMS_SHA256,
        scenario.response_payload.decode("utf-8"),
        hashlib.sha256(scenario.response_payload).hexdigest(),
        "102.375",
        "101.125",
        "51.1875",
        "50.5625",
        "2000002",
        "0.25",
        str(tmp_path),
        *(str(path) for path in scenario.paths.values()),
        "test-profile-reviewer",
        "test-authorization-reviewer",
        "test-calendar-reviewer",
        scenario.identity_artifact.reviewer_id,
        scenario.identity_artifact.executor_id,
        scenario.identity_artifact.identity_source_id,
        scenario.identity_artifact.identifier_evidence_sha256,
        scenario.identity_artifact.lifecycle_evidence_sha256,
        artifact.artifact_id,
        artifact.reviewer_id,
        artifact.executor_id,
        artifact.market_semantics_source_id,
        artifact.raw_semantics_evidence_sha256,
        artifact.adjusted_methodology_evidence_sha256,
        artifact.market_provenance_evidence_sha256,
        artifact.corporate_action_candidate_evidence_sha256,
        "tiingo-end-of-day-v1",
        "provider-documented-eligible-trades-candidate",
        "positive_cash_per_share_candidate",
        "new_shares_per_old_share_candidate",
    ):
        assert prohibited is not None
        assert prohibited not in output
    for security in scenario.identity_artifact.securities:
        assert security.security_id not in output
        assert security.name not in output
    assert tree_snapshot(tmp_path) == before
    assert not hasattr(semantics_cli, "load_owner_only_environment")
    assert not hasattr(semantics_cli, "capture_tiingo_eod")


@pytest.mark.parametrize(
    "unsafe_artifact",
    ["profile", "authorization", "calendar", "identity_lifecycle", "market_semantics"],
)
def test_market_semantics_cli_rejects_all_symlinked_inputs_before_capture_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_artifact: str,
) -> None:
    paths = _read_gate_paths(tmp_path)
    unsafe_path = tmp_path / f"{unsafe_artifact}-link.json"
    unsafe_path.symlink_to(paths[unsafe_artifact])
    paths[unsafe_artifact] = unsafe_path
    monkeypatch.setattr(semantics_cli, "verify_tiingo_eod_capture", _forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        _argv(capture_name=f"20260716T120000000000Z-{'a' * 64}", paths=paths),
    )

    with pytest.raises(SystemExit, match="non-symlinked"):
        semantics_cli.main()


@pytest.mark.parametrize(
    "restricted_artifact",
    ["profile", "authorization", "calendar", "identity_lifecycle", "market_semantics"],
)
def test_market_semantics_cli_requires_owner_only_mode_for_every_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restricted_artifact: str,
) -> None:
    paths = _read_gate_paths(tmp_path)
    paths[restricted_artifact].chmod(0o644)
    monkeypatch.setattr(semantics_cli, "verify_tiingo_eod_capture", _forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        _argv(capture_name=f"20260716T120000000000Z-{'a' * 64}", paths=paths),
    )

    with pytest.raises(SystemExit, match="permissions must be owner-only"):
        semantics_cli.main()


@pytest.mark.parametrize(
    "artifact_case",
    ["noncanonical", "deeply_nested", "template", "private_enum", "private_field"],
)
def test_market_semantics_cli_rejects_invalid_artifact_before_capture_or_qualifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    artifact_case: str,
) -> None:
    selected_profile = profile(
        symbols=SYMBOLS,
        market_provenance=MARKET_PROVENANCE,
    )
    paths = _read_gate_paths(tmp_path)
    private_marker = "PRIVATE-MARKET-SEMANTICS-ARTIFACT-CONTENT"
    canonical = _market_semantics_bytes(
        profile_contract_sha256=selected_profile.contract_sha256,
        identity_lifecycle_qualification_sha256="a" * 64,
    )
    if artifact_case == "noncanonical":
        semantics_bytes = json.dumps(json.loads(canonical)).encode("utf-8")
    elif artifact_case == "deeply_nested":
        semantics_bytes = b"[" * 10_000 + b"]" * 10_000
    elif artifact_case == "template":
        semantics_bytes = (
            REPOSITORY_ROOT / "docs/admission/tiingo-eod-market-semantics.template.json"
        ).read_bytes()
    else:
        payload = cast(dict[str, Any], json.loads(canonical))
        if artifact_case == "private_enum":
            payload["action_candidate_convention"]["split_factor_orientation"] = private_marker
        else:
            payload[private_marker] = True
        semantics_bytes = _canonical_json(payload)
    paths["market_semantics"] = write_artifact(
        tmp_path / "invalid-market-semantics.json",
        semantics_bytes,
    )
    monkeypatch.setattr(semantics_cli, "verify_tiingo_eod_capture", _forbidden)
    monkeypatch.setattr(semantics_cli, "qualify_tiingo_eod_retained_fields", _forbidden)
    monkeypatch.setattr(semantics_cli, "qualify_tiingo_eod_identity_lifecycle", _forbidden)
    monkeypatch.setattr(semantics_cli, "qualify_tiingo_eod_market_semantics", _forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        _argv(capture_name=f"20260716T120000000000Z-{'a' * 64}", paths=paths),
    )

    with pytest.raises(SystemExit) as failure:
        semantics_cli.main()

    captured = capsys.readouterr()
    message = str(failure.value)
    assert message == semantics_cli.QUALIFICATION_FAILURE_MESSAGE
    assert captured.out == captured.err == ""
    assert private_marker not in message
    assert str(tmp_path) not in message


def test_market_semantics_cli_provenance_session_gap_is_generic_and_value_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    scenario = _reviewed_scenario(tmp_path)
    private_source = "private-gapped-market-semantics-source"
    private_effective_from = "2026-07-14T13:30:00.000001Z"
    payload = cast(dict[str, Any], json.loads(scenario.semantics_bytes))
    payload["market_semantics_source_id"] = private_source
    payload["provenance"]["effective_from"] = private_effective_from
    scenario.paths["market_semantics"] = write_artifact(
        tmp_path / "gapped-market-semantics.json",
        _canonical_json(payload),
    )
    before = tree_snapshot(tmp_path)
    monkeypatch.setattr(semantics_cli, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setenv("TIINGO_TOKEN", TOKEN)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        _argv(capture_name=scenario.manifest_path.parent.name, paths=scenario.paths),
    )

    with pytest.raises(SystemExit) as failure:
        semantics_cli.main()

    captured = capsys.readouterr()
    message = str(failure.value)
    assert message == semantics_cli.QUALIFICATION_FAILURE_MESSAGE
    assert captured.out == captured.err == ""
    for prohibited in (
        "Traceback",
        TOKEN,
        CAPTURE_TOKEN,
        private_source,
        private_effective_from,
        str(tmp_path),
        str(scenario.paths["market_semantics"]),
    ):
        assert prohibited not in message
    assert tree_snapshot(tmp_path) == before


def test_market_semantics_make_target_expands_to_strict_offline_command() -> None:
    result = subprocess.run(
        [
            "make",
            "-n",
            "tiingo-eod-semantics-qualify",
            "CAPTURE=final-capture",
            "PROFILE=profile.json",
            "AUTHORIZATION=authorization.json",
            "CALENDAR=calendar.json",
            "IDENTITY_LIFECYCLE=identity-lifecycle.json",
            "MARKET_SEMANTICS=market-semantics.json",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stderr == ""
    assert "uv run --offline --frozen --no-sync --no-env-file python -B" in result.stdout
    assert "scripts/qualify_tiingo_eod_market_semantics.py" in result.stdout
    assert '--capture-name "final-capture"' in result.stdout
    assert '--profile-file "profile.json"' in result.stdout
    assert '--authorization-file "authorization.json"' in result.stdout
    assert '--calendar-file "calendar.json"' in result.stdout
    assert '--identity-lifecycle-file "identity-lifecycle.json"' in result.stdout
    assert '--market-semantics-file "market-semantics.json"' in result.stdout
