from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from packages.adapters.market_data.tiingo_eod import TiingoEodScope
from packages.adapters.market_data.tiingo_eod_capture import (
    TiingoEodApiRequest,
    TiingoEodApiResponse,
)
from scripts import capture_personal_tiingo as capture

FAKE_TOKEN = "fixture-token-never-a-provider-secret"


def _fixture(tmp_path: Path) -> tuple[Path, Path, TiingoEodScope]:
    env_file = tmp_path / "fixture.env"
    env_file.write_text(f"UNRELATED_SECRET=$(do-not-execute)\nTIINGO_TOKEN='{FAKE_TOKEN}'\n")
    env_file.chmod(0o600)
    return (
        env_file,
        tmp_path / "capture",
        TiingoEodScope(
            ("SPY",),
            date(2025, 2, 3),
            date(2025, 2, 3),
        ),
    )


def _body() -> bytes:
    return json.dumps(
        [
            {
                "date": "2025-02-03",
                "open": 100,
                "high": 102,
                "low": 99,
                "close": 101,
                "volume": 1000,
                "adjOpen": 100,
                "adjHigh": 102,
                "adjLow": 99,
                "adjClose": 101,
                "adjVolume": 1000,
                "divCash": 0,
                "splitFactor": 1,
            }
        ]
    ).encode()


def test_capture_reuses_fixed_transport_contract_and_retains_actual_receipts(
    tmp_path: Path,
) -> None:
    env_file, output, scope = _fixture(tmp_path)
    requested = datetime(2026, 9, 9, 1, tzinfo=UTC)
    times = iter((requested, requested + timedelta(seconds=1), requested + timedelta(seconds=2)))
    calls: list[TiingoEodApiRequest] = []

    def transport(request: TiingoEodApiRequest, *, timeout_seconds: float) -> TiingoEodApiResponse:
        calls.append(request)
        assert timeout_seconds == 15
        assert request.headers["Authorization"] == f"Token {FAKE_TOKEN}"
        assert request.url.startswith("https://api.tiingo.com/tiingo/daily/SPY/prices?")
        assert FAKE_TOKEN not in request.url and FAKE_TOKEN not in repr(request)
        return TiingoEodApiResponse(200, _body())

    metadata = capture.capture_personal_tiingo(
        env_file=env_file,
        output_dir=output,
        scope=scope,
        transport=transport,
        clock=lambda: next(times),
    )
    assert len(calls) == 1
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "SPY.json").stat().st_mode & 0o777 == 0o600
    assert (output / "SPY.json").read_bytes() == _body()
    receipt = json.loads((output / "SPY.receipt.json").read_bytes())
    assert receipt["requested_at"] == requested.isoformat()
    assert receipt["received_at"] == (requested + timedelta(seconds=1)).isoformat()
    assert receipt["observed_available_at"] == (requested + timedelta(seconds=2)).isoformat()
    assert FAKE_TOKEN not in json.dumps(metadata)
    assert metadata["admission_effect"] == "none"
    assert metadata["vendor_published_at"] is None


@pytest.mark.parametrize("status", [302, 401, 429, 500])
def test_http_failures_are_sanitized_and_never_retried(tmp_path: Path, status: int) -> None:
    env_file, output, scope = _fixture(tmp_path)
    calls = 0

    def transport(request: TiingoEodApiRequest, *, timeout_seconds: float) -> TiingoEodApiResponse:
        nonlocal calls
        calls += 1
        return TiingoEodApiResponse(status, FAKE_TOKEN.encode())

    with pytest.raises(RuntimeError, match=f"HTTP {status}") as failure:
        capture.capture_personal_tiingo(
            env_file=env_file,
            output_dir=output,
            scope=scope,
            transport=transport,
        )
    assert FAKE_TOKEN not in str(failure.value)
    assert calls == 1
    assert not (output / "capture.json").exists()


@pytest.mark.parametrize(
    "assignment",
    [
        "TIINGO_TOKEN=$(printenv)\n",
        "TIINGO_TOKEN=${OTHER_SECRET}\n",
        f"TIINGO_TOKEN={FAKE_TOKEN}\nTIINGO_TOKEN={FAKE_TOKEN}\n",
    ],
)
def test_credentials_require_one_literal_assignment(tmp_path: Path, assignment: str) -> None:
    env_file, _, _ = _fixture(tmp_path)
    env_file.write_text(assignment)
    with pytest.raises(ValueError, match="one literal"):
        capture._load_token(env_file)


def test_cli_failure_prints_neither_credential_nor_response_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env_file, output, _ = _fixture(tmp_path)

    def fail(**kwargs: object) -> dict[str, object]:
        raise ValueError(FAKE_TOKEN)

    monkeypatch.setattr(capture, "capture_personal_tiingo", fail)
    assert (
        capture.main(
            [
                "--env-file",
                str(env_file),
                "--output-dir",
                str(output),
                "--start-date",
                "2025-02-03",
                "--end-date",
                "2025-02-03",
                "--symbol",
                "SPY",
            ]
        )
        == 2
    )
    assert FAKE_TOKEN not in capsys.readouterr().err


def test_private_capture_rejects_repository_output_before_loading_credentials() -> None:
    from scripts import capture_personal_tiingo as module

    root = Path(module.__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="outside the checkout"):
        module.capture_personal_tiingo(
            env_file=Path("/unread-missing-credential-file"),
            output_dir=root / "private-capture-must-not-be-created",
            scope=TiingoEodScope(("SPY",), date(2025, 2, 3), date(2025, 2, 7)),
        )
