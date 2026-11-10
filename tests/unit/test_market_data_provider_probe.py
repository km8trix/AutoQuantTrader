import json
from datetime import date
from pathlib import Path

import pytest

from packages.adapters.market_data.provider_probe import (
    ProbeAccess,
    ProbeNetworkError,
    ProbeProvider,
    ProbeRequest,
    ProbeResponse,
    probe_provider,
)
from scripts.probe_market_data_access import _load_environment

SESSION_DATE = date(2026, 7, 14)


def test_missing_credential_does_not_call_transport() -> None:
    def forbidden_transport(
        request: ProbeRequest,
        *,
        timeout_seconds: float,
    ) -> ProbeResponse:
        raise AssertionError((request, timeout_seconds))

    result = probe_provider(
        ProbeProvider.MASSIVE_TRADES,
        environ={},
        symbol="SPY",
        session_date=SESSION_DATE,
        transport=forbidden_transport,
    )

    assert result.access is ProbeAccess.NOT_CONFIGURED
    assert not result.configured
    assert result.http_status is None


@pytest.mark.parametrize(
    ("provider", "variable", "payload", "authorization"),
    [
        (
            ProbeProvider.MASSIVE_TRADES,
            "MASSIVE_API_KEY",
            b'{"results":[{"t":1}]}',
            "Bearer top-secret",
        ),
        (
            ProbeProvider.MASSIVE_QUOTES,
            "MASSIVE_API_KEY",
            b'{"results":[{"sip_timestamp":1}]}',
            "Bearer top-secret",
        ),
        (
            ProbeProvider.SHARADAR_SFP,
            "NASDAQ_DATA_LINK_API_KEY",
            b'{"datatable":{"data":[["SPY"]]}}',
            None,
        ),
        (
            ProbeProvider.TIINGO,
            "TIINGO_TOKEN",
            b'[{"date":"2026-07-14"}]',
            "Token top-secret",
        ),
    ],
)
def test_success_is_sanitized_and_counts_records(
    provider: ProbeProvider,
    variable: str,
    payload: bytes,
    authorization: str | None,
) -> None:
    captured: list[ProbeRequest] = []

    def transport(request: ProbeRequest, *, timeout_seconds: float) -> ProbeResponse:
        captured.append(request)
        assert timeout_seconds == 8.0
        return ProbeResponse(status=200, payload=payload)

    result = probe_provider(
        provider,
        environ={variable: "top-secret"},
        symbol="SPY",
        session_date=SESSION_DATE,
        transport=transport,
    )

    assert result.access is ProbeAccess.ACCESSIBLE
    assert result.record_count == 1
    assert result.to_dict()["admission_effect"] == "none"
    request = captured[0]
    assert repr(request) == f"ProbeRequest(provider={provider.value!r}, redacted=True)"
    assert request.headers.get("Authorization") == authorization
    if provider is ProbeProvider.SHARADAR_SFP:
        assert "api_key=top-secret" in request.url
    serialized = json.dumps(result.to_dict())
    assert "top-secret" not in serialized
    assert "api_key" not in serialized


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (401, ProbeAccess.UNAUTHORIZED),
        (403, ProbeAccess.NOT_ENTITLED),
        (429, ProbeAccess.RATE_LIMITED),
        (503, ProbeAccess.REMOTE_ERROR),
    ],
)
def test_http_failures_are_classified_without_body(status: int, expected: ProbeAccess) -> None:
    def transport(request: ProbeRequest, *, timeout_seconds: float) -> ProbeResponse:
        return ProbeResponse(status=status, payload=b'{"secret":"response detail"}')

    result = probe_provider(
        ProbeProvider.TIINGO,
        environ={"TIINGO_TOKEN": "top-secret"},
        symbol="SPY",
        session_date=SESSION_DATE,
        transport=transport,
    )

    assert result.access is expected
    assert result.http_status == status
    assert "response detail" not in json.dumps(result.to_dict())


def test_success_with_no_rows_is_still_distinct_from_admission() -> None:
    def transport(request: ProbeRequest, *, timeout_seconds: float) -> ProbeResponse:
        return ProbeResponse(status=200, payload=b'{"results":[]}')

    result = probe_provider(
        ProbeProvider.MASSIVE_TRADES,
        environ={"MASSIVE_API_KEY": "top-secret"},
        symbol="SPY",
        session_date=SESSION_DATE,
        transport=transport,
    )

    assert result.access is ProbeAccess.ACCESSIBLE_NO_DATA
    assert result.record_count == 0
    assert result.to_dict()["admission_effect"] == "none"


def test_invalid_success_payload_is_sanitized() -> None:
    def transport(request: ProbeRequest, *, timeout_seconds: float) -> ProbeResponse:
        return ProbeResponse(status=200, payload=b"not-json top-secret")

    result = probe_provider(
        ProbeProvider.MASSIVE_TRADES,
        environ={"MASSIVE_API_KEY": "top-secret"},
        symbol="SPY",
        session_date=SESSION_DATE,
        transport=transport,
    )

    assert result.access is ProbeAccess.INVALID_RESPONSE
    assert "top-secret" not in json.dumps(result.to_dict())


def test_network_failure_is_sanitized() -> None:
    def transport(request: ProbeRequest, *, timeout_seconds: float) -> ProbeResponse:
        raise ProbeNetworkError(f"failed with {request.url}")

    result = probe_provider(
        ProbeProvider.TIINGO,
        environ={"TIINGO_TOKEN": "top-secret"},
        symbol="SPY",
        session_date=SESSION_DATE,
        transport=transport,
    )

    assert result.access is ProbeAccess.NETWORK_ERROR
    assert "top-secret" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("symbol", ["spy", "SPY/../../", "", "SPY Q"])
def test_symbol_validation_happens_before_transport(symbol: str) -> None:
    with pytest.raises(ValueError, match="canonical uppercase"):
        probe_provider(
            ProbeProvider.MASSIVE_TRADES,
            environ={"MASSIVE_API_KEY": "top-secret"},
            symbol=symbol,
            session_date=SESSION_DATE,
        )


@pytest.mark.parametrize("timeout", [0, -1, 31])
def test_timeout_is_bounded(timeout: float) -> None:
    with pytest.raises(ValueError, match="at most 30"):
        probe_provider(
            ProbeProvider.MASSIVE_TRADES,
            environ={"MASSIVE_API_KEY": "top-secret"},
            symbol="SPY",
            session_date=SESSION_DATE,
            timeout_seconds=timeout,
        )


def test_env_file_preserves_literal_values_and_loads_only_probe_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TIINGO_TOKEN", raising=False)
    monkeypatch.delenv("UNRELATED_SECRET", raising=False)
    path = tmp_path / ".env"
    literal = "$" + "{NOT_EXPANDED}$literal"
    path.write_text(
        "TIINGO_TOKEN=" + literal + "\nUNRELATED_SECRET=do-not-load\n",
        encoding="utf-8",
    )
    path.chmod(0o600)

    environment = _load_environment(path)

    assert environment["TIINGO_TOKEN"] == literal
    assert "UNRELATED_SECRET" not in environment


def test_explicit_env_file_does_not_fall_back_to_process_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MASSIVE_API_KEY", "process-value")
    path = tmp_path / ".env"
    path.write_text("TIINGO_TOKEN=file-value\n", encoding="utf-8")
    path.chmod(0o600)

    environment = _load_environment(path)

    assert environment == {"TIINGO_TOKEN": "file-value"}


def test_env_file_rejects_bare_probe_key(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("TIINGO_TOKEN\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(ValueError, match="explicit value"):
        _load_environment(path)


def test_env_file_rejects_group_or_other_access(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("TIINGO_TOKEN=value\n", encoding="utf-8")
    path.chmod(0o644)

    with pytest.raises(ValueError, match="chmod 600"):
        _load_environment(path)


def test_env_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "credentials"
    target.write_text("TIINGO_TOKEN=value\n", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / ".env"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="non-symlinked"):
        _load_environment(link)
