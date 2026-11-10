import json
import sys

import pytest

from apps.runtime_stub import run_stub


def test_local_stub_reports_not_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["stub", "--once"])
    monkeypatch.setenv("AQT_ENVIRONMENT", "local")

    run_stub("worker")

    assert json.loads(capsys.readouterr().out) == {
        "mode": "stub",
        "service": "worker",
        "status": "not_ready",
    }


@pytest.mark.parametrize("environment", ["paper", "live"])
def test_stub_fails_closed_outside_local(
    environment: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["stub", "--once"])
    monkeypatch.setenv("AQT_ENVIRONMENT", environment)
    monkeypatch.setenv("AQT_LOCAL_AUTH_ENABLED", "false")
    monkeypatch.setenv("AQT_SESSION_SECRET", "non-placeholder-secret")

    with pytest.raises(SystemExit) as raised:
        run_stub("trader")

    assert raised.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "stub"
    assert payload["status"] == "not_ready"
    assert "cannot run" in payload["reason"]
