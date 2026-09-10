"""Bounded publication and argument checks without invoking provider access."""

import json
import os
import signal
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from apps.worker.personal_research import (
    _bounded_read,
    _calendar,
    _child_arguments,
    _make_inputs,
    _parser,
    _supervise,
    _write_report,
    main,
    report_json_value,
)


def test_existing_output_is_preserved(tmp_path, capsys):
    output = tmp_path / "report.json"
    output.write_text("existing result")
    assert main(["--fixture", "flat", "--output", str(output)]) == 2
    assert output.read_text() == "existing result"
    assert str(tmp_path) not in capsys.readouterr().out


@pytest.mark.parametrize(
    "option,value",
    [
        ("--max-seconds", "1801"),
        ("--max-memory-mib", "4097"),
        ("--max-output-mib", "1025"),
        ("--max-events", "100001"),
    ],
)
def test_resource_expansion_rejects_before_spawn(tmp_path, option, value):
    with pytest.raises(SystemExit) as error:
        main(["--fixture", "flat", "--output", str(tmp_path / "out"), option, value])
    assert error.value.code == 2


def test_artifact_publication_is_exact_decimal_private_and_no_clobber(tmp_path):
    @dataclass(frozen=True)
    class Value:
        amount: Decimal
        at: datetime

    output = tmp_path / "out.json"
    value = Value(Decimal("1234.567890123456789"), datetime(2025, 1, 1, tzinfo=UTC))
    _write_report(output, value, 1024)
    parsed = json.loads(output.read_bytes())
    assert parsed["amount"] == "1234.567890123456789"
    assert output.stat().st_mode & 0o777 == 0o600
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        _write_report(output, value, 1024)
    assert output.read_bytes() == before
    with pytest.raises(ValueError):
        report_json_value(float("nan"))


def test_oversized_artifact_leaves_no_partial_result(tmp_path):
    output = tmp_path / "out.json"
    with pytest.raises(ValueError, match="ceiling"):
        _write_report(output, ("x" * 100,), 16)
    assert not output.exists()


def test_input_size_and_symlink_are_rejected(tmp_path):
    source = tmp_path / "input"
    source.write_bytes(b"x" * 10)
    with pytest.raises(ValueError, match="byte limit"):
        _bounded_read(source, 9)
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="regular file"):
        _bounded_read(link, 10)
    args = _parser().parse_args(["--dataset", str(link), "--output", str(tmp_path / "out")])
    child = _child_arguments(args, tmp_path / "staged")
    forwarded = Path(child[child.index("--dataset") + 1])
    assert forwarded == link.absolute()
    with pytest.raises(ValueError, match="regular file"):
        _bounded_read(forwarded, 10)


@pytest.mark.parametrize("boundary", ["cancel", "deadline", "ordinary", "memory"])
def test_supervisor_never_publishes_completion_after_cancel_or_deadline(
    tmp_path, monkeypatch, capsys, boundary
):
    from apps.worker import personal_research as cli

    output = tmp_path / "result.json"
    args = _parser().parse_args(
        ["--fixture", "flat", "--output", str(output), "--max-seconds", "1"]
    )
    clock = [0.0]
    handlers = {}
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli.signal, "getsignal", lambda sig: None)
    monkeypatch.setattr(cli.signal, "signal", lambda sig, fn: handlers.__setitem__(sig, fn))
    monkeypatch.setattr(
        cli, "_resident_bytes", lambda pid: 5 * 1024**3 if boundary == "memory" else 1024
    )

    class Child:
        returncode = None
        pid = 123

        def __init__(self, command, **kwargs):
            self.staged = Path(command[command.index("--output") + 1])
            assert "--_expected-build-sha" in command
            assert set(kwargs["env"]) == {"PATH", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "TZ"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def wait(self, timeout):
            self.staged.write_text('{"status":"completed"}')
            if boundary == "cancel":
                handlers[signal.SIGTERM](signal.SIGTERM, None)
            if boundary == "deadline":
                clock[0] = 2.0
            self.returncode = 0

    monkeypatch.setattr(cli.subprocess, "Popen", Child)
    assert _supervise(args) == (0 if boundary == "ordinary" else 3)
    assert output.exists() == (boundary == "ordinary")
    response = json.loads(capsys.readouterr().out)
    assert response["artifact_written"] == (boundary == "ordinary")


def test_explicit_calendar_requires_complete_fields_and_ordered_unique_dates(tmp_path):
    path = tmp_path / "calendar.json"
    body = {
        "calendar_id": "explicit-synthetic",
        "version": "1",
        "timezone": "America/New_York",
        "business_dates": ["2025-01-02", "2025-01-03"],
    }
    path.write_text(json.dumps(body))
    assert len(_calendar(path).business_dates) == 2
    body["business_dates"] = ["2025-01-03", "2025-01-02"]
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="sorted"):
        _calendar(path)
    body["unreviewed"] = True
    path.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="fields"):
        _calendar(path)


def test_input_selection_and_configuration_are_bound_to_spec(tmp_path):
    parser = _parser()
    args = parser.parse_args(
        [
            "--fixture",
            "regime",
            "--fixture-sessions",
            "10",
            "--warmup",
            "3",
            "--strategy",
            "trend_sma",
            "--lookback",
            "3",
            "--max-events",
            "1000",
            "--max-seconds",
            "30",
            "--output",
            str(tmp_path / "out"),
        ]
    )
    inputs = _make_inputs(args)
    assert inputs.spec.strategy_configuration.kind == "trend_sma"
    assert inputs.spec.strategy_configuration.lookback == 3
    assert len(inputs.spec.evaluation.scored_sessions) == 7
    assert inputs.spec.max_events == 1000
    assert inputs.spec.max_cpu_cores == 1
    assert inputs.spec.max_wall_seconds == 30


def test_child_rejects_source_change_before_constructing_inputs(tmp_path, monkeypatch):
    from apps.worker import personal_research as cli

    with (tmp_path / "lock").open("w") as lock:
        args = _parser().parse_args(
            [
                "--fixture",
                "flat",
                "--output",
                str(tmp_path / "out"),
                "--_lock-fd",
                str(lock.fileno()),
                "--_parent-pid",
                str(os.getppid()),
                "--_expected-build-sha",
                "0" * 64,
            ]
        )
        monkeypatch.setattr(cli.resource, "setrlimit", lambda *args: None)
        monkeypatch.setattr(cli.signal, "signal", lambda *args: None)

        def unexpected(args):
            pytest.fail("source mismatch must reject before input construction")

        monkeypatch.setattr(cli, "_make_inputs", unexpected)
        with pytest.raises(ValueError, match="supervised source snapshot"):
            cli._child(args)


def test_guard_descriptor_is_available_only_while_held(tmp_path):
    from packages.application.personal_runtime import LocalInstanceGuard

    guard = LocalInstanceGuard(tmp_path / "instance.lock")
    with pytest.raises(RuntimeError, match="not held"):
        guard.fileno()
    with guard:
        assert os.fstat(guard.fileno()).st_uid == os.getuid()
    with pytest.raises(RuntimeError, match="not held"):
        guard.fileno()
