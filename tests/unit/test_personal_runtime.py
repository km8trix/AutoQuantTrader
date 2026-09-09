import json
import os
import signal
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import TextIO

import pytest

from packages.adapters.standard_clock import StandardClock
from packages.application.personal_runtime import (
    ClockHealthSnapshot,
    ClockHealthStatus,
    DuplicateRuntimeError,
    LocalInstanceGuard,
    PersonalRuntimeConfig,
    run_personal_runtime,
)


@pytest.mark.parametrize("environment", ["production", "live", "paper", "sandbox", "local"])
def test_runtime_configuration_rejects_every_other_environment(
    environment: str, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="production is disabled"):
        PersonalRuntimeConfig(tmp_path / "instance.lock", environment=environment)


@pytest.mark.parametrize("interval", [0.0, -1.0, 10.01, float("nan"), float("inf"), True])
def test_runtime_configuration_requires_bounded_polling(interval: float, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="poll interval"):
        PersonalRuntimeConfig(tmp_path / "instance.lock", poll_interval_seconds=interval)


def test_runtime_configuration_requires_explicit_absolute_lock_path() -> None:
    with pytest.raises(ValueError, match="absolute"):
        PersonalRuntimeConfig(Path("relative.lock"))


def test_duplicate_guard_releases_on_close_without_unlinking(tmp_path: Path) -> None:
    path = tmp_path / "instance.lock"
    with LocalInstanceGuard(path), pytest.raises(DuplicateRuntimeError), LocalInstanceGuard(path):
        pass
    original_inode = path.stat().st_ino
    with LocalInstanceGuard(path):
        assert path.stat().st_ino == original_inode
    assert path.stat().st_mode & 0o777 == 0o600


def test_guard_rejects_symlink_and_nonprivate_lock(tmp_path: Path) -> None:
    real = tmp_path / "real.lock"
    real.touch(mode=0o600)
    link = tmp_path / "link.lock"
    link.symlink_to(real)
    with pytest.raises(OSError), LocalInstanceGuard(link):
        pass
    real.chmod(0o644)
    with pytest.raises(ValueError, match="private"), LocalInstanceGuard(real):
        pass


def test_once_reports_halted_then_stop_without_claiming_no_broker_exposure(tmp_path: Path) -> None:
    events: list[dict[str, object]] = []
    config = PersonalRuntimeConfig(tmp_path / "instance.lock", poll_interval_seconds=0.01)
    result = run_personal_runtime(
        config, clock=StandardClock(simulated_health=True), emit=events.append, once=True
    )
    assert result == 0
    assert events[0]["status"] == "HALTED"
    assert events[-1]["status"] == "STOPPED"
    assert all(event["live_enabled"] is False for event in events)
    assert all(event["order_authority"] is False for event in events)
    assert all(event["broker_exposure"] == "unknown" for event in events)
    assert all(event["status"] != "RUNNING" for event in events)
    assert any("simulated" in json.dumps(event) for event in events)


class BrokenClock:
    def now(self) -> datetime:
        raise RuntimeError("unavailable UTC")

    def monotonic_ns(self) -> int:
        raise RuntimeError("unavailable monotonic")

    def health_snapshot(self) -> ClockHealthSnapshot:
        raise RuntimeError("private state must not appear")


def test_stop_survives_clock_failure_and_restores_signal_handlers(tmp_path: Path) -> None:
    events: list[dict[str, object]] = []
    before = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    run_personal_runtime(
        PersonalRuntimeConfig(tmp_path / "instance.lock"),
        clock=BrokenClock(),
        emit=events.append,
        once=True,
    )
    assert events[-1]["status"] == "STOPPED"
    assert events[-1]["broker_exposure"] == "unknown"
    assert "clock_unavailable" in json.dumps(events)
    assert "private state" not in json.dumps(events)
    assert before == (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))


def test_stop_does_not_wait_for_a_stuck_clock_source(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    stop = threading.Event()
    finished = threading.Event()
    events: list[dict[str, object]] = []

    class StuckClock(BrokenClock):
        def health_snapshot(self) -> ClockHealthSnapshot:
            entered.set()
            release.wait(timeout=5)
            return ClockHealthSnapshot(ClockHealthStatus.BLOCKED, ("source_unavailable",))

    def run() -> None:
        try:
            run_personal_runtime(
                PersonalRuntimeConfig(tmp_path / "instance.lock"),
                clock=StuckClock(),
                emit=events.append,
                stop_event=stop,
            )
        finally:
            finished.set()

    runner = threading.Thread(target=run)
    runner.start()
    try:
        assert entered.wait(timeout=2)
        stop.set()
        assert finished.wait(timeout=1)
        assert events[-1]["status"] == "STOPPED"
        assert events[-1]["broker_exposure"] == "unknown"
    finally:
        release.set()
        runner.join(timeout=2)


def test_previously_healthy_clock_cannot_remain_healthy_when_sampler_stalls(tmp_path: Path) -> None:
    stalled = threading.Event()
    release = threading.Event()
    stop = threading.Event()
    healthy_reported = threading.Event()
    stale_reported = threading.Event()
    boundary_read = threading.Event()
    watchdog_time = [0]
    events: list[dict[str, object]] = []

    class EventuallyStuckClock(BrokenClock):
        def __init__(self) -> None:
            self.calls = 0

        def health_snapshot(self) -> ClockHealthSnapshot:
            self.calls += 1
            if self.calls > 1:
                stalled.set()
                release.wait(timeout=5)
            return ClockHealthSnapshot(
                ClockHealthStatus.HEALTHY, ("within_limit",), recovery_ready=True
            )

    def watch() -> int:
        if watchdog_time[0] == 29_999_999_999:
            boundary_read.set()
        return watchdog_time[0]

    def capture(event: dict[str, object]) -> None:
        events.append(event)
        health = event["clock_health"]
        assert isinstance(health, dict)
        if health["status"] == "healthy":
            healthy_reported.set()
        if "clock_sampler_stale" in health["reasons"]:
            stale_reported.set()

    runner = threading.Thread(
        target=run_personal_runtime,
        args=(PersonalRuntimeConfig(tmp_path / "instance.lock", poll_interval_seconds=0.01),),
        kwargs={
            "clock": EventuallyStuckClock(),
            "emit": capture,
            "stop_event": stop,
            "watchdog_monotonic_ns": watch,
        },
    )
    runner.start()
    try:
        assert healthy_reported.wait(timeout=2)
        assert stalled.wait(timeout=2)
        watchdog_time[0] = 29_999_999_999
        assert boundary_read.wait(timeout=2)
        assert not stale_reported.is_set()
        watchdog_time[0] = 30_000_000_000
        assert stale_reported.wait(timeout=2)
        stop.set()
        runner.join(timeout=1)
        assert not runner.is_alive()
        health = events[-1]["clock_health"]
        assert isinstance(health, dict)
        assert health["status"] == "blocked"
        assert health["recovery_ready"] is False
        assert events[-1]["broker_exposure"] == "unknown"
    finally:
        stop.set()
        release.set()
        runner.join(timeout=2)


@pytest.mark.parametrize("failure", ["regression", "exception"])
def test_watchdog_failure_is_blocked_and_does_not_prevent_stop(
    failure: str, tmp_path: Path
) -> None:
    events: list[dict[str, object]] = []
    stop = threading.Event()
    readings = iter([100, 99])

    def watch() -> int:
        if failure == "exception":
            raise RuntimeError("private watchdog detail")
        return next(readings)

    def capture(event: dict[str, object]) -> None:
        events.append(event)
        if "watchdog_" in json.dumps(event):
            stop.set()

    run_personal_runtime(
        PersonalRuntimeConfig(tmp_path / "instance.lock", poll_interval_seconds=0.01),
        clock=StandardClock(simulated_health=True),
        stop_event=stop,
        emit=capture,
        watchdog_monotonic_ns=watch,
    )
    reason = "watchdog_regression" if failure == "regression" else "watchdog_unavailable"
    assert reason in json.dumps(events[-1])
    assert "private watchdog detail" not in json.dumps(events)
    assert events[-1]["status"] == "STOPPED"


PROCESS_CODE = """
import sys
from pathlib import Path
from packages.adapters.standard_clock import StandardClock
from packages.application.personal_runtime import PersonalRuntimeConfig, run_personal_runtime
class UnavailableClock(StandardClock):
    def health_snapshot(self):
        raise RuntimeError('clock and data unavailable')
clock = UnavailableClock() if sys.argv[2] == 'fault' else StandardClock(simulated_health=True)
run_personal_runtime(PersonalRuntimeConfig(Path(sys.argv[1]), poll_interval_seconds=0.01),
                     clock=clock)
"""


def _collect_lines(output: TextIO, lines: Queue[str]) -> None:
    for line in output:
        lines.put(line)


@pytest.mark.parametrize("mode", ["simulation", "fault"])
@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
def test_real_process_start_duplicate_exclusion_stop_and_halted_restart(
    mode: str, stop_signal: int, tmp_path: Path
) -> None:
    root = Path(__file__).resolve().parents[2]
    lock_path = tmp_path / "process.lock"
    command = [sys.executable, "-B", "-c", PROCESS_CODE, str(lock_path), mode]
    environment = {"PATH": os.defpath, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    for attempt in range(2):
        process = subprocess.Popen(
            command,
            cwd=tmp_path,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        lines: Queue[str] = Queue()
        assert process.stdout is not None

        reader = threading.Thread(target=_collect_lines, args=(process.stdout, lines), daemon=True)
        reader.start()
        try:
            started = json.loads(lines.get(timeout=5))
            assert started["event"] == "started"
            assert started["status"] == "HALTED"
            sampled = json.loads(lines.get(timeout=5))
            assert sampled["clock_health"]["status"] == "blocked"
            if mode == "fault":
                assert sampled["clock_health"]["reasons"] == ["clock_unavailable"]
            else:
                assert sampled["clock_health"]["evidence_class"] == "simulated"
            if attempt == 0:
                duplicate = subprocess.run(
                    command,
                    cwd=tmp_path,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                assert duplicate.returncode != 0
                assert "already running" in duplicate.stderr
                assert not duplicate.stdout
            process.send_signal(stop_signal)
            assert process.wait(timeout=3) == 0
            reader.join(timeout=1)
            stopped = json.loads(lines.get(timeout=1))
            assert stopped["event"] == "stopped"
            assert stopped["status"] == "STOPPED"
            assert stopped["broker_exposure"] == "unknown"
            assert stopped["order_authority"] is False
            assert process.stderr is not None
            assert process.stderr.read() == ""
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            process.stdout.close()
            assert process.stderr is not None
            process.stderr.close()


def test_guard_can_restart_after_confirmed_crash(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    path = tmp_path / "crash.lock"
    command = [sys.executable, "-B", "-c", PROCESS_CODE, str(path), "simulation"]
    environment = {"PATH": os.defpath, "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1"}
    process = subprocess.Popen(
        command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert process.stdout is not None
    lines: Queue[str] = Queue()
    reader = threading.Thread(target=_collect_lines, args=(process.stdout, lines), daemon=True)
    reader.start()
    try:
        assert json.loads(lines.get(timeout=5))["event"] == "started"
        process.kill()
        assert process.wait(timeout=3) != 0
        with LocalInstanceGuard(path):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        reader.join(timeout=1)
        process.stdout.close()
        assert process.stderr is not None
        process.stderr.close()
