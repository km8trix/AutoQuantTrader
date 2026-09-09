"""Ordinary, halted local simulation process; no account or order authority.

The file lock excludes cooperating processes using the same local lock path. It
is not an account lease or a broker fence. Those durable controls belong to W4.
"""

from __future__ import annotations

import fcntl
import json
import math
import os
import signal
import stat
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from queue import Empty, Queue
from typing import Protocol


class ClockHealthStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class ClockHealthSnapshot:
    status: ClockHealthStatus
    reasons: tuple[str, ...]
    evidence_class: str = "unavailable"
    source_id: str | None = None
    observed_at_utc: datetime | None = None
    observed_monotonic_ns: int | None = None
    source_observed_at_utc: datetime | None = None
    source_observed_monotonic_ns: int | None = None
    epoch: str | None = None
    sequence: int = 0
    offset_ns: int | None = None
    uncertainty_ns: int | None = None
    sampling_duration_ns: int | None = None
    sample_age_ns: int | None = None
    recovery_ready: bool = False
    rearm_required: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "reasons": list(self.reasons),
            "evidence_class": self.evidence_class,
            "source_id": self.source_id,
            "observed_at_utc": (
                self.observed_at_utc.isoformat() if self.observed_at_utc is not None else None
            ),
            "observed_monotonic_ns": self.observed_monotonic_ns,
            "source_observed_at_utc": (
                self.source_observed_at_utc.isoformat()
                if self.source_observed_at_utc is not None
                else None
            ),
            "source_observed_monotonic_ns": self.source_observed_monotonic_ns,
            "epoch": self.epoch,
            "sequence": self.sequence,
            "offset_ns": self.offset_ns,
            "uncertainty_ns": self.uncertainty_ns,
            "sampling_duration_ns": self.sampling_duration_ns,
            "sample_age_ns": self.sample_age_ns,
            "recovery_ready": self.recovery_ready,
            "rearm_required": self.rearm_required,
        }


class RuntimeClock(Protocol):
    def now(self) -> datetime: ...

    def monotonic_ns(self) -> int: ...

    def health_snapshot(self) -> ClockHealthSnapshot: ...


@dataclass(frozen=True, slots=True)
class PersonalRuntimeConfig:
    instance_lock_path: Path
    environment: str = "personal-simulation"
    poll_interval_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.environment != "personal-simulation":
            raise ValueError("only personal-simulation is supported; production is disabled")
        if (
            not isinstance(self.instance_lock_path, Path)
            or not self.instance_lock_path.is_absolute()
        ):
            raise ValueError("instance lock path must be an explicit absolute path")
        if (
            type(self.poll_interval_seconds) not in (int, float)
            or not math.isfinite(self.poll_interval_seconds)
            or not 0 < self.poll_interval_seconds <= 10
        ):
            raise ValueError("poll interval must be greater than zero and at most 10 seconds")


class DuplicateRuntimeError(RuntimeError):
    """The selected simulation instance is already running."""


class LocalInstanceGuard:
    """Hold a POSIX advisory lock until process exit, without PID-based takeover.

    The parent directory must already exist and be controlled by the owner. The
    persistent lock file is never unlinked: unlinking can split lock ownership.
    Kernel release on process exit permits a fresh, halted restart.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def __enter__(self) -> LocalInstanceGuard:
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError("instance lock must be an owner-controlled regular file")
            if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError("instance lock must be private and have one filesystem link")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DuplicateRuntimeError(
                    "personal simulation instance already running"
                ) from None
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def __exit__(self, *_: object) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None


def _print_event(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def run_personal_runtime(
    config: PersonalRuntimeConfig,
    *,
    clock: RuntimeClock,
    stop_event: threading.Event | None = None,
    emit: Callable[[dict[str, object]], None] = _print_event,
    once: bool = False,
    watchdog_monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> int:
    """Run the W1 lifecycle foundation, remaining HALTED throughout.

    Sampling runs in a daemon so even a stuck injected health source cannot hold
    shutdown hostage. Stop uses cached status and never requests clock, data,
    database or broker state. Residual broker exposure is therefore unknown.
    """
    stopped = stop_event if stop_event is not None else threading.Event()
    sample_stop = threading.Event()
    samples: Queue[ClockHealthSnapshot] = Queue(maxsize=1)
    latest = ClockHealthSnapshot(ClockHealthStatus.BLOCKED, ("startup_no_sample",))
    previous_handlers: dict[signal.Signals, object] = {}
    runtime_faults: set[str] = set()
    previous_watchdog: int | None = None
    received_at: int | None = None

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stopped.set()

    def sample_clock() -> None:
        while not sample_stop.is_set():
            try:
                snapshot = clock.health_snapshot()
                if type(snapshot) is not ClockHealthSnapshot:
                    raise TypeError("invalid clock snapshot")
            except Exception:
                snapshot = ClockHealthSnapshot(ClockHealthStatus.BLOCKED, ("clock_unavailable",))
            if sample_stop.is_set():
                return
            # This is the sole producer; dropping a cached sample never blocks stop.
            if samples.full():
                with suppress(Empty):
                    samples.get_nowait()
            samples.put_nowait(snapshot)
            if sample_stop.wait(config.poll_interval_seconds):
                return

    def report(event: str) -> None:
        emit(
            {
                "event": event,
                "environment": config.environment,
                "mode": "personal-simulation-foundation",
                "status": "STOPPED" if event == "stopped" else "HALTED",
                "live_enabled": False,
                "order_authority": False,
                "clock_health": latest.as_dict(),
                "broker_exposure": "unknown",
                "broker_exposure_reason": (
                    "broker state was not read; orders or positions may remain"
                ),
            }
        )

    with LocalInstanceGuard(config.instance_lock_path):
        try:
            if threading.current_thread() is threading.main_thread():
                for signum in (signal.SIGINT, signal.SIGTERM):
                    previous_handlers[signum] = signal.getsignal(signum)
                    signal.signal(signum, request_stop)
            report("started")
            sampler = threading.Thread(target=sample_clock, name="simulation-clock", daemon=True)
            sampler.start()
            while not stopped.is_set():
                snapshot = None
                with suppress(Empty):
                    snapshot = samples.get(timeout=min(config.poll_interval_seconds, 0.1))
                # Independently age receipts even if the injected clock thread stalls.
                try:
                    watchdog_now = watchdog_monotonic_ns()
                    if type(watchdog_now) is not int or watchdog_now < 0:
                        raise ValueError("invalid watchdog clock")
                    if previous_watchdog is not None and watchdog_now < previous_watchdog:
                        runtime_faults.add("watchdog_regression")
                    if received_at is not None and watchdog_now - received_at >= 30_000_000_000:
                        runtime_faults.add("clock_sampler_stale")
                    previous_watchdog = watchdog_now
                    if received_at is None or snapshot is not None:
                        received_at = watchdog_now
                except Exception:
                    runtime_faults.add("watchdog_unavailable")
                snapshot = latest if snapshot is None else snapshot
                if runtime_faults:
                    snapshot = replace(
                        snapshot,
                        status=ClockHealthStatus.BLOCKED,
                        reasons=tuple(sorted(set(snapshot.reasons) | runtime_faults)),
                        recovery_ready=False,
                        rearm_required=True,
                    )
                changed = (snapshot.status, snapshot.reasons, snapshot.recovery_ready) != (
                    latest.status,
                    latest.reasons,
                    latest.recovery_ready,
                )
                latest = snapshot
                if changed:
                    report("clock_health")
                if once:
                    break
        finally:
            sample_stop.set()
            # No join: external health producers must not delay local process stop.
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)  # type: ignore[arg-type]
            report("stopped")
    return 0
