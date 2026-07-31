"""Process-isolated execution of one bounded strategy invocation."""

from __future__ import annotations

import hashlib
import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import IO

from packages.domain.canonical import canonical_json_bytes
from packages.domain.market_batch import MarketBatch
from packages.domain.strategy_invocation_lifecycle import (
    StrategyInvocationStartAuthorization,
)
from packages.domain.strategy_supervision import (
    MAX_STRATEGY_STDERR_BYTES,
    MAX_STRATEGY_STDOUT_BYTES,
    STRATEGY_DECISION_DEADLINE_MICROSECONDS,
    STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS,
    STRATEGY_SUPERVISION_CONTRACT_VERSION,
    StrategyInvocation,
    StrategyProtocolError,
    StrategyProtocolResponse,
    StrategyResourceExceeded,
    StrategyRuntimeBinding,
    StrategySupervisionError,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
    decode_strategy_response,
    encode_strategy_request,
)

STRATEGY_SUBPROCESS_POLL_SECONDS = 0.01
MAX_STRATEGY_ARGV_ITEMS = 64
MAX_STRATEGY_ARGV_ITEM_BYTES = 4_096
MAX_STRATEGY_ARGV_BYTES = 16_384

STRATEGY_SUBPROCESS_ENVIRONMENT = (
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PYTHONHASHSEED", "0"),
    ("PYTHONIOENCODING", "utf-8"),
    ("PYTHONUTF8", "1"),
    ("TZ", "UTC"),
)

MonotonicClock = Callable[[], float]
UtcClock = Callable[[], datetime]
Sleeper = Callable[[float], None]


class StrategySubprocessError(StrategySupervisionError):
    """The local supervisor or its injected trusted clocks are invalid."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def strategy_launch_spec_sha256(argv: tuple[str, ...]) -> str:
    """Authenticate the exact argv and fixed environment policy."""

    _validate_argv(argv)
    return _sha256(
        (
            STRATEGY_SUPERVISION_CONTRACT_VERSION,
            "subprocess_launch",
            argv,
            STRATEGY_SUBPROCESS_ENVIRONMENT,
            "shell_false",
            "close_fds_true",
            "start_new_session_true",
            "stdin_stdout_stderr_pipes",
        )
    )


def _validate_argv(argv: tuple[str, ...]) -> None:
    if type(argv) is not tuple or not argv:
        raise StrategySubprocessError("strategy subprocess argv must be a non-empty tuple")
    if len(argv) > MAX_STRATEGY_ARGV_ITEMS:
        raise StrategySubprocessError("strategy subprocess argv has too many items")
    total_bytes = 0
    for item in argv:
        if type(item) is not str or not item or "\x00" in item:
            raise StrategySubprocessError(
                "strategy subprocess argv items must be non-empty NUL-free strings"
            )
        encoded_length = len(item.encode("utf-8"))
        if encoded_length > MAX_STRATEGY_ARGV_ITEM_BYTES:
            raise StrategySubprocessError("strategy subprocess argv item is too large")
        total_bytes += encoded_length
    if total_bytes > MAX_STRATEGY_ARGV_BYTES:
        raise StrategySubprocessError("strategy subprocess argv is too large")
    if not os.path.isabs(argv[0]):
        raise StrategySubprocessError("strategy subprocess executable must use an absolute path")


@dataclass(frozen=True, slots=True)
class StrategySubprocessSpec:
    """A no-shell launch description with no caller-controlled environment."""

    argv: tuple[str, ...]
    runtime_id: str
    runtime_version: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        _validate_argv(self.argv)
        # The domain binding performs the canonical text/digest validation.
        _ = self.runtime_binding

    @property
    def launch_spec_sha256(self) -> str:
        return strategy_launch_spec_sha256(self.argv)

    @property
    def runtime_binding(self) -> StrategyRuntimeBinding:
        return StrategyRuntimeBinding(
            runtime_id=self.runtime_id,
            runtime_version=self.runtime_version,
            artifact_sha256=self.artifact_sha256,
            launch_spec_sha256=self.launch_spec_sha256,
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_utc(clock: UtcClock, field_name: str) -> datetime:
    value = clock()
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise StrategySubprocessError(f"{field_name} must return a timezone-aware datetime")
    if value.utcoffset() != UTC.utcoffset(value):
        raise StrategySubprocessError(f"{field_name} must return UTC")
    return value


def _read_monotonic(clock: MonotonicClock, previous: float | None = None) -> float:
    raw_value = clock()
    if type(raw_value) not in {int, float}:
        raise StrategySubprocessError("monotonic clock must return a finite number")
    value = float(raw_value)
    if not math.isfinite(value):
        raise StrategySubprocessError("monotonic clock must return a finite number")
    if previous is not None and value < previous:
        raise StrategySubprocessError("monotonic clock moved backwards")
    return value


def _elapsed_microseconds(started: float, completed: float) -> int:
    return max(0, int((completed - started) * 1_000_000))


@dataclass(slots=True)
class _BoundedPipeCapture:
    limit: int
    value: bytearray = field(default_factory=bytearray)
    exceeded: threading.Event = field(default_factory=threading.Event)
    failed: threading.Event = field(default_factory=threading.Event)

    def read(self, stream: IO[bytes]) -> None:
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    return
                remaining = self.limit + 1 - len(self.value)
                if remaining > 0:
                    self.value.extend(chunk[:remaining])
                if len(self.value) > self.limit:
                    self.exceeded.set()
                    return
        except (OSError, ValueError):
            self.failed.set()
        finally:
            try:
                stream.close()
            except OSError:
                self.failed.set()


def _write_request(
    stream: IO[bytes],
    request: bytes,
    failed: threading.Event,
) -> None:
    try:
        stream.write(request)
        stream.flush()
    except BrokenPipeError:
        # The child exit classification is more useful than a secondary pipe error.
        pass
    except (OSError, ValueError):
        failed.set()
    finally:
        try:
            stream.close()
        except OSError:
            failed.set()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError:
        with suppress(ProcessLookupError):
            process.kill()


def _finish_process(
    process: subprocess.Popen[bytes],
    threads: tuple[threading.Thread, ...],
    *,
    kill: bool,
    cleanup_deadline: float,
    monotonic_clock: MonotonicClock | None = None,
) -> None:
    cleanup_clock = time.monotonic if monotonic_clock is None else monotonic_clock
    cleanup_started = _read_monotonic(cleanup_clock)
    if type(cleanup_deadline) not in {int, float} or not math.isfinite(float(cleanup_deadline)):
        raise StrategySubprocessError("strategy subprocess cleanup deadline must be finite")
    cleanup_deadline = float(cleanup_deadline)
    last_cleanup_read = cleanup_started

    def remaining_cleanup_seconds() -> float:
        nonlocal last_cleanup_read
        current = _read_monotonic(cleanup_clock, last_cleanup_read)
        last_cleanup_read = current
        return max(0.0, cleanup_deadline - current)

    if kill:
        _kill_process_group(process)
    termination_error: subprocess.TimeoutExpired | None = None
    remaining = remaining_cleanup_seconds()
    if remaining <= 0:
        raise StrategySubprocessError("strategy subprocess cleanup deadline expired")
    try:
        process.wait(timeout=min(1.0, remaining))
    except subprocess.TimeoutExpired as first_error:
        _kill_process_group(process)
        remaining = remaining_cleanup_seconds()
        if remaining <= 0:
            termination_error = first_error
        else:
            try:
                process.wait(timeout=min(1.0, remaining))
            except subprocess.TimeoutExpired as second_error:
                termination_error = second_error
    for thread in threads:
        remaining = remaining_cleanup_seconds()
        if remaining <= 0:
            break
        thread.join(timeout=remaining)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            with suppress(OSError):
                stream.close()
    for thread in threads:
        if not thread.is_alive():
            continue
        remaining = remaining_cleanup_seconds()
        if remaining <= 0:
            break
        thread.join(timeout=remaining)
    if termination_error is not None:
        raise StrategySubprocessError(
            "strategy subprocess could not be terminated within the cleanup deadline"
        ) from termination_error
    if any(thread.is_alive() for thread in threads):
        raise StrategySubprocessError(
            "strategy subprocess pipe cleanup exceeded the cleanup deadline"
        )
    completed_cleanup = _read_monotonic(cleanup_clock, last_cleanup_read)
    if completed_cleanup > cleanup_deadline:
        raise StrategySubprocessError("strategy subprocess cleanup exceeded the cleanup deadline")


def _result(
    *,
    invocation: StrategyInvocation,
    outcome: StrategySupervisionOutcome,
    started_at: datetime,
    completed_at: datetime,
    elapsed_microseconds: int,
    process_started: bool,
    exit_code: int | None,
    stdout: bytes,
    stderr: bytes,
    detail_code: str,
    response: StrategyProtocolResponse | None = None,
) -> StrategySupervisionResult:
    return StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        elapsed_microseconds=elapsed_microseconds,
        process_started=process_started,
        exit_code=exit_code,
        stdout_bytes=len(stdout),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_bytes=len(stderr),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        detail_code=detail_code,
        response=response,
    )


def run_supervised_strategy(
    *,
    invocation: StrategyInvocation,
    market_batch: MarketBatch,
    subprocess_spec: StrategySubprocessSpec,
    start_authorization: StrategyInvocationStartAuthorization,
    monotonic_clock: MonotonicClock = time.monotonic,
    utc_clock: UtcClock = _utc_now,
    sleeper: Sleeper = time.sleep,
) -> StrategySupervisionResult:
    """Run one child and return bounded evidence without touching other loops.

    The child receives only the canonical request on stdin and the fixed
    sanitized environment.  Failure kills only this new process group.  This
    function has no order, risk, broker-event, cancel, reconciliation, control
    mutation, or re-arm port.
    """

    if type(invocation) is not StrategyInvocation:
        raise StrategySubprocessError("supervisor requires an exact invocation")
    if type(subprocess_spec) is not StrategySubprocessSpec:
        raise StrategySubprocessError("supervisor requires an exact subprocess spec")
    if type(start_authorization) is not StrategyInvocationStartAuthorization:
        raise StrategySubprocessError("supervisor requires an exact strategy start authorization")
    start_authorization.__post_init__()
    if start_authorization.claim.invocation != invocation:
        raise StrategySubprocessError("strategy start authorization belongs to another invocation")
    # Consume before batch/runtime validation, request encoding, clock reads, or
    # process creation. Any subsequent failure safely sacrifices this one start.
    start_authorization.consume_for_runner_start()
    invocation.require_batch(market_batch)
    invocation.require_runtime(subprocess_spec.runtime_binding)

    try:
        request = encode_strategy_request(invocation, market_batch)
    except StrategyResourceExceeded:
        completed_monotonic = _read_monotonic(monotonic_clock)
        completed_at = _read_utc(utc_clock, "strategy UTC clock")
        start_authorization.require_start_at(completed_at)
        return _result(
            invocation=invocation,
            outcome=StrategySupervisionOutcome.RESOURCE_EXCEEDED,
            started_at=completed_at,
            completed_at=completed_at,
            elapsed_microseconds=_elapsed_microseconds(
                completed_monotonic,
                completed_monotonic,
            ),
            process_started=False,
            exit_code=None,
            stdout=b"",
            stderr=b"",
            detail_code="request_too_large",
        )

    environment = dict(STRATEGY_SUBPROCESS_ENVIRONMENT)
    started_monotonic = _read_monotonic(monotonic_clock)
    cleanup_deadline = started_monotonic + (
        (STRATEGY_DECISION_DEADLINE_MICROSECONDS + STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS)
        / 1_000_000
    )
    last_monotonic = started_monotonic
    started_at = _read_utc(utc_clock, "strategy UTC clock")
    # This check deliberately sits at the final trusted boundary before Popen
    # so bounded request preparation cannot silently consume the durable
    # claim's execution window.
    start_authorization.require_start_at(started_at)
    try:
        process = subprocess.Popen(
            subprocess_spec.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
            env=environment,
            bufsize=0,
        )
    except OSError:
        completed_monotonic = _read_monotonic(monotonic_clock, last_monotonic)
        completed_at = _read_utc(utc_clock, "strategy UTC clock")
        return _result(
            invocation=invocation,
            outcome=StrategySupervisionOutcome.CRASH,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_microseconds=_elapsed_microseconds(started_monotonic, completed_monotonic),
            process_started=False,
            exit_code=None,
            stdout=b"",
            stderr=b"",
            detail_code="spawn_failed",
        )

    if process.stdin is None or process.stdout is None or process.stderr is None:
        _finish_process(
            process,
            (),
            kill=True,
            cleanup_deadline=cleanup_deadline,
            monotonic_clock=monotonic_clock,
        )
        raise StrategySubprocessError("strategy subprocess pipes were not created")

    stdout_capture = _BoundedPipeCapture(MAX_STRATEGY_STDOUT_BYTES)
    stderr_capture = _BoundedPipeCapture(MAX_STRATEGY_STDERR_BYTES)
    write_failed = threading.Event()
    threads = (
        threading.Thread(
            target=_write_request,
            args=(process.stdin, request, write_failed),
            name=f"strategy-stdin-{process.pid}",
            daemon=True,
        ),
        threading.Thread(
            target=stdout_capture.read,
            args=(process.stdout,),
            name=f"strategy-stdout-{process.pid}",
            daemon=True,
        ),
        threading.Thread(
            target=stderr_capture.read,
            args=(process.stderr,),
            name=f"strategy-stderr-{process.pid}",
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()

    terminal_outcome: StrategySupervisionOutcome | None = None
    detail_code = ""
    try:
        while True:
            current_monotonic = _read_monotonic(monotonic_clock, last_monotonic)
            last_monotonic = current_monotonic
            elapsed = current_monotonic - started_monotonic
            if elapsed * 1_000_000 >= STRATEGY_DECISION_DEADLINE_MICROSECONDS:
                terminal_outcome = StrategySupervisionOutcome.TIMEOUT
                detail_code = "deadline_exceeded"
                break
            if stdout_capture.exceeded.is_set():
                terminal_outcome = StrategySupervisionOutcome.RESOURCE_EXCEEDED
                detail_code = "stdout_too_large"
                break
            if stderr_capture.exceeded.is_set():
                terminal_outcome = StrategySupervisionOutcome.RESOURCE_EXCEEDED
                detail_code = "stderr_too_large"
                break
            if stdout_capture.failed.is_set() or stderr_capture.failed.is_set():
                terminal_outcome = StrategySupervisionOutcome.CRASH
                detail_code = "supervisor_pipe_failed"
                break
            if process.poll() is not None:
                break
            remaining = (STRATEGY_DECISION_DEADLINE_MICROSECONDS / 1_000_000) - elapsed
            sleeper(min(STRATEGY_SUBPROCESS_POLL_SECONDS, max(0.0, remaining)))
    except BaseException:
        _finish_process(
            process,
            threads,
            kill=True,
            cleanup_deadline=cleanup_deadline,
            monotonic_clock=monotonic_clock,
        )
        raise

    _finish_process(
        process,
        threads,
        kill=terminal_outcome is not None,
        cleanup_deadline=cleanup_deadline,
        monotonic_clock=monotonic_clock,
    )
    stdout = bytes(stdout_capture.value)
    stderr = bytes(stderr_capture.value)
    completed_monotonic = _read_monotonic(monotonic_clock, last_monotonic)
    last_monotonic = completed_monotonic
    elapsed_microseconds = _elapsed_microseconds(started_monotonic, completed_monotonic)

    if elapsed_microseconds >= STRATEGY_DECISION_DEADLINE_MICROSECONDS:
        terminal_outcome = StrategySupervisionOutcome.TIMEOUT
        detail_code = "deadline_exceeded"
    elif stdout_capture.exceeded.is_set():
        terminal_outcome = StrategySupervisionOutcome.RESOURCE_EXCEEDED
        detail_code = "stdout_too_large"
    elif stderr_capture.exceeded.is_set():
        terminal_outcome = StrategySupervisionOutcome.RESOURCE_EXCEEDED
        detail_code = "stderr_too_large"
    elif stdout_capture.failed.is_set() or stderr_capture.failed.is_set() or write_failed.is_set():
        terminal_outcome = StrategySupervisionOutcome.CRASH
        detail_code = "supervisor_pipe_failed"

    completed_at = _read_utc(utc_clock, "strategy UTC clock")
    if terminal_outcome is not None:
        if terminal_outcome is StrategySupervisionOutcome.TIMEOUT:
            elapsed_microseconds = max(
                elapsed_microseconds,
                STRATEGY_DECISION_DEADLINE_MICROSECONDS,
            )
        return _result(
            invocation=invocation,
            outcome=terminal_outcome,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_microseconds=elapsed_microseconds,
            process_started=True,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            detail_code=detail_code,
        )

    if process.returncode != 0:
        return _result(
            invocation=invocation,
            outcome=StrategySupervisionOutcome.CRASH,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_microseconds=elapsed_microseconds,
            process_started=True,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            detail_code="nonzero_exit",
        )

    try:
        response = decode_strategy_response(stdout, invocation)
    except StrategyResourceExceeded:
        return _result(
            invocation=invocation,
            outcome=StrategySupervisionOutcome.RESOURCE_EXCEEDED,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_microseconds=elapsed_microseconds,
            process_started=True,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            detail_code="stdout_too_large",
        )
    except StrategyProtocolError:
        return _result(
            invocation=invocation,
            outcome=StrategySupervisionOutcome.PROTOCOL_ERROR,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_microseconds=elapsed_microseconds,
            process_started=True,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            detail_code="invalid_response",
        )

    validated_monotonic = _read_monotonic(monotonic_clock, last_monotonic)
    validated_elapsed_microseconds = _elapsed_microseconds(started_monotonic, validated_monotonic)
    validated_at = _read_utc(utc_clock, "strategy UTC clock")
    if validated_elapsed_microseconds >= STRATEGY_DECISION_DEADLINE_MICROSECONDS:
        return _result(
            invocation=invocation,
            outcome=StrategySupervisionOutcome.TIMEOUT,
            started_at=started_at,
            completed_at=validated_at,
            elapsed_microseconds=validated_elapsed_microseconds,
            process_started=True,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            detail_code="deadline_exceeded",
        )
    return _result(
        invocation=invocation,
        outcome=StrategySupervisionOutcome.COMPLETED,
        started_at=started_at,
        completed_at=validated_at,
        elapsed_microseconds=validated_elapsed_microseconds,
        process_started=True,
        exit_code=process.returncode,
        stdout=stdout,
        stderr=stderr,
        detail_code="completed",
        response=response,
    )


@dataclass(frozen=True, slots=True)
class ConfiguredSupervisedStrategyRunner:
    """Bind one authenticated subprocess artifact to the durable runner port."""

    subprocess_spec: StrategySubprocessSpec
    monotonic_clock: MonotonicClock = time.monotonic
    utc_clock: UtcClock = _utc_now
    sleeper: Sleeper = time.sleep

    def __post_init__(self) -> None:
        if type(self.subprocess_spec) is not StrategySubprocessSpec:
            raise StrategySubprocessError("configured supervisor requires an exact subprocess spec")
        self.subprocess_spec.__post_init__()
        for dependency, field_name in (
            (self.monotonic_clock, "monotonic clock"),
            (self.utc_clock, "UTC clock"),
            (self.sleeper, "sleeper"),
        ):
            if not callable(dependency):
                raise StrategySubprocessError(
                    f"configured supervisor requires a callable {field_name}"
                )

    def run(
        self,
        *,
        invocation: StrategyInvocation,
        market_batch: MarketBatch,
        start_authorization: StrategyInvocationStartAuthorization,
    ) -> StrategySupervisionResult:
        return run_supervised_strategy(
            invocation=invocation,
            market_batch=market_batch,
            subprocess_spec=self.subprocess_spec,
            start_authorization=start_authorization,
            monotonic_clock=self.monotonic_clock,
            utc_clock=self.utc_clock,
            sleeper=self.sleeper,
        )


__all__ = [
    "ConfiguredSupervisedStrategyRunner",
    "StrategySubprocessError",
    "StrategySubprocessSpec",
    "run_supervised_strategy",
    "strategy_launch_spec_sha256",
]
