"""Run local subprocesses with hard input, output, and wall-time bounds."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, cast

_MAXIMUM_STREAM_BYTES = 128 * 1_024 * 1_024
_MAXIMUM_TIMEOUT_SECONDS = 3_600.0
_REAP_RESERVE_SECONDS = 0.25


class BoundedSubprocessError(RuntimeError):
    """A subprocess violated or could not satisfy its fixed resource contract."""


def run_bounded_subprocess(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    maximum_stdout_bytes: int,
    maximum_stderr_bytes: int,
    stdin_bytes: bytes | None = None,
    maximum_stdin_bytes: int = 0,
) -> subprocess.CompletedProcess[bytes]:
    """Run one command while streaming every pipe within exact byte bounds."""

    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str or not item or "\x00" in item for item in argv)
        or not isinstance(cwd, Path)
        or not isinstance(environment, Mapping)
        or type(timeout_seconds) not in {int, float}
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= _MAXIMUM_TIMEOUT_SECONDS
        or type(maximum_stdout_bytes) is not int
        or not 0 <= maximum_stdout_bytes <= _MAXIMUM_STREAM_BYTES
        or type(maximum_stderr_bytes) is not int
        or not 0 <= maximum_stderr_bytes <= _MAXIMUM_STREAM_BYTES
        or type(maximum_stdin_bytes) is not int
        or not 0 <= maximum_stdin_bytes <= _MAXIMUM_STREAM_BYTES
        or (stdin_bytes is not None and type(stdin_bytes) is not bytes)
        or (stdin_bytes is None and maximum_stdin_bytes != 0)
        or (isinstance(stdin_bytes, bytes) and len(stdin_bytes) > maximum_stdin_bytes)
    ):
        raise BoundedSubprocessError("bounded subprocess contract is invalid")
    try:
        exact_environment = dict(environment)
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise BoundedSubprocessError("bounded subprocess contract is invalid") from None
    if any(
        type(key) is not str
        or type(value) is not str
        or not key
        or "=" in key
        or "\x00" in key
        or "\x00" in value
        for key, value in exact_environment.items()
    ):
        raise BoundedSubprocessError("bounded subprocess contract is invalid")

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    input_view = memoryview(b"" if stdin_bytes is None else stdin_bytes)
    started = time.monotonic()
    lifecycle_deadline = started + float(timeout_seconds)
    reap_reserve = min(_REAP_RESERVE_SECONDS, float(timeout_seconds) / 2)
    observation_deadline = lifecycle_deadline - reap_reserve

    def stop_process() -> None:
        if process is None:
            return
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with suppress(OSError):
            process.kill()
        remaining = max(0.0, lifecycle_deadline - time.monotonic())
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=min(_REAP_RESERVE_SECONDS, remaining))
        with suppress(OSError):
            process.poll()

    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=exact_environment,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            close_fds=True,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            raise OSError
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(
            process.stdout,
            selectors.EVENT_READ,
            ("stdout", stdout, maximum_stdout_bytes),
        )
        selector.register(
            process.stderr,
            selectors.EVENT_READ,
            ("stderr", stderr, maximum_stderr_bytes),
        )
        if stdin_bytes is not None:
            if process.stdin is None:
                raise OSError
            if input_view:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", None, None))
            else:
                process.stdin.close()

        while selector.get_map():
            remaining = observation_deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, float(timeout_seconds))
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(argv, float(timeout_seconds))
            for key, _ in events:
                stream_kind, buffer, maximum = key.data
                if stream_kind == "stdin":
                    try:
                        written = os.write(key.fd, input_view[:65_536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        raise BoundedSubprocessError(
                            "bounded subprocess stdin was not fully consumed"
                        ) from None
                    if written <= 0:
                        raise BoundedSubprocessError(
                            "bounded subprocess stdin was not fully consumed"
                        )
                    if written > 0:
                        input_view = input_view[written:]
                    if not input_view:
                        selector.unregister(key.fileobj)
                        cast(BinaryIO, key.fileobj).close()
                    continue
                assert isinstance(buffer, bytearray)
                assert isinstance(maximum, int)
                try:
                    chunk = os.read(key.fd, min(65_536, maximum + 1 - len(buffer)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    cast(BinaryIO, key.fileobj).close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    raise BoundedSubprocessError(
                        f"bounded subprocess {stream_kind} exceeded its byte limit"
                    )

        remaining = observation_deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, float(timeout_seconds))
        return_code = process.wait(timeout=remaining)
        if time.monotonic() > lifecycle_deadline:
            raise subprocess.TimeoutExpired(argv, float(timeout_seconds))
        return subprocess.CompletedProcess(
            argv,
            return_code,
            bytes(stdout),
            bytes(stderr),
        )
    except BoundedSubprocessError:
        stop_process()
        raise
    except (OSError, subprocess.SubprocessError):
        stop_process()
        raise BoundedSubprocessError("bounded subprocess execution failed") from None
    except BaseException:
        stop_process()
        raise
    finally:
        selector.close()
        input_view.release()
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
