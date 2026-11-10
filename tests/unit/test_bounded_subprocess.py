from __future__ import annotations

import dis
import os
import signal
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.bounded_subprocess import (
    BoundedSubprocessError,
    BoundedSubprocessResult,
    run_bounded_subprocess,
)


def _base_python_executable() -> str:
    candidate = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    assert candidate.is_file() and not candidate.is_symlink()
    return str(candidate)


def _environment() -> dict[str, str]:
    return {"LC_ALL": "C", "PATH": os.defpath}


def test_bounded_subprocess_streams_exact_input_and_outputs(tmp_path: Path) -> None:
    payload = b"approved-input"
    completed = run_bounded_subprocess(
        (
            _base_python_executable(),
            "-I",
            "-B",
            "-c",
            "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); "
            "sys.stderr.buffer.write(b'exact-stderr')",
        ),
        cwd=tmp_path,
        environment=_environment(),
        stdin_bytes=payload,
        maximum_stdin_bytes=len(payload),
        maximum_stdout_bytes=len(payload),
        maximum_stderr_bytes=len(b"exact-stderr"),
        timeout_seconds=2,
    )

    assert type(completed) is tuple
    assert len(completed) == 4
    assert tuple.__getitem__(completed, 1) == 0
    assert type(tuple.__getitem__(completed, 0)) is tuple
    assert tuple.__getitem__(completed, 2) == payload
    assert tuple.__getitem__(completed, 3) == b"exact-stderr"
    with pytest.raises(AttributeError):
        object.__setattr__(completed, "stdout", b"forged")


def test_bounded_subprocess_result_rejects_caller_store_boundary_relabel(
    tmp_path: Path,
) -> None:
    observed: list[BoundedSubprocessResult] = []

    def caller() -> BoundedSubprocessResult:
        result = run_bounded_subprocess(
            (_base_python_executable(), "-I", "-B", "-c", "print('exact')"),
            cwd=tmp_path,
            environment=_environment(),
            maximum_stdout_bytes=16,
            maximum_stderr_bytes=16,
            timeout_seconds=2,
        )
        return result

    instructions = list(dis.get_instructions(caller))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "STORE_FAST" and instruction.argval == "result"
    )
    post_store_offset = instructions[store_index + 1].offset
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def reject_relabel(_: object, offset: int) -> None:
        if offset == post_store_offset:
            result = sys._getframe(1).f_locals["result"]
            assert type(result) is tuple
            assert len(result) == 4
            with pytest.raises(AttributeError):
                object.__setattr__(result, "stdout", b"forged\n")
            observed.append(result)

    sys.monitoring.use_tool_id(tool_id, "bounded-subprocess-result-store-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        reject_relabel,
    )
    sys.monitoring.set_local_events(
        tool_id,
        caller.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        result = caller()
    finally:
        sys.monitoring.set_local_events(tool_id, caller.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert observed == [result]
    assert tuple.__getitem__(result, 2) == b"exact\n"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_bounded_subprocess_kills_output_overflow(tmp_path: Path, stream: str) -> None:
    output = "sys.stdout" if stream == "stdout" else "sys.stderr"
    with pytest.raises(BoundedSubprocessError, match=f"{stream} exceeded"):
        run_bounded_subprocess(
            (
                _base_python_executable(),
                "-I",
                "-B",
                "-c",
                f"import sys,time; {output}.buffer.write(b'x'*1024); "
                f"{output}.flush(); time.sleep(10)",
            ),
            cwd=tmp_path,
            environment=_environment(),
            maximum_stdout_bytes=16,
            maximum_stderr_bytes=16,
            timeout_seconds=1,
        )


def test_bounded_subprocess_kills_timeout(tmp_path: Path) -> None:
    with pytest.raises(BoundedSubprocessError, match="execution failed"):
        run_bounded_subprocess(
            (
                _base_python_executable(),
                "-I",
                "-B",
                "-c",
                "import time; time.sleep(10)",
            ),
            cwd=tmp_path,
            environment=_environment(),
            maximum_stdout_bytes=16,
            maximum_stderr_bytes=16,
            timeout_seconds=0.1,
        )


def test_bounded_subprocess_rejects_input_before_spawn(tmp_path: Path) -> None:
    with pytest.raises(BoundedSubprocessError, match="contract is invalid"):
        run_bounded_subprocess(
            (_base_python_executable(), "-I", "-B", "-c", "raise SystemExit"),
            cwd=tmp_path,
            environment=_environment(),
            stdin_bytes=b"too-large",
            maximum_stdin_bytes=1,
            maximum_stdout_bytes=16,
            maximum_stderr_bytes=16,
            timeout_seconds=1,
        )


def test_bounded_subprocess_rejects_unconsumed_input(tmp_path: Path) -> None:
    with pytest.raises(BoundedSubprocessError, match="stdin was not fully consumed"):
        run_bounded_subprocess(
            (_base_python_executable(), "-I", "-B", "-c", "raise SystemExit"),
            cwd=tmp_path,
            environment=_environment(),
            stdin_bytes=b"x" * (2 * 1_024 * 1_024),
            maximum_stdin_bytes=2 * 1_024 * 1_024,
            maximum_stdout_bytes=16,
            maximum_stderr_bytes=16,
            timeout_seconds=1,
        )


def test_bounded_subprocess_kills_and_reaps_group_on_keyboard_interrupt(
    tmp_path: Path,
) -> None:
    class FakeStream:
        def __init__(self, descriptor: int) -> None:
            self._descriptor = descriptor
            self.closed = False

        def fileno(self) -> int:
            return self._descriptor

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        pid = 12_345
        stdin = None

        def __init__(self) -> None:
            self.stdout = FakeStream(10)
            self.stderr = FakeStream(11)
            self.kill_count = 0
            self.wait_count = 0
            self.poll_count = 0

        def kill(self) -> None:
            self.kill_count += 1

        def wait(self, *, timeout: float) -> int:
            assert 0 <= timeout <= 0.25
            self.wait_count += 1
            return -signal.SIGKILL

        def poll(self) -> int:
            self.poll_count += 1
            return -signal.SIGKILL

    class InterruptingSelector:
        def __init__(self) -> None:
            self.registered = 0
            self.closed = False

        def register(self, *_args: object) -> None:
            self.registered += 1

        def get_map(self) -> dict[int, object]:
            return {index: object() for index in range(self.registered)}

        def select(self, _timeout: float) -> list[object]:
            raise KeyboardInterrupt

        def close(self) -> None:
            self.closed = True

    process = FakeProcess()
    selector = InterruptingSelector()
    with (
        patch("scripts.bounded_subprocess.subprocess.Popen", return_value=process),
        patch("scripts.bounded_subprocess.selectors.DefaultSelector", return_value=selector),
        patch("scripts.bounded_subprocess.os.set_blocking"),
        patch("scripts.bounded_subprocess.os.killpg") as killpg,
        pytest.raises(KeyboardInterrupt),
    ):
        run_bounded_subprocess(
            (_base_python_executable(), "-I", "-B", "-c", "raise SystemExit"),
            cwd=tmp_path,
            environment=_environment(),
            maximum_stdout_bytes=16,
            maximum_stderr_bytes=16,
            timeout_seconds=1,
        )

    killpg.assert_called_once_with(process.pid, signal.SIGKILL)
    assert process.kill_count == 1
    assert process.wait_count == 1
    assert process.poll_count == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True
    assert selector.closed is True
