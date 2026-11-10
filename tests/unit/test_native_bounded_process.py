from __future__ import annotations

import errno
import inspect
import os
import resource
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import BuiltinFunctionType
from typing import Any, cast

import pytest

from packages.adapters.trusted_time import _bounded_process as native_process

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CAT = str(Path("/bin/cat").resolve(strict=True))
DD = str(Path("/bin/dd").resolve(strict=True))
SHELL = str(Path("/bin/sh").resolve(strict=True))
PRINTF = str(Path("/usr/bin/printf").resolve(strict=True))


def test_api_is_an_exact_builtin_and_native_namespace_is_absent() -> None:
    operation = native_process._run_bounded_process

    assert type(operation) is BuiltinFunctionType
    assert inspect.isbuiltin(operation)
    assert not hasattr(operation, "__code__")
    assert native_process.__all__ == ()
    assert "_autoquant_native_bounded_process" not in sys.modules
    native_process._native_bounded_process_self_test()
    assert native_process._native_bounded_process_capabilities() == (
        "cpython-c-bounded-process-v1",
        "exact-immutable-input-and-result-tuples",
        "absolute-executable-no-path-search",
        "native-posix-spawn-chdir-process-group",
        "exact-stdio-pipes-and-environment",
        "bounded-stdin-stdout-stderr-deadline",
        "kill-group-and-reap-before-python-signal",
        "gil-held-no-live-process-capability",
    )


def test_round_trip_is_bounded_and_returns_only_immutable_values() -> None:
    argv = (CAT,)

    result = native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (("LANG", "C"),),
        b"bounded-input",
        64,
        64,
        2_000_000_000,
    )

    assert type(result) is tuple
    assert result == (argv, 0, b"bounded-input", b"")
    assert result[0] is argv
    assert all(type(item) in (tuple, int, bytes) for item in result)


def test_nonzero_exit_and_exact_environment_are_captured() -> None:
    argv = (SHELL, "-c", "printf '%s' \"$AQT_TEST_VALUE\"; exit 7")

    result = native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (("AQT_TEST_VALUE", "exact"), ("LANG", "C")),
        b"",
        64,
        64,
        2_000_000_000,
    )

    assert result == (argv, 7, b"exact", b"")


@pytest.mark.parametrize(
    "replacement",
    (
        [CAT],
        ("cat",),
        (f"{CAT}\0replacement",),
    ),
)
def test_argv_rejects_mutable_relative_and_embedded_nul_values(
    replacement: object,
) -> None:
    unchecked_operation = cast(Any, native_process._run_bounded_process)
    with pytest.raises((TypeError, ValueError)):
        unchecked_operation(
            replacement,
            str(REPOSITORY_ROOT),
            (),
            b"",
            64,
            64,
            1_000_000_000,
        )


@pytest.mark.parametrize(
    "environment",
    (
        {"LANG": "C"},
        (("Z", "last"), ("A", "first")),
        (("A", "one"), ("A", "two")),
        (("INVALID=KEY", "value"),),
    ),
)
def test_environment_must_be_an_exact_sorted_unique_tuple(environment: object) -> None:
    unchecked_operation = cast(Any, native_process._run_bounded_process)
    with pytest.raises((TypeError, ValueError)):
        unchecked_operation(
            (CAT,),
            str(REPOSITORY_ROOT),
            environment,
            b"",
            64,
            64,
            1_000_000_000,
        )


def test_capture_overflow_kills_and_reaps_before_raising() -> None:
    with pytest.raises(OverflowError, match="output exceeded"):
        native_process._run_bounded_process(
            (PRINTF, "12345"),
            str(REPOSITORY_ROOT),
            (("LANG", "C"),),
            b"",
            4,
            4,
            2_000_000_000,
        )


def test_timeout_kills_the_process_group_before_raising() -> None:
    with pytest.raises(TimeoutError, match="exceeded its deadline"):
        native_process._run_bounded_process(
            (SHELL, "-c", "sleep 30 & wait"),
            str(REPOSITORY_ROOT),
            (("LANG", "C"), ("PATH", "/usr/bin:/bin")),
            b"",
            64,
            64,
            20_000_000,
        )


def test_exited_parent_cannot_leave_a_pipe_holding_grandchild(tmp_path: Path) -> None:
    marker = tmp_path / "leaked-grandchild"
    script = '(sleep 0.2; printf leaked > "$1") & exit 0'

    with pytest.raises(TimeoutError, match="exceeded its deadline"):
        native_process._run_bounded_process(
            (SHELL, "-c", script, "bounded-grandchild", str(marker)),
            str(REPOSITORY_ROOT),
            (("LANG", "C"), ("PATH", "/usr/bin:/bin")),
            b"",
            64,
            64,
            20_000_000,
        )

    time.sleep(0.3)
    assert not marker.exists()


def test_sigint_kills_group_and_reaps_before_python_handler(tmp_path: Path) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    child_pid_path = tmp_path / "interrupted-child-pid"
    descendant_ready_path = tmp_path / "interrupted-descendant-ready"
    descendant_marker_path = tmp_path / "interrupted-descendant-survived"
    parent_pid = os.getpid()
    signaler = os.fork()
    if signaler == 0:
        try:
            for _ in range(500):
                if child_pid_path.exists() and descendant_ready_path.exists():
                    os.kill(parent_pid, signal.SIGINT)
                    os._exit(0)
                time.sleep(0.01)
        except BaseException:
            os._exit(3)
        os._exit(2)

    script = (
        'printf "%s" "$$" > "$1"; (printf ready > "$2"; sleep 0.5; printf leaked > "$3") & wait'
    )
    try:
        with pytest.raises(KeyboardInterrupt):
            native_process._run_bounded_process(
                (
                    SHELL,
                    "-c",
                    script,
                    "bounded-interrupt",
                    str(child_pid_path),
                    str(descendant_ready_path),
                    str(descendant_marker_path),
                ),
                str(REPOSITORY_ROOT),
                (("LANG", "C"), ("PATH", "/usr/bin:/bin")),
                b"",
                64,
                64,
                5_000_000_000,
            )
    finally:
        waited, status = os.waitpid(signaler, 0)

    assert waited == signaler
    assert os.waitstatus_to_exitcode(status) == 0
    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    with pytest.raises(ChildProcessError):
        os.waitpid(child_pid, os.WNOHANG)
    time.sleep(0.7)
    assert not descendant_marker_path.exists()


def test_normal_exit_kills_same_group_descendant_that_closed_stdio(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "closed-stdio-descendant-survived"
    script = '(exec </dev/null >/dev/null 2>&1; sleep 0.2; printf leaked > "$1") & exit 0'
    argv = (SHELL, "-c", script, "bounded-descendant", str(marker))

    result = native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (("LANG", "C"), ("PATH", "/usr/bin:/bin")),
        b"",
        64,
        64,
        2_000_000_000,
    )

    assert result == (argv, 0, b"", b"")
    time.sleep(0.4)
    assert not marker.exists()


def test_rapid_exit_pid_churn_reaps_every_direct_child(tmp_path: Path) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    churner = os.fork()
    if churner == 0:
        try:
            for _ in range(64):
                churned = os.fork()
                if churned == 0:
                    os._exit(0)
                waited, status = os.waitpid(churned, 0)
                if waited != churned or os.waitstatus_to_exitcode(status) != 0:
                    os._exit(3)
        except BaseException:
            os._exit(4)
        os._exit(0)

    try:
        for index in range(32):
            child_pid_path = tmp_path / f"rapid-child-{index}"
            argv = (
                SHELL,
                "-c",
                'printf "%s" "$$" > "$1"',
                "bounded-rapid-exit",
                str(child_pid_path),
            )
            assert native_process._run_bounded_process(
                argv,
                str(REPOSITORY_ROOT),
                (("LANG", "C"),),
                b"",
                1,
                1,
                2_000_000_000,
            ) == (argv, 0, b"", b"")
            child_pid = int(child_pid_path.read_text(encoding="ascii"))
            with pytest.raises(ChildProcessError):
                os.waitpid(child_pid, os.WNOHANG)
    finally:
        waited, status = os.waitpid(churner, 0)

    assert waited == churner
    assert os.waitstatus_to_exitcode(status) == 0


@pytest.mark.filterwarnings(
    r"ignore:This process .* is multi-threaded, use of fork\(\) may lead to deadlocks"
)
def test_gil_blocks_thread_fork_until_live_transaction_is_gone() -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    ready = threading.Event()
    start = threading.Event()
    sleeping = threading.Event()
    wake_elapsed: list[float] = []
    fork_status: list[int] = []

    def fork_after_delay() -> None:
        ready.set()
        assert start.wait(timeout=1.0)
        delay_started = time.monotonic()
        sleeping.set()
        time.sleep(0.05)
        wake_elapsed.append(time.monotonic() - delay_started)
        forked = os.fork()
        if forked == 0:
            try:
                native_process._run_bounded_process(
                    (CAT,),
                    str(REPOSITORY_ROOT),
                    (),
                    b"",
                    1,
                    1,
                    1_000_000,
                )
            except RuntimeError:
                os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(1)
        waited, status = os.waitpid(forked, 0)
        assert waited == forked
        fork_status.append(os.waitstatus_to_exitcode(status))

    worker = threading.Thread(target=fork_after_delay)
    worker.start()
    assert ready.wait(timeout=1.0)
    start.set()
    assert sleeping.wait(timeout=1.0)
    argv = (SHELL, "-c", "sleep 0.3")
    assert native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (("LANG", "C"), ("PATH", "/usr/bin:/bin")),
        b"",
        1,
        1,
        2_000_000_000,
    ) == (argv, 0, b"", b"")
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert len(wake_elapsed) == 1
    assert wake_elapsed[0] >= 0.2
    assert fork_status == [0]


def test_caller_signal_mask_is_restored_exactly() -> None:
    if not hasattr(signal, "pthread_sigmask"):
        pytest.skip("pthread signal masks are unavailable")
    original = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    try:
        blocked = set(original)
        blocked.add(signal.SIGPIPE)
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        expected = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        assert native_process._run_bounded_process(
            (CAT,),
            str(REPOSITORY_ROOT),
            (),
            b"",
            1,
            1,
            1_000_000_000,
        )[1:] == (0, b"", b"")
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == expected
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original)


def test_stdin_epipe_does_not_block_simultaneous_stdout_stderr_drain() -> None:
    chunk = "0123456789abcdef" * 128
    repetitions = 1024
    expected = chunk.encode("ascii") * repetitions
    stdin_payload = b"x" * (16 * 1024 * 1024)
    read_descriptor, write_descriptor = os.pipe()
    pipe_capacity = 0
    try:
        os.set_blocking(write_descriptor, False)
        while pipe_capacity < len(stdin_payload):
            try:
                written = os.write(write_descriptor, stdin_payload[pipe_capacity:])
            except BlockingIOError:
                break
            assert written > 0
            pipe_capacity += written
    finally:
        os.close(write_descriptor)
        os.close(read_descriptor)
    if pipe_capacity + 1 >= len(stdin_payload):
        pytest.skip("the platform pipe can absorb the maximum bounded stdin")

    script = (
        '"$3" bs=1 count=1 of=/dev/null 2>/dev/null; exec 0<&-; '
        '(i=0; while [ "$i" -lt "$2" ]; do '
        'printf "%s" "$1"; i=$((i + 1)); done) & '
        '(i=0; while [ "$i" -lt "$2" ]; do '
        'printf "%s" "$1"; i=$((i + 1)); done) >&2 & '
        "wait; exit 9"
    )
    argv = (
        SHELL,
        "-c",
        script,
        "bounded-epipe",
        chunk,
        str(repetitions),
        DD,
    )
    original_mask = (
        signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if hasattr(signal, "pthread_sigmask")
        else None
    )

    result = native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (("LANG", "C"),),
        stdin_payload,
        len(expected),
        len(expected),
        5_000_000_000,
    )

    assert result == (argv, 9, expected, expected)
    if original_mask is not None:
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask


def test_signal_terminated_child_returns_exact_negative_signal() -> None:
    argv = (SHELL, "-c", "printf out; printf error >&2; kill -TERM $$")

    result = native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (),
        b"",
        3,
        5,
        2_000_000_000,
    )

    assert result == (argv, -signal.SIGTERM, b"out", b"error")


def test_zero_and_exact_capture_caps_are_enforced() -> None:
    empty_argv = (SHELL, "-c", ":")
    assert native_process._run_bounded_process(
        empty_argv,
        str(REPOSITORY_ROOT),
        (),
        b"",
        0,
        0,
        2_000_000_000,
    ) == (empty_argv, 0, b"", b"")

    exact_argv = (SHELL, "-c", "printf 1234; printf abcd >&2")
    assert native_process._run_bounded_process(
        exact_argv,
        str(REPOSITORY_ROOT),
        (),
        b"",
        4,
        4,
        2_000_000_000,
    ) == (exact_argv, 0, b"1234", b"abcd")

    for script in ("printf x", "printf x >&2"):
        with pytest.raises(OverflowError, match="output exceeded"):
            native_process._run_bounded_process(
                (SHELL, "-c", script),
                str(REPOSITORY_ROOT),
                (),
                b"",
                0,
                0,
                2_000_000_000,
            )


@pytest.mark.parametrize("descriptor", (0, 1, 2))
def test_closed_standard_descriptor_fails_closed_without_rebinding(
    descriptor: int,
) -> None:
    original_inheritable = os.get_inheritable(descriptor)
    saved = os.dup(descriptor)
    try:
        os.close(descriptor)
        with pytest.raises(OSError) as raised:
            native_process._run_bounded_process(
                (CAT,),
                str(REPOSITORY_ROOT),
                (),
                b"",
                1,
                1,
                1_000_000_000,
            )
    finally:
        os.dup2(saved, descriptor, inheritable=original_inheritable)
        os.close(saved)

    assert raised.value.errno == errno.EBADF


@pytest.mark.parametrize("available_descriptors", (0, 2, 4))
def test_partial_pipe_setup_failure_closes_every_opened_descriptor(
    available_descriptors: int,
) -> None:
    original_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    free_descriptors = [os.dup(0) for _ in range(6)]
    for descriptor in reversed(free_descriptors):
        os.close(descriptor)
    lowered_soft_limit = (
        free_descriptors[0]
        if available_descriptors == 0
        else free_descriptors[available_descriptors - 1] + 1
    )
    if original_limit[0] <= lowered_soft_limit:
        pytest.skip("descriptor limit cannot admit the requested test pipes")

    reclaimed: list[int] = []
    try:
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (lowered_soft_limit, original_limit[1]),
        )
        with pytest.raises(OSError) as raised:
            native_process._run_bounded_process(
                (CAT,),
                str(REPOSITORY_ROOT),
                (),
                b"",
                1,
                1,
                1_000_000_000,
            )
        assert raised.value.errno == errno.EMFILE
        reclaimed = [os.dup(0) for _ in range(available_descriptors)]
        assert reclaimed == free_descriptors[:available_descriptors]
        with pytest.raises(OSError) as exhausted:
            os.dup(0)
        assert exhausted.value.errno == errno.EMFILE
    finally:
        for descriptor in reversed(reclaimed):
            os.close(descriptor)
        resource.setrlimit(resource.RLIMIT_NOFILE, original_limit)

    argv = (CAT,)
    assert native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (),
        b"",
        1,
        1,
        1_000_000_000,
    ) == (argv, 0, b"", b"")


def test_spawn_failure_after_full_setup_restores_process_state() -> None:
    descriptor, invalid_executable = tempfile.mkstemp(
        prefix=".native-invalid-executable-",
        dir=REPOSITORY_ROOT,
    )
    try:
        payload = b"not-an-executable-format\n"
        assert os.write(descriptor, payload) == len(payload)
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    first_free = os.dup(0)
    os.close(first_free)
    original_mask = (
        signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if hasattr(signal, "pthread_sigmask")
        else None
    )
    try:
        with pytest.raises(OSError) as raised:
            native_process._run_bounded_process(
                (invalid_executable,),
                str(REPOSITORY_ROOT),
                (),
                b"",
                1,
                1,
                1_000_000_000,
            )
    finally:
        os.unlink(invalid_executable)

    assert raised.value.errno == errno.ENOEXEC
    if original_mask is not None:
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
    probe = os.dup(0)
    os.close(probe)
    assert probe == first_free

    argv = (CAT,)
    assert native_process._run_bounded_process(
        argv,
        str(REPOSITORY_ROOT),
        (),
        b"",
        1,
        1,
        1_000_000_000,
    ) == (argv, 0, b"", b"")


def test_result_allocation_failure_occurs_only_after_direct_child_reap(
    tmp_path: Path,
) -> None:
    child_pid_path = tmp_path / "reaped-child-pid"
    allocation_fault = "__autoquant_test_fail_result_allocation_after_reap__"

    with pytest.raises(MemoryError):
        native_process._run_bounded_process(
            (
                SHELL,
                "-c",
                'printf "%s" "$$" > "$1"',
                "allocation-fault",
                str(child_pid_path),
                allocation_fault,
            ),
            str(REPOSITORY_ROOT),
            (("LANG", "C"),),
            b"",
            64,
            64,
            2_000_000_000,
        )

    child_pid = int(child_pid_path.read_text(encoding="ascii"))
    with pytest.raises(ChildProcessError):
        os.waitpid(child_pid, os.WNOHANG)


def test_caps_timeout_and_stdin_reject_bool_and_oversize() -> None:
    unchecked_operation = cast(Any, native_process._run_bounded_process)
    for index in (4, 5, 6):
        arguments: list[object] = [
            (CAT,),
            str(REPOSITORY_ROOT),
            (),
            b"",
            64,
            64,
            1_000_000_000,
        ]
        arguments[index] = True
        with pytest.raises(TypeError):
            unchecked_operation(*arguments)

    with pytest.raises(ValueError, match="stdin exceeds"):
        native_process._run_bounded_process(
            (CAT,),
            str(REPOSITORY_ROOT),
            (),
            b"x" * (16 * 1024 * 1024 + 1),
            64,
            64,
            1_000_000_000,
        )


def test_forked_child_cannot_reuse_the_parent_process_module() -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")

    child = os.fork()
    if child == 0:
        try:
            native_process._run_bounded_process(
                (CAT,),
                str(REPOSITORY_ROOT),
                (),
                b"",
                1,
                1,
                1_000_000,
            )
        except RuntimeError:
            os._exit(0)
        except BaseException:
            os._exit(2)
        os._exit(1)
    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.waitstatus_to_exitcode(status) == 0
