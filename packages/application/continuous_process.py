"""Bounded supervision of one reviewed, local continuous-account operation.

The child owns its real stores and final SQL checks. Its opaque receipt is a
bounded process artifact, never proof of delivery, freshness or trading authority.
This is not a sandbox for hostile code or indefinitely blocked kernel I/O.
"""

from __future__ import annotations

import json
import math
import os
import queue
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from types import FrameType
from typing import Any, Literal, Protocol
from uuid import uuid4

from packages.domain.research_job_contracts import ObjectRef, require_identifier

_MAX_REQUEST = 64 * 1024
_MAX_FILE_BYTES = 256 * 1024 * 1024
_PROBE_AGE = 0.5
_TERM_GRACE = 0.25
_REAP_GRACE = 0.5
_CLEANUP_RESERVE = _TERM_GRACE + _REAP_GRACE
_PRODUCTION_MODULE = "apps.trader.continuous_simulation"


@dataclass(frozen=True, slots=True)
class ContinuousProcessLimits:
    wall_seconds: float = 30.0
    cpu_seconds: int = 30
    memory_bytes: int = 512 * 1024 * 1024
    receipt_bytes: int = 1024 * 1024
    pipe_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if (
            type(self.wall_seconds) not in (int, float)
            or not math.isfinite(self.wall_seconds)
            or not 1 <= self.wall_seconds <= 120
            or type(self.cpu_seconds) is not int
            or not 1 <= self.cpu_seconds <= 120
            or type(self.memory_bytes) is not int
            or not 128 * 1024 * 1024 <= self.memory_bytes <= 1024 * 1024 * 1024
            or type(self.receipt_bytes) is not int
            or not 1 <= self.receipt_bytes <= 1024 * 1024
            or type(self.pipe_bytes) is not int
            or not 0 <= self.pipe_bytes <= 64 * 1024
        ):
            raise ValueError("continuous process limits invalid")


@dataclass(frozen=True, slots=True)
class ContinuousProcessRequest:
    account_id: str
    operation_id: str
    configuration_path: Path
    objects: tuple[ObjectRef, ...] = ()
    limits: ContinuousProcessLimits = ContinuousProcessLimits()

    def __post_init__(self) -> None:
        require_identifier(self.account_id, "continuous account")
        require_identifier(self.operation_id, "continuous operation")
        if (
            not isinstance(self.configuration_path, Path)
            or not self.configuration_path.is_absolute()
            or self.configuration_path.suffix != ".json"
            or any(part.startswith(".env") for part in self.configuration_path.parts)
            or type(self.objects) is not tuple
            or len(self.objects) > 32
            or any(type(item) is not ObjectRef for item in self.objects)
            or any(type(item.byte_count) is not int for item in self.objects)
            or sum(item.byte_count for item in self.objects) > 32 * 1024 * 1024
            or type(self.limits) is not ContinuousProcessLimits
        ):
            raise ValueError("continuous process request invalid")
        for item in self.objects:
            item.__post_init__()
        self.limits.__post_init__()


@dataclass(frozen=True, slots=True)
class ContinuousProcessReceiptRef:
    """Private orchestration reference; never expose its path in API/UI output."""

    path: Path
    object_sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class ContinuousProcessOutcome:
    status: Literal["completed", "stopped", "failed"]
    reason: str
    receipt: ContinuousProcessReceiptRef | None = None


@dataclass(frozen=True, slots=True)
class ContinuousProcessStartup:
    """Parent-issued lifecycle binding; no account or source receipt authority."""

    request: ContinuousProcessRequest
    directory: Path
    parent_nonce: str
    parent_pid: int
    request_sha256: str
    configuration_sha256: str
    lock_device: int
    lock_inode: int
    started_monotonic: float
    startup_deadline: float
    work_deadline: float


type ContinuousLifecyclePhase = Literal["starting", "leased", "closing", "released"]


class ContinuousProcessLifecycle(Protocol):
    def prepare(self, startup: ContinuousProcessStartup) -> None: ...

    def observe(self, *, child_pid: int | None, child_exited: bool) -> ContinuousLifecyclePhase: ...

    def require_result(self, payload: bytes) -> None: ...


def _private_directory(path: Path) -> None:
    info = path.lstat()
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError("continuous private directory invalid")


def _private_read(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= maximum
        ):
            raise ValueError("continuous private artifact invalid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        if len(payload) != info.st_size or len(payload) > maximum:
            raise ValueError("continuous private artifact changed")
        return payload
    finally:
        os.close(fd)


def _private_write(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()


def _lock_descriptor(fd: int) -> None:
    if type(fd) is not int or fd < 3:
        raise ValueError("continuous instance lock invalid")
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ValueError("continuous instance lock invalid")


def _encode(request: ContinuousProcessRequest) -> bytes:
    request.__post_init__()
    value = asdict(request)
    value["configuration_path"] = str(request.configuration_path)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_REQUEST:
        raise ValueError("continuous process request oversized")
    return payload


def _decode(payload: bytes) -> ContinuousProcessRequest:
    value = json.loads(payload)
    if (
        type(value) is not dict
        or set(value) != {"account_id", "operation_id", "configuration_path", "objects", "limits"}
        or type(value["objects"]) is not list
        or len(value["objects"]) > 32
    ):
        raise ValueError("continuous process request invalid")
    request = ContinuousProcessRequest(
        value["account_id"],
        value["operation_id"],
        Path(value["configuration_path"]),
        tuple(ObjectRef(**item) for item in value["objects"]),
        ContinuousProcessLimits(**value["limits"]),
    )
    if _encode(request) != payload:
        raise ValueError("continuous process request encoding invalid")
    return request


@dataclass(frozen=True, slots=True)
class _ChildObservation:
    exited: bool
    resident_bytes: int


def _observe_child(pid: int, *, timeout: float = 0.1) -> _ChildObservation:
    # State and RSS only; ps does not reap our child. EOF alone is not exit.
    result = subprocess.run(
        ("/bin/ps", "-o", "state=,rss=", "-p", str(pid)),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=timeout,
    )
    fields = result.stdout.split()
    if (
        result.returncode
        or len(result.stdout) > 64
        or len(fields) != 2
        or not 1 <= len(fields[0]) <= 16
        or (
            fields[0][:1] not in (b"D", b"I", b"R", b"S", b"T", b"U", b"W", b"Z")
            and not (sys.platform == "darwin" and fields[0][:1] == b"?" and b"E" in fields[0][1:])
        )
        or any(value not in b"+<>AELNSsVWXl" for value in fields[0][1:])
        or not fields[1].isdigit()
    ):
        raise ValueError("continuous child observation unavailable")
    return _ChildObservation(fields[0].startswith(b"Z"), int(fields[1]) * 1024)


@dataclass(frozen=True, slots=True)
class _ChildCleanup:
    reaped: bool
    group_absent: bool
    returncode: int | None
    issues: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return self.reaped and self.group_absent


def _terminate_owned_child(
    child: subprocess.Popen[bytes], *, deadline: float, exit_observed: bool
) -> _ChildCleanup:
    # This supervisor is the sole waiter. Keep its session leader unreaped
    # through the final group signal, even if it has already become a zombie.
    # A returncode set by another waiter invalidates that ownership protocol.
    issues: list[str] = []

    def signal_group(sig: signal.Signals, name: str) -> bool:
        if child.returncode is not None:
            issues.append("reaped_before_" + name)
            return False
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            issues.append(name + "_group_missing")
        except PermissionError:
            # Darwin may deny signalling a zombie. That is not proof that its
            # descendants are gone: the final reap and group check still apply.
            issues.append(name + "_denied")
        except OSError:
            issues.append(name + "_failed")
        return True

    if not signal_group(signal.SIGTERM, "term"):
        return _ChildCleanup(False, False, child.returncode, tuple(issues))
    term_deadline = min(time.monotonic() + _TERM_GRACE, deadline - _REAP_GRACE)
    while not exit_observed and time.monotonic() < term_deadline:
        try:
            observation = _observe_child(
                child.pid, timeout=min(0.1, max(0, term_deadline - time.monotonic()))
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            issues.append("cleanup_observation_unavailable")
            break
        exit_observed = observation.exited
        if not exit_observed:
            time.sleep(min(0.01, max(0, term_deadline - time.monotonic())))
    if not signal_group(signal.SIGKILL, "kill"):
        return _ChildCleanup(False, False, child.returncode, tuple(issues))

    # No destructive signal is allowed beyond this point, including on timeout.
    reap_deadline = min(deadline, time.monotonic() + _REAP_GRACE)
    try:
        status = child.wait(timeout=max(0, reap_deadline - time.monotonic()))
    except (OSError, subprocess.SubprocessError):
        issues.append("reap_unconfirmed")
        return _ChildCleanup(False, False, child.returncode, tuple(issues))
    while True:
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            return _ChildCleanup(True, True, status, tuple(issues))
        except PermissionError:
            issues.append("group_probe_denied")
            break
        except OSError:
            issues.append("group_probe_failed")
            break
        if time.monotonic() >= reap_deadline:
            issues.append("group_still_present")
            break
        time.sleep(min(0.01, max(0, reap_deadline - time.monotonic())))
    return _ChildCleanup(True, False, status, tuple(issues))


class ContinuousProcessSupervisor:
    """One operation at a time; callbacks return observations, never permissions."""

    def __init__(self, *, artifact_directory: Path) -> None:
        _private_directory(artifact_directory)
        self.artifact_directory = artifact_directory
        self._operation = threading.Lock()
        self._probe_thread: threading.Thread | None = None
        self._cleanup_complete = True
        self._cleanup: _ChildCleanup | None = None

    def run(
        self,
        request: ContinuousProcessRequest,
        *,
        lock_descriptor: int,
        stop_requested: Callable[[], bool],
        lifecycle: ContinuousProcessLifecycle | None = None,
        fence_is_current: Callable[[], bool] | None = None,
    ) -> ContinuousProcessOutcome:
        # The old boolean seam cannot qualify the fixed production entrypoint.
        # It remains accepted here only to fail closed for old API callers.
        return self._run(
            request,
            lock_descriptor=lock_descriptor,
            stop_requested=stop_requested,
            fence_is_current=fence_is_current,
            lifecycle=lifecycle,
            module=_PRODUCTION_MODULE,
        )

    def _run_fixture_for_test(
        self,
        request: ContinuousProcessRequest,
        *,
        lock_descriptor: int,
        stop_requested: Callable[[], bool],
        fence_is_current: Callable[[], bool],
    ) -> ContinuousProcessOutcome:
        """Explicit repository fixture; public production run has no argv override."""
        return self._run(
            request,
            lock_descriptor=lock_descriptor,
            stop_requested=stop_requested,
            fence_is_current=fence_is_current,
            lifecycle=None,
            module="tests.fixtures.continuous_process_child",
        )

    # Supervision and termination update these fields across call boundaries.
    def _read_cleanup_complete(self) -> bool:
        return self._cleanup_complete

    def _read_cleanup(self) -> _ChildCleanup | None:
        return self._cleanup

    def _run(
        self,
        request: ContinuousProcessRequest,
        *,
        lock_descriptor: int,
        stop_requested: Callable[[], bool],
        fence_is_current: Callable[[], bool] | None,
        lifecycle: ContinuousProcessLifecycle | None,
        module: str,
    ) -> ContinuousProcessOutcome:
        if module == _PRODUCTION_MODULE and (lifecycle is None or fence_is_current is not None):
            return ContinuousProcessOutcome("failed", "lifecycle_required")
        if not self._operation.acquire(blocking=False):
            return ContinuousProcessOutcome("failed", "operation_busy")
        try:
            if not self._cleanup_complete:
                return ContinuousProcessOutcome("failed", "cleanup_incomplete")
            if self._probe_thread is not None and self._probe_thread.is_alive():
                return ContinuousProcessOutcome("failed", "probe_stalled")
            outcome = self._supervise(
                request, lock_descriptor, stop_requested, fence_is_current, lifecycle, module
            )
            if not self._read_cleanup_complete():
                if outcome.receipt is not None:
                    with suppress(OSError):
                        outcome.receipt.path.unlink()
                return ContinuousProcessOutcome("failed", "cleanup_incomplete")
            return outcome
        finally:
            self._operation.release()

    def _supervise(
        self,
        request: ContinuousProcessRequest,
        lock_fd: int,
        stop_requested: Callable[[], bool],
        fence_is_current: Callable[[], bool] | None,
        lifecycle: ContinuousProcessLifecycle | None,
        module: str,
    ) -> ContinuousProcessOutcome:
        started = time.monotonic()
        self._cleanup_complete = True
        self._cleanup = None
        if type(request) is not ContinuousProcessRequest:
            return ContinuousProcessOutcome("failed", "request_invalid")
        try:
            encoded = _encode(request)
            _private_directory(self.artifact_directory)
            _lock_descriptor(lock_fd)
            # Configuration is a private declarative JSON reference, never .env.
            # Its schema and financial contents belong to the actual worker.
            configuration = _private_read(request.configuration_path, _MAX_REQUEST)
        except (OSError, ValueError, TypeError):
            return ContinuousProcessOutcome("failed", "request_invalid")
        deadline = started + request.limits.wall_seconds
        work_deadline = deadline - _CLEANUP_RESERVE
        stopping = threading.Event()
        cancelled = threading.Event()
        child_exit_observed = threading.Event()
        observations: queue.Queue[tuple[float, str | None, str, bool]] = queue.Queue(maxsize=1)
        child: subprocess.Popen[bytes] | None = None
        temporary: Path | None = None
        lifecycle_phase = "starting" if lifecycle is not None else "leased"
        observed_exit = False
        try:
            temporary = Path(
                tempfile.mkdtemp(prefix=".continuous-operation-", dir=self.artifact_directory)
            )
            request_path, receipt_path = temporary / "request.json", temporary / "receipt.json"
            _private_write(request_path, encoded)
            lock_info = os.fstat(lock_fd)
        except (OSError, ValueError):
            if temporary is not None:
                with suppress(OSError):
                    (temporary / "request.json").unlink()
                with suppress(OSError):
                    temporary.rmdir()
            return ContinuousProcessOutcome("failed", "request_invalid")
        startup = ContinuousProcessStartup(
            request,
            temporary,
            uuid4().hex,
            os.getpid(),
            sha256(encoded).hexdigest(),
            sha256(configuration).hexdigest(),
            lock_info.st_dev,
            lock_info.st_ino,
            started,
            min(work_deadline, started + 10.0),
            work_deadline,
        )

        def probe() -> None:
            initialized = False
            while not stopping.is_set():
                # Frozen by the sole process owner after non-reaping exit proof.
                # Never query the PID again after reap, or hold a lock across SQL.
                sampled_exit = child_exit_observed.is_set()
                try:
                    stop: object = stop_requested()
                    phase = "leased"
                    if type(stop) is not bool:
                        raise ValueError("invalid stop observation")
                    if stop:
                        reason = "stopped"
                    elif lifecycle is not None:
                        if not initialized:
                            lifecycle.prepare(startup)
                            initialized = True
                        phase = lifecycle.observe(
                            child_pid=None if child is None else child.pid,
                            child_exited=sampled_exit,
                        )
                        if phase not in ("starting", "leased", "closing", "released"):
                            raise ValueError("invalid lifecycle observation")
                        reason = None
                    else:
                        current: object = False if fence_is_current is None else fence_is_current()
                        reason = "lease_lost" if current is False else None
                        if type(current) is not bool:
                            reason = "probe_failed"
                except Exception:
                    phase, reason = "starting", "probe_failed"
                with suppress(queue.Empty):
                    observations.get_nowait()
                with suppress(queue.Full):
                    observations.put_nowait((time.monotonic(), reason, phase, sampled_exit))
                if reason is not None:
                    return
                stopping.wait(0.05)

        self._probe_thread = threading.Thread(target=probe, daemon=True)
        self._probe_thread.start()
        previous_handlers: dict[signal.Signals, Any] = {}
        if threading.current_thread() is threading.main_thread():

            def signal_stop(_sig: int, _frame: FrameType | None) -> None:
                cancelled.set()

            for sig in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, signal_stop)
        death_read, death_write = os.pipe()
        selector = selectors.DefaultSelector()
        reason: str | None = None
        last_probe = started
        child_done: float | None = None
        total_output = 0
        cleanup_done = False

        def terminate_and_reap() -> bool:
            nonlocal cleanup_done
            if cleanup_done:
                return self._cleanup_complete
            cleanup_done = True
            if child is None:
                return True
            self._cleanup = _terminate_owned_child(
                child, deadline=deadline, exit_observed=child_exit_observed.is_set()
            )
            self._cleanup_complete = self._cleanup.complete
            return self._cleanup_complete

        try:
            # Initial Stop/fence failure prevents even starting the worker.
            while True:
                try:
                    last_probe, reason, lifecycle_phase, observed_exit = observations.get(
                        timeout=0.01
                    )
                    if reason is not None:
                        return ContinuousProcessOutcome(
                            "stopped" if reason == "stopped" else "failed", reason
                        )
                    if lifecycle is not None and lifecycle_phase != "starting":
                        return ContinuousProcessOutcome("failed", "lifecycle_invalid")
                    break
                except queue.Empty:
                    if cancelled.is_set():
                        return ContinuousProcessOutcome("stopped", "stopped")
                    if time.monotonic() - started >= _PROBE_AGE:
                        return ContinuousProcessOutcome("failed", "probe_stalled")
            root = Path(__file__).resolve().parents[2]
            command = (
                sys.executable,
                "-B",
                "-m",
                module,
                "--worker",
                "--process-request",
                str(request_path),
                "--process-receipt",
                str(receipt_path),
                "--instance-lock-fd",
                str(lock_fd),
                "--parent-pid",
                str(os.getpid()),
                "--parent-death-fd",
                str(death_read),
            )
            child = subprocess.Popen(
                command,
                cwd=temporary,
                env={
                    "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
                    "PYTHONPATH": str(root),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TZ": "UTC",
                    "LC_ALL": "C",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=(lock_fd, death_read),
                start_new_session=True,
            )
            os.close(death_read)
            death_read = -1
            assert child.stdout is not None and child.stderr is not None
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while reason is None:
                now = time.monotonic()
                if cancelled.is_set():
                    reason = "stopped"
                    break
                with suppress(queue.Empty):
                    last_probe, reason, lifecycle_phase, observed_exit = observations.get_nowait()
                if reason is not None:
                    break
                if now >= work_deadline:
                    reason = "deadline"
                    break
                if now - last_probe > _PROBE_AGE:
                    reason = "probe_stalled"
                    break
                for key, _mask in selector.select(timeout=min(0.05, max(0, work_deadline - now))):
                    chunk = os.read(key.fd, min(4096, request.limits.pipe_bytes + 1 - total_output))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total_output += len(chunk)
                    if total_output > request.limits.pipe_bytes:
                        reason = "output_limit"
                        break
                if reason is not None:
                    break
                if not child_exit_observed.is_set():
                    remaining = work_deadline - time.monotonic()
                    if remaining <= 0:
                        reason = "deadline"
                        break
                    try:
                        observation = _observe_child(child.pid, timeout=min(0.1, remaining))
                    except subprocess.TimeoutExpired:
                        reason = (
                            "deadline"
                            if time.monotonic() >= work_deadline
                            else "child_observation_failed"
                        )
                        break
                    except (OSError, ValueError, subprocess.SubprocessError):
                        reason = "child_observation_failed"
                        break
                    if observation.exited:
                        child_done = time.monotonic()
                        child_exit_observed.set()
                    elif observation.resident_bytes > request.limits.memory_bytes:
                        reason = "memory_limit"
                if child_exit_observed.is_set():
                    # Final signals precede the only reap; no later PID lookup
                    # can replace the original exit observation used by SQL.
                    if not terminate_and_reap():
                        reason = "cleanup_incomplete"
                        break
                    cleanup = self._read_cleanup()
                    assert cleanup is not None
                    if cleanup.returncode != 0:
                        reason = "child_failed"
                        break
                    assert child_done is not None
                    # A post-exit original probe must finish before accepting bytes.
                    if not selector.get_map() and last_probe >= child_done and observed_exit:
                        stopping.set()
                        self._probe_thread.join(
                            timeout=min(0.05, max(0, work_deadline - time.monotonic()))
                        )
                        if self._probe_thread.is_alive():
                            reason = "probe_stalled"
                            break
                        with suppress(queue.Empty):
                            last_probe, reason, lifecycle_phase, observed_exit = (
                                observations.get_nowait()
                            )
                        if reason is not None:
                            break
                        if lifecycle is not None and lifecycle_phase != "released":
                            reason = "lifecycle_incomplete"
                            break
                        payload = _private_read(receipt_path, request.limits.receipt_bytes)
                        if lifecycle is not None:
                            lifecycle.require_result(payload)
                        if time.monotonic() >= work_deadline:
                            reason = "deadline"
                            break
                        installed = self.artifact_directory / (
                            "continuous-receipt-" + uuid4().hex + ".json"
                        )
                        _private_write(installed, payload)
                        if not terminate_and_reap():
                            installed.unlink()
                            return ContinuousProcessOutcome("failed", "cleanup_incomplete")
                        return ContinuousProcessOutcome(
                            "completed",
                            "completed",
                            ContinuousProcessReceiptRef(
                                installed, sha256(payload).hexdigest(), len(payload)
                            ),
                        )
            return ContinuousProcessOutcome(
                "stopped" if reason == "stopped" else "failed", reason or "child_failed"
            )
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            return ContinuousProcessOutcome("failed", "process_failed")
        finally:
            stopping.set()
            if self._probe_thread is not None:
                self._probe_thread.join(timeout=min(0.05, max(0, deadline - time.monotonic())))
            os.close(death_write)
            if death_read >= 0:
                os.close(death_read)
            terminate_and_reap()
            selector.close()
            if child is not None:
                for closing_stream in (child.stdout, child.stderr):
                    if closing_stream is not None:
                        closing_stream.close()
            if temporary is not None:
                for name in (
                    "request.json",
                    "receipt.json",
                    "lifecycle.json",
                    "lease-ready.json",
                    "parent-accepted.json",
                    "result-ready.json",
                    "lease-released.json",
                ):
                    with suppress(OSError):
                        (temporary / name).unlink()
                    with suppress(OSError):
                        (temporary / (name + ".pending")).unlink()
                with suppress(OSError):
                    temporary.rmdir()
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)


class ContinuousWorkerContext:
    """Child lifecycle only; construct the actual account graph after entering.

    The fixed file ceiling contains each write; it grants no storage entitlement
    or total disk quota. The factory must separately preflight the existing
    dedicated SQLite/config/object files and preserve every store's smaller caps.
    """

    def __init__(
        self,
        *,
        process_request: Path,
        process_receipt: Path,
        instance_lock_fd: int,
        parent_pid: int,
        parent_death_fd: int,
    ) -> None:
        _lock_descriptor(instance_lock_fd)
        if type(parent_pid) is not int or parent_pid <= 1 or os.getppid() != parent_pid:
            raise ValueError("continuous worker parent invalid")
        info = os.fstat(parent_death_fd)
        if not stat.S_ISFIFO(info.st_mode) or parent_death_fd == instance_lock_fd:
            raise ValueError("continuous worker parent pipe invalid")
        _private_directory(process_request.parent)
        if process_receipt != process_request.parent / "receipt.json":
            raise ValueError("continuous worker receipt path invalid")
        self.request = _decode(_private_read(process_request, _MAX_REQUEST))
        limits = self.request.limits
        if sys.platform.startswith("linux"):
            resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes,) * 2)
        elif sys.platform != "darwin":
            raise ValueError("continuous worker platform unsupported")
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_FILE_BYTES,) * 2)
        self._receipt = process_receipt
        lock_info = os.fstat(instance_lock_fd)
        self._lock_identity = (lock_info.st_dev, lock_info.st_ino)
        self._cancelled = threading.Event()
        self._closed = threading.Event()
        self._parent_pid = parent_pid
        self._parent_fd = parent_death_fd
        self._deadline = time.monotonic() + limits.wall_seconds - _CLEANUP_RESERVE
        self._handlers: dict[signal.Signals, Any] = {}
        for sig in (signal.SIGTERM, signal.SIGINT):
            self._handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, self._signal)
        os.set_blocking(parent_death_fd, False)
        self._watcher = threading.Thread(target=self._watch_parent, daemon=True)
        self._watcher.start()

    def _signal(self, _sig: int, _frame: FrameType | None) -> None:
        self._cancelled.set()

    def _watch_parent(self) -> None:
        while not self._closed.wait(0.05):
            orphaned = os.getppid() != self._parent_pid
            try:
                orphaned = os.read(self._parent_fd, 1) == b"" or orphaned
            except BlockingIOError:
                pass
            except OSError:
                orphaned = True
            if orphaned or time.monotonic() >= self._deadline:
                self._cancelled.set()
                # Give cooperative SQL work time to roll back, then stop an
                # otherwise stuck reviewed child without relying on a live parent.
                if not self._closed.wait(_TERM_GRACE):
                    os._exit(70)
                return

    @property
    def process_directory(self) -> Path:
        return self._receipt.parent

    @property
    def instance_lock_identity(self) -> tuple[int, int]:
        return self._lock_identity

    @property
    def parent_pid(self) -> int:
        return self._parent_pid

    @property
    def work_deadline_monotonic(self) -> float:
        return self._deadline

    @property
    def stop_event(self) -> threading.Event:
        """Original child cancellation Event; setting it supplies denial only."""
        return self._cancelled

    def stop_requested(self) -> bool:
        if self._cancelled.is_set():
            return True
        if time.monotonic() >= self._deadline:
            self._cancelled.set()
            return True
        return False

    def write_receipt(self, payload: bytes) -> None:
        if (
            self.stop_requested()
            or type(payload) is not bytes
            or not 0 < len(payload) <= self.request.limits.receipt_bytes
        ):
            raise ValueError("continuous worker receipt rejected")
        # macOS has no effective address-space limit; check this child image's
        # final high water as well as the parent's independent RSS sampling.
        if (
            sys.platform == "darwin"
            and resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            > self.request.limits.memory_bytes
        ):
            raise ValueError("continuous worker memory exceeded")
        _private_write(self._receipt, payload)
        if self.stop_requested():
            self._receipt.unlink()
            raise ValueError("continuous worker stopped")

    def __enter__(self) -> ContinuousWorkerContext:
        return self

    def __exit__(self, *_: object) -> None:
        self._closed.set()
        for sig, handler in self._handlers.items():
            signal.signal(sig, handler)


def enter_continuous_worker(
    *,
    process_request: Path,
    process_receipt: Path,
    instance_lock_fd: int,
    parent_pid: int,
    parent_death_fd: int,
) -> ContinuousWorkerContext:
    return ContinuousWorkerContext(
        process_request=process_request,
        process_receipt=process_receipt,
        instance_lock_fd=instance_lock_fd,
        parent_pid=parent_pid,
        parent_death_fd=parent_death_fd,
    )
