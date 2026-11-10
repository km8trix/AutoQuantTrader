"""Process-isolated execution of bounded Phase 3H fixture economics."""

from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import IO, NoReturn, cast

from packages.domain.canonical import canonical_decimal_text, canonical_json_bytes
from packages.domain.feature_target import CertifiedFeatureTargetReplay
from packages.domain.fixture_segment_economics import (
    FIXTURE_ECONOMIC_ADDRESS_SPACE_LIMITS,
    FIXTURE_ECONOMIC_CHILD_PROCESSES,
    FIXTURE_ECONOMIC_CPU_SECONDS,
    FIXTURE_ECONOMIC_FILE_BYTES,
    FIXTURE_ECONOMIC_OPEN_FILES,
    FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
    FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS,
    MAX_FIXTURE_ECONOMIC_REQUEST_BYTES,
    MAX_FIXTURE_ECONOMIC_STDERR_BYTES,
    MAX_FIXTURE_ECONOMIC_STDOUT_BYTES,
    FixtureEconomicPosition,
    FixtureEconomicProcessEvidence,
    FixtureEconomicProcessOutcome,
    FixtureEconomicSegmentError,
    FixtureEconomicSegmentReceipt,
    FixtureEconomicSegmentRequest,
    FixtureEconomicSegmentResult,
    bind_fixture_economic_request,
    fixture_economic_isolation_profile_sha256,
)
from packages.domain.fixture_segment_worker import FixtureSegmentJobProjection

FIXTURE_ECONOMIC_CHILD_RUNTIME_ID = "repository-fixture-economic-child"
FIXTURE_ECONOMIC_CHILD_RUNTIME_VERSION = "1.0.0"
FIXTURE_ECONOMIC_SUBPROCESS_POLL_SECONDS = 0.005
FIXTURE_ECONOMIC_CLEANUP_SECONDS = 1.0
FIXTURE_ECONOMIC_ENVIRONMENT = (
    ("LANG", "C"),
    ("LC_ALL", "C"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONHASHSEED", "0"),
    ("PYTHONIOENCODING", "utf-8"),
    ("PYTHONUTF8", "1"),
    ("TZ", "UTC"),
    ("__CF_USER_TEXT_ENCODING", "0x0:0x0:0x0"),
)


class FixtureEconomicExecutionError(RuntimeError):
    """A closed process/protocol classification with no raw child material."""

    def __init__(self, outcome: FixtureEconomicProcessOutcome) -> None:
        if type(outcome) is not FixtureEconomicProcessOutcome:
            raise TypeError("economic execution outcome must be exact")
        self.outcome = outcome
        super().__init__(f"bounded fixture economic execution failed: {outcome.value}")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _plain_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _utc_text(value: object) -> str:
    from datetime import datetime

    if type(value) is not datetime:
        raise FixtureEconomicSegmentError("economic protocol time must be exact")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _request_payload(request: FixtureEconomicSegmentRequest) -> dict[str, object]:
    return {
        "attempt_id": request.attempt_id,
        "completion_receipt_sha256": request.completion_receipt_sha256,
        "configuration_sha256": request.configuration_sha256,
        "family_id": request.family_id,
        "job_id": request.job_id,
        "model_version": request.model_version,
        "request_semantic_sha256": request.semantic_sha256,
        "rows": [
            {
                "as_of": _utc_text(row.as_of),
                "instruments": [
                    {
                        "close_price": canonical_decimal_text(item.close_price),
                        "instrument_id": item.instrument_id,
                        "symbol": item.symbol,
                        "target_quantity": (
                            None
                            if item.target_quantity is None
                            else canonical_decimal_text(item.target_quantity)
                        ),
                    }
                    for item in row.instruments
                ],
                "sequence": row.sequence,
                "source_batch_sha256": row.source_batch_sha256,
                "target_id": row.target_id,
            }
            for row in request.rows
        ],
        "segment_kind": request.segment_kind,
        "segment_sha256": request.segment_sha256,
        "starting_cash": canonical_decimal_text(request.starting_cash),
        "target_artifact_sha256": request.target_artifact_sha256,
        "target_certification_sha256": request.target_certification_sha256,
        "target_transcript_sha256": request.target_transcript_sha256,
    }


def encode_fixture_economic_request(
    request: FixtureEconomicSegmentRequest,
) -> tuple[bytes, str]:
    if type(request) is not FixtureEconomicSegmentRequest:
        raise FixtureEconomicSegmentError("economic protocol requires an exact request")
    request.__post_init__()
    payload = _request_payload(request)
    payload_sha256 = _sha256_bytes(_plain_json_bytes(payload))
    encoded = _plain_json_bytes(
        {
            "contract_version": FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
            "request": payload,
            "request_payload_sha256": payload_sha256,
        }
    )
    if len(encoded) > MAX_FIXTURE_ECONOMIC_REQUEST_BYTES:
        raise FixtureEconomicSegmentError("economic protocol request exceeds its byte bound")
    return encoded, payload_sha256


def _reject_json_number(_value: str) -> NoReturn:
    raise FixtureEconomicSegmentError("economic response cannot contain a JSON float")


def _reject_json_constant(_value: str) -> NoReturn:
    raise FixtureEconomicSegmentError("economic response cannot contain a JSON constant")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureEconomicSegmentError("economic response contains a duplicate key")
        result[key] = value
    return result


def _decimal_text(value: object, field_name: str) -> Decimal:
    if type(value) is not str:
        raise FixtureEconomicSegmentError(f"{field_name} must be an exact Decimal string")
    try:
        parsed = Decimal(value)
    except (ArithmeticError, ValueError) as error:
        raise FixtureEconomicSegmentError(f"{field_name} is malformed") from error
    if not parsed.is_finite() or canonical_decimal_text(parsed) != value:
        raise FixtureEconomicSegmentError(f"{field_name} is not canonical")
    return parsed


def decode_fixture_economic_response(
    payload: bytes,
    *,
    request: FixtureEconomicSegmentRequest,
    request_payload_sha256: str,
) -> FixtureEconomicSegmentResult:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_FIXTURE_ECONOMIC_STDOUT_BYTES
    ):
        raise FixtureEconomicSegmentError("economic response is outside its byte bound")
    if type(request) is not FixtureEconomicSegmentRequest:
        raise FixtureEconomicSegmentError("economic response requires an exact request")
    body = payload[:-1] if payload.endswith(b"\n") else payload
    try:
        text = body.decode("utf-8", errors="strict")
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_constant,
        )
    except FixtureEconomicSegmentError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise FixtureEconomicSegmentError(
            "economic response is not canonical UTF-8 JSON"
        ) from error
    if _plain_json_bytes(decoded) != body:
        raise FixtureEconomicSegmentError("economic response is not canonical JSON")
    if type(decoded) is not dict or set(decoded) != {
        "contract_version",
        "isolation",
        "request_payload_sha256",
        "result",
    }:
        raise FixtureEconomicSegmentError("economic response envelope is unsupported")
    if decoded["contract_version"] != FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION:
        raise FixtureEconomicSegmentError("economic response contract version is unsupported")
    if decoded["request_payload_sha256"] != request_payload_sha256:
        raise FixtureEconomicSegmentError("economic response belongs to another request payload")
    isolation = decoded["isolation"]
    if type(isolation) is not dict or set(isolation) != {
        "environment",
        "limits",
        "process_id",
        "session_id",
    }:
        raise FixtureEconomicSegmentError("economic child isolation evidence is unsupported")
    if isolation["environment"] != [list(item) for item in FIXTURE_ECONOMIC_ENVIRONMENT]:
        raise FixtureEconomicSegmentError("economic child inherited unsupported environment")
    try:
        address_space_bytes = dict(FIXTURE_ECONOMIC_ADDRESS_SPACE_LIMITS)[sys.platform]
    except KeyError as error:
        raise FixtureEconomicSegmentError("economic child platform is unsupported") from error
    if isolation["limits"] != {
        "address_space_bytes": address_space_bytes,
        "child_processes": FIXTURE_ECONOMIC_CHILD_PROCESSES,
        "core_bytes": 0,
        "cpu_seconds": FIXTURE_ECONOMIC_CPU_SECONDS,
        "file_bytes": FIXTURE_ECONOMIC_FILE_BYTES,
        "open_files": FIXTURE_ECONOMIC_OPEN_FILES,
    }:
        raise FixtureEconomicSegmentError("economic child resource limits are unsupported")
    process_id = isolation["process_id"]
    session_id = isolation["session_id"]
    if (
        type(process_id) is not int
        or type(session_id) is not int
        or process_id <= 1
        or session_id != process_id
        or process_id == os.getpid()
        or session_id == os.getsid(0)
    ):
        raise FixtureEconomicSegmentError("economic child lacks independent process/session")
    result = decoded["result"]
    if type(result) is not dict or set(result) != {
        "ending_cash",
        "ending_equity",
        "ending_market_value",
        "filled_target_count",
        "gross_traded_notional",
        "net_pnl",
        "positions",
        "request_semantic_sha256",
        "trade_count",
    }:
        raise FixtureEconomicSegmentError("economic result shape is unsupported")
    if result["request_semantic_sha256"] != request.semantic_sha256:
        raise FixtureEconomicSegmentError("economic result belongs to another request")
    positions_raw = result["positions"]
    if type(positions_raw) is not list:
        raise FixtureEconomicSegmentError("economic result positions must be a JSON array")
    positions: list[FixtureEconomicPosition] = []
    for raw in cast(list[object], positions_raw):
        if type(raw) is not dict or set(raw) != {
            "instrument_id",
            "mark_price",
            "market_value",
            "quantity",
            "symbol",
        }:
            raise FixtureEconomicSegmentError("economic result position shape is unsupported")
        item = cast(Mapping[str, object], raw)
        if type(item["instrument_id"]) is not str or type(item["symbol"]) is not str:
            raise FixtureEconomicSegmentError("economic result position identity is malformed")
        positions.append(
            FixtureEconomicPosition(
                instrument_id=item["instrument_id"],
                symbol=item["symbol"],
                quantity=_decimal_text(item["quantity"], "economic result quantity"),
                mark_price=_decimal_text(item["mark_price"], "economic result mark price"),
                market_value=_decimal_text(item["market_value"], "economic result market value"),
            )
        )
    for field_name in ("trade_count", "filled_target_count"):
        if type(result[field_name]) is not int:
            raise FixtureEconomicSegmentError(f"economic result {field_name} must be an integer")
    return FixtureEconomicSegmentResult(
        request_sha256=request.semantic_sha256,
        ending_cash=_decimal_text(result["ending_cash"], "economic result ending cash"),
        ending_market_value=_decimal_text(
            result["ending_market_value"], "economic result ending market value"
        ),
        ending_equity=_decimal_text(result["ending_equity"], "economic result ending equity"),
        net_pnl=_decimal_text(result["net_pnl"], "economic result net P&L"),
        gross_traded_notional=_decimal_text(
            result["gross_traded_notional"], "economic result gross traded notional"
        ),
        trade_count=cast(int, result["trade_count"]),
        filled_target_count=cast(int, result["filled_target_count"]),
        positions=tuple(positions),
    )


@dataclass(slots=True)
class _BoundedCapture:
    limit: int
    value: bytearray = field(default_factory=bytearray)
    exceeded: threading.Event = field(default_factory=threading.Event)
    failed: threading.Event = field(default_factory=threading.Event)

    def read(self, stream: IO[bytes]) -> None:
        try:
            while True:
                chunk = stream.read(8_192)
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
            with suppress(OSError):
                stream.close()


def _write_request(stream: IO[bytes], request: bytes, failed: threading.Event) -> None:
    try:
        stream.write(request)
        stream.flush()
    except BrokenPipeError:
        pass
    except (OSError, ValueError):
        failed.set()
    finally:
        with suppress(OSError):
            stream.close()


@dataclass(frozen=True, slots=True)
class _RawProcessObservation:
    outcome: FixtureEconomicProcessOutcome
    process_started: bool
    exit_code: int | None
    elapsed_microseconds: int
    stdout: bytes
    stderr: bytes
    runtime_artifact_sha256: str
    launch_spec_sha256: str


def _required_descriptor_flags() -> tuple[int, int]:
    close_on_exec = getattr(os, "O_CLOEXEC", None)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if (
        type(close_on_exec) is not int
        or close_on_exec <= 0
        or type(no_follow) is not int
        or no_follow <= 0
    ):
        raise RuntimeError("required descriptor isolation flags are unavailable")
    return close_on_exec, no_follow


def _same_regular_file_projection(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISREG(left.st_mode)
        and stat.S_ISREG(right.st_mode)
        and left.st_ino == right.st_ino
        and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
        and left.st_uid == right.st_uid
        and left.st_gid == right.st_gid
        and left.st_size == right.st_size
        and left.st_nlink == right.st_nlink
    )


def _same_regular_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and _same_regular_file_projection(left, right)


def _read_descriptor_bytes(descriptor: int, maximum: int) -> bytes:
    value = bytearray()
    while len(value) <= maximum:
        chunk = os.read(descriptor, min(8_192, maximum + 1 - len(value)))
        if not chunk:
            break
        value.extend(chunk)
    if not value or len(value) > maximum:
        raise RuntimeError("fixed child source is outside its byte bound")
    return bytes(value)


def _resolved_python_executable() -> str:
    if sys.implementation.name != "cpython" or type(sys.base_prefix) is not str:
        raise RuntimeError("Python runtime identity is unsupported")
    candidate = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    if not candidate.is_absolute():
        raise RuntimeError("Python executable must be absolute")
    try:
        executable = candidate.resolve(strict=True)
        metadata = executable.stat()
    except OSError:
        raise RuntimeError("Python executable is unsupported") from None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
        raise RuntimeError("Python executable is unsupported")
    return str(executable)


def _read_fixed_child_source() -> bytes:
    close_on_exec, no_follow = _required_descriptor_flags()
    application = Path(__file__).resolve(strict=True)
    child = application.with_name("_fixture_segment_economic_child.py")
    metadata = child.lstat()
    descriptor = -1
    try:
        descriptor = os.open(child, os.O_RDONLY | close_on_exec | no_follow)
        opened = os.fstat(descriptor)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not _same_regular_file(metadata, opened)
            or metadata.st_nlink != 1
            or os.get_inheritable(descriptor)
        ):
            raise RuntimeError("fixed child source identity is unsupported")
        return _read_descriptor_bytes(descriptor, 131_072)
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _verified_dev_fd_script(
    descriptor: int,
    expected: os.stat_result,
) -> str:
    close_on_exec, _no_follow = _required_descriptor_flags()
    if sys.platform not in {"darwin", "linux"}:
        raise RuntimeError("/dev/fd execution is unsupported on this platform")
    descriptor_root = "/dev/fd"
    root_metadata = os.stat(descriptor_root, follow_symlinks=True)
    script = f"{descriptor_root}/{descriptor}"
    script_metadata = os.stat(script, follow_symlinks=True)
    verification_descriptor = -1
    try:
        verification_descriptor = os.open(script, os.O_RDONLY | close_on_exec)
        verification_metadata = os.fstat(verification_descriptor)
        if not _same_regular_file(expected, verification_metadata) or os.get_inheritable(
            verification_descriptor
        ):
            raise RuntimeError("/dev/fd opened a different child snapshot")
    finally:
        if verification_descriptor >= 0:
            with suppress(OSError):
                os.close(verification_descriptor)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or not _same_regular_file_projection(expected, script_metadata)
        or not _same_regular_file(expected, os.fstat(descriptor))
        or os.get_inheritable(descriptor)
        or os.lseek(descriptor, 0, os.SEEK_SET) != 0
    ):
        raise RuntimeError("/dev/fd does not preserve the child snapshot identity")
    return script


def _snapshot_child_source(
    working_directory: str,
    source: bytes,
) -> tuple[int, str, str]:
    close_on_exec, no_follow = _required_descriptor_flags()
    directory_metadata = os.lstat(working_directory)
    if (
        stat.S_ISLNK(directory_metadata.st_mode)
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        or directory_metadata.st_uid != os.getuid()
    ):
        raise RuntimeError("private child snapshot directory is unsupported")
    snapshot = Path(working_directory) / ".fixture-economic-child.py"
    writable = -1
    readable = -1
    try:
        writable = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | close_on_exec | no_follow,
            stat.S_IRUSR,
        )
        offset = 0
        while offset < len(source):
            written = os.write(writable, source[offset:])
            if written <= 0:
                raise RuntimeError("fixed child snapshot write was incomplete")
            offset += written
        os.fsync(writable)
        os.fchmod(writable, stat.S_IRUSR)
        writable_metadata = os.fstat(writable)
        readable = os.open(snapshot, os.O_RDONLY | close_on_exec | no_follow)
        readable_metadata = os.fstat(readable)
        os.close(writable)
        writable = -1
        path_metadata = snapshot.lstat()
        if (
            not _same_regular_file(writable_metadata, readable_metadata)
            or not _same_regular_file(readable_metadata, path_metadata)
            or stat.S_IMODE(readable_metadata.st_mode) != stat.S_IRUSR
            or readable_metadata.st_nlink != 1
            or readable_metadata.st_uid != os.getuid()
            or os.get_inheritable(readable)
        ):
            raise RuntimeError("fixed child snapshot identity is unsupported")
        readback = _read_descriptor_bytes(readable, 131_072)
        if readback != source or len(readback) != readable_metadata.st_size:
            raise RuntimeError("fixed child snapshot readback differs")
        runtime_artifact_sha256 = _sha256_bytes(readback)
        if os.lseek(readable, 0, os.SEEK_SET) != 0:
            raise RuntimeError("fixed child snapshot offset could not be reset")
        snapshot.unlink()
        unlinked_metadata = os.fstat(readable)
        if unlinked_metadata.st_nlink != 0:
            raise RuntimeError("fixed child snapshot remained path-addressable")
        script = _verified_dev_fd_script(readable, unlinked_metadata)
        return readable, script, runtime_artifact_sha256
    except BaseException:
        if readable >= 0:
            with suppress(OSError):
                os.close(readable)
        raise
    finally:
        if writable >= 0:
            with suppress(OSError):
                os.close(writable)
        with suppress(FileNotFoundError):
            snapshot.unlink()


def _launch_spec_sha256(
    executable: str,
    child_script: str,
    runtime_artifact_sha256: str,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            (
                FIXTURE_ECONOMIC_SEGMENT_CONTRACT_VERSION,
                "economic-launch-spec",
                FIXTURE_ECONOMIC_CHILD_RUNTIME_ID,
                FIXTURE_ECONOMIC_CHILD_RUNTIME_VERSION,
                runtime_artifact_sha256,
                executable,
                ("-I", "-S", "-B", child_script),
                ("pass-fds", "one-read-only-unlinked-child-snapshot"),
                FIXTURE_ECONOMIC_ENVIRONMENT,
                fixture_economic_isolation_profile_sha256(),
            )
        )
    ).hexdigest()


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


def _force_reap(
    process: subprocess.Popen[bytes],
    threads: tuple[threading.Thread, ...],
) -> None:
    """Best-effort bounded cleanup used on every exceptional child path."""

    _kill_process_group(process)
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=FIXTURE_ECONOMIC_CLEANUP_SECONDS)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            with suppress(OSError):
                stream.close()
    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=FIXTURE_ECONOMIC_CLEANUP_SECONDS)


def _run_fixture_economic_child(request: bytes) -> _RawProcessObservation:
    if os.name != "posix" or type(request) is not bytes:
        raise FixtureEconomicExecutionError(FixtureEconomicProcessOutcome.SPAWN_FAILED)
    failed_outcome: FixtureEconomicProcessOutcome | None = None
    observation: _RawProcessObservation | None = None
    try:
        executable = _resolved_python_executable()
        source = _read_fixed_child_source()
        started = time.monotonic()
        if not math.isfinite(started):
            raise RuntimeError("economic supervisor clock is unsupported")
        with tempfile.TemporaryDirectory(prefix="autoquant-phase3h-") as working_directory:
            child_descriptor = -1
            try:
                child_descriptor, child_script, runtime_sha256 = _snapshot_child_source(
                    working_directory,
                    source,
                )
                launch_sha256 = _launch_spec_sha256(
                    executable,
                    child_script,
                    runtime_sha256,
                )
                process = subprocess.Popen(
                    (executable, "-I", "-S", "-B", child_script),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    close_fds=True,
                    pass_fds=(child_descriptor,),
                    start_new_session=True,
                    cwd=working_directory,
                    env=dict(FIXTURE_ECONOMIC_ENVIRONMENT),
                    bufsize=0,
                )
            finally:
                if child_descriptor >= 0:
                    with suppress(OSError):
                        os.close(child_descriptor)
            started_threads: list[threading.Thread] = []
            try:
                if process.stdin is None or process.stdout is None or process.stderr is None:
                    raise FixtureEconomicExecutionError(FixtureEconomicProcessOutcome.SPAWN_FAILED)
                stdout = _BoundedCapture(MAX_FIXTURE_ECONOMIC_STDOUT_BYTES)
                stderr = _BoundedCapture(MAX_FIXTURE_ECONOMIC_STDERR_BYTES)
                write_failed = threading.Event()
                threads = (
                    threading.Thread(
                        target=_write_request,
                        args=(process.stdin, request, write_failed),
                        name=f"fixture-economic-stdin-{process.pid}",
                        daemon=True,
                    ),
                    threading.Thread(
                        target=stdout.read,
                        args=(process.stdout,),
                        name=f"fixture-economic-stdout-{process.pid}",
                        daemon=True,
                    ),
                    threading.Thread(
                        target=stderr.read,
                        args=(process.stderr,),
                        name=f"fixture-economic-stderr-{process.pid}",
                        daemon=True,
                    ),
                )
                for thread in threads:
                    thread.start()
                    started_threads.append(thread)
                outcome: FixtureEconomicProcessOutcome | None = None
                deadline = started + FIXTURE_ECONOMIC_WALL_TIMEOUT_MILLISECONDS / 1_000
                while process.poll() is None:
                    current = time.monotonic()
                    if not math.isfinite(current) or current < started:
                        outcome = FixtureEconomicProcessOutcome.CRASHED
                        break
                    if current >= deadline:
                        outcome = FixtureEconomicProcessOutcome.TIMEOUT
                        break
                    if stdout.exceeded.is_set() or stderr.exceeded.is_set():
                        outcome = FixtureEconomicProcessOutcome.RESOURCE_EXCEEDED
                        break
                    if stdout.failed.is_set() or stderr.failed.is_set() or write_failed.is_set():
                        outcome = FixtureEconomicProcessOutcome.CRASHED
                        break
                    time.sleep(FIXTURE_ECONOMIC_SUBPROCESS_POLL_SECONDS)
                if outcome is not None:
                    _kill_process_group(process)
                try:
                    process.wait(timeout=FIXTURE_ECONOMIC_CLEANUP_SECONDS)
                except subprocess.TimeoutExpired:
                    _force_reap(process, tuple(started_threads))
                    outcome = outcome or FixtureEconomicProcessOutcome.CRASHED
                for thread in started_threads:
                    thread.join(timeout=FIXTURE_ECONOMIC_CLEANUP_SECONDS)
                if any(thread.is_alive() for thread in started_threads):
                    _force_reap(process, tuple(started_threads))
                    outcome = FixtureEconomicProcessOutcome.CRASHED
                if outcome is None:
                    if stdout.exceeded.is_set() or stderr.exceeded.is_set():
                        outcome = FixtureEconomicProcessOutcome.RESOURCE_EXCEEDED
                    elif (
                        stdout.failed.is_set()
                        or stderr.failed.is_set()
                        or write_failed.is_set()
                        or process.returncode != 0
                    ):
                        outcome = FixtureEconomicProcessOutcome.CRASHED
                    else:
                        outcome = FixtureEconomicProcessOutcome.COMPLETED
                completed = time.monotonic()
                elapsed = max(0, int((completed - started) * 1_000_000))
                observation = _RawProcessObservation(
                    outcome=outcome,
                    process_started=True,
                    exit_code=process.returncode,
                    elapsed_microseconds=elapsed,
                    stdout=bytes(stdout.value),
                    stderr=bytes(stderr.value),
                    runtime_artifact_sha256=runtime_sha256,
                    launch_spec_sha256=launch_sha256,
                )
            except BaseException:
                _force_reap(process, tuple(started_threads))
                raise
    except FixtureEconomicExecutionError as error:
        failed_outcome = error.outcome
    except Exception:
        failed_outcome = FixtureEconomicProcessOutcome.SPAWN_FAILED
    if failed_outcome is not None:
        raise FixtureEconomicExecutionError(failed_outcome)
    if observation is None:
        raise FixtureEconomicExecutionError(FixtureEconomicProcessOutcome.SPAWN_FAILED)
    return observation


def execute_fixture_segment_economics(
    projection: FixtureSegmentJobProjection,
    certification: CertifiedFeatureTargetReplay,
) -> FixtureEconomicSegmentReceipt:
    """Execute one exact completed fixture transcript in the fixed child."""

    request = bind_fixture_economic_request(projection, certification)
    encoded, request_payload_sha256 = encode_fixture_economic_request(request)
    observation = _run_fixture_economic_child(encoded)
    if observation.outcome is not FixtureEconomicProcessOutcome.COMPLETED:
        raise FixtureEconomicExecutionError(observation.outcome)
    if (
        observation.process_started is not True
        or observation.exit_code != 0
        or observation.stderr
        or not observation.stdout
    ):
        raise FixtureEconomicExecutionError(FixtureEconomicProcessOutcome.CRASHED)
    receipt: FixtureEconomicSegmentReceipt | None = None
    protocol_failed = False
    try:
        result = decode_fixture_economic_response(
            observation.stdout,
            request=request,
            request_payload_sha256=request_payload_sha256,
        )
        process = FixtureEconomicProcessEvidence._from_supervisor(
            runtime_artifact_sha256=observation.runtime_artifact_sha256,
            launch_spec_sha256=observation.launch_spec_sha256,
            request_bytes=len(encoded),
            request_payload_sha256=request_payload_sha256,
            stdout_bytes=len(observation.stdout),
            stdout_sha256=_sha256_bytes(observation.stdout),
            stderr_bytes=0,
            stderr_sha256=_sha256_bytes(b""),
            elapsed_microseconds=observation.elapsed_microseconds,
        )
        receipt = FixtureEconomicSegmentReceipt._from_verified_execution(
            request,
            result,
            process,
        )
    except FixtureEconomicSegmentError:
        protocol_failed = True
    if protocol_failed or receipt is None:
        raise FixtureEconomicExecutionError(FixtureEconomicProcessOutcome.PROTOCOL_ERROR)
    return receipt


__all__ = [
    "FIXTURE_ECONOMIC_CHILD_RUNTIME_ID",
    "FIXTURE_ECONOMIC_CHILD_RUNTIME_VERSION",
    "FIXTURE_ECONOMIC_ENVIRONMENT",
    "FixtureEconomicExecutionError",
    "decode_fixture_economic_response",
    "encode_fixture_economic_request",
    "execute_fixture_segment_economics",
]
