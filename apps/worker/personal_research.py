"""Run a bounded offline historical simulation from an explicit dataset or fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import fields, is_dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from types import FrameType
from uuid import uuid4

from packages.adapters.personal_build import current_build_pins
from packages.application.personal_codec import decode_record, encode_record
from packages.application.personal_inputs import research_engine_inputs, synthetic_engine_inputs
from packages.application.personal_runtime import DuplicateRuntimeError, LocalInstanceGuard
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.research_dataset import research_dataset_from_json_bytes
from packages.domain.accounting_contracts import SettlementCalendar
from packages.domain.daily_reference import ReferenceConfiguration
from packages.domain.engine_contracts import EngineInputs, EvaluationSpec, RunSpec
from packages.domain.personal_contracts import content_digest
from packages.domain.report_contracts import ReportArtifact, ReportConventions
from packages.domain.research_job_contracts import (
    MAX_EXECUTION_METADATA_BYTES,
    MAX_PUBLICATION_BYTES,
    ObjectRef,
    ResearchPublication,
    RetainedResearchExecutionRequest,
)

_MAX_ARCHIVE = 64 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture", choices=("flat", "regime"), help="labelled engineering prices")
    source.add_argument(
        "--dataset", type=Path, help="previously imported personal research archive"
    )
    source.add_argument("--_inputs", type=Path, help=argparse.SUPPRESS)
    source.add_argument("--_request", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_artifact-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_publication", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_progress", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_conventions", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_attempt-id", help=argparse.SUPPRESS)
    parser.add_argument(
        "--settlement-calendar",
        type=Path,
        help="explicit business-date JSON, required for an archive",
    )
    parser.add_argument("--strategy", choices=("buy_hold", "trend_sma"), default="buy_hold")
    parser.add_argument("--lookback", type=int, default=200)
    parser.add_argument(
        "--allocation",
        type=Decimal,
        help="per-instrument fraction; default 0.25, or 0.2375 for four instruments",
    )
    parser.add_argument("--rebalance-sessions", type=int)
    parser.add_argument("--warmup", type=int, default=252)
    parser.add_argument("--fixture-sessions", type=int, default=520)
    parser.add_argument("--initial-cash", type=Decimal, default=Decimal("10000"))
    parser.add_argument("--slippage-bps", type=Decimal, default=Decimal("5"))
    parser.add_argument("--fee-per-share", type=Decimal, default=Decimal("0.01"))
    parser.add_argument("--max-seconds", type=int, default=1800)
    parser.add_argument("--max-events", type=int, default=100000)
    parser.add_argument("--max-output-mib", type=int, default=1024)
    parser.add_argument("--max-memory-mib", type=int, default=4096)
    parser.add_argument(
        "--output", type=Path, required=True, help="new report JSON path; never overwritten"
    )
    parser.add_argument("--_child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--_expected-build-sha", help=argparse.SUPPRESS)
    parser.add_argument("--_lock-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--_parent-pid", type=int, help=argparse.SUPPRESS)
    return parser


def _bounded_read(path: Path, maximum: int) -> bytes:
    if path.is_symlink():
        raise ValueError("input must be an explicit regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("input must be an explicit regular file")
        payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise ValueError("input exceeds its byte limit")
    return payload


def _calendar(path: Path) -> SettlementCalendar:
    value = json.loads(_bounded_read(path, 1024 * 1024))
    if type(value) is not dict or set(value) != {
        "calendar_id",
        "version",
        "business_dates",
        "timezone",
    }:
        raise ValueError("invalid settlement calendar fields")
    if type(value["business_dates"]) is not list or len(value["business_dates"]) > 10000:
        raise ValueError("invalid settlement date list")
    return SettlementCalendar(
        value["calendar_id"],
        value["version"],
        tuple(date.fromisoformat(day) for day in value["business_dates"]),
        value["timezone"],
    )


def _make_inputs(args: argparse.Namespace) -> EngineInputs:
    if args._inputs is not None:
        inputs = decode_record(_bounded_read(args._inputs, 32 * 1024 * 1024), EngineInputs)
        _check_retained_limits(args, inputs.spec)
        return inputs
    allocation = args.allocation if args.allocation is not None else Decimal("0.25")
    configuration = ReferenceConfiguration(
        args.strategy, args.lookback, allocation, args.rebalance_sessions
    )
    pins = current_build_pins()
    common = {
        "configuration": configuration,
        "pins": pins,
        "initial_cash": args.initial_cash,
        "slippage_bps": args.slippage_bps,
        "fee_per_share": args.fee_per_share,
    }
    if args.fixture:
        inputs = synthetic_engine_inputs(
            fixture=args.fixture,
            session_count=args.fixture_sessions,
            warmup_count=args.warmup,
            **common,
        )
    else:
        if args.settlement_calendar is None:
            raise ValueError("an imported archive requires an explicit settlement calendar")
        dataset = research_dataset_from_json_bytes(_bounded_read(args.dataset, _MAX_ARCHIVE))
        if args.allocation is None and len(dataset.manifest.instruments) == 4:
            common["configuration"] = replace(configuration, allocation=Decimal("0.2375"))
        sessions = tuple(session.session_label for session in dataset.manifest.calendar.sessions)
        if not 0 <= args.warmup < len(sessions) - 1:
            raise ValueError("warmup must leave a scored session and a final calendar horizon")
        evaluation = EvaluationSpec(
            "explicit-archive-evaluation",
            sessions[: args.warmup],
            sessions[args.warmup : -1],
            "exploratory-owner-accessed-final-session-is-calendar-horizon",
        )
        inputs = research_engine_inputs(
            dataset,
            evaluation=evaluation,
            settlement_calendar=_calendar(args.settlement_calendar),
            **common,
        )
        inputs = replace(
            inputs,
            spec=replace(
                inputs.spec,
                limitations=tuple(
                    sorted(
                        {
                            *inputs.spec.limitations,
                            "last-archive-session-reserved-as-calendar-horizon",
                        }
                    )
                ),
            ),
        )
    return replace(
        inputs,
        spec=replace(
            inputs.spec,
            limitations=tuple(
                sorted(
                    {
                        *inputs.spec.limitations,
                        "resident-memory-sampled-100ms-plus-final-high-water-check-v1",
                    }
                )
            ),
            max_events=args.max_events,
            max_wall_seconds=args.max_seconds,
            max_memory_bytes=args.max_memory_mib * 1024 * 1024,
            max_cpu_cores=1,
            max_output_bytes=args.max_output_mib * 1024 * 1024,
        ),
    )


def report_json_value(value: object) -> object:
    """Readable deterministic artifact values; no lossy floating-point conversion."""
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: report_json_value(getattr(value, field.name)) for field in fields(value)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("artifact cannot contain nonfinite money")
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, tuple):
        return [report_json_value(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    raise ValueError("unsupported report artifact value")


def _write_report(path: Path, value: object, limit: int) -> None:
    encoder = json.JSONEncoder(
        sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as stream:
            for part in encoder.iterencode(report_json_value(value)):
                encoded = part.encode("utf-8")
                written += len(encoded)
                if written + 1 > limit:
                    raise ValueError("report exceeds output ceiling")
                stream.write(encoded)
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_record(path: Path, value: object, limit: int) -> None:
    payload = encode_record(value)
    _write_payload(path, payload, limit)


def _write_payload(path: Path, payload: bytes, limit: int) -> None:
    if len(payload) > limit:
        raise ValueError("typed artifact exceeds output ceiling")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _matches_spec_build(spec: RunSpec) -> bool:
    expected = current_build_pins()
    selected = {pin.name: pin for pin in spec.pins}
    return all(selected.get(pin.name) == pin for pin in expected)


def _matches_build(inputs: EngineInputs) -> bool:
    return _matches_spec_build(inputs.spec)


def _check_retained_limits(args: argparse.Namespace, spec: RunSpec) -> None:
    if (
        spec.max_events != args.max_events
        or spec.max_wall_seconds != args.max_seconds
        or spec.max_memory_bytes != args.max_memory_mib * 1024 * 1024
        or spec.max_output_bytes != args.max_output_mib * 1024 * 1024
        or spec.max_output_bytes > 64 * 1024 * 1024
        or spec.max_cpu_cores != 1
    ):
        raise ValueError("supervised limits differ from immutable inputs")


def _child_progress(args: argparse.Namespace, stage: str) -> None:
    if args._progress is None:
        return
    temporary = args._progress.with_name(".progress-" + uuid4().hex)
    try:
        _write_payload(temporary, stage.encode("ascii"), 64)
        os.replace(temporary, args._progress)
    finally:
        temporary.unlink(missing_ok=True)


def _resolve_retained(
    args: argparse.Namespace,
) -> tuple[RetainedResearchExecutionRequest, EngineInputs]:
    from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
    from packages.application.research_catalog import StoredResearchInputResolver

    if args._artifact_root is None or args._publication is None or args._progress is None:
        raise ValueError("retained execution requires its private artifacts and observation files")
    execution = decode_record(
        _bounded_read(args._request, MAX_EXECUTION_METADATA_BYTES),
        RetainedResearchExecutionRequest,
    )
    _check_retained_limits(args, execution.request.spec)
    if args._attempt_id != execution.claim.attempt_id or not _matches_spec_build(
        execution.request.spec
    ):
        raise ValueError("retained execution differs from its attempt or current build")
    inputs = StoredResearchInputResolver(LocalResearchArtifactStore(args._artifact_root)).resolve(
        execution.request
    )
    return execution, inputs


def _validated_artifact_payload(artifact: ReportArtifact, limit: int) -> bytes:
    """Validate the actual report graph inside the supervised memory/wall boundary."""
    payload = encode_record(artifact)
    if len(payload) > limit:
        raise ValueError("typed artifact exceeds output ceiling")
    if decode_record(payload, ReportArtifact) != artifact:
        raise ValueError("actual report codec round-trip differs")
    return payload


def _child(args: argparse.Namespace) -> int:
    # This is a bounded process for reviewed reference code, not a hostile-code sandbox.
    if args._lock_fd is None or args._parent_pid is None:
        raise ValueError("research child requires its supervised instance lock")
    lock_info = os.fstat(args._lock_fd)
    if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid():
        raise ValueError("invalid inherited research instance lock")
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (args.max_memory_mib * 1024 * 1024,) * 2)
    elif sys.platform != "darwin":
        raise ValueError("unsupported process resource platform")
    resource.setrlimit(resource.RLIMIT_CPU, (args.max_seconds, args.max_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (args.max_output_mib * 1024 * 1024,) * 2)
    cancelled = threading.Event()

    def cancel(_signum: int, _frame: FrameType | None) -> None:
        cancelled.set()

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)

    def stop_requested() -> bool:
        return cancelled.is_set() or os.getppid() != args._parent_pid

    if (
        args._expected_build_sha is None
        or content_digest(current_build_pins()) != args._expected_build_sha
    ):
        raise ValueError("implementation differs from the supervised source snapshot")
    _child_progress(args, "loading")
    retained = None
    if args._request is not None:
        retained, inputs = _resolve_retained(args)
    else:
        inputs = _make_inputs(args)
    if not _matches_build(inputs):
        raise ValueError("implementation changed while constructing historical inputs")
    # Imports remain explicit; none reaches a provider, account configuration or database.
    from packages.application.causal_engine import run_causal_engine
    from packages.application.run_report import build_report_artifact, build_run_report
    from packages.backtest.personal_accounting import PersonalAccounting

    strategy = ReferenceStrategy(
        reserve_fraction=inputs.spec.risk_policy.adverse_reserve_fraction,
        fee_per_share=inputs.spec.execution_policy.fee_per_share,
    )
    _child_progress(args, "running")
    result = run_causal_engine(
        inputs, accounting=PersonalAccounting(), strategy=strategy, stop_requested=stop_requested
    )
    if not _matches_build(inputs):
        raise ValueError("implementation changed during the historical run")
    _child_progress(args, "validating")
    conventions = (
        retained.request.conventions
        if retained is not None
        else (
            ReportConventions()
            if args._conventions is None
            else decode_record(_bounded_read(args._conventions, 1024 * 1024), ReportConventions)
        )
    )
    report = build_run_report(result, conventions)
    artifact = build_report_artifact(
        report,
        attempt_id=args._attempt_id or "attempt-" + uuid4().hex,
        generated_at=datetime.now(UTC),
    )
    if stop_requested():
        return 3
    _check_peak_memory(args.max_memory_mib * 1024 * 1024)
    publication = None
    if retained is not None:
        payload = _validated_artifact_payload(artifact, inputs.spec.max_output_bytes)
        if not _matches_build(inputs):
            raise ValueError("implementation changed during report validation")
        publication = ResearchPublication(
            retained.request.job_id,
            retained.request.run_id,
            retained.claim.attempt_id,
            report.status,
            result.semantic_sha256,
            report.semantic_sha256,
            artifact.semantic_sha256,
            ObjectRef(hashlib.sha256(payload).hexdigest(), len(payload)),
        )
        _child_progress(args, "publishing")
        _write_payload(args.output, payload, inputs.spec.max_output_bytes)
    else:
        writer = _write_record if args._inputs is not None else _write_report
        writer(args.output, artifact, inputs.spec.max_output_bytes)
    try:
        _check_peak_memory(args.max_memory_mib * 1024 * 1024)
    except (MemoryError, OSError, ValueError):
        args.output.unlink(missing_ok=True)
        raise
    if stop_requested():
        args.output.unlink(missing_ok=True)
        return 3
    if publication is not None:
        _write_record(args._publication, publication, MAX_PUBLICATION_BYTES)
    return 0 if result.status == "completed" else 3


def _check_peak_memory(limit: int) -> None:
    if sys.platform == "linux":
        # Linux getrusage preserves the replaced address space's peak across
        # exec. VmHWM belongs to the current mm, including released allocations.
        # Keep this bounded and fail closed when that measurement is unavailable.
        payload = _bounded_read(Path("/proc/self/status"), 16 * 1024)
        rows = [line.split() for line in payload.splitlines() if line.startswith(b"VmHWM:")]
        if (
            len(rows) != 1
            or len(rows[0]) != 3
            or rows[0][0] != b"VmHWM:"
            or rows[0][2] != b"kB"
            or not rows[0][1].isdigit()
            or int(rows[0][1]) <= 0
        ):
            raise ValueError("resident memory measurement unavailable")
        peak = int(rows[0][1]) * 1024
    elif sys.platform == "darwin":
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    else:
        raise ValueError("resident memory measurement unavailable")
    if peak > limit:
        raise MemoryError("resident memory exceeded its budget")


def _resident_bytes(pid: int) -> int | None:
    """Read only the supervised process's resident size, never its command/environment."""
    sample = subprocess.run(
        ["/bin/ps", "-o", "rss=", "-p", str(pid)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        timeout=1,
        check=False,
    )
    value = sample.stdout.strip()
    if sample.returncode == 1 and not value:
        return None  # Process exited between poll and sample.
    if sample.returncode != 0 or not value.isdigit():
        raise ValueError("resident memory measurement unavailable")
    return int(value) * 1024


def _research_guard() -> LocalInstanceGuard:
    directory = Path("/tmp") / f"autoquant-personal-research-{os.getuid()}"
    directory.mkdir(mode=0o700, exist_ok=True)
    metadata = directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("research lock directory must be private and owner-controlled")
    return LocalInstanceGuard(directory / "instance.lock")


def _child_arguments(args: argparse.Namespace, output: Path) -> list[str]:
    result = ["--_child", "--output", str(output)]
    for name in (
        "fixture",
        "dataset",
        "settlement_calendar",
        "strategy",
        "lookback",
        "allocation",
        "rebalance_sessions",
        "warmup",
        "fixture_sessions",
        "initial_cash",
        "slippage_bps",
        "fee_per_share",
        "max_seconds",
        "max_events",
        "max_output_mib",
        "max_memory_mib",
    ):
        value = getattr(args, name)
        if value is not None:
            result.extend(
                [
                    "--" + name.replace("_", "-"),
                    str(value.absolute() if isinstance(value, Path) else value),
                ]
            )
    for name, flag in (
        ("_inputs", "--_inputs"),
        ("_request", "--_request"),
        ("_artifact_root", "--_artifact-root"),
        ("_publication", "--_publication"),
        ("_progress", "--_progress"),
        ("_conventions", "--_conventions"),
        ("_attempt_id", "--_attempt-id"),
    ):
        value = getattr(args, name)
        if value is not None:
            result.extend([flag, str(value.absolute() if isinstance(value, Path) else value)])
    return result


def _supervise(
    args: argparse.Namespace,
    *,
    lock_descriptor: int | None = None,
    control: Callable[[], bool] | None = None,
    on_signal: Callable[[], None] | None = None,
    emit_status: bool = True,
) -> int:
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists")
    if not output.parent.is_dir():
        raise ValueError("output parent directory must already exist")
    root = Path(__file__).resolve().parents[2]
    env = {
        "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
        "PYTHONPATH": str(root),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    cancel_requested = False

    def cancel(_signum: int, _frame: FrameType | None) -> None:
        nonlocal cancel_requested
        cancel_requested = True
        if on_signal is not None:
            on_signal()

    old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in old_handlers:
        signal.signal(sig, cancel)
    try:
        with tempfile.TemporaryDirectory(
            prefix=".autoquant-research-", dir=output.parent
        ) as temporary:
            staged = Path(temporary) / "report.json"
            expected_build = content_digest(current_build_pins())
            command = [
                sys.executable,
                "-B",
                "-m",
                "apps.worker.personal_research",
                *_child_arguments(args, staged),
                "--_expected-build-sha",
                expected_build,
            ]
            if lock_descriptor is not None:
                command.extend(
                    ["--_lock-fd", str(lock_descriptor), "--_parent-pid", str(os.getpid())]
                )
            started = time.monotonic()
            terminated_at: float | None = None
            resource_exceeded = False
            with subprocess.Popen(
                command,
                cwd=temporary,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=() if lock_descriptor is None else (lock_descriptor,),
            ) as child:
                while child.poll() is None:
                    now = time.monotonic()
                    if control is not None:
                        try:
                            cancel_requested = control() or cancel_requested
                        except Exception:
                            # Loss of control authority stops computation. The durable
                            # caller retains its claim failure; no late result escapes.
                            cancel_requested = True
                    try:
                        resident = _resident_bytes(child.pid)
                    except (ValueError, OSError, subprocess.TimeoutExpired):
                        child.kill()
                        resource_exceeded = True
                        break
                    if resident is not None and resident > args.max_memory_mib * 1024 * 1024:
                        child.kill()
                        resource_exceeded = True
                        break
                    if cancel_requested or now - started >= args.max_seconds:
                        if terminated_at is None:
                            child.terminate()
                            terminated_at = now
                        elif now - terminated_at >= 5:
                            child.kill()
                    try:
                        child.wait(timeout=0.1)
                    except subprocess.TimeoutExpired:
                        continue
                status = child.returncode
            if control is not None:
                try:
                    cancel_requested = control() or cancel_requested
                except Exception:
                    cancel_requested = True
            if (
                status in (0, 3)
                and not cancel_requested
                and not resource_exceeded
                and terminated_at is None
                and time.monotonic() - started < args.max_seconds
                and staged.is_file()
                and staged.stat().st_size <= args.max_output_mib * 1024 * 1024
            ):
                # Same directory filesystem: atomic no-clobber publication.
                os.link(staged, output)
                if emit_status:
                    print(
                        json.dumps(
                            {
                                "status": "completed" if status == 0 else "incomplete",
                                "artifact_written": True,
                                "trading_authorized": False,
                            },
                            sort_keys=True,
                        )
                    )
                return status
            if emit_status:
                print(
                    json.dumps(
                        {
                            "status": "cancelled" if cancel_requested else "failed",
                            "artifact_written": False,
                            "reason": "bounded-run-failed-or-resource-limit",
                            "trading_authorized": False,
                        },
                        sort_keys=True,
                    )
                )
            return 3
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not (
        1 <= args.max_seconds <= 1800
        and 1 <= args.max_events <= 100000
        and 1 <= args.max_output_mib <= 1024
        and 128 <= args.max_memory_mib <= 4096
    ):
        parser.error("requested resource limits exceed the personal research envelope")
    try:
        if args._child:
            return _child(args)
        with _research_guard() as guard:
            return _supervise(args, lock_descriptor=guard.fileno())
    except (ValueError, TypeError, OSError, MemoryError, ArithmeticError, DuplicateRuntimeError):
        # Never echo a raw input payload, private path or inherited configuration.
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "artifact_written": False,
                    "reason": "invalid-input-or-runtime-boundary",
                    "trading_authorized": False,
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
