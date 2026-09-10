"""Verify the offline research CLI as real isolated processes; retain metadata only.

Run against a frozen source tree or an installed wheel. Reports remain private
inside a new directory outside the checkout; evidence.json contains no paths,
environment values, report payloads or child diagnostics.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import signal
import stat
import subprocess
import tempfile
import time
from contextlib import ExitStack, suppress
from decimal import Decimal
from pathlib import Path
from types import FrameType
from typing import BinaryIO

_LOCK = Path(f"/tmp/autoquant-personal-research-{os.getuid()}/instance.lock")
_MAX_REPORT = 16 * 1024 * 1024
_STATUSES = {"completed", "incomplete", "cancelled", "failed", "rejected", "already_running"}


class VerificationFailure(Exception):
    """A fixed, non-sensitive verification failure code."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise VerificationFailure(code)


def _lock_held() -> bool:
    """Observe an existing flock without creating or changing the lock file."""
    try:
        descriptor = os.open(_LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), "invalid_lock_file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def _artifact(path: Path) -> dict[str, object]:
    if not path.exists():
        _require(not path.is_symlink(), "artifact_symlink")
        return {"artifact_present": False, "artifact_completed": False}
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode), "artifact_not_regular")
    _require(
        stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(), "artifact_not_private"
    )
    _require(info.st_size <= _MAX_REPORT, "artifact_exceeds_bound")
    payload = path.read_bytes()
    value = json.loads(payload)
    report = value["report"]
    status = report["status"]
    source_status = report["source"]["status"]
    _require(status in {"completed", "incomplete"}, "invalid_report_status")
    _require(
        source_status in {"completed", "cancelled", "failed", "rejected"}, "invalid_source_status"
    )
    metrics = {metric["name"]: metric["value"] for metric in report["metrics"]}
    expected = Decimal("9998.56")
    nav = report["source"]["final_snapshot"]["nav"]
    return {
        "artifact_present": True,
        "artifact_completed": status == source_status == "completed",
        "report_status": status,
        "source_status": source_status,
        "private_mode": True,
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "nav_matches_expected": nav is not None
        and Decimal(nav) == expected
        and metrics.get("ending_equity") is not None
        and Decimal(metrics["ending_equity"]) == expected,
    }


class Verifier:
    def __init__(self, python: Path, output: Path, source: Path | None) -> None:
        self.python, self.output = python, output
        self.environment = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
        if source is not None:
            self.environment["PYTHONPATH"] = str(source)
        self.started = time.monotonic()
        self.deadline = self.started + 30
        self.children: list[tuple[subprocess.Popen[bytes], BinaryIO]] = []
        self.streams = ExitStack()
        self.cases: list[dict[str, object]] = []

    def _remaining(self, maximum: float) -> float:
        remaining = min(maximum, self.deadline - time.monotonic())
        _require(remaining > 0, "verification_deadline")
        return remaining

    def start(
        self, name: str, *, sessions: int = 12, limits: tuple[str, ...] = ()
    ) -> tuple[subprocess.Popen[bytes], BinaryIO, float]:
        # ExitStack owns this stream through the child's complete lifetime.
        stream = self.streams.enter_context(tempfile.TemporaryFile(mode="w+b", dir=self.output))  # noqa: SIM115
        try:
            child = subprocess.Popen(
                [
                    str(self.python),
                    "-B",
                    "-m",
                    "apps.worker.main",
                    "--fixture",
                    "flat",
                    "--fixture-sessions",
                    str(sessions),
                    "--warmup",
                    "3",
                    "--lookback",
                    "3",
                    "--max-seconds",
                    "20",
                    "--max-output-mib",
                    "16",
                    "--output",
                    str(self.output / f"{name}.json"),
                    *limits,
                ],
                cwd=self.output,
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except BaseException:
            stream.close()
            raise
        self.children.append((child, stream))
        return child, stream, time.monotonic()

    def finish(
        self,
        name: str,
        running: tuple[subprocess.Popen[bytes], BinaryIO, float],
        *,
        timeout: float = 6,
    ) -> dict[str, object]:
        child, stream, started = running
        child.wait(timeout=self._remaining(timeout))
        stream.seek(0)
        payload = stream.read(4097)
        _require(len(payload) <= 4096, "child_status_exceeds_bound")
        cli_status = "no_status"
        if payload.strip():
            value = json.loads(payload)
            status = value.get("status")
            cli_status = status if status in _STATUSES else "unrecognized"
        observation: dict[str, object] = {
            "case": name,
            "returncode": child.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "cli_status": cli_status,
            "stdout_sha256": hashlib.sha256(payload).hexdigest(),
            **_artifact(self.output / f"{name}.json"),
        }
        self.cases.append(observation)
        return observation

    def wait_lock(
        self, held: bool, *, child: subprocess.Popen[bytes] | None = None, timeout: float = 5
    ) -> None:
        deadline = time.monotonic() + self._remaining(timeout)
        while time.monotonic() < deadline:
            if _lock_held() is held:
                if child is not None:
                    _require(child.poll() is None, "long_run_exited_before_probe")
                return
            if child is not None:
                _require(child.poll() is None, "long_run_exited_before_lock")
            time.sleep(0.02)
        raise VerificationFailure("lock_observation_timeout")

    def short(self, name: str) -> None:
        result = self.finish(name, self.start(name))
        _require(
            result["returncode"] == 0
            and result["artifact_completed"] is True
            and result["nav_matches_expected"] is True,
            "short_run_failed",
        )

    def run(self) -> None:
        _require(not _lock_held(), "preexisting_research_process")
        self.short("short")
        original = _artifact(self.output / "short.json")
        overwrite = self.finish("short", self.start("short"))
        overwrite["case"] = "existing_output"
        _require(
            overwrite["returncode"] != 0
            and overwrite["artifact_sha256"] == original["artifact_sha256"],
            "existing_output_changed",
        )
        overwrite["original_hash_preserved"] = True
        long = self.start("terminated", sessions=520)
        self.wait_lock(True, child=long[0])
        duplicate = self.finish("duplicate", self.start("duplicate"), timeout=3)
        _require(
            duplicate["returncode"] != 0 and not duplicate["artifact_present"],
            "duplicate_not_rejected",
        )
        _require(long[0].poll() is None and _lock_held(), "original_run_lost_lock")
        duplicate["original_lock_observed_held"] = True
        stopped = time.monotonic()
        long[0].terminate()
        result = self.finish("terminated", long, timeout=8)
        result["shutdown_ms"] = round((time.monotonic() - stopped) * 1000)
        _require(
            time.monotonic() - stopped <= 8
            and result["returncode"] != 0
            and not result["artifact_completed"],
            "sigterm_did_not_stop",
        )
        self.wait_lock(False, timeout=1)
        self.short("restart")

        killed = self.start("killed", sessions=520)
        self.wait_lock(True, child=killed[0])
        # Give the real supervisor time to spawn its inherited-lock child. The
        # bounded cleanup assertion does not assume an immediate retry rejection.
        time.sleep(self._remaining(0.5))
        _require(killed[0].poll() is None, "kill_target_already_exited")
        stopped = time.monotonic()
        killed[0].kill()  # Parent only: test the child's actual orphan detection.
        result = self.finish("killed", killed, timeout=2)
        self.wait_lock(False, timeout=8)
        result.update(_artifact(self.output / "killed.json"))
        result["startup_grace_ms"] = 500
        result["orphan_lock_release_ms"] = round((time.monotonic() - stopped) * 1000)
        _require(
            time.monotonic() - stopped <= 8 and not (self.output / "killed.json").exists(),
            "orphan_cleanup_failed",
        )
        self.short("restart_after_kill")

        for name, limits in (
            ("max_wall", ("--max-seconds", "1")),
            ("max_events", ("--max-events", "1")),
        ):
            result = self.finish(name, self.start(name, sessions=520, limits=limits), timeout=8)
            _require(
                result["returncode"] in (2, 3) and not result["artifact_completed"],
                "resource_limit_not_controlled",
            )
        self.wait_lock(False, timeout=1)

    def cleanup(self) -> bool:
        # Each group was created by this verifier and includes its supervisor's
        # descendants. Cleanup also covers a parent already reaped after SIGKILL.
        success = True
        for child, _stream in self.children:
            try:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGTERM)
            except OSError:
                success = False
        deadline = time.monotonic() + 1
        for child, _stream in self.children:
            with suppress(subprocess.TimeoutExpired):
                child.wait(timeout=max(0.01, deadline - time.monotonic()))
        for child, stream in self.children:
            try:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=1)
            except (OSError, subprocess.SubprocessError):
                success = False
            finally:
                stream.close()
        self.streams.close()
        return success


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args()
    verifier = None
    status, reason = "failed", "invalid_verification_input"

    def interrupted(_signum: int, _frame: FrameType | None) -> None:
        raise VerificationFailure("verification_interrupted")

    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in handlers:
        signal.signal(sig, interrupted)
    try:
        _require(
            args.python.is_absolute() and args.python.is_file() and os.access(args.python, os.X_OK),
            reason,
        )
        _require(
            args.output_dir.is_absolute()
            and not args.output_dir.exists()
            and not args.output_dir.is_symlink(),
            reason,
        )
        output = args.output_dir.parent.resolve(strict=True) / args.output_dir.name
        roots = [Path(__file__).resolve().parents[1]]
        source = None if args.source_root is None else args.source_root.resolve(strict=True)
        if source is not None:
            _require((source / "apps/worker/main.py").is_file(), reason)
            roots.append(source)
        _require(
            all(not output.is_relative_to(root) for root in roots),
            "output_must_be_outside_checkout",
        )
        output.mkdir(mode=0o700)
        verifier = Verifier(args.python, output, source)
        verifier.run()
        status, reason = "passed", "all_process_checks_passed"
    except VerificationFailure as error:
        reason = str(error)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        ArithmeticError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ):
        reason = "verification_runtime_failure"
    finally:
        if verifier is not None and not verifier.cleanup():
            status, reason = "failed", "child_cleanup_failed"
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    evidence = {
        "version": "personal-research-process-verification/1",
        "status": status,
        "reason": reason,
        "cases": [] if verifier is None else verifier.cases,
        "duration_ms": 0
        if verifier is None
        else round((time.monotonic() - verifier.started) * 1000),
    }
    if verifier is not None:
        try:
            descriptor = os.open(
                verifier.output / "evidence.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "w") as stream:
                json.dump(evidence, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
        except OSError:
            evidence["status"], evidence["reason"] = "failed", "evidence_write_failed"
            status = "failed"
    print(json.dumps(evidence, sort_keys=True))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
