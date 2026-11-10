"""Run one HALTED synthetic restore through the original supervised worker.

All five inputs are explicit. Existing private stores are required; this command
does not initialize, migrate, repair, adopt, activate or retry an account. Its
bounded summary grants no operating authority and contains no private paths.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NoReturn

from packages.application.continuous_process import (
    ContinuousProcessRequest,
    ContinuousProcessSupervisor,
)
from packages.application.personal_runtime import DuplicateRuntimeError, LocalInstanceGuard

if TYPE_CHECKING:
    from apps.trader.continuous_process_lifecycle import SqlContinuousParentProbe

_FAILURE_REASONS = frozenset(
    {
        "lifecycle_required",
        "operation_busy",
        "cleanup_incomplete",
        "probe_stalled",
        "request_invalid",
        "lifecycle_invalid",
        "probe_failed",
        "lease_lost",
        "deadline",
        "output_limit",
        "child_observation_failed",
        "memory_limit",
        "child_failed",
        "lifecycle_incomplete",
        "process_failed",
    }
)
type _Status = Literal["completed", "stopped", "failed"]
type _Summary = tuple[_Status, str, int]


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise ValueError("invalid_arguments")


class _Once(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        del option_string
        if getattr(namespace, self.dest, None) is not None:
            parser.error("duplicate option")
        setattr(namespace, self.dest, values)


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = _ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--configuration", required=True, type=Path, action=_Once)
    parser.add_argument("--account-id", required=True, action=_Once)
    parser.add_argument("--operation-id", required=True, action=_Once)
    parser.add_argument("--instance-lock", required=True, type=Path, action=_Once)
    parser.add_argument("--artifact-directory", required=True, type=Path, action=_Once)
    return parser.parse_args(argv)


def _explicit_path(path: Path) -> None:
    if not path.is_absolute() or any(part.startswith(".env") for part in path.parts):
        raise ValueError("configuration_invalid")


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _prepare(arguments: argparse.Namespace) -> ContinuousProcessRequest:
    # Delay the full account graph import until explicit argument admission. No
    # database, artifact payload, environment or credential is discovered here.
    from apps.trader.continuous_simulation_factory import (
        _existing_private,
        load_continuous_configuration,
    )

    configuration_path: Path = arguments.configuration
    artifacts: Path = arguments.artifact_directory
    lock: Path = arguments.instance_lock
    for path in (configuration_path, artifacts, lock):
        _explicit_path(path)
    _existing_private(str(configuration_path), directory=False)
    _existing_private(str(artifacts), directory=True)
    _existing_private(str(lock.parent), directory=True)
    if lock.exists() or lock.is_symlink():
        _existing_private(str(lock), directory=False)
    configuration = load_continuous_configuration(configuration_path)
    if (
        configuration.operation != "restore"
        or configuration.capture_evidence_class != "synthetic_fixture"
        or configuration.clock_profile != "explicit_simulation_time_model"
        or (
            configuration.lease_ttl_microseconds,
            configuration.maximum_in_flight_microseconds,
            configuration.takeover_safety_microseconds,
        )
        != (60_000_000, 5_000_000, 10_000_000)
    ):
        raise ValueError("configuration_invalid")
    database = _existing_private(configuration.database_path, directory=False)
    venue_database = _existing_private(configuration.venue_database_path, directory=False)
    objects = _existing_private(configuration.artifact_root, directory=True)
    venue_objects = _existing_private(configuration.venue_artifact_root, directory=True)
    if database == venue_database or _overlap(objects, venue_objects):
        raise ValueError("configuration_invalid")
    protected = (configuration_path, database, venue_database, objects, venue_objects)
    if (
        any(_overlap(artifacts, path) for path in protected)
        or lock in protected
        or lock.is_relative_to(objects)
        or lock.is_relative_to(venue_objects)
        or lock == artifacts
    ):
        raise ValueError("configuration_invalid")
    # The original request supplies its original default limits. There is no
    # command-line override or parent-side reconstruction of financial inputs.
    return ContinuousProcessRequest(
        account_id=arguments.account_id,
        operation_id=arguments.operation_id,
        configuration_path=configuration_path,
        objects=tuple(reference.object_ref for reference in configuration.references),
    )


def _finish_probe(supervisor: ContinuousProcessSupervisor, probe: SqlContinuousParentProbe) -> bool:
    # The original probe has no close API. Read only its existing owner fields,
    # and dispose its read-only engine only after the supervisor's thread ended.
    thread = supervisor._probe_thread
    if thread is not None and thread.is_alive():
        # Never dispose under a live query, add a new grace period or claim that
        # a stalled daemon completed. Process exit is not a lease-release proof.
        return False
    try:
        if probe._database is not None:
            probe._database.engine.dispose()
        return supervisor._read_cleanup_complete()
    except (Exception, KeyboardInterrupt):
        return False


def _recover(
    request: ContinuousProcessRequest, artifacts: Path, descriptor: int
) -> tuple[_Summary, bool]:
    from apps.trader.continuous_process_lifecycle import SqlContinuousParentProbe

    supervisor = ContinuousProcessSupervisor(artifact_directory=artifacts)
    probe = SqlContinuousParentProbe(request)
    result: _Summary = ("failed", "recovery_failed", 3)
    cleanup_complete = False
    try:
        outcome = supervisor.run(
            request,
            lock_descriptor=descriptor,
            stop_requested=lambda: False,
            lifecycle=probe,
        )
        if (
            outcome.status == "completed"
            and outcome.reason == "completed"
            and outcome.receipt is not None
        ):
            result = ("completed", "completed", 0)
        elif outcome.status == "stopped" and outcome.reason == "stopped":
            result = ("stopped", "stopped", 3)
        elif outcome.status == "failed" and outcome.reason in _FAILURE_REASONS:
            result = ("failed", outcome.reason, 3)
    except KeyboardInterrupt:
        result = ("stopped", "stopped", 3)
    except Exception:
        # Neither original exceptions nor private configuration data are rendered.
        result = ("failed", "recovery_failed", 3)
    finally:
        cleanup_complete = _finish_probe(supervisor, probe)
    return result, cleanup_complete


def _emit(summary: _Summary, *, cleanup_complete: bool | None = None) -> int:
    state, reason, exit_code = summary
    payload = {
        "schema": "continuous-synthetic-recovery-summary/1",
        "status": state,
        "reason": reason,
        "operation": "restore",
        "trading_authority": False,
    }
    if cleanup_complete is not None:
        payload["cleanup_complete"] = cleanup_complete
    if cleanup_complete is False:
        # Preserve only the public supervisor result (or our static exception
        # classification), never infer its private pre-cleanup outcome.
        payload["primary_status"] = state
        payload["primary_reason"] = reason
        payload["status"] = "failed"
        payload["reason"] = "cleanup_incomplete"
        exit_code = 3
    try:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)
    except OSError:
        return 3
    return exit_code


def main(argv: list[str] | None = None) -> int:
    """Attempt one original HALTED recovery and print only its bounded status."""
    try:
        arguments = _parse(argv)
    except ValueError:
        return _emit(("failed", "invalid_arguments", 2))
    try:
        request = _prepare(arguments)
    except Exception:
        return _emit(("failed", "configuration_invalid", 2))
    entered = False
    summary: _Summary | None = None
    cleanup_complete: bool | None = None
    try:
        with LocalInstanceGuard(arguments.instance_lock) as guard:
            entered = True
            summary, cleanup_complete = _recover(
                request, arguments.artifact_directory, guard.fileno()
            )
    except DuplicateRuntimeError:
        return _emit(("failed", "instance_busy", 2))
    except KeyboardInterrupt:
        if summary is not None:
            return _emit(summary, cleanup_complete=False)
        return _emit(("stopped", "stopped", 3))
    except Exception:
        if summary is not None:
            return _emit(summary, cleanup_complete=False)
        return _emit(
            (
                "failed",
                "recovery_failed" if entered else "configuration_invalid",
                3 if entered else 2,
            )
        )
    return _emit(summary, cleanup_complete=cleanup_complete)


if __name__ == "__main__":
    raise SystemExit(main())
