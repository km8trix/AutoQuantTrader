"""One private lifecycle for the original configured owner and fixed reader.

Construction is data only. Explicit synchronous entry starts resources; it does
not establish readiness or grant an HTTP, authentication or financial capability.
The original read port retains its complete-body and deferred cleanup ownership.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from threading import Lock

from apps.api.readiness_read_store import (
    ReadinessReadStore,
    ReadinessReadStoreStatus,
    open_readiness_read_store,
)
from apps.trader.configured_readiness_owner import create_configured_readiness_owner
from apps.trader.continuous_readiness_owner import (
    ContinuousReadinessOwner,
    ReadinessOwnerLimits,
    ReadinessOwnerStatus,
)
from packages.domain.durable_journal_contracts import journal_identifier

_OWNER = ContinuousReadinessOwner
_START = ContinuousReadinessOwner.start
_STOP = ContinuousReadinessOwner.stop
_STORE = ReadinessReadStore
_CLOSE = ReadinessReadStore.close
_DEFAULT_LIMITS = ReadinessOwnerLimits()


def _native_text(value: object) -> bool:
    return type(value) is str


def _owner_bindings(owner: ContinuousReadinessOwner) -> None:
    if type(owner) is not _OWNER:
        raise ValueError("CONFIGURED_READINESS_READS_ORIGINAL_OWNER_REQUIRED")
    for name, original in (("start", _START), ("stop", _STOP)):
        if vars(_OWNER).get(name) is not original or name in vars(owner):
            raise RuntimeError("CONFIGURED_READINESS_READS_BINDING_CHANGED")


def _close_binding(port: ReadinessReadStore) -> None:
    if type(port) is not _STORE or vars(_STORE).get("close") is not _CLOSE or "close" in vars(port):
        raise RuntimeError("CONFIGURED_READINESS_READS_BINDING_CHANGED")


def _owner_status(value: object) -> ReadinessOwnerStatus:
    if (
        type(value) is not ReadinessOwnerStatus
        or not _native_text(value.phase)
        or not _native_text(value.incarnation)
        or type(value.busy) is not bool
        or type(value.cleanup_complete) is not bool
        or (value.primary_failure is not None and type(value.primary_failure) is not str)
        or (value.cleanup_failure is not None and type(value.cleanup_failure) is not str)
    ):
        raise RuntimeError("CONFIGURED_READINESS_READS_OWNER_STATUS_INVALID")
    try:
        journal_identifier(value.incarnation)
    except ValueError:
        raise RuntimeError("CONFIGURED_READINESS_READS_OWNER_STATUS_INVALID") from None
    return value


def _read_cleanup(value: object) -> None:
    if (
        type(value) is not ReadinessReadStoreStatus
        or not _native_text(value.phase)
        or type(value.busy) is not bool
        or type(value.cleanup_complete) is not bool
        or (value.cleanup_failure is not None and type(value.cleanup_failure) is not str)
        or value.phase != "closed"
        or value.busy is not False
        or value.cleanup_complete is not True
        or value.cleanup_failure is not None
    ):
        # This is the observed cutoff, not a claim about K's private exception or
        # eventual deferred cleanup. Never inspect its Engine/error fields here.
        raise RuntimeError("CONFIGURED_READINESS_READS_READ_CLEANUP_INCOMPLETE")


def _combined(errors: list[BaseException], message: str) -> BaseException | None:
    if len(errors) == 1:
        return errors[0]
    if errors:
        return BaseExceptionGroup(message, errors)
    return None


def configured_readiness_reads(
    *,
    configuration_path: str,
    account_id: str,
    instance_lock: str,
    limits: ReadinessOwnerLimits = _DEFAULT_LIMITS,
) -> AbstractContextManager[ReadinessReadStore]:
    """Construct once without I/O; explicit one-use entry owns the lifecycle."""
    owner = create_configured_readiness_owner(
        configuration_path=configuration_path,
        account_id=account_id,
        instance_lock=instance_lock,
        limits=limits,
    )
    if type(owner) is not _OWNER:
        raise ValueError("CONFIGURED_READINESS_READS_ORIGINAL_OWNER_REQUIRED")
    entry_lock = Lock()
    entered = False

    @contextmanager
    def held() -> Iterator[ReadinessReadStore]:
        nonlocal entered
        # Recreated contextlib generators share this same admission latch. The
        # lock covers no owner work, filesystem access, clock or SQL operation.
        with entry_lock:
            if entered:
                raise RuntimeError("CONFIGURED_READINESS_READS_ALREADY_ENTERED")
            entered = True
        attempted_start = False
        accepted_incarnation: str | None = None
        port: ReadinessReadStore | None = None
        primary: BaseException | None = None
        try:
            _owner_bindings(owner)
            attempted_start = True
            started = _owner_status(_START(owner))
            if (
                started.phase != "idle"
                or started.busy is not False
                or started.cleanup_complete is not False
                or started.primary_failure is not None
                or started.cleanup_failure is not None
            ):
                raise RuntimeError("CONFIGURED_READINESS_READS_STARTUP_UNAVAILABLE")
            accepted_incarnation = started.incarnation
            candidate = open_readiness_read_store(owner)
            if type(candidate) is not _STORE:
                raise ValueError("CONFIGURED_READINESS_READS_READ_STORE_REQUIRED")
            port = candidate
            yield port
        except BaseException as error:
            primary = error
            raise
        finally:
            cleanup_errors: list[BaseException] = []
            if port is not None:
                close_errors: list[BaseException] = []
                try:
                    _close_binding(port)
                except BaseException as error:
                    close_errors.append(error)
                try:
                    # Guard failure cannot skip known-owned original cleanup.
                    _read_cleanup(_CLOSE(port))
                except BaseException as error:
                    close_errors.append(error)
                close_error = _combined(
                    close_errors, "CONFIGURED_READINESS_READS_CLOSE_AND_CHECK_FAILED"
                )
                if close_error is not None:
                    cleanup_errors.append(close_error)
            if attempted_start:
                stop_errors: list[BaseException] = []
                try:
                    _owner_bindings(owner)
                except BaseException as error:
                    stop_errors.append(error)
                try:
                    stopped = _owner_status(_STOP(owner))
                    if (
                        stopped.phase != "stopped"
                        or stopped.busy is not False
                        or stopped.cleanup_complete is not True
                        or stopped.cleanup_failure is not None
                        or (
                            accepted_incarnation is not None
                            and stopped.incarnation != accepted_incarnation
                        )
                    ):
                        raise RuntimeError("CONFIGURED_READINESS_READS_OWNER_CLEANUP_INCOMPLETE")
                    # A native historical primary_failure is not a new cleanup
                    # failure and cannot justify a second stop/release attempt.
                except BaseException as error:
                    stop_errors.append(error)
                stop_error = _combined(
                    stop_errors, "CONFIGURED_READINESS_READS_STOP_AND_CHECK_FAILED"
                )
                if stop_error is not None:
                    cleanup_errors.append(stop_error)
            if cleanup_errors:
                failures = ([primary] if primary is not None else []) + cleanup_errors
                failure = _combined(
                    failures, "CONFIGURED_READINESS_READS_OPERATION_AND_CLEANUP_FAILED"
                )
                if failure is not None:
                    raise failure from None

    return held()
