"""Durable, non-authorizing recovery outcome for a future trusted-time start.

The module deliberately has no command-line entry point and no topology,
release, provider, database, or trading integration.  It can only retain the
fixed recovery-required projection authorized by the topology reader's
callback-local retention capability.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Never, cast

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    _finalize_post_enrollment_recovery_projection_types,
    _stage_post_enrollment_recovery_outcome_reason_type,
    _stage_post_enrollment_recovery_outcome_status_type,
    _stage_retained_post_enrollment_recovery_outcome_type,
    _TrustedTimePostEnrollmentRecoveryRetentionCheckpoint,
)

POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-retained-recovery-outcome-v1"
)
POST_ENROLLMENT_START_RETAINED_OUTCOME_SERVICE = (
    "trusted-time-post-enrollment-start-host-controller"
)
POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX = "trusted-time-post-enrollment-start-outcome-"
POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX = ".json"
POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME = "trusted-time-post-enrollment-start-outcome.json"
POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME = ".post-enrollment-start-controller-outcome-slot"
_POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME = (
    ".post-enrollment-start-recovery-outcome-staging"
)
MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES = 128 * 1_024
MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES = 4_096
MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES = 255
POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS = 605

_SHA256_LENGTH = 64
_NANOSECONDS_PER_SECOND = 1_000_000_000
_OUTCOME_SLOT_PROCESS_LOCK = threading.RLock()
_OUTCOME_SLOT_PROCESS_LOCK_ORIGIN_PID = os.getpid()
_CLOSED_OUTCOME_FIELDS = (
    "authority_granted",
    "claim_chronology_authenticated",
    "claim_retention_authorized",
    "database_secret_disclosed",
    "outcome_retention_authorized",
    "persistent_start_authorized",
    "persistent_start_confirmed",
    "qualified",
    "release_attempted",
    "release_authorized",
    "release_confirmed",
    "retry_authorized",
    "sequence_2_authorized",
    "sequence_2_confirmed",
    "shutdown_authorized",
    "source_start_authorized",
    "supervisor_start_authorized",
    "topology_mutation_authorized",
    "topology_qualified",
)


@_stage_post_enrollment_recovery_outcome_status_type
class TrustedTimePostEnrollmentStartRetainedOutcomeStatus(StrEnum):
    """The only outcome status this pre-release module can retain."""

    RECOVERY_REQUIRED = "recovery_required"


@_stage_post_enrollment_recovery_outcome_reason_type
class TrustedTimePostEnrollmentStartRetainedOutcomeReason(StrEnum):
    """The only non-caller-selected reason this module can retain."""

    POST_ENROLLMENT_START_RECOVERY_REQUIRED = "post_enrollment_start_recovery_required"


class TrustedTimePostEnrollmentStartOutcomeRejected(RuntimeError):
    """Recovery outcome inputs were rejected before retention was attempted."""


class TrustedTimePostEnrollmentStartOutcomeCapabilityUnavailable(RuntimeError):
    """The reader did not admit the callback-local retention capability."""


class TrustedTimePostEnrollmentStartOutcomeAlreadyRetained(RuntimeError):
    """The global post-enrollment recovery outcome slot is already occupied."""


class TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(RuntimeError):
    """Outcome creation may have occurred, but durable retention is unconfirmed."""


class TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(RuntimeError):
    """A unique exact retained recovery outcome cannot be loaded."""


def _reset_outcome_slot_process_lock_after_fork() -> None:
    global _OUTCOME_SLOT_PROCESS_LOCK
    global _OUTCOME_SLOT_PROCESS_LOCK_ORIGIN_PID

    _OUTCOME_SLOT_PROCESS_LOCK = threading.RLock()
    _OUTCOME_SLOT_PROCESS_LOCK_ORIGIN_PID = os.getpid()


os.register_at_fork(after_in_child=_reset_outcome_slot_process_lock_after_fork)


def _outcome_slot_process_lock_depth() -> int:
    counter = getattr(_OUTCOME_SLOT_PROCESS_LOCK, "_recursion_count", None)
    if not callable(counter):
        raise RuntimeError("trusted-time outcome process lock is unavailable")
    depth = cast(Callable[[], int], counter)()
    if type(depth) is not int or depth < 0:
        raise RuntimeError("trusted-time outcome process lock is unavailable")
    return depth


def _preferred_base_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_base_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_base_exception(preferred, error)
    return preferred


class _OwnedFileDescriptor(ctypes.c_int):
    """Own one libc-opened descriptor before its Python CALL can return."""

    def __index__(self) -> int:
        return self.fileno()

    def fileno(self) -> int:
        descriptor = self.value
        if descriptor < 0:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))
        return descriptor

    @property
    def closed(self) -> bool:
        return self.value < 0

    def close(self) -> None:
        descriptor = self.value
        if descriptor < 0:
            return
        state_error: BaseException | None = None
        try:
            self.value = -1
        except BaseException as error:
            state_error = error
            try:
                self.value = -1
            except BaseException as retry_error:
                terminal = _preferred_base_exception(error, retry_error)
                if terminal is error or terminal is None:
                    raise
                raise terminal from error
        try:
            os.close(descriptor)
        except BaseException as error:
            terminal = _preferred_base_exception(state_error, error)
            if terminal is error or terminal is None:
                raise
            raise terminal from error
        terminal = state_error
        if terminal is not None:
            raise terminal

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


_LIBC = ctypes.CDLL(None, use_errno=True)
_OWNED_OPEN = _LIBC.open
_OWNED_OPEN.argtypes = (ctypes.c_char_p, ctypes.c_int)
_OWNED_OPEN.restype = _OwnedFileDescriptor
_OWNED_OPENAT = _LIBC.openat
_OWNED_OPENAT.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
_OWNED_OPENAT.restype = _OwnedFileDescriptor


def _open_owned_descriptor(
    path: str | Path,
    *,
    flags: int,
    mode: int = 0,
    dir_fd: int | None = None,
) -> _OwnedFileDescriptor:
    ctypes.set_errno(0)
    if dir_fd is None:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPEN(os.fsencode(path), flags, ctypes.c_int(mode)),
        )
    else:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPENAT(dir_fd, os.fsencode(path), flags, ctypes.c_int(mode)),
        )
    if owner.value >= 0:
        return owner
    error_number = ctypes.get_errno() or errno.EIO
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), os.fspath(path))
    if error_number == errno.ENOENT:
        raise FileNotFoundError(error_number, os.strerror(error_number), os.fspath(path))
    raise OSError(error_number, os.strerror(error_number), os.fspath(path))


def _close_descriptor_owners(
    owners: tuple[_OwnedFileDescriptor | None, ...],
) -> BaseException | None:
    first_error: BaseException | None = None
    for owner in owners:
        if owner is None or owner.closed:
            continue
        try:
            owner.close()
        except BaseException as error:
            first_error = _preferred_base_exception(first_error, error)
    return first_error


def _release_outcome_slot_process_lock_to_depth(
    expected_depth: int,
) -> BaseException | None:
    first_error: BaseException | None = None
    for _ in range(2):
        try:
            if _outcome_slot_process_lock_depth() <= expected_depth:
                break
            _OUTCOME_SLOT_PROCESS_LOCK.release()
        except BaseException as error:
            if first_error is None:
                first_error = error
    try:
        if _outcome_slot_process_lock_depth() > expected_depth:
            return first_error or RuntimeError(
                "trusted-time outcome process lock could not be released"
            )
    except BaseException as error:
        return _preferred_base_exception(first_error, error)
    return first_error


@contextmanager
def _held_outcome_slot_process_lock() -> Iterator[None]:
    """Hold the VM-local lock without leaking it across async boundaries."""

    global _OUTCOME_SLOT_PROCESS_LOCK_ORIGIN_PID

    current_pid = os.getpid()
    if current_pid != _OUTCOME_SLOT_PROCESS_LOCK_ORIGIN_PID:
        _reset_outcome_slot_process_lock_after_fork()
    initial_depth = _outcome_slot_process_lock_depth()
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            _OUTCOME_SLOT_PROCESS_LOCK.acquire()
            yield
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _release_outcome_slot_process_lock_to_depth(initial_depth)
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _release_outcome_slot_process_lock_to_depth(initial_depth)
    terminal = _preferred_base_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal


def _close_outcome_slot_file_owner(file_owner: io.FileIO | None) -> BaseException | None:
    if file_owner is None or _file_owner_is_closed(file_owner):
        return None
    first_error: BaseException | None = None
    try:
        fcntl.flock(file_owner.fileno(), fcntl.LOCK_UN)
    except BaseException as error:
        first_error = error
    for _ in range(2):
        if _file_owner_is_closed(file_owner):
            break
        try:
            file_owner.close()
        except BaseException as error:
            first_error = _preferred_base_exception(first_error, error)
    if not _file_owner_is_closed(file_owner):
        first_error = _preferred_base_exception(
            first_error,
            RuntimeError("trusted-time outcome slot descriptor could not be closed"),
        )
    return first_error


def _file_owner_is_closed(file_owner: io.FileIO) -> bool:
    return file_owner.closed


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _outcome_slot_bytes(
    outcome_sha256: str,
    *,
    outcome_contract_version: str,
    status: str = "reserved",
) -> bytes:
    if (
        not _is_sha256(outcome_sha256)
        or type(outcome_contract_version) is not str
        or status not in {"reserved", "retained"}
    ):
        raise ValueError("trusted-time post-enrollment outcome slot binding is invalid")
    return canonical_first_enrollment_json_bytes(
        {
            "contract_version": outcome_contract_version,
            "outcome_sha256": outcome_sha256,
            "status": status,
        }
    )


def _open_owner_only_file(
    directory_descriptor: int,
    file_name: str,
    *,
    exclusive: bool,
) -> io.FileIO:
    """Return a VM-owned descriptor so async CALL/STORE loss closes it."""

    mode = "xb" if exclusive else "rb"

    if exclusive:
        return io.FileIO(
            file_name,
            mode=mode,
            opener=partial(
                os.open,
                mode=0o600,
                dir_fd=directory_descriptor,
            ),
        )

    def opener(path: str, flags: int) -> int:
        return os.open(
            path,
            flags
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            0o600,
            dir_fd=directory_descriptor,
        )

    return io.FileIO(file_name, mode=mode, opener=opener)


def _write_locked_slot(descriptor: int, encoded: bytes) -> tuple[int, ...]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError
        view = view[written:]
    os.ftruncate(descriptor, len(encoded))
    os.fchmod(descriptor, 0o600)
    os.fsync(descriptor)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or metadata.st_size != len(encoded)
    ):
        raise OSError
    return _stable_file_identity(metadata)


def _reserve_outcome_slot(
    directory_descriptor: int,
    *,
    encoded: bytes,
) -> tuple[int, ...]:
    """Atomically reserve and durably publish the process-global outcome slot."""

    file_owner: io.FileIO | None = None
    with _held_outcome_slot_process_lock():
        body_error: BaseException | None = None
        transition_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        retry_error: BaseException | None = None
        identity: tuple[int, ...] | None = None
        try:
            try:
                file_owner = _open_owner_only_file(
                    directory_descriptor,
                    POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                    exclusive=True,
                )
                descriptor = file_owner.fileno()
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                identity = _write_locked_slot(descriptor, encoded)
                os.fsync(directory_descriptor)
            except BaseException as error:
                body_error = error
            finally:
                cleanup_error = _close_outcome_slot_file_owner(file_owner)
        except BaseException as error:
            transition_error = error
        finally:
            retry_error = _close_outcome_slot_file_owner(file_owner)
        terminal = _preferred_base_exceptions(
            body_error,
            transition_error,
            cleanup_error,
            retry_error,
        )
        if terminal is not None:
            raise terminal
        if identity is None:
            raise RuntimeError("trusted-time outcome slot reservation did not complete")
        return identity


@contextmanager
def _reserve_and_lock_outcome_slot(
    directory_descriptor: int,
    *,
    encoded: bytes,
) -> Iterator[tuple[int, tuple[int, ...]]]:
    """Reserve the slot and keep its exact inode exclusively locked."""

    file_owner: io.FileIO | None = None
    with _held_outcome_slot_process_lock():
        body_error: BaseException | None = None
        transition_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        retry_error: BaseException | None = None
        try:
            try:
                file_owner = _open_owner_only_file(
                    directory_descriptor,
                    POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                    exclusive=True,
                )
                descriptor = file_owner.fileno()
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                identity = _write_locked_slot(descriptor, encoded)
                os.fsync(directory_descriptor)
                yield descriptor, identity
            except BaseException as error:
                body_error = error
            finally:
                cleanup_error = _close_outcome_slot_file_owner(file_owner)
        except BaseException as error:
            transition_error = error
        finally:
            retry_error = _close_outcome_slot_file_owner(file_owner)
        terminal = _preferred_base_exceptions(
            body_error,
            transition_error,
            cleanup_error,
            retry_error,
        )
        if terminal is not None:
            raise terminal


@contextmanager
def _locked_outcome_slot(
    directory_descriptor: int,
    *,
    exclusive: bool,
) -> Iterator[int]:
    """Hold a process- and host-wide lock on the permanent outcome slot."""

    file_owner: io.FileIO | None = None
    with _held_outcome_slot_process_lock():
        body_error: BaseException | None = None
        transition_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        retry_error: BaseException | None = None
        try:
            try:
                file_owner = _open_owner_only_file(
                    directory_descriptor,
                    POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                    exclusive=False,
                )
                descriptor = file_owner.fileno()
                fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                yield descriptor
            except BaseException as error:
                body_error = error
            finally:
                cleanup_error = _close_outcome_slot_file_owner(file_owner)
        except BaseException as error:
            transition_error = error
        finally:
            retry_error = _close_outcome_slot_file_owner(file_owner)
        terminal = _preferred_base_exceptions(
            body_error,
            transition_error,
            cleanup_error,
            retry_error,
        )
        if terminal is not None:
            raise terminal


def _outcome_payload(
    *,
    operation_id: str,
    approval_sha256: str,
    claim_sha256: str,
    retained_claim_artifact_sha256: str,
) -> dict[str, object]:
    if (
        not _is_uuid4(operation_id)
        or not _is_sha256(approval_sha256)
        or not _is_sha256(claim_sha256)
        or not _is_sha256(retained_claim_artifact_sha256)
    ):
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome evidence is invalid"
        )
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update({field_name: False for field_name in _CLOSED_OUTCOME_FIELDS})
    payload.update(
        {
            "approval_sha256": approval_sha256,
            "claim_retention_revalidated": True,
            "claim_sha256": claim_sha256,
            "contract_version": POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION,
            "operation_id": operation_id,
            "reason": (
                TrustedTimePostEnrollmentStartRetainedOutcomeReason.POST_ENROLLMENT_START_RECOVERY_REQUIRED
            ),
            "retained_claim_artifact_sha256": retained_claim_artifact_sha256,
            "service": POST_ENROLLMENT_START_RETAINED_OUTCOME_SERVICE,
            "status": (TrustedTimePostEnrollmentStartRetainedOutcomeStatus.RECOVERY_REQUIRED),
        }
    )
    return payload


def retained_post_enrollment_start_recovery_required_outcome_bytes(
    *,
    operation_id: str,
    approval_sha256: str,
    claim_sha256: str,
    retained_claim_artifact_sha256: str,
) -> bytes:
    """Encode the exact bounded fixed recovery-required payload."""

    try:
        encoded = canonical_first_enrollment_json_bytes(
            _outcome_payload(
                operation_id=operation_id,
                approval_sha256=approval_sha256,
                claim_sha256=claim_sha256,
                retained_claim_artifact_sha256=retained_claim_artifact_sha256,
            )
        )
    except TrustedTimePostEnrollmentStartOutcomeRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome evidence is invalid"
        ) from None
    if not encoded or len(encoded) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES:
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome evidence is invalid"
        )
    return encoded


def _outcome_file_name(outcome_sha256: str) -> str:
    if not _is_sha256(outcome_sha256):
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome artifact binding is invalid"
        )
    file_name = (
        f"{POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}{outcome_sha256}"
        f"{POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    if (
        len(os.fsencode(file_name)) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
    ):
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome artifact binding is invalid"
        )
    return file_name


@_stage_retained_post_enrollment_recovery_outcome_type
@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedTrustedTimePostEnrollmentStartOutcome:
    """Exact bytes and inode identity of one retained recovery-required outcome."""

    operation_id: str
    approval_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    outcome_sha256: str
    artifact_path: Path
    encoded: bytes
    file_identity: tuple[int, ...]
    slot_file_identity: tuple[int, ...]
    status: TrustedTimePostEnrollmentStartRetainedOutcomeStatus
    reason: TrustedTimePostEnrollmentStartRetainedOutcomeReason

    def __post_init__(self) -> None:
        if (
            type(self) is not RetainedTrustedTimePostEnrollmentStartOutcome
            or not _is_uuid4(self.operation_id)
            or not _is_sha256(self.approval_sha256)
            or not _is_sha256(self.claim_sha256)
            or not _is_sha256(self.retained_claim_artifact_sha256)
            or not _is_sha256(self.outcome_sha256)
            or type(self.artifact_path) is not type(Path())
            or not self.artifact_path.is_absolute()
            or self.artifact_path != Path(os.path.abspath(self.artifact_path))
            or self.artifact_path.name != _outcome_file_name(self.outcome_sha256)
            or type(self.encoded) is not bytes
            or not self.encoded
            or len(self.encoded) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES
            or hashlib.sha256(self.encoded).hexdigest() != self.outcome_sha256
            or type(self.file_identity) is not tuple
            or len(self.file_identity) != 9
            or any(type(value) is not int for value in self.file_identity)
            or not stat.S_ISREG(self.file_identity[2])
            or stat.S_IMODE(self.file_identity[2]) != 0o600
            or self.file_identity[3] != os.geteuid()
            or self.file_identity[5] != 1
            or self.file_identity[6] != len(self.encoded)
            or type(self.slot_file_identity) is not tuple
            or len(self.slot_file_identity) != 9
            or any(type(value) is not int for value in self.slot_file_identity)
            or not stat.S_ISREG(self.slot_file_identity[2])
            or stat.S_IMODE(self.slot_file_identity[2]) != 0o600
            or self.slot_file_identity[3] != os.geteuid()
            or self.slot_file_identity[5] != 1
            or self.slot_file_identity[6]
            != len(
                _outcome_slot_bytes(
                    self.outcome_sha256,
                    outcome_contract_version=(
                        POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION
                    ),
                    status="retained",
                )
            )
            or self.status
            is not TrustedTimePostEnrollmentStartRetainedOutcomeStatus.RECOVERY_REQUIRED
            or self.reason
            is not (
                TrustedTimePostEnrollmentStartRetainedOutcomeReason.POST_ENROLLMENT_START_RECOVERY_REQUIRED
            )
        ):
            raise TrustedTimePostEnrollmentStartOutcomeRejected(
                "trusted-time post-enrollment retained recovery outcome is invalid"
            )
        expected = retained_post_enrollment_start_recovery_required_outcome_bytes(
            operation_id=self.operation_id,
            approval_sha256=self.approval_sha256,
            claim_sha256=self.claim_sha256,
            retained_claim_artifact_sha256=self.retained_claim_artifact_sha256,
        )
        if self.encoded != expected:
            raise TrustedTimePostEnrollmentStartOutcomeRejected(
                "trusted-time post-enrollment retained recovery outcome is invalid"
            )


class TrustedTimePostEnrollmentStartRecoveryOutcomeRetained(RuntimeError):
    """Terminal signal carrying the exact durably retained recovery outcome."""

    retained_outcome: RetainedTrustedTimePostEnrollmentStartOutcome

    def __init__(self, retained_outcome: RetainedTrustedTimePostEnrollmentStartOutcome) -> None:
        if type(retained_outcome) is not RetainedTrustedTimePostEnrollmentStartOutcome:
            raise TrustedTimePostEnrollmentStartOutcomeRejected(
                "trusted-time post-enrollment retained recovery outcome is invalid"
            )
        retained_outcome.__post_init__()
        self.retained_outcome = retained_outcome
        super().__init__("trusted-time post-enrollment recovery outcome was retained")


def _artifact_directory(artifact_directory: Path, *, ignored_root: Path) -> Path:
    try:
        canonical_root = Path(os.path.abspath(ignored_root))
        expected = canonical_root / "trusted-time"
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome directory is invalid"
        ) from None
    if (
        type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or not artifact_directory.is_absolute()
        or artifact_directory != Path(os.path.abspath(artifact_directory))
        or ignored_root != canonical_root
        or artifact_directory != expected
    ):
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome directory is invalid"
        )
    return expected


def _open_owner_only_artifact_directory(
    path: Path,
    *,
    ignored_root: Path,
    create: bool,
) -> _OwnedFileDescriptor:
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if absolute != path or root != ignored_root or absolute != root / "trusted-time":
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome directory is unavailable"
        )
    directory_owner: _OwnedFileDescriptor | None = None
    next_owner: _OwnedFileDescriptor | None = None
    previous_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_owned_descriptor(
            absolute.anchor,
            flags=(
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
        )
    except OSError:
        raise TrustedTimePostEnrollmentStartOutcomeRejected(
            "trusted-time post-enrollment recovery outcome directory is unavailable"
        ) from None
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            protected = current == root or current.is_relative_to(root)
            created = False
            if protected and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory_owner.fileno())
                    created = True
                except FileExistsError:
                    pass
            next_owner = _open_owned_descriptor(
                part,
                flags=(
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                ),
                dir_fd=directory_owner.fileno(),
            )
            metadata = os.fstat(next_owner.fileno())
            if created:
                os.fchmod(next_owner.fileno(), 0o700)
                metadata = os.fstat(next_owner.fileno())
            if protected and (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise OSError
            if created:
                os.fsync(next_owner.fileno())
                os.fsync(directory_owner.fileno())
            previous_owner = directory_owner
            directory_owner = next_owner
            next_owner = None
            previous_owner.close()
            previous_owner = None
        return directory_owner
    except BaseException as error:
        cleanup_error = _close_descriptor_owners((directory_owner, next_owner, previous_owner))
        terminal = _preferred_base_exception(error, cleanup_error)
        if terminal is not error and terminal is not None:
            raise terminal from error
        if isinstance(error, OSError):
            raise TrustedTimePostEnrollmentStartOutcomeRejected(
                "trusted-time post-enrollment recovery outcome directory is unavailable"
            ) from None
        raise


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _outcome_names(directory_descriptor: int) -> frozenset[str]:
    """Return one stable bounded inventory without reading outcome bytes."""

    if type(directory_descriptor) is not int or directory_descriptor < 0:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment recovery outcome inventory is unavailable"
        )
    try:
        before = os.fstat(directory_descriptor)
        names: list[str] = []
        with os.scandir(directory_descriptor) as iterator:
            for entry in iterator:
                name = entry.name
                if (
                    type(name) is not str
                    or not name
                    or len(os.fsencode(name))
                    > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES
                    or len(names) == MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES
                ):
                    raise OSError
                names.append(name)
        after = os.fstat(directory_descriptor)
        if _stable_file_identity(before) != _stable_file_identity(after):
            raise OSError
    except OSError:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment recovery outcome inventory is unavailable"
        ) from None
    return frozenset(
        name
        for name in names
        if name == POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME
        or (
            name.startswith(POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX)
            and name.endswith(POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX)
        )
    )


def _read_retained_outcome(
    directory_descriptor: int,
    *,
    file_name: str,
    expected_outcome_names: frozenset[str] | None = None,
) -> tuple[bytes, tuple[int, ...]]:
    file_owner: io.FileIO | None = None
    try:
        directory_before = os.fstat(directory_descriptor)
        file_owner = _open_owner_only_file(
            directory_descriptor,
            file_name,
            exclusive=False,
        )
        descriptor = file_owner.fileno()
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES
        ):
            raise OSError
        retained = bytearray()
        while len(retained) <= MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        after = os.fstat(descriptor)
        if expected_outcome_names is not None and (
            type(expected_outcome_names) is not frozenset
            or _outcome_names(directory_descriptor) != expected_outcome_names
        ):
            raise OSError
        named = os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
        directory_after = os.fstat(directory_descriptor)
        if (
            _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(named)
            or _stable_file_identity(directory_before) != _stable_file_identity(directory_after)
            or len(retained) != before.st_size
            or len(retained) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES
        ):
            raise OSError
        return bytes(retained), _stable_file_identity(before)
    except OSError:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment retained recovery outcome is unavailable"
        ) from None
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()


def _entry_is_absent(directory_descriptor: int, file_name: str) -> bool:
    try:
        os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _obscure_unconfirmed_recovery_outcome(
    directory_descriptor: int,
    *,
    file_name: str,
) -> None:
    """Keep an ambiguous final ineligible, preserving its inode when possible."""

    sentinel_owner: io.FileIO | None = None
    final_exists = not _entry_is_absent(directory_descriptor, file_name)
    staging_absent = _entry_is_absent(
        directory_descriptor,
        _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
    )
    if final_exists and staging_absent:
        try:
            os.rename(
                file_name,
                _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
        except BaseException:
            try:
                sentinel_owner = _open_owner_only_file(
                    directory_descriptor,
                    _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
                    exclusive=True,
                )
                sentinel_descriptor = sentinel_owner.fileno()
                os.fchmod(sentinel_descriptor, 0o600)
                os.fsync(sentinel_descriptor)
            except BaseException:
                try:
                    os.unlink(
                        file_name,
                        dir_fd=directory_descriptor,
                    )
                except BaseException:
                    raise OSError("trusted-time recovery outcome could not be obscured") from None
    if sentinel_owner is not None:
        sentinel_owner.close()
    os.fsync(directory_descriptor)
    if _entry_is_absent(
        directory_descriptor,
        _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
    ) and not _entry_is_absent(directory_descriptor, file_name):
        raise OSError("trusted-time recovery outcome remained publicly visible")


@contextmanager
def _fail_closed_recovery_outcome_publication(
    directory_descriptor: int,
    *,
    file_name: str,
) -> Iterator[None]:
    """Leave every interrupted legacy publication visibly incomplete."""

    try:
        yield
    except BaseException:
        _obscure_unconfirmed_recovery_outcome(
            directory_descriptor,
            file_name=file_name,
        )
        raise


def _receipt_from_encoded(
    *,
    encoded: bytes,
    artifact_path: Path,
    file_identity: tuple[int, ...],
    slot_file_identity: tuple[int, ...],
) -> RetainedTrustedTimePostEnrollmentStartOutcome:
    try:
        payload = json.loads(encoded)
        if type(payload) is not dict or canonical_first_enrollment_json_bytes(payload) != encoded:
            raise ValueError
        expected_keys = {
            *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
            *_CLOSED_OUTCOME_FIELDS,
            "approval_sha256",
            "claim_retention_revalidated",
            "claim_sha256",
            "contract_version",
            "operation_id",
            "reason",
            "retained_claim_artifact_sha256",
            "service",
            "status",
        }
        if (
            set(payload) != expected_keys
            or any(
                payload[field_name] is not False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
            )
            or any(payload[field_name] is not False for field_name in _CLOSED_OUTCOME_FIELDS)
            or payload["claim_retention_revalidated"] is not True
            or payload["contract_version"]
            != POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION
            or payload["service"] != POST_ENROLLMENT_START_RETAINED_OUTCOME_SERVICE
            or payload["status"]
            != TrustedTimePostEnrollmentStartRetainedOutcomeStatus.RECOVERY_REQUIRED
            or payload["reason"]
            != (
                TrustedTimePostEnrollmentStartRetainedOutcomeReason.POST_ENROLLMENT_START_RECOVERY_REQUIRED
            )
        ):
            raise ValueError
        operation_id = payload["operation_id"]
        approval_sha256 = payload["approval_sha256"]
        claim_sha256 = payload["claim_sha256"]
        retained_claim_artifact_sha256 = payload["retained_claim_artifact_sha256"]
        if (
            type(operation_id) is not str
            or type(approval_sha256) is not str
            or type(claim_sha256) is not str
            or type(retained_claim_artifact_sha256) is not str
        ):
            raise ValueError
        outcome_sha256 = hashlib.sha256(encoded).hexdigest()
        if artifact_path.name != _outcome_file_name(outcome_sha256):
            raise ValueError
        return RetainedTrustedTimePostEnrollmentStartOutcome(
            operation_id=operation_id,
            approval_sha256=approval_sha256,
            claim_sha256=claim_sha256,
            retained_claim_artifact_sha256=retained_claim_artifact_sha256,
            outcome_sha256=outcome_sha256,
            artifact_path=artifact_path,
            encoded=encoded,
            file_identity=file_identity,
            slot_file_identity=slot_file_identity,
            status=TrustedTimePostEnrollmentStartRetainedOutcomeStatus.RECOVERY_REQUIRED,
            reason=(
                TrustedTimePostEnrollmentStartRetainedOutcomeReason.POST_ENROLLMENT_START_RECOVERY_REQUIRED
            ),
        )
    except Exception:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment retained recovery outcome is unavailable"
        ) from None


def _persist_outcome(
    *,
    retained_claim: RetainedTrustedTimePostEnrollmentStartClaim,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentStartOutcome:
    claim = retained_claim.claim
    encoded = retained_post_enrollment_start_recovery_required_outcome_bytes(
        operation_id=retained_claim.operation_id,
        approval_sha256=claim.approval.approval_sha256,
        claim_sha256=claim.claim_sha256,
        retained_claim_artifact_sha256=retained_claim.artifact_sha256,
    )
    outcome_sha256 = hashlib.sha256(encoded).hexdigest()
    file_name = _outcome_file_name(outcome_sha256)
    reserved_slot_encoded = _outcome_slot_bytes(
        outcome_sha256,
        outcome_contract_version=POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION,
    )
    retained_slot_encoded = _outcome_slot_bytes(
        outcome_sha256,
        outcome_contract_version=POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION,
        status="retained",
    )
    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    file_owner: io.FileIO | None = None
    created_file_identity: tuple[int, ...] | None = None
    created_slot_identity: tuple[int, ...] | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
            create=True,
        )
        directory_descriptor = directory_owner.fileno()
        if _outcome_names(directory_descriptor):
            raise TrustedTimePostEnrollmentStartOutcomeAlreadyRetained(
                "trusted-time post-enrollment recovery outcome was already retained"
            )
        if not revalidate_retained_post_enrollment_start_claim(
            retained_claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ):
            raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
                "trusted-time post-enrollment recovery claim evidence is unavailable"
            )
        with (
            _reserve_and_lock_outcome_slot(
                directory_descriptor,
                encoded=reserved_slot_encoded,
            ) as locked_slot,
            _fail_closed_recovery_outcome_publication(
                directory_descriptor,
                file_name=file_name,
            ),
        ):
            slot_descriptor, reserved_slot_identity = locked_slot
            if _outcome_names(directory_descriptor):
                raise TrustedTimePostEnrollmentStartOutcomeAlreadyRetained(
                    "trusted-time post-enrollment recovery outcome was already retained"
                )
            file_owner = _open_owner_only_file(
                directory_descriptor,
                _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
                exclusive=True,
            )
            file_descriptor = file_owner.fileno()
            view = memoryview(encoded)
            while view:
                written = os.write(file_descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fchmod(file_descriptor, 0o600)
            os.fsync(file_descriptor)
            staged = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(staged.st_mode)
                or staged.st_uid != os.geteuid()
                or stat.S_IMODE(staged.st_mode) != 0o600
                or staged.st_nlink != 1
                or staged.st_size != len(encoded)
            ):
                raise OSError
            os.link(
                _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
                file_name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            linked = os.stat(
                file_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            staged_linked = os.fstat(file_descriptor)
            if (
                _stable_file_identity(linked) != _stable_file_identity(staged_linked)
                or staged_linked.st_nlink != 2
            ):
                raise OSError
            os.fsync(directory_descriptor)
            os.unlink(
                _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
                dir_fd=directory_descriptor,
            )
            published = os.fstat(file_descriptor)
            named = os.stat(
                file_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                _stable_file_identity(published) != _stable_file_identity(named)
                or published.st_nlink != 1
            ):
                raise OSError
            os.fsync(directory_descriptor)
            created_file_identity = _stable_file_identity(published)
            retained, observed_file_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=file_name,
                expected_outcome_names=frozenset({file_name}),
            )
            if (
                retained != encoded
                or observed_file_identity != created_file_identity
                or hashlib.sha256(retained).hexdigest() != outcome_sha256
            ):
                raise OSError
            reserved_slot, observed_reserved_slot_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                expected_outcome_names=frozenset({file_name}),
            )
            if (
                reserved_slot != reserved_slot_encoded
                or observed_reserved_slot_identity != reserved_slot_identity
                or _stable_file_identity(os.fstat(slot_descriptor))
                != observed_reserved_slot_identity
            ):
                raise OSError
            created_slot_identity = _write_locked_slot(
                slot_descriptor,
                retained_slot_encoded,
            )
            os.fsync(directory_descriptor)
            directory_identity = _stable_file_identity(os.fstat(directory_descriptor))
            slot, observed_slot_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                expected_outcome_names=frozenset({file_name}),
            )
            if (
                slot != retained_slot_encoded
                or observed_slot_identity != created_slot_identity
                or _stable_file_identity(os.fstat(slot_descriptor)) != observed_slot_identity
                or _stable_file_identity(os.fstat(directory_descriptor)) != directory_identity
            ):
                raise OSError
    except TrustedTimePostEnrollmentStartOutcomeAlreadyRetained:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise
    except FileExistsError:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartOutcomeAlreadyRetained(
            "trusted-time post-enrollment recovery outcome was already retained"
        ) from None
    except TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
            "trusted-time post-enrollment recovery outcome retention is unconfirmed"
        ) from None
    except TrustedTimePostEnrollmentStartOutcomeRejected:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise
    except OSError:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
            "trusted-time post-enrollment recovery outcome retention is unconfirmed"
        ) from None
    except BaseException:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
    if created_file_identity is None or created_slot_identity is None:
        raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
            "trusted-time post-enrollment recovery outcome retention is unconfirmed"
        )
    return RetainedTrustedTimePostEnrollmentStartOutcome(
        operation_id=retained_claim.operation_id,
        approval_sha256=claim.approval.approval_sha256,
        claim_sha256=claim.claim_sha256,
        retained_claim_artifact_sha256=retained_claim.artifact_sha256,
        outcome_sha256=outcome_sha256,
        artifact_path=artifact_directory / file_name,
        encoded=encoded,
        file_identity=created_file_identity,
        slot_file_identity=created_slot_identity,
        status=TrustedTimePostEnrollmentStartRetainedOutcomeStatus.RECOVERY_REQUIRED,
        reason=(
            TrustedTimePostEnrollmentStartRetainedOutcomeReason.POST_ENROLLMENT_START_RECOVERY_REQUIRED
        ),
    )


def _checkpoint_retained_claim(
    checkpoint: _TrustedTimePostEnrollmentRecoveryRetentionCheckpoint,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentStartClaim:
    try:
        retained_claim = checkpoint.retained_claim
        checkpoint_artifact_directory = checkpoint.artifact_directory
        checkpoint_ignored_root = checkpoint.ignored_root
        started = checkpoint.started_monotonic_ns
        deadline = checkpoint.deadline_monotonic_ns
        observed = checkpoint.observed_monotonic_ns
        if (
            type(checkpoint) is not _TrustedTimePostEnrollmentRecoveryRetentionCheckpoint
            or type(retained_claim) is not RetainedTrustedTimePostEnrollmentStartClaim
            or checkpoint_artifact_directory != artifact_directory
            or checkpoint_ignored_root != ignored_root
            or type(started) is not int
            or type(deadline) is not int
            or type(observed) is not int
            or started < 0
            or observed < started
            or observed >= deadline
            or deadline - started
            != POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS * _NANOSECONDS_PER_SECOND
        ):
            raise ValueError
        retained_claim.__post_init__()
        if retained_claim.artifact_path.parent != artifact_directory:
            raise ValueError
        return retained_claim
    except Exception:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment recovery claim evidence is unavailable"
        ) from None


def _abandon_retention(
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    recovery_retention_capability: object,
    checkpoint: _TrustedTimePostEnrollmentRecoveryRetentionCheckpoint,
) -> None:
    with suppress(BaseException):
        topology_issuer._abandon_recovery_outcome_retention(
            recovery_retention_capability,
            checkpoint,
        )


def retain_post_enrollment_start_recovery_required_outcome(
    *,
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    recovery_retention_capability: object,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> Never:
    """Retain the fixed claim-bound outcome, then raise its terminal receipt."""

    if type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer:
        raise TrustedTimePostEnrollmentStartOutcomeCapabilityUnavailable(
            "trusted-time post-enrollment recovery outcome capability is unavailable"
        )
    try:
        checkpoint = topology_issuer._begin_recovery_outcome_retention(
            recovery_retention_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    except BaseException:
        raise TrustedTimePostEnrollmentStartOutcomeCapabilityUnavailable(
            "trusted-time post-enrollment recovery outcome capability is unavailable"
        ) from None

    try:
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        retained_claim = _checkpoint_retained_claim(
            checkpoint,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        )
        if not revalidate_retained_post_enrollment_start_claim(
            retained_claim,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        ):
            raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
                "trusted-time post-enrollment recovery claim evidence is unavailable"
            )
        retained_outcome = _persist_outcome(
            retained_claim=retained_claim,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        )
        if not revalidate_retained_post_enrollment_start_claim(
            retained_claim,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        ):
            raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
                "trusted-time post-enrollment recovery outcome retention is unconfirmed"
            )
        if not revalidate_retained_post_enrollment_start_outcome(
            retained_outcome,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        ):
            raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
                "trusted-time post-enrollment recovery outcome retention is unconfirmed"
            )
        terminal = TrustedTimePostEnrollmentStartRecoveryOutcomeRetained(retained_outcome)
        try:
            topology_issuer._complete_recovery_outcome_retention(
                recovery_retention_capability,
                checkpoint,
                retained_outcome,
            )
        except BaseException:
            raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
                "trusted-time post-enrollment recovery outcome retention is unconfirmed"
            ) from None
    except (
        TrustedTimePostEnrollmentStartOutcomeAlreadyRetained,
        TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable,
        TrustedTimePostEnrollmentStartOutcomeRejected,
        TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed,
    ):
        _abandon_retention(topology_issuer, recovery_retention_capability, checkpoint)
        raise
    except BaseException:
        _abandon_retention(topology_issuer, recovery_retention_capability, checkpoint)
        raise TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed(
            "trusted-time post-enrollment recovery outcome retention is unconfirmed"
        ) from None

    raise terminal


def load_retained_post_enrollment_start_outcome(
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentStartOutcome:
    """Load one unique exact retained recovery outcome without authorizing action."""

    directory_owner: _OwnedFileDescriptor | None = None
    try:
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        directory_owner = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
    except Exception:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment retained recovery outcome is unavailable"
        ) from None
    try:
        with _locked_outcome_slot(directory_descriptor, exclusive=False) as slot_descriptor:
            os.fsync(slot_descriptor)
            os.fsync(directory_descriptor)
            directory_identity = _stable_file_identity(os.fstat(directory_descriptor))
            if not _entry_is_absent(
                directory_descriptor,
                _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
            ):
                raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
                    "trusted-time post-enrollment retained recovery outcome is unavailable"
                )
            names = _outcome_names(directory_descriptor)
            if len(names) != 1:
                raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
                    "trusted-time post-enrollment retained recovery outcome is unavailable"
                )
            file_name = next(iter(names))
            digest = file_name[
                len(POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX) : -len(
                    POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX
                )
            ]
            if file_name != _outcome_file_name(digest):
                raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
                    "trusted-time post-enrollment retained recovery outcome is unavailable"
                )
            encoded, file_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=file_name,
                expected_outcome_names=frozenset({file_name}),
            )
            slot, slot_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                expected_outcome_names=frozenset({file_name}),
            )
            if (
                slot
                != _outcome_slot_bytes(
                    digest,
                    outcome_contract_version=(
                        POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION
                    ),
                    status="retained",
                )
                or _stable_file_identity(os.fstat(slot_descriptor)) != slot_identity
                or _stable_file_identity(os.fstat(directory_descriptor)) != directory_identity
            ):
                raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
                    "trusted-time post-enrollment retained recovery outcome is unavailable"
                )
            return _receipt_from_encoded(
                encoded=encoded,
                artifact_path=absolute_directory / file_name,
                file_identity=file_identity,
                slot_file_identity=slot_identity,
            )
    except TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable(
            "trusted-time post-enrollment retained recovery outcome is unavailable"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def revalidate_retained_post_enrollment_start_outcome(
    retained: RetainedTrustedTimePostEnrollmentStartOutcome,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bool:
    """Return true only while the exact outcome inode and bytes remain stable."""

    if type(retained) is not RetainedTrustedTimePostEnrollmentStartOutcome:
        return False
    directory_owner: _OwnedFileDescriptor | None = None
    try:
        retained.__post_init__()
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        file_name = _outcome_file_name(retained.outcome_sha256)
        if retained.artifact_path != absolute_directory / file_name:
            return False
        directory_owner = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
    except Exception:
        return False
    try:
        with _locked_outcome_slot(directory_descriptor, exclusive=False) as slot_descriptor:
            os.fsync(slot_descriptor)
            os.fsync(directory_descriptor)
            directory_identity = _stable_file_identity(os.fstat(directory_descriptor))
            if not _entry_is_absent(
                directory_descriptor,
                _POST_ENROLLMENT_START_RECOVERY_OUTCOME_STAGING_FILE_NAME,
            ):
                return False
            observed, observed_file_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=file_name,
                expected_outcome_names=frozenset({file_name}),
            )
            slot, slot_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
                expected_outcome_names=frozenset({file_name}),
            )
            return (
                observed_file_identity == retained.file_identity
                and observed == retained.encoded
                and hashlib.sha256(observed).hexdigest() == retained.outcome_sha256
                and slot
                == _outcome_slot_bytes(
                    retained.outcome_sha256,
                    outcome_contract_version=(
                        POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION
                    ),
                    status="retained",
                )
                and slot_identity == retained.slot_file_identity
                and _stable_file_identity(os.fstat(slot_descriptor)) == slot_identity
                and _stable_file_identity(os.fstat(directory_descriptor)) == directory_identity
            )
    except Exception:
        return False
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


_finalize_post_enrollment_recovery_projection_types()

del _finalize_post_enrollment_recovery_projection_types
del _stage_post_enrollment_recovery_outcome_reason_type
del _stage_post_enrollment_recovery_outcome_status_type
del _stage_retained_post_enrollment_recovery_outcome_type


__all__ = [
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES",
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES",
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES",
    "POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME",
    "POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX",
    "POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX",
    "POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME",
    "POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS",
    "POST_ENROLLMENT_START_RETAINED_OUTCOME_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_RETAINED_OUTCOME_SERVICE",
    "RetainedTrustedTimePostEnrollmentStartOutcome",
    "TrustedTimePostEnrollmentStartOutcomeAlreadyRetained",
    "TrustedTimePostEnrollmentStartOutcomeCapabilityUnavailable",
    "TrustedTimePostEnrollmentStartOutcomeEvidenceUnavailable",
    "TrustedTimePostEnrollmentStartOutcomeRejected",
    "TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed",
    "TrustedTimePostEnrollmentStartRecoveryOutcomeRetained",
    "TrustedTimePostEnrollmentStartRetainedOutcomeReason",
    "TrustedTimePostEnrollmentStartRetainedOutcomeStatus",
    "load_retained_post_enrollment_start_outcome",
    "retain_post_enrollment_start_recovery_required_outcome",
    "retained_post_enrollment_start_recovery_required_outcome_bytes",
    "revalidate_retained_post_enrollment_start_outcome",
]
