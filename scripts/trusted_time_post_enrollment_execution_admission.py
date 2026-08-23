"""Owner-only, single-use admission for a dormant post-enrollment executor.

This module authenticates one externally retained, content-addressed approval
projection and one fresh immutable-image admission, then permanently reserves
the host-wide execution-attempt slot.  It does not read secrets, mutate a
topology, expose a CLI, or grant release, runtime, operational, or trading
authority.
"""

from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import uuid
import weakref
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.adapters.trusted_time._owned_file_descriptor import (
    _flock as _native_flock,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _fstat as _native_fstat,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _fsync as _native_fsync,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _open_child_directory as _native_open_child_directory,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _open_child_regular as _native_open_child_regular,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _open_root_directory as _native_open_root_directory,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _OwnedFileDescriptor as _NativeOwnedFileDescriptor,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _read_snapshot as _native_read_snapshot,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _statat as _native_statat,
)
from packages.adapters.trusted_time.ed25519_operator_attestation import (
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
    Ed25519PostEnrollmentOperatorAttestationVerifier,
    TrustedTimePostEnrollmentOperatorAttestationVerification,
    TrustedTimePostEnrollmentOperatorAttestationVerificationError,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    FIRST_ENROLLMENT_IDENTITY_FIELDS,
    POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION,
    POST_ENROLLMENT_START_REVIEW_SERVICE,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
    EXECUTION_APPROVAL_V2_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS,
    TrustedTimePostEnrollmentOperatorAttestationError,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
    decode_post_enrollment_operator_attestation_envelope,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
    require_strict_post_enrollment_operator_public_key,
)
from packages.domain.trusted_time_post_enrollment_start import (
    POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION,
    POST_ENROLLMENT_START_EXPECTED_PREDECESSOR_SEQUENCE,
    POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON,
    POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE,
    POST_ENROLLMENT_START_SERVICE,
    TrustedTimePostEnrollmentStartApproval,
)
from scripts import (
    trusted_time_post_enrollment_operator_attestation_artifacts as _external_artifacts,
)
from scripts.verify_trusted_time_images import (
    IGNORED_ARTIFACT_ROOT,
    IMAGE_ADMISSION_CONTRACT_VERSION,
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    ROOT,
    TrustedTimeImageAdmission,
    TrustedTimeImageAdmissionProvenance,
    _canonical_immutable_json_bytes,
    _decode_immutable_json_text,
    _head_reviewed_operator_authority_object,
    _load_image_admission_provenance_artifact_with_snapshot,
    _provenance_snapshot_value,
    _require_provenance_snapshot,
    _suspend_aware_monotonic_ns,
    load_image_admission_artifact,
    load_image_admission_provenance_artifact,
)
from scripts.verify_trusted_time_images import (
    _immutable_json_object as _verified_immutable_json_object,
)
from scripts.verify_trusted_time_images import (
    _immutable_json_object_items as _verified_immutable_json_object_items,
)

POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-approval-v2"
)
POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-attempt-v3"
)
POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-admission-v3"
)
HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-attempt-v2"
)
POST_ENROLLMENT_EXECUTION_APPROVAL_SERVICE = "trusted-time-post-enrollment-start-execution-approval"
POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE = (
    "trusted-time-post-enrollment-start-execution-admission"
)
POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX = (
    "trusted-time-post-enrollment-start-execution-approval-"
)
POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX = ".json"
POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX = (
    "trusted-time-post-enrollment-start-execution-approval-v3-"
)
POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH = (
    "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
)
POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME = ".post-enrollment-start-execution-attempt-slot"
POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS = 605
MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES = 65_536
DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY = IGNORED_ARTIFACT_ROOT / "trusted-time"

_CLOSED_EXECUTION_FIELDS = (
    "active_controller_authorized",
    "authority_granted",
    "claim_retention_authorized",
    "controller_execution_authorized",
    "database_secret_disclosed",
    "outcome_retention_authorized",
    "persistent_start_authorized",
    "release_authorized",
    "runtime_start_authorized",
    "sequence_2_authorized",
    "shutdown_authorized",
    "source_start_authorized",
    "supervisor_start_authorized",
    "topology_mutation_authorized",
)


class TrustedTimePostEnrollmentExecutionAdmissionRejected(RuntimeError):
    """The exact approval or immutable-image admission was not established."""


class TrustedTimePostEnrollmentExecutionAttemptConsumed(RuntimeError):
    """The permanent host-wide execution-attempt slot already exists."""


class TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(RuntimeError):
    """Attempt reservation may exist, but exact durable retention is unconfirmed."""


class TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(RuntimeError):
    """The exact retained v3 execution-attempt evidence is unavailable."""


def _authority_is_never_granted(_: object) -> bool:
    return False


def _authenticated_fact(value: object) -> bool:
    _validate_execution_admission(value)
    return True


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _closed_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update({field_name: False for field_name in _CLOSED_EXECUTION_FIELDS})
    return payload


def _v3_closed_payload() -> dict[str, object]:
    """Return the verifier's complete closed authority set for v3 only."""

    return {
        field_name: False
        for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
    }


def _is_git_revision(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_git_object_id(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_approval(
    approval: object,
    *,
    expected_approval_sha256: object,
) -> TrustedTimePostEnrollmentStartApproval:
    if type(approval) is not TrustedTimePostEnrollmentStartApproval or not _is_sha256(
        expected_approval_sha256
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval is invalid"
        )
    try:
        approval.__post_init__()
        observed_sha256 = approval.approval_sha256
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval is invalid"
        ) from None
    if observed_sha256 != expected_approval_sha256:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval differs from expectation"
        )
    return approval


def _tuple_payload(approval: TrustedTimePostEnrollmentStartApproval) -> dict[str, object]:
    return {
        "approval_sha256": approval.approval_sha256,
        "approved_image_provenance_sha256": (approval.proposed_launch.image_admission_sha256),
        "confirmed_enrollment_evidence_sha256": (approval.confirmed_enrollment.evidence_sha256),
        "git_revision": approval.proposed_launch.git_revision,
        "operation_id": approval.operation_id,
        "review_projection_sha256": approval.review.projection_sha256,
        "source_image_id": approval.proposed_launch.source_image_id,
        "supervisor_image_id": approval.proposed_launch.supervisor_image_id,
    }


def _execution_approval_payload(
    approval: TrustedTimePostEnrollmentStartApproval,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(
        {
            "approval": approval.payload(),
            "contract_version": POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION,
            "image_witness_contract_version": IMAGE_ADMISSION_CONTRACT_VERSION,
            "image_witness_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "service": POST_ENROLLMENT_EXECUTION_APPROVAL_SERVICE,
            "status": "execution_approval_artifact",
        }
    )
    return payload


def post_enrollment_execution_approval_bytes(
    approval: TrustedTimePostEnrollmentStartApproval,
    *,
    expected_approval_sha256: str,
) -> bytes:
    """Encode the one exact closed approval artifact for external retention."""

    exact = _require_approval(
        approval,
        expected_approval_sha256=expected_approval_sha256,
    )
    try:
        encoded = canonical_first_enrollment_json_bytes(_execution_approval_payload(exact))
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval is invalid"
        ) from None
    if not encoded or len(encoded) > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval is invalid"
        )
    return encoded


def _approval_file_name(artifact_sha256: str) -> str:
    if not _is_sha256(artifact_sha256):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact binding is invalid"
        )
    name = (
        f"{POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX}{artifact_sha256}"
        f"{POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX}"
    )
    if name in {".", ".."} or "/" in name or "\x00" in name or len(os.fsencode(name)) > 255:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact binding is invalid"
        )
    return name


def _approval_artifact_sha256_from_name(file_name: object) -> str:
    if (
        type(file_name) is not str
        or not file_name.startswith(POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX)
        or not file_name.endswith(POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX)
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact binding is invalid"
        )
    artifact_sha256 = file_name[
        len(POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX) : -len(
            POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX
        )
    ]
    if _approval_file_name(artifact_sha256) != file_name:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact binding is invalid"
        )
    return artifact_sha256


def post_enrollment_execution_approval_artifact_path(
    approval: TrustedTimePostEnrollmentStartApproval,
    *,
    expected_approval_sha256: str,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> Path:
    """Return the only canonical content-addressed path for the exact approval."""

    exact_directory, _ = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    encoded = post_enrollment_execution_approval_bytes(
        approval,
        expected_approval_sha256=expected_approval_sha256,
    )
    return exact_directory / _approval_file_name(hashlib.sha256(encoded).hexdigest())


def _exact_artifact_roots(
    artifact_directory: object,
    *,
    ignored_root: object,
) -> tuple[Path, Path]:
    if type(artifact_directory) is not type(Path()) or type(ignored_root) is not type(Path()):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution artifact root is invalid"
        )
    absolute_directory = Path(os.path.abspath(artifact_directory))
    absolute_root = Path(os.path.abspath(ignored_root))
    if (
        not artifact_directory.is_absolute()
        or absolute_directory != artifact_directory
        or not ignored_root.is_absolute()
        or absolute_root != ignored_root
        or absolute_directory != absolute_root / "trusted-time"
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution artifact root is invalid"
        )
    return absolute_directory, absolute_root


class _OwnedFileDescriptor(ctypes.c_int):
    """Own one libc-opened descriptor before the Python CALL can return."""

    def __index__(self) -> int:
        return self.fileno()

    def fileno(self) -> int:
        descriptor = self.value
        if descriptor < 0:
            raise OSError
        return descriptor

    @property
    def closed(self) -> bool:
        return self.value < 0

    def close(self) -> None:
        descriptor = self.value
        if descriptor < 0:
            return
        try:
            self.value = -1
            cleanup_error = _close_raw_descriptor_resiliently(descriptor)
        except BaseException as error:
            try:
                cleanup_error = _close_raw_descriptor_resiliently(descriptor)
            except BaseException as cleanup_failure:
                cleanup_error = cleanup_failure
            terminal = _preferred_cleanup_exception(error, cleanup_error)
            if terminal is None:
                raise error
            raise terminal from error
        if cleanup_error is not None:
            raise cleanup_error

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


def _preferred_cleanup_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_cleanup_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_cleanup_exception(preferred, error)
    return preferred


def _close_raw_descriptor_resiliently(descriptor: int) -> BaseException | None:
    first_error: BaseException | None = None
    closed = False
    for _ in range(3):
        try:
            os.close(descriptor)
            closed = True
            break
        except OSError as error:
            if error.errno == errno.EBADF:
                closed = True
                break
            first_error = _preferred_cleanup_exception(first_error, error)
        except BaseException as error:
            first_error = _preferred_cleanup_exception(first_error, error)
    if not closed and first_error is None:
        first_error = OSError(errno.EIO, os.strerror(errno.EIO))
    return first_error


def _cleanup_locked_owner(
    owner: _OwnedFileDescriptor | None,
    *,
    lock_call_started: bool,
) -> BaseException | None:
    if owner is None or owner.closed:
        return None
    first_error: BaseException | None = None
    if lock_call_started:
        unlocked = False
        for _ in range(2):
            try:
                fcntl.flock(owner.fileno(), fcntl.LOCK_UN)
                unlocked = True
                break
            except BaseException as error:
                first_error = _preferred_cleanup_exception(first_error, error)
        if not unlocked and first_error is None:
            first_error = OSError(errno.EIO, os.strerror(errno.EIO))
    try:
        owner.close()
    except BaseException as error:
        first_error = _preferred_cleanup_exception(first_error, error)
    return first_error


def _cleanup_locked_owners(
    owners: tuple[tuple[_OwnedFileDescriptor | None, bool], ...],
) -> BaseException | None:
    first_error: BaseException | None = None
    for owner, lock_call_started in owners:
        try:
            observed = _cleanup_locked_owner(
                owner,
                lock_call_started=lock_call_started,
            )
        except BaseException as error:
            observed = error
        first_error = _preferred_cleanup_exception(first_error, observed)
    return first_error


def _cleanup_native_locked_owner(
    owner: _NativeOwnedFileDescriptor | None,
    *,
    lock_call_started: bool,
) -> BaseException | None:
    if owner is None:
        return None
    first_error: BaseException | None = None
    if lock_call_started and not owner.closed:
        unlocked = False
        for _ in range(2):
            try:
                _native_flock(owner, fcntl.LOCK_UN)
                unlocked = True
                break
            except BaseException as error:
                first_error = _preferred_cleanup_exception(first_error, error)
        if not unlocked and first_error is None:
            first_error = OSError(errno.EIO, os.strerror(errno.EIO))
    for _ in range(2):
        try:
            if owner.closed:
                break
            owner.close()
        except BaseException as error:
            first_error = _preferred_cleanup_exception(first_error, error)
    try:
        if not owner.closed:
            first_error = _preferred_cleanup_exception(
                first_error,
                RuntimeError("native owned file descriptor could not be closed"),
            )
    except BaseException as error:
        first_error = _preferred_cleanup_exception(first_error, error)
    return first_error


def _cleanup_native_locked_owners(
    owners: tuple[tuple[_NativeOwnedFileDescriptor | None, bool], ...],
) -> BaseException | None:
    first_error: BaseException | None = None
    for owner, lock_call_started in owners:
        try:
            observed = _cleanup_native_locked_owner(
                owner,
                lock_call_started=lock_call_started,
            )
        except BaseException as error:
            observed = error
        first_error = _preferred_cleanup_exception(first_error, observed)
    return first_error


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
    """Open directly into a VM-owned descriptor object or raise exact errno."""

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


def _open_owner_only_artifact_directory(
    path: Path,
    *,
    ignored_root: Path,
) -> _OwnedFileDescriptor:
    """Open an existing canonical owner-only directory without following links."""

    if path != ignored_root / "trusted-time":
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution artifact directory is unavailable"
        )
    directory_owner: _OwnedFileDescriptor | None = None
    current = Path(path.anchor)
    try:
        directory_owner = _open_owned_descriptor(
            path.anchor,
            flags=(
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
        )
        for part in path.parts[1:]:
            current /= part
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
            try:
                metadata = os.fstat(next_owner.fileno())
                protected = current == ignored_root or current.is_relative_to(ignored_root)
                if protected and (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise OSError
            except BaseException:
                next_owner.close()
                raise
            directory_owner.close()
            directory_owner = next_owner
        return directory_owner
    except BaseException as error:
        if directory_owner is not None:
            directory_owner.close()
        if isinstance(error, OSError):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution artifact directory is unavailable"
            ) from None
        raise


def _open_owner_only_file(
    directory_descriptor: int,
    file_name: str,
    *,
    exclusive: bool,
) -> _OwnedFileDescriptor:
    """Return a VM-owned descriptor so async CALL/STORE loss closes it."""

    flags = (
        (
            (os.O_RDWR | os.O_CREAT | os.O_EXCL)
            if exclusive
            else (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        )
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return _open_owned_descriptor(
        file_name,
        flags=flags,
        mode=0o600,
        dir_fd=directory_descriptor,
    )


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


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FILE_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


type _ExternalOperatorAttestedApprovalBinding = tuple[
    str,
    str,
    bytes,
    tuple[int, int],
    tuple[int, ...],
]


def _make_external_approval_binding(
    *,
    path: str,
    encoded: bytes,
    directory_identity: tuple[int, int],
    file_identity: tuple[int, ...],
) -> _ExternalOperatorAttestedApprovalBinding:
    return (
        "external-operator-attested-approval-binding-v1",
        path,
        encoded,
        directory_identity,
        file_identity,
    )


def _require_external_approval_binding(
    value: object,
) -> _ExternalOperatorAttestedApprovalBinding:
    if type(value) is not tuple or len(value) != 5:
        raise ValueError
    tag = tuple.__getitem__(value, 0)
    path = tuple.__getitem__(value, 1)
    encoded = tuple.__getitem__(value, 2)
    directory_identity = tuple.__getitem__(value, 3)
    file_identity = tuple.__getitem__(value, 4)
    if (
        type(tag) is not str
        or tag != "external-operator-attested-approval-binding-v1"
        or type(path) is not str
        or type(encoded) is not bytes
        or type(directory_identity) is not tuple
        or len(directory_identity) != 2
        or any(type(item) is not int for item in directory_identity)
        or type(file_identity) is not tuple
        or len(file_identity) != 9
        or any(type(item) is not int for item in file_identity)
    ):
        raise ValueError
    return cast(_ExternalOperatorAttestedApprovalBinding, value)


def _external_approval_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_external_approval_binding(value), index)


def _open_directory_chain(
    path: Path,
    *,
    rejected_identities: frozenset[tuple[int, int]] = frozenset(),
) -> _OwnedFileDescriptor:
    owner: _OwnedFileDescriptor | None = None
    try:
        owner = _open_owned_descriptor(path.anchor, flags=_DIRECTORY_OPEN_FLAGS)
        metadata = os.fstat(owner.fileno())
        if (metadata.st_dev, metadata.st_ino) in rejected_identities:
            raise OSError
        for part in path.parts[1:]:
            next_owner = _open_owned_descriptor(
                part,
                flags=_DIRECTORY_OPEN_FLAGS,
                dir_fd=owner.fileno(),
            )
            try:
                metadata = os.fstat(next_owner.fileno())
                if (metadata.st_dev, metadata.st_ino) in rejected_identities:
                    raise OSError
            except BaseException:
                next_owner.close()
                raise
            owner.close()
            owner = next_owner
        return owner
    except BaseException:
        if owner is not None:
            with suppress(OSError):
                owner.close()
        raise


def _directory_identity(path: Path) -> tuple[int, int]:
    owner: _OwnedFileDescriptor | None = None
    try:
        owner = _open_directory_chain(path)
        metadata = os.fstat(owner.fileno())
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError
        return metadata.st_dev, metadata.st_ino
    finally:
        if owner is not None:
            with suppress(OSError):
                owner.close()


def _native_directory_identity(
    path: str,
    *,
    rejected_identities: frozenset[tuple[int, int]] = frozenset(),
) -> tuple[int, int]:
    """Return one primitive directory identity after closing every native owner."""

    owner: _NativeOwnedFileDescriptor | None = None
    next_owner: _NativeOwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    result: tuple[int, int] | None = None
    try:
        try:
            owner = _native_open_root_directory()
            metadata = _native_fstat(owner)
            if (metadata[0], metadata[1]) in rejected_identities:
                raise OSError
            for component in _external_artifacts._absolute_path_components(path):
                next_owner = _native_open_child_directory(owner, component)
                metadata = _native_fstat(next_owner)
                if (metadata[0], metadata[1]) in rejected_identities:
                    raise OSError
                intermediate_error = _cleanup_native_locked_owners(((owner, False),))
                if intermediate_error is not None:
                    raise intermediate_error
                owner = next_owner
                next_owner = None
            metadata = _native_fstat(owner)
            if not stat.S_ISDIR(metadata[2]):
                raise OSError
            result = metadata[0], metadata[1]
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_native_locked_owners(((next_owner, False), (owner, False)))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_native_locked_owners(((next_owner, False), (owner, False)))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if result is None:
        raise OSError
    return result


def _external_operator_attested_approval_file_name(envelope_sha256: str) -> str:
    if not _is_sha256(envelope_sha256):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact binding is invalid"
        )
    file_name = (
        f"{POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX}"
        f"{envelope_sha256}{POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX}"
    )
    if (
        file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or len(os.fsencode(file_name)) > 255
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact binding is invalid"
        )
    return file_name


def _operator_attested_approval_sha256_from_name(file_name: object) -> str:
    if (
        type(file_name) is not str
        or not file_name.startswith(POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX)
        or not file_name.endswith(POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX)
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact binding is invalid"
        )
    envelope_sha256 = file_name[
        len(POST_ENROLLMENT_OPERATOR_ATTESTED_APPROVAL_FILE_PREFIX) : -len(
            POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX
        )
    ]
    if _external_operator_attested_approval_file_name(envelope_sha256) != file_name:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact binding is invalid"
        )
    return envelope_sha256


def _open_external_operator_attested_approval_directory(
    path: Path,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> _OwnedFileDescriptor:
    if (
        path in (ROOT, ignored_root, artifact_directory)
        or path.is_relative_to(ROOT)
        or path.is_relative_to(ignored_root)
        or path.is_relative_to(artifact_directory)
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval external directory is unavailable"
        )
    owner: _OwnedFileDescriptor | None = None
    try:
        rejected = frozenset(
            {
                _directory_identity(ROOT),
                _directory_identity(ignored_root),
                _directory_identity(artifact_directory),
            }
        )
        owner = _open_directory_chain(path, rejected_identities=rejected)
        metadata = os.fstat(owner.fileno())
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OSError
        return owner
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        raise
    except BaseException as error:
        if owner is not None:
            with suppress(OSError):
                owner.close()
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval external directory is unavailable"
        ) from None


def _read_external_operator_attested_approval(
    operator_attested_approval_artifact: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> _ExternalOperatorAttestedApprovalBinding:
    if (
        type(operator_attested_approval_artifact) is not type(Path())
        or not operator_attested_approval_artifact.is_absolute()
        or operator_attested_approval_artifact
        != Path(os.path.abspath(operator_attested_approval_artifact))
        or operator_attested_approval_artifact.name in {"", ".", ".."}
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact binding is invalid"
        )
    path = operator_attested_approval_artifact
    exact_path = _external_artifacts._absolute_path(
        path,
        reason_code="operator_attested_approval_artifact_path_invalid",
    )
    _operator_attested_approval_sha256_from_name(os.path.basename(exact_path))
    try:
        artifact_directory_string = os.fspath(artifact_directory)
        ignored_root_string = os.fspath(ignored_root)
        repository_root_string = os.path.abspath(os.fspath(ROOT))
        candidate_directory = os.path.dirname(exact_path)
        if any(
            candidate_directory == rejected_root
            or candidate_directory.startswith(
                rejected_root if rejected_root.endswith(os.sep) else rejected_root + os.sep
            )
            for rejected_root in (
                repository_root_string,
                ignored_root_string,
                artifact_directory_string,
            )
        ):
            raise OSError
        rejected_identities = frozenset(
            {
                _native_directory_identity(repository_root_string),
                _native_directory_identity(ignored_root_string),
                _native_directory_identity(artifact_directory_string),
            }
        )
        binding = _external_artifacts._read_external_binding(
            Path(exact_path),
            allowed_modes=frozenset({0o600}),
            minimum_bytes=1,
            maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
            phase="operator_attested_approval_artifact",
        )
        binding_path = _external_artifacts._external_file_path(binding)
        binding_encoded = _external_artifacts._external_file_encoded(binding)
        binding_directory_identity = _external_artifacts._external_file_directory_identity(binding)
        binding_file_identity = _external_artifacts._external_file_file_identity(binding)
        if (
            binding_path != exact_path
            or binding_directory_identity in rejected_identities
            or _external_artifacts._external_file_allowed_modes(binding) != frozenset({0o600})
            or _external_artifacts._external_file_minimum_bytes(binding) != 1
            or _external_artifacts._external_file_maximum_bytes(binding)
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES
            or _external_artifacts._external_file_phase(binding)
            != "operator_attested_approval_artifact"
        ):
            raise OSError
        return _make_external_approval_binding(
            path=binding_path,
            encoded=binding_encoded,
            directory_identity=binding_directory_identity,
            file_identity=binding_file_identity,
        )
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact is unavailable"
        ) from None


def _revalidate_external_operator_attested_approval(
    binding: _ExternalOperatorAttestedApprovalBinding,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    try:
        exact_binding = _require_external_approval_binding(binding)
        observed = _read_external_operator_attested_approval(
            Path(
                cast(
                    str,
                    _external_approval_value(exact_binding, 1),
                )
            ),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        if observed != binding:
            raise ValueError
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval artifact changed during authentication"
        ) from None


def _read_owner_only_artifact(
    directory_descriptor: int,
    *,
    file_name: str,
) -> tuple[bytes, tuple[int, ...]]:
    file_owner: _OwnedFileDescriptor | None = None
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
            or before.st_size > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
        ):
            raise OSError
        retained = bytearray()
        while len(retained) <= MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
        directory_after = os.fstat(directory_descriptor)
        if (
            len(retained) != before.st_size
            or len(retained) > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
            or _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(named)
            or _stable_file_identity(directory_before) != _stable_file_identity(directory_after)
        ):
            raise OSError
        return bytes(retained), _stable_file_identity(before)
    except OSError:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is unavailable"
        ) from None
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()


def _confirm_owner_only_artifact_durable(
    directory_descriptor: int,
    *,
    file_name: str,
    expected_encoded: bytes | None,
    exclusive_flock: bool = False,
) -> tuple[bytes, tuple[int, ...]]:
    """Fsync and read back one exact held owner-only artifact and its name."""

    file_owner: _OwnedFileDescriptor | None = None

    def readback(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        retained = bytearray()
        while len(retained) <= MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        return bytes(retained)

    try:
        directory_before = os.fstat(directory_descriptor)
        file_owner = _open_owner_only_file(
            directory_descriptor,
            file_name,
            exclusive=False,
        )
        descriptor = file_owner.fileno()
        if exclusive_flock:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = os.fstat(descriptor)
            named_locked = os.stat(
                file_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if _stable_file_identity(locked) != _stable_file_identity(named_locked):
                raise OSError
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
        ):
            raise OSError
        encoded = readback(descriptor)
        after_read = os.fstat(descriptor)
        named_before = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            len(encoded) != before.st_size
            or (expected_encoded is not None and encoded != expected_encoded)
            or _stable_file_identity(before) != _stable_file_identity(after_read)
            or _stable_file_identity(after_read) != _stable_file_identity(named_before)
        ):
            raise OSError
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
        final_encoded = readback(descriptor)
        final = os.fstat(descriptor)
        named_final = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        directory_final = os.fstat(directory_descriptor)
        if (
            final_encoded != encoded
            or _stable_file_identity(before) != _stable_file_identity(final)
            or _stable_file_identity(final) != _stable_file_identity(named_final)
            or _stable_file_identity(directory_before) != _stable_file_identity(directory_final)
        ):
            raise OSError
        return final_encoded, _stable_file_identity(final)
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _decode_canonical_json(encoded: bytes) -> Mapping[str, object]:
    try:
        payload: Any = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None
    if type(payload) is not dict:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    try:
        canonical = canonical_first_enrollment_json_bytes(payload)
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None
    if canonical != encoded:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return payload


def _exact_mapping(
    value: object,
    *,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return value


def _exact_string(mapping: Mapping[str, object], name: str) -> str:
    value = mapping.get(name)
    if type(value) is not str:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return value


def _exact_integer(mapping: Mapping[str, object], name: str) -> int:
    value = mapping.get(name)
    if type(value) is not int:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return value


def _decode_launch(value: object) -> TrustedTimeImmutableLaunchEvidence:
    payload = _exact_mapping(
        value,
        keys=frozenset(
            {
                "git_revision",
                "image_admission_sha256",
                "source_image_id",
                "supervisor_image_id",
            }
        ),
    )
    try:
        return TrustedTimeImmutableLaunchEvidence(
            git_revision=_exact_string(payload, "git_revision"),
            image_admission_sha256=_exact_string(
                payload,
                "image_admission_sha256",
            ),
            source_image_id=_exact_string(payload, "source_image_id"),
            supervisor_image_id=_exact_string(payload, "supervisor_image_id"),
        )
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None


def _decode_identities(value: object) -> TrustedTimeFirstEnrollmentIdentities:
    payload = _exact_mapping(value, keys=FIRST_ENROLLMENT_IDENTITY_FIELDS)
    try:
        return TrustedTimeFirstEnrollmentIdentities(
            anchor_authority_sha256=_exact_string(
                payload,
                "anchor_authority_sha256",
            ),
            anchor_project_identity_sha256=_exact_string(
                payload,
                "anchor_project_identity_sha256",
            ),
            bucket_identity_sha256=_exact_string(payload, "bucket_identity_sha256"),
            deployment_identity_sha256=_exact_string(
                payload,
                "deployment_identity_sha256",
            ),
            host_identity_sha256=_exact_string(payload, "host_identity_sha256"),
            principal_identity_sha256=_exact_string(
                payload,
                "principal_identity_sha256",
            ),
            runtime_database_identity_sha256=_exact_string(
                payload,
                "runtime_database_identity_sha256",
            ),
            signing_public_key_sha256=_exact_string(
                payload,
                "signing_public_key_sha256",
            ),
            source_authority_sha256=_exact_string(
                payload,
                "source_authority_sha256",
            ),
        )
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None


_SEQUENCE_ONE_PAYLOAD_FIELDS = frozenset(
    {
        "anchor_intent_semantic_sha256",
        "anchor_sequence",
        "candidate_remote_readback_sha256",
        "checkpoint_reason",
        "completion_disposition",
        "current_anchor_semantic_sha256",
        "current_anchor_sha256",
        "current_host_head_sha256",
        "full_audit_completed",
        "idempotent_duplicate_count",
        "pending_intent_recovered",
        "receipt_semantic_sha256",
        "remote_namespace_sha256",
        "uploaded_anchor_count",
    }
)


def _decode_sequence_one(value: object) -> TrustedTimeSequenceOneEvidence:
    payload = _exact_mapping(value, keys=_SEQUENCE_ONE_PAYLOAD_FIELDS)
    if (
        payload.get("anchor_sequence") != 1
        or payload.get("checkpoint_reason") != "enrollment"
        or payload.get("full_audit_completed") is not True
        or payload.get("pending_intent_recovered") is not False
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    try:
        result = TrustedTimeSequenceOneEvidence(
            completion_disposition=_exact_string(
                payload,
                "completion_disposition",
            ),
            uploaded_anchor_count=_exact_integer(payload, "uploaded_anchor_count"),
            idempotent_duplicate_count=_exact_integer(
                payload,
                "idempotent_duplicate_count",
            ),
            anchor_intent_semantic_sha256=_exact_string(
                payload,
                "anchor_intent_semantic_sha256",
            ),
            candidate_remote_readback_sha256=_exact_string(
                payload,
                "candidate_remote_readback_sha256",
            ),
            current_anchor_semantic_sha256=_exact_string(
                payload,
                "current_anchor_semantic_sha256",
            ),
            current_anchor_sha256=_exact_string(
                payload,
                "current_anchor_sha256",
            ),
            current_host_head_sha256=_exact_string(
                payload,
                "current_host_head_sha256",
            ),
            receipt_semantic_sha256=_exact_string(
                payload,
                "receipt_semantic_sha256",
            ),
            remote_namespace_sha256=_exact_string(
                payload,
                "remote_namespace_sha256",
            ),
        )
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None
    if result.payload() != payload:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return result


_CONFIRMED_ENROLLMENT_PAYLOAD_FIELDS = frozenset(
    {
        "approval_sha256",
        "claim_sha256",
        "enrollment_launch",
        "identities",
        "operation_id",
        "outcome_sha256",
        "sequence_one",
        "unenrolled_admission_sha256",
    }
)


def _decode_confirmed_enrollment(
    value: object,
) -> TrustedTimeConfirmedFirstEnrollment:
    payload = _exact_mapping(
        value,
        keys=_CONFIRMED_ENROLLMENT_PAYLOAD_FIELDS,
    )
    try:
        result = TrustedTimeConfirmedFirstEnrollment(
            operation_id=_exact_string(payload, "operation_id"),
            approval_sha256=_exact_string(payload, "approval_sha256"),
            claim_sha256=_exact_string(payload, "claim_sha256"),
            outcome_sha256=_exact_string(payload, "outcome_sha256"),
            unenrolled_admission_sha256=_exact_string(
                payload,
                "unenrolled_admission_sha256",
            ),
            enrollment_launch=_decode_launch(payload.get("enrollment_launch")),
            identities=_decode_identities(payload.get("identities")),
            sequence_one=_decode_sequence_one(payload.get("sequence_one")),
        )
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None
    if result.payload() != payload:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return result


def _decode_approval_projection(value: object) -> TrustedTimePostEnrollmentStartApproval:
    if type(value) is not dict:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    confirmed = _decode_confirmed_enrollment(value.get("confirmed_enrollment"))
    proposed_launch = _decode_launch(value.get("proposed_launch"))
    try:
        approval = TrustedTimePostEnrollmentStartApproval(
            operation_id=_exact_string(value, "operation_id"),
            review=build_post_enrollment_start_review(
                confirmed_enrollment=confirmed,
                proposed_launch=proposed_launch,
            ),
        )
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        ) from None
    if approval.payload() != value:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return approval


def _decode_execution_approval_artifact(
    value: Mapping[str, object],
) -> TrustedTimePostEnrollmentStartApproval:
    approval = _decode_approval_projection(value.get("approval"))
    if _execution_approval_payload(approval) != value:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return approval


def decode_post_enrollment_execution_approval_bytes(
    encoded: object,
) -> TrustedTimePostEnrollmentStartApproval:
    """Semantically reconstruct one exact canonical embedded v2 approval."""

    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    exact_encoded = encoded
    payload = _decode_canonical_json(exact_encoded)
    approval = _decode_execution_approval_artifact(payload)
    expected = post_enrollment_execution_approval_bytes(
        approval,
        expected_approval_sha256=approval.approval_sha256,
    )
    if expected != exact_encoded:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact is invalid"
        )
    return approval


@dataclass(frozen=True, slots=True)
class LoadedTrustedTimePostEnrollmentExecutionApproval:
    """Exact bytes and inode of one externally retained closed approval."""

    approval: TrustedTimePostEnrollmentStartApproval
    image_provenance: TrustedTimeImageAdmissionProvenance
    artifact_sha256: str
    artifact_path: Path
    encoded: bytes = field(repr=False)
    file_identity: tuple[int, ...] = field(repr=False)

    def __post_init__(self) -> None:
        try:
            expected = canonical_first_enrollment_json_bytes(
                _execution_approval_payload(self.approval)
            )
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval receipt is invalid"
            ) from None
        if (
            type(self.approval) is not TrustedTimePostEnrollmentStartApproval
            or type(self.image_provenance) is not TrustedTimeImageAdmissionProvenance
            or not _is_sha256(self.artifact_sha256)
            or type(self.artifact_path) is not type(Path())
            or not self.artifact_path.is_absolute()
            or self.artifact_path != Path(os.path.abspath(self.artifact_path))
            or self.artifact_path.name != _approval_file_name(self.artifact_sha256)
            or type(self.encoded) is not bytes
            or not self.encoded
            or self.encoded != expected
            or hashlib.sha256(self.encoded).hexdigest() != self.artifact_sha256
            or type(self.file_identity) is not tuple
            or len(self.file_identity) != 9
            or any(type(item) is not int for item in self.file_identity)
            or not stat.S_ISREG(self.file_identity[2])
            or stat.S_IMODE(self.file_identity[2]) != 0o600
            or self.file_identity[3] != os.geteuid()
            or self.file_identity[5] != 1
            or self.file_identity[6] != len(self.encoded)
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval receipt is invalid"
            )
        launch = self.approval.proposed_launch
        try:
            self.image_provenance.__post_init__()
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval receipt is invalid"
            ) from None
        if (
            self.image_provenance.artifact_sha256 != launch.image_admission_sha256
            or self.image_provenance.git_revision != launch.git_revision
            or self.image_provenance.identities.source_id != launch.source_image_id
            or self.image_provenance.identities.supervisor_id != launch.supervisor_image_id
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval receipt is invalid"
            )


def load_post_enrollment_execution_approval(
    *,
    approval_artifact: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    image_provenance_loader: Callable[..., TrustedTimeImageAdmissionProvenance] = (
        load_image_admission_provenance_artifact
    ),
) -> LoadedTrustedTimePostEnrollmentExecutionApproval:
    """Load and reconstruct one self-contained exact approval artifact."""

    exact_directory, exact_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    if (
        type(approval_artifact) is not type(Path())
        or not approval_artifact.is_absolute()
        or approval_artifact != Path(os.path.abspath(approval_artifact))
        or approval_artifact.parent != exact_directory
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact binding is invalid"
        )
    file_name = approval_artifact.name
    artifact_sha256 = _approval_artifact_sha256_from_name(file_name)
    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            exact_directory,
            ignored_root=exact_root,
        )
        encoded, identity = _read_owner_only_artifact(
            directory_owner.fileno(),
            file_name=file_name,
        )
    finally:
        if directory_owner is not None:
            directory_owner.close()
    exact = decode_post_enrollment_execution_approval_bytes(encoded)
    if hashlib.sha256(encoded).hexdigest() != artifact_sha256:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval artifact differs from expectation"
        )
    try:
        provenance = image_provenance_loader(
            _image_admission_artifact_path(
                exact,
                artifact_directory=exact_directory,
            ),
            ignored_root=exact_root,
        )
        if type(provenance) is not TrustedTimeImageAdmissionProvenance:
            raise ValueError
        provenance.__post_init__()
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image provenance is invalid"
        ) from None
    return LoadedTrustedTimePostEnrollmentExecutionApproval(
        approval=exact,
        image_provenance=provenance,
        artifact_sha256=artifact_sha256,
        artifact_path=exact_directory / file_name,
        encoded=encoded,
        file_identity=identity,
    )


_OPERATOR_ATTESTATION_VERIFICATION_FIELDS = frozenset(
    {
        *POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
        "authority_artifact_sha256",
        "contract_version",
        "execution_approval_v2_sha256",
        "operator_attestation_envelope_sha256",
        "operator_attestation_statement_sha256",
        "public_key_sha256",
        "service",
        "status",
        "verification_only",
    }
)


def _require_exact_operator_attestation_verification(
    verification: object,
    *,
    authority_artifact_sha256: str,
    public_key_sha256: str,
    execution_approval_v2_sha256: str,
    operator_attestation_statement_sha256: str,
    operator_attestation_envelope_sha256: str,
) -> TrustedTimePostEnrollmentOperatorAttestationVerification:
    if type(verification) is not TrustedTimePostEnrollmentOperatorAttestationVerification:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval verification is invalid"
        )
    try:
        verification.__post_init__()
        payload = verification.payload()
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval verification is invalid"
        ) from None
    expected_digests = {
        "authority_artifact_sha256": authority_artifact_sha256,
        "public_key_sha256": public_key_sha256,
        "execution_approval_v2_sha256": execution_approval_v2_sha256,
        "operator_attestation_statement_sha256": operator_attestation_statement_sha256,
        "operator_attestation_envelope_sha256": operator_attestation_envelope_sha256,
    }
    if (
        set(payload) != _OPERATOR_ATTESTATION_VERIFICATION_FIELDS
        or payload.get("contract_version")
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
        or payload.get("service") != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
        or payload.get("status") != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
        or payload.get("verification_only") is not True
        or verification.verification_only is not True
        or any(payload.get(key) != value for key, value in expected_digests.items())
        or any(getattr(verification, key) != value for key, value in expected_digests.items())
        or any(
            payload.get(field_name) is not False or getattr(verification, field_name) is not False
            for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        )
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval verification is invalid"
        )
    return verification


_LOADED_ATTESTED_APPROVAL_CONSTRUCTION_CAPABILITY = object()


def _loaded_attested_seal_values(value: Any) -> tuple[object, ...]:
    provenance = value.image_provenance
    verification = value.verification
    return (
        canonical_first_enrollment_json_bytes(value.approval.payload()),
        os.fspath(provenance.path),
        provenance.identities.source_id,
        provenance.identities.supervisor_id,
        provenance.boot_session_id,
        provenance.git_revision,
        provenance.source_revision_sha256,
        provenance.artifact_sha256,
        provenance.created_at_utc,
        provenance.created_monotonic_ns,
        provenance.encoded,
        provenance.file_identity,
        os.fspath(value.artifact_path),
        value.operator_authority_git_revision,
        value.operator_authority_git_relative_path,
        value.operator_authority_git_mode,
        value.operator_authority_git_blob_object_id,
        value.operator_authority_artifact_sha256,
        value.operator_public_key_sha256,
        value.execution_approval_v2_sha256,
        value.operator_attestation_statement_sha256,
        value.operator_attestation_signature_sha256,
        value.operator_attestation_envelope_sha256,
        value.operator_attestation_verification_contract_version,
        value.operator_attestation_verification_service,
        value.operator_attestation_verification_status,
        verification.authority_artifact_sha256,
        verification.public_key_sha256,
        verification.execution_approval_v2_sha256,
        verification.operator_attestation_statement_sha256,
        verification.operator_attestation_envelope_sha256,
        value.encoded,
        value.directory_identity,
        value.file_identity,
    )


def _loaded_attested_fact(value: object) -> bool:
    if type(value) is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval receipt is invalid"
        )
    value.__post_init__()
    return True


@dataclass(frozen=True, slots=True, init=False)
class LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
    """Authenticated Git-authority, v3 envelope, and semantic v2 snapshot."""

    approval: TrustedTimePostEnrollmentStartApproval
    image_provenance: TrustedTimeImageAdmissionProvenance
    artifact_path: Path
    operator_authority_git_revision: str
    operator_authority_git_relative_path: str
    operator_authority_git_mode: str
    operator_authority_git_blob_object_id: str
    operator_authority_artifact_sha256: str
    operator_public_key_sha256: str
    execution_approval_v2_sha256: str
    operator_attestation_statement_sha256: str
    operator_attestation_signature_sha256: str
    operator_attestation_envelope_sha256: str
    operator_attestation_verification_contract_version: str
    operator_attestation_verification_service: str
    operator_attestation_verification_status: str
    verification: TrustedTimePostEnrollmentOperatorAttestationVerification = field(repr=False)
    encoded: bytes = field(repr=False)
    directory_identity: tuple[int, int] = field(repr=False)
    file_identity: tuple[int, ...] = field(repr=False)
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        approval: TrustedTimePostEnrollmentStartApproval,
        image_provenance: TrustedTimeImageAdmissionProvenance,
        artifact_path: Path,
        operator_authority_git_revision: str,
        operator_authority_git_relative_path: str,
        operator_authority_git_mode: str,
        operator_authority_git_blob_object_id: str,
        operator_authority_artifact_sha256: str,
        operator_public_key_sha256: str,
        execution_approval_v2_sha256: str,
        operator_attestation_statement_sha256: str,
        operator_attestation_signature_sha256: str,
        operator_attestation_envelope_sha256: str,
        operator_attestation_verification_contract_version: str,
        operator_attestation_verification_service: str,
        operator_attestation_verification_status: str,
        verification: TrustedTimePostEnrollmentOperatorAttestationVerification,
        encoded: bytes,
        directory_identity: tuple[int, int],
        file_identity: tuple[int, ...],
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
            or _construction_capability is not _LOADED_ATTESTED_APPROVAL_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time operator-attested approval receipt is invalid"
            )
        values = {
            "approval": approval,
            "image_provenance": image_provenance,
            "artifact_path": artifact_path,
            "operator_authority_git_revision": operator_authority_git_revision,
            "operator_authority_git_relative_path": operator_authority_git_relative_path,
            "operator_authority_git_mode": operator_authority_git_mode,
            "operator_authority_git_blob_object_id": operator_authority_git_blob_object_id,
            "operator_authority_artifact_sha256": operator_authority_artifact_sha256,
            "operator_public_key_sha256": operator_public_key_sha256,
            "execution_approval_v2_sha256": execution_approval_v2_sha256,
            "operator_attestation_statement_sha256": operator_attestation_statement_sha256,
            "operator_attestation_signature_sha256": operator_attestation_signature_sha256,
            "operator_attestation_envelope_sha256": operator_attestation_envelope_sha256,
            "operator_attestation_verification_contract_version": (
                operator_attestation_verification_contract_version
            ),
            "operator_attestation_verification_service": (
                operator_attestation_verification_service
            ),
            "operator_attestation_verification_status": (operator_attestation_verification_status),
            "verification": verification,
            "encoded": encoded,
            "directory_identity": directory_identity,
            "file_identity": file_identity,
        }
        for field_name, field_value in values.items():
            object.__setattr__(self, field_name, field_value)
        try:
            sealed_fields = _loaded_attested_seal_values(self)
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time operator-attested approval receipt is invalid"
            ) from None
        object.__setattr__(self, "_sealed_fields", sealed_fields)
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            envelope = decode_post_enrollment_operator_attestation_envelope(self.encoded)
            if (
                canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
                != self.encoded
            ):
                raise ValueError
            approval = decode_post_enrollment_execution_approval_bytes(
                envelope.execution_approval_v2
            )
            self.image_provenance.__post_init__()
            verification = _require_exact_operator_attestation_verification(
                self.verification,
                authority_artifact_sha256=self.operator_authority_artifact_sha256,
                public_key_sha256=self.operator_public_key_sha256,
                execution_approval_v2_sha256=self.execution_approval_v2_sha256,
                operator_attestation_statement_sha256=(self.operator_attestation_statement_sha256),
                operator_attestation_envelope_sha256=(self.operator_attestation_envelope_sha256),
            )
            seal_values = _loaded_attested_seal_values(self)
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time operator-attested approval receipt is invalid"
            ) from None
        launch = approval.proposed_launch
        if (
            type(self) is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
            or seal_values != getattr(self, "_sealed_fields", None)
            or type(self.approval) is not TrustedTimePostEnrollmentStartApproval
            or self.approval != approval
            or type(self.image_provenance) is not TrustedTimeImageAdmissionProvenance
            or type(self.artifact_path) is not type(Path())
            or not self.artifact_path.is_absolute()
            or self.artifact_path != Path(os.path.abspath(self.artifact_path))
            or self.artifact_path.name
            != _external_operator_attested_approval_file_name(
                self.operator_attestation_envelope_sha256
            )
            or type(self.encoded) is not bytes
            or not self.encoded
            or len(self.encoded) > POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES
            or hashlib.sha256(self.encoded).hexdigest() != self.operator_attestation_envelope_sha256
            or self.operator_authority_git_revision != launch.git_revision
            or not _is_git_revision(self.operator_authority_git_revision)
            or self.operator_authority_git_relative_path
            != POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
            or self.operator_authority_git_mode != "100644"
            or not _is_git_object_id(self.operator_authority_git_blob_object_id)
            or any(
                not _is_sha256(value)
                for value in (
                    self.operator_authority_artifact_sha256,
                    self.operator_public_key_sha256,
                    self.execution_approval_v2_sha256,
                    self.operator_attestation_statement_sha256,
                    self.operator_attestation_signature_sha256,
                    self.operator_attestation_envelope_sha256,
                )
            )
            or hashlib.sha256(envelope.execution_approval_v2).hexdigest()
            != self.execution_approval_v2_sha256
            or envelope.statement.statement_sha256 != self.operator_attestation_statement_sha256
            or hashlib.sha256(envelope.signature_ed25519).hexdigest()
            != self.operator_attestation_signature_sha256
            or envelope.envelope_sha256 != self.operator_attestation_envelope_sha256
            or self.operator_attestation_verification_contract_version
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
            or self.operator_attestation_verification_service
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
            or self.operator_attestation_verification_status
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
            or verification.execution_approval_v2_sha256 != self.execution_approval_v2_sha256
            or type(self.file_identity) is not tuple
            or len(self.file_identity) != 9
            or any(type(item) is not int for item in self.file_identity)
            or not stat.S_ISREG(self.file_identity[2])
            or stat.S_IMODE(self.file_identity[2]) != 0o600
            or self.file_identity[3] != os.geteuid()
            or self.file_identity[5] != 1
            or self.file_identity[6] != len(self.encoded)
            or type(self.directory_identity) is not tuple
            or len(self.directory_identity) != 2
            or any(type(item) is not int for item in self.directory_identity)
            or self.image_provenance.artifact_sha256 != launch.image_admission_sha256
            or self.image_provenance.git_revision != launch.git_revision
            or self.image_provenance.identities.source_id != launch.source_image_id
            or self.image_provenance.identities.supervisor_id != launch.supervisor_image_id
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time operator-attested approval receipt is invalid"
            )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval receipt cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval receipt cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval receipt cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval receipt cannot be serialized"
        )

    operator_authority_git_object_authenticated = property(_loaded_attested_fact)
    operator_attestation_envelope_authenticated = property(_loaded_attested_fact)
    operator_attestation_signature_authenticated = property(_loaded_attested_fact)
    execution_approval_v2_semantically_authenticated = property(_loaded_attested_fact)


def _validate_loaded_operator_attested_approval(value: object) -> None:
    if type(value) is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval receipt is invalid"
        )
    value.__post_init__()


_GitOperatorAuthorityLoader = Callable[[str], tuple[str, str, bytes]]


type _ImmutableJSONObject = tuple[object, ...]


type _ImmutableExecutionApprovalProjection = tuple[
    str,
    _ImmutableJSONObject,
    bytes,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
]


def _make_execution_approval_projection(
    *,
    approval: _ImmutableJSONObject,
    approval_encoded: bytes,
    approval_sha256: str,
    confirmed_enrollment_evidence_sha256: str,
    review_projection_sha256: str,
    operation_id: str,
    source_image_id: str,
    supervisor_image_id: str,
    git_revision: str,
    image_admission_sha256: str,
) -> _ImmutableExecutionApprovalProjection:
    return (
        "immutable-execution-approval-projection-v1",
        approval,
        approval_encoded,
        approval_sha256,
        confirmed_enrollment_evidence_sha256,
        review_projection_sha256,
        operation_id,
        source_image_id,
        supervisor_image_id,
        git_revision,
        image_admission_sha256,
    )


def _require_execution_approval_projection(
    value: object,
) -> _ImmutableExecutionApprovalProjection:
    if type(value) is not tuple or len(value) != 11:
        raise ValueError
    tag = tuple.__getitem__(value, 0)
    approval = tuple.__getitem__(value, 1)
    approval_encoded = tuple.__getitem__(value, 2)
    string_values = tuple(tuple.__getitem__(value, index) for index in range(3, 11))
    if (
        type(tag) is not str
        or tag != "immutable-execution-approval-projection-v1"
        or type(approval_encoded) is not bytes
        or any(type(item) is not str for item in string_values)
    ):
        raise ValueError
    _immutable_object_keys(approval)
    return cast(_ImmutableExecutionApprovalProjection, value)


def _execution_approval_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_execution_approval_projection(value), index)


def _immutable_json_object(
    items: tuple[tuple[str, object], ...],
) -> _ImmutableJSONObject:
    return _verified_immutable_json_object(tuple(sorted(items, key=lambda item: item[0])))


def _decode_immutable_canonical_json_object(
    encoded: object,
    *,
    maximum_bytes: int,
) -> _ImmutableJSONObject:
    if type(encoded) is not bytes or not encoded or len(encoded) > maximum_bytes:
        raise ValueError

    try:
        value = _decode_immutable_json_text(
            encoded.decode("utf-8", errors="strict"),
            maximum_characters=maximum_bytes,
            maximum_nodes=256,
            label="operator-attested execution approval",
        )
        _verified_immutable_json_object_items(
            value,
            label="operator-attested execution approval",
        )
    except (TypeError, UnicodeError, ValueError, RecursionError, RuntimeError):
        raise ValueError from None
    if _canonical_immutable_json_bytes(value) + b"\n" != encoded:
        raise ValueError
    return cast(_ImmutableJSONObject, value)


def _immutable_object_keys(value: object) -> frozenset[str]:
    try:
        items = _verified_immutable_json_object_items(
            value,
            label="operator-attested execution approval",
        )
    except RuntimeError:
        raise ValueError from None
    keys = tuple(cast(str, tuple.__getitem__(item, 0)) for item in items)
    if keys != tuple(sorted(keys)):
        raise ValueError
    return frozenset(keys)


def _immutable_object_value(value: object, field_name: str) -> object:
    if type(field_name) is not str:
        raise ValueError
    _immutable_object_keys(value)
    exact = _verified_immutable_json_object_items(
        value,
        label="operator-attested execution approval",
    )
    matches = tuple(
        tuple.__getitem__(item, 1) for item in exact if tuple.__getitem__(item, 0) == field_name
    )
    if len(matches) != 1:
        raise ValueError
    return matches[0]


def _require_immutable_object(
    value: object,
    *,
    fields: frozenset[str],
) -> _ImmutableJSONObject:
    if _immutable_object_keys(value) != fields:
        raise ValueError
    return cast(_ImmutableJSONObject, value)


def _immutable_string(value: object) -> str:
    if type(value) is not str:
        raise ValueError
    return value


def _immutable_integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError
    return value


def _is_uuid4_string(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_image_id(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _canonical_base64_value(value: object, *, exact_length: int | None = None) -> bytes:
    if type(value) is not str:
        raise ValueError
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError from None
    if (exact_length is not None and len(decoded) != exact_length) or base64.b64encode(
        decoded
    ).decode("ascii") != value:
        raise ValueError
    return decoded


def _require_immutable_launch(
    value: object,
) -> tuple[_ImmutableJSONObject, tuple[str, str, str, str]]:
    launch = _require_immutable_object(
        value,
        fields=frozenset(
            {
                "git_revision",
                "image_admission_sha256",
                "source_image_id",
                "supervisor_image_id",
            }
        ),
    )
    revision = _immutable_string(_immutable_object_value(launch, "git_revision"))
    image_admission_sha256 = _immutable_string(
        _immutable_object_value(launch, "image_admission_sha256")
    )
    source_image_id = _immutable_string(_immutable_object_value(launch, "source_image_id"))
    supervisor_image_id = _immutable_string(_immutable_object_value(launch, "supervisor_image_id"))
    if (
        not _is_git_revision(revision)
        or not _is_sha256(image_admission_sha256)
        or not _is_image_id(source_image_id)
        or not _is_image_id(supervisor_image_id)
        or source_image_id == supervisor_image_id
    ):
        raise ValueError
    expected = _immutable_json_object(
        (
            ("git_revision", revision),
            ("image_admission_sha256", image_admission_sha256),
            ("source_image_id", source_image_id),
            ("supervisor_image_id", supervisor_image_id),
        )
    )
    if launch != expected:
        raise ValueError
    return expected, (
        revision,
        image_admission_sha256,
        source_image_id,
        supervisor_image_id,
    )


def _require_immutable_identities(value: object) -> _ImmutableJSONObject:
    identities = _require_immutable_object(
        value,
        fields=FIRST_ENROLLMENT_IDENTITY_FIELDS,
    )
    if any(
        not _is_sha256(_immutable_object_value(identities, name))
        for name in FIRST_ENROLLMENT_IDENTITY_FIELDS
    ):
        raise ValueError
    expected = _immutable_json_object(
        tuple(
            (name, _immutable_string(_immutable_object_value(identities, name)))
            for name in FIRST_ENROLLMENT_IDENTITY_FIELDS
        )
    )
    if identities != expected:
        raise ValueError
    return expected


def _require_immutable_sequence_one(value: object) -> _ImmutableJSONObject:
    sequence = _require_immutable_object(value, fields=_SEQUENCE_ONE_PAYLOAD_FIELDS)
    uploaded = _immutable_integer(_immutable_object_value(sequence, "uploaded_anchor_count"))
    duplicate = _immutable_integer(_immutable_object_value(sequence, "idempotent_duplicate_count"))
    digest_fields = (
        "anchor_intent_semantic_sha256",
        "candidate_remote_readback_sha256",
        "current_anchor_semantic_sha256",
        "current_anchor_sha256",
        "current_host_head_sha256",
        "receipt_semantic_sha256",
        "remote_namespace_sha256",
    )
    digest_values = tuple(
        (name, _immutable_string(_immutable_object_value(sequence, name))) for name in digest_fields
    )
    if (
        _immutable_object_value(sequence, "anchor_sequence") != 1
        or _immutable_object_value(sequence, "checkpoint_reason") != "enrollment"
        or _immutable_object_value(sequence, "completion_disposition") != "new_intent_completed"
        or _immutable_object_value(sequence, "full_audit_completed") is not True
        or _immutable_object_value(sequence, "pending_intent_recovered") is not False
        or uploaded not in {0, 1}
        or duplicate not in {0, 1}
        or uploaded + duplicate != 1
        or any(not _is_sha256(item) for _, item in digest_values)
        or _immutable_object_value(sequence, "candidate_remote_readback_sha256")
        != _immutable_object_value(sequence, "current_anchor_sha256")
    ):
        raise ValueError
    expected = _immutable_json_object(
        (
            *digest_values,
            ("anchor_sequence", 1),
            ("checkpoint_reason", "enrollment"),
            ("completion_disposition", "new_intent_completed"),
            ("full_audit_completed", True),
            ("idempotent_duplicate_count", duplicate),
            ("pending_intent_recovered", False),
            ("uploaded_anchor_count", uploaded),
        )
    )
    if sequence != expected:
        raise ValueError
    return expected


def _require_immutable_confirmed_enrollment(
    value: object,
) -> tuple[
    _ImmutableJSONObject,
    str,
    tuple[str, str, str, str],
]:
    confirmed = _require_immutable_object(value, fields=_CONFIRMED_ENROLLMENT_PAYLOAD_FIELDS)
    operation_id = _immutable_string(_immutable_object_value(confirmed, "operation_id"))
    if not _is_uuid4_string(operation_id):
        raise ValueError
    for name in (
        "approval_sha256",
        "claim_sha256",
        "outcome_sha256",
        "unenrolled_admission_sha256",
    ):
        if not _is_sha256(_immutable_object_value(confirmed, name)):
            raise ValueError
    enrollment_launch, enrollment_launch_values = _require_immutable_launch(
        _immutable_object_value(confirmed, "enrollment_launch")
    )
    identities = _require_immutable_identities(_immutable_object_value(confirmed, "identities"))
    sequence_one = _require_immutable_sequence_one(
        _immutable_object_value(confirmed, "sequence_one")
    )
    expected = _immutable_json_object(
        (
            ("approval_sha256", _immutable_object_value(confirmed, "approval_sha256")),
            ("claim_sha256", _immutable_object_value(confirmed, "claim_sha256")),
            ("enrollment_launch", enrollment_launch),
            ("identities", identities),
            ("operation_id", operation_id),
            ("outcome_sha256", _immutable_object_value(confirmed, "outcome_sha256")),
            ("sequence_one", sequence_one),
            (
                "unenrolled_admission_sha256",
                _immutable_object_value(confirmed, "unenrolled_admission_sha256"),
            ),
        )
    )
    if confirmed != expected:
        raise ValueError
    return expected, operation_id, enrollment_launch_values


def _require_immutable_approval_projection(
    value: object,
) -> tuple[
    _ImmutableJSONObject,
    str,
    str,
    str,
    tuple[str, str, str, str],
]:
    closed_names = frozenset(
        {
            *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
            "authority_granted",
            "database_secret_disclosed",
            "persistent_start_authorized",
            "release_authorized",
            "sequence_2_authorized",
            "shutdown_authorized",
        }
    )
    approval = _require_immutable_object(
        value,
        fields=frozenset(
            {
                *closed_names,
                "confirmed_enrollment",
                "confirmed_enrollment_evidence_sha256",
                "contract_version",
                "expected_predecessor_sequence",
                "expected_successor_reason",
                "expected_successor_sequence",
                "operation_id",
                "proposed_launch",
                "review_projection_sha256",
                "service",
                "status",
            }
        ),
    )
    if any(_immutable_object_value(approval, name) is not False for name in closed_names):
        raise ValueError
    operation_id = _immutable_string(_immutable_object_value(approval, "operation_id"))
    if not _is_uuid4_string(operation_id):
        raise ValueError
    confirmed, confirmed_operation_id, enrollment_launch_values = (
        _require_immutable_confirmed_enrollment(
            _immutable_object_value(approval, "confirmed_enrollment")
        )
    )
    proposed_launch, proposed_launch_values = _require_immutable_launch(
        _immutable_object_value(approval, "proposed_launch")
    )
    if operation_id == confirmed_operation_id or any(
        proposed == enrollment
        for proposed, enrollment in zip(
            proposed_launch_values,
            enrollment_launch_values,
            strict=True,
        )
    ):
        raise ValueError
    confirmed_encoded = _canonical_immutable_json_bytes(confirmed) + b"\n"
    confirmed_sha256 = hashlib.sha256(confirmed_encoded).hexdigest()
    review_closed_names = frozenset(
        {
            *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
            "authority_granted",
            "database_secret_disclosed",
            "persistent_start_authorized",
            "sequence_2_authorized",
            "shutdown_authorized",
        }
    )
    review = _immutable_json_object(
        (
            *((name, False) for name in review_closed_names),
            ("confirmed_enrollment", confirmed),
            ("contract_version", POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION),
            ("proposed_launch", proposed_launch),
            ("service", POST_ENROLLMENT_START_REVIEW_SERVICE),
            ("status", "review_required"),
        )
    )
    review_sha256 = hashlib.sha256(_canonical_immutable_json_bytes(review) + b"\n").hexdigest()
    if (
        _immutable_object_value(approval, "confirmed_enrollment_evidence_sha256")
        != confirmed_sha256
        or _immutable_object_value(approval, "review_projection_sha256") != review_sha256
        or _immutable_object_value(approval, "contract_version")
        != POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION
        or _immutable_object_value(approval, "expected_predecessor_sequence")
        != POST_ENROLLMENT_START_EXPECTED_PREDECESSOR_SEQUENCE
        or _immutable_object_value(approval, "expected_successor_reason")
        != POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON
        or _immutable_object_value(approval, "expected_successor_sequence")
        != POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE
        or _immutable_object_value(approval, "service") != POST_ENROLLMENT_START_SERVICE
        or _immutable_object_value(approval, "status")
        != "approval_projection_external_attestation_required"
    ):
        raise ValueError
    expected = _immutable_json_object(
        (
            *((name, False) for name in closed_names),
            ("confirmed_enrollment", confirmed),
            ("confirmed_enrollment_evidence_sha256", confirmed_sha256),
            ("contract_version", POST_ENROLLMENT_START_APPROVAL_CONTRACT_VERSION),
            (
                "expected_predecessor_sequence",
                POST_ENROLLMENT_START_EXPECTED_PREDECESSOR_SEQUENCE,
            ),
            ("expected_successor_reason", POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_REASON),
            (
                "expected_successor_sequence",
                POST_ENROLLMENT_START_EXPECTED_SUCCESSOR_SEQUENCE,
            ),
            ("operation_id", operation_id),
            ("proposed_launch", proposed_launch),
            ("review_projection_sha256", review_sha256),
            ("service", POST_ENROLLMENT_START_SERVICE),
            ("status", "approval_projection_external_attestation_required"),
        )
    )
    if approval != expected:
        raise ValueError
    return expected, operation_id, confirmed_sha256, review_sha256, proposed_launch_values


def _immutable_execution_approval_projection(
    encoded: bytes,
) -> _ImmutableExecutionApprovalProjection:
    projection = _decode_immutable_canonical_json_object(
        encoded,
        maximum_bytes=MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES,
    )
    closed_names = frozenset({*FIRST_ENROLLMENT_AUTHORITY_FIELDS, *_CLOSED_EXECUTION_FIELDS})
    projection_fields = frozenset(
        {
            *closed_names,
            "approval",
            "approval_sha256",
            "approved_image_provenance_sha256",
            "confirmed_enrollment_evidence_sha256",
            "contract_version",
            "git_revision",
            "image_witness_contract_version",
            "image_witness_minimum_headroom_seconds",
            "operation_id",
            "review_projection_sha256",
            "service",
            "source_image_id",
            "status",
            "supervisor_image_id",
        }
    )
    _require_immutable_object(projection, fields=projection_fields)
    if any(_immutable_object_value(projection, name) is not False for name in closed_names):
        raise ValueError
    (
        approval,
        operation_id,
        confirmed_sha256,
        review_sha256,
        launch_values,
    ) = _require_immutable_approval_projection(_immutable_object_value(projection, "approval"))
    revision, image_admission_sha256, source_image_id, supervisor_image_id = launch_values
    approval_encoded = _canonical_immutable_json_bytes(approval) + b"\n"
    approval_sha256 = hashlib.sha256(approval_encoded).hexdigest()
    if (
        _immutable_object_value(projection, "approval_sha256") != approval_sha256
        or _immutable_object_value(projection, "approved_image_provenance_sha256")
        != image_admission_sha256
        or _immutable_object_value(projection, "confirmed_enrollment_evidence_sha256")
        != confirmed_sha256
        or _immutable_object_value(projection, "contract_version")
        != EXECUTION_APPROVAL_V2_CONTRACT_VERSION
        or _immutable_object_value(projection, "git_revision") != revision
        or _immutable_object_value(projection, "image_witness_contract_version")
        != IMAGE_ADMISSION_CONTRACT_VERSION
        or _immutable_object_value(projection, "image_witness_minimum_headroom_seconds")
        != POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        or _immutable_object_value(projection, "operation_id") != operation_id
        or _immutable_object_value(projection, "review_projection_sha256") != review_sha256
        or _immutable_object_value(projection, "service")
        != POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE
        or _immutable_object_value(projection, "source_image_id") != source_image_id
        or _immutable_object_value(projection, "status") != EXECUTION_APPROVAL_V2_STATUS
        or _immutable_object_value(projection, "supervisor_image_id") != supervisor_image_id
    ):
        raise ValueError
    expected = _immutable_json_object(
        (
            *((name, False) for name in closed_names),
            ("approval", approval),
            ("approval_sha256", approval_sha256),
            ("approved_image_provenance_sha256", image_admission_sha256),
            ("confirmed_enrollment_evidence_sha256", confirmed_sha256),
            ("contract_version", EXECUTION_APPROVAL_V2_CONTRACT_VERSION),
            ("git_revision", revision),
            ("image_witness_contract_version", IMAGE_ADMISSION_CONTRACT_VERSION),
            (
                "image_witness_minimum_headroom_seconds",
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS,
            ),
            ("operation_id", operation_id),
            ("review_projection_sha256", review_sha256),
            ("service", POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE),
            ("source_image_id", source_image_id),
            ("status", EXECUTION_APPROVAL_V2_STATUS),
            ("supervisor_image_id", supervisor_image_id),
        )
    )
    if projection != expected or _canonical_immutable_json_bytes(expected) + b"\n" != encoded:
        raise ValueError
    return _require_execution_approval_projection(
        _make_execution_approval_projection(
            approval=approval,
            approval_encoded=approval_encoded,
            approval_sha256=approval_sha256,
            confirmed_enrollment_evidence_sha256=confirmed_sha256,
            review_projection_sha256=review_sha256,
            operation_id=operation_id,
            source_image_id=source_image_id,
            supervisor_image_id=supervisor_image_id,
            git_revision=revision,
            image_admission_sha256=image_admission_sha256,
        )
    )


type _LoadedOperatorAttestedApprovalSnapshot = tuple[object, ...]
type _ImmutableAttestationEnvelopeProjection = tuple[object, ...]
type _ImmutableOperatorAuthorityProjection = tuple[object, ...]


def _make_loaded_approval_snapshot(*values: object) -> _LoadedOperatorAttestedApprovalSnapshot:
    return ("loaded-operator-attested-approval-snapshot-v1", *values)


def _require_loaded_approval_snapshot(value: object) -> _LoadedOperatorAttestedApprovalSnapshot:
    if type(value) is not tuple or len(value) != 31:
        raise ValueError
    if (
        type(tuple.__getitem__(value, 0)) is not str
        or tuple.__getitem__(value, 0) != "loaded-operator-attested-approval-snapshot-v1"
    ):
        raise ValueError
    string_indexes = (
        1,
        2,
        3,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        22,
        23,
        24,
        25,
        26,
        27,
    )
    bytes_indexes = (
        4,
        7,
        8,
        21,
        28,
    )
    if any(type(tuple.__getitem__(value, index)) is not str for index in string_indexes) or any(
        type(tuple.__getitem__(value, index)) is not bytes for index in bytes_indexes
    ):
        raise ValueError
    for index, length in (
        (5, 2),
        (6, 9),
    ):
        identity = tuple.__getitem__(value, index)
        if (
            type(identity) is not tuple
            or len(identity) != length
            or any(type(item) is not int for item in identity)
        ):
            raise ValueError
    _require_provenance_snapshot(tuple.__getitem__(value, 29))
    seal_values = tuple.__getitem__(value, 30)
    if type(seal_values) is not tuple:
        raise ValueError
    return cast(_LoadedOperatorAttestedApprovalSnapshot, value)


def _loaded_approval_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_loaded_approval_snapshot(value), index)


def _make_attestation_envelope_projection(
    *values: object,
) -> _ImmutableAttestationEnvelopeProjection:
    return ("immutable-attestation-envelope-projection-v1", *values)


def _require_attestation_envelope_projection(
    value: object,
) -> _ImmutableAttestationEnvelopeProjection:
    if type(value) is not tuple or len(value) != 11:
        raise ValueError
    if (
        type(tuple.__getitem__(value, 0)) is not str
        or tuple.__getitem__(value, 0) != "immutable-attestation-envelope-projection-v1"
        or type(tuple.__getitem__(value, 3)) is not bytes
        or type(tuple.__getitem__(value, 6)) is not bytes
        or type(tuple.__getitem__(value, 8)) is not bytes
        or any(
            type(tuple.__getitem__(value, index)) is not str
            for index in (
                4,
                7,
                9,
                10,
            )
        )
    ):
        raise ValueError
    _immutable_object_keys(tuple.__getitem__(value, 1))
    _require_execution_approval_projection(tuple.__getitem__(value, 2))
    _immutable_object_keys(tuple.__getitem__(value, 5))
    return cast(_ImmutableAttestationEnvelopeProjection, value)


def _attestation_envelope_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_attestation_envelope_projection(value), index)


def _make_operator_authority_projection(*values: object) -> _ImmutableOperatorAuthorityProjection:
    return ("immutable-operator-authority-projection-v1", *values)


def _require_operator_authority_projection(
    value: object,
) -> _ImmutableOperatorAuthorityProjection:
    if type(value) is not tuple or len(value) != 5:
        raise ValueError
    if (
        type(tuple.__getitem__(value, 0)) is not str
        or tuple.__getitem__(value, 0) != "immutable-operator-authority-projection-v1"
        or type(tuple.__getitem__(value, 2)) is not bytes
        or type(tuple.__getitem__(value, 3)) is not str
        or type(tuple.__getitem__(value, 4)) is not str
    ):
        raise ValueError
    _immutable_object_keys(tuple.__getitem__(value, 1))
    return cast(_ImmutableOperatorAuthorityProjection, value)


def _operator_authority_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_operator_authority_projection(value), index)


def _immutable_attestation_envelope_projection(
    encoded: bytes,
) -> _ImmutableAttestationEnvelopeProjection:
    envelope = _decode_immutable_canonical_json_object(
        encoded,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    )
    envelope_fields = frozenset(
        {
            "contract_version",
            "execution_approval_v2_base64",
            "execution_approval_v2_sha256",
            "operator_attestation_statement",
            "operator_attestation_statement_sha256",
            "service",
            "signature_algorithm",
            "signature_base64",
            "status",
        }
    )
    _require_immutable_object(envelope, fields=envelope_fields)
    execution_approval_v2_base64 = _immutable_string(
        _immutable_object_value(envelope, "execution_approval_v2_base64")
    )
    signature_base64 = _immutable_string(_immutable_object_value(envelope, "signature_base64"))
    execution_approval_v2_encoded = _canonical_base64_value(execution_approval_v2_base64)
    signature_encoded = _canonical_base64_value(signature_base64, exact_length=64)
    execution_approval = _immutable_execution_approval_projection(execution_approval_v2_encoded)
    execution_approval_v2_sha256 = hashlib.sha256(execution_approval_v2_encoded).hexdigest()
    statement = _require_immutable_object(
        _immutable_object_value(envelope, "operator_attestation_statement"),
        fields=frozenset(
            {
                "algorithm",
                "authority_artifact_sha256",
                "authority_contract_version",
                "contract_version",
                "decision",
                "execution_approval_contract_version",
                "execution_approval_v2_sha256",
                "key_id",
                "public_key_sha256",
                "replay_domain",
                "service",
                "status",
            }
        ),
    )
    authority_sha256 = _immutable_string(
        _immutable_object_value(statement, "authority_artifact_sha256")
    )
    public_key_sha256 = _immutable_string(_immutable_object_value(statement, "public_key_sha256"))
    if (
        not _is_sha256(authority_sha256)
        or not _is_sha256(public_key_sha256)
        or _immutable_object_value(statement, "algorithm")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM
        or _immutable_object_value(statement, "authority_contract_version")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION
        or _immutable_object_value(statement, "contract_version")
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
        or _immutable_object_value(statement, "decision")
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION
        or _immutable_object_value(statement, "execution_approval_contract_version")
        != EXECUTION_APPROVAL_V2_CONTRACT_VERSION
        or _immutable_object_value(statement, "execution_approval_v2_sha256")
        != execution_approval_v2_sha256
        or _immutable_object_value(statement, "key_id") != POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID
        or _immutable_object_value(statement, "replay_domain")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
        or _immutable_object_value(statement, "service")
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE
        or _immutable_object_value(statement, "status")
        != POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS
    ):
        raise ValueError
    expected_statement = _immutable_json_object(
        (
            ("algorithm", POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM),
            ("authority_artifact_sha256", authority_sha256),
            (
                "authority_contract_version",
                POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
            ),
            (
                "contract_version",
                POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
            ),
            ("decision", POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION),
            ("execution_approval_contract_version", EXECUTION_APPROVAL_V2_CONTRACT_VERSION),
            ("execution_approval_v2_sha256", execution_approval_v2_sha256),
            ("key_id", POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID),
            ("public_key_sha256", public_key_sha256),
            ("replay_domain", POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN),
            ("service", POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE),
            ("status", POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS),
        )
    )
    if statement != expected_statement:
        raise ValueError
    statement_encoded = _canonical_immutable_json_bytes(expected_statement) + b"\n"
    statement_sha256 = hashlib.sha256(statement_encoded).hexdigest()
    envelope_sha256 = hashlib.sha256(encoded).hexdigest()
    if (
        _immutable_object_value(envelope, "contract_version")
        != POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION
        or _immutable_object_value(envelope, "execution_approval_v2_sha256")
        != execution_approval_v2_sha256
        or _immutable_object_value(envelope, "operator_attestation_statement_sha256")
        != statement_sha256
        or _immutable_object_value(envelope, "service")
        != POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE
        or _immutable_object_value(envelope, "signature_algorithm")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM
        or _immutable_object_value(envelope, "status")
        != POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS
    ):
        raise ValueError
    expected_envelope = _immutable_json_object(
        (
            (
                "contract_version",
                POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION,
            ),
            ("execution_approval_v2_base64", execution_approval_v2_base64),
            ("execution_approval_v2_sha256", execution_approval_v2_sha256),
            ("operator_attestation_statement", expected_statement),
            ("operator_attestation_statement_sha256", statement_sha256),
            ("service", POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE),
            ("signature_algorithm", POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM),
            ("signature_base64", signature_base64),
            ("status", POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS),
        )
    )
    if (
        envelope != expected_envelope
        or _canonical_immutable_json_bytes(expected_envelope) + b"\n" != encoded
    ):
        raise ValueError
    return _require_attestation_envelope_projection(
        _make_attestation_envelope_projection(
            expected_envelope,
            execution_approval,
            execution_approval_v2_encoded,
            execution_approval_v2_sha256,
            expected_statement,
            statement_encoded,
            statement_sha256,
            signature_encoded,
            hashlib.sha256(signature_encoded).hexdigest(),
            envelope_sha256,
        )
    )


def _immutable_operator_authority_projection(
    encoded: bytes,
) -> _ImmutableOperatorAuthorityProjection:
    authority = _decode_immutable_canonical_json_object(
        encoded,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    )
    _require_immutable_object(
        authority,
        fields=frozenset(
            {
                "algorithm",
                "contract_version",
                "key_id",
                "public_key_base64",
                "public_key_sha256",
                "replay_domain",
                "service",
                "status",
            }
        ),
    )
    public_key_base64 = _immutable_string(_immutable_object_value(authority, "public_key_base64"))
    public_key_encoded = _canonical_base64_value(public_key_base64, exact_length=32)
    require_strict_post_enrollment_operator_public_key(public_key_encoded)
    public_key_sha256 = hashlib.sha256(public_key_encoded).hexdigest()
    if (
        _immutable_object_value(authority, "algorithm")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM
        or _immutable_object_value(authority, "contract_version")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION
        or _immutable_object_value(authority, "key_id") != POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID
        or _immutable_object_value(authority, "public_key_sha256") != public_key_sha256
        or _immutable_object_value(authority, "replay_domain")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
        or _immutable_object_value(authority, "service")
        != POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE
        or _immutable_object_value(authority, "status") != POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS
    ):
        raise ValueError
    expected_authority = _immutable_json_object(
        (
            ("algorithm", POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM),
            ("contract_version", POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION),
            ("key_id", POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID),
            ("public_key_base64", public_key_base64),
            ("public_key_sha256", public_key_sha256),
            ("replay_domain", POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN),
            ("service", POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE),
            ("status", POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS),
        )
    )
    if (
        authority != expected_authority
        or _canonical_immutable_json_bytes(expected_authority) + b"\n" != encoded
    ):
        raise ValueError
    return _require_operator_authority_projection(
        _make_operator_authority_projection(
            expected_authority,
            public_key_encoded,
            public_key_sha256,
            hashlib.sha256(encoded).hexdigest(),
        )
    )


def _immutable_verification_encoded(
    *,
    authority_artifact_sha256: str,
    public_key_sha256: str,
    execution_approval_v2_sha256: str,
    statement_sha256: str,
    envelope_sha256: str,
) -> bytes:
    expected = _immutable_json_object(
        (
            *(
                (name, False)
                for name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
            ),
            ("authority_artifact_sha256", authority_artifact_sha256),
            (
                "contract_version",
                POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
            ),
            ("execution_approval_v2_sha256", execution_approval_v2_sha256),
            ("operator_attestation_envelope_sha256", envelope_sha256),
            ("operator_attestation_statement_sha256", statement_sha256),
            ("public_key_sha256", public_key_sha256),
            ("service", POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE),
            ("status", POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS),
            ("verification_only", True),
        )
    )
    return _canonical_immutable_json_bytes(expected) + b"\n"


def _load_post_enrollment_operator_attested_execution_approval_with_snapshot(
    *,
    operator_attested_approval_artifact: Path,
    artifact_directory: Path,
    ignored_root: Path,
) -> tuple[
    LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
    _LoadedOperatorAttestedApprovalSnapshot,
]:
    """Authenticate and return a private immutable pre-publication source snapshot."""

    exact_directory, exact_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    binding = _read_external_operator_attested_approval(
        operator_attested_approval_artifact,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    binding = _require_external_approval_binding(binding)
    binding_path = cast(str, _external_approval_value(binding, 1))
    binding_encoded = cast(
        bytes,
        _external_approval_value(binding, 2),
    )
    binding_directory_identity = cast(
        tuple[int, int],
        _external_approval_value(binding, 3),
    )
    binding_file_identity = cast(
        tuple[int, ...],
        _external_approval_value(binding, 4),
    )
    try:
        envelope_projection = _immutable_attestation_envelope_projection(binding_encoded)
        execution_projection = cast(
            _ImmutableExecutionApprovalProjection,
            _attestation_envelope_value(
                envelope_projection,
                2,
            ),
        )
        exact_operation_id = cast(
            str,
            _execution_approval_value(execution_projection, 6),
        )
        exact_approval_sha256 = cast(
            str,
            _execution_approval_value(
                execution_projection,
                3,
            ),
        )
        exact_confirmed_enrollment_evidence_sha256 = cast(
            str,
            _execution_approval_value(
                execution_projection,
                4,
            ),
        )
        exact_review_projection_sha256 = cast(
            str,
            _execution_approval_value(
                execution_projection,
                5,
            ),
        )
        exact_source_image_id = cast(
            str,
            _execution_approval_value(execution_projection, 7),
        )
        exact_supervisor_image_id = cast(
            str,
            _execution_approval_value(
                execution_projection,
                8,
            ),
        )
        exact_revision = cast(
            str,
            _execution_approval_value(execution_projection, 9),
        )
        exact_image_admission_sha256 = cast(
            str,
            _execution_approval_value(
                execution_projection,
                10,
            ),
        )
        execution_approval_v2_encoded = cast(
            bytes,
            _attestation_envelope_value(
                envelope_projection,
                3,
            ),
        )
        execution_approval_v2_sha256 = cast(
            str,
            _attestation_envelope_value(
                envelope_projection,
                4,
            ),
        )
        approval_encoded = cast(
            bytes,
            _execution_approval_value(
                execution_projection,
                2,
            ),
        )
        statement_sha256 = cast(
            str,
            _attestation_envelope_value(
                envelope_projection,
                7,
            ),
        )
        signature_sha256 = cast(
            str,
            _attestation_envelope_value(
                envelope_projection,
                9,
            ),
        )
        envelope_sha256 = cast(
            str,
            _attestation_envelope_value(
                envelope_projection,
                10,
            ),
        )
        envelope = decode_post_enrollment_operator_attestation_envelope(binding_encoded)
        if (
            canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
            != binding_encoded
            or envelope.execution_approval_v2 != execution_approval_v2_encoded
            or envelope.signature_ed25519
            != _attestation_envelope_value(
                envelope_projection,
                8,
            )
        ):
            raise ValueError
        if (
            Path(binding_path).name
            != _external_operator_attested_approval_file_name(envelope_sha256)
            or _operator_attested_approval_sha256_from_name(Path(binding_path).name)
            != envelope_sha256
        ):
            raise ValueError
        approval = decode_post_enrollment_execution_approval_bytes(execution_approval_v2_encoded)
        launch = approval.proposed_launch
        if (
            canonical_first_enrollment_json_bytes(approval.payload()) != approval_encoded
            or approval.operation_id != exact_operation_id
            or approval.approval_sha256 != exact_approval_sha256
            or approval.confirmed_enrollment.evidence_sha256
            != exact_confirmed_enrollment_evidence_sha256
            or approval.review.projection_sha256 != exact_review_projection_sha256
            or launch.source_image_id != exact_source_image_id
            or launch.supervisor_image_id != exact_supervisor_image_id
            or launch.git_revision != exact_revision
            or launch.image_admission_sha256 != exact_image_admission_sha256
        ):
            raise ValueError
        mode, blob_object_id, authority_encoded = _head_reviewed_operator_authority_object(
            exact_revision
        )
        if (
            type(mode) is not str
            or mode != "100644"
            or not _is_git_object_id(blob_object_id)
            or type(authority_encoded) is not bytes
            or not authority_encoded
            or len(authority_encoded) > POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES
        ):
            raise ValueError
        authority_projection = _immutable_operator_authority_projection(authority_encoded)
        if _operator_authority_value(
            authority_projection,
            4,
        ) != _immutable_object_value(
            _attestation_envelope_value(
                envelope_projection,
                5,
            ),
            "authority_artifact_sha256",
        ) or _operator_authority_value(
            authority_projection,
            3,
        ) != _immutable_object_value(
            _attestation_envelope_value(
                envelope_projection,
                5,
            ),
            "public_key_sha256",
        ):
            raise ValueError
        exact_public_key_sha256 = cast(
            str,
            _operator_authority_value(
                authority_projection,
                3,
            ),
        )
        authority_sha256 = cast(
            str,
            _operator_authority_value(authority_projection, 4),
        )
        Ed25519PublicKey.from_public_bytes(
            cast(
                bytes,
                _operator_authority_value(
                    authority_projection,
                    2,
                ),
            )
        ).verify(
            cast(
                bytes,
                _attestation_envelope_value(
                    envelope_projection,
                    8,
                ),
            ),
            cast(
                bytes,
                _attestation_envelope_value(
                    envelope_projection,
                    6,
                ),
            ),
        )
        authority = decode_post_enrollment_operator_authority(authority_encoded)
        if (
            canonical_post_enrollment_operator_authority_bytes(authority) != authority_encoded
            or authority.public_key_sha256 != exact_public_key_sha256
        ):
            raise ValueError
        verifier = Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority)
        verification = verifier.verify(envelope)
        if (
            envelope.statement.statement_sha256 != statement_sha256
            or envelope.statement.authority_artifact_sha256 != authority_sha256
            or envelope.statement.public_key_sha256 != exact_public_key_sha256
            or envelope.statement.execution_approval_v2_sha256 != execution_approval_v2_sha256
        ):
            raise ValueError
        _require_exact_operator_attestation_verification(
            verification,
            authority_artifact_sha256=authority_sha256,
            public_key_sha256=exact_public_key_sha256,
            execution_approval_v2_sha256=execution_approval_v2_sha256,
            operator_attestation_statement_sha256=statement_sha256,
            operator_attestation_envelope_sha256=envelope_sha256,
        )
        provenance, provenance_snapshot = _load_image_admission_provenance_artifact_with_snapshot(
            exact_directory / f"image-admission-{exact_image_admission_sha256}.json",
            ignored_root=exact_root,
        )
        provenance_snapshot = _require_provenance_snapshot(provenance_snapshot)
        provenance_path = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 1),
        )
        provenance_source_id = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 2),
        )
        provenance_supervisor_id = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 3),
        )
        provenance_boot_session_id = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 4),
        )
        provenance_git_revision = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 5),
        )
        provenance_source_revision_sha256 = cast(
            str,
            _provenance_snapshot_value(
                provenance_snapshot,
                6,
            ),
        )
        provenance_artifact_sha256 = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 8),
        )
        provenance_created_at_utc = cast(
            str,
            _provenance_snapshot_value(provenance_snapshot, 9),
        )
        provenance_created_monotonic_ns = cast(
            int,
            _provenance_snapshot_value(
                provenance_snapshot,
                10,
            ),
        )
        provenance_encoded = cast(
            bytes,
            _provenance_snapshot_value(provenance_snapshot, 11),
        )
        provenance_file_identity = cast(
            tuple[int, ...],
            _provenance_snapshot_value(provenance_snapshot, 13),
        )
        if (
            provenance_artifact_sha256 != exact_image_admission_sha256
            or provenance_git_revision != exact_revision
            or provenance_source_id != exact_source_image_id
            or provenance_supervisor_id != exact_supervisor_image_id
            or provenance.artifact_sha256 != provenance_artifact_sha256
            or provenance.git_revision != provenance_git_revision
            or provenance.identities.source_id != provenance_source_id
            or provenance.identities.supervisor_id != provenance_supervisor_id
            or launch.image_admission_sha256 != exact_image_admission_sha256
            or launch.git_revision != exact_revision
            or launch.source_image_id != exact_source_image_id
            or launch.supervisor_image_id != exact_supervisor_image_id
        ):
            raise ValueError
        verification_encoded = _immutable_verification_encoded(
            authority_artifact_sha256=authority_sha256,
            public_key_sha256=exact_public_key_sha256,
            execution_approval_v2_sha256=execution_approval_v2_sha256,
            statement_sha256=statement_sha256,
            envelope_sha256=envelope_sha256,
        )
        if canonical_first_enrollment_json_bytes(verification.payload()) != verification_encoded:
            raise ValueError
        loaded_seal_values: tuple[object, ...] = (
            approval_encoded,
            provenance_path,
            provenance_source_id,
            provenance_supervisor_id,
            provenance_boot_session_id,
            provenance_git_revision,
            provenance_source_revision_sha256,
            provenance_artifact_sha256,
            provenance_created_at_utc,
            provenance_created_monotonic_ns,
            provenance_encoded,
            provenance_file_identity,
            binding_path,
            exact_revision,
            POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH,
            mode,
            blob_object_id,
            authority_sha256,
            exact_public_key_sha256,
            execution_approval_v2_sha256,
            statement_sha256,
            signature_sha256,
            envelope_sha256,
            POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
            POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
            POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
            authority_sha256,
            exact_public_key_sha256,
            execution_approval_v2_sha256,
            statement_sha256,
            envelope_sha256,
            binding_encoded,
            binding_directory_identity,
            binding_file_identity,
        )
        snapshot = _require_loaded_approval_snapshot(
            _make_loaded_approval_snapshot(
                os.fspath(exact_directory),
                os.fspath(exact_root),
                binding_path,
                binding_encoded,
                binding_directory_identity,
                binding_file_identity,
                execution_approval_v2_encoded,
                approval_encoded,
                exact_approval_sha256,
                exact_confirmed_enrollment_evidence_sha256,
                exact_review_projection_sha256,
                exact_operation_id,
                exact_source_image_id,
                exact_supervisor_image_id,
                exact_revision,
                exact_image_admission_sha256,
                os.path.abspath(os.fspath(ROOT)),
                POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH,
                mode,
                blob_object_id,
                authority_encoded,
                authority_sha256,
                exact_public_key_sha256,
                execution_approval_v2_sha256,
                statement_sha256,
                signature_sha256,
                envelope_sha256,
                verification_encoded,
                provenance_snapshot,
                loaded_seal_values,
            )
        )
        loaded = LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval(
            approval=approval,
            image_provenance=provenance,
            artifact_path=Path(binding_path),
            operator_authority_git_revision=exact_revision,
            operator_authority_git_relative_path=(
                POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
            ),
            operator_authority_git_mode=mode,
            operator_authority_git_blob_object_id=blob_object_id,
            operator_authority_artifact_sha256=authority_sha256,
            operator_public_key_sha256=exact_public_key_sha256,
            execution_approval_v2_sha256=execution_approval_v2_sha256,
            operator_attestation_statement_sha256=statement_sha256,
            operator_attestation_signature_sha256=signature_sha256,
            operator_attestation_envelope_sha256=envelope_sha256,
            operator_attestation_verification_contract_version=(
                POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
            ),
            operator_attestation_verification_service=(
                POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
            ),
            operator_attestation_verification_status=(
                POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
            ),
            verification=verification,
            encoded=binding_encoded,
            directory_identity=binding_directory_identity,
            file_identity=binding_file_identity,
            _construction_capability=_LOADED_ATTESTED_APPROVAL_CONSTRUCTION_CAPABILITY,
        )
        if _loaded_attested_seal_values(loaded) != _loaded_approval_value(
            snapshot,
            30,
        ):
            raise ValueError
        _revalidate_external_operator_attested_approval(
            binding,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
        )
        final_mode, final_blob_object_id, final_authority_encoded = (
            _head_reviewed_operator_authority_object(exact_revision)
        )
        _, final_provenance_snapshot = _load_image_admission_provenance_artifact_with_snapshot(
            Path(provenance_path),
            ignored_root=exact_root,
        )
        if (
            (final_mode, final_blob_object_id, final_authority_encoded)
            != (mode, blob_object_id, authority_encoded)
            or final_provenance_snapshot != provenance_snapshot
            or _immutable_attestation_envelope_projection(binding_encoded) != envelope_projection
            or _immutable_operator_authority_projection(final_authority_encoded)
            != authority_projection
            or _loaded_attested_seal_values(loaded) != _loaded_approval_value(snapshot, 30)
        ):
            raise ValueError
        return loaded, snapshot
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval authentication failed"
        ) from None


def _load_post_enrollment_operator_attested_execution_approval(
    *,
    operator_attested_approval_artifact: Path,
    artifact_directory: Path,
    ignored_root: Path,
    image_provenance_loader: Callable[..., TrustedTimeImageAdmissionProvenance],
    git_operator_authority_loader: _GitOperatorAuthorityLoader,
) -> LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
    exact_directory, exact_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    binding = _read_external_operator_attested_approval(
        operator_attested_approval_artifact,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    binding = _require_external_approval_binding(binding)
    binding_path = cast(str, _external_approval_value(binding, 1))
    binding_encoded = cast(
        bytes,
        _external_approval_value(binding, 2),
    )
    binding_directory_identity = cast(
        tuple[int, int],
        _external_approval_value(binding, 3),
    )
    binding_file_identity = cast(
        tuple[int, ...],
        _external_approval_value(binding, 4),
    )
    try:
        envelope = decode_post_enrollment_operator_attestation_envelope(binding_encoded)
        if (
            canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
            != binding_encoded
        ):
            raise ValueError
        envelope_sha256 = hashlib.sha256(binding_encoded).hexdigest()
        if (
            Path(binding_path).name
            != _external_operator_attested_approval_file_name(envelope_sha256)
            or _operator_attested_approval_sha256_from_name(Path(binding_path).name)
            != envelope_sha256
        ):
            raise ValueError
        approval = decode_post_enrollment_execution_approval_bytes(envelope.execution_approval_v2)
        revision = approval.proposed_launch.git_revision
        mode, blob_object_id, authority_encoded = git_operator_authority_loader(revision)
        if (
            type(mode) is not str
            or mode != "100644"
            or not _is_git_object_id(blob_object_id)
            or type(authority_encoded) is not bytes
            or not authority_encoded
            or len(authority_encoded) > POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES
        ):
            raise ValueError
        authority = decode_post_enrollment_operator_authority(authority_encoded)
        if canonical_post_enrollment_operator_authority_bytes(authority) != authority_encoded:
            raise ValueError
        authority_sha256 = hashlib.sha256(authority_encoded).hexdigest()
        verifier = Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority)
        verification = verifier.verify(envelope)
        statement_sha256 = envelope.statement.statement_sha256
        execution_approval_v2_sha256 = hashlib.sha256(envelope.execution_approval_v2).hexdigest()
        _require_exact_operator_attestation_verification(
            verification,
            authority_artifact_sha256=authority_sha256,
            public_key_sha256=authority.public_key_sha256,
            execution_approval_v2_sha256=execution_approval_v2_sha256,
            operator_attestation_statement_sha256=statement_sha256,
            operator_attestation_envelope_sha256=envelope_sha256,
        )
        provenance = image_provenance_loader(
            _image_admission_artifact_path(
                approval,
                artifact_directory=exact_directory,
            ),
            ignored_root=exact_root,
        )
        if type(provenance) is not TrustedTimeImageAdmissionProvenance:
            raise ValueError
        provenance.__post_init__()
        launch = approval.proposed_launch
        if (
            provenance.artifact_sha256 != launch.image_admission_sha256
            or provenance.git_revision != launch.git_revision
            or provenance.identities.source_id != launch.source_image_id
            or provenance.identities.supervisor_id != launch.supervisor_image_id
        ):
            raise ValueError
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        raise
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        TrustedTimePostEnrollmentOperatorAuthorityError,
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval authentication failed"
        ) from None
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time operator-attested approval authentication failed"
        ) from None
    _revalidate_external_operator_attested_approval(
        binding,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    return LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval(
        approval=approval,
        image_provenance=provenance,
        artifact_path=Path(binding_path),
        operator_authority_git_revision=revision,
        operator_authority_git_relative_path=(POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH),
        operator_authority_git_mode=mode,
        operator_authority_git_blob_object_id=blob_object_id,
        operator_authority_artifact_sha256=authority_sha256,
        operator_public_key_sha256=authority.public_key_sha256,
        execution_approval_v2_sha256=execution_approval_v2_sha256,
        operator_attestation_statement_sha256=statement_sha256,
        operator_attestation_signature_sha256=hashlib.sha256(
            envelope.signature_ed25519
        ).hexdigest(),
        operator_attestation_envelope_sha256=envelope_sha256,
        operator_attestation_verification_contract_version=(
            POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
        ),
        operator_attestation_verification_service=(
            POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
        ),
        operator_attestation_verification_status=(
            POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
        ),
        verification=verification,
        encoded=binding_encoded,
        directory_identity=binding_directory_identity,
        file_identity=binding_file_identity,
        _construction_capability=_LOADED_ATTESTED_APPROVAL_CONSTRUCTION_CAPABILITY,
    )


def load_post_enrollment_operator_attested_execution_approval(
    *,
    operator_attested_approval_artifact: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
    """Authenticate one external v3 envelope and its exact reviewed Git authority."""

    return _load_post_enrollment_operator_attested_execution_approval(
        operator_attested_approval_artifact=operator_attested_approval_artifact,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        image_provenance_loader=load_image_admission_provenance_artifact,
        git_operator_authority_loader=_head_reviewed_operator_authority_object,
    )


def retain_post_enrollment_execution_approval(
    approval: TrustedTimePostEnrollmentStartApproval,
    *,
    expected_approval_sha256: str,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> LoadedTrustedTimePostEnrollmentExecutionApproval:
    """Durably retain one stable approval, accepting only exact idempotence."""

    exact_directory, exact_root = _exact_artifact_roots(
        artifact_directory,
        ignored_root=ignored_root,
    )
    encoded = post_enrollment_execution_approval_bytes(
        approval,
        expected_approval_sha256=expected_approval_sha256,
    )
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    path = exact_directory / _approval_file_name(artifact_sha256)

    # Authenticate the approved stable provenance before creating approval bytes.
    try:
        provenance = load_image_admission_provenance_artifact(
            _image_admission_artifact_path(
                approval,
                artifact_directory=exact_directory,
            ),
            ignored_root=exact_root,
        )
        if (
            provenance.artifact_sha256 != approval.proposed_launch.image_admission_sha256
            or provenance.git_revision != approval.proposed_launch.git_revision
            or provenance.identities.source_id != approval.proposed_launch.source_image_id
            or provenance.identities.supervisor_id != approval.proposed_launch.supervisor_image_id
        ):
            raise ValueError
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image provenance is invalid"
        ) from None

    directory_owner: _OwnedFileDescriptor | None = None
    file_owner: _OwnedFileDescriptor | None = None
    creation_call_started = False
    created = False
    try:
        directory_owner = _open_owner_only_artifact_directory(
            exact_directory,
            ignored_root=exact_root,
        )
        directory_descriptor = directory_owner.fileno()
        try:
            creation_call_started = True
            file_owner = _open_owner_only_file(
                directory_descriptor,
                path.name,
                exclusive=True,
            )
        except FileExistsError:
            creation_call_started = False
            file_owner = None
            try:
                existing, _ = _read_owner_only_artifact(
                    directory_descriptor,
                    file_name=path.name,
                )
            except BaseException as error:
                raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                    "trusted-time post-enrollment execution approval retention is unconfirmed"
                ) from error
            if existing != encoded:
                raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                    "trusted-time post-enrollment execution approval differs from expectation"
                ) from None
            try:
                _confirm_owner_only_artifact_durable(
                    directory_descriptor,
                    file_name=path.name,
                    expected_encoded=encoded,
                )
            except BaseException as error:
                raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                    "trusted-time post-enrollment execution approval retention is unconfirmed"
                ) from error
        if file_owner is not None:
            created = True
            descriptor = file_owner.fileno()
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.ftruncate(descriptor, len(encoded))
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(directory_descriptor)
    except BaseException as error:
        if creation_call_started or created:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval retention is unconfirmed"
            ) from error
        raise
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()
        if directory_owner is not None:
            directory_owner.close()

    loaded = load_post_enrollment_execution_approval(
        approval_artifact=path,
        artifact_directory=exact_directory,
        ignored_root=exact_root,
    )
    if loaded.approval != approval or loaded.encoded != encoded:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution approval differs from expectation"
        )
    return loaded


def _image_admission_artifact_path(
    approval: TrustedTimePostEnrollmentStartApproval,
    *,
    artifact_directory: Path,
) -> Path:
    return artifact_directory / (
        f"image-admission-{approval.proposed_launch.image_admission_sha256}.json"
    )


def _image_witness_artifact_path(
    image_admission: TrustedTimeImageAdmission,
    *,
    artifact_directory: Path,
) -> Path:
    return artifact_directory / f"image-admission-{image_admission.artifact_sha256}.json"


def _same_image_admission(
    left: TrustedTimeImageAdmission,
    right: TrustedTimeImageAdmission,
) -> bool:
    return (
        left.identities == right.identities
        and left.boot_session_id == right.boot_session_id
        and left.git_revision == right.git_revision
        and left.source_revision_sha256 == right.source_revision_sha256
        and left.artifact_sha256 == right.artifact_sha256
        and left.created_at_utc == right.created_at_utc
        and left.created_monotonic_ns == right.created_monotonic_ns
    )


def _load_exact_image_witness(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    image_provenance: TrustedTimeImageAdmissionProvenance,
    image_admission: TrustedTimeImageAdmission,
    artifact_directory: Path,
    ignored_root: Path,
    observed_monotonic_ns: int,
    admission_loader: Callable[..., TrustedTimeImageAdmission],
    provenance_loader: Callable[..., TrustedTimeImageAdmissionProvenance],
) -> tuple[TrustedTimeImageAdmissionProvenance, int]:
    if type(observed_monotonic_ns) is not int or observed_monotonic_ns < 0:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission clock is unavailable"
        )
    if type(image_admission) is not TrustedTimeImageAdmission:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image witness is invalid"
        )
    expected_path = _image_witness_artifact_path(
        image_admission,
        artifact_directory=artifact_directory,
    )
    try:
        before = provenance_loader(
            expected_path,
            ignored_root=ignored_root,
        )
        admission = admission_loader(
            expected_path,
            ignored_root=ignored_root,
            monotonic_ns=observed_monotonic_ns,
        )
        after = provenance_loader(
            expected_path,
            ignored_root=ignored_root,
        )
        if (
            type(before) is not TrustedTimeImageAdmissionProvenance
            or type(admission) is not TrustedTimeImageAdmission
            or type(after) is not TrustedTimeImageAdmissionProvenance
        ):
            raise ValueError
        before.__post_init__()
        admission.__post_init__()
        admission.identities.__post_init__()
        after.__post_init__()
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image witness is invalid"
        ) from None
    launch = approval.proposed_launch
    maximum_age_ns = IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    required_headroom_ns = (
        POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS * 1_000_000_000
    )
    remaining_headroom_ns = maximum_age_ns - (
        observed_monotonic_ns - admission.created_monotonic_ns
    )
    if (
        before != after
        or before.admission() != admission
        or admission.path != expected_path
        or not _same_image_admission(image_admission, admission)
        or admission.git_revision != launch.git_revision
        or admission.identities.source_id != launch.source_image_id
        or admission.identities.supervisor_id != launch.supervisor_image_id
        or admission.source_revision_sha256 != image_provenance.source_revision_sha256
        or observed_monotonic_ns < admission.created_monotonic_ns
        or remaining_headroom_ns < required_headroom_ns
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image witness lacks exact headroom"
        )
    return before, remaining_headroom_ns


def _attempt_slot_payload(
    *,
    loaded_attested_approval: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
    image_provenance: TrustedTimeImageAdmissionProvenance,
    image_witness: TrustedTimeImageAdmissionProvenance,
    observed_monotonic_ns: int,
    remaining_headroom_ns: int,
) -> dict[str, object]:
    approval = loaded_attested_approval.approval
    payload = _v3_closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(
        {
            "contract_version": POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
            "execution_approval_v2_semantically_authenticated": True,
            "execution_approval_v2_sha256": (loaded_attested_approval.execution_approval_v2_sha256),
            "approved_image_provenance_source_revision_sha256": (
                image_provenance.source_revision_sha256
            ),
            "image_witness_boot_session_id": image_witness.boot_session_id,
            "image_witness_checked_monotonic_ns": observed_monotonic_ns,
            "image_witness_contract_version": IMAGE_ADMISSION_CONTRACT_VERSION,
            "image_witness_created_monotonic_ns": image_witness.created_monotonic_ns,
            "image_witness_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "image_witness_remaining_headroom_nanoseconds": remaining_headroom_ns,
            "image_witness_sha256": image_witness.artifact_sha256,
            "image_witness_source_revision_sha256": (image_witness.source_revision_sha256),
            "operator_attestation_envelope_authenticated": True,
            "operator_attestation_envelope_sha256": (
                loaded_attested_approval.operator_attestation_envelope_sha256
            ),
            "operator_attestation_signature_authenticated": True,
            "operator_attestation_signature_sha256": (
                loaded_attested_approval.operator_attestation_signature_sha256
            ),
            "operator_attestation_statement_sha256": (
                loaded_attested_approval.operator_attestation_statement_sha256
            ),
            "operator_attestation_verification_contract_version": (
                loaded_attested_approval.operator_attestation_verification_contract_version
            ),
            "operator_attestation_verification_service": (
                loaded_attested_approval.operator_attestation_verification_service
            ),
            "operator_attestation_verification_status": (
                loaded_attested_approval.operator_attestation_verification_status
            ),
            "operator_authority_artifact_sha256": (
                loaded_attested_approval.operator_authority_artifact_sha256
            ),
            "operator_authority_git_blob_object_id": (
                loaded_attested_approval.operator_authority_git_blob_object_id
            ),
            "operator_authority_git_mode": loaded_attested_approval.operator_authority_git_mode,
            "operator_authority_git_object_authenticated": True,
            "operator_authority_git_relative_path": (
                loaded_attested_approval.operator_authority_git_relative_path
            ),
            "operator_authority_git_revision": (
                loaded_attested_approval.operator_authority_git_revision
            ),
            "operator_public_key_sha256": loaded_attested_approval.operator_public_key_sha256,
            "service": POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE,
            "status": "execution_attempt_reserved",
        }
    )
    return payload


_HISTORICAL_ATTEMPT_SLOT_FIELDS = frozenset(
    {
        *_closed_payload(),
        "approval_artifact_sha256",
        "approval_sha256",
        "approved_image_provenance_sha256",
        "approved_image_provenance_source_revision_sha256",
        "confirmed_enrollment_evidence_sha256",
        "contract_version",
        "git_revision",
        "image_witness_boot_session_id",
        "image_witness_checked_monotonic_ns",
        "image_witness_contract_version",
        "image_witness_created_monotonic_ns",
        "image_witness_minimum_headroom_seconds",
        "image_witness_remaining_headroom_nanoseconds",
        "image_witness_sha256",
        "image_witness_source_revision_sha256",
        "operation_id",
        "review_projection_sha256",
        "service",
        "source_image_id",
        "status",
        "supervisor_image_id",
    }
)
_HISTORICAL_ATTEMPT_SLOT_SHA256_FIELDS = (
    "approval_artifact_sha256",
    "approval_sha256",
    "approved_image_provenance_sha256",
    "approved_image_provenance_source_revision_sha256",
    "confirmed_enrollment_evidence_sha256",
    "image_witness_sha256",
    "image_witness_source_revision_sha256",
    "review_projection_sha256",
)

_ATTEMPT_SLOT_FIELDS = frozenset(
    {
        *_v3_closed_payload(),
        "approval_sha256",
        "approved_image_provenance_sha256",
        "approved_image_provenance_source_revision_sha256",
        "confirmed_enrollment_evidence_sha256",
        "contract_version",
        "execution_approval_v2_semantically_authenticated",
        "execution_approval_v2_sha256",
        "git_revision",
        "image_witness_boot_session_id",
        "image_witness_checked_monotonic_ns",
        "image_witness_contract_version",
        "image_witness_created_monotonic_ns",
        "image_witness_minimum_headroom_seconds",
        "image_witness_remaining_headroom_nanoseconds",
        "image_witness_sha256",
        "image_witness_source_revision_sha256",
        "operation_id",
        "operator_attestation_envelope_authenticated",
        "operator_attestation_envelope_sha256",
        "operator_attestation_signature_authenticated",
        "operator_attestation_signature_sha256",
        "operator_attestation_statement_sha256",
        "operator_attestation_verification_contract_version",
        "operator_attestation_verification_service",
        "operator_attestation_verification_status",
        "operator_authority_artifact_sha256",
        "operator_authority_git_blob_object_id",
        "operator_authority_git_mode",
        "operator_authority_git_object_authenticated",
        "operator_authority_git_relative_path",
        "operator_authority_git_revision",
        "operator_public_key_sha256",
        "review_projection_sha256",
        "service",
        "source_image_id",
        "status",
        "supervisor_image_id",
    }
)
_ATTEMPT_SLOT_SHA256_FIELDS = (
    "approval_sha256",
    "approved_image_provenance_sha256",
    "approved_image_provenance_source_revision_sha256",
    "confirmed_enrollment_evidence_sha256",
    "execution_approval_v2_sha256",
    "image_witness_sha256",
    "image_witness_source_revision_sha256",
    "operator_attestation_envelope_sha256",
    "operator_attestation_signature_sha256",
    "operator_attestation_statement_sha256",
    "operator_authority_artifact_sha256",
    "operator_public_key_sha256",
    "review_projection_sha256",
)


def _is_complete_historical_attempt_slot_artifact(payload: Mapping[str, object]) -> bool:
    return (
        set(payload) == _HISTORICAL_ATTEMPT_SLOT_FIELDS
        and all(payload.get(field_name) is False for field_name in _closed_payload())
        and all(
            _is_sha256(payload.get(field_name))
            for field_name in _HISTORICAL_ATTEMPT_SLOT_SHA256_FIELDS
        )
        and payload.get("contract_version")
        == HISTORICAL_POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
        and payload.get("image_witness_contract_version") == IMAGE_ADMISSION_CONTRACT_VERSION
        and payload.get("image_witness_minimum_headroom_seconds")
        == POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        and payload.get("service") == POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE
        and payload.get("status") == "execution_attempt_reserved"
        and type(payload.get("git_revision")) is str
        and type(payload.get("image_witness_boot_session_id")) is str
        and type(payload.get("operation_id")) is str
        and type(payload.get("source_image_id")) is str
        and type(payload.get("supervisor_image_id")) is str
        and type(payload.get("image_witness_checked_monotonic_ns")) is int
        and cast(int, payload["image_witness_checked_monotonic_ns"]) >= 0
        and type(payload.get("image_witness_created_monotonic_ns")) is int
        and cast(int, payload["image_witness_created_monotonic_ns"]) >= 0
        and type(payload.get("image_witness_remaining_headroom_nanoseconds")) is int
        and cast(int, payload["image_witness_remaining_headroom_nanoseconds"]) >= 0
    )


def _is_complete_current_attempt_slot_artifact(payload: Mapping[str, object]) -> bool:
    return (
        set(payload) == _ATTEMPT_SLOT_FIELDS
        and all(payload.get(field_name) is False for field_name in _v3_closed_payload())
        and all(_is_sha256(payload.get(field_name)) for field_name in _ATTEMPT_SLOT_SHA256_FIELDS)
        and payload.get("contract_version") == POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
        and payload.get("operator_authority_git_revision") == payload.get("git_revision")
        and _is_git_revision(payload.get("operator_authority_git_revision"))
        and payload.get("operator_authority_git_relative_path")
        == POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
        and payload.get("operator_authority_git_mode") == "100644"
        and _is_git_object_id(payload.get("operator_authority_git_blob_object_id"))
        and payload.get("operator_attestation_verification_contract_version")
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
        and payload.get("operator_attestation_verification_service")
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
        and payload.get("operator_attestation_verification_status")
        == POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
        and all(
            payload.get(field_name) is True
            for field_name in (
                "execution_approval_v2_semantically_authenticated",
                "operator_attestation_envelope_authenticated",
                "operator_attestation_signature_authenticated",
                "operator_authority_git_object_authenticated",
            )
        )
        and payload.get("image_witness_contract_version") == IMAGE_ADMISSION_CONTRACT_VERSION
        and payload.get("image_witness_minimum_headroom_seconds")
        == POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
        and payload.get("service") == POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE
        and payload.get("status") == "execution_attempt_reserved"
        and type(payload.get("git_revision")) is str
        and type(payload.get("image_witness_boot_session_id")) is str
        and type(payload.get("operation_id")) is str
        and type(payload.get("source_image_id")) is str
        and type(payload.get("supervisor_image_id")) is str
        and type(payload.get("image_witness_checked_monotonic_ns")) is int
        and cast(int, payload["image_witness_checked_monotonic_ns"]) >= 0
        and type(payload.get("image_witness_created_monotonic_ns")) is int
        and cast(int, payload["image_witness_created_monotonic_ns"]) >= 0
        and type(payload.get("image_witness_remaining_headroom_nanoseconds")) is int
        and cast(int, payload["image_witness_remaining_headroom_nanoseconds"]) >= 0
    )


def _is_complete_attempt_slot_artifact(encoded: bytes) -> bool:
    """Classify an exact complete historical v2 or current v3 attempt."""

    try:
        payload = _decode_canonical_json(encoded)
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        return False
    if _is_complete_historical_attempt_slot_artifact(payload):
        return True
    return _is_complete_current_attempt_slot_artifact(payload)


def _require_complete_attempt_slot_payload(
    encoded: bytes,
    *,
    expected_bindings: _ImmutableJSONObject,
) -> Mapping[str, object]:
    """Reconstruct the complete v3 slot and compare its exact immutable bytes."""

    payload = _decode_canonical_json(encoded)
    checked_monotonic_ns = payload.get("image_witness_checked_monotonic_ns")
    exact_expected_bindings = _verified_immutable_json_object_items(
        expected_bindings,
        label="trusted-time retained execution-attempt expected bindings",
    )
    created_monotonic_values = tuple(
        value
        for name, value in exact_expected_bindings
        if name == "image_witness_created_monotonic_ns"
    )
    created_monotonic_ns = (
        created_monotonic_values[0] if len(created_monotonic_values) == 1 else None
    )
    remaining_headroom_ns = payload.get("image_witness_remaining_headroom_nanoseconds")
    maximum_age_ns = IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    if (
        type(checked_monotonic_ns) is not int
        or type(created_monotonic_ns) is not int
        or checked_monotonic_ns < created_monotonic_ns
        or type(remaining_headroom_ns) is not int
        or remaining_headroom_ns != maximum_age_ns - (checked_monotonic_ns - created_monotonic_ns)
        or remaining_headroom_ns
        < POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS * 1_000_000_000
    ):
        raise ValueError
    expected_items = tuple(
        sorted(
            (
                *(
                    (name, False)
                    for name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
                ),
                *exact_expected_bindings,
                (
                    "contract_version",
                    POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
                ),
                ("execution_approval_v2_semantically_authenticated", True),
                ("image_witness_checked_monotonic_ns", checked_monotonic_ns),
                ("image_witness_contract_version", IMAGE_ADMISSION_CONTRACT_VERSION),
                (
                    "image_witness_minimum_headroom_seconds",
                    POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS,
                ),
                ("image_witness_remaining_headroom_nanoseconds", remaining_headroom_ns),
                ("operator_attestation_envelope_authenticated", True),
                ("operator_attestation_signature_authenticated", True),
                ("operator_authority_git_object_authenticated", True),
                ("service", POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE),
                ("status", "execution_attempt_reserved"),
            ),
            key=lambda item: item[0],
        )
    )
    if (
        tuple(name for name, _ in expected_items) != tuple(sorted(_ATTEMPT_SLOT_FIELDS))
        or _canonical_immutable_json_bytes(_immutable_json_object(expected_items)) + b"\n"
        != encoded
    ):
        raise ValueError
    return payload


def _require_retained_attempt_slot_binding(
    encoded: bytes,
    loaded_attested_approval: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
) -> Mapping[str, object]:
    """Decode and bind one exact v3 slot without treating its witness as current."""

    try:
        loaded_attested_approval.__post_init__()
        approval = loaded_attested_approval.approval
        provenance = loaded_attested_approval.image_provenance
        provenance.__post_init__()
        expected_bindings = _immutable_json_object(
            tuple(
                sorted(
                    (
                        ("approval_sha256", approval.approval_sha256),
                        (
                            "approved_image_provenance_sha256",
                            approval.proposed_launch.image_admission_sha256,
                        ),
                        (
                            "approved_image_provenance_source_revision_sha256",
                            provenance.source_revision_sha256,
                        ),
                        (
                            "confirmed_enrollment_evidence_sha256",
                            approval.confirmed_enrollment.evidence_sha256,
                        ),
                        (
                            "execution_approval_v2_sha256",
                            loaded_attested_approval.execution_approval_v2_sha256,
                        ),
                        ("git_revision", approval.proposed_launch.git_revision),
                        ("image_witness_boot_session_id", provenance.boot_session_id),
                        (
                            "image_witness_created_monotonic_ns",
                            provenance.created_monotonic_ns,
                        ),
                        ("image_witness_sha256", provenance.artifact_sha256),
                        (
                            "image_witness_source_revision_sha256",
                            provenance.source_revision_sha256,
                        ),
                        ("operation_id", approval.operation_id),
                        (
                            "operator_attestation_envelope_sha256",
                            loaded_attested_approval.operator_attestation_envelope_sha256,
                        ),
                        (
                            "operator_attestation_signature_sha256",
                            loaded_attested_approval.operator_attestation_signature_sha256,
                        ),
                        (
                            "operator_attestation_statement_sha256",
                            loaded_attested_approval.operator_attestation_statement_sha256,
                        ),
                        (
                            "operator_attestation_verification_contract_version",
                            loaded_attested_approval.operator_attestation_verification_contract_version,
                        ),
                        (
                            "operator_attestation_verification_service",
                            loaded_attested_approval.operator_attestation_verification_service,
                        ),
                        (
                            "operator_attestation_verification_status",
                            loaded_attested_approval.operator_attestation_verification_status,
                        ),
                        (
                            "operator_authority_artifact_sha256",
                            loaded_attested_approval.operator_authority_artifact_sha256,
                        ),
                        (
                            "operator_authority_git_blob_object_id",
                            loaded_attested_approval.operator_authority_git_blob_object_id,
                        ),
                        (
                            "operator_authority_git_mode",
                            loaded_attested_approval.operator_authority_git_mode,
                        ),
                        (
                            "operator_authority_git_relative_path",
                            loaded_attested_approval.operator_authority_git_relative_path,
                        ),
                        (
                            "operator_authority_git_revision",
                            loaded_attested_approval.operator_authority_git_revision,
                        ),
                        (
                            "operator_public_key_sha256",
                            loaded_attested_approval.operator_public_key_sha256,
                        ),
                        ("review_projection_sha256", approval.review.projection_sha256),
                        ("source_image_id", approval.proposed_launch.source_image_id),
                        (
                            "supervisor_image_id",
                            approval.proposed_launch.supervisor_image_id,
                        ),
                    ),
                    key=lambda item: item[0],
                )
            )
        )
        return _require_complete_attempt_slot_payload(
            encoded,
            expected_bindings=expected_bindings,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        ) from None


def _require_attempt_snapshot_binding(
    encoded: bytes,
    approval_snapshot: _LoadedOperatorAttestedApprovalSnapshot,
) -> Mapping[str, object]:
    """Bind one exact v3 slot only to immutable pre-publication source bytes."""

    try:
        approval_snapshot = _require_loaded_approval_snapshot(approval_snapshot)
        provenance_snapshot = _require_provenance_snapshot(
            _loaded_approval_value(approval_snapshot, 29)
        )
        expected_bindings = _immutable_json_object(
            (
                (
                    "approval_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        9,
                    ),
                ),
                (
                    "approved_image_provenance_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        16,
                    ),
                ),
                (
                    "approved_image_provenance_source_revision_sha256",
                    _provenance_snapshot_value(
                        provenance_snapshot,
                        6,
                    ),
                ),
                (
                    "confirmed_enrollment_evidence_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        10,
                    ),
                ),
                (
                    "execution_approval_v2_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        24,
                    ),
                ),
                (
                    "git_revision",
                    _loaded_approval_value(
                        approval_snapshot,
                        15,
                    ),
                ),
                (
                    "image_witness_boot_session_id",
                    _provenance_snapshot_value(
                        provenance_snapshot,
                        4,
                    ),
                ),
                (
                    "image_witness_created_monotonic_ns",
                    _provenance_snapshot_value(
                        provenance_snapshot,
                        10,
                    ),
                ),
                (
                    "image_witness_sha256",
                    _provenance_snapshot_value(
                        provenance_snapshot,
                        8,
                    ),
                ),
                (
                    "image_witness_source_revision_sha256",
                    _provenance_snapshot_value(
                        provenance_snapshot,
                        6,
                    ),
                ),
                (
                    "operation_id",
                    _loaded_approval_value(
                        approval_snapshot,
                        12,
                    ),
                ),
                (
                    "operator_attestation_envelope_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        27,
                    ),
                ),
                (
                    "operator_attestation_signature_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        26,
                    ),
                ),
                (
                    "operator_attestation_statement_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        25,
                    ),
                ),
                (
                    "operator_attestation_verification_contract_version",
                    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
                ),
                (
                    "operator_attestation_verification_service",
                    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
                ),
                (
                    "operator_attestation_verification_status",
                    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
                ),
                (
                    "operator_authority_artifact_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        22,
                    ),
                ),
                (
                    "operator_authority_git_blob_object_id",
                    _loaded_approval_value(
                        approval_snapshot,
                        20,
                    ),
                ),
                (
                    "operator_authority_git_mode",
                    _loaded_approval_value(
                        approval_snapshot,
                        19,
                    ),
                ),
                (
                    "operator_authority_git_relative_path",
                    _loaded_approval_value(
                        approval_snapshot,
                        18,
                    ),
                ),
                (
                    "operator_authority_git_revision",
                    _loaded_approval_value(
                        approval_snapshot,
                        15,
                    ),
                ),
                (
                    "operator_public_key_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        23,
                    ),
                ),
                (
                    "review_projection_sha256",
                    _loaded_approval_value(
                        approval_snapshot,
                        11,
                    ),
                ),
                (
                    "source_image_id",
                    _loaded_approval_value(
                        approval_snapshot,
                        13,
                    ),
                ),
                (
                    "supervisor_image_id",
                    _loaded_approval_value(
                        approval_snapshot,
                        14,
                    ),
                ),
            )
        )
        if (
            hashlib.sha256(
                cast(
                    bytes,
                    _loaded_approval_value(
                        approval_snapshot,
                        7,
                    ),
                )
            ).hexdigest()
            != _loaded_approval_value(
                approval_snapshot,
                24,
            )
            or _provenance_snapshot_value(
                provenance_snapshot,
                8,
            )
            != _loaded_approval_value(
                approval_snapshot,
                16,
            )
            or _provenance_snapshot_value(provenance_snapshot, 5)
            != _loaded_approval_value(approval_snapshot, 15)
            or _provenance_snapshot_value(provenance_snapshot, 2)
            != _loaded_approval_value(approval_snapshot, 13)
            or _provenance_snapshot_value(provenance_snapshot, 3)
            != _loaded_approval_value(
                approval_snapshot,
                14,
            )
        ):
            raise ValueError
        return _require_complete_attempt_slot_payload(
            encoded,
            expected_bindings=expected_bindings,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        ) from None


type _RetainedExecutionAttemptSlotBinding = tuple[
    str,
    bytes,
    tuple[int, int],
    tuple[int, ...],
]


def _make_attempt_slot_binding(
    *,
    encoded: bytes,
    directory_identity: tuple[int, int],
    file_identity: tuple[int, ...],
) -> _RetainedExecutionAttemptSlotBinding:
    return (
        "retained-execution-attempt-slot-binding-v1",
        encoded,
        directory_identity,
        file_identity,
    )


def _require_attempt_slot_binding(value: object) -> _RetainedExecutionAttemptSlotBinding:
    if type(value) is not tuple or len(value) != 4:
        raise ValueError
    tag = tuple.__getitem__(value, 0)
    encoded = tuple.__getitem__(value, 1)
    directory_identity = tuple.__getitem__(value, 2)
    file_identity = tuple.__getitem__(value, 3)
    if (
        type(tag) is not str
        or tag != "retained-execution-attempt-slot-binding-v1"
        or type(encoded) is not bytes
        or type(directory_identity) is not tuple
        or len(directory_identity) != 2
        or any(type(item) is not int for item in directory_identity)
        or type(file_identity) is not tuple
        or len(file_identity) != 9
        or any(type(item) is not int for item in file_identity)
    ):
        raise ValueError
    return cast(_RetainedExecutionAttemptSlotBinding, value)


def _attempt_slot_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_attempt_slot_binding(value), index)


def _read_legacy_locked_retained_execution_attempt_slot(
    directory_descriptor: int,
) -> _RetainedExecutionAttemptSlotBinding:
    """Fsync and read the fixed slot while holding its shared inode lock."""

    file_owner: _OwnedFileDescriptor | None = None
    file_lock_call_started = False
    result: _RetainedExecutionAttemptSlotBinding | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None

    def readback(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        retained = bytearray()
        while len(retained) <= MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        return bytes(retained)

    try:
        try:
            directory_before = os.fstat(directory_descriptor)
            file_owner = _open_owner_only_file(
                directory_descriptor,
                POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                exclusive=False,
            )
            descriptor = file_owner.fileno()
            file_lock_call_started = True
            fcntl.flock(descriptor, fcntl.LOCK_SH)
            before = os.fstat(descriptor)
            named_before = os.stat(
                POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size < 1
                or before.st_size > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
                or _stable_file_identity(before) != _stable_file_identity(named_before)
            ):
                raise OSError
            encoded = readback(descriptor)
            after_read = os.fstat(descriptor)
            if len(encoded) != before.st_size or _stable_file_identity(
                before
            ) != _stable_file_identity(after_read):
                raise OSError
            os.fsync(descriptor)
            os.fsync(directory_descriptor)
            final_encoded = readback(descriptor)
            final = os.fstat(descriptor)
            named_final = os.stat(
                POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            directory_final = os.fstat(directory_descriptor)
            if (
                final_encoded != encoded
                or _stable_file_identity(before) != _stable_file_identity(final)
                or _stable_file_identity(final) != _stable_file_identity(named_final)
                or (directory_before.st_dev, directory_before.st_ino)
                != (directory_final.st_dev, directory_final.st_ino)
            ):
                raise OSError
            result = _make_attempt_slot_binding(
                encoded=encoded,
                directory_identity=(directory_final.st_dev, directory_final.st_ino),
                file_identity=_stable_file_identity(final),
            )
        except BaseException as error:
            body_error = error
        finally:
            try:
                cleanup_error = _cleanup_locked_owners(((file_owner, file_lock_call_started),))
            except BaseException as error:
                cleanup_error = error
    except BaseException as error:
        transition_error = error
    finally:
        try:
            retry_error = _cleanup_locked_owners(((file_owner, file_lock_call_started),))
        except BaseException as error:
            retry_error = error
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        )
    return result


def _read_locked_retained_execution_attempt_slot(
    directory_owner: _NativeOwnedFileDescriptor,
) -> _RetainedExecutionAttemptSlotBinding:
    """Read the fixed slot through one held native directory authority."""

    file_owner: _NativeOwnedFileDescriptor | None = None
    file_lock_call_started = False
    result: _RetainedExecutionAttemptSlotBinding | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            directory_before = _native_fstat(directory_owner)
            file_owner = _native_open_child_regular(
                directory_owner,
                POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            )
            file_lock_call_started = True
            _native_flock(file_owner, fcntl.LOCK_SH | fcntl.LOCK_NB)
            before = _native_fstat(file_owner)
            named_before = _native_statat(
                directory_owner,
                POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            )
            if (
                not stat.S_ISREG(before[2])
                or before[3] != os.geteuid()
                or stat.S_IMODE(before[2]) != 0o600
                or before[5] != 1
                or before[6] < 1
                or before[6] > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
                or before != named_before
            ):
                raise OSError
            encoded, read_before, read_after = _native_read_snapshot(
                file_owner,
                MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES,
            )
            if read_before != before or read_after != before or len(encoded) != before[6]:
                raise OSError
            _native_fsync(file_owner)
            _native_fsync(directory_owner)
            final_encoded, final_read_before, final_read_after = _native_read_snapshot(
                file_owner,
                MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES,
            )
            final = _native_fstat(file_owner)
            named_final = _native_statat(
                directory_owner,
                POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            )
            directory_final = _native_fstat(directory_owner)
            if (
                final_encoded != encoded
                or final_read_before != before
                or final_read_after != before
                or final != before
                or named_final != before
                or directory_final != directory_before
            ):
                raise OSError
            result = _make_attempt_slot_binding(
                encoded=encoded,
                directory_identity=(directory_final[0], directory_final[1]),
                file_identity=final,
            )
        except BaseException as error:
            body_error = error
        finally:
            try:
                cleanup_error = _cleanup_native_locked_owners(
                    ((file_owner, file_lock_call_started),)
                )
            except BaseException as error:
                cleanup_error = error
    except BaseException as error:
        transition_error = error
    finally:
        try:
            retry_error = _cleanup_native_locked_owners(((file_owner, file_lock_call_started),))
        except BaseException as error:
            retry_error = error
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        )
    return result


_RETAINED_OPERATOR_ATTESTED_ATTEMPT_CONSTRUCTION_CAPABILITY = object()


def _retained_operator_attested_attempt_seal_values(value: Any) -> tuple[object, ...]:
    loaded = value.loaded_attested_approval
    loaded.__post_init__()
    return (
        _loaded_attested_seal_values(loaded),
        os.fspath(value.artifact_path),
        value.attempt_slot_sha256,
        value.encoded,
        value.directory_identity,
        value.file_identity,
    )


def _retained_operator_attested_attempt_fact(value: object) -> bool:
    if type(value) is not RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        )
    value.__post_init__()
    return True


@dataclass(frozen=True, slots=True, init=False)
class RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt:
    """Exact historical v3 slot and authenticated start envelope; never currentness."""

    loaded_attested_approval: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval = (
        field(repr=False)
    )
    artifact_path: Path
    attempt_slot_sha256: str
    encoded: bytes = field(repr=False)
    directory_identity: tuple[int, int] = field(repr=False)
    file_identity: tuple[int, ...] = field(repr=False)
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        loaded_attested_approval: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
        artifact_path: Path,
        attempt_slot_sha256: str,
        encoded: bytes,
        directory_identity: tuple[int, int],
        file_identity: tuple[int, ...],
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt
            or _construction_capability
            is not _RETAINED_OPERATOR_ATTESTED_ATTEMPT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
                "trusted-time retained operator-attested execution-attempt evidence is unavailable"
            )
        object.__setattr__(self, "loaded_attested_approval", loaded_attested_approval)
        object.__setattr__(self, "artifact_path", artifact_path)
        object.__setattr__(self, "attempt_slot_sha256", attempt_slot_sha256)
        object.__setattr__(self, "encoded", encoded)
        object.__setattr__(self, "directory_identity", directory_identity)
        object.__setattr__(self, "file_identity", file_identity)
        try:
            sealed_fields = _retained_operator_attested_attempt_seal_values(self)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
                "trusted-time retained operator-attested execution-attempt evidence is unavailable"
            ) from None
        object.__setattr__(self, "_sealed_fields", sealed_fields)
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            _require_retained_attempt_slot_binding(
                self.encoded,
                self.loaded_attested_approval,
            )
            seal_values = _retained_operator_attested_attempt_seal_values(self)
            if (
                type(self) is not RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt
                or seal_values != getattr(self, "_sealed_fields", None)
                or type(self.artifact_path) is not type(Path())
                or not self.artifact_path.is_absolute()
                or self.artifact_path != Path(os.path.abspath(self.artifact_path))
                or self.artifact_path.name != POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
                or not _is_sha256(self.attempt_slot_sha256)
                or hashlib.sha256(self.encoded).hexdigest() != self.attempt_slot_sha256
                or type(self.directory_identity) is not tuple
                or len(self.directory_identity) != 2
                or any(type(item) is not int for item in self.directory_identity)
                or type(self.file_identity) is not tuple
                or len(self.file_identity) != 9
                or any(type(item) is not int for item in self.file_identity)
                or not stat.S_ISREG(self.file_identity[2])
                or stat.S_IMODE(self.file_identity[2]) != 0o600
                or self.file_identity[3] != os.geteuid()
                or self.file_identity[5] != 1
                or self.file_identity[6] != len(self.encoded)
            ):
                raise ValueError
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
                "trusted-time retained operator-attested execution-attempt evidence is unavailable"
            ) from None

    @property
    def approval(self) -> TrustedTimePostEnrollmentStartApproval:
        self.__post_init__()
        return self.loaded_attested_approval.approval

    @property
    def operator_attestation_envelope_sha256(self) -> str:
        self.__post_init__()
        return self.loaded_attested_approval.operator_attestation_envelope_sha256

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt "
            "evidence cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt "
            "evidence cannot be serialized"
        )

    execution_attempt_retained = property(_retained_operator_attested_attempt_fact)
    execution_approval_v2_semantically_authenticated = property(
        _retained_operator_attested_attempt_fact
    )
    operator_attestation_envelope_authenticated = property(_retained_operator_attested_attempt_fact)
    operator_attestation_signature_authenticated = property(
        _retained_operator_attested_attempt_fact
    )
    operator_authority_git_object_authenticated = property(_retained_operator_attested_attempt_fact)
    currentness_authenticated = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    single_use_authenticated = property(_authority_is_never_granted)
    stop_attempt_reservation_authorized = property(_authority_is_never_granted)
    stop_execution_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)


_RetainedAttestedApprovalLoader = Callable[
    ...,
    LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
]


type _RetainedOperatorAttestedExecutionAttemptSnapshot = tuple[object, ...]


def _make_retained_attempt_snapshot(
    *values: object,
) -> _RetainedOperatorAttestedExecutionAttemptSnapshot:
    return ("retained-operator-attested-execution-attempt-snapshot-v1", *values)


def _require_retained_attempt_snapshot(
    value: object,
) -> _RetainedOperatorAttestedExecutionAttemptSnapshot:
    if type(value) is not tuple or len(value) != 10:
        raise ValueError
    if (
        type(tuple.__getitem__(value, 0)) is not str
        or tuple.__getitem__(value, 0) != "retained-operator-attested-execution-attempt-snapshot-v1"
        or any(
            type(tuple.__getitem__(value, index)) is not str
            for index in (
                1,
                2,
                3,
                5,
            )
        )
        or type(tuple.__getitem__(value, 4)) is not bytes
    ):
        raise ValueError
    for index, length in (
        (6, 2),
        (7, 9),
    ):
        identity = tuple.__getitem__(value, index)
        if (
            type(identity) is not tuple
            or len(identity) != length
            or any(type(item) is not int for item in identity)
        ):
            raise ValueError
    _require_loaded_approval_snapshot(tuple.__getitem__(value, 8))
    if type(tuple.__getitem__(value, 9)) is not tuple:
        raise ValueError
    return cast(_RetainedOperatorAttestedExecutionAttemptSnapshot, value)


def _retained_attempt_snapshot_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_retained_attempt_snapshot(value), index)


def _load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot(
    *,
    start_operator_attested_approval_artifact: Path,
    artifact_directory: Path,
    ignored_root: Path,
) -> tuple[
    RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt,
    _RetainedOperatorAttestedExecutionAttemptSnapshot,
]:
    """Load the locked slot and return its private pre-publication snapshot."""

    directory_owner: _NativeOwnedFileDescriptor | None = None
    next_directory_owner: _NativeOwnedFileDescriptor | None = None
    directory_lock_call_started = False
    rebound_directory_owner: _NativeOwnedFileDescriptor | None = None
    next_rebound_directory_owner: _NativeOwnedFileDescriptor | None = None
    rebound_directory_lock_call_started = False
    result: (
        tuple[
            RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt,
            _RetainedOperatorAttestedExecutionAttemptSnapshot,
        ]
        | None
    ) = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            exact_directory, exact_root = _exact_artifact_roots(
                artifact_directory,
                ignored_root=ignored_root,
            )
            exact_directory_string = os.fspath(exact_directory)
            exact_root_string = os.fspath(exact_root)
            directory_components = _external_artifacts._absolute_path_components(
                exact_directory_string
            )
            ignored_root_components = _external_artifacts._absolute_path_components(
                exact_root_string
            )
            if directory_components[:-1] != ignored_root_components or directory_components[
                -1:
            ] != ("trusted-time",):
                raise ValueError
            _, initial_approval_snapshot = (
                _load_post_enrollment_operator_attested_execution_approval_with_snapshot(
                    operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
                    artifact_directory=exact_directory,
                    ignored_root=exact_root,
                )
            )
            directory_owner = _native_open_root_directory()
            for index, component in enumerate(directory_components, start=1):
                next_directory_owner = _native_open_child_directory(
                    directory_owner,
                    component,
                )
                component_metadata = _native_fstat(next_directory_owner)
                if index >= len(ignored_root_components) and (
                    not stat.S_ISDIR(component_metadata[2])
                    or component_metadata[3] != os.geteuid()
                    or stat.S_IMODE(component_metadata[2]) != 0o700
                ):
                    raise OSError
                intermediate_cleanup_error = _cleanup_native_locked_owners(
                    ((directory_owner, False),)
                )
                if intermediate_cleanup_error is not None:
                    raise intermediate_cleanup_error
                directory_owner = next_directory_owner
                next_directory_owner = None
            directory_lock_call_started = True
            _native_flock(directory_owner, fcntl.LOCK_SH | fcntl.LOCK_NB)
            first_slot = _read_locked_retained_execution_attempt_slot(directory_owner)
            _require_attempt_snapshot_binding(
                cast(bytes, _attempt_slot_value(first_slot, 1)),
                initial_approval_snapshot,
            )
            final_approval, final_approval_snapshot = (
                _load_post_enrollment_operator_attested_execution_approval_with_snapshot(
                    operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
                    artifact_directory=exact_directory,
                    ignored_root=exact_root,
                )
            )
            final_slot = _read_locked_retained_execution_attempt_slot(directory_owner)
            _require_attempt_snapshot_binding(
                cast(bytes, _attempt_slot_value(final_slot, 1)),
                final_approval_snapshot,
            )
            if initial_approval_snapshot != final_approval_snapshot or first_slot != final_slot:
                raise ValueError
            _require_retained_attempt_slot_binding(
                cast(bytes, _attempt_slot_value(final_slot, 1)),
                final_approval,
            )
            held_directory_before_rebind = _native_fstat(directory_owner)
            rebound_directory_owner = _native_open_root_directory()
            for index, component in enumerate(directory_components, start=1):
                next_rebound_directory_owner = _native_open_child_directory(
                    rebound_directory_owner,
                    component,
                )
                rebound_component_metadata = _native_fstat(next_rebound_directory_owner)
                if index >= len(ignored_root_components) and (
                    not stat.S_ISDIR(rebound_component_metadata[2])
                    or rebound_component_metadata[3] != os.geteuid()
                    or stat.S_IMODE(rebound_component_metadata[2]) != 0o700
                ):
                    raise OSError
                intermediate_cleanup_error = _cleanup_native_locked_owners(
                    ((rebound_directory_owner, False),)
                )
                if intermediate_cleanup_error is not None:
                    raise intermediate_cleanup_error
                rebound_directory_owner = next_rebound_directory_owner
                next_rebound_directory_owner = None
            rebound_directory_lock_call_started = True
            _native_flock(rebound_directory_owner, fcntl.LOCK_SH | fcntl.LOCK_NB)
            rebound_directory_before = _native_fstat(rebound_directory_owner)
            expected_directory_identity = (
                held_directory_before_rebind[0],
                held_directory_before_rebind[1],
                held_directory_before_rebind[3],
                stat.S_IMODE(held_directory_before_rebind[2]),
            )
            if (
                not stat.S_ISDIR(held_directory_before_rebind[2])
                or expected_directory_identity
                != (
                    rebound_directory_before[0],
                    rebound_directory_before[1],
                    rebound_directory_before[3],
                    stat.S_IMODE(rebound_directory_before[2]),
                )
                or expected_directory_identity[2] != os.geteuid()
                or expected_directory_identity[3] != 0o700
            ):
                raise ValueError
            rebound_slot = _read_locked_retained_execution_attempt_slot(rebound_directory_owner)
            held_directory_final = _native_fstat(directory_owner)
            rebound_directory_final = _native_fstat(rebound_directory_owner)
            if (
                rebound_slot != final_slot
                or expected_directory_identity
                != (
                    held_directory_final[0],
                    held_directory_final[1],
                    held_directory_final[3],
                    stat.S_IMODE(held_directory_final[2]),
                )
                or expected_directory_identity
                != (
                    rebound_directory_final[0],
                    rebound_directory_final[1],
                    rebound_directory_final[3],
                    stat.S_IMODE(rebound_directory_final[2]),
                )
            ):
                raise ValueError
            rebound_encoded = cast(
                bytes,
                _attempt_slot_value(rebound_slot, 1),
            )
            rebound_directory_identity = cast(
                tuple[int, int],
                _attempt_slot_value(rebound_slot, 2),
            )
            rebound_file_identity = cast(
                tuple[int, ...],
                _attempt_slot_value(rebound_slot, 3),
            )
            _require_attempt_snapshot_binding(rebound_encoded, final_approval_snapshot)
            _require_retained_attempt_slot_binding(rebound_encoded, final_approval)
            attempt_path = os.fspath(
                exact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
            )
            attempt_sha256 = hashlib.sha256(rebound_encoded).hexdigest()
            retained_seal_values: tuple[object, ...] = (
                _loaded_approval_value(
                    final_approval_snapshot,
                    30,
                ),
                attempt_path,
                attempt_sha256,
                rebound_encoded,
                rebound_directory_identity,
                rebound_file_identity,
            )
            snapshot = _require_retained_attempt_snapshot(
                _make_retained_attempt_snapshot(
                    os.fspath(exact_directory),
                    os.fspath(exact_root),
                    attempt_path,
                    rebound_encoded,
                    attempt_sha256,
                    rebound_directory_identity,
                    rebound_file_identity,
                    final_approval_snapshot,
                    retained_seal_values,
                )
            )
            retained = RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt(
                loaded_attested_approval=final_approval,
                artifact_path=Path(attempt_path),
                attempt_slot_sha256=attempt_sha256,
                encoded=rebound_encoded,
                directory_identity=rebound_directory_identity,
                file_identity=rebound_file_identity,
                _construction_capability=(
                    _RETAINED_OPERATOR_ATTESTED_ATTEMPT_CONSTRUCTION_CAPABILITY
                ),
            )
            if _retained_operator_attested_attempt_seal_values(
                retained
            ) != _retained_attempt_snapshot_value(
                snapshot,
                9,
            ):
                raise ValueError
            final_rebound_slot = _read_locked_retained_execution_attempt_slot(
                rebound_directory_owner
            )
            _, return_approval_snapshot = (
                _load_post_enrollment_operator_attested_execution_approval_with_snapshot(
                    operator_attested_approval_artifact=Path(
                        cast(
                            str,
                            _loaded_approval_value(
                                _retained_attempt_snapshot_value(
                                    snapshot,
                                    8,
                                ),
                                3,
                            ),
                        )
                    ),
                    artifact_directory=exact_directory,
                    ignored_root=exact_root,
                )
            )
            _require_attempt_snapshot_binding(
                cast(
                    bytes,
                    _attempt_slot_value(final_rebound_slot, 1),
                ),
                return_approval_snapshot,
            )
            if (
                final_rebound_slot != rebound_slot
                or return_approval_snapshot != final_approval_snapshot
                or _retained_operator_attested_attempt_seal_values(retained)
                != _retained_attempt_snapshot_value(
                    snapshot,
                    9,
                )
                or _native_fstat(directory_owner) != held_directory_final
                or _native_fstat(rebound_directory_owner) != rebound_directory_final
            ):
                raise ValueError
            result = (retained, snapshot)
        except BaseException as error:
            body_error = error
        finally:
            try:
                cleanup_error = _cleanup_native_locked_owners(
                    (
                        (next_rebound_directory_owner, False),
                        (rebound_directory_owner, rebound_directory_lock_call_started),
                        (next_directory_owner, False),
                        (directory_owner, directory_lock_call_started),
                    )
                )
            except BaseException as error:
                cleanup_error = error
    except BaseException as error:
        transition_error = error
    finally:
        try:
            retry_error = _cleanup_native_locked_owners(
                (
                    (next_rebound_directory_owner, False),
                    (rebound_directory_owner, rebound_directory_lock_call_started),
                    (next_directory_owner, False),
                    (directory_owner, directory_lock_call_started),
                )
            )
        except BaseException as error:
            retry_error = error
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        )
    return result


def _revalidate_retained_post_enrollment_operator_attested_execution_attempt_snapshot(
    snapshot: _RetainedOperatorAttestedExecutionAttemptSnapshot,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> bool:
    try:
        snapshot = _require_retained_attempt_snapshot(snapshot)
        approval_snapshot = _require_loaded_approval_snapshot(
            _retained_attempt_snapshot_value(snapshot, 8)
        )
        _, reloaded = (
            _load_retained_post_enrollment_operator_attested_execution_attempt_with_snapshot(
                start_operator_attested_approval_artifact=Path(
                    cast(
                        str,
                        _loaded_approval_value(
                            approval_snapshot,
                            3,
                        ),
                    )
                ),
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        )
        return reloaded == snapshot
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def _load_retained_post_enrollment_operator_attested_execution_attempt(
    *,
    start_operator_attested_approval_artifact: Path,
    artifact_directory: Path,
    ignored_root: Path,
    operator_attested_approval_loader: _RetainedAttestedApprovalLoader,
) -> RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt:
    directory_owner: _OwnedFileDescriptor | None = None
    directory_lock_call_started = False
    rebound_directory_owner: _OwnedFileDescriptor | None = None
    rebound_directory_lock_call_started = False
    result: RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            exact_directory, exact_root = _exact_artifact_roots(
                artifact_directory,
                ignored_root=ignored_root,
            )
            initial_approval = operator_attested_approval_loader(
                operator_attested_approval_artifact=start_operator_attested_approval_artifact,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
            )
            if (
                type(initial_approval)
                is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
            ):
                raise ValueError
            initial_approval.__post_init__()
            directory_owner = _open_owner_only_artifact_directory(
                exact_directory,
                ignored_root=exact_root,
            )
            directory_descriptor = directory_owner.fileno()
            directory_lock_call_started = True
            fcntl.flock(directory_descriptor, fcntl.LOCK_SH)
            first_slot = _read_legacy_locked_retained_execution_attempt_slot(directory_descriptor)
            final_approval = operator_attested_approval_loader(
                operator_attested_approval_artifact=start_operator_attested_approval_artifact,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
            )
            if (
                type(final_approval)
                is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
            ):
                raise ValueError
            final_approval.__post_init__()
            final_slot = _read_legacy_locked_retained_execution_attempt_slot(directory_descriptor)
            if initial_approval != final_approval or first_slot != final_slot:
                raise ValueError
            _require_retained_attempt_slot_binding(
                cast(bytes, _attempt_slot_value(final_slot, 1)),
                final_approval,
            )

            held_directory_before_rebind = os.fstat(directory_descriptor)
            rebound_directory_owner = _open_owner_only_artifact_directory(
                exact_directory,
                ignored_root=exact_root,
            )
            rebound_directory_descriptor = rebound_directory_owner.fileno()
            rebound_directory_lock_call_started = True
            fcntl.flock(rebound_directory_descriptor, fcntl.LOCK_SH)
            rebound_directory_before = os.fstat(rebound_directory_descriptor)
            expected_directory_identity = (
                held_directory_before_rebind.st_dev,
                held_directory_before_rebind.st_ino,
                held_directory_before_rebind.st_uid,
                stat.S_IMODE(held_directory_before_rebind.st_mode),
            )
            if (
                not stat.S_ISDIR(held_directory_before_rebind.st_mode)
                or expected_directory_identity
                != (
                    rebound_directory_before.st_dev,
                    rebound_directory_before.st_ino,
                    rebound_directory_before.st_uid,
                    stat.S_IMODE(rebound_directory_before.st_mode),
                )
                or expected_directory_identity[2] != os.geteuid()
                or expected_directory_identity[3] != 0o700
            ):
                raise ValueError
            rebound_slot = _read_legacy_locked_retained_execution_attempt_slot(
                rebound_directory_descriptor
            )
            held_directory_final = os.fstat(directory_descriptor)
            rebound_directory_final = os.fstat(rebound_directory_descriptor)
            if (
                rebound_slot != final_slot
                or expected_directory_identity
                != (
                    held_directory_final.st_dev,
                    held_directory_final.st_ino,
                    held_directory_final.st_uid,
                    stat.S_IMODE(held_directory_final.st_mode),
                )
                or expected_directory_identity
                != (
                    rebound_directory_final.st_dev,
                    rebound_directory_final.st_ino,
                    rebound_directory_final.st_uid,
                    stat.S_IMODE(rebound_directory_final.st_mode),
                )
            ):
                raise ValueError
            rebound_encoded = cast(
                bytes,
                _attempt_slot_value(rebound_slot, 1),
            )
            rebound_directory_identity = cast(
                tuple[int, int],
                _attempt_slot_value(rebound_slot, 2),
            )
            rebound_file_identity = cast(
                tuple[int, ...],
                _attempt_slot_value(rebound_slot, 3),
            )
            _require_retained_attempt_slot_binding(rebound_encoded, final_approval)
            result = RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt(
                loaded_attested_approval=final_approval,
                artifact_path=exact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                attempt_slot_sha256=hashlib.sha256(rebound_encoded).hexdigest(),
                encoded=rebound_encoded,
                directory_identity=rebound_directory_identity,
                file_identity=rebound_file_identity,
                _construction_capability=(
                    _RETAINED_OPERATOR_ATTESTED_ATTEMPT_CONSTRUCTION_CAPABILITY
                ),
            )
        except BaseException as error:
            body_error = error
        finally:
            try:
                cleanup_error = _cleanup_locked_owners(
                    (
                        (rebound_directory_owner, rebound_directory_lock_call_started),
                        (directory_owner, directory_lock_call_started),
                    )
                )
            except BaseException as error:
                cleanup_error = error
    except BaseException as error:
        transition_error = error
    finally:
        try:
            retry_error = _cleanup_locked_owners(
                (
                    (rebound_directory_owner, rebound_directory_lock_call_started),
                    (directory_owner, directory_lock_call_started),
                )
            )
        except BaseException as error:
            retry_error = error
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable(
            "trusted-time retained operator-attested execution-attempt evidence is unavailable"
        )
    return result


def load_retained_post_enrollment_operator_attested_execution_attempt(
    *,
    start_operator_attested_approval_artifact: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt:
    """Authenticate one exact historical v3 attempt without currentness authority."""

    return _load_retained_post_enrollment_operator_attested_execution_attempt(
        start_operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        operator_attested_approval_loader=(
            load_post_enrollment_operator_attested_execution_approval
        ),
    )


def revalidate_retained_post_enrollment_operator_attested_execution_attempt(
    retained: RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bool:
    """Reopen and compare the exact v3 slot, envelope, Git authority, and provenance."""

    if type(retained) is not RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt:
        return False
    try:
        retained.__post_init__()
        reloaded = load_retained_post_enrollment_operator_attested_execution_attempt(
            start_operator_attested_approval_artifact=(
                retained.loaded_attested_approval.artifact_path
            ),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return reloaded == retained
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def _reserve_attempt_slot(
    directory_descriptor: int,
    *,
    encoded: bytes,
) -> tuple[tuple[int, ...], str]:
    """Permanently create, fsync, and read back the fixed attempt slot."""

    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution attempt binding is invalid"
        )
    file_owner: _OwnedFileDescriptor | None = None
    creation_call_started = False
    created = False
    directory_lock_call_started = False
    try:
        # The directory lock bridges O_EXCL creation to the inode flock.  The
        # inode flock remains the durable-record serialization primitive.
        directory_lock_call_started = True
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX)
        creation_call_started = True
        file_owner = _open_owner_only_file(
            directory_descriptor,
            POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            exclusive=True,
        )
        created = True
        descriptor = file_owner.fileno()
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.fstat(descriptor)
        named_locked = os.stat(
            POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(locked.st_mode)
            or locked.st_uid != os.geteuid()
            or stat.S_IMODE(locked.st_mode) != 0o600
            or locked.st_nlink != 1
            or locked.st_size != 0
            or _stable_file_identity(locked) != _stable_file_identity(named_locked)
        ):
            raise OSError
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.ftruncate(descriptor, len(encoded))
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
        before = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        readback = bytearray()
        while len(readback) <= MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES:
            chunk = os.read(
                descriptor,
                min(
                    65_536,
                    MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES + 1 - len(readback),
                ),
            )
            if not chunk:
                break
            readback.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(
            POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != len(encoded)
            or bytes(readback) != encoded
            or _stable_file_identity(before) != _stable_file_identity(after)
            or _stable_file_identity(after) != _stable_file_identity(named)
        ):
            raise OSError
        return _stable_file_identity(after), hashlib.sha256(encoded).hexdigest()
    except FileExistsError:
        creation_call_started = False
        try:
            retained, _ = _confirm_owner_only_artifact_durable(
                directory_descriptor,
                file_name=POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                expected_encoded=None,
                exclusive_flock=True,
            )
        except BaseException as error:
            raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                "trusted-time post-enrollment execution attempt retention is unconfirmed"
            ) from error
        if not _is_complete_attempt_slot_artifact(retained):
            raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                "trusted-time post-enrollment execution attempt retention is unconfirmed"
            ) from None
        raise TrustedTimePostEnrollmentExecutionAttemptConsumed(
            "trusted-time post-enrollment execution attempt was already consumed"
        ) from None
    except BaseException as error:
        if not isinstance(error, OSError):
            if creation_call_started or created:
                raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                    "trusted-time post-enrollment execution attempt retention is unconfirmed"
                ) from error
            raise
        if creation_call_started or created:
            raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                "trusted-time post-enrollment execution attempt retention is unconfirmed"
            ) from None
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution attempt could not be reserved"
        ) from None
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()
        if directory_lock_call_started:
            with suppress(OSError):
                fcntl.flock(directory_descriptor, fcntl.LOCK_UN)


class _ExecutionAdmissionCapability:
    __slots__ = ()

    def __new__(cls) -> _ExecutionAdmissionCapability:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission capability is unavailable"
        )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be serialized"
        )


def _operator_attested_binding_payload(value: Any) -> dict[str, object]:
    return {
        "execution_approval_v2_semantically_authenticated": True,
        "execution_approval_v2_sha256": value.execution_approval_v2_sha256,
        "operator_attestation_envelope_authenticated": True,
        "operator_attestation_envelope_sha256": (value.operator_attestation_envelope_sha256),
        "operator_attestation_signature_authenticated": True,
        "operator_attestation_signature_sha256": (value.operator_attestation_signature_sha256),
        "operator_attestation_statement_sha256": (value.operator_attestation_statement_sha256),
        "operator_attestation_verification_contract_version": (
            value.operator_attestation_verification_contract_version
        ),
        "operator_attestation_verification_service": (
            value.operator_attestation_verification_service
        ),
        "operator_attestation_verification_status": (
            value.operator_attestation_verification_status
        ),
        "operator_authority_artifact_sha256": value.operator_authority_artifact_sha256,
        "operator_authority_git_blob_object_id": (value.operator_authority_git_blob_object_id),
        "operator_authority_git_mode": value.operator_authority_git_mode,
        "operator_authority_git_object_authenticated": True,
        "operator_authority_git_relative_path": (value.operator_authority_git_relative_path),
        "operator_authority_git_revision": value.operator_authority_git_revision,
        "operator_public_key_sha256": value.operator_public_key_sha256,
    }


def _admission_payload(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    operator_attested_binding: object,
    attempt_slot_sha256: str,
    image_provenance_source_revision_sha256: str,
    image_witness_sha256: str,
    image_witness_source_revision_sha256: str,
    image_witness_remaining_headroom_nanoseconds: int,
) -> dict[str, object]:
    payload = _v3_closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(_operator_attested_binding_payload(operator_attested_binding))
    payload.update(
        {
            "attempt_slot_sha256": attempt_slot_sha256,
            "approved_image_provenance_authenticated": True,
            "approved_image_provenance_source_revision_sha256": (
                image_provenance_source_revision_sha256
            ),
            "contract_version": POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION,
            "execution_attempt_retained": True,
            "image_witness_authenticated": True,
            "image_witness_contract_version": IMAGE_ADMISSION_CONTRACT_VERSION,
            "image_witness_headroom_authenticated": True,
            "image_witness_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "image_witness_remaining_headroom_nanoseconds": (
                image_witness_remaining_headroom_nanoseconds
            ),
            "image_witness_sha256": image_witness_sha256,
            "image_witness_source_revision_sha256": (image_witness_source_revision_sha256),
            "owner_only_artifacts_authenticated": True,
            "service": POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE,
            "status": "execution_admission_unqualified",
        }
    )
    return payload


@dataclass(frozen=True, slots=True, weakref_slot=True)
class TrustedTimePostEnrollmentExecutionAdmission:
    """Process-sealed, one-shot evidence prerequisite; never action authority."""

    approval: TrustedTimePostEnrollmentStartApproval = field(repr=False)
    operator_authority_git_revision: str
    operator_authority_git_relative_path: str
    operator_authority_git_mode: str
    operator_authority_git_blob_object_id: str
    operator_authority_artifact_sha256: str
    operator_public_key_sha256: str
    execution_approval_v2_sha256: str
    operator_attestation_statement_sha256: str
    operator_attestation_signature_sha256: str
    operator_attestation_envelope_sha256: str
    operator_attestation_verification_contract_version: str
    operator_attestation_verification_service: str
    operator_attestation_verification_status: str
    attempt_slot_sha256: str
    image_provenance_source_revision_sha256: str
    image_witness_sha256: str
    image_witness_source_revision_sha256: str
    image_witness_remaining_headroom_nanoseconds: int
    _capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not TrustedTimePostEnrollmentExecutionAdmission:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution admission is invalid"
            )
        try:
            self.approval.__post_init__()
            material = _admission_payload(
                approval=self.approval,
                operator_attested_binding=self,
                attempt_slot_sha256=self.attempt_slot_sha256,
                image_provenance_source_revision_sha256=(
                    self.image_provenance_source_revision_sha256
                ),
                image_witness_sha256=self.image_witness_sha256,
                image_witness_source_revision_sha256=(self.image_witness_source_revision_sha256),
                image_witness_remaining_headroom_nanoseconds=(
                    self.image_witness_remaining_headroom_nanoseconds
                ),
            )
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution admission is invalid"
            ) from None
        if (
            type(self.approval) is not TrustedTimePostEnrollmentStartApproval
            or self.operator_authority_git_revision != self.approval.proposed_launch.git_revision
            or not _is_git_revision(self.operator_authority_git_revision)
            or self.operator_authority_git_relative_path
            != POST_ENROLLMENT_OPERATOR_AUTHORITY_GIT_RELATIVE_PATH
            or self.operator_authority_git_mode != "100644"
            or not _is_git_object_id(self.operator_authority_git_blob_object_id)
            or any(
                not _is_sha256(value)
                for value in (
                    self.operator_authority_artifact_sha256,
                    self.operator_public_key_sha256,
                    self.execution_approval_v2_sha256,
                    self.operator_attestation_statement_sha256,
                    self.operator_attestation_signature_sha256,
                    self.operator_attestation_envelope_sha256,
                )
            )
            or self.operator_attestation_verification_contract_version
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
            or self.operator_attestation_verification_service
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
            or self.operator_attestation_verification_status
            != POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
            or not _is_sha256(self.attempt_slot_sha256)
            or not _is_sha256(self.image_provenance_source_revision_sha256)
            or not _is_sha256(self.image_witness_sha256)
            or not _is_sha256(self.image_witness_source_revision_sha256)
            or self.image_witness_source_revision_sha256
            != self.image_provenance_source_revision_sha256
            or type(self.image_witness_remaining_headroom_nanoseconds) is not int
            or self.image_witness_remaining_headroom_nanoseconds
            < POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS * 1_000_000_000
            or not _valid_execution_admission_capability(
                self._capability,
                material,
                self,
            )
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution admission is invalid"
            )

    @property
    def operation_id(self) -> str:
        _validate_execution_admission(self)
        return self.approval.operation_id

    @property
    def approval_sha256(self) -> str:
        _validate_execution_admission(self)
        return self.approval.approval_sha256

    @property
    def status(self) -> str:
        return "execution_admission_unqualified"

    def payload(self) -> dict[str, object]:
        _validate_execution_admission(self)
        return _admission_payload(
            approval=self.approval,
            operator_attested_binding=self,
            attempt_slot_sha256=self.attempt_slot_sha256,
            image_provenance_source_revision_sha256=(self.image_provenance_source_revision_sha256),
            image_witness_sha256=self.image_witness_sha256,
            image_witness_source_revision_sha256=(self.image_witness_source_revision_sha256),
            image_witness_remaining_headroom_nanoseconds=(
                self.image_witness_remaining_headroom_nanoseconds
            ),
        )

    @property
    def admission_sha256(self) -> str:
        return hashlib.sha256(canonical_first_enrollment_json_bytes(self.payload())).hexdigest()

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission cannot be serialized"
        )

    approved_image_provenance_authenticated = property(_authenticated_fact)
    execution_approval_v2_semantically_authenticated = property(_authenticated_fact)
    execution_attempt_retained = property(_authenticated_fact)
    image_witness_authenticated = property(_authenticated_fact)
    image_witness_headroom_authenticated = property(_authenticated_fact)
    owner_only_artifacts_authenticated = property(_authenticated_fact)
    operator_attestation_envelope_authenticated = property(_authenticated_fact)
    operator_attestation_signature_authenticated = property(_authenticated_fact)
    operator_authority_git_object_authenticated = property(_authenticated_fact)
    active_controller_authorized = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    controller_execution_authorized = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    execution_admission_authorized = property(_authority_is_never_granted)
    execution_attempt_reservation_authorized = property(_authority_is_never_granted)
    outcome_retention_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    retry_authorized = property(_authority_is_never_granted)
    runtime_start_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    success_outcome_retention_authorized = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)


def _validate_execution_admission(value: object) -> None:
    if type(value) is not TrustedTimePostEnrollmentExecutionAdmission:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission is invalid"
        )
    value.__post_init__()


_ImageAdmissionLoader = Callable[..., TrustedTimeImageAdmission]
_ImageProvenanceLoader = Callable[..., TrustedTimeImageAdmissionProvenance]
_OperatorAttestedApprovalLoader = Callable[
    ...,
    LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
]


@dataclass(frozen=True, slots=True)
class _ExecutionAdmissionContinuation:
    admission_reference: weakref.ReferenceType[TrustedTimePostEnrollmentExecutionAdmission]
    operator_attested_approval_artifact: Path
    artifact_directory: Path
    ignored_root: Path
    loaded_attested_approval: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
    image_admission: TrustedTimeImageAdmission
    image_witness: TrustedTimeImageAdmissionProvenance
    slot_encoded: bytes
    slot_identity: tuple[int, ...]
    process_id: int
    thread: threading.Thread


_CAPABILITY_VALIDATOR_LOCK = threading.Lock()
_CAPABILITY_VALIDATORS: dict[
    _ExecutionAdmissionCapability,
    Callable[[object, dict[str, object], object], bool],
] = {}


def _valid_execution_admission_capability(
    candidate: object,
    material: dict[str, object],
    result: object,
) -> bool:
    if type(candidate) is not _ExecutionAdmissionCapability:
        return False
    with _CAPABILITY_VALIDATOR_LOCK:
        validator = _CAPABILITY_VALIDATORS.get(candidate)
    if validator is None:
        return False
    try:
        return validator(candidate, material, result)
    except BaseException:
        return False


def _build_execution_admitter(
    *,
    image_admission_loader: _ImageAdmissionLoader = load_image_admission_artifact,
    image_provenance_loader: _ImageProvenanceLoader = (load_image_admission_provenance_artifact),
    operator_attested_approval_loader: _OperatorAttestedApprovalLoader = (
        load_post_enrollment_operator_attested_execution_approval
    ),
    monotonic_ns: Callable[[], int] = _suspend_aware_monotonic_ns,
    process_id: Callable[[], int] = os.getpid,
    current_thread: Callable[[], threading.Thread] = threading.current_thread,
) -> tuple[
    Callable[..., TrustedTimePostEnrollmentExecutionAdmission],
    Callable[[object, dict[str, object], object], bool],
    Callable[..., bool],
]:
    """Build the production gate; injectable dependencies are private test seams."""

    registry_lock = threading.Lock()
    origin_pid = process_id()
    capabilities: dict[
        _ExecutionAdmissionCapability,
        tuple[
            str,
            weakref.ReferenceType[TrustedTimePostEnrollmentExecutionAdmission] | None,
        ],
    ] = {}
    continuations: dict[_ExecutionAdmissionCapability, _ExecutionAdmissionContinuation] = {}

    def valid_capability(candidate: object, material: dict[str, object], result: object) -> bool:
        if (
            process_id() != origin_pid
            or type(candidate) is not _ExecutionAdmissionCapability
            or type(result) is not TrustedTimePostEnrollmentExecutionAdmission
        ):
            return False
        material_sha256 = hashlib.sha256(
            canonical_first_enrollment_json_bytes(material)
        ).hexdigest()
        with registry_lock:
            registration = capabilities.get(candidate)
            if registration is None or registration[0] != material_sha256:
                return False
            if registration[1] is None:

                def admission_lost(
                    reference: weakref.ReferenceType[TrustedTimePostEnrollmentExecutionAdmission],
                ) -> None:
                    with registry_lock:
                        current = capabilities.get(candidate)
                        if current is None or current[1] is not reference:
                            return
                        continuations.pop(candidate, None)
                        capabilities.pop(candidate, None)
                    with _CAPABILITY_VALIDATOR_LOCK:
                        _CAPABILITY_VALIDATORS.pop(candidate, None)

                capabilities[candidate] = (
                    material_sha256,
                    weakref.ref(result, admission_lost),
                )
                return True
            return registration[1]() is result

    def unregister(candidate: object) -> None:
        if type(candidate) is not _ExecutionAdmissionCapability:
            return
        with registry_lock:
            continuations.pop(candidate, None)
            capabilities.pop(candidate, None)
        with _CAPABILITY_VALIDATOR_LOCK:
            _CAPABILITY_VALIDATORS.pop(candidate, None)

    def observe_monotonic_ns() -> int:
        try:
            observed = monotonic_ns()
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution admission clock is unavailable"
            ) from None
        if type(observed) is not int or observed < 0:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution admission clock is unavailable"
            )
        return observed

    def reserve(
        *,
        loaded_attested_approval: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
        image_admission: TrustedTimeImageAdmission,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimePostEnrollmentExecutionAdmission:
        capability: _ExecutionAdmissionCapability | None = None
        if process_id() != origin_pid:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution admission is unavailable after fork"
            )
        exact_directory, exact_root = _exact_artifact_roots(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if (
            type(loaded_attested_approval)
            is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
            or type(image_admission) is not TrustedTimeImageAdmission
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution late admission is invalid"
            )
        loaded_attested_approval.__post_init__()
        reloaded = operator_attested_approval_loader(
            operator_attested_approval_artifact=loaded_attested_approval.artifact_path,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
        )
        if type(reloaded) is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval changed before reservation"
            )
        reloaded.__post_init__()
        if reloaded != loaded_attested_approval:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution approval changed before reservation"
            )
        exact = reloaded.approval
        observed = observe_monotonic_ns()
        image_witness, initial_remaining_headroom_ns = _load_exact_image_witness(
            approval=exact,
            image_provenance=reloaded.image_provenance,
            image_admission=image_admission,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
            observed_monotonic_ns=observed,
            admission_loader=image_admission_loader,
            provenance_loader=image_provenance_loader,
        )
        slot_payload = _attempt_slot_payload(
            loaded_attested_approval=reloaded,
            image_provenance=reloaded.image_provenance,
            image_witness=image_witness,
            observed_monotonic_ns=observed,
            remaining_headroom_ns=initial_remaining_headroom_ns,
        )
        try:
            slot_encoded = canonical_first_enrollment_json_bytes(slot_payload)
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution attempt binding is invalid"
            ) from None
        directory_owner: _OwnedFileDescriptor | None = None
        attempt_slot_may_have_begun = False
        try:
            directory_owner = _open_owner_only_artifact_directory(
                exact_directory,
                ignored_root=exact_root,
            )
            attempt_slot_may_have_begun = True
            slot_identity, slot_sha256 = _reserve_attempt_slot(
                directory_owner.fileno(),
                encoded=slot_encoded,
            )
        except (
            TrustedTimePostEnrollmentExecutionAttemptConsumed,
            TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed,
        ):
            raise
        except BaseException as error:
            if attempt_slot_may_have_begun:
                raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                    "trusted-time post-enrollment execution attempt retention is unconfirmed"
                ) from error
            raise
        finally:
            if directory_owner is not None:
                try:
                    directory_owner.close()
                except BaseException as error:
                    if attempt_slot_may_have_begun:
                        raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                            "trusted-time post-enrollment execution attempt retention "
                            "is unconfirmed"
                        ) from error
                    raise
        try:
            final_approval = operator_attested_approval_loader(
                operator_attested_approval_artifact=reloaded.artifact_path,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
            )
            if (
                type(final_approval)
                is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
            ):
                raise ValueError
            final_approval.__post_init__()
            if final_approval != reloaded:
                raise ValueError
            final_observed = observe_monotonic_ns()
            final_witness, final_remaining_headroom_ns = _load_exact_image_witness(
                approval=exact,
                image_provenance=reloaded.image_provenance,
                image_admission=image_admission,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
                observed_monotonic_ns=final_observed,
                admission_loader=image_admission_loader,
                provenance_loader=image_provenance_loader,
            )
            if final_witness != image_witness:
                raise ValueError
            material = _admission_payload(
                approval=exact,
                operator_attested_binding=reloaded,
                attempt_slot_sha256=slot_sha256,
                image_provenance_source_revision_sha256=(
                    reloaded.image_provenance.source_revision_sha256
                ),
                image_witness_sha256=image_witness.artifact_sha256,
                image_witness_source_revision_sha256=(image_witness.source_revision_sha256),
                image_witness_remaining_headroom_nanoseconds=(final_remaining_headroom_ns),
            )
            capability = object.__new__(_ExecutionAdmissionCapability)
            material_sha256 = hashlib.sha256(
                canonical_first_enrollment_json_bytes(material)
            ).hexdigest()
            with registry_lock:
                capabilities[capability] = (material_sha256, None)
            with _CAPABILITY_VALIDATOR_LOCK:
                _CAPABILITY_VALIDATORS[capability] = valid_capability
            result = TrustedTimePostEnrollmentExecutionAdmission(
                approval=exact,
                operator_authority_git_revision=reloaded.operator_authority_git_revision,
                operator_authority_git_relative_path=(
                    reloaded.operator_authority_git_relative_path
                ),
                operator_authority_git_mode=reloaded.operator_authority_git_mode,
                operator_authority_git_blob_object_id=(
                    reloaded.operator_authority_git_blob_object_id
                ),
                operator_authority_artifact_sha256=(reloaded.operator_authority_artifact_sha256),
                operator_public_key_sha256=reloaded.operator_public_key_sha256,
                execution_approval_v2_sha256=reloaded.execution_approval_v2_sha256,
                operator_attestation_statement_sha256=(
                    reloaded.operator_attestation_statement_sha256
                ),
                operator_attestation_signature_sha256=(
                    reloaded.operator_attestation_signature_sha256
                ),
                operator_attestation_envelope_sha256=(
                    reloaded.operator_attestation_envelope_sha256
                ),
                operator_attestation_verification_contract_version=(
                    reloaded.operator_attestation_verification_contract_version
                ),
                operator_attestation_verification_service=(
                    reloaded.operator_attestation_verification_service
                ),
                operator_attestation_verification_status=(
                    reloaded.operator_attestation_verification_status
                ),
                attempt_slot_sha256=slot_sha256,
                image_provenance_source_revision_sha256=(
                    reloaded.image_provenance.source_revision_sha256
                ),
                image_witness_sha256=image_witness.artifact_sha256,
                image_witness_source_revision_sha256=(image_witness.source_revision_sha256),
                image_witness_remaining_headroom_nanoseconds=(final_remaining_headroom_ns),
                _capability=capability,
            )
            with registry_lock:
                registration = capabilities.get(capability)
                if (
                    registration is None
                    or registration[1] is None
                    or registration[1]() is not result
                ):
                    raise ValueError
                continuations[capability] = _ExecutionAdmissionContinuation(
                    admission_reference=registration[1],
                    operator_attested_approval_artifact=reloaded.artifact_path,
                    artifact_directory=exact_directory,
                    ignored_root=exact_root,
                    loaded_attested_approval=reloaded,
                    image_admission=image_admission,
                    image_witness=image_witness,
                    slot_encoded=slot_encoded,
                    slot_identity=slot_identity,
                    process_id=process_id(),
                    thread=current_thread(),
                )
            return result
        except BaseException as error:
            if capability is not None:
                with suppress(BaseException):
                    unregister(capability)
            raise TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed(
                "trusted-time post-enrollment execution attempt retention is unconfirmed"
            ) from error

    def consume(
        candidate: object,
        *,
        operator_attested_approval_artifact: object,
        artifact_directory: object = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: object = IGNORED_ARTIFACT_ROOT,
    ) -> bool:
        if (
            process_id() != origin_pid
            or type(candidate) is not TrustedTimePostEnrollmentExecutionAdmission
        ):
            return False
        capability = getattr(candidate, "_capability", None)
        if type(capability) is not _ExecutionAdmissionCapability:
            return False
        with registry_lock:
            continuation = continuations.pop(capability, None)
        if continuation is None:
            return False
        try:
            retained = continuation.admission_reference()
            accepted = (
                retained is candidate
                and type(operator_attested_approval_artifact) is type(Path())
                and continuation.operator_attested_approval_artifact
                == operator_attested_approval_artifact
                and type(artifact_directory) is type(Path())
                and type(ignored_root) is type(Path())
                and continuation.artifact_directory == artifact_directory
                and continuation.ignored_root == ignored_root
                and continuation.process_id == process_id()
                and continuation.thread is current_thread()
            )
            if not accepted:
                return False
            exact_operator_attested_approval_artifact = cast(
                Path,
                operator_attested_approval_artifact,
            )
            exact_artifact_directory = cast(Path, artifact_directory)
            exact_ignored_root = cast(Path, ignored_root)
            candidate.__post_init__()
            loaded = operator_attested_approval_loader(
                operator_attested_approval_artifact=(exact_operator_attested_approval_artifact),
                artifact_directory=exact_artifact_directory,
                ignored_root=exact_ignored_root,
            )
            if type(loaded) is not LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval:
                return False
            loaded.__post_init__()
            exact = loaded.approval
            if (
                loaded != continuation.loaded_attested_approval
                or any(
                    getattr(loaded, field_name) != getattr(candidate, field_name)
                    for field_name in (
                        "operator_authority_git_revision",
                        "operator_authority_git_relative_path",
                        "operator_authority_git_mode",
                        "operator_authority_git_blob_object_id",
                        "operator_authority_artifact_sha256",
                        "operator_public_key_sha256",
                        "execution_approval_v2_sha256",
                        "operator_attestation_statement_sha256",
                        "operator_attestation_signature_sha256",
                        "operator_attestation_envelope_sha256",
                        "operator_attestation_verification_contract_version",
                        "operator_attestation_verification_service",
                        "operator_attestation_verification_status",
                    )
                )
                or exact != candidate.approval
            ):
                return False
            directory_owner: _OwnedFileDescriptor | None = None
            try:
                directory_owner = _open_owner_only_artifact_directory(
                    exact_artifact_directory,
                    ignored_root=exact_ignored_root,
                )
                slot_encoded, slot_identity = _read_owner_only_artifact(
                    directory_owner.fileno(),
                    file_name=POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                )
            finally:
                if directory_owner is not None:
                    directory_owner.close()
            if (
                slot_encoded != continuation.slot_encoded
                or slot_identity != continuation.slot_identity
                or hashlib.sha256(slot_encoded).hexdigest() != candidate.attempt_slot_sha256
            ):
                return False
            observed = observe_monotonic_ns()
            witness, remaining_headroom_ns = _load_exact_image_witness(
                approval=exact,
                image_provenance=loaded.image_provenance,
                image_admission=continuation.image_admission,
                artifact_directory=exact_artifact_directory,
                ignored_root=exact_ignored_root,
                observed_monotonic_ns=observed,
                admission_loader=image_admission_loader,
                provenance_loader=image_provenance_loader,
            )
            return not (
                witness != continuation.image_witness
                or remaining_headroom_ns
                < POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS * 1_000_000_000
            )
        except Exception:
            return False

    return reserve, valid_capability, consume


(
    reserve_post_enrollment_execution_attempt,
    _production_valid_execution_admission_capability,
    _consume_post_enrollment_execution_admission,
) = _build_execution_admitter()


__all__ = [
    "DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY",
    "MAXIMUM_POST_ENROLLMENT_EXECUTION_ARTIFACT_BYTES",
    "POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION",
    "POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION",
    "POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX",
    "POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX",
    "POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION",
    "POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME",
    "POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS",
    "LoadedTrustedTimePostEnrollmentExecutionApproval",
    "LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval",
    "RetainedTrustedTimePostEnrollmentOperatorAttestedExecutionAttempt",
    "TrustedTimePostEnrollmentExecutionAdmission",
    "TrustedTimePostEnrollmentExecutionAdmissionRejected",
    "TrustedTimePostEnrollmentExecutionAttemptConsumed",
    "TrustedTimePostEnrollmentExecutionAttemptEvidenceUnavailable",
    "TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed",
    "decode_post_enrollment_execution_approval_bytes",
    "load_post_enrollment_execution_approval",
    "load_post_enrollment_operator_attested_execution_approval",
    "load_retained_post_enrollment_operator_attested_execution_attempt",
    "post_enrollment_execution_approval_artifact_path",
    "post_enrollment_execution_approval_bytes",
    "reserve_post_enrollment_execution_attempt",
    "retain_post_enrollment_execution_approval",
    "revalidate_retained_post_enrollment_operator_attested_execution_attempt",
]
