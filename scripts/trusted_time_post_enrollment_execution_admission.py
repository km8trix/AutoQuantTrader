"""Owner-only, single-use admission for a dormant post-enrollment executor.

This module authenticates one externally retained, content-addressed approval
projection and one fresh immutable-image admission, then permanently reserves
the host-wide execution-attempt slot.  It does not read secrets, mutate a
topology, expose a CLI, or grant release, runtime, operational, or trading
authority.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import threading
import weakref
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Never, SupportsIndex, cast

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    FIRST_ENROLLMENT_IDENTITY_FIELDS,
    TrustedTimeConfirmedFirstEnrollment,
    TrustedTimeFirstEnrollmentIdentities,
    TrustedTimeImmutableLaunchEvidence,
    TrustedTimeSequenceOneEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.verify_trusted_time_images import (
    IGNORED_ARTIFACT_ROOT,
    IMAGE_ADMISSION_CONTRACT_VERSION,
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    TrustedTimeImageAdmission,
    TrustedTimeImageAdmissionProvenance,
    _suspend_aware_monotonic_ns,
    load_image_admission_artifact,
    load_image_admission_provenance_artifact,
)

POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-approval-v2"
)
POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-attempt-v2"
)
POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-admission-v2"
)
POST_ENROLLMENT_EXECUTION_APPROVAL_SERVICE = "trusted-time-post-enrollment-start-execution-approval"
POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE = (
    "trusted-time-post-enrollment-start-execution-admission"
)
POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_PREFIX = (
    "trusted-time-post-enrollment-start-execution-approval-"
)
POST_ENROLLMENT_EXECUTION_APPROVAL_FILE_SUFFIX = ".json"
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

    def close(self) -> None:
        descriptor = self.value
        if descriptor < 0:
            return
        try:
            self.value = -1
            os.close(descriptor)
        except OSError:
            raise
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise

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
    payload = _decode_canonical_json(encoded)
    exact = _decode_execution_approval_artifact(payload)
    expected_encoded = post_enrollment_execution_approval_bytes(
        exact,
        expected_approval_sha256=exact.approval_sha256,
    )
    if encoded != expected_encoded or hashlib.sha256(encoded).hexdigest() != artifact_sha256:
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
    approval: TrustedTimePostEnrollmentStartApproval,
    approval_artifact_sha256: str,
    image_provenance: TrustedTimeImageAdmissionProvenance,
    image_witness: TrustedTimeImageAdmissionProvenance,
    observed_monotonic_ns: int,
    remaining_headroom_ns: int,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(
        {
            "approval_artifact_sha256": approval_artifact_sha256,
            "contract_version": POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
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
            "service": POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE,
            "status": "execution_attempt_reserved",
        }
    )
    return payload


_ATTEMPT_SLOT_FIELDS = frozenset(
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
_ATTEMPT_SLOT_SHA256_FIELDS = (
    "approval_artifact_sha256",
    "approval_sha256",
    "approved_image_provenance_sha256",
    "approved_image_provenance_source_revision_sha256",
    "confirmed_enrollment_evidence_sha256",
    "image_witness_sha256",
    "image_witness_source_revision_sha256",
    "review_projection_sha256",
)


def _is_complete_attempt_slot_artifact(encoded: bytes) -> bool:
    """Classify only one complete canonical v2 attempt as confirmed consumed."""

    try:
        payload = _decode_canonical_json(encoded)
    except TrustedTimePostEnrollmentExecutionAdmissionRejected:
        return False
    return (
        set(payload) == _ATTEMPT_SLOT_FIELDS
        and all(payload.get(field_name) is False for field_name in _closed_payload())
        and all(_is_sha256(payload.get(field_name)) for field_name in _ATTEMPT_SLOT_SHA256_FIELDS)
        and payload.get("contract_version") == POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION
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


def _admission_payload(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    approval_artifact_sha256: str,
    attempt_slot_sha256: str,
    image_provenance_source_revision_sha256: str,
    image_witness_sha256: str,
    image_witness_source_revision_sha256: str,
    image_witness_remaining_headroom_nanoseconds: int,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(
        {
            "approval_artifact_authenticated": True,
            "approval_artifact_sha256": approval_artifact_sha256,
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
    approval_artifact_sha256: str
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
                approval_artifact_sha256=self.approval_artifact_sha256,
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
            or not _is_sha256(self.approval_artifact_sha256)
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
            approval_artifact_sha256=self.approval_artifact_sha256,
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

    approval_artifact_authenticated = property(_authenticated_fact)
    approved_image_provenance_authenticated = property(_authenticated_fact)
    execution_attempt_retained = property(_authenticated_fact)
    image_witness_authenticated = property(_authenticated_fact)
    image_witness_headroom_authenticated = property(_authenticated_fact)
    owner_only_artifacts_authenticated = property(_authenticated_fact)
    active_controller_authorized = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    controller_execution_authorized = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    outcome_retention_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    runtime_start_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
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


@dataclass(frozen=True, slots=True)
class _ExecutionAdmissionContinuation:
    admission_reference: weakref.ReferenceType[TrustedTimePostEnrollmentExecutionAdmission]
    approval_artifact: Path
    artifact_directory: Path
    ignored_root: Path
    approval_receipt: LoadedTrustedTimePostEnrollmentExecutionApproval
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
        loaded_approval: LoadedTrustedTimePostEnrollmentExecutionApproval,
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
            type(loaded_approval) is not LoadedTrustedTimePostEnrollmentExecutionApproval
            or type(image_admission) is not TrustedTimeImageAdmission
            or loaded_approval.artifact_path.parent != exact_directory
        ):
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution late admission is invalid"
            )
        loaded_approval.__post_init__()
        reloaded = load_post_enrollment_execution_approval(
            approval_artifact=loaded_approval.artifact_path,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
            image_provenance_loader=image_provenance_loader,
        )
        if reloaded != loaded_approval:
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
            approval=exact,
            approval_artifact_sha256=reloaded.artifact_sha256,
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
        try:
            directory_owner = _open_owner_only_artifact_directory(
                exact_directory,
                ignored_root=exact_root,
            )
            slot_identity, slot_sha256 = _reserve_attempt_slot(
                directory_owner.fileno(),
                encoded=slot_encoded,
            )
        finally:
            if directory_owner is not None:
                directory_owner.close()
        try:
            final_approval = load_post_enrollment_execution_approval(
                approval_artifact=reloaded.artifact_path,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
                image_provenance_loader=image_provenance_loader,
            )
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
                approval_artifact_sha256=reloaded.artifact_sha256,
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
                approval_artifact_sha256=reloaded.artifact_sha256,
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
                    approval_artifact=reloaded.artifact_path,
                    artifact_directory=exact_directory,
                    ignored_root=exact_root,
                    approval_receipt=reloaded,
                    image_admission=image_admission,
                    image_witness=image_witness,
                    slot_encoded=slot_encoded,
                    slot_identity=slot_identity,
                    process_id=process_id(),
                    thread=current_thread(),
                )
            return result
        except BaseException:
            if capability is not None:
                with suppress(BaseException):
                    unregister(capability)
            raise

    def consume(
        candidate: object,
        *,
        approval_artifact: object,
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
                and type(approval_artifact) is type(Path())
                and continuation.approval_artifact == approval_artifact
                and type(artifact_directory) is type(Path())
                and type(ignored_root) is type(Path())
                and continuation.artifact_directory == artifact_directory
                and continuation.ignored_root == ignored_root
                and continuation.process_id == process_id()
                and continuation.thread is current_thread()
            )
            if not accepted:
                return False
            exact_approval_artifact = cast(Path, approval_artifact)
            exact_artifact_directory = cast(Path, artifact_directory)
            exact_ignored_root = cast(Path, ignored_root)
            candidate.__post_init__()
            loaded = load_post_enrollment_execution_approval(
                approval_artifact=exact_approval_artifact,
                artifact_directory=exact_artifact_directory,
                ignored_root=exact_ignored_root,
                image_provenance_loader=image_provenance_loader,
            )
            exact = loaded.approval
            if (
                loaded != continuation.approval_receipt
                or loaded.artifact_sha256 != candidate.approval_artifact_sha256
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

# Transitional import name with the v2 late-reservation signature.  It does not
# accept the v1 approval-artifact-only call shape.
admit_post_enrollment_execution_attempt = reserve_post_enrollment_execution_attempt


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
    "TrustedTimePostEnrollmentExecutionAdmission",
    "TrustedTimePostEnrollmentExecutionAdmissionRejected",
    "TrustedTimePostEnrollmentExecutionAttemptConsumed",
    "TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed",
    "admit_post_enrollment_execution_attempt",
    "load_post_enrollment_execution_approval",
    "post_enrollment_execution_approval_artifact_path",
    "post_enrollment_execution_approval_bytes",
    "reserve_post_enrollment_execution_attempt",
    "retain_post_enrollment_execution_approval",
]
