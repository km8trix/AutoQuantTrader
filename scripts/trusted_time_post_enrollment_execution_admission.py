"""Owner-only, single-use admission for a dormant post-enrollment executor.

This module authenticates one externally retained, content-addressed approval
projection and one fresh immutable-image admission, then permanently reserves
the host-wide execution-attempt slot.  It does not read secrets, mutate a
topology, expose a CLI, or grant release, runtime, operational, or trading
authority.
"""

from __future__ import annotations

import hashlib
import io
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
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    TrustedTimeImageAdmission,
    _suspend_aware_monotonic_ns,
    load_image_admission_artifact,
)

POST_ENROLLMENT_EXECUTION_APPROVAL_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-approval-v1"
)
POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-attempt-v1"
)
POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-admission-v1"
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
        "confirmed_enrollment_evidence_sha256": (approval.confirmed_enrollment.evidence_sha256),
        "git_revision": approval.proposed_launch.git_revision,
        "image_admission_sha256": approval.proposed_launch.image_admission_sha256,
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
            "image_admission_minimum_headroom_seconds": (
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


def _open_owner_only_artifact_directory(path: Path, *, ignored_root: Path) -> int:
    """Open an existing canonical owner-only directory without following links."""

    if path != ignored_root / "trusted-time":
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution artifact directory is unavailable"
        )
    descriptor: int | None = None
    next_descriptor: int | None = None
    prior_descriptor: int | None = None
    current = Path(path.anchor)
    try:
        descriptor = os.open(
            path.anchor,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        for part in path.parts[1:]:
            current /= part
            next_descriptor = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            metadata = os.fstat(next_descriptor)
            protected = current == ignored_root or current.is_relative_to(ignored_root)
            if protected and (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise OSError
            prior_descriptor = descriptor
            descriptor = next_descriptor
            next_descriptor = None
            os.close(prior_descriptor)
            prior_descriptor = None
        return descriptor
    except BaseException as error:
        for candidate in {descriptor, next_descriptor, prior_descriptor}:
            if candidate is not None:
                with suppress(OSError):
                    os.close(candidate)
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
) -> io.FileIO:
    """Return a VM-owned descriptor so async CALL/STORE loss closes it."""

    mode = "x+b" if exclusive else "rb"

    def opener(path: str, flags: int) -> int:
        return os.open(
            path,
            flags
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | (0 if exclusive else getattr(os, "O_NONBLOCK", 0)),
            0o600,
            dir_fd=directory_descriptor,
        )

    return io.FileIO(file_name, mode=mode, opener=opener)


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


def load_post_enrollment_execution_approval(
    *,
    approval_artifact: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
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
    directory_descriptor: int | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            exact_directory,
            ignored_root=exact_root,
        )
        encoded, identity = _read_owner_only_artifact(
            directory_descriptor,
            file_name=file_name,
        )
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
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
    return LoadedTrustedTimePostEnrollmentExecutionApproval(
        approval=exact,
        artifact_sha256=artifact_sha256,
        artifact_path=exact_directory / file_name,
        encoded=encoded,
        file_identity=identity,
    )


def _image_admission_artifact_path(
    approval: TrustedTimePostEnrollmentStartApproval,
    *,
    artifact_directory: Path,
) -> Path:
    return artifact_directory / (
        f"image-admission-{approval.proposed_launch.image_admission_sha256}.json"
    )


def _load_exact_image_admission(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    artifact_directory: Path,
    ignored_root: Path,
    observed_monotonic_ns: int,
    loader: Callable[..., TrustedTimeImageAdmission],
) -> tuple[TrustedTimeImageAdmission, int]:
    if type(observed_monotonic_ns) is not int or observed_monotonic_ns < 0:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution admission clock is unavailable"
        )
    expected_path = _image_admission_artifact_path(
        approval,
        artifact_directory=artifact_directory,
    )
    try:
        admission = loader(
            expected_path,
            ignored_root=ignored_root,
            monotonic_ns=observed_monotonic_ns,
        )
        if type(admission) is not TrustedTimeImageAdmission:
            raise ValueError
        admission.__post_init__()
        admission.identities.__post_init__()
    except Exception:
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image admission is invalid"
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
        admission.path != expected_path
        or admission.artifact_sha256 != launch.image_admission_sha256
        or admission.git_revision != launch.git_revision
        or admission.identities.source_id != launch.source_image_id
        or admission.identities.supervisor_id != launch.supervisor_image_id
        or observed_monotonic_ns < admission.created_monotonic_ns
        or remaining_headroom_ns < required_headroom_ns
    ):
        raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
            "trusted-time post-enrollment execution image admission lacks exact headroom"
        )
    return admission, remaining_headroom_ns


def _attempt_slot_payload(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    approval_artifact_sha256: str,
    image_admission: TrustedTimeImageAdmission,
    observed_monotonic_ns: int,
    remaining_headroom_ns: int,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(
        {
            "approval_artifact_sha256": approval_artifact_sha256,
            "contract_version": POST_ENROLLMENT_EXECUTION_ATTEMPT_CONTRACT_VERSION,
            "image_admission_boot_session_id": image_admission.boot_session_id,
            "image_admission_checked_monotonic_ns": observed_monotonic_ns,
            "image_admission_created_monotonic_ns": (image_admission.created_monotonic_ns),
            "image_admission_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "image_admission_remaining_headroom_nanoseconds": remaining_headroom_ns,
            "image_admission_source_revision_sha256": (image_admission.source_revision_sha256),
            "service": POST_ENROLLMENT_EXECUTION_ADMISSION_SERVICE,
            "status": "execution_attempt_reserved",
        }
    )
    return payload


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
    file_owner: io.FileIO | None = None
    created = False
    try:
        file_owner = _open_owner_only_file(
            directory_descriptor,
            POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
            exclusive=True,
        )
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
        raise TrustedTimePostEnrollmentExecutionAttemptConsumed(
            "trusted-time post-enrollment execution attempt was already consumed"
        ) from None
    except OSError:
        if created:
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
    image_admission_remaining_headroom_nanoseconds: int,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(_tuple_payload(approval))
    payload.update(
        {
            "approval_artifact_authenticated": True,
            "approval_artifact_sha256": approval_artifact_sha256,
            "attempt_slot_sha256": attempt_slot_sha256,
            "contract_version": POST_ENROLLMENT_EXECUTION_ADMISSION_CONTRACT_VERSION,
            "execution_attempt_retained": True,
            "image_admission_authenticated": True,
            "image_admission_headroom_authenticated": True,
            "image_admission_minimum_headroom_seconds": (
                POST_ENROLLMENT_EXECUTION_MINIMUM_IMAGE_ADMISSION_HEADROOM_SECONDS
            ),
            "image_admission_remaining_headroom_nanoseconds": (
                image_admission_remaining_headroom_nanoseconds
            ),
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
    image_admission_remaining_headroom_nanoseconds: int
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
                image_admission_remaining_headroom_nanoseconds=(
                    self.image_admission_remaining_headroom_nanoseconds
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
            or type(self.image_admission_remaining_headroom_nanoseconds) is not int
            or self.image_admission_remaining_headroom_nanoseconds
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
            image_admission_remaining_headroom_nanoseconds=(
                self.image_admission_remaining_headroom_nanoseconds
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
    execution_attempt_retained = property(_authenticated_fact)
    image_admission_authenticated = property(_authenticated_fact)
    image_admission_headroom_authenticated = property(_authenticated_fact)
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
    continuations: dict[
        _ExecutionAdmissionCapability,
        tuple[
            weakref.ReferenceType[TrustedTimePostEnrollmentExecutionAdmission],
            Path,
            Path,
            Path,
            bytes,
            tuple[int, ...],
            int,
            threading.Thread,
        ],
    ] = {}

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

    def admit(
        *,
        approval_artifact: Path,
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
        loaded = load_post_enrollment_execution_approval(
            approval_artifact=approval_artifact,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
        )
        exact = loaded.approval
        observed = observe_monotonic_ns()
        image_admission, initial_remaining_headroom_ns = _load_exact_image_admission(
            approval=exact,
            artifact_directory=exact_directory,
            ignored_root=exact_root,
            observed_monotonic_ns=observed,
            loader=image_admission_loader,
        )
        slot_payload = _attempt_slot_payload(
            approval=exact,
            approval_artifact_sha256=loaded.artifact_sha256,
            image_admission=image_admission,
            observed_monotonic_ns=observed,
            remaining_headroom_ns=initial_remaining_headroom_ns,
        )
        try:
            slot_encoded = canonical_first_enrollment_json_bytes(slot_payload)
        except Exception:
            raise TrustedTimePostEnrollmentExecutionAdmissionRejected(
                "trusted-time post-enrollment execution attempt binding is invalid"
            ) from None
        directory_descriptor: int | None = None
        try:
            directory_descriptor = _open_owner_only_artifact_directory(
                exact_directory,
                ignored_root=exact_root,
            )
            slot_identity, slot_sha256 = _reserve_attempt_slot(
                directory_descriptor,
                encoded=slot_encoded,
            )
        finally:
            if directory_descriptor is not None:
                with suppress(OSError):
                    os.close(directory_descriptor)
        try:
            reloaded = load_post_enrollment_execution_approval(
                approval_artifact=approval_artifact,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
            )
            if (
                reloaded.artifact_sha256 != loaded.artifact_sha256
                or reloaded.file_identity != loaded.file_identity
                or reloaded.encoded != loaded.encoded
            ):
                raise ValueError
            final_observed = observe_monotonic_ns()
            _, final_remaining_headroom_ns = _load_exact_image_admission(
                approval=exact,
                artifact_directory=exact_directory,
                ignored_root=exact_root,
                observed_monotonic_ns=final_observed,
                loader=image_admission_loader,
            )
            material = _admission_payload(
                approval=exact,
                approval_artifact_sha256=loaded.artifact_sha256,
                attempt_slot_sha256=slot_sha256,
                image_admission_remaining_headroom_nanoseconds=(final_remaining_headroom_ns),
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
                approval_artifact_sha256=loaded.artifact_sha256,
                attempt_slot_sha256=slot_sha256,
                image_admission_remaining_headroom_nanoseconds=(final_remaining_headroom_ns),
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
                continuations[capability] = (
                    registration[1],
                    approval_artifact,
                    exact_directory,
                    exact_root,
                    slot_encoded,
                    slot_identity,
                    process_id(),
                    current_thread(),
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
            retained = continuation[0]()
            accepted = (
                retained is candidate
                and type(approval_artifact) is type(Path())
                and continuation[1] == approval_artifact
                and type(artifact_directory) is type(Path())
                and type(ignored_root) is type(Path())
                and continuation[2] == artifact_directory
                and continuation[3] == ignored_root
                and continuation[6] == process_id()
                and continuation[7] is current_thread()
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
            )
            exact = loaded.approval
            if (
                loaded.artifact_sha256 != candidate.approval_artifact_sha256
                or exact != candidate.approval
            ):
                return False
            directory_descriptor: int | None = None
            try:
                directory_descriptor = _open_owner_only_artifact_directory(
                    exact_artifact_directory,
                    ignored_root=exact_ignored_root,
                )
                slot_encoded, slot_identity = _read_owner_only_artifact(
                    directory_descriptor,
                    file_name=POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
                )
            finally:
                if directory_descriptor is not None:
                    with suppress(OSError):
                        os.close(directory_descriptor)
            if (
                slot_encoded != continuation[4]
                or slot_identity != continuation[5]
                or hashlib.sha256(slot_encoded).hexdigest() != candidate.attempt_slot_sha256
            ):
                return False
            observed = observe_monotonic_ns()
            _load_exact_image_admission(
                approval=exact,
                artifact_directory=exact_artifact_directory,
                ignored_root=exact_ignored_root,
                observed_monotonic_ns=observed,
                loader=image_admission_loader,
            )
            return True
        except Exception:
            return False

    return admit, valid_capability, consume


(
    admit_post_enrollment_execution_attempt,
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
    "TrustedTimePostEnrollmentExecutionAdmission",
    "TrustedTimePostEnrollmentExecutionAdmissionRejected",
    "TrustedTimePostEnrollmentExecutionAttemptConsumed",
    "TrustedTimePostEnrollmentExecutionAttemptRetentionUnconfirmed",
    "admit_post_enrollment_execution_attempt",
    "load_post_enrollment_execution_approval",
    "post_enrollment_execution_approval_artifact_path",
    "post_enrollment_execution_approval_bytes",
]
