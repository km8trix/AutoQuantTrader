"""Consume one exact approval for a dormant trusted-time first enrollment."""

# ruff: noqa: E402 -- the CLI bootstrap must run before first-party imports.

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import sys
import time
import uuid
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
) -> Path:
    """Fail closed unless this CLI is canonical source in an isolated runtime."""

    try:
        repository_root = Path.cwd()
        expected_source = repository_root / expected_relative_path
        actual_source = Path(os.path.abspath(module_file))
        source_metadata = expected_source.lstat()
        canonical_root = repository_root.resolve(strict=True)
        canonical_source = expected_source.resolve(strict=True)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        reusable_repository_venv = (canonical_root / ".venv").resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError("trusted-time CLI runtime attestation failed") from None
    if (
        repository_root != canonical_root
        or expected_source != canonical_source
        or actual_source != expected_source
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.pycache_prefix != "/dev/null"
        or runtime_prefix in (base_prefix, reusable_repository_venv)
        or runtime_prefix.is_relative_to(reusable_repository_venv)
    ):
        raise RuntimeError("trusted-time CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time CLI runtime attestation failed") from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("trusted-time CLI runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


def _require_repository_first_party_sources(repository_root: Path) -> None:
    """Require every loaded first-party module to be its exact source file."""

    for module_name, module in tuple(sys.modules.items()):
        if module_name.split(".", 1)[0] not in {"apps", "packages", "scripts"}:
            continue
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise RuntimeError("trusted-time first-party source attestation failed")
        module_path = repository_root.joinpath(*module_name.split("."))
        expected_sources = {
            module_path.with_suffix(".py"),
            module_path / "__init__.py",
        }
        try:
            lexical_origin = Path(os.path.abspath(origin))
            canonical_origin = lexical_origin.resolve(strict=True)
            source_metadata = lexical_origin.lstat()
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time first-party source attestation failed") from None
        if (
            lexical_origin != canonical_origin
            or lexical_origin not in expected_sources
            or lexical_origin.suffix != ".py"
            or "__pycache__" in lexical_origin.parts
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
        ):
            raise RuntimeError("trusted-time first-party source attestation failed")


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path("scripts/enroll_trusted_time_head_anchor.py")
    )
    if __name__ == "__main__"
    else None
)

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
    decode_trusted_time_authority,
)
from apps.trusted_time_supervisor.first_enrollment import (
    first_enrollment_identity_sha256,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    TrustedTimeHeadAnchorAuthority,
    decode_trusted_time_head_anchor_authority,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION,
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION,
    FIRST_ENROLLMENT_IDENTITY_FIELDS,
    FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION,
    FIRST_ENROLLMENT_RESULT_DIGEST_FIELDS,
    MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES,
    TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
    TrustedTimeEnrollmentEvidenceError,
    TrustedTimeFirstEnrollmentOperationMode,
    canonical_first_enrollment_json_bytes,
)
from scripts.start_trusted_time_supervisor import (
    DATABASE_SECRET_DIRECTORY_PATTERN,
    DATABASE_SECRET_FILE_NAME,
    DATABASE_SECRET_ROOT,
    DATABASE_SECRET_RUNTIME_PATH,
    DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
    FIRST_ENROLLMENT_COMMAND,
    FIRST_ENROLLMENT_SERVICE,
    HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
    HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT,
    HEAD_ANCHOR_AUTHORITY_FILE_NAME,
    HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT,
    HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN,
    HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
    HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT,
    MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES,
    UNENROLLED_ADMISSION_CONTRACT_VERSION,
    LocalDockerDaemonIdentity,
    MaterializedDatabaseSecret,
    MaterializedHeadAnchorInputs,
    TrustedTimeApprovedLaunch,
    TrustedTimeRuntimeConfiguration,
    TrustedTimeVolumeIdentities,
    _acquire_trusted_time_launch_lock,
    _approved_image_admission_path,
    _capture_trusted_time_volume_identities,
    _cleanup_materialized_runtime_inputs,
    _compose_prefix,
    _inspect_container,
    _inspect_image_configuration,
    _load_approved_image_admission,
    _mapping,
    _minimal_docker_environment,
    _release_trusted_time_launch_lock,
    _require_approved_git_revision,
    _require_approved_launch_state,
    _require_same_local_daemon,
    _run_docker,
    _runtime_input_host_path,
    _validate_mounted_staged_inputs,
    _validate_runtime_compose_payload,
    _validate_unenrolled_admission_payload,
    _validate_unenrolled_admission_teardown,
    _wait_for_database_secret_consumption,
    load_trusted_time_runtime_configuration,
    materialize_database_secret,
    materialize_trusted_time_head_anchor_inputs,
    qualify_local_docker_daemon,
    validate_created_container,
    validate_materialized_database_secret,
    validate_materialized_trusted_time_head_anchor_inputs,
)
from scripts.verify_trusted_time_compose import (
    PLACEHOLDER_DATABASE_SECRET_FILE,
    PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
    PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
    PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE,
    TrustedTimeComposeVerificationError,
    render_compose_model,
    validate_compose_model,
)
from scripts.verify_trusted_time_images import (
    DATABASE_SECRET_FILE_ENVIRONMENT,
    DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    IGNORED_ARTIFACT_ROOT,
    IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
    SOURCE_IMAGE_ENVIRONMENT,
    SUPERVISOR_IMAGE_ENVIRONMENT,
    TrustedTimeImageVerificationError,
    _head_reviewed_input_payload,
    _load_current_image_admission_snapshot,
    _open_owner_only_artifact_directory,
    _OwnedFileDescriptor,
    _require_current_admission_snapshot,
    _require_verified_images,
    _verify_images_with_manifest,
)

if TYPE_CHECKING:
    from scripts.verify_trusted_time_images import _CurrentTrustedTimeImageAdmissionSnapshot

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)

FIRST_ENROLLMENT_PROFILE = "trusted-time-first-enrollment"
FIRST_ENROLLMENT_RELEASE_COMMAND = (
    "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
    "first-enrollment-release",
)
FIRST_ENROLLMENT_RECOVERY_RELEASE_COMMAND = (
    "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
    "first-enrollment-recovery-release",
)
FIRST_ENROLLMENT_MINIMUM_IMAGE_ADMISSION_RESERVE_SECONDS = 300
FIRST_ENROLLMENT_TERMINAL_TIMEOUT_SECONDS = 180.0
FIRST_ENROLLMENT_TERMINAL_POLL_SECONDS = 0.1
MAXIMUM_FIRST_ENROLLMENT_TERMINAL_BYTES = 4_096
_SHA256_CHARACTERS = frozenset("0123456789abcdef")
_AUTHORITY_FIELDS = FIRST_ENROLLMENT_AUTHORITY_FIELDS
_IDENTITY_FIELDS = FIRST_ENROLLMENT_IDENTITY_FIELDS
_RESULT_DIGEST_FIELDS = FIRST_ENROLLMENT_RESULT_DIGEST_FIELDS
_TERMINAL_FIELDS = (
    _AUTHORITY_FIELDS
    | _IDENTITY_FIELDS
    | _RESULT_DIGEST_FIELDS
    | frozenset(
        {
            "anchor_sequence",
            "checkpoint_reason",
            "completion_disposition",
            "contract_version",
            "database_secret_disclosed",
            "full_audit_completed",
            "idempotent_duplicate_count",
            "operation_mode",
            "pending_intent_recovered",
            "reason",
            "remote_namespace_sha256",
            "service",
            "status",
            "uploaded_anchor_count",
        }
    )
)
_FATAL_TERMINAL_REASONS = frozenset(
    {
        "configuration_rejected",
        "first_enrollment_already_completed",
        "first_enrollment_completed_postconditions_unconfirmed",
        "first_enrollment_failed",
        "first_enrollment_precondition_rejected",
        "first_enrollment_recovery_required",
        "provider_unavailable_before_commit",
    }
)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _required_string(value: Mapping[str, object], field_name: str) -> str:
    observed = value.get(field_name)
    if type(observed) is not str:
        raise ValueError
    return observed


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return canonical_first_enrollment_json_bytes(value)
    except TrustedTimeEnrollmentEvidenceError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment evidence is invalid"
        ) from None


@dataclass(frozen=True, slots=True)
class TrustedTimeFirstEnrollmentApproval:
    """Every nonsecret value approved for exactly one enrollment operation."""

    operation_id: str
    operation_mode: TrustedTimeFirstEnrollmentOperationMode
    approved_launch: TrustedTimeApprovedLaunch
    unenrolled_admission_sha256: str
    anchor_authority_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    source_authority_sha256: str
    signing_public_key_sha256: str
    host_identity_sha256: str
    principal_identity_sha256: str
    bucket_identity_sha256: str
    prior_new_operation_id: str | None = None
    prior_new_claim_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            not _is_uuid4(self.operation_id)
            or type(self.operation_mode) is not TrustedTimeFirstEnrollmentOperationMode
            or type(self.approved_launch) is not TrustedTimeApprovedLaunch
            or any(
                not _is_sha256(value)
                for value in (
                    self.unenrolled_admission_sha256,
                    self.anchor_authority_sha256,
                    self.deployment_identity_sha256,
                    self.runtime_database_identity_sha256,
                    self.anchor_project_identity_sha256,
                    self.source_authority_sha256,
                    self.signing_public_key_sha256,
                    self.host_identity_sha256,
                    self.principal_identity_sha256,
                    self.bucket_identity_sha256,
                )
            )
            or (
                self.operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW
                and (
                    self.prior_new_operation_id is not None
                    or self.prior_new_claim_sha256 is not None
                )
            )
            or (
                self.operation_mode is TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
                and (
                    not _is_uuid4(self.prior_new_operation_id)
                    or not _is_sha256(self.prior_new_claim_sha256)
                    or self.prior_new_operation_id == self.operation_id
                )
            )
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment approval is invalid"
            )
        self.approved_launch.__post_init__()

    def payload(self) -> dict[str, object]:
        return {
            "anchor_authority_sha256": self.anchor_authority_sha256,
            "anchor_project_identity_sha256": self.anchor_project_identity_sha256,
            "approved_git_revision": self.approved_launch.git_revision,
            "approved_image_admission_sha256": (self.approved_launch.image_admission_sha256),
            "approved_source_image_id": self.approved_launch.source_image_id,
            "approved_supervisor_image_id": self.approved_launch.supervisor_image_id,
            "bucket_identity_sha256": self.bucket_identity_sha256,
            "contract_version": FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION,
            "deployment_identity_sha256": self.deployment_identity_sha256,
            "host_identity_sha256": self.host_identity_sha256,
            "operation_id": self.operation_id,
            "operation_mode": self.operation_mode.value,
            "prior_new_claim_sha256": self.prior_new_claim_sha256,
            "prior_new_operation_id": self.prior_new_operation_id,
            "principal_identity_sha256": self.principal_identity_sha256,
            "runtime_database_identity_sha256": self.runtime_database_identity_sha256,
            "signing_public_key_sha256": self.signing_public_key_sha256,
            "source_authority_sha256": self.source_authority_sha256,
            "unenrolled_admission_sha256": self.unenrolled_admission_sha256,
        }

    @property
    def approval_sha256(self) -> str:
        return hashlib.sha256(_canonical_json_bytes(self.payload())).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedTimeFirstEnrollmentTerminalEvidence:
    """Strict, secretless terminal projection from the one-shot container."""

    exit_code: int
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.exit_code) is not int or self.exit_code not in {0, 2}:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment terminal evidence is invalid"
            )
        _validate_terminal_payload(self.payload, exit_code=self.exit_code)

    @property
    def confirmed(self) -> bool:
        return self.exit_code == 0 and self.payload.get("status") == "confirmed"


@dataclass(frozen=True, slots=True)
class TrustedTimeFirstEnrollmentHostOutcome:
    """A retained host-side result; it never grants trading authority."""

    encoded: bytes
    artifact_path: Path
    confirmed: bool

    def __post_init__(self) -> None:
        if (
            type(self.encoded) is not bytes
            or not self.encoded
            or not self.artifact_path.is_absolute()
            or type(self.confirmed) is not bool
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment host outcome is invalid"
            )


class TrustedTimeFirstEnrollmentPossibleMutation(RuntimeError):
    """The one-shot release may have crossed the durable mutation boundary."""


class TrustedTimeFirstEnrollmentClaimConsumed(RuntimeError):
    """The exact approval already has a retained claim."""


class TrustedTimeFirstEnrollmentOutcomeRetentionUnconfirmed(RuntimeError):
    """A post-release outcome could not be durably retained."""


class TrustedTimeFirstEnrollmentLockReleaseUnconfirmed(RuntimeError):
    """The global launcher lock could not be confirmed released."""


def _expected_identity_payload(
    approval: TrustedTimeFirstEnrollmentApproval,
) -> dict[str, str]:
    return {field_name: getattr(approval, field_name) for field_name in _IDENTITY_FIELDS}


def _claim_payload(
    approval: TrustedTimeFirstEnrollmentApproval,
) -> dict[str, object]:
    approval.__post_init__()
    payload = approval.payload()
    payload.update({field_name: False for field_name in _AUTHORITY_FIELDS})
    payload.update(
        {
            "approval_sha256": approval.approval_sha256,
            "authority_granted": False,
            "claim_contract_version": FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION,
            "new_exposure_authorized": False,
            "service": "trusted-time-first-enrollment-host-launcher",
            "status": "claimed",
        }
    )
    return payload


def _validate_terminal_payload(payload: object, *, exit_code: int) -> None:
    if type(payload) is not dict or set(payload) != _TERMINAL_FIELDS:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment terminal evidence is invalid"
        )
    if (
        any(payload.get(field_name) is not False for field_name in _AUTHORITY_FIELDS)
        or payload.get("contract_version") != TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION
        or payload.get("database_secret_disclosed") is not False
        or payload.get("operation_mode")
        not in {
            TrustedTimeFirstEnrollmentOperationMode.NEW.value,
            TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING.value,
        }
        or payload.get("service") != FIRST_ENROLLMENT_SERVICE
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment terminal evidence is invalid"
        )
    if any(not _is_sha256(payload.get(field_name)) for field_name in _IDENTITY_FIELDS):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment terminal identity is invalid"
        )
    if exit_code == 0:
        disposition = payload.get("completion_disposition")
        counts = (
            payload.get("uploaded_anchor_count"),
            payload.get("idempotent_duplicate_count"),
        )
        if (
            payload.get("status") != "confirmed"
            or payload.get("reason") != "first_enrollment_confirmed"
            or type(payload.get("anchor_sequence")) is not int
            or payload.get("anchor_sequence") != 1
            or payload.get("checkpoint_reason") != "enrollment"
            or payload.get("full_audit_completed") is not True
            or disposition
            not in {
                "new_intent_completed",
                "pending_intent_recovered",
                "confirmed_receipt_reobserved",
            }
            or payload.get("pending_intent_recovered")
            is not (disposition == "pending_intent_recovered")
            or any(not _is_sha256(payload.get(field_name)) for field_name in _RESULT_DIGEST_FIELDS)
            or not _is_sha256(payload.get("remote_namespace_sha256"))
            or payload.get("candidate_remote_readback_sha256")
            != payload.get("current_anchor_sha256")
            or (disposition == "confirmed_receipt_reobserved" and counts != (None, None))
            or (
                disposition != "confirmed_receipt_reobserved"
                and (
                    any(type(value) is not int or value not in {0, 1} for value in counts)
                    or sum(value for value in counts if type(value) is int) != 1
                )
            )
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment confirmed evidence is invalid"
            )
        return
    if (
        exit_code != 2
        or payload.get("status") != "fatal"
        or payload.get("reason") not in _FATAL_TERMINAL_REASONS
        or payload.get("remote_namespace_sha256") is not None
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment fatal evidence is invalid"
        )
    empty_projection = (
        payload.get("anchor_sequence") is None
        and payload.get("checkpoint_reason") is None
        and payload.get("completion_disposition") is None
        and all(payload.get(field_name) is None for field_name in _RESULT_DIGEST_FIELDS)
        and payload.get("full_audit_completed") is False
        and payload.get("idempotent_duplicate_count") is None
        and payload.get("pending_intent_recovered") is False
        and payload.get("uploaded_anchor_count") is None
    )
    uploaded_count = payload.get("uploaded_anchor_count")
    duplicate_count = payload.get("idempotent_duplicate_count")
    completed_projection = (
        payload.get("reason") == "first_enrollment_completed_postconditions_unconfirmed"
        and type(payload.get("anchor_sequence")) is int
        and payload.get("anchor_sequence") == 1
        and payload.get("checkpoint_reason") == "enrollment"
        and payload.get("completion_disposition")
        in {
            "new_intent_completed",
            "pending_intent_recovered",
            "confirmed_receipt_reobserved",
        }
        and all(_is_sha256(payload.get(field_name)) for field_name in _RESULT_DIGEST_FIELDS)
        and payload.get("candidate_remote_readback_sha256") == payload.get("current_anchor_sha256")
        and payload.get("full_audit_completed") is True
        and payload.get("pending_intent_recovered")
        is (payload.get("completion_disposition") == "pending_intent_recovered")
        and (
            (
                payload.get("completion_disposition") == "confirmed_receipt_reobserved"
                and uploaded_count is None
                and duplicate_count is None
            )
            or (
                payload.get("completion_disposition")
                in {"new_intent_completed", "pending_intent_recovered"}
                and type(uploaded_count) is int
                and uploaded_count in {0, 1}
                and type(duplicate_count) is int
                and duplicate_count in {0, 1}
                and uploaded_count + duplicate_count == 1
            )
        )
    )
    if not empty_projection and not completed_projection:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment fatal evidence is invalid"
        )


def _trusted_time_artifact_directory(
    artifact_dir: Path,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> Path:
    if not isinstance(artifact_dir, Path) or not isinstance(ignored_root, Path):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment artifact path is invalid"
        )
    absolute = Path(os.path.abspath(artifact_dir))
    root = Path(os.path.abspath(ignored_root))
    trusted_time_root = root / "trusted-time"
    if (
        not artifact_dir.is_absolute()
        or absolute != artifact_dir
        or not ignored_root.is_absolute()
        or root != ignored_root
        or absolute != trusted_time_root
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment artifact path is invalid"
        )
    return absolute


def _require_new_operation_has_no_prior_claim(
    approval: TrustedTimeFirstEnrollmentApproval,
    *,
    artifact_dir: Path,
) -> None:
    """A NEW operation may clean/restart only while no claim has ever been retained."""

    approval.__post_init__()
    if approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING:
        return
    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            artifact_dir,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        entries = os.listdir(directory_descriptor)
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment claim state is unavailable"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_descriptor = None
    if (
        len(entries) > 4_096
        or any(type(entry) is not str or len(entry) > 255 for entry in entries)
        or any(
            entry.startswith("trusted-time-first-enrollment-claim-") and entry.endswith(".json")
            for entry in entries
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time new enrollment is blocked by a retained claim"
        )


def _read_owner_only_artifact(
    artifact_dir: Path,
    file_name: str,
    *,
    maximum_bytes: int,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bytes:
    absolute_directory = _trusted_time_artifact_directory(
        artifact_dir,
        ignored_root=ignored_root,
    )
    if (
        type(file_name) is not str
        or not file_name
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
        or type(maximum_bytes) is not int
        or maximum_bytes <= 0
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment artifact path is invalid"
        )
    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        file_descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            raise OSError
        retained = bytearray()
        while len(retained) <= maximum_bytes:
            chunk = os.read(
                file_descriptor,
                min(65_536, maximum_bytes + 1 - len(retained)),
            )
            if not chunk:
                break
            retained.extend(chunk)
        after = os.fstat(file_descriptor)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            stable_before != stable_after
            or len(retained) != before.st_size
            or len(retained) > maximum_bytes
        ):
            raise OSError
        return bytes(retained)
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment artifact is unavailable"
        ) from None
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def load_approved_unenrolled_admission(
    approval: TrustedTimeFirstEnrollmentApproval,
    *,
    artifact_dir: Path = DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
) -> bytes:
    """Load the content-addressed fail-closed receipt bound to this exact tuple."""

    approval.__post_init__()
    file_name = (
        f"trusted-time-unenrolled-launch-admission-{approval.unenrolled_admission_sha256}.json"
    )
    encoded = _read_owner_only_artifact(
        artifact_dir,
        file_name,
        maximum_bytes=MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES,
    )
    if hashlib.sha256(encoded).hexdigest() != approval.unenrolled_admission_sha256:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment unenrolled admission changed"
        )
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment unenrolled admission is invalid"
        ) from None
    _validate_unenrolled_admission_payload(payload)
    try:
        canonical = (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii", errors="strict")
    except (TypeError, UnicodeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment unenrolled admission is invalid"
        ) from None
    launch = approval.approved_launch
    if (
        canonical != encoded
        or payload.get("contract_version") != UNENROLLED_ADMISSION_CONTRACT_VERSION
        or payload.get("approved_git_revision") != launch.git_revision
        or payload.get("source_image_id") != launch.source_image_id
        or payload.get("supervisor_image_id") != launch.supervisor_image_id
        or (
            approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW
            and payload.get("image_admission_sha256") != launch.image_admission_sha256
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment unenrolled admission differs from approval"
        )
    return encoded


def load_approved_prior_new_claim(
    approval: TrustedTimeFirstEnrollmentApproval,
    *,
    artifact_dir: Path = DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
) -> bytes | None:
    """Authenticate the exact prior NEW claim required by recovery."""

    approval.__post_init__()
    if approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW:
        return None
    prior_operation_id = approval.prior_new_operation_id
    prior_claim_sha256 = approval.prior_new_claim_sha256
    if not _is_uuid4(prior_operation_id) or not _is_sha256(prior_claim_sha256):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment prior claim is invalid"
        )
    encoded = _read_owner_only_artifact(
        artifact_dir,
        f"trusted-time-first-enrollment-claim-{prior_operation_id}.json",
        maximum_bytes=MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES,
    )
    if hashlib.sha256(encoded).hexdigest() != prior_claim_sha256:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment prior claim changed"
        )
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if type(payload) is not dict:
            raise ValueError
        prior_approval = TrustedTimeFirstEnrollmentApproval(
            operation_id=_required_string(payload, "operation_id"),
            operation_mode=TrustedTimeFirstEnrollmentOperationMode(
                _required_string(payload, "operation_mode")
            ),
            approved_launch=TrustedTimeApprovedLaunch(
                git_revision=_required_string(payload, "approved_git_revision"),
                image_admission_sha256=_required_string(payload, "approved_image_admission_sha256"),
                source_image_id=_required_string(payload, "approved_source_image_id"),
                supervisor_image_id=_required_string(payload, "approved_supervisor_image_id"),
            ),
            unenrolled_admission_sha256=_required_string(payload, "unenrolled_admission_sha256"),
            anchor_authority_sha256=_required_string(payload, "anchor_authority_sha256"),
            deployment_identity_sha256=_required_string(payload, "deployment_identity_sha256"),
            runtime_database_identity_sha256=_required_string(
                payload, "runtime_database_identity_sha256"
            ),
            anchor_project_identity_sha256=_required_string(
                payload, "anchor_project_identity_sha256"
            ),
            source_authority_sha256=_required_string(payload, "source_authority_sha256"),
            signing_public_key_sha256=_required_string(payload, "signing_public_key_sha256"),
            host_identity_sha256=_required_string(payload, "host_identity_sha256"),
            principal_identity_sha256=_required_string(payload, "principal_identity_sha256"),
            bucket_identity_sha256=_required_string(payload, "bucket_identity_sha256"),
            prior_new_operation_id=None,
            prior_new_claim_sha256=None,
        )
    except (
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
        TrustedTimeSupervisorConfigurationError,
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment prior claim is invalid"
        ) from None
    current_launch = approval.approved_launch
    prior_launch = prior_approval.approved_launch
    if (
        _canonical_json_bytes(payload) != encoded
        or payload != _claim_payload(prior_approval)
        or prior_approval.operation_mode is not TrustedTimeFirstEnrollmentOperationMode.NEW
        or prior_approval.operation_id != prior_operation_id
        or prior_approval.prior_new_operation_id is not None
        or prior_approval.prior_new_claim_sha256 is not None
        or prior_launch.git_revision != current_launch.git_revision
        or prior_launch.source_image_id != current_launch.source_image_id
        or prior_launch.supervisor_image_id != current_launch.supervisor_image_id
        or prior_approval.unenrolled_admission_sha256 != approval.unenrolled_admission_sha256
        or _expected_identity_payload(prior_approval) != _expected_identity_payload(approval)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment prior claim differs from approval"
        )
    return encoded


def _require_prior_claim_receipt_binding(
    *,
    approval: TrustedTimeFirstEnrollmentApproval,
    prior_claim_encoded: bytes | None,
    receipt_encoded: bytes,
) -> None:
    """Bind a recovery claim's original image admission to its exact receipt."""

    if approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW:
        if prior_claim_encoded is not None:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment prior claim is invalid"
            )
        return
    if type(prior_claim_encoded) is not bytes:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment prior claim differs from receipt"
        )
    try:
        prior_payload: Any = json.loads(
            prior_claim_encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        receipt_payload: Any = json.loads(
            receipt_encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if (
            type(prior_payload) is not dict
            or type(receipt_payload) is not dict
            or prior_payload.get("approved_image_admission_sha256")
            != receipt_payload.get("image_admission_sha256")
        ):
            raise ValueError
    except (
        AttributeError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment prior claim differs from receipt"
        ) from None


def _load_bound_authority(
    runtime: TrustedTimeRuntimeConfiguration,
    approval: TrustedTimeFirstEnrollmentApproval,
) -> TrustedTimeHeadAnchorAuthority:
    if type(runtime) is not TrustedTimeRuntimeConfiguration:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment runtime inputs are invalid"
        )
    revision = approval.approved_launch.git_revision
    try:
        source_authority = decode_trusted_time_authority(
            _head_reviewed_input_payload(
                revision,
                "infra/trusted-time/source-authority.json",
            ),
            chrony_config_payload=_head_reviewed_input_payload(
                revision,
                "infra/trusted-time/chrony.conf",
            ),
            database_ca_payload=_head_reviewed_input_payload(
                revision,
                "packages/persistence/certs/supabase-prod-ca-2021.crt",
            ),
        )
    except TrustedTimeImageVerificationError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment reviewed authority is unavailable"
        ) from None
    anchor = decode_trusted_time_head_anchor_authority(
        runtime.head_anchor_payloads.authority,
        database_url=runtime.database_url,
        expected_host_id=source_authority.host_id,
        expected_source_authority_sha256=source_authority.source_authority_sha256,
    )
    observed = {
        "anchor_authority_sha256": anchor.anchor_authority_sha256,
        "anchor_project_identity_sha256": anchor.anchor_project_identity_sha256,
        "bucket_identity_sha256": first_enrollment_identity_sha256(
            kind="bucket",
            value=anchor.bucket_name,
        ),
        "deployment_identity_sha256": anchor.deployment_identity_sha256,
        "host_identity_sha256": first_enrollment_identity_sha256(
            kind="host",
            value=anchor.host_id,
        ),
        "principal_identity_sha256": first_enrollment_identity_sha256(
            kind="principal",
            value=anchor.principal_id,
        ),
        "runtime_database_identity_sha256": anchor.runtime_database_identity_sha256,
        "signing_public_key_sha256": anchor.signing_public_key_sha256,
        "source_authority_sha256": anchor.source_authority_sha256,
    }
    if observed != _expected_identity_payload(approval):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment authority differs from approval"
        )
    return anchor


def _require_same_runtime_inputs(
    expected: TrustedTimeRuntimeConfiguration,
    observed: TrustedTimeRuntimeConfiguration,
    approval: TrustedTimeFirstEnrollmentApproval,
) -> None:
    _load_bound_authority(observed, approval)
    if (
        type(expected) is not TrustedTimeRuntimeConfiguration
        or type(observed) is not TrustedTimeRuntimeConfiguration
        or expected.database_url != observed.database_url
        or expected.head_anchor_payloads != observed.head_anchor_payloads
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment runtime inputs changed before release"
        )


def _require_image_admission_reserve(
    admission: _CurrentTrustedTimeImageAdmissionSnapshot,
) -> None:
    try:
        admission = _require_current_admission_snapshot(admission)
    except TrustedTimeImageVerificationError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment image admission is invalid"
        ) from None
    observed = time.monotonic_ns()
    maximum_age_ns = IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    reserve_ns = FIRST_ENROLLMENT_MINIMUM_IMAGE_ADMISSION_RESERVE_SECONDS * 1_000_000_000
    if (
        type(observed) is not int
        or observed < admission[12]
        or maximum_age_ns - (observed - admission[12]) < reserve_ns
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment image admission lacks release reserve"
        )


def _image_admission_is_fresh(
    admission: _CurrentTrustedTimeImageAdmissionSnapshot,
) -> bool:
    try:
        admission = _require_current_admission_snapshot(admission)
        observed = time.monotonic_ns()
    except (Exception, TrustedTimeImageVerificationError):
        return False
    return (
        type(observed) is int
        and admission[12] <= observed
        and observed - admission[12] <= IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    )


def _final_approval_state_is_valid(
    *,
    approval: TrustedTimeFirstEnrollmentApproval,
    admission: _CurrentTrustedTimeImageAdmissionSnapshot,
    receipt_encoded: bytes,
    prior_new_claim_encoded: bytes | None,
    image_admission_artifact: Path,
    artifact_dir: Path,
    daemon_identity: LocalDockerDaemonIdentity,
    docker_environment: Mapping[str, str],
) -> bool:
    """Recheck immutable bindings after release without applying the TTL again."""

    try:
        _require_approved_git_revision(approval.approved_launch)
        admission_path = _approved_image_admission_path(
            image_admission_artifact,
            approval.approved_launch,
        )
        admission = _require_current_admission_snapshot(admission)
        observed_admission = _require_current_admission_snapshot(
            _load_current_image_admission_snapshot(
                admission_path,
                monotonic_ns=admission[12],
            )
        )
        if observed_admission != admission:
            return False
        observed_images = _require_verified_images(
            _verify_images_with_manifest(
                approval.approved_launch.source_image_id,
                approval.approved_launch.supervisor_image_id,
                docker_environment=docker_environment,
            )
        )
        if (
            observed_images[1] != approval.approved_launch.source_image_id
            or observed_images[2] != approval.approved_launch.supervisor_image_id
        ):
            return False
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        observed_receipt = load_approved_unenrolled_admission(
            approval,
            artifact_dir=artifact_dir,
        )
        observed_prior_claim = load_approved_prior_new_claim(
            approval,
            artifact_dir=artifact_dir,
        )
        _require_prior_claim_receipt_binding(
            approval=approval,
            prior_claim_encoded=observed_prior_claim,
            receipt_encoded=observed_receipt,
        )
        return (
            observed_receipt == receipt_encoded and observed_prior_claim == prior_new_claim_encoded
        )
    except Exception:
        return False


def _write_exclusive_retained_artifact(
    artifact_dir: Path,
    *,
    file_name: str,
    encoded: bytes,
) -> Path:
    """Durably create one owner-only artifact and never roll it back."""

    absolute_directory = _trusted_time_artifact_directory(artifact_dir)
    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES
        or type(file_name) is not str
        or not file_name
        or file_name in {".", ".."}
        or "/" in file_name
        or "\x00" in file_name
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment retained artifact is invalid"
        )
    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            create=True,
        )
        directory_descriptor = directory_owner.fileno()
        file_descriptor = os.open(
            file_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(encoded)
        ):
            raise OSError
        os.fsync(directory_descriptor)
    except FileExistsError:
        raise TrustedTimeFirstEnrollmentClaimConsumed(
            "trusted-time first enrollment approval was already consumed"
        ) from None
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment artifact retention is unconfirmed"
        ) from None
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
    retained = _read_owner_only_artifact(
        absolute_directory,
        file_name,
        maximum_bytes=MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES,
    )
    if retained != encoded:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment artifact retention is unconfirmed"
        )
    return absolute_directory / file_name


def _retain_single_use_claim(
    approval: TrustedTimeFirstEnrollmentApproval,
    *,
    artifact_dir: Path,
) -> tuple[str, Path, bytes]:
    encoded = _canonical_json_bytes(_claim_payload(approval))
    claim_sha256 = hashlib.sha256(encoded).hexdigest()
    file_name = f"trusted-time-first-enrollment-claim-{approval.operation_id}.json"
    path = _write_exclusive_retained_artifact(
        artifact_dir,
        file_name=file_name,
        encoded=encoded,
    )
    return claim_sha256, path, encoded


def _revalidate_retained_claim(
    *,
    artifact_dir: Path,
    operation_id: str,
    claim_sha256: str,
    expected: bytes,
) -> bool:
    try:
        observed = _read_owner_only_artifact(
            artifact_dir,
            f"trusted-time-first-enrollment-claim-{operation_id}.json",
            maximum_bytes=MAXIMUM_FIRST_ENROLLMENT_ARTIFACT_BYTES,
        )
    except TrustedTimeSupervisorConfigurationError:
        return False
    return observed == expected and hashlib.sha256(observed).hexdigest() == claim_sha256


def _enrollment_compose_prefix() -> tuple[str, ...]:
    return (*_compose_prefix(), "--profile", FIRST_ENROLLMENT_PROFILE)


def _enrollment_up_argv() -> tuple[str, ...]:
    return (
        *_enrollment_compose_prefix(),
        "up",
        "--detach",
        "--no-build",
        "--pull",
        "never",
        "--force-recreate",
        "--no-deps",
        FIRST_ENROLLMENT_SERVICE,
    )


def _stop_enrollment_topology(
    *,
    environment: Mapping[str, str],
    compose_payload: bytes,
) -> bool:
    try:
        completed = _run_docker(
            (
                *_enrollment_compose_prefix(),
                "down",
                "--remove-orphans",
                "--timeout",
                "10",
            ),
            environment=environment,
            timeout_seconds=60,
            compose_payload=compose_payload,
        )
    except TrustedTimeSupervisorConfigurationError:
        return False
    return completed[1] == 0


def _compose_project_container_ids(
    *,
    environment: Mapping[str, str],
    compose_payload: bytes,
) -> tuple[str, ...]:
    completed = _run_docker(
        (*_enrollment_compose_prefix(), "ps", "--all", "--quiet"),
        environment=environment,
        timeout_seconds=10,
        compose_payload=compose_payload,
    )
    lines = completed[2].splitlines()
    if (
        completed[1] != 0
        or completed[3]
        or any(
            len(line) != 64 or any(character not in _SHA256_CHARACTERS for character in line)
            for line in lines
        )
        or len(set(lines)) != len(lines)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment project identity is unavailable"
        )
    return tuple(lines)


_STALE_ENROLLMENT_INPUTS = {
    DATABASE_SECRET_RUNTIME_PATH: (DATABASE_SECRET_FILE_NAME, None),
    HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH: (HEAD_ANCHOR_AUTHORITY_FILE_NAME, "authority"),
    HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH: (HEAD_ANCHOR_AUTH_SECRET_FILE_NAME, "auth"),
    HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH: (
        HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
        "signing-key",
    ),
}


def _stale_enrollment_input_paths(
    inspection: object,
    *,
    container_id: str,
    supervisor_image_id: str,
    environment: Mapping[str, str],
) -> tuple[Path, Path, Path, Path]:
    """Validate one exact stale one-shot and return only its staged input paths."""

    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment topology is invalid"
        )
    container = _mapping(
        inspection[0],
        "trusted-time stale first enrollment container",
    )
    if container.get("Id") != container_id:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment container identity is invalid"
        )
    host = _mapping(
        container.get("HostConfig"),
        "trusted-time stale first enrollment HostConfig",
    )
    raw_mounts = host.get("Mounts")
    raw_binds = host.get("Binds")
    if raw_mounts in (None, []):
        mounts: list[object] = []
    elif type(raw_mounts) is list:
        mounts = raw_mounts
    else:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment mounts are invalid"
        )
    if raw_binds in (None, []):
        binds: list[object] = []
    elif type(raw_binds) is list:
        binds = raw_binds
    else:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment mounts are invalid"
        )
    by_target: dict[str, Path] = {}
    for raw_mount in mounts:
        mount = _mapping(raw_mount, "trusted-time stale first enrollment mount")
        target = mount.get("Target")
        source = _runtime_input_host_path(mount.get("Source"))
        if (
            type(target) is not str
            or target in by_target
            or target not in _STALE_ENROLLMENT_INPUTS
            or mount.get("Type") != "bind"
            or mount.get("ReadOnly") is not True
            or source is None
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment mounts are invalid"
            )
        path = Path(source)
        file_name, kind = _STALE_ENROLLMENT_INPUTS[target]
        directory_match = HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN.fullmatch(path.parent.name)
        directory_valid = (
            DATABASE_SECRET_DIRECTORY_PATTERN.fullmatch(path.parent.name) is not None
            if kind is None
            else directory_match is not None and directory_match.group(1) == kind
        )
        if (
            not path.is_absolute()
            or path != Path(os.path.abspath(path))
            or path.name != file_name
            or path.parent.parent != DATABASE_SECRET_ROOT
            or not directory_valid
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment mounts are invalid"
            )
        by_target[target] = path
    for raw_bind in binds:
        if type(raw_bind) is not str:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment mounts are invalid"
            )
        fields = raw_bind.rsplit(":", 2)
        if len(fields) != 3:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment mounts are invalid"
            )
        raw_source, target, access = fields
        source = _runtime_input_host_path(raw_source)
        if (
            target in by_target
            or target not in _STALE_ENROLLMENT_INPUTS
            or access != "ro"
            or source is None
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment mounts are invalid"
            )
        path = Path(source)
        file_name, kind = _STALE_ENROLLMENT_INPUTS[target]
        directory_match = HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN.fullmatch(path.parent.name)
        directory_valid = (
            DATABASE_SECRET_DIRECTORY_PATTERN.fullmatch(path.parent.name) is not None
            if kind is None
            else directory_match is not None and directory_match.group(1) == kind
        )
        if (
            not path.is_absolute()
            or path != Path(os.path.abspath(path))
            or path.name != file_name
            or path.parent.parent != DATABASE_SECRET_ROOT
            or not directory_valid
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment mounts are invalid"
            )
        by_target[target] = path
    if set(by_target) != set(_STALE_ENROLLMENT_INPUTS):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment mounts are invalid"
        )
    paths = (
        by_target[DATABASE_SECRET_RUNTIME_PATH],
        by_target[HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH],
        by_target[HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH],
        by_target[HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH],
    )
    validate_created_container(
        inspection,
        expected_image_id=supervisor_image_id,
        expected_image_configuration=_inspect_image_configuration(
            supervisor_image_id,
            environment=environment,
        ),
        expected_service=FIRST_ENROLLMENT_SERVICE,
        require_healthy=False,
        allow_stopped=True,
        expected_database_secret_file=paths[0],
        expected_head_anchor_authority_file=paths[1],
        expected_head_anchor_auth_secret_file=paths[2],
        expected_head_anchor_signing_key_secret_file=paths[3],
    )
    return paths


def _cleanup_stale_enrollment_input(path: Path, *, file_name: str, kind: str | None) -> None:
    """Remove one exact staged input left by a killed host launcher without reading it."""

    directory_match = HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN.fullmatch(path.parent.name)
    directory_valid = (
        DATABASE_SECRET_DIRECTORY_PATTERN.fullmatch(path.parent.name) is not None
        if kind is None
        else directory_match is not None and directory_match.group(1) == kind
    )
    if (
        not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or path.name != file_name
        or path.parent.parent != DATABASE_SECRET_ROOT
        or not directory_valid
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment input cleanup is invalid"
        )
    if not os.path.lexists(path.parent) and not os.path.lexists(path):
        return
    root_owner: _OwnedFileDescriptor | None = None
    root_descriptor: int | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        root_owner = _open_owner_only_artifact_directory(
            DATABASE_SECRET_ROOT,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            create=False,
        )
        root_descriptor = root_owner.fileno()
        directory_descriptor = os.open(
            path.parent.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        directory_metadata = os.fstat(directory_descriptor)
        entries = os.listdir(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or entries not in ([], [file_name])
        ):
            raise OSError
        if entries:
            file_descriptor = os.open(
                file_name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            file_metadata = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(file_metadata.st_mode) != 0o400
                or file_metadata.st_nlink != 1
            ):
                raise OSError
            os.close(file_descriptor)
            file_descriptor = None
            os.unlink(file_name, dir_fd=directory_descriptor)
        os.close(directory_descriptor)
        directory_descriptor = None
        os.rmdir(path.parent.name, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment input cleanup is unconfirmed"
        ) from None
    finally:
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
        if root_owner is not None:
            with suppress(OSError):
                root_owner.close()
    if os.path.lexists(path) or os.path.lexists(path.parent):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment input cleanup is unconfirmed"
        )


def _cleanup_orphaned_enrollment_inputs_without_container() -> None:
    """Remove only exact staged-input orphans while no project container exists."""

    if not os.path.lexists(DATABASE_SECRET_ROOT):
        return
    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            DATABASE_SECRET_ROOT,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        entries = sorted(os.listdir(directory_descriptor))
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment input inventory is unavailable"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
        directory_owner = None
        directory_descriptor = None
    if len(entries) > 128 or any(type(entry) is not str or len(entry) > 96 for entry in entries):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment input inventory is invalid"
        )
    candidates: list[tuple[Path, str, str | None]] = []
    for entry in entries:
        if DATABASE_SECRET_DIRECTORY_PATTERN.fullmatch(entry) is not None:
            file_name = DATABASE_SECRET_FILE_NAME
            kind: str | None = None
        else:
            match = HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN.fullmatch(entry)
            if match is None:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time stale first enrollment input inventory is invalid"
                )
            kind = match.group(1)
            file_name = {
                "authority": HEAD_ANCHOR_AUTHORITY_FILE_NAME,
                "auth": HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
                "signing-key": HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
            }[kind]
        candidates.append((DATABASE_SECRET_ROOT / entry / file_name, file_name, kind))
    for path, file_name, kind in candidates:
        _cleanup_stale_enrollment_input(path, file_name=file_name, kind=kind)
    try:
        directory_owner = _open_owner_only_artifact_directory(
            DATABASE_SECRET_ROOT,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        if os.listdir(directory_descriptor):
            raise OSError
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment input cleanup is unconfirmed"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _remove_exact_stale_enrollment_topology(
    *,
    supervisor_image_id: str,
    environment: Mapping[str, str],
    docker_environment: Mapping[str, str],
    daemon_identity: LocalDockerDaemonIdentity,
    expected_volume_identities: TrustedTimeVolumeIdentities,
    compose_payload: bytes,
) -> None:
    """Remove only an exact stranded one-shot; never execute its release command."""

    container_ids = _compose_project_container_ids(
        environment=environment,
        compose_payload=compose_payload,
    )
    if not container_ids:
        if not _stop_enrollment_topology(
            environment=environment,
            compose_payload=compose_payload,
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time stale first enrollment topology removal failed"
            )
        _validate_unenrolled_admission_teardown(
            compose_environment=environment,
            docker_environment=docker_environment,
            daemon_identity=daemon_identity,
            expected_volume_identities=expected_volume_identities,
            compose_payload=compose_payload,
        )
        _cleanup_orphaned_enrollment_inputs_without_container()
        return
    if len(container_ids) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment requires an empty project topology"
        )
    container_id = container_ids[0]
    paths = _stale_enrollment_input_paths(
        _inspect_container(container_id, environment=docker_environment),
        container_id=container_id,
        supervisor_image_id=supervisor_image_id,
        environment=docker_environment,
    )
    if (
        _stale_enrollment_input_paths(
            _inspect_container(container_id, environment=docker_environment),
            container_id=container_id,
            supervisor_image_id=supervisor_image_id,
            environment=docker_environment,
        )
        != paths
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment topology drifted"
        )
    if not _stop_enrollment_topology(
        environment=environment,
        compose_payload=compose_payload,
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time stale first enrollment topology removal failed"
        )
    _validate_unenrolled_admission_teardown(
        compose_environment=environment,
        docker_environment=docker_environment,
        daemon_identity=daemon_identity,
        expected_volume_identities=expected_volume_identities,
        compose_payload=compose_payload,
    )
    for path, (file_name, kind) in zip(
        paths,
        _STALE_ENROLLMENT_INPUTS.values(),
        strict=True,
    ):
        _cleanup_stale_enrollment_input(path, file_name=file_name, kind=kind)
    _cleanup_orphaned_enrollment_inputs_without_container()


def _enrollment_container_id(
    *,
    environment: Mapping[str, str],
    compose_payload: bytes,
    include_stopped: bool = False,
) -> str:
    selection = ("--all",) if include_stopped else ()
    completed = _run_docker(
        (
            *_enrollment_compose_prefix(),
            "ps",
            *selection,
            "--quiet",
            FIRST_ENROLLMENT_SERVICE,
        ),
        environment=environment,
        timeout_seconds=10,
        compose_payload=compose_payload,
    )
    lines = completed[2].splitlines()
    if (
        completed[1] != 0
        or completed[3]
        or len(lines) != 1
        or len(lines[0]) != 64
        or any(character not in _SHA256_CHARACTERS for character in lines[0])
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment container identity is unavailable"
        )
    return lines[0]


def _validate_running_enrollment_container(
    *,
    container_id: str,
    supervisor_image_id: str,
    database_secret: MaterializedDatabaseSecret,
    head_anchor_inputs: MaterializedHeadAnchorInputs,
    environment: Mapping[str, str],
    compose_payload: bytes,
) -> None:
    if _compose_project_container_ids(
        environment=environment,
        compose_payload=compose_payload,
    ) != (container_id,):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment topology drifted"
        )
    validate_created_container(
        _inspect_container(container_id, environment=environment),
        expected_image_id=supervisor_image_id,
        expected_image_configuration=_inspect_image_configuration(
            supervisor_image_id,
            environment=environment,
        ),
        expected_service=FIRST_ENROLLMENT_SERVICE,
        require_healthy=False,
        expected_database_secret_file=database_secret.path,
        expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
    )
    _validate_mounted_staged_inputs(
        container_id,
        database_secret=database_secret,
        head_anchor_inputs=head_anchor_inputs,
        environment=environment,
    )


def _validate_retired_enrollment_inputs(
    *,
    container_id: str,
    supervisor_image_id: str,
    database_secret: MaterializedDatabaseSecret,
    head_anchor_inputs: MaterializedHeadAnchorInputs,
    environment: Mapping[str, str],
    compose_payload: bytes,
) -> None:
    if _compose_project_container_ids(
        environment=environment,
        compose_payload=compose_payload,
    ) != (container_id,):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment topology drifted"
        )
    validate_created_container(
        _inspect_container(container_id, environment=environment),
        expected_image_id=supervisor_image_id,
        expected_image_configuration=_inspect_image_configuration(
            supervisor_image_id,
            environment=environment,
        ),
        expected_service=FIRST_ENROLLMENT_SERVICE,
        require_healthy=False,
        expected_database_secret_file=database_secret.path,
        expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
    )
    _validate_mounted_staged_inputs(
        container_id,
        database_secret=database_secret,
        head_anchor_inputs=head_anchor_inputs,
        environment=environment,
        allow_retired_unreadable=True,
    )


def _release_enrollment_container(
    *,
    container_id: str,
    operation_mode: TrustedTimeFirstEnrollmentOperationMode,
    environment: Mapping[str, str],
) -> None:
    if operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW:
        release_command = FIRST_ENROLLMENT_RELEASE_COMMAND
    elif operation_mode is TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING:
        release_command = FIRST_ENROLLMENT_RECOVERY_RELEASE_COMMAND
    else:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment release mode is invalid"
        )
    completed = _run_docker(
        (
            "docker",
            "container",
            "exec",
            "--user",
            "10001:10001",
            container_id,
            *release_command,
        ),
        environment=environment,
        timeout_seconds=10,
    )
    if completed[1] != 0 or completed[2] or completed[3]:
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment release is unconfirmed"
        )


def _terminal_state(
    inspection: object,
    *,
    container_id: str,
    supervisor_image_id: str,
) -> tuple[str, bool, int, bool]:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment terminal state is invalid"
        )
    container = _mapping(inspection[0], "trusted-time first enrollment container")
    configuration = _mapping(
        container.get("Config"),
        "trusted-time first enrollment container Config",
    )
    labels = _mapping(
        configuration.get("Labels"),
        "trusted-time first enrollment container labels",
    )
    state = _mapping(
        container.get("State"),
        "trusted-time first enrollment container state",
    )
    status = state.get("Status")
    running = state.get("Running")
    exit_code = state.get("ExitCode")
    oom_killed = state.get("OOMKilled")
    if (
        container.get("Id") != container_id
        or container.get("Image") != supervisor_image_id
        or labels.get("com.docker.compose.project") != "autoquanttrader-trusted-time"
        or labels.get("com.docker.compose.service") != FIRST_ENROLLMENT_SERVICE
        or configuration.get("Cmd") != list(FIRST_ENROLLMENT_COMMAND)
        or container.get("RestartCount") != 0
        or type(status) is not str
        or type(running) is not bool
        or type(exit_code) is not int
        or isinstance(exit_code, bool)
        or type(oom_killed) is not bool
        or state.get("Dead") is not False
        or state.get("Error") not in {"", None}
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment terminal state is invalid"
        )
    if (status, running, exit_code, oom_killed) not in {
        ("running", True, 0, False),
        ("exited", False, 0, False),
        ("exited", False, 2, False),
    }:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment terminal state is unqualified"
        )
    return status, running, exit_code, oom_killed


def _observe_enrollment_terminal(
    *,
    container_id: str,
    approval: TrustedTimeFirstEnrollmentApproval,
    environment: Mapping[str, str],
) -> TrustedTimeFirstEnrollmentTerminalEvidence:
    started = time.monotonic()
    if not math.isfinite(started):
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal clock is invalid"
        )
    deadline = started + FIRST_ENROLLMENT_TERMINAL_TIMEOUT_SECONDS
    observed = started
    exit_code: int | None = None
    while observed < deadline:
        try:
            status, running, candidate_exit_code, _ = _terminal_state(
                _inspect_container(container_id, environment=environment),
                container_id=container_id,
                supervisor_image_id=approval.approved_launch.supervisor_image_id,
            )
        except TrustedTimeSupervisorConfigurationError:
            raise TrustedTimeFirstEnrollmentPossibleMutation(
                "trusted-time first enrollment terminal state is unconfirmed"
            ) from None
        if status == "exited" and running is False:
            exit_code = candidate_exit_code
            break
        time.sleep(min(FIRST_ENROLLMENT_TERMINAL_POLL_SECONDS, deadline - observed))
        current = time.monotonic()
        if not math.isfinite(current) or current < observed:
            raise TrustedTimeFirstEnrollmentPossibleMutation(
                "trusted-time first enrollment terminal clock is invalid"
            )
        observed = current
    if exit_code is None:
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal was not observed"
        )
    completed = _run_docker(
        ("docker", "container", "logs", "--tail", "2", container_id),
        environment=environment,
        timeout_seconds=10,
    )
    try:
        encoded = completed[2].encode("ascii", errors="strict")
    except UnicodeError:
        encoded = b""
    if (
        completed[1] != 0
        or completed[3]
        or not encoded
        or len(encoded) > MAXIMUM_FIRST_ENROLLMENT_TERMINAL_BYTES
        or not encoded.endswith(b"\n")
        or encoded.count(b"\n") != 1
    ):
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal output is unconfirmed"
        )
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal output is unconfirmed"
        ) from None
    if _canonical_json_bytes(payload) != encoded:
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal output is noncanonical"
        )
    try:
        evidence = TrustedTimeFirstEnrollmentTerminalEvidence(
            exit_code=exit_code,
            payload=payload,
        )
    except TrustedTimeSupervisorConfigurationError:
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal output is unqualified"
        ) from None
    expected_dispositions = (
        {"new_intent_completed"}
        if approval.operation_mode is TrustedTimeFirstEnrollmentOperationMode.NEW
        else {"pending_intent_recovered", "confirmed_receipt_reobserved"}
    )
    if (
        payload.get("operation_mode") != approval.operation_mode.value
        or any(
            payload.get(field_name) != expected_value
            for field_name, expected_value in _expected_identity_payload(approval).items()
        )
        or (
            evidence.confirmed
            and payload.get("completion_disposition") not in expected_dispositions
        )
    ):
        raise TrustedTimeFirstEnrollmentPossibleMutation(
            "trusted-time first enrollment terminal differs from approval"
        )
    return evidence


def _outcome_reason(
    *,
    terminal_evidence: TrustedTimeFirstEnrollmentTerminalEvidence | None,
    gates: Mapping[str, bool],
) -> tuple[str, str, bool]:
    all_gates = all(gates.values())
    if terminal_evidence is not None and terminal_evidence.confirmed and all_gates:
        return "confirmed", "first_enrollment_confirmed", True
    if terminal_evidence is not None and (
        terminal_evidence.confirmed
        or terminal_evidence.payload.get("reason")
        == "first_enrollment_completed_postconditions_unconfirmed"
    ):
        return (
            "fatal",
            "first_enrollment_completed_postconditions_unconfirmed",
            False,
        )
    if terminal_evidence is not None and all_gates:
        reason = terminal_evidence.payload.get("reason")
        if type(reason) is str and reason in _FATAL_TERMINAL_REASONS:
            return "fatal", reason, False
    return "fatal", "first_enrollment_recovery_required", False


def _retain_host_outcome(
    *,
    approval: TrustedTimeFirstEnrollmentApproval,
    claim_sha256: str,
    terminal_evidence: TrustedTimeFirstEnrollmentTerminalEvidence | None,
    gates: Mapping[str, bool],
    artifact_dir: Path,
) -> TrustedTimeFirstEnrollmentHostOutcome:
    expected_gates = {
        "final_approval_state_validated",
        "final_image_admission_fresh",
        "runtime_inputs_retired",
        "secure_launch_validated",
        "single_use_claim_retained",
        "state_volumes_preserved",
        "terminal_evidence_qualified",
        "topology_removed",
    }
    if (
        not _is_sha256(claim_sha256)
        or type(gates) is not dict
        or set(gates) != expected_gates
        or any(type(value) is not bool for value in gates.values())
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment outcome gates are invalid"
        )
    status, reason, confirmed = _outcome_reason(
        terminal_evidence=terminal_evidence,
        gates=gates,
    )
    try:
        payload: dict[str, object] = {field_name: False for field_name in _AUTHORITY_FIELDS}
        payload.update(
            {
                "approval": approval.payload(),
                "approval_sha256": approval.approval_sha256,
                "authority_granted": False,
                "claim_sha256": claim_sha256,
                "contract_version": FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION,
                "database_secret_disclosed": False,
                "gates": dict(gates),
                "new_exposure_authorized": False,
                "reason": reason,
                "runtime_terminal": (
                    None if terminal_evidence is None else dict(terminal_evidence.payload)
                ),
                "service": "trusted-time-first-enrollment-host-launcher",
                "status": status,
            }
        )
        encoded = _canonical_json_bytes(payload)
        outcome_sha256 = hashlib.sha256(encoded).hexdigest()
        artifact_path = _write_exclusive_retained_artifact(
            artifact_dir,
            file_name=f"trusted-time-first-enrollment-outcome-{outcome_sha256}.json",
            encoded=encoded,
        )
        return TrustedTimeFirstEnrollmentHostOutcome(
            encoded=encoded,
            artifact_path=artifact_path,
            confirmed=confirmed,
        )
    except Exception:
        raise TrustedTimeFirstEnrollmentOutcomeRetentionUnconfirmed(
            "trusted-time first enrollment outcome retention is unconfirmed"
        ) from None


def _placeholder_control_environment(
    *,
    docker_environment: Mapping[str, str],
    approved_launch: TrustedTimeApprovedLaunch,
) -> dict[str, str]:
    environment = dict(docker_environment)
    environment[SOURCE_IMAGE_ENVIRONMENT] = approved_launch.source_image_id
    environment[SUPERVISOR_IMAGE_ENVIRONMENT] = approved_launch.supervisor_image_id
    environment[DATABASE_SECRET_FILE_ENVIRONMENT] = str(PLACEHOLDER_DATABASE_SECRET_FILE)
    environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE
    )
    environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE
    )
    environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
    )
    return environment


def _run_first_enrollment_under_lock(
    *,
    env_file: Path,
    approval: TrustedTimeFirstEnrollmentApproval,
    image_admission_artifact: Path,
    artifact_dir: Path,
) -> TrustedTimeFirstEnrollmentHostOutcome:
    """Run an exact one-shot operation after the caller holds the global lock."""

    if not isinstance(env_file, Path) or env_file.name == ".env":
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment requires a dedicated launch-only env file"
        )
    approval.__post_init__()
    artifact_dir = _trusted_time_artifact_directory(artifact_dir)
    _require_new_operation_has_no_prior_claim(
        approval,
        artifact_dir=artifact_dir,
    )
    _approved_image_admission_path(image_admission_artifact, approval.approved_launch)
    receipt_encoded = load_approved_unenrolled_admission(
        approval,
        artifact_dir=artifact_dir,
    )
    prior_new_claim_encoded = load_approved_prior_new_claim(
        approval,
        artifact_dir=artifact_dir,
    )
    _require_prior_claim_receipt_binding(
        approval=approval,
        prior_claim_encoded=prior_new_claim_encoded,
        receipt_encoded=receipt_encoded,
    )
    _require_approved_git_revision(approval.approved_launch)
    docker_environment = _minimal_docker_environment()
    daemon_identity = qualify_local_docker_daemon(environment=docker_environment)
    admission = _load_approved_image_admission(
        image_admission_artifact,
        approval.approved_launch,
    )
    _require_image_admission_reserve(admission)
    verified_images = _require_verified_images(
        _verify_images_with_manifest(
            approval.approved_launch.source_image_id,
            approval.approved_launch.supervisor_image_id,
            docker_environment=docker_environment,
        )
    )
    if (
        verified_images[1] != approval.approved_launch.source_image_id
        or verified_images[2] != approval.approved_launch.supervisor_image_id
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment image identities changed"
        )
    _require_same_local_daemon(daemon_identity, environment=docker_environment)
    try:
        compose_payload = _head_reviewed_input_payload(
            approval.approved_launch.git_revision,
            "infra/compose/trusted-time.compose.yaml",
        )
    except TrustedTimeImageVerificationError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment immutable Compose payload is unavailable"
        ) from None
    compose_payload = _validate_runtime_compose_payload(compose_payload)
    control_environment = _placeholder_control_environment(
        docker_environment=docker_environment,
        approved_launch=approval.approved_launch,
    )
    placeholder_model = render_compose_model(
        source_image=approval.approved_launch.source_image_id,
        supervisor_image=approval.approved_launch.supervisor_image_id,
        database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        head_anchor_authority_file=PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
        head_anchor_auth_secret_file=PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
        head_anchor_signing_key_secret_file=(PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE),
        compose_payload=compose_payload,
        docker_environment=docker_environment,
    )
    validate_compose_model(
        placeholder_model,
        expected_source_image=approval.approved_launch.source_image_id,
        expected_supervisor_image=approval.approved_launch.supervisor_image_id,
        expected_database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        expected_head_anchor_authority_file=PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
        expected_head_anchor_auth_secret_file=PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
        expected_head_anchor_signing_key_secret_file=(
            PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
        ),
    )
    volume_identities = _capture_trusted_time_volume_identities(environment=docker_environment)
    _remove_exact_stale_enrollment_topology(
        supervisor_image_id=approval.approved_launch.supervisor_image_id,
        environment=control_environment,
        docker_environment=docker_environment,
        daemon_identity=daemon_identity,
        expected_volume_identities=volume_identities,
        compose_payload=compose_payload,
    )
    _validate_unenrolled_admission_teardown(
        compose_environment=control_environment,
        docker_environment=docker_environment,
        daemon_identity=daemon_identity,
        expected_volume_identities=volume_identities,
        compose_payload=compose_payload,
    )

    runtime: TrustedTimeRuntimeConfiguration | None = None
    materialized_database: MaterializedDatabaseSecret | None = None
    materialized_anchor_inputs: MaterializedHeadAnchorInputs | None = None
    retired_database: MaterializedDatabaseSecret | None = None
    retired_anchor_inputs: MaterializedHeadAnchorInputs | None = None
    container_id: str | None = None
    compose_attempted = False
    release_attempted = False
    secure_launch_validated = False
    runtime_inputs_retired = False
    terminal_evidence: TrustedTimeFirstEnrollmentTerminalEvidence | None = None
    claim_sha256: str | None = None
    claim_encoded: bytes | None = None
    primary_error: BaseException | None = None
    teardown_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    topology_removed = False
    state_volumes_preserved = False
    try:
        runtime = load_trusted_time_runtime_configuration(env_file)
        _load_bound_authority(runtime, approval)
        materialized_database = materialize_database_secret(runtime.database_url)
        materialized_anchor_inputs = materialize_trusted_time_head_anchor_inputs(
            runtime.head_anchor_payloads
        )
        validate_materialized_database_secret(materialized_database)
        validate_materialized_trusted_time_head_anchor_inputs(materialized_anchor_inputs)
        control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = str(materialized_database.path)
        control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = str(
            materialized_anchor_inputs.authority.path
        )
        control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = str(
            materialized_anchor_inputs.auth_secret.path
        )
        control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = str(
            materialized_anchor_inputs.signing_key.path
        )
        runtime_model = render_compose_model(
            source_image=approval.approved_launch.source_image_id,
            supervisor_image=approval.approved_launch.supervisor_image_id,
            database_secret_file=materialized_database.path,
            head_anchor_authority_file=materialized_anchor_inputs.authority.path,
            head_anchor_auth_secret_file=materialized_anchor_inputs.auth_secret.path,
            head_anchor_signing_key_secret_file=materialized_anchor_inputs.signing_key.path,
            compose_payload=compose_payload,
            docker_environment=docker_environment,
        )
        validate_compose_model(
            runtime_model,
            expected_source_image=approval.approved_launch.source_image_id,
            expected_supervisor_image=approval.approved_launch.supervisor_image_id,
            expected_database_secret_file=materialized_database.path,
            expected_head_anchor_authority_file=materialized_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=materialized_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=(
                materialized_anchor_inputs.signing_key.path
            ),
        )
        _require_approved_launch_state(
            image_admission_artifact,
            approval.approved_launch,
            expected_admission=admission,
        )
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        compose_attempted = True
        completed = _run_docker(
            _enrollment_up_argv(),
            environment=control_environment,
            timeout_seconds=60,
            compose_payload=compose_payload,
        )
        if completed[1] != 0:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment container creation failed"
            )
        container_id = _enrollment_container_id(
            environment=control_environment,
            compose_payload=compose_payload,
        )
        _validate_running_enrollment_container(
            container_id=container_id,
            supervisor_image_id=approval.approved_launch.supervisor_image_id,
            database_secret=materialized_database,
            head_anchor_inputs=materialized_anchor_inputs,
            environment=control_environment,
            compose_payload=compose_payload,
        )
        _wait_for_database_secret_consumption(
            container_id,
            environment=control_environment,
        )
        _validate_running_enrollment_container(
            container_id=container_id,
            supervisor_image_id=approval.approved_launch.supervisor_image_id,
            database_secret=materialized_database,
            head_anchor_inputs=materialized_anchor_inputs,
            environment=control_environment,
            compose_payload=compose_payload,
        )
        retired_database = materialized_database
        retired_anchor_inputs = materialized_anchor_inputs
        _cleanup_materialized_runtime_inputs(
            database_secret=materialized_database,
            head_anchor_inputs=materialized_anchor_inputs,
        )
        materialized_database = None
        materialized_anchor_inputs = None
        _validate_retired_enrollment_inputs(
            container_id=container_id,
            supervisor_image_id=approval.approved_launch.supervisor_image_id,
            database_secret=retired_database,
            head_anchor_inputs=retired_anchor_inputs,
            environment=control_environment,
            compose_payload=compose_payload,
        )
        runtime_inputs_retired = True

        repeated_runtime = load_trusted_time_runtime_configuration(env_file)
        _require_same_runtime_inputs(runtime, repeated_runtime, approval)
        del repeated_runtime
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        _require_approved_launch_state(
            image_admission_artifact,
            approval.approved_launch,
            expected_admission=admission,
        )
        current_admission = _load_approved_image_admission(
            image_admission_artifact,
            approval.approved_launch,
        )
        if current_admission != admission:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment image admission changed before release"
            )
        _require_image_admission_reserve(current_admission)
        verified_images = _require_verified_images(
            _verify_images_with_manifest(
                approval.approved_launch.source_image_id,
                approval.approved_launch.supervisor_image_id,
                docker_environment=docker_environment,
            )
        )
        if (
            verified_images[1] != approval.approved_launch.source_image_id
            or verified_images[2] != approval.approved_launch.supervisor_image_id
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment images changed before release"
            )
        observed_receipt = load_approved_unenrolled_admission(
            approval,
            artifact_dir=artifact_dir,
        )
        observed_prior_new_claim = load_approved_prior_new_claim(
            approval,
            artifact_dir=artifact_dir,
        )
        _require_prior_claim_receipt_binding(
            approval=approval,
            prior_claim_encoded=observed_prior_new_claim,
            receipt_encoded=observed_receipt,
        )
        if (
            observed_receipt != receipt_encoded
            or observed_prior_new_claim != prior_new_claim_encoded
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment approval evidence changed before release"
            )
        _validate_retired_enrollment_inputs(
            container_id=container_id,
            supervisor_image_id=approval.approved_launch.supervisor_image_id,
            database_secret=retired_database,
            head_anchor_inputs=retired_anchor_inputs,
            environment=control_environment,
            compose_payload=compose_payload,
        )
        secure_launch_validated = True
        _require_new_operation_has_no_prior_claim(
            approval,
            artifact_dir=artifact_dir,
        )
        claim_sha256, _, claim_encoded = _retain_single_use_claim(
            approval,
            artifact_dir=artifact_dir,
        )
        runtime = None
        release_attempted = True
        _release_enrollment_container(
            container_id=container_id,
            operation_mode=approval.operation_mode,
            environment=docker_environment,
        )
        terminal_evidence = _observe_enrollment_terminal(
            container_id=container_id,
            approval=approval,
            environment=docker_environment,
        )
    except BaseException as error:
        primary_error = error
    finally:
        try:
            _cleanup_materialized_runtime_inputs(
                database_secret=materialized_database,
                head_anchor_inputs=materialized_anchor_inputs,
            )
        except BaseException as error:
            cleanup_error = error
        else:
            materialized_database = None
            materialized_anchor_inputs = None
        if compose_attempted:
            try:
                if not _stop_enrollment_topology(
                    environment=control_environment,
                    compose_payload=compose_payload,
                ):
                    raise TrustedTimeSupervisorConfigurationError(
                        "trusted-time first enrollment topology removal failed"
                    )
                _validate_unenrolled_admission_teardown(
                    compose_environment=control_environment,
                    docker_environment=docker_environment,
                    daemon_identity=daemon_identity,
                    expected_volume_identities=volume_identities,
                    compose_payload=compose_payload,
                )
                topology_removed = True
                state_volumes_preserved = True
                compose_attempted = False
            except BaseException as error:
                teardown_error = error
        control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = ""
        control_environment[SOURCE_IMAGE_ENVIRONMENT] = ""
        control_environment[SUPERVISOR_IMAGE_ENVIRONMENT] = ""
        runtime = None
        retired_database = None
        retired_anchor_inputs = None

    if not release_attempted:
        if cleanup_error is not None:
            raise cleanup_error from primary_error
        if teardown_error is not None:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time first enrollment pre-release teardown is unconfirmed"
            ) from teardown_error
        if primary_error is not None:
            raise primary_error
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment release did not occur"
        )
    if claim_sha256 is None or claim_encoded is None:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment claim evidence is unavailable"
        )
    claim_retained = _revalidate_retained_claim(
        artifact_dir=artifact_dir,
        operation_id=approval.operation_id,
        claim_sha256=claim_sha256,
        expected=claim_encoded,
    )
    final_approval_state_validated = _final_approval_state_is_valid(
        approval=approval,
        admission=admission,
        receipt_encoded=receipt_encoded,
        prior_new_claim_encoded=prior_new_claim_encoded,
        image_admission_artifact=image_admission_artifact,
        artifact_dir=artifact_dir,
        daemon_identity=daemon_identity,
        docker_environment=docker_environment,
    )
    final_image_admission_fresh = _image_admission_is_fresh(admission)
    gates = {
        "final_approval_state_validated": final_approval_state_validated,
        "final_image_admission_fresh": final_image_admission_fresh,
        "runtime_inputs_retired": runtime_inputs_retired and cleanup_error is None,
        "secure_launch_validated": secure_launch_validated,
        "single_use_claim_retained": claim_retained,
        "state_volumes_preserved": state_volumes_preserved,
        "terminal_evidence_qualified": terminal_evidence is not None,
        "topology_removed": topology_removed,
    }
    return _retain_host_outcome(
        approval=approval,
        claim_sha256=claim_sha256,
        terminal_evidence=terminal_evidence,
        gates=gates,
        artifact_dir=artifact_dir,
    )


def run_first_enrollment(
    *,
    env_file: Path,
    approval: TrustedTimeFirstEnrollmentApproval,
    image_admission_artifact: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    artifact_dir: Path = DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
) -> TrustedTimeFirstEnrollmentHostOutcome:
    """Exclude every launcher and consume one approval at most once."""

    lock_descriptor = _acquire_trusted_time_launch_lock()
    primary_error: BaseException | None = None
    outcome: TrustedTimeFirstEnrollmentHostOutcome | None = None
    try:
        outcome = _run_first_enrollment_under_lock(
            env_file=env_file,
            approval=approval,
            image_admission_artifact=image_admission_artifact,
            artifact_dir=artifact_dir,
        )
        return outcome
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            _release_trusted_time_launch_lock(lock_descriptor)
        except TrustedTimeSupervisorConfigurationError:
            if primary_error is None:
                raise TrustedTimeFirstEnrollmentLockReleaseUnconfirmed(
                    "trusted-time first enrollment launch lock release is unconfirmed"
                ) from None


def _safe_pre_release_payload(reason: str) -> bytes:
    if reason not in {
        "approval_already_consumed",
        "first_enrollment_launch_configuration_rejected",
        "first_enrollment_launch_lock_release_unconfirmed",
        "first_enrollment_outcome_retention_unconfirmed",
    }:
        reason = "first_enrollment_launch_configuration_rejected"
    payload: dict[str, object] = {field_name: False for field_name in _AUTHORITY_FIELDS}
    payload.update(
        {
            "authority_granted": False,
            "contract_version": FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION,
            "database_secret_disclosed": False,
            "new_exposure_authorized": False,
            "reason": reason,
            "service": "trusted-time-first-enrollment-host-launcher",
            "status": "fatal",
        }
    )
    return _canonical_json_bytes(payload)


def _emit_exact(encoded: bytes) -> None:
    try:
        rendered = encoded.decode("ascii", errors="strict")
        if sys.stdout.write(rendered) != len(rendered):
            raise OSError
        sys.stdout.flush()
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment output failed"
        ) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help=(
            "dedicated owner-only exact-four trusted-time launch env; never use "
            "the general repository .env"
        ),
    )
    parser.add_argument(
        "--image-admission-artifact",
        type=Path,
        default=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
    )
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--recover-pending", action="store_true")
    parser.add_argument("--prior-new-operation-id")
    parser.add_argument("--prior-new-claim-sha256")
    parser.add_argument("--approved-git-revision", required=True)
    parser.add_argument("--approved-image-admission-sha256", required=True)
    parser.add_argument("--approved-source-image-id", required=True)
    parser.add_argument("--approved-supervisor-image-id", required=True)
    parser.add_argument("--unenrolled-admission-sha256", required=True)
    parser.add_argument("--anchor-authority-sha256", required=True)
    parser.add_argument("--deployment-identity-sha256", required=True)
    parser.add_argument("--runtime-database-identity-sha256", required=True)
    parser.add_argument("--anchor-project-identity-sha256", required=True)
    parser.add_argument("--source-authority-sha256", required=True)
    parser.add_argument("--signing-public-key-sha256", required=True)
    parser.add_argument("--host-identity-sha256", required=True)
    parser.add_argument("--principal-identity-sha256", required=True)
    parser.add_argument("--bucket-identity-sha256", required=True)
    arguments = parser.parse_args()
    try:
        operation_mode = (
            TrustedTimeFirstEnrollmentOperationMode.RECOVER_PENDING
            if arguments.recover_pending
            else TrustedTimeFirstEnrollmentOperationMode.NEW
        )
        approval = TrustedTimeFirstEnrollmentApproval(
            operation_id=arguments.operation_id,
            operation_mode=operation_mode,
            prior_new_operation_id=arguments.prior_new_operation_id,
            prior_new_claim_sha256=arguments.prior_new_claim_sha256,
            approved_launch=TrustedTimeApprovedLaunch(
                git_revision=arguments.approved_git_revision,
                image_admission_sha256=arguments.approved_image_admission_sha256,
                source_image_id=arguments.approved_source_image_id,
                supervisor_image_id=arguments.approved_supervisor_image_id,
            ),
            unenrolled_admission_sha256=arguments.unenrolled_admission_sha256,
            anchor_authority_sha256=arguments.anchor_authority_sha256,
            deployment_identity_sha256=arguments.deployment_identity_sha256,
            runtime_database_identity_sha256=(arguments.runtime_database_identity_sha256),
            anchor_project_identity_sha256=(arguments.anchor_project_identity_sha256),
            source_authority_sha256=arguments.source_authority_sha256,
            signing_public_key_sha256=arguments.signing_public_key_sha256,
            host_identity_sha256=arguments.host_identity_sha256,
            principal_identity_sha256=arguments.principal_identity_sha256,
            bucket_identity_sha256=arguments.bucket_identity_sha256,
        )
        outcome = run_first_enrollment(
            env_file=arguments.env_file,
            approval=approval,
            image_admission_artifact=arguments.image_admission_artifact,
            artifact_dir=arguments.artifact_dir,
        )
    except TrustedTimeFirstEnrollmentClaimConsumed:
        _emit_exact(_safe_pre_release_payload("approval_already_consumed"))
        raise SystemExit(2) from None
    except TrustedTimeFirstEnrollmentOutcomeRetentionUnconfirmed:
        _emit_exact(_safe_pre_release_payload("first_enrollment_outcome_retention_unconfirmed"))
        raise SystemExit(2) from None
    except TrustedTimeFirstEnrollmentLockReleaseUnconfirmed:
        _emit_exact(_safe_pre_release_payload("first_enrollment_launch_lock_release_unconfirmed"))
        raise SystemExit(2) from None
    except (
        TrustedTimeComposeVerificationError,
        TrustedTimeImageVerificationError,
        TrustedTimeSupervisorConfigurationError,
    ):
        _emit_exact(_safe_pre_release_payload("first_enrollment_launch_configuration_rejected"))
        raise SystemExit(2) from None
    except Exception:
        _emit_exact(_safe_pre_release_payload("first_enrollment_launch_configuration_rejected"))
        raise SystemExit(2) from None
    try:
        _emit_exact(outcome.encoded)
    except TrustedTimeSupervisorConfigurationError:
        raise SystemExit(2) from None
    if not outcome.confirmed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
