"""Generate the external trusted-head signing and deployment artifacts safely.

This command is deliberately offline.  It creates one raw Ed25519 private key,
one exact Supabase Auth-secret document, and one nonsecret deployment-authority
document at caller-selected paths outside the repository.  Every target is
created owner-only without overwriting an existing directory entry.  Secret
values are never included in the success receipt, error output, or object
representations.

Generating these inputs does not provision Supabase, run a Storage proof, or
approve the first external enrollment.  The resulting deployment remains fixed
at ``allow_enrollment=False`` and enrollment status ``UNRUN``.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import hashlib
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from apps.trusted_time_supervisor.head_anchor_config import (
    ED25519_PRIVATE_KEY_BYTES,
    TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
    TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS,
    TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS,
    decode_trusted_time_head_anchor_auth_secret,
    decode_trusted_time_head_anchor_authority,
    trusted_time_head_anchor_deployment_identity_sha256,
    trusted_time_head_anchor_project_identity_sha256,
)
from packages.adapters.trusted_time.ed25519_anchor import ed25519_public_key_sha256
from packages.adapters.trusted_time.supabase_storage_anchor import (
    SupabaseStorageAnchorCredentials,
    SupabaseStorageAnchorError,
)
from packages.application.trusted_time_head_anchor import (
    TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
)
from scripts.local_artifact import read_owner_only_artifact
from scripts.provision_trusted_time_anchor_project import (
    AnchorProjectProvisioningError,
    build_provisioning_contract,
)

GENERATOR_CONTRACT_VERSION = "phase6d-trusted-time-anchor-artifact-generator-v1"
SIGNING_KEY_ID = "aqt-trusted-time-anchor-ed25519-v1"
ENROLLMENT_STATUS = "UNRUN"
ALLOW_ENROLLMENT = False
MAXIMUM_AUTH_PASSWORD_BYTES = 256
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

_SHA256 = frozenset("0123456789abcdef")
_AUTHORITY_FLAGS: dict[str, bool] = {
    "alert_delivery": False,
    "automatic_rearm": False,
    "external_head_anchor_evidence_only": True,
    "live_trading": False,
    "new_exposure": False,
    "operational_control": False,
    "paper_trading": False,
    "readiness": False,
}


class TrustedTimeAnchorArtifactGenerationError(RuntimeError):
    """One sanitized reason for rejecting or failing artifact generation."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class TrustedTimeAnchorArtifactPayloads:
    """Validated exact payloads; secret fields never render."""

    signing_key: bytes = field(repr=False)
    auth_secret: bytes = field(repr=False)
    authority: bytes
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    signing_public_key_base64: str
    signing_public_key_sha256: str

    def __post_init__(self) -> None:
        if type(self.signing_key) is not bytes or len(self.signing_key) != (
            ED25519_PRIVATE_KEY_BYTES
        ):
            raise TrustedTimeAnchorArtifactGenerationError("generated_signing_key_invalid")
        if type(self.auth_secret) is not bytes or not self.auth_secret:
            raise TrustedTimeAnchorArtifactGenerationError("generated_auth_secret_invalid")
        if type(self.authority) is not bytes or not self.authority:
            raise TrustedTimeAnchorArtifactGenerationError("generated_authority_invalid")
        for value in (
            self.deployment_identity_sha256,
            self.runtime_database_identity_sha256,
            self.anchor_project_identity_sha256,
            self.signing_public_key_sha256,
        ):
            _require_sha256(value)


@dataclass(frozen=True, slots=True)
class TrustedTimeAnchorArtifactReceipt:
    """Secret-free review receipt for one successful three-file creation."""

    authority_artifact_sha256: str
    deployment_identity_sha256: str
    runtime_database_identity_sha256: str
    anchor_project_identity_sha256: str
    signing_public_key_base64: str
    signing_public_key_sha256: str
    bucket_name: str = TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
    signing_key_id: str = SIGNING_KEY_ID
    checkpoint_interval_seconds: int = TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
    stale_after_seconds: int = TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS
    full_prefix_verification_required: bool = True
    no_overwrite_required: bool = True
    all_control_authority_flags_false: bool = True
    external_head_anchor_evidence_only: bool = True
    allow_enrollment: bool = ALLOW_ENROLLMENT
    enrollment_status: str = ENROLLMENT_STATUS
    contract_version: str = GENERATOR_CONTRACT_VERSION

    def __post_init__(self) -> None:
        for value in (
            self.authority_artifact_sha256,
            self.deployment_identity_sha256,
            self.runtime_database_identity_sha256,
            self.anchor_project_identity_sha256,
            self.signing_public_key_sha256,
        ):
            _require_sha256(value)
        if (
            self.bucket_name != TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME
            or self.signing_key_id != SIGNING_KEY_ID
            or self.checkpoint_interval_seconds
            != TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
            or self.stale_after_seconds != TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS
            or self.full_prefix_verification_required is not True
            or self.no_overwrite_required is not True
            or self.all_control_authority_flags_false is not True
            or self.external_head_anchor_evidence_only is not True
            or self.allow_enrollment is not False
            or self.enrollment_status != "UNRUN"
            or self.contract_version != GENERATOR_CONTRACT_VERSION
        ):
            raise TrustedTimeAnchorArtifactGenerationError("generated_receipt_invalid")

    @property
    def public_payload(self) -> dict[str, object]:
        """Return the canonical nonsecret review result."""

        return {
            "allow_enrollment": self.allow_enrollment,
            "all_control_authority_flags_false": self.all_control_authority_flags_false,
            "anchor_project_identity_sha256": self.anchor_project_identity_sha256,
            "authority_artifact_sha256": self.authority_artifact_sha256,
            "bucket_name": self.bucket_name,
            "checkpoint_interval_seconds": self.checkpoint_interval_seconds,
            "contract_version": self.contract_version,
            "deployment_identity_sha256": self.deployment_identity_sha256,
            "enrollment_status": self.enrollment_status,
            "external_head_anchor_evidence_only": self.external_head_anchor_evidence_only,
            "full_prefix_verification_required": self.full_prefix_verification_required,
            "no_overwrite_required": self.no_overwrite_required,
            "runtime_database_identity_sha256": self.runtime_database_identity_sha256,
            "signing_key_id": self.signing_key_id,
            "signing_public_key_base64": self.signing_public_key_base64,
            "signing_public_key_sha256": self.signing_public_key_sha256,
            "stale_after_seconds": self.stale_after_seconds,
        }


@dataclass(slots=True)
class _PreparedArtifact:
    path: Path
    directory_descriptor: int
    temporary_name: str
    device: int
    inode: int
    size: int
    sha256: str
    linked: bool = False
    temporary_present: bool = True


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise TrustedTimeAnchorArtifactGenerationError("generated_json_invalid") from None


def _require_sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _SHA256 for character in value)
    ):
        raise TrustedTimeAnchorArtifactGenerationError("sha256_invalid")
    return value


def _absolute_output_path(value: object) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or value.name in {"", ".", ".."}:
        raise TrustedTimeAnchorArtifactGenerationError("output_path_invalid")
    absolute = Path(os.path.abspath(value))
    if "\x00" in str(absolute):
        raise TrustedTimeAnchorArtifactGenerationError("output_path_invalid")
    return absolute


def _open_directory_descriptor(
    path: Path,
    *,
    rejected_identity: tuple[int, int] | None = None,
) -> int:
    descriptor = os.open(
        path.anchor,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if rejected_identity == (metadata.st_dev, metadata.st_ino):
            raise TrustedTimeAnchorArtifactGenerationError("output_path_inside_repository")
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if rejected_identity == (metadata.st_dev, metadata.st_ino):
                raise TrustedTimeAnchorArtifactGenerationError("output_path_inside_repository")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_output_directory(path: Path) -> tuple[int, tuple[int, int]]:
    repository_descriptor: int | None = None
    directory_descriptor: int | None = None
    try:
        repository_descriptor = _open_directory_descriptor(REPOSITORY_ROOT)
        repository_metadata = os.fstat(repository_descriptor)
        repository_identity = (repository_metadata.st_dev, repository_metadata.st_ino)
        directory_descriptor = _open_directory_descriptor(
            path,
            rejected_identity=repository_identity,
        )
        metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise OSError
    except BaseException:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise
    finally:
        if repository_descriptor is not None:
            os.close(repository_descriptor)
    assert directory_descriptor is not None
    return directory_descriptor, repository_identity


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError
        view = view[written:]


def _prepare_artifact(path: Path, payload: bytes) -> _PreparedArtifact:
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    temporary_name = f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    temporary_present = False
    try:
        directory_descriptor, repository_identity = _open_output_directory(path.parent)
        try:
            target_metadata = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            if (target_metadata.st_dev, target_metadata.st_ino) == repository_identity:
                raise TrustedTimeAnchorArtifactGenerationError("output_path_inside_repository")
            raise FileExistsError
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_present = True
        _write_all(file_descriptor, payload)
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(payload)
        ):
            raise OSError
        os.close(file_descriptor)
        file_descriptor = None
        return _PreparedArtifact(
            path=path,
            directory_descriptor=directory_descriptor,
            temporary_name=temporary_name,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
    except TrustedTimeAnchorArtifactGenerationError:
        if temporary_present and directory_descriptor is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise
    except FileExistsError:
        if temporary_present and directory_descriptor is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise TrustedTimeAnchorArtifactGenerationError("output_already_exists") from None
    except (OSError, ValueError):
        if temporary_present and directory_descriptor is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise TrustedTimeAnchorArtifactGenerationError("output_write_failed") from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)


def _unlink_exact_entry(prepared: _PreparedArtifact, name: str) -> None:
    metadata = os.stat(
        name,
        dir_fd=prepared.directory_descriptor,
        follow_symlinks=False,
    )
    if metadata.st_dev != prepared.device or metadata.st_ino != prepared.inode:
        raise OSError
    os.unlink(name, dir_fd=prepared.directory_descriptor)


def _cleanup_prepared(prepared: list[_PreparedArtifact]) -> None:
    for item in reversed(prepared):
        if item.linked:
            with contextlib.suppress(OSError):
                _unlink_exact_entry(item, item.path.name)
        if item.temporary_present:
            with contextlib.suppress(OSError):
                _unlink_exact_entry(item, item.temporary_name)
        with contextlib.suppress(OSError):
            os.fsync(item.directory_descriptor)
        os.close(item.directory_descriptor)


def _verify_linked_artifact(prepared: _PreparedArtifact) -> None:
    descriptor = os.open(
        prepared.path.name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        dir_fd=prepared.directory_descriptor,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != prepared.device
            or before.st_ino != prepared.inode
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != prepared.size
        ):
            raise OSError
        payload = bytearray()
        while len(payload) <= prepared.size:
            chunk = os.read(descriptor, min(8_192, prepared.size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(payload) != prepared.size
            or hashlib.sha256(payload).hexdigest() != prepared.sha256
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise OSError
    finally:
        os.close(descriptor)


def _commit_artifacts(artifacts: tuple[tuple[Path, bytes], ...]) -> None:
    prepared: list[_PreparedArtifact] = []
    try:
        for path, payload in artifacts:
            prepared.append(_prepare_artifact(path, payload))
        for item in prepared:
            os.link(
                item.temporary_name,
                item.path.name,
                src_dir_fd=item.directory_descriptor,
                dst_dir_fd=item.directory_descriptor,
                follow_symlinks=False,
            )
            item.linked = True
            _unlink_exact_entry(item, item.temporary_name)
            item.temporary_present = False
        for item in prepared:
            _verify_linked_artifact(item)
            os.fsync(item.directory_descriptor)
    except TrustedTimeAnchorArtifactGenerationError:
        _cleanup_prepared(prepared)
        raise
    except FileExistsError:
        _cleanup_prepared(prepared)
        raise TrustedTimeAnchorArtifactGenerationError("output_already_exists") from None
    except (OSError, ValueError):
        _cleanup_prepared(prepared)
        raise TrustedTimeAnchorArtifactGenerationError("output_write_failed") from None
    else:
        for item in prepared:
            os.close(item.directory_descriptor)


def _raw_private_key(private_key: Ed25519PrivateKey) -> bytes:
    try:
        payload = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception:
        raise TrustedTimeAnchorArtifactGenerationError("signing_key_generation_failed") from None
    if type(payload) is not bytes or len(payload) != ED25519_PRIVATE_KEY_BYTES:
        raise TrustedTimeAnchorArtifactGenerationError("signing_key_generation_failed")
    return payload


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    try:
        payload = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception:
        raise TrustedTimeAnchorArtifactGenerationError("signing_key_generation_failed") from None
    if type(payload) is not bytes or len(payload) != ED25519_PRIVATE_KEY_BYTES:
        raise TrustedTimeAnchorArtifactGenerationError("signing_key_generation_failed")
    return payload


def _validation_database_url(runtime_project_ref: str) -> str:
    return (
        "postgresql+psycopg://postgres."
        f"{runtime_project_ref}:validation-only@aws-0-us-east-1.pooler.supabase.com:5432/"
        "postgres?sslmode=verify-full"
    )


def build_trusted_time_anchor_artifact_payloads(
    *,
    anchor_project_url: object,
    anchor_project_ref: object,
    runtime_project_ref: object,
    test_project_ref: object,
    publishable_key: object,
    writer_principal_id: object,
    auth_email: object,
    auth_password: object,
    host_id: object,
    source_authority_sha256: object,
    private_key: Ed25519PrivateKey,
) -> TrustedTimeAnchorArtifactPayloads:
    """Build and re-decode the three exact artifact payloads without writing."""

    try:
        provisioning = build_provisioning_contract(
            anchor_project_url=anchor_project_url,
            anchor_project_ref=anchor_project_ref,
            runtime_project_ref=runtime_project_ref,
            test_project_ref=test_project_ref,
            publishable_key=publishable_key,
            writer_principal_id=writer_principal_id,
        )
        if type(host_id) is not str or type(source_authority_sha256) is not str:
            raise TrustedTimeAnchorArtifactGenerationError("deployment_binding_invalid")
        source_digest = _require_sha256(source_authority_sha256)
        runtime_identity = trusted_time_head_anchor_project_identity_sha256(
            role="runtime_database",
            project_ref=provisioning.runtime_project_ref,
        )
        anchor_identity = trusted_time_head_anchor_project_identity_sha256(
            role="external_anchor",
            project_ref=provisioning.anchor_project_ref,
        )
        if type(auth_email) is not str or type(auth_password) is not str:
            raise TrustedTimeAnchorArtifactGenerationError("auth_secret_input_invalid")
        SupabaseStorageAnchorCredentials(
            project_url=provisioning.anchor_project_url,
            publishable_key=provisioning.publishable_key,
            principal_id=provisioning.writer_principal_id,
            anchor_project_identity_sha256=anchor_identity,
            email=auth_email,
            password=auth_password,
        )
        signing_key = _raw_private_key(private_key)
        public_key = _raw_public_key(private_key)
        public_key_digest = ed25519_public_key_sha256(public_key)
        deployment_identity = trusted_time_head_anchor_deployment_identity_sha256(
            host_id=host_id,
            source_authority_sha256=source_digest,
            runtime_database_identity_sha256=runtime_identity,
            anchor_project_identity_sha256=anchor_identity,
            principal_id=provisioning.writer_principal_id,
            signing_key_id=SIGNING_KEY_ID,
            signing_public_key_sha256=public_key_digest,
        )
        authority_object: dict[str, object] = {
            "anchor_project_identity_sha256": anchor_identity,
            "anchor_project_ref": provisioning.anchor_project_ref,
            "anchor_project_url": provisioning.anchor_project_url,
            "authority": _AUTHORITY_FLAGS,
            "bucket_name": TRUSTED_TIME_HEAD_ANCHOR_BUCKET_NAME,
            "checkpoint": {
                "checkpoint_interval_seconds": (
                    TRUSTED_TIME_HEAD_ANCHOR_CHECKPOINT_INTERVAL_SECONDS
                ),
                "full_prefix_verification_required": True,
                "no_overwrite_required": True,
                "stale_after_seconds": TRUSTED_TIME_HEAD_ANCHOR_STALE_AFTER_SECONDS,
            },
            "contract_version": TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_CONTRACT_VERSION,
            "deployment_identity_sha256": deployment_identity,
            "host_id": host_id,
            "principal_id": provisioning.writer_principal_id,
            "runtime_database_identity_sha256": runtime_identity,
            "runtime_database_project_ref": provisioning.runtime_project_ref,
            "signing": {
                "algorithm": "Ed25519",
                "key_id": SIGNING_KEY_ID,
                "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                "public_key_sha256": public_key_digest,
            },
            "source_authority_sha256": source_digest,
        }
        auth_secret_object: dict[str, object] = {
            "contract_version": TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_CONTRACT_VERSION,
            "email": auth_email,
            "password": auth_password,
            "principal_id": provisioning.writer_principal_id,
            "project_url": provisioning.anchor_project_url,
            "publishable_key": provisioning.publishable_key,
        }
        authority = _canonical_json_bytes(authority_object)
        auth_secret = _canonical_json_bytes(auth_secret_object)
        decoded_authority = decode_trusted_time_head_anchor_authority(
            authority,
            database_url=_validation_database_url(provisioning.runtime_project_ref),
            expected_host_id=host_id,
            expected_source_authority_sha256=source_digest,
        )
        decode_trusted_time_head_anchor_auth_secret(
            auth_secret,
            authority=decoded_authority,
        )
    except TrustedTimeAnchorArtifactGenerationError:
        raise
    except AnchorProjectProvisioningError as exc:
        raise TrustedTimeAnchorArtifactGenerationError(exc.reason_code) from None
    except (SupabaseStorageAnchorError, TrustedTimeSupervisorConfigurationError, ValueError):
        raise TrustedTimeAnchorArtifactGenerationError("generated_contract_invalid") from None
    return TrustedTimeAnchorArtifactPayloads(
        signing_key=signing_key,
        auth_secret=auth_secret,
        authority=authority,
        deployment_identity_sha256=deployment_identity,
        runtime_database_identity_sha256=runtime_identity,
        anchor_project_identity_sha256=anchor_identity,
        signing_public_key_base64=base64.b64encode(public_key).decode("ascii"),
        signing_public_key_sha256=public_key_digest,
    )


def generate_trusted_time_anchor_artifacts(
    *,
    anchor_project_url: object,
    anchor_project_ref: object,
    runtime_project_ref: object,
    test_project_ref: object,
    publishable_key: object,
    writer_principal_id: object,
    auth_email: object,
    auth_password: object,
    host_id: object,
    source_authority_sha256: object,
    signing_key_path: Path,
    auth_secret_path: Path,
    authority_path: Path,
    private_key_factory: Callable[[], Ed25519PrivateKey] | None = None,
) -> TrustedTimeAnchorArtifactReceipt:
    """Generate, validate, and exclusively create the three runtime inputs."""

    paths = tuple(
        _absolute_output_path(path) for path in (signing_key_path, auth_secret_path, authority_path)
    )
    if len(set(paths)) != len(paths):
        raise TrustedTimeAnchorArtifactGenerationError("output_paths_not_distinct")
    factory = Ed25519PrivateKey.generate if private_key_factory is None else private_key_factory
    try:
        private_key = factory()
    except Exception:
        raise TrustedTimeAnchorArtifactGenerationError("signing_key_generation_failed") from None
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TrustedTimeAnchorArtifactGenerationError("signing_key_generation_failed")
    payloads = build_trusted_time_anchor_artifact_payloads(
        anchor_project_url=anchor_project_url,
        anchor_project_ref=anchor_project_ref,
        runtime_project_ref=runtime_project_ref,
        test_project_ref=test_project_ref,
        publishable_key=publishable_key,
        writer_principal_id=writer_principal_id,
        auth_email=auth_email,
        auth_password=auth_password,
        host_id=host_id,
        source_authority_sha256=source_authority_sha256,
        private_key=private_key,
    )
    _commit_artifacts(
        (
            (paths[0], payloads.signing_key),
            (paths[1], payloads.auth_secret),
            (paths[2], payloads.authority),
        )
    )
    return TrustedTimeAnchorArtifactReceipt(
        authority_artifact_sha256=hashlib.sha256(payloads.authority).hexdigest(),
        deployment_identity_sha256=payloads.deployment_identity_sha256,
        runtime_database_identity_sha256=payloads.runtime_database_identity_sha256,
        anchor_project_identity_sha256=payloads.anchor_project_identity_sha256,
        signing_public_key_base64=payloads.signing_public_key_base64,
        signing_public_key_sha256=payloads.signing_public_key_sha256,
    )


def _read_auth_password(path: Path | None) -> str:
    if path is None:
        try:
            value = getpass.getpass("Supabase Auth writer password: ")
        except (EOFError, OSError):
            raise TrustedTimeAnchorArtifactGenerationError("auth_password_unavailable") from None
    else:
        if not path.is_absolute():
            raise TrustedTimeAnchorArtifactGenerationError("auth_password_path_invalid")
        try:
            payload = read_owner_only_artifact(
                path,
                limit=MAXIMUM_AUTH_PASSWORD_BYTES,
                label="trusted-time Auth password",
            )
            value = payload.decode("ascii", errors="strict")
        except (UnicodeDecodeError, ValueError):
            raise TrustedTimeAnchorArtifactGenerationError("auth_password_unavailable") from None
    return value


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise TrustedTimeAnchorArtifactGenerationError("command_arguments_invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description=(
            "Generate no-overwrite trusted-time anchor key, Auth secret, and authority files."
        )
    )
    parser.add_argument("--anchor-project-url", required=True)
    parser.add_argument("--anchor-project-ref", required=True)
    parser.add_argument("--runtime-project-ref", required=True)
    parser.add_argument("--test-project-ref", required=True)
    parser.add_argument("--publishable-key", required=True)
    parser.add_argument("--writer-principal-id", required=True)
    parser.add_argument("--auth-email", required=True)
    parser.add_argument(
        "--auth-password-file",
        type=Path,
        help="absolute owner-only file containing the exact password; otherwise prompt securely",
    )
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--source-authority-sha256", required=True)
    parser.add_argument("--signing-key-path", type=Path, required=True)
    parser.add_argument("--auth-secret-path", type=Path, required=True)
    parser.add_argument("--authority-path", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Create exact artifacts and emit only their sanitized public receipt."""

    try:
        arguments = _parser().parse_args(argv)
        password = _read_auth_password(arguments.auth_password_file)
        receipt = generate_trusted_time_anchor_artifacts(
            anchor_project_url=arguments.anchor_project_url,
            anchor_project_ref=arguments.anchor_project_ref,
            runtime_project_ref=arguments.runtime_project_ref,
            test_project_ref=arguments.test_project_ref,
            publishable_key=arguments.publishable_key,
            writer_principal_id=arguments.writer_principal_id,
            auth_email=arguments.auth_email,
            auth_password=password,
            host_id=arguments.host_id,
            source_authority_sha256=arguments.source_authority_sha256,
            signing_key_path=arguments.signing_key_path,
            auth_secret_path=arguments.auth_secret_path,
            authority_path=arguments.authority_path,
        )
    except TrustedTimeAnchorArtifactGenerationError as exc:
        print(exc.reason_code, file=sys.stderr)
        return 2
    sys.stdout.write(_canonical_json_bytes(receipt.public_payload).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())


__all__ = [
    "ALLOW_ENROLLMENT",
    "ENROLLMENT_STATUS",
    "GENERATOR_CONTRACT_VERSION",
    "SIGNING_KEY_ID",
    "TrustedTimeAnchorArtifactGenerationError",
    "TrustedTimeAnchorArtifactPayloads",
    "TrustedTimeAnchorArtifactReceipt",
    "build_trusted_time_anchor_artifact_payloads",
    "generate_trusted_time_anchor_artifacts",
    "main",
]
