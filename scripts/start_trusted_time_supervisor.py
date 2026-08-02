"""Start the local trusted-time topology with owner-staged runtime inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
    validate_database_url,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    ED25519_PRIVATE_KEY_BYTES,
    MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES,
    MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES,
)
from scripts.credential_env import load_owner_only_environment
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
    SOURCE_IMAGE_ENVIRONMENT,
    SUPERVISOR_IMAGE_ENVIRONMENT,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
    _open_owner_only_artifact_directory,
    build_verify_and_write_image_admission,
    load_image_admission_artifact,
    validate_socket_volume_inspection,
)

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "infra" / "compose" / "trusted-time.compose.yaml"
DEFAULTS_PATH = ROOT / "infra" / "compose" / "trusted-time.defaults.env"
MAXIMUM_ENV_FILE_BYTES = 65_536
COMPOSE_WAIT_TIMEOUT_SECONDS = 60
COMPOSE_SOCKET_VOLUME_NAME = "autoquanttrader-trusted-time_chrony_command_socket"
COMPOSE_STATE_VOLUME_NAME = "autoquanttrader-trusted-time_chrony_state"
COMPOSE_NETWORK_NAME = "autoquanttrader-trusted-time_default"
DATABASE_SECRET_ROOT = IGNORED_ARTIFACT_ROOT / "trusted-time" / "runtime-secrets"
DATABASE_SECRET_FILE_NAME = "database-url"
DATABASE_SECRET_DIRECTORY_PATTERN = re.compile(r"[.]database-secret-[0-9a-f]{32}")
HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT = "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_SOURCE_FILE"
HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT = "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE"
HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT = (
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_SOURCE_FILE"
)
HEAD_ANCHOR_AUTHORITY_FILE_NAME = "head-anchor-authority.json"
HEAD_ANCHOR_AUTH_SECRET_FILE_NAME = "head-anchor-auth"
HEAD_ANCHOR_SIGNING_KEY_FILE_NAME = "head-anchor-signing-key"
HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN = re.compile(
    r"[.]head-anchor-(authority|auth|signing-key)-[0-9a-f]{32}"
)
DATABASE_SECRET_CONSUMED_PATH = "/tmp/database-secret-consumed"
DATABASE_SECRET_CONSUMED_SHA256 = hashlib.sha256(
    b"phase6c-database-secret-consumed-v1\n"
).hexdigest()
DATABASE_SECRET_RUNTIME_PATH = "/run/secrets/trusted_time_database_url"
HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH = "/etc/autoquant/trusted-time/head-anchor-authority.json"
HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH = "/run/secrets/trusted_time_head_anchor_auth"
HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH = "/run/secrets/trusted_time_head_anchor_signing_key"
_SUPERVISOR_RUNTIME_ENVIRONMENT = {
    "AQT_TRUSTED_TIME_AUTHORITY_PATH": "/etc/autoquant/trusted-time/source-authority.json",
    "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH": "/etc/autoquant/trusted-time/chrony.conf",
    "AQT_TRUSTED_TIME_DATABASE_URL_FILE": DATABASE_SECRET_RUNTIME_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH": HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE": HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE": HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
}
_CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{12,64}")
_DAEMON_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,255}")
_PASSTHROUGH_ENVIRONMENT = frozenset(
    {
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "HOME",
        "LANG",
        "NO_COLOR",
        "PATH",
        "TERM",
        "TMPDIR",
        "XDG_CONFIG_HOME",
    }
)


@dataclass(frozen=True, slots=True)
class LocalDockerDaemonIdentity:
    """One approved local Unix endpoint and the daemon reached through it."""

    context_name: str
    endpoint: str
    daemon_id: str


@dataclass(frozen=True, slots=True)
class MaterializedDatabaseSecret:
    """One exact temporary host file whose containing directory is owner-only."""

    root: Path
    ignored_root: Path
    directory: Path
    path: Path
    directory_device: int
    directory_inode: int
    file_device: int
    file_inode: int
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class TrustedTimeHeadAnchorSourcePayloads:
    """Exact owner-file bytes; secret members never render."""

    authority: bytes = field(repr=False)
    auth_secret: bytes = field(repr=False)
    signing_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class MaterializedHeadAnchorFile:
    """One exact staged Phase 6D file and its held inode identity."""

    root: Path
    ignored_root: Path
    directory: Path
    path: Path
    directory_device: int
    directory_inode: int
    file_device: int
    file_inode: int
    size: int
    sha256: str
    kind: str


@dataclass(frozen=True, slots=True)
class MaterializedHeadAnchorInputs:
    """All three Phase 6D staged inputs, with secret values excluded."""

    authority: MaterializedHeadAnchorFile
    auth_secret: MaterializedHeadAnchorFile = field(repr=False)
    signing_key: MaterializedHeadAnchorFile = field(repr=False)


def _safe_payload(status: str, reason: str) -> str:
    return json.dumps(
        {
            "database_secret_disclosed": False,
            "new_exposure_authorized": False,
            "reason": reason,
            "service": "trusted-time-local-launcher",
            "status": status,
        },
        sort_keys=True,
    )


def load_runtime_database_url(env_file: Path) -> str:
    try:
        environment = load_owner_only_environment(
            env_file,
            variables=("AQT_DATABASE_URL",),
            maximum_bytes=MAXIMUM_ENV_FILE_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
        )
    except ValueError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time owner env file was rejected"
        ) from None
    database_url = environment.get("AQT_DATABASE_URL")
    if database_url is None:
        raise TrustedTimeSupervisorConfigurationError("trusted-time database secret is missing")
    return validate_database_url(database_url)


def _read_owner_only_source_file(
    value: str,
    *,
    maximum_bytes: int,
    exact_bytes: int | None = None,
) -> bytes:
    """Read one absolute file through nonsymlinked directory descriptors."""

    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor source file was rejected"
        )
    path = Path(value)
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor source file was rejected"
        )
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        directory_descriptor = os.open(
            path.anchor,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        for component in path.parts[1:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum_bytes
            or (exact_bytes is not None and before.st_size != exact_bytes)
        ):
            raise OSError
        chunks: list[bytes] = []
        observed = 0
        while observed <= maximum_bytes:
            chunk = os.read(file_descriptor, min(8_192, maximum_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        after = os.fstat(file_descriptor)
        payload = b"".join(chunks)
        if (
            len(payload) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or (exact_bytes is not None and len(payload) != exact_bytes)
        ):
            raise OSError
        return payload
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor source file was rejected"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def load_trusted_time_head_anchor_source_payloads(
    env_file: Path,
) -> TrustedTimeHeadAnchorSourcePayloads:
    """Load only three absolute source paths from the owner-only environment."""

    variables = (
        HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT,
        HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT,
        HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT,
    )
    try:
        environment = load_owner_only_environment(
            env_file,
            variables=variables,
            maximum_bytes=MAXIMUM_ENV_FILE_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
        )
    except ValueError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time owner env file was rejected"
        ) from None
    if set(environment) != set(variables):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor source paths are missing"
        )
    return TrustedTimeHeadAnchorSourcePayloads(
        authority=_read_owner_only_source_file(
            environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT],
            maximum_bytes=MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES,
        ),
        auth_secret=_read_owner_only_source_file(
            environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT],
            maximum_bytes=MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES,
        ),
        signing_key=_read_owner_only_source_file(
            environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT],
            maximum_bytes=ED25519_PRIVATE_KEY_BYTES,
            exact_bytes=ED25519_PRIVATE_KEY_BYTES,
        ),
    )


def materialize_database_secret(
    database_url: str,
    *,
    root: Path = DATABASE_SECRET_ROOT,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> MaterializedDatabaseSecret:
    """Create one 0400 secret below a fresh owner-only directory."""

    validated = validate_database_url(database_url)
    encoded = validated.encode("utf-8")
    root_descriptor: int | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    directory_name = f".database-secret-{secrets.token_hex(16)}"
    directory_created = False
    file_created = False
    try:
        root_descriptor = _open_owner_only_artifact_directory(
            root,
            ignored_root=ignored_root,
            create=True,
        )
        os.mkdir(directory_name, 0o700, dir_fd=root_descriptor)
        directory_created = True
        directory_descriptor = os.open(
            directory_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        directory_metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise OSError
        file_descriptor = os.open(
            DATABASE_SECRET_FILE_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        file_created = True
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o400)
        os.fsync(file_descriptor)
        file_metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(file_metadata.st_mode) != 0o400
            or file_metadata.st_nlink != 1
            or file_metadata.st_size != len(encoded)
        ):
            raise OSError
        os.fsync(directory_descriptor)
        return MaterializedDatabaseSecret(
            root=root,
            ignored_root=ignored_root,
            directory=root / directory_name,
            path=root / directory_name / DATABASE_SECRET_FILE_NAME,
            directory_device=directory_metadata.st_dev,
            directory_inode=directory_metadata.st_ino,
            file_device=file_metadata.st_dev,
            file_inode=file_metadata.st_ino,
            size=len(encoded),
            sha256=hashlib.sha256(encoded).hexdigest(),
        )
    except (OSError, TrustedTimeImageVerificationError):
        if file_created and directory_descriptor is not None:
            with suppress(OSError):
                os.unlink(DATABASE_SECRET_FILE_NAME, dir_fd=directory_descriptor)
        if directory_created and root_descriptor is not None:
            with suppress(OSError):
                os.rmdir(directory_name, dir_fd=root_descriptor)
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret materialization failed"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def validate_materialized_database_secret(secret: MaterializedDatabaseSecret) -> None:
    """Recheck the exact held host inode immediately before Compose consumes it."""

    if type(secret) is not MaterializedDatabaseSecret:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret metadata changed"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            secret.path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 8_192)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        directory_metadata = secret.directory.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_dev != secret.directory_device
            or directory_metadata.st_ino != secret.directory_inode
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or before.st_dev != secret.file_device
            or before.st_ino != secret.file_inode
            or before.st_size != secret.size
            or observed != secret.size
            or digest.hexdigest() != secret.sha256
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise OSError
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret metadata changed"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def cleanup_materialized_database_secret(secret: MaterializedDatabaseSecret) -> None:
    """Unlink exactly the file and fresh directory created by the launcher."""

    if (
        type(secret) is not MaterializedDatabaseSecret
        or secret.directory.parent != secret.root
        or secret.path != secret.directory / DATABASE_SECRET_FILE_NAME
        or DATABASE_SECRET_DIRECTORY_PATTERN.fullmatch(secret.directory.name) is None
        or not secret.root.is_relative_to(secret.ignored_root)
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time database secret cleanup failed")
    root_descriptor: int | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        root_descriptor = _open_owner_only_artifact_directory(
            secret.root,
            ignored_root=secret.ignored_root,
            create=False,
        )
        directory_descriptor = os.open(
            secret.directory.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        directory_metadata = os.fstat(directory_descriptor)
        exact_directory = (
            stat.S_ISDIR(directory_metadata.st_mode)
            and directory_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(directory_metadata.st_mode) == 0o700
            and directory_metadata.st_dev == secret.directory_device
            and directory_metadata.st_ino == secret.directory_inode
        )
        if not exact_directory:
            raise OSError
        file_descriptor = os.open(
            DATABASE_SECRET_FILE_NAME,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        file_metadata = os.fstat(file_descriptor)
        exact_file = (
            stat.S_ISREG(file_metadata.st_mode)
            and file_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(file_metadata.st_mode) == 0o400
            and file_metadata.st_dev == secret.file_device
            and file_metadata.st_ino == secret.file_inode
            and file_metadata.st_nlink == 1
            and file_metadata.st_size == secret.size
        )
        if not exact_file:
            raise OSError
        os.close(file_descriptor)
        file_descriptor = None
        os.unlink(DATABASE_SECRET_FILE_NAME, dir_fd=directory_descriptor)
        os.close(directory_descriptor)
        directory_descriptor = None
        os.rmdir(secret.directory.name, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time database secret cleanup failed"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
    if secret.path.exists() or secret.directory.exists():
        raise TrustedTimeSupervisorConfigurationError("trusted-time database secret cleanup failed")


_HEAD_ANCHOR_FILE_NAMES = {
    "authority": HEAD_ANCHOR_AUTHORITY_FILE_NAME,
    "auth": HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
    "signing-key": HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
}


def _materialize_head_anchor_file(
    payload: bytes,
    *,
    kind: str,
    root: Path,
    ignored_root: Path,
) -> MaterializedHeadAnchorFile:
    file_name = _HEAD_ANCHOR_FILE_NAMES.get(kind)
    if file_name is None or type(payload) is not bytes or not payload:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor input materialization failed"
        )
    directory_name = f".head-anchor-{kind}-{secrets.token_hex(16)}"
    root_descriptor: int | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    directory_created = False
    file_created = False
    try:
        root_descriptor = _open_owner_only_artifact_directory(
            root,
            ignored_root=ignored_root,
            create=True,
        )
        os.mkdir(directory_name, 0o700, dir_fd=root_descriptor)
        directory_created = True
        directory_descriptor = os.open(
            directory_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        directory_metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise OSError
        file_descriptor = os.open(
            file_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        file_created = True
        view = memoryview(payload)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o400)
        os.fsync(file_descriptor)
        file_metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(file_metadata.st_mode) != 0o400
            or file_metadata.st_nlink != 1
            or file_metadata.st_size != len(payload)
        ):
            raise OSError
        os.fsync(directory_descriptor)
        return MaterializedHeadAnchorFile(
            root=root,
            ignored_root=ignored_root,
            directory=root / directory_name,
            path=root / directory_name / file_name,
            directory_device=directory_metadata.st_dev,
            directory_inode=directory_metadata.st_ino,
            file_device=file_metadata.st_dev,
            file_inode=file_metadata.st_ino,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            kind=kind,
        )
    except (OSError, TrustedTimeImageVerificationError):
        if file_created and directory_descriptor is not None:
            with suppress(OSError):
                os.unlink(file_name, dir_fd=directory_descriptor)
        if directory_created and root_descriptor is not None:
            with suppress(OSError):
                os.rmdir(directory_name, dir_fd=root_descriptor)
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor input materialization failed"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def validate_materialized_head_anchor_file(
    materialized: MaterializedHeadAnchorFile,
) -> None:
    if (
        type(materialized) is not MaterializedHeadAnchorFile
        or materialized.kind not in _HEAD_ANCHOR_FILE_NAMES
        or materialized.path != materialized.directory / _HEAD_ANCHOR_FILE_NAMES[materialized.kind]
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged input changed"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            materialized.path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 8_192)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        directory_metadata = materialized.directory.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_dev != materialized.directory_device
            or directory_metadata.st_ino != materialized.directory_inode
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or before.st_dev != materialized.file_device
            or before.st_ino != materialized.file_inode
            or before.st_size != materialized.size
            or observed != materialized.size
            or digest.hexdigest() != materialized.sha256
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise OSError
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged input changed"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def cleanup_materialized_head_anchor_file(
    materialized: MaterializedHeadAnchorFile,
) -> None:
    kind = materialized.kind if type(materialized) is MaterializedHeadAnchorFile else None
    file_name = _HEAD_ANCHOR_FILE_NAMES.get(kind) if kind is not None else None
    directory_match = (
        HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN.fullmatch(materialized.directory.name)
        if type(materialized) is MaterializedHeadAnchorFile
        else None
    )
    if (
        type(materialized) is not MaterializedHeadAnchorFile
        or file_name is None
        or materialized.directory.parent != materialized.root
        or materialized.path != materialized.directory / file_name
        or directory_match is None
        or directory_match.group(1) != materialized.kind
        or not materialized.root.is_relative_to(materialized.ignored_root)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged input cleanup failed"
        )
    root_descriptor: int | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        root_descriptor = _open_owner_only_artifact_directory(
            materialized.root,
            ignored_root=materialized.ignored_root,
            create=False,
        )
        directory_descriptor = os.open(
            materialized.directory.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        directory_metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_dev != materialized.directory_device
            or directory_metadata.st_ino != materialized.directory_inode
        ):
            raise OSError
        file_descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        file_metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(file_metadata.st_mode)
            or file_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(file_metadata.st_mode) != 0o400
            or file_metadata.st_dev != materialized.file_device
            or file_metadata.st_ino != materialized.file_inode
            or file_metadata.st_nlink != 1
            or file_metadata.st_size != materialized.size
        ):
            raise OSError
        os.close(file_descriptor)
        file_descriptor = None
        os.unlink(file_name, dir_fd=directory_descriptor)
        os.close(directory_descriptor)
        directory_descriptor = None
        os.rmdir(materialized.directory.name, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged input cleanup failed"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
    if materialized.path.exists() or materialized.directory.exists():
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged input cleanup failed"
        )


def materialize_trusted_time_head_anchor_inputs(
    payloads: TrustedTimeHeadAnchorSourcePayloads,
    *,
    root: Path = DATABASE_SECRET_ROOT,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> MaterializedHeadAnchorInputs:
    if type(payloads) is not TrustedTimeHeadAnchorSourcePayloads:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor input materialization failed"
        )
    created: list[MaterializedHeadAnchorFile] = []
    try:
        for kind, payload in (
            ("authority", payloads.authority),
            ("auth", payloads.auth_secret),
            ("signing-key", payloads.signing_key),
        ):
            created.append(
                _materialize_head_anchor_file(
                    payload,
                    kind=kind,
                    root=root,
                    ignored_root=ignored_root,
                )
            )
        return MaterializedHeadAnchorInputs(
            authority=created[0],
            auth_secret=created[1],
            signing_key=created[2],
        )
    except BaseException as primary_error:
        cleanup_error: Exception | None = None
        for materialized in reversed(created):
            try:
                cleanup_materialized_head_anchor_file(materialized)
            except Exception as error:
                cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error from primary_error
        raise


def validate_materialized_trusted_time_head_anchor_inputs(
    inputs: MaterializedHeadAnchorInputs,
) -> None:
    if type(inputs) is not MaterializedHeadAnchorInputs:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged inputs changed"
        )
    for materialized in (inputs.authority, inputs.auth_secret, inputs.signing_key):
        validate_materialized_head_anchor_file(materialized)


def cleanup_materialized_trusted_time_head_anchor_inputs(
    inputs: MaterializedHeadAnchorInputs,
) -> None:
    if type(inputs) is not MaterializedHeadAnchorInputs:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time head-anchor staged input cleanup failed"
        )
    primary_error: Exception | None = None
    for materialized in (inputs.signing_key, inputs.auth_secret, inputs.authority):
        try:
            cleanup_materialized_head_anchor_file(materialized)
        except Exception as error:
            primary_error = error
    if primary_error is not None:
        raise primary_error


def _cleanup_materialized_runtime_inputs(
    *,
    database_secret: MaterializedDatabaseSecret | None,
    head_anchor_inputs: MaterializedHeadAnchorInputs | None,
) -> None:
    cleanup_error: Exception | None = None
    if head_anchor_inputs is not None:
        try:
            cleanup_materialized_trusted_time_head_anchor_inputs(head_anchor_inputs)
        except Exception as error:
            cleanup_error = error
    if database_secret is not None:
        try:
            cleanup_materialized_database_secret(database_secret)
        except Exception as error:
            cleanup_error = error
    if cleanup_error is not None:
        raise cleanup_error


def _compose_prefix() -> tuple[str, ...]:
    return (
        "docker",
        "compose",
        "--env-file",
        str(DEFAULTS_PATH),
        "--file",
        str(COMPOSE_PATH),
    )


def compose_argv() -> tuple[str, ...]:
    return (
        *_compose_prefix(),
        "up",
        "--detach",
        "--no-build",
        "--pull",
        "never",
        "--force-recreate",
        "--wait",
        "--wait-timeout",
        str(COMPOSE_WAIT_TIMEOUT_SECONDS),
    )


def _compose_down_argv() -> tuple[str, ...]:
    return (*_compose_prefix(), "down", "--remove-orphans", "--timeout", "10")


def _minimal_docker_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key in _PASSTHROUGH_ENVIRONMENT or key.startswith("LC_")
    }


def _run_docker(
    argv: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    timeout_seconds: float = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=ROOT,
            env=dict(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker Compose was unavailable"
        ) from None


def _one_quiet_line(
    completed: subprocess.CompletedProcess[str],
    *,
    label: str,
) -> str:
    lines = completed.stdout.splitlines()
    if completed.returncode != 0 or completed.stderr or len(lines) != 1 or not lines[0]:
        raise TrustedTimeSupervisorConfigurationError(f"{label} is unavailable")
    return lines[0]


def _context_endpoint(
    context_name: str,
    *,
    environment: Mapping[str, str],
) -> str:
    completed = _run_docker(
        (
            "docker",
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
            context_name,
        ),
        environment=environment,
    )
    encoded = _one_quiet_line(completed, label="trusted-time Docker context endpoint")
    try:
        endpoint: Any = json.loads(encoded)
    except json.JSONDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker context endpoint is malformed"
        ) from None
    if type(endpoint) is not str or not endpoint:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker context endpoint is malformed"
        )
    return endpoint


def _effective_docker_endpoint(
    *,
    environment: Mapping[str, str],
) -> tuple[str, str]:
    explicit_context = environment.get("DOCKER_CONTEXT", "")
    explicit_host = environment.get("DOCKER_HOST", "")
    if explicit_context:
        return explicit_context, _context_endpoint(explicit_context, environment=environment)
    if explicit_host:
        return "<DOCKER_HOST>", explicit_host
    completed = _run_docker(
        ("docker", "context", "show"),
        environment=environment,
    )
    context_name = _one_quiet_line(completed, label="trusted-time Docker context")
    return context_name, _context_endpoint(context_name, environment=environment)


def _canonical_local_socket_endpoint(endpoint: str) -> str:
    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker endpoint must be a local Unix socket"
        ) from None
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not parsed.path
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker endpoint must be a local Unix socket"
        )
    socket_path = Path(unquote(parsed.path))
    if not socket_path.is_absolute():
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker endpoint must be a local Unix socket"
        )
    try:
        resolved_path = socket_path.resolve(strict=True)
        metadata = resolved_path.stat()
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time local Docker socket is unavailable"
        ) from None
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time local Docker socket metadata is invalid"
        )
    return f"unix://{resolved_path}"


def qualify_local_docker_daemon(
    *,
    environment: Mapping[str, str] | None = None,
) -> LocalDockerDaemonIdentity:
    """Bind launch admission to one local Unix socket and daemon identity."""

    docker_environment = _minimal_docker_environment() if environment is None else dict(environment)
    context_name, endpoint = _effective_docker_endpoint(environment=docker_environment)
    canonical_endpoint = _canonical_local_socket_endpoint(endpoint)
    completed = _run_docker(
        ("docker", "info", "--format", "{{json .ID}}"),
        environment=docker_environment,
    )
    encoded_daemon_id = _one_quiet_line(
        completed,
        label="trusted-time Docker daemon identity",
    )
    try:
        daemon_id: Any = json.loads(encoded_daemon_id)
    except json.JSONDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker daemon identity is malformed"
        ) from None
    if type(daemon_id) is not str or _DAEMON_ID_PATTERN.fullmatch(daemon_id) is None:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker daemon identity is malformed"
        )
    return LocalDockerDaemonIdentity(
        context_name=context_name,
        endpoint=canonical_endpoint,
        daemon_id=daemon_id,
    )


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise TrustedTimeSupervisorConfigurationError(f"{field_name} is malformed")
    return value


def _compose_container_id(
    service_name: str,
    *,
    environment: Mapping[str, str],
) -> str:
    completed = _run_docker(
        (*_compose_prefix(), "ps", "--quiet", service_name),
        environment=environment,
    )
    lines = completed.stdout.splitlines()
    if (
        completed.returncode != 0
        or completed.stderr
        or len(lines) != 1
        or _CONTAINER_ID_PATTERN.fullmatch(lines[0]) is None
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container identity is unavailable"
        )
    return lines[0]


def _inspect_container(
    container_id: str,
    *,
    environment: Mapping[str, str],
) -> object:
    completed = _run_docker(
        ("docker", "container", "inspect", container_id),
        environment=environment,
    )
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container inspection failed"
        )
    try:
        inspected: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container inspection is malformed"
        ) from None
    return inspected


def _inspect_image_configuration(
    image_id: str,
    *,
    environment: Mapping[str, str],
) -> Mapping[str, object]:
    completed = _run_docker(
        ("docker", "image", "inspect", image_id),
        environment=environment,
    )
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admitted image inspection failed"
        )
    try:
        inspected: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admitted image inspection is malformed"
        ) from None
    if type(inspected) is not list or len(inspected) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admitted image inspection is malformed"
        )
    image = _mapping(inspected[0], "trusted-time admitted image")
    return _mapping(image.get("Config"), "trusted-time admitted image Config")


def _inspect_volume(
    volume_name: str,
    *,
    environment: Mapping[str, str],
) -> object:
    completed = _run_docker(
        ("docker", "volume", "inspect", volume_name),
        environment=environment,
    )
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeSupervisorConfigurationError("trusted-time volume inspection failed")
    try:
        inspected: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time volume inspection is malformed"
        ) from None
    return inspected


def validate_chrony_state_volume_inspection(
    inspection: object,
    *,
    expected_name: str = COMPOSE_STATE_VOLUME_NAME,
) -> None:
    """Reject stale or redirected storage while preserving its existing content."""

    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time state volume inspection is malformed"
        )
    volume = _mapping(inspection[0], "trusted-time state volume")
    labels = _mapping(volume.get("Labels"), "trusted-time state volume labels")
    if (
        volume.get("Name") != expected_name
        or volume.get("Driver") != "local"
        or volume.get("Scope") != "local"
        or volume.get("Options") not in (None, {})
        or labels.get("com.docker.compose.project") != "autoquanttrader-trusted-time"
        or labels.get("com.docker.compose.volume") != "chrony_state"
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time state volume identity or driver drifted"
        )


def _string_sequence(value: object, field_name: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise TrustedTimeSupervisorConfigurationError(f"{field_name} is malformed")
    return value


def _environment_mapping(value: object, field_name: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _string_sequence(value, field_name):
        key, separator, item_value = item.partition("=")
        if not separator or not key or key in result:
            raise TrustedTimeSupervisorConfigurationError(f"{field_name} is malformed")
        result[key] = item_value
    return result


def _validate_mount_request(
    request: Mapping[str, object],
    *,
    expected_source: str,
    expected_target: str,
    expected_nocopy: bool,
) -> None:
    volume_options = _mapping(
        request.get("VolumeOptions"),
        "trusted-time runtime volume options",
    )
    if (
        request.get("Type") != "volume"
        or request.get("Source") != expected_source
        or request.get("Target") != expected_target
        or request.get("ReadOnly") not in (None, False)
        or volume_options.get("NoCopy", False) is not expected_nocopy
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time runtime volume request drifted")


def _runtime_input_host_path(value: object) -> str | None:
    if type(value) is not str or not value:
        return None
    if value.startswith("/host_mnt/"):
        return value.removeprefix("/host_mnt")
    return value


def _approved_runtime_input_source_path(
    value: str,
    *,
    file_name: str,
    head_anchor_kind: str | None,
) -> bool:
    host_path = _runtime_input_host_path(value)
    if host_path is None:
        return False
    path = Path(host_path)
    if head_anchor_kind is None:
        directory_is_approved = (
            DATABASE_SECRET_DIRECTORY_PATTERN.fullmatch(path.parent.name) is not None
        )
    else:
        directory_match = HEAD_ANCHOR_INPUT_DIRECTORY_PATTERN.fullmatch(path.parent.name)
        directory_is_approved = (
            directory_match is not None and directory_match.group(1) == head_anchor_kind
        )
    return (
        path.is_absolute()
        and path.name == file_name
        and path.parent.parent == DATABASE_SECRET_ROOT
        and directory_is_approved
        and not os.path.lexists(path)
        and not os.path.lexists(path.parent)
    )


def _approved_database_secret_source_path(value: str) -> bool:
    return _approved_runtime_input_source_path(
        value,
        file_name=DATABASE_SECRET_FILE_NAME,
        head_anchor_kind=None,
    )


def _runtime_input_source_is_approved(
    value: object,
    *,
    expected_file: Path | None,
    file_name: str,
    head_anchor_kind: str | None,
) -> bool:
    host_path = _runtime_input_host_path(value)
    if host_path is None:
        return False
    if expected_file is not None:
        return expected_file.is_absolute() and str(expected_file) == host_path
    return _approved_runtime_input_source_path(
        host_path,
        file_name=file_name,
        head_anchor_kind=head_anchor_kind,
    )


def _expected_supervisor_runtime_input_mounts(
    *,
    expected_database_secret_file: Path | None,
    expected_head_anchor_authority_file: Path | None,
    expected_head_anchor_auth_secret_file: Path | None,
    expected_head_anchor_signing_key_secret_file: Path | None,
) -> dict[str, tuple[Path | None, str, str | None, str]]:
    return {
        DATABASE_SECRET_RUNTIME_PATH: (
            expected_database_secret_file,
            DATABASE_SECRET_FILE_NAME,
            None,
            "database secret",
        ),
        HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH: (
            expected_head_anchor_authority_file,
            HEAD_ANCHOR_AUTHORITY_FILE_NAME,
            "authority",
            "head-anchor authority",
        ),
        HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH: (
            expected_head_anchor_auth_secret_file,
            HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
            "auth",
            "head-anchor Auth secret",
        ),
        HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH: (
            expected_head_anchor_signing_key_secret_file,
            HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
            "signing-key",
            "head-anchor signing-key secret",
        ),
    }


def _validate_state_volume_bind_string(value: object) -> None:
    if value != f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw":
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime state volume bind drifted"
        )


def _validate_host_mount_requests(
    host: Mapping[str, object],
    *,
    expected_service: str,
    expected_database_secret_file: Path | None,
    expected_head_anchor_authority_file: Path | None,
    expected_head_anchor_auth_secret_file: Path | None,
    expected_head_anchor_signing_key_secret_file: Path | None,
) -> None:
    raw_mounts = host.get("Mounts")
    mounts = [] if raw_mounts in (None, []) else list(_sequence(raw_mounts, "runtime mounts"))
    raw_binds = host.get("Binds")
    binds = [] if raw_binds in (None, []) else list(_string_sequence(raw_binds, "runtime binds"))
    volume_requests = [
        _mapping(item, "trusted-time runtime volume request")
        for item in mounts
        if type(item) is dict and item.get("Type") == "volume"
    ]
    bind_requests = [
        _mapping(item, "trusted-time runtime bind request")
        for item in mounts
        if type(item) is dict and item.get("Type") == "bind"
    ]
    if len(volume_requests) + len(bind_requests) != len(mounts):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime mount request type drifted"
        )
    source = expected_service == "chrony-nts"
    source_state_is_legacy_bind = source and len(volume_requests) == 1
    if len(volume_requests) != (1 if source_state_is_legacy_bind else (2 if source else 1)):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime volume request set drifted"
        )
    by_target = {request.get("Target"): request for request in volume_requests}
    if len(by_target) != len(volume_requests) or "/run/chrony" not in by_target:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime volume request set drifted"
        )
    _validate_mount_request(
        by_target["/run/chrony"],
        expected_source=COMPOSE_SOCKET_VOLUME_NAME,
        expected_target="/run/chrony",
        expected_nocopy=True,
    )
    if source:
        if bind_requests:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time source cannot receive bind mounts"
            )
        if source_state_is_legacy_bind:
            if set(by_target) != {"/run/chrony"} or len(binds) != 1:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time runtime volume request set drifted"
                )
            _validate_state_volume_bind_string(binds[0])
            return
        if set(by_target) != {"/run/chrony", "/var/lib/chrony"} or binds:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime volume request set drifted"
            )
        _validate_mount_request(
            by_target["/var/lib/chrony"],
            expected_source=COMPOSE_STATE_VOLUME_NAME,
            expected_target="/var/lib/chrony",
            expected_nocopy=False,
        )
        return
    if set(by_target) != {"/run/chrony"}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor volume request set drifted"
        )
    expected_inputs = _expected_supervisor_runtime_input_mounts(
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )
    if len(binds) + len(bind_requests) != len(expected_inputs):
        raise TrustedTimeSupervisorConfigurationError("trusted-time runtime input bind set drifted")
    observed_inputs: dict[str, object] = {}
    for value in binds:
        fields = value.rsplit(":", 2)
        if len(fields) != 3 or fields[1] in observed_inputs:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime input bind is malformed"
            )
        observed_inputs[fields[1]] = fields
    for request in bind_requests:
        target = request.get("Target")
        if type(target) is not str or target in observed_inputs:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime input bind is malformed"
            )
        observed_inputs[target] = request
    if set(observed_inputs) != set(expected_inputs):
        raise TrustedTimeSupervisorConfigurationError("trusted-time runtime input bind set drifted")
    for target, (expected_file, file_name, head_anchor_kind, label) in expected_inputs.items():
        observed = observed_inputs[target]
        source_path: object
        if type(observed) is list:
            fields = observed
            source_path = fields[0]
            read_only = fields[2] == "ro"
        else:
            request = _mapping(observed, "trusted-time runtime input bind request")
            source_path = request.get("Source")
            read_only = request.get("ReadOnly") is True
        if not read_only or not _runtime_input_source_is_approved(
            source_path,
            expected_file=expected_file,
            file_name=file_name,
            head_anchor_kind=head_anchor_kind,
        ):
            raise TrustedTimeSupervisorConfigurationError(f"trusted-time {label} bind drifted")


def _sequence(value: object, field_name: str) -> list[object]:
    if type(value) is not list:
        raise TrustedTimeSupervisorConfigurationError(f"{field_name} is malformed")
    return value


def _validate_runtime_mounts(
    value: object,
    *,
    expected_service: str,
) -> None:
    mounts = _sequence(value, "trusted-time runtime mounts")
    expected_targets = (
        {"/run/chrony", "/var/lib/chrony"}
        if expected_service == "chrony-nts"
        else {
            "/run/chrony",
            DATABASE_SECRET_RUNTIME_PATH,
            HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
            HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
            HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
        }
    )
    by_target: dict[str, Mapping[str, object]] = {}
    for raw_mount in mounts:
        mount = _mapping(raw_mount, "trusted-time runtime mount")
        target = mount.get("Destination")
        if type(target) is not str or target in by_target:
            raise TrustedTimeSupervisorConfigurationError("trusted-time runtime mount set drifted")
        by_target[target] = mount
    if set(by_target) != expected_targets or len(by_target) != len(mounts):
        raise TrustedTimeSupervisorConfigurationError("trusted-time runtime mount set drifted")
    socket_mount = by_target["/run/chrony"]
    if (
        socket_mount.get("Type") != "volume"
        or socket_mount.get("Name") != COMPOSE_SOCKET_VOLUME_NAME
        or socket_mount.get("RW") is not True
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time runtime socket mount drifted")
    if expected_service == "chrony-nts":
        state_mount = by_target["/var/lib/chrony"]
        if (
            state_mount.get("Type") != "volume"
            or state_mount.get("Name") != COMPOSE_STATE_VOLUME_NAME
            or state_mount.get("RW") is not True
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime state mount drifted"
            )
        return
    for target in expected_targets - {"/run/chrony"}:
        input_mount = by_target[target]
        if input_mount.get("Type") != "bind" or input_mount.get("RW") is not False:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime input mount drifted"
            )


def _validate_host_hardening(
    host: Mapping[str, object],
    *,
    expected_service: str,
    expected_database_secret_file: Path | None,
    expected_head_anchor_authority_file: Path | None,
    expected_head_anchor_auth_secret_file: Path | None,
    expected_head_anchor_signing_key_secret_file: Path | None,
) -> None:
    source = expected_service == "chrony-nts"
    if (
        host.get("ReadonlyRootfs") is not True
        or host.get("CapDrop") != ["ALL"]
        or host.get("CapAdd") not in (None, [])
        or host.get("SecurityOpt") not in (["no-new-privileges:true"], ["no-new-privileges"])
        or host.get("Privileged") is not False
        or host.get("PidsLimit") != (32 if source else 64)
        or host.get("NanoCpus") != (250_000_000 if source else 500_000_000)
        or host.get("Memory") != (67_108_864 if source else 268_435_456)
        or host.get("Init") is not True
        or host.get("NetworkMode") != COMPOSE_NETWORK_NAME
        or host.get("PublishAllPorts") is not False
        or host.get("PortBindings") not in (None, {})
        or host.get("Devices") not in (None, [])
        or host.get("DeviceCgroupRules") not in (None, [])
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime isolation or resource policy drifted"
        )
    expected_tmpfs = {
        "/tmp": (
            f"rw,noexec,nosuid,nodev,size={'8m' if source else '16m'},uid=10001,gid=10001,mode=0700"
        )
    }
    if host.get("Tmpfs") != expected_tmpfs:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime temporary filesystem drifted"
        )
    restart = _mapping(host.get("RestartPolicy"), "trusted-time runtime restart policy")
    if restart != {
        "Name": "unless-stopped" if source else "no",
        "MaximumRetryCount": 0,
    }:
        raise TrustedTimeSupervisorConfigurationError("trusted-time runtime restart policy drifted")
    _validate_host_mount_requests(
        host,
        expected_service=expected_service,
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )


def _validate_runtime_healthcheck(
    configuration: Mapping[str, object],
    *,
    expected_service: str,
) -> None:
    healthcheck = configuration.get("Healthcheck")
    if expected_service != "chrony-nts":
        if healthcheck not in (None, {}):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time supervisor healthcheck drifted"
            )
        return
    exact = _mapping(healthcheck, "trusted-time source healthcheck")
    if (
        exact.get("Test")
        != [
            "CMD",
            "/usr/bin/chronyc",
            "-h",
            "/run/chrony/chronyd.sock",
            "activity",
        ]
        or exact.get("Interval") != 2_000_000_000
        or exact.get("Timeout") != 1_000_000_000
        or exact.get("StartPeriod") != 2_000_000_000
        or exact.get("Retries") != 15
        or any(
            key not in {"Test", "Interval", "Timeout", "StartPeriod", "StartInterval", "Retries"}
            for key in exact
        )
        or exact.get("StartInterval", 0) != 0
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time source healthcheck drifted")


def validate_created_container(
    inspection: object,
    *,
    expected_image_id: str,
    expected_image_configuration: Mapping[str, object],
    expected_service: str,
    require_healthy: bool,
    expected_database_secret_file: Path | None = None,
    expected_head_anchor_authority_file: Path | None = None,
    expected_head_anchor_auth_secret_file: Path | None = None,
    expected_head_anchor_signing_key_secret_file: Path | None = None,
) -> None:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container inspection is malformed"
        )
    container = _mapping(inspection[0], "trusted-time created container")
    configuration = _mapping(container.get("Config"), "trusted-time container Config")
    host = _mapping(container.get("HostConfig"), "trusted-time container HostConfig")
    network_settings = _mapping(
        container.get("NetworkSettings"),
        "trusted-time container NetworkSettings",
    )
    networks = _mapping(
        network_settings.get("Networks"),
        "trusted-time container networks",
    )
    labels = _mapping(configuration.get("Labels"), "trusted-time container labels")
    state = _mapping(container.get("State"), "trusted-time container state")
    if (
        container.get("Image") != expected_image_id
        or labels.get("com.docker.compose.project") != "autoquanttrader-trusted-time"
        or labels.get("com.docker.compose.service") != expected_service
        or state.get("Running") is not True
        or state.get("Status") != "running"
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container identity or state drifted"
        )
    if set(networks) != {COMPOSE_NETWORK_NAME}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container network attachment drifted"
        )
    if expected_service not in {"chrony-nts", "trusted-time-supervisor"}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container service identity drifted"
        )
    for field_name in ("User", "Entrypoint", "Cmd", "WorkingDir", "ExposedPorts"):
        if configuration.get(field_name) != expected_image_configuration.get(field_name):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time created container command or image configuration drifted"
            )
    expected_environment = _environment_mapping(
        expected_image_configuration.get("Env"),
        "trusted-time admitted image environment",
    )
    if expected_service == "trusted-time-supervisor":
        expected_environment.update(_SUPERVISOR_RUNTIME_ENVIRONMENT)
    runtime_environment = _environment_mapping(
        configuration.get("Env"),
        "trusted-time runtime environment",
    )
    if runtime_environment != expected_environment:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime environment allowlist drifted"
        )
    _validate_runtime_healthcheck(configuration, expected_service=expected_service)
    _validate_host_hardening(
        host,
        expected_service=expected_service,
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )
    _validate_runtime_mounts(container.get("Mounts"), expected_service=expected_service)
    if require_healthy:
        health = _mapping(state.get("Health"), "trusted-time container health")
        if health.get("Status") != "healthy":
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time source container is not healthy"
            )


def _validate_runtime_path_metadata(
    container_id: str,
    *,
    path: str,
    expected: str,
    label: str,
    environment: Mapping[str, str],
) -> None:
    completed = _run_docker(
        (
            "docker",
            "container",
            "exec",
            "--user",
            "10001:10001",
            container_id,
            "/bin/stat",
            "-c",
            "%u:%g:%a",
            path,
        ),
        environment=environment,
    )
    if completed.returncode != 0 or completed.stderr or completed.stdout != f"{expected}\n":
        raise TrustedTimeSupervisorConfigurationError(f"{label} metadata drifted")


def _validate_chrony_state_directory(
    container_id: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> None:
    docker_environment = _minimal_docker_environment() if environment is None else dict(environment)
    metadata = _run_docker(
        (
            "docker",
            "container",
            "exec",
            "--user",
            "10001:10001",
            container_id,
            "/bin/stat",
            "-c",
            "%u:%g:%a",
            "/var/lib/chrony",
        ),
        environment=docker_environment,
    )
    if metadata.returncode != 0 or metadata.stderr:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Chrony state directory metadata drifted"
        )
    fields = metadata.stdout.strip().split(":")
    try:
        owner_uid, owner_gid, mode = int(fields[0]), int(fields[1]), int(fields[2], 8)
    except (IndexError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Chrony state directory metadata drifted"
        ) from None
    if (
        len(fields) != 3
        or owner_uid != 10001
        or owner_gid != 10001
        or mode & 0o700 != 0o700
        or mode & 0o022
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Chrony state directory metadata drifted"
        )
    for access_mode in ("-d", "-r", "-w", "-x"):
        accessible = _run_docker(
            (
                "docker",
                "container",
                "exec",
                "--user",
                "10001:10001",
                container_id,
                "/bin/busybox",
                "test",
                access_mode,
                "/var/lib/chrony",
            ),
            environment=docker_environment,
        )
        if accessible.returncode != 0 or accessible.stdout or accessible.stderr:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time Chrony state directory is not usable by the fixed runtime identity"
            )


def _validate_mounted_runtime_input(
    container_id: str,
    *,
    path: str,
    label: str,
    expected_size: int,
    expected_sha256: str,
    environment: Mapping[str, str],
    allow_retired_unreadable: bool = False,
) -> None:
    metadata = _run_docker(
        (
            "docker",
            "container",
            "exec",
            "--user",
            "10001:10001",
            container_id,
            "/bin/stat",
            "-c",
            "%u:%g:%a:%s",
            path,
        ),
        environment=environment,
    )
    digest = _run_docker(
        (
            "docker",
            "container",
            "exec",
            "--user",
            "10001:10001",
            container_id,
            "/usr/bin/sha256sum",
            path,
        ),
        environment=environment,
    )
    digest_is_exact = (
        digest.returncode == 0
        and not digest.stderr
        and digest.stdout == f"{expected_sha256}  {path}\n"
    )
    digest_is_retired = (
        allow_retired_unreadable
        and digest.returncode != 0
        and not digest.stdout
        and bool(digest.stderr)
    )
    if (
        metadata.returncode != 0
        or metadata.stderr
        or metadata.stdout != f"10001:10001:400:{expected_size}\n"
        or not (digest_is_exact or digest_is_retired)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            f"trusted-time mounted {label} differs from the held source"
        )


def _validate_mounted_database_secret(
    container_id: str,
    *,
    expected_size: int,
    expected_sha256: str,
    environment: Mapping[str, str],
    allow_retired_unreadable: bool = False,
) -> None:
    _validate_mounted_runtime_input(
        container_id,
        path=DATABASE_SECRET_RUNTIME_PATH,
        label="database secret",
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        environment=environment,
        allow_retired_unreadable=allow_retired_unreadable,
    )


def _validate_mounted_staged_inputs(
    container_id: str,
    *,
    database_secret: MaterializedDatabaseSecret,
    head_anchor_inputs: MaterializedHeadAnchorInputs,
    environment: Mapping[str, str],
    allow_retired_unreadable: bool = False,
) -> None:
    _validate_mounted_database_secret(
        container_id,
        expected_size=database_secret.size,
        expected_sha256=database_secret.sha256,
        environment=environment,
        allow_retired_unreadable=allow_retired_unreadable,
    )
    for materialized, path, label in (
        (
            head_anchor_inputs.authority,
            HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
            "head-anchor authority",
        ),
        (
            head_anchor_inputs.auth_secret,
            HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
            "head-anchor Auth secret",
        ),
        (
            head_anchor_inputs.signing_key,
            HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
            "head-anchor signing-key secret",
        ),
    ):
        _validate_mounted_runtime_input(
            container_id,
            path=path,
            label=label,
            expected_size=materialized.size,
            expected_sha256=materialized.sha256,
            environment=environment,
            allow_retired_unreadable=allow_retired_unreadable,
        )


def _wait_for_database_secret_consumption(
    container_id: str,
    *,
    environment: Mapping[str, str],
) -> None:
    deadline = time.monotonic() + 10
    while True:
        metadata = _run_docker(
            (
                "docker",
                "container",
                "exec",
                "--user",
                "10001:10001",
                container_id,
                "/bin/stat",
                "-c",
                "%u:%g:%a",
                DATABASE_SECRET_CONSUMED_PATH,
            ),
            environment=environment,
            timeout_seconds=2,
        )
        digest = _run_docker(
            (
                "docker",
                "container",
                "exec",
                "--user",
                "10001:10001",
                container_id,
                "/usr/bin/sha256sum",
                DATABASE_SECRET_CONSUMED_PATH,
            ),
            environment=environment,
            timeout_seconds=2,
        )
        if (
            metadata.returncode == 0
            and not metadata.stderr
            and metadata.stdout == "10001:10001:400\n"
            and digest.returncode == 0
            and not digest.stderr
            and digest.stdout
            == f"{DATABASE_SECRET_CONSUMED_SHA256}  {DATABASE_SECRET_CONSUMED_PATH}\n"
        ):
            return
        if time.monotonic() >= deadline:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time supervisor did not consume its database secret"
            )
        time.sleep(0.1)


def validate_live_trusted_time_topology(
    identities: TrustedTimeImageIdentities,
    *,
    source_container_id: str,
    supervisor_container_id: str,
    environment: Mapping[str, str],
    expected_database_secret_file: Path | None = None,
    expected_head_anchor_authority_file: Path | None = None,
    expected_head_anchor_auth_secret_file: Path | None = None,
    expected_head_anchor_signing_key_secret_file: Path | None = None,
) -> None:
    """Authenticate one running topology without reading its database secret."""

    if (
        type(identities) is not TrustedTimeImageIdentities
        or _CONTAINER_ID_PATTERN.fullmatch(source_container_id) is None
        or _CONTAINER_ID_PATTERN.fullmatch(supervisor_container_id) is None
        or source_container_id == supervisor_container_id
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time live topology identity is malformed"
        )
    docker_environment = dict(environment)
    if "AQT_TRUSTED_TIME_DATABASE_URL" in docker_environment:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time live topology inspection received a database secret"
        )
    validate_socket_volume_inspection(
        _inspect_volume(COMPOSE_SOCKET_VOLUME_NAME, environment=docker_environment),
        expected_name=COMPOSE_SOCKET_VOLUME_NAME,
    )
    validate_chrony_state_volume_inspection(
        _inspect_volume(COMPOSE_STATE_VOLUME_NAME, environment=docker_environment),
    )
    source_image_configuration = _inspect_image_configuration(
        identities.source_id,
        environment=docker_environment,
    )
    supervisor_image_configuration = _inspect_image_configuration(
        identities.supervisor_id,
        environment=docker_environment,
    )
    validate_created_container(
        _inspect_container(source_container_id, environment=docker_environment),
        expected_image_id=identities.source_id,
        expected_image_configuration=source_image_configuration,
        expected_service="chrony-nts",
        require_healthy=True,
        expected_database_secret_file=None,
    )
    validate_created_container(
        _inspect_container(supervisor_container_id, environment=docker_environment),
        expected_image_id=identities.supervisor_id,
        expected_image_configuration=supervisor_image_configuration,
        expected_service="trusted-time-supervisor",
        require_healthy=False,
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )
    for container_id in (source_container_id, supervisor_container_id):
        _validate_runtime_path_metadata(
            container_id,
            path="/run/chrony",
            expected="10001:10001:750",
            label="trusted-time socket command directory",
            environment=docker_environment,
        )
    for path, label in (
        (DATABASE_SECRET_RUNTIME_PATH, "trusted-time database secret mount"),
        (HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH, "trusted-time head-anchor authority mount"),
        (HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH, "trusted-time head-anchor Auth mount"),
        (
            HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
            "trusted-time head-anchor signing-key mount",
        ),
    ):
        _validate_runtime_path_metadata(
            supervisor_container_id,
            path=path,
            expected="10001:10001:400",
            label=label,
            environment=docker_environment,
        )
    _validate_chrony_state_directory(
        source_container_id,
        environment=docker_environment,
    )


def _validate_created_topology(
    identities: TrustedTimeImageIdentities,
    *,
    environment: Mapping[str, str],
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
) -> None:
    source_container_id = _compose_container_id("chrony-nts", environment=environment)
    supervisor_container_id = _compose_container_id(
        "trusted-time-supervisor",
        environment=environment,
    )
    validate_live_trusted_time_topology(
        identities,
        source_container_id=source_container_id,
        supervisor_container_id=supervisor_container_id,
        environment=_minimal_docker_environment(),
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )


def _stop_created_topology(environment: Mapping[str, str]) -> bool:
    try:
        completed = _run_docker(
            _compose_down_argv(),
            environment=environment,
            timeout_seconds=60,
        )
    except TrustedTimeSupervisorConfigurationError:
        return False
    return completed.returncode == 0


def _require_same_local_daemon(
    expected: LocalDockerDaemonIdentity,
    *,
    environment: Mapping[str, str],
) -> None:
    if qualify_local_docker_daemon(environment=environment) != expected:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time local Docker daemon identity changed during admission"
        )


def run_local_topology(
    *,
    env_file: Path,
    image_admission_artifact: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
) -> int:
    docker_environment = _minimal_docker_environment()
    daemon_identity = qualify_local_docker_daemon(environment=docker_environment)
    admission = build_verify_and_write_image_admission(image_admission_artifact)
    repeated_admission = load_image_admission_artifact(image_admission_artifact)
    if repeated_admission != admission:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time image admission artifact changed before launch"
        )
    identities = admission.identities
    compose_model = render_compose_model(
        source_image=identities.source_id,
        supervisor_image=identities.supervisor_id,
        database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        head_anchor_authority_file=PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
        head_anchor_auth_secret_file=PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
        head_anchor_signing_key_secret_file=(PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE),
    )
    validate_compose_model(
        compose_model,
        expected_source_image=identities.source_id,
        expected_supervisor_image=identities.supervisor_id,
        expected_database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        expected_head_anchor_authority_file=PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
        expected_head_anchor_auth_secret_file=PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
        expected_head_anchor_signing_key_secret_file=(
            PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
        ),
    )
    _require_same_local_daemon(daemon_identity, environment=docker_environment)
    if load_image_admission_artifact(image_admission_artifact) != admission:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time image admission artifact changed before secret load"
        )
    database_url = ""
    materialized_secret: MaterializedDatabaseSecret | None = None
    head_anchor_payloads: TrustedTimeHeadAnchorSourcePayloads | None = None
    materialized_head_anchor_inputs: MaterializedHeadAnchorInputs | None = None
    control_environment = dict(docker_environment)
    control_environment[SOURCE_IMAGE_ENVIRONMENT] = identities.source_id
    control_environment[SUPERVISOR_IMAGE_ENVIRONMENT] = identities.supervisor_id
    control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = ""
    control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = ""
    control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = ""
    control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = ""
    compose_attempted = False
    try:
        database_url = load_runtime_database_url(env_file)
        head_anchor_payloads = load_trusted_time_head_anchor_source_payloads(env_file)
        materialized_secret = materialize_database_secret(database_url)
        materialized_head_anchor_inputs = materialize_trusted_time_head_anchor_inputs(
            head_anchor_payloads
        )
        head_anchor_payloads = None
        validate_materialized_database_secret(materialized_secret)
        validate_materialized_trusted_time_head_anchor_inputs(materialized_head_anchor_inputs)
        compose_model = render_compose_model(
            source_image=identities.source_id,
            supervisor_image=identities.supervisor_id,
            database_secret_file=materialized_secret.path,
            head_anchor_authority_file=materialized_head_anchor_inputs.authority.path,
            head_anchor_auth_secret_file=(materialized_head_anchor_inputs.auth_secret.path),
            head_anchor_signing_key_secret_file=(materialized_head_anchor_inputs.signing_key.path),
        )
        validate_compose_model(
            compose_model,
            expected_source_image=identities.source_id,
            expected_supervisor_image=identities.supervisor_id,
            expected_database_secret_file=materialized_secret.path,
            expected_head_anchor_authority_file=(materialized_head_anchor_inputs.authority.path),
            expected_head_anchor_auth_secret_file=(
                materialized_head_anchor_inputs.auth_secret.path
            ),
            expected_head_anchor_signing_key_secret_file=(
                materialized_head_anchor_inputs.signing_key.path
            ),
        )
        validate_materialized_database_secret(materialized_secret)
        validate_materialized_trusted_time_head_anchor_inputs(materialized_head_anchor_inputs)
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = str(materialized_secret.path)
        control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = str(
            materialized_head_anchor_inputs.authority.path
        )
        control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = str(
            materialized_head_anchor_inputs.auth_secret.path
        )
        control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = str(
            materialized_head_anchor_inputs.signing_key.path
        )
        compose_attempted = True
        completed = _run_docker(
            compose_argv(),
            environment=control_environment,
            timeout_seconds=COMPOSE_WAIT_TIMEOUT_SECONDS + 60,
        )
        if completed.returncode != 0:
            if not _stop_created_topology(control_environment):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time failed topology could not be stopped"
                )
            compose_attempted = False
            _cleanup_materialized_runtime_inputs(
                database_secret=materialized_secret,
                head_anchor_inputs=materialized_head_anchor_inputs,
            )
            materialized_head_anchor_inputs = None
            materialized_secret = None
            return completed.returncode
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        _validate_created_topology(
            identities,
            environment=control_environment,
            expected_database_secret_file=materialized_secret.path,
            expected_head_anchor_authority_file=(materialized_head_anchor_inputs.authority.path),
            expected_head_anchor_auth_secret_file=(
                materialized_head_anchor_inputs.auth_secret.path
            ),
            expected_head_anchor_signing_key_secret_file=(
                materialized_head_anchor_inputs.signing_key.path
            ),
        )
        supervisor_container_id = _compose_container_id(
            "trusted-time-supervisor",
            environment=control_environment,
        )
        _validate_mounted_staged_inputs(
            supervisor_container_id,
            database_secret=materialized_secret,
            head_anchor_inputs=materialized_head_anchor_inputs,
            environment=control_environment,
        )
        _wait_for_database_secret_consumption(
            supervisor_container_id,
            environment=control_environment,
        )
        _validate_created_topology(
            identities,
            environment=control_environment,
            expected_database_secret_file=materialized_secret.path,
            expected_head_anchor_authority_file=(materialized_head_anchor_inputs.authority.path),
            expected_head_anchor_auth_secret_file=(
                materialized_head_anchor_inputs.auth_secret.path
            ),
            expected_head_anchor_signing_key_secret_file=(
                materialized_head_anchor_inputs.signing_key.path
            ),
        )
        _validate_mounted_staged_inputs(
            supervisor_container_id,
            database_secret=materialized_secret,
            head_anchor_inputs=materialized_head_anchor_inputs,
            environment=control_environment,
        )
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        retained_secret = materialized_secret
        retained_head_anchor_inputs = materialized_head_anchor_inputs
        _cleanup_materialized_runtime_inputs(
            database_secret=materialized_secret,
            head_anchor_inputs=materialized_head_anchor_inputs,
        )
        materialized_head_anchor_inputs = None
        materialized_secret = None
        _validate_mounted_staged_inputs(
            supervisor_container_id,
            database_secret=retained_secret,
            head_anchor_inputs=retained_head_anchor_inputs,
            environment=control_environment,
            allow_retired_unreadable=True,
        )
        _validate_created_topology(
            identities,
            environment=control_environment,
            expected_database_secret_file=retained_secret.path,
            expected_head_anchor_authority_file=(retained_head_anchor_inputs.authority.path),
            expected_head_anchor_auth_secret_file=(retained_head_anchor_inputs.auth_secret.path),
            expected_head_anchor_signing_key_secret_file=(
                retained_head_anchor_inputs.signing_key.path
            ),
        )
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        compose_attempted = False
        return 0
    except BaseException as primary_error:
        if compose_attempted and not _stop_created_topology(control_environment):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time unqualified topology could not be stopped"
            ) from primary_error
        try:
            _cleanup_materialized_runtime_inputs(
                database_secret=materialized_secret,
                head_anchor_inputs=materialized_head_anchor_inputs,
            )
        except Exception as cleanup_error:
            raise cleanup_error from primary_error
        materialized_secret = None
        materialized_head_anchor_inputs = None
        raise
    finally:
        control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = ""
        control_environment[SOURCE_IMAGE_ENVIRONMENT] = ""
        control_environment[SUPERVISOR_IMAGE_ENVIRONMENT] = ""
        head_anchor_payloads = None
        database_url = ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help=(
            "owner-only dotenv containing AQT_DATABASE_URL and the three absolute "
            "owner-only head-anchor source-file paths"
        ),
    )
    parser.add_argument(
        "--image-admission-artifact",
        type=Path,
        default=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        help="absolute owner-only image admission artifact below repository artifacts/",
    )
    arguments = parser.parse_args()
    try:
        return_code = run_local_topology(
            env_file=arguments.env_file,
            image_admission_artifact=arguments.image_admission_artifact,
        )
    except (
        TrustedTimeComposeVerificationError,
        TrustedTimeSupervisorConfigurationError,
        TrustedTimeImageVerificationError,
    ):
        print(_safe_payload("fatal", "launch_configuration_rejected"), flush=True)
        raise SystemExit(2) from None
    if return_code != 0:
        print(_safe_payload("fatal", "compose_start_failed"), flush=True)
        raise SystemExit(return_code)
    print(_safe_payload("started", "direct_operator_supervision_required"), flush=True)


if __name__ == "__main__":
    main()
