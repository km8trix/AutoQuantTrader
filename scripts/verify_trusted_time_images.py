"""Build and qualify the two Phase 6D trusted-time images by immutable ID."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
) -> Path:
    """Fail closed unless this CLI is executing canonical source in an isolated runtime."""

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
    """Require every loaded first-party module to originate at its exact source path."""

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
        expected_relative_path=Path("scripts/verify_trusted_time_images.py")
    )
    if __name__ == "__main__"
    else None
)

from scripts.bounded_subprocess import (  # noqa: E402
    BoundedSubprocessError,
    run_bounded_subprocess,
)

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)
CONFIG_SHA256 = hashlib.sha256(
    (ROOT / "infra" / "trusted-time" / "chrony.conf").read_bytes()
).hexdigest()
AUTHORITY_SHA256 = hashlib.sha256(
    (ROOT / "infra" / "trusted-time" / "source-authority.json").read_bytes()
).hexdigest()
DATABASE_CA_SHA256 = hashlib.sha256(
    (ROOT / "packages" / "persistence" / "certs" / "supabase-prod-ca-2021.crt").read_bytes()
).hexdigest()
COMPOSE_PATH = ROOT / "infra" / "compose" / "trusted-time.compose.yaml"
DEFAULTS_PATH = ROOT / "infra" / "compose" / "trusted-time.defaults.env"
SOURCE_IMAGE = "autoquanttrader-trusted-time-source:phase6d-v1"
SUPERVISOR_IMAGE = "autoquanttrader-trusted-time-supervisor:phase6d-v1"
SOURCE_IMAGE_ENVIRONMENT = "AQT_TRUSTED_TIME_SOURCE_IMAGE"
SUPERVISOR_IMAGE_ENVIRONMENT = "AQT_TRUSTED_TIME_SUPERVISOR_IMAGE"
DATABASE_SECRET_FILE_ENVIRONMENT = "AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"
IGNORED_ARTIFACT_ROOT = ROOT / "artifacts"
DEFAULT_IMAGE_ADMISSION_ARTIFACT = IGNORED_ARTIFACT_ROOT / "trusted-time" / "image-admission.json"
IMAGE_ADMISSION_CONTRACT_VERSION = "phase6d-trusted-time-image-admission-v2"
IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS = 900
MAXIMUM_IMAGE_ADMISSION_BYTES = 65_536
_MAXIMUM_GIT_REVISION_STDOUT_BYTES = 64
_MAXIMUM_GIT_STATUS_STDOUT_BYTES = 65_536
_MAXIMUM_GIT_TREE_STDOUT_BYTES = 8 * 1_024 * 1_024
_MAXIMUM_GIT_BATCH_STDOUT_BYTES = 64 * 1_024 * 1_024
_MAXIMUM_GIT_BATCH_STDIN_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_GIT_STDERR_BYTES = 16_384
_MAXIMUM_DOCKER_BUILD_STDOUT_BYTES = 128
_MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_DOCKER_INSPECTION_STDOUT_BYTES = 4 * 1_024 * 1_024
_MAXIMUM_DOCKER_STDERR_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_DOCKER_BUILD_CONTEXT_BYTES = 72 * 1_024 * 1_024
MIGRATION_PATH = ROOT / "migrations" / "versions" / "0036_phase6_trusted_time_head_anchors.py"
_TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH = "infra/docker/trusted-time.Dockerfile"
_TRUSTED_TIME_DOCKERFILE_FRONTEND = (
    b"# syntax=docker/dockerfile:1.7@sha256:"
    b"a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e\n"
)
_REVIEWED_FIXED_RELATIVE_PATHS = (
    ".dockerignore",
    "Makefile",
    "apps/__init__.py",
    "infra/compose/trusted-time.compose.yaml",
    "infra/compose/trusted-time.defaults.env",
    _TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH,
    "infra/docker/trusted-time.Dockerfile.dockerignore",
    "infra/trusted-time/chrony.conf",
    "infra/trusted-time/source-authority.json",
    "migrations/versions/0036_phase6_trusted_time_head_anchors.py",
    "pyproject.toml",
    "scripts/bounded_subprocess.py",
    "scripts/credential_env.py",
    "scripts/inspect_trusted_time_qualification.py",
    "scripts/start_trusted_time_supervisor.py",
    "scripts/verify_trusted_time_compose.py",
    "scripts/verify_trusted_time_images.py",
    "uv.lock",
)
_REVIEWED_DIRECTORY_RELATIVE_PATHS = (
    "apps/trusted_time_supervisor",
    "infra/trusted-time",
    "packages",
)
_TRUSTED_TIME_DOCKERIGNORE_BYTES = b"""\
**
!pyproject.toml
!uv.lock
!apps/
!apps/__init__.py
!apps/trusted_time_supervisor/
!apps/trusted_time_supervisor/**/
!apps/trusted_time_supervisor/**/*.py
!packages/
!packages/**/
!packages/**/*.py
!packages/persistence/certs/supabase-prod-ca-2021.crt
!infra/
!infra/trusted-time/
!infra/trusted-time/chrony.conf
!infra/trusted-time/source-authority.json
**/__pycache__
**/__pycache__/**
**/.hypothesis
**/.hypothesis/**
**/.mypy_cache
**/.mypy_cache/**
**/.pytest_cache
**/.pytest_cache/**
**/.ruff_cache
**/.ruff_cache/**
**/.venv
**/.venv/**
**/node_modules
**/node_modules/**
"""
_BUILD_CONTEXT_FIXED_RELATIVE_PATHS = frozenset(
    {
        "apps/__init__.py",
        _TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH,
        "infra/docker/trusted-time.Dockerfile.dockerignore",
        "infra/trusted-time/chrony.conf",
        "infra/trusted-time/source-authority.json",
        "packages/persistence/certs/supabase-prod-ca-2021.crt",
        "pyproject.toml",
        "uv.lock",
    }
)
EXPECTED_SCHEMA_REVISION = "0036_phase6_time_anchors"
EXPECTED_CATALOG_RELATIONS = (
    "phase6_trusted_time_head_anchor_intents",
    "phase6_trusted_time_head_anchor_receipts",
)
SUPERVISOR_APPLICATION_PYTHON = "/opt/venv/bin/python"
SOCKET_VOLUME_DRIVER_OPTIONS = {
    "type": "tmpfs",
    "device": "tmpfs",
    "o": "size=8m,uid=10001,gid=10001,mode=0750",
}
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_GIT_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_GIT_OBJECT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_BOOT_SESSION_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_BOOT_SESSION_ID_PATTERN = re.compile(
    r"(?:darwin|linux):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
_LINUX_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_DARWIN_BOOT_SESSION_COMMAND = (
    "/usr/sbin/sysctl",
    "-n",
    "kern.bootsessionuuid",
)
_CREATED_AT_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z"
)
_CHRONYD_VERSION_PATTERN = re.compile(
    r"chronyd \(chrony\) version 4\.8 \((?P<features>[+-][A-Z0-9_]+"
    r"(?: [+-][A-Z0-9_]+)*)\)\n?"
)
_CHRONYC_VERSION_PATTERN = re.compile(
    r"chronyc \(chrony\) version 4\.8 \([+-][A-Z0-9_]+"
    r"(?: [+-][A-Z0-9_]+)*\)\n?"
)
_PASSTHROUGH_ENVIRONMENT = frozenset(
    {
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "TERM",
        "TMPDIR",
        "XDG_CONFIG_HOME",
    }
)
_STATIC_ELF_CHECK = """\
import struct
import sys

path = "/usr/local/bin/chronyc"
try:
    payload = open(path, "rb").read()
    if len(payload) < 64 or payload[:4] != b"\\x7fELF" or payload[4] != 2:
        raise ValueError
    byte_order = "<" if payload[5] == 1 else ">" if payload[5] == 2 else None
    if byte_order is None:
        raise ValueError
    program_offset = struct.unpack_from(byte_order + "Q", payload, 32)[0]
    entry_size = struct.unpack_from(byte_order + "H", payload, 54)[0]
    entry_count = struct.unpack_from(byte_order + "H", payload, 56)[0]
    if entry_size < 56 or program_offset + entry_size * entry_count > len(payload):
        raise ValueError
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        if struct.unpack_from(byte_order + "I", payload, offset)[0] == 3:
            raise ValueError
except (OSError, struct.error, ValueError):
    sys.exit(1)
"""
_CA_STORE_CHECK = """\
import os
import sys

path = "/etc/ssl/certs/ca-certificates.crt"
try:
    metadata = os.stat(path, follow_symlinks=True)
except OSError:
    sys.exit(1)
sys.exit(0 if metadata.st_size > 0 else 1)
"""
_SCHEMA_CONTRACT_CHECK = """\
import json

from packages.persistence.database import EXPECTED_SCHEMA_REVISION
from packages.persistence.schema import metadata

relations = sorted(
    name
    for name in metadata.tables
    if name.startswith("phase6_trusted_time_head_anchor_")
)
print(
    json.dumps(
        {
            "catalog_relations": relations,
            "schema_revision": EXPECTED_SCHEMA_REVISION,
        },
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
)
"""


class TrustedTimeImageVerificationError(RuntimeError):
    """A built image differs from the reviewed evidence-only contract."""


def _canonical_boot_session_id(platform_name: str, encoded_uuid: bytes) -> str:
    if type(encoded_uuid) is not bytes:
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    if encoded_uuid.endswith(b"\n"):
        encoded_uuid = encoded_uuid[:-1]
    try:
        boot_uuid = encoded_uuid.decode("ascii").lower()
    except UnicodeDecodeError:
        raise TrustedTimeImageVerificationError(
            "trusted-time boot session identity is unavailable"
        ) from None
    if (
        platform_name not in {"darwin", "linux"}
        or _BOOT_SESSION_UUID_PATTERN.fullmatch(boot_uuid) is None
        or boot_uuid.replace("-", "") == "0" * 32
    ):
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    return f"{platform_name}:{boot_uuid}"


def _linux_boot_session_id() -> str:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            _LINUX_BOOT_ID_PATH,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        encoded_uuid = os.read(descriptor, 38)
        if os.read(descriptor, 1) != b"":
            raise OSError
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise OSError
    except OSError:
        raise TrustedTimeImageVerificationError(
            "trusted-time boot session identity is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return _canonical_boot_session_id("linux", encoded_uuid)


def _darwin_boot_session_id() -> str:
    try:
        completed = run_bounded_subprocess(
            _DARWIN_BOOT_SESSION_COMMAND,
            cwd=ROOT,
            environment={"LC_ALL": "C", "PATH": os.defpath},
            timeout_seconds=5,
            maximum_stdout_bytes=64,
            maximum_stderr_bytes=256,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time boot session identity is unavailable"
        ) from None
    if (
        completed.returncode != 0
        or type(completed.stdout) is not bytes
        or type(completed.stderr) is not bytes
        or completed.stderr != b""
    ):
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    return _canonical_boot_session_id("darwin", completed.stdout)


def _current_boot_session_id() -> str:
    """Return one strict, nonsecret identity for the current kernel boot."""

    if sys.platform == "linux":
        return _linux_boot_session_id()
    if sys.platform == "darwin":
        return _darwin_boot_session_id()
    raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")


@dataclass(frozen=True, slots=True)
class TrustedTimeImageIdentities:
    """Immutable Docker image IDs admitted as one source/supervisor pair."""

    source_id: str
    supervisor_id: str

    def __post_init__(self) -> None:
        if (
            _IMAGE_ID_PATTERN.fullmatch(self.source_id) is None
            or _IMAGE_ID_PATTERN.fullmatch(self.supervisor_id) is None
            or self.source_id == self.supervisor_id
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time immutable image identities are malformed"
            )


@dataclass(frozen=True, slots=True)
class TrustedTimeImageAdmission:
    """One canonical owner-only admission bound to reviewed source bytes."""

    path: Path
    identities: TrustedTimeImageIdentities
    boot_session_id: str
    git_revision: str
    source_revision_sha256: str
    artifact_sha256: str
    created_at_utc: str
    created_monotonic_ns: int

    def __post_init__(self) -> None:
        if (
            not self.path.is_absolute()
            or type(self.boot_session_id) is not str
            or _BOOT_SESSION_ID_PATTERN.fullmatch(self.boot_session_id) is None
            or self.boot_session_id.partition(":")[2].replace("-", "") == "0" * 32
            or _GIT_REVISION_PATTERN.fullmatch(self.git_revision) is None
            or _SHA256_PATTERN.fullmatch(self.source_revision_sha256) is None
            or _SHA256_PATTERN.fullmatch(self.artifact_sha256) is None
            or _CREATED_AT_PATTERN.fullmatch(self.created_at_utc) is None
            or type(self.created_monotonic_ns) is not int
            or self.created_monotonic_ns < 0
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact is malformed"
            )


@dataclass(frozen=True, slots=True)
class _ReviewedInputBindings:
    authority_sha256: str
    chrony_config_sha256: str
    compose_sha256: str
    database_ca_sha256: str
    dockerfile_sha256: str
    migration_sha256: str
    schema_revision: str
    catalog_relations: tuple[str, ...]
    source_revision_sha256: str
    uv_lock_sha256: str

    def payload(self) -> dict[str, object]:
        return {
            "authority_sha256": self.authority_sha256,
            "chrony_config_sha256": self.chrony_config_sha256,
            "compose_sha256": self.compose_sha256,
            "database_ca_sha256": self.database_ca_sha256,
            "dockerfile_sha256": self.dockerfile_sha256,
            "migration_sha256": self.migration_sha256,
            "schema_revision": self.schema_revision,
            "catalog_relations": list(self.catalog_relations),
            "source_revision_sha256": self.source_revision_sha256,
            "uv_lock_sha256": self.uv_lock_sha256,
        }


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise TrustedTimeImageVerificationError(f"{field_name} must be an object")
    return value


def _string_sequence(value: object, field_name: str) -> Sequence[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise TrustedTimeImageVerificationError(f"{field_name} must be a string list")
    return value


def _sequence(value: object, field_name: str) -> Sequence[object]:
    if type(value) is not list:
        raise TrustedTimeImageVerificationError(f"{field_name} must be a list")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact is malformed"
            )
        result[key] = value
    return result


def _stable_file_sha256(path: Path) -> str:
    try:
        if path.resolve(strict=True) != path:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input is unavailable"
        ) from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0:
            raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            observed != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed input changed during admission"
            )
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _reviewed_input_paths() -> tuple[Path, ...]:
    fixed = {ROOT / relative for relative in _REVIEWED_FIXED_RELATIVE_PATHS}
    for relative_directory in _REVIEWED_DIRECTORY_RELATIVE_PATHS:
        directory = ROOT / relative_directory
        try:
            candidates = tuple(directory.rglob("*"))
        except OSError:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed input is unavailable"
            ) from None
        for candidate in candidates:
            relative_parts = candidate.relative_to(ROOT).parts
            if (
                "__pycache__" in relative_parts
                or candidate.suffix == ".pyc"
                or candidate.name == ".DS_Store"
                or candidate.name == ".env"
                or (candidate.name.startswith(".env.") and candidate.name != ".env.example")
                or any(
                    part
                    in {
                        ".hypothesis",
                        ".mypy_cache",
                        ".pytest_cache",
                        ".ruff_cache",
                        ".venv",
                        "node_modules",
                    }
                    for part in relative_parts
                )
            ):
                continue
            if candidate.is_symlink():
                raise TrustedTimeImageVerificationError(
                    "trusted-time reviewed input cannot contain a symlink"
                )
            if candidate.is_file():
                fixed.add(candidate)
    return tuple(sorted(fixed, key=lambda item: item.relative_to(ROOT).as_posix()))


def reviewed_input_bindings() -> _ReviewedInputBindings:
    """Hash every reviewed input that can affect this admission boundary."""

    entries: list[dict[str, str]] = []
    hashes: dict[Path, str] = {}
    for path in _reviewed_input_paths():
        digest = _stable_file_sha256(path)
        hashes[path] = digest
        entries.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": digest,
            }
        )
    source_revision_sha256 = hashlib.sha256(
        _canonical_json_bytes(
            {
                "algorithm": "sha256-canonical-reviewed-path-manifest-v1",
                "files": entries,
            }
        )
    ).hexdigest()
    return _ReviewedInputBindings(
        authority_sha256=hashes[ROOT / "infra" / "trusted-time" / "source-authority.json"],
        chrony_config_sha256=hashes[ROOT / "infra" / "trusted-time" / "chrony.conf"],
        compose_sha256=hashes[ROOT / "infra" / "compose" / "trusted-time.compose.yaml"],
        database_ca_sha256=hashes[
            ROOT / "packages" / "persistence" / "certs" / "supabase-prod-ca-2021.crt"
        ],
        dockerfile_sha256=hashes[ROOT / "infra" / "docker" / "trusted-time.Dockerfile"],
        migration_sha256=hashes[MIGRATION_PATH],
        schema_revision=EXPECTED_SCHEMA_REVISION,
        catalog_relations=EXPECTED_CATALOG_RELATIONS,
        source_revision_sha256=source_revision_sha256,
        uv_lock_sha256=hashes[ROOT / "uv.lock"],
    )


def _absolute_artifact_path(path: Path, *, ignored_root: Path) -> tuple[Path, Path]:
    if not isinstance(path, Path) or not isinstance(ignored_root, Path):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        )
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if (
        not path.is_absolute()
        or absolute != path
        or not ignored_root.is_absolute()
        or root != ignored_root
        or absolute == root
        or not absolute.is_relative_to(root)
        or absolute.name in {"", ".", ".."}
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        )
    return absolute, root


def _open_owner_only_artifact_directory(
    path: Path,
    *,
    ignored_root: Path,
    create: bool,
) -> int:
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if absolute != path or (absolute != root and not absolute.is_relative_to(root)):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact directory is invalid"
        )
    try:
        descriptor = os.open(
            absolute.anchor,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact directory is invalid"
        ) from None
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            protected = current == root or current.is_relative_to(root)
            if protected and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                    created = True
                except FileExistsError:
                    created = False
            else:
                created = False
            next_descriptor = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                metadata = os.fstat(next_descriptor)
                if created:
                    os.fchmod(next_descriptor, 0o700)
                    metadata = os.fstat(next_descriptor)
                if protected and (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                    or not stat.S_ISDIR(metadata.st_mode)
                ):
                    raise TrustedTimeImageVerificationError(
                        "trusted-time image admission artifact directory is invalid"
                    )
                if created:
                    os.fsync(next_descriptor)
                    os.fsync(descriptor)
            except (OSError, TrustedTimeImageVerificationError):
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, TrustedTimeImageVerificationError):
        os.close(descriptor)
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact directory is invalid"
        ) from None


def _read_existing_owner_only_artifact(
    directory_descriptor: int,
    file_name: str,
    *,
    label: str,
) -> bytes | None:
    try:
        descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise TrustedTimeImageVerificationError(
            f"trusted-time image admission {label} is invalid"
        ) from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAXIMUM_IMAGE_ADMISSION_BYTES
        ):
            raise TrustedTimeImageVerificationError(
                f"trusted-time image admission {label} is invalid"
            )
        chunks: list[bytes] = []
        remaining = MAXIMUM_IMAGE_ADMISSION_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(encoded) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise TrustedTimeImageVerificationError(
                f"trusted-time image admission {label} is invalid"
            )
        return encoded
    finally:
        os.close(descriptor)


def _retain_content_addressed_image_admission(
    canonical_path: Path,
    encoded: bytes,
    *,
    ignored_root: Path,
) -> Path:
    """Create an immutable owner-only copy named by the exact artifact bytes."""

    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    archive = canonical_path.with_name(f"image-admission-{artifact_sha256}.json")
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    temporary_created = False
    temporary_name = f".{archive.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            archive.parent,
            ignored_root=ignored_root,
            create=True,
        )
        existing = _read_existing_owner_only_artifact(
            directory_descriptor,
            archive.name,
            label="archive",
        )
        if existing is not None:
            if existing != encoded:
                raise TrustedTimeImageVerificationError(
                    "trusted-time image admission archive is invalid"
                )
            return archive

        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.link(
            temporary_name,
            archive.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)
        return archive
    except TrustedTimeImageVerificationError:
        raise
    except (OSError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission archive write failed"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary_created and directory_descriptor is not None:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _validate_content_addressed_image_admission(
    canonical_path: Path,
    encoded: bytes,
    *,
    ignored_root: Path,
) -> None:
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    archive = canonical_path.with_name(f"image-admission-{artifact_sha256}.json")
    directory_descriptor: int | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            archive.parent,
            ignored_root=ignored_root,
            create=False,
        )
        existing = _read_existing_owner_only_artifact(
            directory_descriptor,
            archive.name,
            label="archive",
        )
        if existing != encoded:
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission archive is invalid"
            )
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _admission_payload(
    identities: TrustedTimeImageIdentities,
    bindings: _ReviewedInputBindings,
    *,
    boot_session_id: str,
    git_revision: str,
    created_at_utc: str,
    created_monotonic_ns: int,
) -> dict[str, object]:
    return {
        "authority_granted": False,
        "boot_session_id": boot_session_id,
        "contract_version": IMAGE_ADMISSION_CONTRACT_VERSION,
        "created_at_utc": created_at_utc,
        "created_monotonic_ns": created_monotonic_ns,
        "fresh_for_seconds": IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
        "git_revision": git_revision,
        "images": {
            "source_id": identities.source_id,
            "supervisor_id": identities.supervisor_id,
        },
        "inputs": bindings.payload(),
        "new_exposure_authorized": False,
        "service": "trusted-time-image-admission",
        "status": "admitted",
    }


def write_image_admission_artifact(
    path: Path,
    identities: TrustedTimeImageIdentities,
    *,
    git_revision: str,
    bindings: _ReviewedInputBindings | None = None,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    utc_now: datetime | None = None,
    monotonic_ns: int | None = None,
) -> TrustedTimeImageAdmission:
    """Atomically replace the canonical owner-only image admission artifact."""

    if type(identities) is not TrustedTimeImageIdentities:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission identities are invalid"
        )
    if type(git_revision) is not str or _GIT_REVISION_PATTERN.fullmatch(git_revision) is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission Git revision is invalid"
        )
    absolute, _ = _absolute_artifact_path(path, ignored_root=ignored_root)
    reviewed = reviewed_input_bindings() if bindings is None else bindings
    if type(reviewed) is not _ReviewedInputBindings:
        raise TrustedTimeImageVerificationError("trusted-time image admission inputs are invalid")
    observed_boot_session = _current_boot_session_id()
    observed_utc = datetime.now(UTC) if utc_now is None else utc_now
    observed_monotonic = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    if (
        type(observed_utc) is not datetime
        or observed_utc.tzinfo is None
        or observed_utc.utcoffset() != UTC.utcoffset(observed_utc)
        or type(observed_monotonic) is not int
        or observed_monotonic < 0
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission creation clock is invalid"
        )
    created_at = (
        observed_utc.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    encoded = _canonical_json_bytes(
        _admission_payload(
            identities,
            reviewed,
            boot_session_id=observed_boot_session,
            git_revision=git_revision,
            created_at_utc=created_at,
            created_monotonic_ns=observed_monotonic,
        )
    )
    if not encoded or len(encoded) > MAXIMUM_IMAGE_ADMISSION_BYTES:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )

    prior_directory_descriptor: int | None = None
    try:
        prior_directory_descriptor = _open_owner_only_artifact_directory(
            absolute.parent,
            ignored_root=ignored_root,
            create=True,
        )
        prior_encoded = _read_existing_owner_only_artifact(
            prior_directory_descriptor,
            absolute.name,
            label="artifact target",
        )
    finally:
        if prior_directory_descriptor is not None:
            os.close(prior_directory_descriptor)
    if prior_encoded is not None:
        _retain_content_addressed_image_admission(
            absolute,
            prior_encoded,
            ignored_root=ignored_root,
        )
    _retain_content_addressed_image_admission(
        absolute,
        encoded,
        ignored_root=ignored_root,
    )

    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    temporary_created = False
    temporary_name = f".{absolute.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute.parent,
            ignored_root=ignored_root,
            create=True,
        )
        if (
            _read_existing_owner_only_artifact(
                directory_descriptor,
                absolute.name,
                label="artifact target",
            )
            != prior_encoded
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact target is invalid"
            )
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.replace(
            temporary_name,
            absolute.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        temporary_created = False
        os.fsync(directory_descriptor)
    except TrustedTimeImageVerificationError:
        raise
    except (OSError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact write failed"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary_created and directory_descriptor is not None:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)

    if reviewed_input_bindings() != reviewed:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during admission"
        )
    admission = load_image_admission_artifact(
        absolute,
        ignored_root=ignored_root,
        monotonic_ns=observed_monotonic,
    )
    if (
        admission.identities != identities
        or admission.boot_session_id != observed_boot_session
        or admission.git_revision != git_revision
        or admission.source_revision_sha256 != reviewed.source_revision_sha256
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact changed during creation"
        )
    return admission


def _decode_admission_payload(
    payload: object,
    *,
    path: Path,
    artifact_sha256: str,
    boot_session_id: str,
    monotonic_ns: int,
) -> TrustedTimeImageAdmission:
    if (
        type(boot_session_id) is not str
        or _BOOT_SESSION_ID_PATTERN.fullmatch(boot_session_id) is None
        or boot_session_id.partition(":")[2].replace("-", "") == "0" * 32
    ):
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    root = _mapping(payload, "trusted-time image admission")
    if set(root) != {
        "authority_granted",
        "boot_session_id",
        "contract_version",
        "created_at_utc",
        "created_monotonic_ns",
        "fresh_for_seconds",
        "git_revision",
        "images",
        "inputs",
        "new_exposure_authorized",
        "service",
        "status",
    }:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    images = _mapping(root.get("images"), "trusted-time image admission images")
    inputs = _mapping(root.get("inputs"), "trusted-time image admission inputs")
    expected_inputs = reviewed_input_bindings()
    if (
        root.get("authority_granted") is not False
        or root.get("contract_version") != IMAGE_ADMISSION_CONTRACT_VERSION
        or root.get("fresh_for_seconds") != IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
        or root.get("new_exposure_authorized") is not False
        or root.get("service") != "trusted-time-image-admission"
        or root.get("status") != "admitted"
        or set(images) != {"source_id", "supervisor_id"}
        or set(inputs) != set(expected_inputs.payload())
        or inputs != expected_inputs.payload()
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    created_at = root.get("created_at_utc")
    created_monotonic = root.get("created_monotonic_ns")
    artifact_boot_session = root.get("boot_session_id")
    git_revision = root.get("git_revision")
    if (
        type(created_at) is not str
        or _CREATED_AT_PATTERN.fullmatch(created_at) is None
        or type(created_monotonic) is not int
        or type(artifact_boot_session) is not str
        or _BOOT_SESSION_ID_PATTERN.fullmatch(artifact_boot_session) is None
        or artifact_boot_session.partition(":")[2].replace("-", "") == "0" * 32
        or type(git_revision) is not str
        or _GIT_REVISION_PATTERN.fullmatch(git_revision) is None
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    if artifact_boot_session != boot_session_id:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact belongs to a different boot session"
        )
    if (
        created_monotonic < 0
        or type(monotonic_ns) is not int
        or monotonic_ns < created_monotonic
        or monotonic_ns - created_monotonic > IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    ):
        raise TrustedTimeImageVerificationError("trusted-time image admission artifact is stale")
    try:
        parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None
    if (
        parsed_created_at.tzinfo is None
        or parsed_created_at.utcoffset() != UTC.utcoffset(parsed_created_at)
        or parsed_created_at.isoformat(timespec="microseconds").replace("+00:00", "Z") != created_at
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    return TrustedTimeImageAdmission(
        path=path,
        identities=TrustedTimeImageIdentities(
            source_id=images.get("source_id"),  # type: ignore[arg-type]
            supervisor_id=images.get("supervisor_id"),  # type: ignore[arg-type]
        ),
        boot_session_id=artifact_boot_session,
        git_revision=git_revision,
        source_revision_sha256=expected_inputs.source_revision_sha256,
        artifact_sha256=artifact_sha256,
        created_at_utc=created_at,
        created_monotonic_ns=created_monotonic,
    )


def load_image_admission_artifact(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    monotonic_ns: int | None = None,
) -> TrustedTimeImageAdmission:
    """Read one canonical admission through an owner-only non-symlink descriptor."""

    absolute, _ = _absolute_artifact_path(path, ignored_root=ignored_root)
    observed_boot_session = _current_boot_session_id()
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute.parent,
            ignored_root=ignored_root,
            create=False,
        )
        file_descriptor = os.open(
            absolute.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAXIMUM_IMAGE_ADMISSION_BYTES
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact metadata is invalid"
            )
        chunks: list[bytes] = []
        remaining = MAXIMUM_IMAGE_ADMISSION_BYTES + 1
        while remaining:
            chunk = os.read(file_descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        after = os.fstat(file_descriptor)
        if (
            len(encoded) != before.st_size
            or len(encoded) > MAXIMUM_IMAGE_ADMISSION_BYTES
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact changed during read"
            )
    except TrustedTimeImageVerificationError:
        raise
    except OSError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is unavailable"
        ) from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    try:
        payload: Any = json.loads(encoded, object_pairs_hook=_unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None
    if _canonical_json_bytes(payload) != encoded:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is not canonical"
        )
    admission = _decode_admission_payload(
        payload,
        path=absolute,
        artifact_sha256=hashlib.sha256(encoded).hexdigest(),
        boot_session_id=observed_boot_session,
        monotonic_ns=time.monotonic_ns() if monotonic_ns is None else monotonic_ns,
    )
    _validate_content_addressed_image_admission(
        absolute,
        encoded,
        ignored_root=ignored_root,
    )
    return admission


def _config_from_inspection(inspection: object) -> Mapping[str, object]:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeImageVerificationError("Docker image inspection is malformed")
    image = _mapping(inspection[0], "Docker image inspection")
    return _mapping(image.get("Config"), "Docker image Config")


def _reject_embedded_secrets(configuration: Mapping[str, object]) -> None:
    environment = _string_sequence(configuration.get("Env"), "image environment")
    forbidden = (
        "ALPACA_",
        "ETRADE_",
        "AQT_DATABASE",
        "AQT_SUPABASE",
        "AQT_TEST_POSTGRES",
        "AQT_TRUSTED_TIME_DATABASE",
        "DATABASE_URL",
        "SENTRY_DSN",
    )
    if any(item.startswith(forbidden) for item in environment):
        raise TrustedTimeImageVerificationError("image environment embeds a secret reference")


def validate_source_inspection(inspection: object) -> None:
    configuration = _config_from_inspection(inspection)
    if configuration.get("User") != "10001:10001":
        raise TrustedTimeImageVerificationError("Chrony image user drifted")
    if configuration.get("Entrypoint") != ["/usr/sbin/chronyd"]:
        raise TrustedTimeImageVerificationError("Chrony image entrypoint drifted")
    if configuration.get("Cmd") != [
        "-x",
        "-d",
        "-U",
        "-f",
        "/etc/autoquant/trusted-time/chrony.conf",
    ]:
        raise TrustedTimeImageVerificationError("Chrony image command drifted")
    if configuration.get("ExposedPorts") not in (None, {}):
        raise TrustedTimeImageVerificationError("Chrony image cannot expose a port")
    _reject_embedded_secrets(configuration)


def validate_supervisor_inspection(inspection: object) -> None:
    configuration = _config_from_inspection(inspection)
    if configuration.get("User") != "10001:10001":
        raise TrustedTimeImageVerificationError("supervisor image user drifted")
    if configuration.get("Entrypoint") not in (None, []):
        raise TrustedTimeImageVerificationError("supervisor image entrypoint drifted")
    if configuration.get("Cmd") != ["autoquant-trusted-time-supervisor"]:
        raise TrustedTimeImageVerificationError("supervisor image command drifted")
    if configuration.get("ExposedPorts") not in (None, {}):
        raise TrustedTimeImageVerificationError("supervisor image cannot expose a port")
    _reject_embedded_secrets(configuration)


def validate_chronyd_version(returncode: int, stdout: str, stderr: str) -> None:
    output = stdout + stderr
    match = _CHRONYD_VERSION_PATTERN.fullmatch(output)
    if returncode != 0 or match is None or "+NTS" not in match.group("features").split():
        raise TrustedTimeImageVerificationError(
            "Chrony source image lacks exact NTS-enabled version 4.8"
        )


def validate_chronyc_version(returncode: int, stdout: str, stderr: str) -> None:
    output = stdout + stderr
    if returncode != 0 or _CHRONYC_VERSION_PATTERN.fullmatch(output) is None:
        raise TrustedTimeImageVerificationError(
            "supervisor image lacks exact Chrony client version 4.8"
        )


def validate_static_chronyc(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stdout or stderr:
        raise TrustedTimeImageVerificationError(
            "supervisor Chrony client has a dynamic ELF interpreter"
        )


def validate_ca_trust_store(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stdout or stderr:
        raise TrustedTimeImageVerificationError(
            "supervisor image lacks a nonempty system CA trust store"
        )


def validate_database_ca_metadata(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stderr or stdout != "0:0:444\n":
        raise TrustedTimeImageVerificationError("supervisor pinned database CA metadata drifted")


def validate_operational_schema_contract(
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    expected = json.dumps(
        {
            "catalog_relations": list(EXPECTED_CATALOG_RELATIONS),
            "schema_revision": EXPECTED_SCHEMA_REVISION,
        },
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if returncode != 0 or stderr or stdout != f"{expected}\n":
        raise TrustedTimeImageVerificationError("supervisor operational schema contract drifted")


def validate_config_hashes(
    *,
    source_output: str,
    supervisor_output: str,
) -> None:
    expected_source = f"{CONFIG_SHA256}  /etc/autoquant/trusted-time/chrony.conf\n"
    expected_supervisor = (
        expected_source
        + f"{AUTHORITY_SHA256}  /etc/autoquant/trusted-time/source-authority.json\n"
        + f"{DATABASE_CA_SHA256}  /etc/autoquant/trusted-time/supabase-prod-ca-2021.crt\n"
    )
    if source_output != expected_source or supervisor_output != expected_supervisor:
        raise TrustedTimeImageVerificationError("trusted-time protected image bytes drifted")


def validate_secretless_supervisor(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 2 or stderr:
        raise TrustedTimeImageVerificationError(
            "secretless supervisor did not fail closed and quietly"
        )
    try:
        payload: Any = json.loads(stdout)
    except json.JSONDecodeError:
        raise TrustedTimeImageVerificationError(
            "secretless supervisor returned malformed JSON"
        ) from None
    if payload != {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "exposure_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "reason": "configuration_rejected",
        "service": "trusted-time-supervisor",
        "status": "fatal",
    }:
        raise TrustedTimeImageVerificationError(
            "secretless supervisor response is not the exact blocked contract"
        )


def validate_socket_volume_inspection(
    inspection: object,
    *,
    expected_name: str,
) -> None:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeImageVerificationError(
            "trusted-time socket volume inspection is malformed"
        )
    volume = _mapping(inspection[0], "trusted-time socket volume inspection")
    if (
        volume.get("Name") != expected_name
        or volume.get("Driver") != "local"
        or volume.get("Options") != SOCKET_VOLUME_DRIVER_OPTIONS
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time socket volume is not the exact tmpfs contract"
        )


def _minimal_docker_environment(
    additions: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key in _PASSTHROUGH_ENVIRONMENT
    }
    if additions is not None:
        environment.update(additions)
    return environment


def _stable_reviewed_file_sha256(path: Path, *, required_mode: int) -> str:
    """Hash one exact-mode, single-link reviewed file through a stable descriptor."""

    if required_mode not in {0o644, 0o755}:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    try:
        if path.resolve(strict=True) != path:
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        ) from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != required_mode
            or before.st_nlink != 1
            or before.st_size < 0
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            observed != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _head_reviewed_input_entries(
    revision: str,
    *,
    environment: Mapping[str, str],
) -> Mapping[Path, tuple[int, str]]:
    """Resolve the exact regular-file modes and blob IDs tracked at one HEAD."""

    pathspecs = (*_REVIEWED_FIXED_RELATIVE_PATHS, *_REVIEWED_DIRECTORY_RELATIVE_PATHS)
    try:
        completed = run_bounded_subprocess(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                revision,
                "--",
                *pathspecs,
            ),
            cwd=ROOT,
            environment=environment,
            timeout_seconds=5,
            maximum_stdout_bytes=_MAXIMUM_GIT_TREE_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        ) from None
    if completed.returncode != 0 or completed.stderr or not completed.stdout.endswith(b"\0"):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    entries: dict[Path, tuple[int, str]] = {}
    for record in completed.stdout[:-1].split(b"\0"):
        metadata, separator, encoded_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or len(fields) != 3 or fields[1] != b"blob":
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        mode = 0o644 if fields[0] == b"100644" else 0o755 if fields[0] == b"100755" else 0
        try:
            object_id = fields[2].decode("ascii", errors="strict")
            relative = Path(os.fsdecode(encoded_path))
        except (UnicodeDecodeError, ValueError):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            ) from None
        path = ROOT / relative
        if (
            mode == 0
            or _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None
            or relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or path in entries
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        entries[path] = (mode, object_id)
    return entries


def _read_head_blob_payloads(
    object_ids: Sequence[str],
    *,
    environment: Mapping[str, str],
) -> Mapping[str, bytes]:
    """Fetch exact HEAD blobs through Git's object validator and bounded batch protocol."""

    unique_object_ids = tuple(sorted(set(object_ids)))
    if (
        not unique_object_ids
        or len(unique_object_ids) != len(set(unique_object_ids))
        or any(_GIT_OBJECT_ID_PATTERN.fullmatch(item) is None for item in unique_object_ids)
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    request = b"".join(item.encode("ascii") + b"\n" for item in unique_object_ids)
    try:
        completed = run_bounded_subprocess(
            ("git", "-c", "core.fsmonitor=false", "cat-file", "--batch"),
            cwd=ROOT,
            environment=environment,
            timeout_seconds=10,
            maximum_stdout_bytes=_MAXIMUM_GIT_BATCH_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
            stdin_bytes=request,
            maximum_stdin_bytes=_MAXIMUM_GIT_BATCH_STDIN_BYTES,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        ) from None
    maximum_total_bytes = _MAXIMUM_GIT_BATCH_STDOUT_BYTES
    maximum_file_bytes = 8 * 1_024 * 1_024
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > maximum_total_bytes:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    payloads: dict[str, bytes] = {}
    offset = 0
    for requested_object_id in unique_object_ids:
        header_end = completed.stdout.find(b"\n", offset, offset + 256)
        if header_end < 0:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        header = completed.stdout[offset:header_end].split(b" ")
        if len(header) != 3 or header[1] != b"blob":
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        try:
            observed_object_id = header[0].decode("ascii", errors="strict")
            encoded_size = header[2].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            ) from None
        if (
            observed_object_id != requested_object_id
            or not encoded_size.isascii()
            or not encoded_size.isdecimal()
            or (len(encoded_size) > 1 and encoded_size.startswith("0"))
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        size = int(encoded_size)
        content_start = header_end + 1
        content_end = content_start + size
        if (
            size > maximum_file_bytes
            or content_end >= len(completed.stdout)
            or completed.stdout[content_end : content_end + 1] != b"\n"
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        payloads[requested_object_id] = completed.stdout[content_start:content_end]
        offset = content_end + 1
    if offset != len(completed.stdout):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    return payloads


def _head_reviewed_input_snapshot(
    revision: str,
    *,
    environment: Mapping[str, str],
) -> Mapping[Path, tuple[int, bytes]]:
    """Return exact Git-validated bytes and modes for the reviewed HEAD tree."""

    entries = _head_reviewed_input_entries(revision, environment=environment)
    payloads = _read_head_blob_payloads(
        tuple(object_id for _, object_id in entries.values()),
        environment=environment,
    )
    return {path: (mode, payloads[object_id]) for path, (mode, object_id) in entries.items()}


def _head_reviewed_input_payload(
    revision: str,
    relative_path: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> bytes:
    """Return one allowlisted reviewed file directly from the exact Git object."""

    if (
        _GIT_REVISION_PATTERN.fullmatch(revision) is None
        or relative_path not in _REVIEWED_FIXED_RELATIVE_PATHS
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed Git payload is unavailable")
    snapshot = _head_reviewed_input_snapshot(
        revision,
        environment=(_minimal_git_environment() if environment is None else dict(environment)),
    )
    item = snapshot.get(ROOT / relative_path)
    if item is None:
        raise TrustedTimeImageVerificationError("trusted-time reviewed Git payload is unavailable")
    return item[1]


def _require_ordinary_git_index_flags(*, environment: Mapping[str, str]) -> None:
    """Reject assume-unchanged and skip-worktree state anywhere in the index."""

    try:
        completed = run_bounded_subprocess(
            ("git", "-c", "core.fsmonitor=false", "ls-files", "-v", "-z"),
            cwd=ROOT,
            environment=environment,
            timeout_seconds=5,
            maximum_stdout_bytes=_MAXIMUM_GIT_TREE_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision is unavailable"
        ) from None
    records = completed.stdout[:-1].split(b"\0") if completed.stdout.endswith(b"\0") else []
    if (
        completed.returncode != 0
        or completed.stderr
        or not records
        or any(not record.startswith(b"H ") for record in records)
    ):
        raise TrustedTimeImageVerificationError("trusted-time clean Git revision is unavailable")


def _require_head_reviewed_inputs(
    revision: str,
    *,
    environment: Mapping[str, str],
) -> None:
    """Require the current reviewed/build inputs to be exact raw HEAD blobs."""

    current_paths = _reviewed_input_paths()
    expected = _head_reviewed_input_snapshot(revision, environment=environment)
    if set(current_paths) != set(expected):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    for path in current_paths:
        required_mode, expected_payload = expected[path]
        if (
            _stable_reviewed_file_sha256(
                path,
                required_mode=required_mode,
            )
            != hashlib.sha256(expected_payload).hexdigest()
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )


def _minimal_git_environment() -> dict[str, str]:
    """Return the fixed secretless environment for Git object and tree reads."""

    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": "/tmp",
    }


def _decode_bounded_subprocess(
    completed: subprocess.CompletedProcess[bytes],
) -> subprocess.CompletedProcess[str]:
    """Decode one bounded command without accepting replacement characters."""

    return subprocess.CompletedProcess(
        completed.args,
        completed.returncode,
        completed.stdout.decode("utf-8", errors="strict"),
        completed.stderr.decode("utf-8", errors="strict"),
    )


def _current_clean_git_revision() -> str:
    """Resolve one stable commit with a clean tree and exact tracked inputs."""

    environment = _minimal_git_environment()
    revision_argv = (
        "git",
        "-c",
        "core.fsmonitor=false",
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
    )
    status_argv = (
        "git",
        "-c",
        "core.fsmonitor=false",
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
        "--ignore-submodules=none",
    )

    def run_git(
        argv: tuple[str, ...],
        *,
        maximum_stdout_bytes: int,
    ) -> subprocess.CompletedProcess[str]:
        return _decode_bounded_subprocess(
            run_bounded_subprocess(
                argv,
                cwd=ROOT,
                environment=environment,
                timeout_seconds=2,
                maximum_stdout_bytes=maximum_stdout_bytes,
                maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
            )
        )

    try:
        before = run_git(
            revision_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_REVISION_STDOUT_BYTES,
        )
        status_result = run_git(
            status_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_STATUS_STDOUT_BYTES,
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision is unavailable"
        ) from None
    revision = before.stdout.strip()
    if (
        before.returncode != 0
        or before.stderr
        or before.stdout != f"{revision}\n"
        or _GIT_REVISION_PATTERN.fullmatch(revision) is None
        or status_result.returncode != 0
        or status_result.stdout
        or status_result.stderr
    ):
        raise TrustedTimeImageVerificationError("trusted-time clean Git revision is unavailable")
    _require_ordinary_git_index_flags(environment=environment)
    _require_head_reviewed_inputs(revision, environment=environment)
    try:
        after_status_result = run_git(
            status_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_STATUS_STDOUT_BYTES,
        )
        after = run_git(
            revision_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_REVISION_STDOUT_BYTES,
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision is unavailable"
        ) from None
    if (
        after_status_result.returncode != 0
        or after_status_result.stdout
        or after_status_result.stderr
        or after.returncode != 0
        or after.stderr
        or after.stdout != f"{revision}\n"
    ):
        raise TrustedTimeImageVerificationError("trusted-time clean Git revision is unavailable")
    return revision


def _sealed_head_build_context(revision: str) -> bytes:
    """Create one deterministic Docker tar context only from validated HEAD blobs."""

    if _GIT_REVISION_PATTERN.fullmatch(revision) is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    snapshot = _head_reviewed_input_snapshot(
        revision,
        environment=_minimal_git_environment(),
    )
    selected: dict[str, tuple[int, bytes]] = {}
    for path, item in snapshot.items():
        relative = path.relative_to(ROOT).as_posix()
        if (
            relative in _BUILD_CONTEXT_FIXED_RELATIVE_PATHS
            or (relative.startswith("apps/trusted_time_supervisor/") and relative.endswith(".py"))
            or (relative.startswith("packages/") and relative.endswith(".py"))
        ):
            selected[relative] = item
    if not _BUILD_CONTEXT_FIXED_RELATIVE_PATHS.issubset(selected):
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    dockerfile = selected.get(_TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH)
    if dockerfile is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    _validate_trusted_time_dockerfile_frontend(dockerfile[1])
    total_payload_bytes = sum(len(payload) for _, payload in selected.values())
    if not selected or total_payload_bytes > 64 * 1_024 * 1_024:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    directory_names: set[str] = set()
    for relative in selected:
        parent = Path(relative).parent
        while parent != Path("."):
            directory_names.add(parent.as_posix())
            parent = parent.parent
    stream = io.BytesIO()
    try:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for directory_name in sorted(
                directory_names,
                key=lambda item: (item.count("/"), item),
            ):
                info = tarfile.TarInfo(f"{directory_name}/")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info)
            for relative in sorted(selected):
                mode, payload = selected[relative]
                info = tarfile.TarInfo(relative)
                info.type = tarfile.REGTYPE
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    except (OSError, tarfile.TarError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        ) from None
    encoded = stream.getvalue()
    if not encoded or len(encoded) > 72 * 1_024 * 1_024:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    return encoded


def _validate_trusted_time_dockerfile_frontend(payload: bytes) -> None:
    """Require the exact content-addressed Dockerfile frontend directive."""

    if (
        type(payload) is not bytes
        or not payload.startswith(_TRUSTED_TIME_DOCKERFILE_FRONTEND)
        or payload.count(b"# syntax=") != 1
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time Dockerfile frontend is not content-addressed"
        )


def _docker(
    *arguments: str,
    timeout_seconds: float = 60,
    environment: Mapping[str, str] | None = None,
    stdin_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    process_environment = (
        _minimal_docker_environment() if environment is None else dict(environment)
    )
    maximum_stdout_bytes = (
        _MAXIMUM_DOCKER_BUILD_STDOUT_BYTES
        if arguments[:1] == ("build",)
        else (
            _MAXIMUM_DOCKER_INSPECTION_STDOUT_BYTES
            if "inspect" in arguments
            else _MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES
        )
    )
    try:
        if stdin_bytes is not None and (
            type(stdin_bytes) is not bytes or len(stdin_bytes) > _MAXIMUM_DOCKER_BUILD_CONTEXT_BYTES
        ):
            raise BoundedSubprocessError("bounded subprocess contract is invalid")
        completed = run_bounded_subprocess(
            ("docker", *arguments),
            cwd=ROOT,
            environment=process_environment,
            timeout_seconds=timeout_seconds,
            maximum_stdout_bytes=maximum_stdout_bytes,
            maximum_stderr_bytes=_MAXIMUM_DOCKER_STDERR_BYTES,
            stdin_bytes=stdin_bytes,
            maximum_stdin_bytes=(0 if stdin_bytes is None else _MAXIMUM_DOCKER_BUILD_CONTEXT_BYTES),
        )
        return _decode_bounded_subprocess(completed)
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError("Docker is unavailable") from None


def _inspection(
    image_id: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> object:
    completed = _docker("image", "inspect", image_id, environment=environment)
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeImageVerificationError("trusted-time image inspection failed")
    try:
        inspected: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image inspection returned malformed JSON"
        ) from None
    return inspected


def resolve_image_id(
    image_reference: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    completed = _docker(
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        image_reference,
        environment=environment,
    )
    image_id = completed.stdout.strip()
    if (
        completed.returncode != 0
        or completed.stderr
        or completed.stdout != f"{image_id}\n"
        or _IMAGE_ID_PATTERN.fullmatch(image_id) is None
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image tag did not resolve to one immutable image ID"
        )
    return image_id


def build_trusted_time_images(
    git_revision: str,
    *,
    docker_environment: Mapping[str, str] | None = None,
) -> TrustedTimeImageIdentities:
    """Build both fixed targets from one immutable Git-object-derived context."""

    environment = (
        _minimal_docker_environment() if docker_environment is None else dict(docker_environment)
    )
    context = _sealed_head_build_context(git_revision)
    built_ids: list[str] = []
    for target, image in (
        ("chrony-source", SOURCE_IMAGE),
        ("trusted-time-supervisor", SUPERVISOR_IMAGE),
    ):
        completed = _docker(
            "build",
            "--quiet",
            "--file",
            "infra/docker/trusted-time.Dockerfile",
            "--target",
            target,
            "--tag",
            image,
            "-",
            timeout_seconds=1_800,
            environment=environment,
            stdin_bytes=context,
        )
        image_id = completed.stdout.strip()
        if (
            completed.returncode != 0
            or completed.stderr
            or completed.stdout != f"{image_id}\n"
            or _IMAGE_ID_PATTERN.fullmatch(image_id) is None
        ):
            raise TrustedTimeImageVerificationError("trusted-time image build failed")
        built_ids.append(image_id)
    return TrustedTimeImageIdentities(
        source_id=built_ids[0],
        supervisor_id=built_ids[1],
    )


def _validate_trusted_time_dockerignore_contract(payload: bytes | None = None) -> None:
    """Require the trusted-time Dockerfile's deny-by-default context allowlist."""

    observed_sha256 = (
        _stable_file_sha256(ROOT / "infra" / "docker" / "trusted-time.Dockerfile.dockerignore")
        if payload is None
        else hashlib.sha256(payload).hexdigest()
    )
    if observed_sha256 != hashlib.sha256(_TRUSTED_TIME_DOCKERIGNORE_BYTES).hexdigest():
        raise TrustedTimeImageVerificationError(
            "trusted-time Docker build-context contract was rejected"
        )


def validate_prebuild_compose_contract(
    *,
    git_revision: str,
    docker_environment: Mapping[str, str],
) -> None:
    """Admit the fixed context and secretless Compose model before build."""

    from scripts.verify_trusted_time_compose import (
        PLACEHOLDER_DATABASE_SECRET_FILE,
        TrustedTimeComposeVerificationError,
        render_compose_model,
        validate_compose_model,
    )

    compose_payload = _head_reviewed_input_payload(
        git_revision,
        "infra/compose/trusted-time.compose.yaml",
    )
    dockerignore_payload = _head_reviewed_input_payload(
        git_revision,
        "infra/docker/trusted-time.Dockerfile.dockerignore",
    )
    _validate_trusted_time_dockerignore_contract(dockerignore_payload)
    try:
        model = render_compose_model(
            source_image=SOURCE_IMAGE,
            supervisor_image=SUPERVISOR_IMAGE,
            database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
            compose_payload=compose_payload,
            docker_environment=docker_environment,
        )
        validate_compose_model(
            model,
            expected_source_image=SOURCE_IMAGE,
            expected_supervisor_image=SUPERVISOR_IMAGE,
            expected_database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        )
    except TrustedTimeComposeVerificationError:
        raise TrustedTimeImageVerificationError(
            "trusted-time prebuild Compose contract was rejected"
        ) from None


def _run_read_only(
    image: str,
    *command: str,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return _docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "10001:10001",
        "--entrypoint",
        command[0],
        image,
        *command[1:],
        environment=environment,
    )


def _validate_source_probe_inspection(
    inspection: object,
    *,
    image_id: str,
    volume_name: str,
) -> None:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeImageVerificationError("source topology inspection is malformed")
    container = _mapping(inspection[0], "source topology inspection")
    configuration = _mapping(container.get("Config"), "source topology Config")
    host = _mapping(container.get("HostConfig"), "source topology HostConfig")
    if container.get("Image") != image_id or configuration.get("User") != "10001:10001":
        raise TrustedTimeImageVerificationError("source topology image or identity drifted")
    if (
        host.get("NetworkMode") != "none"
        or host.get("ReadonlyRootfs") is not True
        or host.get("CapDrop") != ["ALL"]
        or host.get("SecurityOpt") != ["no-new-privileges"]
    ):
        raise TrustedTimeImageVerificationError("source topology isolation drifted")
    if host.get("Binds") not in (None, []):
        raise TrustedTimeImageVerificationError("source topology cannot use bind mounts")
    tmpfs = _mapping(host.get("Tmpfs"), "source topology tmpfs")
    if tmpfs != {
        "/tmp": "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700",
        "/var/lib/chrony": ("rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"),
    }:
        raise TrustedTimeImageVerificationError("source topology tmpfs contract drifted")
    mount_requests = _sequence(host.get("Mounts"), "source topology mount requests")
    if len(mount_requests) != 1:
        raise TrustedTimeImageVerificationError("source topology mount request set drifted")
    mount_request = _mapping(mount_requests[0], "source topology mount request")
    volume_options = _mapping(
        mount_request.get("VolumeOptions"),
        "source topology volume options",
    )
    if (
        mount_request.get("Type") != "volume"
        or mount_request.get("Source") != volume_name
        or mount_request.get("Target") != "/run/chrony"
        or volume_options.get("NoCopy") is not True
    ):
        raise TrustedTimeImageVerificationError("source topology mount request drifted")
    mounts = _sequence(container.get("Mounts"), "source topology mounts")
    command_mounts = [
        _mapping(mount, "source topology mount")
        for mount in mounts
        if type(mount) is dict and mount.get("Destination") == "/run/chrony"
    ]
    if len(command_mounts) != 1 or not (
        command_mounts[0].get("Type") == "volume"
        and command_mounts[0].get("Name") == volume_name
        and command_mounts[0].get("RW") is True
    ):
        raise TrustedTimeImageVerificationError("source topology socket volume drifted")


def _parse_json_output(
    completed: subprocess.CompletedProcess[str],
    *,
    label: str,
) -> object:
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeImageVerificationError(f"{label} failed")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise TrustedTimeImageVerificationError(f"{label} returned malformed JSON") from None


def _require_activity(completed: subprocess.CompletedProcess[str], *, label: str) -> None:
    if completed.returncode != 0 or completed.stderr or not completed.stdout.strip():
        raise TrustedTimeImageVerificationError(f"{label} could not use the shared socket")


def _named_container_absent(
    container_name: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> bool:
    try:
        completed = _docker(
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name=^/{container_name}$",
            environment=environment,
        )
    except TrustedTimeImageVerificationError:
        return False
    return completed.returncode == 0 and not completed.stderr and not completed.stdout


def _named_volume_absent(
    volume_name: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> bool:
    try:
        completed = _docker(
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{volume_name}$",
            environment=environment,
        )
    except TrustedTimeImageVerificationError:
        return False
    return completed.returncode == 0 and not completed.stderr and not completed.stdout


def _probe_runtime_topology(
    source_id: str,
    supervisor_id: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> None:
    token = secrets.token_hex(16)
    resource_prefix = f"aqt-trusted-time-admission-{token}"
    volume_name = f"{resource_prefix}-socket"
    source_name = f"{resource_prefix}-source"
    volume_create_attempted = False
    source_run_attempted = False
    primary_error: BaseException | None = None
    try:
        volume_create_attempted = True
        volume = _docker(
            "volume",
            "create",
            "--driver",
            "local",
            "--label",
            f"com.autoquanttrader.trusted-time-admission={token}",
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            "o=size=8m,uid=10001,gid=10001,mode=0750",
            volume_name,
            environment=environment,
        )
        if volume.returncode != 0 or volume.stderr or volume.stdout != f"{volume_name}\n":
            raise TrustedTimeImageVerificationError(
                "trusted-time socket probe volume creation failed"
            )
        validate_socket_volume_inspection(
            _parse_json_output(
                _docker("volume", "inspect", volume_name, environment=environment),
                label="trusted-time socket probe volume inspection",
            ),
            expected_name=volume_name,
        )

        source_run_attempted = True
        source = _docker(
            "run",
            "--detach",
            "--pull=never",
            "--name",
            source_name,
            "--label",
            f"com.autoquanttrader.trusted-time-admission={token}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--pids-limit",
            "32",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700",
            "--tmpfs",
            ("/var/lib/chrony:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"),
            "--mount",
            f"type=volume,source={volume_name},destination=/run/chrony,volume-nocopy",
            source_id,
            environment=environment,
        )
        if source.returncode != 0 or source.stderr or not source.stdout.strip():
            raise TrustedTimeImageVerificationError("trusted-time source socket probe failed")

        source_inspection = _parse_json_output(
            _docker("container", "inspect", source_name, environment=environment),
            label="trusted-time source topology inspection",
        )
        _validate_source_probe_inspection(
            source_inspection,
            image_id=source_id,
            volume_name=volume_name,
        )

        directory = _docker(
            "container",
            "exec",
            "--user",
            "10001:10001",
            source_name,
            "/bin/stat",
            "-c",
            "%u:%g:%a",
            "/run/chrony",
            environment=environment,
        )
        if directory.returncode != 0 or directory.stderr or directory.stdout != "10001:10001:750\n":
            raise TrustedTimeImageVerificationError(
                "trusted-time socket command directory permissions drifted"
            )

        deadline = time.monotonic() + 10
        while True:
            activity = _docker(
                "container",
                "exec",
                "--user",
                "10001:10001",
                source_name,
                "/usr/bin/chronyc",
                "-h",
                "/run/chrony/chronyd.sock",
                "activity",
                timeout_seconds=2,
                environment=environment,
            )
            if activity.returncode == 0 and not activity.stderr and activity.stdout.strip():
                break
            if time.monotonic() >= deadline:
                raise TrustedTimeImageVerificationError(
                    "trusted-time source command socket did not become responsive"
                )
            time.sleep(0.1)

        supervisor_activity = _docker(
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--mount",
            f"type=volume,source={volume_name},destination=/run/chrony,volume-nocopy",
            "--entrypoint",
            "/usr/local/bin/chronyc",
            supervisor_id,
            "-h",
            "/run/chrony/chronyd.sock",
            "activity",
            environment=environment,
        )
        _require_activity(supervisor_activity, label="trusted-time supervisor client")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_failed = False
        if source_run_attempted:
            try:
                removed_source = _docker(
                    "container",
                    "rm",
                    "--force",
                    source_name,
                    environment=environment,
                )
            except TrustedTimeImageVerificationError:
                cleanup_failed = True
            else:
                cleanup_failed = (
                    removed_source.returncode != 0 or bool(removed_source.stderr)
                ) and not _named_container_absent(
                    source_name,
                    environment=environment,
                )
        if volume_create_attempted:
            try:
                removed_volume = _docker(
                    "volume",
                    "rm",
                    volume_name,
                    environment=environment,
                )
            except TrustedTimeImageVerificationError:
                cleanup_failed = True
            else:
                volume_cleanup_failed = (
                    removed_volume.returncode != 0 or bool(removed_volume.stderr)
                ) and not _named_volume_absent(
                    volume_name,
                    environment=environment,
                )
                cleanup_failed = cleanup_failed or volume_cleanup_failed
        if cleanup_failed:
            cleanup_error = TrustedTimeImageVerificationError(
                "trusted-time topology probe cleanup failed"
            )
            if primary_error is None:
                raise cleanup_error
            raise cleanup_error from primary_error


def verify_images(
    source_image: str = SOURCE_IMAGE,
    supervisor_image: str = SUPERVISOR_IMAGE,
    *,
    docker_environment: Mapping[str, str] | None = None,
) -> TrustedTimeImageIdentities:
    """Verify one pair using only the exact Docker environment when supplied."""

    environment = (
        _minimal_docker_environment() if docker_environment is None else dict(docker_environment)
    )
    identities = TrustedTimeImageIdentities(
        source_id=resolve_image_id(source_image, environment=environment),
        supervisor_id=resolve_image_id(supervisor_image, environment=environment),
    )
    validate_source_inspection(_inspection(identities.source_id, environment=environment))
    validate_supervisor_inspection(_inspection(identities.supervisor_id, environment=environment))

    chronyd = _run_read_only(
        identities.source_id,
        "/usr/sbin/chronyd",
        "-v",
        environment=environment,
    )
    validate_chronyd_version(chronyd.returncode, chronyd.stdout, chronyd.stderr)
    chronyc = _run_read_only(
        identities.supervisor_id,
        "/usr/local/bin/chronyc",
        "-v",
        environment=environment,
    )
    validate_chronyc_version(chronyc.returncode, chronyc.stdout, chronyc.stderr)
    static_chronyc = _run_read_only(
        identities.supervisor_id,
        "/usr/local/bin/python",
        "-c",
        _STATIC_ELF_CHECK,
        environment=environment,
    )
    validate_static_chronyc(
        static_chronyc.returncode,
        static_chronyc.stdout,
        static_chronyc.stderr,
    )
    ca_store = _run_read_only(
        identities.supervisor_id,
        "/usr/local/bin/python",
        "-c",
        _CA_STORE_CHECK,
        environment=environment,
    )
    validate_ca_trust_store(ca_store.returncode, ca_store.stdout, ca_store.stderr)
    database_ca_metadata = _run_read_only(
        identities.supervisor_id,
        "/usr/bin/stat",
        "-c",
        "%u:%g:%a",
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
        environment=environment,
    )
    validate_database_ca_metadata(
        database_ca_metadata.returncode,
        database_ca_metadata.stdout,
        database_ca_metadata.stderr,
    )
    schema_contract = _run_read_only(
        identities.supervisor_id,
        SUPERVISOR_APPLICATION_PYTHON,
        "-c",
        _SCHEMA_CONTRACT_CHECK,
        environment=environment,
    )
    validate_operational_schema_contract(
        schema_contract.returncode,
        schema_contract.stdout,
        schema_contract.stderr,
    )

    source_hashes = _run_read_only(
        identities.source_id,
        "/usr/bin/sha256sum",
        "/etc/autoquant/trusted-time/chrony.conf",
        environment=environment,
    )
    supervisor_hashes = _run_read_only(
        identities.supervisor_id,
        "/usr/bin/sha256sum",
        "/etc/autoquant/trusted-time/chrony.conf",
        "/etc/autoquant/trusted-time/source-authority.json",
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
        environment=environment,
    )
    if (
        source_hashes.returncode != 0
        or source_hashes.stderr
        or supervisor_hashes.returncode != 0
        or supervisor_hashes.stderr
    ):
        raise TrustedTimeImageVerificationError("trusted-time image hash read failed")
    validate_config_hashes(
        source_output=source_hashes.stdout,
        supervisor_output=supervisor_hashes.stdout,
    )

    secretless = _docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        identities.supervisor_id,
        environment=environment,
    )
    validate_secretless_supervisor(
        secretless.returncode,
        secretless.stdout,
        secretless.stderr,
    )
    _probe_runtime_topology(
        identities.source_id,
        identities.supervisor_id,
        environment=environment,
    )
    return identities


def build_and_verify_images() -> TrustedTimeImageIdentities:
    git_revision = _current_clean_git_revision()
    docker_environment = _minimal_docker_environment()
    before = reviewed_input_bindings()
    validate_prebuild_compose_contract(
        git_revision=git_revision,
        docker_environment=docker_environment,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before image build"
        )
    built_identities = build_trusted_time_images(
        git_revision,
        docker_environment=docker_environment,
    )
    identities = verify_images(
        built_identities.source_id,
        built_identities.supervisor_id,
        docker_environment=docker_environment,
    )
    if identities != built_identities:
        raise TrustedTimeImageVerificationError(
            "trusted-time built image identities changed before verification"
        )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image build"
        )
    if _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision changed during image build"
        )
    return identities


def build_verify_and_write_image_admission(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> TrustedTimeImageAdmission:
    """Freshly build, fully verify, and atomically bind one immutable pair."""

    _absolute_artifact_path(path, ignored_root=ignored_root)
    git_revision = _current_clean_git_revision()
    docker_environment = _minimal_docker_environment()
    before = reviewed_input_bindings()
    validate_prebuild_compose_contract(
        git_revision=git_revision,
        docker_environment=docker_environment,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before image build"
        )
    built_identities = build_trusted_time_images(
        git_revision,
        docker_environment=docker_environment,
    )
    identities = verify_images(
        built_identities.source_id,
        built_identities.supervisor_id,
        docker_environment=docker_environment,
    )
    if identities != built_identities:
        raise TrustedTimeImageVerificationError(
            "trusted-time built image identities changed before verification"
        )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image build"
        )
    if _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision changed during image build"
        )
    admission = write_image_admission_artifact(
        path,
        identities,
        git_revision=git_revision,
        bindings=before,
        ignored_root=ignored_root,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image admission"
        )
    if _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision changed during image admission"
        )
    return admission


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build",
        action="store_true",
        help="build and admit the fixed nonsecret targets",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        default=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        help=(
            "absolute owner-only artifact path below the repository artifacts root; "
            "used only with --build"
        ),
    )
    parser.add_argument("source_image", nargs="?", default=SOURCE_IMAGE)
    parser.add_argument("supervisor_image", nargs="?", default=SUPERVISOR_IMAGE)
    arguments = parser.parse_args()
    if arguments.build and (
        arguments.source_image != SOURCE_IMAGE or arguments.supervisor_image != SUPERVISOR_IMAGE
    ):
        parser.error("--build is limited to the fixed Phase 6D build tags")
    if not arguments.build and arguments.artifact != DEFAULT_IMAGE_ADMISSION_ARTIFACT:
        parser.error("--artifact requires --build")
    if arguments.build:
        admission = build_verify_and_write_image_admission(arguments.artifact)
        identities = admission.identities
        artifact_sha256: str | None = admission.artifact_sha256
        boot_session_id: str | None = admission.boot_session_id
        git_revision: str | None = admission.git_revision
    else:
        identities = verify_images(arguments.source_image, arguments.supervisor_image)
        artifact_sha256 = None
        boot_session_id = None
        git_revision = None
    print(
        json.dumps(
            {
                "artifact_sha256": artifact_sha256,
                "boot_session_id": boot_session_id,
                "git_revision": git_revision,
                "images": [identities.source_id, identities.supervisor_id],
                "new_exposure_authorized": False,
                "service": "trusted-time-image-verifier",
                "status": "admitted",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
