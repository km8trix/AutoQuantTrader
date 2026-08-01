"""Build and qualify the two Phase 6D trusted-time images by immutable ID."""

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
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
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
IMAGE_ADMISSION_CONTRACT_VERSION = "phase6d-trusted-time-image-admission-v1"
IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS = 900
MAXIMUM_IMAGE_ADMISSION_BYTES = 65_536
MIGRATION_PATH = ROOT / "migrations" / "versions" / "0036_phase6_trusted_time_head_anchors.py"
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
    source_revision_sha256: str
    artifact_sha256: str
    created_at_utc: str
    created_monotonic_ns: int

    def __post_init__(self) -> None:
        if (
            not self.path.is_absolute()
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
    fixed = {
        ROOT / ".dockerignore",
        ROOT / "apps" / "__init__.py",
        ROOT / "infra" / "compose" / "trusted-time.compose.yaml",
        ROOT / "infra" / "compose" / "trusted-time.defaults.env",
        ROOT / "infra" / "docker" / "trusted-time.Dockerfile",
        ROOT / "infra" / "trusted-time" / "chrony.conf",
        ROOT / "infra" / "trusted-time" / "source-authority.json",
        MIGRATION_PATH,
        ROOT / "pyproject.toml",
        ROOT / "scripts" / "inspect_trusted_time_qualification.py",
        ROOT / "scripts" / "start_trusted_time_supervisor.py",
        ROOT / "scripts" / "verify_trusted_time_compose.py",
        ROOT / "scripts" / "verify_trusted_time_images.py",
        ROOT / "uv.lock",
    }
    for directory in (ROOT / "apps" / "trusted_time_supervisor", ROOT / "packages"):
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
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if created:
                os.fchmod(descriptor, 0o700)
                metadata = os.fstat(descriptor)
            if protected and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise TrustedTimeImageVerificationError(
                    "trusted-time image admission artifact directory is invalid"
                )
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
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
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
    created_at_utc: str,
    created_monotonic_ns: int,
) -> dict[str, object]:
    return {
        "authority_granted": False,
        "contract_version": IMAGE_ADMISSION_CONTRACT_VERSION,
        "created_at_utc": created_at_utc,
        "created_monotonic_ns": created_monotonic_ns,
        "fresh_for_seconds": IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
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
    absolute, _ = _absolute_artifact_path(path, ignored_root=ignored_root)
    reviewed = reviewed_input_bindings() if bindings is None else bindings
    if type(reviewed) is not _ReviewedInputBindings:
        raise TrustedTimeImageVerificationError("trusted-time image admission inputs are invalid")
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
    if admission.identities != identities or admission.source_revision_sha256 != (
        reviewed.source_revision_sha256
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
    monotonic_ns: int,
) -> TrustedTimeImageAdmission:
    root = _mapping(payload, "trusted-time image admission")
    if set(root) != {
        "authority_granted",
        "contract_version",
        "created_at_utc",
        "created_monotonic_ns",
        "fresh_for_seconds",
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
    if (
        type(created_at) is not str
        or _CREATED_AT_PATTERN.fullmatch(created_at) is None
        or type(created_monotonic) is not int
        or created_monotonic < 0
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
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
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
        key: value
        for key, value in os.environ.items()
        if key in _PASSTHROUGH_ENVIRONMENT or key.startswith("LC_")
    }
    if additions is not None:
        environment.update(additions)
    return environment


def _docker(
    *arguments: str,
    timeout_seconds: float = 60,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *arguments],
            cwd=ROOT,
            env=_minimal_docker_environment(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise TrustedTimeImageVerificationError("Docker is unavailable") from None


def _inspection(image_id: str) -> object:
    completed = _docker("image", "inspect", image_id)
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeImageVerificationError("trusted-time image inspection failed")
    try:
        inspected: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image inspection returned malformed JSON"
        ) from None
    return inspected


def resolve_image_id(image_reference: str) -> str:
    completed = _docker("image", "inspect", "--format", "{{.Id}}", image_reference)
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


def build_trusted_time_images() -> None:
    completed = _docker(
        "compose",
        "--env-file",
        str(DEFAULTS_PATH),
        "--file",
        str(COMPOSE_PATH),
        "build",
        timeout_seconds=1_800,
        environment={
            DATABASE_SECRET_FILE_ENVIRONMENT: "/dev/null",
            SOURCE_IMAGE_ENVIRONMENT: SOURCE_IMAGE,
            SUPERVISOR_IMAGE_ENVIRONMENT: SUPERVISOR_IMAGE,
        },
    )
    if completed.returncode != 0:
        raise TrustedTimeImageVerificationError("trusted-time image build failed")


def validate_prebuild_compose_contract() -> None:
    """Admit the fixed-tag, secretless Compose model before it can build."""

    from scripts.verify_trusted_time_compose import (
        PLACEHOLDER_DATABASE_SECRET_FILE,
        TrustedTimeComposeVerificationError,
        render_compose_model,
        validate_compose_model,
    )

    try:
        model = render_compose_model(
            source_image=SOURCE_IMAGE,
            supervisor_image=SUPERVISOR_IMAGE,
            database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
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


def _run_read_only(image: str, *command: str) -> subprocess.CompletedProcess[str]:
    return _docker(
        "run",
        "--rm",
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


def _named_container_absent(container_name: str) -> bool:
    try:
        completed = _docker(
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name=^/{container_name}$",
        )
    except TrustedTimeImageVerificationError:
        return False
    return completed.returncode == 0 and not completed.stderr and not completed.stdout


def _named_volume_absent(volume_name: str) -> bool:
    try:
        completed = _docker(
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{volume_name}$",
        )
    except TrustedTimeImageVerificationError:
        return False
    return completed.returncode == 0 and not completed.stderr and not completed.stdout


def _probe_runtime_topology(source_id: str, supervisor_id: str) -> None:
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
        )
        if volume.returncode != 0 or volume.stderr or volume.stdout != f"{volume_name}\n":
            raise TrustedTimeImageVerificationError(
                "trusted-time socket probe volume creation failed"
            )
        validate_socket_volume_inspection(
            _parse_json_output(
                _docker("volume", "inspect", volume_name),
                label="trusted-time socket probe volume inspection",
            ),
            expected_name=volume_name,
        )

        source_run_attempted = True
        source = _docker(
            "run",
            "--detach",
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
        )
        if source.returncode != 0 or source.stderr or not source.stdout.strip():
            raise TrustedTimeImageVerificationError("trusted-time source socket probe failed")

        source_inspection = _parse_json_output(
            _docker("container", "inspect", source_name),
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
        )
        _require_activity(supervisor_activity, label="trusted-time supervisor client")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_failed = False
        if source_run_attempted:
            try:
                removed_source = _docker("container", "rm", "--force", source_name)
            except TrustedTimeImageVerificationError:
                cleanup_failed = True
            else:
                cleanup_failed = (
                    removed_source.returncode != 0 or bool(removed_source.stderr)
                ) and not _named_container_absent(source_name)
        if volume_create_attempted:
            try:
                removed_volume = _docker("volume", "rm", volume_name)
            except TrustedTimeImageVerificationError:
                cleanup_failed = True
            else:
                volume_cleanup_failed = (
                    removed_volume.returncode != 0 or bool(removed_volume.stderr)
                ) and not _named_volume_absent(volume_name)
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
) -> TrustedTimeImageIdentities:
    identities = TrustedTimeImageIdentities(
        source_id=resolve_image_id(source_image),
        supervisor_id=resolve_image_id(supervisor_image),
    )
    validate_source_inspection(_inspection(identities.source_id))
    validate_supervisor_inspection(_inspection(identities.supervisor_id))

    chronyd = _run_read_only(identities.source_id, "/usr/sbin/chronyd", "-v")
    validate_chronyd_version(chronyd.returncode, chronyd.stdout, chronyd.stderr)
    chronyc = _run_read_only(identities.supervisor_id, "/usr/local/bin/chronyc", "-v")
    validate_chronyc_version(chronyc.returncode, chronyc.stdout, chronyc.stderr)
    static_chronyc = _run_read_only(
        identities.supervisor_id,
        "/usr/local/bin/python",
        "-c",
        _STATIC_ELF_CHECK,
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
    )
    validate_ca_trust_store(ca_store.returncode, ca_store.stdout, ca_store.stderr)
    database_ca_metadata = _run_read_only(
        identities.supervisor_id,
        "/usr/bin/stat",
        "-c",
        "%u:%g:%a",
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
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
    )
    supervisor_hashes = _run_read_only(
        identities.supervisor_id,
        "/usr/bin/sha256sum",
        "/etc/autoquant/trusted-time/chrony.conf",
        "/etc/autoquant/trusted-time/source-authority.json",
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
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
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        identities.supervisor_id,
    )
    validate_secretless_supervisor(
        secretless.returncode,
        secretless.stdout,
        secretless.stderr,
    )
    _probe_runtime_topology(identities.source_id, identities.supervisor_id)
    return identities


def build_and_verify_images() -> TrustedTimeImageIdentities:
    before = reviewed_input_bindings()
    validate_prebuild_compose_contract()
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before image build"
        )
    build_trusted_time_images()
    identities = verify_images()
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image build"
        )
    return identities


def build_verify_and_write_image_admission(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> TrustedTimeImageAdmission:
    """Freshly build, fully verify, and atomically bind one immutable pair."""

    before = reviewed_input_bindings()
    validate_prebuild_compose_contract()
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before image build"
        )
    build_trusted_time_images()
    identities = verify_images()
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image build"
        )
    admission = write_image_admission_artifact(
        path,
        identities,
        bindings=before,
        ignored_root=ignored_root,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image admission"
        )
    return admission


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build",
        action="store_true",
        help="build the fixed nonsecret tags before resolving and admitting them",
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
    else:
        identities = verify_images(arguments.source_image, arguments.supervisor_image)
        artifact_sha256 = None
    print(
        json.dumps(
            {
                "artifact_sha256": artifact_sha256,
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
