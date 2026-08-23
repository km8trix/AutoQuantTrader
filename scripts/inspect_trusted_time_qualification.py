"""Inspect one live evidence-only trusted-time qualification window.

The inspector reads only the fixed Phase 6C host from runtime PostgreSQL.  It
does not expose database coordinates, credentials, absolute observation times,
or raw Chrony output, and it grants no trading or control authority.
"""

# ruff: noqa: E402 -- the CLI bootstrap must run before third-party/first-party imports.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from decimal import Decimal
from itertools import pairwise
from pathlib import Path
from typing import Any, cast


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
        expected_relative_path=Path("scripts/inspect_trusted_time_qualification.py")
    )
    if __name__ == "__main__"
    else None
)

import sqlalchemy as sa
from sqlalchemy import Connection, Engine, make_url
from sqlalchemy.engine import RowMapping

from apps.trusted_time_supervisor.config import (
    MAXIMUM_AUTHORITY_BYTES,
    MAXIMUM_CHRONY_CONFIG_BYTES,
    MAXIMUM_DATABASE_CA_BYTES,
    TrustedTimeDeploymentAuthority,
    TrustedTimeSupervisorConfigurationError,
    decode_trusted_time_authority,
)
from packages.application.trusted_time_monitor import TrustedTimeProbeStatus
from packages.domain.trusted_time import TrustedTimeHealth, TrustedTimeReason
from packages.persistence.database import EXPECTED_SCHEMA_REVISION, verify_operational_schema
from packages.persistence.postgres_tls import (
    PostgresTLSConfigurationError,
    pinned_verify_full_connect_args,
)
from packages.persistence.schema import (
    phase6_trusted_time_epoch_registrations,
    phase6_trusted_time_host_heads,
    phase6_trusted_time_probe_evaluations,
)
from packages.persistence.trusted_time import verify_trusted_time_integrity
from scripts.bounded_subprocess import BoundedSubprocessError, run_bounded_subprocess
from scripts.credential_env import load_owner_only_environment
from scripts.start_trusted_time_supervisor import (
    LocalDockerDaemonIdentity,
    _validate_live_trusted_time_topology_ids,
    qualify_local_docker_daemon,
)
from scripts.verify_local_paper_smoke_preflight import (
    LocalPaperSmokePreflightError,
    validate_supabase_session_database_url,
)
from scripts.verify_trusted_time_images import (
    DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    TrustedTimeImageVerificationError,
    _load_current_image_admission_snapshot,
    _require_current_admission_snapshot,
    _require_verified_images,
    _verify_images_with_manifest,
)

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)
AUTHORITY_PATH = ROOT / "infra" / "trusted-time" / "source-authority.json"
CHRONY_CONFIG_PATH = ROOT / "infra" / "trusted-time" / "chrony.conf"
DATABASE_CA_PATH = ROOT / "packages" / "persistence" / "certs" / "supabase-prod-ca-2021.crt"
IGNORED_ARTIFACT_ROOT = ROOT / "artifacts"
HOST_ID = "local-paper-docker-primary-v1"
CONTRACT_VERSION = "phase6c-live-trusted-time-qualification-inspection-v5"
_CURRENT_SOURCE_ID = "chrony-nts-cloudflare-system76-virginia-v2"
_MAXIMUM_DOCKER_STDOUT_BYTES = 2 * 1_024 * 1_024
_MAXIMUM_DOCKER_STDERR_BYTES = 262_144
_CURRENT_SOURCE_AUTHORITY_SHA256 = (
    "9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c"
)
_CURRENT_CHRONY_CONFIG_SHA256 = "5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23"
_CURRENT_DATABASE_CA_SHA256 = "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"
_SOURCE_AUTHORITY_GENERATIONS = (
    (
        "chrony-nts-cloudflare-netnod-v1",
        "356723c84e30478f18ad99f3cfef2ee65b3bdd3fc26936a7d5c9910fd1bcb3ab",
    ),
    (_CURRENT_SOURCE_ID, _CURRENT_SOURCE_AUTHORITY_SHA256),
)
DEFAULT_MINIMUM_EVALUATIONS = 4
MAXIMUM_OWNER_ENVIRONMENT_BYTES = 65_536
MAXIMUM_ARTIFACT_BYTES = 65_536
DATABASE_CONNECT_TIMEOUT_SECONDS = 3
DATABASE_STATEMENT_TIMEOUT_MILLISECONDS = 3_000
DATABASE_LOCK_TIMEOUT_MILLISECONDS = 1_000
DATABASE_POOL_TIMEOUT_SECONDS = 3.0
MAXIMUM_SIGNED_BIGINT = 9_223_372_036_854_775_807
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_LINUX_TIME_NAMESPACE = re.compile(r"^time:\[[1-9][0-9]{0,19}\]$")
_LINUX_BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ZERO_TIME_NAMESPACE_OFFSETS_OUTPUT = re.compile(
    r"\Amonotonic[ \t]+0[ \t]+0\nboottime[ \t]+0[ \t]+0\n\Z",
    re.ASCII,
)
_PROC_PROCESS_STATES = frozenset("RSDZTtWXxKPI")
_DOCKER_STARTED_AT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:[.][0-9]{1,9})?Z$"
)
_AUTHORITY_FLAGS = (
    "alert_delivery",
    "automatic_rearm",
    "external_head_anchor",
    "live_trading",
    "new_exposure",
    "operational_control",
    "paper_trading",
    "readiness",
)
_DOCKER_ENVIRONMENT_ALLOWLIST = frozenset(
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

type EngineFactory = Callable[[str], Engine]
type BoottimeClock = Callable[[RunningImageIds], int]
type EvidenceRow = Mapping[str, object] | RowMapping
type TimeNamespaceOffsets = tuple[tuple[str, int, int], tuple[str, int, int]]

_ZERO_TIME_NAMESPACE_OFFSETS: TimeNamespaceOffsets = (
    ("monotonic", 0, 0),
    ("boottime", 0, 0),
)
_PID1_CLOCK_IDENTITY_SCRIPT = """\
set -f
[ "$#" -eq 0 ] || exit 40
[ /proc/1/ns/time -ef /proc/1/ns/time_for_children ] || exit 41
[ /proc/self/ns/time -ef /proc/1/ns/time ] || exit 42
IFS= read -r pid1_stat < /proc/1/stat || exit 43
printf '%s\n' 'pid1-stat-v1' "$pid1_stat" 'pid1-offsets-v1'
while IFS= read -r line; do printf '%s\n' "$line"; done < /proc/1/timens_offsets
printf '%s\n' 'reader-offsets-v1'
while IFS= read -r line; do printf '%s\n' "$line"; done < /proc/self/timens_offsets
"""
_BOOTTIME_READER_SCRIPT = """\
import os
import time

def identity(path):
    metadata = os.stat(path)
    return metadata.st_dev, metadata.st_ino

if not (
    identity("/proc/1/ns/time") == identity("/proc/1/ns/time_for_children")
    == identity("/proc/self/ns/time")
):
    raise SystemExit(41)
print("boottime-ns-v1")
print(time.clock_gettime_ns(time.CLOCK_BOOTTIME))
print("reader-offsets-v1")
with open("/proc/self/timens_offsets", encoding="ascii", newline="") as offsets:
    print(offsets.read(), end="")
"""


class TrustedTimeQualificationInspectionError(RuntimeError):
    """A sanitized, non-authorizing inspection failure."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class CheckedInAuthority:
    """Only the nonsecret authority fields needed by the inspector."""

    deployment: TrustedTimeDeploymentAuthority
    chrony_config_sha256: str
    authority_flags: tuple[str, ...]

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.chrony_config_sha256) is None:
            raise TrustedTimeQualificationInspectionError("authority_invalid")
        if self.deployment.host_id != HOST_ID or self.authority_flags != _AUTHORITY_FLAGS:
            raise TrustedTimeQualificationInspectionError("authority_invalid")


@dataclass(frozen=True, slots=True)
class RunningImageIds:
    """Immutable image identities of the two currently running services."""

    source: str
    supervisor: str
    source_container_id: str
    source_started_at_utc: datetime
    source_pid1_start_ticks: int
    source_time_namespace: str = dataclass_field(repr=False)
    source_time_namespace_offsets: TimeNamespaceOffsets = dataclass_field(repr=False)
    source_boot_id: str = dataclass_field(repr=False)
    supervisor_container_id: str
    supervisor_started_at_utc: datetime
    supervisor_pid1_start_ticks: int
    supervisor_time_namespace: str = dataclass_field(repr=False)
    supervisor_time_namespace_offsets: TimeNamespaceOffsets = dataclass_field(repr=False)
    supervisor_boot_id: str = dataclass_field(repr=False)
    clock_ticks_per_second: int
    docker_daemon: LocalDockerDaemonIdentity = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if (
            _IMAGE_ID.fullmatch(self.source) is None
            or _IMAGE_ID.fullmatch(self.supervisor) is None
            or self.source == self.supervisor
            or _CONTAINER_ID.fullmatch(self.source_container_id) is None
            or _CONTAINER_ID.fullmatch(self.supervisor_container_id) is None
            or self.source_container_id == self.supervisor_container_id
            or type(self.source_started_at_utc) is not datetime
            or self.source_started_at_utc.tzinfo is None
            or self.source_started_at_utc.utcoffset() != UTC.utcoffset(self.source_started_at_utc)
            or self.source_started_at_utc <= datetime(1970, 1, 1, tzinfo=UTC)
            or type(self.source_pid1_start_ticks) is not int
            or self.source_pid1_start_ticks <= 0
            or self.source_pid1_start_ticks > MAXIMUM_SIGNED_BIGINT
            or type(self.source_time_namespace) is not str
            or _LINUX_TIME_NAMESPACE.fullmatch(self.source_time_namespace) is None
            or self.source_time_namespace_offsets != _ZERO_TIME_NAMESPACE_OFFSETS
            or type(self.source_boot_id) is not str
            or _LINUX_BOOT_ID.fullmatch(self.source_boot_id) is None
            or type(self.supervisor_started_at_utc) is not datetime
            or self.supervisor_started_at_utc.tzinfo is None
            or self.supervisor_started_at_utc.utcoffset()
            != UTC.utcoffset(self.supervisor_started_at_utc)
            or self.supervisor_started_at_utc <= datetime(1970, 1, 1, tzinfo=UTC)
            or type(self.supervisor_pid1_start_ticks) is not int
            or self.supervisor_pid1_start_ticks <= 0
            or self.supervisor_pid1_start_ticks > MAXIMUM_SIGNED_BIGINT
            or type(self.supervisor_time_namespace) is not str
            or _LINUX_TIME_NAMESPACE.fullmatch(self.supervisor_time_namespace) is None
            or self.supervisor_time_namespace_offsets != _ZERO_TIME_NAMESPACE_OFFSETS
            or type(self.supervisor_boot_id) is not str
            or _LINUX_BOOT_ID.fullmatch(self.supervisor_boot_id) is None
            or self.source_boot_id != self.supervisor_boot_id
            or type(self.clock_ticks_per_second) is not int
            or self.clock_ticks_per_second != 100
            or type(self.docker_daemon) is not LocalDockerDaemonIdentity
        ):
            raise TrustedTimeQualificationInspectionError("runtime_images_invalid")


@dataclass(frozen=True, slots=True)
class _RunningContainer:
    container_id: str
    image_id: str
    started_at_utc: datetime
    pid1_start_ticks: int
    time_namespace: str = dataclass_field(repr=False)
    time_namespace_offsets: TimeNamespaceOffsets = dataclass_field(repr=False)
    boot_id: str = dataclass_field(repr=False)

    def __post_init__(self) -> None:
        if (
            _CONTAINER_ID.fullmatch(self.container_id) is None
            or _IMAGE_ID.fullmatch(self.image_id) is None
            or type(self.started_at_utc) is not datetime
            or self.started_at_utc.tzinfo is None
            or self.started_at_utc.utcoffset() != UTC.utcoffset(self.started_at_utc)
            or self.started_at_utc <= datetime(1970, 1, 1, tzinfo=UTC)
            or type(self.pid1_start_ticks) is not int
            or self.pid1_start_ticks <= 0
            or self.pid1_start_ticks > MAXIMUM_SIGNED_BIGINT
            or type(self.time_namespace) is not str
            or _LINUX_TIME_NAMESPACE.fullmatch(self.time_namespace) is None
            or self.time_namespace_offsets != _ZERO_TIME_NAMESPACE_OFFSETS
            or type(self.boot_id) is not str
            or _LINUX_BOOT_ID.fullmatch(self.boot_id) is None
        ):
            raise TrustedTimeQualificationInspectionError("runtime_images_invalid")


@dataclass(frozen=True, slots=True)
class HostSnapshot:
    """One repeatable-read snapshot restricted to the fixed host."""

    epochs: tuple[EvidenceRow, ...]
    head: EvidenceRow | None
    evaluations: tuple[EvidenceRow, ...]


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise TrustedTimeQualificationInspectionError("evidence_not_canonical") from None


def _source_authority_registry_sha256() -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            (
                "phase6c-source-authority-generation-registry-v1",
                _SOURCE_AUTHORITY_GENERATIONS,
            )
        )
    ).hexdigest()


def _read_checked_in_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise OSError
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size or len(payload) > maximum_bytes:
            raise OSError
        return payload
    except OSError:
        raise TrustedTimeQualificationInspectionError(
            f"{label}_unavailable",
        ) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_checked_in_authority() -> CheckedInAuthority:
    """Authenticate the exact checked-in authority, config, and database CA."""

    authority_payload = _read_checked_in_file(
        AUTHORITY_PATH,
        maximum_bytes=MAXIMUM_AUTHORITY_BYTES,
        label="authority",
    )
    chrony_config_payload = _read_checked_in_file(
        CHRONY_CONFIG_PATH,
        maximum_bytes=MAXIMUM_CHRONY_CONFIG_BYTES,
        label="chrony_config",
    )
    database_ca_payload = _read_checked_in_file(
        DATABASE_CA_PATH,
        maximum_bytes=MAXIMUM_DATABASE_CA_BYTES,
        label="database_ca",
    )
    try:
        deployment = decode_trusted_time_authority(
            authority_payload,
            chrony_config_payload=chrony_config_payload,
            database_ca_payload=database_ca_payload,
        )
        manifest: Any = json.loads(authority_payload)
        authority = manifest["authority"]
    except Exception:
        raise TrustedTimeQualificationInspectionError("authority_invalid") from None
    if (
        type(authority) is not dict
        or tuple(sorted(authority)) != _AUTHORITY_FLAGS
        or any(authority[flag] is not False for flag in _AUTHORITY_FLAGS)
    ):
        raise TrustedTimeQualificationInspectionError("authority_grant_detected")
    return CheckedInAuthority(
        deployment=deployment,
        chrony_config_sha256=hashlib.sha256(chrony_config_payload).hexdigest(),
        authority_flags=_AUTHORITY_FLAGS,
    )


def load_runtime_database_url(env_file: Path) -> str:
    """Load only the runtime DSN through the hardened owner-file boundary."""

    if not isinstance(env_file, Path) or not env_file.is_absolute() or env_file.name == ".env":
        raise TrustedTimeQualificationInspectionError("owner_environment_invalid")
    variables = ("AQT_DATABASE_URL",)
    try:
        environment = load_owner_only_environment(
            env_file,
            variables=variables,
            allowed_variables=variables,
            maximum_bytes=MAXIMUM_OWNER_ENVIRONMENT_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
        )
        database_url = environment.get("AQT_DATABASE_URL")
        if type(database_url) is not str or not database_url:
            raise ValueError
        validate_supabase_session_database_url(database_url)
    except (LocalPaperSmokePreflightError, ValueError):
        raise TrustedTimeQualificationInspectionError("owner_environment_invalid") from None
    return database_url


def create_read_only_qualification_engine(database_url: str) -> Engine:
    """Create one pinned-CA, bounded, default-read-only PostgreSQL engine."""

    try:
        validate_supabase_session_database_url(database_url)
        tls = pinned_verify_full_connect_args(database_url, required=True)
    except (LocalPaperSmokePreflightError, PostgresTLSConfigurationError):
        raise TrustedTimeQualificationInspectionError("database_configuration_invalid") from None
    return sa.create_engine(
        make_url(database_url),
        connect_args={
            "connect_timeout": DATABASE_CONNECT_TIMEOUT_SECONDS,
            **tls,
            "options": (
                "-c default_transaction_read_only=on "
                f"-c statement_timeout={DATABASE_STATEMENT_TIMEOUT_MILLISECONDS} "
                f"-c lock_timeout={DATABASE_LOCK_TIMEOUT_MILLISECONDS}"
            ),
        },
        max_overflow=0,
        pool_pre_ping=True,
        pool_size=1,
        pool_timeout=DATABASE_POOL_TIMEOUT_SECONDS,
    )


def _read_boottime_ns(clock: BoottimeClock, images: RunningImageIds) -> int:
    try:
        value = clock(images)
    except TrustedTimeQualificationInspectionError:
        raise
    except Exception:
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable") from None
    if type(value) is not int or value < 0 or value > MAXIMUM_SIGNED_BIGINT:
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable")
    return value


def _minimal_docker_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in _DOCKER_ENVIRONMENT_ALLOWLIST}


def _qualified_local_docker_daemon() -> LocalDockerDaemonIdentity:
    try:
        identity = qualify_local_docker_daemon()
    except TrustedTimeSupervisorConfigurationError:
        raise TrustedTimeQualificationInspectionError("local_docker_daemon_unavailable") from None
    if type(identity) is not LocalDockerDaemonIdentity:
        raise TrustedTimeQualificationInspectionError("local_docker_daemon_unavailable")
    return identity


def _require_same_local_docker_daemon(expected: LocalDockerDaemonIdentity) -> None:
    if _qualified_local_docker_daemon() != expected:
        raise TrustedTimeQualificationInspectionError("runtime_daemon_changed_during_inspection")


def _docker(*arguments: str) -> tuple[tuple[str, ...], int, str, str]:
    try:
        completed = run_bounded_subprocess(
            ("docker", *arguments),
            cwd=ROOT,
            environment=_minimal_docker_environment(),
            maximum_stdout_bytes=_MAXIMUM_DOCKER_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_DOCKER_STDERR_BYTES,
            timeout_seconds=20,
        )
        if (
            type(completed) is not tuple
            or len(completed) != 4
            or type(completed[0]) is not tuple
            or any(type(argument) is not str for argument in completed[0])
            or type(completed[1]) is not int
            or type(completed[2]) is not bytes
            or type(completed[3]) is not bytes
        ):
            raise UnicodeError("bounded subprocess result is malformed")
        return (
            completed[0],
            completed[1],
            completed[2].decode("utf-8", errors="strict"),
            completed[3].decode("utf-8", errors="strict"),
        )
    except (BoundedSubprocessError, UnicodeDecodeError):
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable") from None


def _docker_started_at(value: object) -> datetime:
    if type(value) is not str or _DOCKER_STARTED_AT.fullmatch(value) is None:
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable") from None
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable")
    return parsed.astimezone(UTC)


def _inspected_container_runtime(container_id: str) -> tuple[str, datetime]:
    inspected = _docker(
        "container",
        "inspect",
        "--format",
        "[{{json .Image}},{{json .State.StartedAt}}]",
        container_id,
    )
    try:
        runtime: Any = json.loads(inspected[2])
    except json.JSONDecodeError:
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable") from None
    if (
        inspected[1] != 0
        or inspected[3]
        or type(runtime) is not list
        or len(runtime) != 2
        or type(runtime[0]) is not str
        or _IMAGE_ID.fullmatch(runtime[0]) is None
    ):
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable")
    return runtime[0], _docker_started_at(runtime[1])


def _zero_time_namespace_offsets(lines: list[str]) -> TimeNamespaceOffsets:
    encoded = "\n".join(lines) + "\n"
    if _ZERO_TIME_NAMESPACE_OFFSETS_OUTPUT.fullmatch(encoded) is None:
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    return _ZERO_TIME_NAMESPACE_OFFSETS


def _pid1_start_ticks(container_id: str) -> int:
    completed = _docker(
        "container",
        "exec",
        "--user",
        "10001:10001",
        container_id,
        "/bin/sh",
        "-c",
        _PID1_CLOCK_IDENTITY_SCRIPT,
    )
    if (
        completed[1] != 0
        or completed[3]
        or len(completed[2]) > 4608
        or not completed[2].endswith("\n")
        or not completed[2].isascii()
        or "\r" in completed[2]
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    lines = completed[2].splitlines()
    if (
        len(lines) != 8
        or lines[0] != "pid1-stat-v1"
        or lines[2] != "pid1-offsets-v1"
        or lines[5] != "reader-offsets-v1"
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    _zero_time_namespace_offsets(lines[3:5])
    _zero_time_namespace_offsets(lines[6:8])
    line = lines[1]
    closing_parenthesis = line.rfind(") ")
    if not line.startswith("1 (") or closing_parenthesis < 3:
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    # The suffix starts at proc(5) field 3.  Start time is field 22, so it is
    # suffix index 19.  Parsing after the final close-parenthesis preserves a
    # process comm containing whitespace or parentheses.
    suffix = line[closing_parenthesis + 2 :].split(" ")
    if (
        len(suffix) < 20
        or len(suffix[0]) != 1
        or suffix[0] not in _PROC_PROCESS_STATES
        or "\x00" in line
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    encoded_ticks = suffix[19]
    if (
        not encoded_ticks.isdecimal()
        or not encoded_ticks.isascii()
        or len(encoded_ticks) > 19
        or (len(encoded_ticks) > 1 and encoded_ticks.startswith("0"))
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    ticks = int(encoded_ticks)
    if ticks <= 0 or ticks > MAXIMUM_SIGNED_BIGINT:
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    return ticks


def _pid1_time_namespace(container_id: str) -> str:
    completed = _docker(
        "container",
        "exec",
        "--user",
        "10001:10001",
        container_id,
        "/usr/bin/readlink",
        "/proc/1/ns/time",
    )
    identity = completed[2].strip()
    if (
        completed[1] != 0
        or completed[3]
        or completed[2] != f"{identity}\n"
        or _LINUX_TIME_NAMESPACE.fullmatch(identity) is None
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    return identity


def _linux_boot_id(container_id: str) -> str:
    completed = _docker(
        "container",
        "exec",
        "--user",
        "10001:10001",
        container_id,
        "/bin/cat",
        "/proc/sys/kernel/random/boot_id",
    )
    boot_id = completed[2].strip()
    if (
        completed[1] != 0
        or completed[3]
        or completed[2] != f"{boot_id}\n"
        or _LINUX_BOOT_ID.fullmatch(boot_id) is None
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    return boot_id


def _clock_ticks_per_second(supervisor_container_id: str) -> int:
    completed = _docker(
        "container",
        "exec",
        "--user",
        "10001:10001",
        supervisor_container_id,
        "/usr/local/bin/python",
        "-I",
        "-B",
        "-S",
        "-c",
        "import os;print(os.sysconf('SC_CLK_TCK'))",
    )
    encoded = completed[2].strip()
    if (
        completed[1] != 0
        or completed[3]
        or completed[2] != f"{encoded}\n"
        or not encoded.isascii()
        or not encoded.isdecimal()
        or len(encoded) > 19
        or (len(encoded) > 1 and encoded.startswith("0"))
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    ticks_per_second = int(encoded)
    if ticks_per_second != 100:
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    return ticks_per_second


def _listed_service_container_id(service: str) -> str:
    listed = _docker(
        "container",
        "ls",
        "--filter",
        "label=com.docker.compose.project=autoquanttrader-trusted-time",
        "--filter",
        f"label=com.docker.compose.service={service}",
        "--format",
        "{{.ID}}",
    )
    container_ids = listed[2].splitlines()
    if (
        listed[1] != 0
        or listed[3]
        or len(container_ids) != 1
        or _CONTAINER_ID.fullmatch(container_ids[0]) is None
    ):
        raise TrustedTimeQualificationInspectionError("runtime_images_unavailable")
    return container_ids[0]


def _running_service_container(service: str) -> _RunningContainer:
    container_id = _listed_service_container_id(service)
    image_id, started_at_utc = _inspected_container_runtime(container_id)
    pid1_start_ticks = _pid1_start_ticks(container_id)
    time_namespace = _pid1_time_namespace(container_id)
    time_namespace_offsets = _ZERO_TIME_NAMESPACE_OFFSETS
    boot_id = _linux_boot_id(container_id)
    repeated_image_id, repeated_started_at_utc = _inspected_container_runtime(container_id)
    repeated_pid1_start_ticks = _pid1_start_ticks(container_id)
    repeated_time_namespace = _pid1_time_namespace(container_id)
    repeated_time_namespace_offsets = _ZERO_TIME_NAMESPACE_OFFSETS
    repeated_boot_id = _linux_boot_id(container_id)
    if (
        image_id != repeated_image_id
        or started_at_utc != repeated_started_at_utc
        or pid1_start_ticks != repeated_pid1_start_ticks
        or time_namespace != repeated_time_namespace
        or time_namespace_offsets != repeated_time_namespace_offsets
        or boot_id != repeated_boot_id
        or _listed_service_container_id(service) != container_id
    ):
        raise TrustedTimeQualificationInspectionError("runtime_changed_during_inspection")
    return _RunningContainer(
        container_id=container_id,
        image_id=image_id,
        started_at_utc=started_at_utc,
        pid1_start_ticks=pid1_start_ticks,
        time_namespace=time_namespace,
        time_namespace_offsets=time_namespace_offsets,
        boot_id=boot_id,
    )


def _unchanged_running_containers(
    images: RunningImageIds,
) -> tuple[_RunningContainer, _RunningContainer]:
    source = _running_service_container("chrony-nts")
    supervisor = _running_service_container("trusted-time-supervisor")
    if (
        source.image_id != images.source
        or source.container_id != images.source_container_id
        or source.started_at_utc != images.source_started_at_utc
        or source.pid1_start_ticks != images.source_pid1_start_ticks
        or source.time_namespace != images.source_time_namespace
        or source.time_namespace_offsets != images.source_time_namespace_offsets
        or source.boot_id != images.source_boot_id
        or supervisor.image_id != images.supervisor
        or supervisor.container_id != images.supervisor_container_id
        or supervisor.started_at_utc != images.supervisor_started_at_utc
        or supervisor.pid1_start_ticks != images.supervisor_pid1_start_ticks
        or supervisor.time_namespace != images.supervisor_time_namespace
        or supervisor.time_namespace_offsets != images.supervisor_time_namespace_offsets
        or supervisor.boot_id != images.supervisor_boot_id
        or source.boot_id != supervisor.boot_id
        or _clock_ticks_per_second(supervisor.container_id) != images.clock_ticks_per_second
    ):
        raise TrustedTimeQualificationInspectionError("runtime_changed_during_inspection")
    return source, supervisor


def _validate_current_runtime_topology(images: RunningImageIds) -> None:
    """Authenticate exact live metadata between daemon/container identity fences."""

    _require_same_local_docker_daemon(images.docker_daemon)
    source, supervisor = _unchanged_running_containers(images)
    try:
        _validate_live_trusted_time_topology_ids(
            images.source,
            images.supervisor,
            source_container_id=source.container_id,
            supervisor_container_id=supervisor.container_id,
            environment=_minimal_docker_environment(),
        )
    except (TrustedTimeImageVerificationError, TrustedTimeSupervisorConfigurationError):
        raise TrustedTimeQualificationInspectionError("runtime_topology_not_admitted") from None
    _unchanged_running_containers(images)
    _require_same_local_docker_daemon(images.docker_daemon)


def _boottime_monotonic_ns(images: RunningImageIds) -> int:
    """Read Linux CLOCK_BOOTTIME inside the same running supervisor container."""

    _require_same_local_docker_daemon(images.docker_daemon)
    _, supervisor = _unchanged_running_containers(images)
    completed = _docker(
        "container",
        "exec",
        "--user",
        "10001:10001",
        supervisor.container_id,
        "/usr/local/bin/python",
        "-I",
        "-B",
        "-S",
        "-c",
        _BOOTTIME_READER_SCRIPT,
    )
    lines = completed[2].splitlines()
    if (
        completed[1] != 0
        or completed[3]
        or len(completed[2]) > 512
        or not completed[2].endswith("\n")
        or not completed[2].isascii()
        or "\r" in completed[2]
        or len(lines) != 5
        or lines[0] != "boottime-ns-v1"
        or lines[2] != "reader-offsets-v1"
    ):
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable")
    output = lines[1]
    if (
        not output.isascii()
        or not output.isdecimal()
        or len(output) > 19
        or (len(output) > 1 and output.startswith("0"))
    ):
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable")
    try:
        _zero_time_namespace_offsets(lines[3:5])
    except TrustedTimeQualificationInspectionError:
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable") from None
    value = int(output)
    if value > MAXIMUM_SIGNED_BIGINT:
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable")
    _unchanged_running_containers(images)
    _require_same_local_docker_daemon(images.docker_daemon)
    _validate_current_runtime_topology(images)
    return value


def inspect_running_image_ids(
    admission_artifact_path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
) -> RunningImageIds:
    """Consume the launch admission and bind its exact running processes."""

    docker_daemon = _qualified_local_docker_daemon()
    try:
        admission = _require_current_admission_snapshot(
            _load_current_image_admission_snapshot(admission_artifact_path)
        )
        admitted = _require_verified_images(
            _verify_images_with_manifest(
                admission[4],
                admission[5],
            )
        )
    except TrustedTimeImageVerificationError:
        raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted") from None
    _require_same_local_docker_daemon(docker_daemon)
    if admitted[1] != admission[4] or admitted[2] != admission[5]:
        raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted")
    try:
        observed_admission = _require_current_admission_snapshot(
            _load_current_image_admission_snapshot(admission_artifact_path)
        )
        if observed_admission != admission:
            raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted")
    except TrustedTimeImageVerificationError:
        raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted") from None
    source = _running_service_container("chrony-nts")
    supervisor = _running_service_container("trusted-time-supervisor")
    if admission[4] != source.image_id or admission[5] != supervisor.image_id:
        raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted")
    if (
        source.time_namespace_offsets != _ZERO_TIME_NAMESPACE_OFFSETS
        or supervisor.time_namespace_offsets != _ZERO_TIME_NAMESPACE_OFFSETS
        or source.boot_id != supervisor.boot_id
    ):
        raise TrustedTimeQualificationInspectionError("runtime_process_identity_unavailable")
    clock_ticks_per_second = _clock_ticks_per_second(supervisor.container_id)
    images = RunningImageIds(
        source=source.image_id,
        supervisor=supervisor.image_id,
        source_container_id=source.container_id,
        source_started_at_utc=source.started_at_utc,
        source_pid1_start_ticks=source.pid1_start_ticks,
        source_time_namespace=source.time_namespace,
        source_time_namespace_offsets=source.time_namespace_offsets,
        source_boot_id=source.boot_id,
        supervisor_container_id=supervisor.container_id,
        supervisor_started_at_utc=supervisor.started_at_utc,
        supervisor_pid1_start_ticks=supervisor.pid1_start_ticks,
        supervisor_time_namespace=supervisor.time_namespace,
        supervisor_time_namespace_offsets=supervisor.time_namespace_offsets,
        supervisor_boot_id=supervisor.boot_id,
        clock_ticks_per_second=clock_ticks_per_second,
        docker_daemon=docker_daemon,
    )
    _validate_current_runtime_topology(images)
    try:
        final_admission = _require_current_admission_snapshot(
            _load_current_image_admission_snapshot(admission_artifact_path)
        )
        if final_admission != admission:
            raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted")
    except TrustedTimeImageVerificationError:
        raise TrustedTimeQualificationInspectionError("runtime_images_not_admitted") from None
    return images


@contextmanager
def _read_only_repeatable_read(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        connection = connection.execution_options(isolation_level="REPEATABLE READ")
        transaction = connection.begin()
        try:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            yield connection
        finally:
            transaction.rollback()


def _read_host_snapshot(connection: Connection) -> HostSnapshot:
    epoch_columns = (
        phase6_trusted_time_epoch_registrations.c.host_id,
        phase6_trusted_time_epoch_registrations.c.epoch_sequence,
        phase6_trusted_time_epoch_registrations.c.monitor_epoch_id,
        phase6_trusted_time_epoch_registrations.c.source_id,
        phase6_trusted_time_epoch_registrations.c.source_authority_sha256,
        phase6_trusted_time_epoch_registrations.c.registered_at_utc,
        phase6_trusted_time_epoch_registrations.c.semantic_sha256,
    )
    epochs = tuple(
        connection.execute(
            sa.select(*epoch_columns)
            .where(phase6_trusted_time_epoch_registrations.c.host_id == HOST_ID)
            .order_by(phase6_trusted_time_epoch_registrations.c.epoch_sequence)
        )
        .mappings()
        .all()
    )
    head_columns = (
        phase6_trusted_time_host_heads.c.host_id,
        phase6_trusted_time_host_heads.c.epoch_sequence,
        phase6_trusted_time_host_heads.c.monitor_epoch_id,
        phase6_trusted_time_host_heads.c.epoch_sha256,
        phase6_trusted_time_host_heads.c.evaluation_sequence,
        phase6_trusted_time_host_heads.c.evaluation_id,
        phase6_trusted_time_host_heads.c.evaluation_record_sha256,
        phase6_trusted_time_host_heads.c.state_sha256,
        phase6_trusted_time_host_heads.c.health,
        phase6_trusted_time_host_heads.c.reason,
        phase6_trusted_time_host_heads.c.hard_failure_latched,
        phase6_trusted_time_host_heads.c.clock_recovery_qualified,
        phase6_trusted_time_host_heads.c.evaluated_at_utc,
        phase6_trusted_time_host_heads.c.evaluated_at_monotonic_ns,
        phase6_trusted_time_host_heads.c.semantic_sha256,
    )
    head = (
        connection.execute(
            sa.select(*head_columns).where(phase6_trusted_time_host_heads.c.host_id == HOST_ID)
        )
        .mappings()
        .one_or_none()
    )
    if head is None:
        return HostSnapshot(epochs=epochs, head=None, evaluations=())
    evaluation_columns = (
        phase6_trusted_time_probe_evaluations.c.host_id,
        phase6_trusted_time_probe_evaluations.c.monitor_epoch_id,
        phase6_trusted_time_probe_evaluations.c.evaluation_id,
        phase6_trusted_time_probe_evaluations.c.evaluation_sequence,
        phase6_trusted_time_probe_evaluations.c.probe_status,
        phase6_trusted_time_probe_evaluations.c.sample_sequence,
        phase6_trusted_time_probe_evaluations.c.source_evidence_sha256,
        phase6_trusted_time_probe_evaluations.c.probe_started_at_utc,
        phase6_trusted_time_probe_evaluations.c.probe_completed_at_utc,
        phase6_trusted_time_probe_evaluations.c.probe_started_monotonic_ns,
        phase6_trusted_time_probe_evaluations.c.probe_completed_monotonic_ns,
        phase6_trusted_time_probe_evaluations.c.source_uncertainty_milliseconds,
        phase6_trusted_time_probe_evaluations.c.health,
        phase6_trusted_time_probe_evaluations.c.reason,
        phase6_trusted_time_probe_evaluations.c.hard_failure_latched,
        phase6_trusted_time_probe_evaluations.c.clock_recovery_qualified,
        phase6_trusted_time_probe_evaluations.c.evaluated_at_utc,
        phase6_trusted_time_probe_evaluations.c.evaluated_at_monotonic_ns,
        phase6_trusted_time_probe_evaluations.c.state_sha256,
        phase6_trusted_time_probe_evaluations.c.semantic_sha256,
    )
    evaluations = tuple(
        connection.execute(
            sa.select(*evaluation_columns)
            .where(
                phase6_trusted_time_probe_evaluations.c.host_id == HOST_ID,
                phase6_trusted_time_probe_evaluations.c.monitor_epoch_id
                == head["monitor_epoch_id"],
            )
            .order_by(phase6_trusted_time_probe_evaluations.c.evaluation_sequence)
        )
        .mappings()
        .all()
    )
    return HostSnapshot(epochs=epochs, head=head, evaluations=evaluations)


def _text(row: EvidenceRow, field: str) -> str:
    value = row.get(field)
    if type(value) is not str or not value or value != value.strip():
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid")
    return value


def _sha256(row: EvidenceRow, field: str) -> str:
    value = _text(row, field)
    if _SHA256.fullmatch(value) is None:
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid")
    return value


def _integer(row: EvidenceRow, field: str, *, minimum: int = 0) -> int:
    value = row.get(field)
    if type(value) is not int or value < minimum:
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid")
    return value


def _boolean(row: EvidenceRow, field: str) -> bool:
    value = row.get(field)
    if type(value) is not bool:
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid")
    return value


def _utc(row: EvidenceRow, field: str) -> datetime:
    value = row.get(field)
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid")
    return value


def _uuid_identity(row: EvidenceRow, field: str) -> str:
    value = _text(row, field)
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid") from None
    if str(parsed) != value:
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid")
    return value


def _optional_fields_are_none(row: EvidenceRow, fields: tuple[str, ...]) -> bool:
    return all(row.get(field) is None for field in fields)


_SAMPLE_FIELDS = (
    "sample_sequence",
    "source_evidence_sha256",
    "probe_started_at_utc",
    "probe_completed_at_utc",
    "probe_started_monotonic_ns",
    "probe_completed_monotonic_ns",
    "source_uncertainty_milliseconds",
)


def _validated_evaluation(
    row: EvidenceRow,
    *,
    expected_sequence: int,
    monitor_epoch_id: str,
    authority: CheckedInAuthority,
) -> tuple[str, int, Decimal | None]:
    if (
        _text(row, "host_id") != HOST_ID
        or _uuid_identity(row, "monitor_epoch_id") != monitor_epoch_id
        or _integer(row, "evaluation_sequence", minimum=1) != expected_sequence
    ):
        raise TrustedTimeQualificationInspectionError("evaluation_chain_invalid")
    _uuid_identity(row, "evaluation_id")
    _sha256(row, "state_sha256")
    _sha256(row, "semantic_sha256")
    try:
        status = TrustedTimeProbeStatus(_text(row, "probe_status"))
        TrustedTimeHealth(_text(row, "health"))
        TrustedTimeReason(_text(row, "reason"))
    except ValueError:
        raise TrustedTimeQualificationInspectionError("persisted_evidence_invalid") from None
    _boolean(row, "hard_failure_latched")
    _boolean(row, "clock_recovery_qualified")
    evaluated_at_utc = _utc(row, "evaluated_at_utc")
    evaluated_at_ns = _integer(row, "evaluated_at_monotonic_ns")
    if status is not TrustedTimeProbeStatus.RECORDED:
        if not _optional_fields_are_none(row, _SAMPLE_FIELDS):
            raise TrustedTimeQualificationInspectionError("failure_sample_shape_invalid")
        return status.value, evaluated_at_ns, None

    uncertainty = row.get("source_uncertainty_milliseconds")
    if (
        type(uncertainty) is not Decimal
        or uncertainty < 0
        or uncertainty > authority.deployment.maximum_source_uncertainty_milliseconds
    ):
        raise TrustedTimeQualificationInspectionError("sample_uncertainty_invalid")
    _integer(row, "sample_sequence", minimum=1)
    _sha256(row, "source_evidence_sha256")
    started_at_utc = _utc(row, "probe_started_at_utc")
    completed_at_utc = _utc(row, "probe_completed_at_utc")
    started_at_ns = _integer(row, "probe_started_monotonic_ns")
    completed_at_ns = _integer(row, "probe_completed_monotonic_ns")
    if (
        started_at_ns > completed_at_ns
        or completed_at_ns > evaluated_at_ns
        or completed_at_ns - started_at_ns > authority.deployment.probe_deadline_ns
        or started_at_utc > completed_at_utc
        or completed_at_utc > evaluated_at_utc
    ):
        raise TrustedTimeQualificationInspectionError("sample_timing_invalid")
    return status.value, evaluated_at_ns, uncertainty


def _authority_payload(authority: CheckedInAuthority) -> dict[str, bool]:
    return {flag: False for flag in authority.authority_flags}


def _start_tick_interval_upper_ns(start_ticks: int, clock_ticks_per_second: int) -> int:
    """Return the conservative exclusive upper edge of one proc start tick."""

    numerator = (start_ticks + 1) * 1_000_000_000
    return (numerator + clock_ticks_per_second - 1) // clock_ticks_per_second


def qualify_host_snapshot(
    snapshot: HostSnapshot,
    *,
    authority: CheckedInAuthority,
    images: RunningImageIds,
    minimum_evaluations: int,
    current_boottime_ns: int,
) -> dict[str, object]:
    """Validate one fixed-host snapshot and return only sanitized evidence."""

    if type(minimum_evaluations) is not int or minimum_evaluations < DEFAULT_MINIMUM_EVALUATIONS:
        raise TrustedTimeQualificationInspectionError("minimum_evaluations_invalid")
    if (
        type(current_boottime_ns) is not int
        or current_boottime_ns < 0
        or current_boottime_ns > MAXIMUM_SIGNED_BIGINT
    ):
        raise TrustedTimeQualificationInspectionError("boottime_clock_unavailable")
    if not snapshot.epochs or snapshot.head is None:
        raise TrustedTimeQualificationInspectionError("trusted_time_history_missing")
    current_authority = (
        authority.deployment.source_id,
        authority.deployment.source_authority_sha256,
    )
    if (
        len(set(_SOURCE_AUTHORITY_GENERATIONS)) != len(_SOURCE_AUTHORITY_GENERATIONS)
        or current_authority != _SOURCE_AUTHORITY_GENERATIONS[-1]
    ):
        raise TrustedTimeQualificationInspectionError("authority_invalid")
    prior_generation = -1
    for expected_sequence, epoch in enumerate(snapshot.epochs, start=1):
        if (
            _text(epoch, "host_id") != HOST_ID
            or _integer(epoch, "epoch_sequence", minimum=1) != expected_sequence
        ):
            raise TrustedTimeQualificationInspectionError("epoch_chain_invalid")
        _uuid_identity(epoch, "monitor_epoch_id")
        epoch_authority = (
            _text(epoch, "source_id"),
            _sha256(epoch, "source_authority_sha256"),
        )
        try:
            generation = _SOURCE_AUTHORITY_GENERATIONS.index(epoch_authority)
        except ValueError:
            raise TrustedTimeQualificationInspectionError("epoch_chain_invalid") from None
        if generation < prior_generation:
            raise TrustedTimeQualificationInspectionError("epoch_chain_invalid")
        prior_generation = generation
        _sha256(epoch, "semantic_sha256")

    current_epoch = snapshot.epochs[-1]
    if prior_generation != len(_SOURCE_AUTHORITY_GENERATIONS) - 1:
        raise TrustedTimeQualificationInspectionError("current_epoch_authority_invalid")
    head = snapshot.head
    monitor_epoch_id = _uuid_identity(current_epoch, "monitor_epoch_id")
    current_epoch_sha256 = _sha256(current_epoch, "semantic_sha256")
    _utc(current_epoch, "registered_at_utc")
    if (
        _text(head, "host_id") != HOST_ID
        or _integer(head, "epoch_sequence", minimum=1) != len(snapshot.epochs)
        or _uuid_identity(head, "monitor_epoch_id") != monitor_epoch_id
        or _sha256(head, "epoch_sha256") != current_epoch_sha256
    ):
        raise TrustedTimeQualificationInspectionError("current_head_invalid")
    if not snapshot.evaluations:
        raise TrustedTimeQualificationInspectionError("trusted_time_history_missing")
    statuses: list[str] = []
    evaluated_ns: list[int] = []
    uncertainties: list[Decimal] = []
    sample_sequences: list[int] = []
    for expected_sequence, evaluation in enumerate(snapshot.evaluations, start=1):
        status, observed_ns, uncertainty = _validated_evaluation(
            evaluation,
            expected_sequence=expected_sequence,
            monitor_epoch_id=monitor_epoch_id,
            authority=authority,
        )
        statuses.append(status)
        evaluated_ns.append(observed_ns)
        if uncertainty is not None:
            uncertainties.append(uncertainty)
            sample_sequences.append(_integer(evaluation, "sample_sequence", minimum=1))
    if sample_sequences != list(range(1, len(sample_sequences) + 1)):
        raise TrustedTimeQualificationInspectionError("sample_sequence_invalid")

    supervisor_start_interval_upper_ns = _start_tick_interval_upper_ns(
        images.supervisor_pid1_start_ticks,
        images.clock_ticks_per_second,
    )
    current_epoch_process_bound = (
        images.source_pid1_start_ticks < images.supervisor_pid1_start_ticks
        and current_boottime_ns >= supervisor_start_interval_upper_ns
        and evaluated_ns[0] >= supervisor_start_interval_upper_ns
    )

    minimum_gap_ns = max(
        1,
        authority.deployment.cadence_ns - (2 * authority.deployment.probe_deadline_ns),
    )
    gaps_ns = [later - earlier for earlier, later in pairwise(evaluated_ns)]
    cadence_qualified = all(
        minimum_gap_ns <= gap <= authority.deployment.maximum_gap_ns for gap in gaps_ns
    )
    required_span_ns = (minimum_evaluations - 1) * authority.deployment.cadence_ns - (
        2 * authority.deployment.probe_deadline_ns
    )
    span_ns = evaluated_ns[-1] - evaluated_ns[0]
    terminal = snapshot.evaluations[-1]
    terminal_sequence = len(snapshot.evaluations)
    terminal_health = _text(terminal, "health")
    terminal_reason = _text(terminal, "reason")
    if current_boottime_ns < evaluated_ns[-1]:
        raise TrustedTimeQualificationInspectionError("boottime_clock_regressed")
    terminal_age_ns = current_boottime_ns - evaluated_ns[-1]
    terminal_fresh = terminal_age_ns <= authority.deployment.maximum_gap_ns
    if (
        _integer(head, "evaluation_sequence", minimum=1) != terminal_sequence
        or _uuid_identity(head, "evaluation_id") != _uuid_identity(terminal, "evaluation_id")
        or _sha256(head, "evaluation_record_sha256") != _sha256(terminal, "semantic_sha256")
        or _sha256(head, "state_sha256") != _sha256(terminal, "state_sha256")
        or _text(head, "health") != terminal_health
        or _text(head, "reason") != terminal_reason
        or _boolean(head, "hard_failure_latched") != _boolean(terminal, "hard_failure_latched")
        or _boolean(head, "clock_recovery_qualified")
        != _boolean(terminal, "clock_recovery_qualified")
        or _utc(head, "evaluated_at_utc") != _utc(terminal, "evaluated_at_utc")
        or _integer(head, "evaluated_at_monotonic_ns") != evaluated_ns[-1]
    ):
        raise TrustedTimeQualificationInspectionError("current_head_invalid")

    status_counts = {
        status.value: statuses.count(status.value) for status in TrustedTimeProbeStatus
    }
    recorded_count = status_counts[TrustedTimeProbeStatus.RECORDED.value]
    terminal_qualified = (
        terminal_health == TrustedTimeHealth.HEALTHY.value
        and terminal_reason == TrustedTimeReason.WITHIN_LIMIT.value
        and _boolean(head, "hard_failure_latched") is False
        and _boolean(head, "clock_recovery_qualified") is True
    )
    qualification_passed = (
        len(snapshot.evaluations) >= minimum_evaluations
        and recorded_count >= minimum_evaluations
        and cadence_qualified
        and span_ns >= required_span_ns
        and terminal_qualified
        and terminal_fresh
        and current_epoch_process_bound
    )
    body: dict[str, object] = {
        "authority": {
            "all_false": True,
            "flags": _authority_payload(authority),
        },
        "contract_version": CONTRACT_VERSION,
        "counts": {
            "current_epoch_evaluations": len(snapshot.evaluations),
            "epochs": len(snapshot.epochs),
            "failures": len(snapshot.evaluations) - recorded_count,
            "heads": 1,
            "minimum_required_recorded": minimum_evaluations,
            "recorded": recorded_count,
            "status": status_counts,
        },
        "current": {
            "clock_recovery_qualified": _boolean(head, "clock_recovery_qualified"),
            "epoch_sequence": len(snapshot.epochs),
            "evaluation_sequence": terminal_sequence,
            "hard_failure_latched": _boolean(head, "hard_failure_latched"),
            "health": terminal_health,
            "reason": terminal_reason,
        },
        "hashes": {
            "chrony_config_sha256": authority.chrony_config_sha256,
            "current_epoch_sha256": current_epoch_sha256,
            "current_host_head_sha256": _sha256(head, "semantic_sha256"),
            "current_record_sha256": _sha256(terminal, "semantic_sha256"),
            "current_state_sha256": _sha256(terminal, "state_sha256"),
            "database_ca_sha256": authority.deployment.database_ca_sha256,
            "source_authority_registry_sha256": _source_authority_registry_sha256(),
            "source_authority_sha256": authority.deployment.source_authority_sha256,
        },
        "identities": {
            "host_id": HOST_ID,
            "monitor_epoch_id": monitor_epoch_id,
            "source_id": authority.deployment.source_id,
        },
        "images": {
            "admitted": True,
            "current_epoch_process_bound": current_epoch_process_bound,
            "source": images.source,
            "supervisor": images.supervisor,
        },
        "qualification_passed": qualification_passed,
        "schema_revision": EXPECTED_SCHEMA_REVISION,
        "status": "qualified" if qualification_passed else "not_qualified",
        "timing": {
            "cadence_qualified": cadence_qualified,
            "cadence_ns": authority.deployment.cadence_ns,
            "evaluation_gaps_ns": gaps_ns,
            "evaluation_span_ns": span_ns,
            "maximum_gap_ns": authority.deployment.maximum_gap_ns,
            "minimum_accepted_gap_ns": minimum_gap_ns,
            "required_evaluation_span_ns": required_span_ns,
            "terminal_age_ns": terminal_age_ns,
            "terminal_fresh": terminal_fresh,
        },
        "uncertainty_milliseconds": {
            "approved_maximum": str(authority.deployment.maximum_source_uncertainty_milliseconds),
            "observed_maximum": None if not uncertainties else str(max(uncertainties)),
            "observed_minimum": None if not uncertainties else str(min(uncertainties)),
        },
    }
    body["qualification_sha256"] = hashlib.sha256(_canonical_json_bytes(body)).hexdigest()
    _validate_sanitized_evidence_payload(body)
    return body


def _exact_mapping(
    value: object,
    *,
    fields: frozenset[str],
) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    return cast(dict[str, object], value)


def _exact_nonnegative_integer(value: object) -> int:
    if type(value) is not int or value < 0:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    return value


def _validate_sanitized_evidence_payload(value: object) -> None:
    """Accept only the closed, nonsecret public evidence schema."""

    payload = _exact_mapping(
        value,
        fields=frozenset(
            {
                "authority",
                "contract_version",
                "counts",
                "current",
                "hashes",
                "identities",
                "images",
                "qualification_passed",
                "qualification_sha256",
                "schema_revision",
                "status",
                "timing",
                "uncertainty_milliseconds",
            }
        ),
    )
    if (
        payload["contract_version"] != CONTRACT_VERSION
        or payload["schema_revision"] != EXPECTED_SCHEMA_REVISION
        or payload["status"] not in {"qualified", "not_qualified"}
        or type(payload["qualification_passed"]) is not bool
        or (payload["status"] == "qualified") is not payload["qualification_passed"]
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    qualification_sha256 = payload["qualification_sha256"]
    if type(qualification_sha256) is not str or _SHA256.fullmatch(qualification_sha256) is None:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    body = dict(payload)
    body.pop("qualification_sha256")
    if hashlib.sha256(_canonical_json_bytes(body)).hexdigest() != qualification_sha256:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    authority = _exact_mapping(
        payload["authority"],
        fields=frozenset({"all_false", "flags"}),
    )
    flags = _exact_mapping(authority["flags"], fields=frozenset(_AUTHORITY_FLAGS))
    if authority["all_false"] is not True or any(value is not False for value in flags.values()):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    counts = _exact_mapping(
        payload["counts"],
        fields=frozenset(
            {
                "current_epoch_evaluations",
                "epochs",
                "failures",
                "heads",
                "minimum_required_recorded",
                "recorded",
                "status",
            }
        ),
    )
    for field in (
        "current_epoch_evaluations",
        "epochs",
        "failures",
        "heads",
        "minimum_required_recorded",
        "recorded",
    ):
        _exact_nonnegative_integer(counts[field])
    status_counts = _exact_mapping(
        counts["status"],
        fields=frozenset(status.value for status in TrustedTimeProbeStatus),
    )
    for status_count in status_counts.values():
        _exact_nonnegative_integer(status_count)
    evaluation_count = _exact_nonnegative_integer(counts["current_epoch_evaluations"])
    recorded_count = _exact_nonnegative_integer(counts["recorded"])
    failure_count = _exact_nonnegative_integer(counts["failures"])
    minimum_recorded = _exact_nonnegative_integer(counts["minimum_required_recorded"])
    if (
        _exact_nonnegative_integer(counts["epochs"]) < 1
        or counts["heads"] != 1
        or minimum_recorded < DEFAULT_MINIMUM_EVALUATIONS
        or sum(cast(int, count) for count in status_counts.values()) != evaluation_count
        or status_counts[TrustedTimeProbeStatus.RECORDED.value] != recorded_count
        or evaluation_count - recorded_count != failure_count
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    current = _exact_mapping(
        payload["current"],
        fields=frozenset(
            {
                "clock_recovery_qualified",
                "epoch_sequence",
                "evaluation_sequence",
                "hard_failure_latched",
                "health",
                "reason",
            }
        ),
    )
    if (
        type(current["clock_recovery_qualified"]) is not bool
        or type(current["hard_failure_latched"]) is not bool
        or _exact_nonnegative_integer(current["epoch_sequence"]) < 1
        or _exact_nonnegative_integer(current["evaluation_sequence"]) < 1
        or current["epoch_sequence"] != counts["epochs"]
        or current["evaluation_sequence"] != evaluation_count
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    try:
        TrustedTimeHealth(cast(str, current["health"]))
        TrustedTimeReason(cast(str, current["reason"]))
    except (TypeError, ValueError):
        raise TrustedTimeQualificationInspectionError("artifact_invalid") from None

    hashes = _exact_mapping(
        payload["hashes"],
        fields=frozenset(
            {
                "chrony_config_sha256",
                "current_epoch_sha256",
                "current_host_head_sha256",
                "current_record_sha256",
                "current_state_sha256",
                "database_ca_sha256",
                "source_authority_registry_sha256",
                "source_authority_sha256",
            }
        ),
    )
    if any(
        type(digest) is not str or _SHA256.fullmatch(digest) is None for digest in hashes.values()
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    if (
        hashes["chrony_config_sha256"] != _CURRENT_CHRONY_CONFIG_SHA256
        or hashes["database_ca_sha256"] != _CURRENT_DATABASE_CA_SHA256
        or hashes["source_authority_registry_sha256"] != _source_authority_registry_sha256()
        or hashes["source_authority_sha256"] != _CURRENT_SOURCE_AUTHORITY_SHA256
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    identities = _exact_mapping(
        payload["identities"],
        fields=frozenset({"host_id", "monitor_epoch_id", "source_id"}),
    )
    if identities["host_id"] != HOST_ID or identities["source_id"] != _CURRENT_SOURCE_ID:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    try:
        if (
            str(uuid.UUID(cast(str, identities["monitor_epoch_id"])))
            != identities["monitor_epoch_id"]
        ):
            raise ValueError
    except (TypeError, ValueError):
        raise TrustedTimeQualificationInspectionError("artifact_invalid") from None

    images = _exact_mapping(
        payload["images"],
        fields=frozenset(
            {
                "admitted",
                "current_epoch_process_bound",
                "source",
                "supervisor",
            }
        ),
    )
    if (
        images["admitted"] is not True
        or type(images["current_epoch_process_bound"]) is not bool
        or type(images["source"]) is not str
        or _IMAGE_ID.fullmatch(images["source"]) is None
        or type(images["supervisor"]) is not str
        or _IMAGE_ID.fullmatch(images["supervisor"]) is None
        or images["source"] == images["supervisor"]
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    timing = _exact_mapping(
        payload["timing"],
        fields=frozenset(
            {
                "cadence_qualified",
                "cadence_ns",
                "evaluation_gaps_ns",
                "evaluation_span_ns",
                "maximum_gap_ns",
                "minimum_accepted_gap_ns",
                "required_evaluation_span_ns",
                "terminal_age_ns",
                "terminal_fresh",
            }
        ),
    )
    if type(timing["cadence_qualified"]) is not bool or type(timing["terminal_fresh"]) is not bool:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    for field in (
        "cadence_ns",
        "evaluation_span_ns",
        "maximum_gap_ns",
        "minimum_accepted_gap_ns",
        "required_evaluation_span_ns",
        "terminal_age_ns",
    ):
        _exact_nonnegative_integer(timing[field])
    gaps = timing["evaluation_gaps_ns"]
    if type(gaps) is not list:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    for gap in gaps:
        _exact_nonnegative_integer(gap)
    expected_minimum_gap_ns = 18_000_000_000
    expected_cadence = all(
        expected_minimum_gap_ns <= cast(int, gap) <= 30_000_000_000 for gap in gaps
    )
    expected_terminal_fresh = cast(int, timing["terminal_age_ns"]) <= cast(
        int,
        timing["maximum_gap_ns"],
    )
    if (
        len(gaps) != max(0, evaluation_count - 1)
        or timing["cadence_ns"] != 20_000_000_000
        or timing["maximum_gap_ns"] != 30_000_000_000
        or timing["minimum_accepted_gap_ns"] != expected_minimum_gap_ns
        or timing["required_evaluation_span_ns"]
        != (minimum_recorded - 1) * 20_000_000_000 - 2_000_000_000
        or timing["evaluation_span_ns"] != sum(cast(int, gap) for gap in gaps)
        or timing["cadence_qualified"] is not expected_cadence
        or timing["terminal_fresh"] is not expected_terminal_fresh
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    uncertainty = _exact_mapping(
        payload["uncertainty_milliseconds"],
        fields=frozenset({"approved_maximum", "observed_maximum", "observed_minimum"}),
    )
    for field in ("approved_maximum", "observed_maximum", "observed_minimum"):
        observed = uncertainty[field]
        if observed is None and field != "approved_maximum":
            continue
        if type(observed) is not str:
            raise TrustedTimeQualificationInspectionError("artifact_invalid")
        try:
            decimal = Decimal(observed)
        except Exception:
            raise TrustedTimeQualificationInspectionError("artifact_invalid") from None
        if not decimal.is_finite() or decimal < 0 or decimal > Decimal("100"):
            raise TrustedTimeQualificationInspectionError("artifact_invalid")
    if (recorded_count == 0) != (uncertainty["observed_minimum"] is None):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    if (recorded_count == 0) != (uncertainty["observed_maximum"] is None):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    if uncertainty["approved_maximum"] != "100":
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    if recorded_count > 0 and Decimal(cast(str, uncertainty["observed_minimum"])) > Decimal(
        cast(str, uncertainty["observed_maximum"])
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    expected_qualified = (
        evaluation_count >= minimum_recorded
        and recorded_count >= minimum_recorded
        and timing["cadence_qualified"] is True
        and timing["evaluation_span_ns"] >= timing["required_evaluation_span_ns"]
        and timing["terminal_fresh"] is True
        and images["admitted"] is True
        and images["current_epoch_process_bound"] is True
        and current["health"] == TrustedTimeHealth.HEALTHY.value
        and current["reason"] == TrustedTimeReason.WITHIN_LIMIT.value
        and current["hard_failure_latched"] is False
        and current["clock_recovery_qualified"] is True
    )
    if payload["qualification_passed"] is not expected_qualified:
        raise TrustedTimeQualificationInspectionError("artifact_invalid")


def inspect_trusted_time_qualification(
    *,
    env_file: Path,
    minimum_evaluations: int = DEFAULT_MINIMUM_EVALUATIONS,
    engine_factory: EngineFactory = create_read_only_qualification_engine,
    authority_loader: Callable[[], CheckedInAuthority] = load_checked_in_authority,
    image_inspector: Callable[[], RunningImageIds] | None = None,
    image_admission_artifact: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    boottime_clock: BoottimeClock = _boottime_monotonic_ns,
) -> dict[str, object]:
    """Run all read-only integrity gates and return sanitized evidence."""

    engine: Engine | None = None
    database_url = ""
    try:
        authority = authority_loader()
        images = (
            inspect_running_image_ids(image_admission_artifact)
            if image_inspector is None
            else image_inspector()
        )
        database_url = load_runtime_database_url(env_file)
        engine = engine_factory(database_url)
        if not isinstance(engine, Engine):
            raise TrustedTimeQualificationInspectionError("database_engine_invalid")
        verify_operational_schema(engine, require_phase_zero_facts=False)
        verify_trusted_time_integrity(engine)
        with _read_only_repeatable_read(engine) as connection:
            snapshot = _read_host_snapshot(connection)
        current_boottime_ns = _read_boottime_ns(boottime_clock, images)
        return qualify_host_snapshot(
            snapshot,
            authority=authority,
            images=images,
            minimum_evaluations=minimum_evaluations,
            current_boottime_ns=current_boottime_ns,
        )
    except TrustedTimeQualificationInspectionError:
        raise
    except Exception:
        raise TrustedTimeQualificationInspectionError("qualification_inspection_failed") from None
    finally:
        database_url = ""
        if engine is not None:
            with suppress(Exception):
                engine.dispose()


def _open_owner_only_artifact_directory(path: Path, *, ignored_root: Path) -> int:
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if (
        not path.is_absolute()
        or absolute != path
        or (absolute != root and not absolute.is_relative_to(root))
    ):
        raise TrustedTimeQualificationInspectionError("artifact_directory_invalid")
    descriptor = os.open(
        absolute.anchor,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            should_be_owner_only = current == root or current.is_relative_to(root)
            if should_be_owner_only:
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
            if should_be_owner_only and (
                metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise TrustedTimeQualificationInspectionError("artifact_directory_invalid")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_qualification_artifact(
    artifact_dir: Path,
    encoded: bytes,
    *,
    qualification_sha256: str,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> Path:
    """Atomically create the canonical evidence as one owner-only ignored file."""

    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > MAXIMUM_ARTIFACT_BYTES
        or _SHA256.fullmatch(qualification_sha256) is None
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")
    try:
        decoded: Any = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TrustedTimeQualificationInspectionError("artifact_invalid") from None
    _validate_sanitized_evidence_payload(decoded)
    if (
        _canonical_json_bytes(decoded) != encoded
        or decoded["qualification_sha256"] != qualification_sha256
    ):
        raise TrustedTimeQualificationInspectionError("artifact_invalid")

    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    temporary_created = False
    file_name = f"trusted-time-qualification-{qualification_sha256}.json"
    temporary_name = f".{file_name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            artifact_dir,
            ignored_root=ignored_root,
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
        os.link(
            temporary_name,
            file_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)
    except TrustedTimeQualificationInspectionError:
        raise
    except FileExistsError:
        raise TrustedTimeQualificationInspectionError("artifact_already_exists") from None
    except (OSError, ValueError):
        raise TrustedTimeQualificationInspectionError("artifact_write_failed") from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary_created and directory_descriptor is not None:
            with suppress(OSError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    return artifact_dir / file_name


def _safe_failure_payload() -> dict[str, object]:
    return {
        "authority_granted": False,
        "database_secret_disclosed": False,
        "reason": "qualification_inspection_rejected",
        "service": "trusted-time-qualification-inspector",
        "status": "fatal",
    }


def _minimum_evaluations(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"must be an integer of at least {DEFAULT_MINIMUM_EVALUATIONS}"
        ) from None
    if parsed < DEFAULT_MINIMUM_EVALUATIONS:
        raise argparse.ArgumentTypeError(
            f"must be an integer of at least {DEFAULT_MINIMUM_EVALUATIONS}"
        )
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help=(
            "dedicated owner-only dotenv containing exactly AQT_DATABASE_URL; "
            "never use the general repository .env"
        ),
    )
    parser.add_argument(
        "--minimum-evaluations",
        default=DEFAULT_MINIMUM_EVALUATIONS,
        type=_minimum_evaluations,
        help="minimum current-epoch recorded samples; cannot be below 4 (default: 4)",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help="optional absolute directory below the repository artifacts/ root",
    )
    parser.add_argument(
        "--image-admission-artifact",
        type=Path,
        default=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        help="owner-only launch image admission artifact (default: canonical local path)",
    )
    arguments = parser.parse_args()
    try:
        payload = inspect_trusted_time_qualification(
            env_file=arguments.env_file,
            minimum_evaluations=arguments.minimum_evaluations,
            image_admission_artifact=arguments.image_admission_artifact,
        )
        encoded = _canonical_json_bytes(payload)
        if arguments.artifact_dir is not None:
            write_qualification_artifact(
                arguments.artifact_dir,
                encoded,
                qualification_sha256=cast(str, payload["qualification_sha256"]),
            )
    except Exception:
        sys.stdout.write(_canonical_json_bytes(_safe_failure_payload()).decode("utf-8"))
        raise SystemExit(2) from None
    sys.stdout.write(encoded.decode("utf-8"))
    if payload["qualification_passed"] is not True:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
