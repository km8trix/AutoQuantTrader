"""Start the local trusted-time topology with owner-staged runtime inputs."""

# ruff: noqa: E402 -- the CLI bootstrap must run before first-party imports.

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


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
        expected_relative_path=Path("scripts/start_trusted_time_supervisor.py")
    )
    if __name__ == "__main__"
    else None
)

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
    validate_database_url,
)
from apps.trusted_time_supervisor.head_anchor_config import (
    ED25519_PRIVATE_KEY_BYTES,
    MAXIMUM_HEAD_ANCHOR_AUTH_SECRET_BYTES,
    MAXIMUM_HEAD_ANCHOR_AUTHORITY_BYTES,
)
from scripts.bounded_subprocess import BoundedSubprocessError, run_bounded_subprocess
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
    TrustedTimeImageAdmission,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
    _head_reviewed_input_payload,
    _open_owner_only_artifact_directory,
    _require_head_reviewed_inputs,
    _require_ordinary_git_index_flags,
    load_image_admission_artifact,
    validate_socket_volume_inspection,
    verify_images,
)

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)
COMPOSE_PATH = ROOT / "infra" / "compose" / "trusted-time.compose.yaml"
DEFAULTS_PATH = ROOT / "infra" / "compose" / "trusted-time.defaults.env"
MAXIMUM_ENV_FILE_BYTES = 65_536
COMPOSE_WAIT_TIMEOUT_SECONDS = 60
UNENROLLED_TERMINAL_OBSERVATION_TIMEOUT_SECONDS = 60.0
UNENROLLED_TERMINAL_OBSERVATION_POLL_SECONDS = 0.1
MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES = 4_096
_MAXIMUM_BOUNDED_COMPOSE_PAYLOAD_BYTES = 8_192
_MAXIMUM_GIT_REVISION_STDOUT_BYTES = 64
_MAXIMUM_GIT_STATUS_STDOUT_BYTES = 65_536
_MAXIMUM_GIT_STDERR_BYTES = 16_384
_MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES = 65_536
_MAXIMUM_DOCKER_INSPECTION_STDOUT_BYTES = 4 * 1_024 * 1_024
_MAXIMUM_DOCKER_STDERR_BYTES = 1_024 * 1_024
MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES = 4_096
UNENROLLED_ADMISSION_CONTRACT_VERSION = "phase6d-unenrolled-secure-launch-admission-v2"
DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR = IGNORED_ARTIFACT_ROOT / "trusted-time"
TRUSTED_TIME_LAUNCH_LOCK_PATH = (
    DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR / "trusted-time-launch.lock"
)
FIRST_ENROLLMENT_CLAIM_FILE_PREFIX = "trusted-time-first-enrollment-claim-"
FIRST_ENROLLMENT_CLAIM_FILE_SUFFIX = ".json"
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
FIRST_ENROLLMENT_SERVICE = "trusted-time-first-enrollment"
FIRST_ENROLLMENT_COMMAND = "/opt/venv/bin/autoquant-trusted-time-first-enrollment"
_FIRST_ENROLLMENT_RUNTIME_ENVIRONMENT = {
    "AQT_TRUSTED_TIME_DATABASE_URL_FILE": DATABASE_SECRET_RUNTIME_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH": HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE": HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE": HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
}
_FULL_CONTAINER_ID_PATTERN = re.compile(r"[0-9a-f]{64}")
_DAEMON_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,255}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_GIT_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_UUID4_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_EXPECTED_UNENROLLED_TERMINAL_REASON = "head_anchor_remote_history_absent_enrollment_not_approved"
_SUPERVISOR_TERMINAL_REASONS = frozenset(
    {
        "configuration_rejected",
        "supervision_failed",
        _EXPECTED_UNENROLLED_TERMINAL_REASON,
    }
)
_SUPERVISOR_AUTHORITY_FIELDS = frozenset(
    {
        "alert_delivery_authorized",
        "arming_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
        "rearm_authorized",
    }
)
_SUPERVISOR_NARROW_STATE_FORMAT = "\t".join(
    (
        "{{json .Id}}",
        "{{json .Image}}",
        '{{json (index .Config.Labels "com.docker.compose.project")}}',
        '{{json (index .Config.Labels "com.docker.compose.service")}}',
        "{{json .RestartCount}}",
        "{{json .State.Status}}",
        "{{json .State.Running}}",
        "{{json .State.ExitCode}}",
        "{{json .State.OOMKilled}}",
        "{{json .State.Dead}}",
        "{{json .State.Error}}",
    )
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


@dataclass(frozen=True, slots=True)
class LocalDockerDaemonIdentity:
    """One approved local Unix endpoint and the daemon reached through it."""

    context_name: str
    endpoint: str
    daemon_id: str


@dataclass(frozen=True, slots=True)
class TrustedTimeApprovedLaunch:
    """Exact nonsecret values approved for one fail-closed launch attempt."""

    git_revision: str
    image_admission_sha256: str
    source_image_id: str
    supervisor_image_id: str

    def __post_init__(self) -> None:
        if (
            type(self.git_revision) is not str
            or _GIT_REVISION_PATTERN.fullmatch(self.git_revision) is None
            or type(self.image_admission_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.image_admission_sha256) is None
            or type(self.source_image_id) is not str
            or _IMAGE_ID_PATTERN.fullmatch(self.source_image_id) is None
            or type(self.supervisor_image_id) is not str
            or _IMAGE_ID_PATTERN.fullmatch(self.supervisor_image_id) is None
            or self.source_image_id == self.supervisor_image_id
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time approved launch binding is invalid"
            )

    @property
    def identities(self) -> TrustedTimeImageIdentities:
        return TrustedTimeImageIdentities(
            source_id=self.source_image_id,
            supervisor_id=self.supervisor_image_id,
        )


@dataclass(frozen=True, slots=True)
class TrustedTimeVolumeIdentities:
    """Stable nonsecret identities for the two admitted named volumes."""

    socket_sha256: str
    state_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.socket_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.socket_sha256) is None
            or type(self.state_sha256) is not str
            or _SHA256_PATTERN.fullmatch(self.state_sha256) is None
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time volume identities are invalid"
            )


@dataclass(frozen=True, slots=True)
class SupervisorTerminalEvidence:
    """Closed, nonsecret projection of one admitted supervisor terminal line."""

    state: str
    exit_code: int
    status: str
    reason: str

    def __post_init__(self) -> None:
        if (
            type(self.state) is not str
            or self.state != "exited"
            or type(self.exit_code) is not int
            or isinstance(self.exit_code, bool)
            or self.exit_code != 2
            or type(self.status) is not str
            or self.status != "fatal"
            or type(self.reason) is not str
            or self.reason not in _SUPERVISOR_TERMINAL_REASONS
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time supervisor terminal evidence is invalid"
            )


@dataclass(frozen=True, slots=True)
class _SupervisorNarrowState:
    status: str
    running: bool
    exit_code: int
    oom_killed: bool


class TrustedTimeSupervisorTerminalObserved(RuntimeError):
    """Carry one fully validated, torn-down expected terminal to the CLI."""

    def __init__(
        self,
        evidence: SupervisorTerminalEvidence,
        *,
        approved_launch: TrustedTimeApprovedLaunch,
    ) -> None:
        evidence.__post_init__()
        if (
            evidence.reason != _EXPECTED_UNENROLLED_TERMINAL_REASON
            or type(approved_launch) is not TrustedTimeApprovedLaunch
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time expected supervisor terminal reason was not observed"
            )
        approved_launch.__post_init__()
        self.evidence = evidence
        self.approved_launch = approved_launch
        super().__init__("trusted-time supervisor failed closed")


class TrustedTimeSupervisorTerminalUnqualified(RuntimeError):
    """Carry one valid but unexpected terminal projection to the CLI."""

    def __init__(self, evidence: SupervisorTerminalEvidence) -> None:
        evidence.__post_init__()
        if evidence.reason == _EXPECTED_UNENROLLED_TERMINAL_REASON:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time unqualified supervisor terminal reason is invalid"
            )
        self.evidence = evidence
        super().__init__("trusted-time supervisor terminal was unqualified")


class TrustedTimeSupervisorTerminalNotObserved(RuntimeError):
    """The admission-only observation window ended without qualified evidence."""


class TrustedTimeSupervisorSecureLaunchIncomplete(RuntimeError):
    """An expected terminal occurred before every secure-launch gate completed."""


class TrustedTimeSupervisorAdmissionOutputError(RuntimeError):
    """Canonical receipt output failed after its publication began."""


class TrustedTimeSupervisorAdmissionRetentionUnconfirmed(RuntimeError):
    """Receipt cleanup or its directory durability could not be confirmed."""


class _TrustedTimeSupervisorContainerIdentityUnavailable(TrustedTimeSupervisorConfigurationError):
    """The admitted supervisor disappeared before exact running-state validation."""


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
class TrustedTimeRuntimeConfiguration:
    """One exact launch-only environment projection and its owner-file payloads."""

    database_url: str = field(repr=False)
    head_anchor_payloads: TrustedTimeHeadAnchorSourcePayloads = field(repr=False)


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


def _safe_terminal_payload(evidence: SupervisorTerminalEvidence) -> str:
    evidence.__post_init__()
    return json.dumps(
        {
            "database_secret_disclosed": False,
            "new_exposure_authorized": False,
            "reason": (
                "secure_launch_incomplete"
                if evidence.reason == _EXPECTED_UNENROLLED_TERMINAL_REASON
                else "supervisor_terminal_unqualified"
            ),
            "service": "trusted-time-local-launcher",
            "status": "fatal",
            "supervisor_exit_code": evidence.exit_code,
            "supervisor_reason": evidence.reason,
            "supervisor_state": evidence.state,
            "supervisor_status": evidence.status,
        },
        sort_keys=True,
    )


def _terminal_outcome_error(
    evidence: SupervisorTerminalEvidence,
    *,
    approved_launch: TrustedTimeApprovedLaunch,
) -> RuntimeError:
    if evidence.reason == _EXPECTED_UNENROLLED_TERMINAL_REASON:
        return TrustedTimeSupervisorTerminalObserved(
            evidence,
            approved_launch=approved_launch,
        )
    return TrustedTimeSupervisorTerminalUnqualified(evidence)


def _valid_uuid4(value: object) -> bool:
    if type(value) is not str or _UUID4_PATTERN.fullmatch(value) is None:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _canonical_unenrolled_admission_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        return (
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
            "trusted-time unenrolled admission evidence is invalid"
        ) from None


def _validate_unenrolled_admission_payload(payload: object) -> None:
    if type(payload) is not dict or set(payload) != {
        "admission_id",
        "approved_git_revision",
        "authority_granted",
        "contract_version",
        "database_secret_disclosed",
        "gates",
        "image_admission_sha256",
        "new_exposure_authorized",
        "reason",
        "service",
        "source_image_id",
        "status",
        "supervisor",
        "supervisor_image_id",
    }:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission evidence is invalid"
        )
    gates = payload.get("gates")
    supervisor = payload.get("supervisor")
    if (
        not _valid_uuid4(payload.get("admission_id"))
        or type(payload.get("approved_git_revision")) is not str
        or _GIT_REVISION_PATTERN.fullmatch(payload["approved_git_revision"]) is None
        or payload.get("authority_granted") is not False
        or payload.get("contract_version") != UNENROLLED_ADMISSION_CONTRACT_VERSION
        or payload.get("database_secret_disclosed") is not False
        or type(gates) is not dict
        or set(gates)
        != {
            "runtime_inputs_retired",
            "secure_launch_validated",
            "state_volumes_preserved",
            "topology_removed",
        }
        or any(value is not True for value in gates.values())
        or type(payload.get("image_admission_sha256")) is not str
        or _SHA256_PATTERN.fullmatch(payload["image_admission_sha256"]) is None
        or payload.get("new_exposure_authorized") is not False
        or payload.get("reason") != "expected_unenrolled_fail_closed_observed"
        or payload.get("service") != "trusted-time-local-launcher"
        or type(payload.get("source_image_id")) is not str
        or _IMAGE_ID_PATTERN.fullmatch(payload["source_image_id"]) is None
        or payload.get("status") != "admitted"
        or type(supervisor) is not dict
        or set(supervisor)
        != {
            "authorities_all_false",
            "exit_code",
            "oom_killed",
            "reason",
            "state",
            "status",
        }
        or supervisor.get("authorities_all_false") is not True
        or type(supervisor.get("exit_code")) is not int
        or isinstance(supervisor.get("exit_code"), bool)
        or supervisor.get("exit_code") != 2
        or supervisor.get("oom_killed") is not False
        or supervisor.get("reason") != _EXPECTED_UNENROLLED_TERMINAL_REASON
        or supervisor.get("state") != "exited"
        or supervisor.get("status") != "fatal"
        or type(payload.get("supervisor_image_id")) is not str
        or _IMAGE_ID_PATTERN.fullmatch(payload["supervisor_image_id"]) is None
        or payload.get("source_image_id") == payload.get("supervisor_image_id")
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission evidence is invalid"
        )


def build_unenrolled_admission_receipt(
    *,
    admission_id: str,
    approved_launch: TrustedTimeApprovedLaunch,
    terminal_evidence: SupervisorTerminalEvidence,
) -> bytes:
    """Build one closed, nonsecret receipt for the expected fail-closed run."""

    terminal_evidence.__post_init__()
    if terminal_evidence.reason != _EXPECTED_UNENROLLED_TERMINAL_REASON:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission terminal is unqualified"
        )
    if type(approved_launch) is not TrustedTimeApprovedLaunch:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission approval is invalid"
        )
    approved_launch.__post_init__()
    payload: dict[str, object] = {
        "admission_id": admission_id,
        "approved_git_revision": approved_launch.git_revision,
        "authority_granted": False,
        "contract_version": UNENROLLED_ADMISSION_CONTRACT_VERSION,
        "database_secret_disclosed": False,
        "gates": {
            "runtime_inputs_retired": True,
            "secure_launch_validated": True,
            "state_volumes_preserved": True,
            "topology_removed": True,
        },
        "image_admission_sha256": approved_launch.image_admission_sha256,
        "new_exposure_authorized": False,
        "reason": "expected_unenrolled_fail_closed_observed",
        "service": "trusted-time-local-launcher",
        "source_image_id": approved_launch.source_image_id,
        "status": "admitted",
        "supervisor": {
            "authorities_all_false": True,
            "exit_code": terminal_evidence.exit_code,
            "oom_killed": False,
            "reason": terminal_evidence.reason,
            "state": terminal_evidence.state,
            "status": terminal_evidence.status,
        },
        "supervisor_image_id": approved_launch.supervisor_image_id,
    }
    _validate_unenrolled_admission_payload(payload)
    encoded = _canonical_unenrolled_admission_bytes(payload)
    if not encoded or len(encoded) > MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission evidence is invalid"
        )
    return encoded


def write_unenrolled_admission_receipt(
    artifact_dir: Path,
    encoded: bytes,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    emit: Callable[[bytes], None] | None = None,
) -> Path:
    """Exclusively retain one owner-only content-addressed admission receipt."""

    if (
        not isinstance(artifact_dir, Path)
        or not isinstance(ignored_root, Path)
        or type(encoded) is not bytes
        or not encoded
        or len(encoded) > MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES
        or (emit is not None and not callable(emit))
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission artifact is invalid"
        )
    absolute_directory = Path(os.path.abspath(artifact_dir))
    absolute_ignored_root = Path(os.path.abspath(ignored_root))
    trusted_time_root = absolute_ignored_root / "trusted-time"
    if (
        not artifact_dir.is_absolute()
        or absolute_directory != artifact_dir
        or not ignored_root.is_absolute()
        or absolute_ignored_root != ignored_root
        or (
            absolute_directory != trusted_time_root
            and not absolute_directory.is_relative_to(trusted_time_root)
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission artifact path is invalid"
        )
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_terminal_payload,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission artifact is invalid"
        ) from None
    _validate_unenrolled_admission_payload(payload)
    if _canonical_unenrolled_admission_bytes(payload) != encoded:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission artifact is invalid"
        )

    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    file_name = f"trusted-time-unenrolled-launch-admission-{artifact_sha256}.json"
    temporary_name = f".{file_name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    verification_descriptor: int | None = None
    temporary_created = False
    final_linked = False
    published = False
    written_identity: tuple[int, int] | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=absolute_ignored_root,
            create=True,
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
        written_metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(written_metadata.st_mode)
            or written_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(written_metadata.st_mode) != 0o600
            or written_metadata.st_nlink != 1
            or written_metadata.st_size != len(encoded)
        ):
            raise OSError
        written_identity = (written_metadata.st_dev, written_metadata.st_ino)
        os.close(file_descriptor)
        file_descriptor = None
        os.link(
            temporary_name,
            file_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        final_linked = True
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        temporary_created = False
        os.fsync(directory_descriptor)

        verification_descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
        final_metadata = os.fstat(verification_descriptor)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
            or final_metadata.st_nlink != 1
            or final_metadata.st_size != len(encoded)
            or written_identity != (final_metadata.st_dev, final_metadata.st_ino)
        ):
            raise OSError
        retained = bytearray()
        while len(retained) <= MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES:
            chunk = os.read(
                verification_descriptor,
                min(
                    65_536,
                    MAXIMUM_UNENROLLED_ADMISSION_ARTIFACT_BYTES + 1 - len(retained),
                ),
            )
            if not chunk:
                break
            retained.extend(chunk)
        repeated_metadata = os.fstat(verification_descriptor)
        stable_metadata = (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_mode,
            final_metadata.st_uid,
            final_metadata.st_gid,
            final_metadata.st_nlink,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
            final_metadata.st_ctime_ns,
        )
        repeated_stable_metadata = (
            repeated_metadata.st_dev,
            repeated_metadata.st_ino,
            repeated_metadata.st_mode,
            repeated_metadata.st_uid,
            repeated_metadata.st_gid,
            repeated_metadata.st_nlink,
            repeated_metadata.st_size,
            repeated_metadata.st_mtime_ns,
            repeated_metadata.st_ctime_ns,
        )
        if (
            repeated_stable_metadata != stable_metadata
            or bytes(retained) != encoded
            or hashlib.sha256(retained).hexdigest() != artifact_sha256
        ):
            raise OSError
        os.close(verification_descriptor)
        verification_descriptor = None
        if emit is not None:
            emit(encoded)
        published = True
        return absolute_directory / file_name
    except FileExistsError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission artifact already exists"
        ) from None
    except (OSError, TrustedTimeImageVerificationError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission artifact write failed"
        ) from None
    finally:
        retention_unconfirmed = False
        if verification_descriptor is not None:
            with suppress(OSError):
                os.close(verification_descriptor)
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        if directory_descriptor is not None:
            rollback_attempted = False
            if temporary_created:
                rollback_attempted = True
                try:
                    os.unlink(temporary_name, dir_fd=directory_descriptor)
                except OSError:
                    retention_unconfirmed = True
            if final_linked and not published:
                rollback_attempted = True
                try:
                    os.unlink(file_name, dir_fd=directory_descriptor)
                except OSError:
                    retention_unconfirmed = True
            if rollback_attempted:
                try:
                    os.fsync(directory_descriptor)
                except OSError:
                    retention_unconfirmed = True
            with suppress(OSError):
                os.close(directory_descriptor)
        if retention_unconfirmed:
            raise TrustedTimeSupervisorAdmissionRetentionUnconfirmed(
                "trusted-time unenrolled admission retention is unconfirmed"
            ) from None


def load_runtime_database_url(env_file: Path) -> str:
    variables = ("AQT_DATABASE_URL",)
    if not isinstance(env_file, Path) or env_file.name == ".env":
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time requires a dedicated database-only env file"
        )
    try:
        environment = load_owner_only_environment(
            env_file,
            variables=variables,
            allowed_variables=variables,
            maximum_bytes=MAXIMUM_ENV_FILE_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
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
    if not path.is_absolute() or os.path.abspath(value) != value or path.name in {"", ".", ".."}:
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
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
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

    if not isinstance(env_file, Path) or env_file.name == ".env":
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time requires a dedicated head-anchor env file"
        )
    variables = (
        HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT,
        HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT,
        HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT,
    )
    try:
        environment = load_owner_only_environment(
            env_file,
            variables=variables,
            allowed_variables=variables,
            maximum_bytes=MAXIMUM_ENV_FILE_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
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


def load_trusted_time_runtime_configuration(
    env_file: Path,
) -> TrustedTimeRuntimeConfiguration:
    """Parse exactly four launch assignments once, then open their source files."""

    if not isinstance(env_file, Path) or env_file.name == ".env":
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time requires a dedicated launch-only env file"
        )
    variables = (
        "AQT_DATABASE_URL",
        HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT,
        HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT,
        HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT,
    )
    try:
        environment = load_owner_only_environment(
            env_file,
            variables=variables,
            allowed_variables=variables,
            maximum_bytes=MAXIMUM_ENV_FILE_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
            require_secure_path=True,
            required_mode=0o600,
        )
    except ValueError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time launch-only env file was rejected"
        ) from None
    if set(environment) != set(variables):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time launch-only environment is incomplete"
        )
    database_url = validate_database_url(environment["AQT_DATABASE_URL"])
    payloads = TrustedTimeHeadAnchorSourcePayloads(
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
    return TrustedTimeRuntimeConfiguration(
        database_url=database_url,
        head_anchor_payloads=payloads,
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


def _acquire_trusted_time_launch_lock(
    *,
    path: Path = TRUSTED_TIME_LAUNCH_LOCK_PATH,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> int:
    """Acquire the shared nonblocking lock for every trusted-time launcher."""

    if (
        not isinstance(path, Path)
        or not isinstance(ignored_root, Path)
        or not path.is_absolute()
        or Path(os.path.abspath(path)) != path
        or path.parent != Path(os.path.abspath(ignored_root)) / "trusted-time"
        or path.name != TRUSTED_TIME_LAUNCH_LOCK_PATH.name
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time launcher lock path is invalid")
    directory_descriptor: int | None = None
    lock_descriptor: int | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            path.parent,
            ignored_root=ignored_root,
            create=True,
        )
        lock_descriptor = os.open(
            path.name,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        metadata = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise OSError
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(directory_descriptor)
        return lock_descriptor
    except (OSError, BlockingIOError):
        if lock_descriptor is not None:
            with suppress(OSError):
                os.close(lock_descriptor)
        raise TrustedTimeSupervisorConfigurationError(
            "another trusted-time launcher is active"
        ) from None
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


def _release_trusted_time_launch_lock(lock_descriptor: int) -> None:
    """Release one shared launcher lock descriptor without deleting its inode."""

    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time launcher lock release failed"
        ) from None


def _require_no_retained_first_enrollment_claim(
    *,
    artifact_dir: Path = DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> None:
    """Keep normal supervision closed after any one-shot approval is consumed."""

    if (
        not isinstance(artifact_dir, Path)
        or not isinstance(ignored_root, Path)
        or artifact_dir != Path(os.path.abspath(ignored_root)) / "trusted-time"
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment claim boundary is invalid"
        )
    directory_descriptor: int | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            artifact_dir,
            ignored_root=ignored_root,
            create=False,
        )
        entries = os.listdir(directory_descriptor)
    except (OSError, TrustedTimeImageVerificationError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time first enrollment claim state is unavailable"
        ) from None
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
    if (
        len(entries) > 4_096
        or any(type(entry) is not str or len(entry) > 255 for entry in entries)
        or any(
            entry.startswith(FIRST_ENROLLMENT_CLAIM_FILE_PREFIX)
            and entry.endswith(FIRST_ENROLLMENT_CLAIM_FILE_SUFFIX)
            for entry in entries
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time normal launch is blocked by a first enrollment claim"
        )


def _compose_prefix() -> tuple[str, ...]:
    return (
        "docker",
        "compose",
        "--env-file",
        os.devnull,
        "--project-directory",
        str(COMPOSE_PATH.parent),
        "--file",
        "-",
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


def _docker_environment_projection(environment: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in environment.items() if key in _PASSTHROUGH_ENVIRONMENT}


def _minimal_docker_environment() -> dict[str, str]:
    return _docker_environment_projection(os.environ)


def _minimal_git_environment() -> dict[str, str]:
    """Return a fixed, secretless environment for the read-only revision check."""

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


def _current_git_revision() -> str:
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
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Git revision is unavailable"
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
        raise TrustedTimeSupervisorConfigurationError("trusted-time Git revision is unavailable")
    try:
        _require_ordinary_git_index_flags(environment=environment)
        _require_head_reviewed_inputs(revision, environment=environment)
        after_status_result = run_git(
            status_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_STATUS_STDOUT_BYTES,
        )
        after = run_git(
            revision_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_REVISION_STDOUT_BYTES,
        )
    except (
        BoundedSubprocessError,
        UnicodeError,
        TrustedTimeImageVerificationError,
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Git revision is unavailable"
        ) from None
    if (
        after_status_result.returncode != 0
        or after_status_result.stdout
        or after_status_result.stderr
        or after.returncode != 0
        or after.stderr
        or after.stdout != f"{revision}\n"
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time Git revision is unavailable")
    return revision


def _require_approved_git_revision(approved_launch: TrustedTimeApprovedLaunch) -> None:
    approved_launch.__post_init__()
    if _current_git_revision() != approved_launch.git_revision:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time approved Git revision changed before launch"
        )


def _validate_image_admission_artifact_path(
    image_admission_artifact: Path,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> Path:
    if not isinstance(image_admission_artifact, Path) or not isinstance(ignored_root, Path):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time image admission artifact path is invalid"
        )
    absolute = Path(os.path.abspath(image_admission_artifact))
    root = Path(os.path.abspath(ignored_root))
    if (
        not image_admission_artifact.is_absolute()
        or absolute != image_admission_artifact
        or not ignored_root.is_absolute()
        or root != ignored_root
        or absolute == root
        or not absolute.is_relative_to(root)
        or absolute.name in {"", ".", ".."}
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time image admission artifact path is invalid"
        )
    return absolute


def _approved_image_admission_path(
    image_admission_artifact: Path,
    approved_launch: TrustedTimeApprovedLaunch,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> Path:
    absolute = _validate_image_admission_artifact_path(
        image_admission_artifact,
        ignored_root=ignored_root,
    )
    try:
        return absolute.with_name(f"image-admission-{approved_launch.image_admission_sha256}.json")
    except (OSError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time image admission artifact path is invalid"
        ) from None


def _load_approved_image_admission(
    image_admission_artifact: Path,
    approved_launch: TrustedTimeApprovedLaunch,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> TrustedTimeImageAdmission:
    approved_launch.__post_init__()
    admission = load_image_admission_artifact(
        _approved_image_admission_path(
            image_admission_artifact,
            approved_launch,
            ignored_root=ignored_root,
        ),
        ignored_root=ignored_root,
    )
    if (
        admission.artifact_sha256 != approved_launch.image_admission_sha256
        or admission.git_revision != approved_launch.git_revision
        or admission.identities != approved_launch.identities
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time image admission differs from the approved launch binding"
        )
    return admission


def _validate_runtime_compose_payload(compose_payload: object) -> bytes:
    if (
        type(compose_payload) is not bytes
        or not compose_payload
        or len(compose_payload) > _MAXIMUM_BOUNDED_COMPOSE_PAYLOAD_BYTES
        or b"\0" in compose_payload
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time immutable Compose payload is unavailable"
        )
    try:
        compose_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time immutable Compose payload is unavailable"
        ) from None
    return compose_payload


def _require_approved_launch_state(
    image_admission_artifact: Path,
    approved_launch: TrustedTimeApprovedLaunch,
    *,
    expected_admission: TrustedTimeImageAdmission,
) -> None:
    _require_approved_git_revision(approved_launch)
    if (
        _load_approved_image_admission(image_admission_artifact, approved_launch)
        != expected_admission
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time approved image admission changed before launch"
        )


def _run_docker(
    argv: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    timeout_seconds: float = 120,
    compose_payload: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    is_compose = argv[: len(_compose_prefix())] == _compose_prefix()
    if is_compose:
        stdin = _validate_runtime_compose_payload(compose_payload).decode("utf-8")
    else:
        if compose_payload is not None:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time immutable Compose payload is invalid"
            )
        stdin = None
    process_environment = (
        dict(environment) if is_compose else _docker_environment_projection(environment)
    )
    maximum_stdout_bytes = (
        _MAXIMUM_DOCKER_INSPECTION_STDOUT_BYTES
        if "inspect" in argv
        else _MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES
    )
    try:
        return _decode_bounded_subprocess(
            run_bounded_subprocess(
                argv,
                cwd=ROOT,
                environment=process_environment,
                timeout_seconds=timeout_seconds,
                maximum_stdout_bytes=maximum_stdout_bytes,
                maximum_stderr_bytes=_MAXIMUM_DOCKER_STDERR_BYTES,
                stdin_bytes=None if stdin is None else stdin.encode("utf-8"),
                maximum_stdin_bytes=(
                    0 if stdin is None else _MAXIMUM_BOUNDED_COMPOSE_PAYLOAD_BYTES
                ),
            )
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time Docker Compose was unavailable"
        ) from None


def _run_docker_bounded(
    argv: tuple[str, ...],
    *,
    environment: Mapping[str, str],
    maximum_stdout_bytes: int,
    maximum_stderr_bytes: int,
    timeout_seconds: float,
    compose_payload: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one fixed Docker read with hard byte and absolute-time bounds."""

    exact_observation = (
        (
            len(argv) == 6
            and argv[:4] == ("docker", "container", "inspect", "--format")
            and argv[4] == _SUPERVISOR_NARROW_STATE_FORMAT
            and _FULL_CONTAINER_ID_PATTERN.fullmatch(argv[5]) is not None
        )
        or (
            len(argv) == 6
            and argv[:5] == ("docker", "container", "logs", "--tail", "1")
            and _FULL_CONTAINER_ID_PATTERN.fullmatch(argv[5]) is not None
        )
        or (
            argv
            == (
                *_compose_prefix(),
                "ps",
                "--all",
                "--quiet",
                "trusted-time-supervisor",
            )
        )
        or argv == (*_compose_prefix(), "ps", "--all", "--quiet")
        or argv
        == (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{COMPOSE_NETWORK_NAME}$",
        )
    )
    is_compose = argv[: len(_compose_prefix())] == _compose_prefix()
    if (
        not exact_observation
        or type(maximum_stdout_bytes) is not int
        or not 0 < maximum_stdout_bytes <= MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES
        or type(maximum_stderr_bytes) is not int
        or not 0 < maximum_stderr_bytes <= MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES
        or type(timeout_seconds) not in {int, float}
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= 2
        or (is_compose and (type(compose_payload) is not bytes or not compose_payload))
        or (not is_compose and compose_payload is not None)
        or (
            isinstance(compose_payload, bytes)
            and len(compose_payload) > _MAXIMUM_BOUNDED_COMPOSE_PAYLOAD_BYTES
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time bounded Docker observation is invalid"
        )
    process_environment = (
        dict(environment) if is_compose else _docker_environment_projection(environment)
    )
    try:
        completed = run_bounded_subprocess(
            argv,
            cwd=ROOT,
            environment=process_environment,
            timeout_seconds=timeout_seconds,
            maximum_stdout_bytes=maximum_stdout_bytes,
            maximum_stderr_bytes=maximum_stderr_bytes,
            stdin_bytes=compose_payload,
            maximum_stdin_bytes=(
                0 if compose_payload is None else _MAXIMUM_BOUNDED_COMPOSE_PAYLOAD_BYTES
            ),
        )
        return subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            completed.stdout.decode("ascii", errors="strict"),
            completed.stderr.decode("ascii", errors="strict"),
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time bounded Docker observation is unavailable"
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
    compose_payload: bytes,
    include_stopped: bool = False,
    timeout_seconds: float = 120,
) -> str:
    if type(include_stopped) is not bool:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time container identity selection is invalid"
        )
    selection = ("--all",) if include_stopped else ()
    argv = (*_compose_prefix(), "ps", *selection, "--quiet", service_name)
    completed = (
        _run_docker_bounded(
            argv,
            environment=environment,
            maximum_stdout_bytes=128,
            maximum_stderr_bytes=1_024,
            timeout_seconds=timeout_seconds,
            compose_payload=compose_payload,
        )
        if include_stopped
        else _run_docker(
            argv,
            environment=environment,
            timeout_seconds=timeout_seconds,
            compose_payload=compose_payload,
        )
    )
    lines = completed.stdout.splitlines()
    if (
        completed.returncode != 0
        or completed.stderr
        or len(lines) != 1
        or _FULL_CONTAINER_ID_PATTERN.fullmatch(lines[0]) is None
    ):
        error_type: type[TrustedTimeSupervisorConfigurationError] = (
            _TrustedTimeSupervisorContainerIdentityUnavailable
            if not include_stopped and service_name == "trusted-time-supervisor"
            else TrustedTimeSupervisorConfigurationError
        )
        raise error_type("trusted-time created container identity is unavailable")
    return lines[0]


def _optional_stopped_supervisor_container_id(
    *,
    environment: Mapping[str, str],
    compose_payload: bytes,
    timeout_seconds: float = 2,
) -> str | None:
    """Return zero or one exact stopped/running Compose supervisor identity."""

    argv = (
        *_compose_prefix(),
        "ps",
        "--all",
        "--quiet",
        "trusted-time-supervisor",
    )
    completed = _run_docker_bounded(
        argv,
        environment=environment,
        maximum_stdout_bytes=128,
        maximum_stderr_bytes=1_024,
        timeout_seconds=timeout_seconds,
        compose_payload=compose_payload,
    )
    lines = completed.stdout.splitlines()
    if (
        completed.returncode != 0
        or completed.stderr
        or len(lines) > 1
        or (lines and _FULL_CONTAINER_ID_PATTERN.fullmatch(lines[0]) is None)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time prior supervisor identity is unavailable"
        )
    return lines[0] if lines else None


def _inspect_supervisor_narrow_state(
    container_id: str,
    *,
    expected_image_id: str,
    environment: Mapping[str, str],
    timeout_seconds: float = 2,
) -> _SupervisorNarrowState:
    if (
        _FULL_CONTAINER_ID_PATTERN.fullmatch(container_id) is None
        or type(expected_image_id) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id) is None
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal identity is invalid"
        )
    completed = _run_docker_bounded(
        (
            "docker",
            "container",
            "inspect",
            "--format",
            _SUPERVISOR_NARROW_STATE_FORMAT,
            container_id,
        ),
        environment=environment,
        maximum_stdout_bytes=2_048,
        maximum_stderr_bytes=1_024,
        timeout_seconds=timeout_seconds,
    )
    try:
        encoded = completed.stdout.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        encoded = b""
    lines = completed.stdout.splitlines()
    if (
        completed.returncode != 0
        or completed.stderr
        or not encoded
        or len(encoded) > 2_048
        or len(lines) != 1
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal state is unavailable"
        )
    fields = lines[0].split("\t")
    if len(fields) != 11:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal state is malformed"
        )
    try:
        (
            inspected_container_id,
            image_id,
            project,
            service,
            restart_count,
            status,
            running,
            exit_code,
            oom_killed,
            dead,
            state_error,
        ) = (json.loads(field) for field in fields)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal state is malformed"
        ) from None
    if (
        inspected_container_id != container_id
        or image_id != expected_image_id
        or project != "autoquanttrader-trusted-time"
        or service != "trusted-time-supervisor"
        or type(restart_count) is not int
        or isinstance(restart_count, bool)
        or restart_count != 0
        or type(status) is not str
        or type(running) is not bool
        or type(exit_code) is not int
        or isinstance(exit_code, bool)
        or type(oom_killed) is not bool
        or type(dead) is not bool
        or dead
        or type(state_error) is not str
        or state_error
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal identity or state drifted"
        )
    state = _SupervisorNarrowState(
        status=status,
        running=running,
        exit_code=exit_code,
        oom_killed=oom_killed,
    )
    if state == _SupervisorNarrowState(
        status="running",
        running=True,
        exit_code=0,
        oom_killed=False,
    ) or state == _SupervisorNarrowState(
        status="exited",
        running=False,
        exit_code=2,
        oom_killed=False,
    ):
        return state
    raise TrustedTimeSupervisorConfigurationError(
        "trusted-time supervisor terminal state is unqualified"
    )


def _unique_terminal_payload(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _read_supervisor_terminal_evidence(
    container_id: str,
    *,
    environment: Mapping[str, str],
    timeout_seconds: float = 2,
) -> SupervisorTerminalEvidence:
    completed = _run_docker_bounded(
        ("docker", "container", "logs", "--tail", "1", container_id),
        environment=environment,
        maximum_stdout_bytes=MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES,
        maximum_stderr_bytes=1_024,
        timeout_seconds=timeout_seconds,
    )
    try:
        encoded = completed.stdout.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        encoded = b""
    if (
        completed.returncode != 0
        or completed.stderr
        or not encoded
        or len(encoded) > MAXIMUM_SUPERVISOR_TERMINAL_LINE_BYTES
        or not completed.stdout.endswith("\n")
        or completed.stdout.count("\n") != 1
        or "\r" in completed.stdout
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal line is unavailable"
        )
    try:
        payload: Any = json.loads(
            completed.stdout,
            object_pairs_hook=_unique_terminal_payload,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal line is malformed"
        ) from None
    if (
        type(payload) is not dict
        or set(payload) != _SUPERVISOR_AUTHORITY_FIELDS | {"reason", "service", "status"}
        or any(payload.get(field_name) is not False for field_name in _SUPERVISOR_AUTHORITY_FIELDS)
        or type(payload.get("reason")) is not str
        or payload.get("reason") not in _SUPERVISOR_TERMINAL_REASONS
        or type(payload.get("service")) is not str
        or payload.get("service") != "trusted-time-supervisor"
        or type(payload.get("status")) is not str
        or payload.get("status") != "fatal"
        or json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n" != completed.stdout
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal line is unqualified"
        )
    return SupervisorTerminalEvidence(
        state="exited",
        exit_code=2,
        status="fatal",
        reason=payload["reason"],
    )


def observe_unenrolled_supervisor_terminal(
    *,
    expected_image_id: str,
    environment: Mapping[str, str],
    compose_payload: bytes,
    container_id: str | None = None,
    timeout_seconds: float = UNENROLLED_TERMINAL_OBSERVATION_TIMEOUT_SECONDS,
    monotonic_clock: Any = time.monotonic,
    sleeper: Any = time.sleep,
) -> SupervisorTerminalEvidence | None:
    """Observe one terminal line without retaining raw logs or broad inspection."""

    if (
        type(timeout_seconds) not in {int, float}
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or not 0 <= float(timeout_seconds) <= UNENROLLED_TERMINAL_OBSERVATION_TIMEOUT_SECONDS
        or type(expected_image_id) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id) is None
        or not callable(monotonic_clock)
        or not callable(sleeper)
        or type(compose_payload) is not bytes
        or not compose_payload
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal observation bound is invalid"
        )
    observer_environment = {
        key: value for key, value in environment.items() if key in _PASSTHROUGH_ENVIRONMENT
    }
    compose_observer_environment = dict(observer_environment)
    compose_observer_environment[SOURCE_IMAGE_ENVIRONMENT] = expected_image_id
    compose_observer_environment[SUPERVISOR_IMAGE_ENVIRONMENT] = expected_image_id
    compose_observer_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = str(
        PLACEHOLDER_DATABASE_SECRET_FILE
    )
    compose_observer_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE
    )
    compose_observer_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE
    )
    compose_observer_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
    )
    started = monotonic_clock()
    if (
        type(started) not in {int, float}
        or isinstance(started, bool)
        or not math.isfinite(float(started))
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal observation clock is invalid"
        )
    observed = float(started)
    deadline = observed + float(timeout_seconds)
    exact_container_id = container_id
    if exact_container_id is None:
        if observed >= deadline:
            return None
        exact_container_id = _compose_container_id(
            "trusted-time-supervisor",
            environment=compose_observer_environment,
            compose_payload=compose_payload,
            include_stopped=True,
            timeout_seconds=min(2.0, deadline - observed),
        )
    while True:
        current = monotonic_clock()
        if (
            type(current) not in {int, float}
            or isinstance(current, bool)
            or not math.isfinite(float(current))
            or float(current) < observed
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time supervisor terminal observation clock is invalid"
            )
        observed = float(current)
        if observed >= deadline:
            return None
        state = _inspect_supervisor_narrow_state(
            exact_container_id,
            expected_image_id=expected_image_id,
            environment=observer_environment,
            timeout_seconds=min(2.0, deadline - observed),
        )
        if state.status == "exited":
            current = monotonic_clock()
            if (
                type(current) not in {int, float}
                or isinstance(current, bool)
                or not math.isfinite(float(current))
                or float(current) < observed
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time supervisor terminal observation clock is invalid"
                )
            observed = float(current)
            if observed >= deadline:
                return None
            evidence = _read_supervisor_terminal_evidence(
                exact_container_id,
                environment=observer_environment,
                timeout_seconds=min(2.0, deadline - observed),
            )
            if evidence.exit_code != state.exit_code:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time supervisor terminal line conflicts with state"
                )
            current = monotonic_clock()
            if (
                type(current) not in {int, float}
                or isinstance(current, bool)
                or not math.isfinite(float(current))
                or float(current) < observed
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time supervisor terminal observation clock is invalid"
                )
            observed = float(current)
            if observed >= deadline:
                return None
            repeated_container_id = _compose_container_id(
                "trusted-time-supervisor",
                environment=compose_observer_environment,
                compose_payload=compose_payload,
                include_stopped=True,
                timeout_seconds=min(2.0, deadline - observed),
            )
            current = monotonic_clock()
            if (
                type(current) not in {int, float}
                or isinstance(current, bool)
                or not math.isfinite(float(current))
                or float(current) < observed
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time supervisor terminal observation clock is invalid"
                )
            if float(current) >= deadline:
                return None
            if repeated_container_id != exact_container_id:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time supervisor terminal identity changed during observation"
                )
            return evidence
        current = monotonic_clock()
        if (
            type(current) not in {int, float}
            or isinstance(current, bool)
            or not math.isfinite(float(current))
            or float(current) < observed
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time supervisor terminal observation clock is invalid"
            )
        observed = float(current)
        if observed >= deadline:
            return None
        sleeper(min(UNENROLLED_TERMINAL_OBSERVATION_POLL_SECONDS, deadline - observed))


def _observe_unenrolled_supervisor_terminal_safely(
    **kwargs: Any,
) -> SupervisorTerminalEvidence | None:
    """Keep unexpected observer failures inside the launcher's safe error boundary."""

    try:
        return observe_unenrolled_supervisor_terminal(**kwargs)
    except TrustedTimeSupervisorConfigurationError:
        raise
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time supervisor terminal observation failed"
        ) from None


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


def _stable_volume_identity_sha256(
    inspection: object,
    *,
    expected_name: str,
) -> str:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeSupervisorConfigurationError("trusted-time volume identity is malformed")
    volume = _mapping(inspection[0], "trusted-time volume identity")
    created_at = volume.get("CreatedAt")
    mountpoint = volume.get("Mountpoint")
    labels = volume.get("Labels")
    options = volume.get("Options")
    if (
        volume.get("Name") != expected_name
        or volume.get("Driver") != "local"
        or volume.get("Scope") != "local"
        or type(created_at) is not str
        or not created_at
        or len(created_at) > 128
        or any(character in created_at for character in "\x00\r\n")
        or type(mountpoint) is not str
        or not mountpoint
        or len(mountpoint) > 4_096
        or not Path(mountpoint).is_absolute()
        or type(labels) is not dict
        or any(type(key) is not str or type(value) is not str for key, value in labels.items())
        or (options is not None and type(options) is not dict)
        or (
            type(options) is dict
            and any(
                type(key) is not str or type(value) is not str for key, value in options.items()
            )
        )
    ):
        raise TrustedTimeSupervisorConfigurationError("trusted-time volume identity is malformed")
    try:
        encoded = json.dumps(
            {
                "created_at": created_at,
                "driver": volume.get("Driver"),
                "labels": labels,
                "mountpoint": mountpoint,
                "name": expected_name,
                "options": options,
                "scope": volume.get("Scope"),
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii", errors="strict")
    except (TypeError, UnicodeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time volume identity is malformed"
        ) from None
    return hashlib.sha256(encoded).hexdigest()


def _capture_trusted_time_volume_identities(
    *,
    environment: Mapping[str, str],
) -> TrustedTimeVolumeIdentities:
    socket_inspection = _inspect_volume(COMPOSE_SOCKET_VOLUME_NAME, environment=environment)
    validate_socket_volume_inspection(
        socket_inspection,
        expected_name=COMPOSE_SOCKET_VOLUME_NAME,
    )
    state_inspection = _inspect_volume(COMPOSE_STATE_VOLUME_NAME, environment=environment)
    validate_chrony_state_volume_inspection(state_inspection)
    return TrustedTimeVolumeIdentities(
        socket_sha256=_stable_volume_identity_sha256(
            socket_inspection,
            expected_name=COMPOSE_SOCKET_VOLUME_NAME,
        ),
        state_sha256=_stable_volume_identity_sha256(
            state_inspection,
            expected_name=COMPOSE_STATE_VOLUME_NAME,
        ),
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
    first_enrollment = expected_service == FIRST_ENROLLMENT_SERVICE
    if expected_service not in {
        "chrony-nts",
        "trusted-time-supervisor",
        FIRST_ENROLLMENT_SERVICE,
    }:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime service identity drifted"
        )
    source_state_is_legacy_bind = source and len(volume_requests) == 1
    expected_volume_count = (
        0 if first_enrollment else (1 if source_state_is_legacy_bind else (2 if source else 1))
    )
    if len(volume_requests) != expected_volume_count:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime volume request set drifted"
        )
    by_target = {request.get("Target"): request for request in volume_requests}
    if (
        len(by_target) != len(volume_requests)
        or (first_enrollment and by_target)
        or (not first_enrollment and "/run/chrony" not in by_target)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime volume request set drifted"
        )
    if not first_enrollment:
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
    if (first_enrollment and by_target) or (
        not first_enrollment and set(by_target) != {"/run/chrony"}
    ):
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
    if expected_service == "chrony-nts":
        expected_targets = {"/run/chrony", "/var/lib/chrony"}
    elif expected_service == FIRST_ENROLLMENT_SERVICE:
        expected_targets = {
            DATABASE_SECRET_RUNTIME_PATH,
            HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
            HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
            HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
        }
    elif expected_service == "trusted-time-supervisor":
        expected_targets = {
            "/run/chrony",
            DATABASE_SECRET_RUNTIME_PATH,
            HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
            HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
            HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
        }
    else:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time runtime service identity drifted"
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
    if expected_service != FIRST_ENROLLMENT_SERVICE:
        socket_mount = by_target["/run/chrony"]
        if (
            socket_mount.get("Type") != "volume"
            or socket_mount.get("Name") != COMPOSE_SOCKET_VOLUME_NAME
            or socket_mount.get("RW") is not True
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time runtime socket mount drifted"
            )
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


def _validate_trusted_time_container_runtime_policy(
    container: Mapping[str, object],
    configuration: Mapping[str, object],
    host: Mapping[str, object],
    state: Mapping[str, object],
    *,
    expected_image_configuration: Mapping[str, object],
    expected_service: str,
    require_healthy: bool,
    expected_database_secret_file: Path | None,
    expected_head_anchor_authority_file: Path | None,
    expected_head_anchor_auth_secret_file: Path | None,
    expected_head_anchor_signing_key_secret_file: Path | None,
) -> None:
    """Validate the shared image, environment, hardening, and mount policy."""

    if expected_service not in {
        "chrony-nts",
        "trusted-time-supervisor",
        FIRST_ENROLLMENT_SERVICE,
    }:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container service identity drifted"
        )
    for field_name in ("User", "Entrypoint", "WorkingDir", "ExposedPorts"):
        if configuration.get(field_name) != expected_image_configuration.get(field_name):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time created container command or image configuration drifted"
            )
    expected_command = (
        [FIRST_ENROLLMENT_COMMAND]
        if expected_service == FIRST_ENROLLMENT_SERVICE
        else expected_image_configuration.get("Cmd")
    )
    if configuration.get("Cmd") != expected_command:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container command or image configuration drifted"
        )
    expected_environment = _environment_mapping(
        expected_image_configuration.get("Env"),
        "trusted-time admitted image environment",
    )
    if expected_service == "trusted-time-supervisor":
        expected_environment.update(_SUPERVISOR_RUNTIME_ENVIRONMENT)
    elif expected_service == FIRST_ENROLLMENT_SERVICE:
        expected_environment.update(_FIRST_ENROLLMENT_RUNTIME_ENVIRONMENT)
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


def validate_created_container(
    inspection: object,
    *,
    expected_image_id: str,
    expected_image_configuration: Mapping[str, object],
    expected_service: str,
    require_healthy: bool,
    allow_stopped: bool = False,
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
    running_state = state.get("Running") is True and state.get("Status") == "running"
    removable_one_shot_state = (
        allow_stopped
        and expected_service == FIRST_ENROLLMENT_SERVICE
        and require_healthy is False
        and type(state.get("Running")) is bool
        and state.get("Status")
        in {"created", "running", "restarting", "removing", "paused", "exited", "dead"}
        and type(state.get("ExitCode")) is int
        and type(state.get("OOMKilled")) is bool
        and type(state.get("Dead")) is bool
        and type(state.get("Error")) is str
        and container.get("RestartCount") == 0
    )
    if (
        type(allow_stopped) is not bool
        or container.get("Image") != expected_image_id
        or labels.get("com.docker.compose.project") != "autoquanttrader-trusted-time"
        or labels.get("com.docker.compose.service") != expected_service
        or not (running_state or removable_one_shot_state)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container identity or state drifted"
        )
    allowed_networks = (
        ({COMPOSE_NETWORK_NAME}, set())
        if allow_stopped and expected_service == FIRST_ENROLLMENT_SERVICE
        else ({COMPOSE_NETWORK_NAME},)
    )
    if set(networks) not in allowed_networks:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time created container network attachment drifted"
        )
    _validate_trusted_time_container_runtime_policy(
        container,
        configuration,
        host,
        state,
        expected_image_configuration=expected_image_configuration,
        expected_service=expected_service,
        require_healthy=require_healthy,
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )


_NEVER_STARTED_CREATED_STATE_KEYS = frozenset(
    {
        "Dead",
        "Error",
        "ExitCode",
        "FinishedAt",
        "OOMKilled",
        "Paused",
        "Pid",
        "Restarting",
        "Running",
        "StartedAt",
        "Status",
    }
)
_ZERO_DOCKER_TIMESTAMP = "0001-01-01T00:00:00Z"
_EXACT_CREATED_REQUIRED_CONFIG_KEYS = frozenset(
    {
        "Cmd",
        "Entrypoint",
        "Env",
        "ExposedPorts",
        "Healthcheck",
        "Image",
        "Labels",
        "User",
        "WorkingDir",
    }
)
_EXACT_CREATED_REQUIRED_HOST_CONFIG_KEYS = frozenset(
    {
        "AutoRemove",
        "Binds",
        "CapAdd",
        "CapDrop",
        "DeviceCgroupRules",
        "Devices",
        "ExtraHosts",
        "GroupAdd",
        "Init",
        "IpcMode",
        "Memory",
        "Mounts",
        "NanoCpus",
        "NetworkMode",
        "OomKillDisable",
        "PidMode",
        "PidsLimit",
        "PortBindings",
        "Privileged",
        "PublishAllPorts",
        "ReadonlyRootfs",
        "RestartPolicy",
        "SecurityOpt",
        "Tmpfs",
        "UTSMode",
        "VolumesFrom",
    }
)
_EXACT_CREATED_EXPLICIT_HIGH_RISK_HOST_CONFIG_KEYS = frozenset(
    {
        "CgroupnsMode",
        "DeviceRequests",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "Links",
        "LogConfig",
        "MaskedPaths",
        "ReadonlyPaths",
        "UsernsMode",
    }
)
_EXACT_CREATED_MINIMUM_MASKED_PATHS = frozenset(
    {
        "/proc/acpi",
        "/proc/asound",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/sys/firmware",
    }
)
_EXACT_CREATED_MINIMUM_READONLY_PATHS = frozenset(
    {
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger",
    }
)


def _expected_container_path_and_args(
    expected_image_configuration: Mapping[str, object],
) -> tuple[str, list[str]]:
    entrypoint_value = expected_image_configuration.get("Entrypoint")
    entrypoint = (
        []
        if entrypoint_value is None
        else _string_sequence(
            entrypoint_value,
            "trusted-time admitted image entrypoint",
        )
    )
    command = _string_sequence(
        expected_image_configuration.get("Cmd"),
        "trusted-time admitted image command",
    )
    process = [*entrypoint, *command]
    if not process:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admitted image process is malformed"
        )
    return process[0], process[1:]


def _validate_exact_never_started_created_state(
    container: Mapping[str, object],
    state: Mapping[str, object],
) -> None:
    if (
        set(state) != _NEVER_STARTED_CREATED_STATE_KEYS
        or state.get("Status") != "created"
        or state.get("Running") is not False
        or state.get("Paused") is not False
        or state.get("Restarting") is not False
        or state.get("OOMKilled") is not False
        or state.get("Dead") is not False
        or type(state.get("Pid")) is not int
        or state.get("Pid") != 0
        or type(state.get("ExitCode")) is not int
        or state.get("ExitCode") != 0
        or state.get("Error") != ""
        or state.get("StartedAt") != _ZERO_DOCKER_TIMESTAMP
        or state.get("FinishedAt") != _ZERO_DOCKER_TIMESTAMP
        or type(container.get("RestartCount")) is not int
        or container.get("RestartCount") != 0
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time container is not exact never-started created state"
        )


def _validate_exact_never_started_projection_presence(
    configuration: Mapping[str, object],
    host: Mapping[str, object],
) -> None:
    if not _EXACT_CREATED_REQUIRED_CONFIG_KEYS.issubset(configuration):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started Config projection is incomplete"
        )
    if not (
        _EXACT_CREATED_REQUIRED_HOST_CONFIG_KEYS
        | _EXACT_CREATED_EXPLICIT_HIGH_RISK_HOST_CONFIG_KEYS
    ).issubset(host):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started HostConfig projection is incomplete"
        )


def _is_explicit_neutral_list(value: object) -> bool:
    return value is None or (type(value) is list and not value)


def _is_explicit_neutral_mapping(value: object) -> bool:
    return value is None or (type(value) is dict and not value)


def _is_string_list_containing(
    value: object,
    minimum: frozenset[str],
) -> bool:
    return (
        type(value) is list and all(type(item) is str for item in value) and minimum.issubset(value)
    )


def _validate_exact_never_started_host_boundary(host: Mapping[str, object]) -> None:
    if (
        host.get("AutoRemove") is not False
        or host.get("PidMode") != ""
        or host.get("IpcMode") != "private"
        or host.get("UTSMode") != ""
        or not _is_explicit_neutral_list(host.get("GroupAdd"))
        or not _is_explicit_neutral_list(host.get("VolumesFrom"))
        or not _is_explicit_neutral_list(host.get("ExtraHosts"))
        or host.get("OomKillDisable") not in (None, False)
        or type(host.get("OomKillDisable")) not in (type(None), bool)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started host isolation drifted"
        )


def _validate_exact_never_started_high_risk_boundary(
    configuration: Mapping[str, object],
    host: Mapping[str, object],
    *,
    expected_image_configuration: Mapping[str, object],
) -> None:
    sysctls = host.get("Sysctls")
    log_configuration = host.get("LogConfig")
    expected_stop_signal = expected_image_configuration.get("StopSignal")
    runtime_stop_signal = configuration.get("StopSignal")
    if (
        not _is_explicit_neutral_list(host.get("DeviceRequests"))
        or host.get("CgroupnsMode") != "private"
        or host.get("UsernsMode") != ""
        or host.get("Cgroup") not in (None, "")
        or type(log_configuration) is not dict
        or type(log_configuration.get("Config")) is not dict
        or log_configuration != {"Type": "json-file", "Config": {}}
        or any(
            not _is_explicit_neutral_list(host.get(field_name))
            for field_name in ("Dns", "DnsOptions", "DnsSearch", "Links")
        )
        or not _is_explicit_neutral_mapping(sysctls)
        or not _is_string_list_containing(
            host.get("MaskedPaths"),
            _EXACT_CREATED_MINIMUM_MASKED_PATHS,
        )
        or not _is_string_list_containing(
            host.get("ReadonlyPaths"),
            _EXACT_CREATED_MINIMUM_READONLY_PATHS,
        )
        or (
            "NetworkDisabled" in configuration and configuration.get("NetworkDisabled") is not False
        )
        or type(runtime_stop_signal) is not type(expected_stop_signal)
        or runtime_stop_signal != expected_stop_signal
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started high-risk runtime boundary drifted"
        )


def _validate_exact_never_started_numeric_types(
    configuration: Mapping[str, object],
    host: Mapping[str, object],
    *,
    expected_service: str,
) -> None:
    restart_policy = _mapping(
        host.get("RestartPolicy"),
        "trusted-time never-started restart policy",
    )
    numeric_values = [
        host.get("PidsLimit"),
        host.get("NanoCpus"),
        host.get("Memory"),
        restart_policy.get("MaximumRetryCount"),
    ]
    if expected_service == "chrony-nts":
        healthcheck = _mapping(
            configuration.get("Healthcheck"),
            "trusted-time never-started source healthcheck",
        )
        numeric_values.extend(
            healthcheck.get(field_name)
            for field_name in ("Interval", "Timeout", "StartPeriod", "Retries")
        )
        if "StartInterval" in healthcheck:
            numeric_values.append(healthcheck.get("StartInterval"))
    if any(type(value) is not int for value in numeric_values):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started numeric runtime boundary drifted"
        )


def _is_absolute_lexically_canonical_path(value: object) -> bool:
    if type(value) is not type(Path()) or not value.is_absolute():
        return False
    try:
        encoded = os.fspath(value)
        return (
            encoded.startswith("/")
            and not encoded.startswith("//")
            and not any(ord(character) < 32 or ord(character) == 127 for character in encoded)
            and value == Path(os.path.abspath(encoded))
        )
    except (OSError, TypeError, ValueError):
        return False


def validate_exact_never_started_created_container(
    inspection: object,
    *,
    expected_container_id: str,
    expected_image_id: str,
    expected_image_configuration: Mapping[str, object],
    expected_service: str,
    expected_database_secret_file: Path | None = None,
    expected_head_anchor_authority_file: Path | None = None,
    expected_head_anchor_auth_secret_file: Path | None = None,
    expected_head_anchor_signing_key_secret_file: Path | None = None,
) -> None:
    """Validate one exact Compose-created container that has never started."""

    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started container inspection is malformed"
        )
    container = _mapping(inspection[0], "trusted-time never-started container")
    configuration = _mapping(
        container.get("Config"),
        "trusted-time never-started container Config",
    )
    host = _mapping(
        container.get("HostConfig"),
        "trusted-time never-started container HostConfig",
    )
    _validate_exact_never_started_projection_presence(configuration, host)
    network_settings = _mapping(
        container.get("NetworkSettings"),
        "trusted-time never-started container NetworkSettings",
    )
    networks = _mapping(
        network_settings.get("Networks"),
        "trusted-time never-started container networks",
    )
    labels = _mapping(
        configuration.get("Labels"),
        "trusted-time never-started container labels",
    )
    state = _mapping(
        container.get("State"),
        "trusted-time never-started container state",
    )
    if (
        expected_service not in {"chrony-nts", "trusted-time-supervisor"}
        or type(expected_container_id) is not str
        or _FULL_CONTAINER_ID_PATTERN.fullmatch(expected_container_id) is None
        or type(expected_image_id) is not str
        or _IMAGE_ID_PATTERN.fullmatch(expected_image_id) is None
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started container binding is invalid"
        )
    staged_paths = (
        expected_database_secret_file,
        expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file,
    )
    if (expected_service == "chrony-nts" and any(path is not None for path in staged_paths)) or (
        expected_service == "trusted-time-supervisor"
        and (
            not all(_is_absolute_lexically_canonical_path(path) for path in staged_paths)
            or len(set(staged_paths)) != len(staged_paths)
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started staged input binding is invalid"
        )
    expected_path, expected_args = _expected_container_path_and_args(expected_image_configuration)
    if (
        container.get("Id") != expected_container_id
        or container.get("Image") != expected_image_id
        or configuration.get("Image") != expected_image_id
        or container.get("Path") != expected_path
        or type(container.get("Args")) is not list
        or container.get("Args") != expected_args
        or labels.get("com.docker.compose.project") != "autoquanttrader-trusted-time"
        or labels.get("com.docker.compose.service") != expected_service
        or labels.get("com.docker.compose.oneoff") != "False"
        or labels.get("com.docker.compose.container-number") != "1"
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started container identity drifted"
        )
    if set(networks) != {COMPOSE_NETWORK_NAME}:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time never-started container network attachment drifted"
        )
    _validate_exact_never_started_created_state(container, state)
    _validate_exact_never_started_host_boundary(host)
    _validate_exact_never_started_high_risk_boundary(
        configuration,
        host,
        expected_image_configuration=expected_image_configuration,
    )
    _validate_exact_never_started_numeric_types(
        configuration,
        host,
        expected_service=expected_service,
    )
    _validate_trusted_time_container_runtime_policy(
        container,
        configuration,
        host,
        state,
        expected_image_configuration=expected_image_configuration,
        expected_service=expected_service,
        require_healthy=False,
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
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
        or _FULL_CONTAINER_ID_PATTERN.fullmatch(source_container_id) is None
        or _FULL_CONTAINER_ID_PATTERN.fullmatch(supervisor_container_id) is None
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
    compose_payload: bytes,
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
) -> None:
    source_container_id = _compose_container_id(
        "chrony-nts",
        environment=environment,
        compose_payload=compose_payload,
    )
    supervisor_container_id = _compose_container_id(
        "trusted-time-supervisor",
        environment=environment,
        compose_payload=compose_payload,
    )
    validate_live_trusted_time_topology(
        identities,
        source_container_id=source_container_id,
        supervisor_container_id=supervisor_container_id,
        environment=_docker_environment_projection(environment),
        expected_database_secret_file=expected_database_secret_file,
        expected_head_anchor_authority_file=expected_head_anchor_authority_file,
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
    )


def _stop_created_topology(
    environment: Mapping[str, str],
    *,
    compose_payload: bytes,
) -> bool:
    try:
        completed = _run_docker(
            _compose_down_argv(),
            environment=environment,
            timeout_seconds=60,
            compose_payload=compose_payload,
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


def _validate_unenrolled_admission_teardown(
    *,
    compose_environment: Mapping[str, str],
    docker_environment: Mapping[str, str],
    daemon_identity: LocalDockerDaemonIdentity,
    expected_volume_identities: TrustedTimeVolumeIdentities | None,
    compose_payload: bytes,
) -> None:
    """Prove the exact project is gone while both admitted volumes remain."""

    if expected_volume_identities is not None and type(expected_volume_identities) is not (
        TrustedTimeVolumeIdentities
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admission volume identities are unavailable"
        )
    if expected_volume_identities is not None:
        expected_volume_identities.__post_init__()
    _require_same_local_daemon(daemon_identity, environment=docker_environment)
    completed = _run_docker_bounded(
        (*_compose_prefix(), "ps", "--all", "--quiet"),
        environment=compose_environment,
        maximum_stdout_bytes=128,
        maximum_stderr_bytes=1_024,
        timeout_seconds=2,
        compose_payload=compose_payload,
    )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admission topology removal is unconfirmed"
        )
    network = _run_docker_bounded(
        (
            "docker",
            "network",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{COMPOSE_NETWORK_NAME}$",
        ),
        environment=docker_environment,
        maximum_stdout_bytes=128,
        maximum_stderr_bytes=1_024,
        timeout_seconds=2,
    )
    if network.returncode != 0 or network.stdout or network.stderr:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admission network removal is unconfirmed"
        )
    observed_volume_identities = _capture_trusted_time_volume_identities(
        environment=docker_environment
    )
    if (
        expected_volume_identities is not None
        and observed_volume_identities != expected_volume_identities
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admission volume preservation is unconfirmed"
        )
    _require_same_local_daemon(daemon_identity, environment=docker_environment)


def _run_local_topology_under_lock(
    *,
    env_file: Path,
    approved_launch: TrustedTimeApprovedLaunch,
    image_admission_artifact: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    expect_unenrolled_fail_closed: bool = False,
) -> int:
    if type(expect_unenrolled_fail_closed) is not bool:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission mode is invalid"
        )
    if not expect_unenrolled_fail_closed:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time persistent supervision remains approval-blocked"
        )
    _require_no_retained_first_enrollment_claim()
    image_admission_artifact = _validate_image_admission_artifact_path(image_admission_artifact)
    if type(approved_launch) is not TrustedTimeApprovedLaunch:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time launch requires an exact approved launch binding"
        )
    approved_launch.__post_init__()
    _approved_image_admission_path(image_admission_artifact, approved_launch)
    _require_approved_git_revision(approved_launch)
    git_revision = approved_launch.git_revision
    docker_environment = _minimal_docker_environment()
    daemon_identity = qualify_local_docker_daemon(environment=docker_environment)
    admission = _load_approved_image_admission(
        image_admission_artifact,
        approved_launch,
    )
    verified_identities = verify_images(
        approved_launch.source_image_id,
        approved_launch.supervisor_image_id,
        docker_environment=docker_environment,
    )
    if verified_identities != approved_launch.identities:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time approved image identities changed during verification"
        )
    _require_same_local_daemon(daemon_identity, environment=docker_environment)
    identities = admission.identities
    try:
        compose_payload = _head_reviewed_input_payload(
            git_revision,
            "infra/compose/trusted-time.compose.yaml",
        )
    except TrustedTimeImageVerificationError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time immutable Compose payload is unavailable"
        ) from None
    compose_payload = _validate_runtime_compose_payload(compose_payload)
    compose_model = render_compose_model(
        source_image=identities.source_id,
        supervisor_image=identities.supervisor_id,
        database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        head_anchor_authority_file=PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
        head_anchor_auth_secret_file=PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
        head_anchor_signing_key_secret_file=(PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE),
        compose_payload=compose_payload,
        docker_environment=docker_environment,
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
    _require_approved_launch_state(
        image_admission_artifact,
        approved_launch,
        expected_admission=admission,
    )
    control_environment = dict(docker_environment)
    control_environment[SOURCE_IMAGE_ENVIRONMENT] = identities.source_id
    control_environment[SUPERVISOR_IMAGE_ENVIRONMENT] = identities.supervisor_id
    control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = ""
    control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = ""
    control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = ""
    control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = ""
    admission_identity_environment = dict(control_environment)
    admission_identity_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = str(
        PLACEHOLDER_DATABASE_SECRET_FILE
    )
    admission_identity_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE
    )
    admission_identity_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE
    )
    admission_identity_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = str(
        PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
    )
    if expect_unenrolled_fail_closed and (
        _optional_stopped_supervisor_container_id(
            environment=admission_identity_environment,
            compose_payload=compose_payload,
        )
        is not None
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time admission requires no prior supervisor container"
        )
    admission_volume_identities: TrustedTimeVolumeIdentities | None = None
    database_url = ""
    runtime_configuration: TrustedTimeRuntimeConfiguration | None = None
    materialized_secret: MaterializedDatabaseSecret | None = None
    head_anchor_payloads: TrustedTimeHeadAnchorSourcePayloads | None = None
    materialized_head_anchor_inputs: MaterializedHeadAnchorInputs | None = None
    supervisor_container_id: str | None = None
    compose_attempted = False
    try:
        runtime_configuration = load_trusted_time_runtime_configuration(env_file)
        database_url = runtime_configuration.database_url
        head_anchor_payloads = runtime_configuration.head_anchor_payloads
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
            compose_payload=compose_payload,
            docker_environment=docker_environment,
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
        _require_approved_launch_state(
            image_admission_artifact,
            approved_launch,
            expected_admission=admission,
        )
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
            compose_payload=compose_payload,
        )
        if completed.returncode != 0:
            terminal_evidence: SupervisorTerminalEvidence | None = None
            if expect_unenrolled_fail_closed:
                current_supervisor_container_id = _optional_stopped_supervisor_container_id(
                    environment=admission_identity_environment,
                    compose_payload=compose_payload,
                )
                if current_supervisor_container_id is None:
                    raise TrustedTimeSupervisorConfigurationError(
                        "trusted-time current-attempt supervisor identity is unavailable"
                    )
                with suppress(TrustedTimeSupervisorConfigurationError):
                    terminal_evidence = _observe_unenrolled_supervisor_terminal_safely(
                        expected_image_id=identities.supervisor_id,
                        environment=docker_environment,
                        compose_payload=compose_payload,
                        container_id=current_supervisor_container_id,
                        timeout_seconds=2,
                    )
            if not _stop_created_topology(
                control_environment,
                compose_payload=compose_payload,
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time failed topology could not be stopped"
                )
            if expect_unenrolled_fail_closed:
                _validate_unenrolled_admission_teardown(
                    compose_environment=admission_identity_environment,
                    docker_environment=docker_environment,
                    daemon_identity=daemon_identity,
                    expected_volume_identities=admission_volume_identities,
                    compose_payload=compose_payload,
                )
            compose_attempted = False
            _cleanup_materialized_runtime_inputs(
                database_secret=materialized_secret,
                head_anchor_inputs=materialized_head_anchor_inputs,
            )
            materialized_head_anchor_inputs = None
            materialized_secret = None
            if expect_unenrolled_fail_closed:
                if terminal_evidence is not None:
                    if terminal_evidence.reason == _EXPECTED_UNENROLLED_TERMINAL_REASON:
                        raise TrustedTimeSupervisorSecureLaunchIncomplete(
                            "trusted-time expected terminal preceded secure launch validation"
                        )
                    raise TrustedTimeSupervisorTerminalUnqualified(terminal_evidence)
                raise TrustedTimeSupervisorTerminalNotObserved(
                    "trusted-time unenrolled supervisor terminal was not observed"
                )
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        _validate_created_topology(
            identities,
            environment=control_environment,
            compose_payload=compose_payload,
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
            compose_payload=compose_payload,
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
            compose_payload=compose_payload,
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
            compose_payload=compose_payload,
            expected_database_secret_file=retained_secret.path,
            expected_head_anchor_authority_file=(retained_head_anchor_inputs.authority.path),
            expected_head_anchor_auth_secret_file=(retained_head_anchor_inputs.auth_secret.path),
            expected_head_anchor_signing_key_secret_file=(
                retained_head_anchor_inputs.signing_key.path
            ),
        )
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        if expect_unenrolled_fail_closed:
            admission_volume_identities = _capture_trusted_time_volume_identities(
                environment=docker_environment
            )
            current_supervisor_container_id = _optional_stopped_supervisor_container_id(
                environment=admission_identity_environment,
                compose_payload=compose_payload,
            )
            if (
                current_supervisor_container_id is None
                or current_supervisor_container_id != supervisor_container_id
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time current-attempt supervisor identity is unavailable"
                )
            terminal_evidence = _observe_unenrolled_supervisor_terminal_safely(
                expected_image_id=identities.supervisor_id,
                environment=docker_environment,
                compose_payload=compose_payload,
                container_id=current_supervisor_container_id,
            )
            if not _stop_created_topology(
                control_environment,
                compose_payload=compose_payload,
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time admission topology could not be stopped"
                )
            _validate_unenrolled_admission_teardown(
                compose_environment=admission_identity_environment,
                docker_environment=docker_environment,
                daemon_identity=daemon_identity,
                expected_volume_identities=admission_volume_identities,
                compose_payload=compose_payload,
            )
            compose_attempted = False
            if terminal_evidence is None:
                raise TrustedTimeSupervisorTerminalNotObserved(
                    "trusted-time unenrolled supervisor terminal was not observed"
                )
            _require_approved_launch_state(
                image_admission_artifact,
                approved_launch,
                expected_admission=admission,
            )
            raise _terminal_outcome_error(
                terminal_evidence,
                approved_launch=approved_launch,
            )
    except BaseException as primary_error:
        terminal_evidence = None
        terminal_observation_error: BaseException | None = None
        if (
            compose_attempted
            and expect_unenrolled_fail_closed
            and type(primary_error) is _TrustedTimeSupervisorContainerIdentityUnavailable
        ):
            try:
                current_supervisor_container_id = _optional_stopped_supervisor_container_id(
                    environment=admission_identity_environment,
                    compose_payload=compose_payload,
                )
                if current_supervisor_container_id is None:
                    raise TrustedTimeSupervisorConfigurationError(
                        "trusted-time current-attempt supervisor identity is unavailable"
                    )
                terminal_evidence = _observe_unenrolled_supervisor_terminal_safely(
                    expected_image_id=identities.supervisor_id,
                    environment=docker_environment,
                    compose_payload=compose_payload,
                    container_id=current_supervisor_container_id,
                    timeout_seconds=2,
                )
            except TrustedTimeSupervisorConfigurationError:
                terminal_evidence = None
            except BaseException as observation_error:
                terminal_observation_error = observation_error
        teardown_needed = compose_attempted
        teardown_error: BaseException | None = None
        if teardown_needed:
            try:
                if not _stop_created_topology(
                    control_environment,
                    compose_payload=compose_payload,
                ):
                    raise TrustedTimeSupervisorConfigurationError(
                        "trusted-time unqualified topology could not be stopped"
                    )
                if expect_unenrolled_fail_closed:
                    _validate_unenrolled_admission_teardown(
                        compose_environment=admission_identity_environment,
                        docker_environment=docker_environment,
                        daemon_identity=daemon_identity,
                        expected_volume_identities=admission_volume_identities,
                        compose_payload=compose_payload,
                    )
                compose_attempted = False
            except BaseException as error:
                teardown_error = error
        cleanup_error: BaseException | None = None
        try:
            _cleanup_materialized_runtime_inputs(
                database_secret=materialized_secret,
                head_anchor_inputs=materialized_head_anchor_inputs,
            )
        except BaseException as error:
            cleanup_error = error
        else:
            materialized_secret = None
            materialized_head_anchor_inputs = None
        if cleanup_error is not None:
            raise cleanup_error from (teardown_error or primary_error)
        if teardown_error is not None:
            if isinstance(
                teardown_error,
                (
                    TrustedTimeSupervisorConfigurationError,
                    TrustedTimeImageVerificationError,
                ),
            ):
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time unqualified topology teardown is unconfirmed"
                ) from teardown_error
            raise teardown_error from primary_error
        if terminal_observation_error is not None:
            raise terminal_observation_error from primary_error
        if terminal_evidence is not None:
            if terminal_evidence.reason == _EXPECTED_UNENROLLED_TERMINAL_REASON:
                raise TrustedTimeSupervisorSecureLaunchIncomplete(
                    "trusted-time expected terminal preceded secure launch validation"
                ) from None
            raise TrustedTimeSupervisorTerminalUnqualified(terminal_evidence) from None
        raise
    finally:
        control_environment[DATABASE_SECRET_FILE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] = ""
        control_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] = ""
        control_environment[SOURCE_IMAGE_ENVIRONMENT] = ""
        control_environment[SUPERVISOR_IMAGE_ENVIRONMENT] = ""
        head_anchor_payloads = None
        runtime_configuration = None
        database_url = ""


def run_local_topology(
    *,
    env_file: Path,
    approved_launch: TrustedTimeApprovedLaunch,
    image_admission_artifact: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    expect_unenrolled_fail_closed: bool = False,
) -> int:
    """Run one normal/admission launcher while excluding every enrollment launcher."""

    if type(expect_unenrolled_fail_closed) is not bool:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission mode is invalid"
        )
    if not expect_unenrolled_fail_closed:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time persistent supervision remains approval-blocked"
        )

    lock_descriptor = _acquire_trusted_time_launch_lock()
    primary_error: BaseException | None = None
    try:
        return _run_local_topology_under_lock(
            env_file=env_file,
            approved_launch=approved_launch,
            image_admission_artifact=image_admission_artifact,
            expect_unenrolled_fail_closed=expect_unenrolled_fail_closed,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            _release_trusted_time_launch_lock(lock_descriptor)
        except TrustedTimeSupervisorConfigurationError:
            if primary_error is None:
                raise


def _new_unenrolled_admission_id() -> str:
    try:
        admission_id = str(uuid.uuid4())
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission identity is unavailable"
        ) from None
    if not _valid_uuid4(admission_id):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time unenrolled admission identity is invalid"
        )
    return admission_id


def _emit_unenrolled_admission_receipt(encoded: bytes) -> None:
    """Emit exact admitted bytes or raise a closed, nonsecret output failure."""

    try:
        rendered = encoded.decode("ascii", errors="strict")
        if sys.stdout.write(rendered) != len(rendered):
            raise OSError
        sys.stdout.flush()
    except Exception:
        raise TrustedTimeSupervisorAdmissionOutputError(
            "trusted-time unenrolled admission output failed"
        ) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help=(
            "dedicated owner-only dotenv containing exactly AQT_DATABASE_URL and "
            "the three absolute owner-only head-anchor source-file paths; never "
            "use the general repository .env"
        ),
    )
    parser.add_argument(
        "--image-admission-artifact",
        type=Path,
        default=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        help="absolute owner-only image admission artifact below repository artifacts/",
    )
    parser.add_argument(
        "--expect-unenrolled-fail-closed",
        action="store_true",
        help=(
            "observe one bounded expected terminal result, always tear down, "
            "and never start a persistent topology"
        ),
    )
    parser.add_argument(
        "--approved-git-revision",
        help="exact 40-character lowercase merged Git revision approved for launch",
    )
    parser.add_argument(
        "--approved-image-admission-sha256",
        help="exact lowercase SHA-256 of the approved image-admission artifact",
    )
    parser.add_argument(
        "--approved-source-image-id",
        help="exact immutable sha256: source image ID approved for launch",
    )
    parser.add_argument(
        "--approved-supervisor-image-id",
        help="exact immutable sha256: supervisor image ID approved for launch",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=DEFAULT_UNENROLLED_ADMISSION_ARTIFACT_DIR,
        help=(
            "absolute owner-only directory below repository artifacts/trusted-time "
            "for an admitted unenrolled-launch receipt"
        ),
    )
    arguments = parser.parse_args()
    try:
        approval_values = (
            arguments.approved_git_revision,
            arguments.approved_image_admission_sha256,
            arguments.approved_source_image_id,
            arguments.approved_supervisor_image_id,
        )
        if any(value is None for value in approval_values):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time launch approval is incomplete"
            )
        approved_launch = TrustedTimeApprovedLaunch(
            git_revision=arguments.approved_git_revision,
            image_admission_sha256=arguments.approved_image_admission_sha256,
            source_image_id=arguments.approved_source_image_id,
            supervisor_image_id=arguments.approved_supervisor_image_id,
        )
        admission_id = (
            _new_unenrolled_admission_id() if arguments.expect_unenrolled_fail_closed else ""
        )
        return_code = run_local_topology(
            env_file=arguments.env_file,
            image_admission_artifact=arguments.image_admission_artifact,
            expect_unenrolled_fail_closed=arguments.expect_unenrolled_fail_closed,
            approved_launch=approved_launch,
        )
    except TrustedTimeSupervisorTerminalObserved as error:
        try:
            encoded = build_unenrolled_admission_receipt(
                admission_id=admission_id,
                approved_launch=error.approved_launch,
                terminal_evidence=error.evidence,
            )
            write_unenrolled_admission_receipt(
                arguments.artifact_dir,
                encoded,
                emit=_emit_unenrolled_admission_receipt,
            )
        except TrustedTimeSupervisorAdmissionRetentionUnconfirmed:
            with suppress(Exception):
                print(
                    _safe_payload("fatal", "admission_retention_unconfirmed"),
                    file=sys.stderr,
                    flush=True,
                )
            raise SystemExit(2) from None
        except TrustedTimeSupervisorAdmissionOutputError:
            raise SystemExit(2) from None
        except Exception:
            print(_safe_payload("fatal", "admission_artifact_rejected"), flush=True)
            raise SystemExit(2) from None
        return
    except TrustedTimeSupervisorTerminalUnqualified as error:
        print(_safe_terminal_payload(error.evidence), flush=True)
        raise SystemExit(2) from None
    except TrustedTimeSupervisorSecureLaunchIncomplete:
        print(_safe_payload("fatal", "secure_launch_incomplete"), flush=True)
        raise SystemExit(2) from None
    except TrustedTimeSupervisorTerminalNotObserved:
        print(_safe_payload("fatal", "expected_terminal_not_observed"), flush=True)
        raise SystemExit(2) from None
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
