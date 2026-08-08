"""Validate the Phase 6D Compose security and isolation contract."""

# ruff: noqa: E402 -- the CLI bootstrap must run before first-party imports.

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
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
        expected_relative_path=Path("scripts/verify_trusted_time_compose.py")
    )
    if __name__ == "__main__"
    else None
)

from scripts.bounded_subprocess import BoundedSubprocessError, run_bounded_subprocess

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)
COMPOSE_PATH = ROOT / "infra" / "compose" / "trusted-time.compose.yaml"
DEFAULTS_PATH = ROOT / "infra" / "compose" / "trusted-time.defaults.env"
PLACEHOLDER_DATABASE_SECRET_FILE = Path("/dev/null")
PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE = Path("/dev/null")
PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE = Path("/dev/null")
PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE = Path("/dev/null")
SOURCE_IMAGE = "autoquanttrader-trusted-time-source:phase6d-v1"
SUPERVISOR_IMAGE = "autoquanttrader-trusted-time-supervisor:phase6d-v1"
_SENTINEL_SOURCE_IMAGE = "sha256:" + "0" * 64
_SENTINEL_SUPERVISOR_IMAGE = "sha256:" + "f" * 64
_FIRST_ENROLLMENT_PROFILE = "trusted-time-first-enrollment"
_FIRST_ENROLLMENT_COMMAND = "/opt/venv/bin/autoquant-trusted-time-first-enrollment"
_MAXIMUM_COMPOSE_PAYLOAD_BYTES = 1_048_576
_COMPOSE_RENDER_TIMEOUT_SECONDS = 15
_MAXIMUM_DOCKER_ENVIRONMENT_VARIABLES = 64
_MAXIMUM_DOCKER_ENVIRONMENT_BYTES = 131_072
_MAXIMUM_COMPOSE_JSON_BYTES = 1_048_576
_MAXIMUM_COMPOSE_STDERR_BYTES = 65_536
_ROOT_KEYS = frozenset({"configs", "name", "networks", "secrets", "services", "volumes"})
_COMMON_SERVICE_KEYS = frozenset(
    {
        "build",
        "cap_drop",
        "command",
        "cpus",
        "entrypoint",
        "image",
        "init",
        "mem_limit",
        "networks",
        "pids_limit",
        "read_only",
        "restart",
        "security_opt",
        "stop_grace_period",
        "tmpfs",
        "user",
        "volumes",
    }
)
_SOURCE_SERVICE_KEYS = _COMMON_SERVICE_KEYS | {"healthcheck"}
_SUPERVISOR_SERVICE_KEYS = _COMMON_SERVICE_KEYS | {
    "configs",
    "depends_on",
    "environment",
    "secrets",
}
_FIRST_ENROLLMENT_SERVICE_KEYS = (_COMMON_SERVICE_KEYS - {"volumes"}) | {
    "configs",
    "environment",
    "profiles",
    "secrets",
}
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


class TrustedTimeComposeVerificationError(RuntimeError):
    """The rendered deployment model is outside the approved contract."""


def _trusted_time_substitutions(
    *,
    source_image: str,
    supervisor_image: str,
    database_secret_file: Path,
    head_anchor_authority_file: Path,
    head_anchor_auth_secret_file: Path,
    head_anchor_signing_key_secret_file: Path,
) -> dict[str, str]:
    for path, label in (
        (database_secret_file, "database secret"),
        (head_anchor_authority_file, "head-anchor authority"),
        (head_anchor_auth_secret_file, "head-anchor Auth secret"),
        (head_anchor_signing_key_secret_file, "head-anchor signing-key secret"),
    ):
        if not isinstance(path, Path) or not path.is_absolute():
            raise TrustedTimeComposeVerificationError(f"trusted-time {label} file path is invalid")
    if type(source_image) is not str or type(supervisor_image) is not str:
        raise TrustedTimeComposeVerificationError(
            "trusted-time Compose image substitution is invalid"
        )
    return {
        "AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE": str(database_secret_file),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_SOURCE_FILE": str(head_anchor_authority_file),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE": str(head_anchor_auth_secret_file),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_SOURCE_FILE": str(
            head_anchor_signing_key_secret_file
        ),
        "AQT_TRUSTED_TIME_SOURCE_IMAGE": source_image,
        "AQT_TRUSTED_TIME_SUPERVISOR_IMAGE": supervisor_image,
    }


def _validate_frozen_compose_payload(payload: object) -> bytes:
    if type(payload) is not bytes or not payload or len(payload) > _MAXIMUM_COMPOSE_PAYLOAD_BYTES:
        raise TrustedTimeComposeVerificationError("trusted-time frozen Compose payload is invalid")
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise TrustedTimeComposeVerificationError(
            "trusted-time frozen Compose payload is invalid"
        ) from None
    if "\x00" in decoded:
        raise TrustedTimeComposeVerificationError("trusted-time frozen Compose payload is invalid")
    return payload


def _validate_frozen_docker_environment(
    environment: object,
) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise TrustedTimeComposeVerificationError(
            "trusted-time frozen Docker environment is invalid"
        )
    try:
        entries = tuple(environment.items())
    except (AttributeError, RuntimeError, TypeError):
        raise TrustedTimeComposeVerificationError(
            "trusted-time frozen Docker environment is invalid"
        ) from None
    if len(entries) > _MAXIMUM_DOCKER_ENVIRONMENT_VARIABLES:
        raise TrustedTimeComposeVerificationError(
            "trusted-time frozen Docker environment is invalid"
        )
    frozen: dict[str, str] = {}
    total_bytes = 0
    for key, value in entries:
        if (
            type(key) is not str
            or type(value) is not str
            or not key
            or "=" in key
            or "\x00" in key
            or "\x00" in value
            or key not in _PASSTHROUGH_ENVIRONMENT
            or key in frozen
        ):
            raise TrustedTimeComposeVerificationError(
                "trusted-time frozen Docker environment is invalid"
            )
        try:
            total_bytes += len(key.encode("utf-8", errors="strict"))
            total_bytes += len(value.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise TrustedTimeComposeVerificationError(
                "trusted-time frozen Docker environment is invalid"
            ) from None
        if total_bytes > _MAXIMUM_DOCKER_ENVIRONMENT_BYTES:
            raise TrustedTimeComposeVerificationError(
                "trusted-time frozen Docker environment is invalid"
            )
        frozen[key] = value
    return frozen


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise TrustedTimeComposeVerificationError(f"{field_name} must be an object")
    return value


def _sequence(value: object, field_name: str) -> Sequence[object]:
    if type(value) is not list:
        raise TrustedTimeComposeVerificationError(f"{field_name} must be a list")
    return value


def _require_absent(service: Mapping[str, object], *field_names: str) -> None:
    for field_name in field_names:
        if field_name in service and service[field_name] not in (None, [], {}):
            raise TrustedTimeComposeVerificationError(
                f"trusted-time service cannot set {field_name}"
            )


def _validate_common_service(
    service: Mapping[str, object],
    *,
    expected_keys: frozenset[str],
    expected_stop_grace_period: str,
    expected_command: list[str] | None = None,
) -> None:
    if set(service) != expected_keys:
        raise TrustedTimeComposeVerificationError("trusted-time service field allowlist drifted")
    if service.get("user") != "10001:10001":
        raise TrustedTimeComposeVerificationError("trusted-time service must use the fixed UID/GID")
    if service.get("read_only") is not True:
        raise TrustedTimeComposeVerificationError("trusted-time root filesystem must be read-only")
    if service.get("cap_drop") != ["ALL"]:
        raise TrustedTimeComposeVerificationError("trusted-time capabilities must all be dropped")
    if service.get("security_opt") != ["no-new-privileges:true"]:
        raise TrustedTimeComposeVerificationError("trusted-time no-new-privileges policy drifted")
    if service.get("init") is not True:
        raise TrustedTimeComposeVerificationError("trusted-time init wrapper is required")
    if service.get("stop_grace_period") != expected_stop_grace_period:
        raise TrustedTimeComposeVerificationError("trusted-time stop grace period drifted")
    if service.get("command") != expected_command or service.get("entrypoint") is not None:
        raise TrustedTimeComposeVerificationError(
            "trusted-time image command and entrypoint cannot be overridden"
        )
    if service.get("networks") != {"default": None}:
        raise TrustedTimeComposeVerificationError("trusted-time network attachment drifted")


def _volume_targets(service: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    volumes = _sequence(service.get("volumes"), "trusted-time volumes")
    targets: dict[str, Mapping[str, object]] = {}
    for raw_volume in volumes:
        volume = _mapping(raw_volume, "trusted-time volume")
        target = volume.get("target")
        if type(target) is not str or target in targets:
            raise TrustedTimeComposeVerificationError("trusted-time volume target is malformed")
        if volume.get("type") != "volume":
            raise TrustedTimeComposeVerificationError("trusted-time bind mounts are forbidden")
        targets[target] = volume
    return targets


def validate_compose_model(
    payload: object,
    *,
    expected_source_image: str = SOURCE_IMAGE,
    expected_supervisor_image: str = SUPERVISOR_IMAGE,
    expected_database_secret_file: Path = PLACEHOLDER_DATABASE_SECRET_FILE,
    expected_head_anchor_authority_file: Path = (PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE),
    expected_head_anchor_auth_secret_file: Path = (PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE),
    expected_head_anchor_signing_key_secret_file: Path = (
        PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
    ),
) -> None:
    """Reject any rendered service model outside the reviewed local boundary."""

    root = _mapping(payload, "Compose model")
    if set(root) != _ROOT_KEYS:
        raise TrustedTimeComposeVerificationError("trusted-time root field allowlist drifted")
    if root.get("name") != "autoquanttrader-trusted-time":
        raise TrustedTimeComposeVerificationError("trusted-time project identity drifted")
    if root.get("networks") != {
        "default": {
            "name": "autoquanttrader-trusted-time_default",
            "ipam": {},
        }
    }:
        raise TrustedTimeComposeVerificationError("trusted-time network definition drifted")
    services = _mapping(root.get("services"), "Compose services")
    if set(services) != {
        "chrony-nts",
        "trusted-time-first-enrollment",
        "trusted-time-supervisor",
    }:
        raise TrustedTimeComposeVerificationError("trusted-time service set drifted")
    source = _mapping(services["chrony-nts"], "Chrony service")
    first_enrollment = _mapping(
        services["trusted-time-first-enrollment"],
        "first-enrollment service",
    )
    supervisor = _mapping(services["trusted-time-supervisor"], "supervisor service")
    _validate_common_service(
        source,
        expected_keys=_SOURCE_SERVICE_KEYS,
        expected_stop_grace_period="10s",
    )
    _validate_common_service(
        supervisor,
        expected_keys=_SUPERVISOR_SERVICE_KEYS,
        expected_stop_grace_period="40s",
    )
    _validate_common_service(
        first_enrollment,
        expected_keys=_FIRST_ENROLLMENT_SERVICE_KEYS,
        expected_stop_grace_period="40s",
        expected_command=[_FIRST_ENROLLMENT_COMMAND],
    )

    if source.get("image") != expected_source_image:
        raise TrustedTimeComposeVerificationError("Chrony source image identity drifted")
    if (
        supervisor.get("image") != expected_supervisor_image
        or first_enrollment.get("image") != expected_supervisor_image
    ):
        raise TrustedTimeComposeVerificationError("supervisor image identity drifted")
    if (
        source.get("restart") != "unless-stopped"
        or supervisor.get("restart") != "no"
        or first_enrollment.get("restart") != "no"
    ):
        raise TrustedTimeComposeVerificationError("trusted-time restart policy drifted")
    if (
        source.get("pids_limit") != 32
        or supervisor.get("pids_limit") != 64
        or first_enrollment.get("pids_limit") != 64
    ):
        raise TrustedTimeComposeVerificationError("trusted-time process limit drifted")
    if (
        source.get("mem_limit") not in {"67108864", 67_108_864}
        or supervisor.get("mem_limit") not in {"268435456", 268_435_456}
        or first_enrollment.get("mem_limit") not in {"268435456", 268_435_456}
    ):
        raise TrustedTimeComposeVerificationError("trusted-time memory limit drifted")
    if (
        source.get("cpus") != 0.25
        or supervisor.get("cpus") != 0.5
        or first_enrollment.get("cpus") != 0.5
    ):
        raise TrustedTimeComposeVerificationError("trusted-time CPU limit drifted")
    if (
        source.get("tmpfs") != ["/tmp:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700"]
        or supervisor.get("tmpfs")
        != ["/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"]
        or first_enrollment.get("tmpfs")
        != ["/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"]
    ):
        raise TrustedTimeComposeVerificationError("trusted-time temporary filesystem drifted")

    source_build = _mapping(source.get("build"), "Chrony build")
    supervisor_build = _mapping(supervisor.get("build"), "supervisor build")
    first_enrollment_build = _mapping(
        first_enrollment.get("build"),
        "first-enrollment build",
    )
    if source_build != {
        "context": str(ROOT),
        "dockerfile": "infra/docker/trusted-time.Dockerfile",
        "target": "chrony-source",
    }:
        raise TrustedTimeComposeVerificationError("Chrony build target drifted")
    expected_supervisor_build = {
        "context": str(ROOT),
        "dockerfile": "infra/docker/trusted-time.Dockerfile",
        "target": "trusted-time-supervisor",
    }
    if (
        supervisor_build != expected_supervisor_build
        or first_enrollment_build != expected_supervisor_build
    ):
        raise TrustedTimeComposeVerificationError("supervisor build target drifted")

    if first_enrollment.get("profiles") != [_FIRST_ENROLLMENT_PROFILE]:
        raise TrustedTimeComposeVerificationError(
            "first-enrollment service must remain disabled by default"
        )
    _require_absent(first_enrollment, "depends_on", "healthcheck", "ports", "volumes")

    healthcheck = _mapping(source.get("healthcheck"), "Chrony healthcheck")
    if healthcheck.get("test") != [
        "CMD",
        "/usr/bin/chronyc",
        "-h",
        "/run/chrony/chronyd.sock",
        "activity",
    ]:
        raise TrustedTimeComposeVerificationError("Chrony responsiveness check drifted")
    if (
        healthcheck.get("timeout") != "1s"
        or healthcheck.get("interval") != "2s"
        or healthcheck.get("retries") != 15
        or healthcheck.get("start_period") != "2s"
    ):
        raise TrustedTimeComposeVerificationError("Chrony healthcheck budget drifted")

    source_volumes = _volume_targets(source)
    if set(source_volumes) != {"/run/chrony", "/var/lib/chrony"}:
        raise TrustedTimeComposeVerificationError("Chrony volume set drifted")
    if source_volumes["/run/chrony"] != {
        "type": "volume",
        "source": "chrony_command_socket",
        "target": "/run/chrony",
        "volume": {"nocopy": True},
    } or source_volumes["/var/lib/chrony"] != {
        "type": "volume",
        "source": "chrony_state",
        "target": "/var/lib/chrony",
        "volume": {},
    }:
        raise TrustedTimeComposeVerificationError("Chrony volume identity drifted")
    supervisor_volumes = _volume_targets(supervisor)
    if set(supervisor_volumes) != {"/run/chrony"}:
        raise TrustedTimeComposeVerificationError("supervisor volume set drifted")
    if supervisor_volumes["/run/chrony"] != {
        "type": "volume",
        "source": "chrony_command_socket",
        "target": "/run/chrony",
        "volume": {"nocopy": True},
    }:
        raise TrustedTimeComposeVerificationError(
            "supervisor Chrony command scratch volume must be the exact read-write socket volume"
        )

    volumes = _mapping(root.get("volumes"), "Compose volumes")
    if set(volumes) != {"chrony_command_socket", "chrony_state"}:
        raise TrustedTimeComposeVerificationError("trusted-time volume set drifted")
    if volumes.get("chrony_command_socket") != {
        "name": "autoquanttrader-trusted-time_chrony_command_socket",
        "driver": "local",
        "driver_opts": {
            "type": "tmpfs",
            "device": "tmpfs",
            "o": "size=8m,uid=10001,gid=10001,mode=0750",
        },
    }:
        raise TrustedTimeComposeVerificationError("Chrony command scratch volume hardening drifted")
    if volumes.get("chrony_state") != {"name": "autoquanttrader-trusted-time_chrony_state"}:
        raise TrustedTimeComposeVerificationError("Chrony state volume identity drifted")

    environment = _mapping(supervisor.get("environment"), "supervisor environment")
    head_anchor_environment = {
        "AQT_TRUSTED_TIME_DATABASE_URL_FILE": "/run/secrets/trusted_time_database_url",
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH": (
            "/etc/autoquant/trusted-time/head-anchor-authority.json"
        ),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE": (
            "/run/secrets/trusted_time_head_anchor_auth"
        ),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE": (
            "/run/secrets/trusted_time_head_anchor_signing_key"
        ),
    }
    if environment != {
        "AQT_TRUSTED_TIME_AUTHORITY_PATH": ("/etc/autoquant/trusted-time/source-authority.json"),
        "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH": "/etc/autoquant/trusted-time/chrony.conf",
        **head_anchor_environment,
    }:
        raise TrustedTimeComposeVerificationError("supervisor environment allowlist drifted")
    first_enrollment_environment = _mapping(
        first_enrollment.get("environment"),
        "first-enrollment environment",
    )
    if first_enrollment_environment != head_anchor_environment:
        raise TrustedTimeComposeVerificationError("first-enrollment environment allowlist drifted")
    _require_absent(source, "environment", "secrets")

    secrets = _mapping(root.get("secrets"), "Compose secrets")
    if secrets != {
        "trusted_time_database_url": {
            "name": "autoquanttrader-trusted-time_trusted_time_database_url",
            "file": str(expected_database_secret_file),
        },
        "trusted_time_head_anchor_auth": {
            "name": "autoquanttrader-trusted-time_trusted_time_head_anchor_auth",
            "file": str(expected_head_anchor_auth_secret_file),
        },
        "trusted_time_head_anchor_signing_key": {
            "name": ("autoquanttrader-trusted-time_trusted_time_head_anchor_signing_key"),
            "file": str(expected_head_anchor_signing_key_secret_file),
        },
    }:
        raise TrustedTimeComposeVerificationError("database secret source drifted")
    expected_head_anchor_secrets = [
        {
            "source": "trusted_time_database_url",
            "target": "/run/secrets/trusted_time_database_url",
        },
        {
            "source": "trusted_time_head_anchor_auth",
            "target": "/run/secrets/trusted_time_head_anchor_auth",
        },
        {
            "source": "trusted_time_head_anchor_signing_key",
            "target": "/run/secrets/trusted_time_head_anchor_signing_key",
        },
    ]
    supervisor_secrets = _sequence(supervisor.get("secrets"), "supervisor secrets")
    first_enrollment_secrets = _sequence(
        first_enrollment.get("secrets"),
        "first-enrollment secrets",
    )
    if (
        supervisor_secrets != expected_head_anchor_secrets
        or first_enrollment_secrets != expected_head_anchor_secrets
    ):
        raise TrustedTimeComposeVerificationError("supervisor secret mount drifted")

    configs = _mapping(root.get("configs"), "Compose configs")
    if configs != {
        "trusted_time_head_anchor_authority": {
            "name": ("autoquanttrader-trusted-time_trusted_time_head_anchor_authority"),
            "file": str(expected_head_anchor_authority_file),
        }
    }:
        raise TrustedTimeComposeVerificationError(
            "trusted-time head-anchor authority source drifted"
        )
    expected_head_anchor_configs = [
        {
            "source": "trusted_time_head_anchor_authority",
            "target": ("/etc/autoquant/trusted-time/head-anchor-authority.json"),
        }
    ]
    supervisor_configs = _sequence(
        supervisor.get("configs"),
        "supervisor configs",
    )
    first_enrollment_configs = _sequence(
        first_enrollment.get("configs"),
        "first-enrollment configs",
    )
    if (
        supervisor_configs != expected_head_anchor_configs
        or first_enrollment_configs != expected_head_anchor_configs
    ):
        raise TrustedTimeComposeVerificationError("supervisor head-anchor authority mount drifted")

    depends_on = _mapping(supervisor.get("depends_on"), "supervisor dependencies")
    if depends_on != {"chrony-nts": {"condition": "service_healthy", "required": True}}:
        raise TrustedTimeComposeVerificationError("supervisor startup dependency drifted")


def render_compose_model(
    *,
    source_image: str = SOURCE_IMAGE,
    supervisor_image: str = SUPERVISOR_IMAGE,
    database_secret_file: Path = PLACEHOLDER_DATABASE_SECRET_FILE,
    head_anchor_authority_file: Path = PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
    head_anchor_auth_secret_file: Path = PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
    head_anchor_signing_key_secret_file: Path = (PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE),
    compose_payload: bytes | None = None,
    docker_environment: Mapping[str, str] | None = None,
) -> object:
    substitutions = _trusted_time_substitutions(
        source_image=source_image,
        supervisor_image=supervisor_image,
        database_secret_file=database_secret_file,
        head_anchor_authority_file=head_anchor_authority_file,
        head_anchor_auth_secret_file=head_anchor_auth_secret_file,
        head_anchor_signing_key_secret_file=head_anchor_signing_key_secret_file,
    )
    if (compose_payload is None) != (docker_environment is None):
        raise TrustedTimeComposeVerificationError(
            "trusted-time frozen Compose inputs must be supplied together"
        )
    if compose_payload is None:
        environment = {
            key: value for key, value in os.environ.items() if key in _PASSTHROUGH_ENVIRONMENT
        }
        environment.update(substitutions)
        try:
            completed = run_bounded_subprocess(
                (
                    "docker",
                    "compose",
                    "--profile",
                    _FIRST_ENROLLMENT_PROFILE,
                    "--env-file",
                    str(DEFAULTS_PATH),
                    "-f",
                    str(COMPOSE_PATH),
                    "config",
                    "--format",
                    "json",
                ),
                cwd=ROOT,
                environment=environment,
                maximum_stdout_bytes=_MAXIMUM_COMPOSE_JSON_BYTES,
                maximum_stderr_bytes=_MAXIMUM_COMPOSE_STDERR_BYTES,
                timeout_seconds=_COMPOSE_RENDER_TIMEOUT_SECONDS,
            )
        except BoundedSubprocessError:
            raise TrustedTimeComposeVerificationError("Docker Compose validation failed") from None
        if completed.returncode != 0 or completed.stderr:
            raise TrustedTimeComposeVerificationError("Docker Compose validation failed")
        try:
            rendered_json = completed.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise TrustedTimeComposeVerificationError(
                "Docker Compose returned malformed JSON"
            ) from None
    else:
        payload = _validate_frozen_compose_payload(compose_payload)
        environment = _validate_frozen_docker_environment(docker_environment)
        environment.update(substitutions)
        try:
            completed_bytes = run_bounded_subprocess(
                (
                    "docker",
                    "compose",
                    "--profile",
                    _FIRST_ENROLLMENT_PROFILE,
                    "--env-file",
                    os.devnull,
                    "--project-directory",
                    str(COMPOSE_PATH.parent),
                    "--file",
                    "-",
                    "config",
                    "--format",
                    "json",
                ),
                cwd=ROOT,
                environment=environment,
                stdin_bytes=payload,
                maximum_stdin_bytes=_MAXIMUM_COMPOSE_PAYLOAD_BYTES,
                maximum_stdout_bytes=_MAXIMUM_COMPOSE_JSON_BYTES,
                maximum_stderr_bytes=_MAXIMUM_COMPOSE_STDERR_BYTES,
                timeout_seconds=_COMPOSE_RENDER_TIMEOUT_SECONDS,
            )
        except BoundedSubprocessError:
            raise TrustedTimeComposeVerificationError("Docker Compose validation failed") from None
        if completed_bytes.returncode != 0 or completed_bytes.stderr:
            raise TrustedTimeComposeVerificationError("Docker Compose validation failed")
        try:
            rendered_json = completed_bytes.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise TrustedTimeComposeVerificationError(
                "Docker Compose returned malformed JSON"
            ) from None
    try:
        rendered: Any = json.loads(rendered_json)
    except json.JSONDecodeError:
        raise TrustedTimeComposeVerificationError(
            "Docker Compose returned malformed JSON"
        ) from None
    return rendered


def main() -> None:
    validate_compose_model(render_compose_model())
    validate_compose_model(
        render_compose_model(
            source_image=_SENTINEL_SOURCE_IMAGE,
            supervisor_image=_SENTINEL_SUPERVISOR_IMAGE,
        ),
        expected_source_image=_SENTINEL_SOURCE_IMAGE,
        expected_supervisor_image=_SENTINEL_SUPERVISOR_IMAGE,
    )
    print(
        json.dumps(
            {
                "authority": "evidence_only",
                "inbound_ports": 0,
                "new_exposure_authorized": False,
                "service": "trusted-time-compose-verifier",
                "status": "admitted",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
