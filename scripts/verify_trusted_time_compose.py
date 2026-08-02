"""Validate the Phase 6D Compose security and isolation contract."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
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


class TrustedTimeComposeVerificationError(RuntimeError):
    """The rendered deployment model is outside the approved contract."""


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
    if service.get("command") is not None or service.get("entrypoint") is not None:
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
    if set(services) != {"chrony-nts", "trusted-time-supervisor"}:
        raise TrustedTimeComposeVerificationError("trusted-time service set drifted")
    source = _mapping(services["chrony-nts"], "Chrony service")
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

    if source.get("image") != expected_source_image:
        raise TrustedTimeComposeVerificationError("Chrony source image identity drifted")
    if supervisor.get("image") != expected_supervisor_image:
        raise TrustedTimeComposeVerificationError("supervisor image identity drifted")
    if source.get("restart") != "unless-stopped" or supervisor.get("restart") != "no":
        raise TrustedTimeComposeVerificationError("trusted-time restart policy drifted")
    if source.get("pids_limit") != 32 or supervisor.get("pids_limit") != 64:
        raise TrustedTimeComposeVerificationError("trusted-time process limit drifted")
    if source.get("mem_limit") not in {"67108864", 67_108_864} or supervisor.get(
        "mem_limit"
    ) not in {"268435456", 268_435_456}:
        raise TrustedTimeComposeVerificationError("trusted-time memory limit drifted")
    if source.get("cpus") != 0.25 or supervisor.get("cpus") != 0.5:
        raise TrustedTimeComposeVerificationError("trusted-time CPU limit drifted")
    if source.get("tmpfs") != [
        "/tmp:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700"
    ] or supervisor.get("tmpfs") != [
        "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"
    ]:
        raise TrustedTimeComposeVerificationError("trusted-time temporary filesystem drifted")

    source_build = _mapping(source.get("build"), "Chrony build")
    supervisor_build = _mapping(supervisor.get("build"), "supervisor build")
    if source_build != {
        "context": str(ROOT),
        "dockerfile": "infra/docker/trusted-time.Dockerfile",
        "target": "chrony-source",
    }:
        raise TrustedTimeComposeVerificationError("Chrony build target drifted")
    if supervisor_build != {
        "context": str(ROOT),
        "dockerfile": "infra/docker/trusted-time.Dockerfile",
        "target": "trusted-time-supervisor",
    }:
        raise TrustedTimeComposeVerificationError("supervisor build target drifted")

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
    if environment != {
        "AQT_TRUSTED_TIME_AUTHORITY_PATH": ("/etc/autoquant/trusted-time/source-authority.json"),
        "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH": "/etc/autoquant/trusted-time/chrony.conf",
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
    }:
        raise TrustedTimeComposeVerificationError("supervisor environment allowlist drifted")
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
    supervisor_secrets = _sequence(supervisor.get("secrets"), "supervisor secrets")
    if supervisor_secrets != [
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
    ]:
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
    supervisor_configs = _sequence(
        supervisor.get("configs"),
        "supervisor configs",
    )
    if supervisor_configs != [
        {
            "source": "trusted_time_head_anchor_authority",
            "target": ("/etc/autoquant/trusted-time/head-anchor-authority.json"),
        }
    ]:
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
) -> object:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in _PASSTHROUGH_ENVIRONMENT or key.startswith("LC_")
    }
    for path, label in (
        (database_secret_file, "database secret"),
        (head_anchor_authority_file, "head-anchor authority"),
        (head_anchor_auth_secret_file, "head-anchor Auth secret"),
        (head_anchor_signing_key_secret_file, "head-anchor signing-key secret"),
    ):
        if not isinstance(path, Path) or not path.is_absolute():
            raise TrustedTimeComposeVerificationError(f"trusted-time {label} file path is invalid")
    environment["AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"] = str(database_secret_file)
    environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_SOURCE_FILE"] = str(
        head_anchor_authority_file
    )
    environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE"] = str(
        head_anchor_auth_secret_file
    )
    environment["AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_SOURCE_FILE"] = str(
        head_anchor_signing_key_secret_file
    )
    environment["AQT_TRUSTED_TIME_SOURCE_IMAGE"] = source_image
    environment["AQT_TRUSTED_TIME_SUPERVISOR_IMAGE"] = supervisor_image
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(DEFAULTS_PATH),
            "-f",
            str(COMPOSE_PATH),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or completed.stderr:
        raise TrustedTimeComposeVerificationError("Docker Compose validation failed")
    try:
        rendered: Any = json.loads(completed.stdout)
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
