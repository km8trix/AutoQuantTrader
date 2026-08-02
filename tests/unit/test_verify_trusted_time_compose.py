from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from scripts.verify_trusted_time_compose import (
    PLACEHOLDER_DATABASE_SECRET_FILE,
    PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
    PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
    PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE,
    TrustedTimeComposeVerificationError,
    render_compose_model,
    validate_compose_model,
)


def _common() -> dict[str, object]:
    return {
        "command": None,
        "entrypoint": None,
        "user": "10001:10001",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "init": True,
        "networks": {"default": None},
        "stop_grace_period": "10s",
    }


def _model() -> dict[str, object]:
    source = {
        **_common(),
        "image": "autoquanttrader-trusted-time-source:phase6d-v1",
        "restart": "unless-stopped",
        "pids_limit": 32,
        "mem_limit": "67108864",
        "cpus": 0.25,
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700"],
        "build": {
            "context": str(Path(__file__).resolve().parents[2]),
            "dockerfile": "infra/docker/trusted-time.Dockerfile",
            "target": "chrony-source",
        },
        "healthcheck": {
            "test": [
                "CMD",
                "/usr/bin/chronyc",
                "-h",
                "/run/chrony/chronyd.sock",
                "activity",
            ],
            "timeout": "1s",
            "interval": "2s",
            "retries": 15,
            "start_period": "2s",
        },
        "volumes": [
            {
                "type": "volume",
                "source": "chrony_command_socket",
                "target": "/run/chrony",
                "volume": {"nocopy": True},
            },
            {
                "type": "volume",
                "source": "chrony_state",
                "target": "/var/lib/chrony",
                "volume": {},
            },
        ],
    }
    supervisor = {
        **_common(),
        "image": "autoquanttrader-trusted-time-supervisor:phase6d-v1",
        "restart": "no",
        "stop_grace_period": "40s",
        "pids_limit": 64,
        "mem_limit": "268435456",
        "cpus": 0.5,
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"],
        "build": {
            "context": str(Path(__file__).resolve().parents[2]),
            "dockerfile": "infra/docker/trusted-time.Dockerfile",
            "target": "trusted-time-supervisor",
        },
        "environment": {
            "AQT_TRUSTED_TIME_AUTHORITY_PATH": (
                "/etc/autoquant/trusted-time/source-authority.json"
            ),
            "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH": ("/etc/autoquant/trusted-time/chrony.conf"),
            "AQT_TRUSTED_TIME_DATABASE_URL_FILE": ("/run/secrets/trusted_time_database_url"),
            "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH": (
                "/etc/autoquant/trusted-time/head-anchor-authority.json"
            ),
            "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE": (
                "/run/secrets/trusted_time_head_anchor_auth"
            ),
            "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE": (
                "/run/secrets/trusted_time_head_anchor_signing_key"
            ),
        },
        "configs": [
            {
                "source": "trusted_time_head_anchor_authority",
                "target": "/etc/autoquant/trusted-time/head-anchor-authority.json",
            }
        ],
        "secrets": [
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
        ],
        "volumes": [
            {
                "type": "volume",
                "source": "chrony_command_socket",
                "target": "/run/chrony",
                "volume": {"nocopy": True},
            }
        ],
        "depends_on": {"chrony-nts": {"condition": "service_healthy", "required": True}},
    }
    return {
        "name": "autoquanttrader-trusted-time",
        "networks": {
            "default": {
                "name": "autoquanttrader-trusted-time_default",
                "ipam": {},
            }
        },
        "services": {
            "chrony-nts": source,
            "trusted-time-supervisor": supervisor,
        },
        "secrets": {
            "trusted_time_database_url": {
                "name": "autoquanttrader-trusted-time_trusted_time_database_url",
                "file": str(PLACEHOLDER_DATABASE_SECRET_FILE),
            },
            "trusted_time_head_anchor_auth": {
                "name": "autoquanttrader-trusted-time_trusted_time_head_anchor_auth",
                "file": str(PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE),
            },
            "trusted_time_head_anchor_signing_key": {
                "name": ("autoquanttrader-trusted-time_trusted_time_head_anchor_signing_key"),
                "file": str(PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE),
            },
        },
        "configs": {
            "trusted_time_head_anchor_authority": {
                "name": ("autoquanttrader-trusted-time_trusted_time_head_anchor_authority"),
                "file": str(PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE),
            }
        },
        "volumes": {
            "chrony_command_socket": {
                "name": "autoquanttrader-trusted-time_chrony_command_socket",
                "driver": "local",
                "driver_opts": {
                    "type": "tmpfs",
                    "device": "tmpfs",
                    "o": "size=8m,uid=10001,gid=10001,mode=0750",
                },
            },
            "chrony_state": {"name": "autoquanttrader-trusted-time_chrony_state"},
        },
    }


def _service(model: dict[str, object], service_name: str) -> dict[str, object]:
    services = cast(dict[str, object], model["services"])
    return cast(dict[str, object], services[service_name])


def test_compose_model_accepts_exact_isolated_local_contract() -> None:
    validate_compose_model(_model())


def test_compose_renderer_uses_only_nonsecret_docker_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALPACA_PAPER_API_SECRET", "must-not-be-forwarded")
    monkeypatch.setenv("AQT_DATABASE_URL", "must-not-be-forwarded")
    observed: dict[str, str] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.update(cast(dict[str, str], kwargs["env"]))
        return subprocess.CompletedProcess(argv, 0, json.dumps(_model()), "")

    with patch("scripts.verify_trusted_time_compose.subprocess.run", side_effect=fake_run):
        assert render_compose_model() == _model()

    assert observed["AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"] == str(
        PLACEHOLDER_DATABASE_SECRET_FILE
    )
    assert observed["AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_SOURCE_FILE"] == str(
        PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE
    )
    assert observed["AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE"] == str(
        PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE
    )
    assert observed["AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_SOURCE_FILE"] == str(
        PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
    )
    assert "ALPACA_PAPER_API_SECRET" not in observed
    assert "AQT_DATABASE_URL" not in observed


def test_compose_model_accepts_only_the_expected_parameterized_image_pair() -> None:
    model = _model()
    source_id = "sha256:" + "1" * 64
    supervisor_id = "sha256:" + "2" * 64
    _service(model, "chrony-nts")["image"] = source_id
    _service(model, "trusted-time-supervisor")["image"] = supervisor_id

    validate_compose_model(
        model,
        expected_source_image=source_id,
        expected_supervisor_image=supervisor_id,
    )

    with pytest.raises(TrustedTimeComposeVerificationError, match="image identity"):
        validate_compose_model(model)


@pytest.mark.parametrize(
    ("service_name", "field_name", "value"),
    [
        ("chrony-nts", "user", "0:0"),
        ("chrony-nts", "cap_drop", []),
        ("chrony-nts", "cap_add", ["SYS_TIME"]),
        ("chrony-nts", "ports", ["123:123/udp"]),
        ("chrony-nts", "network_mode", "host"),
        ("chrony-nts", "command", ["-d"]),
        ("chrony-nts", "post_start", [{"command": "/bin/true"}]),
        ("trusted-time-supervisor", "read_only", False),
        ("trusted-time-supervisor", "restart", "unless-stopped"),
        ("trusted-time-supervisor", "privileged", True),
        ("trusted-time-supervisor", "entrypoint", ["/bin/sh"]),
        ("trusted-time-supervisor", "pre_stop", [{"command": "/bin/true"}]),
    ],
)
def test_compose_model_rejects_privilege_or_isolation_drift(
    service_name: str,
    field_name: str,
    value: object,
) -> None:
    model = _model()
    _service(model, service_name)[field_name] = value

    with pytest.raises(TrustedTimeComposeVerificationError):
        validate_compose_model(model)


def test_compose_model_rejects_database_secret_or_environment_expansion() -> None:
    model = _model()
    supervisor = _service(model, "trusted-time-supervisor")
    environment = cast(dict[str, object], supervisor["environment"])
    environment["ALPACA_PAPER_API_SECRET"] = "forbidden"

    with pytest.raises(TrustedTimeComposeVerificationError, match="environment allowlist"):
        validate_compose_model(model)

    model = _model()
    source = _service(model, "chrony-nts")
    source["secrets"] = [{"source": "trusted_time_database_url"}]
    with pytest.raises(TrustedTimeComposeVerificationError):
        validate_compose_model(model)

    model = _model()
    secrets = cast(dict[str, dict[str, object]], model["secrets"])
    secrets["trusted_time_database_url"] = {
        "name": "autoquanttrader-trusted-time_trusted_time_database_url",
        "environment": "AQT_TRUSTED_TIME_DATABASE_URL",
    }
    with pytest.raises(TrustedTimeComposeVerificationError, match="secret source"):
        validate_compose_model(model)

    model = _model()
    supervisor = _service(model, "trusted-time-supervisor")
    mounted = cast(list[dict[str, object]], supervisor["secrets"])[0]
    mounted["mode"] = "0444"
    with pytest.raises(TrustedTimeComposeVerificationError, match="secret mount"):
        validate_compose_model(model)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("include", ["untrusted.compose.yaml"]),
        ("configs", {"host_file": {"file": "/etc/passwd"}}),
        ("name", "other-project"),
    ],
)
def test_compose_model_rejects_root_field_or_project_drift(
    field_name: str,
    value: object,
) -> None:
    model = _model()
    model[field_name] = value

    with pytest.raises(TrustedTimeComposeVerificationError):
        validate_compose_model(model)


def test_compose_model_rejects_bind_mount_or_writable_supervisor_socket() -> None:
    model = _model()
    supervisor = _service(model, "trusted-time-supervisor")
    volumes = cast(list[dict[str, object]], supervisor["volumes"])
    volumes[0]["type"] = "bind"

    with pytest.raises(TrustedTimeComposeVerificationError, match="bind mounts"):
        validate_compose_model(model)

    model = _model()
    supervisor = _service(model, "trusted-time-supervisor")
    volumes = cast(list[dict[str, object]], supervisor["volumes"])
    volumes[0]["read_only"] = True
    with pytest.raises(TrustedTimeComposeVerificationError, match="read-write"):
        validate_compose_model(model)
