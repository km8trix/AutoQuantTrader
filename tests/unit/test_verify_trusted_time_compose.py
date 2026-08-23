from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import pytest

import scripts.verify_trusted_time_compose as compose_verifier
from scripts.bounded_subprocess import BoundedSubprocessError
from scripts.verify_trusted_time_compose import (
    PLACEHOLDER_DATABASE_SECRET_FILE,
    PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE,
    PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE,
    PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE,
    TrustedTimeComposeVerificationError,
    render_compose_model,
    validate_compose_model,
)


def test_compose_verifier_import_does_not_activate_cli_runtime_attestation() -> None:
    assert compose_verifier._CLI_REPOSITORY_ROOT is None


def test_compose_verifier_cli_runtime_attestation_accepts_isolated_source_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "verify_trusted_time_compose.py"
    runtime_prefix = tmp_path / "uv-isolated"
    base_prefix = tmp_path / "uv-python"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(root)
    runtime_path = [os.fspath(base_prefix / "lib")]

    with (
        patch(
            "scripts.verify_trusted_time_compose.sys.flags",
            SimpleNamespace(isolated=1, dont_write_bytecode=1),
        ),
        patch("scripts.verify_trusted_time_compose.sys.pycache_prefix", "/dev/null"),
        patch("scripts.verify_trusted_time_compose.sys.prefix", os.fspath(runtime_prefix)),
        patch("scripts.verify_trusted_time_compose.sys.base_prefix", os.fspath(base_prefix)),
        patch("scripts.verify_trusted_time_compose.sys.path", runtime_path),
    ):
        observed_root = compose_verifier._require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/verify_trusted_time_compose.py"),
            module_file=os.fspath(source),
        )

        assert observed_root == root
        assert runtime_path[0] == os.fspath(root)


@pytest.mark.parametrize(
    ("isolated", "dont_write_bytecode", "pycache_prefix"),
    [
        (0, 1, "/dev/null"),
        (1, 0, "/dev/null"),
        (1, 1, None),
        (1, 1, "repository-cache"),
    ],
)
def test_compose_verifier_cli_runtime_attestation_rejects_unsafe_interpreter_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    isolated: int,
    dont_write_bytecode: int,
    pycache_prefix: str | None,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "verify_trusted_time_compose.py"
    runtime_prefix = tmp_path / "uv-isolated"
    base_prefix = tmp_path / "uv-python"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(root)

    with (
        patch(
            "scripts.verify_trusted_time_compose.sys.flags",
            SimpleNamespace(
                isolated=isolated,
                dont_write_bytecode=dont_write_bytecode,
            ),
        ),
        patch("scripts.verify_trusted_time_compose.sys.pycache_prefix", pycache_prefix),
        patch("scripts.verify_trusted_time_compose.sys.prefix", os.fspath(runtime_prefix)),
        patch("scripts.verify_trusted_time_compose.sys.base_prefix", os.fspath(base_prefix)),
        patch(
            "scripts.verify_trusted_time_compose.sys.path",
            [os.fspath(base_prefix / "lib")],
        ),
        pytest.raises(RuntimeError, match="runtime attestation failed"),
    ):
        compose_verifier._require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/verify_trusted_time_compose.py"),
            module_file=os.fspath(source),
        )


def test_compose_verifier_cli_runtime_attestation_rejects_repository_virtual_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "verify_trusted_time_compose.py"
    runtime_prefix = root / ".venv"
    base_prefix = tmp_path / "uv-python"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    runtime_prefix.mkdir()
    base_prefix.mkdir()
    monkeypatch.chdir(root)

    with (
        patch(
            "scripts.verify_trusted_time_compose.sys.flags",
            SimpleNamespace(isolated=1, dont_write_bytecode=1),
        ),
        patch("scripts.verify_trusted_time_compose.sys.pycache_prefix", "/dev/null"),
        patch("scripts.verify_trusted_time_compose.sys.prefix", os.fspath(runtime_prefix)),
        patch("scripts.verify_trusted_time_compose.sys.base_prefix", os.fspath(base_prefix)),
        patch(
            "scripts.verify_trusted_time_compose.sys.path",
            [os.fspath(runtime_prefix / "lib")],
        ),
        pytest.raises(RuntimeError, match="runtime attestation failed"),
    ):
        compose_verifier._require_isolated_cli_source_runtime(
            expected_relative_path=Path("scripts/verify_trusted_time_compose.py"),
            module_file=os.fspath(source),
        )


def test_compose_verifier_first_party_attestation_accepts_exact_repository_source(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    source = root / "scripts" / "bounded_subprocess.py"
    source.parent.mkdir(parents=True)
    source.write_text("# source\n", encoding="utf-8")
    isolated_sys = SimpleNamespace(
        modules={"scripts.bounded_subprocess": SimpleNamespace(__file__=os.fspath(source))}
    )

    with patch("scripts.verify_trusted_time_compose.sys", isolated_sys):
        compose_verifier._require_repository_first_party_sources(root)


def test_compose_verifier_first_party_attestation_rejects_bytecode_origin(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repository"
    bytecode = root / "scripts" / "__pycache__" / "bounded_subprocess.cpython-312.pyc"
    bytecode.parent.mkdir(parents=True)
    bytecode.write_bytes(b"poisoned")
    isolated_sys = SimpleNamespace(
        modules={"scripts.bounded_subprocess": SimpleNamespace(__file__=os.fspath(bytecode))}
    )

    with (
        patch("scripts.verify_trusted_time_compose.sys", isolated_sys),
        pytest.raises(RuntimeError, match="first-party source attestation failed"),
    ):
        compose_verifier._require_repository_first_party_sources(root)


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
    first_enrollment = {
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
        "command": [
            "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
            "first-enrollment",
        ],
        "profiles": ["trusted-time-first-enrollment"],
        "environment": {
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
            "trusted-time-first-enrollment": first_enrollment,
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
                    "o": "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0750",
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


def test_first_enrollment_service_requires_explicit_profile_and_no_chrony_dependency() -> None:
    model = _model()
    first_enrollment = _service(model, "trusted-time-first-enrollment")

    assert first_enrollment["profiles"] == ["trusted-time-first-enrollment"]
    assert first_enrollment["command"] == [
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "first-enrollment",
    ]
    assert "depends_on" not in first_enrollment
    assert "volumes" not in first_enrollment
    validate_compose_model(model)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("profiles", []),
        ("profiles", ["other-profile"]),
        ("command", None),
        ("command", ["autoquant-trusted-time-supervisor"]),
        ("depends_on", {"chrony-nts": {"condition": "service_healthy"}}),
        (
            "volumes",
            [
                {
                    "type": "volume",
                    "source": "chrony_command_socket",
                    "target": "/run/chrony",
                    "volume": {"nocopy": True},
                }
            ],
        ),
    ],
)
def test_compose_model_rejects_first_enrollment_activation_or_chrony_drift(
    field_name: str,
    value: object,
) -> None:
    model = _model()
    _service(model, "trusted-time-first-enrollment")[field_name] = value

    with pytest.raises(TrustedTimeComposeVerificationError):
        validate_compose_model(model)


def test_first_enrollment_console_scripts_use_dedicated_entry_points() -> None:
    project = tomllib.loads(
        (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]

    assert project["scripts"]["autoquant-trusted-time-first-enrollment"] == (
        "apps.trusted_time_supervisor.first_enrollment:main"
    )
    assert project["scripts"]["autoquant-trusted-time-first-enrollment-release"] == (
        "apps.trusted_time_supervisor.first_enrollment:release_main"
    )
    assert project["scripts"]["autoquant-trusted-time-post-enrollment-release"] == (
        "apps.trusted_time_supervisor.post_enrollment_release:release_main"
    )


def test_compose_renderer_uses_only_nonsecret_docker_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ALPACA_PAPER_API_SECRET", "must-not-be-forwarded")
    monkeypatch.setenv("AQT_DATABASE_URL", "must-not-be-forwarded")
    observed: dict[str, str] = {}

    def fake_run(
        argv: tuple[str, ...], **kwargs: object
    ) -> tuple[tuple[str, ...], int, bytes, bytes]:
        observed.update(cast(dict[str, str], kwargs["environment"]))
        return argv, 0, json.dumps(_model()).encode(), b""

    with patch(
        "scripts.verify_trusted_time_compose.run_bounded_subprocess",
        side_effect=fake_run,
    ):
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


def test_frozen_compose_renderer_uses_exact_payload_and_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    approved_payload = b"name: approved-before-live-file-drift\n"
    live_compose_path = tmp_path / "trusted-time.compose.yaml"
    live_defaults_path = tmp_path / "trusted-time.defaults.env"
    live_compose_path.write_bytes(approved_payload)
    live_defaults_path.write_text("MUTATED_DEFAULT=before-snapshot\n", encoding="utf-8")
    live_compose_path.write_bytes(b"name: mutated-after-snapshot\n")
    live_defaults_path.write_text("MUTATED_DEFAULT=after-snapshot\n", encoding="utf-8")
    monkeypatch.setattr(compose_verifier, "COMPOSE_PATH", live_compose_path)
    monkeypatch.setattr(compose_verifier, "DEFAULTS_PATH", live_defaults_path)
    monkeypatch.setenv("DOCKER_CONTEXT", "ambient-context-must-not-be-forwarded")
    monkeypatch.setenv("AQT_DATABASE_URL", "ambient-secret-must-not-be-forwarded")
    exact_docker_environment = {
        "DOCKER_HOST": "unix:///approved/docker.sock",
        "LC_ALL": "C",
    }
    observed: dict[str, object] = {}

    def fake_run(
        argv: tuple[str, ...], **kwargs: object
    ) -> tuple[tuple[str, ...], int, bytes, bytes]:
        observed["argv"] = argv
        observed.update(kwargs)
        return (
            argv,
            0,
            json.dumps(_model()).encode("utf-8"),
            b"",
        )

    with patch(
        "scripts.verify_trusted_time_compose.run_bounded_subprocess",
        side_effect=fake_run,
    ):
        assert (
            render_compose_model(
                compose_payload=approved_payload,
                docker_environment=exact_docker_environment,
            )
            == _model()
        )

    assert observed["argv"] == (
        "docker",
        "compose",
        "--profile",
        "trusted-time-first-enrollment",
        "--env-file",
        os.devnull,
        "--project-directory",
        str(live_compose_path.parent),
        "--file",
        "-",
        "config",
        "--format",
        "json",
    )
    assert observed["stdin_bytes"] is approved_payload
    assert observed["maximum_stdin_bytes"] == 1_048_576
    assert observed["timeout_seconds"] == 15
    environment = cast(dict[str, str], observed["environment"])
    assert environment == {
        **exact_docker_environment,
        "AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE": str(PLACEHOLDER_DATABASE_SECRET_FILE),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_SOURCE_FILE": str(
            PLACEHOLDER_HEAD_ANCHOR_AUTHORITY_FILE
        ),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_SOURCE_FILE": str(
            PLACEHOLDER_HEAD_ANCHOR_AUTH_SECRET_FILE
        ),
        "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_SECRET_SOURCE_FILE": str(
            PLACEHOLDER_HEAD_ANCHOR_SIGNING_KEY_SECRET_FILE
        ),
        "AQT_TRUSTED_TIME_SOURCE_IMAGE": ("autoquanttrader-trusted-time-source:phase6d-v1"),
        "AQT_TRUSTED_TIME_SUPERVISOR_IMAGE": ("autoquanttrader-trusted-time-supervisor:phase6d-v1"),
    }
    assert live_compose_path.read_bytes() != cast(bytes, observed["stdin_bytes"])
    assert "DOCKER_CONTEXT" not in environment
    assert "AQT_DATABASE_URL" not in environment


def test_frozen_compose_renderer_sanitizes_timeout() -> None:
    with (
        patch(
            "scripts.verify_trusted_time_compose.run_bounded_subprocess",
            side_effect=BoundedSubprocessError("bounded subprocess execution failed"),
        ) as run,
        pytest.raises(
            TrustedTimeComposeVerificationError,
            match="Docker Compose validation failed",
        ),
    ):
        render_compose_model(
            compose_payload=b"name: approved\n",
            docker_environment={"DOCKER_HOST": "unix:///approved/docker.sock"},
        )

    run.assert_called_once()
    assert run.call_args.kwargs["timeout_seconds"] == 15


@pytest.mark.parametrize(
    "compose_payload",
    [
        b"",
        bytearray(b"name: mutable\n"),
        b"\xff",
        b"name: embedded\x00nul\n",
        b"x" * 1_048_577,
    ],
)
def test_frozen_compose_renderer_rejects_invalid_payload(
    compose_payload: object,
) -> None:
    with (
        patch("scripts.verify_trusted_time_compose.run_bounded_subprocess") as run,
        pytest.raises(TrustedTimeComposeVerificationError, match="payload is invalid"),
    ):
        render_compose_model(  # type: ignore[arg-type]
            compose_payload=compose_payload,
            docker_environment={"DOCKER_HOST": "unix:///approved/docker.sock"},
        )
    run.assert_not_called()


@pytest.mark.parametrize(
    "docker_environment",
    [
        {"AQT_DATABASE_URL": "must-not-be-forwarded"},
        {"LC_ETRADE_SECRET": "must-not-be-forwarded"},
        {"DOCKER_HOST": 7},
        {"DOCKER_HOST": "unix:///approved/docker.sock\x00suffix"},
        {"LC_ALL": "\udcff"},
    ],
)
def test_frozen_compose_renderer_rejects_invalid_environment(
    docker_environment: object,
) -> None:
    with (
        patch("scripts.verify_trusted_time_compose.run_bounded_subprocess") as run,
        pytest.raises(TrustedTimeComposeVerificationError, match="environment is invalid"),
    ):
        render_compose_model(  # type: ignore[arg-type]
            compose_payload=b"name: approved\n",
            docker_environment=docker_environment,
        )
    run.assert_not_called()


@pytest.mark.parametrize(
    ("compose_payload", "docker_environment"),
    [
        (b"name: approved\n", None),
        (None, {"DOCKER_HOST": "unix:///approved/docker.sock"}),
    ],
)
def test_frozen_compose_renderer_requires_payload_and_environment_together(
    compose_payload: bytes | None,
    docker_environment: dict[str, str] | None,
) -> None:
    with (
        patch("scripts.verify_trusted_time_compose.run_bounded_subprocess") as run,
        pytest.raises(TrustedTimeComposeVerificationError, match="supplied together"),
    ):
        render_compose_model(
            compose_payload=compose_payload,
            docker_environment=docker_environment,
        )
    run.assert_not_called()


def test_compose_model_accepts_only_the_expected_parameterized_image_pair() -> None:
    model = _model()
    source_id = "sha256:" + "1" * 64
    supervisor_id = "sha256:" + "2" * 64
    _service(model, "chrony-nts")["image"] = source_id
    _service(model, "trusted-time-supervisor")["image"] = supervisor_id
    _service(model, "trusted-time-first-enrollment")["image"] = supervisor_id

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
        ("trusted-time-first-enrollment", "user", "0:0"),
        ("trusted-time-first-enrollment", "read_only", False),
        ("trusted-time-first-enrollment", "restart", "on-failure"),
        ("trusted-time-first-enrollment", "privileged", True),
        ("trusted-time-first-enrollment", "ports", ["8080:8080"]),
        ("trusted-time-first-enrollment", "entrypoint", ["/bin/sh"]),
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


def test_compose_model_rejects_first_enrollment_input_expansion_or_mount_drift() -> None:
    model = _model()
    first_enrollment = _service(model, "trusted-time-first-enrollment")
    environment = cast(dict[str, object], first_enrollment["environment"])
    environment["AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH"] = "/etc/autoquant/trusted-time/chrony.conf"

    with pytest.raises(TrustedTimeComposeVerificationError, match="environment allowlist"):
        validate_compose_model(model)

    model = _model()
    first_enrollment = _service(model, "trusted-time-first-enrollment")
    mounted_secret = cast(list[dict[str, object]], first_enrollment["secrets"])[0]
    mounted_secret["target"] = "/tmp/database-url"

    with pytest.raises(TrustedTimeComposeVerificationError, match="secret mount"):
        validate_compose_model(model)

    model = _model()
    first_enrollment = _service(model, "trusted-time-first-enrollment")
    mounted_config = cast(list[dict[str, object]], first_enrollment["configs"])[0]
    mounted_config["target"] = "/tmp/head-anchor-authority.json"

    with pytest.raises(TrustedTimeComposeVerificationError, match="authority mount"):
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
