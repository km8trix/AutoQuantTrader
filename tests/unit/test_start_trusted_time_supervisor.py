from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError
from scripts.start_trusted_time_supervisor import (
    COMPOSE_NETWORK_NAME,
    COMPOSE_SOCKET_VOLUME_NAME,
    COMPOSE_STATE_VOLUME_NAME,
    DATABASE_SECRET_ROOT,
    HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
    HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
    HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT,
    HEAD_ANCHOR_AUTHORITY_FILE_NAME,
    HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
    HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT,
    HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
    HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
    HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT,
    LocalDockerDaemonIdentity,
    MaterializedDatabaseSecret,
    MaterializedHeadAnchorFile,
    MaterializedHeadAnchorInputs,
    TrustedTimeHeadAnchorSourcePayloads,
    _approved_database_secret_source_path,
    _validate_chrony_state_directory,
    _validate_mounted_database_secret,
    cleanup_materialized_database_secret,
    cleanup_materialized_trusted_time_head_anchor_inputs,
    compose_argv,
    load_runtime_database_url,
    load_trusted_time_head_anchor_source_payloads,
    main,
    materialize_database_secret,
    materialize_trusted_time_head_anchor_inputs,
    qualify_local_docker_daemon,
    run_local_topology,
    validate_chrony_state_volume_inspection,
    validate_created_container,
    validate_materialized_database_secret,
    validate_materialized_trusted_time_head_anchor_inputs,
)
from scripts.verify_trusted_time_images import (
    DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    TrustedTimeImageAdmission,
    TrustedTimeImageIdentities,
    TrustedTimeImageVerificationError,
)

DATABASE_URL = (
    "postgresql+psycopg://postgres.abcdefghijklmnopqrst:secret"
    "@aws-0-us-east-1.pooler.supabase.com:5432/postgres?sslmode=verify-full"
)
SOURCE_IMAGE_ID = "sha256:" + "1" * 64
SUPERVISOR_IMAGE_ID = "sha256:" + "2" * 64
SOURCE_CONTAINER_ID = "a" * 64
SUPERVISOR_CONTAINER_ID = "b" * 64
DAEMON_IDENTITY = LocalDockerDaemonIdentity(
    context_name="desktop-linux",
    endpoint="unix:///local/docker.sock",
    daemon_id="LOCAL:DAEMON:1",
)
HEAD_ANCHOR_AUTHORITY = b'{"authority":"launcher-test"}\n'
HEAD_ANCHOR_AUTH_SECRET = b'{"password":"not-a-real-secret"}\n'
HEAD_ANCHOR_SIGNING_KEY = b"k" * 32


def _admission() -> TrustedTimeImageAdmission:
    return TrustedTimeImageAdmission(
        path=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        identities=TrustedTimeImageIdentities(
            source_id=SOURCE_IMAGE_ID,
            supervisor_id=SUPERVISOR_IMAGE_ID,
        ),
        source_revision_sha256="3" * 64,
        artifact_sha256="4" * 64,
        created_at_utc="2026-07-31T18:00:00.000000Z",
        created_monotonic_ns=1,
    )


def _materialized_secret() -> MaterializedDatabaseSecret:
    directory = DATABASE_SECRET_ROOT / (".database-secret-" + "a" * 32)
    return MaterializedDatabaseSecret(
        root=DATABASE_SECRET_ROOT,
        ignored_root=DATABASE_SECRET_ROOT.parents[1],
        directory=directory,
        path=directory / "database-url",
        directory_device=1,
        directory_inode=2,
        file_device=1,
        file_inode=3,
        size=len(DATABASE_URL.encode()),
        sha256="5" * 64,
    )


def _materialized_head_anchor_file(
    *,
    kind: str,
    file_name: str,
    size: int,
    digest: str,
) -> MaterializedHeadAnchorFile:
    directory = DATABASE_SECRET_ROOT / f".head-anchor-{kind}-{'a' * 32}"
    return MaterializedHeadAnchorFile(
        root=DATABASE_SECRET_ROOT,
        ignored_root=DATABASE_SECRET_ROOT.parents[1],
        directory=directory,
        path=directory / file_name,
        directory_device=1,
        directory_inode={"authority": 11, "auth": 12, "signing-key": 13}[kind],
        file_device=1,
        file_inode={"authority": 21, "auth": 22, "signing-key": 23}[kind],
        size=size,
        sha256=digest,
        kind=kind,
    )


def _head_anchor_payloads() -> TrustedTimeHeadAnchorSourcePayloads:
    return TrustedTimeHeadAnchorSourcePayloads(
        authority=HEAD_ANCHOR_AUTHORITY,
        auth_secret=HEAD_ANCHOR_AUTH_SECRET,
        signing_key=HEAD_ANCHOR_SIGNING_KEY,
    )


def _materialized_head_anchor_inputs() -> MaterializedHeadAnchorInputs:
    return MaterializedHeadAnchorInputs(
        authority=_materialized_head_anchor_file(
            kind="authority",
            file_name=HEAD_ANCHOR_AUTHORITY_FILE_NAME,
            size=len(HEAD_ANCHOR_AUTHORITY),
            digest="6" * 64,
        ),
        auth_secret=_materialized_head_anchor_file(
            kind="auth",
            file_name=HEAD_ANCHOR_AUTH_SECRET_FILE_NAME,
            size=len(HEAD_ANCHOR_AUTH_SECRET),
            digest="7" * 64,
        ),
        signing_key=_materialized_head_anchor_file(
            kind="signing-key",
            file_name=HEAD_ANCHOR_SIGNING_KEY_FILE_NAME,
            size=len(HEAD_ANCHOR_SIGNING_KEY),
            digest="8" * 64,
        ),
    )


def _env_file(tmp_path: Path, payload: str) -> Path:
    path = tmp_path / "runtime.env"
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    return path


def _head_anchor_source_environment(tmp_path: Path) -> str:
    values = {
        HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT: HEAD_ANCHOR_AUTHORITY,
        HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT: HEAD_ANCHOR_AUTH_SECRET,
        HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT: HEAD_ANCHOR_SIGNING_KEY,
    }
    lines: list[str] = []
    for variable, payload in values.items():
        path = tmp_path / f"{variable.lower()}.bin"
        path.write_bytes(payload)
        path.chmod(0o600)
        lines.append(f"{variable}={path}")
    return "\n".join(lines) + "\n"


def test_owner_only_loader_extracts_only_valid_runtime_database_url(tmp_path: Path) -> None:
    env_file = _env_file(
        tmp_path,
        f"AQT_DATABASE_URL={DATABASE_URL}\nALPACA_PAPER_API_SECRET=not-forwarded\n",
    )

    assert load_runtime_database_url(env_file) == DATABASE_URL


@pytest.mark.parametrize(
    "payload",
    [
        "AQT_LOG_LEVEL=INFO\n",
        f"AQT_DATABASE_URL={DATABASE_URL}\nAQT_DATABASE_URL={DATABASE_URL}\n",
        "AQT_DATABASE_URL=sqlite+pysqlite:///:memory:\n",
    ],
)
def test_owner_env_loader_rejects_missing_duplicate_or_wrong_database(
    tmp_path: Path,
    payload: str,
) -> None:
    env_file = _env_file(tmp_path, payload)

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        load_runtime_database_url(env_file)


def test_owner_env_loader_rejects_broad_permissions(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    env_file.chmod(0o644)

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="env file was rejected"):
        load_runtime_database_url(env_file)


def test_head_anchor_source_loader_reads_only_exact_owner_files(tmp_path: Path) -> None:
    env_file = _env_file(
        tmp_path,
        _head_anchor_source_environment(tmp_path) + "ALPACA_PAPER_API_SECRET=not-forwarded\n",
    )

    assert load_trusted_time_head_anchor_source_payloads(env_file) == _head_anchor_payloads()


@pytest.mark.parametrize("tamper", ["broad-mode", "symlink", "wrong-key-size"])
def test_head_anchor_source_loader_rejects_unsafe_source_files(
    tmp_path: Path,
    tamper: str,
) -> None:
    environment = _head_anchor_source_environment(tmp_path)
    paths = {
        line.partition("=")[0]: Path(line.partition("=")[2]) for line in environment.splitlines()
    }
    if tamper == "broad-mode":
        paths[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT].chmod(0o644)
    elif tamper == "symlink":
        target = paths[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT]
        held = target.with_name("held-authority")
        target.replace(held)
        target.symlink_to(held)
    else:
        paths[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT].write_bytes(b"short")
    env_file = _env_file(tmp_path, environment)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="head-anchor source file was rejected",
    ):
        load_trusted_time_head_anchor_source_payloads(env_file)


def test_head_anchor_inputs_are_separate_owner_only_inodes_and_cleanup_is_complete(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    root = ignored_root / "trusted-time" / "runtime-secrets"
    inputs = materialize_trusted_time_head_anchor_inputs(
        _head_anchor_payloads(),
        root=root,
        ignored_root=ignored_root,
    )

    validate_materialized_trusted_time_head_anchor_inputs(inputs)
    expected = (
        (inputs.authority, HEAD_ANCHOR_AUTHORITY),
        (inputs.auth_secret, HEAD_ANCHOR_AUTH_SECRET),
        (inputs.signing_key, HEAD_ANCHOR_SIGNING_KEY),
    )
    assert len({item.file_inode for item, _ in expected}) == 3
    assert len({item.directory_inode for item, _ in expected}) == 3
    for item, payload in expected:
        assert item.path.read_bytes() == payload
        assert stat.S_IMODE(item.path.stat().st_mode) == 0o400
        assert stat.S_IMODE(item.directory.stat().st_mode) == 0o700
        assert item.path.stat().st_nlink == 1
    cleanup_materialized_trusted_time_head_anchor_inputs(inputs)
    for item, _ in expected:
        assert not os.path.lexists(item.path)
        assert not os.path.lexists(item.directory)


def test_database_secret_is_exact_owner_only_inode_and_cleanup_is_complete(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    root = ignored_root / "trusted-time" / "runtime-secrets"

    secret = materialize_database_secret(
        DATABASE_URL,
        root=root,
        ignored_root=ignored_root,
    )

    validate_materialized_database_secret(secret)
    assert secret.path.read_bytes() == DATABASE_URL.encode()
    assert stat.S_IMODE(secret.path.stat().st_mode) == 0o400
    assert stat.S_IMODE(secret.directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert secret.path.stat().st_nlink == 1
    cleanup_materialized_database_secret(secret)
    assert not os.path.lexists(secret.path)
    assert not os.path.lexists(secret.directory)


def test_database_secret_recheck_rejects_mode_tamper_and_symlink_swap(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "artifacts"
    root = ignored_root / "trusted-time" / "runtime-secrets"
    secret = materialize_database_secret(
        DATABASE_URL,
        root=root,
        ignored_root=ignored_root,
    )
    secret.path.chmod(0o600)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="metadata changed"):
        validate_materialized_database_secret(secret)
    secret.path.chmod(0o400)
    cleanup_materialized_database_secret(secret)

    replaced = materialize_database_secret(
        DATABASE_URL,
        root=root,
        ignored_root=ignored_root,
    )
    held = replaced.directory / "held"
    replaced.path.replace(held)
    replaced.path.symlink_to(held)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="metadata changed"):
        validate_materialized_database_secret(replaced)
    replaced.path.unlink()
    held.replace(replaced.path)
    cleanup_materialized_database_secret(replaced)


def test_inspector_secret_source_pattern_requires_completed_host_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "artifacts" / "trusted-time" / "runtime-secrets"
    source = root / (".database-secret-" + "a" * 32) / "database-url"
    monkeypatch.setattr(
        "scripts.start_trusted_time_supervisor.DATABASE_SECRET_ROOT",
        root,
    )

    assert _approved_database_secret_source_path(str(source))
    assert _approved_database_secret_source_path("/host_mnt" + str(source))
    assert not _approved_database_secret_source_path("/host_mnt/host_mnt" + str(source))
    source.parent.mkdir(parents=True)
    assert not _approved_database_secret_source_path(str(source))
    assert not _approved_database_secret_source_path("/host_mnt" + str(source))
    source.write_text("lookalike", encoding="utf-8")
    assert not _approved_database_secret_source_path(str(source))


def test_retired_mounted_secret_accepts_only_exact_digest_or_failed_read() -> None:
    expected_sha256 = "a" * 64
    metadata = subprocess.CompletedProcess(
        ["docker", "container", "exec"],
        0,
        "10001:10001:400:137\n",
        "",
    )
    retired = subprocess.CompletedProcess(
        ["docker", "container", "exec"],
        1,
        "",
        "sha256sum: cannot open retired mount\n",
    )
    with patch(
        "scripts.start_trusted_time_supervisor._run_docker",
        side_effect=[metadata, retired],
    ):
        _validate_mounted_database_secret(
            SUPERVISOR_CONTAINER_ID,
            expected_size=137,
            expected_sha256=expected_sha256,
            environment={},
            allow_retired_unreadable=True,
        )

    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            side_effect=[metadata, retired],
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="differs"),
    ):
        _validate_mounted_database_secret(
            SUPERVISOR_CONTAINER_ID,
            expected_size=137,
            expected_sha256=expected_sha256,
            environment={},
        )

    changed = subprocess.CompletedProcess(
        ["docker", "container", "exec"],
        0,
        "b" * 64 + "  /run/secrets/trusted_time_database_url\n",
        "",
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            side_effect=[metadata, changed],
        ),
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="differs"),
    ):
        _validate_mounted_database_secret(
            SUPERVISOR_CONTAINER_ID,
            expected_size=137,
            expected_sha256=expected_sha256,
            environment={},
            allow_retired_unreadable=True,
        )


def _image_configuration(service: str) -> dict[str, object]:
    if service == "chrony-nts":
        return {
            "User": "10001:10001",
            "Entrypoint": ["/usr/sbin/chronyd"],
            "Cmd": [
                "-x",
                "-d",
                "-U",
                "-f",
                "/etc/autoquant/trusted-time/chrony.conf",
            ],
            "WorkingDir": "",
            "ExposedPorts": None,
            "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"],
        }
    return {
        "User": "10001:10001",
        "Entrypoint": None,
        "Cmd": ["autoquant-trusted-time-supervisor"],
        "WorkingDir": "/workspace",
        "ExposedPorts": None,
        "Env": ["PATH=/opt/venv/bin:/usr/local/bin:/usr/bin"],
    }


def _container_inspection(
    *,
    image_id: str,
    service: str,
    healthy: bool,
) -> list[dict[str, object]]:
    image_configuration = _image_configuration(service)
    runtime_environment = list(cast(list[str], image_configuration["Env"]))
    source = service == "chrony-nts"
    if not source:
        runtime_environment.extend(
            [
                "AQT_TRUSTED_TIME_AUTHORITY_PATH=/etc/autoquant/trusted-time/source-authority.json",
                "AQT_TRUSTED_TIME_CHRONY_CONFIG_PATH=/etc/autoquant/trusted-time/chrony.conf",
                "AQT_TRUSTED_TIME_DATABASE_URL_FILE=/run/secrets/trusted_time_database_url",
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTHORITY_PATH=" + HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_AUTH_SECRET_FILE="
                + HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
                "AQT_TRUSTED_TIME_HEAD_ANCHOR_SIGNING_KEY_FILE="
                + HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
            ]
        )
    state: dict[str, object] = {"Running": True, "Status": "running"}
    if healthy:
        state["Health"] = {"Status": "healthy"}
    return [
        {
            "Image": image_id,
            "Config": {
                **image_configuration,
                "Env": runtime_environment,
                "Labels": {
                    "com.docker.compose.project": "autoquanttrader-trusted-time",
                    "com.docker.compose.service": service,
                },
                "Healthcheck": (
                    {
                        "Test": [
                            "CMD",
                            "/usr/bin/chronyc",
                            "-h",
                            "/run/chrony/chronyd.sock",
                            "activity",
                        ],
                        "Interval": 2_000_000_000,
                        "Timeout": 1_000_000_000,
                        "StartPeriod": 2_000_000_000,
                        "Retries": 15,
                    }
                    if source
                    else None
                ),
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Privileged": False,
                "PidsLimit": 32 if source else 64,
                "NanoCpus": 250_000_000 if source else 500_000_000,
                "Memory": 67_108_864 if source else 268_435_456,
                "Init": True,
                "NetworkMode": COMPOSE_NETWORK_NAME,
                "PublishAllPorts": False,
                "PortBindings": {},
                "Devices": None,
                "DeviceCgroupRules": None,
                "Tmpfs": {
                    "/tmp": (
                        "rw,noexec,nosuid,nodev,"
                        f"size={'8m' if source else '16m'},"
                        "uid=10001,gid=10001,mode=0700"
                    )
                },
                "RestartPolicy": {
                    "Name": "unless-stopped" if source else "no",
                    "MaximumRetryCount": 0,
                },
                "Binds": ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw"] if source else None),
                "Mounts": [
                    {
                        "Type": "volume",
                        "Source": COMPOSE_SOCKET_VOLUME_NAME,
                        "Target": "/run/chrony",
                        "VolumeOptions": {"NoCopy": True},
                    },
                    *(
                        [
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".database-secret-" + "a" * 32)
                                    / "database-url"
                                ),
                                "Target": "/run/secrets/trusted_time_database_url",
                                "ReadOnly": True,
                            },
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".head-anchor-authority-" + "a" * 32)
                                    / HEAD_ANCHOR_AUTHORITY_FILE_NAME
                                ),
                                "Target": HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
                                "ReadOnly": True,
                            },
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".head-anchor-auth-" + "a" * 32)
                                    / HEAD_ANCHOR_AUTH_SECRET_FILE_NAME
                                ),
                                "Target": HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
                                "ReadOnly": True,
                            },
                            {
                                "Type": "bind",
                                "Source": "/host_mnt"
                                + str(
                                    DATABASE_SECRET_ROOT
                                    / (".head-anchor-signing-key-" + "a" * 32)
                                    / HEAD_ANCHOR_SIGNING_KEY_FILE_NAME
                                ),
                                "Target": HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
                                "ReadOnly": True,
                            },
                        ]
                        if not source
                        else []
                    ),
                ],
            },
            "Mounts": [
                {
                    "Type": "volume",
                    "Name": COMPOSE_SOCKET_VOLUME_NAME,
                    "Destination": "/run/chrony",
                    "RW": True,
                },
                *(
                    [
                        {
                            "Type": "volume",
                            "Name": COMPOSE_STATE_VOLUME_NAME,
                            "Destination": "/var/lib/chrony",
                            "RW": True,
                        }
                    ]
                    if source
                    else [
                        {
                            "Type": "bind",
                            "Destination": "/run/secrets/trusted_time_database_url",
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Destination": HEAD_ANCHOR_AUTHORITY_RUNTIME_PATH,
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Destination": HEAD_ANCHOR_AUTH_SECRET_RUNTIME_PATH,
                            "RW": False,
                        },
                        {
                            "Type": "bind",
                            "Destination": HEAD_ANCHOR_SIGNING_KEY_RUNTIME_PATH,
                            "RW": False,
                        },
                    ]
                ),
            ],
            "NetworkSettings": {
                "Networks": {
                    COMPOSE_NETWORK_NAME: {},
                }
            },
            "State": state,
        }
    ]


def test_launcher_qualifies_before_secret_and_starts_only_admitted_ids(
    tmp_path: Path,
) -> None:
    env_file = _env_file(
        tmp_path,
        f"AQT_DATABASE_URL={DATABASE_URL}\nALPACA_PAPER_API_SECRET=not-forwarded\n",
    )
    admission = _admission()
    secret = _materialized_secret()
    head_anchor_payloads = _head_anchor_payloads()
    head_anchor_inputs = _materialized_head_anchor_inputs()
    events: list[str] = []
    observed: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def fake_build(_: Path) -> TrustedTimeImageAdmission:
        events.append("admission-created")
        return admission

    def fake_artifact_load(_: Path) -> TrustedTimeImageAdmission:
        events.append("artifact-loaded")
        return admission

    def fake_load(path: Path) -> str:
        events.append("secret-loaded")
        return load_runtime_database_url(path)

    def fake_daemon(**_: object) -> LocalDockerDaemonIdentity:
        events.append("daemon-qualified")
        return DAEMON_IDENTITY

    def fake_render(
        *,
        source_image: str,
        supervisor_image: str,
        database_secret_file: Path,
        head_anchor_authority_file: Path,
        head_anchor_auth_secret_file: Path,
        head_anchor_signing_key_secret_file: Path,
    ) -> object:
        assert source_image == SOURCE_IMAGE_ID
        assert supervisor_image == SUPERVISOR_IMAGE_ID
        if database_secret_file != Path("/dev/null"):
            assert head_anchor_authority_file == head_anchor_inputs.authority.path
            assert head_anchor_auth_secret_file == head_anchor_inputs.auth_secret.path
            assert head_anchor_signing_key_secret_file == head_anchor_inputs.signing_key.path
        events.append(f"compose-rendered:{database_secret_file.name}")
        return {"model": "exact"}

    def fake_validate(
        _: object,
        *,
        expected_source_image: str,
        expected_supervisor_image: str,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
    ) -> None:
        assert expected_source_image == SOURCE_IMAGE_ID
        assert expected_supervisor_image == SUPERVISOR_IMAGE_ID
        events.append(f"compose-qualified:{expected_database_secret_file.name}")

    def fake_topology(
        _: TrustedTimeImageIdentities,
        *,
        environment: dict[str, str],
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
    ) -> None:
        assert "AQT_TRUSTED_TIME_DATABASE_URL" not in environment
        assert expected_database_secret_file == secret.path
        assert expected_head_anchor_authority_file == head_anchor_inputs.authority.path
        assert expected_head_anchor_auth_secret_file == head_anchor_inputs.auth_secret.path
        assert expected_head_anchor_signing_key_secret_file == head_anchor_inputs.signing_key.path
        events.append("runtime-qualified")

    def fake_run(
        argv: tuple[str, ...],
        *,
        environment: Any,
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        exact_environment = cast(dict[str, str], environment)
        observed.append((argv, dict(exact_environment)))
        if argv == compose_argv():
            events.append("compose-up")
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    with (
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            side_effect=fake_build,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            side_effect=fake_artifact_load,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_runtime_database_url",
            side_effect=fake_load,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_trusted_time_head_anchor_source_payloads",
            return_value=head_anchor_payloads,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            side_effect=fake_daemon,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            side_effect=fake_render,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.validate_compose_model",
            side_effect=fake_validate,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._validate_created_topology",
            side_effect=fake_topology,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_database_secret",
            return_value=secret,
        ) as materialize,
        patch(
            "scripts.start_trusted_time_supervisor.materialize_trusted_time_head_anchor_inputs",
            return_value=head_anchor_inputs,
        ) as materialize_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_database_secret"
        ) as validate_secret,
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_trusted_time_head_anchor_inputs"
        ) as validate_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_database_secret"
        ) as cleanup_secret,
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_trusted_time_head_anchor_inputs"
        ) as cleanup_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor._compose_container_id",
            return_value=SUPERVISOR_CONTAINER_ID,
        ),
        patch(
            "scripts.start_trusted_time_supervisor._validate_mounted_staged_inputs"
        ) as validate_mounted,
        patch("scripts.start_trusted_time_supervisor._wait_for_database_secret_consumption"),
        patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run),
    ):
        return_code = run_local_topology(env_file=env_file)

    assert return_code == 0
    assert events.index("admission-created") < events.index("secret-loaded")
    assert events.count("artifact-loaded") == 2
    assert events.count("runtime-qualified") == 3
    assert events.count("compose-up") == 1
    materialize.assert_called_once_with(DATABASE_URL)
    materialize_head_anchor.assert_called_once_with(head_anchor_payloads)
    assert validate_secret.call_count == 2
    assert validate_head_anchor.call_count == 2
    assert validate_mounted.call_count == 3
    assert validate_mounted.call_args_list[-1].kwargs["allow_retired_unreadable"] is True
    cleanup_secret.assert_called_once_with(secret)
    cleanup_head_anchor.assert_called_once_with(head_anchor_inputs)
    up_environment = next(environment for argv, environment in observed if argv == compose_argv())
    assert up_environment["AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"] == str(secret.path)
    assert up_environment[HEAD_ANCHOR_AUTHORITY_SOURCE_ENVIRONMENT] == str(
        head_anchor_inputs.authority.path
    )
    assert up_environment[HEAD_ANCHOR_AUTH_SECRET_SOURCE_ENVIRONMENT] == str(
        head_anchor_inputs.auth_secret.path
    )
    assert up_environment[HEAD_ANCHOR_SIGNING_KEY_SOURCE_ENVIRONMENT] == str(
        head_anchor_inputs.signing_key.path
    )
    assert up_environment["AQT_TRUSTED_TIME_SOURCE_IMAGE"] == SOURCE_IMAGE_ID
    assert up_environment["AQT_TRUSTED_TIME_SUPERVISOR_IMAGE"] == SUPERVISOR_IMAGE_ID
    assert "ALPACA_PAPER_API_SECRET" not in up_environment
    assert compose_argv()[-8:] == (
        "--detach",
        "--no-build",
        "--pull",
        "never",
        "--force-recreate",
        "--wait",
        "--wait-timeout",
        "60",
    )
    for argv, environment in observed:
        if argv[0] == "docker" and argv[1] in {"container", "volume"}:
            assert "AQT_TRUSTED_TIME_DATABASE_URL" not in environment


def test_created_container_validation_requires_exact_image_running_and_health() -> None:
    source = _container_inspection(
        image_id=SOURCE_IMAGE_ID,
        service="chrony-nts",
        healthy=True,
    )
    validate_created_container(
        source,
        expected_image_id=SOURCE_IMAGE_ID,
        expected_image_configuration=_image_configuration("chrony-nts"),
        expected_service="chrony-nts",
        require_healthy=True,
    )

    source[0]["Image"] = SUPERVISOR_IMAGE_ID
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity or state"):
        validate_created_container(
            source,
            expected_image_id=SOURCE_IMAGE_ID,
            expected_image_configuration=_image_configuration("chrony-nts"),
            expected_service="chrony-nts",
            require_healthy=True,
        )


@pytest.mark.parametrize(
    ("binds", "message"),
    [
        (["other-volume:/var/lib/chrony:rw"], "state volume bind"),
        ([f"{COMPOSE_STATE_VOLUME_NAME}:/other:rw"], "state volume bind"),
        ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:ro"], "state volume bind"),
        ([f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw,z"], "state volume bind"),
        (
            [
                f"{COMPOSE_STATE_VOLUME_NAME}:/var/lib/chrony:rw",
                "other-volume:/other:rw",
            ],
            "volume request set",
        ),
    ],
)
def test_source_state_volume_legacy_bind_requires_one_exact_compose_encoding(
    binds: list[str],
    message: str,
) -> None:
    source = _container_inspection(
        image_id=SOURCE_IMAGE_ID,
        service="chrony-nts",
        healthy=True,
    )
    host = cast(dict[str, object], source[0]["HostConfig"])
    host["Binds"] = binds

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match=message):
        validate_created_container(
            source,
            expected_image_id=SOURCE_IMAGE_ID,
            expected_image_configuration=_image_configuration("chrony-nts"),
            expected_service="chrony-nts",
            require_healthy=True,
        )


def test_supervisor_runtime_inputs_require_exact_read_only_native_or_desktop_sources() -> None:
    expected = DATABASE_SECRET_ROOT / (".database-secret-" + "a" * 32) / "database-url"
    head_anchor_inputs = _materialized_head_anchor_inputs()
    supervisor = _container_inspection(
        image_id=SUPERVISOR_IMAGE_ID,
        service="trusted-time-supervisor",
        healthy=False,
    )
    validate_created_container(
        supervisor,
        expected_image_id=SUPERVISOR_IMAGE_ID,
        expected_image_configuration=_image_configuration("trusted-time-supervisor"),
        expected_service="trusted-time-supervisor",
        require_healthy=False,
        expected_database_secret_file=expected,
        expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
    )

    host = cast(dict[str, object], supervisor[0]["HostConfig"])
    mounts = cast(list[dict[str, object]], host["Mounts"])
    for mount in mounts[1:]:
        mount["Source"] = cast(str, mount["Source"]).removeprefix("/host_mnt")
    validate_created_container(
        supervisor,
        expected_image_id=SUPERVISOR_IMAGE_ID,
        expected_image_configuration=_image_configuration("trusted-time-supervisor"),
        expected_service="trusted-time-supervisor",
        require_healthy=False,
        expected_database_secret_file=expected,
        expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
    )

    mounts[1]["Source"] = "/host_mnt/host_mnt" + str(expected)
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="secret bind"):
        validate_created_container(
            supervisor,
            expected_image_id=SUPERVISOR_IMAGE_ID,
            expected_image_configuration=_image_configuration("trusted-time-supervisor"),
            expected_service="trusted-time-supervisor",
            require_healthy=False,
            expected_database_secret_file=expected,
            expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
        )

    mounts[1]["Source"] = str(expected)
    mounts[2]["ReadOnly"] = False
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="authority bind"):
        validate_created_container(
            supervisor,
            expected_image_id=SUPERVISOR_IMAGE_ID,
            expected_image_configuration=_image_configuration("trusted-time-supervisor"),
            expected_service="trusted-time-supervisor",
            require_healthy=False,
            expected_database_secret_file=expected,
            expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
        )

    mounts[2]["ReadOnly"] = True
    runtime_mounts = cast(list[dict[str, object]], supervisor[0]["Mounts"])
    runtime_mounts[2]["RW"] = True
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="runtime input mount"):
        validate_created_container(
            supervisor,
            expected_image_id=SUPERVISOR_IMAGE_ID,
            expected_image_configuration=_image_configuration("trusted-time-supervisor"),
            expected_service="trusted-time-supervisor",
            require_healthy=False,
            expected_database_secret_file=expected,
            expected_head_anchor_authority_file=head_anchor_inputs.authority.path,
            expected_head_anchor_auth_secret_file=head_anchor_inputs.auth_secret.path,
            expected_head_anchor_signing_key_secret_file=head_anchor_inputs.signing_key.path,
        )


@pytest.mark.parametrize(
    ("section", "field_name", "value", "message"),
    [
        ("Config", "Cmd", ["/bin/true"], "command or image"),
        ("Config", "Entrypoint", ["/bin/sh"], "command or image"),
        ("Config", "Env", ["PATH=/usr/bin", "DATABASE_URL=secret"], "environment allowlist"),
        ("HostConfig", "ReadonlyRootfs", False, "isolation or resource"),
        ("HostConfig", "CapAdd", ["SYS_TIME"], "isolation or resource"),
        ("HostConfig", "NetworkMode", "host", "isolation or resource"),
        ("HostConfig", "Mounts", [], "volume request set"),
    ],
)
def test_created_container_validation_rejects_command_cap_network_or_mount_drift(
    section: str,
    field_name: str,
    value: object,
    message: str,
) -> None:
    source = _container_inspection(
        image_id=SOURCE_IMAGE_ID,
        service="chrony-nts",
        healthy=True,
    )
    exact_section = cast(dict[str, object], source[0][section])
    exact_section[field_name] = value

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match=message):
        validate_created_container(
            source,
            expected_image_id=SOURCE_IMAGE_ID,
            expected_image_configuration=_image_configuration("chrony-nts"),
            expected_service="chrony-nts",
            require_healthy=True,
        )


def test_stale_socket_volume_stops_and_removes_unqualified_topology(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    secret = _materialized_secret()
    head_anchor_inputs = _materialized_head_anchor_inputs()
    calls: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv == compose_argv():
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "down" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    with (
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            return_value=DAEMON_IDENTITY,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_trusted_time_head_anchor_source_payloads",
            return_value=_head_anchor_payloads(),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_database_secret",
            return_value=secret,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.materialize_trusted_time_head_anchor_inputs",
            return_value=head_anchor_inputs,
        ),
        patch("scripts.start_trusted_time_supervisor.validate_materialized_database_secret"),
        patch(
            "scripts.start_trusted_time_supervisor.validate_materialized_trusted_time_head_anchor_inputs"
        ),
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_database_secret"
        ) as cleanup,
        patch(
            "scripts.start_trusted_time_supervisor.cleanup_materialized_trusted_time_head_anchor_inputs"
        ) as cleanup_head_anchor,
        patch(
            "scripts.start_trusted_time_supervisor._validate_created_topology",
            side_effect=TrustedTimeImageVerificationError(
                "trusted-time socket volume is not the exact tmpfs contract"
            ),
        ),
        patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run),
        pytest.raises(TrustedTimeImageVerificationError, match="exact tmpfs contract"),
    ):
        run_local_topology(env_file=env_file)

    assert "down" in calls[-1]
    cleanup.assert_called_once_with(secret)
    cleanup_head_anchor.assert_called_once_with(head_anchor_inputs)


def test_local_docker_qualification_accepts_one_owned_unix_socket_and_daemon() -> None:
    socket_path = Path("/private/tmp/aqt-local-docker.sock")
    completed = subprocess.CompletedProcess(
        ["docker", "info"],
        0,
        '"LOCAL:DAEMON:1"\n',
        "",
    )
    metadata = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=os.getuid())
    with (
        patch("scripts.start_trusted_time_supervisor.Path.resolve", return_value=socket_path),
        patch("scripts.start_trusted_time_supervisor.Path.stat", return_value=metadata),
        patch(
            "scripts.start_trusted_time_supervisor._run_docker",
            return_value=completed,
        ) as run,
    ):
        identity = qualify_local_docker_daemon(
            environment={"DOCKER_HOST": f"unix://{socket_path}"},
        )

    assert identity == LocalDockerDaemonIdentity(
        context_name="<DOCKER_HOST>",
        endpoint=f"unix://{socket_path}",
        daemon_id="LOCAL:DAEMON:1",
    )
    assert run.call_args.args[0] == ("docker", "info", "--format", "{{json .ID}}")


@pytest.mark.parametrize(
    "endpoint",
    [
        "tcp://docker.example:2376",
        "ssh://operator@docker.example",
        "http://127.0.0.1:2375",
    ],
)
def test_local_docker_qualification_rejects_remote_endpoint_before_daemon_contact(
    endpoint: str,
) -> None:
    with (
        patch("scripts.start_trusted_time_supervisor._run_docker") as run,
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="local Unix socket"),
    ):
        qualify_local_docker_daemon(environment={"DOCKER_HOST": endpoint})

    run.assert_not_called()


def test_daemon_identity_change_is_rejected_before_secret_load(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    changed = LocalDockerDaemonIdentity(
        context_name=DAEMON_IDENTITY.context_name,
        endpoint=DAEMON_IDENTITY.endpoint,
        daemon_id="LOCAL:DAEMON:2",
    )
    with (
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            side_effect=[DAEMON_IDENTITY, changed],
        ),
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch("scripts.start_trusted_time_supervisor.load_runtime_database_url") as load_secret,
        pytest.raises(TrustedTimeSupervisorConfigurationError, match="identity changed"),
    ):
        run_local_topology(env_file=env_file)

    load_secret.assert_not_called()


def test_image_admission_swap_is_rejected_before_secret_load(tmp_path: Path) -> None:
    env_file = _env_file(tmp_path, f"AQT_DATABASE_URL={DATABASE_URL}\n")
    admission = _admission()
    changed = replace(admission, artifact_sha256="f" * 64)
    with (
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            return_value=DAEMON_IDENTITY,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            side_effect=(admission, changed),
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        patch("scripts.start_trusted_time_supervisor.load_runtime_database_url") as load_secret,
        pytest.raises(
            TrustedTimeSupervisorConfigurationError,
            match="artifact changed before secret load",
        ),
    ):
        run_local_topology(env_file=env_file)

    load_secret.assert_not_called()


def test_chrony_state_volume_requires_exact_compose_owned_local_storage() -> None:
    inspection = [
        {
            "Name": COMPOSE_STATE_VOLUME_NAME,
            "Driver": "local",
            "Scope": "local",
            "Options": None,
            "Labels": {
                "com.docker.compose.project": "autoquanttrader-trusted-time",
                "com.docker.compose.volume": "chrony_state",
            },
        }
    ]
    validate_chrony_state_volume_inspection(inspection)

    inspection[0]["Options"] = {"type": "none", "device": "/host", "o": "bind"}
    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="driver drifted"):
        validate_chrony_state_volume_inspection(inspection)


def test_chrony_state_directory_check_is_non_destructive_and_requires_fixed_identity() -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(
        argv: tuple[str, ...],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[-3:] == ("-c", "%u:%g:%a", "/var/lib/chrony"):
            return subprocess.CompletedProcess(argv, 0, "10001:10001:755\n", "")
        if "/bin/busybox" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    with patch("scripts.start_trusted_time_supervisor._run_docker", side_effect=fake_run):
        _validate_chrony_state_directory(SOURCE_CONTAINER_ID)

    access_modes = [argv[-2] for argv in calls if "/bin/busybox" in argv]
    assert access_modes == ["-d", "-r", "-w", "-x"]
    assert all("touch" not in argv and "rm" not in argv for argv in calls)


def test_main_sanitizes_owner_file_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        ["start-trusted-time-supervisor", "--env-file", "/missing/secret.env"],
    )

    admission = _admission()
    with (
        patch(
            "scripts.start_trusted_time_supervisor.qualify_local_docker_daemon",
            return_value=DAEMON_IDENTITY,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.build_verify_and_write_image_admission",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.load_image_admission_artifact",
            return_value=admission,
        ),
        patch(
            "scripts.start_trusted_time_supervisor.render_compose_model",
            return_value={"model": "exact"},
        ),
        patch("scripts.start_trusted_time_supervisor.validate_compose_model"),
        pytest.raises(SystemExit) as captured,
    ):
        main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert payload["status"] == "fatal"
    assert payload["database_secret_disclosed"] is False
    assert "missing" not in output.out
    assert output.err == ""
