from __future__ import annotations

import configparser
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SYSTEMD_DIRECTORY = (
    REPOSITORY_ROOT / "infra/trusted-time/graceful-stop-v2/systemd"
)

TRANSPORT_MOUNT = (
    r"run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-transport.mount"
)
HOST_SECRET_MOUNT = (
    r"run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-host\x2dsecrets.mount"
)
SUPERVISOR_SECRET_MOUNT = (
    r"run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-supervisor\x2dsecrets.mount"
)
RECOVERY_SECRET_MOUNT = (
    r"run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-recovery\x2dsecrets.mount"
)

EXPECTED_MOUNTS = {
    TRANSPORT_MOUNT: (
        "/run/autoquant/trusted-time/graceful-stop-v2/transport",
        "nodev,nosuid,noexec,size=64K,mode=0770,uid=0,gid=10001",
    ),
    HOST_SECRET_MOUNT: (
        "/run/autoquant/trusted-time/graceful-stop-v2/host-secrets",
        "nodev,nosuid,noexec,size=64K,mode=0700,uid=0,gid=0",
    ),
    SUPERVISOR_SECRET_MOUNT: (
        "/run/autoquant/trusted-time/graceful-stop-v2/supervisor-secrets",
        "nodev,nosuid,noexec,size=64K,mode=0730,uid=0,gid=10001",
    ),
    RECOVERY_SECRET_MOUNT: (
        "/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets",
        "nodev,nosuid,noexec,size=64K,mode=0700,uid=0,gid=0",
    ),
}

EXPECTED_EXECUTABLES = {
    "autoquant-trusted-time-graceful-stop-v2-host.service": (
        "/opt/autoquant/trusted-time-graceful-stop-v2-host/bin/"
        "autoquant-trusted-time-graceful-stop-v2-host"
    ),
    "autoquant-trusted-time-graceful-stop-v2-supervisor.service": (
        "/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/bin/"
        "autoquant-trusted-time-graceful-stop-v2-supervisor"
    ),
    "autoquant-trusted-time-graceful-stop-v2-recovery.service": (
        "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/bin/"
        "autoquant-trusted-time-graceful-stop-v2-recovery"
    ),
    "autoquant-trusted-time-graceful-stop-v2-host-provision.service": (
        "/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/"
        "autoquant-trusted-time-graceful-stop-v2-host-provision"
    ),
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision.service": (
        "/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/"
        "autoquant-trusted-time-graceful-stop-v2-supervisor-provision"
    ),
    "autoquant-trusted-time-graceful-stop-v2-recovery-provision.service": (
        "/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/"
        "autoquant-trusted-time-graceful-stop-v2-recovery-provision"
    ),
}

EXPECTED_UNIT_SHA256 = {
    "autoquant-trusted-time-graceful-stop-v2-host-provision.service": (
        "7f5adf8b294b418c1492eb84044eaa4230bd74708554a3009bae9cd2db6a96f0"
    ),
    "autoquant-trusted-time-graceful-stop-v2-host.service": (
        "7f84bdd03d8e80e571f06d02fc91b427864c0647d522e2887f99c6ffc0c3fcd1"
    ),
    "autoquant-trusted-time-graceful-stop-v2-recovery-provision.service": (
        "e8e02dfbdded2cdacea71d0d2205a7b43fd38ae07c27acad86dad0ae850f7093"
    ),
    "autoquant-trusted-time-graceful-stop-v2-recovery.service": (
        "90aeb875aaea0d690011dd44f150c9500928d04166d95b7399baad48f24fb9d8"
    ),
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision.service": (
        "3d5accb7fefee1a3aafa6eaba3f0fca970ce9a6bdb5cd3a030e3f8662f5646f9"
    ),
    "autoquant-trusted-time-graceful-stop-v2-supervisor.service": (
        "716c0acf326ba0a07e9eac84041d3b80ddcdf83c4438715121ebfc366b9eafc6"
    ),
    HOST_SECRET_MOUNT: (
        "0fd219ec43c6dd68eec70e1c3ff6066f18661e800d405731326aa0942ce08ecd"
    ),
    RECOVERY_SECRET_MOUNT: (
        "b58614a9fc175f24f0503f19d8e0ad73ca56cef09f5ac69e4b2ca60e66c1b6fd"
    ),
    SUPERVISOR_SECRET_MOUNT: (
        "374194dc36000573bb98a897811b0c238375c46100767ce3ede5b00d044e9a6d"
    ),
    TRANSPORT_MOUNT: (
        "34a419c7614574186f4b4419c1cf42a75015a0d85378d1d4e4c33f4b7ad4fd18"
    ),
}


def _read_unit(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
    )
    parser.optionxform = str  # type: ignore[method-assign]
    with path.open(encoding="utf-8") as unit_file:
        parser.read_file(unit_file)
    return parser


def test_source_only_unit_set_and_mount_contracts_are_exact() -> None:
    unit_paths = tuple(sorted(SYSTEMD_DIRECTORY.iterdir()))
    assert {path.name for path in unit_paths} == {
        *EXPECTED_MOUNTS,
        *EXPECTED_EXECUTABLES,
    }
    assert set(EXPECTED_UNIT_SHA256) == {path.name for path in unit_paths}

    for unit_path in unit_paths:
        assert unit_path.is_file()
        assert not unit_path.is_symlink()
        text = unit_path.read_text(encoding="utf-8")
        assert text.endswith("\n")
        assert "[Install]" not in text
        assert "WantedBy=" not in text
        assert "RequiredBy=" not in text
        assert "Alias=" not in text
        assert "systemctl" not in text
        assert "daemon-reload" not in text
        assert hashlib.sha256(unit_path.read_bytes()).hexdigest() == EXPECTED_UNIT_SHA256[
            unit_path.name
        ]

    for file_name, (where, options) in EXPECTED_MOUNTS.items():
        unit = _read_unit(SYSTEMD_DIRECTORY / file_name)
        assert tuple(unit) == ("DEFAULT", "Unit", "Mount")
        assert unit["Mount"] == {
            "What": "tmpfs",
            "Where": where,
            "Type": "tmpfs",
            "Options": options,
        }


def test_every_fixed_service_has_one_argument_free_candidate_executable() -> None:
    for file_name, executable in EXPECTED_EXECUTABLES.items():
        unit = _read_unit(SYSTEMD_DIRECTORY / file_name)
        assert tuple(unit) == ("DEFAULT", "Unit", "Service")
        assert unit["Service"]["ExecStart"] == executable
        assert " " not in unit["Service"]["ExecStart"]
        assert unit["Service"]["StandardInput"] == "null"
        assert unit["Service"]["StandardOutput"] == "null"
        assert unit["Service"]["StandardError"] == "null"
        assert unit["Service"]["NoNewPrivileges"] == "yes"
        assert unit["Service"]["ProtectSystem"] == "strict"
        assert unit["Service"]["ProtectHome"] == "yes"
        assert unit["Service"]["PrivateTmp"] == "yes"


def test_recovery_is_source_isolated_from_normal_transport() -> None:
    recovery = _read_unit(
        SYSTEMD_DIRECTORY
        / "autoquant-trusted-time-graceful-stop-v2-recovery.service"
    )
    recovery_unit = recovery["Unit"]
    conflicts = set(recovery_unit["Conflicts"].split())
    normal_owners = {
        TRANSPORT_MOUNT,
        HOST_SECRET_MOUNT,
        SUPERVISOR_SECRET_MOUNT,
        "autoquant-trusted-time-graceful-stop-v2-host-provision.service",
        "autoquant-trusted-time-graceful-stop-v2-supervisor-provision.service",
        "autoquant-trusted-time-graceful-stop-v2-host.service",
        "autoquant-trusted-time-graceful-stop-v2-supervisor.service",
    }
    assert normal_owners <= conflicts
    assert normal_owners <= set(recovery_unit["After"].split())
    assert recovery["Service"]["PrivateNetwork"] == "yes"
    assert recovery["Service"]["RestrictAddressFamilies"] == "none"
    assert "transport" not in recovery["Service"]["ReadWritePaths"]

    for role in ("host", "supervisor"):
        normal = _read_unit(
            SYSTEMD_DIRECTORY
            / f"autoquant-trusted-time-graceful-stop-v2-{role}.service"
        )
        assert (
            normal["Unit"]["ConditionPathIsMountPoint"]
            == "!/run/autoquant/trusted-time/graceful-stop-v2/recovery-secrets"
        )
        assert RECOVERY_SECRET_MOUNT in normal["Unit"]["Conflicts"].split()
        assert (
            "autoquant-trusted-time-graceful-stop-v2-recovery-provision.service"
            in normal["Unit"]["Conflicts"].split()
        )

    recovery_mount = _read_unit(SYSTEMD_DIRECTORY / RECOVERY_SECRET_MOUNT)
    recovery_provisioner = _read_unit(
        SYSTEMD_DIRECTORY
        / "autoquant-trusted-time-graceful-stop-v2-recovery-provision.service"
    )
    for unit in (recovery_mount, recovery_provisioner):
        assert normal_owners <= set(unit["Unit"]["Conflicts"].split())
        assert normal_owners <= set(unit["Unit"]["After"].split())


def test_no_deployment_or_activation_surface_names_wave_7_resources() -> None:
    forbidden = (
        "/run/autoquant/trusted-time/graceful-stop-v2",
        "/opt/autoquant/trusted-time-graceful-stop-v2",
        "autoquant-trusted-time-graceful-stop-v2-",
        "infra/trusted-time/graceful-stop-v2/systemd",
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "systemctl",
        "daemon-reload",
    )
    surfaces = [REPOSITORY_ROOT / "Makefile"]
    for root in (
        REPOSITORY_ROOT / "infra/compose",
        REPOSITORY_ROOT / "infra/docker",
        REPOSITORY_ROOT / "scripts",
    ):
        surfaces.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
    for path in surfaces:
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert not any(token in source for token in forbidden), path


@pytest.mark.skipif(
    shutil.which("systemd-analyze") is None,
    reason="systemd-analyze is a Linux CI parse gate",
)
def test_systemd_accepts_every_source_unit(tmp_path: Path) -> None:
    root = tmp_path / "systemd-root"
    unit_directory = root / "etc/systemd/system"
    unit_directory.mkdir(parents=True)
    for source in SYSTEMD_DIRECTORY.iterdir():
        shutil.copyfile(source, unit_directory / source.name)
    for executable in EXPECTED_EXECUTABLES.values():
        staged = root / executable.removeprefix("/")
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(b"#!/bin/sh\nexit 191\n")
        staged.chmod(0o555)
    result = subprocess.run(
        [
            "systemd-analyze",
            "--man=no",
            f"--root={root}",
            "verify",
            *EXPECTED_UNIT_SHA256,
        ],
        check=False,
        capture_output=True,
        text=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ["PATH"]},
    )
    assert result.returncode == 0, result.stdout + result.stderr
