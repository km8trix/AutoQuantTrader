from __future__ import annotations

import configparser
from pathlib import Path


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
    assert {
        TRANSPORT_MOUNT,
        HOST_SECRET_MOUNT,
        SUPERVISOR_SECRET_MOUNT,
        "autoquant-trusted-time-graceful-stop-v2-host.service",
        "autoquant-trusted-time-graceful-stop-v2-supervisor.service",
    } <= conflicts
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
