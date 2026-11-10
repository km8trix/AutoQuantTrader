"""Exercise exact Wave 7 candidate bytes inside a disposable locked container."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast

_BUILD_SUPPORT_ROOT = Path(__file__).resolve(strict=True).parent
_ROOT = _BUILD_SUPPORT_ROOT.parent
if not __package__:
    sys.path.insert(0, str(_BUILD_SUPPORT_ROOT))
candidate_builder = importlib.import_module(
    "build_support.build_trusted_time_v2_candidates"
    if __package__
    else "build_trusted_time_v2_candidates"
)

_BASE_IMAGE = "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"
_BASE_IMAGE_RECORD = Path("/usr/share/autoquant/wave7-base-image")
_STAGING_ROOT = Path("/opt/autoquant")
_RECEIPT_NAME = "exact-candidate-execution.json"
_ROLE_DESTINATIONS = {
    "host": Path(
        "/opt/autoquant/trusted-time-graceful-stop-v2-host/bin/"
        "autoquant-trusted-time-graceful-stop-v2-host"
    ),
    "recovery": Path(
        "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/bin/"
        "autoquant-trusted-time-graceful-stop-v2-recovery"
    ),
    "supervisor": Path(
        "/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/bin/"
        "autoquant-trusted-time-graceful-stop-v2-supervisor"
    ),
}
_PROVISIONER_ROOT = Path("/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin")
_PROVISIONER_DESTINATIONS = {
    "host": _PROVISIONER_ROOT / "autoquant-trusted-time-graceful-stop-v2-host-provision",
    "recovery": (_PROVISIONER_ROOT / "autoquant-trusted-time-graceful-stop-v2-recovery-provision"),
    "supervisor": (
        _PROVISIONER_ROOT / "autoquant-trusted-time-graceful-stop-v2-supervisor-provision"
    ),
}
_ROLE_IMPORT_DESTINATIONS = {
    "host": Path("/opt/autoquant/trusted-time-graceful-stop-v2-host/lib/python"),
    "recovery": Path("/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python"),
    "supervisor": Path("/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/lib/python"),
}
_RECOVERY_RUNTIME_DESTINATION = Path(
    "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python-runtime"
)
_RECOVERY_RUNTIME_FILES = frozenset(
    {
        "LICENSE.txt",
        "encodings/__init__.py",
        "encodings/aliases.py",
        "encodings/ascii.py",
        "encodings/utf_8.py",
    }
)


class _MountRecord(TypedDict):
    filesystem: str
    mount_options: list[str]
    super_options: list[str]
    target: str


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha256(document: object) -> str:
    return _sha256_bytes(
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )


def _read_json(path: Path) -> dict[str, object]:
    candidate_builder._regular_file(path)
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        candidate_builder._fail(f"exact-execution JSON is invalid: {path}: {error}")
    if type(document) is not dict:
        candidate_builder._fail(f"exact-execution JSON is not one object: {path}")
    return cast(dict[str, object], document)


def _mount_record(target: str) -> _MountRecord:
    matches: list[_MountRecord] = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        trailing = after.split()
        if not separator or len(fields) < 6 or len(trailing) < 3 or fields[4] != target:
            continue
        matches.append(
            {
                "filesystem": trailing[0],
                "mount_options": sorted(fields[5].split(",")),
                "super_options": sorted(trailing[2].split(",")),
                "target": target,
            }
        )
    if len(matches) != 1:
        candidate_builder._fail(f"the qualification mount is not exact: {target}")
    return matches[0]


def _nested_mount_targets(root: str) -> list[str]:
    prefix = root.rstrip("/") + "/"
    targets: list[str] = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        fields = line.partition(" - ")[0].split()
        if len(fields) >= 5 and fields[4].startswith(prefix):
            targets.append(fields[4])
    return sorted(targets)


def _netlink_address_records() -> list[dict[str, object]]:
    address_family = getattr(socket, "AF_NETLINK", None)
    if not isinstance(address_family, int):
        candidate_builder._fail("the qualification kernel lacks the netlink address API")
    admitted_address_family = cast(int, address_family)
    request_type = 22  # RTM_GETADDR
    response_type = 20  # RTM_NEWADDR
    done_type = 3  # NLMSG_DONE
    error_type = 2  # NLMSG_ERROR
    sequence = 1
    header = struct.pack("=IHHII", 24, request_type, 0x301, sequence, 0)
    request = header + struct.pack("=BBBBI", socket.AF_UNSPEC, 0, 0, 0, 0)
    records: list[dict[str, object]] = []
    with socket.socket(admitted_address_family, socket.SOCK_RAW, 0) as netlink:
        netlink.bind((0, 0))
        netlink.sendto(request, (0, 0))
        complete = False
        while not complete:
            packet = netlink.recv(1024 * 1024)
            offset = 0
            while offset + 16 <= len(packet):
                length, message_type, _, message_sequence, _ = struct.unpack_from(
                    "=IHHII", packet, offset
                )
                if length < 16 or offset + length > len(packet) or message_sequence != sequence:
                    candidate_builder._fail("the qualification netlink response is invalid")
                if message_type == done_type:
                    complete = True
                    break
                if message_type == error_type:
                    error = struct.unpack_from("=i", packet, offset + 16)[0]
                    candidate_builder._fail(
                        f"the qualification netlink address dump failed: {error}"
                    )
                if message_type == response_type:
                    if length < 24:
                        candidate_builder._fail(
                            "the qualification netlink address record is truncated"
                        )
                    family, prefix_length, flags, scope, interface_index = struct.unpack_from(
                        "=BBBBI", packet, offset + 16
                    )
                    attributes: dict[int, bytes] = {}
                    attribute_offset = offset + 24
                    end = offset + length
                    while attribute_offset + 4 <= end:
                        attribute_length, attribute_type = struct.unpack_from(
                            "=HH", packet, attribute_offset
                        )
                        if attribute_length < 4 or attribute_offset + attribute_length > end:
                            candidate_builder._fail(
                                "the qualification netlink address attribute is invalid"
                            )
                        attributes[attribute_type] = packet[
                            attribute_offset + 4 : attribute_offset + attribute_length
                        ]
                        attribute_offset += (attribute_length + 3) & ~3
                    packed_address = attributes.get(2, attributes.get(1))
                    if family in (socket.AF_INET, socket.AF_INET6):
                        expected_size = 4 if family == socket.AF_INET else 16
                        if packed_address is None or len(packed_address) != expected_size:
                            candidate_builder._fail(
                                "the qualification netlink IP address is invalid"
                            )
                        admitted_address = cast(bytes, packed_address)
                        records.append(
                            {
                                "address": socket.inet_ntop(family, admitted_address),
                                "family": "ipv4" if family == socket.AF_INET else "ipv6",
                                "flags": flags,
                                "interface": socket.if_indextoname(interface_index),
                                "prefix_length": prefix_length,
                                "scope": scope,
                            }
                        )
                offset += (length + 3) & ~3
            if offset > len(packet):
                candidate_builder._fail("the qualification netlink packet is misaligned")
    return sorted(
        records,
        key=lambda record: (
            str(record["interface"]),
            str(record["family"]),
            str(record["address"]),
            int(cast(int, record["prefix_length"])),
        ),
    )


def _ipv4_route_records() -> tuple[list[dict[str, object]], str]:
    path = Path("/proc/net/route")
    payload = path.read_bytes()
    lines = payload.decode("ascii").splitlines()
    if not lines or lines[0].split() != [
        "Iface",
        "Destination",
        "Gateway",
        "Flags",
        "RefCnt",
        "Use",
        "Metric",
        "Mask",
        "MTU",
        "Window",
        "IRTT",
    ]:
        candidate_builder._fail("the qualification IPv4 route table is invalid")
    records: list[dict[str, object]] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 11:
            candidate_builder._fail("the qualification IPv4 route row is invalid")
        destination = ipaddress.IPv4Address(struct.pack("<I", int(fields[1], 16)))
        gateway = ipaddress.IPv4Address(struct.pack("<I", int(fields[2], 16)))
        mask = ipaddress.IPv4Address(struct.pack("<I", int(fields[7], 16)))
        network = ipaddress.IPv4Network(f"{destination}/{mask}", strict=False)
        flags = int(fields[3], 16)
        up = bool(flags & 0x1)
        record = {
            "destination": str(network),
            "flags": f"0x{flags:08x}",
            "gateway": str(gateway),
            "interface": fields[0],
            "up": up,
        }
        records.append(record)
        if up and (
            fields[0] != "lo"
            or not network.is_loopback
            or not (gateway.is_unspecified or gateway.is_loopback)
        ):
            candidate_builder._fail("the qualification namespace has an IPv4 route")
    return records, _sha256_bytes(payload)


def _ipv6_route_records() -> tuple[list[dict[str, object]], str]:
    path = Path("/proc/net/ipv6_route")
    payload = path.read_bytes()
    records: list[dict[str, object]] = []
    for line in payload.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 10:
            candidate_builder._fail("the qualification IPv6 route row is invalid")
        destination = ipaddress.IPv6Address(bytes.fromhex(fields[0]))
        prefix_length = int(fields[1], 16)
        next_hop = ipaddress.IPv6Address(bytes.fromhex(fields[4]))
        flags = int(fields[8], 16)
        network = ipaddress.IPv6Network((destination, prefix_length), strict=False)
        up = bool(flags & 0x1)
        record = {
            "destination": str(network),
            "flags": f"0x{flags:08x}",
            "interface": fields[9],
            "next_hop": str(next_hop),
            "up": up,
        }
        records.append(record)
        if up and (
            fields[9] != "lo"
            or not network.is_loopback
            or not (next_hop.is_unspecified or next_hop.is_loopback)
        ):
            candidate_builder._fail("the qualification namespace has an IPv6 route")
    return records, _sha256_bytes(payload)


def _network_namespace_record() -> dict[str, object]:
    interface_records: list[dict[str, object]] = []
    for interface_path in sorted(Path("/sys/class/net").iterdir()):
        flags_path = interface_path / "flags"
        operstate_path = interface_path / "operstate"
        if not flags_path.is_file() or not operstate_path.is_file():
            continue
        flags_text = flags_path.read_text(encoding="ascii").strip()
        operstate = operstate_path.read_text(encoding="ascii").strip()
        try:
            flags = int(flags_text, 0)
        except ValueError:
            candidate_builder._fail(
                f"the qualification interface flags are invalid: {interface_path.name}"
            )
        interface_records.append(
            {
                "flags": f"0x{flags:08x}",
                "iff_running": bool(flags & 0x40),
                "iff_up": bool(flags & 0x1),
                "name": interface_path.name,
                "operstate": operstate,
            }
        )
    interfaces = {str(record["name"]): record for record in interface_records}
    loopback = interfaces.get("lo")
    if loopback is None or loopback["iff_up"] is not True:
        candidate_builder._fail("the qualification loopback interface is not up")
    for name, record in interfaces.items():
        if name != "lo" and (
            record["iff_up"] is True or record["iff_running"] is True or record["operstate"] == "up"
        ):
            candidate_builder._fail(f"a non-loopback qualification interface is active: {name}")
    address_records = _netlink_address_records()
    if any(str(record["interface"]) not in interfaces for record in address_records):
        candidate_builder._fail("the qualification address dump names an unknown interface")
    for record in address_records:
        address = ipaddress.ip_address(str(record["address"]))
        if record["interface"] != "lo" or not address.is_loopback:
            candidate_builder._fail(
                "a non-loopback IP address is configured in the qualification namespace"
            )
    ipv4_routes, ipv4_routes_sha256 = _ipv4_route_records()
    ipv6_routes, ipv6_routes_sha256 = _ipv6_route_records()
    return {
        "addresses": address_records,
        "all_non_loopback_interfaces_inactive": True,
        "all_non_loopback_ip_addresses_absent": True,
        "all_active_non_loopback_routes_absent": True,
        "interfaces": interface_records,
        "ipv4_route_table": ipv4_routes,
        "ipv4_route_table_sha256": ipv4_routes_sha256,
        "ipv6_route_table": ipv6_routes,
        "ipv6_route_table_sha256": ipv6_routes_sha256,
        "loopback_present_and_up": True,
    }


def _validate_container_boundary(python_home: str) -> dict[str, object]:
    if (
        sys.platform != "linux"
        or os.uname().machine != "x86_64"
        or os.geteuid() != 0
        or os.getegid() != 0
        or os.getpid() != 1
        or not Path("/.dockerenv").is_file()
    ):
        candidate_builder._fail(
            "exact candidate execution requires a root-in-container x86_64 PID 1"
        )
    status = Path("/proc/self/status").read_text(encoding="ascii")
    fields = {
        line.partition(":")[0]: line.partition(":")[2].strip()
        for line in status.splitlines()
        if ":" in line
    }
    capability_names = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    observed_capabilities: dict[str, str] = {}
    for name in capability_names:
        value = fields.get(name, "")
        if re.fullmatch(r"[0-9A-Fa-f]+", value) is None or int(value, 16) != 0:
            candidate_builder._fail("the exact-execution container retained a Linux capability set")
        observed_capabilities[name] = value
    if fields.get("NoNewPrivs") != "1":
        candidate_builder._fail("the exact-execution container permits new privileges")
    network_namespace = _network_namespace_record()
    if any(path.exists() for path in (Path("/run/docker.sock"), Path("/var/run/docker.sock"))):
        candidate_builder._fail("the Docker control socket is exposed to exact execution")
    resolved_python_home = Path(python_home).resolve(strict=True)
    resolved_python = Path(sys.executable).resolve(strict=True)
    if str(resolved_python_home) != python_home or not resolved_python.is_relative_to(
        resolved_python_home
    ):
        candidate_builder._fail("the qualification Python is outside its exact mounted home")
    root_mount = _mount_record("/")
    workspace_mount = _mount_record("/workspace")
    python_mount = _mount_record(python_home)
    opt_mount = _mount_record("/opt")
    temporary_mount = _mount_record("/tmp")
    nested_mounts = {
        "python": _nested_mount_targets(python_home),
        "workspace": _nested_mount_targets("/workspace"),
    }
    if any(nested_mounts.values()):
        candidate_builder._fail(
            f"a read-only qualification bind contains nested mounts: {nested_mounts}"
        )
    if "ro" not in root_mount["mount_options"]:
        candidate_builder._fail("the exact-execution container root is writable")
    for record in (workspace_mount, python_mount):
        if "ro" not in record["mount_options"]:
            candidate_builder._fail("an exact-execution host bind mount is writable")
    for record in (opt_mount, temporary_mount):
        if record["filesystem"] != "tmpfs" or "rw" not in record["mount_options"]:
            candidate_builder._fail("an exact-execution scratch mount is not writable tmpfs")
    if "nosuid" not in opt_mount["mount_options"] or "nodev" not in opt_mount["mount_options"]:
        candidate_builder._fail("the transient /opt mount lacks nosuid/nodev")
    if any(
        option not in temporary_mount["mount_options"] for option in ("noexec", "nosuid", "nodev")
    ):
        candidate_builder._fail("the transient /tmp mount lacks noexec/nosuid/nodev")
    ipc_namespace_identity = os.readlink("/proc/self/ns/ipc")
    if re.fullmatch(r"ipc:\[[0-9]+\]", ipc_namespace_identity) is None:
        candidate_builder._fail("the qualification IPC namespace identity is invalid")
    return {
        "capabilities_dropped": True,
        "candidate_staging_mount": "/opt",
        "docker_socket_absent": True,
        "qualification_python": str(resolved_python),
        "mounts": {
            "opt": opt_mount,
            "python": python_mount,
            "root": root_mount,
            "temporary": temporary_mount,
            "workspace": workspace_mount,
        },
        "nested_mounts": nested_mounts,
        "network_namespace": network_namespace,
        "network_none": True,
        "nested_source_and_python_mounts_absent": True,
        "no_new_privileges": True,
        "observed_capability_sets": observed_capabilities,
        "observed_ipc_namespace_identity": ipc_namespace_identity,
        "private_pid_namespace": True,
        "root_filesystem_read_only": True,
        "source_and_python_bind_mounts_read_only": True,
        "temporary_noexec_scratch_mount": "/tmp",
    }


def _dpkg_records() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for package in ("binutils", "gcc", "libc6-dev", "systemd"):
        completed = subprocess.run(
            (
                "/usr/bin/dpkg-query",
                "-W",
                "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n",
                package,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        words = completed.stdout.decode("utf-8", errors="strict").removesuffix("\n").split("\t")
        if completed.returncode != 0 or len(words) != 4 or words[3] != "ii ":
            candidate_builder._fail(f"qualification package identity is unavailable: {package}")
        records.append(
            {
                "architecture": words[2],
                "name": words[0],
                "status": words[3],
                "version": words[1],
            }
        )
    return records


def _candidate_path(root: Path, relative: str) -> Path:
    candidate = root / relative
    resolved = candidate.resolve(strict=True)
    if not resolved.is_relative_to(root):
        candidate_builder._fail("candidate receipt path escapes its output root")
    return resolved


def _copy_regular(source: Path, destination: Path, mode: int) -> dict[str, object]:
    metadata = candidate_builder._regular_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copyfile(source, destination)
    destination.chmod(mode)
    copied = candidate_builder._regular_file(destination, require_root=True)
    if stat.S_IMODE(copied.st_mode) != mode or copied.st_size != metadata.st_size:
        candidate_builder._fail(f"transient candidate copy metadata changed: {destination}")
    return {
        "gid": copied.st_gid,
        "mode": f"{mode:04o}",
        "path": str(destination),
        "sha256": _sha256(destination),
        "size": copied.st_size,
        "uid": copied.st_uid,
    }


def _stage_tree(
    candidate_root: Path,
    record: dict[str, object],
    destination: Path,
    *,
    expected_files: frozenset[str],
    expected_output_root: str,
) -> list[dict[str, object]]:
    output_root = record.get("output_root")
    files = record.get("files")
    intended_runtime_root = record.get("intended_runtime_root")
    if (
        output_root != expected_output_root
        or intended_runtime_root != str(destination)
        or type(files) is not list
        or not destination.is_relative_to(_STAGING_ROOT)
    ):
        candidate_builder._fail("candidate tree record is invalid")
    source_root = _candidate_path(candidate_root, expected_output_root)
    file_records = cast(list[object], files)
    staged: list[dict[str, object]] = []
    admitted_paths: set[str] = set()
    for file_value in file_records:
        file_record = cast(dict[str, object], file_value)
        if type(file_record) is not dict or type(file_record.get("path")) is not str:
            candidate_builder._fail("candidate tree file record is invalid")
        relative = cast(str, file_record["path"])
        relative_path = Path(relative)
        if (
            relative_path.is_absolute()
            or relative_path.as_posix() != relative
            or any(part in ("", ".", "..") for part in relative_path.parts)
            or relative in admitted_paths
        ):
            candidate_builder._fail("candidate tree file path is not exact")
        admitted_paths.add(relative)
        source = _candidate_path(source_root, relative)
        target = destination / relative
        if not target.is_relative_to(destination) or not target.is_relative_to(_STAGING_ROOT):
            candidate_builder._fail("candidate tree destination escaped exact staging")
        copied = _copy_regular(source, target, 0o444)
        if not target.resolve(strict=True).is_relative_to(destination.resolve(strict=True)):
            candidate_builder._fail("candidate tree destination resolved outside its role root")
        if copied["sha256"] != file_record.get("sha256") or copied["size"] != file_record.get(
            "size"
        ):
            candidate_builder._fail(f"transient candidate tree copy changed: {target}")
        staged.append(copied)
    observed = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    }
    if admitted_paths != expected_files or observed != expected_files:
        candidate_builder._fail(f"transient candidate tree contains extras: {destination}")
    return staged


def _seal_staging() -> None:
    for directory in sorted(
        (path for path in _STAGING_ROOT.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        directory.chmod(0o555)
    _STAGING_ROOT.chmod(0o555)


def _snapshot_staging() -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for path in sorted(_STAGING_ROOT.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(_STAGING_ROOT).as_posix()
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                candidate_builder._fail(f"transient candidate file is hard-linked: {path}")
            records[relative] = {
                "gid": metadata.st_gid,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "sha256": _sha256(path),
                "size": metadata.st_size,
                "type": "file",
                "uid": metadata.st_uid,
            }
        elif stat.S_ISDIR(metadata.st_mode):
            records[relative] = {
                "gid": metadata.st_gid,
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "type": "directory",
                "uid": metadata.st_uid,
            }
        else:
            candidate_builder._fail(f"transient candidate staging has a special file: {path}")
    if any(
        name.endswith((".pyc", ".pyo", ".pth", ".so", ".zip")) or "__pycache__" in name
        for name in records
    ):
        candidate_builder._fail("transient candidate staging contains a forbidden runtime file")
    return records


def _unseal_and_remove_staging() -> None:
    if not _STAGING_ROOT.exists():
        return
    for directory in sorted(
        (path for path in _STAGING_ROOT.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
    ):
        directory.chmod(0o700)
    _STAGING_ROOT.chmod(0o700)
    shutil.rmtree(_STAGING_ROOT)


def _execute(path: Path, expected_marker: str) -> dict[str, object]:
    completed = subprocess.run(
        (str(path),),
        cwd=Path("/"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/local/bin:/usr/bin:/bin"},
        check=False,
        timeout=30,
    )
    if len(completed.stdout) > 1024 * 1024:
        candidate_builder._fail(f"exact candidate output exceeded its bound: {path}")
    output = completed.stdout.decode("utf-8", errors="strict")
    if completed.returncode != 191 or output.count(expected_marker) != 1:
        candidate_builder._fail(
            f"exact candidate did not reach its fixed fail-closed marker: {path}: "
            f"status={completed.returncode}, output={output}"
        )
    return {
        "candidate_sha256": _sha256(path),
        "expected_status": 191,
        "marker": expected_marker,
        "marker_count": 1,
        "output": output,
        "output_sha256": _sha256_bytes(completed.stdout),
        "path": str(path),
        "status": 191,
    }


def exercise(candidate_directory: Path, output_directory: Path) -> dict[str, object]:
    candidate_directory = candidate_directory.resolve(strict=True)
    candidate_builder._validate_absent_output_directory(output_directory)
    receipt_path = candidate_directory / "candidate-build.json"
    receipt = _read_json(receipt_path)
    if (
        receipt.get("schema") != "autoquant-trusted-time-graceful-stop-v2-candidate-build-v1"
        or receipt.get("activation_authorized") is not False
        or receipt.get("status") != "candidate_unactivated"
        or receipt.get("role_import_trees_included") is not True
        or receipt.get("seccomp_manifests_included") is not True
    ):
        candidate_builder._fail("the exact-execution candidate receipt is not admitted")
    python = receipt.get("python")
    if type(python) is not dict or type(python.get("home")) is not str:
        candidate_builder._fail("the exact-execution Python record is invalid")
    python_record = cast(dict[str, object], python)
    boundary = _validate_container_boundary(cast(str, python_record["home"]))
    observed_python_before = candidate_builder._python_record(
        candidate_builder._python_build(candidate_builder._toolchain())
    )
    if observed_python_before != python_record:
        candidate_builder._fail("the mounted qualification Python differs from the build receipt")
    python_mount_sha256 = _canonical_sha256(observed_python_before)
    boundary["python_mount_provenance_sha256"] = python_mount_sha256
    if _STAGING_ROOT.exists():
        candidate_builder._fail("the transient exact-/opt staging root already exists")
    if _BASE_IMAGE_RECORD.read_text(encoding="ascii") != _BASE_IMAGE + "\n":
        candidate_builder._fail("the qualification image does not bind its pinned base")
    qualification_image_id = os.environ.get("AQT_WAVE7_QUALIFICATION_IMAGE_ID", "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", qualification_image_id) is None:
        candidate_builder._fail("the post-apt qualification image ID is not bound")
    systemd_creds = receipt.get("systemd_creds")
    if type(systemd_creds) is not dict or systemd_creds.get("path") != "/usr/bin/systemd-creds":
        candidate_builder._fail("the candidate systemd-creds record is invalid")
    systemd_record = cast(dict[str, object], systemd_creds)
    systemd_path = Path("/usr/bin/systemd-creds")
    if _sha256(systemd_path) != systemd_record.get("sha256"):
        candidate_builder._fail(
            "in-container systemd-creds differs from the compiled provisioner pin"
        )
    artifacts = receipt.get("artifacts")
    import_trees = receipt.get("role_import_trees")
    recovery_runtime = receipt.get("recovery_python_runtime")
    if (
        type(artifacts) is not list
        or type(import_trees) is not dict
        or type(recovery_runtime) is not dict
    ):
        candidate_builder._fail("the exact candidate topology record is invalid")
    artifact_values = cast(list[object], artifacts)
    import_tree_records = cast(dict[str, object], import_trees)
    recovery_runtime_record = cast(dict[str, object], recovery_runtime)
    artifact_records: dict[tuple[str, str], dict[str, object]] = {}
    for artifact_value in artifact_values:
        if type(artifact_value) is not dict:
            candidate_builder._fail("an exact candidate artifact record is invalid")
        artifact = cast(dict[str, object], artifact_value)
        key = (str(artifact.get("role")), str(artifact.get("kind")))
        if key in artifact_records:
            candidate_builder._fail("the exact candidate receipt repeats an artifact")
        artifact_records[key] = artifact
    if set(artifact_records) != {
        (role, kind)
        for role in ("host", "recovery", "supervisor")
        for kind in ("provisioner", "role")
    }:
        candidate_builder._fail("the exact candidate receipt is not the six-role topology")
    expected_basenames = {
        (role, "provisioner"): _PROVISIONER_DESTINATIONS[role].name
        for role in _PROVISIONER_DESTINATIONS
    } | {(role, "role"): _ROLE_DESTINATIONS[role].name for role in _ROLE_DESTINATIONS}
    if any(
        artifact_records[key].get("basename") != basename
        or re.fullmatch(r"[0-9a-f]{64}", str(artifact_records[key].get("sha256"))) is None
        for key, basename in expected_basenames.items()
    ):
        candidate_builder._fail("the exact candidate artifact names or digests are invalid")

    output_directory.mkdir(mode=0o700)
    staged_artifacts: dict[tuple[str, str], Path] = {}
    execution_records: list[dict[str, object]] = []
    before: dict[str, dict[str, object]] = {}
    after: dict[str, dict[str, object]] = {}
    try:
        _STAGING_ROOT.mkdir(mode=0o700)
        for role in ("host", "recovery", "supervisor"):
            role_record = artifact_records[(role, "role")]
            provisioner_record = artifact_records[(role, "provisioner")]
            role_source = _candidate_path(candidate_directory, _ROLE_DESTINATIONS[role].name)
            role_destination = _ROLE_DESTINATIONS[role]
            copied_role = _copy_regular(role_source, role_destination, 0o555)
            if copied_role["sha256"] != role_record.get("sha256"):
                candidate_builder._fail(f"the exact {role} candidate copy changed")
            staged_artifacts[(role, "role")] = role_destination
            provisioner_source = _candidate_path(
                candidate_directory,
                _PROVISIONER_DESTINATIONS[role].name,
            )
            provisioner_destination = _PROVISIONER_DESTINATIONS[role]
            copied_provisioner = _copy_regular(
                provisioner_source,
                provisioner_destination,
                0o555,
            )
            if copied_provisioner["sha256"] != provisioner_record.get("sha256"):
                candidate_builder._fail(f"the exact {role} provisioner copy changed")
            staged_artifacts[(role, "provisioner")] = provisioner_destination
            import_record = import_tree_records.get(role)
            if type(import_record) is not dict:
                candidate_builder._fail(f"the exact {role} import-tree record is invalid")
            admitted_import_record = cast(dict[str, object], import_record)
            import_destination = _ROLE_IMPORT_DESTINATIONS[role]
            _stage_tree(
                candidate_directory,
                admitted_import_record,
                import_destination,
                expected_files=frozenset({f"autoquant_trusted_time_v2_{role}_entry.py"}),
                expected_output_root=f"candidate-import-trees/{role}",
            )
        _stage_tree(
            candidate_directory,
            recovery_runtime_record,
            _RECOVERY_RUNTIME_DESTINATION,
            expected_files=_RECOVERY_RUNTIME_FILES,
            expected_output_root="candidate-python-runtimes/recovery",
        )
        _seal_staging()
        before = _snapshot_staging()
        for role in ("host", "recovery", "supervisor"):
            role_execution = _execute(
                staged_artifacts[(role, "role")],
                f"AQT_WAVE7_INERT_{role.upper()}_ENTRY_REACHED",
            )
            role_execution["candidate_artifact_sha256"] = artifact_records[(role, "role")]["sha256"]
            execution_records.append(
                {
                    "kind": "role",
                    "role": role,
                    **role_execution,
                }
            )
        for role in ("host", "recovery", "supervisor"):
            provisioner_execution = _execute(
                staged_artifacts[(role, "provisioner")],
                f"trusted-time lifecycle-v2 {role} provisioner: "
                "credential provisioning failed closed",
            )
            provisioner_execution["candidate_artifact_sha256"] = artifact_records[
                (role, "provisioner")
            ]["sha256"]
            execution_records.append(
                {
                    "kind": "provisioner",
                    "role": role,
                    **provisioner_execution,
                }
            )
        after = _snapshot_staging()
        if after != before:
            candidate_builder._fail("exact candidate execution mutated immutable staging")
    finally:
        _unseal_and_remove_staging()
    if _STAGING_ROOT.exists():
        candidate_builder._fail("transient exact-/opt staging survived cleanup")
    observed_python_after = candidate_builder._python_record(
        candidate_builder._python_build(candidate_builder._toolchain())
    )
    if observed_python_after != observed_python_before:
        candidate_builder._fail("exact execution mutated the read-only qualification Python mount")
    release_root = receipt.get("production_release_root")
    if type(release_root) is not dict or release_root.get("provisioner_authority_results") != {
        "host": "ENOKEY",
        "recovery": "ENOKEY",
        "supervisor": "ENOKEY",
    }:
        candidate_builder._fail("the exact provisioners are not bound to the ENOKEY consumer probe")
    expected_execution_paths = {
        (role, "provisioner"): str(_PROVISIONER_DESTINATIONS[role])
        for role in _PROVISIONER_DESTINATIONS
    } | {(role, "role"): str(_ROLE_DESTINATIONS[role]) for role in _ROLE_DESTINATIONS}
    if any(
        record.get("path") != expected_execution_paths[(str(record["role"]), str(record["kind"]))]
        or record.get("status") != 191
        or record.get("expected_status") != 191
        or record.get("marker_count") != 1
        or record.get("candidate_sha256") != record.get("candidate_artifact_sha256")
        for record in execution_records
    ):
        candidate_builder._fail("the exact candidate execution evidence is inconsistent")
    result: dict[str, object] = {
        "activation_authorized": False,
        "base_image": _BASE_IMAGE,
        "candidate_artifacts_copied_back": False,
        "candidate_build_receipt": {
            "path": str(receipt_path),
            "sha256": _sha256(receipt_path),
        },
        "candidate_staging_persisted": False,
        "container_boundary": boundary,
        "container_packages": _dpkg_records(),
        "dpkg_status_sha256": _sha256(Path("/var/lib/dpkg/status")),
        "enokey_consumer_probe_bound": True,
        "executions": execution_records,
        "exact_execution_count": len(execution_records),
        "input_snapshot_sha256": _sha256_bytes(
            json.dumps(before, sort_keys=True, separators=(",", ":")).encode("ascii")
        ),
        "qualification_image_id": qualification_image_id,
        "output_snapshot_sha256": _sha256_bytes(
            json.dumps(after, sort_keys=True, separators=(",", ":")).encode("ascii")
        ),
        "python_mount_provenance": {
            "candidate_python_record_sha256": _canonical_sha256(python_record),
            "post_execution_sha256": _canonical_sha256(observed_python_after),
            "pre_execution_sha256": python_mount_sha256,
            "unchanged": True,
        },
        "schema": "autoquant-trusted-time-graceful-stop-v2-exact-execution-v1",
        "script_sha256": _sha256(Path(__file__).resolve(strict=True)),
        "status": "six_exact_candidates_failed_closed_as_expected",
        "systemd_creds": {
            "path": str(systemd_path),
            "sha256": _sha256(systemd_path),
            "matches_compiled_pin": True,
        },
        "transient_container_opt_staging_removed": True,
        "transient_exact_path_staging_performed": True,
        "runtime_owner_installed": False,
    }
    output = output_directory / _RECEIPT_NAME
    output.write_text(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    output.chmod(0o444)
    return result


def main(argument_values: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("candidate_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    arguments = parser.parse_args(argument_values)
    result = exercise(arguments.candidate_directory, arguments.output_directory)
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
