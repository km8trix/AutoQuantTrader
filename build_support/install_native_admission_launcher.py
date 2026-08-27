"""Validate the reviewed native trusted-time admission launcher candidate.

The Python implementation is retained only as a nonroot pytest prototype for the
future native installer transaction.  Its production CLI is deliberately
unavailable.  The prototype never activates trusted time, and a candidate receipt
is not installation or activation evidence.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Never

_PREFIX = "/opt/autoquant/trusted-time-admission"
_LAUNCHER_RELATIVE_PATH = "bin/autoquant-trusted-time-python-admission"
_LAUNCHER_PATH = f"{_PREFIX}/{_LAUNCHER_RELATIVE_PATH}"
_SOURCE_RELATIVE_PATH = "share/autoquant-trader/source"
_SOURCE_ROOT = f"{_PREFIX}/{_SOURCE_RELATIVE_PATH}"
_NATIVE_RELATIVE_PATH = "share/autoquant-trader/native"
_BUILD_MANIFEST_BASENAME = "native_admission_launcher_build.json"
_SOURCE_MANIFEST_BASENAME = "native_admission_source_manifest.jsonl"
_RUNTIME_MANIFEST_BASENAME = "native_admission_runtime_manifest.jsonl"
_INSTALL_RECEIPT_BASENAME = "native_admission_launcher_install_receipt.json"
_BUILD_MANIFEST_RELATIVE_PATH = f"{_NATIVE_RELATIVE_PATH}/{_BUILD_MANIFEST_BASENAME}"
_SOURCE_MANIFEST_RELATIVE_PATH = f"{_NATIVE_RELATIVE_PATH}/{_SOURCE_MANIFEST_BASENAME}"
_RUNTIME_MANIFEST_RELATIVE_PATH = f"{_NATIVE_RELATIVE_PATH}/{_RUNTIME_MANIFEST_BASENAME}"
_INSTALL_RECEIPT_RELATIVE_PATH = f"{_NATIVE_RELATIVE_PATH}/{_INSTALL_RECEIPT_BASENAME}"
_BUILD_MANIFEST_PATH = f"{_PREFIX}/{_BUILD_MANIFEST_RELATIVE_PATH}"
_SOURCE_MANIFEST_PATH = f"{_PREFIX}/{_SOURCE_MANIFEST_RELATIVE_PATH}"
_RUNTIME_MANIFEST_PATH = f"{_PREFIX}/{_RUNTIME_MANIFEST_RELATIVE_PATH}"
_INSTALL_RECEIPT_PATH = f"{_PREFIX}/{_INSTALL_RECEIPT_RELATIVE_PATH}"
_BUILD_MANIFEST_SCHEMA = "autoquant-native-admission-launcher-build-v1"
_SOURCE_MANIFEST_SCHEMA = "autoquant-native-admission-source-manifest-v1"
_RUNTIME_MANIFEST_SCHEMA = "autoquant-native-admission-runtime-manifest-v1"
_INSTALL_RECEIPT_SCHEMA = "autoquant-native-admission-launcher-install-receipt-v1"
_MAXIMUM_BUILD_MANIFEST_BYTES = 1024 * 1024
_MAXIMUM_MANIFEST_BYTES = 128 * 1024 * 1024
_MAXIMUM_RECEIPT_BYTES = 64 * 1024
_MAXIMUM_ENTRIES = 250_000
_MAXIMUM_FILE_BYTES = 2 * 1024 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")
_EXPECTED_SOURCES = {
    "native/owned_file_descriptor.c": (
        "b41b39f0bd814315d879ea598e4cbd04758a7001faad96809df6eba2043e4427"
    ),
    "native/bounded_process.c": (
        "be08d5c95a2a5ce6aa9b06a4434c09473ee74ad941a417b8022885a7ef1f5cbd"
    ),
    "native/trusted_time_python_launcher.c": (
        "8f21c008571b4ed04166ae120cea9be2da73955c891a7c026833779dca3381f8"
    ),
    "packages/adapters/trusted_time/_owned_file_descriptor.py": (
        "1c6f540c9922b1a4bfc1c218d216c8045d18e7688014046fcf424f874961d2e2"
    ),
    "packages/adapters/trusted_time/_bounded_process.py": (
        "0bdf6cda1f0ab75d08df768d0d75bb40f2c8ef0cb490d09a18d843fb96a2a006"
    ),
}
_TARGET_IDS = (
    "verify-compose",
    "verify-images-build",
    "verify-images-readmit",
    "start",
    "admit-unenrolled",
    "enroll-first",
    "recover-first-enrollment",
    "post-enrollment-start",
    "operator-authority-prepare",
    "operator-authority-install",
    "graceful-stop-authority-prepare",
    "graceful-stop-authority-install",
    "operator-attestation-prepare",
    "operator-attestation-verify",
    "graceful-stop-decision-prepare",
    "graceful-stop-attestation-prepare",
    "graceful-stop-attestation-verify",
    "runtime-diagnostic",
    "inspect",
)
_EXTERNAL_BOUNDARIES = (
    "git_executable_and_helper_bytes_admitted",
    "docker_executable_and_helper_bytes_admitted",
    "cgroup_descendant_containment",
    "setsid_escape_containment",
    "loader_environment_pre_entry_admitted",
    "same_uid_injection_denied",
    "effective_mount_boundary_admitted",
)


class NativeAdmissionLauncherInstallError(RuntimeError):
    """The fixed native admission launcher installation is not admitted."""


@dataclass(frozen=True, slots=True)
class _TreeRecord:
    path: str
    type: str
    mode: int
    uid: int
    gid: int
    nlink: int | None = None
    size: int | None = None
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class _LoadedCandidate:
    records: Mapping[str, _TreeRecord]
    candidate_uid: int
    candidate_gid: int
    receipt: bytes
    receipt_sha256: str
    build_manifest: bytes
    source_manifest: bytes
    runtime_manifest: bytes
    external_runtime: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _DestinationPolicy:
    root_path: str
    parent_components: tuple[str, ...]
    basename: str
    production: bool
    mapped_root_uid: int
    mapped_root_gid: int


def _fail(message: str) -> Never:
    raise NativeAdmissionLauncherInstallError(message)


def _canonical_json(document: object) -> bytes:
    try:
        return (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("native admission installer metadata is not canonical JSON")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(character in _HEX for character in value)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _fd_has_extended_metadata(descriptor: int) -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    system_name = os.uname().sysname
    operation = getattr(libc, "flistxattr", None)
    if operation is None:
        _fail("native admission installer cannot inspect extended metadata")
    if system_name == "Darwin":
        operation.argtypes = (
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        )
        operation.restype = ctypes.c_ssize_t
        result = int(operation(descriptor, None, 0, 0))
    elif system_name == "Linux":
        operation.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
        operation.restype = ctypes.c_ssize_t
        result = int(operation(descriptor, None, 0))
    else:
        _fail("native admission installer platform is unsupported")
    if result < 0:
        _fail("native admission installer could not inspect extended metadata")
    return result != 0


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _validate_component(component: str) -> str:
    try:
        encoded = component.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail("native admission path component is not strict UTF-8")
    if (
        not encoded
        or component in (".", "..")
        or "/" in component
        or b"\0" in encoded
        or b"\n" in encoded
        or b"\r" in encoded
    ):
        _fail("native admission path component is invalid")
    return component


def _split_relative_path(path: str) -> tuple[str, ...]:
    if type(path) is not str or not path or path.startswith("/"):
        _fail("native admission manifest path is invalid")
    components = tuple(_validate_component(component) for component in path.split("/"))
    if "/".join(components) != path:
        _fail("native admission manifest path is not canonical")
    return components


def _open_directory_at(parent_descriptor: int, name: str) -> int:
    try:
        descriptor = os.open(
            _validate_component(name),
            _directory_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError:
        _fail("native admission directory could not be opened without following links")
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        _fail("native admission path component is not a directory")
    return descriptor


def _open_parent_at(root_descriptor: int, components: Sequence[str]) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for component in components:
            child = _open_directory_at(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_file_at(root_descriptor: int, relative_path: str) -> int:
    components = _split_relative_path(relative_path)
    parent = _open_parent_at(root_descriptor, components[:-1])
    try:
        try:
            descriptor = os.open(components[-1], _file_flags(), dir_fd=parent)
        except OSError:
            _fail("native admission regular file could not be opened without following links")
        try:
            metadata = os.fstat(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            _fail("native admission candidate entry is not a regular file")
        return descriptor
    finally:
        os.close(parent)


def _read_file_at(root_descriptor: int, relative_path: str, maximum: int) -> bytes:
    descriptor = _open_file_at(root_descriptor, relative_path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _fd_has_extended_metadata(descriptor)
        ):
            _fail("native admission metadata file has invalid metadata")
        chunks: list[bytes] = []
        received = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - received))
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            if received > maximum:
                _fail("native admission metadata file exceeded its byte bound")
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after) or received != before.st_size:
            _fail("native admission metadata file changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_canonical_document(payload: bytes, label: str) -> dict[str, object]:
    if not payload or not payload.endswith(b"\n"):
        _fail(f"{label} is not canonical")
    try:
        decoded = payload.decode("ascii", errors="strict")
        value = json.loads(decoded)
    except (UnicodeError, json.JSONDecodeError):
        _fail(f"{label} is malformed")
    if type(value) is not dict or _canonical_json(value) != payload:
        _fail(f"{label} is not canonical")
    return value


def _exact_object(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != fields:
        _fail(f"{label} shape is invalid")
    return value


def _exact_text(value: object, label: str) -> str:
    if type(value) is not str or not value or "\0" in value or "\n" in value or "\r" in value:
        _fail(f"{label} is invalid")
    return value


def _exact_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{label} is invalid")
    return value


def _exact_digest(value: object, label: str) -> str:
    if not _is_digest(value):
        _fail(f"{label} is invalid")
    return str(value)


def _artifact_record(value: object, label: str) -> dict[str, object]:
    artifact = _exact_object(
        value,
        frozenset(("gid", "mode", "path", "sha256", "size", "uid")),
        label,
    )
    _exact_integer(artifact["gid"], f"{label}.gid")
    _exact_integer(artifact["mode"], f"{label}.mode")
    _exact_text(artifact["path"], f"{label}.path")
    _exact_digest(artifact["sha256"], f"{label}.sha256")
    _exact_integer(artifact["size"], f"{label}.size")
    _exact_integer(artifact["uid"], f"{label}.uid")
    return artifact


def _parse_manifest(
    payload: bytes,
    *,
    schema: str,
    root: str,
    label: str,
) -> tuple[_TreeRecord, ...]:
    if not payload or len(payload) > _MAXIMUM_MANIFEST_BYTES or not payload.endswith(b"\n"):
        _fail(f"{label} is invalid")
    lines = payload.splitlines(keepends=True)
    header = _decode_canonical_document(lines[0], f"{label} header")
    if header != {"entry_count": len(lines) - 1, "root": root, "schema": schema}:
        _fail(f"{label} header is invalid")
    if len(lines) - 1 > _MAXIMUM_ENTRIES:
        _fail(f"{label} entry count exceeded its bound")
    records: list[_TreeRecord] = []
    prior_path_bytes: bytes | None = None
    for index, line in enumerate(lines[1:], start=1):
        document = _decode_canonical_document(line, f"{label} record {index}")
        type_value = document.get("type")
        if type_value == "directory":
            exact = _exact_object(
                document,
                frozenset(("gid", "mode", "path", "type", "uid")),
                f"{label} directory record",
            )
            nlink: int | None = None
            size: int | None = None
            digest: str | None = None
        elif type_value == "file":
            exact = _exact_object(
                document,
                frozenset(("gid", "mode", "nlink", "path", "sha256", "size", "type", "uid")),
                f"{label} file record",
            )
            nlink = _exact_integer(exact["nlink"], f"{label}.nlink")
            size = _exact_integer(exact["size"], f"{label}.size")
            digest = _exact_digest(exact["sha256"], f"{label}.sha256")
            if nlink != 1 or size > _MAXIMUM_FILE_BYTES:
                _fail(f"{label} file record is invalid")
        else:
            _fail(f"{label} entry type is invalid")
        path = _exact_text(exact["path"], f"{label}.path")
        _split_relative_path(path)
        path_bytes = path.encode("utf-8", errors="strict")
        if prior_path_bytes is not None and path_bytes <= prior_path_bytes:
            _fail(f"{label} paths are not strictly ordered")
        prior_path_bytes = path_bytes
        mode = _exact_integer(exact["mode"], f"{label}.mode")
        uid = _exact_integer(exact["uid"], f"{label}.uid")
        gid = _exact_integer(exact["gid"], f"{label}.gid")
        if type_value == "directory" and mode not in (0o555, 0o700):
            _fail(f"{label} directory mode is invalid")
        if type_value == "file" and mode not in (0o444, 0o555, 0o600):
            _fail(f"{label} file mode is invalid")
        records.append(_TreeRecord(path, str(type_value), mode, uid, gid, nlink, size, digest))
    return tuple(records)


def _validate_receipt(receipt: dict[str, object]) -> dict[str, dict[str, object]]:
    exact = _exact_object(
        receipt,
        frozenset(
            (
                "activation_authorized",
                "artifacts",
                "external_boundaries",
                "profile",
                "schema",
                "source_root",
                "status",
                "target_ids",
                "trusted_time_prefix",
            )
        ),
        "native admission install receipt",
    )
    if (
        exact["activation_authorized"] is not False
        or exact["profile"] != "admission"
        or exact["schema"] != _INSTALL_RECEIPT_SCHEMA
        or exact["source_root"] != _SOURCE_ROOT
        or exact["status"] != "candidate_unactivated"
        or exact["target_ids"] != list(_TARGET_IDS)
        or exact["trusted_time_prefix"] != _PREFIX
    ):
        _fail("native admission install receipt policy is invalid")
    external = _exact_object(
        exact["external_boundaries"],
        frozenset(_EXTERNAL_BOUNDARIES),
        "native admission external-boundary receipt",
    )
    if any(external[name] is not False for name in _EXTERNAL_BOUNDARIES):
        _fail("native admission install receipt overclaims an external boundary")
    artifacts_raw = _exact_object(
        exact["artifacts"],
        frozenset(("build_manifest", "launcher", "runtime_manifest", "source_manifest")),
        "native admission receipt artifacts",
    )
    artifacts = {
        name: _artifact_record(artifacts_raw[name], f"native admission receipt {name}")
        for name in sorted(artifacts_raw)
    }
    expected = {
        "build_manifest": (_BUILD_MANIFEST_PATH, 0o444),
        "launcher": (_LAUNCHER_PATH, 0o555),
        "runtime_manifest": (_RUNTIME_MANIFEST_PATH, 0o444),
        "source_manifest": (_SOURCE_MANIFEST_PATH, 0o444),
    }
    for name, (path, mode) in expected.items():
        artifact = artifacts[name]
        if (
            artifact["path"] != path
            or artifact["mode"] != mode
            or artifact["uid"] != 0
            or artifact["gid"] != 0
        ):
            _fail("native admission install receipt artifact policy is invalid")
    return artifacts


def _validate_build_manifest(
    build: dict[str, object],
    *,
    source_manifest: bytes,
    runtime_manifest: bytes,
) -> tuple[int, int, dict[str, object]]:
    exact = _exact_object(
        build,
        frozenset(
            (
                "build_commands",
                "builder_identity",
                "compiler",
                "dynamic",
                "git_revision",
                "launcher",
                "platform",
                "platform_attestation",
                "python_runtime",
                "reproducible_build_count",
                "runtime_manifest",
                "schema",
                "source_manifest",
                "sources",
                "trusted_time_prefix",
            )
        ),
        "native admission build manifest",
    )
    if (
        exact["schema"] != _BUILD_MANIFEST_SCHEMA
        or exact["trusted_time_prefix"] != _PREFIX
        or exact["reproducible_build_count"] != 2
        or exact["sources"] != _EXPECTED_SOURCES
        or exact["platform"] not in ("darwin", "linux")
    ):
        _fail("native admission build manifest policy is invalid")
    revision = _exact_text(exact["git_revision"], "native admission Git revision")
    if len(revision) != 40 or any(character not in _HEX for character in revision):
        _fail("native admission Git revision is invalid")
    identity = _exact_object(
        exact["builder_identity"],
        frozenset(("candidate_gid", "candidate_uid", "git", "git_sha256")),
        "native admission builder identity",
    )
    candidate_uid = _exact_integer(identity["candidate_uid"], "candidate uid")
    candidate_gid = _exact_integer(identity["candidate_gid"], "candidate gid")
    if candidate_uid == 0 or not str(identity["git"]).startswith("/"):
        _fail("native admission candidate was not built without privilege")
    _exact_digest(identity["git_sha256"], "native admission Git digest")
    launcher = _exact_object(
        exact["launcher"],
        frozenset(("basename", "path", "profile", "sha256", "size", "target_ids")),
        "native admission launcher build record",
    )
    if (
        launcher["basename"] != _LAUNCHER_RELATIVE_PATH.rsplit("/", maxsplit=1)[1]
        or launcher["path"] != _LAUNCHER_PATH
        or launcher["profile"] != "admission"
        or launcher["target_ids"] != list(_TARGET_IDS)
    ):
        _fail("native admission launcher build record is invalid")
    _exact_digest(launcher["sha256"], "native admission launcher digest")
    _exact_integer(launcher["size"], "native admission launcher size")
    for field, expected_path, expected_schema, payload in (
        ("source_manifest", _SOURCE_MANIFEST_PATH, _SOURCE_MANIFEST_SCHEMA, source_manifest),
        ("runtime_manifest", _RUNTIME_MANIFEST_PATH, _RUNTIME_MANIFEST_SCHEMA, runtime_manifest),
    ):
        manifest = _exact_object(
            exact[field],
            frozenset(("path", "schema", "sha256", "size")),
            f"native admission {field} build record",
        )
        if (
            manifest["path"] != expected_path
            or manifest["schema"] != expected_schema
            or manifest["sha256"] != _sha256(payload)
            or manifest["size"] != len(payload)
        ):
            _fail(f"native admission {field} build binding is invalid")
    compiler = _exact_object(
        exact["compiler"],
        frozenset(("path", "sha256", "version_sha256")),
        "native admission compiler identity",
    )
    if not _exact_text(compiler["path"], "compiler path").startswith("/"):
        _fail("native admission compiler path is invalid")
    _exact_digest(compiler["sha256"], "compiler digest")
    _exact_digest(compiler["version_sha256"], "compiler version digest")
    commands = exact["build_commands"]
    if (
        type(commands) is not list
        or len(commands) != 4
        or any(type(command) is not list or not command for command in commands)
        or any(
            type(argument) is not str or not argument
            for command in commands
            for argument in command
        )
    ):
        _fail("native admission normalized build commands are invalid")
    runtime = _exact_object(
        exact["python_runtime"],
        frozenset(
            (
                "dynload",
                "executable",
                "extension_suffix",
                "header",
                "home",
                "implementation",
                "library",
                "stdlib",
                "version",
            )
        ),
        "native admission Python runtime",
    )
    if runtime["implementation"] != "cpython":
        _fail("native admission Python runtime implementation is invalid")
    for field in ("home", "stdlib", "dynload"):
        if not _exact_text(runtime[field], f"Python runtime {field}").startswith("/"):
            _fail("native admission Python runtime path is invalid")
    suffix = _exact_text(runtime["extension_suffix"], "Python extension suffix")
    if not suffix.startswith(".cpython-") or not suffix.endswith(".so"):
        _fail("native admission Python extension suffix is invalid")
    _exact_text(runtime["version"], "Python version")
    for field in ("executable", "header", "library"):
        _validate_external_file_record(runtime[field], f"Python {field}")
    return candidate_uid, candidate_gid, runtime


def _validate_external_file_record(value: object, label: str) -> dict[str, object]:
    record = _exact_object(
        value,
        frozenset(("gid", "mode", "nlink", "path", "sha256", "size", "uid")),
        label,
    )
    if not _exact_text(record["path"], f"{label}.path").startswith("/"):
        _fail(f"{label} path is invalid")
    _exact_digest(record["sha256"], f"{label}.sha256")
    for field in ("gid", "mode", "nlink", "size", "uid"):
        _exact_integer(record[field], f"{label}.{field}")
    if record["nlink"] != 1:
        _fail(f"{label} link count is invalid")
    return record


def _metadata_file_record(relative_path: str, payload: bytes) -> _TreeRecord:
    return _TreeRecord(relative_path, "file", 0o444, 0, 0, 1, len(payload), _sha256(payload))


def _expected_tree_records(
    source_records: Sequence[_TreeRecord],
    runtime_records: Sequence[_TreeRecord],
    *,
    build_manifest: bytes,
    source_manifest: bytes,
    runtime_manifest: bytes,
    receipt: bytes,
) -> dict[str, _TreeRecord]:
    records: dict[str, _TreeRecord] = {}
    operator_owners: set[tuple[int, int]] = set()

    def add(record: _TreeRecord) -> None:
        if record.path in records:
            _fail("native admission manifests overlap")
        records[record.path] = record

    for record in runtime_records:
        if not (record.path in ("bin", "lib") or record.path.startswith(("bin/", "lib/"))):
            _fail("native admission runtime manifest escaped its closed scope")
        if record.uid != 0 or record.gid != 0:
            _fail("native admission runtime manifest ownership is invalid")
        add(record)
    for record in source_records:
        physical_path = f"{_SOURCE_RELATIVE_PATH}/{record.path}"
        in_artifacts = record.path == "artifacts" or record.path.startswith("artifacts/")
        if not in_artifacts and (record.uid != 0 or record.gid != 0):
            _fail("native admission immutable source ownership is invalid")
        if in_artifacts:
            expected_mode = 0o700 if record.type == "directory" else 0o600
            if record.mode != expected_mode or record.uid == 0:
                _fail("native admission operator artifact metadata is invalid")
            operator_owners.add((record.uid, record.gid))
        add(
            _TreeRecord(
                physical_path,
                record.type,
                record.mode,
                record.uid,
                record.gid,
                record.nlink,
                record.size,
                record.sha256,
            )
        )
    for directory in (
        "share",
        "share/autoquant-trader",
        _NATIVE_RELATIVE_PATH,
        _SOURCE_RELATIVE_PATH,
    ):
        add(_TreeRecord(directory, "directory", 0o555, 0, 0))
    for record in (
        _metadata_file_record(_BUILD_MANIFEST_RELATIVE_PATH, build_manifest),
        _metadata_file_record(_SOURCE_MANIFEST_RELATIVE_PATH, source_manifest),
        _metadata_file_record(_RUNTIME_MANIFEST_RELATIVE_PATH, runtime_manifest),
        _metadata_file_record(_INSTALL_RECEIPT_RELATIVE_PATH, receipt),
    ):
        add(record)
    if len(operator_owners) != 1:
        _fail("native admission operator artifact ownership is not one exact identity")
    return records


def _load_candidate(root_descriptor: int, expected_receipt_sha256: str) -> _LoadedCandidate:
    receipt = _read_file_at(
        root_descriptor,
        _INSTALL_RECEIPT_RELATIVE_PATH,
        _MAXIMUM_RECEIPT_BYTES,
    )
    receipt_sha256 = _sha256(receipt)
    if receipt_sha256 != expected_receipt_sha256:
        _fail("native admission install receipt is not the approved artifact")
    receipt_document = _decode_canonical_document(receipt, "native admission install receipt")
    artifacts = _validate_receipt(receipt_document)
    build_manifest = _read_file_at(
        root_descriptor,
        _BUILD_MANIFEST_RELATIVE_PATH,
        _MAXIMUM_BUILD_MANIFEST_BYTES,
    )
    source_manifest = _read_file_at(
        root_descriptor,
        _SOURCE_MANIFEST_RELATIVE_PATH,
        _MAXIMUM_MANIFEST_BYTES,
    )
    runtime_manifest = _read_file_at(
        root_descriptor,
        _RUNTIME_MANIFEST_RELATIVE_PATH,
        _MAXIMUM_MANIFEST_BYTES,
    )
    artifact_payloads = {
        "build_manifest": build_manifest,
        "runtime_manifest": runtime_manifest,
        "source_manifest": source_manifest,
    }
    for name, payload in artifact_payloads.items():
        if artifacts[name]["sha256"] != _sha256(payload) or artifacts[name]["size"] != len(payload):
            _fail("native admission receipt artifact binding is invalid")
    build_document = _decode_canonical_document(build_manifest, "native admission build manifest")
    candidate_uid, candidate_gid, external_runtime = _validate_build_manifest(
        build_document,
        source_manifest=source_manifest,
        runtime_manifest=runtime_manifest,
    )
    source_records = _parse_manifest(
        source_manifest,
        schema=_SOURCE_MANIFEST_SCHEMA,
        root=_SOURCE_ROOT,
        label="native admission source manifest",
    )
    runtime_records = _parse_manifest(
        runtime_manifest,
        schema=_RUNTIME_MANIFEST_SCHEMA,
        root=_PREFIX,
        label="native admission runtime manifest",
    )
    records = _expected_tree_records(
        source_records,
        runtime_records,
        build_manifest=build_manifest,
        source_manifest=source_manifest,
        runtime_manifest=runtime_manifest,
        receipt=receipt,
    )
    launcher_record = records.get(_LAUNCHER_RELATIVE_PATH)
    launcher_artifact = artifacts["launcher"]
    if (
        launcher_record is None
        or launcher_record.type != "file"
        or launcher_record.sha256 != launcher_artifact["sha256"]
        or launcher_record.size != launcher_artifact["size"]
        or launcher_record.mode != launcher_artifact["mode"]
    ):
        _fail("native admission launcher manifest binding is invalid")
    build_launcher = _exact_object(
        build_document["launcher"],
        frozenset(("basename", "path", "profile", "sha256", "size", "target_ids")),
        "native admission launcher build record",
    )
    if (
        build_launcher["sha256"] != launcher_record.sha256
        or build_launcher["size"] != launcher_record.size
    ):
        _fail("native admission launcher build binding is invalid")
    return _LoadedCandidate(
        records,
        candidate_uid,
        candidate_gid,
        receipt,
        receipt_sha256,
        build_manifest,
        source_manifest,
        runtime_manifest,
        external_runtime,
    )


def _hash_descriptor(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    received = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, expected_size + 1 - received))
        if not chunk:
            break
        digest.update(chunk)
        received += len(chunk)
        if received > expected_size:
            _fail("native admission file grew while it was inspected")
    if received != expected_size:
        _fail("native admission file size changed while it was inspected")
    return digest.hexdigest()


def _physical_owner(
    record: _TreeRecord,
    *,
    loaded: _LoadedCandidate,
    installed: bool,
    policy: _DestinationPolicy,
) -> tuple[int, int]:
    if not installed:
        return loaded.candidate_uid, loaded.candidate_gid
    if record.uid == 0:
        return policy.mapped_root_uid, policy.mapped_root_gid
    return record.uid, record.gid


def _validate_tree(
    root_descriptor: int,
    loaded: _LoadedCandidate,
    *,
    installed: bool,
    policy: _DestinationPolicy,
) -> None:
    root_before = os.fstat(root_descriptor)
    expected_root_owner = (
        (policy.mapped_root_uid, policy.mapped_root_gid)
        if installed
        else (loaded.candidate_uid, loaded.candidate_gid)
    )
    if (
        not stat.S_ISDIR(root_before.st_mode)
        or stat.S_IMODE(root_before.st_mode) != 0o555
        or (root_before.st_uid, root_before.st_gid) != expected_root_owner
        or _fd_has_extended_metadata(root_descriptor)
    ):
        _fail("native admission root metadata is invalid")
    seen: set[str] = set()

    def walk(directory_descriptor: int, prefix: str) -> None:
        before = os.fstat(directory_descriptor)
        try:
            names = os.listdir(directory_descriptor)
        except OSError:
            _fail("native admission directory could not be enumerated")
        try:
            names.sort(key=lambda name: name.encode("utf-8", errors="strict"))
        except UnicodeError:
            _fail("native admission directory name is not strict UTF-8")
        for name in names:
            _validate_component(name)
            relative = name if not prefix else f"{prefix}/{name}"
            record = loaded.records.get(relative)
            if record is None or relative in seen:
                _fail("native admission tree contains an unexpected entry")
            seen.add(relative)
            try:
                metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            except OSError:
                _fail("native admission entry metadata is unavailable")
            owner = _physical_owner(record, loaded=loaded, installed=installed, policy=policy)
            if (
                stat.S_IMODE(metadata.st_mode) != record.mode
                or (metadata.st_uid, metadata.st_gid) != owner
            ):
                _fail("native admission entry metadata differs from its manifest")
            if record.type == "directory":
                child = _open_directory_at(directory_descriptor, name)
                try:
                    if _fd_has_extended_metadata(child):
                        _fail("native admission directory has forbidden extended metadata")
                    walk(child, relative)
                finally:
                    os.close(child)
            else:
                try:
                    descriptor = os.open(name, _file_flags(), dir_fd=directory_descriptor)
                except OSError:
                    _fail("native admission file could not be opened without following links")
                try:
                    opened_before = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened_before.st_mode)
                        or opened_before.st_nlink != record.nlink
                        or opened_before.st_size != record.size
                        or _identity(opened_before) != _identity(metadata)
                        or _fd_has_extended_metadata(descriptor)
                        or record.size is None
                        or record.sha256 is None
                        or _hash_descriptor(descriptor, record.size) != record.sha256
                        or _identity(opened_before) != _identity(os.fstat(descriptor))
                    ):
                        _fail("native admission file differs from its manifest")
                finally:
                    os.close(descriptor)
        if _identity(before) != _identity(os.fstat(directory_descriptor)):
            _fail("native admission directory changed while it was inspected")

    walk(root_descriptor, "")
    if seen != set(loaded.records):
        _fail("native admission tree is incomplete")
    if _identity(root_before) != _identity(os.fstat(root_descriptor)):
        _fail("native admission root changed while it was inspected")


def _validate_root_owned_chain(path: str, *, allow_test_owner: bool) -> None:
    canonical = os.path.realpath(path)
    if not path.startswith("/") or canonical != path:
        _fail("native admission external runtime path is not canonical")
    current = "/"
    for component in path.split("/")[1:]:
        if not component:
            continue
        current = os.path.join(current, component)
        try:
            metadata = os.lstat(current)
        except OSError:
            _fail("native admission external runtime path is unavailable")
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            _fail("native admission external runtime ancestor is mutable")
        if allow_test_owner:
            if metadata.st_uid not in (0, os.geteuid()):
                _fail("native admission test runtime ownership is invalid")
        elif metadata.st_uid != 0 or metadata.st_gid != 0:
            _fail("native admission external runtime ownership is invalid")


def _validate_external_runtime(runtime: Mapping[str, object], *, test_mode: bool) -> None:
    for field in ("home", "stdlib", "dynload"):
        path = _exact_text(runtime[field], f"external runtime {field}")
        _validate_root_owned_chain(path, allow_test_owner=test_mode)
        try:
            descriptor = os.open(path, _directory_flags())
        except OSError:
            _fail("native admission external runtime directory is unavailable")
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or (
                not test_mode and _fd_has_extended_metadata(descriptor)
            ):
                _fail("native admission external runtime directory metadata is invalid")
        finally:
            os.close(descriptor)
    for field in ("executable", "header", "library"):
        record = _validate_external_file_record(runtime[field], f"external runtime {field}")
        path = str(record["path"])
        _validate_root_owned_chain(path, allow_test_owner=test_mode)
        try:
            descriptor = os.open(path, _file_flags())
        except OSError:
            _fail("native admission external runtime file is unavailable")
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != record["nlink"]
                or stat.S_IMODE(metadata.st_mode) != record["mode"]
                or metadata.st_uid != record["uid"]
                or metadata.st_gid != record["gid"]
                or metadata.st_size != record["size"]
                or (not test_mode and _fd_has_extended_metadata(descriptor))
                or _hash_descriptor(descriptor, int(record["size"])) != record["sha256"]
            ):
                _fail("native admission external runtime file identity changed")
        finally:
            os.close(descriptor)


def _open_canonical_directory(path: str) -> int:
    if not path.startswith("/") or os.path.normpath(path) != path or os.path.realpath(path) != path:
        _fail("native admission candidate path must be canonical and absolute")
    try:
        descriptor = os.open(path, _directory_flags())
        lexical = os.lstat(path)
    except OSError:
        _fail("native admission candidate directory is unavailable")
    if _identity(os.fstat(descriptor)) != _identity(lexical):
        os.close(descriptor)
        _fail("native admission candidate path changed while it was opened")
    return descriptor


def _load_and_validate_candidate(
    candidate_directory: str,
    expected_receipt_sha256: str,
    *,
    policy: _DestinationPolicy,
) -> tuple[int, _LoadedCandidate]:
    descriptor = _open_canonical_directory(candidate_directory)
    try:
        loaded = _load_candidate(descriptor, expected_receipt_sha256)
        _validate_tree(descriptor, loaded, installed=False, policy=policy)
        _validate_external_runtime(loaded.external_runtime, test_mode=not policy.production)
        return descriptor, loaded
    except BaseException:
        os.close(descriptor)
        raise


def _validate_parent_directory(
    descriptor: int,
    *,
    uid: int,
    gid: int,
    allow_owner_only_mode: bool,
) -> None:
    metadata = os.fstat(descriptor)
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (allow_owner_only_mode and mode != 0o700)
        or _fd_has_extended_metadata(descriptor)
    ):
        _fail("native admission destination parent metadata is invalid")


def _open_destination_parent(policy: _DestinationPolicy, *, create: bool) -> int:
    try:
        descriptor = os.open(policy.root_path, _directory_flags())
    except OSError:
        _fail("native admission destination root is unavailable")
    try:
        if policy.production:
            _validate_parent_directory(
                descriptor,
                uid=policy.mapped_root_uid,
                gid=policy.mapped_root_gid,
                allow_owner_only_mode=False,
            )
        else:
            _validate_parent_directory(
                descriptor,
                uid=os.geteuid(),
                gid=policy.mapped_root_gid,
                allow_owner_only_mode=True,
            )
        for index, component in enumerate(policy.parent_components):
            try:
                child = _open_directory_at(descriptor, component)
            except NativeAdmissionLauncherInstallError:
                if (
                    not create
                    or not policy.production
                    or index != len(policy.parent_components) - 1
                ):
                    raise
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                    os.fsync(descriptor)
                except OSError:
                    _fail("native admission destination parent could not be created exclusively")
                child = _open_directory_at(descriptor, component)
            os.close(descriptor)
            descriptor = child
            _validate_parent_directory(
                descriptor,
                uid=policy.mapped_root_uid,
                gid=policy.mapped_root_gid,
                allow_owner_only_mode=False,
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _mkdir_relative(root_descriptor: int, relative_path: str) -> None:
    components = _split_relative_path(relative_path)
    parent = _open_parent_at(root_descriptor, components[:-1])
    try:
        try:
            os.mkdir(components[-1], 0o700, dir_fd=parent)
        except OSError:
            _fail("native admission stage directory could not be created exclusively")
        os.fsync(parent)
    finally:
        os.close(parent)


def _mapped_owner(record: _TreeRecord, policy: _DestinationPolicy) -> tuple[int, int]:
    if record.uid == 0:
        return policy.mapped_root_uid, policy.mapped_root_gid
    return record.uid, record.gid


def _copy_file_to_stage(
    candidate_descriptor: int,
    stage_descriptor: int,
    record: _TreeRecord,
    loaded: _LoadedCandidate,
    policy: _DestinationPolicy,
) -> None:
    source = _open_file_at(candidate_descriptor, record.path)
    components = _split_relative_path(record.path)
    parent = _open_parent_at(stage_descriptor, components[:-1])
    destination = -1
    try:
        before = os.fstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != loaded.candidate_uid
            or before.st_gid != loaded.candidate_gid
            or stat.S_IMODE(before.st_mode) != record.mode
            or before.st_nlink != 1
            or before.st_size != record.size
            or _fd_has_extended_metadata(source)
            or record.size is None
            or record.sha256 is None
        ):
            _fail("native admission candidate changed before stage copy")
        try:
            destination = os.open(
                components[-1],
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent,
            )
        except OSError:
            _fail("native admission stage file could not be created exclusively")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source, min(1024 * 1024, record.size + 1 - size))
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if size > record.size:
                _fail("native admission candidate grew during stage copy")
            offset = 0
            while offset < len(chunk):
                written = os.write(destination, chunk[offset:])
                if written <= 0:
                    _fail("native admission stage write did not progress")
                offset += written
        if (
            size != record.size
            or digest.hexdigest() != record.sha256
            or _identity(before) != _identity(os.fstat(source))
        ):
            _fail("native admission candidate changed during stage copy")
        uid, gid = _mapped_owner(record, policy)
        os.fchown(destination, uid, gid)
        os.fchmod(destination, record.mode)
        os.fsync(destination)
        os.fsync(parent)
    except OSError:
        _fail("native admission stage file could not be committed")
    finally:
        if destination >= 0:
            os.close(destination)
        os.close(parent)
        os.close(source)


def _finalize_stage_directories(
    stage_descriptor: int,
    records: Mapping[str, _TreeRecord],
    policy: _DestinationPolicy,
) -> None:
    directories = sorted(
        (record for record in records.values() if record.type == "directory"),
        key=lambda record: (-record.path.count("/"), record.path.encode("utf-8")),
    )
    for record in directories:
        descriptor = _open_parent_at(stage_descriptor, _split_relative_path(record.path))
        try:
            uid, gid = _mapped_owner(record, policy)
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, record.mode)
            os.fsync(descriptor)
        except OSError:
            _fail("native admission stage directory metadata could not be committed")
        finally:
            os.close(descriptor)
    try:
        os.fchown(stage_descriptor, policy.mapped_root_uid, policy.mapped_root_gid)
        os.fchmod(stage_descriptor, 0o555)
        os.fsync(stage_descriptor)
    except OSError:
        _fail("native admission stage root metadata could not be committed")


def _rename_noreplace_at(parent_descriptor: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    system_name = os.uname().sysname
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if system_name == "Linux":
        operation = getattr(libc, "renameat2", None)
        if operation is None:
            _fail("native admission installer lacks atomic no-replace rename")
        operation.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        operation.restype = ctypes.c_int
        result = int(
            operation(
                parent_descriptor,
                source_bytes,
                parent_descriptor,
                destination_bytes,
                1,
            )
        )
    elif system_name == "Darwin":
        operation = getattr(libc, "renameatx_np", None)
        if operation is None:
            _fail("native admission installer lacks atomic no-replace rename")
        operation.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        operation.restype = ctypes.c_int
        result = int(
            operation(
                parent_descriptor,
                source_bytes,
                parent_descriptor,
                destination_bytes,
                0x00000004,
            )
        )
    else:
        _fail("native admission installer platform is unsupported")
    if result != 0:
        operation_errno = ctypes.get_errno()
        if operation_errno in (errno.EEXIST, errno.ENOTEMPTY):
            _fail("native admission destination already exists; repair and overwrite are forbidden")
        _fail("native admission atomic no-replace publication failed")


def _remove_tree_at(parent_descriptor: int, name: str) -> None:
    directory = _open_directory_at(parent_descriptor, name)
    try:
        os.fchmod(directory, 0o700)
        names = os.listdir(directory)
        names.sort(key=lambda value: value.encode("utf-8", errors="strict"))
        for child_name in names:
            metadata = os.stat(child_name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                _remove_tree_at(directory, child_name)
            elif stat.S_ISREG(metadata.st_mode):
                os.unlink(child_name, dir_fd=directory)
            else:
                _fail("native admission private stage acquired a nonordinary entry")
        os.fsync(directory)
    finally:
        os.close(directory)
    os.rmdir(name, dir_fd=parent_descriptor)
    os.fsync(parent_descriptor)


def _destination_exists(parent_descriptor: int, basename: str) -> bool:
    try:
        os.stat(basename, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        _fail("native admission destination existence is ambiguous")
    return True


def _install_loaded_candidate(
    candidate_descriptor: int,
    loaded: _LoadedCandidate,
    *,
    policy: _DestinationPolicy,
) -> None:
    parent = _open_destination_parent(policy, create=True)
    stage_name = f".{policy.basename}.install-{os.getpid()}-{secrets.token_hex(16)}"
    stage_descriptor = -1
    stage_created = False
    published = False
    try:
        if _destination_exists(parent, policy.basename):
            _fail("native admission destination already exists; repair and overwrite are forbidden")
        try:
            os.mkdir(stage_name, 0o700, dir_fd=parent)
            stage_created = True
            os.fsync(parent)
        except OSError:
            _fail("native admission private sibling stage could not be created exclusively")
        stage_descriptor = _open_directory_at(parent, stage_name)
        directory_records = sorted(
            (record for record in loaded.records.values() if record.type == "directory"),
            key=lambda record: (record.path.count("/"), record.path.encode("utf-8")),
        )
        for record in directory_records:
            _mkdir_relative(stage_descriptor, record.path)
        file_records = sorted(
            (record for record in loaded.records.values() if record.type == "file"),
            key=lambda record: record.path.encode("utf-8"),
        )
        for record in file_records:
            _copy_file_to_stage(candidate_descriptor, stage_descriptor, record, loaded, policy)
        _finalize_stage_directories(stage_descriptor, loaded.records, policy)
        if _destination_exists(parent, policy.basename):
            _fail("native admission destination appeared before publication")
        _rename_noreplace_at(parent, stage_name, policy.basename)
        published = True
        try:
            os.fsync(parent)
        except OSError:
            _fail("native admission installation outcome is ambiguous after publication")
    except BaseException as primary:
        if not published and stage_created:
            try:
                if stage_descriptor >= 0:
                    os.close(stage_descriptor)
                    stage_descriptor = -1
                _remove_tree_at(parent, stage_name)
            except BaseException as cleanup:
                if isinstance(primary, (KeyboardInterrupt, SystemExit)):
                    raise primary from None
                if isinstance(cleanup, (KeyboardInterrupt, SystemExit)):
                    raise cleanup from None
                raise NativeAdmissionLauncherInstallError(
                    "native admission private-stage cleanup was not confirmed"
                ) from primary
        raise
    finally:
        if stage_descriptor >= 0:
            os.close(stage_descriptor)
        os.close(parent)


def _open_installed(policy: _DestinationPolicy) -> int:
    parent = _open_destination_parent(policy, create=False)
    try:
        return _open_directory_at(parent, policy.basename)
    finally:
        os.close(parent)


def _verify_installed(
    expected_receipt_sha256: str,
    *,
    policy: _DestinationPolicy,
) -> _LoadedCandidate:
    descriptor = _open_installed(policy)
    try:
        loaded = _load_candidate(descriptor, expected_receipt_sha256)
        _validate_tree(descriptor, loaded, installed=True, policy=policy)
        _validate_external_runtime(loaded.external_runtime, test_mode=not policy.production)
        return loaded
    finally:
        os.close(descriptor)


def _require_expected_digest(value: str) -> str:
    if not _is_digest(value):
        _fail("expected native admission receipt digest must be exact lowercase SHA-256")
    return value


def _install(
    candidate_directory: str,
    expected_receipt_sha256: str,
    *,
    policy: _DestinationPolicy,
) -> _LoadedCandidate:
    candidate_descriptor, loaded = _load_and_validate_candidate(
        candidate_directory,
        expected_receipt_sha256,
        policy=policy,
    )
    try:
        _install_loaded_candidate(candidate_descriptor, loaded, policy=policy)
    finally:
        os.close(candidate_descriptor)
    return _verify_installed(expected_receipt_sha256, policy=policy)


def _test_policy(destination: str) -> _DestinationPolicy:
    if os.geteuid() == 0 or not os.environ.get("PYTEST_CURRENT_TEST"):
        _fail("the private unprivileged installer test seam is unavailable")
    if (
        not destination.startswith("/")
        or os.path.normpath(destination) != destination
        or os.path.realpath(os.path.dirname(destination)) != os.path.dirname(destination)
        or not os.path.basename(destination).startswith("trusted-time-admission-test-")
    ):
        _fail("the private installer test destination is invalid")
    parent = os.path.dirname(destination)
    descriptor = _open_canonical_directory(parent)
    try:
        parent_metadata = os.fstat(descriptor)
        _validate_parent_directory(
            descriptor,
            uid=os.geteuid(),
            gid=parent_metadata.st_gid,
            allow_owner_only_mode=True,
        )
    finally:
        os.close(descriptor)
    return _DestinationPolicy(
        parent,
        (),
        os.path.basename(destination),
        False,
        os.geteuid(),
        parent_metadata.st_gid,
    )


def _install_for_test(
    candidate_directory: str,
    destination: str,
    expected_receipt_sha256: str,
) -> _LoadedCandidate:
    """Exercise install semantics without exposing a production CLI override."""

    return _install(
        candidate_directory,
        _require_expected_digest(expected_receipt_sha256),
        policy=_test_policy(destination),
    )


def _verify_for_test(destination: str, expected_receipt_sha256: str) -> _LoadedCandidate:
    """Exercise verification against the same unprivileged private test seam."""

    return _verify_installed(
        _require_expected_digest(expected_receipt_sha256),
        policy=_test_policy(destination),
    )


def main(argument_values: Sequence[str] | None = None) -> int:
    """Reject every direct production invocation before argument or candidate use."""

    raise NativeAdmissionLauncherInstallError(
        "native admission production installer CLI is unavailable; "
        "the retained Python implementation is a nonroot pytest prototype"
    )


if __name__ == "__main__":
    raise SystemExit(
        "native admission production installer CLI is unavailable; "
        "the retained Python implementation is a nonroot pytest prototype"
    )
