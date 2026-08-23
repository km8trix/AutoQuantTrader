"""Create or verify the immutable production image executable/import manifest."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from collections.abc import Iterator
from typing import Never

_SCHEMA = "autoquant-native-executable-image-manifest-v2"
_MAX_ENTRIES = 250_000
_MAX_MANIFEST_BYTES = 128 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_TRUSTED_BASE_PREFIX = "/usr/local"
_NATIVE_INITIALIZER = b"PyInit_" + b"_native_owned_file_descriptor"
_NATIVE_LAUNCHER_RELATIVE_PATH = "opt/autoquant/trusted-time/bin/autoquant-trusted-time-python"
_EXCLUDED_TOP_LEVEL = frozenset(("dev", "proc", "sys", "tmp"))
_EXCLUDED_RELATIVE_PATHS = frozenset(
    (
        ".dockerenv",
        "etc/hostname",
        "etc/hosts",
        "etc/mtab",
        "etc/resolv.conf",
        "run/chrony",
    )
)


class NativeImageManifestError(RuntimeError):
    """The final image is outside the reviewed executable/import boundary."""


def _fail(message: str) -> Never:
    raise NativeImageManifestError(message)


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb", buffering=0) as stream:
            while True:
                chunk = stream.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        _fail("image manifest candidate could not be hashed")
    return digest.hexdigest()


def _contains_initializer(path: str) -> bool:
    overlap = b""
    try:
        with open(path, "rb", buffering=0) as stream:
            while True:
                chunk = stream.read(_HASH_CHUNK_BYTES)
                if not chunk:
                    return False
                candidate = overlap + chunk
                if _NATIVE_INITIALIZER in candidate:
                    return True
                overlap = candidate[-(len(_NATIVE_INITIALIZER) - 1) :]
    except OSError:
        _fail("image root regular file could not be inspected")


def _reject_extended_metadata(path: str) -> None:
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        _fail("image runtime cannot inspect extended metadata")
    try:
        attributes = listxattr(path, follow_symlinks=False)
    except OSError:
        _fail("image root extended metadata could not be inspected")
    if attributes:
        _fail("image root contains forbidden extended metadata")


def _expected_native_relative_path() -> str:
    architecture = os.uname().machine
    if (
        sys.implementation.name != "cpython"
        or os.uname().sysname != "Linux"
        or sys.version_info[:3] != (3, 12, 13)
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.prefix != _TRUSTED_BASE_PREFIX
        or sys.base_prefix != _TRUSTED_BASE_PREFIX
        or architecture not in ("aarch64", "x86_64")
    ):
        _fail("image manifest native runtime identity is invalid")
    return _NATIVE_LAUNCHER_RELATIVE_PATH


def _base_record(relative_path: str, metadata: os.stat_result, kind: str) -> dict[str, object]:
    return {
        "gid": metadata.st_gid,
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": f"/{relative_path}",
        "uid": metadata.st_uid,
    }


def _walk(
    root: str,
    expected_native_relative_path: str,
    relative_directory: str = "",
) -> Iterator[dict[str, object]]:
    directory = root if not relative_directory else os.path.join(root, relative_directory)
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError:
        _fail("image manifest directory could not be scanned")
    for entry in entries:
        if not relative_directory and entry.name in _EXCLUDED_TOP_LEVEL:
            continue
        relative_path = (
            entry.name if not relative_directory else f"{relative_directory}/{entry.name}"
        )
        if relative_path in _EXCLUDED_RELATIVE_PATHS:
            continue
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError:
            _fail("image manifest entry metadata could not be read")
        _reject_extended_metadata(entry.path)
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(entry.path)
            except OSError:
                _fail("image manifest symbolic link could not be read")
            if not target or "\n" in target or "\r" in target or "\0" in target:
                _fail("image manifest symbolic link target is invalid")
            record = _base_record(relative_path, metadata, "symlink")
            record["target"] = target
            yield record
        elif stat.S_ISDIR(metadata.st_mode):
            yield _base_record(relative_path, metadata, "directory")
            yield from _walk(root, expected_native_relative_path, relative_path)
        elif stat.S_ISREG(metadata.st_mode):
            if entry.name.endswith(".pth") or entry.name in (
                "sitecustomize.py",
                "usercustomize.py",
            ):
                _fail("image root contains a forbidden automatic Python startup hook")
            contains_initializer = _contains_initializer(entry.path)
            if contains_initializer and relative_path != expected_native_relative_path:
                _fail("native owned-file-descriptor initializer exists outside its admitted path")
            if relative_path == expected_native_relative_path and (
                not contains_initializer
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o555
            ):
                _fail("native owned-file-descriptor image artifact metadata is invalid")
            record = _base_record(relative_path, metadata, "file")
            record["nlink"] = metadata.st_nlink
            record["sha256"] = _sha256(entry.path)
            record["size"] = metadata.st_size
            if contains_initializer:
                record["native_initializer"] = True
            yield record
        else:
            _fail("image root contains an unsupported filesystem entry")


def _manifest_bytes(root: str, manifest_path: str) -> bytes:
    canonical_root = os.path.realpath(root)
    canonical_manifest = os.path.realpath(manifest_path)
    if root != canonical_root or not os.path.isabs(root) or not os.path.isabs(manifest_path):
        _fail("image manifest paths must be canonical and absolute")
    if canonical_root != "/" and not canonical_manifest.startswith(f"{canonical_root}/"):
        _fail("image manifest must be inside the scanned root")
    try:
        root_metadata = os.lstat(canonical_root)
    except OSError:
        _fail("image manifest root metadata could not be read")
    if not stat.S_ISDIR(root_metadata.st_mode):
        _fail("image manifest root is not a directory")
    _reject_extended_metadata(canonical_root)
    relative_manifest = os.path.relpath(canonical_manifest, canonical_root)
    if relative_manifest.startswith("../") or relative_manifest == "..":
        _fail("image manifest escaped its scanned root")
    encoded_lines = [json.dumps({"schema": _SCHEMA}, sort_keys=True, separators=(",", ":"))]
    entry_count = 0
    native_initializer_path: object | None = None
    expected_native_relative_path = _expected_native_relative_path()
    for record in _walk(canonical_root, expected_native_relative_path):
        if record["path"] == f"/{relative_manifest}":
            continue
        if record.get("native_initializer") is True:
            if native_initializer_path is not None:
                _fail("image root contains more than one native owned-file-descriptor initializer")
            native_initializer_path = record["path"]
        entry_count += 1
        if entry_count > _MAX_ENTRIES:
            _fail("image manifest entry count exceeded its bound")
        encoded_lines.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    if native_initializer_path != f"/{expected_native_relative_path}":
        _fail("image root does not contain one exact native owned-file-descriptor initializer")
    payload = ("\n".join(encoded_lines) + "\n").encode("utf-8")
    if len(payload) > _MAX_MANIFEST_BYTES:
        _fail("image manifest exceeded its byte bound")
    return payload


def _write(root: str, manifest_path: str) -> str:
    payload = _manifest_bytes(root, manifest_path)
    try:
        descriptor = os.open(
            manifest_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o444,
        )
    except OSError:
        _fail("image manifest output could not be created exclusively")
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _fail("image manifest output write did not progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(payload).hexdigest()


def _verify(root: str, manifest_path: str) -> str:
    try:
        metadata = os.lstat(manifest_path)
    except OSError:
        _fail("image manifest metadata could not be read")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
    ):
        _fail("image manifest metadata is invalid")
    try:
        with open(manifest_path, "rb", buffering=0) as manifest:
            observed = manifest.read(_MAX_MANIFEST_BYTES + 1)
    except OSError:
        _fail("image manifest could not be read")
    expected = _manifest_bytes(root, manifest_path)
    if observed != expected:
        _fail("image executable/import inventory changed")
    return hashlib.sha256(observed).hexdigest()


def _receipt(manifest_sha256: str) -> bytes:
    return f'{{"manifest_sha256":"{manifest_sha256}","schema":"{_SCHEMA}"}}\n'.encode("ascii")


def main(arguments: tuple[str, ...] | None = None) -> int:
    selected = tuple(sys.argv[1:]) if arguments is None else arguments
    if len(selected) != 3 or selected[0] not in ("write", "verify"):
        _fail("usage: native_image_manifest.py (write|verify) ROOT MANIFEST")
    operation, root, manifest_path = selected
    if operation == "write":
        manifest_sha256 = _write(root, manifest_path)
    else:
        manifest_sha256 = _verify(root, manifest_path)
    output = _receipt(manifest_sha256)
    offset = 0
    while offset < len(output):
        written = os.write(1, output[offset:])
        if written <= 0:
            _fail("image manifest receipt write did not progress")
        offset += written
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
