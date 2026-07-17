"""Descriptor-relative reads for owner-only local review artifacts."""

from __future__ import annotations

import os
import stat
from pathlib import Path

_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_owner_only_artifact(path: Path, *, limit: int, label: str) -> bytes:
    """Read one bounded current-user artifact without following any symlink."""

    if not isinstance(path, Path):
        raise ValueError(f"{label} path must be a pathlib.Path")
    if type(limit) is not int or limit < 1:
        raise ValueError(f"{label} size limit must be a positive integer")
    absolute = Path(os.path.abspath(path))
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        directory_descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
        for part in absolute.parts[1:-1]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        file_descriptor = os.open(absolute.name, _FILE_FLAGS, dir_fd=directory_descriptor)
        before = os.fstat(file_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if before.st_uid != os.geteuid():
            raise ValueError(f"{label} must be owned by the current user")
        if stat.S_IMODE(before.st_mode) not in {0o400, 0o600}:
            raise ValueError(f"{label} permissions must be owner-only (chmod 600 or 400)")
        if before.st_nlink != 1:
            raise ValueError(f"{label} must have exactly one hard link")
        if before.st_size < 1:
            raise ValueError(f"{label} must be non-empty")
        if before.st_size > limit:
            raise ValueError(f"{label} exceeds the size limit")
        with os.fdopen(file_descriptor, "rb") as stream:
            file_descriptor = None
            payload = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise ValueError(
            f"{label} path must contain only non-symlinked directories and a readable regular file"
        ) from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    if _stable_identity(before) != _stable_identity(after) or len(payload) != before.st_size:
        raise ValueError(f"{label} changed while it was being read")
    return payload


__all__ = ["read_owner_only_artifact"]
