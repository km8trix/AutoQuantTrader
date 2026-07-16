"""Owner-only, non-interpolating dotenv loading for operational scripts."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path

from dotenv import dotenv_values


def load_owner_only_environment(
    path: Path | None,
    *,
    variables: tuple[str, ...],
) -> Mapping[str, str]:
    if path is None:
        return os.environ
    if path.is_symlink():
        raise ValueError("env file must be a readable, non-symlinked regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("env file must be a readable, non-symlinked regular file") from error
    with os.fdopen(descriptor, encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("env file must be a regular file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("env file permissions must be owner-only (chmod 600)")
        parsed = dotenv_values(stream=stream, interpolate=False)
    environment: dict[str, str] = {}
    for variable in variables:
        if variable not in parsed:
            continue
        value = parsed[variable]
        if value is None:
            raise ValueError(f"{variable} must have an explicit value in the env file")
        environment[variable] = value
    return environment
