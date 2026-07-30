"""Owner-only, non-interpolating dotenv loading for operational scripts."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from io import StringIO
from pathlib import Path

from dotenv import dotenv_values

_DOTENV_ASSIGNMENT = re.compile(
    r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=",
)


def _reject_symlinked_parent_components(path: Path) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    cursor = Path(absolute.anchor)
    for component in absolute.parts[1:-1]:
        cursor /= component
        try:
            if cursor.is_symlink():
                raise ValueError("env file path cannot contain symlinked parent components")
        except OSError as error:
            raise ValueError("env file path components must be inspectable") from error


def _reject_duplicate_variables(payload: str) -> None:
    observed: set[str] = set()
    for line in payload.splitlines():
        match = _DOTENV_ASSIGNMENT.match(line)
        if match is None:
            continue
        variable = match.group(1)
        if variable in observed:
            raise ValueError("env file cannot contain duplicate variable assignments")
        observed.add(variable)


def load_owner_only_environment(
    path: Path | None,
    *,
    variables: tuple[str, ...],
    maximum_bytes: int | None = None,
    reject_duplicate_variables: bool = False,
    reject_symlinked_parents: bool = False,
    require_current_user_owner: bool = False,
) -> Mapping[str, str]:
    if path is None:
        return os.environ
    if reject_symlinked_parents:
        _reject_symlinked_parent_components(path)
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
        if require_current_user_owner and metadata.st_uid != os.getuid():
            raise ValueError("env file must be owned by the current user")
        if maximum_bytes is not None and (
            type(maximum_bytes) is not int or maximum_bytes <= 0 or metadata.st_size > maximum_bytes
        ):
            raise ValueError("env file exceeds the accepted size bound")
        payload = stream.read(
            -1 if maximum_bytes is None else maximum_bytes + 1,
        )
        if maximum_bytes is not None and len(payload.encode("utf-8")) > maximum_bytes:
            raise ValueError("env file exceeds the accepted size bound")
        if reject_duplicate_variables:
            _reject_duplicate_variables(payload)
        parsed = dotenv_values(stream=StringIO(payload), interpolate=False)
    environment: dict[str, str] = {}
    for variable in variables:
        if variable not in parsed:
            continue
        value = parsed[variable]
        if value is None:
            raise ValueError(f"{variable} must have an explicit value in the env file")
        environment[variable] = value
    return environment
