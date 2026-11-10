"""Owner-only, non-interpolating dotenv loading for operational scripts."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from io import StringIO
from pathlib import Path

from dotenv import dotenv_values
from dotenv.parser import parse_stream

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


def _parse_strict_allowlisted_assignments(
    payload: str,
    *,
    allowed_variables: frozenset[str],
) -> Mapping[str, str]:
    """Parse one explicit allowlisted assignment per noncomment physical line."""

    parsed: dict[str, str] = {}
    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        bindings = tuple(parse_stream(StringIO(line)))
        if len(bindings) != 1 or bindings[0].error or bindings[0].key is None:
            raise ValueError("env file must contain only explicit variable assignments")
        binding = bindings[0]
        if binding.key not in allowed_variables:
            raise ValueError("env file cannot contain unknown variable assignments")
        match = _DOTENV_ASSIGNMENT.match(line)
        if match is None or match.group(1) != binding.key or binding.value is None:
            raise ValueError("env file must contain only explicit variable assignments")
        if binding.key in parsed:
            raise ValueError("env file cannot contain duplicate variable assignments")
        parsed[binding.key] = binding.value
    return parsed


def load_owner_only_environment(
    path: Path | None,
    *,
    variables: tuple[str, ...],
    allowed_variables: tuple[str, ...] | None = None,
    maximum_bytes: int | None = None,
    reject_duplicate_variables: bool = False,
    reject_symlinked_parents: bool = False,
    require_current_user_owner: bool = False,
    require_secure_path: bool = False,
    required_mode: int | None = None,
) -> Mapping[str, str]:
    """Load selected variables, optionally rejecting every other dotenv name."""

    allowed = None if allowed_variables is None else frozenset(allowed_variables)
    if allowed is not None and not set(variables).issubset(allowed):
        raise ValueError("returned env variables must be allowed")
    if path is None:
        if allowed is not None:
            raise ValueError("strict env loading requires an owner-only file")
        return os.environ
    if type(require_secure_path) is not bool or (
        required_mode is not None
        and (type(required_mode) is not int or required_mode < 0 or required_mode > 0o777)
    ):
        raise ValueError("env file security requirements are invalid")
    if require_secure_path and (not path.is_absolute() or Path(os.path.abspath(path)) != path):
        raise ValueError("env file path must be absolute and canonical")
    if reject_symlinked_parents:
        _reject_symlinked_parent_components(path)
    if not require_secure_path and path.is_symlink():
        raise ValueError("env file must be a readable, non-symlinked regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor: int | None = None
    descriptor: int | None = None
    try:
        if require_secure_path:
            directory_descriptor = os.open(
                path.anchor,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            for component in path.parts[1:-1]:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
                os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            descriptor = os.open(path.name, flags, dir_fd=directory_descriptor)
        else:
            descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("env file must be a regular file")
        if required_mode is None:
            if mode & 0o077:
                raise ValueError("env file permissions must be owner-only (chmod 600)")
        elif mode != required_mode:
            raise ValueError("env file permissions do not match the required mode")
        if require_current_user_owner and before.st_uid != os.getuid():
            raise ValueError("env file must be owned by the current user")
        if require_secure_path and before.st_nlink != 1:
            raise ValueError("env file must have exactly one link")
        if maximum_bytes is not None and (
            type(maximum_bytes) is not int or maximum_bytes <= 0 or before.st_size > maximum_bytes
        ):
            raise ValueError("env file exceeds the accepted size bound")
        maximum_read = -1 if maximum_bytes is None else maximum_bytes + 1
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            encoded = stream.read(maximum_read)
            after = os.fstat(stream.fileno())
        if maximum_bytes is not None and len(encoded) > maximum_bytes:
            raise ValueError("env file exceeds the accepted size bound")
        if (
            len(encoded) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("env file changed during read")
        try:
            payload = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise ValueError("env file must contain valid UTF-8") from None
        parsed: Mapping[str, str | None]
        if allowed is not None:
            parsed = _parse_strict_allowlisted_assignments(
                payload,
                allowed_variables=allowed,
            )
        else:
            if reject_duplicate_variables:
                _reject_duplicate_variables(payload)
            parsed = dotenv_values(stream=StringIO(payload), interpolate=False)
    except ValueError:
        raise
    except OSError as error:
        raise ValueError("env file must be a readable, non-symlinked regular file") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
    environment: dict[str, str] = {}
    for variable in variables:
        if variable not in parsed:
            continue
        value = parsed[variable]
        if value is None:
            raise ValueError(f"{variable} must have an explicit value in the env file")
        environment[variable] = value
    return environment
