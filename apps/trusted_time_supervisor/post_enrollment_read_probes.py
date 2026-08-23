"""Fixed no-fileno observations for the trusted-time supervisor container."""

from __future__ import annotations

import hashlib
import stat
import sys
from collections.abc import Callable
from typing import cast

from packages.adapters.trusted_time._owned_file_descriptor import (
    _fstat,
    _open_child_directory,
    _open_child_regular,
    _open_root_directory,
    _OwnedFileDescriptor,
    _read_snapshot,
    _statat,
)

_STAGED_BARRIER_TARGET_ID = "post-enrollment-staged-barrier-read"
_PRE_EFFECT_ABSENCE_TARGET_ID = "post-enrollment-pre-effect-runtime-absence"
_PERSISTENT_BARRIER_TARGET_ID = "post-enrollment-persistent-barrier-read"

_STAGED_BARRIER_CONTRACT_VERSION = "phase6d-post-enrollment-barrier-read-probe-v1"
_PRE_EFFECT_ABSENCE_CONTRACT_VERSION = "phase6d-post-enrollment-pre-effect-runtime-absence-probe-v1"
_PERSISTENT_BARRIER_CONTRACT_VERSION = "phase6d-post-enrollment-persistent-barrier-read-probe-v1"

_STAGED_BARRIER_FAILURE = "trusted-time topology probe failed\n"
_PRE_EFFECT_ABSENCE_FAILURE = "trusted-time pre-effect runtime absence probe failed\n"
_PERSISTENT_BARRIER_FAILURE = "trusted-time persistent topology probe failed\n"

_TMP_COMPONENT = "tmp"
_MAXIMUM_MARKER_BYTES = 4_096

_DATABASE_MARKER = ("database-secret-consumed", "/tmp/database-secret-consumed")
_DEADLINE_MARKER = (
    "post-enrollment-start-sequence-two-deadline",
    "/tmp/post-enrollment-start-sequence-two-deadline",
)
_RELEASE_MARKER = (
    "post-enrollment-start-release",
    "/tmp/post-enrollment-start-release",
)
_READY_MARKER = (
    "post-enrollment-start-sequence-two-ready",
    "/tmp/post-enrollment-start-sequence-two-ready",
)
_STAGED_RELEASE_ABSENCES = (
    (
        ".post-enrollment-start-release-staging",
        "/tmp/.post-enrollment-start-release-staging",
    ),
    ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
)
_PRE_EFFECT_ABSENCES = (
    (
        ".post-enrollment-start-sequence-two-deadline-staging",
        "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
    ),
    (
        "post-enrollment-start-sequence-two-deadline",
        "/tmp/post-enrollment-start-sequence-two-deadline",
    ),
    (
        ".post-enrollment-start-release-staging",
        "/tmp/.post-enrollment-start-release-staging",
    ),
    ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
    (
        ".post-enrollment-start-sequence-two-ready-staging",
        "/tmp/.post-enrollment-start-sequence-two-ready-staging",
    ),
    (
        "post-enrollment-start-sequence-two-ready",
        "/tmp/post-enrollment-start-sequence-two-ready",
    ),
)
_PERSISTENT_STAGING_ABSENCES = (
    (
        ".post-enrollment-start-sequence-two-deadline-staging",
        "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
    ),
    (
        ".post-enrollment-start-release-staging",
        "/tmp/.post-enrollment-start-release-staging",
    ),
    (
        ".post-enrollment-start-sequence-two-ready-staging",
        "/tmp/.post-enrollment-start-sequence-two-ready-staging",
    ),
)

_Stat9 = tuple[int, int, int, int, int, int, int, int, int]
_MarkerBinding = tuple[str, str]
_AbsenceBindings = tuple[_MarkerBinding, ...]
_MarkerRead = tuple[bytes, _Stat9]
_StagedProjection = tuple[_MarkerRead, tuple[str, ...]]
_PersistentProjection = tuple[
    _MarkerRead,
    _MarkerRead,
    _MarkerRead,
    _MarkerRead,
    tuple[str, ...],
]


def _preferred_cleanup_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_cleanup_exceptions(
    *errors: BaseException | None,
    _prefer: Callable[[BaseException | None, BaseException | None], BaseException | None] = (
        _preferred_cleanup_exception
    ),
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _prefer(preferred, error)
    return preferred


def _cleanup_native_owners(
    owners: tuple[_OwnedFileDescriptor | None, ...],
    *,
    _prefer: Callable[[BaseException | None, BaseException | None], BaseException | None] = (
        _preferred_cleanup_exception
    ),
) -> BaseException | None:
    """Close every fixed owner slot while preserving async-exception priority."""

    first_error: BaseException | None = None
    for owner in owners:
        if owner is None:
            continue
        for _ in range(2):
            try:
                if owner.closed:
                    break
                owner.close()
            except BaseException as error:
                first_error = _prefer(first_error, error)
        try:
            if not owner.closed:
                first_error = _prefer(
                    first_error,
                    RuntimeError("native owned file descriptor could not be closed"),
                )
        except BaseException as error:
            first_error = _prefer(first_error, error)
    return first_error


def _require_stat9(value: object) -> _Stat9:
    if (
        type(value) is not tuple
        or len(value) != 9
        or any(type(item) is not int or item < 0 for item in value)
    ):
        raise OSError
    return cast(_Stat9, value)


def _json_string_bytes(value: str) -> bytes:
    if (
        type(value) is not str
        or not value
        or any(ord(character) < 0x20 or character in {'"', "\\"} for character in value)
    ):
        raise TypeError
    return b'"' + value.encode("ascii", errors="strict") + b'"'


def _decimal_bytes(value: int) -> bytes:
    if type(value) is not int or value < 0:
        raise TypeError
    return f"{value:d}".encode("ascii")


def _absence_payload_bytes(
    paths: tuple[str, ...],
    *,
    _encode_string: Callable[[str], bytes] = _json_string_bytes,
) -> bytes:
    encoded = tuple(b'{"path":' + _encode_string(path) + b',"status":"absent"}' for path in paths)
    return b"[" + b",".join(encoded) + b"]"


def _require_absences(
    tmp_owner: _OwnedFileDescriptor,
    bindings: _AbsenceBindings,
    *,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str], object] = _statat,
    _is_directory: Callable[[int], bool] = stat.S_ISDIR,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
) -> tuple[str, ...]:
    parent_before = _require_stat(_fstat_exact(tmp_owner))
    if not _is_directory(parent_before[2]):
        raise OSError
    paths: tuple[str, ...] = ()
    for component, path in bindings:
        try:
            _statat_exact(tmp_owner, component)
        except FileNotFoundError:
            paths += (path,)
            continue
        raise OSError
    if _require_stat(_fstat_exact(tmp_owner)) != parent_before:
        raise OSError
    return paths


def _read_marker(
    tmp_owner: _OwnedFileDescriptor,
    component: str,
    *,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str], object] = _statat,
    _open_regular_exact: Callable[[_OwnedFileDescriptor, str], _OwnedFileDescriptor] = (
        _open_child_regular
    ),
    _read_snapshot_exact: Callable[[_OwnedFileDescriptor, int], object] = _read_snapshot,
    _is_directory: Callable[[int], bool] = stat.S_ISDIR,
    _is_regular: Callable[[int], bool] = stat.S_ISREG,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
    _cleanup: Callable[[tuple[_OwnedFileDescriptor | None, ...]], BaseException | None] = (
        _cleanup_native_owners
    ),
    _prefer_errors: Callable[..., BaseException | None] = _preferred_cleanup_exceptions,
) -> _MarkerRead:
    file_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    result: _MarkerRead | None = None
    try:
        try:
            parent_before = _require_stat(_fstat_exact(tmp_owner))
            named_before = _require_stat(_statat_exact(tmp_owner, component))
            file_owner = _open_regular_exact(tmp_owner, component)
            opened_before = _require_stat(_fstat_exact(file_owner))
            if (
                not _is_directory(parent_before[2])
                or opened_before != named_before
                or not _is_regular(opened_before[2])
                or opened_before[5] != 1
                or opened_before[6] > 4_096
            ):
                raise OSError
            snapshot = _read_snapshot_exact(file_owner, 4_096)
            if type(snapshot) is not tuple or len(snapshot) != 3 or type(snapshot[0]) is not bytes:
                raise OSError
            payload = snapshot[0]
            read_before = _require_stat(snapshot[1])
            read_after = _require_stat(snapshot[2])
            opened_after = _require_stat(_fstat_exact(file_owner))
            named_after = _require_stat(_statat_exact(tmp_owner, component))
            parent_after = _require_stat(_fstat_exact(tmp_owner))
            if (
                read_before != opened_before
                or read_after != opened_before
                or opened_after != opened_before
                or named_after != opened_before
                or parent_after != parent_before
                or len(payload) != opened_before[6]
            ):
                raise OSError
            result = (payload, opened_before)
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup((file_owner,))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup((file_owner,))
    terminal = _prefer_errors(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if result is None:
        raise OSError
    return result


def _marker_payload_bytes(
    path: str,
    observed: _MarkerRead,
    *,
    _sha256: Callable[[bytes], object] = hashlib.sha256,
    _mode_bits: Callable[[int], int] = stat.S_IMODE,
    _encode_string: Callable[[str], bytes] = _json_string_bytes,
    _encode_decimal: Callable[[int], bytes] = _decimal_bytes,
) -> bytes:
    payload, metadata = observed
    payload_sha256 = _sha256(payload).hexdigest()  # type: ignore[attr-defined]
    if (
        type(payload_sha256) is not str
        or len(payload_sha256) != 64
        or any(character not in "0123456789abcdef" for character in payload_sha256)
    ):
        raise TypeError
    return b"".join(
        (
            b'{"byte_sha256":"',
            payload_sha256.encode("ascii"),
            b'","changed_time_ns":',
            _encode_decimal(metadata[8]),
            b',"device":',
            _encode_decimal(metadata[0]),
            b',"inode":',
            _encode_decimal(metadata[1]),
            b',"link_count":',
            _encode_decimal(metadata[5]),
            b',"mode":',
            _encode_decimal(_mode_bits(metadata[2])),
            b',"modified_time_ns":',
            _encode_decimal(metadata[7]),
            b',"owner_gid":',
            _encode_decimal(metadata[4]),
            b',"owner_uid":',
            _encode_decimal(metadata[3]),
            b',"path":',
            _encode_string(path),
            b',"regular":true,"size":',
            _encode_decimal(len(payload)),
            b"}",
        )
    )


def _require_open_tmp_context(
    root_owner: _OwnedFileDescriptor,
    tmp_owner: _OwnedFileDescriptor,
    *,
    root_before: _Stat9,
    tmp_before: _Stat9,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str], object] = _statat,
    _is_directory: Callable[[int], bool] = stat.S_ISDIR,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
) -> None:
    if (
        not _is_directory(root_before[2])
        or not _is_directory(tmp_before[2])
        or _require_stat(_fstat_exact(tmp_owner)) != tmp_before
        or _require_stat(_statat_exact(root_owner, "tmp")) != tmp_before
        or _require_stat(_fstat_exact(root_owner)) != root_before
    ):
        raise OSError


def _staged_barrier_bytes(
    *,
    _open_root: Callable[[], _OwnedFileDescriptor] = _open_root_directory,
    _open_directory: Callable[[_OwnedFileDescriptor, str], _OwnedFileDescriptor] = (
        _open_child_directory
    ),
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str], object] = _statat,
    _observe_absences: Callable[..., tuple[str, ...]] = _require_absences,
    _observe_marker: Callable[..., _MarkerRead] = _read_marker,
    _require_context: Callable[..., None] = _require_open_tmp_context,
    _cleanup: Callable[[tuple[_OwnedFileDescriptor | None, ...]], BaseException | None] = (
        _cleanup_native_owners
    ),
    _prefer_errors: Callable[..., BaseException | None] = _preferred_cleanup_exceptions,
    _marker_bytes: Callable[..., bytes] = _marker_payload_bytes,
    _absence_bytes: Callable[..., bytes] = _absence_payload_bytes,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
    _database_binding: _MarkerBinding = (
        "database-secret-consumed",
        "/tmp/database-secret-consumed",
    ),
    _release_bindings: _AbsenceBindings = (
        (
            ".post-enrollment-start-release-staging",
            "/tmp/.post-enrollment-start-release-staging",
        ),
        ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
    ),
) -> bytes:
    root_owner: _OwnedFileDescriptor | None = None
    tmp_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    projection: _StagedProjection | None = None
    try:
        try:
            if _database_binding != (
                "database-secret-consumed",
                "/tmp/database-secret-consumed",
            ) or _release_bindings != (
                (
                    ".post-enrollment-start-release-staging",
                    "/tmp/.post-enrollment-start-release-staging",
                ),
                ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
            ):
                raise OSError
            root_owner = _open_root()
            root_before = _require_stat(_fstat_exact(root_owner))
            tmp_named_before = _require_stat(_statat_exact(root_owner, "tmp"))
            tmp_owner = _open_directory(root_owner, "tmp")
            tmp_before = _require_stat(_fstat_exact(tmp_owner))
            if tmp_named_before != tmp_before:
                raise OSError
            before = _observe_absences(tmp_owner, _release_bindings)
            marker = _observe_marker(tmp_owner, _database_binding[0])
            after = _observe_absences(tmp_owner, _release_bindings)
            if before != after:
                raise OSError
            _require_context(
                root_owner,
                tmp_owner,
                root_before=root_before,
                tmp_before=tmp_before,
            )
            projection = (marker, before)
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup((tmp_owner, root_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup((tmp_owner, root_owner))
    terminal = _prefer_errors(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if projection is None:
        raise OSError
    marker, absences = projection
    return b"".join(
        (
            b'{"contract_version":"phase6d-post-enrollment-barrier-read-probe-v1"',
            b',"marker":',
            _marker_bytes(_database_binding[1], marker),
            b',"release_absences":',
            _absence_bytes(absences),
            b"}",
        )
    )


def _pre_effect_runtime_absence_bytes(
    *,
    _open_root: Callable[[], _OwnedFileDescriptor] = _open_root_directory,
    _open_directory: Callable[[_OwnedFileDescriptor, str], _OwnedFileDescriptor] = (
        _open_child_directory
    ),
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str], object] = _statat,
    _observe_absences: Callable[..., tuple[str, ...]] = _require_absences,
    _require_context: Callable[..., None] = _require_open_tmp_context,
    _cleanup: Callable[[tuple[_OwnedFileDescriptor | None, ...]], BaseException | None] = (
        _cleanup_native_owners
    ),
    _prefer_errors: Callable[..., BaseException | None] = _preferred_cleanup_exceptions,
    _absence_bytes: Callable[..., bytes] = _absence_payload_bytes,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
    _absence_bindings: _AbsenceBindings = (
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
        ),
        (
            "post-enrollment-start-sequence-two-deadline",
            "/tmp/post-enrollment-start-sequence-two-deadline",
        ),
        (
            ".post-enrollment-start-release-staging",
            "/tmp/.post-enrollment-start-release-staging",
        ),
        ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
        (
            ".post-enrollment-start-sequence-two-ready-staging",
            "/tmp/.post-enrollment-start-sequence-two-ready-staging",
        ),
        (
            "post-enrollment-start-sequence-two-ready",
            "/tmp/post-enrollment-start-sequence-two-ready",
        ),
    ),
) -> bytes:
    root_owner: _OwnedFileDescriptor | None = None
    tmp_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    projection: tuple[str, ...] | None = None
    try:
        try:
            if _absence_bindings != (
                (
                    ".post-enrollment-start-sequence-two-deadline-staging",
                    "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
                ),
                (
                    "post-enrollment-start-sequence-two-deadline",
                    "/tmp/post-enrollment-start-sequence-two-deadline",
                ),
                (
                    ".post-enrollment-start-release-staging",
                    "/tmp/.post-enrollment-start-release-staging",
                ),
                ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
                (
                    ".post-enrollment-start-sequence-two-ready-staging",
                    "/tmp/.post-enrollment-start-sequence-two-ready-staging",
                ),
                (
                    "post-enrollment-start-sequence-two-ready",
                    "/tmp/post-enrollment-start-sequence-two-ready",
                ),
            ):
                raise OSError
            root_owner = _open_root()
            root_before = _require_stat(_fstat_exact(root_owner))
            tmp_named_before = _require_stat(_statat_exact(root_owner, "tmp"))
            tmp_owner = _open_directory(root_owner, "tmp")
            tmp_before = _require_stat(_fstat_exact(tmp_owner))
            if tmp_named_before != tmp_before:
                raise OSError
            before = _observe_absences(tmp_owner, _absence_bindings)
            after = _observe_absences(tmp_owner, _absence_bindings)
            if before != after:
                raise OSError
            _require_context(
                root_owner,
                tmp_owner,
                root_before=root_before,
                tmp_before=tmp_before,
            )
            projection = before
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup((tmp_owner, root_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup((tmp_owner, root_owner))
    terminal = _prefer_errors(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if projection is None:
        raise OSError
    return b"".join(
        (
            b'{"absences":',
            _absence_bytes(projection),
            b',"contract_version":"phase6d-post-enrollment-pre-effect-runtime-absence-probe-v1"',
            b"}",
        )
    )


def _persistent_barrier_bytes(
    *,
    _open_root: Callable[[], _OwnedFileDescriptor] = _open_root_directory,
    _open_directory: Callable[[_OwnedFileDescriptor, str], _OwnedFileDescriptor] = (
        _open_child_directory
    ),
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str], object] = _statat,
    _observe_absences: Callable[..., tuple[str, ...]] = _require_absences,
    _observe_marker: Callable[..., _MarkerRead] = _read_marker,
    _require_context: Callable[..., None] = _require_open_tmp_context,
    _cleanup: Callable[[tuple[_OwnedFileDescriptor | None, ...]], BaseException | None] = (
        _cleanup_native_owners
    ),
    _prefer_errors: Callable[..., BaseException | None] = _preferred_cleanup_exceptions,
    _marker_bytes: Callable[..., bytes] = _marker_payload_bytes,
    _absence_bytes: Callable[..., bytes] = _absence_payload_bytes,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
    _marker_bindings: tuple[_MarkerBinding, _MarkerBinding, _MarkerBinding, _MarkerBinding] = (
        ("database-secret-consumed", "/tmp/database-secret-consumed"),
        (
            "post-enrollment-start-sequence-two-deadline",
            "/tmp/post-enrollment-start-sequence-two-deadline",
        ),
        ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
        (
            "post-enrollment-start-sequence-two-ready",
            "/tmp/post-enrollment-start-sequence-two-ready",
        ),
    ),
    _absence_bindings: _AbsenceBindings = (
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
        ),
        (
            ".post-enrollment-start-release-staging",
            "/tmp/.post-enrollment-start-release-staging",
        ),
        (
            ".post-enrollment-start-sequence-two-ready-staging",
            "/tmp/.post-enrollment-start-sequence-two-ready-staging",
        ),
    ),
) -> bytes:
    root_owner: _OwnedFileDescriptor | None = None
    tmp_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    projection: _PersistentProjection | None = None
    try:
        try:
            if _marker_bindings != (
                ("database-secret-consumed", "/tmp/database-secret-consumed"),
                (
                    "post-enrollment-start-sequence-two-deadline",
                    "/tmp/post-enrollment-start-sequence-two-deadline",
                ),
                ("post-enrollment-start-release", "/tmp/post-enrollment-start-release"),
                (
                    "post-enrollment-start-sequence-two-ready",
                    "/tmp/post-enrollment-start-sequence-two-ready",
                ),
            ) or _absence_bindings != (
                (
                    ".post-enrollment-start-sequence-two-deadline-staging",
                    "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
                ),
                (
                    ".post-enrollment-start-release-staging",
                    "/tmp/.post-enrollment-start-release-staging",
                ),
                (
                    ".post-enrollment-start-sequence-two-ready-staging",
                    "/tmp/.post-enrollment-start-sequence-two-ready-staging",
                ),
            ):
                raise OSError
            root_owner = _open_root()
            root_before = _require_stat(_fstat_exact(root_owner))
            tmp_named_before = _require_stat(_statat_exact(root_owner, "tmp"))
            tmp_owner = _open_directory(root_owner, "tmp")
            tmp_before = _require_stat(_fstat_exact(tmp_owner))
            if tmp_named_before != tmp_before:
                raise OSError
            before = _observe_absences(tmp_owner, _absence_bindings)
            database = _observe_marker(tmp_owner, _marker_bindings[0][0])
            deadline = _observe_marker(tmp_owner, _marker_bindings[1][0])
            release = _observe_marker(tmp_owner, _marker_bindings[2][0])
            ready = _observe_marker(tmp_owner, _marker_bindings[3][0])
            after = _observe_absences(tmp_owner, _absence_bindings)
            if before != after:
                raise OSError
            _require_context(
                root_owner,
                tmp_owner,
                root_before=root_before,
                tmp_before=tmp_before,
            )
            projection = (database, deadline, release, ready, before)
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup((tmp_owner, root_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup((tmp_owner, root_owner))
    terminal = _prefer_errors(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if projection is None:
        raise OSError
    database, deadline, release, ready, absences = projection
    return b"".join(
        (
            b'{"contract_version":"phase6d-post-enrollment-persistent-barrier-read-probe-v1"',
            b',"database_marker":',
            _marker_bytes(_marker_bindings[0][1], database),
            b',"deadline_marker":',
            _marker_bytes(_marker_bindings[1][1], deadline),
            b',"release_marker":',
            _marker_bytes(_marker_bindings[2][1], release),
            b',"runtime_staging_absences":',
            _absence_bytes(absences),
            b',"sequence_marker":',
            _marker_bytes(_marker_bindings[3][1], ready),
            b"}",
        )
    )


def staged_barrier_main(
    *,
    _emit: Callable[[], bytes] = _staged_barrier_bytes,
) -> None:
    """Emit the fixed staged consumed-input barrier observation."""

    stdout_write = sys.stdout.write
    stderr_write = sys.stderr.write
    try:
        if type(sys.argv) is not list or sys.argv != ["post-enrollment-staged-barrier-read"]:
            raise ValueError
        encoded = _emit()
        stdout_write(encoded.decode("ascii") + "\n")
    except BaseException:
        stderr_write("trusted-time topology probe failed\n")
        raise SystemExit(2) from None


def pre_effect_runtime_absence_main(
    *,
    _emit: Callable[[], bytes] = _pre_effect_runtime_absence_bytes,
) -> None:
    """Emit the fixed pre-effect runtime-name absence observation."""

    stdout_write = sys.stdout.write
    stderr_write = sys.stderr.write
    try:
        if type(sys.argv) is not list or sys.argv != ["post-enrollment-pre-effect-runtime-absence"]:
            raise ValueError
        encoded = _emit()
        stdout_write(encoded.decode("ascii") + "\n")
    except BaseException:
        stderr_write("trusted-time pre-effect runtime absence probe failed\n")
        raise SystemExit(2) from None


def persistent_barrier_main(
    *,
    _emit: Callable[[], bytes] = _persistent_barrier_bytes,
) -> None:
    """Emit the fixed persistent marker and staging-absence observation."""

    stdout_write = sys.stdout.write
    stderr_write = sys.stderr.write
    try:
        if type(sys.argv) is not list or sys.argv != ["post-enrollment-persistent-barrier-read"]:
            raise ValueError
        encoded = _emit()
        stdout_write(encoded.decode("ascii") + "\n")
    except BaseException:
        stderr_write("trusted-time persistent topology probe failed\n")
        raise SystemExit(2) from None


__all__: tuple[()] = ()
