"""Fixed no-fileno observation of the post-enrollment runtime state."""

from __future__ import annotations

import hashlib
import stat
import sys
import time
from collections.abc import Callable
from typing import cast

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _fstat,
    _open_child_directory,
    _open_child_regular,
    _open_root_directory,
    _OwnedFileDescriptor,
    _read_snapshot,
    _statat,
)

POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION = "phase6d-post-enrollment-runtime-state-v1"
POST_ENROLLMENT_RUNTIME_STATE_STATUS = "sequence_two_ready_observed"

_TARGET_ID = "post-enrollment-runtime-state"
_FAILURE_MESSAGE = "trusted-time post-enrollment runtime state probe failed\n"
_DEADLINE_WINDOW_NANOSECONDS = 120_000_000_000
_MAXIMUM_DEADLINE_BYTES = 512
_MAXIMUM_BOOT_ID_BYTES = 37
_MAXIMUM_POLLS = 1_200
_POLL_SECONDS = 0.1

_RELEASE_BYTES = b"phase6d-post-enrollment-start-release-v1\n"
_READY_BYTES = b"phase6d-post-enrollment-start-sequence-two-ready-v1\n"
_RELEASE_SHA256_BYTES = b"0207100f7073e92f22a5acf8ae06e0735ac33e8dfaef7e60c62d387cd0355731"
_READY_SHA256_BYTES = b"f8faaa629107c4b26b7c70677ee8cc98d67a69741c21fb91300e78b2d9bf5c6d"

_RELEASE_COMPONENT = "post-enrollment-start-release"
_DEADLINE_COMPONENT = "post-enrollment-start-sequence-two-deadline"
_READY_COMPONENT = "post-enrollment-start-sequence-two-ready"
_RELEASE_STAGING_COMPONENT = ".post-enrollment-start-release-staging"
_DEADLINE_STAGING_COMPONENT = ".post-enrollment-start-sequence-two-deadline-staging"
_READY_STAGING_COMPONENT = ".post-enrollment-start-sequence-two-ready-staging"

_DEADLINE_PREFIX = b'{"boot_id_sha256":"'
_DEADLINE_AFTER_BOOT = (
    b'","contract_version":"phase6d-post-enrollment-start-sequence-two-deadline-v1",'
    b'"deadline_boottime_ns":'
)
_DEADLINE_BEFORE_ISSUED = b',"issued_at_boottime_ns":'
_DEADLINE_SUFFIX = b',"release_marker_sha256":"' + _RELEASE_SHA256_BYTES + b'"}\n'

_RUNTIME_STATE_PREFIX = (
    b'{"alert_delivery_authorized":false,"arming_authorized":false,'
    b'"automatic_rearm_authorized":false,"automatic_resume_authorized":false,'
    b'"broker_action_authorized":false,"contract_version":'
    b'"phase6d-post-enrollment-runtime-state-v1","exposure_authorized":false,'
    b'"live_trading_authorized":false,"new_exposure_authorized":false,'
    b'"operational_control_authorized":false,"paper_trading_authorized":false,'
    b'"readiness_authorized":false,"rearm_authorized":false,'
    b'"release_marker_sha256":"'
    + _RELEASE_SHA256_BYTES
    + b'","sequence_two_deadline_marker_sha256":"'
)
_RUNTIME_STATE_SUFFIX = (
    b'","sequence_two_ready_marker_sha256":"'
    + _READY_SHA256_BYTES
    + b'","service":"trusted-time-supervisor",'
    b'"status":"sequence_two_ready_observed"}\n'
)

_Stat9 = tuple[int, int, int, int, int, int, int, int, int]
_MarkerRead = tuple[bytes, _Stat9]
_InitialMarkers = tuple[_MarkerRead, _MarkerRead]
_FinalMarkers = tuple[_MarkerRead, _MarkerRead, _MarkerRead]
_DeadlineProjection = tuple[int, bytes]
_RuntimeStateProjection = tuple[str, int, bytes]
_MarkerComponents = tuple[str, ...]
_AbsenceComponents = tuple[str, ...]

_INITIAL_MARKER_COMPONENTS = (_RELEASE_COMPONENT, _DEADLINE_COMPONENT)
_FINAL_MARKER_COMPONENTS = (
    _RELEASE_COMPONENT,
    _DEADLINE_COMPONENT,
    _READY_COMPONENT,
)
_READY_MARKER_COMPONENTS = (_READY_COMPONENT,)
_ALL_STAGING_COMPONENTS = (
    _DEADLINE_STAGING_COMPONENT,
    _RELEASE_STAGING_COMPONENT,
    _READY_STAGING_COMPONENT,
)
_READY_STAGING_COMPONENTS = (_READY_STAGING_COMPONENT,)


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


def _read_regular_snapshot(
    parent_owner: _OwnedFileDescriptor,
    component: str,
    maximum_bytes: int,
    *,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str | bytes], object] = _statat,
    _open_regular_exact: Callable[
        [_OwnedFileDescriptor, str | bytes], _OwnedFileDescriptor
    ] = _open_child_regular,
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
            if type(component) is not str or not component or type(maximum_bytes) is not int:
                raise OSError
            parent_before = _require_stat(_fstat_exact(parent_owner))
            named_before = _require_stat(_statat_exact(parent_owner, component))
            file_owner = _open_regular_exact(parent_owner, component)
            opened_before = _require_stat(_fstat_exact(file_owner))
            if (
                maximum_bytes < 1
                or not _is_directory(parent_before[2])
                or named_before != opened_before
                or not _is_regular(opened_before[2])
                or opened_before[5] != 1
                or opened_before[6] > maximum_bytes
            ):
                raise OSError
            snapshot = _read_snapshot_exact(file_owner, maximum_bytes)
            if type(snapshot) is not tuple or len(snapshot) != 3 or type(snapshot[0]) is not bytes:
                raise OSError
            payload = snapshot[0]
            read_before = _require_stat(snapshot[1])
            read_after = _require_stat(snapshot[2])
            opened_after = _require_stat(_fstat_exact(file_owner))
            named_after = _require_stat(_statat_exact(parent_owner, component))
            parent_after = _require_stat(_fstat_exact(parent_owner))
            if (
                read_before != opened_before
                or read_after != opened_before
                or opened_after != opened_before
                or named_after != opened_before
                or parent_after != parent_before
                or len(payload) > maximum_bytes
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
    terminal = _prefer_errors(body_error, transition_error, cleanup_error, retry_error)
    if terminal is not None:
        raise terminal
    if result is None:
        raise OSError
    return result


def _require_absences(
    parent_owner: _OwnedFileDescriptor,
    components: _AbsenceComponents,
    *,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str | bytes], object] = _statat,
    _is_directory: Callable[[int], bool] = stat.S_ISDIR,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
) -> _AbsenceComponents:
    parent_before = _require_stat(_fstat_exact(parent_owner))
    if not _is_directory(parent_before[2]) or type(components) is not tuple:
        raise OSError
    observed: tuple[str, ...] = ()
    for component in components:
        if type(component) is not str or not component:
            raise OSError
        try:
            _statat_exact(parent_owner, component)
        except FileNotFoundError:
            observed += (component,)
            continue
        raise OSError
    if _require_stat(_fstat_exact(parent_owner)) != parent_before:
        raise OSError
    return observed


def _require_tmp_context(
    root_owner: _OwnedFileDescriptor,
    tmp_owner: _OwnedFileDescriptor,
    *,
    root_before: _Stat9,
    tmp_before: _Stat9,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str | bytes], object] = _statat,
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


def _read_tmp_snapshot(
    marker_components: _MarkerComponents,
    absence_components: _AbsenceComponents,
    *,
    _open_root: Callable[[], _OwnedFileDescriptor] = _open_root_directory,
    _open_directory: Callable[
        [_OwnedFileDescriptor, str | bytes], _OwnedFileDescriptor
    ] = _open_child_directory,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str | bytes], object] = _statat,
    _read_regular: Callable[..., _MarkerRead] = _read_regular_snapshot,
    _observe_absences: Callable[..., _AbsenceComponents] = _require_absences,
    _require_context: Callable[..., None] = _require_tmp_context,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
    _cleanup: Callable[[tuple[_OwnedFileDescriptor | None, ...]], BaseException | None] = (
        _cleanup_native_owners
    ),
    _prefer_errors: Callable[..., BaseException | None] = _preferred_cleanup_exceptions,
    _initial_profile: tuple[_MarkerComponents, _AbsenceComponents] = (
        (
            "post-enrollment-start-release",
            "post-enrollment-start-sequence-two-deadline",
        ),
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            ".post-enrollment-start-release-staging",
            ".post-enrollment-start-sequence-two-ready-staging",
        ),
    ),
    _final_profile: tuple[_MarkerComponents, _AbsenceComponents] = (
        (
            "post-enrollment-start-release",
            "post-enrollment-start-sequence-two-deadline",
            "post-enrollment-start-sequence-two-ready",
        ),
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            ".post-enrollment-start-release-staging",
            ".post-enrollment-start-sequence-two-ready-staging",
        ),
    ),
    _ready_profile: tuple[_MarkerComponents, _AbsenceComponents] = (
        ("post-enrollment-start-sequence-two-ready",),
        (".post-enrollment-start-sequence-two-ready-staging",),
    ),
    _deadline_component: str = "post-enrollment-start-sequence-two-deadline",
    _release_component: str = "post-enrollment-start-release",
) -> tuple[_MarkerRead, ...]:
    admitted = (marker_components, absence_components) in (
        _initial_profile,
        _final_profile,
        _ready_profile,
    )
    if (
        type(marker_components) is not tuple
        or type(absence_components) is not tuple
        or not admitted
    ):
        raise OSError
    root_owner: _OwnedFileDescriptor | None = None
    tmp_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    projection: tuple[_MarkerRead, ...] | None = None
    try:
        try:
            root_owner = _open_root()
            root_before = _require_stat(_fstat_exact(root_owner))
            tmp_named_before = _require_stat(_statat_exact(root_owner, "tmp"))
            tmp_owner = _open_directory(root_owner, "tmp")
            tmp_before = _require_stat(_fstat_exact(tmp_owner))
            if tmp_named_before != tmp_before:
                raise OSError
            absent_before = _observe_absences(tmp_owner, absence_components)
            markers: tuple[_MarkerRead, ...] = ()
            for component in marker_components:
                maximum = (
                    512
                    if component == _deadline_component
                    else 41
                    if component == _release_component
                    else 52
                )
                markers += (_read_regular(tmp_owner, component, maximum),)
            absent_after = _observe_absences(tmp_owner, absence_components)
            if absent_before != absence_components or absent_after != absent_before:
                raise OSError
            _require_context(
                root_owner,
                tmp_owner,
                root_before=root_before,
                tmp_before=tmp_before,
            )
            projection = markers
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup((tmp_owner, root_owner))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup((tmp_owner, root_owner))
    terminal = _prefer_errors(body_error, transition_error, cleanup_error, retry_error)
    if terminal is not None:
        raise terminal
    if projection is None:
        raise OSError
    return projection


def _read_initial_markers(
    *,
    _read: Callable[[_MarkerComponents, _AbsenceComponents], tuple[_MarkerRead, ...]] = (
        _read_tmp_snapshot
    ),
) -> _InitialMarkers:
    observed = _read(
        ("post-enrollment-start-release", "post-enrollment-start-sequence-two-deadline"),
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            ".post-enrollment-start-release-staging",
            ".post-enrollment-start-sequence-two-ready-staging",
        ),
    )
    if type(observed) is not tuple or len(observed) != 2:
        raise OSError
    return observed


def _read_final_markers(
    *,
    _read: Callable[[_MarkerComponents, _AbsenceComponents], tuple[_MarkerRead, ...]] = (
        _read_tmp_snapshot
    ),
) -> _FinalMarkers:
    observed = _read(
        (
            "post-enrollment-start-release",
            "post-enrollment-start-sequence-two-deadline",
            "post-enrollment-start-sequence-two-ready",
        ),
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            ".post-enrollment-start-release-staging",
            ".post-enrollment-start-sequence-two-ready-staging",
        ),
    )
    if type(observed) is not tuple or len(observed) != 3:
        raise OSError
    return observed


def _read_boot_id_snapshot(
    *,
    _open_root: Callable[[], _OwnedFileDescriptor] = _open_root_directory,
    _open_directory: Callable[
        [_OwnedFileDescriptor, str | bytes], _OwnedFileDescriptor
    ] = _open_child_directory,
    _fstat_exact: Callable[[_OwnedFileDescriptor], object] = _fstat,
    _statat_exact: Callable[[_OwnedFileDescriptor, str | bytes], object] = _statat,
    _read_regular: Callable[..., _MarkerRead] = _read_regular_snapshot,
    _is_directory: Callable[[int], bool] = stat.S_ISDIR,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
    _cleanup: Callable[[tuple[_OwnedFileDescriptor | None, ...]], BaseException | None] = (
        _cleanup_native_owners
    ),
    _prefer_errors: Callable[..., BaseException | None] = _preferred_cleanup_exceptions,
) -> _MarkerRead:
    root_owner: _OwnedFileDescriptor | None = None
    proc_owner: _OwnedFileDescriptor | None = None
    sys_owner: _OwnedFileDescriptor | None = None
    kernel_owner: _OwnedFileDescriptor | None = None
    random_owner: _OwnedFileDescriptor | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    projection: _MarkerRead | None = None
    try:
        try:
            root_owner = _open_root()
            root_before = _require_stat(_fstat_exact(root_owner))
            proc_named = _require_stat(_statat_exact(root_owner, "proc"))
            proc_owner = _open_directory(root_owner, "proc")
            proc_before = _require_stat(_fstat_exact(proc_owner))
            sys_named = _require_stat(_statat_exact(proc_owner, "sys"))
            sys_owner = _open_directory(proc_owner, "sys")
            sys_before = _require_stat(_fstat_exact(sys_owner))
            kernel_named = _require_stat(_statat_exact(sys_owner, "kernel"))
            kernel_owner = _open_directory(sys_owner, "kernel")
            kernel_before = _require_stat(_fstat_exact(kernel_owner))
            random_named = _require_stat(_statat_exact(kernel_owner, "random"))
            random_owner = _open_directory(kernel_owner, "random")
            random_before = _require_stat(_fstat_exact(random_owner))
            if (
                proc_named != proc_before
                or sys_named != sys_before
                or kernel_named != kernel_before
                or random_named != random_before
                or any(
                    not _is_directory(metadata[2])
                    for metadata in (
                        root_before,
                        proc_before,
                        sys_before,
                        kernel_before,
                        random_before,
                    )
                )
            ):
                raise OSError
            projection = _read_regular(random_owner, "boot_id", 37)
            if (
                _require_stat(_fstat_exact(random_owner)) != random_before
                or _require_stat(_statat_exact(kernel_owner, "random")) != random_before
                or _require_stat(_fstat_exact(kernel_owner)) != kernel_before
                or _require_stat(_statat_exact(sys_owner, "kernel")) != kernel_before
                or _require_stat(_fstat_exact(sys_owner)) != sys_before
                or _require_stat(_statat_exact(proc_owner, "sys")) != sys_before
                or _require_stat(_fstat_exact(proc_owner)) != proc_before
                or _require_stat(_statat_exact(root_owner, "proc")) != proc_before
                or _require_stat(_fstat_exact(root_owner)) != root_before
            ):
                raise OSError
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup(
                (random_owner, kernel_owner, sys_owner, proc_owner, root_owner)
            )
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup((random_owner, kernel_owner, sys_owner, proc_owner, root_owner))
    terminal = _prefer_errors(body_error, transition_error, cleanup_error, retry_error)
    if terminal is not None:
        raise terminal
    if projection is None:
        raise OSError
    return projection


def _require_fixed_marker(
    value: object,
    *,
    expected_payload: bytes,
    _is_regular: Callable[[int], bool] = stat.S_ISREG,
    _mode_bits: Callable[[int], int] = stat.S_IMODE,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
) -> _MarkerRead:
    if (
        type(value) is not tuple
        or len(value) != 2
        or type(tuple.__getitem__(value, 0)) is not bytes
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime marker is invalid")
    payload = tuple.__getitem__(value, 0)
    metadata = _require_stat(tuple.__getitem__(value, 1))
    if (
        type(expected_payload) is not bytes
        or payload != expected_payload
        or not _is_regular(metadata[2])
        or _mode_bits(metadata[2]) != 0o400
        or metadata[3] != 10_001
        or metadata[4] != 10_001
        or metadata[5] != 1
        or metadata[6] != len(payload)
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime marker is invalid")
    return cast(_MarkerRead, value)


def _require_deadline_marker(
    value: object,
    *,
    _is_regular: Callable[[int], bool] = stat.S_ISREG,
    _mode_bits: Callable[[int], int] = stat.S_IMODE,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
) -> _MarkerRead:
    if (
        type(value) is not tuple
        or len(value) != 2
        or type(tuple.__getitem__(value, 0)) is not bytes
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    payload = tuple.__getitem__(value, 0)
    metadata = _require_stat(tuple.__getitem__(value, 1))
    if (
        not 0 < len(payload) <= 512
        or not _is_regular(metadata[2])
        or _mode_bits(metadata[2]) != 0o400
        or metadata[3] != 10_001
        or metadata[4] != 10_001
        or metadata[5] != 1
        or metadata[6] != len(payload)
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    return cast(_MarkerRead, value)


def _require_boot_id_marker(
    value: object,
    *,
    _is_regular: Callable[[int], bool] = stat.S_ISREG,
    _require_stat: Callable[[object], _Stat9] = _require_stat9,
) -> _MarkerRead:
    if (
        type(value) is not tuple
        or len(value) != 2
        or type(tuple.__getitem__(value, 0)) is not bytes
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime boot identity is invalid")
    payload = tuple.__getitem__(value, 0)
    metadata = _require_stat(tuple.__getitem__(value, 1))
    if (
        len(payload) != 37
        or payload[36] != 10
        or any(payload[index] != 45 for index in (8, 13, 18, 23))
        or any(
            byte not in b"0123456789abcdef"
            for index, byte in enumerate(payload[:36])
            if index not in (8, 13, 18, 23)
        )
        or not _is_regular(metadata[2])
        or metadata[5] != 1
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime boot identity is invalid")
    return cast(_MarkerRead, value)


def _read_ready_marker(
    *,
    _read: Callable[[_MarkerComponents, _AbsenceComponents], tuple[_MarkerRead, ...]] = (
        _read_tmp_snapshot
    ),
    _require_ready: Callable[..., _MarkerRead] = _require_fixed_marker,
    _expected_payload: bytes = _READY_BYTES,
) -> _MarkerRead:
    observed = _read(
        ("post-enrollment-start-sequence-two-ready",),
        (".post-enrollment-start-sequence-two-ready-staging",),
    )
    if type(observed) is not tuple or len(observed) != 1:
        raise OSError
    return _require_ready(
        tuple.__getitem__(observed, 0),
        expected_payload=_expected_payload,
    )


def _sha256_hex_bytes(
    payload: bytes,
    *,
    _sha256: Callable[[bytes], object] = hashlib.sha256,
) -> bytes:
    if type(payload) is not bytes:
        raise TrustedTimeSupervisorConfigurationError("runtime digest input is invalid")
    digest = _sha256(payload)
    hexdigest = digest.hexdigest()  # type: ignore[attr-defined]
    if (
        type(hexdigest) is not str
        or len(hexdigest) != 64
        or any(character not in "0123456789abcdef" for character in hexdigest)
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime digest is invalid")
    return hexdigest.encode("ascii", errors="strict")


def _parse_decimal(payload: bytes) -> int:
    if type(payload) is not bytes or not payload or (len(payload) > 1 and payload[0] == 48):
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    value = 0
    for byte in payload:
        if byte < 48 or byte > 57:
            raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
        value = value * 10 + byte - 48
        if value > 2**63 - 1:
            raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    return value


def _parse_deadline_marker(
    marker: object,
    boot_marker: object,
    *,
    _require_deadline: Callable[[object], _MarkerRead] = _require_deadline_marker,
    _require_boot: Callable[[object], _MarkerRead] = _require_boot_id_marker,
    _digest: Callable[[bytes], bytes] = _sha256_hex_bytes,
    _parse_number: Callable[[bytes], int] = _parse_decimal,
    _prefix: bytes = _DEADLINE_PREFIX,
    _after_boot: bytes = _DEADLINE_AFTER_BOOT,
    _before_issued: bytes = _DEADLINE_BEFORE_ISSUED,
    _suffix: bytes = _DEADLINE_SUFFIX,
) -> _DeadlineProjection:
    deadline_payload = cast(bytes, tuple.__getitem__(_require_deadline(marker), 0))
    boot_payload = cast(bytes, tuple.__getitem__(_require_boot(boot_marker), 0))
    boot_sha256 = _digest(boot_payload)
    if not deadline_payload.startswith(_prefix):
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    cursor = len(_prefix)
    encoded_boot = deadline_payload[cursor : cursor + 64]
    if encoded_boot != boot_sha256:
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    cursor += 64
    if deadline_payload[cursor : cursor + len(_after_boot)] != _after_boot:
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    cursor += len(_after_boot)
    deadline_end = deadline_payload.find(_before_issued, cursor)
    if deadline_end < 0:
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    deadline = _parse_number(deadline_payload[cursor:deadline_end])
    cursor = deadline_end + len(_before_issued)
    issued_end = deadline_payload.find(_suffix, cursor)
    if issued_end < 0 or issued_end + len(_suffix) != len(deadline_payload):
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    issued = _parse_number(deadline_payload[cursor:issued_end])
    if deadline - issued != 120_000_000_000:
        raise TrustedTimeSupervisorConfigurationError("runtime deadline marker is invalid")
    return deadline, _digest(deadline_payload)


def _boottime_ns(
    *,
    _clock_id: object = getattr(time, "CLOCK_BOOTTIME", None),
    _clock_gettime_ns: Callable[[int], object] = time.clock_gettime_ns,
) -> int:
    if type(_clock_id) is not int:
        raise TrustedTimeSupervisorConfigurationError("runtime clock is unavailable")
    try:
        observed = _clock_gettime_ns(_clock_id)
    except (OSError, ValueError):
        raise TrustedTimeSupervisorConfigurationError("runtime clock is unavailable") from None
    if type(observed) is not int or observed < 0:
        raise TrustedTimeSupervisorConfigurationError("runtime clock is invalid")
    return observed


def _wait_for_ready_marker(
    deadline_monotonic_ns: int,
    *,
    _clock: Callable[[], int] = _boottime_ns,
    _sleep: Callable[[float], None] = time.sleep,
    _read_ready: Callable[[], _MarkerRead] = _read_ready_marker,
) -> _MarkerRead:
    if (
        type(deadline_monotonic_ns) is not int
        or deadline_monotonic_ns < 120_000_000_000
        or not callable(_clock)
        or not callable(_sleep)
        or not callable(_read_ready)
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime wait dependencies are invalid")
    issued_at = deadline_monotonic_ns - 120_000_000_000
    observed = _clock()
    if type(observed) is not int or observed < issued_at:
        raise TrustedTimeSupervisorConfigurationError("runtime clock predates release")
    polls = 0
    while observed < deadline_monotonic_ns and polls < 1_200:
        polls += 1
        try:
            ready = _read_ready()
        except FileNotFoundError:
            ready = None
        if ready is not None:
            confirmed = _clock()
            if type(confirmed) is not int or confirmed < observed:
                raise TrustedTimeSupervisorConfigurationError("runtime clock regressed")
            if confirmed >= deadline_monotonic_ns:
                break
            return ready
        try:
            _sleep(min(0.1, (deadline_monotonic_ns - observed) / 1_000_000_000))
            current = _clock()
        except Exception:
            raise TrustedTimeSupervisorConfigurationError("runtime clock failed") from None
        if type(current) is not int or current <= observed:
            raise TrustedTimeSupervisorConfigurationError("runtime clock did not advance")
        observed = current
    raise TrustedTimeSupervisorConfigurationError("runtime ready marker deadline expired")


def _read_runtime_state_projection(
    *,
    _read_initial: Callable[[], _InitialMarkers] = _read_initial_markers,
    _read_boot: Callable[[], _MarkerRead] = _read_boot_id_snapshot,
    _wait_ready: Callable[[int], _MarkerRead] = _wait_for_ready_marker,
    _read_final: Callable[[], _FinalMarkers] = _read_final_markers,
    _require_fixed: Callable[..., _MarkerRead] = _require_fixed_marker,
    _require_deadline: Callable[[object], _MarkerRead] = _require_deadline_marker,
    _require_boot: Callable[[object], _MarkerRead] = _require_boot_id_marker,
    _parse_deadline: Callable[[object, object], _DeadlineProjection] = _parse_deadline_marker,
    _release_payload: bytes = _RELEASE_BYTES,
    _ready_payload: bytes = _READY_BYTES,
) -> _RuntimeStateProjection:
    initial = _read_initial()
    if type(initial) is not tuple or len(initial) != 2:
        raise TrustedTimeSupervisorConfigurationError("runtime initial markers are invalid")
    initial_release = _require_fixed(
        tuple.__getitem__(initial, 0),
        expected_payload=_release_payload,
    )
    initial_deadline = _require_deadline(tuple.__getitem__(initial, 1))
    initial_boot = _require_boot(_read_boot())
    initial_projection = _parse_deadline(initial_deadline, initial_boot)
    if (
        type(initial_projection) is not tuple
        or len(initial_projection) != 2
        or type(tuple.__getitem__(initial_projection, 0)) is not int
        or type(tuple.__getitem__(initial_projection, 1)) is not bytes
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime deadline projection is invalid")
    deadline = cast(int, tuple.__getitem__(initial_projection, 0))
    deadline_sha256 = cast(bytes, tuple.__getitem__(initial_projection, 1))
    waited_ready = _require_fixed(
        _wait_ready(deadline),
        expected_payload=_ready_payload,
    )

    final = _read_final()
    if type(final) is not tuple or len(final) != 3:
        raise TrustedTimeSupervisorConfigurationError("runtime final markers are invalid")
    final_release = _require_fixed(
        tuple.__getitem__(final, 0),
        expected_payload=_release_payload,
    )
    final_deadline = _require_deadline(tuple.__getitem__(final, 1))
    final_ready = _require_fixed(
        tuple.__getitem__(final, 2),
        expected_payload=_ready_payload,
    )
    final_boot = _require_boot(_read_boot())
    final_projection = _parse_deadline(final_deadline, final_boot)
    if (
        type(final_projection) is not tuple
        or len(final_projection) != 2
        or initial_release != final_release
        or initial_deadline != final_deadline
        or initial_boot != final_boot
        or final_projection != (deadline, deadline_sha256)
        or waited_ready != final_ready
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime markers changed")
    rechecked_ready = _require_fixed(_wait_ready(deadline), expected_payload=_ready_payload)
    if rechecked_ready != final_ready:
        raise TrustedTimeSupervisorConfigurationError("runtime ready marker changed")
    return "trusted-time-runtime-state-projection-v1", deadline, deadline_sha256


def _runtime_state_bytes(
    *,
    _observe: Callable[[], _RuntimeStateProjection] = _read_runtime_state_projection,
    _prefix: bytes = _RUNTIME_STATE_PREFIX,
    _suffix: bytes = _RUNTIME_STATE_SUFFIX,
) -> bytes:
    projection = _observe()
    if type(projection) is not tuple or len(projection) != 3:
        raise TrustedTimeSupervisorConfigurationError("runtime projection is invalid")
    tag = tuple.__getitem__(projection, 0)
    deadline = tuple.__getitem__(projection, 1)
    deadline_sha256 = tuple.__getitem__(projection, 2)
    if (
        tag != "trusted-time-runtime-state-projection-v1"
        or type(deadline) is not int
        or deadline < 120_000_000_000
        or type(deadline_sha256) is not bytes
        or len(deadline_sha256) != 64
        or any(byte not in b"0123456789abcdef" for byte in deadline_sha256)
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime projection is invalid")
    return _prefix + deadline_sha256 + _suffix


def read_post_enrollment_runtime_state(
    *,
    _read_bytes: Callable[[], bytes] = _runtime_state_bytes,
) -> dict[str, object]:
    """Return a secondary compatibility projection; CLI authority uses raw bytes."""

    encoded = _read_bytes()
    if (
        type(encoded) is not bytes
        or not encoded.startswith(_RUNTIME_STATE_PREFIX)
        or not encoded.endswith(_RUNTIME_STATE_SUFFIX)
        or len(encoded) != len(_RUNTIME_STATE_PREFIX) + 64 + len(_RUNTIME_STATE_SUFFIX)
    ):
        raise TrustedTimeSupervisorConfigurationError("runtime receipt is invalid")
    deadline_sha256 = encoded[len(_RUNTIME_STATE_PREFIX) : len(_RUNTIME_STATE_PREFIX) + 64].decode(
        "ascii", errors="strict"
    )
    return {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "contract_version": "phase6d-post-enrollment-runtime-state-v1",
        "exposure_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "release_marker_sha256": _RELEASE_SHA256_BYTES.decode("ascii"),
        "sequence_two_deadline_marker_sha256": deadline_sha256,
        "sequence_two_ready_marker_sha256": _READY_SHA256_BYTES.decode("ascii"),
        "service": "trusted-time-supervisor",
        "status": "sequence_two_ready_observed",
    }


def runtime_state_main(
    *,
    _emit: Callable[[], bytes] = _runtime_state_bytes,
) -> None:
    """Emit one exact receipt for the fixed operational launcher target."""

    stdout_write = sys.stdout.write
    stderr_write = sys.stderr.write
    try:
        if type(sys.argv) is not list or sys.argv != ["post-enrollment-runtime-state"]:
            raise ValueError
        encoded = _emit()
        if type(encoded) is not bytes:
            raise ValueError
        stdout_write(encoded.decode("ascii", errors="strict"))
    except Exception:
        stderr_write("trusted-time post-enrollment runtime state probe failed\n")
        raise SystemExit(2) from None


if __name__ == "__main__":
    runtime_state_main()


__all__ = (
    "POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION",
    "POST_ENROLLMENT_RUNTIME_STATE_STATUS",
    "read_post_enrollment_runtime_state",
    "runtime_state_main",
)
