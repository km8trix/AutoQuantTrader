"""One-shot in-container barrier for a future approved post-enrollment start."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)
from apps.trusted_time_supervisor.post_enrollment_sequence_two_ready import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
)

POST_ENROLLMENT_START_RELEASE_PATH = "/tmp/post-enrollment-start-release"
POST_ENROLLMENT_START_RELEASE_STAGING_PATH = "/tmp/.post-enrollment-start-release-staging"
POST_ENROLLMENT_START_RELEASE_WAIT_SECONDS = 120.0
POST_ENROLLMENT_START_RELEASE_POLL_SECONDS = 0.1
POST_ENROLLMENT_START_RELEASE_MAXIMUM_POLLS = 1_200
POST_ENROLLMENT_START_RELEASE_BYTES = b"phase6d-post-enrollment-start-release-v1\n"
POST_ENROLLMENT_START_RELEASE_SHA256 = hashlib.sha256(
    POST_ENROLLMENT_START_RELEASE_BYTES
).hexdigest()
POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-sequence-two-deadline-v1"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH = (
    "/tmp/post-enrollment-start-sequence-two-deadline"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH = (
    "/tmp/.post-enrollment-start-sequence-two-deadline-staging"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_SECONDS = 120
POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS = 120_000_000_000
_POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_MAXIMUM_BYTES = 512
_LINUX_BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
_LINUX_BOOT_ID_PATTERN = re.compile(
    rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n"
)


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentSequenceTwoDeadlineReceipt:
    """Stable digest-only identity plus the internal absolute wait cutoff."""

    deadline_monotonic_ns: int
    marker_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.deadline_monotonic_ns) is not int
            or self.deadline_monotonic_ns
            < POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
            or type(self.marker_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.marker_sha256) is None
        ):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment sequence-two deadline receipt is invalid"
            )


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _exact_release_metadata(metadata: os.stat_result, *, link_count: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink == link_count
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and metadata.st_size == len(POST_ENROLLMENT_START_RELEASE_BYTES)
    )


def _boottime_monotonic_ns() -> int:
    """Read the Linux suspend-aware clock shared by all container processes."""

    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if type(clock_id) is not int:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline clock is unavailable"
        )
    try:
        observed = time.clock_gettime_ns(clock_id)
    except (OSError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline clock is unavailable"
        ) from None
    if type(observed) is not int or observed < 0:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline clock is invalid"
        )
    return observed


def _read_linux_boot_id_sha256() -> str:
    """Bind deadline evidence to the current Linux boot without exposing it."""

    descriptor: int | None = None
    try:
        descriptor = os.open(
            _LINUX_BOOT_ID_PATH,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        payload = os.read(descriptor, 38)
        if os.read(descriptor, 1):
            raise OSError
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not _same_inode(before, after)
            or _stable_identity(before) != _stable_identity(after)
            or _LINUX_BOOT_ID_PATTERN.fullmatch(payload) is None
        ):
            raise OSError
        return hashlib.sha256(payload).hexdigest()
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline boot identity is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment sequence-two deadline boot identity "
                    "is unavailable"
                ) from None


def _deadline_bytes(
    *,
    boot_id_sha256: str,
    issued_at_boottime_ns: int,
    deadline_boottime_ns: int,
) -> bytes:
    return (
        json.dumps(
            {
                "boot_id_sha256": boot_id_sha256,
                "contract_version": (POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_CONTRACT_VERSION),
                "deadline_boottime_ns": deadline_boottime_ns,
                "issued_at_boottime_ns": issued_at_boottime_ns,
                "release_marker_sha256": POST_ENROLLMENT_START_RELEASE_SHA256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _exact_deadline_metadata(metadata: os.stat_result, *, link_count: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink == link_count
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and 0 < metadata.st_size <= _POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_MAXIMUM_BYTES
    )


def _fsync_parent_directory(path: str) -> None:
    descriptor = os.open(
        os.path.dirname(path),
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_release_names_absent_for_deadline() -> None:
    for path in (
        POST_ENROLLMENT_START_RELEASE_PATH,
        POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
        POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
        POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
    ):
        try:
            os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment sequence-two deadline precondition failed"
            ) from None
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline precondition failed"
        )


def _require_deadline_staging_absent() -> None:
    try:
        os.stat(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise OSError


def write_post_enrollment_start_sequence_two_deadline(
    *,
    monotonic_clock: Callable[[], int] = _boottime_monotonic_ns,
    boot_id_reader: Callable[[], str] | None = None,
) -> int:
    """Publish the one-shot absolute CLOCK_BOOTTIME deadline before release."""

    if not callable(monotonic_clock) or (
        boot_id_reader is not None and not callable(boot_id_reader)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline dependencies are invalid"
        )
    _require_release_names_absent_for_deadline()
    read_boot_id = _read_linux_boot_id_sha256 if boot_id_reader is None else boot_id_reader
    try:
        issued_at = monotonic_clock()
        boot_id_sha256 = read_boot_id()
    except TrustedTimeSupervisorConfigurationError:
        raise
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline clock failed"
        ) from None
    if (
        type(issued_at) is not int
        or issued_at < 0
        or type(boot_id_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", boot_id_sha256) is None
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline clock is invalid"
        )
    deadline = issued_at + POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
    if deadline <= issued_at or deadline > (2**63 - 1):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline clock is invalid"
        )
    payload = _deadline_bytes(
        boot_id_sha256=boot_id_sha256,
        issued_at_boottime_ns=issued_at,
        deadline_boottime_ns=deadline,
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if not _exact_deadline_metadata(staged, link_count=1) or staged.st_size != len(payload):
            raise OSError
        if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
            raise OSError
        if os.read(descriptor, len(payload) + 1) != payload or os.read(descriptor, 1):
            raise OSError
        if _stable_identity(staged) != _stable_identity(os.fstat(descriptor)):
            raise OSError
        os.link(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
            follow_symlinks=False,
        )
        _fsync_parent_directory(POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH)
        linked = os.stat(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
            follow_symlinks=False,
        )
        staged_linked = os.fstat(descriptor)
        if (
            not _same_inode(staged, staged_linked)
            or _stable_identity(linked) != _stable_identity(staged_linked)
            or not _exact_deadline_metadata(staged_linked, link_count=2)
        ):
            raise OSError
        os.unlink(POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH)
        _fsync_parent_directory(POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH)
        published = os.fstat(descriptor)
        named = os.stat(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
            follow_symlinks=False,
        )
        if _stable_identity(published) != _stable_identity(named) or not _exact_deadline_metadata(
            published, link_count=1
        ):
            raise OSError
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline publication failed"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment sequence-two deadline publication failed"
                ) from None
    return deadline


def read_exact_post_enrollment_start_sequence_two_deadline_receipt(
    *,
    boot_id_reader: Callable[[], str] | None = None,
) -> TrustedTimePostEnrollmentSequenceTwoDeadlineReceipt:
    """Return the stable canonical marker digest and its internal cutoff."""

    if boot_id_reader is not None and not callable(boot_id_reader):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline dependencies are invalid"
        )
    read_boot_id = _read_linux_boot_id_sha256 if boot_id_reader is None else boot_id_reader
    descriptor: int | None = None
    try:
        _require_deadline_staging_absent()
        descriptor = os.open(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        payload = os.read(
            descriptor,
            _POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_MAXIMUM_BYTES + 1,
        )
        if os.read(descriptor, 1):
            raise OSError
        after = os.fstat(descriptor)
        named = os.stat(
            POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
            follow_symlinks=False,
        )
        if (
            len(payload) > _POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_MAXIMUM_BYTES
            or not _same_inode(before, after)
            or _stable_identity(before) != _stable_identity(after)
            or _stable_identity(after) != _stable_identity(named)
            or not _exact_deadline_metadata(after, link_count=1)
            or after.st_size != len(payload)
        ):
            raise OSError
        decoded = json.loads(payload)
        if type(decoded) is not dict or set(decoded) != {
            "boot_id_sha256",
            "contract_version",
            "deadline_boottime_ns",
            "issued_at_boottime_ns",
            "release_marker_sha256",
        }:
            raise OSError
        issued_at = decoded.get("issued_at_boottime_ns")
        deadline = decoded.get("deadline_boottime_ns")
        current_boot_id_sha256 = read_boot_id()
        if (
            type(current_boot_id_sha256) is not str
            or decoded.get("boot_id_sha256") != current_boot_id_sha256
            or re.fullmatch(r"[0-9a-f]{64}", current_boot_id_sha256) is None
            or decoded.get("contract_version")
            != POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_CONTRACT_VERSION
            or decoded.get("release_marker_sha256") != POST_ENROLLMENT_START_RELEASE_SHA256
            or type(issued_at) is not int
            or type(deadline) is not int
            or issued_at < 0
            or deadline - issued_at
            != POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
            or deadline > (2**63 - 1)
            or _deadline_bytes(
                boot_id_sha256=current_boot_id_sha256,
                issued_at_boottime_ns=issued_at,
                deadline_boottime_ns=deadline,
            )
            != payload
        ):
            raise OSError
        _require_deadline_staging_absent()
        return TrustedTimePostEnrollmentSequenceTwoDeadlineReceipt(
            deadline_monotonic_ns=deadline,
            marker_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline is invalid"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment sequence-two deadline is invalid"
                ) from None


def read_exact_post_enrollment_start_sequence_two_deadline(
    *,
    boot_id_reader: Callable[[], str] | None = None,
) -> int:
    """Return only the canonical stable owner-only 120-second deadline."""

    return read_exact_post_enrollment_start_sequence_two_deadline_receipt(
        boot_id_reader=boot_id_reader,
    ).deadline_monotonic_ns


def write_post_enrollment_start_release(
    *,
    deadline_monotonic_ns: int | None = None,
    monotonic_clock: Callable[[], int] = _boottime_monotonic_ns,
) -> None:
    """Atomically publish the fixed marker once inside the staged container."""

    if not callable(monotonic_clock) or (
        deadline_monotonic_ns is not None
        and (
            type(deadline_monotonic_ns) is not int
            or deadline_monotonic_ns
            < POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release dependencies are invalid"
        )
    last_observed: int | None = None

    def require_open_deadline() -> None:
        nonlocal last_observed
        _require_sequence_two_ready_names_absent()
        if deadline_monotonic_ns is None:
            return
        try:
            observed = monotonic_clock()
        except Exception:
            raise OSError from None
        issued_at = (
            deadline_monotonic_ns - POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS
        )
        if (
            type(observed) is not int
            or observed < issued_at
            or observed >= deadline_monotonic_ns
            or (last_observed is not None and observed < last_observed)
        ):
            raise OSError
        last_observed = observed

    descriptor: int | None = None
    publication_committed = False
    try:
        require_open_deadline()
        descriptor = os.open(
            POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        view = memoryview(POST_ENROLLMENT_START_RELEASE_BYTES)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if not _exact_release_metadata(staged, link_count=1):
            raise OSError
        require_open_deadline()
        os.link(
            POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
            POST_ENROLLMENT_START_RELEASE_PATH,
            follow_symlinks=False,
        )
        linked = os.stat(POST_ENROLLMENT_START_RELEASE_PATH, follow_symlinks=False)
        staged_linked = os.fstat(descriptor)
        if (
            not _same_inode(staged, staged_linked)
            or _stable_identity(linked) != _stable_identity(staged_linked)
            or not _exact_release_metadata(staged_linked, link_count=2)
        ):
            raise OSError
        _fsync_parent_directory(POST_ENROLLMENT_START_RELEASE_PATH)
        require_open_deadline()
        os.unlink(POST_ENROLLMENT_START_RELEASE_STAGING_PATH)
        publication_committed = True
        try:
            require_open_deadline()
        except OSError:
            try:
                os.link(
                    POST_ENROLLMENT_START_RELEASE_PATH,
                    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
                    follow_symlinks=False,
                )
            except OSError:
                with suppress(OSError):
                    os.unlink(POST_ENROLLMENT_START_RELEASE_PATH)
            with suppress(OSError):
                _fsync_parent_directory(POST_ENROLLMENT_START_RELEASE_PATH)
            raise
        # The final link was synced before the staging name was removed. A
        # crash can therefore leave a pending two-link marker, which the exact
        # reader rejects, but cannot silently lose the final link.
        with suppress(OSError):
            _fsync_parent_directory(POST_ENROLLMENT_START_RELEASE_PATH)
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release failed"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                if not publication_committed:
                    raise TrustedTimeSupervisorConfigurationError(
                        "trusted-time post-enrollment start release failed"
                    ) from None


def _require_release_staging_absent() -> None:
    try:
        os.stat(
            POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise FileNotFoundError


def _require_sequence_two_ready_names_absent() -> None:
    for path in (
        POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
        POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
    ):
        try:
            os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise OSError


def read_exact_post_enrollment_start_release() -> None:
    """Require the exact stable owner-only marker and no trailing byte."""

    descriptor: int | None = None
    try:
        _require_release_staging_absent()
        descriptor = os.open(
            POST_ENROLLMENT_START_RELEASE_PATH,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        payload = os.read(descriptor, len(POST_ENROLLMENT_START_RELEASE_BYTES) + 1)
        if os.read(descriptor, 1):
            raise OSError
        after = os.fstat(descriptor)
        if (
            not _same_inode(before, after)
            or payload != POST_ENROLLMENT_START_RELEASE_BYTES
            or before.st_size != len(payload)
        ):
            raise OSError
        if before.st_nlink == 1 and after.st_nlink == 1:
            if _stable_identity(before) != _stable_identity(after) or not _exact_release_metadata(
                after, link_count=1
            ):
                raise OSError
            _require_release_staging_absent()
            return
        if before.st_nlink == 2 and after.st_nlink == 1:
            named = os.stat(POST_ENROLLMENT_START_RELEASE_PATH, follow_symlinks=False)
            if (
                not _exact_release_metadata(before, link_count=2)
                or not _exact_release_metadata(after, link_count=1)
                or _stable_identity(after) != _stable_identity(named)
            ):
                raise OSError
            _require_release_staging_absent()
            return
        if (
            before.st_nlink != 2
            or after.st_nlink != 2
            or _stable_identity(before) != _stable_identity(after)
            or not _exact_release_metadata(after, link_count=2)
        ):
            raise OSError
        try:
            staging = os.stat(
                POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            named = os.stat(POST_ENROLLMENT_START_RELEASE_PATH, follow_symlinks=False)
            if not _same_inode(after, named) or not _exact_release_metadata(named, link_count=1):
                raise OSError from None
            _require_release_staging_absent()
            return
        if _stable_identity(staging) != _stable_identity(after) or not _exact_release_metadata(
            staging, link_count=2
        ):
            raise OSError
        raise FileNotFoundError
    except FileNotFoundError:
        raise
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release is invalid"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment start release is invalid"
                ) from None


def wait_for_post_enrollment_start_release(
    *,
    monotonic_clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Wait a bounded monotonic interval for the exact one-shot marker."""

    if not callable(monotonic_clock) or not callable(sleeper):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release dependencies are invalid"
        )
    try:
        started = float(monotonic_clock())
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release clock failed"
        ) from None
    if not math.isfinite(started):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release clock failed"
        )
    deadline = started + POST_ENROLLMENT_START_RELEASE_WAIT_SECONDS
    if not math.isfinite(deadline) or deadline <= started:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release clock failed"
        )
    observed = started
    polls = 0
    while observed < deadline and polls < POST_ENROLLMENT_START_RELEASE_MAXIMUM_POLLS:
        polls += 1
        try:
            read_exact_post_enrollment_start_release()
            return
        except FileNotFoundError:
            pass
        try:
            sleeper(min(POST_ENROLLMENT_START_RELEASE_POLL_SECONDS, deadline - observed))
            current = float(monotonic_clock())
        except Exception:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment start release clock failed"
            ) from None
        if not math.isfinite(current):
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment start release clock failed"
            )
        if current < observed:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment start release clock regressed"
            )
        if current == observed:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment start release clock did not advance"
            )
        observed = current
    raise TrustedTimeSupervisorConfigurationError(
        "trusted-time post-enrollment start release was not observed"
    )


def release_main() -> None:
    """Fix the shared deadline before publishing the one-shot release marker."""

    parser = argparse.ArgumentParser(
        description="Release one staged post-enrollment trusted-time supervisor."
    )
    parser.parse_args()
    try:
        deadline_monotonic_ns = write_post_enrollment_start_sequence_two_deadline()
        write_post_enrollment_start_release(deadline_monotonic_ns=deadline_monotonic_ns)
    except TrustedTimeSupervisorConfigurationError:
        raise SystemExit(2) from None


__all__ = [
    "POST_ENROLLMENT_START_RELEASE_BYTES",
    "POST_ENROLLMENT_START_RELEASE_MAXIMUM_POLLS",
    "POST_ENROLLMENT_START_RELEASE_PATH",
    "POST_ENROLLMENT_START_RELEASE_POLL_SECONDS",
    "POST_ENROLLMENT_START_RELEASE_SHA256",
    "POST_ENROLLMENT_START_RELEASE_STAGING_PATH",
    "POST_ENROLLMENT_START_RELEASE_WAIT_SECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_NANOSECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_WINDOW_SECONDS",
    "TrustedTimePostEnrollmentSequenceTwoDeadlineReceipt",
    "read_exact_post_enrollment_start_release",
    "read_exact_post_enrollment_start_sequence_two_deadline",
    "read_exact_post_enrollment_start_sequence_two_deadline_receipt",
    "release_main",
    "wait_for_post_enrollment_start_release",
    "write_post_enrollment_start_release",
    "write_post_enrollment_start_sequence_two_deadline",
]
