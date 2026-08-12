"""Atomic fixed marker for the bounded post-enrollment sequence-two terminal."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from collections.abc import Callable
from contextlib import suppress

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)

POST_ENROLLMENT_START_SEQUENCE_TWO_READY_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-sequence-two-ready-v1"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH = "/tmp/post-enrollment-start-sequence-two-ready"
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH = (
    "/tmp/.post-enrollment-start-sequence-two-ready-staging"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_SECONDS = 120.0
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_NANOSECONDS = 120_000_000_000
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_POLL_SECONDS = 0.1
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_MAXIMUM_POLLS = 1_200
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_SECONDS = 5.0
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_NANOSECONDS = 5_000_000_000
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES = (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_CONTRACT_VERSION.encode("ascii") + b"\n"
)
POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256 = hashlib.sha256(
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES
).hexdigest()


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


def _exact_ready_metadata(metadata: os.stat_result, *, link_count: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == 0o400
        and metadata.st_nlink == link_count
        and metadata.st_uid == os.geteuid()
        and metadata.st_gid == os.getegid()
        and metadata.st_size == len(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES)
    )


def _boottime_monotonic_ns() -> int:
    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if type(clock_id) is not int:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready clock is unavailable"
        )
    try:
        observed = time.clock_gettime_ns(clock_id)
    except (OSError, ValueError):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready clock is unavailable"
        ) from None
    if type(observed) is not int or observed < 0:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready clock is invalid"
        )
    return observed


def _read_clock(clock: Callable[[], int]) -> int:
    try:
        observed = clock()
    except TrustedTimeSupervisorConfigurationError:
        raise
    except Exception:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready clock failed"
        ) from None
    if type(observed) is not int or observed < 0:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready clock failed"
        )
    return observed


def _fsync_parent_directory(path: str, *, suppress_failure: bool = False) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            os.path.dirname(path),
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        os.fsync(descriptor)
    except OSError:
        if not suppress_failure:
            raise
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                if not suppress_failure:
                    raise


def _require_ready_staging_absent() -> None:
    try:
        os.stat(
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise FileNotFoundError


def write_post_enrollment_start_sequence_two_ready(
    *,
    publication_deadline_monotonic_ns: int | None = None,
    monotonic_clock: Callable[[], int] = time.monotonic_ns,
) -> None:
    """Publish one payload-free owner-only marker after exact terminal success."""

    if not callable(monotonic_clock) or (
        publication_deadline_monotonic_ns is not None
        and (
            type(publication_deadline_monotonic_ns) is not int
            or publication_deadline_monotonic_ns < 0
        )
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready dependencies are invalid"
        )
    started_at = _read_clock(monotonic_clock)
    local_deadline = (
        started_at + POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_NANOSECONDS
    )
    deadline = min(
        local_deadline,
        publication_deadline_monotonic_ns
        if publication_deadline_monotonic_ns is not None
        else local_deadline,
    )
    if deadline <= started_at:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready publication deadline expired"
        )

    last_observed = started_at

    def observe_open_deadline() -> int:
        nonlocal last_observed
        observed = _read_clock(monotonic_clock)
        if observed < last_observed or observed >= deadline:
            raise OSError
        last_observed = observed
        return observed

    descriptor: int | None = None
    publication_committed = False
    try:
        observe_open_deadline()
        descriptor = os.open(
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        view = memoryview(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        observe_open_deadline()
        before_readback = os.fstat(descriptor)
        if not _exact_ready_metadata(before_readback, link_count=1):
            raise OSError
        if os.lseek(descriptor, 0, os.SEEK_SET) != 0:
            raise OSError
        payload = os.read(
            descriptor,
            len(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES) + 1,
        )
        if os.read(descriptor, 1):
            raise OSError
        after_readback = os.fstat(descriptor)
        if payload != POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES or _stable_identity(
            before_readback
        ) != _stable_identity(after_readback):
            raise OSError
        observe_open_deadline()
        os.link(
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
            follow_symlinks=False,
        )
        linked = os.stat(
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
            follow_symlinks=False,
        )
        staged_linked = os.fstat(descriptor)
        if (
            not _same_inode(after_readback, staged_linked)
            or _stable_identity(linked) != _stable_identity(staged_linked)
            or not _exact_ready_metadata(staged_linked, link_count=2)
        ):
            raise OSError
        _fsync_parent_directory(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH)
        observe_open_deadline()
        # Unlinking the staging name is the only visibility commit. All
        # operations that can reject publication occur before this point.
        os.unlink(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH)
        publication_committed = True
        try:
            observe_open_deadline()
        except (OSError, TrustedTimeSupervisorConfigurationError):
            # Make a late visibility commit unqualified before reporting the
            # failure. The final name is this writer's exact inode.
            try:
                os.link(
                    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
                    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
                    follow_symlinks=False,
                )
                _fsync_parent_directory(
                    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
                    suppress_failure=True,
                )
            except OSError:
                with suppress(OSError):
                    os.unlink(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH)
                _fsync_parent_directory(
                    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
                    suppress_failure=True,
                )
            raise OSError from None
        # The final link was directory-synced while both names existed. A
        # crash before this best-effort unlink sync leaves either the exact
        # final marker or a two-link pending marker that readers reject.
        _fsync_parent_directory(
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
            suppress_failure=True,
        )
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready publication failed"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                if not publication_committed:
                    raise TrustedTimeSupervisorConfigurationError(
                        "trusted-time post-enrollment sequence-two-ready publication failed"
                    ) from None


def read_exact_post_enrollment_start_sequence_two_ready() -> None:
    """Require the exact stable owner-only marker and no trailing byte."""

    descriptor: int | None = None
    try:
        # A live or abandoned writer makes every final name unqualified.
        _require_ready_staging_absent()
        descriptor = os.open(
            POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        payload = os.read(
            descriptor,
            len(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES) + 1,
        )
        if os.read(descriptor, 1):
            raise OSError
        after = os.fstat(descriptor)
        if (
            not _same_inode(before, after)
            or payload != POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES
            or before.st_size != len(payload)
        ):
            raise OSError
        if before.st_nlink == 1 and after.st_nlink == 1:
            named = os.stat(
                POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
                follow_symlinks=False,
            )
            if (
                _stable_identity(before) != _stable_identity(after)
                or _stable_identity(after) != _stable_identity(named)
                or not _exact_ready_metadata(after, link_count=1)
            ):
                raise OSError
            _require_ready_staging_absent()
            return
        if before.st_nlink == 2 and after.st_nlink == 1:
            named = os.stat(
                POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
                follow_symlinks=False,
            )
            if (
                not _exact_ready_metadata(before, link_count=2)
                or not _exact_ready_metadata(after, link_count=1)
                or _stable_identity(after) != _stable_identity(named)
            ):
                raise OSError
            _require_ready_staging_absent()
            return
        if (
            before.st_nlink != 2
            or after.st_nlink != 2
            or _stable_identity(before) != _stable_identity(after)
            or not _exact_ready_metadata(after, link_count=2)
        ):
            raise OSError
        try:
            staging = os.stat(
                POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            named = os.stat(
                POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
                follow_symlinks=False,
            )
            if not _same_inode(after, named) or not _exact_ready_metadata(
                named,
                link_count=1,
            ):
                raise OSError from None
            _require_ready_staging_absent()
            return
        if _stable_identity(staging) != _stable_identity(after) or not _exact_ready_metadata(
            staging,
            link_count=2,
        ):
            raise OSError
        raise FileNotFoundError
    except FileNotFoundError:
        raise
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready marker is invalid"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment sequence-two-ready marker is invalid"
                ) from None


def wait_for_post_enrollment_start_sequence_two_ready(
    *,
    deadline_monotonic_ns: int,
    monotonic_clock: Callable[[], int] = _boottime_monotonic_ns,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Wait only to the release-bound absolute CLOCK_BOOTTIME deadline."""

    if (
        type(deadline_monotonic_ns) is not int
        or deadline_monotonic_ns < POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_NANOSECONDS
        or not callable(monotonic_clock)
        or not callable(sleeper)
    ):
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready dependencies are invalid"
        )
    issued_at = deadline_monotonic_ns - POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_NANOSECONDS
    observed = _read_clock(monotonic_clock)
    if observed < issued_at:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two-ready clock predates release"
        )
    polls = 0
    while (
        observed < deadline_monotonic_ns
        and polls < POST_ENROLLMENT_START_SEQUENCE_TWO_READY_MAXIMUM_POLLS
    ):
        polls += 1
        try:
            read_exact_post_enrollment_start_sequence_two_ready()
            confirmed = _read_clock(monotonic_clock)
            if confirmed < observed:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment sequence-two-ready clock regressed"
                )
            if confirmed >= deadline_monotonic_ns:
                break
            return
        except FileNotFoundError:
            pass
        try:
            sleeper(
                min(
                    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_POLL_SECONDS,
                    (deadline_monotonic_ns - observed) / 1_000_000_000,
                )
            )
            current = _read_clock(monotonic_clock)
        except Exception:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment sequence-two-ready clock failed"
            ) from None
        if current < observed:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment sequence-two-ready clock regressed"
            )
        if current == observed:
            raise TrustedTimeSupervisorConfigurationError(
                "trusted-time post-enrollment sequence-two-ready clock did not advance"
            )
        observed = current
    raise TrustedTimeSupervisorConfigurationError(
        "trusted-time post-enrollment sequence-two-ready was not observed"
    )


__all__ = [
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_MAXIMUM_POLLS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_POLL_SECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_NANOSECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_SECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_NANOSECONDS",
    "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_SECONDS",
    "read_exact_post_enrollment_start_sequence_two_ready",
    "wait_for_post_enrollment_start_sequence_two_ready",
    "write_post_enrollment_start_sequence_two_ready",
]
