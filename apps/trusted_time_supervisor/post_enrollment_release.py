"""One-shot in-container barrier for a future approved post-enrollment start."""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import stat
import time
from collections.abc import Callable

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
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


def write_post_enrollment_start_release() -> None:
    """Atomically publish the fixed marker once inside the staged container."""

    descriptor: int | None = None
    try:
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
        os.unlink(POST_ENROLLMENT_START_RELEASE_STAGING_PATH)
        published = os.fstat(descriptor)
        named = os.stat(POST_ENROLLMENT_START_RELEASE_PATH, follow_symlinks=False)
        if _stable_identity(published) != _stable_identity(named) or not _exact_release_metadata(
            published, link_count=1
        ):
            raise OSError
    except OSError:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment start release failed"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise TrustedTimeSupervisorConfigurationError(
                    "trusted-time post-enrollment start release failed"
                ) from None


def read_exact_post_enrollment_start_release() -> None:
    """Require the exact stable owner-only marker and no trailing byte."""

    descriptor: int | None = None
    try:
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
            return
        if before.st_nlink == 2 and after.st_nlink == 1:
            named = os.stat(POST_ENROLLMENT_START_RELEASE_PATH, follow_symlinks=False)
            if (
                not _exact_release_metadata(before, link_count=2)
                or not _exact_release_metadata(after, link_count=1)
                or _stable_identity(after) != _stable_identity(named)
            ):
                raise OSError
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
    """Publish one marker only when invoked inside the exact staged container."""

    parser = argparse.ArgumentParser(
        description="Release one staged post-enrollment trusted-time supervisor."
    )
    parser.parse_args()
    try:
        write_post_enrollment_start_release()
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
    "read_exact_post_enrollment_start_release",
    "release_main",
    "wait_for_post_enrollment_start_release",
    "write_post_enrollment_start_release",
]
