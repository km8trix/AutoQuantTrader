from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import Mock

import pytest

from apps.trusted_time_supervisor import post_enrollment_sequence_two_ready as ready
from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)
from apps.trusted_time_supervisor.head_anchor_worker import (
    TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS,
)


def _capture_ready_fchown(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[int, int, int, int]]:
    exact_fchown = ready.os.fchown
    calls: list[tuple[int, int, int, int]] = []

    def capture(descriptor: int, uid: int, gid: int) -> None:
        metadata = os.fstat(descriptor)
        calls.append((metadata.st_dev, metadata.st_ino, uid, gid))
        exact_fchown(descriptor, uid, gid)

    monkeypatch.setattr(ready.os, "fchown", capture)
    return calls


def _use_temp_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "post-enrollment-start-sequence-two-ready"
    staging = tmp_path / ".post-enrollment-start-sequence-two-ready-staging"
    monkeypatch.setattr(ready, "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH", str(marker))
    monkeypatch.setattr(
        ready,
        "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH",
        str(staging),
    )
    return marker, staging


def test_sequence_two_ready_writer_is_exact_owner_only_atomic_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, staging = _use_temp_paths(monkeypatch, tmp_path)
    fchown_calls = _capture_ready_fchown(monkeypatch)

    ready.write_post_enrollment_start_sequence_two_ready()
    ready.read_exact_post_enrollment_start_sequence_two_ready()

    metadata = marker.stat()
    assert marker.read_bytes() == (b"phase6d-post-enrollment-start-sequence-two-ready-v1\n")
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_gid == os.getegid()
    assert stat.S_IMODE(metadata.st_mode) == 0o400
    assert metadata.st_nlink == 1
    assert staging.exists() is False
    assert fchown_calls == [(metadata.st_dev, metadata.st_ino, os.geteuid(), os.getegid())]

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="publication failed",
    ):
        ready.write_post_enrollment_start_sequence_two_ready()

    assert marker.read_bytes() == ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES
    assert staging.exists() is True


def test_sequence_two_ready_writer_never_replaces_existing_final_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, staging = _use_temp_paths(monkeypatch, tmp_path)
    marker.write_bytes(b"foreign-marker\n")
    marker.chmod(0o400)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="publication failed",
    ):
        ready.write_post_enrollment_start_sequence_two_ready()

    assert marker.read_bytes() == b"foreign-marker\n"
    assert staging.read_bytes() == ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES

    with pytest.raises(FileNotFoundError):
        ready.read_exact_post_enrollment_start_sequence_two_ready()


def test_sequence_two_ready_reader_rejects_exact_stale_final_with_separate_staging(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, staging = _use_temp_paths(monkeypatch, tmp_path)
    marker.write_bytes(ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES)
    marker.chmod(0o400)
    staging.write_bytes(b"new writer")

    with pytest.raises(FileNotFoundError):
        ready.read_exact_post_enrollment_start_sequence_two_ready()


def test_sequence_two_ready_writer_leaves_publication_pending_when_deadline_crosses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, staging = _use_temp_paths(monkeypatch, tmp_path)
    observations = iter((0, 1, 2, 3, 5_000_000_000))

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="publication failed",
    ):
        ready.write_post_enrollment_start_sequence_two_ready(
            monotonic_clock=lambda: next(observations)
        )

    assert marker.exists() is True
    assert staging.exists() is True
    with pytest.raises(FileNotFoundError):
        ready.read_exact_post_enrollment_start_sequence_two_ready()


def test_sequence_two_ready_writer_poisons_visibility_commit_at_absolute_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, staging = _use_temp_paths(monkeypatch, tmp_path)
    observations = iter((0, 1, 2, 3, 4, 120_000_000_000))

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="publication failed",
    ):
        ready.write_post_enrollment_start_sequence_two_ready(
            publication_deadline_monotonic_ns=120_000_000_000,
            monotonic_clock=lambda: next(observations),
        )

    assert marker.exists() is True
    assert staging.exists() is True
    with pytest.raises(FileNotFoundError):
        ready.read_exact_post_enrollment_start_sequence_two_ready()


def test_sequence_two_ready_writer_syncs_link_and_unlink_namespaces(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, _ = _use_temp_paths(monkeypatch, tmp_path)
    syncs: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        ready,
        "_fsync_parent_directory",
        lambda path, *, suppress_failure=False: syncs.append((path, suppress_failure)),
    )

    ready.write_post_enrollment_start_sequence_two_ready()

    assert syncs == [(str(marker), False), (str(marker), True)]


def test_sequence_two_ready_writer_treats_post_commit_sync_failure_as_committed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _use_temp_paths(monkeypatch, tmp_path)
    calls = 0
    real_fsync = os.fsync

    def fail_third_sync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError
        real_fsync(descriptor)

    monkeypatch.setattr(ready.os, "fsync", fail_third_sync)

    ready.write_post_enrollment_start_sequence_two_ready()
    ready.read_exact_post_enrollment_start_sequence_two_ready()

    assert calls == 3


def test_sequence_two_ready_writer_readback_failure_never_publishes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, staging = _use_temp_paths(monkeypatch, tmp_path)
    original_read = os.read
    corrupted = False

    def corrupt_first_read(descriptor: int, count: int) -> bytes:
        nonlocal corrupted
        payload = original_read(descriptor, count)
        if not corrupted and payload:
            corrupted = True
            return b"x" + payload[1:]
        return payload

    monkeypatch.setattr(os, "read", corrupt_first_read)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="publication failed",
    ):
        ready.write_post_enrollment_start_sequence_two_ready()

    assert corrupted is True
    assert marker.exists() is False
    assert staging.exists() is True


@pytest.mark.parametrize(
    ("payload", "mode"),
    [
        (b"phase6d-post-enrollment-start-sequence-two-ready-v1\nextra", 0o400),
        (b"phase6d-post-enrollment-start-sequence-two-ready-v1\n", 0o600),
        (b"phase6d-post-enrollment-start-sequence-two-ready-v2\n", 0o400),
    ],
)
def test_sequence_two_ready_reader_rejects_payload_or_metadata_substitution(
    payload: bytes,
    mode: int,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, _ = _use_temp_paths(monkeypatch, tmp_path)
    marker.write_bytes(payload)
    marker.chmod(mode)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="marker is invalid",
    ):
        ready.read_exact_post_enrollment_start_sequence_two_ready()


def test_sequence_two_ready_reader_rejects_symlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker, _ = _use_temp_paths(monkeypatch, tmp_path)
    target = tmp_path / "target"
    target.write_bytes(ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES)
    target.chmod(0o400)
    marker.symlink_to(target)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="marker is invalid",
    ):
        ready.read_exact_post_enrollment_start_sequence_two_ready()


def test_sequence_two_ready_fixed_payload_contains_no_runtime_evidence() -> None:
    assert (
        ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_CONTRACT_VERSION.encode("ascii") + b"\n"
    ) == ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES
    assert b"{" not in ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES
    assert len(ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256) == 64


def test_sequence_two_ready_wait_uses_one_bounded_poll_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = iter((10_000_000_000, 10_100_000_000, 10_200_000_000, 10_200_000_000))
    reads = 0
    sleeps: list[float] = []

    def read_ready() -> None:
        nonlocal reads
        reads += 1
        if reads < 3:
            raise FileNotFoundError

    monkeypatch.setattr(
        ready,
        "read_exact_post_enrollment_start_sequence_two_ready",
        read_ready,
    )

    ready.wait_for_post_enrollment_start_sequence_two_ready(
        deadline_monotonic_ns=130_000_000_000,
        monotonic_clock=lambda: next(observations),
        sleeper=sleeps.append,
    )

    assert reads == 3
    assert sleeps == [0.1, 0.1]


def test_sequence_two_ready_wait_times_out_at_exact_fixed_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = iter((120_000_000_000, 120_100_000_000, 120_200_000_000))
    read_ready = Mock(side_effect=FileNotFoundError)
    sleeps: list[float] = []
    monkeypatch.setattr(
        ready,
        "read_exact_post_enrollment_start_sequence_two_ready",
        read_ready,
    )
    monkeypatch.setattr(ready, "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_MAXIMUM_POLLS", 2)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="was not observed",
    ):
        ready.wait_for_post_enrollment_start_sequence_two_ready(
            deadline_monotonic_ns=120_200_000_000,
            monotonic_clock=lambda: next(observations),
            sleeper=sleeps.append,
        )

    assert read_ready.call_count == 2
    assert sleeps == [0.1, 0.1]


@pytest.mark.parametrize(
    ("observations", "message"),
    [
        ((1_000_000_000, 500_000_000), "clock regressed"),
        ((1_000_000_000, 1_000_000_000), "clock did not advance"),
        ((float("nan"),), "clock failed"),
    ],
)
def test_sequence_two_ready_wait_rejects_clock_failure(
    observations: tuple[float, ...],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = iter(observations)
    monkeypatch.setattr(
        ready,
        "read_exact_post_enrollment_start_sequence_two_ready",
        Mock(side_effect=FileNotFoundError),
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match=message):
        ready.wait_for_post_enrollment_start_sequence_two_ready(
            deadline_monotonic_ns=120_000_000_000,
            monotonic_clock=lambda: next(values),
            sleeper=lambda _: None,
        )


def test_sequence_two_ready_wait_rejects_marker_from_prior_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = Mock(side_effect=AssertionError("stale boot reached marker read"))
    monkeypatch.setattr(
        ready,
        "read_exact_post_enrollment_start_sequence_two_ready",
        observer,
    )

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="clock predates release",
    ):
        ready.wait_for_post_enrollment_start_sequence_two_ready(
            deadline_monotonic_ns=200_000_000_000,
            monotonic_clock=lambda: 79_999_999_999,
        )

    observer.assert_not_called()


def test_sequence_two_ready_wait_rejects_marker_observed_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ready,
        "read_exact_post_enrollment_start_sequence_two_ready",
        lambda: None,
    )
    observations = iter((1, 120_000_000_000))

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="was not observed",
    ):
        ready.wait_for_post_enrollment_start_sequence_two_ready(
            deadline_monotonic_ns=120_000_000_000,
            monotonic_clock=lambda: next(observations),
        )


def test_sequence_two_ready_production_wait_constants_are_fixed() -> None:
    assert ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_SECONDS == 120.0
    assert ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_POLL_SECONDS == 0.1
    assert ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_MAXIMUM_POLLS == 1_200
    assert ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_NANOSECONDS == (120_000_000_000)
    assert ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_SECONDS == 5.0
    assert ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PUBLICATION_TIMEOUT_NANOSECONDS == (
        5_000_000_000
    )
    assert (
        ready.POST_ENROLLMENT_START_SEQUENCE_TWO_READY_WAIT_SECONDS
        - TRUSTED_TIME_HEAD_ANCHOR_STARTUP_TERMINAL_TIMEOUT_SECONDS
        == 5.0
    )
