from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from apps.trusted_time_supervisor import post_enrollment_release as release
from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)


@pytest.fixture
def marker_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "post-enrollment-start-release"
    monkeypatch.setattr(release, "POST_ENROLLMENT_START_RELEASE_PATH", os.fspath(path))
    monkeypatch.setattr(
        release,
        "POST_ENROLLMENT_START_RELEASE_STAGING_PATH",
        os.fspath(tmp_path / ".post-enrollment-start-release-staging"),
    )
    return path


def test_literal_release_contract_is_frozen_and_nonsecret() -> None:
    assert release.POST_ENROLLMENT_START_RELEASE_PATH == ("/tmp/post-enrollment-start-release")
    assert release.POST_ENROLLMENT_START_RELEASE_STAGING_PATH == (
        "/tmp/.post-enrollment-start-release-staging"
    )
    assert release.POST_ENROLLMENT_START_RELEASE_BYTES == (
        b"phase6d-post-enrollment-start-release-v1\n"
    )
    expected_sha256 = hashlib.sha256(release.POST_ENROLLMENT_START_RELEASE_BYTES).hexdigest()
    assert expected_sha256 == release.POST_ENROLLMENT_START_RELEASE_SHA256
    assert release.POST_ENROLLMENT_START_RELEASE_WAIT_SECONDS == 120.0
    assert release.POST_ENROLLMENT_START_RELEASE_POLL_SECONDS == 0.1
    assert release.POST_ENROLLMENT_START_RELEASE_MAXIMUM_POLLS == 1_200


def test_writer_and_reader_require_exact_owner_only_single_link_marker(
    marker_path: Path,
) -> None:
    release.write_post_enrollment_start_release()

    metadata = marker_path.stat()
    assert marker_path.read_bytes() == release.POST_ENROLLMENT_START_RELEASE_BYTES
    assert metadata.st_uid == os.geteuid()
    assert metadata.st_gid == os.getegid()
    assert metadata.st_nlink == 1
    assert metadata.st_mode & 0o777 == 0o400
    assert not Path(release.POST_ENROLLMENT_START_RELEASE_STAGING_PATH).exists()
    release.read_exact_post_enrollment_start_release()


def test_reader_treats_only_the_atomic_link_window_as_pending(
    marker_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_unlink = os.unlink
    observations = 0

    def observe_before_unlink(path: str) -> None:
        nonlocal observations
        assert path == release.POST_ENROLLMENT_START_RELEASE_STAGING_PATH
        with pytest.raises(FileNotFoundError):
            release.read_exact_post_enrollment_start_release()
        observations += 1
        real_unlink(path)

    monkeypatch.setattr(release.os, "unlink", observe_before_unlink)

    release.write_post_enrollment_start_release()

    assert observations == 1
    release.read_exact_post_enrollment_start_release()


def test_release_is_exclusive_and_never_overwrites_first_marker(marker_path: Path) -> None:
    release.write_post_enrollment_start_release()
    before = marker_path.stat()

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="post-enrollment start release failed",
    ):
        release.write_post_enrollment_start_release()

    after = marker_path.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns, marker_path.read_bytes()) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
        release.POST_ENROLLMENT_START_RELEASE_BYTES,
    )


@pytest.mark.parametrize(
    ("mutation",),
    [
        ("bytes",),
        ("mode",),
        ("hardlink",),
    ],
)
def test_reader_rejects_marker_content_mode_and_link_tampering(
    marker_path: Path,
    mutation: str,
) -> None:
    release.write_post_enrollment_start_release()
    if mutation == "bytes":
        marker_path.chmod(0o600)
        marker_path.write_bytes(b"phase6d-post-enrollment-start-release-v2\n")
        marker_path.chmod(0o400)
    elif mutation == "mode":
        marker_path.chmod(0o600)
    else:
        os.link(marker_path, marker_path.with_name("second-link"))

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="post-enrollment start release is invalid",
    ):
        release.read_exact_post_enrollment_start_release()


def test_writer_rejects_preexisting_symlink_without_touching_target(
    marker_path: Path,
) -> None:
    target = marker_path.with_name("target")
    target.write_bytes(b"unchanged")
    marker_path.symlink_to(target)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="post-enrollment start release failed",
    ):
        release.write_post_enrollment_start_release()

    assert target.read_bytes() == b"unchanged"


def test_reader_rejects_identity_drift_during_observation(
    marker_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release.write_post_enrollment_start_release()
    stable = release._stable_identity
    calls = 0

    def drifting_identity(metadata: os.stat_result) -> tuple[int, ...]:
        nonlocal calls
        calls += 1
        observed = stable(metadata)
        if calls == 2:
            return (observed[0], observed[1] + 1, *observed[2:])
        return observed

    monkeypatch.setattr(release, "_stable_identity", drifting_identity)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="post-enrollment start release is invalid",
    ):
        release.read_exact_post_enrollment_start_release()


def test_waiter_polls_boundedly_then_accepts_exact_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations = Mock(side_effect=[FileNotFoundError, None])
    sleeper = Mock()
    times = iter([10.0, 10.1])
    monkeypatch.setattr(release, "read_exact_post_enrollment_start_release", observations)

    release.wait_for_post_enrollment_start_release(
        monotonic_clock=lambda: next(times),
        sleeper=sleeper,
    )

    assert observations.call_count == 2
    sleeper.assert_called_once_with(0.1)


def test_waiter_times_out_without_accepting_a_missing_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        release,
        "read_exact_post_enrollment_start_release",
        Mock(side_effect=FileNotFoundError),
    )
    times = iter([5.0, 125.0])

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="release was not observed",
    ):
        release.wait_for_post_enrollment_start_release(
            monotonic_clock=lambda: next(times),
            sleeper=lambda _: None,
        )


@pytest.mark.parametrize(
    ("times", "message"),
    [
        ([float("nan")], "release clock failed"),
        ([10.0, 9.0], "release clock regressed"),
        ([10.0, 10.0], "release clock did not advance"),
    ],
)
def test_waiter_rejects_nonfinite_or_regressing_clock(
    monkeypatch: pytest.MonkeyPatch,
    times: list[float],
    message: str,
) -> None:
    monkeypatch.setattr(
        release,
        "read_exact_post_enrollment_start_release",
        Mock(side_effect=FileNotFoundError),
    )
    observed = iter(times)

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match=message):
        release.wait_for_post_enrollment_start_release(
            monotonic_clock=lambda: next(observed),
            sleeper=lambda _: None,
        )


def test_waiter_rejects_a_deadline_that_cannot_advance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = Mock(side_effect=AssertionError("marker read crossed invalid deadline"))
    monkeypatch.setattr(release, "read_exact_post_enrollment_start_release", observer)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="release clock failed",
    ):
        release.wait_for_post_enrollment_start_release(
            monotonic_clock=lambda: sys.float_info.max,
            sleeper=lambda _: None,
        )

    observer.assert_not_called()


def test_waiter_has_a_finite_poll_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = Mock(side_effect=FileNotFoundError)
    times = iter([0.0, 0.01, 0.02])
    monkeypatch.setattr(release, "POST_ENROLLMENT_START_RELEASE_MAXIMUM_POLLS", 2)
    monkeypatch.setattr(release, "read_exact_post_enrollment_start_release", observer)

    with pytest.raises(
        TrustedTimeSupervisorConfigurationError,
        match="release was not observed",
    ):
        release.wait_for_post_enrollment_start_release(
            monotonic_clock=lambda: next(times),
            sleeper=lambda _: None,
        )

    assert observer.call_count == 2


def test_release_cli_is_silent_and_maps_failure_to_exit_two(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    writer = Mock()
    monkeypatch.setattr(sys, "argv", ["autoquant-trusted-time-post-enrollment-release"])
    monkeypatch.setattr(release, "write_post_enrollment_start_release", writer)
    release.release_main()

    assert capsys.readouterr() == ("", "")
    writer.side_effect = TrustedTimeSupervisorConfigurationError("secret detail")
    with pytest.raises(SystemExit) as captured:
        release.release_main()

    assert captured.value.code == 2
    assert capsys.readouterr() == ("", "")
