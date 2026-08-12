from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from apps.trusted_time_supervisor import post_enrollment_release as release
from apps.trusted_time_supervisor import post_enrollment_runtime_state as runtime_state
from apps.trusted_time_supervisor import post_enrollment_sequence_two_ready as ready
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_SHA256,
    TrustedTimePostEnrollmentSequenceTwoDeadlineReceipt,
)
from apps.trusted_time_supervisor.post_enrollment_sequence_two_ready import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256,
)

ROOT = Path(__file__).resolve().parents[2]


def test_runtime_state_reads_both_real_fixed_marker_contracts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    release_marker = tmp_path / "post-enrollment-start-release"
    release_staging = tmp_path / ".post-enrollment-start-release-staging"
    ready_marker = tmp_path / "post-enrollment-start-sequence-two-ready"
    ready_staging = tmp_path / ".post-enrollment-start-sequence-two-ready-staging"
    deadline_marker = tmp_path / "post-enrollment-start-sequence-two-deadline"
    deadline_staging = tmp_path / ".post-enrollment-start-sequence-two-deadline-staging"
    monkeypatch.setattr(release, "POST_ENROLLMENT_START_RELEASE_PATH", str(release_marker))
    monkeypatch.setattr(
        release,
        "POST_ENROLLMENT_START_RELEASE_STAGING_PATH",
        str(release_staging),
    )
    monkeypatch.setattr(
        release,
        "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH",
        str(deadline_marker),
    )
    monkeypatch.setattr(
        release,
        "POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH",
        str(deadline_staging),
    )
    monkeypatch.setattr(ready, "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH", str(ready_marker))
    monkeypatch.setattr(
        ready,
        "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH",
        str(ready_staging),
    )
    monkeypatch.setattr(
        release,
        "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH",
        str(ready_marker),
    )
    monkeypatch.setattr(
        release,
        "POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH",
        str(ready_staging),
    )
    monkeypatch.setattr(release, "_read_linux_boot_id_sha256", lambda: "b" * 64)
    deadline = release.write_post_enrollment_start_sequence_two_deadline(
        monotonic_clock=lambda: 1_000_000_000
    )
    release.write_post_enrollment_start_release()
    ready.write_post_enrollment_start_sequence_two_ready()
    observations = iter((2_000_000_000, 2_000_000_000, 2_000_000_000, 2_000_000_000))
    monkeypatch.setattr(
        runtime_state,
        "wait_for_post_enrollment_start_sequence_two_ready",
        lambda *, deadline_monotonic_ns: ready.wait_for_post_enrollment_start_sequence_two_ready(
            deadline_monotonic_ns=deadline_monotonic_ns,
            monotonic_clock=lambda: next(observations),
        ),
    )

    payload = runtime_state.read_post_enrollment_runtime_state()

    assert payload["status"] == "sequence_two_ready_observed"
    assert (
        payload["sequence_two_deadline_marker_sha256"]
        == hashlib.sha256(deadline_marker.read_bytes()).hexdigest()
    )
    assert deadline == 121_000_000_000


def test_runtime_state_requires_release_then_sequence_two_ready_and_grants_no_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        runtime_state,
        "read_exact_post_enrollment_start_release",
        lambda: events.append("release"),
    )
    monkeypatch.setattr(
        runtime_state,
        "read_exact_post_enrollment_start_sequence_two_deadline_receipt",
        lambda: (
            events.append("deadline")
            or TrustedTimePostEnrollmentSequenceTwoDeadlineReceipt(
                deadline_monotonic_ns=130_000_000_000,
                marker_sha256="d" * 64,
            )
        ),
    )
    monkeypatch.setattr(
        runtime_state,
        "wait_for_post_enrollment_start_sequence_two_ready",
        lambda *, deadline_monotonic_ns: events.append(
            f"wait_sequence_two_ready:{deadline_monotonic_ns}"
        ),
    )
    monkeypatch.setattr(
        runtime_state,
        "read_exact_post_enrollment_start_sequence_two_ready",
        lambda: events.append("sequence_two_ready"),
    )

    payload = runtime_state.read_post_enrollment_runtime_state()

    assert events == [
        "release",
        "deadline",
        "wait_sequence_two_ready:130000000000",
        "release",
        "deadline",
        "sequence_two_ready",
        "wait_sequence_two_ready:130000000000",
    ]
    assert payload["contract_version"] == "phase6d-post-enrollment-runtime-state-v1"
    assert payload["status"] == "sequence_two_ready_observed"
    assert payload["release_marker_sha256"] == POST_ENROLLMENT_START_RELEASE_SHA256
    assert payload["sequence_two_deadline_marker_sha256"] == "d" * 64
    assert (
        payload["sequence_two_ready_marker_sha256"]
        == POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256
    )
    for field_name in (
        "alert_delivery_authorized",
        "arming_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "paper_trading_authorized",
        "readiness_authorized",
        "rearm_authorized",
    ):
        assert payload[field_name] is False


def test_runtime_state_cli_emits_one_canonical_nonsecret_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = {"contract_version": "fixed", "status": "observed"}
    monkeypatch.setattr(runtime_state, "read_post_enrollment_runtime_state", lambda: payload)
    monkeypatch.setattr(sys, "argv", ["autoquant-trusted-time-post-enrollment-runtime-state"])

    runtime_state.runtime_state_main()

    captured = capsys.readouterr()
    assert captured.out == '{"contract_version":"fixed","status":"observed"}\n'
    assert captured.err == ""


@pytest.mark.parametrize("failure", [FileNotFoundError(), OSError("private detail")])
def test_runtime_state_cli_fails_closed_without_emitting_marker_detail(
    failure: Exception,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    if isinstance(failure, OSError) and not isinstance(failure, FileNotFoundError):
        from apps.trusted_time_supervisor.config import (
            TrustedTimeSupervisorConfigurationError,
        )

        failure = TrustedTimeSupervisorConfigurationError("private detail")
    read = Mock(side_effect=failure)
    monkeypatch.setattr(runtime_state, "read_post_enrollment_runtime_state", read)
    monkeypatch.setattr(sys, "argv", ["autoquant-trusted-time-post-enrollment-runtime-state"])

    with pytest.raises(SystemExit) as captured:
        runtime_state.runtime_state_main()

    assert captured.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "private detail" not in output.err


def test_runtime_state_console_script_is_inspection_only() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text()

    assert (
        "autoquant-trusted-time-post-enrollment-runtime-state = "
        '"apps.trusted_time_supervisor.post_enrollment_runtime_state:runtime_state_main"'
        in pyproject
    )
    assert "subprocess" not in vars(runtime_state)
    assert "write_post_enrollment_start_release" not in vars(runtime_state)
    assert "write_post_enrollment_start_sequence_two_ready" not in vars(runtime_state)
