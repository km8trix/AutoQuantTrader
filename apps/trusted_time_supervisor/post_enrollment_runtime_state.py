"""Read-only fixed-marker projection for a post-enrollment runtime."""

from __future__ import annotations

import argparse
import json

from apps.trusted_time_supervisor.config import (
    TrustedTimeSupervisorConfigurationError,
)
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_SHA256,
    read_exact_post_enrollment_start_release,
    read_exact_post_enrollment_start_sequence_two_deadline_receipt,
)
from apps.trusted_time_supervisor.post_enrollment_sequence_two_ready import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256,
    read_exact_post_enrollment_start_sequence_two_ready,
    wait_for_post_enrollment_start_sequence_two_ready,
)

POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION = "phase6d-post-enrollment-runtime-state-v1"
POST_ENROLLMENT_RUNTIME_STATE_STATUS = "sequence_two_ready_observed"


def read_post_enrollment_runtime_state() -> dict[str, object]:
    """Validate both exact markers and return one fixed non-authorizing receipt."""

    read_exact_post_enrollment_start_release()
    deadline_receipt = read_exact_post_enrollment_start_sequence_two_deadline_receipt()
    deadline_monotonic_ns = deadline_receipt.deadline_monotonic_ns
    wait_for_post_enrollment_start_sequence_two_ready(deadline_monotonic_ns=deadline_monotonic_ns)
    read_exact_post_enrollment_start_release()
    if read_exact_post_enrollment_start_sequence_two_deadline_receipt() != deadline_receipt:
        raise TrustedTimeSupervisorConfigurationError(
            "trusted-time post-enrollment sequence-two deadline changed"
        )
    read_exact_post_enrollment_start_sequence_two_ready()
    # Close the final read/expiry race under the same absolute deadline.
    wait_for_post_enrollment_start_sequence_two_ready(deadline_monotonic_ns=deadline_monotonic_ns)
    return {
        "alert_delivery_authorized": False,
        "arming_authorized": False,
        "automatic_rearm_authorized": False,
        "automatic_resume_authorized": False,
        "broker_action_authorized": False,
        "contract_version": POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION,
        "exposure_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "operational_control_authorized": False,
        "paper_trading_authorized": False,
        "readiness_authorized": False,
        "rearm_authorized": False,
        "release_marker_sha256": POST_ENROLLMENT_START_RELEASE_SHA256,
        "sequence_two_deadline_marker_sha256": deadline_receipt.marker_sha256,
        "sequence_two_ready_marker_sha256": (POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256),
        "service": "trusted-time-supervisor",
        "status": POST_ENROLLMENT_RUNTIME_STATE_STATUS,
    }


def runtime_state_main() -> None:
    """Emit one canonical receipt; reject missing, changed, or extra input."""

    parser = argparse.ArgumentParser(
        description="Inspect fixed post-enrollment trusted-time runtime markers."
    )
    parser.parse_args()
    try:
        payload = read_post_enrollment_runtime_state()
    except (FileNotFoundError, TrustedTimeSupervisorConfigurationError):
        raise SystemExit(2) from None
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    runtime_state_main()


__all__ = [
    "POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION",
    "POST_ENROLLMENT_RUNTIME_STATE_STATUS",
    "read_post_enrollment_runtime_state",
    "runtime_state_main",
]
