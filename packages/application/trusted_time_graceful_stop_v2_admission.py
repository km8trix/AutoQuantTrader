"""Private, injected ADR-0112 handoff for lifecycle-v2 admission experiments.

There is no production caller.  This module can consume historical receipt
evidence only; it cannot create a lifecycle root or perform an effect.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts import (
    _LIFECYCLE_V2_BRIDGE_CAPABILITY,
    LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    _consume_loaded_decision_receipt_for_v2,
    _ConsumedLoadedDecisionArtifactReceiptV2Snapshot,
    _reject_loaded_decision_receipt_for_v2_admission_identity,
    _require_consumed_loaded_decision_artifact_receipt_v2_snapshot,
)

_ADMISSION_IDENTITY_CAPABILITY = object()


class LifecycleV2HistoricalReceiptHandoffRejected(RuntimeError):
    """The private historical receipt capability was invalid or already consumed."""


@dataclass(frozen=True, slots=True, eq=False)
class _LifecycleV2AdmissionIdentity:
    graceful_stop_operation_id: str
    admission_sha256: str
    channel_id: str
    owner_pid: int
    owner_thread: threading.Thread
    _capability: object = field(repr=False, compare=False)


def _build_injected_lifecycle_v2_admission_identity(
    *,
    graceful_stop_operation_id: str,
    admission_sha256: str,
    channel_id: str,
) -> _LifecycleV2AdmissionIdentity:
    """Build an unreachable test identity; not an operational admission."""

    return _LifecycleV2AdmissionIdentity(
        graceful_stop_operation_id=graceful_stop_operation_id,
        admission_sha256=admission_sha256,
        channel_id=channel_id,
        owner_pid=os.getpid(),
        owner_thread=threading.current_thread(),
        _capability=_ADMISSION_IDENTITY_CAPABILITY,
    )


def _consume_historical_receipt_for_injected_lifecycle_v2_admission(
    loaded: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    *,
    admission_identity: _LifecycleV2AdmissionIdentity,
    start_operator_attested_approval_artifact: Path,
    expected_graceful_stop_decision_v1_sha256: str,
    artifact_directory: Path,
    ignored_root: Path,
) -> _ConsumedLoadedDecisionArtifactReceiptV2Snapshot:
    """Consume ADR-0112 evidence under the separate v2 capability domain."""

    if (
        type(admission_identity) is not _LifecycleV2AdmissionIdentity
        or admission_identity._capability is not _ADMISSION_IDENTITY_CAPABILITY
        or admission_identity.owner_pid != os.getpid()
        or admission_identity.owner_thread is not threading.current_thread()
    ):
        try:
            _reject_loaded_decision_receipt_for_v2_admission_identity(
                loaded,
                bridge_capability=_LIFECYCLE_V2_BRIDGE_CAPABILITY,
            )
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise LifecycleV2HistoricalReceiptHandoffRejected(
                "v2 admission identity is invalid"
            ) from None
    snapshot = _consume_loaded_decision_receipt_for_v2(
        loaded,
        start_operator_attested_approval_artifact=(start_operator_attested_approval_artifact),
        expected_graceful_stop_decision_v1_sha256=(expected_graceful_stop_decision_v1_sha256),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        graceful_stop_operation_id=admission_identity.graceful_stop_operation_id,
        admission_sha256=admission_identity.admission_sha256,
        channel_id=admission_identity.channel_id,
        admission_identity=admission_identity,
        bridge_capability=_LIFECYCLE_V2_BRIDGE_CAPABILITY,
    )
    return _require_consumed_loaded_decision_artifact_receipt_v2_snapshot(
        snapshot,
        loaded_identity=loaded,
        admission_identity=admission_identity,
        graceful_stop_operation_id=admission_identity.graceful_stop_operation_id,
        admission_sha256=admission_identity.admission_sha256,
        channel_id=admission_identity.channel_id,
        bridge_capability=_LIFECYCLE_V2_BRIDGE_CAPABILITY,
    )


def lifecycle_v2_admission_non_authority_facts() -> dict[str, bool]:
    return {
        "production_caller_present": False,
        "root_reservation_present": False,
        "transport_dispatch_present": False,
        "effect_authority_present": False,
        "v1_bridge_identity_reused": False,
    }


__all__ = [
    "LifecycleV2HistoricalReceiptHandoffRejected",
    "lifecycle_v2_admission_non_authority_facts",
]
