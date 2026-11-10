"""One exact post-claim trusted-time controller execution tail.

The public function is deliberately not wired to a CLI, Make target, launcher,
or runtime.  It consumes the process-private controller admission inside the
same topology-reader callback, performs one final full pre-effect observation,
irreversibly crosses the release boundary, confirms sequence two and a fresh
persistent topology, and durably retains the sole terminal outcome.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
)
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_PATH,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
)
from apps.trusted_time_supervisor.post_enrollment_sequence_two_ready import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
)
from apps.trusted_time_supervisor.post_enrollment_start import (
    bind_post_enrollment_start_successor,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
    TrustedTimePostEnrollmentStartSuccessor,
)
from scripts.start_trusted_time_supervisor import (
    LocalDockerDaemonIdentity,
    TrustedTimeApprovedLaunch,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
    _consume_active_controller_continuation,
)
from scripts.trusted_time_post_enrollment_claimed_fence import (
    TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
)
from scripts.trusted_time_post_enrollment_controller_outcome import (
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable,
    TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
    TrustedTimePostEnrollmentStartControllerOutcomeReason,
    TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed,
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
    retain_post_enrollment_start_controller_outcome,
)
from scripts.trusted_time_post_enrollment_outcome import (
    RetainedTrustedTimePostEnrollmentStartOutcome,
    TrustedTimePostEnrollmentStartRecoveryOutcomeRetained,
    retain_post_enrollment_start_recovery_required_outcome,
)
from scripts.trusted_time_post_enrollment_persistent_topology import (
    TrustedTimePostEnrollmentPersistentTopologySnapshot,
    TrustedTimePostEnrollmentReleaseMarkerProjection,
    validate_post_enrollment_start_persistent_topology,
)
from scripts.trusted_time_post_enrollment_sequence_two_verifier import (
    TrustedTimePostEnrollmentStartSequenceTwoVerifier,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    _EXACT_IMMUTABLE_JSON_SERIALIZER,
    TrustedTimePostEnrollmentAbsentPathProjection,
    TrustedTimePostEnrollmentConsumedMarkerProjection,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology import (
    post_enrollment_created_topology_network_name,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentCreatedTopologyObservation,
    TrustedTimePostEnrollmentFinalActionTopologyObservation,
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    TrustedTimePostEnrollmentTopologyReaderError,
    _authenticated_issuer_runtime_provenance,
    _daemon_identity_view,
    _FixedMarkerProjection,
    _network_identity,
    _NetworkObservation,
    _observe_host_retirements,
    _parse_persistent_barrier_probe,
    _parse_pre_effect_absence_probe,
    _PersistentBarrierProbeProjection,
    _PreEffectAbsenceProbeProjection,
    _raw_sha256,
    _read_receipt_immutable_json,
    _ReadReceipt,
    _ReadReceipts,
    _require_anchored_retirement_observation,
    _require_read_receipt,
    _require_reviewed_created_registration,
    _RuntimeMarkerProjection,
    _validate_staged_paths,
)

POST_ENROLLMENT_START_ACTIVE_CONTROLLER_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-active-controller-v1"
)
POST_ENROLLMENT_START_ACTIVE_CONTROLLER_STATUS = "post_enrollment_start_confirmed"

_RELEASE_EXECUTION_CONTRACT_VERSION = "phase6d-post-enrollment-release-execution-v1"
_PERSISTENT_BARRIER_PROBE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-persistent-barrier-read-probe-v1"
)
_PRE_EFFECT_RUNTIME_ABSENCE_PROBE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-pre-effect-runtime-absence-probe-v1"
)
_PRE_EFFECT_RUNTIME_ABSENCE_COMMAND = (
    "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
    "post-enrollment-pre-effect-runtime-absence",
)
_PERSISTENT_BARRIER_COMMAND = (
    "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
    "post-enrollment-persistent-barrier-read",
)
_RUNTIME_STATE_COMMAND = (
    "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
    "post-enrollment-runtime-state",
)
_RUNTIME_STATE_MAXIMUM_STDOUT_BYTES = 4 * 1_024
_RUNTIME_STATE_TIMEOUT_SECONDS = 122.0
_FINAL_RUNTIME_STATE_TIMEOUT_SECONDS = 2.0
_MINIMUM_RELEASE_BUDGET_SECONDS = 260
_MINIMUM_RELEASE_BUDGET_NANOSECONDS = _MINIMUM_RELEASE_BUDGET_SECONDS * 1_000_000_000
_FIRST_SEQUENCE_TWO_BUDGET_NANOSECONDS = 130 * 1_000_000_000
_SECOND_SEQUENCE_TWO_BUDGET_NANOSECONDS = 50 * 1_000_000_000
_SUCCESS_RETENTION_BUDGET_NANOSECONDS = 5 * 1_000_000_000
_PERSISTENT_BARRIER_MAXIMUM_STDOUT_BYTES = 8 * 1_024
_PRE_EFFECT_RUNTIME_ABSENCE_MAXIMUM_STDOUT_BYTES = 4 * 1_024
_MAXIMUM_DEADLINE_MARKER_BYTES = 512

_PRE_EFFECT_RUNTIME_PATHS = (
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
    POST_ENROLLMENT_START_RELEASE_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
)
_POST_EFFECT_RUNTIME_STAGING_PATHS = (
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_STAGING_PATH,
)

_RUNTIME_STATE_CLOSED_FIELDS = (
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
)


class TrustedTimePostEnrollmentStartActiveControllerRejected(RuntimeError):
    """Inputs were rejected before an exact admission was established."""


class _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(RuntimeError):
    """Normalize one internal failure after exact admission consumption."""


class TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired(RuntimeError):
    """A post-effect failure was durably retained and grants no retry."""

    retained_outcome: RetainedTrustedTimePostEnrollmentStartControllerOutcome

    def __init__(
        self,
        retained_outcome: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    ) -> None:
        if (
            type(retained_outcome) is not RetainedTrustedTimePostEnrollmentStartControllerOutcome
            or retained_outcome.status
            is not TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ):
            raise TrustedTimePostEnrollmentStartActiveControllerRejected(
                "trusted-time active-controller recovery outcome is invalid"
            )
        retained_outcome.__post_init__()
        self.retained_outcome = retained_outcome
        super().__init__("trusted-time active-controller recovery is required")


def _adopt_current_scope_terminal_controller_outcome(
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    recovery_retention_capability: object,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome | None:
    """Adopt only a durable receipt registered by this exact live controller scope."""

    if type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer:
        return None
    try:
        retained = topology_issuer._adopt_registered_confirmed_terminal_outcome(
            choreography_lease,
            recovery_retention_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    except TrustedTimePostEnrollmentTopologyReaderError:
        return None
    if type(retained) is RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        if retained.status is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED:
            return retained
        raise TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired(retained)
    if type(retained) is RetainedTrustedTimePostEnrollmentStartOutcome:
        raise TrustedTimePostEnrollmentStartRecoveryOutcomeRetained(retained)
    raise TrustedTimePostEnrollmentTopologyReaderError(
        "trusted-time confirmed terminal outcome is unavailable"
    )


def _canonical_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


_RuntimeStateProjection = tuple[str, int, str, str]

_RUNTIME_STATE_PREFIX = (
    b'{"alert_delivery_authorized":false,"arming_authorized":false,'
    b'"automatic_rearm_authorized":false,"automatic_resume_authorized":false,'
    b'"broker_action_authorized":false,"contract_version":'
    b'"phase6d-post-enrollment-runtime-state-v1","exposure_authorized":false,'
    b'"live_trading_authorized":false,"new_exposure_authorized":false,'
    b'"operational_control_authorized":false,"paper_trading_authorized":false,'
    b'"readiness_authorized":false,"rearm_authorized":false,'
    b'"release_marker_sha256":'
    b'"0207100f7073e92f22a5acf8ae06e0735ac33e8dfaef7e60c62d387cd0355731",'
    b'"sequence_two_deadline_marker_sha256":"'
)
_RUNTIME_STATE_SUFFIX = (
    b'","sequence_two_ready_marker_sha256":'
    b'"f8faaa629107c4b26b7c70677ee8cc98d67a69741c21fb91300e78b2d9bf5c6d",'
    b'"service":"trusted-time-supervisor",'
    b'"status":"sequence_two_ready_observed"}\n'
)


def _parse_runtime_state_probe(
    raw: object,
    *,
    _prefix: bytes = _RUNTIME_STATE_PREFIX,
    _suffix: bytes = _RUNTIME_STATE_SUFFIX,
    _sha256: Callable[[bytes], str] = _raw_sha256,
) -> _RuntimeStateProjection:
    if (
        type(raw) is not bytes
        or not raw.startswith(_prefix)
        or not raw.endswith(_suffix)
        or len(raw) != len(_prefix) + 64 + len(_suffix)
    ):
        raise ValueError
    deadline_bytes = raw[len(_prefix) : len(_prefix) + 64]
    if any(character not in b"0123456789abcdef" for character in deadline_bytes):
        raise ValueError
    deadline_sha256 = deadline_bytes.decode("ascii", errors="strict")
    if _prefix + deadline_bytes + _suffix != raw:
        raise ValueError
    return (
        "trusted-time-runtime-state-projection-v1",
        len(raw),
        _sha256(raw),
        deadline_sha256,
    )


def _require_runtime_state_projection(
    value: object,
    *,
    _expected_size: int = len(_RUNTIME_STATE_PREFIX) + 64 + len(_RUNTIME_STATE_SUFFIX),
    _is_digest: Callable[[object], bool] = _is_sha256,
) -> _RuntimeStateProjection:
    if (
        type(value) is not tuple
        or len(value) != 4
        or tuple.__getitem__(value, 0) != "trusted-time-runtime-state-projection-v1"
        or type(tuple.__getitem__(value, 1)) is not int
        or tuple.__getitem__(value, 1) != _expected_size
        or not _is_digest(tuple.__getitem__(value, 2))
        or not _is_digest(tuple.__getitem__(value, 3))
    ):
        raise ValueError
    return cast(_RuntimeStateProjection, value)


def _runtime_state_immutable_json(
    value: object,
    *,
    _require: Callable[[object], _RuntimeStateProjection] = (_require_runtime_state_projection),
) -> object:
    projection = _require(value)
    return (
        0,
        (
            ("alert_delivery_authorized", False),
            ("arming_authorized", False),
            ("automatic_rearm_authorized", False),
            ("automatic_resume_authorized", False),
            ("broker_action_authorized", False),
            ("contract_version", "phase6d-post-enrollment-runtime-state-v1"),
            ("exposure_authorized", False),
            ("live_trading_authorized", False),
            ("new_exposure_authorized", False),
            ("operational_control_authorized", False),
            ("paper_trading_authorized", False),
            ("readiness_authorized", False),
            ("rearm_authorized", False),
            (
                "release_marker_sha256",
                "0207100f7073e92f22a5acf8ae06e0735ac33e8dfaef7e60c62d387cd0355731",
            ),
            ("sequence_two_deadline_marker_sha256", tuple.__getitem__(projection, 3)),
            (
                "sequence_two_ready_marker_sha256",
                "f8faaa629107c4b26b7c70677ee8cc98d67a69741c21fb91300e78b2d9bf5c6d",
            ),
            ("service", "trusted-time-supervisor"),
            ("status", "sequence_two_ready_observed"),
        ),
    )


def _marker_immutable_json(
    value: object,
    *,
    _is_digest: Callable[[object], bool] = _is_sha256,
) -> object:
    if type(value) is not tuple:
        raise ValueError
    tag = tuple.__getitem__(value, 0) if value else None
    if tag == "trusted-time-deadline-marker-projection-v1" and len(value) == 7:
        sha256 = tuple.__getitem__(value, 1)
        size = tuple.__getitem__(value, 2)
        device = tuple.__getitem__(value, 3)
        inode = tuple.__getitem__(value, 4)
        modified = tuple.__getitem__(value, 5)
        changed = tuple.__getitem__(value, 6)
        path = "/tmp/post-enrollment-start-sequence-two-deadline"
    elif tag == "trusted-time-ready-marker-projection-v1" and len(value) == 5:
        sha256 = "f8faaa629107c4b26b7c70677ee8cc98d67a69741c21fb91300e78b2d9bf5c6d"
        size = 52
        device = tuple.__getitem__(value, 1)
        inode = tuple.__getitem__(value, 2)
        modified = tuple.__getitem__(value, 3)
        changed = tuple.__getitem__(value, 4)
        path = "/tmp/post-enrollment-start-sequence-two-ready"
    else:
        raise ValueError
    if (
        not _is_digest(sha256)
        or type(size) is not int
        or not 0 < size <= 512
        or type(device) is not int
        or device < 0
        or type(inode) is not int
        or inode < 1
        or type(modified) is not int
        or modified < 0
        or type(changed) is not int
        or changed < 0
    ):
        raise ValueError
    return (
        0,
        (
            ("byte_sha256", sha256),
            ("changed_time_ns", changed),
            ("device", device),
            ("inode", inode),
            ("link_count", 1),
            ("mode", 0o400),
            ("modified_time_ns", modified),
            ("owner_gid", 10_001),
            ("owner_uid", 10_001),
            ("path", path),
            ("regular", True),
            ("size", size),
        ),
    )


def _absence_projections_immutable_json(value: object) -> object:
    if type(value) is not tuple:
        raise ValueError
    result: tuple[object, ...] = ()
    for projection in value:
        if (
            type(projection) is not tuple
            or len(projection) != 2
            or tuple.__getitem__(projection, 0) != "trusted-time-absent-path-projection-v1"
            or type(tuple.__getitem__(projection, 1)) is not str
        ):
            raise ValueError
        result += (
            (
                0,
                (
                    ("path", tuple.__getitem__(projection, 1)),
                    ("status", "absent"),
                ),
            ),
        )
    return (1, result)


def _receipts_immutable_json(
    receipts: object,
    *,
    _receipt_json: Callable[..., object] = _read_receipt_immutable_json,
) -> object:
    if type(receipts) is not tuple:
        raise ValueError
    return (
        1,
        tuple(
            _receipt_json(receipt, expected_ordinal=ordinal)
            for ordinal, receipt in enumerate(receipts, start=1)
        ),
    )


def _registered_fixed_probe_coordinates(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    *,
    _require_registration: Callable[..., tuple[object, ...]] = (
        _require_reviewed_created_registration
    ),
    _runtime_provenance: Callable[..., tuple[object, ...]] = (
        _authenticated_issuer_runtime_provenance
    ),
    _is_digest: Callable[[object], bool] = _is_sha256,
    _fspath: Callable[[os.PathLike[str]], str] = os.fspath,
) -> tuple[str, str, str]:
    with issuer._lifecycle_lock:
        registration = _require_registration(issuer._reviewed_mutation_created_registration)
        runtime_registration = _runtime_provenance(
            issuer,
            issuer._authentication_capability,
        )
        docker_executable = tuple.__getitem__(runtime_registration, 4)
        session_sha256 = tuple.__getitem__(runtime_registration, 5)
        container_ids = tuple.__getitem__(runtime_registration, 6)
        if type(container_ids) is not tuple or len(container_ids) != 2:
            raise ValueError
        container_id = tuple.__getitem__(container_ids, 1)
    if (
        type(container_id) is not str
        or not _is_digest(container_id)
        or type(docker_executable) is not str
        or not docker_executable.startswith("/")
        or tuple.__getitem__(registration, 5) != docker_executable
        or tuple.__getitem__(registration, 4) != container_ids
        or docker_executable != issuer._docker_executable_path_value
        or _fspath(issuer._docker_executable_path) != docker_executable
        or type(session_sha256) is not str
        or not _is_digest(session_sha256)
        or session_sha256 != issuer._session_sha256
    ):
        raise ValueError
    return docker_executable, container_id, session_sha256


def _require_remaining_budget(checkpoint: object, minimum_nanoseconds: int) -> None:
    observed = cast(Any, checkpoint)
    if (
        type(minimum_nanoseconds) is not int
        or minimum_nanoseconds <= 0
        or type(observed.deadline_monotonic_ns) is not int
        or type(observed.observed_monotonic_ns) is not int
        or observed.deadline_monotonic_ns - observed.observed_monotonic_ns < minimum_nanoseconds
    ):
        raise _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(
            "trusted-time active-controller remaining budget is unavailable"
        )


def _retained_claim(
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
) -> RetainedTrustedTimePostEnrollmentStartClaim:
    try:
        retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
        if type(retained) is not RetainedTrustedTimePostEnrollmentStartClaim:
            raise ValueError
        retained.__post_init__()
        if (
            retained.operation_id != admission.operation_id
            or retained.claim.claim_sha256 != admission.claim_sha256
            or retained.artifact_sha256 != admission.retained_claim_artifact_sha256
        ):
            raise ValueError
        return retained
    except BaseException:
        raise TrustedTimePostEnrollmentStartActiveControllerRejected(
            "trusted-time active-controller claim binding is unavailable"
        ) from None


def _nested_materials(
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
) -> tuple[
    TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
    TrustedTimePostEnrollmentCreatedTopologyObservation,
    TrustedTimePostEnrollmentFinalActionTopologyObservation,
    TrustedTimePostEnrollmentStartApproval,
    TrustedTimeApprovedLaunch,
]:
    try:
        action_fence = cast(Any, admission)._action_fence
        claimed = action_fence._claimed_fence
        created = claimed._created_observation
        final = action_fence._final_action_observation
        approval = claimed._approval
        if (
            type(claimed) is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
            or type(created) is not TrustedTimePostEnrollmentCreatedTopologyObservation
            or type(final) is not TrustedTimePostEnrollmentFinalActionTopologyObservation
            or type(approval) is not TrustedTimePostEnrollmentStartApproval
        ):
            raise ValueError
        admission.__post_init__()
        claimed.__post_init__()
        created.__post_init__()
        final.__post_init__()
        approval.__post_init__()
        launch = approval.proposed_launch
        approved_launch = TrustedTimeApprovedLaunch(
            git_revision=launch.git_revision,
            image_admission_sha256=launch.image_admission_sha256,
            source_image_id=launch.source_image_id,
            supervisor_image_id=launch.supervisor_image_id,
        )
        approved_launch.__post_init__()
        return claimed, created, final, approval, approved_launch
    except BaseException:
        raise TrustedTimePostEnrollmentStartActiveControllerRejected(
            "trusted-time active-controller evidence binding is unavailable"
        ) from None


def _require_claim(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    post_effect_capability: object | None,
    choreography_lease: object,
    recovery_retention_capability: object,
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    if not revalidate_retained_post_enrollment_start_claim(
        retained,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    ):
        raise _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(
            "trusted-time active-controller claim changed"
        )
    if post_effect_capability is None:
        issuer._require_armed_recovery_outcome_retention(
            choreography_lease,
            recovery_retention_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        issuer._require_active_choreography_lease(choreography_lease)
    else:
        issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            choreography_lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )


def _observe_pre_effect_runtime_absences(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    receipts: _ReadReceipts,
    *,
    _coordinates: Callable[..., tuple[str, str, str]] = (_registered_fixed_probe_coordinates),
    _parse_probe: Callable[[object], _PreEffectAbsenceProbeProjection] = (
        _parse_pre_effect_absence_probe
    ),
    _require_receipt_exact: Callable[..., _ReadReceipt] = _require_read_receipt,
) -> tuple[_PreEffectAbsenceProbeProjection, _ReadReceipts]:
    docker_executable, supervisor_container_id, _ = _coordinates(issuer)
    raw, updated_receipts = issuer._run_bytes(
        receipts,
        label="pre_effect_runtime_absences",
        argv=(
            docker_executable,
            "container",
            "exec",
            "--user",
            "10001:10001",
            supervisor_container_id,
            "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
            "post-enrollment-pre-effect-runtime-absence",
        ),
        maximum_stdout_bytes=4 * 1_024,
    )
    projection = _parse_probe(raw)
    receipt = _require_receipt_exact(
        tuple.__getitem__(updated_receipts, -1),
        expected_ordinal=len(updated_receipts),
    )
    if tuple.__getitem__(projection, 1) != tuple.__getitem__(receipt, 5) or tuple.__getitem__(
        projection, 2
    ) != tuple.__getitem__(receipt, 6):
        raise ValueError
    return projection, updated_receipts


def _fresh_pre_effect_observation(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    *,
    created: TrustedTimePostEnrollmentCreatedTopologyObservation,
    final: TrustedTimePostEnrollmentFinalActionTopologyObservation,
    approval: TrustedTimePostEnrollmentStartApproval,
    approved_launch: TrustedTimeApprovedLaunch,
    staged_paths: tuple[Path, Path, Path, Path],
    _observe_absences: Callable[..., tuple[_PreEffectAbsenceProbeProjection, _ReadReceipts]] = (
        _observe_pre_effect_runtime_absences
    ),
    _coordinates: Callable[..., tuple[str, str, str]] = (_registered_fixed_probe_coordinates),
    _serialize: Callable[[object], bytes] = _EXACT_IMMUTABLE_JSON_SERIALIZER,
    _sha256: Callable[[bytes], str] = _raw_sha256,
    _receipts_json: Callable[[object], object] = _receipts_immutable_json,
    _absences_json: Callable[[object], object] = _absence_projections_immutable_json,
) -> str:
    receipts: _ReadReceipts = ()
    begun = False
    try:
        issuer._begin_observation(choreography_lease)
        begun = True
        snapshot, receipts = issuer._observe_staged_unreleased_snapshot(
            created_observation=created,
            approval=approval,
            approved_launch=approved_launch,
            staged_paths=staged_paths,
        )
        runtime_absence_probe, receipts = _observe_absences(
            issuer,
            receipts,
        )
        if (
            type(snapshot) is not TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot
            or snapshot.snapshot_sha256 != final.snapshot.snapshot_sha256
            or snapshot.stable_topology_sha256 != final.snapshot.stable_topology_sha256
            or len(receipts) != 17
        ):
            raise ValueError
        issuer._validate_session()
        _, _, session_sha256 = _coordinates(issuer)
        immutable_payload = (
            0,
            (
                (
                    "active_controller_admission_snapshot_sha256",
                    final.snapshot.snapshot_sha256,
                ),
                (
                    "contract_version",
                    "phase6d-post-enrollment-start-active-controller-v1",
                ),
                ("kind", "final_pre_effect_staged_unreleased"),
                ("reads", _receipts_json(receipts)),
                (
                    "runtime_path_absences",
                    _absences_json(tuple.__getitem__(runtime_absence_probe, 3)),
                ),
                ("session_sha256", session_sha256),
            ),
        )
        return _sha256(_serialize(immutable_payload) + b"\n")
    except BaseException:
        if begun:
            with suppress(BaseException):
                issuer._fail_observation()
        raise
    finally:
        if begun:
            try:
                issuer._finish_observation()
            except BaseException:
                with suppress(BaseException), issuer._lifecycle_lock:
                    issuer._busy = False
                    issuer._poison_locked()
                raise


def _run_exact_control(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    *,
    argv: tuple[str, ...],
    timeout_seconds: float,
    maximum_stdout_bytes: int,
    require_empty_stdout: bool,
) -> bytes:
    completed = issuer._run_bound_control(
        argv,
        timeout_seconds=timeout_seconds,
        maximum_stdout_bytes=maximum_stdout_bytes,
        maximum_stderr_bytes=4 * 1_024,
    )
    if type(completed) is not tuple or len(completed) != 4:
        raise _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(
            "trusted-time active-controller command was unconfirmed"
        )
    completed_argv = tuple.__getitem__(completed, 0)
    returncode = tuple.__getitem__(completed, 1)
    stdout = tuple.__getitem__(completed, 2)
    stderr = tuple.__getitem__(completed, 3)
    if (
        completed_argv is not argv
        or type(completed_argv) is not tuple
        or completed_argv != argv
        or any(type(argument) is not str or not argument for argument in completed_argv)
        or type(returncode) is not int
        or returncode != 0
        or type(stdout) is not bytes
        or (require_empty_stdout and stdout)
        or (not require_empty_stdout and not stdout)
        or len(stdout) > maximum_stdout_bytes
        or type(stderr) is not bytes
        or stderr
    ):
        raise _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(
            "trusted-time active-controller command was unconfirmed"
        )
    return stdout


def _execute_release(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    *,
    _coordinates: Callable[..., tuple[str, str, str]] = (_registered_fixed_probe_coordinates),
    _run_control: Callable[..., bytes] = _run_exact_control,
    _serialize: Callable[[object], bytes] = _EXACT_IMMUTABLE_JSON_SERIALIZER,
    _sha256: Callable[[bytes], str] = _raw_sha256,
) -> str:
    docker_executable, supervisor_container_id, session_sha256 = _coordinates(issuer)
    argv = (
        docker_executable,
        "container",
        "exec",
        "--user",
        "10001:10001",
        supervisor_container_id,
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "post-enrollment-release",
    )
    _run_control(
        issuer,
        argv=argv,
        timeout_seconds=issuer._choreography_command_timeout_seconds(),
        maximum_stdout_bytes=1,
        require_empty_stdout=True,
    )
    immutable_payload = (
        0,
        (
            ("argv", (1, argv)),
            ("contract_version", "phase6d-post-enrollment-release-execution-v1"),
            (
                "release_marker_sha256",
                "0207100f7073e92f22a5acf8ae06e0735ac33e8dfaef7e60c62d387cd0355731",
            ),
            ("session_sha256", session_sha256),
        ),
    )
    return _sha256(_serialize(immutable_payload) + b"\n")


def _observe_runtime_state(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    checkpoint: object,
    *,
    maximum_timeout_seconds: float = _RUNTIME_STATE_TIMEOUT_SECONDS,
    _coordinates: Callable[..., tuple[str, str, str]] = (_registered_fixed_probe_coordinates),
    _run_control: Callable[..., bytes] = _run_exact_control,
    _parse_probe: Callable[[object], _RuntimeStateProjection] = _parse_runtime_state_probe,
) -> tuple[_RuntimeStateProjection, str]:
    observed = cast(Any, checkpoint)
    remaining_seconds = (
        observed.deadline_monotonic_ns - observed.observed_monotonic_ns
    ) / 1_000_000_000
    if (
        remaining_seconds <= 0
        or type(maximum_timeout_seconds) is not float
        or not 0 < maximum_timeout_seconds <= _RUNTIME_STATE_TIMEOUT_SECONDS
    ):
        raise ValueError
    docker_executable, supervisor_container_id, _ = _coordinates(issuer)
    argv = (
        docker_executable,
        "container",
        "exec",
        "--user",
        "10001:10001",
        supervisor_container_id,
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "post-enrollment-runtime-state",
    )
    raw = _run_control(
        issuer,
        argv=argv,
        timeout_seconds=min(maximum_timeout_seconds, remaining_seconds),
        maximum_stdout_bytes=4 * 1_024,
        require_empty_stdout=False,
    )
    projection = _parse_probe(raw)
    return projection, projection[2]


def _observe_network_raw(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    receipts: _ReadReceipts,
    *,
    inventory: tuple[str, str],
    expected_create_invocation_sha256: str,
) -> tuple[dict[str, object], _NetworkObservation, _ReadReceipts]:
    expected_network_name = post_enrollment_created_topology_network_name(
        expected_create_invocation_sha256
    )
    observed, updated_receipts = issuer._run_json(
        receipts,
        label="persistent_project_network",
        argv=(
            os.fspath(issuer._docker_executable_path),
            "network",
            "inspect",
            "--format",
            "{{json .}}",
            expected_network_name,
        ),
        maximum_stdout_bytes=512 * 1_024,
        expected_type=dict,
    )
    identity = _network_identity(
        observed,
        expected_inventory=frozenset(inventory),
        expected_state="staged_unreleased",
        expected_network_name=expected_network_name,
        expected_create_invocation_sha256=expected_create_invocation_sha256,
    )
    return observed, identity, updated_receipts


def _require_runtime_marker_chronology(
    *,
    deadline: _RuntimeMarkerProjection,
    release: TrustedTimePostEnrollmentReleaseMarkerProjection,
    sequence: _FixedMarkerProjection,
) -> None:
    if (
        type(deadline) is not tuple
        or len(deadline) != 7
        or deadline[0] != "trusted-time-deadline-marker-projection-v1"
        or type(release) is not tuple
        or len(release) != 5
        or release[0] != "trusted-time-release-marker-projection-v1"
        or type(sequence) is not tuple
        or len(sequence) != 5
        or sequence[0] != "trusted-time-ready-marker-projection-v1"
        or deadline[3] != release[1]
        or release[1] != sequence[1]
        or deadline[4] == release[2]
        or deadline[4] == sequence[2]
        or release[2] == sequence[2]
        or deadline[5] > release[3]
        or deadline[6] > release[4]
        or release[3] > sequence[3]
        or release[4] > sequence[4]
    ):
        raise ValueError


def _observe_persistent_barrier(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    receipts: _ReadReceipts,
    *,
    expected_deadline_marker_sha256: str,
    _coordinates: Callable[..., tuple[str, str, str]] = (_registered_fixed_probe_coordinates),
    _parse_probe: Callable[..., _PersistentBarrierProbeProjection] = (
        _parse_persistent_barrier_probe
    ),
    _require_receipt_exact: Callable[..., _ReadReceipt] = _require_read_receipt,
    _require_chronology: Callable[..., None] = _require_runtime_marker_chronology,
) -> tuple[_PersistentBarrierProbeProjection, _ReadReceipts]:
    docker_executable, supervisor_container_id, _ = _coordinates(issuer)
    raw, updated_receipts = issuer._run_bytes(
        receipts,
        label="persistent_barrier",
        argv=(
            docker_executable,
            "container",
            "exec",
            "--user",
            "10001:10001",
            supervisor_container_id,
            "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
            "post-enrollment-persistent-barrier-read",
        ),
        maximum_stdout_bytes=8 * 1_024,
    )
    projection = _parse_probe(
        raw,
        expected_deadline_sha256=expected_deadline_marker_sha256,
    )
    receipt = _require_receipt_exact(
        tuple.__getitem__(updated_receipts, -1),
        expected_ordinal=len(updated_receipts),
    )
    if tuple.__getitem__(projection, 1) != tuple.__getitem__(receipt, 5) or tuple.__getitem__(
        projection, 2
    ) != tuple.__getitem__(receipt, 6):
        raise ValueError
    _require_chronology(
        deadline=tuple.__getitem__(projection, 4),
        release=tuple.__getitem__(projection, 5),
        sequence=tuple.__getitem__(projection, 6),
    )
    return projection, updated_receipts


def _fresh_persistent_topology(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    *,
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
    final: TrustedTimePostEnrollmentFinalActionTopologyObservation,
    successor: TrustedTimePostEnrollmentStartSuccessor,
    runtime_state: _RuntimeStateProjection,
    approved_launch: TrustedTimeApprovedLaunch,
    staged_paths: tuple[Path, Path, Path, Path],
    _require_runtime_state: Callable[[object], _RuntimeStateProjection] = (
        _require_runtime_state_projection
    ),
    _observe_network: Callable[
        ...,
        tuple[dict[str, object], _NetworkObservation, _ReadReceipts],
    ] = _observe_network_raw,
    _observe_barrier: Callable[..., tuple[_PersistentBarrierProbeProjection, _ReadReceipts]] = (
        _observe_persistent_barrier
    ),
    _observe_retirements: Callable[[tuple[Path, Path, Path, Path]], object] = (
        _observe_host_retirements
    ),
    _require_retirements: Callable[..., tuple[object, ...]] = (
        _require_anchored_retirement_observation
    ),
    _coordinates: Callable[..., tuple[str, str, str]] = (_registered_fixed_probe_coordinates),
    _serialize: Callable[[object], bytes] = _EXACT_IMMUTABLE_JSON_SERIALIZER,
    _sha256: Callable[[bytes], str] = _raw_sha256,
    _receipts_json: Callable[[object], object] = _receipts_immutable_json,
    _absences_json: Callable[[object], object] = _absence_projections_immutable_json,
    _runtime_state_json: Callable[[object], object] = _runtime_state_immutable_json,
    _marker_json: Callable[[object], object] = _marker_immutable_json,
    _daemon_view: Callable[[object], LocalDockerDaemonIdentity] = _daemon_identity_view,
) -> tuple[TrustedTimePostEnrollmentPersistentTopologySnapshot, str]:
    receipts: _ReadReceipts = ()
    begun = False
    try:
        issuer._begin_observation(choreography_lease)
        begun = True
        runtime_state = _require_runtime_state(runtime_state)
        daemon_before, receipts = issuer._observe_daemon(receipts)
        volumes_before, receipts = issuer._observe_volumes(receipts)
        inventory_before, receipts = issuer._observe_inventory(receipts)
        network_before_raw, network_before, receipts = _observe_network(
            issuer,
            receipts,
            inventory=inventory_before,
            expected_create_invocation_sha256=final.session_sha256,
        )
        retirements_before = _observe_retirements(staged_paths)
        deadline_marker_sha256 = tuple.__getitem__(runtime_state, 3)
        barrier_before, receipts = _observe_barrier(
            issuer,
            receipts,
            expected_deadline_marker_sha256=deadline_marker_sha256,
        )
        source_configuration, supervisor_configuration, receipts = (
            issuer._observe_image_configurations(
                receipts,
                approved_launch=approved_launch,
            )
        )
        barrier_after, receipts = _observe_barrier(
            issuer,
            receipts,
            expected_deadline_marker_sha256=deadline_marker_sha256,
        )
        inspections, receipts = issuer._observe_containers(
            receipts,
            inventory=inventory_before,
            network=network_before,
            expected_state="staged_unreleased",
            approved_launch=approved_launch,
            source_configuration=source_configuration,
            supervisor_configuration=supervisor_configuration,
            staged_paths=staged_paths,
            expected_network_name=post_enrollment_created_topology_network_name(
                final.session_sha256
            ),
            expected_create_invocation_sha256=final.session_sha256,
        )
        retirements_after = _observe_retirements(staged_paths)
        inventory_after, receipts = issuer._observe_inventory(receipts)
        network_after_raw, network_after, receipts = _observe_network(
            issuer,
            receipts,
            inventory=inventory_after,
            expected_create_invocation_sha256=final.session_sha256,
        )
        volumes_after, receipts = issuer._observe_volumes(receipts)
        daemon_after, receipts = issuer._observe_daemon(receipts)
        barrier_final, receipts = _observe_barrier(
            issuer,
            receipts,
            expected_deadline_marker_sha256=deadline_marker_sha256,
        )
        retirements_before = _require_retirements(retirements_before)
        retirements_after = _require_retirements(retirements_after)
        if (
            len(receipts) != 17
            or daemon_before != daemon_after
            or tuple.__getitem__(retirements_before, 1) != tuple.__getitem__(retirements_after, 1)
            or network_before.network_id != network_after.network_id
            or network_before.identity_sha256 != network_after.identity_sha256
            or barrier_before != barrier_after
            or barrier_after != barrier_final
        ):
            raise ValueError
        database_before = cast(
            TrustedTimePostEnrollmentConsumedMarkerProjection,
            tuple.__getitem__(barrier_before, 3),
        )
        database_final = cast(
            TrustedTimePostEnrollmentConsumedMarkerProjection,
            tuple.__getitem__(barrier_final, 3),
        )
        deadline_final = cast(
            _RuntimeMarkerProjection,
            tuple.__getitem__(barrier_final, 4),
        )
        release_before = cast(
            TrustedTimePostEnrollmentReleaseMarkerProjection,
            tuple.__getitem__(barrier_before, 5),
        )
        release_final = cast(
            TrustedTimePostEnrollmentReleaseMarkerProjection,
            tuple.__getitem__(barrier_final, 5),
        )
        sequence_final = cast(
            _FixedMarkerProjection,
            tuple.__getitem__(barrier_final, 6),
        )
        absences_before = cast(
            tuple[TrustedTimePostEnrollmentAbsentPathProjection, ...],
            tuple.__getitem__(barrier_before, 7),
        )
        absences_final = cast(
            tuple[TrustedTimePostEnrollmentAbsentPathProjection, ...],
            tuple.__getitem__(barrier_final, 7),
        )
        release_absences_before = (tuple.__getitem__(absences_before, 1),)
        release_absences_after = (tuple.__getitem__(absences_final, 1),)
        retirement_absences_before = cast(
            tuple[TrustedTimePostEnrollmentAbsentPathProjection, ...],
            tuple.__getitem__(retirements_before, 2),
        )
        retirement_absences_after = cast(
            tuple[TrustedTimePostEnrollmentAbsentPathProjection, ...],
            tuple.__getitem__(retirements_after, 2),
        )
        snapshot = validate_post_enrollment_start_persistent_topology(
            admission=admission,
            final_action_staged_topology=final.snapshot,
            successor=successor,
            approved_launch=approved_launch,
            daemon_identity_before=_daemon_view(daemon_before),
            daemon_identity_after=_daemon_view(daemon_after),
            volume_identities_before=volumes_before,
            volume_identities_after=volumes_after,
            project_container_ids_before=inventory_before,
            project_container_ids_after=inventory_after,
            project_network_before=network_before_raw,
            project_network_after=network_after_raw,
            container_inspections=inspections,
            source_image_configuration=source_configuration,
            supervisor_image_configuration=supervisor_configuration,
            expected_database_secret_file=staged_paths[0],
            expected_head_anchor_authority_file=staged_paths[1],
            expected_head_anchor_auth_secret_file=staged_paths[2],
            expected_head_anchor_signing_key_secret_file=staged_paths[3],
            database_secret_consumed_before=database_before,
            database_secret_consumed_after=database_final,
            release_marker_before=release_before,
            release_marker_after=release_final,
            release_staging_absences_before=release_absences_before,
            release_staging_absences_after=release_absences_after,
            staged_input_retirements_before=retirement_absences_before,
            staged_input_retirements_after=retirement_absences_after,
        )
        if (
            snapshot.daemon_context_name != tuple.__getitem__(daemon_before, 1)
            or snapshot.daemon_endpoint != tuple.__getitem__(daemon_before, 2)
            or snapshot.daemon_id != tuple.__getitem__(daemon_before, 3)
        ):
            raise ValueError
        _, _, session_sha256 = _coordinates(issuer)
        immutable_payload = (
            0,
            (
                (
                    "contract_version",
                    "phase6d-post-enrollment-start-active-controller-v1",
                ),
                ("kind", "persistent_post_effect"),
                ("reads", _receipts_json(receipts)),
                ("runtime_deadline_marker", _marker_json(deadline_final)),
                ("runtime_sequence_marker", _marker_json(sequence_final)),
                ("runtime_staging_absences", _absences_json(absences_before)),
                ("runtime_state", _runtime_state_json(runtime_state)),
                ("session_sha256", session_sha256),
                ("snapshot_sha256", snapshot.snapshot_sha256),
            ),
        )
        transcript_sha256 = _sha256(_serialize(immutable_payload) + b"\n")
        return snapshot, transcript_sha256
    except BaseException:
        if begun:
            with suppress(BaseException):
                issuer._fail_observation()
        raise
    finally:
        if begun:
            try:
                issuer._finish_observation()
            except BaseException:
                with suppress(BaseException), issuer._lifecycle_lock:
                    issuer._busy = False
                    issuer._poison_locked()
                raise


def _failure_evidence(
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
    *,
    pre_effect_observation_sha256: str,
    release_execution_sha256: str | None,
    runtime_state_sha256: str | None,
    successor: TrustedTimePostEnrollmentStartSuccessor | None,
    persistent_topology: TrustedTimePostEnrollmentPersistentTopologySnapshot | None,
    persistent_topology_transcript_sha256: str | None,
    verifier_binding_sha256: str,
    read_only_configuration_sha256: str,
    verification_transcript_sha256: str | None,
) -> TrustedTimePostEnrollmentStartControllerOutcomeEvidence:
    if release_execution_sha256 is None:
        reason = TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
        runtime_state_sha256 = None
        successor = None
        persistent_topology = None
        persistent_topology_transcript_sha256 = None
        verification_transcript_sha256 = None
    elif successor is None:
        reason = TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
        persistent_topology = None
        persistent_topology_transcript_sha256 = None
        verification_transcript_sha256 = None
    else:
        if (
            persistent_topology is None
            or persistent_topology_transcript_sha256 is None
            or verification_transcript_sha256 is None
        ):
            raise _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(
                "trusted-time controller success evidence is incomplete"
            )
        reason = TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
    return TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED,
        reason=reason,
        pre_effect_observation_sha256=pre_effect_observation_sha256,
        release_execution_sha256=release_execution_sha256,
        runtime_state_sha256=runtime_state_sha256,
        successor=successor,
        persistent_topology=persistent_topology,
        persistent_topology_transcript_sha256=persistent_topology_transcript_sha256,
        verifier_binding_sha256=verifier_binding_sha256,
        read_only_configuration_sha256=read_only_configuration_sha256,
        verification_transcript_sha256=verification_transcript_sha256,
    )


def run_post_enrollment_start_active_controller(
    *,
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    recovery_retention_capability: object,
    sequence_two_verifier: TrustedTimePostEnrollmentStartSequenceTwoVerifier,
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Consume one exact admission and retain one terminal controller outcome."""

    exact_admission_established = False
    continuation_admission_attempted = False
    post_effect_capability: object | None = None
    release_execution_sha256: str | None = None
    runtime_state_sha256: str | None = None
    runtime_state: _RuntimeStateProjection | None = None
    successor: TrustedTimePostEnrollmentStartSuccessor | None = None
    persistent_topology: TrustedTimePostEnrollmentPersistentTopologySnapshot | None = None
    persistent_transcript_sha256: str | None = None
    pre_effect_observation_sha256: str | None = None
    verifier_binding_sha256: str | None = None
    read_only_configuration_sha256: str | None = None
    verification_transcript_sha256: str | None = None
    action_deadline_monotonic_ns: int | None = None
    sequence_two_verifier_accepted = False
    sequence_two_verifier_abort_attempted = False

    def abort_sequence_two_verifier_once() -> None:
        nonlocal sequence_two_verifier_abort_attempted
        if not sequence_two_verifier_accepted or sequence_two_verifier_abort_attempted:
            return
        sequence_two_verifier_abort_attempted = True
        sequence_two_verifier.abort()

    try:
        if type(admission) is not TrustedTimePostEnrollmentStartActiveControllerAdmission:
            raise ValueError
        exact_admission_established = True
        continuation_admission_attempted = True
        continuation_accepted = _consume_active_controller_continuation(
            admission,
            topology_issuer=topology_issuer,
            choreography_lease=choreography_lease,
            recovery_retention_capability=recovery_retention_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        if not continuation_accepted:
            continuation_admission_attempted = False
            raise ValueError
        if (
            type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
            or type(artifact_directory) is not type(Path())
            or type(ignored_root) is not type(Path())
            or artifact_directory != ignored_root / "trusted-time"
        ):
            raise ValueError
        admission.__post_init__()
        if type(sequence_two_verifier) is not TrustedTimePostEnrollmentStartSequenceTwoVerifier:
            raise ValueError
        sequence_two_verifier_accepted = True
        verifier_binding_sha256 = sequence_two_verifier.verifier_binding_sha256
        read_only_configuration_sha256 = sequence_two_verifier.read_only_configuration_sha256
        if not _is_sha256(verifier_binding_sha256) or not _is_sha256(
            read_only_configuration_sha256
        ):
            raise ValueError
        staged_paths = (
            expected_database_secret_file,
            expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file,
        )
        _validate_staged_paths(staged_paths)
        _claimed, created, final, approval, approved_launch = _nested_materials(admission)
        retained = _retained_claim(admission)
        _require_claim(
            topology_issuer,
            None,
            choreography_lease,
            recovery_retention_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        pre_effect_observation_sha256 = _fresh_pre_effect_observation(
            topology_issuer,
            choreography_lease,
            created=created,
            final=final,
            approval=approval,
            approved_launch=approved_launch,
            staged_paths=staged_paths,
        )
        _require_claim(
            topology_issuer,
            None,
            choreography_lease,
            recovery_retention_capability,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        budget = topology_issuer._require_active_choreography_lease(choreography_lease)
        _require_remaining_budget(budget, _MINIMUM_RELEASE_BUDGET_NANOSECONDS)
        action_deadline_monotonic_ns = budget.deadline_monotonic_ns
        if type(action_deadline_monotonic_ns) is not int:
            raise ValueError
        if pre_effect_observation_sha256 == admission.final_action_observation_sha256:
            raise ValueError
        post_effect_capability = topology_issuer._issue_post_effect_outcome_retention_candidate()
        topology_issuer._transition_to_post_effect_outcome_retention(
            choreography_lease,
            recovery_retention_capability,
            retained,
            post_effect_outcome_candidate=post_effect_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            choreography_lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        release_execution_sha256 = _execute_release(topology_issuer)
        checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            choreography_lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        runtime_state, runtime_state_sha256 = _observe_runtime_state(
            topology_issuer,
            checkpoint,
        )
        checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            choreography_lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        _require_remaining_budget(checkpoint, _FIRST_SEQUENCE_TWO_BUDGET_NANOSECONDS)

        first_observed: TrustedTimeHeadAnchorPostEnrollmentStartPostcondition | None = None
        second_observed: TrustedTimeHeadAnchorPostEnrollmentStartPostcondition | None = None
        try:
            first_observed = sequence_two_verifier.reauthenticate_post_enrollment_start_successor(
                admission=admission,
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                recovery_retention_capability=recovery_retention_capability,
                action_deadline_monotonic_ns=action_deadline_monotonic_ns,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            first_successor = bind_post_enrollment_start_successor(
                claim=retained.claim,
                observed=first_observed,
            )
            topology_issuer._require_active_post_effect_outcome_retention(
                post_effect_capability,
                choreography_lease,
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            persistent_topology, persistent_transcript_sha256 = _fresh_persistent_topology(
                topology_issuer,
                choreography_lease,
                admission=admission,
                final=final,
                successor=first_successor,
                runtime_state=runtime_state,
                approved_launch=approved_launch,
                staged_paths=staged_paths,
            )
            if persistent_transcript_sha256 == persistent_topology.snapshot_sha256:
                raise ValueError
            checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
                post_effect_capability,
                choreography_lease,
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            _require_remaining_budget(checkpoint, _SECOND_SEQUENCE_TWO_BUDGET_NANOSECONDS)
            second_observed = sequence_two_verifier.reauthenticate_post_enrollment_start_successor(
                admission=admission,
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                recovery_retention_capability=recovery_retention_capability,
                action_deadline_monotonic_ns=action_deadline_monotonic_ns,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            repeated_successor = bind_post_enrollment_start_successor(
                claim=retained.claim,
                observed=second_observed,
            )
            if repeated_successor != first_successor:
                raise ValueError
            completed_verification_transcript_sha256 = (
                sequence_two_verifier.verification_transcript_sha256
            )
            if not _is_sha256(completed_verification_transcript_sha256):
                raise ValueError
            checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
                post_effect_capability,
                choreography_lease,
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            final_runtime_state, final_runtime_state_sha256 = _observe_runtime_state(
                topology_issuer,
                checkpoint,
                maximum_timeout_seconds=_FINAL_RUNTIME_STATE_TIMEOUT_SECONDS,
            )
            if (
                final_runtime_state != runtime_state
                or final_runtime_state_sha256 != runtime_state_sha256
            ):
                raise ValueError
            verification_transcript_sha256 = completed_verification_transcript_sha256
            successor = first_successor
        finally:
            abort_sequence_two_verifier_once()
        if first_observed is None or second_observed is None:
            raise ValueError
        checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            choreography_lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        _require_remaining_budget(checkpoint, _SUCCESS_RETENTION_BUDGET_NANOSECONDS)
        success_evidence = TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
            admission=admission,
            status=TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED,
            reason=(
                TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
            ),
            pre_effect_observation_sha256=pre_effect_observation_sha256,
            release_execution_sha256=release_execution_sha256,
            runtime_state_sha256=runtime_state_sha256,
            successor=successor,
            persistent_topology=persistent_topology,
            persistent_topology_transcript_sha256=persistent_transcript_sha256,
            verifier_binding_sha256=verifier_binding_sha256,
            read_only_configuration_sha256=read_only_configuration_sha256,
            verification_transcript_sha256=verification_transcript_sha256,
        )
        return retain_post_enrollment_start_controller_outcome(
            topology_issuer=topology_issuer,
            choreography_lease=choreography_lease,
            post_effect_outcome_capability=post_effect_capability,
            evidence=success_evidence,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
    except BaseException as primary_error:
        causal_error: BaseException = primary_error
        try:
            abort_sequence_two_verifier_once()
        except BaseException as close_error:
            causal_error = close_error
        adopted_terminal = _adopt_current_scope_terminal_controller_outcome(
            topology_issuer,
            choreography_lease,
            recovery_retention_capability,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        if adopted_terminal is not None:
            return adopted_terminal
        if not exact_admission_established:
            raise TrustedTimePostEnrollmentStartActiveControllerRejected(
                "trusted-time active-controller admission is unavailable"
            ) from None
        if post_effect_capability is None:
            if (
                continuation_admission_attempted
                and type(topology_issuer) is TrustedTimePostEnrollmentTopologyObservationIssuer
                and type(artifact_directory) is type(Path())
                and type(ignored_root) is type(Path())
                and artifact_directory == ignored_root / "trusted-time"
            ):
                retain_post_enrollment_start_recovery_required_outcome(
                    topology_issuer=topology_issuer,
                    recovery_retention_capability=recovery_retention_capability,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            raise TrustedTimePostEnrollmentStartActiveControllerRejected(
                "trusted-time active-controller continuation is unavailable"
            ) from None
        try:
            if pre_effect_observation_sha256 is None:
                raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
                    "trusted-time controller pre-effect evidence is unavailable"
                )
            if verifier_binding_sha256 is None or read_only_configuration_sha256 is None:
                raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
                    "trusted-time controller verifier evidence is unavailable"
                )
            failure = _failure_evidence(
                admission,
                pre_effect_observation_sha256=pre_effect_observation_sha256,
                release_execution_sha256=release_execution_sha256,
                runtime_state_sha256=runtime_state_sha256,
                successor=successor,
                persistent_topology=persistent_topology,
                persistent_topology_transcript_sha256=persistent_transcript_sha256,
                verifier_binding_sha256=verifier_binding_sha256,
                read_only_configuration_sha256=read_only_configuration_sha256,
                verification_transcript_sha256=verification_transcript_sha256,
            )
            retained_failure = retain_post_enrollment_start_controller_outcome(
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                post_effect_outcome_capability=post_effect_capability,
                evidence=failure,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        except TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable:
            retain_post_enrollment_start_recovery_required_outcome(
                topology_issuer=topology_issuer,
                recovery_retention_capability=recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            raise AssertionError(
                "trusted-time recovery outcome retention unexpectedly returned"
            ) from None
        except BaseException as retention_error:
            adopted_terminal = _adopt_current_scope_terminal_controller_outcome(
                topology_issuer,
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            if adopted_terminal is not None:
                return adopted_terminal
            if isinstance(
                retention_error,
                TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed,
            ):
                raise
            raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
                "trusted-time controller failure outcome retention is unconfirmed"
            ) from causal_error
        try:
            confirmed_failure = topology_issuer._return_confirmed_post_effect_controller_failure(
                choreography_lease,
                retained_failure,
            )
            if confirmed_failure is not retained_failure:
                raise ValueError
        except BaseException as handoff_error:
            adopted_terminal = _adopt_current_scope_terminal_controller_outcome(
                topology_issuer,
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            if adopted_terminal is not None:
                return adopted_terminal
            raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
                "trusted-time controller failure outcome retention is unconfirmed"
            ) from handoff_error
        raise TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired(
            confirmed_failure
        ) from causal_error


__all__ = [
    "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_STATUS",
    "TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired",
    "TrustedTimePostEnrollmentStartActiveControllerRejected",
    "run_post_enrollment_start_active_controller",
]
