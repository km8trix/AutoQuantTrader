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
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from apps.trusted_time_supervisor.head_anchor_attempt import (
    TrustedTimeHeadAnchorPostEnrollmentStartPostcondition,
)
from apps.trusted_time_supervisor.post_enrollment_release import (
    POST_ENROLLMENT_START_RELEASE_PATH,
    POST_ENROLLMENT_START_RELEASE_SHA256,
    POST_ENROLLMENT_START_RELEASE_STAGING_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_STAGING_PATH,
)
from apps.trusted_time_supervisor.post_enrollment_runtime_state import (
    POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION,
    POST_ENROLLMENT_RUNTIME_STATE_STATUS,
)
from apps.trusted_time_supervisor.post_enrollment_sequence_two_ready import (
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH,
    POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256,
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
    DATABASE_SECRET_CONSUMED_PATH,
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
    TrustedTimePostEnrollmentReleaseMarkerCandidate,
    validate_post_enrollment_start_persistent_topology,
)
from scripts.trusted_time_post_enrollment_sequence_two_verifier import (
    TrustedTimePostEnrollmentStartSequenceTwoVerifier,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    TrustedTimePostEnrollmentAbsentPathCandidate,
    TrustedTimePostEnrollmentConsumedMarkerCandidate,
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_staging import (
    post_enrollment_start_release_argv,
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
    _decode_strict_json,
    _network_identity,
    _NetworkObservation,
    _observe_host_retirements,
    _ReadReceipt,
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
_RUNTIME_STATE_COMMAND = "/opt/venv/bin/autoquant-trusted-time-post-enrollment-runtime-state"
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


def _build_persistent_barrier_probe_source() -> str:
    template = r"""import hashlib,json,os,stat,sys
CONTRACT=__CONTRACT__
PATHS=(__DATABASE__,__DEADLINE__,__RELEASE__,__SEQUENCE__)
STAGINGS=__STAGINGS__
def ident(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,
            value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def absent():
    result=[]
    for path in STAGINGS:
        try:
            os.stat(path,follow_symlinks=False)
        except FileNotFoundError:
            result.append({"path":path,"status":"absent"})
            continue
        raise OSError
    return result
def read(path):
    descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|
                       getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0))
    try:
        before=os.fstat(descriptor)
        chunks=[]
        observed=0
        while True:
            chunk=os.read(descriptor,min(4097-observed,4096))
            if not chunk:
                break
            chunks.append(chunk)
            observed+=len(chunk)
            if observed>4096:
                raise OSError
        after=os.fstat(descriptor)
        named=os.stat(path,follow_symlinks=False)
    finally:
        os.close(descriptor)
    if (ident(before)!=ident(after) or ident(after)!=ident(named)
            or not stat.S_ISREG(before.st_mode)):
        raise OSError
    payload=b"".join(chunks)
    return {"byte_sha256":hashlib.sha256(payload).hexdigest(),
            "changed_time_ns":before.st_ctime_ns,"device":before.st_dev,
            "inode":before.st_ino,"link_count":before.st_nlink,
            "mode":stat.S_IMODE(before.st_mode),"modified_time_ns":before.st_mtime_ns,
            "owner_gid":before.st_gid,"owner_uid":before.st_uid,"path":path,
            "regular":True,"size":len(payload)}
def main():
    before=absent()
    database,deadline,release,sequence=(read(path) for path in PATHS)
    after=absent()
    if before!=after:
        raise OSError
    result={"contract_version":CONTRACT,"database_marker":database,
            "deadline_marker":deadline,"release_marker":release,
            "runtime_staging_absences":before,"sequence_marker":sequence}
    sys.stdout.write(json.dumps(result,allow_nan=False,ensure_ascii=True,
                                separators=(",",":"),sort_keys=True)+"\n")
try:
    main()
except BaseException:
    sys.stderr.write("trusted-time persistent topology probe failed\n")
    raise SystemExit(2)
"""
    return (
        template.replace("__CONTRACT__", repr(_PERSISTENT_BARRIER_PROBE_CONTRACT_VERSION))
        .replace("__DATABASE__", repr(DATABASE_SECRET_CONSUMED_PATH))
        .replace("__DEADLINE__", repr(POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH))
        .replace("__RELEASE__", repr(POST_ENROLLMENT_START_RELEASE_PATH))
        .replace("__SEQUENCE__", repr(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH))
        .replace("__STAGINGS__", repr(_POST_EFFECT_RUNTIME_STAGING_PATHS))
    )


def _build_pre_effect_runtime_absence_probe_source() -> str:
    template = r"""import json,os,sys
CONTRACT=__CONTRACT__
PATHS=__PATHS__
def main():
    absences=[]
    for path in PATHS:
        try:
            os.stat(path,follow_symlinks=False)
        except FileNotFoundError:
            absences.append({"path":path,"status":"absent"})
            continue
        raise OSError
    sys.stdout.write(json.dumps({"absences":absences,"contract_version":CONTRACT},
                                allow_nan=False,ensure_ascii=True,
                                separators=(",",":"),sort_keys=True)+"\n")
try:
    main()
except BaseException:
    sys.stderr.write("trusted-time pre-effect runtime absence probe failed\n")
    raise SystemExit(2)
"""
    return template.replace(
        "__CONTRACT__",
        repr(_PRE_EFFECT_RUNTIME_ABSENCE_PROBE_CONTRACT_VERSION),
    ).replace("__PATHS__", repr(_PRE_EFFECT_RUNTIME_PATHS))


_PERSISTENT_BARRIER_PROBE_SOURCE = _build_persistent_barrier_probe_source()
_PRE_EFFECT_RUNTIME_ABSENCE_PROBE_SOURCE = _build_pre_effect_runtime_absence_probe_source()
del _build_persistent_barrier_probe_source
del _build_pre_effect_runtime_absence_probe_source


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
    receipts: list[_ReadReceipt],
    *,
    supervisor_container_id: str,
) -> tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...]:
    root = issuer._run_json(
        receipts,
        label="pre_effect_runtime_absences",
        argv=(
            os.fspath(issuer._docker_executable_path),
            "container",
            "exec",
            "--user",
            "10001:10001",
            supervisor_container_id,
            "/opt/venv/bin/python",
            "-I",
            "-S",
            "-c",
            _PRE_EFFECT_RUNTIME_ABSENCE_PROBE_SOURCE,
        ),
        maximum_stdout_bytes=_PRE_EFFECT_RUNTIME_ABSENCE_MAXIMUM_STDOUT_BYTES,
        expected_type=dict,
    )
    if (
        set(root) != {"absences", "contract_version"}
        or root.get("contract_version") != _PRE_EFFECT_RUNTIME_ABSENCE_PROBE_CONTRACT_VERSION
        or type(root.get("absences")) is not list
    ):
        raise ValueError
    values = cast(list[object], root["absences"])
    if len(values) != len(_PRE_EFFECT_RUNTIME_PATHS):
        raise ValueError
    candidates: list[TrustedTimePostEnrollmentAbsentPathCandidate] = []
    for expected_path, value in zip(_PRE_EFFECT_RUNTIME_PATHS, values, strict=True):
        if type(value) is not dict:
            raise ValueError
        candidate = TrustedTimePostEnrollmentAbsentPathCandidate(**cast(dict[str, Any], value))
        candidate.__post_init__()
        if candidate.path != expected_path:
            raise ValueError
        candidates.append(candidate)
    return tuple(candidates)


def _fresh_pre_effect_observation(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    *,
    created: TrustedTimePostEnrollmentCreatedTopologyObservation,
    final: TrustedTimePostEnrollmentFinalActionTopologyObservation,
    approval: TrustedTimePostEnrollmentStartApproval,
    approved_launch: TrustedTimeApprovedLaunch,
    staged_paths: tuple[Path, Path, Path, Path],
) -> str:
    receipts: list[_ReadReceipt] = []
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
        runtime_absences = _observe_pre_effect_runtime_absences(
            issuer,
            receipts,
            supervisor_container_id=final.snapshot.supervisor.container_id,
        )
        if (
            type(snapshot) is not TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot
            or snapshot.snapshot_sha256 != final.snapshot.snapshot_sha256
            or snapshot.stable_topology_sha256 != final.snapshot.stable_topology_sha256
            or len(receipts) != 17
        ):
            raise ValueError
        issuer._validate_session()
        return _canonical_sha256(
            {
                "active_controller_admission_snapshot_sha256": final.snapshot.snapshot_sha256,
                "contract_version": POST_ENROLLMENT_START_ACTIVE_CONTROLLER_CONTRACT_VERSION,
                "kind": "final_pre_effect_staged_unreleased",
                "reads": [receipt.payload() for receipt in receipts],
                "runtime_path_absences": [candidate.payload() for candidate in runtime_absences],
                "session_sha256": issuer._session_sha256,
            }
        )
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
    if (
        type(completed) is not subprocess.CompletedProcess
        or completed.args != argv
        or type(completed.returncode) is not int
        or completed.returncode != 0
        or type(completed.stdout) is not bytes
        or (require_empty_stdout and completed.stdout)
        or (not require_empty_stdout and not completed.stdout)
        or len(completed.stdout) > maximum_stdout_bytes
        or type(completed.stderr) is not bytes
        or completed.stderr
    ):
        raise _TrustedTimePostEnrollmentStartActiveControllerExecutionFailed(
            "trusted-time active-controller command was unconfirmed"
        )
    return completed.stdout


def _execute_release(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    supervisor_container_id: str,
) -> str:
    handoff_release_argv = post_enrollment_start_release_argv(supervisor_container_id)
    argv = (os.fspath(issuer._docker_executable_path), *handoff_release_argv[1:])
    _run_exact_control(
        issuer,
        argv=argv,
        timeout_seconds=issuer._choreography_command_timeout_seconds(),
        maximum_stdout_bytes=1,
        require_empty_stdout=True,
    )
    return _canonical_sha256(
        {
            "argv": list(argv),
            "contract_version": _RELEASE_EXECUTION_CONTRACT_VERSION,
            "release_marker_sha256": POST_ENROLLMENT_START_RELEASE_SHA256,
            "session_sha256": issuer._session_sha256,
        }
    )


def _observe_runtime_state(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    supervisor_container_id: str,
    checkpoint: object,
    *,
    maximum_timeout_seconds: float = _RUNTIME_STATE_TIMEOUT_SECONDS,
) -> tuple[dict[str, object], str]:
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
    argv = (
        os.fspath(issuer._docker_executable_path),
        "container",
        "exec",
        "--user",
        "10001:10001",
        supervisor_container_id,
        _RUNTIME_STATE_COMMAND,
    )
    raw = _run_exact_control(
        issuer,
        argv=argv,
        timeout_seconds=min(maximum_timeout_seconds, remaining_seconds),
        maximum_stdout_bytes=_RUNTIME_STATE_MAXIMUM_STDOUT_BYTES,
        require_empty_stdout=False,
    )
    payload = _decode_strict_json(
        raw,
        expected_type=dict,
        maximum_bytes=_RUNTIME_STATE_MAXIMUM_STDOUT_BYTES,
    )
    expected_keys = {
        *_RUNTIME_STATE_CLOSED_FIELDS,
        "contract_version",
        "release_marker_sha256",
        "sequence_two_deadline_marker_sha256",
        "sequence_two_ready_marker_sha256",
        "service",
        "status",
    }
    if (
        set(payload) != expected_keys
        or any(payload[field_name] is not False for field_name in _RUNTIME_STATE_CLOSED_FIELDS)
        or payload.get("contract_version") != POST_ENROLLMENT_RUNTIME_STATE_CONTRACT_VERSION
        or payload.get("release_marker_sha256") != POST_ENROLLMENT_START_RELEASE_SHA256
        or not _is_sha256(payload.get("sequence_two_deadline_marker_sha256"))
        or payload.get("sequence_two_ready_marker_sha256")
        != POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256
        or payload.get("service") != "trusted-time-supervisor"
        or payload.get("status") != POST_ENROLLMENT_RUNTIME_STATE_STATUS
    ):
        raise ValueError
    return payload, _canonical_sha256(payload)


def _observe_network_raw(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    receipts: list[_ReadReceipt],
    *,
    inventory: tuple[str, str],
    expected_create_invocation_sha256: str,
) -> tuple[dict[str, object], _NetworkObservation]:
    expected_network_name = post_enrollment_created_topology_network_name(
        expected_create_invocation_sha256
    )
    observed = issuer._run_json(
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
    return observed, identity


def _exact_sequence_marker(candidate: object) -> dict[str, object]:
    if type(candidate) is not dict:
        raise ValueError
    marker = cast(dict[str, object], candidate)
    if (
        set(marker)
        != {
            "byte_sha256",
            "changed_time_ns",
            "device",
            "inode",
            "link_count",
            "mode",
            "modified_time_ns",
            "owner_gid",
            "owner_uid",
            "path",
            "regular",
            "size",
        }
        or marker["path"] != POST_ENROLLMENT_START_SEQUENCE_TWO_READY_PATH
        or marker["byte_sha256"] != POST_ENROLLMENT_START_SEQUENCE_TWO_READY_SHA256
        or marker["size"] != len(POST_ENROLLMENT_START_SEQUENCE_TWO_READY_BYTES)
        or marker["owner_uid"] != 10_001
        or marker["owner_gid"] != 10_001
        or marker["mode"] != 0o400
        or marker["link_count"] != 1
        or marker["regular"] is not True
        or any(
            type(marker[field_name]) is not int or cast(int, marker[field_name]) < minimum
            for field_name, minimum in (
                ("device", 0),
                ("inode", 1),
                ("modified_time_ns", 0),
                ("changed_time_ns", 0),
            )
        )
    ):
        raise ValueError
    return marker


def _exact_deadline_marker(
    candidate: object,
    *,
    expected_sha256: str,
) -> dict[str, object]:
    if type(candidate) is not dict or not _is_sha256(expected_sha256):
        raise ValueError
    marker = cast(dict[str, object], candidate)
    if (
        set(marker)
        != {
            "byte_sha256",
            "changed_time_ns",
            "device",
            "inode",
            "link_count",
            "mode",
            "modified_time_ns",
            "owner_gid",
            "owner_uid",
            "path",
            "regular",
            "size",
        }
        or marker["path"] != POST_ENROLLMENT_START_SEQUENCE_TWO_DEADLINE_PATH
        or marker["byte_sha256"] != expected_sha256
        or type(marker["size"]) is not int
        or not 0 < marker["size"] <= _MAXIMUM_DEADLINE_MARKER_BYTES
        or marker["owner_uid"] != 10_001
        or marker["owner_gid"] != 10_001
        or marker["mode"] != 0o400
        or marker["link_count"] != 1
        or marker["regular"] is not True
        or any(
            type(marker[field_name]) is not int or cast(int, marker[field_name]) < minimum
            for field_name, minimum in (
                ("device", 0),
                ("inode", 1),
                ("modified_time_ns", 0),
                ("changed_time_ns", 0),
            )
        )
    ):
        raise ValueError
    return marker


def _require_runtime_marker_chronology(
    *,
    deadline: dict[str, object],
    release: TrustedTimePostEnrollmentReleaseMarkerCandidate,
    sequence: dict[str, object],
) -> None:
    if (
        deadline["device"] != release.device
        or release.device != sequence["device"]
        or len({deadline["inode"], release.inode, sequence["inode"]}) != 3
        or cast(int, deadline["modified_time_ns"]) > release.modified_time_ns
        or cast(int, deadline["changed_time_ns"]) > release.changed_time_ns
        or release.modified_time_ns > cast(int, sequence["modified_time_ns"])
        or release.changed_time_ns > cast(int, sequence["changed_time_ns"])
    ):
        raise ValueError


def _observe_persistent_barrier(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    receipts: list[_ReadReceipt],
    *,
    supervisor_container_id: str,
    expected_deadline_marker_sha256: str,
) -> tuple[
    TrustedTimePostEnrollmentConsumedMarkerCandidate,
    dict[str, object],
    TrustedTimePostEnrollmentReleaseMarkerCandidate,
    dict[str, object],
    tuple[TrustedTimePostEnrollmentAbsentPathCandidate, ...],
]:
    root = issuer._run_json(
        receipts,
        label="persistent_barrier",
        argv=(
            os.fspath(issuer._docker_executable_path),
            "container",
            "exec",
            "--user",
            "10001:10001",
            supervisor_container_id,
            "/opt/venv/bin/python",
            "-I",
            "-S",
            "-c",
            _PERSISTENT_BARRIER_PROBE_SOURCE,
        ),
        maximum_stdout_bytes=_PERSISTENT_BARRIER_MAXIMUM_STDOUT_BYTES,
        expected_type=dict,
    )
    if (
        set(root)
        != {
            "contract_version",
            "database_marker",
            "deadline_marker",
            "release_marker",
            "sequence_marker",
            "runtime_staging_absences",
        }
        or root.get("contract_version") != _PERSISTENT_BARRIER_PROBE_CONTRACT_VERSION
        or type(root.get("database_marker")) is not dict
        or type(root.get("deadline_marker")) is not dict
        or type(root.get("release_marker")) is not dict
        or type(root.get("runtime_staging_absences")) is not list
    ):
        raise ValueError
    database = TrustedTimePostEnrollmentConsumedMarkerCandidate(
        **cast(dict[str, Any], root["database_marker"])
    )
    deadline = _exact_deadline_marker(
        root["deadline_marker"],
        expected_sha256=expected_deadline_marker_sha256,
    )
    release = TrustedTimePostEnrollmentReleaseMarkerCandidate(
        **cast(dict[str, Any], root["release_marker"])
    )
    sequence = _exact_sequence_marker(root["sequence_marker"])
    _require_runtime_marker_chronology(
        deadline=deadline,
        release=release,
        sequence=sequence,
    )
    absence_values = cast(list[object], root["runtime_staging_absences"])
    if len(absence_values) != len(_POST_EFFECT_RUNTIME_STAGING_PATHS):
        raise ValueError
    absences: list[TrustedTimePostEnrollmentAbsentPathCandidate] = []
    for expected_path, value in zip(
        _POST_EFFECT_RUNTIME_STAGING_PATHS,
        absence_values,
        strict=True,
    ):
        if type(value) is not dict:
            raise ValueError
        absence = TrustedTimePostEnrollmentAbsentPathCandidate(**cast(dict[str, Any], value))
        absence.__post_init__()
        if absence.path != expected_path:
            raise ValueError
        absences.append(absence)
    return database, deadline, release, sequence, tuple(absences)


def _fresh_persistent_topology(
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    *,
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
    final: TrustedTimePostEnrollmentFinalActionTopologyObservation,
    successor: TrustedTimePostEnrollmentStartSuccessor,
    runtime_state: dict[str, object],
    approved_launch: TrustedTimeApprovedLaunch,
    staged_paths: tuple[Path, Path, Path, Path],
) -> tuple[TrustedTimePostEnrollmentPersistentTopologySnapshot, str]:
    receipts: list[_ReadReceipt] = []
    begun = False
    try:
        issuer._begin_observation(choreography_lease)
        begun = True
        daemon_before = issuer._observe_daemon(receipts)
        volumes_before = issuer._observe_volumes(receipts)
        inventory_before = issuer._observe_inventory(receipts)
        network_before_raw, network_before = _observe_network_raw(
            issuer,
            receipts,
            inventory=inventory_before,
            expected_create_invocation_sha256=final.session_sha256,
        )
        retirements_before = _observe_host_retirements(staged_paths)
        deadline_marker_sha256 = runtime_state.get("sequence_two_deadline_marker_sha256")
        if not _is_sha256(deadline_marker_sha256):
            raise ValueError
        database_before, deadline_before, release_before, sequence_before, absences_before = (
            _observe_persistent_barrier(
                issuer,
                receipts,
                supervisor_container_id=final.snapshot.supervisor.container_id,
                expected_deadline_marker_sha256=cast(str, deadline_marker_sha256),
            )
        )
        source_configuration, supervisor_configuration = issuer._observe_image_configurations(
            receipts,
            approved_launch=approved_launch,
        )
        database_after, deadline_after, release_after, sequence_after, absences_after = (
            _observe_persistent_barrier(
                issuer,
                receipts,
                supervisor_container_id=final.snapshot.supervisor.container_id,
                expected_deadline_marker_sha256=cast(str, deadline_marker_sha256),
            )
        )
        inspections = issuer._observe_containers(
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
        retirements_after = _observe_host_retirements(staged_paths)
        inventory_after = issuer._observe_inventory(receipts)
        network_after_raw, network_after = _observe_network_raw(
            issuer,
            receipts,
            inventory=inventory_after,
            expected_create_invocation_sha256=final.session_sha256,
        )
        volumes_after = issuer._observe_volumes(receipts)
        daemon_after = issuer._observe_daemon(receipts)
        database_final, deadline_final, release_final, sequence_final, absences_final = (
            _observe_persistent_barrier(
                issuer,
                receipts,
                supervisor_container_id=final.snapshot.supervisor.container_id,
                expected_deadline_marker_sha256=cast(str, deadline_marker_sha256),
            )
        )
        if (
            len(receipts) != 17
            or retirements_before.root_identity != retirements_after.root_identity
            or network_before.network_id != network_after.network_id
            or network_before.identity_sha256 != network_after.identity_sha256
            or database_before != database_after
            or database_after != database_final
            or deadline_before != deadline_after
            or deadline_after != deadline_final
            or release_before != release_after
            or release_after != release_final
            or sequence_before != sequence_after
            or sequence_after != sequence_final
            or absences_before != absences_after
            or absences_after != absences_final
        ):
            raise ValueError
        release_absences_before = tuple(
            candidate
            for candidate in absences_before
            if candidate.path == POST_ENROLLMENT_START_RELEASE_STAGING_PATH
        )
        release_absences_after = tuple(
            candidate
            for candidate in absences_final
            if candidate.path == POST_ENROLLMENT_START_RELEASE_STAGING_PATH
        )
        if len(release_absences_before) != 1 or len(release_absences_after) != 1:
            raise ValueError
        snapshot = validate_post_enrollment_start_persistent_topology(
            admission=admission,
            final_action_staged_topology=final.snapshot,
            successor=successor,
            approved_launch=approved_launch,
            daemon_identity_before=daemon_before,
            daemon_identity_after=daemon_after,
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
            staged_input_retirements_before=retirements_before.candidates,
            staged_input_retirements_after=retirements_after.candidates,
        )
        transcript_sha256 = _canonical_sha256(
            {
                "contract_version": POST_ENROLLMENT_START_ACTIVE_CONTROLLER_CONTRACT_VERSION,
                "kind": "persistent_post_effect",
                "reads": [receipt.payload() for receipt in receipts],
                "runtime_staging_absences": [candidate.payload() for candidate in absences_before],
                "runtime_state": runtime_state,
                "runtime_deadline_marker": deadline_final,
                "runtime_sequence_marker": sequence_final,
                "session_sha256": issuer._session_sha256,
                "snapshot_sha256": snapshot.snapshot_sha256,
            }
        )
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
    runtime_state: dict[str, object] | None = None
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
        release_execution_sha256 = _execute_release(
            topology_issuer,
            final.snapshot.supervisor.container_id,
        )
        checkpoint = topology_issuer._require_active_post_effect_outcome_retention(
            post_effect_capability,
            choreography_lease,
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        runtime_state, runtime_state_sha256 = _observe_runtime_state(
            topology_issuer,
            final.snapshot.supervisor.container_id,
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
                final.snapshot.supervisor.container_id,
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
