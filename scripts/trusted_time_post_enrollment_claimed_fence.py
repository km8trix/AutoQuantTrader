"""Code-only claimed pre-release chronology for a future trusted-time start.

This module may durably consume the globally single-use start claim when called,
but it cannot create or start topology, publish or execute the release marker,
observe sequence 2, retain an outcome, or expose a CLI.  It exists so a later
admitted controller can prove that staged ordinal 2 was issued only after the
exact retained claim in one continuously open topology-reader session.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Never, Protocol, SupportsIndex

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.start_trusted_time_supervisor import TrustedTimeApprovedLaunch
from scripts.trusted_time_post_enrollment_staging import (
    TrustedTimePostEnrollmentStartReauthenticationIssuer,
    TrustedTimePostEnrollmentStartStagingHandoff,
    prepare_post_enrollment_start_release_under_lock,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_fence import (
    TrustedTimePostEnrollmentStartPreClaimTopologyFence,
    TrustedTimePostEnrollmentStartPreReleaseTopologyFence,
    bind_post_enrollment_start_pre_release_topology_fence,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentCreatedTopologyObservation,
    TrustedTimePostEnrollmentStagedTopologyObservation,
    TrustedTimePostEnrollmentTopologyObservationCursor,
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    _observe_host_retirements,
    _validate_staged_paths,
)

POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-claimed-pre-release-topology-fence-v1"
)
POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS = (
    "claimed_pre_release_topology_fence_unqualified"
)


class TrustedTimePostEnrollmentStartClaimedFenceRejected(RuntimeError):
    """The chronology was rejected before real claim preparation began."""


class TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(RuntimeError):
    """Claim preparation began, so the single-use operation requires recovery."""


def _authority_is_never_granted(_: object) -> bool:
    return False


def _validate_claimed_fence(value: object) -> None:
    if type(value) is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology fence is invalid"
        )
    try:
        TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence.__post_init__(value)
    except TrustedTimePostEnrollmentStartClaimedFenceRejected:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology fence is invalid"
        ) from None


def _authenticated_fact(value: object) -> bool:
    _validate_claimed_fence(value)
    return True


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _payload_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


def _closed_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update(
        {
            "authority_granted": False,
            "claim_chronology_authenticated": False,
            "claim_retention_authorized": False,
            "container_identity_authenticated": False,
            "created_topology_authenticated": False,
            "current_daemon_session_authenticated": False,
            "current_lock_session_authenticated": False,
            "daemon_identity_authenticated": False,
            "database_secret_consumption_authenticated": False,
            "database_secret_disclosed": False,
            "freshness_authenticated": False,
            "inventory_authenticated": False,
            "persistent_start_authorized": False,
            "release_absence_authenticated": False,
            "release_authorized": False,
            "sequence_2_authorized": False,
            "shutdown_authorized": False,
            "source_start_authenticated": False,
            "source_start_authorized": False,
            "staged_input_retirement_authenticated": False,
            "start_order_authenticated": False,
            "supervisor_start_authenticated": False,
            "supervisor_start_authorized": False,
            "topology_authenticated": False,
            "topology_mutation_authorized": False,
            "volume_identity_authenticated": False,
        }
    )
    return payload


class _ClaimedFenceCapability:
    __slots__ = ()

    def __new__(cls) -> _ClaimedFenceCapability:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release capability is unavailable"
        )


def _require_cursor(
    cursor: TrustedTimePostEnrollmentTopologyObservationCursor,
    *,
    expected_cursor_ordinal: int,
    expected_staged_count: int,
    expected_session_sha256: str,
    expected_created_observation_sha256: str,
    expected_last_observation_sha256: str,
    expected_first_staged_snapshot_sha256: str,
) -> None:
    if type(cursor) is not TrustedTimePostEnrollmentTopologyObservationCursor:
        raise ValueError
    cursor.__post_init__()
    if (
        cursor.cursor_ordinal != expected_cursor_ordinal
        or cursor.staged_observation_count != expected_staged_count
        or cursor.session_sha256 != expected_session_sha256
        or cursor.created_observation_sha256 != expected_created_observation_sha256
        or cursor.last_observation_sha256 != expected_last_observation_sha256
        or cursor.first_staged_snapshot_sha256 != expected_first_staged_snapshot_sha256
    ):
        raise ValueError


def _require_pre_claim_structural_inputs(
    *,
    artifact_directory: Path,
    ignored_root: Path,
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
) -> None:
    if (
        type(artifact_directory) is not type(Path())
        or type(ignored_root) is not type(Path())
        or not artifact_directory.is_absolute()
        or not ignored_root.is_absolute()
        or artifact_directory != Path(os.path.abspath(artifact_directory))
        or ignored_root != Path(os.path.abspath(ignored_root))
        or artifact_directory != ignored_root / "trusted-time"
    ):
        raise ValueError
    staged_root = _validate_staged_paths(
        (
            expected_database_secret_file,
            expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file,
        )
    )
    try:
        staged_root_metadata = os.stat(staged_root, follow_symlinks=False)
    except OSError:
        raise ValueError from None
    if (
        staged_root != artifact_directory / "runtime-secrets"
        or not stat.S_ISDIR(staged_root_metadata.st_mode)
        or staged_root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(staged_root_metadata.st_mode) != 0o700
    ):
        raise ValueError


def _staged_input_retirement_sha256(paths: tuple[Path, Path, Path, Path]) -> str:
    return _payload_sha256(
        [{"path": os.fspath(path), "status": "absent"} for path in sorted(paths, key=os.fspath)]
    )


def _claimed_fence_payload(
    *,
    operation_id: str,
    approval_sha256: str,
    session_sha256: str,
    pre_claim_fence_sha256: str,
    claim_sha256: str,
    retained_claim_artifact_sha256: str,
    pre_claim_cursor_sha256: str,
    post_claim_cursor_sha256: str,
    pre_release_staged_observation_sha256: str,
    pre_release_fence_sha256: str,
    final_cursor_sha256: str,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(
        {
            "approval_sha256": approval_sha256,
            "claim_chronology_authenticated": True,
            "claim_retention_authenticated": True,
            "claim_sha256": claim_sha256,
            "contract_version": (
                POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION
            ),
            "final_cursor_sha256": final_cursor_sha256,
            "final_cursor_session_authenticated": True,
            "observation_provenance_authenticated": True,
            "operation_id": operation_id,
            "ordinal_2_after_claim_authenticated": True,
            "post_claim_cursor_sha256": post_claim_cursor_sha256,
            "pre_claim_cursor_sha256": pre_claim_cursor_sha256,
            "pre_claim_fence_sha256": pre_claim_fence_sha256,
            "pre_release_fence_sha256": pre_release_fence_sha256,
            "pre_release_staged_observation_sha256": (pre_release_staged_observation_sha256),
            "retained_claim_artifact_sha256": retained_claim_artifact_sha256,
            "same_session_observation_chain_authenticated": True,
            "session_sha256": session_sha256,
            "stable_topology_match_authenticated": True,
            "status": POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS,
        }
    )
    return payload


@dataclass(frozen=True, slots=True)
class _ClaimedFenceMaterials:
    approval: TrustedTimePostEnrollmentStartApproval
    created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation
    pre_claim_fence: TrustedTimePostEnrollmentStartPreClaimTopologyFence
    handoff: TrustedTimePostEnrollmentStartStagingHandoff
    pre_claim_cursor: TrustedTimePostEnrollmentTopologyObservationCursor
    post_claim_cursor: TrustedTimePostEnrollmentTopologyObservationCursor
    pre_release_staged_observation: TrustedTimePostEnrollmentStagedTopologyObservation
    pre_release_fence: TrustedTimePostEnrollmentStartPreReleaseTopologyFence
    final_cursor: TrustedTimePostEnrollmentTopologyObservationCursor


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence:
    """Sealed digest projection of exact claim-before-ordinal-2 chronology."""

    operation_id: str
    approval_sha256: str
    session_sha256: str
    pre_claim_fence_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    pre_claim_cursor_sha256: str
    post_claim_cursor_sha256: str
    pre_release_staged_observation_sha256: str
    pre_release_fence_sha256: str
    final_cursor_sha256: str
    _approval: object = field(repr=False, compare=False)
    _created_observation: object = field(repr=False, compare=False)
    _pre_claim_fence: object = field(repr=False, compare=False)
    _handoff: object = field(repr=False, compare=False)
    _pre_claim_cursor: object = field(repr=False, compare=False)
    _post_claim_cursor: object = field(repr=False, compare=False)
    _pre_release_staged_observation: object = field(repr=False, compare=False)
    _pre_release_fence: object = field(repr=False, compare=False)
    _final_cursor: object = field(repr=False, compare=False)
    _capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence:
            raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
                "trusted-time claimed pre-release topology fence is invalid"
            )
        try:
            if (
                type(self._approval) is not TrustedTimePostEnrollmentStartApproval
                or type(self._created_observation)
                is not TrustedTimePostEnrollmentCreatedTopologyObservation
                or type(self._pre_claim_fence)
                is not TrustedTimePostEnrollmentStartPreClaimTopologyFence
                or type(self._handoff) is not TrustedTimePostEnrollmentStartStagingHandoff
                or type(self._pre_claim_cursor)
                is not TrustedTimePostEnrollmentTopologyObservationCursor
                or type(self._post_claim_cursor)
                is not TrustedTimePostEnrollmentTopologyObservationCursor
                or type(self._pre_release_staged_observation)
                is not TrustedTimePostEnrollmentStagedTopologyObservation
                or type(self._pre_release_fence)
                is not TrustedTimePostEnrollmentStartPreReleaseTopologyFence
                or type(self._final_cursor)
                is not TrustedTimePostEnrollmentTopologyObservationCursor
            ):
                raise ValueError
            approval = self._approval
            created = self._created_observation
            pre_claim = self._pre_claim_fence
            handoff = self._handoff
            cursor_one = self._pre_claim_cursor
            cursor_two = self._post_claim_cursor
            ordinal_two = self._pre_release_staged_observation
            pre_release = self._pre_release_fence
            cursor_three = self._final_cursor
            approval.__post_init__()
            created.__post_init__()
            pre_claim.__post_init__()
            handoff.__post_init__()
            ordinal_two.__post_init__()
            pre_release.__post_init__()
            _require_cursor(
                cursor_one,
                expected_cursor_ordinal=1,
                expected_staged_count=1,
                expected_session_sha256=pre_claim.session_sha256,
                expected_created_observation_sha256=pre_claim.created_observation_sha256,
                expected_last_observation_sha256=pre_claim.staged_observation_sha256,
                expected_first_staged_snapshot_sha256=pre_claim.staged_snapshot_sha256,
            )
            _require_cursor(
                cursor_two,
                expected_cursor_ordinal=2,
                expected_staged_count=1,
                expected_session_sha256=pre_claim.session_sha256,
                expected_created_observation_sha256=pre_claim.created_observation_sha256,
                expected_last_observation_sha256=pre_claim.staged_observation_sha256,
                expected_first_staged_snapshot_sha256=pre_claim.staged_snapshot_sha256,
            )
            _require_cursor(
                cursor_three,
                expected_cursor_ordinal=3,
                expected_staged_count=2,
                expected_session_sha256=pre_claim.session_sha256,
                expected_created_observation_sha256=pre_claim.created_observation_sha256,
                expected_last_observation_sha256=ordinal_two.observation_sha256,
                expected_first_staged_snapshot_sha256=pre_claim.staged_snapshot_sha256,
            )
            digests = (
                self.approval_sha256,
                self.session_sha256,
                self.pre_claim_fence_sha256,
                self.claim_sha256,
                self.retained_claim_artifact_sha256,
                self.pre_claim_cursor_sha256,
                self.post_claim_cursor_sha256,
                self.pre_release_staged_observation_sha256,
                self.pre_release_fence_sha256,
                self.final_cursor_sha256,
            )
            retained = handoff.retained_claim
            if (
                any(not _is_sha256(value) for value in digests)
                or self.operation_id != approval.operation_id
                or self.approval_sha256 != approval.approval_sha256
                or handoff.approval != approval
                or handoff.approval_sha256 != approval.approval_sha256
                or created.observation_sha256 != pre_claim.created_observation_sha256
                or self.session_sha256 != pre_claim.session_sha256
                or self.pre_claim_fence_sha256 != pre_claim.fence_sha256
                or self.claim_sha256 != retained.claim.claim_sha256
                or self.retained_claim_artifact_sha256 != retained.artifact_sha256
                or self.pre_claim_cursor_sha256 != cursor_one.cursor_sha256
                or self.post_claim_cursor_sha256 != cursor_two.cursor_sha256
                or self.pre_release_staged_observation_sha256 != ordinal_two.observation_sha256
                or self.pre_release_fence_sha256 != pre_release.fence_sha256
                or self.final_cursor_sha256 != cursor_three.cursor_sha256
                or pre_release.pre_claim_fence_sha256 != pre_claim.fence_sha256
                or pre_release.pre_release_staged_observation_sha256
                != ordinal_two.observation_sha256
                or len(
                    {
                        cursor_one.cursor_sha256,
                        cursor_two.cursor_sha256,
                        cursor_three.cursor_sha256,
                    }
                )
                != 3
                or not _valid_claimed_fence_capability(
                    self._capability,
                    _claimed_fence_payload(
                        operation_id=self.operation_id,
                        approval_sha256=self.approval_sha256,
                        session_sha256=self.session_sha256,
                        pre_claim_fence_sha256=self.pre_claim_fence_sha256,
                        claim_sha256=self.claim_sha256,
                        retained_claim_artifact_sha256=(self.retained_claim_artifact_sha256),
                        pre_claim_cursor_sha256=self.pre_claim_cursor_sha256,
                        post_claim_cursor_sha256=self.post_claim_cursor_sha256,
                        pre_release_staged_observation_sha256=(
                            self.pre_release_staged_observation_sha256
                        ),
                        pre_release_fence_sha256=self.pre_release_fence_sha256,
                        final_cursor_sha256=self.final_cursor_sha256,
                    ),
                    self,
                )
            ):
                raise ValueError
        except TrustedTimePostEnrollmentStartClaimedFenceRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
                "trusted-time claimed pre-release topology fence is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS

    def payload(self) -> dict[str, object]:
        _validate_claimed_fence(self)
        return _claimed_fence_payload(
            operation_id=self.operation_id,
            approval_sha256=self.approval_sha256,
            session_sha256=self.session_sha256,
            pre_claim_fence_sha256=self.pre_claim_fence_sha256,
            claim_sha256=self.claim_sha256,
            retained_claim_artifact_sha256=self.retained_claim_artifact_sha256,
            pre_claim_cursor_sha256=self.pre_claim_cursor_sha256,
            post_claim_cursor_sha256=self.post_claim_cursor_sha256,
            pre_release_staged_observation_sha256=(self.pre_release_staged_observation_sha256),
            pre_release_fence_sha256=self.pre_release_fence_sha256,
            final_cursor_sha256=self.final_cursor_sha256,
        )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology fence cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology fence cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology fence cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology fence cannot be serialized"
        )

    @property
    def fence_sha256(self) -> str:
        return _payload_sha256(self.payload())

    observation_provenance_authenticated = property(_authenticated_fact)
    same_session_observation_chain_authenticated = property(_authenticated_fact)
    stable_topology_match_authenticated = property(_authenticated_fact)
    claim_retention_authenticated = property(_authenticated_fact)
    claim_chronology_authenticated = property(_authenticated_fact)
    ordinal_2_after_claim_authenticated = property(_authenticated_fact)
    final_cursor_session_authenticated = property(_authenticated_fact)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    created_topology_authenticated = property(_authority_is_never_granted)
    current_daemon_session_authenticated = property(_authority_is_never_granted)
    current_lock_session_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_consumption_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    inventory_authenticated = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    release_absence_authenticated = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authenticated = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    staged_input_retirement_authenticated = property(_authority_is_never_granted)
    start_order_authenticated = property(_authority_is_never_granted)
    supervisor_start_authenticated = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    volume_identity_authenticated = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)


def _prepare_post_enrollment_start_claimed_pre_release_materials(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    expected_approval_sha256: str,
    approved_launch: TrustedTimeApprovedLaunch,
    created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation,
    pre_claim_fence: TrustedTimePostEnrollmentStartPreClaimTopologyFence,
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    supervisor_container_id: str,
    reauthentication_issuer: TrustedTimePostEnrollmentStartReauthenticationIssuer,
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> _ClaimedFenceMaterials:
    """Retain one claim and prove ordinal 2 was issued after it; never release."""

    try:
        if (
            type(approval) is not TrustedTimePostEnrollmentStartApproval
            or type(approved_launch) is not TrustedTimeApprovedLaunch
            or type(created_observation) is not TrustedTimePostEnrollmentCreatedTopologyObservation
            or type(pre_claim_fence) is not TrustedTimePostEnrollmentStartPreClaimTopologyFence
            or type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
            or type(expected_approval_sha256) is not str
            or expected_approval_sha256 != approval.approval_sha256
            or not callable(
                getattr(
                    reauthentication_issuer, "reauthenticate_first_enrollment_postcondition", None
                )
            )
            or not callable(getattr(reauthentication_issuer, "close", None))
        ):
            raise ValueError
        approval.__post_init__()
        approved_launch.__post_init__()
        created_observation.__post_init__()
        pre_claim_fence.__post_init__()
        _require_pre_claim_structural_inputs(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            expected_database_secret_file=expected_database_secret_file,
            expected_head_anchor_authority_file=expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file=(
                expected_head_anchor_signing_key_secret_file
            ),
        )
        created_snapshot = created_observation.snapshot
        staged_paths = (
            expected_database_secret_file,
            expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file,
        )
        live_retirements = _observe_host_retirements(staged_paths)
        pre_claim_staged_observation = pre_claim_fence._staged_observation
        if (
            pre_claim_fence.created_observation_sha256 != created_observation.observation_sha256
            or pre_claim_fence.session_sha256 != created_observation.session_sha256
            or pre_claim_fence.created_snapshot_sha256 != created_snapshot.snapshot_sha256
            or created_snapshot.operation_id != approval.operation_id
            or created_snapshot.approval_sha256 != approval.approval_sha256
            or created_snapshot.review_projection_sha256 != approval.review.projection_sha256
            or created_snapshot.confirmed_enrollment_evidence_sha256
            != approval.confirmed_enrollment.evidence_sha256
            or created_snapshot.approved_launch != approval.proposed_launch
            or supervisor_container_id != created_snapshot.supervisor.container_id
            or type(pre_claim_staged_observation)
            is not TrustedTimePostEnrollmentStagedTopologyObservation
            or tuple(candidate.path for candidate in live_retirements.candidates)
            != tuple(os.fspath(path) for path in staged_paths)
            or pre_claim_staged_observation.snapshot.staged_input_retirement_candidate_sha256
            != _staged_input_retirement_sha256(staged_paths)
            or approval.proposed_launch.git_revision != approved_launch.git_revision
            or approval.proposed_launch.image_admission_sha256
            != approved_launch.image_admission_sha256
            or approval.proposed_launch.source_image_id != approved_launch.source_image_id
            or approval.proposed_launch.supervisor_image_id != approved_launch.supervisor_image_id
        ):
            raise ValueError
        cursor_one = topology_issuer.issue_observation_cursor()
        _require_cursor(
            cursor_one,
            expected_cursor_ordinal=1,
            expected_staged_count=1,
            expected_session_sha256=pre_claim_fence.session_sha256,
            expected_created_observation_sha256=pre_claim_fence.created_observation_sha256,
            expected_last_observation_sha256=pre_claim_fence.staged_observation_sha256,
            expected_first_staged_snapshot_sha256=pre_claim_fence.staged_snapshot_sha256,
        )
    except BaseException:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology inputs are unavailable"
        ) from None

    claim_preparation_began = False
    try:
        claim_preparation_began = True
        handoff = prepare_post_enrollment_start_release_under_lock(
            approval=approval,
            expected_approval_sha256=expected_approval_sha256,
            supervisor_container_id=supervisor_container_id,
            reauthentication_issuer=reauthentication_issuer,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        retained = handoff.retained_claim
        if not revalidate_retained_post_enrollment_start_claim(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ):
            raise RuntimeError
        cursor_two = topology_issuer.issue_observation_cursor()
        _require_cursor(
            cursor_two,
            expected_cursor_ordinal=2,
            expected_staged_count=1,
            expected_session_sha256=pre_claim_fence.session_sha256,
            expected_created_observation_sha256=pre_claim_fence.created_observation_sha256,
            expected_last_observation_sha256=pre_claim_fence.staged_observation_sha256,
            expected_first_staged_snapshot_sha256=pre_claim_fence.staged_snapshot_sha256,
        )
        if cursor_two.cursor_sha256 == cursor_one.cursor_sha256:
            raise RuntimeError
        ordinal_two = topology_issuer.issue_staged_unreleased_snapshot(
            created_observation=created_observation,
            approval=approval,
            approved_launch=approved_launch,
            expected_database_secret_file=expected_database_secret_file,
            expected_head_anchor_authority_file=expected_head_anchor_authority_file,
            expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
            expected_head_anchor_signing_key_secret_file=(
                expected_head_anchor_signing_key_secret_file
            ),
        )
        pre_release = bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim_fence,
            ordinal_two,
        )
        cursor_three = topology_issuer.issue_observation_cursor()
        _require_cursor(
            cursor_three,
            expected_cursor_ordinal=3,
            expected_staged_count=2,
            expected_session_sha256=pre_claim_fence.session_sha256,
            expected_created_observation_sha256=pre_claim_fence.created_observation_sha256,
            expected_last_observation_sha256=ordinal_two.observation_sha256,
            expected_first_staged_snapshot_sha256=pre_claim_fence.staged_snapshot_sha256,
        )
        if (
            len({cursor_one.cursor_sha256, cursor_two.cursor_sha256, cursor_three.cursor_sha256})
            != 3
        ):
            raise RuntimeError
        if not revalidate_retained_post_enrollment_start_claim(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ):
            raise RuntimeError
        return _ClaimedFenceMaterials(
            approval=approval,
            created_observation=created_observation,
            pre_claim_fence=pre_claim_fence,
            handoff=handoff,
            pre_claim_cursor=cursor_one,
            post_claim_cursor=cursor_two,
            pre_release_staged_observation=ordinal_two,
            pre_release_fence=pre_release,
            final_cursor=cursor_three,
        )
    except BaseException:
        if claim_preparation_began:
            raise TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(
                "trusted-time claimed pre-release topology requires recovery"
            ) from None
        raise


class _ClaimedFencePreparer(Protocol):
    def __call__(
        self,
        *,
        approval: TrustedTimePostEnrollmentStartApproval,
        expected_approval_sha256: str,
        approved_launch: TrustedTimeApprovedLaunch,
        created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation,
        pre_claim_fence: TrustedTimePostEnrollmentStartPreClaimTopologyFence,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        supervisor_container_id: str,
        reauthentication_issuer: TrustedTimePostEnrollmentStartReauthenticationIssuer,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
        artifact_directory: Path = ...,
        ignored_root: Path = ...,
    ) -> TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence: ...


class _ClaimedFenceCapabilityValidator(Protocol):
    def __call__(
        self,
        candidate: object,
        material: Mapping[str, object],
        result: TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
    ) -> bool: ...


def _build_claimed_fence_preparer(
    prepare_materials: Callable[..., _ClaimedFenceMaterials],
) -> tuple[
    _ClaimedFencePreparer,
    _ClaimedFenceCapabilityValidator,
]:
    registry_lock = threading.Lock()
    origin_pid = os.getpid()
    registrations: dict[object, tuple[str, object | None]] = {}

    def register(material: Mapping[str, object]) -> _ClaimedFenceCapability:
        if os.getpid() != origin_pid:
            raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
                "trusted-time claimed pre-release capability is unavailable"
            )
        capability = object.__new__(_ClaimedFenceCapability)
        with registry_lock:
            registrations[capability] = (_payload_sha256(dict(material)), None)
        return capability

    def unregister(candidate: object) -> None:
        if os.getpid() != origin_pid:
            return
        with registry_lock:
            registrations.pop(candidate, None)

    def valid(
        candidate: object,
        material: Mapping[str, object],
        result: TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
    ) -> bool:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not _ClaimedFenceCapability
            or type(result) is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
        ):
            return False
        material_sha256 = _payload_sha256(dict(material))
        with registry_lock:
            registration = registrations.get(candidate)
            if registration is None or registration[0] != material_sha256:
                return False
            bound_result = registration[1]
            if bound_result is None:
                registrations[candidate] = (material_sha256, result)
                return True
            return bound_result is result

    def prepare_post_enrollment_start_claimed_pre_release_fence(
        *,
        approval: TrustedTimePostEnrollmentStartApproval,
        expected_approval_sha256: str,
        approved_launch: TrustedTimeApprovedLaunch,
        created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation,
        pre_claim_fence: TrustedTimePostEnrollmentStartPreClaimTopologyFence,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        supervisor_container_id: str,
        reauthentication_issuer: TrustedTimePostEnrollmentStartReauthenticationIssuer,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence:
        capability: _ClaimedFenceCapability | None = None
        materials_prepared = False
        try:
            materials = prepare_materials(
                approval=approval,
                expected_approval_sha256=expected_approval_sha256,
                approved_launch=approved_launch,
                created_observation=created_observation,
                pre_claim_fence=pre_claim_fence,
                topology_issuer=topology_issuer,
                supervisor_container_id=supervisor_container_id,
                reauthentication_issuer=reauthentication_issuer,
                expected_database_secret_file=expected_database_secret_file,
                expected_head_anchor_authority_file=expected_head_anchor_authority_file,
                expected_head_anchor_auth_secret_file=(expected_head_anchor_auth_secret_file),
                expected_head_anchor_signing_key_secret_file=(
                    expected_head_anchor_signing_key_secret_file
                ),
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            materials_prepared = True
            retained = materials.handoff.retained_claim
            payload = _claimed_fence_payload(
                operation_id=materials.approval.operation_id,
                approval_sha256=materials.approval.approval_sha256,
                session_sha256=materials.pre_claim_fence.session_sha256,
                pre_claim_fence_sha256=materials.pre_claim_fence.fence_sha256,
                claim_sha256=retained.claim.claim_sha256,
                retained_claim_artifact_sha256=retained.artifact_sha256,
                pre_claim_cursor_sha256=materials.pre_claim_cursor.cursor_sha256,
                post_claim_cursor_sha256=materials.post_claim_cursor.cursor_sha256,
                pre_release_staged_observation_sha256=(
                    materials.pre_release_staged_observation.observation_sha256
                ),
                pre_release_fence_sha256=materials.pre_release_fence.fence_sha256,
                final_cursor_sha256=materials.final_cursor.cursor_sha256,
            )
            capability = register(payload)
            result = TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence(
                operation_id=materials.approval.operation_id,
                approval_sha256=materials.approval.approval_sha256,
                session_sha256=materials.pre_claim_fence.session_sha256,
                pre_claim_fence_sha256=materials.pre_claim_fence.fence_sha256,
                claim_sha256=retained.claim.claim_sha256,
                retained_claim_artifact_sha256=retained.artifact_sha256,
                pre_claim_cursor_sha256=materials.pre_claim_cursor.cursor_sha256,
                post_claim_cursor_sha256=materials.post_claim_cursor.cursor_sha256,
                pre_release_staged_observation_sha256=(
                    materials.pre_release_staged_observation.observation_sha256
                ),
                pre_release_fence_sha256=materials.pre_release_fence.fence_sha256,
                final_cursor_sha256=materials.final_cursor.cursor_sha256,
                _approval=materials.approval,
                _created_observation=materials.created_observation,
                _pre_claim_fence=materials.pre_claim_fence,
                _handoff=materials.handoff,
                _pre_claim_cursor=materials.pre_claim_cursor,
                _post_claim_cursor=materials.post_claim_cursor,
                _pre_release_staged_observation=(materials.pre_release_staged_observation),
                _pre_release_fence=materials.pre_release_fence,
                _final_cursor=materials.final_cursor,
                _capability=capability,
            )
            result.__post_init__()
            return result
        except TrustedTimePostEnrollmentStartClaimedFenceRejected:
            if not materials_prepared:
                raise
            unregister(capability)
            raise TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(
                "trusted-time claimed pre-release topology requires recovery"
            ) from None
        except TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired:
            raise
        except BaseException:
            unregister(capability)
            if not materials_prepared:
                raise
            raise TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(
                "trusted-time claimed pre-release topology requires recovery"
            ) from None

    return prepare_post_enrollment_start_claimed_pre_release_fence, valid


(
    prepare_post_enrollment_start_claimed_pre_release_fence,
    _valid_claimed_fence_capability,
) = _build_claimed_fence_preparer(_prepare_post_enrollment_start_claimed_pre_release_materials)
del _build_claimed_fence_preparer
del _prepare_post_enrollment_start_claimed_pre_release_materials


__all__ = [
    "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
    "TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired",
    "TrustedTimePostEnrollmentStartClaimedFenceRejected",
    "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
    "prepare_post_enrollment_start_claimed_pre_release_fence",
]
