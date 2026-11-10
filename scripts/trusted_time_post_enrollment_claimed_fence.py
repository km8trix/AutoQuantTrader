"""Code-only claimed pre-release chronology for a future trusted-time start.

This module may durably consume the globally single-use start claim when called,
but it cannot create or start topology, publish or execute the release marker,
observe sequence 2, retain an outcome, or expose a CLI.  It exists so a later
admitted controller can prove that staged ordinal 2 was issued only after the
exact retained claim in one continuously open topology-reader session.
"""

from __future__ import annotations

import _thread
import hashlib
import os
import stat
import threading
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MemberDescriptorType
from typing import TYPE_CHECKING, Any, Never, Protocol, SupportsIndex

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
    _prepare_post_enrollment_start_release_under_lock_with_salvage,
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
    _AnchoredRetirementObservation,
    _finalize_claimed_fence_recovery_binder_recipe,
    _observe_host_retirements,
    _require_anchored_retirement_observation,
    _stage_claimed_fence_recovery_binder_authorization_type,
    _stage_claimed_fence_recovery_binder_recipe,
    _TrustedTimePostEnrollmentRecoveryClaimBinder,
    _TrustedTimePostEnrollmentRecoveryRetentionCapability,
    _TrustedTimePostEnrollmentTopologyChoreographyLease,
    _validate_staged_paths,
)

_EXACT_RLOCK_TYPE = type(threading.RLock())
_EXACT_PATH_TYPE = type(Path())

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


def _preferred_control_error(
    primary: BaseException | None,
    candidate: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if candidate is not None and not isinstance(candidate, Exception):
        return candidate
    return primary if primary is not None else candidate


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


@_stage_claimed_fence_recovery_binder_authorization_type
class _ClaimedFenceRecoveryBinderAuthorization:
    """Opaque one-shot authority minted only inside claimed chronology."""

    __slots__ = ()

    def __new__(cls) -> _ClaimedFenceRecoveryBinderAuthorization:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time recovery binder authorization is unavailable"
        )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time recovery binder authorization cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time recovery binder authorization cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time recovery binder authorization cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time recovery binder authorization cannot be serialized"
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
    _choreography_lease: object | None = None,
    _recovery_retention_capability: object | None = None,
    _recovery_binder_issuer: Callable[
        ...,
        None,
    ],
    _recovery_binder_failure: Callable[..., None],
    _recovery_binder_salvager: Callable[..., bool],
    _observe_retirements: Callable[[tuple[Path, Path, Path, Path]], object] = (
        _observe_host_retirements
    ),
    _require_retirements: Callable[[object], _AnchoredRetirementObservation] = (
        _require_anchored_retirement_observation
    ),
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
            or (_recovery_retention_capability is not None and _choreography_lease is None)
            or not callable(_recovery_binder_issuer)
            or not callable(_recovery_binder_salvager)
        ):
            raise ValueError
        approval.__post_init__()
        approved_launch.__post_init__()
        created_observation.__post_init__()
        pre_claim_fence.__post_init__()
        if _choreography_lease is not None:
            topology_issuer._require_active_choreography_lease(_choreography_lease)
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
        live_retirements = _require_retirements(_observe_retirements(staged_paths))
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
            or tuple(projection[1] for projection in live_retirements[2])
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
        if _choreography_lease is None:
            cursor_one = topology_issuer.issue_observation_cursor()
        else:
            cursor_one = topology_issuer.issue_observation_cursor(
                _choreography_lease=_choreography_lease
            )
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
    retained_claim_binder: _TrustedTimePostEnrollmentRecoveryClaimBinder | None = None
    binder_binding_may_have_begun = False
    try:
        if _choreography_lease is not None:
            topology_issuer._require_active_choreography_lease(_choreography_lease)

        if _recovery_retention_capability is not None:
            if _choreography_lease is None:
                raise RuntimeError
            retained_claim_binder = object.__new__(_TrustedTimePostEnrollmentRecoveryClaimBinder)
            _recovery_binder_issuer(
                topology_issuer=topology_issuer,
                choreography_lease=_choreography_lease,
                recovery_retention_capability=_recovery_retention_capability,
                recovery_claim_binder=retained_claim_binder,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )

        claim_preparation_began = True
        if retained_claim_binder is None:
            handoff = prepare_post_enrollment_start_release_under_lock(
                approval=approval,
                expected_approval_sha256=expected_approval_sha256,
                supervisor_container_id=supervisor_container_id,
                reauthentication_issuer=reauthentication_issuer,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
        else:
            binder_binding_may_have_begun = True

            def salvage_retained_claim(
                *,
                recovery_claim_binder: object,
                claim: object,
                artifact_directory: object,
                ignored_root: object,
                retain_salvaged_claim: object,
            ) -> bool:
                return _recovery_binder_salvager(
                    topology_issuer=topology_issuer,
                    recovery_claim_binder=recovery_claim_binder,
                    claim=claim,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                    retain_salvaged_claim=retain_salvaged_claim,
                )

            handoff = _prepare_post_enrollment_start_release_under_lock_with_salvage(
                approval=approval,
                expected_approval_sha256=expected_approval_sha256,
                supervisor_container_id=supervisor_container_id,
                reauthentication_issuer=reauthentication_issuer,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
                _retained_claim_binder=retained_claim_binder,
                _retained_claim_salvager=salvage_retained_claim,
            )
        if _choreography_lease is not None:
            topology_issuer._require_active_choreography_lease(_choreography_lease)
        retained = handoff.retained_claim
        if not revalidate_retained_post_enrollment_start_claim(
            retained,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ):
            raise RuntimeError
        if _choreography_lease is None:
            cursor_two = topology_issuer.issue_observation_cursor()
        else:
            cursor_two = topology_issuer.issue_observation_cursor(
                _choreography_lease=_choreography_lease
            )
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
        ordinal_two_arguments = {
            "created_observation": created_observation,
            "approval": approval,
            "approved_launch": approved_launch,
            "expected_database_secret_file": expected_database_secret_file,
            "expected_head_anchor_authority_file": expected_head_anchor_authority_file,
            "expected_head_anchor_auth_secret_file": expected_head_anchor_auth_secret_file,
            "expected_head_anchor_signing_key_secret_file": (
                expected_head_anchor_signing_key_secret_file
            ),
        }
        if _choreography_lease is None:
            ordinal_two = topology_issuer.issue_staged_unreleased_snapshot(**ordinal_two_arguments)
        else:
            ordinal_two = topology_issuer.issue_staged_unreleased_snapshot(
                **ordinal_two_arguments,
                _choreography_lease=_choreography_lease,
            )
        pre_release = bind_post_enrollment_start_pre_release_topology_fence(
            pre_claim_fence,
            ordinal_two,
        )
        if _choreography_lease is None:
            cursor_three = topology_issuer.issue_observation_cursor()
        else:
            cursor_three = topology_issuer.issue_observation_cursor(
                _choreography_lease=_choreography_lease
            )
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
        if _choreography_lease is not None:
            topology_issuer._require_active_choreography_lease(_choreography_lease)
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
    except BaseException as primary_error:
        cleanup_error: BaseException | None = None
        if retained_claim_binder is not None:
            try:
                _recovery_binder_failure(
                    topology_issuer=topology_issuer,
                    recovery_claim_binder=retained_claim_binder,
                    binding_may_have_begun=binder_binding_may_have_begun,
                )
            except BaseException as error:
                cleanup_error = error
        terminal_error = _preferred_control_error(primary_error, cleanup_error)
        if terminal_error is not None and not isinstance(terminal_error, Exception):
            raise terminal_error from None
        if claim_preparation_began:
            raise TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(
                "trusted-time claimed pre-release topology requires recovery"
            ) from None
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology inputs are unavailable"
        ) from None


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
        _choreography_lease: object | None = ...,
        _recovery_retention_capability: object | None = ...,
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
    *,
    _rlock_type: Callable[[], Any] = _EXACT_RLOCK_TYPE,
    _rlock_acquire: Callable[..., object] = _EXACT_RLOCK_TYPE.acquire,
    _rlock_release: Callable[..., object] = _EXACT_RLOCK_TYPE.release,
    _rlock_recursion_count: Callable[..., object] = (
        _EXACT_RLOCK_TYPE.__dict__["_recursion_count"]
    ),
    _base_exception_type: type[BaseException] = BaseException,
    _ordinary_exception_type: type[Exception] = Exception,
    _exact_int_type: type[int] = int,
    _exact_type: Callable[[object], type[object]] = type,
    _exact_range: Callable[..., range] = range,
    _exact_isinstance: Callable[[object, type[object]], bool] = isinstance,
    _exact_any: Callable[..., bool] = any,
    _exact_len: Callable[..., int] = len,
    _exact_tuple_type: type[tuple[object, ...]] = tuple,
    _exact_str_type: type[str] = str,
    _runtime_error_new: Callable[..., RuntimeError] = RuntimeError.__new__,
    _runtime_error_type: type[RuntimeError] = RuntimeError,
    _id: Callable[[object], int] = id,
    _getpid: Callable[[], int] = os.getpid,
    _fspath: Callable[[os.PathLike[str]], str] = os.fspath,
    _path_type: type[Path] = _EXACT_PATH_TYPE,
    _authorization_type: type[object] = _ClaimedFenceRecoveryBinderAuthorization,
    _recovery_binder_type: type[object] = _TrustedTimePostEnrollmentRecoveryClaimBinder,
    _issuer_type: type[object] = TrustedTimePostEnrollmentTopologyObservationIssuer,
    _issue_recovery_binder: Callable[..., None] = (
        TrustedTimePostEnrollmentTopologyObservationIssuer._issue_recovery_retention_claim_binder
    ),
    _weakref: Callable[..., weakref.ReferenceType[object]] = weakref.ref,
    _weakref_type: type[weakref.ReferenceType[object]] = weakref.ReferenceType,
    _weakref_callback_descriptor: MemberDescriptorType = (
        weakref.ReferenceType.__dict__["__callback__"]
    ),
    _member_descriptor_get: Callable[..., object] = MemberDescriptorType.__get__,
    _stage_reader_recovery_binder_recipe: Callable[..., None] = (
        _stage_claimed_fence_recovery_binder_recipe
    ),
    _thread_local_type: type[object] = _thread._local,
    _thread_local_getattribute: Callable[..., object] = (
        _thread._local.__dict__["__getattribute__"]
    ),
    _thread_local_setattr: Callable[..., None] = _thread._local.__dict__["__setattr__"],
    _attribute_error_type: type[AttributeError] = AttributeError,
    _exact_object_type: type[object] = object,
    _choreography_lease_type: type[object] = (_TrustedTimePostEnrollmentTopologyChoreographyLease),
    _recovery_capability_type: type[object] = (
        _TrustedTimePostEnrollmentRecoveryRetentionCapability
    ),
    _salvage_binder: Callable[..., bool] = (
        TrustedTimePostEnrollmentTopologyObservationIssuer._salvage_recovery_retention_claim_binder
    ),
) -> tuple[
    _ClaimedFencePreparer,
    _ClaimedFenceCapabilityValidator,
    Callable[..., bool],
]:
    if not TYPE_CHECKING:
        _ClaimedFenceRecoveryBinderAuthorization = _authorization_type
        _TrustedTimePostEnrollmentRecoveryClaimBinder = _recovery_binder_type
        any = _exact_any
        int = _exact_int_type
        isinstance = _exact_isinstance
        len = _exact_len
        object = _exact_object_type
        range = _exact_range
        str = _exact_str_type
        tuple = _exact_tuple_type
        type = _exact_type

    def sealed_bridge_error(message: str) -> RuntimeError:
        candidate = _runtime_error_new(_runtime_error_type, message)
        if _exact_type(candidate) is not _runtime_error_type:
            raise _base_exception_type
        return candidate

    def preferred_control_error(
        primary: BaseException | None,
        candidate: BaseException | None,
    ) -> BaseException | None:
        if primary is not None and not isinstance(primary, _ordinary_exception_type):
            return primary
        if candidate is not None and not isinstance(candidate, _ordinary_exception_type):
            return candidate
        return primary if primary is not None else candidate

    def exact_rlock_depth(lock: object) -> int:
        if _exact_type(lock) is not _rlock_type:
            raise sealed_bridge_error(
                "trusted-time recovery binder authorization lock is unavailable"
            )
        depth: int = _rlock_recursion_count(lock)  # type: ignore[assignment]
        if _exact_type(depth) is not _exact_int_type or depth < 0:
            raise sealed_bridge_error(
                "trusted-time recovery binder authorization lock is unavailable"
            )
        return depth

    def restore_rlock_depth(
        lock: object,
        expected_depth: int,
        record_error: Callable[[BaseException], None],
    ) -> bool:
        for _ in _exact_range(8):
            try:
                depth = exact_rlock_depth(lock)
            except _base_exception_type as error:
                record_error(error)
                continue
            if depth == expected_depth:
                return True
            try:
                if depth > expected_depth:
                    _rlock_release(lock)
                elif _rlock_acquire(lock) is not True:
                    raise sealed_bridge_error(
                        "trusted-time recovery binder authorization lock is unavailable"
                    )
            except _base_exception_type as error:
                record_error(error)
        try:
            return exact_rlock_depth(lock) == expected_depth
        except _base_exception_type as error:
            record_error(error)
            return False

    def run_under_exact_rlock[RegistryResult](
        lock: object,
        operation: Callable[[], RegistryResult],
    ) -> RegistryResult:
        initial_depth = exact_rlock_depth(lock)
        body_completed = False
        result: RegistryResult
        primary_error: BaseException | None = None
        transition_error: BaseException | None = None
        cleanup_error: BaseException | None = None

        def record_cleanup_error(error: BaseException) -> None:
            nonlocal cleanup_error
            cleanup_error = preferred_control_error(cleanup_error, error)

        try:
            try:
                if _rlock_acquire(lock) is not True:
                    raise sealed_bridge_error(
                        "trusted-time recovery binder authorization lock is unavailable"
                    )
                result = operation()
                body_completed = True
            except _base_exception_type as error:
                primary_error = error
            finally:
                restore_rlock_depth(lock, initial_depth, record_cleanup_error)
        except _base_exception_type as error:
            transition_error = error
        finally:
            restore_rlock_depth(lock, initial_depth, record_cleanup_error)
        try:
            restored = exact_rlock_depth(lock) == initial_depth
        except _base_exception_type as error:
            record_cleanup_error(error)
            restored = False
        terminal = preferred_control_error(
            preferred_control_error(primary_error, transition_error),
            cleanup_error,
        )
        if terminal is not None:
            raise terminal
        if not body_completed or not restored:
            raise sealed_bridge_error(
                "trusted-time recovery binder authorization lock is unavailable"
            )
        return result

    def sealed_normpath(value: str) -> str:
        if type(value) is not str or not value.startswith("/"):
            return ""
        resolved: tuple[str, ...] = ()
        for component in value.split("/"):
            if component == "" or component == ".":
                continue
            if component == "..":
                if resolved:
                    resolved = resolved[:-1]
                continue
            resolved = (*resolved, component)
        return "/" if not resolved else "/" + "/".join(resolved)

    registry_lock = _rlock_type()
    recovery_binder_registry_lock = _rlock_type()
    recovery_binder_thread_local = _thread_local_type()
    origin_pid = _getpid()
    registrations: dict[object, tuple[str, object | None]] = {}
    claimed_action_choreographies: dict[
        _ClaimedFenceCapability,
        tuple[object, object | None, object | None, Path, Path, int, threading.Thread],
    ] = {}
    consumed_claimed_action_origins: dict[
        _ClaimedFenceCapability,
        weakref.ReferenceType[TrustedTimePostEnrollmentTopologyObservationIssuer],
    ] = {}
    recovery_binder_authorizations: dict[
        int,
        tuple[
            weakref.ReferenceType[object],
            object,
            object,
            object,
            str,
            str,
            int,
            object,
            _ClaimedFenceRecoveryBinderAuthorization,
        ],
    ] = {}

    def recovery_binder_thread_token() -> object:
        try:
            token = _thread_local_getattribute(
                recovery_binder_thread_local,
                "trusted_time_thread_token",
            )
        except _attribute_error_type:
            candidate = _exact_object_type()
            _thread_local_setattr(
                recovery_binder_thread_local,
                "trusted_time_thread_token",
                candidate,
            )
            token = _thread_local_getattribute(
                recovery_binder_thread_local,
                "trusted_time_thread_token",
            )
        if type(token) is not _exact_object_type:
            raise sealed_bridge_error("trusted-time recovery binder authorization is unavailable")
        return token

    def run_under_registry_lock[RegistryResult](
        operation: Callable[[], RegistryResult],
    ) -> RegistryResult:
        return run_under_exact_rlock(registry_lock, operation)

    def run_under_recovery_binder_registry_lock[RegistryResult](
        operation: Callable[[], RegistryResult],
    ) -> RegistryResult:
        return run_under_exact_rlock(recovery_binder_registry_lock, operation)

    def recovery_binder_authorizations_are_exact_locked(
        allow_dead_references: bool,
    ) -> bool:
        seen_binders: list[object] = []
        for authorization_key, registration in recovery_binder_authorizations.items():
            if (
                type(authorization_key) is not int
                or type(registration) is not tuple
                or len(registration) != 9
                or type(registration[0]) is not _weakref_type
                or type(registration[1]) is not _choreography_lease_type
                or type(registration[2]) is not _recovery_capability_type
                or type(registration[3]) is not _TrustedTimePostEnrollmentRecoveryClaimBinder
                or type(registration[4]) is not str
                or type(registration[5]) is not str
                or type(registration[6]) is not int
                or type(registration[7]) is not _exact_object_type
                or type(registration[8]) is not _ClaimedFenceRecoveryBinderAuthorization
                or _id(registration[8]) != authorization_key
                or any(registration[3] is binder for binder in seen_binders)
            ):
                recovery_binder_authorizations.clear()
                return False
            registration_reference = registration[0]
            registration_referent = registration_reference()
            registration_callback = _member_descriptor_get(
                _weakref_callback_descriptor,
                registration_reference,
                _weakref_type,
            )
            if not (
                registration_callback is retire_lost_recovery_binder_issuer
                or (
                    allow_dead_references
                    and registration_referent is None
                    and registration_callback is None
                )
            ):
                recovery_binder_authorizations.clear()
                return False
            seen_binders.append(registration[3])
        return True

    def retire_lost_recovery_binder_issuer(issuer_reference: object) -> None:
        if _getpid() != origin_pid:
            return
        cleanup_confirmed = False

        def retire_lost_issuer_locked() -> None:
            nonlocal cleanup_confirmed
            if (
                type(issuer_reference) is not _weakref_type
                or issuer_reference() is not None
                or _member_descriptor_get(
                    _weakref_callback_descriptor,
                    issuer_reference,
                    _weakref_type,
                )
                is not None
                or not recovery_binder_authorizations_are_exact_locked(True)
            ):
                recovery_binder_authorizations.clear()
                raise sealed_bridge_error(
                    "trusted-time recovery binder authorization cleanup is unavailable"
                )
            for authorization, registration in tuple(recovery_binder_authorizations.items()):
                if registration[0]() is None:
                    recovery_binder_authorizations.pop(authorization, None)
            if any(
                registration[0]() is None
                for registration in recovery_binder_authorizations.values()
            ):
                recovery_binder_authorizations.clear()
                raise sealed_bridge_error(
                    "trusted-time recovery binder authorization cleanup is unavailable"
                )
            cleanup_confirmed = True

        for _ in _exact_range(4):
            try:
                run_under_recovery_binder_registry_lock(retire_lost_issuer_locked)
            except _base_exception_type:
                continue
            if cleanup_confirmed:
                return

    _stage_reader_recovery_binder_recipe(
        recovery_binder_authorizations,
        recovery_binder_registry_lock,
        recovery_binder_thread_local,
        origin_pid,
        _choreography_lease_type,
        _recovery_capability_type,
        retire_lost_recovery_binder_issuer,
        (
            _rlock_type,
            _rlock_acquire,
            _rlock_release,
            _rlock_recursion_count,
            _base_exception_type,
            _ordinary_exception_type,
            _exact_int_type,
            _exact_type,
            _exact_range,
            _exact_isinstance,
            _exact_any,
            _exact_len,
            _exact_tuple_type,
            _exact_str_type,
            _exact_object_type,
            _runtime_error_type,
            _runtime_error_new,
            _id,
            _weakref,
            _weakref_type,
            _weakref_callback_descriptor,
            _member_descriptor_get,
            _getpid,
            _fspath,
            _path_type,
            _thread_local_type,
            _thread_local_getattribute,
            _thread_local_setattr,
            _attribute_error_type,
            _authorization_type,
            _recovery_binder_type,
            _issuer_type,
            _issue_recovery_binder,
        ),
    )

    def recovery_binder_path_values(
        artifact_directory: object,
        ignored_root: object,
    ) -> tuple[str, str]:
        if type(artifact_directory) is not _path_type or type(ignored_root) is not _path_type:
            raise sealed_bridge_error("trusted-time recovery binder authorization is unavailable")
        artifact_directory_value = _fspath(artifact_directory)
        ignored_root_value = _fspath(ignored_root)
        if (
            type(artifact_directory_value) is not str
            or type(ignored_root_value) is not str
            or not ignored_root_value.startswith("/")
            or sealed_normpath(ignored_root_value) != ignored_root_value
            or artifact_directory_value != sealed_normpath(ignored_root_value + "/trusted-time")
        ):
            raise sealed_bridge_error("trusted-time recovery binder authorization is unavailable")
        return artifact_directory_value, ignored_root_value

    def issue_recovery_binder(
        *,
        topology_issuer: object,
        choreography_lease: object,
        recovery_retention_capability: object,
        recovery_claim_binder: object,
        artifact_directory: object,
        ignored_root: object,
    ) -> None:
        if (
            _getpid() != origin_pid
            or type(topology_issuer) is not _issuer_type
            or type(choreography_lease) is not _choreography_lease_type
            or type(recovery_retention_capability) is not _recovery_capability_type
            or type(recovery_claim_binder) is not _TrustedTimePostEnrollmentRecoveryClaimBinder
        ):
            raise sealed_bridge_error("trusted-time recovery binder authorization is unavailable")
        artifact_directory_value, ignored_root_value = recovery_binder_path_values(
            artifact_directory,
            ignored_root,
        )
        authorization = _exact_object_type.__new__(_ClaimedFenceRecoveryBinderAuthorization)
        authorization_key = _id(authorization)

        issuer_reference = _weakref(
            topology_issuer,
            retire_lost_recovery_binder_issuer,
        )

        def register_authorization_locked() -> None:
            if not recovery_binder_authorizations_are_exact_locked(False) or any(
                registration[3] is recovery_claim_binder
                for registration in recovery_binder_authorizations.values()
            ):
                recovery_binder_authorizations.clear()
                raise sealed_bridge_error(
                    "trusted-time recovery binder authorization is unavailable"
                )
            recovery_binder_authorizations[authorization_key] = (
                issuer_reference,
                choreography_lease,
                recovery_retention_capability,
                recovery_claim_binder,
                artifact_directory_value,
                ignored_root_value,
                _getpid(),
                recovery_binder_thread_token(),
                authorization,
            )
            if not recovery_binder_authorizations_are_exact_locked(False):
                raise sealed_bridge_error(
                    "trusted-time recovery binder authorization is unavailable"
                )

        primary_error: BaseException | None = None
        cleanup_error: BaseException | None = None
        cleanup_confirmed = False

        def retire_authorization_locked() -> None:
            if not recovery_binder_authorizations_are_exact_locked(False):
                recovery_binder_authorizations.clear()
                raise sealed_bridge_error(
                    "trusted-time recovery binder authorization cleanup is unavailable"
                )
            recovery_binder_authorizations.pop(authorization_key, None)
            if authorization_key in recovery_binder_authorizations:
                recovery_binder_authorizations.clear()
                raise sealed_bridge_error(
                    "trusted-time recovery binder authorization cleanup is unavailable"
                )

        def retire_authorization_once() -> None:
            nonlocal cleanup_confirmed, cleanup_error
            try:
                run_under_recovery_binder_registry_lock(retire_authorization_locked)
                cleanup_confirmed = True
            except _base_exception_type as error:
                cleanup_error = preferred_control_error(cleanup_error, error)

        try:
            try:
                run_under_recovery_binder_registry_lock(register_authorization_locked)
                _issue_recovery_binder(
                    topology_issuer,
                    choreography_lease,
                    recovery_retention_capability,
                    recovery_claim_binder,
                    claimed_fence_authorization=authorization,
                    artifact_directory=artifact_directory,
                    ignored_root=ignored_root,
                )
            except _base_exception_type as error:
                primary_error = error
        finally:
            try:
                retire_authorization_once()
            finally:
                try:
                    if not cleanup_confirmed:
                        retire_authorization_once()
                finally:
                    try:
                        if not cleanup_confirmed:
                            retire_authorization_once()
                    finally:
                        if not cleanup_confirmed:
                            retire_authorization_once()

        terminal_error = preferred_control_error(primary_error, cleanup_error)
        if terminal_error is not None and not isinstance(terminal_error, _ordinary_exception_type):
            raise terminal_error from None
        if primary_error is not None:
            raise primary_error
        if not cleanup_confirmed:
            raise sealed_bridge_error(
                "trusted-time recovery binder authorization cleanup is unavailable"
            ) from cleanup_error

    def fail_recovery_binder(
        *,
        topology_issuer: object,
        recovery_claim_binder: object,
        binding_may_have_begun: object,
    ) -> None:
        if (
            os.getpid() != origin_pid
            or type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
            or type(recovery_claim_binder) is not _TrustedTimePostEnrollmentRecoveryClaimBinder
            or type(binding_may_have_begun) is not bool
        ):
            raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
                "trusted-time recovery binder cleanup is unavailable"
            )
        TrustedTimePostEnrollmentTopologyObservationIssuer._fail_recovery_retention_claim_binder(
            topology_issuer,
            recovery_claim_binder,
            binding_may_have_begun=binding_may_have_begun,
        )

    def salvage_recovery_binder(
        *,
        topology_issuer: object,
        recovery_claim_binder: object,
        claim: object,
        artifact_directory: object,
        ignored_root: object,
        retain_salvaged_claim: object,
    ) -> bool:
        if (
            os.getpid() != origin_pid
            or type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
            or type(recovery_claim_binder) is not _TrustedTimePostEnrollmentRecoveryClaimBinder
            or type(artifact_directory) is not type(Path())
            or type(ignored_root) is not type(Path())
            or not callable(retain_salvaged_claim)
        ):
            return False
        return _salvage_binder(
            topology_issuer,
            recovery_claim_binder,
            claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            retain_salvaged_claim=retain_salvaged_claim,
        )

    def register(
        candidate: _ClaimedFenceCapability,
        material: Mapping[str, object],
        *,
        topology_issuer: object,
        choreography_lease: object | None,
        recovery_retention_capability: object | None,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        if os.getpid() != origin_pid or type(candidate) is not _ClaimedFenceCapability:
            raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
                "trusted-time claimed pre-release capability is unavailable"
            )

        def register_locked() -> None:
            registrations[candidate] = (_payload_sha256(dict(material)), None)
            claimed_action_choreographies[candidate] = (
                topology_issuer,
                choreography_lease,
                recovery_retention_capability,
                artifact_directory,
                ignored_root,
                os.getpid(),
                threading.current_thread(),
            )

        run_under_registry_lock(register_locked)

    def unregister(candidate: object) -> None:
        if os.getpid() != origin_pid or type(candidate) is not _ClaimedFenceCapability:
            return

        def unregister_locked() -> bool:
            claimed_action_choreographies.pop(candidate, None)
            consumed_claimed_action_origins.pop(candidate, None)
            registrations.pop(candidate, None)
            return (
                candidate not in claimed_action_choreographies
                and candidate not in consumed_claimed_action_origins
                and candidate not in registrations
            )

        cleanup_error: BaseException | None = None
        cleanup_confirmed = False
        for _ in range(4):
            try:
                cleanup_confirmed = run_under_registry_lock(unregister_locked)
                if cleanup_confirmed:
                    break
            except _base_exception_type as error:
                cleanup_error = preferred_control_error(cleanup_error, error)
        if cleanup_error is not None and not isinstance(cleanup_error, _ordinary_exception_type):
            raise cleanup_error from None
        if not cleanup_confirmed:
            raise TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(
                "trusted-time claimed pre-release capability cleanup is unavailable"
            ) from cleanup_error

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

        def valid_locked() -> bool:
            registration = registrations.get(candidate)
            if registration is None or registration[0] != material_sha256:
                return False
            bound_result = registration[1]
            if bound_result is None:
                registrations[candidate] = (material_sha256, result)
                return True
            return bound_result is result

        return run_under_registry_lock(valid_locked)

    def consume_claimed_action_choreography(
        candidate: object,
        *,
        topology_issuer: object,
        choreography_lease: object,
        recovery_retention_capability: object,
        artifact_directory: object,
        ignored_root: object,
    ) -> bool:
        """Consume the exact claim-origin binding before any final action read."""

        if (
            os.getpid() != origin_pid
            or type(candidate) is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
        ):
            return False
        capability = candidate._capability
        if type(capability) is not _ClaimedFenceCapability:
            return False
        origin: (
            tuple[object, object | None, object | None, Path, Path, int, threading.Thread] | None
        ) = None
        consumed_origin: (
            weakref.ReferenceType[TrustedTimePostEnrollmentTopologyObservationIssuer] | None
        ) = None
        replayed_origin: TrustedTimePostEnrollmentTopologyObservationIssuer | None = None
        try:
            with registry_lock:
                registration = registrations.get(capability)
                origin = claimed_action_choreographies.pop(capability, None)
                consumed_origin = consumed_claimed_action_origins.get(capability)
            if origin is None:
                replayed_origin = consumed_origin() if consumed_origin is not None else None
                if type(replayed_origin) is TrustedTimePostEnrollmentTopologyObservationIssuer:
                    with replayed_origin._lifecycle_lock:
                        replayed_origin._poison_locked()
                return False
            accepted = bool(
                registration is not None
                and registration[1] is candidate
                and getattr(origin[0], "_poisoned", False) is False
                and getattr(origin[0], "_closed", False) is False
                and origin[0] is topology_issuer
                and origin[1] is choreography_lease
                and origin[2] is recovery_retention_capability
                and recovery_retention_capability is not None
                and origin[3] == artifact_directory
                and origin[4] == ignored_root
                and origin[5] == os.getpid()
                and origin[6] is threading.current_thread()
            )
            if not accepted:
                origin_issuer = origin[0]
                if type(origin_issuer) is TrustedTimePostEnrollmentTopologyObservationIssuer:
                    with origin_issuer._lifecycle_lock:
                        origin_issuer._poison_locked()
            else:
                origin_issuer = origin[0]
                assert type(origin_issuer) is TrustedTimePostEnrollmentTopologyObservationIssuer
                with registry_lock:
                    consumed_claimed_action_origins[capability] = weakref.ref(origin_issuer)
            return accepted
        except BaseException:
            if origin is None:
                with registry_lock:
                    origin = claimed_action_choreographies.pop(capability, None)
                    consumed_origin = consumed_claimed_action_origins.get(capability)
                if consumed_origin is not None:
                    replayed_origin = consumed_origin()
            if origin is not None:
                origin_issuer = origin[0]
                if type(origin_issuer) is TrustedTimePostEnrollmentTopologyObservationIssuer:
                    with origin_issuer._lifecycle_lock:
                        origin_issuer._poison_locked()
            elif type(replayed_origin) is TrustedTimePostEnrollmentTopologyObservationIssuer:
                with replayed_origin._lifecycle_lock:
                    replayed_origin._poison_locked()
            raise

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
        _choreography_lease: object | None = None,
        _recovery_retention_capability: object | None = None,
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
                _choreography_lease=_choreography_lease,
                _recovery_retention_capability=_recovery_retention_capability,
                _recovery_binder_issuer=issue_recovery_binder,
                _recovery_binder_failure=fail_recovery_binder,
                _recovery_binder_salvager=salvage_recovery_binder,
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
            capability = object.__new__(_ClaimedFenceCapability)
            register(
                capability,
                payload,
                topology_issuer=topology_issuer,
                choreography_lease=_choreography_lease,
                recovery_retention_capability=_recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
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
            if _choreography_lease is not None:
                topology_issuer._require_active_choreography_lease(_choreography_lease)
            return result
        except BaseException as primary_error:
            cleanup_error: BaseException | None = None
            if materials_prepared:
                try:
                    unregister(capability)
                except BaseException as error:
                    cleanup_error = error
            terminal_error = preferred_control_error(primary_error, cleanup_error)
            if terminal_error is not None and not isinstance(
                terminal_error, _ordinary_exception_type
            ):
                raise terminal_error from None
            if isinstance(
                primary_error,
                TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired,
            ):
                raise primary_error
            if not materials_prepared:
                raise primary_error
            raise TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired(
                "trusted-time claimed pre-release topology requires recovery"
            ) from cleanup_error

    return (
        prepare_post_enrollment_start_claimed_pre_release_fence,
        valid,
        consume_claimed_action_choreography,
    )


(
    prepare_post_enrollment_start_claimed_pre_release_fence,
    _valid_claimed_fence_capability,
    _consume_claimed_fence_action_choreography,
) = _build_claimed_fence_preparer(_prepare_post_enrollment_start_claimed_pre_release_materials)
_finalize_claimed_fence_recovery_binder_recipe()


def prepare_post_enrollment_start_leased_claimed_pre_release_fence(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    expected_approval_sha256: str,
    approved_launch: TrustedTimeApprovedLaunch,
    created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation,
    pre_claim_fence: TrustedTimePostEnrollmentStartPreClaimTopologyFence,
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    supervisor_container_id: str,
    reauthentication_issuer: TrustedTimePostEnrollmentStartReauthenticationIssuer,
    expected_database_secret_file: Path,
    expected_head_anchor_authority_file: Path,
    expected_head_anchor_auth_secret_file: Path,
    expected_head_anchor_signing_key_secret_file: Path,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    recovery_retention_capability: object | None = None,
) -> TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence:
    """Run the unchanged claimed chronology under one active private lease."""

    try:
        topology_issuer._require_active_choreography_lease(choreography_lease)
    except BaseException:
        raise TrustedTimePostEnrollmentStartClaimedFenceRejected(
            "trusted-time claimed pre-release topology inputs are unavailable"
        ) from None
    return prepare_post_enrollment_start_claimed_pre_release_fence(
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
        expected_head_anchor_auth_secret_file=expected_head_anchor_auth_secret_file,
        expected_head_anchor_signing_key_secret_file=(expected_head_anchor_signing_key_secret_file),
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        _choreography_lease=choreography_lease,
        _recovery_retention_capability=recovery_retention_capability,
    )


__all__ = [
    "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
    "TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired",
    "TrustedTimePostEnrollmentStartClaimedFenceRejected",
    "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
    "prepare_post_enrollment_start_claimed_pre_release_fence",
    "prepare_post_enrollment_start_leased_claimed_pre_release_fence",
]
