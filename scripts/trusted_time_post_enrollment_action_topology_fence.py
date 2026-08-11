"""Bind one claim-origin lease to a final dormant topology reobservation.

The code-only result proves one full post-claim read under the same armed
recovery choreography.  It cannot release or mutate topology, create sequence
2, start a runtime, retain an outcome, or authorize operational/trading work.
"""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Never, SupportsIndex, cast

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.start_trusted_time_supervisor import TrustedTimeApprovedLaunch
from scripts.trusted_time_post_enrollment_claimed_fence import (
    TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
    _consume_claimed_fence_action_choreography,
)
from scripts.trusted_time_post_enrollment_staging import (
    TrustedTimePostEnrollmentStartStagingHandoff,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentCreatedTopologyObservation,
    TrustedTimePostEnrollmentFinalActionTopologyObservation,
    TrustedTimePostEnrollmentStagedTopologyObservation,
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    _validate_staged_paths,
)

POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-claimed-action-topology-fence-v1"
)
POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS = (
    "claimed_action_topology_fence_unqualified"
)


class TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(RuntimeError):
    """A candidate was rejected before an exact claimed fence was established."""


class TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired(RuntimeError):
    """The durable claim already exists, so this start requires recovery."""


def _authority_is_never_granted(_: object) -> bool:
    return False


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


class _ClaimedActionTopologyObservationAuthorization:
    """Opaque one-shot authorization for the exact reader action observation."""

    __slots__ = ()

    def __new__(cls) -> _ClaimedActionTopologyObservationAuthorization:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology authorization is unavailable"
        )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology authorization cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology authorization cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology authorization cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology authorization cannot be serialized"
        )


class _ClaimedActionTopologyFenceCapability:
    __slots__ = ()

    def __new__(cls) -> _ClaimedActionTopologyFenceCapability:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence capability is unavailable"
        )


def _claimed_action_fence_payload(
    *,
    operation_id: str,
    approval_sha256: str,
    session_sha256: str,
    claim_sha256: str,
    retained_claim_artifact_sha256: str,
    claimed_fence_sha256: str,
    predecessor_observation_sha256: str,
    final_action_observation_sha256: str,
    final_action_snapshot_sha256: str,
    final_action_stable_topology_sha256: str,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(
        {
            "approval_sha256": approval_sha256,
            "claim_chronology_authenticated": True,
            "claim_retention_authenticated": True,
            "claim_sha256": claim_sha256,
            "claimed_fence_sha256": claimed_fence_sha256,
            "contract_version": (
                POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_CONTRACT_VERSION
            ),
            "final_action_observation_sha256": final_action_observation_sha256,
            "final_action_snapshot_sha256": final_action_snapshot_sha256,
            "final_action_stable_topology_sha256": (final_action_stable_topology_sha256),
            "final_action_topology_reobservation_authenticated": True,
            "observation_provenance_authenticated": True,
            "operation_id": operation_id,
            "predecessor_observation_sha256": predecessor_observation_sha256,
            "retained_claim_artifact_sha256": retained_claim_artifact_sha256,
            "retained_claim_revalidated": True,
            "same_session_observation_chain_authenticated": True,
            "session_sha256": session_sha256,
            "stable_topology_match_authenticated": True,
            "status": POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS,
        }
    )
    return payload


def _validate_claimed_action_fence(value: object) -> None:
    if type(value) is not TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence is invalid"
        )
    try:
        TrustedTimePostEnrollmentStartClaimedActionTopologyFence.__post_init__(value)
    except TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence is invalid"
        ) from None


def _authenticated_fact(value: object) -> bool:
    _validate_claimed_action_fence(value)
    return True


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
    """Digest-only proof of one claimed, leased, final full topology read."""

    operation_id: str
    approval_sha256: str
    session_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    claimed_fence_sha256: str
    predecessor_observation_sha256: str
    final_action_observation_sha256: str
    final_action_snapshot_sha256: str
    final_action_stable_topology_sha256: str
    _claimed_fence: object = field(repr=False, compare=False)
    _final_action_observation: object = field(repr=False, compare=False)
    _capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
            raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
                "trusted-time claimed action topology fence is invalid"
            )
        try:
            if (
                type(self._claimed_fence)
                is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
                or type(self._final_action_observation)
                is not TrustedTimePostEnrollmentFinalActionTopologyObservation
            ):
                raise ValueError
            claimed = self._claimed_fence
            final = self._final_action_observation
            claimed.__post_init__()
            final.__post_init__()
            created = cast(
                TrustedTimePostEnrollmentCreatedTopologyObservation,
                claimed._created_observation,
            )
            ordinal_two = cast(
                TrustedTimePostEnrollmentStagedTopologyObservation,
                claimed._pre_release_staged_observation,
            )
            handoff = cast(
                TrustedTimePostEnrollmentStartStagingHandoff,
                claimed._handoff,
            )
            retained = handoff.retained_claim
            if (
                type(created) is not TrustedTimePostEnrollmentCreatedTopologyObservation
                or any(
                    not _is_sha256(value)
                    for value in (
                        self.approval_sha256,
                        self.session_sha256,
                        self.claim_sha256,
                        self.retained_claim_artifact_sha256,
                        self.claimed_fence_sha256,
                        self.predecessor_observation_sha256,
                        self.final_action_observation_sha256,
                        self.final_action_snapshot_sha256,
                        self.final_action_stable_topology_sha256,
                    )
                )
                or self.operation_id != claimed.operation_id
                or self.approval_sha256 != claimed.approval_sha256
                or self.session_sha256 != claimed.session_sha256
                or self.claim_sha256 != claimed.claim_sha256
                or self.retained_claim_artifact_sha256 != claimed.retained_claim_artifact_sha256
                or self.claimed_fence_sha256 != claimed.fence_sha256
                or self.predecessor_observation_sha256 != ordinal_two.observation_sha256
                or self.final_action_observation_sha256 != final.observation_sha256
                or self.final_action_snapshot_sha256 != final.snapshot.snapshot_sha256
                or self.final_action_stable_topology_sha256 != final.snapshot.stable_topology_sha256
                or final.claimed_fence_sha256 != claimed.fence_sha256
                or final.session_sha256 != claimed.session_sha256
                or final.created_observation_sha256 != created.observation_sha256
                or final.predecessor_observation_sha256 != ordinal_two.observation_sha256
                or final.snapshot.snapshot_sha256 != ordinal_two.snapshot.snapshot_sha256
                or final.snapshot.stable_topology_sha256
                != ordinal_two.snapshot.stable_topology_sha256
                or retained.claim.claim_sha256 != self.claim_sha256
                or retained.artifact_sha256 != self.retained_claim_artifact_sha256
                or not _valid_claimed_action_fence_capability(
                    self._capability,
                    _claimed_action_fence_payload(
                        operation_id=self.operation_id,
                        approval_sha256=self.approval_sha256,
                        session_sha256=self.session_sha256,
                        claim_sha256=self.claim_sha256,
                        retained_claim_artifact_sha256=(self.retained_claim_artifact_sha256),
                        claimed_fence_sha256=self.claimed_fence_sha256,
                        predecessor_observation_sha256=(self.predecessor_observation_sha256),
                        final_action_observation_sha256=(self.final_action_observation_sha256),
                        final_action_snapshot_sha256=self.final_action_snapshot_sha256,
                        final_action_stable_topology_sha256=(
                            self.final_action_stable_topology_sha256
                        ),
                    ),
                    self,
                )
            ):
                raise ValueError
        except TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected:
            raise
        except BaseException:
            raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
                "trusted-time claimed action topology fence is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS

    def payload(self) -> dict[str, object]:
        _validate_claimed_action_fence(self)
        return _claimed_action_fence_payload(
            operation_id=self.operation_id,
            approval_sha256=self.approval_sha256,
            session_sha256=self.session_sha256,
            claim_sha256=self.claim_sha256,
            retained_claim_artifact_sha256=self.retained_claim_artifact_sha256,
            claimed_fence_sha256=self.claimed_fence_sha256,
            predecessor_observation_sha256=self.predecessor_observation_sha256,
            final_action_observation_sha256=self.final_action_observation_sha256,
            final_action_snapshot_sha256=self.final_action_snapshot_sha256,
            final_action_stable_topology_sha256=self.final_action_stable_topology_sha256,
        )

    @property
    def fence_sha256(self) -> str:
        return _payload_sha256(self.payload())

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
            "trusted-time claimed action topology fence cannot be serialized"
        )

    claim_chronology_authenticated = property(_authenticated_fact)
    claim_retention_authenticated = property(_authenticated_fact)
    final_action_topology_reobservation_authenticated = property(_authenticated_fact)
    observation_provenance_authenticated = property(_authenticated_fact)
    retained_claim_revalidated = property(_authenticated_fact)
    same_session_observation_chain_authenticated = property(_authenticated_fact)
    stable_topology_match_authenticated = property(_authenticated_fact)
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


def _poison_action(
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> None:
    owner_pid = getattr(topology_issuer, "_owner_pid", None)
    if type(owner_pid) is not int or owner_pid != os.getpid():
        return
    with topology_issuer._lifecycle_lock:
        topology_issuer._poison_locked()


def _build_claimed_action_topology_fence_preparer() -> tuple[
    Callable[..., TrustedTimePostEnrollmentStartClaimedActionTopologyFence],
    Callable[[object, dict[str, object], object], bool],
    Callable[..., bool],
]:
    registry_lock = threading.Lock()
    origin_pid = os.getpid()
    authorizations: dict[
        _ClaimedActionTopologyObservationAuthorization,
        tuple[
            object,
            object,
            object,
            str,
            object,
            object,
            object,
            tuple[Path, Path, Path, Path],
            int,
            threading.Thread,
        ],
    ] = {}
    result_capabilities: dict[
        _ClaimedActionTopologyFenceCapability,
        tuple[str, object | None],
    ] = {}

    def consume_authorization(
        candidate: object,
        *,
        topology_issuer: object,
        choreography_lease: object,
        claimed_fence: object,
        claimed_fence_sha256: object,
        created_observation: object,
        approval: object,
        approved_launch: object,
        staged_paths: object,
    ) -> bool:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not _ClaimedActionTopologyObservationAuthorization
        ):
            return False
        with registry_lock:
            registration = authorizations.pop(candidate, None)
        return bool(
            registration is not None
            and type(claimed_fence_sha256) is str
            and type(staged_paths) is tuple
            and len(staged_paths) == 4
            and all(type(path) is type(Path()) for path in staged_paths)
            and registration[0] is topology_issuer
            and registration[1] is choreography_lease
            and registration[2] is claimed_fence
            and registration[3] == claimed_fence_sha256
            and registration[4] is created_observation
            and registration[5] is approval
            and registration[6] is approved_launch
            and registration[7] == staged_paths
            and registration[8] == os.getpid()
            and registration[9] is threading.current_thread()
        )

    def register_result(
        candidate: _ClaimedActionTopologyFenceCapability,
        material: dict[str, object],
    ) -> None:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not _ClaimedActionTopologyFenceCapability
        ):
            raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
                "trusted-time claimed action topology fence capability is unavailable"
            )
        with registry_lock:
            result_capabilities[candidate] = (_payload_sha256(material), None)

    def unregister_result(candidate: object) -> None:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not _ClaimedActionTopologyFenceCapability
        ):
            return
        with registry_lock:
            result_capabilities.pop(candidate, None)

    def valid_result(
        candidate: object,
        material: dict[str, object],
        result: object,
    ) -> bool:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not _ClaimedActionTopologyFenceCapability
            or type(result) is not TrustedTimePostEnrollmentStartClaimedActionTopologyFence
        ):
            return False
        material_sha256 = _payload_sha256(material)
        with registry_lock:
            registration = result_capabilities.get(candidate)
            if registration is None or registration[0] != material_sha256:
                return False
            if registration[1] is None:
                result_capabilities[candidate] = (material_sha256, result)
                return True
            return registration[1] is result

    def prepare(
        *,
        claimed_fence: TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        choreography_lease: object,
        recovery_retention_capability: object,
        approved_launch: TrustedTimeApprovedLaunch,
        expected_database_secret_file: Path,
        expected_head_anchor_authority_file: Path,
        expected_head_anchor_auth_secret_file: Path,
        expected_head_anchor_signing_key_secret_file: Path,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
        exact_claimed_fence_established = False
        authorization: _ClaimedActionTopologyObservationAuthorization | None = None
        capability: _ClaimedActionTopologyFenceCapability | None = None
        try:
            if (
                type(claimed_fence)
                is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
            ):
                raise ValueError
            exact_claimed_fence_established = True
            if not _consume_claimed_fence_action_choreography(
                claimed_fence,
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                recovery_retention_capability=recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ):
                raise ValueError
            claimed_fence.__post_init__()
            if (
                type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
                or type(approved_launch) is not TrustedTimeApprovedLaunch
                or type(artifact_directory) is not type(Path())
                or type(ignored_root) is not type(Path())
                or artifact_directory != ignored_root / "trusted-time"
            ):
                raise ValueError
            approved_launch.__post_init__()
            staged_paths = (
                expected_database_secret_file,
                expected_head_anchor_authority_file,
                expected_head_anchor_auth_secret_file,
                expected_head_anchor_signing_key_secret_file,
            )
            _validate_staged_paths(staged_paths)
            approval = cast(
                TrustedTimePostEnrollmentStartApproval,
                claimed_fence._approval,
            )
            created = cast(
                TrustedTimePostEnrollmentCreatedTopologyObservation,
                claimed_fence._created_observation,
            )
            ordinal_two = cast(
                TrustedTimePostEnrollmentStagedTopologyObservation,
                claimed_fence._pre_release_staged_observation,
            )
            handoff = cast(
                TrustedTimePostEnrollmentStartStagingHandoff,
                claimed_fence._handoff,
            )
            retained = handoff.retained_claim
            proposed = approval.proposed_launch
            if (
                handoff.artifact_directory != artifact_directory
                or handoff.ignored_root != ignored_root
                or retained.artifact_path.parent != artifact_directory
                or proposed.git_revision != approved_launch.git_revision
                or proposed.image_admission_sha256 != approved_launch.image_admission_sha256
                or proposed.source_image_id != approved_launch.source_image_id
                or proposed.supervisor_image_id != approved_launch.supervisor_image_id
                or created.snapshot.approved_launch != proposed
                or ordinal_two.snapshot.approved_launch != proposed
            ):
                raise ValueError
            topology_issuer._require_armed_recovery_outcome_retention(
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            topology_issuer._require_active_choreography_lease(choreography_lease)
            if not revalidate_retained_post_enrollment_start_claim(
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ):
                raise ValueError
            topology_issuer._require_armed_recovery_outcome_retention(
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            topology_issuer._require_active_choreography_lease(choreography_lease)
            authorization = object.__new__(_ClaimedActionTopologyObservationAuthorization)
            try:
                with registry_lock:
                    authorizations[authorization] = (
                        topology_issuer,
                        choreography_lease,
                        claimed_fence,
                        claimed_fence.fence_sha256,
                        created,
                        approval,
                        approved_launch,
                        staged_paths,
                        os.getpid(),
                        threading.current_thread(),
                    )
                final = topology_issuer._issue_claimed_final_action_topology_snapshot(
                    claimed_action_authorization=authorization,
                    claimed_fence=claimed_fence,
                    claimed_fence_sha256=claimed_fence.fence_sha256,
                    created_observation=created,
                    approval=approval,
                    approved_launch=approved_launch,
                    expected_database_secret_file=staged_paths[0],
                    expected_head_anchor_authority_file=staged_paths[1],
                    expected_head_anchor_auth_secret_file=staged_paths[2],
                    expected_head_anchor_signing_key_secret_file=staged_paths[3],
                    _choreography_lease=choreography_lease,
                )
            finally:
                try:
                    with registry_lock:
                        authorizations.pop(authorization, None)
                except BaseException:
                    with suppress(BaseException), registry_lock:
                        authorizations.pop(authorization, None)
                    raise
            final.__post_init__()
            if not revalidate_retained_post_enrollment_start_claim(
                retained,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ):
                raise ValueError
            topology_issuer._require_armed_recovery_outcome_retention(
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            topology_issuer._require_active_choreography_lease(choreography_lease)
            payload = _claimed_action_fence_payload(
                operation_id=claimed_fence.operation_id,
                approval_sha256=claimed_fence.approval_sha256,
                session_sha256=claimed_fence.session_sha256,
                claim_sha256=claimed_fence.claim_sha256,
                retained_claim_artifact_sha256=(claimed_fence.retained_claim_artifact_sha256),
                claimed_fence_sha256=claimed_fence.fence_sha256,
                predecessor_observation_sha256=(ordinal_two.observation_sha256),
                final_action_observation_sha256=final.observation_sha256,
                final_action_snapshot_sha256=final.snapshot.snapshot_sha256,
                final_action_stable_topology_sha256=(final.snapshot.stable_topology_sha256),
            )
            capability = object.__new__(_ClaimedActionTopologyFenceCapability)
            register_result(capability, payload)
            result = TrustedTimePostEnrollmentStartClaimedActionTopologyFence(
                operation_id=claimed_fence.operation_id,
                approval_sha256=claimed_fence.approval_sha256,
                session_sha256=claimed_fence.session_sha256,
                claim_sha256=claimed_fence.claim_sha256,
                retained_claim_artifact_sha256=(claimed_fence.retained_claim_artifact_sha256),
                claimed_fence_sha256=claimed_fence.fence_sha256,
                predecessor_observation_sha256=ordinal_two.observation_sha256,
                final_action_observation_sha256=final.observation_sha256,
                final_action_snapshot_sha256=final.snapshot.snapshot_sha256,
                final_action_stable_topology_sha256=(final.snapshot.stable_topology_sha256),
                _claimed_fence=claimed_fence,
                _final_action_observation=final,
                _capability=capability,
            )
            result.__post_init__()
            topology_issuer._require_armed_recovery_outcome_retention(
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            topology_issuer._require_active_choreography_lease(choreography_lease)
            return result
        except BaseException:
            if exact_claimed_fence_established:
                try:
                    if type(topology_issuer) is TrustedTimePostEnrollmentTopologyObservationIssuer:
                        _poison_action(topology_issuer)
                finally:
                    with suppress(BaseException):
                        unregister_result(capability)
                raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired(
                    "trusted-time claimed action topology requires recovery"
                ) from None
            unregister_result(capability)
            raise TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected(
                "trusted-time claimed action topology inputs are unavailable"
            ) from None

    return prepare, valid_result, consume_authorization


(
    prepare_post_enrollment_start_leased_claimed_action_topology_fence,
    _valid_claimed_action_fence_capability,
    _consume_claimed_action_topology_observation_authorization,
) = _build_claimed_action_topology_fence_preparer()
del _build_claimed_action_topology_fence_preparer


__all__ = [
    "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS",
    "TrustedTimePostEnrollmentStartClaimedActionTopologyFence",
    "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired",
    "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected",
    "prepare_post_enrollment_start_leased_claimed_action_topology_fence",
]
