"""Reserve one exact, inert continuation for a future active controller.

This process-private seam consumes the action-fence choreography origin and
revalidates its live action and recovery context.  It performs no Docker,
release, SQL, provider, runtime, or outcome action and grants no authority.
"""

from __future__ import annotations

import hashlib
import os
import threading
import weakref
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Never, SupportsIndex, cast

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_action_topology_fence import (
    TrustedTimePostEnrollmentStartClaimedActionTopologyFence,
    _consume_claimed_action_fence_controller_choreography,
)
from scripts.trusted_time_post_enrollment_claimed_fence import (
    TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
)
from scripts.trusted_time_post_enrollment_staging import (
    TrustedTimePostEnrollmentStartStagingHandoff,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyObservationIssuer,
)

POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-active-controller-admission-v1"
)
POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS = "active_controller_admission_unqualified"


class TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(RuntimeError):
    """A candidate was rejected before an exact action fence was established."""


class TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired(RuntimeError):
    """The durable claim exists, so a failed admission requires recovery."""


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


_CLOSED_ADMISSION_FIELDS = (
    "active_controller_authorized",
    "authority_granted",
    "claim_retention_authorized",
    "container_identity_authenticated",
    "controller_execution_authorized",
    "created_topology_authenticated",
    "current_daemon_session_authenticated",
    "current_lock_session_authenticated",
    "daemon_identity_authenticated",
    "database_secret_consumption_authenticated",
    "database_secret_disclosed",
    "freshness_authenticated",
    "inventory_authenticated",
    "outcome_retention_authorized",
    "persistent_start_authorized",
    "persistent_start_confirmed",
    "release_absence_authenticated",
    "release_attempted",
    "release_authorized",
    "release_confirmed",
    "runtime_start_authorized",
    "runtime_start_confirmed",
    "sequence_2_authorized",
    "sequence_2_confirmed",
    "shutdown_authorized",
    "source_start_authenticated",
    "source_start_authorized",
    "staged_input_retirement_authenticated",
    "start_order_authenticated",
    "success_outcome_retained",
    "success_outcome_retention_authorized",
    "supervisor_start_authenticated",
    "supervisor_start_authorized",
    "topology_authenticated",
    "topology_mutation_authorized",
    "topology_qualified",
    "volume_identity_authenticated",
)


def _closed_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update({field_name: False for field_name in _CLOSED_ADMISSION_FIELDS})
    return payload


class _ActiveControllerAdmissionCapability:
    __slots__ = ()

    def __new__(cls) -> _ActiveControllerAdmissionCapability:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission capability is unavailable"
        )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission capability cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission capability cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission capability cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission capability cannot be serialized"
        )


_ActiveControllerContinuation = tuple[
    object,
    weakref.ReferenceType[TrustedTimePostEnrollmentTopologyObservationIssuer],
    object,
    object,
    Path,
    Path,
    int,
    threading.Thread,
]


def _admission_payload(
    *,
    operation_id: str,
    approval_sha256: str,
    session_sha256: str,
    claim_sha256: str,
    retained_claim_artifact_sha256: str,
    claimed_action_fence_sha256: str,
    final_action_observation_sha256: str,
    final_action_snapshot_sha256: str,
    final_action_stable_topology_sha256: str,
) -> dict[str, object]:
    payload = _closed_payload()
    payload.update(
        {
            "action_topology_fence_authenticated": True,
            "approval_sha256": approval_sha256,
            "claim_chronology_authenticated": True,
            "claim_retention_authenticated": True,
            "claim_sha256": claim_sha256,
            "claimed_action_fence_sha256": claimed_action_fence_sha256,
            "contract_version": (
                POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_CONTRACT_VERSION
            ),
            "controller_origin_authenticated": True,
            "final_action_observation_sha256": final_action_observation_sha256,
            "final_action_snapshot_sha256": final_action_snapshot_sha256,
            "final_action_stable_topology_sha256": final_action_stable_topology_sha256,
            "final_action_topology_reobservation_authenticated": True,
            "observation_provenance_authenticated": True,
            "operation_id": operation_id,
            "retained_claim_artifact_sha256": retained_claim_artifact_sha256,
            "retained_claim_revalidated": True,
            "same_session_observation_chain_authenticated": True,
            "session_sha256": session_sha256,
            "stable_topology_match_authenticated": True,
            "status": POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS,
        }
    )
    return payload


def _validate_admission(value: object) -> None:
    if type(value) is not TrustedTimePostEnrollmentStartActiveControllerAdmission:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission is invalid"
        )
    try:
        TrustedTimePostEnrollmentStartActiveControllerAdmission.__post_init__(value)
    except TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission is invalid"
        ) from None


def _authenticated_fact(value: object) -> bool:
    _validate_admission(value)
    return True


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartActiveControllerAdmission:
    """Process-sealed, nonauthorizing reservation for one future continuation."""

    operation_id: str
    approval_sha256: str
    session_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    claimed_action_fence_sha256: str
    final_action_observation_sha256: str
    final_action_snapshot_sha256: str
    final_action_stable_topology_sha256: str
    _action_fence: object = field(repr=False, compare=False)
    _capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not TrustedTimePostEnrollmentStartActiveControllerAdmission:
            raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
                "trusted-time active-controller admission is invalid"
            )
        try:
            if (
                type(self._action_fence)
                is not TrustedTimePostEnrollmentStartClaimedActionTopologyFence
            ):
                raise ValueError
            action_fence = self._action_fence
            action_fence.__post_init__()
            if (
                any(
                    not _is_sha256(value)
                    for value in (
                        self.approval_sha256,
                        self.session_sha256,
                        self.claim_sha256,
                        self.retained_claim_artifact_sha256,
                        self.claimed_action_fence_sha256,
                        self.final_action_observation_sha256,
                        self.final_action_snapshot_sha256,
                        self.final_action_stable_topology_sha256,
                    )
                )
                or self.operation_id != action_fence.operation_id
                or self.approval_sha256 != action_fence.approval_sha256
                or self.session_sha256 != action_fence.session_sha256
                or self.claim_sha256 != action_fence.claim_sha256
                or self.retained_claim_artifact_sha256
                != action_fence.retained_claim_artifact_sha256
                or self.claimed_action_fence_sha256 != action_fence.fence_sha256
                or self.final_action_observation_sha256
                != action_fence.final_action_observation_sha256
                or self.final_action_snapshot_sha256 != action_fence.final_action_snapshot_sha256
                or self.final_action_stable_topology_sha256
                != action_fence.final_action_stable_topology_sha256
                or not _valid_active_controller_admission_capability(
                    self._capability,
                    _admission_payload(
                        operation_id=self.operation_id,
                        approval_sha256=self.approval_sha256,
                        session_sha256=self.session_sha256,
                        claim_sha256=self.claim_sha256,
                        retained_claim_artifact_sha256=(self.retained_claim_artifact_sha256),
                        claimed_action_fence_sha256=self.claimed_action_fence_sha256,
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
        except TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected:
            raise
        except BaseException:
            raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
                "trusted-time active-controller admission is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS

    def payload(self) -> dict[str, object]:
        _validate_admission(self)
        return _admission_payload(
            operation_id=self.operation_id,
            approval_sha256=self.approval_sha256,
            session_sha256=self.session_sha256,
            claim_sha256=self.claim_sha256,
            retained_claim_artifact_sha256=self.retained_claim_artifact_sha256,
            claimed_action_fence_sha256=self.claimed_action_fence_sha256,
            final_action_observation_sha256=self.final_action_observation_sha256,
            final_action_snapshot_sha256=self.final_action_snapshot_sha256,
            final_action_stable_topology_sha256=self.final_action_stable_topology_sha256,
        )

    @property
    def admission_sha256(self) -> str:
        return _payload_sha256(self.payload())

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
            "trusted-time active-controller admission cannot be serialized"
        )

    action_topology_fence_authenticated = property(_authenticated_fact)
    claim_chronology_authenticated = property(_authenticated_fact)
    claim_retention_authenticated = property(_authenticated_fact)
    controller_origin_authenticated = property(_authenticated_fact)
    final_action_topology_reobservation_authenticated = property(_authenticated_fact)
    observation_provenance_authenticated = property(_authenticated_fact)
    retained_claim_revalidated = property(_authenticated_fact)
    same_session_observation_chain_authenticated = property(_authenticated_fact)
    stable_topology_match_authenticated = property(_authenticated_fact)
    active_controller_authorized = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    controller_execution_authorized = property(_authority_is_never_granted)
    created_topology_authenticated = property(_authority_is_never_granted)
    current_daemon_session_authenticated = property(_authority_is_never_granted)
    current_lock_session_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_consumption_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    inventory_authenticated = property(_authority_is_never_granted)
    outcome_retention_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    persistent_start_confirmed = property(_authority_is_never_granted)
    release_absence_authenticated = property(_authority_is_never_granted)
    release_attempted = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    release_confirmed = property(_authority_is_never_granted)
    runtime_start_authorized = property(_authority_is_never_granted)
    runtime_start_confirmed = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    sequence_2_confirmed = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authenticated = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    staged_input_retirement_authenticated = property(_authority_is_never_granted)
    start_order_authenticated = property(_authority_is_never_granted)
    success_outcome_retained = property(_authority_is_never_granted)
    success_outcome_retention_authorized = property(_authority_is_never_granted)
    supervisor_start_authenticated = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_authenticated = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    topology_qualified = property(_authority_is_never_granted)
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


def _poison_action(topology_issuer: object) -> None:
    if type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer:
        return
    owner_pid = getattr(topology_issuer, "_owner_pid", None)
    if type(owner_pid) is not int or owner_pid != os.getpid():
        return
    with topology_issuer._lifecycle_lock:
        topology_issuer._poison_locked()


def _build_active_controller_admission_preparer() -> tuple[
    Callable[..., TrustedTimePostEnrollmentStartActiveControllerAdmission],
    Callable[[object, dict[str, object], object], bool],
    Callable[..., bool],
]:
    registry_lock = threading.Lock()
    origin_pid = os.getpid()
    result_capabilities: dict[
        _ActiveControllerAdmissionCapability,
        tuple[str, object | None],
    ] = {}
    continuations: dict[
        _ActiveControllerAdmissionCapability,
        _ActiveControllerContinuation,
    ] = {}
    consumed_origins: dict[
        _ActiveControllerAdmissionCapability,
        weakref.ReferenceType[TrustedTimePostEnrollmentTopologyObservationIssuer],
    ] = {}

    def revoke_interrupted_continuation(
        candidate: _ActiveControllerAdmissionCapability,
        known_origin: _ActiveControllerContinuation | None,
    ) -> tuple[
        _ActiveControllerContinuation | None,
        weakref.ReferenceType[TrustedTimePostEnrollmentTopologyObservationIssuer] | None,
    ]:
        with registry_lock:
            pending_origin = continuations.get(candidate)
            origin_reference = (
                known_origin[1]
                if known_origin is not None
                else (
                    pending_origin[1]
                    if pending_origin is not None
                    else consumed_origins.get(candidate)
                )
            )
            if origin_reference is not None:
                consumed_origins[candidate] = origin_reference
            removed_origin = continuations.pop(candidate, None)
            return (
                known_origin if known_origin is not None else removed_origin,
                origin_reference,
            )

    def register_result(
        candidate: _ActiveControllerAdmissionCapability,
        material: dict[str, object],
    ) -> None:
        if os.getpid() != origin_pid or type(candidate) is not _ActiveControllerAdmissionCapability:
            raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
                "trusted-time active-controller admission capability is unavailable"
            )
        with registry_lock:
            result_capabilities[candidate] = (_payload_sha256(material), None)

    def unregister(candidate: object) -> None:
        if os.getpid() != origin_pid or type(candidate) is not _ActiveControllerAdmissionCapability:
            return
        try:
            with registry_lock:
                continuations.pop(candidate, None)
                consumed_origins.pop(candidate, None)
                result_capabilities.pop(candidate, None)
        except BaseException:
            with suppress(BaseException), registry_lock:
                continuations.pop(candidate, None)
                consumed_origins.pop(candidate, None)
                result_capabilities.pop(candidate, None)
            raise

    def valid_result(candidate: object, material: dict[str, object], result: object) -> bool:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not _ActiveControllerAdmissionCapability
            or type(result) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
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

    def register_continuation(
        candidate: _ActiveControllerAdmissionCapability,
        result: TrustedTimePostEnrollmentStartActiveControllerAdmission,
        *,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        choreography_lease: object,
        recovery_retention_capability: object,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        if os.getpid() != origin_pid:
            raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
                "trusted-time active-controller continuation is unavailable"
            )
        with registry_lock:
            registration = result_capabilities.get(candidate)
            if registration is None or registration[1] is not result:
                raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
                    "trusted-time active-controller continuation is unavailable"
                )
            continuations[candidate] = (
                result,
                weakref.ref(topology_issuer),
                choreography_lease,
                recovery_retention_capability,
                artifact_directory,
                ignored_root,
                os.getpid(),
                threading.current_thread(),
            )

    def consume_continuation(
        candidate: object,
        *,
        topology_issuer: object,
        choreography_lease: object,
        recovery_retention_capability: object,
        artifact_directory: object,
        ignored_root: object,
    ) -> bool:
        if (
            os.getpid() != origin_pid
            or type(candidate) is not TrustedTimePostEnrollmentStartActiveControllerAdmission
        ):
            return False
        capability = getattr(candidate, "_capability", None)
        if type(capability) is not _ActiveControllerAdmissionCapability:
            return False
        origin: _ActiveControllerContinuation | None = None
        origin_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer | None = None
        consumed_origin: (
            weakref.ReferenceType[TrustedTimePostEnrollmentTopologyObservationIssuer] | None
        ) = None
        try:
            with registry_lock:
                registration = result_capabilities.get(capability)
                origin = continuations.pop(capability, None)
                consumed_origin = consumed_origins.get(capability)
                if origin is not None:
                    origin_issuer = origin[1]()
                    if type(origin_issuer) is TrustedTimePostEnrollmentTopologyObservationIssuer:
                        consumed_origins[capability] = weakref.ref(origin_issuer)
            if origin is None:
                origin_issuer = consumed_origin() if consumed_origin is not None else None
                if origin_issuer is not None:
                    _poison_action(origin_issuer)
                return False
            accepted = bool(
                registration is not None
                and registration[1] is candidate
                and origin[0] is candidate
                and origin_issuer is topology_issuer
                and getattr(origin_issuer, "_poisoned", False) is False
                and getattr(origin_issuer, "_closed", False) is False
                and origin[2] is choreography_lease
                and origin[3] is recovery_retention_capability
                and recovery_retention_capability is not None
                and type(artifact_directory) is type(Path())
                and type(ignored_root) is type(Path())
                and origin[4] == artifact_directory
                and origin[5] == ignored_root
                and origin[6] == os.getpid()
                and origin[7] is threading.current_thread()
            )
            if not accepted or origin_issuer is None:
                if origin_issuer is not None:
                    _poison_action(origin_issuer)
                return False
            exact_artifact_directory = cast(Path, artifact_directory)
            exact_ignored_root = cast(Path, ignored_root)
            candidate.__post_init__()
            origin_issuer._require_armed_recovery_outcome_retention(
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=exact_artifact_directory,
                ignored_root=exact_ignored_root,
            )
            origin_issuer._require_active_choreography_lease(choreography_lease)
            return True
        except BaseException:
            try:
                origin, consumed_origin = revoke_interrupted_continuation(
                    capability,
                    origin,
                )
            except BaseException:
                with suppress(BaseException):
                    origin, consumed_origin = revoke_interrupted_continuation(
                        capability,
                        origin,
                    )
            if origin_issuer is None:
                if origin is not None:
                    with suppress(BaseException):
                        recovered_issuer = origin[1]()
                        if (
                            type(recovered_issuer)
                            is TrustedTimePostEnrollmentTopologyObservationIssuer
                        ):
                            origin_issuer = recovered_issuer
                elif consumed_origin is not None:
                    with suppress(BaseException):
                        recovered_issuer = consumed_origin()
                        if (
                            type(recovered_issuer)
                            is TrustedTimePostEnrollmentTopologyObservationIssuer
                        ):
                            origin_issuer = recovered_issuer
            if origin_issuer is not None:
                with suppress(BaseException), registry_lock:
                    consumed_origins[capability] = weakref.ref(origin_issuer)
                _poison_action(origin_issuer)
            raise

    def prepare(
        *,
        action_fence: TrustedTimePostEnrollmentStartClaimedActionTopologyFence,
        topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
        choreography_lease: object,
        recovery_retention_capability: object,
        artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    ) -> TrustedTimePostEnrollmentStartActiveControllerAdmission:
        exact_action_fence_established = False
        capability: _ActiveControllerAdmissionCapability | None = None
        try:
            if type(action_fence) is not TrustedTimePostEnrollmentStartClaimedActionTopologyFence:
                raise ValueError
            exact_action_fence_established = True
            if not _consume_claimed_action_fence_controller_choreography(
                action_fence,
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                recovery_retention_capability=recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            ):
                raise ValueError
            action_fence.__post_init__()
            if (
                type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
                or recovery_retention_capability is None
                or type(artifact_directory) is not type(Path())
                or type(ignored_root) is not type(Path())
                or artifact_directory != ignored_root / "trusted-time"
            ):
                raise ValueError
            claimed_fence = cast(
                TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence,
                action_fence._claimed_fence,
            )
            if (
                type(claimed_fence)
                is not TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence
            ):
                raise ValueError
            handoff = cast(TrustedTimePostEnrollmentStartStagingHandoff, claimed_fence._handoff)
            if type(handoff) is not TrustedTimePostEnrollmentStartStagingHandoff:
                raise ValueError
            retained = handoff.retained_claim
            if (
                type(retained) is not RetainedTrustedTimePostEnrollmentStartClaim
                or handoff.artifact_directory != artifact_directory
                or handoff.ignored_root != ignored_root
                or retained.artifact_path.parent != artifact_directory
                or retained.claim.claim_sha256 != action_fence.claim_sha256
                or retained.artifact_sha256 != action_fence.retained_claim_artifact_sha256
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
            payload = _admission_payload(
                operation_id=action_fence.operation_id,
                approval_sha256=action_fence.approval_sha256,
                session_sha256=action_fence.session_sha256,
                claim_sha256=action_fence.claim_sha256,
                retained_claim_artifact_sha256=(action_fence.retained_claim_artifact_sha256),
                claimed_action_fence_sha256=action_fence.fence_sha256,
                final_action_observation_sha256=(action_fence.final_action_observation_sha256),
                final_action_snapshot_sha256=action_fence.final_action_snapshot_sha256,
                final_action_stable_topology_sha256=(
                    action_fence.final_action_stable_topology_sha256
                ),
            )
            capability = object.__new__(_ActiveControllerAdmissionCapability)
            register_result(capability, payload)
            result = TrustedTimePostEnrollmentStartActiveControllerAdmission(
                operation_id=action_fence.operation_id,
                approval_sha256=action_fence.approval_sha256,
                session_sha256=action_fence.session_sha256,
                claim_sha256=action_fence.claim_sha256,
                retained_claim_artifact_sha256=(action_fence.retained_claim_artifact_sha256),
                claimed_action_fence_sha256=action_fence.fence_sha256,
                final_action_observation_sha256=(action_fence.final_action_observation_sha256),
                final_action_snapshot_sha256=action_fence.final_action_snapshot_sha256,
                final_action_stable_topology_sha256=(
                    action_fence.final_action_stable_topology_sha256
                ),
                _action_fence=action_fence,
                _capability=capability,
            )
            result.__post_init__()
            action_fence.__post_init__()
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
            register_continuation(
                capability,
                result,
                topology_issuer=topology_issuer,
                choreography_lease=choreography_lease,
                recovery_retention_capability=recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            topology_issuer._require_armed_recovery_outcome_retention(
                choreography_lease,
                recovery_retention_capability,
                artifact_directory=artifact_directory,
                ignored_root=ignored_root,
            )
            topology_issuer._require_active_choreography_lease(choreography_lease)
            return result
        except BaseException:
            if exact_action_fence_established:
                try:
                    _poison_action(topology_issuer)
                finally:
                    with suppress(BaseException):
                        unregister(capability)
                raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired(
                    "trusted-time active-controller admission requires recovery"
                ) from None
            unregister(capability)
            raise TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected(
                "trusted-time active-controller admission inputs are unavailable"
            ) from None

    return prepare, valid_result, consume_continuation


(
    prepare_post_enrollment_start_active_controller_admission,
    _valid_active_controller_admission_capability,
    _consume_active_controller_continuation,
) = _build_active_controller_admission_preparer()
del _build_active_controller_admission_preparer


__all__ = [
    "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS",
    "TrustedTimePostEnrollmentStartActiveControllerAdmission",
    "TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired",
    "TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected",
    "prepare_post_enrollment_start_active_controller_admission",
]
