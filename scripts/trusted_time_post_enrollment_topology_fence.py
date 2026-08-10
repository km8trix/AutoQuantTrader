"""Pure same-session fences over authenticated topology observations.

The two binders' public payloads expose only immutable digests; private fields
retain the sealed envelopes required for revalidation.  They perform no I/O,
read no clock, retain no claim, and authorize no start, release, sequence,
shutdown, operational, or trading action.  They authenticate the reader-issued
observation chain, not the topology's freshness at a later action boundary.

In particular, the pre-release binder cannot prove that staged ordinal 2 was
obtained after a claim was retained or immediately before release.  A future
active controller must enforce that chronology while the live reader session
and its launcher lock remain held.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_staged_topology import (
    TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_topology import (
    TrustedTimePostEnrollmentCreatedTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentCreatedTopologyObservation,
    TrustedTimePostEnrollmentStagedTopologyObservation,
)

POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-pre-claim-topology-fence-v1"
)
POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS = (
    "pre_claim_same_session_topology_fence_unqualified"
)
POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-pre-release-topology-fence-v1"
)
POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS = (
    "pre_release_same_session_topology_fence_unqualified"
)

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _authority_is_never_granted(_: object) -> bool:
    return False


def _authenticated_fact(_: object) -> bool:
    return True


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_PATTERN.fullmatch(value) is not None


def _payload_sha256(payload: dict[str, object]) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(payload)).hexdigest()


class TrustedTimePostEnrollmentStartTopologyFenceRejected(ValueError):
    """One topology observation chain could not be bound safely."""


def _closed_fence_payload() -> dict[str, object]:
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


def _require_created_staged_identity_match(
    created: TrustedTimePostEnrollmentCreatedTopologySnapshot,
    staged: TrustedTimePostEnrollmentStagedUnreleasedTopologySnapshot,
) -> None:
    """Require every immutable identity carried across the topology transition."""

    if (
        staged.operation_id != created.operation_id
        or staged.approval_sha256 != created.approval_sha256
        or staged.review_projection_sha256 != created.review_projection_sha256
        or staged.confirmed_enrollment_evidence_sha256
        != created.confirmed_enrollment_evidence_sha256
        or staged.approved_launch != created.approved_launch
        or staged.created_topology_snapshot_sha256 != created.snapshot_sha256
        or staged.daemon_context_name != created.daemon_context_name
        or staged.daemon_endpoint != created.daemon_endpoint
        or staged.daemon_id != created.daemon_id
        or staged.socket_volume_sha256 != created.socket_volume_sha256
        or staged.state_volume_sha256 != created.state_volume_sha256
        or staged.source.service != created.source.service
        or staged.source.container_id != created.source.container_id
        or staged.source.image_id != created.source.image_id
        or staged.source.image_configuration_projection_sha256
        != created.source.image_configuration_projection_sha256
        or staged.supervisor.service != created.supervisor.service
        or staged.supervisor.container_id != created.supervisor.container_id
        or staged.supervisor.image_id != created.supervisor.image_id
        or staged.supervisor.image_configuration_projection_sha256
        != created.supervisor.image_configuration_projection_sha256
    ):
        raise TrustedTimePostEnrollmentStartTopologyFenceRejected(
            "trusted-time created-to-staged topology identities changed"
        )


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartPreClaimTopologyFence:
    """Digest-only created-to-staged ordinal-1 observation-chain fence."""

    session_sha256: str
    created_observation_sha256: str
    created_snapshot_sha256: str
    staged_observation_ordinal: int
    predecessor_observation_sha256: str
    staged_observation_sha256: str
    staged_snapshot_sha256: str
    staged_stable_topology_sha256: str
    _created_observation: object = field(repr=False, compare=False)
    _staged_observation: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if (
                type(self._created_observation)
                is not TrustedTimePostEnrollmentCreatedTopologyObservation
                or type(self._staged_observation)
                is not TrustedTimePostEnrollmentStagedTopologyObservation
            ):
                raise ValueError
            created = self._created_observation
            staged = self._staged_observation
            created.__post_init__()
            staged.__post_init__()
            _require_created_staged_identity_match(created.snapshot, staged.snapshot)
            digests = (
                self.session_sha256,
                self.created_observation_sha256,
                self.created_snapshot_sha256,
                self.predecessor_observation_sha256,
                self.staged_observation_sha256,
                self.staged_snapshot_sha256,
                self.staged_stable_topology_sha256,
            )
            if (
                any(not _is_sha256(value) for value in digests)
                or type(self.staged_observation_ordinal) is not int
                or self.staged_observation_ordinal != 1
                or created.session_sha256 != staged.session_sha256
                or staged.staged_observation_ordinal != 1
                or staged.created_observation_sha256 != created.observation_sha256
                or staged.predecessor_observation_sha256 != created.observation_sha256
                or self.session_sha256 != created.session_sha256
                or self.created_observation_sha256 != created.observation_sha256
                or self.created_snapshot_sha256 != created.snapshot.snapshot_sha256
                or self.predecessor_observation_sha256 != staged.predecessor_observation_sha256
                or self.staged_observation_sha256 != staged.observation_sha256
                or self.staged_snapshot_sha256 != staged.snapshot.snapshot_sha256
                or self.staged_stable_topology_sha256 != staged.snapshot.stable_topology_sha256
                or self.staged_observation_sha256 == self.created_observation_sha256
            ):
                raise ValueError
        except TrustedTimePostEnrollmentStartTopologyFenceRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentStartTopologyFenceRejected(
                "trusted-time pre-claim topology fence is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS

    def payload(self) -> dict[str, object]:
        payload = _closed_fence_payload()
        payload.update(
            {
                "contract_version": (
                    POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_CONTRACT_VERSION
                ),
                "created_observation_sha256": self.created_observation_sha256,
                "created_snapshot_sha256": self.created_snapshot_sha256,
                "observation_provenance_authenticated": True,
                "predecessor_observation_sha256": self.predecessor_observation_sha256,
                "same_session_observation_chain_authenticated": True,
                "session_sha256": self.session_sha256,
                "stable_topology_match_authenticated": False,
                "staged_observation_ordinal": self.staged_observation_ordinal,
                "staged_observation_sha256": self.staged_observation_sha256,
                "staged_snapshot_sha256": self.staged_snapshot_sha256,
                "staged_stable_topology_sha256": self.staged_stable_topology_sha256,
                "status": self.status,
            }
        )
        return payload

    @property
    def fence_sha256(self) -> str:
        self.__post_init__()
        return _payload_sha256(self.payload())

    observation_provenance_authenticated = property(_authenticated_fact)
    same_session_observation_chain_authenticated = property(_authenticated_fact)
    stable_topology_match_authenticated = property(_authority_is_never_granted)
    claim_chronology_authenticated = property(_authority_is_never_granted)
    current_daemon_session_authenticated = property(_authority_is_never_granted)
    current_lock_session_authenticated = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    created_topology_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_consumption_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
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


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartPreReleaseTopologyFence:
    """Digest-only ordinal-1-to-ordinal-2 stable-topology chain fence."""

    session_sha256: str
    pre_claim_fence_sha256: str
    created_observation_sha256: str
    created_snapshot_sha256: str
    pre_claim_staged_observation_ordinal: int
    pre_claim_predecessor_observation_sha256: str
    pre_claim_staged_observation_sha256: str
    pre_release_staged_observation_ordinal: int
    pre_release_predecessor_observation_sha256: str
    pre_release_staged_observation_sha256: str
    staged_snapshot_sha256: str
    staged_stable_topology_sha256: str
    _pre_claim_fence: object = field(repr=False, compare=False)
    _staged_observation: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if (
                type(self._pre_claim_fence)
                is not TrustedTimePostEnrollmentStartPreClaimTopologyFence
                or type(self._staged_observation)
                is not TrustedTimePostEnrollmentStagedTopologyObservation
            ):
                raise ValueError
            pre_claim = self._pre_claim_fence
            staged = self._staged_observation
            pre_claim.__post_init__()
            staged.__post_init__()
            digests = (
                self.session_sha256,
                self.pre_claim_fence_sha256,
                self.created_observation_sha256,
                self.created_snapshot_sha256,
                self.pre_claim_predecessor_observation_sha256,
                self.pre_claim_staged_observation_sha256,
                self.pre_release_predecessor_observation_sha256,
                self.pre_release_staged_observation_sha256,
                self.staged_snapshot_sha256,
                self.staged_stable_topology_sha256,
            )
            if (
                any(not _is_sha256(value) for value in digests)
                or type(self.pre_claim_staged_observation_ordinal) is not int
                or self.pre_claim_staged_observation_ordinal != 1
                or type(self.pre_release_staged_observation_ordinal) is not int
                or self.pre_release_staged_observation_ordinal != 2
                or staged.staged_observation_ordinal != 2
                or staged.session_sha256 != pre_claim.session_sha256
                or staged.created_observation_sha256 != pre_claim.created_observation_sha256
                or staged.predecessor_observation_sha256 != pre_claim.staged_observation_sha256
                or staged.snapshot.created_topology_snapshot_sha256
                != pre_claim.created_snapshot_sha256
                or staged.snapshot.snapshot_sha256 != pre_claim.staged_snapshot_sha256
                or staged.snapshot.stable_topology_sha256 != pre_claim.staged_stable_topology_sha256
                or self.session_sha256 != pre_claim.session_sha256
                or self.pre_claim_fence_sha256 != pre_claim.fence_sha256
                or self.created_observation_sha256 != pre_claim.created_observation_sha256
                or self.created_snapshot_sha256 != pre_claim.created_snapshot_sha256
                or self.pre_claim_staged_observation_ordinal != pre_claim.staged_observation_ordinal
                or self.pre_claim_predecessor_observation_sha256
                != pre_claim.predecessor_observation_sha256
                or self.pre_claim_staged_observation_sha256 != pre_claim.staged_observation_sha256
                or self.pre_release_staged_observation_ordinal != staged.staged_observation_ordinal
                or self.pre_release_predecessor_observation_sha256
                != staged.predecessor_observation_sha256
                or self.pre_release_staged_observation_sha256 != staged.observation_sha256
                or self.staged_snapshot_sha256 != staged.snapshot.snapshot_sha256
                or self.staged_stable_topology_sha256 != staged.snapshot.stable_topology_sha256
                or len(
                    {
                        self.created_observation_sha256,
                        self.pre_claim_staged_observation_sha256,
                        self.pre_release_staged_observation_sha256,
                    }
                )
                != 3
            ):
                raise ValueError
        except TrustedTimePostEnrollmentStartTopologyFenceRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentStartTopologyFenceRejected(
                "trusted-time pre-release topology fence is invalid"
            ) from None

    @property
    def status(self) -> str:
        return POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS

    def payload(self) -> dict[str, object]:
        payload = _closed_fence_payload()
        payload.update(
            {
                "contract_version": (
                    POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION
                ),
                "created_observation_sha256": self.created_observation_sha256,
                "created_snapshot_sha256": self.created_snapshot_sha256,
                "observation_provenance_authenticated": True,
                "pre_claim_fence_sha256": self.pre_claim_fence_sha256,
                "pre_claim_predecessor_observation_sha256": (
                    self.pre_claim_predecessor_observation_sha256
                ),
                "pre_claim_staged_observation_ordinal": (self.pre_claim_staged_observation_ordinal),
                "pre_claim_staged_observation_sha256": (self.pre_claim_staged_observation_sha256),
                "pre_release_predecessor_observation_sha256": (
                    self.pre_release_predecessor_observation_sha256
                ),
                "pre_release_staged_observation_ordinal": (
                    self.pre_release_staged_observation_ordinal
                ),
                "pre_release_staged_observation_sha256": (
                    self.pre_release_staged_observation_sha256
                ),
                "same_session_observation_chain_authenticated": True,
                "session_sha256": self.session_sha256,
                "stable_topology_match_authenticated": True,
                "staged_snapshot_sha256": self.staged_snapshot_sha256,
                "staged_stable_topology_sha256": self.staged_stable_topology_sha256,
                "status": self.status,
            }
        )
        return payload

    @property
    def fence_sha256(self) -> str:
        self.__post_init__()
        return _payload_sha256(self.payload())

    observation_provenance_authenticated = property(_authenticated_fact)
    same_session_observation_chain_authenticated = property(_authenticated_fact)
    stable_topology_match_authenticated = property(_authenticated_fact)
    claim_chronology_authenticated = property(_authority_is_never_granted)
    current_daemon_session_authenticated = property(_authority_is_never_granted)
    current_lock_session_authenticated = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    container_identity_authenticated = property(_authority_is_never_granted)
    created_topology_authenticated = property(_authority_is_never_granted)
    daemon_identity_authenticated = property(_authority_is_never_granted)
    database_secret_consumption_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
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


def bind_post_enrollment_start_pre_claim_topology_fence(
    created_observation: TrustedTimePostEnrollmentCreatedTopologyObservation,
    staged_observation: TrustedTimePostEnrollmentStagedTopologyObservation,
) -> TrustedTimePostEnrollmentStartPreClaimTopologyFence:
    """Bind the exact created -> staged ordinal-1 observation chain."""

    try:
        if (
            type(created_observation) is not TrustedTimePostEnrollmentCreatedTopologyObservation
            or type(staged_observation) is not TrustedTimePostEnrollmentStagedTopologyObservation
        ):
            raise ValueError
        created_observation.__post_init__()
        staged_observation.__post_init__()
        created_observation_sha256 = created_observation.observation_sha256
        staged_observation_sha256 = staged_observation.observation_sha256
        if (
            created_observation.session_sha256 != staged_observation.session_sha256
            or staged_observation.staged_observation_ordinal != 1
            or staged_observation.created_observation_sha256 != created_observation_sha256
            or staged_observation.predecessor_observation_sha256 != created_observation_sha256
            or staged_observation_sha256 == created_observation_sha256
        ):
            raise ValueError
        _require_created_staged_identity_match(
            created_observation.snapshot,
            staged_observation.snapshot,
        )
        return TrustedTimePostEnrollmentStartPreClaimTopologyFence(
            session_sha256=created_observation.session_sha256,
            created_observation_sha256=created_observation_sha256,
            created_snapshot_sha256=created_observation.snapshot.snapshot_sha256,
            staged_observation_ordinal=staged_observation.staged_observation_ordinal,
            predecessor_observation_sha256=(staged_observation.predecessor_observation_sha256),
            staged_observation_sha256=staged_observation_sha256,
            staged_snapshot_sha256=staged_observation.snapshot.snapshot_sha256,
            staged_stable_topology_sha256=(staged_observation.snapshot.stable_topology_sha256),
            _created_observation=created_observation,
            _staged_observation=staged_observation,
        )
    except TrustedTimePostEnrollmentStartTopologyFenceRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentStartTopologyFenceRejected(
            "trusted-time pre-claim topology fence is unavailable"
        ) from None


def bind_post_enrollment_start_pre_release_topology_fence(
    pre_claim_fence: TrustedTimePostEnrollmentStartPreClaimTopologyFence,
    staged_observation: TrustedTimePostEnrollmentStagedTopologyObservation,
) -> TrustedTimePostEnrollmentStartPreReleaseTopologyFence:
    """Bind pre-claim ordinal 1 to equal staged ordinal 2 without an action."""

    try:
        if (
            type(pre_claim_fence) is not TrustedTimePostEnrollmentStartPreClaimTopologyFence
            or type(staged_observation) is not TrustedTimePostEnrollmentStagedTopologyObservation
        ):
            raise ValueError
        pre_claim_fence.__post_init__()
        staged_observation.__post_init__()
        staged_observation_sha256 = staged_observation.observation_sha256
        if (
            staged_observation.session_sha256 != pre_claim_fence.session_sha256
            or staged_observation.staged_observation_ordinal != 2
            or staged_observation.created_observation_sha256
            != pre_claim_fence.created_observation_sha256
            or staged_observation.predecessor_observation_sha256
            != pre_claim_fence.staged_observation_sha256
            or staged_observation.snapshot.created_topology_snapshot_sha256
            != pre_claim_fence.created_snapshot_sha256
            or staged_observation.snapshot.snapshot_sha256 != pre_claim_fence.staged_snapshot_sha256
            or staged_observation.snapshot.stable_topology_sha256
            != pre_claim_fence.staged_stable_topology_sha256
            or staged_observation_sha256
            in {
                pre_claim_fence.created_observation_sha256,
                pre_claim_fence.staged_observation_sha256,
            }
        ):
            raise ValueError
        return TrustedTimePostEnrollmentStartPreReleaseTopologyFence(
            session_sha256=pre_claim_fence.session_sha256,
            pre_claim_fence_sha256=pre_claim_fence.fence_sha256,
            created_observation_sha256=pre_claim_fence.created_observation_sha256,
            created_snapshot_sha256=pre_claim_fence.created_snapshot_sha256,
            pre_claim_staged_observation_ordinal=(pre_claim_fence.staged_observation_ordinal),
            pre_claim_predecessor_observation_sha256=(
                pre_claim_fence.predecessor_observation_sha256
            ),
            pre_claim_staged_observation_sha256=(pre_claim_fence.staged_observation_sha256),
            pre_release_staged_observation_ordinal=(staged_observation.staged_observation_ordinal),
            pre_release_predecessor_observation_sha256=(
                staged_observation.predecessor_observation_sha256
            ),
            pre_release_staged_observation_sha256=staged_observation_sha256,
            staged_snapshot_sha256=staged_observation.snapshot.snapshot_sha256,
            staged_stable_topology_sha256=(staged_observation.snapshot.stable_topology_sha256),
            _pre_claim_fence=pre_claim_fence,
            _staged_observation=staged_observation,
        )
    except TrustedTimePostEnrollmentStartTopologyFenceRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentStartTopologyFenceRejected(
            "trusted-time pre-release topology fence is unavailable"
        ) from None


__all__ = [
    "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS",
    "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
    "TrustedTimePostEnrollmentStartPreClaimTopologyFence",
    "TrustedTimePostEnrollmentStartPreReleaseTopologyFence",
    "TrustedTimePostEnrollmentStartTopologyFenceRejected",
    "bind_post_enrollment_start_pre_claim_topology_fence",
    "bind_post_enrollment_start_pre_release_topology_fence",
]
