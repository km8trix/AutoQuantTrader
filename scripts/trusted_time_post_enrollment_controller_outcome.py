"""Durable terminal evidence for one post-effect trusted-time controller.

This module owns the single global post-enrollment outcome slot after the
pre-release recovery capability has been irreversibly transitioned.  It can
retain either one fully confirmed start or one truthful post-effect recovery
disposition.  Neither form grants reusable runtime, shutdown, operational, or
trading authority.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from packages.adapters.trusted_time._owned_file_descriptor import (
    _flock as _native_flock,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _fstat as _native_fstat,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _list_snapshot as _native_list_snapshot,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _open_child_directory as _native_open_child_directory,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _open_child_regular as _native_open_child_regular,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _open_root_directory as _native_open_root_directory,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _OwnedFileDescriptor as _NativeOwnedFileDescriptor,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _read_snapshot as _native_read_snapshot,
)
from packages.adapters.trusted_time._owned_file_descriptor import (
    _statat as _native_statat,
)
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_start import (
    TrustedTimePostEnrollmentStartSuccessor,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
)
from scripts.trusted_time_post_enrollment_outcome import (
    MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES,
    MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES,
    MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES,
    POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME,
    POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX,
    POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX,
    POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME,
    _held_outcome_slot_process_lock,
    _locked_outcome_slot,
    _open_owner_only_artifact_directory,
    _outcome_names,
    _outcome_slot_bytes,
    _OwnedFileDescriptor,
    _read_retained_outcome,
    _reserve_outcome_slot,
    _stable_file_identity,
)
from scripts.trusted_time_post_enrollment_persistent_topology import (
    TrustedTimePostEnrollmentPersistentTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_shutdown_locator import (
    TrustedTimePostEnrollmentGracefulStopShutdownLocator,
    _canonical_json_object_bytes,
    _canonical_json_object_keys,
    _canonical_json_object_value,
    _decode_canonical_object,
    _shutdown_locator_projection_from_encoded,
    _shutdown_locator_slot,
    build_post_enrollment_graceful_stop_shutdown_locator,
    decode_post_enrollment_graceful_stop_shutdown_locator,
    post_enrollment_graceful_stop_shutdown_locator_sha256,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    _finalize_post_enrollment_controller_projection_types,
    _stage_post_enrollment_controller_outcome_reason_type,
    _stage_post_enrollment_controller_outcome_status_type,
    _stage_post_enrollment_controller_prepared_marker_type,
    _stage_retained_post_enrollment_controller_outcome_type,
    _TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint,
)

POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-retained-controller-outcome-v1"
)
POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-retained-controller-outcome-v2"
)
POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_SERVICE = (
    "trusted-time-post-enrollment-start-active-controller"
)
_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_STAGING_FILE_NAME = (
    ".post-enrollment-start-controller-outcome-staging"
)
_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME = (
    POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
)
_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME = (
    ".post-enrollment-start-controller-outcome-commit-staging"
)
_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME = (
    ".post-enrollment-start-controller-outcome-committed"
)


@_stage_post_enrollment_controller_prepared_marker_type
class _PREPARED_OUTCOME_RECEIPT_MARKER:
    __slots__ = ()


@_stage_post_enrollment_controller_outcome_status_type
class TrustedTimePostEnrollmentStartControllerOutcomeStatus(StrEnum):
    """The two terminal states admitted after the release boundary."""

    CONFIRMED = "post_enrollment_start_confirmed"
    RECOVERY_REQUIRED = "recovery_required"


@_stage_post_enrollment_controller_outcome_reason_type
class TrustedTimePostEnrollmentStartControllerOutcomeReason(StrEnum):
    """Fixed progress-sensitive reasons; callers cannot supply free text."""

    POST_ENROLLMENT_START_CONFIRMED = "post_enrollment_start_confirmed"
    RELEASE_OUTCOME_UNCONFIRMED = "release_outcome_unconfirmed"
    SEQUENCE_TWO_UNCONFIRMED = "sequence_2_unconfirmed"
    SUCCESS_OUTCOME_UNCONFIRMED = "success_outcome_unconfirmed"


class TrustedTimePostEnrollmentStartControllerOutcomeRejected(RuntimeError):
    """Controller evidence was rejected before persistence began."""


class TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable(RuntimeError):
    """The exact post-effect one-shot capability was unavailable."""


class TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained(RuntimeError):
    """The global post-enrollment outcome slot is already occupied."""


class TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(RuntimeError):
    """Outcome creation may have occurred, but durability is unconfirmed."""


class TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(RuntimeError):
    """A unique exact controller outcome could not be loaded or revalidated."""


_CLOSED_FIELDS = (
    "active_controller_authorized",
    "alert_delivery_authorized",
    "arming_authorized",
    "authority_granted",
    "automatic_rearm_authorized",
    "automatic_resume_authorized",
    "broker_action_authorized",
    "claim_retention_authorized",
    "controller_execution_authorized",
    "database_secret_disclosed",
    "exposure_authorized",
    "live_trading_authorized",
    "new_exposure_authorized",
    "operational_control_authorized",
    "outcome_retention_authorized",
    "paper_trading_authorized",
    "persistent_start_authorized",
    "readiness_authorized",
    "rearm_authorized",
    "release_authorized",
    "retry_authorized",
    "sequence_2_authorized",
    "shutdown_authorized",
    "source_start_authorized",
    "success_outcome_retention_authorized",
    "supervisor_start_authorized",
    "topology_mutation_authorized",
)

_V1_EVIDENCE_FIELDS = (
    "active_controller_admission_sha256",
    "approval_sha256",
    "claim_retention_revalidated",
    "claim_sha256",
    "contract_version",
    "controller_execution_confirmed",
    "operation_id",
    "pre_effect_observation_sha256",
    "persistent_start_confirmed",
    "persistent_topology_transcript_sha256",
    "persistent_topology_sha256",
    "qualified",
    "reason",
    "release_attempted",
    "release_confirmed",
    "release_execution_sha256",
    "retained_claim_artifact_sha256",
    "runtime_start_confirmed",
    "runtime_state_sha256",
    "read_only_configuration_sha256",
    "sequence_2_confirmed",
    "service",
    "source_start_confirmed",
    "status",
    "success_outcome_retained",
    "successor_candidate_sha256",
    "supervisor_start_confirmed",
    "topology_qualified",
    "verification_transcript_sha256",
    "verifier_binding_sha256",
)
_EVIDENCE_FIELDS = (
    *_V1_EVIDENCE_FIELDS,
    "durable_shutdown_locator",
    "durable_shutdown_locator_sha256",
)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _successor_sha256(value: TrustedTimePostEnrollmentStartSuccessor) -> str:
    return hashlib.sha256(canonical_first_enrollment_json_bytes(value.payload())).hexdigest()


def _admission_retained_claim(
    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission,
) -> RetainedTrustedTimePostEnrollmentStartClaim:
    try:
        admission.__post_init__()
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
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome admission binding is invalid"
        ) from None


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentStartControllerOutcomeEvidence:
    """Exact non-authorizing evidence submitted to the durable writer."""

    admission: TrustedTimePostEnrollmentStartActiveControllerAdmission = field(repr=False)
    status: TrustedTimePostEnrollmentStartControllerOutcomeStatus
    reason: TrustedTimePostEnrollmentStartControllerOutcomeReason
    pre_effect_observation_sha256: str
    verifier_binding_sha256: str
    read_only_configuration_sha256: str
    verification_transcript_sha256: str | None
    release_execution_sha256: str | None
    runtime_state_sha256: str | None
    successor: TrustedTimePostEnrollmentStartSuccessor | None = field(repr=False)
    persistent_topology: TrustedTimePostEnrollmentPersistentTopologySnapshot | None = field(
        repr=False
    )
    persistent_topology_transcript_sha256: str | None

    def __post_init__(self) -> None:
        try:
            if (
                type(self) is not TrustedTimePostEnrollmentStartControllerOutcomeEvidence
                or type(self.admission)
                is not TrustedTimePostEnrollmentStartActiveControllerAdmission
                or type(self.status) is not TrustedTimePostEnrollmentStartControllerOutcomeStatus
                or type(self.reason) is not TrustedTimePostEnrollmentStartControllerOutcomeReason
                or not _is_sha256(self.pre_effect_observation_sha256)
                or not _is_sha256(self.verifier_binding_sha256)
                or not _is_sha256(self.read_only_configuration_sha256)
                or (
                    self.verification_transcript_sha256 is not None
                    and not _is_sha256(self.verification_transcript_sha256)
                )
                or (
                    self.release_execution_sha256 is not None
                    and not _is_sha256(self.release_execution_sha256)
                )
                or (
                    self.runtime_state_sha256 is not None
                    and not _is_sha256(self.runtime_state_sha256)
                )
                or (
                    self.successor is not None
                    and type(self.successor) is not TrustedTimePostEnrollmentStartSuccessor
                )
                or (
                    self.persistent_topology is not None
                    and type(self.persistent_topology)
                    is not TrustedTimePostEnrollmentPersistentTopologySnapshot
                )
                or (
                    self.persistent_topology_transcript_sha256 is not None
                    and not _is_sha256(self.persistent_topology_transcript_sha256)
                )
                or (
                    (self.persistent_topology is None)
                    != (self.persistent_topology_transcript_sha256 is None)
                )
            ):
                raise ValueError
            retained = _admission_retained_claim(self.admission)
            if self.successor is not None:
                self.successor.__post_init__()
                if (
                    self.successor.predecessor_anchor_sha256
                    != retained.claim.reauthentication.current_anchor_sha256
                ):
                    raise ValueError
            if self.persistent_topology is not None:
                self.persistent_topology.__post_init__()
                if (
                    self.persistent_topology._admission is not self.admission
                    or self.persistent_topology.successor is not self.successor
                ):
                    raise ValueError

            confirmed = (
                self.status is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
            )
            if confirmed != (
                self.reason
                is (
                    TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
                )
            ):
                raise ValueError
            if confirmed:
                if (
                    self.release_execution_sha256 is None
                    or self.runtime_state_sha256 is None
                    or self.successor is None
                    or self.persistent_topology is None
                    or self.persistent_topology_transcript_sha256 is None
                    or self.verification_transcript_sha256 is None
                ):
                    raise ValueError
            elif self.reason is (
                TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
            ):
                if any(
                    value is not None
                    for value in (
                        self.release_execution_sha256,
                        self.runtime_state_sha256,
                        self.successor,
                        self.persistent_topology,
                        self.persistent_topology_transcript_sha256,
                        self.verification_transcript_sha256,
                    )
                ):
                    raise ValueError
            elif self.reason is (
                TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
            ):
                if (
                    self.release_execution_sha256 is None
                    or self.successor is not None
                    or self.persistent_topology is not None
                    or self.persistent_topology_transcript_sha256 is not None
                    or self.verification_transcript_sha256 is not None
                ):
                    raise ValueError
            elif self.reason is (
                TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
            ):
                if (
                    self.release_execution_sha256 is None
                    or self.runtime_state_sha256 is None
                    or self.successor is None
                    or self.persistent_topology is None
                    or self.persistent_topology_transcript_sha256 is None
                    or self.verification_transcript_sha256 is None
                ):
                    raise ValueError
            else:
                raise ValueError
        except TrustedTimePostEnrollmentStartControllerOutcomeRejected:
            raise
        except BaseException:
            raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
                "trusted-time controller outcome evidence is invalid"
            ) from None

    @property
    def release_confirmed(self) -> bool:
        self.__post_init__()
        return self.release_execution_sha256 is not None

    @property
    def sequence_2_confirmed(self) -> bool:
        self.__post_init__()
        return self.successor is not None and self.runtime_state_sha256 is not None

    @property
    def topology_qualified(self) -> bool:
        self.__post_init__()
        return self.persistent_topology is not None

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        retained = _admission_retained_claim(self.admission)
        confirmed = self.status is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
        shutdown_locator = (
            None
            if self.persistent_topology is None
            else build_post_enrollment_graceful_stop_shutdown_locator(
                admission=self.admission,
                persistent_topology=self.persistent_topology,
                persistent_topology_transcript_sha256=cast(
                    str, self.persistent_topology_transcript_sha256
                ),
            )
        )
        payload: dict[str, object] = {
            field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
        }
        payload.update({field_name: False for field_name in _CLOSED_FIELDS})
        payload.update(
            {
                "active_controller_admission_sha256": self.admission.admission_sha256,
                "approval_sha256": self.admission.approval_sha256,
                "claim_retention_revalidated": True,
                "claim_sha256": self.admission.claim_sha256,
                "contract_version": (
                    POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
                ),
                "controller_execution_confirmed": confirmed,
                "durable_shutdown_locator": (
                    None if shutdown_locator is None else shutdown_locator.payload()
                ),
                "durable_shutdown_locator_sha256": (
                    None
                    if shutdown_locator is None
                    else post_enrollment_graceful_stop_shutdown_locator_sha256(shutdown_locator)
                ),
                "operation_id": self.admission.operation_id,
                "pre_effect_observation_sha256": self.pre_effect_observation_sha256,
                "read_only_configuration_sha256": self.read_only_configuration_sha256,
                "persistent_start_confirmed": self.topology_qualified,
                "persistent_topology_transcript_sha256": (
                    self.persistent_topology_transcript_sha256
                ),
                "persistent_topology_sha256": (
                    None
                    if self.persistent_topology is None
                    else self.persistent_topology.snapshot_sha256
                ),
                "qualified": confirmed,
                "reason": self.reason,
                "release_attempted": True,
                "release_confirmed": self.release_confirmed,
                "release_execution_sha256": self.release_execution_sha256,
                "retained_claim_artifact_sha256": retained.artifact_sha256,
                "runtime_start_confirmed": self.sequence_2_confirmed,
                "runtime_state_sha256": self.runtime_state_sha256,
                "sequence_2_confirmed": self.sequence_2_confirmed,
                "service": POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_SERVICE,
                "source_start_confirmed": True,
                "status": self.status,
                "success_outcome_retained": confirmed,
                "successor_candidate_sha256": (
                    None if self.successor is None else _successor_sha256(self.successor)
                ),
                "supervisor_start_confirmed": True,
                "topology_qualified": self.topology_qualified,
                "verification_transcript_sha256": self.verification_transcript_sha256,
                "verifier_binding_sha256": self.verifier_binding_sha256,
            }
        )
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(canonical_first_enrollment_json_bytes(self.payload())).hexdigest()


type _ControllerOutcomeSemanticSnapshot = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    bytes | None,
    str | None,
    tuple[str, ...] | None,
]


def _semantic_slot(
    value: _ControllerOutcomeSemanticSnapshot,
    index: int,
) -> object:
    if (
        type(index) is not int
        or index < 1
        or index >= 12
        or type(value) is not tuple
        or len(value) != 12
        or tuple.__getitem__(value, 0) != "controller-outcome-semantic-snapshot-v1"
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _validate_encoded_payload_projection(
    encoded: bytes,
) -> tuple[
    _ControllerOutcomeSemanticSnapshot,
    TrustedTimePostEnrollmentGracefulStopShutdownLocator | None,
]:
    try:
        projection = _decode_canonical_object(
            encoded,
            maximum_bytes=MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES,
        )
        get = _canonical_json_object_value
        contract_version = get(projection, "contract_version")
        evidence_fields: tuple[str, ...]
        if contract_version == POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION:
            evidence_fields = _EVIDENCE_FIELDS
        elif contract_version == (
            POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
        ):
            evidence_fields = _V1_EVIDENCE_FIELDS
        else:
            raise ValueError
        if _canonical_json_object_keys(projection) != {
            *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
            *_CLOSED_FIELDS,
            *evidence_fields,
        }:
            raise ValueError
        if (
            any(
                get(projection, field_name) is not False
                for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
            )
            or any(get(projection, field_name) is not False for field_name in _CLOSED_FIELDS)
            or get(projection, "service")
            != POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_SERVICE
            or not _is_uuid4(get(projection, "operation_id"))
            or any(
                not _is_sha256(get(projection, field_name))
                for field_name in (
                    "active_controller_admission_sha256",
                    "approval_sha256",
                    "claim_sha256",
                    "pre_effect_observation_sha256",
                    "read_only_configuration_sha256",
                    "retained_claim_artifact_sha256",
                    "verifier_binding_sha256",
                )
            )
            or any(
                get(projection, field_name) is not True
                for field_name in (
                    "claim_retention_revalidated",
                    "release_attempted",
                    "source_start_confirmed",
                    "supervisor_start_confirmed",
                )
            )
            or any(
                type(get(projection, field_name)) is not bool
                for field_name in (
                    "controller_execution_confirmed",
                    "persistent_start_confirmed",
                    "qualified",
                    "release_confirmed",
                    "runtime_start_confirmed",
                    "sequence_2_confirmed",
                    "success_outcome_retained",
                    "topology_qualified",
                )
            )
            or any(
                get(projection, field_name) is not None
                and not _is_sha256(get(projection, field_name))
                for field_name in (
                    "persistent_topology_sha256",
                    "persistent_topology_transcript_sha256",
                    "release_execution_sha256",
                    "runtime_state_sha256",
                    "successor_candidate_sha256",
                    "verification_transcript_sha256",
                )
            )
        ):
            raise ValueError
        status = get(projection, "status")
        reason = get(projection, "reason")
        if (
            type(status) is not str
            or status not in {"post_enrollment_start_confirmed", "recovery_required"}
            or type(reason) is not str
            or reason
            not in {
                "post_enrollment_start_confirmed",
                "release_outcome_unconfirmed",
                "sequence_2_unconfirmed",
                "success_outcome_unconfirmed",
            }
        ):
            raise ValueError
        release_confirmed = get(projection, "release_execution_sha256") is not None
        runtime_state_present = get(projection, "runtime_state_sha256") is not None
        successor_present = get(projection, "successor_candidate_sha256") is not None
        sequence_confirmed = runtime_state_present and successor_present
        topology_qualified = get(projection, "persistent_topology_sha256") is not None
        verification_confirmed = get(projection, "verification_transcript_sha256") is not None
        if topology_qualified != (
            get(projection, "persistent_topology_transcript_sha256") is not None
        ):
            raise ValueError
        shutdown_locator: TrustedTimePostEnrollmentGracefulStopShutdownLocator | None = None
        shutdown_locator_encoded: bytes | None = None
        shutdown_locator_sha256: str | None = None
        persistent_topology_binding_values: tuple[str, ...] | None = None
        if contract_version == POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION:
            locator_payload = get(projection, "durable_shutdown_locator")
            locator_sha256 = get(projection, "durable_shutdown_locator_sha256")
            locator_present = locator_payload is not None
            if locator_present != (locator_sha256 is not None) or locator_present != (
                topology_qualified
            ):
                raise ValueError
            if locator_present:
                if not _is_sha256(locator_sha256):
                    raise ValueError
                shutdown_locator_encoded = _canonical_json_object_bytes(locator_payload)
                locator_projection = _shutdown_locator_projection_from_encoded(
                    shutdown_locator_encoded
                )
                shutdown_locator = decode_post_enrollment_graceful_stop_shutdown_locator(
                    shutdown_locator_encoded
                )
                persistent_topology_binding_values = cast(
                    tuple[str, ...],
                    _shutdown_locator_slot(
                        locator_projection,
                        8,
                    ),
                )
                shutdown_locator_sha256 = cast(str, locator_sha256)
                (
                    topology_operation_id,
                    topology_approval_sha256,
                    topology_claim_sha256,
                    topology_retained_claim_sha256,
                    topology_admission_sha256,
                    topology_successor_sha256,
                    _,
                    _,
                    _,
                    _,
                ) = persistent_topology_binding_values
                if (
                    hashlib.sha256(shutdown_locator_encoded).hexdigest() != locator_sha256
                    or _shutdown_locator_slot(
                        locator_projection,
                        5,
                    )
                    != get(projection, "persistent_topology_sha256")
                    or _shutdown_locator_slot(
                        locator_projection,
                        6,
                    )
                    != get(projection, "persistent_topology_transcript_sha256")
                    or topology_operation_id != get(projection, "operation_id")
                    or topology_approval_sha256 != get(projection, "approval_sha256")
                    or topology_claim_sha256 != get(projection, "claim_sha256")
                    or topology_retained_claim_sha256
                    != get(projection, "retained_claim_artifact_sha256")
                    or topology_admission_sha256
                    != get(projection, "active_controller_admission_sha256")
                    or topology_successor_sha256 != get(projection, "successor_candidate_sha256")
                ):
                    raise ValueError
        confirmed = status == "post_enrollment_start_confirmed"
        if (
            get(projection, "release_confirmed") is not release_confirmed
            or get(projection, "sequence_2_confirmed") is not sequence_confirmed
            or get(projection, "topology_qualified") is not topology_qualified
            or get(projection, "persistent_start_confirmed") is not topology_qualified
            or get(projection, "runtime_start_confirmed") is not sequence_confirmed
            or get(projection, "controller_execution_confirmed") is not confirmed
            or get(projection, "qualified") is not confirmed
            or get(projection, "success_outcome_retained") is not confirmed
        ):
            raise ValueError
        if confirmed:
            if (
                reason != "post_enrollment_start_confirmed"
                or not release_confirmed
                or not sequence_confirmed
                or not topology_qualified
                or not verification_confirmed
            ):
                raise ValueError
        elif status != "recovery_required":
            raise ValueError
        elif reason == "release_outcome_unconfirmed":
            if (
                release_confirmed
                or runtime_state_present
                or successor_present
                or topology_qualified
                or verification_confirmed
            ):
                raise ValueError
        elif reason == "sequence_2_unconfirmed":
            if (
                not release_confirmed
                or successor_present
                or topology_qualified
                or verification_confirmed
            ):
                raise ValueError
        elif reason == "success_outcome_unconfirmed":
            if (
                not release_confirmed
                or not sequence_confirmed
                or not topology_qualified
                or not verification_confirmed
            ):
                raise ValueError
        else:
            raise ValueError
        if _canonical_json_object_bytes(projection) != encoded:
            raise ValueError
        return (
            (
                "controller-outcome-semantic-snapshot-v1",
                contract_version,
                status,
                reason,
                cast(str, get(projection, "operation_id")),
                cast(str, get(projection, "approval_sha256")),
                cast(str, get(projection, "claim_sha256")),
                cast(
                    str,
                    get(projection, "retained_claim_artifact_sha256"),
                ),
                cast(
                    str,
                    get(projection, "active_controller_admission_sha256"),
                ),
                shutdown_locator_encoded,
                shutdown_locator_sha256,
                persistent_topology_binding_values,
            ),
            shutdown_locator,
        )
    except (KeyError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome evidence is invalid"
        ) from None


def _validate_payload_projection(
    payload: object,
) -> tuple[
    str,
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
    TrustedTimePostEnrollmentStartControllerOutcomeReason,
    TrustedTimePostEnrollmentGracefulStopShutdownLocator | None,
]:
    try:
        semantic, shutdown_locator = _validate_encoded_payload_projection(
            canonical_first_enrollment_json_bytes(payload)
        )
        return (
            cast(str, _semantic_slot(semantic, 1)),
            TrustedTimePostEnrollmentStartControllerOutcomeStatus(
                cast(str, _semantic_slot(semantic, 2))
            ),
            TrustedTimePostEnrollmentStartControllerOutcomeReason(
                cast(str, _semantic_slot(semantic, 3))
            ),
            shutdown_locator,
        )
    except (
        TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable,
        TypeError,
        ValueError,
    ):
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome evidence is invalid"
        ) from None


def _encoded_evidence(
    evidence: TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
) -> bytes:
    try:
        evidence.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(evidence.payload())
    except TrustedTimePostEnrollmentStartControllerOutcomeRejected:
        raise
    except BaseException:
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome evidence is invalid"
        ) from None
    if not encoded or len(encoded) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES:
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome evidence is invalid"
        )
    return encoded


def _outcome_file_name(outcome_sha256: str) -> str:
    if not _is_sha256(outcome_sha256):
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome artifact binding is invalid"
        )
    name = (
        f"{POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}{outcome_sha256}"
        f"{POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
    )
    if (
        len(os.fsencode(name)) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
    ):
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome artifact binding is invalid"
        )
    return name


def _slot_bytes(
    outcome_sha256: str,
    *,
    contract_version: str = POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
) -> bytes:
    try:
        if contract_version not in {
            POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
            POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION,
        }:
            raise ValueError
        return _outcome_slot_bytes(
            outcome_sha256,
            outcome_contract_version=contract_version,
        )
    except ValueError:
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome slot binding is invalid"
        ) from None


def _commit_bytes(
    outcome_sha256: str,
    *,
    contract_version: str = POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
) -> bytes:
    if not _is_sha256(outcome_sha256) or contract_version not in {
        POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
        POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION,
    }:
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome commit binding is invalid"
        )
    return canonical_first_enrollment_json_bytes(
        {
            "contract_version": contract_version,
            "outcome_sha256": outcome_sha256,
            "status": "committed",
        }
    )


@_stage_retained_post_enrollment_controller_outcome_type
@dataclass(frozen=True, slots=True, weakref_slot=True)
class RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Exact bytes and inode identity of one terminal controller outcome."""

    operation_id: str
    approval_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    active_controller_admission_sha256: str
    contract_version: str
    status: TrustedTimePostEnrollmentStartControllerOutcomeStatus
    reason: TrustedTimePostEnrollmentStartControllerOutcomeReason
    durable_shutdown_locator: TrustedTimePostEnrollmentGracefulStopShutdownLocator | None = field(
        repr=False
    )
    durable_shutdown_locator_sha256: str | None
    outcome_sha256: str
    artifact_path: Path
    encoded: bytes = field(repr=False)
    file_identity: tuple[int, ...]
    slot_file_identity: tuple[int, ...]
    commit_file_identity: tuple[int, ...] | None = None
    _prepared_marker: object | None = field(default=None, repr=False, compare=False)
    _evidence: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            if (
                type(self) is not RetainedTrustedTimePostEnrollmentStartControllerOutcome
                or not _is_uuid4(self.operation_id)
                or not _is_sha256(self.approval_sha256)
                or not _is_sha256(self.claim_sha256)
                or not _is_sha256(self.retained_claim_artifact_sha256)
                or not _is_sha256(self.active_controller_admission_sha256)
                or self.contract_version
                not in {
                    POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
                    POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION,
                }
                or type(self.status) is not TrustedTimePostEnrollmentStartControllerOutcomeStatus
                or type(self.reason) is not TrustedTimePostEnrollmentStartControllerOutcomeReason
                or (
                    self.durable_shutdown_locator is not None
                    and type(self.durable_shutdown_locator)
                    is not TrustedTimePostEnrollmentGracefulStopShutdownLocator
                )
                or (
                    (self.durable_shutdown_locator is None)
                    != (self.durable_shutdown_locator_sha256 is None)
                )
                or (
                    self.durable_shutdown_locator_sha256 is not None
                    and not _is_sha256(self.durable_shutdown_locator_sha256)
                )
                or not _is_sha256(self.outcome_sha256)
                or type(self.artifact_path) is not type(Path())
                or not self.artifact_path.is_absolute()
                or self.artifact_path != Path(os.path.abspath(self.artifact_path))
                or self.artifact_path.name != _outcome_file_name(self.outcome_sha256)
                or type(self.encoded) is not bytes
                or hashlib.sha256(self.encoded).hexdigest() != self.outcome_sha256
                or type(self.file_identity) is not tuple
                or len(self.file_identity) != 9
                or any(type(value) is not int for value in self.file_identity)
                or not stat.S_ISREG(self.file_identity[2])
                or stat.S_IMODE(self.file_identity[2]) != 0o600
                or self.file_identity[3] != os.geteuid()
                or self.file_identity[5] != 1
                or self.file_identity[6] != len(self.encoded)
                or type(self.slot_file_identity) is not tuple
                or len(self.slot_file_identity) != 9
                or any(type(value) is not int for value in self.slot_file_identity)
                or not stat.S_ISREG(self.slot_file_identity[2])
                or stat.S_IMODE(self.slot_file_identity[2]) != 0o600
                or self.slot_file_identity[3] != os.geteuid()
                or self.slot_file_identity[5] != 1
                or self.slot_file_identity[6]
                != len(
                    _slot_bytes(
                        self.outcome_sha256,
                        contract_version=self.contract_version,
                    )
                )
            ):
                raise ValueError
            if self.commit_file_identity is None:
                if self._prepared_marker is not _PREPARED_OUTCOME_RECEIPT_MARKER:
                    raise ValueError
            elif (
                self._prepared_marker is not None
                or type(self.commit_file_identity) is not tuple
                or len(self.commit_file_identity) != 9
                or any(type(value) is not int for value in self.commit_file_identity)
                or not stat.S_ISREG(self.commit_file_identity[2])
                or stat.S_IMODE(self.commit_file_identity[2]) != 0o600
                or self.commit_file_identity[3] != os.geteuid()
                or self.commit_file_identity[5] != 1
                or self.commit_file_identity[6]
                != len(
                    _commit_bytes(
                        self.outcome_sha256,
                        contract_version=self.contract_version,
                    )
                )
            ):
                raise ValueError
            semantic, shutdown_locator = _validate_encoded_payload_projection(self.encoded)
            if (
                _semantic_slot(semantic, 4) != self.operation_id
                or _semantic_slot(semantic, 5) != self.approval_sha256
                or _semantic_slot(semantic, 6) != self.claim_sha256
                or _semantic_slot(semantic, 7) != self.retained_claim_artifact_sha256
                or _semantic_slot(semantic, 8) != self.active_controller_admission_sha256
                or _semantic_slot(semantic, 1) != self.contract_version
                or _semantic_slot(semantic, 2) != self.status.value
                or _semantic_slot(semantic, 3) != self.reason.value
                or shutdown_locator != self.durable_shutdown_locator
                or _semantic_slot(semantic, 10) != self.durable_shutdown_locator_sha256
            ):
                raise ValueError
            if self._evidence is not None:
                if (
                    type(self._evidence)
                    is not TrustedTimePostEnrollmentStartControllerOutcomeEvidence
                ):
                    raise ValueError
                evidence = self._evidence
                evidence.__post_init__()
                if self.encoded != _encoded_evidence(evidence):
                    raise ValueError
        except (
            TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable,
            TrustedTimePostEnrollmentStartControllerOutcomeRejected,
        ):
            raise
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
                "trusted-time retained controller outcome is invalid"
            ) from None

    @property
    def durable_shutdown_locator_available(self) -> bool:
        """Report only locator availability; this grants no shutdown authority."""

        self.__post_init__()
        return (
            self.contract_version
            == POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
            and self.durable_shutdown_locator is not None
            and self.durable_shutdown_locator_sha256 is not None
        )


type _RetainedControllerOutcomeSnapshot = tuple[
    str,
    str,
    str,
    tuple[int, ...],
    bool,
    tuple[str, ...],
    str,
    bytes,
    _ControllerOutcomeSemanticSnapshot,
    tuple[int, ...],
    bytes,
    tuple[int, ...],
    bytes,
    tuple[int, ...],
]


def _snapshot_slot(
    value: _RetainedControllerOutcomeSnapshot,
    index: int,
) -> object:
    if (
        type(index) is not int
        or index < 1
        or index >= 14
        or type(value) is not tuple
        or len(value) != 14
        or tuple.__getitem__(value, 0) != "retained-controller-outcome-snapshot-v1"
    ):
        raise ValueError
    return tuple.__getitem__(value, index)


def _artifact_directory(path: Path, *, ignored_root: Path) -> Path:
    try:
        canonical_root = Path(os.path.abspath(ignored_root))
        canonical_path = Path(os.path.abspath(path))
    except (OSError, TypeError, ValueError):
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome directory is invalid"
        ) from None
    if (
        type(path) is not type(Path())
        or type(ignored_root) is not type(Path())
        or not path.is_absolute()
        or not ignored_root.is_absolute()
        or path != canonical_path
        or ignored_root != canonical_root
        or path != canonical_root / "trusted-time"
    ):
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome directory is invalid"
        )
    return canonical_path


def _persist(
    evidence: TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
    *,
    retained_claim: RetainedTrustedTimePostEnrollmentStartClaim,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    encoded = _encoded_evidence(evidence)
    semantic, shutdown_locator = _validate_encoded_payload_projection(encoded)
    contract_version = cast(str, _semantic_slot(semantic, 1))
    outcome_sha256 = hashlib.sha256(encoded).hexdigest()
    file_name = _outcome_file_name(outcome_sha256)
    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    created_identity: tuple[int, ...] | None = None
    slot_identity: tuple[int, ...] | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
            create=True,
        )
        directory_descriptor = directory_owner.fileno()
        if _outcome_names(directory_descriptor):
            raise TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained(
                "trusted-time post-enrollment outcome was already retained"
            )
        slot_identity = _reserve_outcome_slot(
            directory_descriptor,
            encoded=_slot_bytes(outcome_sha256),
        )
        if _outcome_names(directory_descriptor):
            raise TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained(
                "trusted-time post-enrollment outcome was already retained"
            )
        if not revalidate_retained_post_enrollment_start_claim(
            retained_claim,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        ):
            raise OSError
        file_descriptor = os.open(
            _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_STAGING_FILE_NAME,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        metadata = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size != len(encoded)
        ):
            raise OSError
        os.link(
            _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_STAGING_FILE_NAME,
            file_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        linked = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        staged_linked = os.fstat(file_descriptor)
        if (
            (linked.st_dev, linked.st_ino) != (metadata.st_dev, metadata.st_ino)
            or _stable_file_identity(linked) != _stable_file_identity(staged_linked)
            or staged_linked.st_nlink != 2
        ):
            raise OSError
        os.unlink(
            _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_STAGING_FILE_NAME,
            dir_fd=directory_descriptor,
        )
        published = os.fstat(file_descriptor)
        named = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            _stable_file_identity(published) != _stable_file_identity(named)
            or published.st_nlink != 1
        ):
            raise OSError
        created_identity = _stable_file_identity(published)
        os.fsync(directory_descriptor)
    except TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise
    except FileExistsError:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained(
            "trusted-time post-enrollment outcome was already retained"
        ) from None
    except BaseException as error:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
            directory_owner = None
            directory_descriptor = None
        if isinstance(error, TrustedTimePostEnrollmentStartControllerOutcomeRejected):
            raise
        if not isinstance(error, (OSError, Exception)):
            raise
        raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
            "trusted-time controller outcome retention is unconfirmed"
        ) from None
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                if directory_owner is not None:
                    with suppress(OSError):
                        directory_owner.close()
                    directory_owner = None
                    directory_descriptor = None
                raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
                    "trusted-time controller outcome retention is unconfirmed"
                ) from None
    try:
        if directory_descriptor is None or created_identity is None or slot_identity is None:
            raise OSError
        retained, observed_identity = _read_retained_outcome(
            directory_descriptor,
            file_name=file_name,
            expected_outcome_names=frozenset({file_name}),
        )
        if retained != encoded or observed_identity != created_identity:
            raise OSError
        slot_bytes, observed_slot_identity = _read_retained_outcome(
            directory_descriptor,
            file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME,
            expected_outcome_names=frozenset({file_name}),
        )
        if slot_bytes != _slot_bytes(outcome_sha256) or observed_slot_identity != slot_identity:
            raise OSError
    except BaseException:
        raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
            "trusted-time controller outcome retention is unconfirmed"
        ) from None
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()
    return RetainedTrustedTimePostEnrollmentStartControllerOutcome(
        operation_id=evidence.admission.operation_id,
        approval_sha256=evidence.admission.approval_sha256,
        claim_sha256=evidence.admission.claim_sha256,
        retained_claim_artifact_sha256=(evidence.admission.retained_claim_artifact_sha256),
        active_controller_admission_sha256=evidence.admission.admission_sha256,
        contract_version=contract_version,
        status=evidence.status,
        reason=evidence.reason,
        durable_shutdown_locator=shutdown_locator,
        durable_shutdown_locator_sha256=(
            None
            if shutdown_locator is None
            else post_enrollment_graceful_stop_shutdown_locator_sha256(shutdown_locator)
        ),
        outcome_sha256=outcome_sha256,
        artifact_path=artifact_directory / file_name,
        encoded=encoded,
        file_identity=created_identity,
        slot_file_identity=slot_identity,
        _prepared_marker=_PREPARED_OUTCOME_RECEIPT_MARKER,
        _evidence=evidence,
    )


def _entry_is_absent(directory_descriptor: int, file_name: str) -> bool:
    try:
        os.stat(file_name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        raise
    return False


def _prepared_binding_is_valid(
    retained: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    *,
    directory_descriptor: int,
    slot_descriptor: int,
) -> bool:
    names = _outcome_names(directory_descriptor)
    if names != frozenset({retained.artifact_path.name}):
        return False
    encoded, identity = _read_retained_outcome(
        directory_descriptor,
        file_name=retained.artifact_path.name,
        expected_outcome_names=names,
    )
    slot, slot_identity = _read_retained_outcome(
        directory_descriptor,
        file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME,
        expected_outcome_names=names,
    )
    return (
        encoded == retained.encoded
        and identity == retained.file_identity
        and slot
        == _slot_bytes(
            retained.outcome_sha256,
            contract_version=retained.contract_version,
        )
        and slot_identity == retained.slot_file_identity
        and _stable_file_identity(os.fstat(slot_descriptor)) == slot_identity
    )


def _revalidate_prepared_controller_outcome(
    retained: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> bool:
    """Validate private prepared evidence without making it publicly loadable."""

    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    try:
        retained.__post_init__()
        if (
            retained.commit_file_identity is not None
            or retained._prepared_marker is not _PREPARED_OUTCOME_RECEIPT_MARKER
        ):
            return False
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if retained.artifact_path.parent != absolute_directory:
            return False
        directory_owner = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        with _locked_outcome_slot(directory_descriptor, exclusive=False) as slot_descriptor:
            return (
                _entry_is_absent(
                    directory_descriptor,
                    _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                )
                and _entry_is_absent(
                    directory_descriptor,
                    _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                )
                and _prepared_binding_is_valid(
                    retained,
                    directory_descriptor=directory_descriptor,
                    slot_descriptor=slot_descriptor,
                )
            )
    except BaseException:
        return False
    finally:
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _obscure_unconfirmed_commit_marker(directory_descriptor: int) -> None:
    try:
        final_exists = not _entry_is_absent(
            directory_descriptor,
            _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
        )
        staging_absent = _entry_is_absent(
            directory_descriptor,
            _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
        )
        if final_exists and staging_absent:
            try:
                os.link(
                    _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                    _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except BaseException:
                with suppress(BaseException):
                    os.unlink(
                        _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                        dir_fd=directory_descriptor,
                    )
        os.fsync(directory_descriptor)
    except BaseException:
        pass


@contextmanager
def _fail_closed_commit_publication(directory_descriptor: int) -> Iterator[None]:
    """Ensure an interrupted commit remains visibly incomplete before unlock."""

    try:
        yield
    except BaseException:
        _obscure_unconfirmed_commit_marker(directory_descriptor)
        raise


def _commit_prepared_controller_outcome(
    retained: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> None:
    """Durably commit one registry-completed prepared controller outcome."""

    directory_owner: _OwnedFileDescriptor | None = None
    directory_descriptor: int | None = None
    commit_descriptor: int | None = None
    commit_identity: tuple[int, ...] | None = None
    try:
        retained.__post_init__()
        if (
            retained.commit_file_identity is not None
            or retained._prepared_marker is not _PREPARED_OUTCOME_RECEIPT_MARKER
        ):
            raise OSError
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if retained.artifact_path.parent != absolute_directory:
            raise OSError
        directory_owner = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        with (
            _locked_outcome_slot(directory_descriptor, exclusive=True) as slot_descriptor,
            _fail_closed_commit_publication(directory_descriptor),
        ):
            if (
                not _entry_is_absent(
                    directory_descriptor,
                    _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                )
                or not _entry_is_absent(
                    directory_descriptor,
                    _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                )
                or not _prepared_binding_is_valid(
                    retained,
                    directory_descriptor=directory_descriptor,
                    slot_descriptor=slot_descriptor,
                )
            ):
                raise OSError
            encoded = _commit_bytes(
                retained.outcome_sha256,
                contract_version=retained.contract_version,
            )
            commit_descriptor = os.open(
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            view = memoryview(encoded)
            while view:
                written = os.write(commit_descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fchmod(commit_descriptor, 0o600)
            os.fsync(commit_descriptor)
            staged = os.fstat(commit_descriptor)
            if (
                not stat.S_ISREG(staged.st_mode)
                or stat.S_IMODE(staged.st_mode) != 0o600
                or staged.st_uid != os.geteuid()
                or staged.st_nlink != 1
                or staged.st_size != len(encoded)
            ):
                raise OSError
            os.fsync(directory_descriptor)
            os.link(
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            linked = os.fstat(commit_descriptor)
            named = os.stat(
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if linked.st_nlink != 2 or _stable_file_identity(linked) != _stable_file_identity(
                named
            ):
                raise OSError
            os.fsync(directory_descriptor)
            os.unlink(
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                dir_fd=directory_descriptor,
            )
            published = os.fstat(commit_descriptor)
            named = os.stat(
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if published.st_nlink != 1 or _stable_file_identity(published) != _stable_file_identity(
                named
            ):
                raise OSError
            os.fsync(directory_descriptor)
            commit_identity = _stable_file_identity(published)
            observed, observed_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                expected_outcome_names=frozenset({retained.artifact_path.name}),
            )
            if observed != encoded or observed_identity != commit_identity:
                raise OSError
            descriptor_to_close = commit_descriptor
            commit_descriptor = None
            os.close(descriptor_to_close)
            object.__setattr__(retained, "commit_file_identity", commit_identity)
            object.__setattr__(retained, "_prepared_marker", None)
            retained.__post_init__()
    except BaseException as error:
        if directory_descriptor is not None:
            _obscure_unconfirmed_commit_marker(directory_descriptor)
        with suppress(BaseException):
            object.__setattr__(retained, "commit_file_identity", None)
            object.__setattr__(retained, "_prepared_marker", _PREPARED_OUTCOME_RECEIPT_MARKER)
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
            "trusted-time controller outcome retention is unconfirmed"
        ) from None
    finally:
        if commit_descriptor is not None:
            with suppress(OSError):
                os.close(commit_descriptor)
        if directory_owner is not None:
            with suppress(OSError):
                directory_owner.close()


def _checkpoint_claim(
    checkpoint: _TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint,
    evidence: TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
    *,
    artifact_directory: Path,
    ignored_root: Path,
) -> RetainedTrustedTimePostEnrollmentStartClaim:
    try:
        if (
            type(checkpoint) is not _TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint
            or checkpoint.artifact_directory != artifact_directory
            or checkpoint.ignored_root != ignored_root
            or checkpoint.outcome_kind
            != (
                "success"
                if evidence.status
                is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
                else "failure"
            )
            or checkpoint.observed_monotonic_ns < checkpoint.started_monotonic_ns
            or checkpoint.observed_monotonic_ns >= checkpoint.deadline_monotonic_ns
        ):
            raise ValueError
        retained = checkpoint.retained_claim
        expected = _admission_retained_claim(evidence.admission)
        if retained is not expected:
            raise ValueError
        return retained
    except BaseException:
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time controller outcome claim evidence is unavailable"
        ) from None


def retain_post_enrollment_start_controller_outcome(
    *,
    topology_issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    choreography_lease: object,
    post_effect_outcome_capability: object,
    evidence: TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Consume one post-effect capability and retain one terminal outcome."""

    if (
        type(topology_issuer) is not TrustedTimePostEnrollmentTopologyObservationIssuer
        or type(evidence) is not TrustedTimePostEnrollmentStartControllerOutcomeEvidence
    ):
        raise TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable(
            "trusted-time controller outcome capability is unavailable"
        )
    checkpoint: _TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint | None = None
    begin_attempted = False
    post_effect_transitioned: bool | None = None
    retained_outcome: RetainedTrustedTimePostEnrollmentStartControllerOutcome | None = None
    absolute_directory: Path | None = None
    try:
        evidence.__post_init__()
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        begin_attempted = True
        checkpoint = topology_issuer._begin_post_effect_controller_outcome_retention(
            post_effect_outcome_capability,
            choreography_lease,
            _admission_retained_claim(evidence.admission),
            outcome_kind=(
                "success"
                if evidence.status
                is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
                else "failure"
            ),
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        )
        retained_claim = _checkpoint_claim(
            checkpoint,
            evidence,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        )
        if not revalidate_retained_post_enrollment_start_claim(
            retained_claim,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        ):
            raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
                "trusted-time controller outcome claim evidence is unavailable"
            )
        retained_outcome = _persist(
            evidence,
            retained_claim=retained_claim,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        )
        if not _revalidate_prepared_controller_outcome(
            retained_outcome,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        ):
            raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
                "trusted-time controller outcome retention is unconfirmed"
            )
        topology_issuer._complete_post_effect_controller_outcome_retention(
            post_effect_outcome_capability,
            checkpoint,
            retained_outcome,
        )
        _commit_prepared_controller_outcome(
            retained_outcome,
            artifact_directory=absolute_directory,
            ignored_root=ignored_root,
        )
        return retained_outcome
    except TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable:
        raise
    except BaseException as error:
        if (
            retained_outcome is not None
            and absolute_directory is not None
            and retained_outcome.commit_file_identity is not None
            and revalidate_retained_post_enrollment_start_controller_outcome(
                retained_outcome,
                artifact_directory=absolute_directory,
                ignored_root=ignored_root,
            )
        ):
            return retained_outcome
        if begin_attempted:
            if checkpoint is None:
                try:
                    post_effect_transitioned = (
                        topology_issuer._post_effect_outcome_retention_was_transitioned(
                            post_effect_outcome_capability
                        )
                    )
                except BaseException:
                    post_effect_transitioned = None
            with suppress(BaseException):
                topology_issuer._abandon_post_effect_controller_outcome_retention(
                    post_effect_outcome_capability,
                    checkpoint,
                    retained_outcome,
                )
        if isinstance(
            error,
            (
                TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained,
                TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable,
                TrustedTimePostEnrollmentStartControllerOutcomeRejected,
                TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed,
            ),
        ):
            raise
        if checkpoint is None and post_effect_transitioned is False:
            raise TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable(
                "trusted-time controller outcome capability is unavailable"
            ) from None
        raise TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed(
            "trusted-time controller outcome retention is unconfirmed"
        ) from None


def _receipt_from_encoded(
    *,
    encoded: bytes,
    artifact_path: Path,
    file_identity: tuple[int, ...],
    slot_file_identity: tuple[int, ...],
    commit_file_identity: tuple[int, ...],
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    try:
        semantic, shutdown_locator = _validate_encoded_payload_projection(encoded)
        outcome_sha256 = hashlib.sha256(encoded).hexdigest()
        if artifact_path.name != _outcome_file_name(outcome_sha256):
            raise ValueError
        return RetainedTrustedTimePostEnrollmentStartControllerOutcome(
            operation_id=cast(str, _semantic_slot(semantic, 4)),
            approval_sha256=cast(str, _semantic_slot(semantic, 5)),
            claim_sha256=cast(str, _semantic_slot(semantic, 6)),
            retained_claim_artifact_sha256=cast(
                str,
                _semantic_slot(semantic, 7),
            ),
            active_controller_admission_sha256=cast(
                str,
                _semantic_slot(semantic, 8),
            ),
            contract_version=cast(str, _semantic_slot(semantic, 1)),
            status=TrustedTimePostEnrollmentStartControllerOutcomeStatus(
                cast(str, _semantic_slot(semantic, 2))
            ),
            reason=TrustedTimePostEnrollmentStartControllerOutcomeReason(
                cast(str, _semantic_slot(semantic, 3))
            ),
            durable_shutdown_locator=shutdown_locator,
            durable_shutdown_locator_sha256=cast(
                str | None,
                _semantic_slot(semantic, 10),
            ),
            outcome_sha256=outcome_sha256,
            artifact_path=artifact_path,
            encoded=encoded,
            file_identity=file_identity,
            slot_file_identity=slot_file_identity,
            commit_file_identity=commit_file_identity,
        )
    except (
        TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable,
        TrustedTimePostEnrollmentStartControllerOutcomeRejected,
    ):
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome is unavailable"
        ) from None
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome is unavailable"
        ) from None


def _snapshot_outcome_projection(
    snapshot: _RetainedControllerOutcomeSnapshot,
) -> tuple[object, ...]:
    """Validate and decode only the exact tagged native-file snapshot."""

    try:
        artifact_directory = _snapshot_slot(snapshot, 1)
        ignored_root = _snapshot_slot(snapshot, 2)
        directory_identity = _snapshot_slot(snapshot, 3)
        commit_staging_absent = _snapshot_slot(snapshot, 4)
        outcome_names = _snapshot_slot(snapshot, 5)
        outcome_path = _snapshot_slot(snapshot, 6)
        outcome_encoded = _snapshot_slot(snapshot, 7)
        snapshot_semantic = _snapshot_slot(snapshot, 8)
        outcome_file_identity = _snapshot_slot(snapshot, 9)
        slot_encoded = _snapshot_slot(snapshot, 10)
        slot_file_identity = _snapshot_slot(snapshot, 11)
        commit_encoded = _snapshot_slot(snapshot, 12)
        commit_file_identity = _snapshot_slot(snapshot, 13)
        if (
            type(artifact_directory) is not str
            or type(ignored_root) is not str
            or type(directory_identity) is not tuple
            or len(directory_identity) != 9
            or any(type(value) is not int for value in directory_identity)
            or not stat.S_ISDIR(directory_identity[2])
            or stat.S_IMODE(directory_identity[2]) != 0o700
            or directory_identity[3] != os.geteuid()
            or commit_staging_absent is not True
            or type(outcome_names) is not tuple
            or len(outcome_names) != 1
            or any(type(value) is not str for value in outcome_names)
            or type(outcome_path) is not str
            or type(outcome_encoded) is not bytes
            or type(snapshot_semantic) is not tuple
            or type(outcome_file_identity) is not tuple
            or type(slot_encoded) is not bytes
            or type(slot_file_identity) is not tuple
            or type(commit_encoded) is not bytes
            or type(commit_file_identity) is not tuple
            or any(
                len(identity) != 9
                or any(type(value) is not int for value in identity)
                or not stat.S_ISREG(identity[2])
                or stat.S_IMODE(identity[2]) != 0o600
                or identity[3] != os.geteuid()
                or identity[5] != 1
                or identity[6] != expected_size
                for identity, expected_size in (
                    (outcome_file_identity, len(outcome_encoded)),
                    (slot_file_identity, len(slot_encoded)),
                    (commit_file_identity, len(commit_encoded)),
                )
            )
        ):
            raise ValueError
        exact_directory = _artifact_directory(
            Path(artifact_directory),
            ignored_root=Path(ignored_root),
        )
        if (
            os.fspath(exact_directory) != artifact_directory
            or os.fspath(Path(ignored_root)) != ignored_root
            or outcome_path != os.fspath(exact_directory / outcome_names[0])
        ):
            raise ValueError
        semantic, _ = _validate_encoded_payload_projection(outcome_encoded)
        outcome_sha256 = hashlib.sha256(outcome_encoded).hexdigest()
        semantic_contract_version = cast(
            str,
            _semantic_slot(semantic, 1),
        )
        if (
            semantic != snapshot_semantic
            or outcome_names[0] != _outcome_file_name(outcome_sha256)
            or slot_encoded
            != _slot_bytes(
                outcome_sha256,
                contract_version=semantic_contract_version,
            )
            or commit_encoded
            != _commit_bytes(
                outcome_sha256,
                contract_version=semantic_contract_version,
            )
        ):
            raise ValueError
        return (
            cast(str, _semantic_slot(semantic, 4)),
            cast(str, _semantic_slot(semantic, 5)),
            cast(str, _semantic_slot(semantic, 6)),
            cast(str, _semantic_slot(semantic, 7)),
            cast(str, _semantic_slot(semantic, 8)),
            semantic_contract_version,
            cast(str, _semantic_slot(semantic, 2)),
            cast(str, _semantic_slot(semantic, 3)),
            _semantic_slot(semantic, 9),
            _semantic_slot(semantic, 10),
            outcome_sha256,
            outcome_path,
            outcome_encoded,
            outcome_file_identity,
            slot_file_identity,
            commit_file_identity,
        )
    except (
        TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable,
        TrustedTimePostEnrollmentStartControllerOutcomeRejected,
    ):
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome snapshot is unavailable"
        ) from None


def _retained_outcome_matches_snapshot(
    retained: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    snapshot: _RetainedControllerOutcomeSnapshot,
) -> bool:
    """Treat the public retained object only as a secondary consistency sentinel."""

    try:
        expected = _snapshot_outcome_projection(snapshot)
        retained.__post_init__()
        shutdown_locator_encoded = (
            None
            if retained.durable_shutdown_locator is None
            else canonical_first_enrollment_json_bytes(retained.durable_shutdown_locator.payload())
        )
        observed = (
            retained.operation_id,
            retained.approval_sha256,
            retained.claim_sha256,
            retained.retained_claim_artifact_sha256,
            retained.active_controller_admission_sha256,
            retained.contract_version,
            retained.status.value,
            retained.reason.value,
            shutdown_locator_encoded,
            retained.durable_shutdown_locator_sha256,
            retained.outcome_sha256,
            os.fspath(retained.artifact_path),
            retained.encoded,
            retained.file_identity,
            retained.slot_file_identity,
            retained.commit_file_identity,
        )
        return (
            type(retained) is RetainedTrustedTimePostEnrollmentStartControllerOutcome
            and retained._prepared_marker is None
            and observed == expected
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


_NativeStatIdentity = tuple[int, int, int, int, int, int, int, int, int]


def _preferred_native_cleanup_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_native_cleanup_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_native_cleanup_exception(preferred, error)
    return preferred


def _cleanup_native_owners(
    owners: tuple[_NativeOwnedFileDescriptor | None, ...],
) -> BaseException | None:
    first_error: BaseException | None = None
    for owner in owners:
        if owner is None:
            continue
        for _ in range(2):
            try:
                if owner.closed:
                    break
                owner.close()
            except BaseException as error:
                first_error = _preferred_native_cleanup_exception(first_error, error)
        try:
            if not owner.closed:
                first_error = _preferred_native_cleanup_exception(
                    first_error,
                    RuntimeError("native owned file descriptor could not be closed"),
                )
        except BaseException as error:
            first_error = _preferred_native_cleanup_exception(first_error, error)
    return first_error


def _require_native_stat_identity(value: object) -> _NativeStatIdentity:
    if (
        type(value) is not tuple
        or len(value) != 9
        or any(type(field) is not int for field in value)
    ):
        raise OSError
    return cast(_NativeStatIdentity, value)


def _native_absolute_path_components(path: str) -> tuple[str, ...]:
    if (
        type(path) is not str
        or not os.path.isabs(path)
        or os.path.abspath(path) != path
        or os.path.normpath(path) != path
        or "\x00" in path
    ):
        raise OSError
    components = tuple(path.split(os.sep))[1:]
    if any(
        not component
        or component in {".", ".."}
        or os.sep in component
        or "\x00" in component
        or len(os.fsencode(component)) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES
        for component in components
    ):
        raise OSError
    return components


def _native_inventory_snapshot(
    directory_owner: _NativeOwnedFileDescriptor,
) -> tuple[tuple[str, ...], _NativeStatIdentity]:
    names, before, after = _native_list_snapshot(directory_owner)
    before = _require_native_stat_identity(before)
    after = _require_native_stat_identity(after)
    final = _require_native_stat_identity(_native_fstat(directory_owner))
    if (
        type(names) is not tuple
        or len(names) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES
        or any(
            type(name) is not str
            or not name
            or len(os.fsencode(name)) > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES
            for name in names
        )
        or names != tuple(sorted(names))
        or len(names) != len(frozenset(names))
        or before != after
        or after != final
    ):
        raise OSError
    return names, final


def _native_outcome_names(names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        name
        for name in names
        if name == POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME
        or (
            name.startswith(POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX)
            and name.endswith(POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX)
        )
    )


def _native_entry_is_absent(
    directory_owner: _NativeOwnedFileDescriptor,
    file_name: str,
) -> bool:
    try:
        _native_statat(directory_owner, file_name)
    except FileNotFoundError:
        return True
    return False


def _native_read_retained_outcome(
    directory_owner: _NativeOwnedFileDescriptor,
    *,
    file_name: str,
    expected_outcome_names: tuple[str, ...],
) -> tuple[bytes, _NativeStatIdentity]:
    file_owner: _NativeOwnedFileDescriptor | None = None
    result: tuple[bytes, _NativeStatIdentity] | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            if (
                type(file_name) is not str
                or not file_name
                or file_name in {".", ".."}
                or os.sep in file_name
                or "\x00" in file_name
            ):
                raise OSError
            directory_before = _require_native_stat_identity(_native_fstat(directory_owner))
            file_owner = _native_open_child_regular(directory_owner, file_name)
            encoded, before, after = _native_read_snapshot(
                file_owner,
                MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES,
            )
            before = _require_native_stat_identity(before)
            after = _require_native_stat_identity(after)
            if (
                not stat.S_ISREG(before[2])
                or before[3] != os.geteuid()
                or stat.S_IMODE(before[2]) != 0o600
                or before[5] != 1
                or before[6] < 1
                or before[6] > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES
                or len(encoded) != before[6]
            ):
                raise OSError
            named = _require_native_stat_identity(_native_statat(directory_owner, file_name))
            inventory, directory_after = _native_inventory_snapshot(directory_owner)
            if (
                before != after
                or after != named
                or directory_before != directory_after
                or _native_outcome_names(inventory) != expected_outcome_names
            ):
                raise OSError
            result = encoded, after
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_native_owners((file_owner,))
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_native_owners((file_owner,))
    terminal = _preferred_native_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        raise terminal
    if result is None:
        raise RuntimeError("native retained outcome read did not produce a result")
    return result


def _load_retained_post_enrollment_start_controller_outcome_with_snapshot(
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> tuple[
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    _RetainedControllerOutcomeSnapshot,
]:
    """Load one committed outcome and its native-owner-rooted tagged snapshot."""

    result: (
        tuple[
            RetainedTrustedTimePostEnrollmentStartControllerOutcome,
            _RetainedControllerOutcomeSnapshot,
        ]
        | None
    ) = None
    try:
        with _held_outcome_slot_process_lock():
            directory_owner: _NativeOwnedFileDescriptor | None = None
            next_owner: _NativeOwnedFileDescriptor | None = None
            slot_owner: _NativeOwnedFileDescriptor | None = None
            body_error: BaseException | None = None
            transition_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            retry_error: BaseException | None = None
            try:
                try:
                    absolute_directory = _artifact_directory(
                        artifact_directory,
                        ignored_root=ignored_root,
                    )
                    exact_directory = os.fspath(absolute_directory)
                    exact_ignored_root = os.fspath(ignored_root)
                    if (
                        type(exact_directory) is not str
                        or type(exact_ignored_root) is not str
                        or exact_directory != os.path.abspath(exact_directory)
                        or exact_directory != os.path.normpath(exact_directory)
                        or exact_ignored_root != os.path.abspath(exact_ignored_root)
                        or exact_ignored_root != os.path.normpath(exact_ignored_root)
                        or exact_directory != os.path.join(exact_ignored_root, "trusted-time")
                    ):
                        raise ValueError
                    directory_owner = _native_open_root_directory()
                    current_path = os.sep
                    for component in _native_absolute_path_components(exact_directory):
                        next_owner = _native_open_child_directory(
                            directory_owner,
                            component,
                        )
                        current_path = os.path.join(current_path, component)
                        next_identity = _require_native_stat_identity(_native_fstat(next_owner))
                        protected = current_path == exact_ignored_root or current_path.startswith(
                            exact_ignored_root + os.sep
                        )
                        if not stat.S_ISDIR(next_identity[2]) or (
                            protected
                            and (
                                next_identity[3] != os.geteuid()
                                or stat.S_IMODE(next_identity[2]) != 0o700
                            )
                        ):
                            raise OSError
                        intermediate_error = _cleanup_native_owners((directory_owner,))
                        if intermediate_error is not None:
                            raise intermediate_error
                        directory_owner = next_owner
                        next_owner = None
                    directory_identity = _require_native_stat_identity(
                        _native_fstat(directory_owner)
                    )
                    if (
                        not stat.S_ISDIR(directory_identity[2])
                        or directory_identity[3] != os.geteuid()
                        or stat.S_IMODE(directory_identity[2]) != 0o700
                    ):
                        raise OSError
                    slot_owner = _native_open_child_regular(
                        directory_owner,
                        _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME,
                    )
                    _native_flock(slot_owner, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    locked_slot_identity = _require_native_stat_identity(_native_fstat(slot_owner))
                    if (
                        not stat.S_ISREG(locked_slot_identity[2])
                        or locked_slot_identity[3] != os.geteuid()
                        or stat.S_IMODE(locked_slot_identity[2]) != 0o600
                        or locked_slot_identity[5] != 1
                        or locked_slot_identity[6] < 1
                        or locked_slot_identity[6] > MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES
                    ):
                        raise OSError
                    initial_inventory, inventory_directory_identity = _native_inventory_snapshot(
                        directory_owner
                    )
                    commit_staging_absent = _native_entry_is_absent(
                        directory_owner,
                        _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                    )
                    outcome_names = _native_outcome_names(initial_inventory)
                    if (
                        inventory_directory_identity != directory_identity
                        or not commit_staging_absent
                        or _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME
                        in initial_inventory
                        or len(outcome_names) != 1
                    ):
                        raise ValueError
                    file_name = outcome_names[0]
                    if file_name == POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME:
                        raise ValueError
                    digest = file_name[
                        len(POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX) : -len(
                            POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX
                        )
                    ]
                    if file_name != _outcome_file_name(digest):
                        raise ValueError
                    encoded, identity = _native_read_retained_outcome(
                        directory_owner,
                        file_name=file_name,
                        expected_outcome_names=outcome_names,
                    )
                    slot, slot_identity = _native_read_retained_outcome(
                        directory_owner,
                        file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME,
                        expected_outcome_names=outcome_names,
                    )
                    marker, marker_identity = _native_read_retained_outcome(
                        directory_owner,
                        file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                        expected_outcome_names=outcome_names,
                    )
                    if slot_identity != locked_slot_identity:
                        raise ValueError
                    semantic, _ = _validate_encoded_payload_projection(encoded)
                    snapshot: _RetainedControllerOutcomeSnapshot = (
                        "retained-controller-outcome-snapshot-v1",
                        exact_directory,
                        exact_ignored_root,
                        directory_identity,
                        commit_staging_absent,
                        outcome_names,
                        os.path.join(exact_directory, file_name),
                        encoded,
                        semantic,
                        identity,
                        slot,
                        slot_identity,
                        marker,
                        marker_identity,
                    )
                    _snapshot_outcome_projection(snapshot)
                    retained = _receipt_from_encoded(
                        encoded=cast(bytes, _snapshot_slot(snapshot, 7)),
                        artifact_path=Path(cast(str, _snapshot_slot(snapshot, 6))),
                        file_identity=cast(
                            tuple[int, ...],
                            _snapshot_slot(snapshot, 9),
                        ),
                        slot_file_identity=cast(
                            tuple[int, ...],
                            _snapshot_slot(snapshot, 11),
                        ),
                        commit_file_identity=cast(
                            tuple[int, ...],
                            _snapshot_slot(snapshot, 13),
                        ),
                    )
                    final_encoded, final_identity = _native_read_retained_outcome(
                        directory_owner,
                        file_name=file_name,
                        expected_outcome_names=outcome_names,
                    )
                    final_slot, final_slot_identity = _native_read_retained_outcome(
                        directory_owner,
                        file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME,
                        expected_outcome_names=outcome_names,
                    )
                    final_marker, final_marker_identity = _native_read_retained_outcome(
                        directory_owner,
                        file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                        expected_outcome_names=outcome_names,
                    )
                    final_inventory, final_directory_identity = _native_inventory_snapshot(
                        directory_owner
                    )
                    final_semantic, _ = _validate_encoded_payload_projection(final_encoded)
                    if (
                        not _native_entry_is_absent(
                            directory_owner,
                            _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
                        )
                        or final_inventory != initial_inventory
                        or final_directory_identity != directory_identity
                        or _require_native_stat_identity(_native_fstat(slot_owner))
                        != locked_slot_identity
                        or final_encoded != _snapshot_slot(snapshot, 7)
                        or final_identity != _snapshot_slot(snapshot, 9)
                        or final_slot != _snapshot_slot(snapshot, 10)
                        or final_slot_identity != _snapshot_slot(snapshot, 11)
                        or final_marker != _snapshot_slot(snapshot, 12)
                        or final_marker_identity != _snapshot_slot(snapshot, 13)
                        or final_semantic != _snapshot_slot(snapshot, 8)
                        or type(retained)
                        is not RetainedTrustedTimePostEnrollmentStartControllerOutcome
                    ):
                        raise ValueError
                    result = retained, snapshot
                except BaseException as error:
                    body_error = error
                finally:
                    cleanup_error = _cleanup_native_owners(
                        (slot_owner, next_owner, directory_owner)
                    )
            except BaseException as error:
                transition_error = error
            finally:
                retry_error = _cleanup_native_owners((slot_owner, next_owner, directory_owner))
            terminal = _preferred_native_cleanup_exceptions(
                body_error,
                transition_error,
                cleanup_error,
                retry_error,
            )
            if terminal is not None:
                raise terminal
    except TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable:
        raise
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome is unavailable"
        ) from None
    if result is None:
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome is unavailable"
        )
    return result


def _revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
    snapshot: object,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bool:
    """Reload and compare one exact immutable controller-outcome snapshot."""

    try:
        if type(snapshot) is not tuple:
            return False
        typed_snapshot = cast(_RetainedControllerOutcomeSnapshot, snapshot)
        _snapshot_outcome_projection(typed_snapshot)
        exact_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if os.fspath(exact_directory) != _snapshot_slot(typed_snapshot, 1) or os.fspath(
            ignored_root
        ) != _snapshot_slot(typed_snapshot, 2):
            return False
        _, fresh_snapshot = _load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=exact_directory,
            ignored_root=ignored_root,
        )
        return fresh_snapshot == typed_snapshot
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def revalidate_retained_post_enrollment_start_controller_outcome(
    retained: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bool:
    if type(retained) is not RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        return False
    try:
        _, snapshot = _load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        return _retained_outcome_matches_snapshot(retained, snapshot)
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        return False


def load_retained_post_enrollment_start_controller_outcome(
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Load one exact durable controller outcome without granting authority."""

    retained, _ = _load_retained_post_enrollment_start_controller_outcome_with_snapshot(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    return retained


_finalize_post_enrollment_controller_projection_types()

del _finalize_post_enrollment_controller_projection_types
del _stage_post_enrollment_controller_outcome_reason_type
del _stage_post_enrollment_controller_outcome_status_type
del _stage_post_enrollment_controller_prepared_marker_type
del _stage_retained_post_enrollment_controller_outcome_type


__all__ = [
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES",
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES",
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES",
    "POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME",
    "POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX",
    "POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX",
    "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_SERVICE",
    "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION",
    "RetainedTrustedTimePostEnrollmentStartControllerOutcome",
    "TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained",
    "TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable",
    "TrustedTimePostEnrollmentStartControllerOutcomeEvidence",
    "TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable",
    "TrustedTimePostEnrollmentStartControllerOutcomeReason",
    "TrustedTimePostEnrollmentStartControllerOutcomeRejected",
    "TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed",
    "TrustedTimePostEnrollmentStartControllerOutcomeStatus",
    "load_retained_post_enrollment_start_controller_outcome",
    "retain_post_enrollment_start_controller_outcome",
    "revalidate_retained_post_enrollment_start_controller_outcome",
]
