"""Durable terminal evidence for one post-effect trusted-time controller.

This module owns the single global post-enrollment outcome slot after the
pre-release recovery capability has been irreversibly transitioned.  It can
retain either one fully confirmed start or one truthful post-effect recovery
disposition.  Neither form grants reusable runtime, shutdown, operational, or
trading authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

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
    _locked_outcome_slot,
    _open_owner_only_artifact_directory,
    _outcome_names,
    _outcome_slot_bytes,
    _read_retained_outcome,
    _reserve_outcome_slot,
    _stable_file_identity,
)
from scripts.trusted_time_post_enrollment_persistent_topology import (
    TrustedTimePostEnrollmentPersistentTopologySnapshot,
)
from scripts.trusted_time_post_enrollment_start import (
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    IGNORED_ARTIFACT_ROOT,
    RetainedTrustedTimePostEnrollmentStartClaim,
    revalidate_retained_post_enrollment_start_claim,
)
from scripts.trusted_time_post_enrollment_topology_reader import (
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    _TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint,
)

POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-retained-controller-outcome-v1"
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
_PREPARED_OUTCOME_RECEIPT_MARKER = object()


class TrustedTimePostEnrollmentStartControllerOutcomeStatus(StrEnum):
    """The two terminal states admitted after the release boundary."""

    CONFIRMED = "post_enrollment_start_confirmed"
    RECOVERY_REQUIRED = "recovery_required"


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

_EVIDENCE_FIELDS = (
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


def _validate_payload_projection(
    payload: object,
) -> tuple[
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
    TrustedTimePostEnrollmentStartControllerOutcomeReason,
]:
    try:
        if type(payload) is not dict or set(payload) != {
            *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
            *_CLOSED_FIELDS,
            *_EVIDENCE_FIELDS,
        }:
            raise ValueError
        projection = payload
        if (
            any(
                projection[field_name] is not False
                for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
            )
            or any(projection[field_name] is not False for field_name in _CLOSED_FIELDS)
            or projection["contract_version"]
            != POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
            or projection["service"] != POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_SERVICE
            or not _is_uuid4(projection["operation_id"])
            or any(
                not _is_sha256(projection[field_name])
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
                projection[field_name] is not True
                for field_name in (
                    "claim_retention_revalidated",
                    "release_attempted",
                    "source_start_confirmed",
                    "supervisor_start_confirmed",
                )
            )
            or any(
                type(projection[field_name]) is not bool
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
                projection[field_name] is not None and not _is_sha256(projection[field_name])
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
        status = TrustedTimePostEnrollmentStartControllerOutcomeStatus(projection["status"])
        reason = TrustedTimePostEnrollmentStartControllerOutcomeReason(projection["reason"])
        release_confirmed = projection["release_execution_sha256"] is not None
        sequence_confirmed = (
            projection["runtime_state_sha256"] is not None
            and projection["successor_candidate_sha256"] is not None
        )
        topology_qualified = projection["persistent_topology_sha256"] is not None
        verification_confirmed = projection["verification_transcript_sha256"] is not None
        if topology_qualified != (projection["persistent_topology_transcript_sha256"] is not None):
            raise ValueError
        confirmed = status is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
        if (
            projection["release_confirmed"] is not release_confirmed
            or projection["sequence_2_confirmed"] is not sequence_confirmed
            or projection["topology_qualified"] is not topology_qualified
            or projection["persistent_start_confirmed"] is not topology_qualified
            or projection["runtime_start_confirmed"] is not sequence_confirmed
            or projection["controller_execution_confirmed"] is not confirmed
            or projection["qualified"] is not confirmed
            or projection["success_outcome_retained"] is not confirmed
        ):
            raise ValueError
        if confirmed:
            if (
                reason
                is not (
                    TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
                )
                or not release_confirmed
                or not sequence_confirmed
                or not topology_qualified
                or not verification_confirmed
            ):
                raise ValueError
        elif status is not TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED:
            raise ValueError
        elif reason is (
            TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
        ):
            if (
                release_confirmed
                or sequence_confirmed
                or topology_qualified
                or verification_confirmed
            ):
                raise ValueError
        elif reason is (
            TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED
        ):
            if (
                not release_confirmed
                or sequence_confirmed
                or topology_qualified
                or verification_confirmed
            ):
                raise ValueError
        elif reason is (
            TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
        ):
            if (
                not release_confirmed
                or not sequence_confirmed
                or not topology_qualified
                or not verification_confirmed
            ):
                raise ValueError
        else:
            raise ValueError
        return status, reason
    except (KeyError, TypeError, ValueError):
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


def _slot_bytes(outcome_sha256: str) -> bytes:
    try:
        return _outcome_slot_bytes(
            outcome_sha256,
            outcome_contract_version=(
                POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
            ),
        )
    except ValueError:
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome slot binding is invalid"
        ) from None


def _commit_bytes(outcome_sha256: str) -> bytes:
    if not _is_sha256(outcome_sha256):
        raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
            "trusted-time controller outcome commit binding is invalid"
        )
    return canonical_first_enrollment_json_bytes(
        {
            "contract_version": (
                POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
            ),
            "outcome_sha256": outcome_sha256,
            "status": "committed",
        }
    )


@dataclass(frozen=True, slots=True)
class RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Exact bytes and inode identity of one terminal controller outcome."""

    operation_id: str
    approval_sha256: str
    claim_sha256: str
    retained_claim_artifact_sha256: str
    active_controller_admission_sha256: str
    status: TrustedTimePostEnrollmentStartControllerOutcomeStatus
    reason: TrustedTimePostEnrollmentStartControllerOutcomeReason
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
                or type(self.status) is not TrustedTimePostEnrollmentStartControllerOutcomeStatus
                or type(self.reason) is not TrustedTimePostEnrollmentStartControllerOutcomeReason
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
                or self.slot_file_identity[6] != len(_slot_bytes(self.outcome_sha256))
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
                or self.commit_file_identity[6] != len(_commit_bytes(self.outcome_sha256))
            ):
                raise ValueError
            payload = json.loads(self.encoded)
            if canonical_first_enrollment_json_bytes(payload) != self.encoded:
                raise ValueError
            status, reason = _validate_payload_projection(payload)
            if (
                payload["operation_id"] != self.operation_id
                or payload["approval_sha256"] != self.approval_sha256
                or payload["claim_sha256"] != self.claim_sha256
                or payload["retained_claim_artifact_sha256"] != self.retained_claim_artifact_sha256
                or payload["active_controller_admission_sha256"]
                != self.active_controller_admission_sha256
                or status is not self.status
                or reason is not self.reason
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
        except BaseException:
            raise TrustedTimePostEnrollmentStartControllerOutcomeRejected(
                "trusted-time retained controller outcome is invalid"
            ) from None


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
    outcome_sha256 = hashlib.sha256(encoded).hexdigest()
    file_name = _outcome_file_name(outcome_sha256)
    directory_descriptor: int | None = None
    file_descriptor: int | None = None
    created_identity: tuple[int, ...] | None = None
    slot_identity: tuple[int, ...] | None = None
    try:
        directory_descriptor = _open_owner_only_artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
            create=True,
        )
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
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
            directory_descriptor = None
        raise
    except FileExistsError:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
            directory_descriptor = None
        raise TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained(
            "trusted-time post-enrollment outcome was already retained"
        ) from None
    except BaseException as error:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
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
                if directory_descriptor is not None:
                    with suppress(OSError):
                        os.close(directory_descriptor)
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
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)
    return RetainedTrustedTimePostEnrollmentStartControllerOutcome(
        operation_id=evidence.admission.operation_id,
        approval_sha256=evidence.admission.approval_sha256,
        claim_sha256=evidence.admission.claim_sha256,
        retained_claim_artifact_sha256=(evidence.admission.retained_claim_artifact_sha256),
        active_controller_admission_sha256=evidence.admission.admission_sha256,
        status=evidence.status,
        reason=evidence.reason,
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
        and slot == _slot_bytes(retained.outcome_sha256)
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
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
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
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


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
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
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
            encoded = _commit_bytes(retained.outcome_sha256)
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
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


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
        payload = json.loads(encoded)
        if canonical_first_enrollment_json_bytes(payload) != encoded:
            raise ValueError
        status, reason = _validate_payload_projection(payload)
        outcome_sha256 = hashlib.sha256(encoded).hexdigest()
        if artifact_path.name != _outcome_file_name(outcome_sha256):
            raise ValueError
        operation_id = payload["operation_id"]
        approval_sha256 = payload["approval_sha256"]
        claim_sha256 = payload["claim_sha256"]
        retained_claim_artifact_sha256 = payload["retained_claim_artifact_sha256"]
        admission_sha256 = payload["active_controller_admission_sha256"]
        if any(
            type(value) is not str
            for value in (
                operation_id,
                approval_sha256,
                claim_sha256,
                retained_claim_artifact_sha256,
                admission_sha256,
            )
        ):
            raise ValueError
        return RetainedTrustedTimePostEnrollmentStartControllerOutcome(
            operation_id=operation_id,
            approval_sha256=approval_sha256,
            claim_sha256=claim_sha256,
            retained_claim_artifact_sha256=retained_claim_artifact_sha256,
            active_controller_admission_sha256=admission_sha256,
            status=status,
            reason=reason,
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
    except BaseException:
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome is unavailable"
        ) from None


def revalidate_retained_post_enrollment_start_controller_outcome(
    retained: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> bool:
    if type(retained) is not RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        return False
    directory_descriptor: int | None = None
    try:
        retained.__post_init__()
        if retained.commit_file_identity is None or retained._prepared_marker is not None:
            return False
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        if retained.artifact_path.parent != absolute_directory:
            return False
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        with _locked_outcome_slot(directory_descriptor, exclusive=False) as slot_descriptor:
            directory_identity = _stable_file_identity(os.fstat(directory_descriptor))
            if not _entry_is_absent(
                directory_descriptor,
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
            ) or not _prepared_binding_is_valid(
                retained,
                directory_descriptor=directory_descriptor,
                slot_descriptor=slot_descriptor,
            ):
                return False
            marker, marker_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                expected_outcome_names=frozenset({retained.artifact_path.name}),
            )
            return (
                marker == _commit_bytes(retained.outcome_sha256)
                and marker_identity == retained.commit_file_identity
                and _stable_file_identity(os.fstat(directory_descriptor)) == directory_identity
            )
    except BaseException:
        return False
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


def load_retained_post_enrollment_start_controller_outcome(
    *,
    artifact_directory: Path = DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Load one exact durable controller outcome without granting authority."""

    directory_descriptor: int | None = None
    try:
        absolute_directory = _artifact_directory(
            artifact_directory,
            ignored_root=ignored_root,
        )
        directory_descriptor = _open_owner_only_artifact_directory(
            absolute_directory,
            ignored_root=ignored_root,
            create=False,
        )
        with _locked_outcome_slot(directory_descriptor, exclusive=False) as slot_descriptor:
            directory_identity = _stable_file_identity(os.fstat(directory_descriptor))
            if not _entry_is_absent(
                directory_descriptor,
                _POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME,
            ):
                raise ValueError
            names = _outcome_names(directory_descriptor)
            if len(names) != 1:
                raise ValueError
            file_name = next(iter(names))
            if file_name == POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME:
                raise ValueError
            digest = file_name[
                len(POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX) : -len(
                    POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX
                )
            ]
            if file_name != _outcome_file_name(digest):
                raise ValueError
            encoded, identity = _read_retained_outcome(
                directory_descriptor,
                file_name=file_name,
                expected_outcome_names=names,
            )
            slot, slot_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME,
                expected_outcome_names=names,
            )
            marker, marker_identity = _read_retained_outcome(
                directory_descriptor,
                file_name=_POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME,
                expected_outcome_names=names,
            )
            if (
                slot != _slot_bytes(digest)
                or _stable_file_identity(os.fstat(slot_descriptor)) != slot_identity
                or marker != _commit_bytes(digest)
                or _stable_file_identity(os.fstat(directory_descriptor)) != directory_identity
            ):
                raise ValueError
            return _receipt_from_encoded(
                encoded=encoded,
                artifact_path=absolute_directory / file_name,
                file_identity=identity,
                slot_file_identity=slot_identity,
                commit_file_identity=marker_identity,
            )
    except BaseException:
        raise TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable(
            "trusted-time retained controller outcome is unavailable"
        ) from None
    finally:
        if directory_descriptor is not None:
            with suppress(OSError):
                os.close(directory_descriptor)


__all__ = [
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_ENTRIES",
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_ARTIFACT_NAME_BYTES",
    "MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES",
    "POST_ENROLLMENT_START_LEGACY_OUTCOME_FILE_NAME",
    "POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX",
    "POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX",
    "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION",
    "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_SERVICE",
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
