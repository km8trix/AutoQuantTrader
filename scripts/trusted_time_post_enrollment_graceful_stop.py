"""Pure, non-authorizing post-enrollment graceful-stop projections.

This module binds one exact committed start outcome to its durable shutdown
locator and then binds that inert target to one distinct operator decision.
It performs no I/O, reads no clock, verifies no signature, and exposes no
runtime, shutdown, teardown, retry, operational-control, or trading authority.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Never, SupportsIndex, cast

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    TrustedTimeEnrollmentEvidenceError,
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_controller_outcome import (
    POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION,
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    TrustedTimePostEnrollmentStartControllerOutcomeReason,
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
)
from scripts.trusted_time_post_enrollment_shutdown_locator import (
    _CLOSED_FIELDS as _SHUTDOWN_LOCATOR_CLOSED_FIELDS,
)
from scripts.trusted_time_post_enrollment_shutdown_locator import (
    TrustedTimePostEnrollmentGracefulStopShutdownLocator,
    canonical_post_enrollment_graceful_stop_shutdown_locator_bytes,
    decode_post_enrollment_graceful_stop_shutdown_locator,
    post_enrollment_graceful_stop_shutdown_locator_sha256,
)

POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-target-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-decision-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_SERVICE = "trusted-time-post-enrollment-graceful-stop"
POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS = "graceful_stop_target_unqualified"
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS = "external_attestation_required"
POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN = (
    "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
    "post-enrollment-graceful-stop/operator-attestation/v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_DECISION = "approve_one_post_enrollment_graceful_stop_attempt"
POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES = 96 * 1_024
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES = 128 * 1_024

POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS = frozenset(
    {
        *FIRST_ENROLLMENT_AUTHORITY_FIELDS,
        *_SHUTDOWN_LOCATOR_CLOSED_FIELDS,
        "clean_stop_outcome_retention_authorized",
        "confirmed_start_outcome_authenticated",
        "current_topology_authenticated",
        "decision_authenticated",
        "freshness_authenticated",
        "graceful_stop_authorized",
        "operator_attestation_authenticated",
        "persistent_topology_authenticated",
        "shutdown_locator_authenticated",
        "shutdown_outcome_retention_authorized",
        "single_use_authenticated",
        "start_execution_attempt_authenticated",
        "stop_attempt_reservation_authorized",
        "stop_decision_authenticated",
        "stop_execution_authorized",
        "target_authenticated",
    }
)

POST_ENROLLMENT_GRACEFUL_STOP_TARGET_FIELDS = frozenset(
    {
        *POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
        "contract_version",
        "controller_outcome_contract_version",
        "controller_outcome_reason",
        "controller_outcome_sha256",
        "controller_outcome_status",
        "durable_shutdown_locator",
        "durable_shutdown_locator_sha256",
        "service",
        "start_approval_sha256",
        "start_execution_attempt_slot_sha256",
        "start_operation_id",
        "start_operator_attestation_envelope_sha256",
        "status",
    }
)
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_FIELDS = frozenset(
    {
        *POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
        "contract_version",
        "decision",
        "graceful_stop_target",
        "graceful_stop_target_sha256",
        "operation_id",
        "replay_domain",
        "service",
        "status",
    }
)

_MAXIMUM_JSON_DEPTH = 24
_MAXIMUM_JSON_NODES = 4_096
_MAXIMUM_JSON_INTEGER_BITS = 256
_TARGET_CONSTRUCTION_CAPABILITY = object()
_DECISION_CONSTRUCTION_CAPABILITY = object()


class TrustedTimePostEnrollmentGracefulStopRejected(ValueError):
    """The graceful-stop target or decision is malformed or conflicts."""


class _InvalidGracefulStop(ValueError):
    pass


def _invalid() -> Never:
    raise _InvalidGracefulStop


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


def _closed_payload() -> dict[str, object]:
    return {field_name: False for field_name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS}


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _bounded_json_integer(token: str) -> int:
    if len(token) > 80:
        _invalid()
    value = int(token)
    if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
        _invalid()
    return value


def _require_bounded_json_tree(root: object) -> None:
    remaining = _MAXIMUM_JSON_NODES
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > _MAXIMUM_JSON_DEPTH:
            _invalid()
        if value is None or type(value) is bool:
            continue
        if type(value) is str:
            if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
                _invalid()
            continue
        if type(value) is int:
            if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
                _invalid()
            continue
        if type(value) is list:
            stack.extend((item, depth + 1) for item in reversed(cast(list[object], value)))
            continue
        if type(value) is dict:
            for key, item in reversed(tuple(cast(dict[object, object], value).items())):
                if type(key) is not str:
                    _invalid()
                stack.append((item, depth + 1))
                stack.append((key, depth + 1))
            continue
        _invalid()


def _decode_canonical_object(encoded: object, *, maximum_bytes: int) -> dict[str, object]:
    if type(encoded) is not bytes or not encoded or len(encoded) > maximum_bytes:
        _invalid()
    try:
        payload: Any = json.loads(
            encoded.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _invalid(),
            parse_float=lambda _: _invalid(),
            parse_int=_bounded_json_integer,
        )
        _require_bounded_json_tree(payload)
        canonical = canonical_first_enrollment_json_bytes(payload)
    except (
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        TrustedTimeEnrollmentEvidenceError,
    ):
        _invalid()
    if type(payload) is not dict or canonical != encoded:
        _invalid()
    return cast(dict[str, object], payload)


def _canonical_nested_bytes(value: object) -> bytes:
    try:
        encoded = canonical_first_enrollment_json_bytes(value)
    except TrustedTimeEnrollmentEvidenceError:
        _invalid()
    return encoded


def _require_closed(payload: dict[str, object]) -> None:
    if any(
        payload.get(field_name) is not False
        for field_name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
    ):
        _invalid()


class _ClosedGracefulStopProjection:
    active_controller_authorized = property(lambda _: False)
    alert_delivery_authorized = property(lambda _: False)
    arming_authorized = property(lambda _: False)
    authority_granted = property(lambda _: False)
    automatic_rearm_authorized = property(lambda _: False)
    automatic_resume_authorized = property(lambda _: False)
    broker_action_authorized = property(lambda _: False)
    claim_retention_authorized = property(lambda _: False)
    clean_stop_authorized = property(lambda _: False)
    clean_stop_outcome_retention_authorized = property(lambda _: False)
    confirmed_start_outcome_authenticated = property(lambda _: False)
    container_removal_authorized = property(lambda _: False)
    controller_execution_authorized = property(lambda _: False)
    current_topology_authenticated = property(lambda _: False)
    database_secret_disclosed = property(lambda _: False)
    decision_authenticated = property(lambda _: False)
    execution_admission_authorized = property(lambda _: False)
    execution_attempt_reservation_authorized = property(lambda _: False)
    exposure_authorized = property(lambda _: False)
    freshness_authenticated = property(lambda _: False)
    graceful_stop_authorized = property(lambda _: False)
    live_trading_authorized = property(lambda _: False)
    network_removal_authorized = property(lambda _: False)
    new_exposure_authorized = property(lambda _: False)
    operational_control_authorized = property(lambda _: False)
    operator_attestation_authenticated = property(lambda _: False)
    outcome_retention_authorized = property(lambda _: False)
    paper_trading_authorized = property(lambda _: False)
    persistent_start_authorized = property(lambda _: False)
    persistent_topology_authenticated = property(lambda _: False)
    qualified = property(lambda _: False)
    readiness_authorized = property(lambda _: False)
    rearm_authorized = property(lambda _: False)
    release_authorized = property(lambda _: False)
    retry_authorized = property(lambda _: False)
    runtime_start_authorized = property(lambda _: False)
    sequence_2_authorized = property(lambda _: False)
    shutdown_authorized = property(lambda _: False)
    shutdown_locator_authenticated = property(lambda _: False)
    shutdown_outcome_retention_authorized = property(lambda _: False)
    single_use_authenticated = property(lambda _: False)
    source_start_authorized = property(lambda _: False)
    source_stop_authorized = property(lambda _: False)
    start_execution_attempt_authenticated = property(lambda _: False)
    stop_attempt_reservation_authorized = property(lambda _: False)
    stop_decision_authenticated = property(lambda _: False)
    stop_execution_authorized = property(lambda _: False)
    success_outcome_retention_authorized = property(lambda _: False)
    supervisor_signal_authorized = property(lambda _: False)
    supervisor_start_authorized = property(lambda _: False)
    supervisor_stop_authorized = property(lambda _: False)
    target_authenticated = property(lambda _: False)
    teardown_authorized = property(lambda _: False)
    topology_mutation_authorized = property(lambda _: False)
    volume_removal_authorized = property(lambda _: False)


def _locator_start_bindings(
    locator: TrustedTimePostEnrollmentGracefulStopShutdownLocator,
) -> tuple[str, str]:
    locator.__post_init__()
    topology = locator.persistent_topology
    operation_id = topology.get("operation_id")
    approval_sha256 = topology.get("approval_sha256")
    if not _is_uuid4(operation_id) or not _is_sha256(approval_sha256):
        _invalid()
    return cast(str, operation_id), cast(str, approval_sha256)


def _target_seal_values(value: Any) -> tuple[object, ...]:
    return (
        value.start_operation_id,
        value.start_approval_sha256,
        value.controller_outcome_contract_version,
        value.controller_outcome_status,
        value.controller_outcome_reason,
        value.controller_outcome_sha256,
        value.start_execution_attempt_slot_sha256,
        value.start_operator_attestation_envelope_sha256,
        value.durable_shutdown_locator_sha256,
        value._durable_shutdown_locator_encoded,
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopTarget(_ClosedGracefulStopProjection):
    """Historical exact start target; never current shutdown authority."""

    start_operation_id: str
    start_approval_sha256: str
    controller_outcome_contract_version: str
    controller_outcome_status: str
    controller_outcome_reason: str
    controller_outcome_sha256: str
    start_execution_attempt_slot_sha256: str
    start_operator_attestation_envelope_sha256: str
    durable_shutdown_locator_sha256: str
    _durable_shutdown_locator_encoded: bytes = field(repr=False)
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        start_operation_id: str,
        start_approval_sha256: str,
        controller_outcome_contract_version: str,
        controller_outcome_status: str,
        controller_outcome_reason: str,
        controller_outcome_sha256: str,
        start_execution_attempt_slot_sha256: str,
        start_operator_attestation_envelope_sha256: str,
        durable_shutdown_locator_sha256: str,
        durable_shutdown_locator_encoded: bytes,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _TARGET_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopRejected(
                "trusted-time post-enrollment graceful-stop target is invalid"
            )
        object.__setattr__(self, "start_operation_id", start_operation_id)
        object.__setattr__(self, "start_approval_sha256", start_approval_sha256)
        object.__setattr__(
            self, "controller_outcome_contract_version", controller_outcome_contract_version
        )
        object.__setattr__(self, "controller_outcome_status", controller_outcome_status)
        object.__setattr__(self, "controller_outcome_reason", controller_outcome_reason)
        object.__setattr__(self, "controller_outcome_sha256", controller_outcome_sha256)
        object.__setattr__(
            self, "start_execution_attempt_slot_sha256", start_execution_attempt_slot_sha256
        )
        object.__setattr__(
            self,
            "start_operator_attestation_envelope_sha256",
            start_operator_attestation_envelope_sha256,
        )
        object.__setattr__(self, "durable_shutdown_locator_sha256", durable_shutdown_locator_sha256)
        object.__setattr__(
            self, "_durable_shutdown_locator_encoded", durable_shutdown_locator_encoded
        )
        object.__setattr__(self, "_sealed_fields", _target_seal_values(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if type(self) is not TrustedTimePostEnrollmentGracefulStopTarget:
                _invalid()
            locator = decode_post_enrollment_graceful_stop_shutdown_locator(
                self._durable_shutdown_locator_encoded
            )
            operation_id, approval_sha256 = _locator_start_bindings(locator)
            if (
                not _is_uuid4(self.start_operation_id)
                or self.start_operation_id != operation_id
                or not _is_sha256(self.start_approval_sha256)
                or self.start_approval_sha256 != approval_sha256
                or self.controller_outcome_contract_version
                != POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
                or self.controller_outcome_status
                != TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED.value
                or self.controller_outcome_reason
                != (
                    TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED.value
                )
                or not _is_sha256(self.controller_outcome_sha256)
                or not _is_sha256(self.start_execution_attempt_slot_sha256)
                or not _is_sha256(self.start_operator_attestation_envelope_sha256)
                or not _is_sha256(self.durable_shutdown_locator_sha256)
                or post_enrollment_graceful_stop_shutdown_locator_sha256(locator)
                != self.durable_shutdown_locator_sha256
                or _target_seal_values(self) != self._sealed_fields
            ):
                _invalid()
        except TrustedTimePostEnrollmentGracefulStopRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopRejected(
                "trusted-time post-enrollment graceful-stop target is invalid"
            ) from None

    @property
    def durable_shutdown_locator(
        self,
    ) -> TrustedTimePostEnrollmentGracefulStopShutdownLocator:
        self.__post_init__()
        return decode_post_enrollment_graceful_stop_shutdown_locator(
            self._durable_shutdown_locator_encoded
        )

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _closed_payload()
        payload.update(
            {
                "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION,
                "controller_outcome_contract_version": (self.controller_outcome_contract_version),
                "controller_outcome_reason": self.controller_outcome_reason,
                "controller_outcome_sha256": self.controller_outcome_sha256,
                "controller_outcome_status": self.controller_outcome_status,
                "durable_shutdown_locator": self.durable_shutdown_locator.payload(),
                "durable_shutdown_locator_sha256": self.durable_shutdown_locator_sha256,
                "service": POST_ENROLLMENT_GRACEFUL_STOP_SERVICE,
                "start_approval_sha256": self.start_approval_sha256,
                "start_execution_attempt_slot_sha256": (self.start_execution_attempt_slot_sha256),
                "start_operation_id": self.start_operation_id,
                "start_operator_attestation_envelope_sha256": (
                    self.start_operator_attestation_envelope_sha256
                ),
                "status": POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS,
            }
        )
        return payload

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_target_bytes(self)

    @property
    def target_sha256(self) -> str:
        return post_enrollment_graceful_stop_target_sha256(self)

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target cannot be serialized"
        )


def _new_target(
    *,
    start_operation_id: str,
    start_approval_sha256: str,
    controller_outcome_contract_version: str,
    controller_outcome_status: str,
    controller_outcome_reason: str,
    controller_outcome_sha256: str,
    start_execution_attempt_slot_sha256: str,
    start_operator_attestation_envelope_sha256: str,
    locator: TrustedTimePostEnrollmentGracefulStopShutdownLocator,
) -> TrustedTimePostEnrollmentGracefulStopTarget:
    locator_encoded = canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(locator)
    return TrustedTimePostEnrollmentGracefulStopTarget(
        start_operation_id=start_operation_id,
        start_approval_sha256=start_approval_sha256,
        controller_outcome_contract_version=controller_outcome_contract_version,
        controller_outcome_status=controller_outcome_status,
        controller_outcome_reason=controller_outcome_reason,
        controller_outcome_sha256=controller_outcome_sha256,
        start_execution_attempt_slot_sha256=start_execution_attempt_slot_sha256,
        start_operator_attestation_envelope_sha256=(start_operator_attestation_envelope_sha256),
        durable_shutdown_locator_sha256=(
            post_enrollment_graceful_stop_shutdown_locator_sha256(locator)
        ),
        durable_shutdown_locator_encoded=locator_encoded,
        _construction_capability=_TARGET_CONSTRUCTION_CAPABILITY,
    )


def build_post_enrollment_graceful_stop_target(
    *,
    retained_start_outcome: RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    start_execution_attempt_slot_sha256: str,
    start_operator_attestation_envelope_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopTarget:
    """Bind one structurally revalidated committed v2 start receipt, without I/O."""

    try:
        if (
            type(retained_start_outcome)
            is not RetainedTrustedTimePostEnrollmentStartControllerOutcome
        ):
            _invalid()
        retained_start_outcome.__post_init__()
        locator = retained_start_outcome.durable_shutdown_locator
        if (
            retained_start_outcome.commit_file_identity is None
            or retained_start_outcome._prepared_marker is not None
            or retained_start_outcome.contract_version
            != POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
            or retained_start_outcome.status
            is not TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
            or retained_start_outcome.reason
            is not (
                TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
            )
            or retained_start_outcome.durable_shutdown_locator_available is not True
            or type(locator) is not TrustedTimePostEnrollmentGracefulStopShutdownLocator
            or retained_start_outcome.durable_shutdown_locator_sha256
            != post_enrollment_graceful_stop_shutdown_locator_sha256(locator)
            or not _is_sha256(start_execution_attempt_slot_sha256)
            or not _is_sha256(start_operator_attestation_envelope_sha256)
        ):
            _invalid()
        operation_id, approval_sha256 = _locator_start_bindings(locator)
        topology = locator.persistent_topology
        retained_payload = _decode_canonical_object(
            retained_start_outcome.encoded,
            maximum_bytes=len(retained_start_outcome.encoded),
        )
        if (
            operation_id != retained_start_outcome.operation_id
            or approval_sha256 != retained_start_outcome.approval_sha256
            or topology.get("claim_sha256") != retained_start_outcome.claim_sha256
            or topology.get("retained_claim_artifact_sha256")
            != retained_start_outcome.retained_claim_artifact_sha256
            or topology.get("active_controller_admission_sha256")
            != retained_start_outcome.active_controller_admission_sha256
            or retained_payload.get("persistent_topology_sha256")
            != locator.persistent_topology_sha256
            or retained_payload.get("persistent_topology_transcript_sha256")
            != locator.persistent_topology_transcript_sha256
            or retained_payload.get("durable_shutdown_locator_sha256")
            != retained_start_outcome.durable_shutdown_locator_sha256
        ):
            _invalid()
        result = _new_target(
            start_operation_id=retained_start_outcome.operation_id,
            start_approval_sha256=retained_start_outcome.approval_sha256,
            controller_outcome_contract_version=retained_start_outcome.contract_version,
            controller_outcome_status=retained_start_outcome.status.value,
            controller_outcome_reason=retained_start_outcome.reason.value,
            controller_outcome_sha256=retained_start_outcome.outcome_sha256,
            start_execution_attempt_slot_sha256=start_execution_attempt_slot_sha256,
            start_operator_attestation_envelope_sha256=(start_operator_attestation_envelope_sha256),
            locator=locator,
        )
        canonical_post_enrollment_graceful_stop_target_bytes(result)
        return result
    except TrustedTimePostEnrollmentGracefulStopRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target is invalid"
        ) from None


def canonical_post_enrollment_graceful_stop_target_bytes(target: object) -> bytes:
    """Return exact bounded canonical bytes for one inert target."""

    try:
        if type(target) is not TrustedTimePostEnrollmentGracefulStopTarget:
            _invalid()
        target.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(target.payload())
        if not encoded or len(encoded) > POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES:
            _invalid()
        return encoded
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target is invalid"
        ) from None


def post_enrollment_graceful_stop_target_sha256(target: object) -> str:
    """Return the exact canonical target identity."""

    return hashlib.sha256(canonical_post_enrollment_graceful_stop_target_bytes(target)).hexdigest()


def decode_post_enrollment_graceful_stop_target(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopTarget:
    """Strictly decode one canonical target without authenticating currentness."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES,
        )
        if (
            set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_TARGET_FIELDS
            or payload.get("contract_version")
            != POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION
            or payload.get("service") != POST_ENROLLMENT_GRACEFUL_STOP_SERVICE
            or payload.get("status") != POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS
        ):
            _invalid()
        _require_closed(payload)
        locator_encoded = _canonical_nested_bytes(payload.get("durable_shutdown_locator"))
        locator = decode_post_enrollment_graceful_stop_shutdown_locator(locator_encoded)
        if not _is_sha256(
            payload.get("durable_shutdown_locator_sha256")
        ) or post_enrollment_graceful_stop_shutdown_locator_sha256(locator) != payload.get(
            "durable_shutdown_locator_sha256"
        ):
            _invalid()
        result = _new_target(
            start_operation_id=cast(str, payload.get("start_operation_id")),
            start_approval_sha256=cast(str, payload.get("start_approval_sha256")),
            controller_outcome_contract_version=cast(
                str, payload.get("controller_outcome_contract_version")
            ),
            controller_outcome_status=cast(str, payload.get("controller_outcome_status")),
            controller_outcome_reason=cast(str, payload.get("controller_outcome_reason")),
            controller_outcome_sha256=cast(str, payload.get("controller_outcome_sha256")),
            start_execution_attempt_slot_sha256=cast(
                str, payload.get("start_execution_attempt_slot_sha256")
            ),
            start_operator_attestation_envelope_sha256=cast(
                str, payload.get("start_operator_attestation_envelope_sha256")
            ),
            locator=locator,
        )
        if result.payload() != payload:
            _invalid()
        return result
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop target is invalid"
        ) from None


def _decision_seal_values(value: Any) -> tuple[object, ...]:
    return (value.operation_id, value._target_encoded)


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopDecision(_ClosedGracefulStopProjection):
    """One externally attestable stop decision; never execution authority."""

    operation_id: str
    _target_encoded: bytes = field(repr=False)
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        operation_id: str,
        target_encoded: bytes,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _DECISION_CONSTRUCTION_CAPABILITY:
            raise TrustedTimePostEnrollmentGracefulStopRejected(
                "trusted-time post-enrollment graceful-stop decision is invalid"
            )
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "_target_encoded", target_encoded)
        object.__setattr__(self, "_sealed_fields", _decision_seal_values(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if type(self) is not TrustedTimePostEnrollmentGracefulStopDecision:
                _invalid()
            target = decode_post_enrollment_graceful_stop_target(self._target_encoded)
            if (
                not _is_uuid4(self.operation_id)
                or self.operation_id == target.start_operation_id
                or _decision_seal_values(self) != self._sealed_fields
            ):
                _invalid()
        except TrustedTimePostEnrollmentGracefulStopRejected:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopRejected(
                "trusted-time post-enrollment graceful-stop decision is invalid"
            ) from None

    @property
    def target(self) -> TrustedTimePostEnrollmentGracefulStopTarget:
        self.__post_init__()
        return decode_post_enrollment_graceful_stop_target(self._target_encoded)

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        target = self.target
        payload = _closed_payload()
        payload.update(
            {
                "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION,
                "decision": POST_ENROLLMENT_GRACEFUL_STOP_DECISION,
                "graceful_stop_target": target.payload(),
                "graceful_stop_target_sha256": target.target_sha256,
                "operation_id": self.operation_id,
                "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN,
                "service": POST_ENROLLMENT_GRACEFUL_STOP_SERVICE,
                "status": POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS,
            }
        )
        return payload

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_decision_bytes(self)

    @property
    def decision_sha256(self) -> str:
        return post_enrollment_graceful_stop_decision_sha256(self)

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision cannot be serialized"
        )


def _new_decision(
    *,
    operation_id: str,
    target: TrustedTimePostEnrollmentGracefulStopTarget,
) -> TrustedTimePostEnrollmentGracefulStopDecision:
    return TrustedTimePostEnrollmentGracefulStopDecision(
        operation_id=operation_id,
        target_encoded=canonical_post_enrollment_graceful_stop_target_bytes(target),
        _construction_capability=_DECISION_CONSTRUCTION_CAPABILITY,
    )


def build_post_enrollment_graceful_stop_decision(
    *,
    operation_id: str,
    target: TrustedTimePostEnrollmentGracefulStopTarget,
) -> TrustedTimePostEnrollmentGracefulStopDecision:
    """Bind one distinct stop UUID to one exact inert target."""

    try:
        if type(target) is not TrustedTimePostEnrollmentGracefulStopTarget:
            _invalid()
        target.__post_init__()
        result = _new_decision(operation_id=operation_id, target=target)
        canonical_post_enrollment_graceful_stop_decision_bytes(result)
        return result
    except TrustedTimePostEnrollmentGracefulStopRejected:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision is invalid"
        ) from None


def canonical_post_enrollment_graceful_stop_decision_bytes(decision: object) -> bytes:
    """Return exact bounded canonical bytes for one inert decision."""

    try:
        if type(decision) is not TrustedTimePostEnrollmentGracefulStopDecision:
            _invalid()
        decision.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(decision.payload())
        if not encoded or len(encoded) > POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES:
            _invalid()
        return encoded
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision is invalid"
        ) from None


def post_enrollment_graceful_stop_decision_sha256(decision: object) -> str:
    """Return the exact canonical decision identity."""

    return hashlib.sha256(
        canonical_post_enrollment_graceful_stop_decision_bytes(decision)
    ).hexdigest()


def decode_post_enrollment_graceful_stop_decision(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopDecision:
    """Strictly decode one canonical external-attestation decision projection."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES,
        )
        if (
            set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_FIELDS
            or payload.get("contract_version")
            != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION
            or payload.get("decision") != POST_ENROLLMENT_GRACEFUL_STOP_DECISION
            or payload.get("replay_domain") != POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN
            or payload.get("service") != POST_ENROLLMENT_GRACEFUL_STOP_SERVICE
            or payload.get("status") != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS
        ):
            _invalid()
        _require_closed(payload)
        target_encoded = _canonical_nested_bytes(payload.get("graceful_stop_target"))
        target = decode_post_enrollment_graceful_stop_target(target_encoded)
        if not _is_sha256(
            payload.get("graceful_stop_target_sha256")
        ) or target.target_sha256 != payload.get("graceful_stop_target_sha256"):
            _invalid()
        result = _new_decision(
            operation_id=cast(str, payload.get("operation_id")),
            target=target,
        )
        if result.payload() != payload:
            _invalid()
        return result
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopRejected(
            "trusted-time post-enrollment graceful-stop decision is invalid"
        ) from None


__all__ = [
    "POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS",
    "POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN",
    "POST_ENROLLMENT_GRACEFUL_STOP_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS",
    "TrustedTimePostEnrollmentGracefulStopDecision",
    "TrustedTimePostEnrollmentGracefulStopRejected",
    "TrustedTimePostEnrollmentGracefulStopTarget",
    "build_post_enrollment_graceful_stop_decision",
    "build_post_enrollment_graceful_stop_target",
    "canonical_post_enrollment_graceful_stop_decision_bytes",
    "canonical_post_enrollment_graceful_stop_target_bytes",
    "decode_post_enrollment_graceful_stop_decision",
    "decode_post_enrollment_graceful_stop_target",
    "post_enrollment_graceful_stop_decision_sha256",
    "post_enrollment_graceful_stop_target_sha256",
]
