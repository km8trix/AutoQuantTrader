"""Canonical, non-authorizing correlation for one operation-bound clean stop.

The wire records in this module are deliberately inert.  A request can be
associated with one exact worker core before that core creates its
``CLEAN_STOP`` work request.  Only the exact resulting work request and the
already worker-consumed ADR-0108 terminal result can issue the corresponding
result.  No class here sends a signal, performs I/O, authenticates transport or
currentness, or grants shutdown authority.
"""

from __future__ import annotations

import builtins as _BUILTINS
import hashlib
import json
import os
import threading
import uuid
import weakref
from builtins import property as _EVIDENCE_PROPERTY
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Never, SupportsIndex, cast

TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_CONTRACT_VERSION = (
    "phase6d-trusted-time-head-anchor-clean-stop-supervisor-bridge-request-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_CONTRACT_VERSION = (
    "phase6d-trusted-time-head-anchor-clean-stop-supervisor-bridge-result-v1"
)
TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_SERVICE = (
    "trusted-time-head-anchor-clean-stop-supervisor-bridge"
)
TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_STATUS = (
    "operation_bound_clean_stop_requested_unqualified"
)
TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_STATUS = (
    "exact_operation_bound_new_record_clean_stop_correlated_unqualified"
)
TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_PROGRESS_PHASE = (
    "operation_bound_supervisor_bridge_required"
)
MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_BYTES = 64 * 1_024
MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_BYTES = 128 * 1_024

_MAXIMUM_JSON_DEPTH = 16
_MAXIMUM_JSON_NODES = 1_024
_MAXIMUM_JSON_INTEGER_BITS = 63
_MAXIMUM_INTEGER = (1 << 63) - 1
_RESULT_CONSTRUCTION_CAPABILITY = object()
_ORIGIN_PID = os.getpid()

_CLOSED_FIELDS = frozenset(
    {
        "active_controller_authorized",
        "admission_authorized",
        "alert_delivery_authorized",
        "arming_authorized",
        "authority_granted",
        "automatic_rearm_authorized",
        "automatic_recovery_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "claim_retention_authorized",
        "clean_stop_authorized",
        "clean_stop_outcome_retention_authorized",
        "confirmed_start_outcome_authenticated",
        "container_removal_authorized",
        "controller_execution_authorized",
        "current_topology_authenticated",
        "currentness_authenticated",
        "decision_authenticated",
        "durability_authenticated",
        "durable_stop_outcome_authenticated",
        "effect_authorized",
        "execution_admission_authorized",
        "execution_attempt_reservation_authorized",
        "exposure_authorized",
        "freshness_authenticated",
        "graceful_stop_authorized",
        "live_trading_authorized",
        "network_removal_authorized",
        "new_exposure_authorized",
        "no_new_record_authenticated",
        "no_new_record_success",
        "operation_bound_supervisor_bridge_authenticated",
        "operational_control_authorized",
        "operator_attestation_authenticated",
        "outcome_retention_authorized",
        "paper_trading_authorized",
        "persistent_start_authorized",
        "persistent_topology_authenticated",
        "provider_terminal_authenticated",
        "provider_terminal_currentness_authenticated",
        "provider_terminal_observed_under_stable_sql_authenticated",
        "readiness_authorized",
        "rearm_authorized",
        "recovery_action_authorized",
        "release_authorized",
        "retry_authorized",
        "runtime_start_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "shutdown_locator_authenticated",
        "shutdown_outcome_retention_authorized",
        "signal_attempted",
        "signal_authorized",
        "single_use_authenticated",
        "slot_authorized",
        "source_start_authorized",
        "source_stop_authorized",
        "start_execution_attempt_authenticated",
        "stop_admission_qualified",
        "stop_attempt_reservation_authorized",
        "stop_attempt_slot_reserved",
        "stop_decision_authenticated",
        "stop_execution_authorized",
        "stop_outcome_retained",
        "success_outcome_retention_authorized",
        "supervisor_signal_authorized",
        "supervisor_start_authorized",
        "supervisor_stop_authorized",
        "target_authenticated",
        "teardown_authenticated",
        "teardown_authorized",
        "terminal_outcome_success_confirmed",
        "topology_mutation_authorized",
        "transport_authenticated",
        "volume_removal_authorized",
        "watchdog_authorized",
    }
)

_REQUEST_BINDING_FIELDS = (
    "graceful_stop_operation_id",
    "graceful_stop_target_sha256",
    "graceful_stop_decision_v1_sha256",
    "graceful_stop_decision_artifact_receipt_sha256",
    "operator_attestation_envelope_sha256",
    "attempt_slot_sha256",
    "bridge_required_progress_sha256",
    "controller_outcome_sha256",
    "durable_shutdown_locator_sha256",
    "active_controller_session_sha256",
    "persistent_topology_sha256",
    "persistent_topology_transcript_sha256",
    "supervisor_container_id",
)

_REQUEST_FIELDS = frozenset(
    {
        *_CLOSED_FIELDS,
        *_REQUEST_BINDING_FIELDS,
        "checkpoint_reason",
        "contract_version",
        "exact_new_record_required",
        "progress_ordinal",
        "progress_phase",
        "service",
        "status",
    }
)

_TERMINAL_FIELDS = (
    "request_sequence",
    "request_scheduled_monotonic_ns",
    "anchor_sequence",
    "checkpoint_reason",
    "confirmed_anchor_count",
    "local_transition_count",
    "confirmed_anchor_local_transition_ordinal",
    "predecessor_anchor_sha256",
    "current_host_head_sha256",
    "current_anchor_sha256",
    "current_anchor_semantic_sha256",
    "receipt_observed_at_utc",
    "full_audit_completed",
    "prior_pending_intent_recovered",
    "uploaded_anchor_count",
    "idempotent_duplicate_count",
    "current_anchor_intent_semantic_sha256",
    "current_candidate_remote_readback_sha256",
    "current_receipt_semantic_sha256",
    "clean_stop_terminal_result_semantic_sha256",
)

_RESULT_FIELDS = frozenset(
    {
        *_CLOSED_FIELDS,
        *_TERMINAL_FIELDS,
        "contract_version",
        "exact_request_work_result_correlated",
        "operation_bound_request",
        "operation_bound_request_sha256",
        "service",
        "status",
    }
)


class TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(RuntimeError):
    """The operation-bound clean-stop correlation is invalid or unavailable."""


class _InvalidBridge(ValueError):
    pass


def _invalid() -> Never:
    raise _InvalidBridge


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
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.version == 4 and str(parsed) == value


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc_text(value: object) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        _invalid()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _invalid()
    if (
        type(parsed) is not datetime
        or parsed.tzinfo is None
        or parsed.utcoffset() != UTC.utcoffset(parsed)
        or _utc_text(parsed) != value
    ):
        _invalid()
    return parsed


def _closed_payload() -> dict[str, object]:
    return {field_name: False for field_name in _CLOSED_FIELDS}


def _require_closed(payload: dict[str, object]) -> None:
    if any(payload.get(field_name) is not False for field_name in _CLOSED_FIELDS):
        _invalid()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _bounded_json_integer(token: str) -> int:
    if len(token) > 20:
        _invalid()
    value = int(token)
    if value.bit_length() > _MAXIMUM_JSON_INTEGER_BITS:
        _invalid()
    return value


def _reject_float(_: str) -> Never:
    _invalid()


def _require_bounded_json_tree(root: object) -> None:
    remaining = _MAXIMUM_JSON_NODES
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        value, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > _MAXIMUM_JSON_DEPTH:
            _invalid()
        if value is None or type(value) in {bool, int}:
            continue
        if type(value) is str:
            if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
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
            parse_float=_reject_float,
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


def _cannot_copy() -> Never:
    raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
        "trusted-time clean-stop supervisor bridge evidence cannot be copied or serialized"
    )


class _ClosedBridgeEvidence:
    active_controller_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    admission_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    alert_delivery_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    arming_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    authority_granted = _EVIDENCE_PROPERTY(lambda _: False)
    automatic_rearm_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    automatic_recovery_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    automatic_resume_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    broker_action_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    claim_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    clean_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    clean_stop_outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    confirmed_start_outcome_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    container_removal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    controller_execution_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    current_topology_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    currentness_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    decision_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    durability_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    durable_stop_outcome_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    effect_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    execution_admission_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    execution_attempt_reservation_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    exposure_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    freshness_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    graceful_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    live_trading_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    network_removal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    new_exposure_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    no_new_record_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    no_new_record_success = _EVIDENCE_PROPERTY(lambda _: False)
    operation_bound_supervisor_bridge_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    operational_control_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    operator_attestation_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    paper_trading_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    persistent_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    persistent_topology_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    provider_terminal_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    provider_terminal_currentness_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    provider_terminal_observed_under_stable_sql_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    readiness_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    rearm_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    recovery_action_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    release_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    retry_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    runtime_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    sequence_2_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    shutdown_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    shutdown_locator_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    shutdown_outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    signal_attempted = _EVIDENCE_PROPERTY(lambda _: False)
    signal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    single_use_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    slot_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    source_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    source_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    start_execution_attempt_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    stop_admission_qualified = _EVIDENCE_PROPERTY(lambda _: False)
    stop_attempt_reservation_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    stop_attempt_slot_reserved = _EVIDENCE_PROPERTY(lambda _: False)
    stop_decision_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    stop_execution_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    stop_outcome_retained = _EVIDENCE_PROPERTY(lambda _: False)
    success_outcome_retention_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    supervisor_signal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    supervisor_start_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    supervisor_stop_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    target_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    teardown_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    teardown_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    terminal_outcome_success_confirmed = _EVIDENCE_PROPERTY(lambda _: False)
    topology_mutation_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    transport_authenticated = _EVIDENCE_PROPERTY(lambda _: False)
    volume_removal_authorized = _EVIDENCE_PROPERTY(lambda _: False)
    watchdog_authorized = _EVIDENCE_PROPERTY(lambda _: False)


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False, eq=False)
class TrustedTimeHeadAnchorOperationBoundCleanStopRequest(_ClosedBridgeEvidence):
    """Canonical unqualified request binding for one future supervisor call."""

    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_decision_artifact_receipt_sha256: str
    operator_attestation_envelope_sha256: str
    attempt_slot_sha256: str
    bridge_required_progress_sha256: str
    controller_outcome_sha256: str
    durable_shutdown_locator_sha256: str
    active_controller_session_sha256: str
    persistent_topology_sha256: str
    persistent_topology_transcript_sha256: str
    supervisor_container_id: str
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        graceful_stop_decision_artifact_receipt_sha256: str,
        operator_attestation_envelope_sha256: str,
        attempt_slot_sha256: str,
        bridge_required_progress_sha256: str,
        controller_outcome_sha256: str,
        durable_shutdown_locator_sha256: str,
        active_controller_session_sha256: str,
        persistent_topology_sha256: str,
        persistent_topology_transcript_sha256: str,
        supervisor_container_id: str,
    ) -> None:
        values = (
            graceful_stop_operation_id,
            graceful_stop_target_sha256,
            graceful_stop_decision_v1_sha256,
            graceful_stop_decision_artifact_receipt_sha256,
            operator_attestation_envelope_sha256,
            attempt_slot_sha256,
            bridge_required_progress_sha256,
            controller_outcome_sha256,
            durable_shutdown_locator_sha256,
            active_controller_session_sha256,
            persistent_topology_sha256,
            persistent_topology_transcript_sha256,
            supervisor_container_id,
        )
        for name, value in zip(_REQUEST_BINDING_FIELDS, values, strict=True):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_sealed_fields", values)
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            values = tuple(getattr(self, name) for name in _REQUEST_BINDING_FIELDS)
            if (
                type(self) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
                or not _is_uuid4(self.graceful_stop_operation_id)
                or not all(_is_sha256(value) for value in values[1:])
                or values != self._sealed_fields
            ):
                raise ValueError
        except TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop request is invalid"
            ) from None

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _closed_payload()
        payload.update({name: getattr(self, name) for name in _REQUEST_BINDING_FIELDS})
        payload.update(
            {
                "checkpoint_reason": TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP.value,
                "contract_version": (
                    TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_CONTRACT_VERSION
                ),
                "exact_new_record_required": True,
                "progress_ordinal": 1,
                "progress_phase": (
                    TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_PROGRESS_PHASE
                ),
                "service": TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_SERVICE,
                "status": TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_STATUS,
            }
        )
        return payload

    @_EVIDENCE_PROPERTY
    def encoded(self) -> bytes:
        return canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes(self)

    @_EVIDENCE_PROPERTY
    def request_sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __replace__(self, **_: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        _cannot_copy()


def canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes(
    request: object,
) -> bytes:
    """Return strict canonical bytes for one unqualified bridge request."""

    try:
        if type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
            _invalid()
        request.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(request.payload())
        if (
            not encoded
            or len(encoded)
            > MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_BYTES
        ):
            _invalid()
        return encoded
    except TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop request is invalid"
        ) from None


def decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
    encoded: object,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    """Strictly decode structural request evidence without authenticating it."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=(
                MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_BYTES
            ),
        )
        if (
            set(payload) != _REQUEST_FIELDS
            or payload.get("contract_version")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_CONTRACT_VERSION
            or payload.get("service")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_SERVICE
            or payload.get("status")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_STATUS
            or payload.get("checkpoint_reason")
            != TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP.value
            or payload.get("exact_new_record_required") is not True
            or type(payload.get("progress_ordinal")) is not int
            or payload.get("progress_ordinal") != 1
            or payload.get("progress_phase")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_PROGRESS_PHASE
        ):
            _invalid()
        _require_closed(payload)
        request = TrustedTimeHeadAnchorOperationBoundCleanStopRequest(
            **{name: cast(str, payload[name]) for name in _REQUEST_BINDING_FIELDS}
        )
        if request.payload() != payload or request.encoded != encoded:
            _invalid()
        return request
    except TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop request is invalid"
        ) from None


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TrustedTimeHeadAnchorOperationBoundCleanStopResult(_ClosedBridgeEvidence):
    """Canonical correlation of one exact worker request and ADR-0108 result."""

    request_sequence: int
    request_scheduled_monotonic_ns: int
    anchor_sequence: int
    checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason
    confirmed_anchor_count: int
    local_transition_count: int
    confirmed_anchor_local_transition_ordinal: int
    predecessor_anchor_sha256: str
    current_host_head_sha256: str
    current_anchor_sha256: str
    current_anchor_semantic_sha256: str
    receipt_observed_at_utc: datetime
    full_audit_completed: bool
    prior_pending_intent_recovered: bool
    uploaded_anchor_count: int
    idempotent_duplicate_count: int
    current_anchor_intent_semantic_sha256: str
    current_candidate_remote_readback_sha256: str
    current_receipt_semantic_sha256: str
    clean_stop_terminal_result_semantic_sha256: str
    _request_encoded: bytes = field(repr=False, compare=False)
    _sealed_fields: tuple[object, ...] = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        request_encoded: bytes,
        request_sequence: int,
        request_scheduled_monotonic_ns: int,
        anchor_sequence: int,
        checkpoint_reason: TrustedTimeHeadAnchorCheckpointReason,
        confirmed_anchor_count: int,
        local_transition_count: int,
        confirmed_anchor_local_transition_ordinal: int,
        predecessor_anchor_sha256: str,
        current_host_head_sha256: str,
        current_anchor_sha256: str,
        current_anchor_semantic_sha256: str,
        receipt_observed_at_utc: datetime,
        full_audit_completed: bool,
        prior_pending_intent_recovered: bool,
        uploaded_anchor_count: int,
        idempotent_duplicate_count: int,
        current_anchor_intent_semantic_sha256: str,
        current_candidate_remote_readback_sha256: str,
        current_receipt_semantic_sha256: str,
        clean_stop_terminal_result_semantic_sha256: str,
        _construction_capability: object,
    ) -> None:
        if _construction_capability is not _RESULT_CONSTRUCTION_CAPABILITY:
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop result must be decoded or issued"
            )
        values = (
            request_sequence,
            request_scheduled_monotonic_ns,
            anchor_sequence,
            checkpoint_reason,
            confirmed_anchor_count,
            local_transition_count,
            confirmed_anchor_local_transition_ordinal,
            predecessor_anchor_sha256,
            current_host_head_sha256,
            current_anchor_sha256,
            current_anchor_semantic_sha256,
            receipt_observed_at_utc,
            full_audit_completed,
            prior_pending_intent_recovered,
            uploaded_anchor_count,
            idempotent_duplicate_count,
            current_anchor_intent_semantic_sha256,
            current_candidate_remote_readback_sha256,
            current_receipt_semantic_sha256,
            clean_stop_terminal_result_semantic_sha256,
        )
        for name, value in zip(_TERMINAL_FIELDS, values, strict=True):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_request_encoded", request_encoded)
        object.__setattr__(self, "_sealed_fields", (request_encoded, *values))
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if type(self) is not TrustedTimeHeadAnchorOperationBoundCleanStopResult:
                raise ValueError
            request = decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
                self._request_encoded
            )
            integer_values = (
                self.request_sequence,
                self.anchor_sequence,
                self.confirmed_anchor_count,
                self.local_transition_count,
                self.confirmed_anchor_local_transition_ordinal,
            )
            digest_values = (
                self.predecessor_anchor_sha256,
                self.current_host_head_sha256,
                self.current_anchor_sha256,
                self.current_anchor_semantic_sha256,
                self.current_anchor_intent_semantic_sha256,
                self.current_candidate_remote_readback_sha256,
                self.current_receipt_semantic_sha256,
                self.clean_stop_terminal_result_semantic_sha256,
            )
            values = tuple(getattr(self, name) for name in _TERMINAL_FIELDS)
            terminal_semantic_sha256 = _result_semantic_sha256(values[:-1])
            if (
                any(
                    type(value) is not int or not 0 < value <= _MAXIMUM_INTEGER
                    for value in integer_values
                )
                or type(self.request_scheduled_monotonic_ns) is not int
                or not 0 <= self.request_scheduled_monotonic_ns <= _MAXIMUM_INTEGER
                or self.checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
                or self.anchor_sequence < 3
                or self.confirmed_anchor_count != self.anchor_sequence
                or self.confirmed_anchor_local_transition_ordinal != self.local_transition_count
                or self.local_transition_count < self.anchor_sequence
                or not all(_is_sha256(value) for value in digest_values)
                or self.clean_stop_terminal_result_semantic_sha256 != terminal_semantic_sha256
                or self.current_candidate_remote_readback_sha256 != self.current_anchor_sha256
                or type(self.receipt_observed_at_utc) is not datetime
                or self.receipt_observed_at_utc.tzinfo is None
                or self.receipt_observed_at_utc.utcoffset()
                != UTC.utcoffset(self.receipt_observed_at_utc)
                or type(self.full_audit_completed) is not bool
                or type(self.prior_pending_intent_recovered) is not bool
                or type(self.uploaded_anchor_count) is not int
                or self.uploaded_anchor_count not in (0, 1)
                or type(self.idempotent_duplicate_count) is not int
                or self.idempotent_duplicate_count not in (0, 1)
                or self.uploaded_anchor_count + self.idempotent_duplicate_count != 1
                or (self._request_encoded, *values) != self._sealed_fields
                or request.encoded != self._request_encoded
            ):
                raise ValueError
        except TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
            raise
        except Exception:
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop result is invalid"
            ) from None

    @_EVIDENCE_PROPERTY
    def request(self) -> TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
        self.__post_init__()
        return decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
            self._request_encoded
        )

    @_EVIDENCE_PROPERTY
    def request_sha256(self) -> str:
        self.__post_init__()
        return hashlib.sha256(self._request_encoded).hexdigest()

    @_EVIDENCE_PROPERTY
    def encoded(self) -> bytes:
        return canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes(self)

    @_EVIDENCE_PROPERTY
    def result_sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()

    @_EVIDENCE_PROPERTY
    def exact_request_work_result_correlated(self) -> bool:
        self.__post_init__()
        return True

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload = _closed_payload()
        payload.update(
            {
                "anchor_sequence": self.anchor_sequence,
                "checkpoint_reason": self.checkpoint_reason.value,
                "clean_stop_terminal_result_semantic_sha256": (
                    self.clean_stop_terminal_result_semantic_sha256
                ),
                "confirmed_anchor_count": self.confirmed_anchor_count,
                "confirmed_anchor_local_transition_ordinal": (
                    self.confirmed_anchor_local_transition_ordinal
                ),
                "contract_version": (
                    TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_CONTRACT_VERSION
                ),
                "current_anchor_intent_semantic_sha256": (
                    self.current_anchor_intent_semantic_sha256
                ),
                "current_anchor_semantic_sha256": self.current_anchor_semantic_sha256,
                "current_anchor_sha256": self.current_anchor_sha256,
                "current_candidate_remote_readback_sha256": (
                    self.current_candidate_remote_readback_sha256
                ),
                "current_host_head_sha256": self.current_host_head_sha256,
                "current_receipt_semantic_sha256": self.current_receipt_semantic_sha256,
                "exact_request_work_result_correlated": True,
                "full_audit_completed": self.full_audit_completed,
                "idempotent_duplicate_count": self.idempotent_duplicate_count,
                "local_transition_count": self.local_transition_count,
                "operation_bound_request": self.request.payload(),
                "operation_bound_request_sha256": self.request_sha256,
                "predecessor_anchor_sha256": self.predecessor_anchor_sha256,
                "prior_pending_intent_recovered": self.prior_pending_intent_recovered,
                "receipt_observed_at_utc": _utc_text(self.receipt_observed_at_utc),
                "request_scheduled_monotonic_ns": self.request_scheduled_monotonic_ns,
                "request_sequence": self.request_sequence,
                "service": TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_SERVICE,
                "status": TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_STATUS,
                "uploaded_anchor_count": self.uploaded_anchor_count,
            }
        )
        return payload

    def __copy__(self) -> Never:
        _cannot_copy()

    def __deepcopy__(self, _: object) -> Never:
        _cannot_copy()

    def __replace__(self, **_: object) -> Never:
        _cannot_copy()

    def __reduce__(self) -> Never:
        _cannot_copy()

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        _cannot_copy()


from packages.application.trusted_time_head_anchor import (  # noqa: E402
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_clean_stop import (  # noqa: E402
    TrustedTimeHeadAnchorCleanStopTerminalResult,
    _consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge,
    _result_semantic_sha256,
)
from packages.domain.trusted_time_enrollment_evidence import (  # noqa: E402
    TrustedTimeEnrollmentEvidenceError,
    canonical_first_enrollment_json_bytes,
)

if _BUILTINS.property is not _EVIDENCE_PROPERTY:
    raise RuntimeError("builtins.property changed during bridge dependency imports")


def _new_result(
    *,
    request_encoded: bytes,
    fields: dict[str, object],
) -> TrustedTimeHeadAnchorOperationBoundCleanStopResult:
    return TrustedTimeHeadAnchorOperationBoundCleanStopResult(
        request_encoded=request_encoded,
        request_sequence=cast(int, fields["request_sequence"]),
        request_scheduled_monotonic_ns=cast(int, fields["request_scheduled_monotonic_ns"]),
        anchor_sequence=cast(int, fields["anchor_sequence"]),
        checkpoint_reason=cast(
            TrustedTimeHeadAnchorCheckpointReason,
            fields["checkpoint_reason"],
        ),
        confirmed_anchor_count=cast(int, fields["confirmed_anchor_count"]),
        local_transition_count=cast(int, fields["local_transition_count"]),
        confirmed_anchor_local_transition_ordinal=cast(
            int,
            fields["confirmed_anchor_local_transition_ordinal"],
        ),
        predecessor_anchor_sha256=cast(str, fields["predecessor_anchor_sha256"]),
        current_host_head_sha256=cast(str, fields["current_host_head_sha256"]),
        current_anchor_sha256=cast(str, fields["current_anchor_sha256"]),
        current_anchor_semantic_sha256=cast(str, fields["current_anchor_semantic_sha256"]),
        receipt_observed_at_utc=cast(datetime, fields["receipt_observed_at_utc"]),
        full_audit_completed=cast(bool, fields["full_audit_completed"]),
        prior_pending_intent_recovered=cast(bool, fields["prior_pending_intent_recovered"]),
        uploaded_anchor_count=cast(int, fields["uploaded_anchor_count"]),
        idempotent_duplicate_count=cast(int, fields["idempotent_duplicate_count"]),
        current_anchor_intent_semantic_sha256=cast(
            str,
            fields["current_anchor_intent_semantic_sha256"],
        ),
        current_candidate_remote_readback_sha256=cast(
            str,
            fields["current_candidate_remote_readback_sha256"],
        ),
        current_receipt_semantic_sha256=cast(
            str,
            fields["current_receipt_semantic_sha256"],
        ),
        clean_stop_terminal_result_semantic_sha256=cast(
            str,
            fields["clean_stop_terminal_result_semantic_sha256"],
        ),
        _construction_capability=_RESULT_CONSTRUCTION_CAPABILITY,
    )


def canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes(
    result: object,
) -> bytes:
    """Return strict canonical bytes for one unqualified correlated result."""

    try:
        if type(result) is not TrustedTimeHeadAnchorOperationBoundCleanStopResult:
            _invalid()
        result.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(result.payload())
        if (
            not encoded
            or len(encoded)
            > MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_BYTES
        ):
            _invalid()
        return encoded
    except TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop result is invalid"
        ) from None


def decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
    encoded: object,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopResult:
    """Strictly decode structural result evidence without authenticating transport."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=(
                MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_BYTES
            ),
        )
        if (
            set(payload) != _RESULT_FIELDS
            or payload.get("contract_version")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_CONTRACT_VERSION
            or payload.get("service")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_SERVICE
            or payload.get("status")
            != TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_STATUS
            or payload.get("exact_request_work_result_correlated") is not True
            or payload.get("checkpoint_reason")
            != TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP.value
        ):
            _invalid()
        _require_closed(payload)
        request_encoded = canonical_first_enrollment_json_bytes(payload["operation_bound_request"])
        request = decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
            request_encoded
        )
        if not _is_sha256(
            payload.get("operation_bound_request_sha256")
        ) or request.request_sha256 != payload.get("operation_bound_request_sha256"):
            _invalid()
        fields = {name: payload[name] for name in _TERMINAL_FIELDS}
        fields["checkpoint_reason"] = TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
        fields["receipt_observed_at_utc"] = _parse_utc_text(payload["receipt_observed_at_utc"])
        result = _new_result(request_encoded=request_encoded, fields=fields)
        if result.payload() != payload or result.encoded != encoded:
            _invalid()
        return result
    except TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop result is invalid"
        ) from None


@dataclass(slots=True)
class _RequestRegistration:
    request_reference: weakref.ReferenceType[TrustedTimeHeadAnchorOperationBoundCleanStopRequest]
    request_sha256: str
    core_identity: object
    control_thread_identity: threading.Thread
    worker_thread_identity: threading.Thread | None = None
    work_request_identity: object | None = None
    work_request_values: tuple[object, ...] | None = None
    result_identity: TrustedTimeHeadAnchorOperationBoundCleanStopResult | None = None
    result_values: tuple[object, ...] | None = None
    result_encoded: bytes | None = None
    result_sha256: str | None = None
    status: str = "registered"


_REGISTRY_LOCK = threading.Lock()
_REQUEST_REGISTRY: dict[int, _RequestRegistration] = {}
_SEEN_REQUEST_SHA256S: set[str] = set()


def _locate_registration_unvalidated(
    request: object,
) -> tuple[int, _RequestRegistration]:
    if (
        os.getpid() != _ORIGIN_PID
        or type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
    ):
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop request association is unavailable"
        )
    request_id = id(request)
    registration = _REQUEST_REGISTRY.get(request_id)
    if registration is None or registration.request_reference() is not request:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop request association is unavailable"
        )
    return request_id, registration


def _register_trusted_time_head_anchor_operation_bound_clean_stop_request(
    request: object,
    *,
    core_identity: object,
) -> None:
    """Associate one exact request object with one exact core before scheduling."""

    from packages.application.trusted_time_head_anchor_worker import (
        TrustedTimeHeadAnchorWorkerCore,
    )

    if (
        os.getpid() != _ORIGIN_PID
        or type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
    ):
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop request association is unavailable"
        )
    request.__post_init__()
    request_id = id(request)
    request_sha256 = request.request_sha256
    control_thread_identity = threading.current_thread()

    def request_lost(
        reference: weakref.ReferenceType[TrustedTimeHeadAnchorOperationBoundCleanStopRequest],
    ) -> None:
        if os.getpid() != _ORIGIN_PID:
            return
        with _REGISTRY_LOCK:
            current = _REQUEST_REGISTRY.get(request_id)
            if current is not None and current.request_reference is reference:
                _REQUEST_REGISTRY.pop(request_id, None)

    request_reference = weakref.ref(request, request_lost)
    with _REGISTRY_LOCK:
        if request_id in _REQUEST_REGISTRY or request_sha256 in _SEEN_REQUEST_SHA256S:
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop request was replayed"
            )
        _SEEN_REQUEST_SHA256S.add(request_sha256)
        if (
            type(core_identity) is not TrustedTimeHeadAnchorWorkerCore
            or core_identity._fatal
            or core_identity._stopped
            or core_identity._clean_stop_requested
            or core_identity._operation_bound_clean_stop_request is not request
            or core_identity._operation_bound_clean_stop_work_request is not None
            or core_identity._operation_bound_clean_stop_terminal_result is not None
            or (
                core_identity._in_flight is not None
                and core_identity._in_flight.checkpoint_reason
                is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
            )
        ):
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop request association is unavailable"
            )
        _REQUEST_REGISTRY[request_id] = _RequestRegistration(
            request_reference=request_reference,
            request_sha256=request_sha256,
            core_identity=core_identity,
            control_thread_identity=control_thread_identity,
        )


def _bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
    request: object,
    *,
    core_identity: object,
    work_request_identity: object,
    work_request_values: tuple[object, ...],
) -> None:
    """Bind the bridge request to the exact newly selected CLEAN_STOP work object."""

    from packages.application.trusted_time_head_anchor_worker import (
        TrustedTimeHeadAnchorWorkerCore,
        TrustedTimeHeadAnchorWorkRequest,
    )

    if os.getpid() != _ORIGIN_PID:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop work association is unavailable"
        )

    with _REGISTRY_LOCK:
        request_id, registration = _locate_registration_unvalidated(request)
        _REQUEST_REGISTRY.pop(request_id, None)
        try:
            exact_request = cast(
                TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
                request,
            )
            if type(work_request_identity) is not TrustedTimeHeadAnchorWorkRequest:
                raise ValueError
            if (
                type(work_request_values) is not tuple
                or len(work_request_values) != 5
                or type(work_request_values[0]) is not int
                or type(work_request_values[1]) is not TrustedTimeHeadAnchorCheckpointReason
                or type(work_request_values[2]) is not bool
                or type(work_request_values[3]) is not bool
                or type(work_request_values[4]) is not int
            ):
                raise ValueError
            work_request_identity.__post_init__()
            exact_request.__post_init__()
            if (
                registration.status != "registered"
                or type(core_identity) is not TrustedTimeHeadAnchorWorkerCore
                or registration.core_identity is not core_identity
                or core_identity._fatal
                or core_identity._stopped
                or registration.worker_thread_identity is not None
                or registration.work_request_identity is not None
                or registration.request_sha256 != exact_request.request_sha256
                or core_identity._operation_bound_clean_stop_request is not exact_request
                or core_identity._operation_bound_clean_stop_work_request is not None
                or core_identity._operation_bound_clean_stop_terminal_result is not None
                or core_identity._in_flight is not work_request_identity
                or not core_identity._clean_stop_requested
                or work_request_identity.checkpoint_reason
                is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
                or (
                    work_request_identity.request_sequence,
                    work_request_identity.checkpoint_reason,
                    work_request_identity.full_audit,
                    work_request_identity.allow_enrollment,
                    work_request_identity.scheduled_monotonic_ns,
                )
                != work_request_values
            ):
                raise ValueError
            worker_thread_identity = threading.current_thread()
            if (
                not isinstance(worker_thread_identity, threading.Thread)
                or (
                    work_request_identity.request_sequence,
                    work_request_identity.checkpoint_reason,
                    work_request_identity.full_audit,
                    work_request_identity.allow_enrollment,
                    work_request_identity.scheduled_monotonic_ns,
                )
                != work_request_values
            ):
                raise ValueError
        except Exception:
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop work association is unavailable"
            ) from None
        registration.worker_thread_identity = worker_thread_identity
        registration.work_request_identity = work_request_identity
        registration.work_request_values = work_request_values
        registration.status = "work_bound"
        _REQUEST_REGISTRY[request_id] = registration


def _issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
    request: object,
    *,
    core_identity: object,
    work_request_identity: object,
    terminal_result: object,
    attempt_result: object,
) -> TrustedTimeHeadAnchorOperationBoundCleanStopResult:
    """Issue after, and only after, the worker consumed the exact ADR-0108 result."""

    from packages.application.trusted_time_head_anchor_worker import (
        TrustedTimeHeadAnchorAttemptResult,
        TrustedTimeHeadAnchorWorkerCore,
        TrustedTimeHeadAnchorWorkRequest,
    )

    if os.getpid() != _ORIGIN_PID:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop terminal export is unavailable"
        )

    with _REGISTRY_LOCK:
        request_id, registration = _locate_registration_unvalidated(request)
        _REQUEST_REGISTRY.pop(request_id, None)
        try:
            exact_request = cast(
                TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
                request,
            )
            if (
                registration.status != "work_bound"
                or type(core_identity) is not TrustedTimeHeadAnchorWorkerCore
                or registration.core_identity is not core_identity
                or core_identity._fatal
                or core_identity._stopped
                or registration.worker_thread_identity is not threading.current_thread()
                or type(work_request_identity) is not TrustedTimeHeadAnchorWorkRequest
                or registration.work_request_identity is not work_request_identity
                or registration.work_request_values is None
                or type(terminal_result) is not TrustedTimeHeadAnchorCleanStopTerminalResult
                or type(attempt_result) is not TrustedTimeHeadAnchorAttemptResult
                or core_identity._operation_bound_clean_stop_request is not exact_request
                or core_identity._operation_bound_clean_stop_work_request
                is not work_request_identity
                or core_identity._operation_bound_clean_stop_terminal_result is not None
                or core_identity._in_flight is not work_request_identity
                or not core_identity._clean_stop_requested
            ):
                raise ValueError
            work_request_identity.__post_init__()
            exact_request.__post_init__()
            (
                captured_request_sequence,
                captured_checkpoint_reason,
                captured_full_audit,
                captured_allow_enrollment,
                captured_scheduled_monotonic_ns,
            ) = registration.work_request_values
            if (
                registration.request_sha256 != exact_request.request_sha256
                or (
                    work_request_identity.request_sequence,
                    work_request_identity.checkpoint_reason,
                    work_request_identity.full_audit,
                    work_request_identity.allow_enrollment,
                    work_request_identity.scheduled_monotonic_ns,
                )
                != registration.work_request_values
                or captured_checkpoint_reason
                is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
                or captured_allow_enrollment is not False
            ):
                raise ValueError
            terminal_values, terminal_semantic_sha256 = (
                _consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
                    terminal_result,
                    request_identity=work_request_identity,
                )
            )
            if len(terminal_values) != len(_TERMINAL_FIELDS) - 1:
                raise ValueError
            terminal_receipt_observed_at_utc = terminal_values[11]
            attempt_completed_at_utc = attempt_result.completed_at_utc
            if (
                (
                    work_request_identity.request_sequence,
                    work_request_identity.checkpoint_reason,
                    work_request_identity.full_audit,
                    work_request_identity.allow_enrollment,
                    work_request_identity.scheduled_monotonic_ns,
                )
                != registration.work_request_values
                or terminal_values[0] != captured_request_sequence
                or terminal_values[1] != captured_scheduled_monotonic_ns
                or terminal_values[3] is not captured_checkpoint_reason
                or attempt_result.clean_stop_terminal_result is not terminal_result
                or attempt_result.request_sequence != terminal_values[0]
                or attempt_result.checkpoint_reason is not terminal_values[3]
                or attempt_result.current_host_head_sha256 != terminal_values[8]
                or attempt_result.current_anchor_sha256 != terminal_values[9]
                or attempt_result.current_anchor_semantic_sha256 != terminal_values[10]
                or attempt_result.full_audit_completed is not terminal_values[12]
                or attempt_result.pending_intent_recovered is not terminal_values[13]
                or attempt_result.candidate_remote_readback_sha256 != terminal_values[17]
                or attempt_result.receipt_semantic_sha256 != terminal_values[18]
                or (captured_full_audit is True and not attempt_result.full_audit_completed)
                or type(attempt_completed_at_utc) is not datetime
                or attempt_completed_at_utc.tzinfo is None
                or attempt_completed_at_utc.utcoffset() is None
                or attempt_completed_at_utc.utcoffset() != UTC.utcoffset(attempt_completed_at_utc)
                or type(terminal_receipt_observed_at_utc) is not datetime
                or terminal_receipt_observed_at_utc > attempt_completed_at_utc
            ):
                raise ValueError
            request_encoded = exact_request.encoded
            fields = dict(zip(_TERMINAL_FIELDS[:-1], terminal_values, strict=True))
            fields["clean_stop_terminal_result_semantic_sha256"] = terminal_semantic_sha256
            candidate = _new_result(request_encoded=request_encoded, fields=fields)
            candidate_values = (
                object.__getattribute__(candidate, "_request_encoded"),
                *(getattr(candidate, name) for name in _TERMINAL_FIELDS),
            )
            candidate_encoded = candidate.encoded
            candidate_sha256 = hashlib.sha256(candidate_encoded).hexdigest()
        except Exception:
            raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
                "trusted-time operation-bound clean-stop terminal export is unavailable"
            ) from None
        registration.result_identity = candidate
        registration.result_values = candidate_values
        registration.result_encoded = candidate_encoded
        registration.result_sha256 = candidate_sha256
        registration.status = "issued"
        _REQUEST_REGISTRY[request_id] = registration
        return candidate


def _take_trusted_time_head_anchor_operation_bound_clean_stop_result_once(
    request: object,
    *,
    core_identity: object,
    result_identity: object,
) -> bytes | None:
    """Consume the exact issued bridge result from its exact core once."""

    if os.getpid() != _ORIGIN_PID:
        raise TrustedTimeHeadAnchorCleanStopSupervisorBridgeError(
            "trusted-time operation-bound clean-stop result is unavailable"
        )
    with _REGISTRY_LOCK:
        request_id, registration = _locate_registration_unvalidated(request)
        _REQUEST_REGISTRY.pop(request_id, None)
        try:
            from packages.application.trusted_time_head_anchor_worker import (
                TrustedTimeHeadAnchorWorkerCore,
                TrustedTimeHeadAnchorWorkRequest,
            )

            exact_request = cast(
                TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
                request,
            )
            if (
                registration.status != "issued"
                or type(core_identity) is not TrustedTimeHeadAnchorWorkerCore
                or registration.core_identity is not core_identity
                or registration.control_thread_identity is not threading.current_thread()
                or type(result_identity) is not TrustedTimeHeadAnchorOperationBoundCleanStopResult
                or registration.result_identity is not result_identity
                or registration.result_values is None
                or registration.result_encoded is None
                or registration.result_sha256 is None
                or type(registration.work_request_identity) is not TrustedTimeHeadAnchorWorkRequest
                or registration.work_request_values is None
                or core_identity._operation_bound_clean_stop_request is not exact_request
                or core_identity._operation_bound_clean_stop_work_request
                is not registration.work_request_identity
                or core_identity._operation_bound_clean_stop_terminal_result is not result_identity
                or core_identity._in_flight is not None
                or core_identity._fatal
                or not core_identity._stopped
                or not core_identity._clean_stop_requested
                or not core_identity._clean_shutdown_completed
            ):
                raise ValueError
            exact_request.__post_init__()
            result_identity.__post_init__()
            registration.work_request_identity.__post_init__()
            current_work_values = (
                registration.work_request_identity.request_sequence,
                registration.work_request_identity.checkpoint_reason,
                registration.work_request_identity.full_audit,
                registration.work_request_identity.allow_enrollment,
                registration.work_request_identity.scheduled_monotonic_ns,
            )
            current_values = (
                object.__getattribute__(result_identity, "_request_encoded"),
                *(getattr(result_identity, name) for name in _TERMINAL_FIELDS),
            )
            current_encoded = result_identity.encoded
            if (
                registration.request_sha256 != exact_request.request_sha256
                or result_identity.request_sha256 != registration.request_sha256
                or current_work_values != registration.work_request_values
                or current_values != registration.result_values
                or current_encoded != registration.result_encoded
                or hashlib.sha256(current_encoded).hexdigest() != registration.result_sha256
            ):
                raise ValueError
        except Exception:
            return None
        return registration.result_encoded


def _revoke_trusted_time_head_anchor_operation_bound_clean_stop_request(
    request: object,
    *,
    core_identity: object,
) -> None:
    """Burn one registered association without making its digest reusable."""

    if (
        os.getpid() != _ORIGIN_PID
        or type(request) is not TrustedTimeHeadAnchorOperationBoundCleanStopRequest
    ):
        return
    with _REGISTRY_LOCK:
        try:
            request_id, _ = _locate_registration_unvalidated(request)
        except Exception:
            return
        _REQUEST_REGISTRY.pop(request_id, None)


__all__ = [
    "MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_BYTES",
    "MAXIMUM_TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_BYTES",
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_PROGRESS_PHASE",
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_STATUS",
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_CONTRACT_VERSION",
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_RESULT_STATUS",
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_SERVICE",
    "TrustedTimeHeadAnchorCleanStopSupervisorBridgeError",
    "TrustedTimeHeadAnchorOperationBoundCleanStopRequest",
    "TrustedTimeHeadAnchorOperationBoundCleanStopResult",
    "canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes",
    "canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes",
    "decode_trusted_time_head_anchor_operation_bound_clean_stop_request",
    "decode_trusted_time_head_anchor_operation_bound_clean_stop_result",
]
