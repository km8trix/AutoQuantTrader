"""Process-local evidence for one exact new-record clean-stop completion.

The result in this module is deliberately narrower than a provider-terminal
postcondition or a durable graceful-stop outcome.  It records that one exact
``CLEAN_STOP`` request produced a new remotely read-back record and a durable
local receipt.  It grants no authority, proves no later-record absence, and
has no serialization, persistence, signal, admission, or teardown surface.
"""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Never, SupportsIndex, cast

from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)

TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_TERMINAL_RESULT_CONTRACT_VERSION = (
    "phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1"
)

_MAXIMUM_INTEGER = 9_223_372_036_854_775_807
_ORIGIN_PID = os.getpid()
_REGISTRY_LOCK = threading.Lock()


class TrustedTimeHeadAnchorCleanStopTerminalResultError(RuntimeError):
    """The process-local clean-stop terminal result is invalid or unavailable."""


def _authority_is_never_granted(_: object) -> bool:
    return False


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _result_values(value: TrustedTimeHeadAnchorCleanStopTerminalResult) -> tuple[object, ...]:
    return (
        value.request_sequence,
        value.request_scheduled_monotonic_ns,
        value.anchor_sequence,
        value.checkpoint_reason,
        value.confirmed_anchor_count,
        value.local_transition_count,
        value.confirmed_anchor_local_transition_ordinal,
        value.predecessor_anchor_sha256,
        value.current_host_head_sha256,
        value.current_anchor_sha256,
        value.current_anchor_semantic_sha256,
        value.receipt_observed_at_utc,
        value.full_audit_completed,
        value.prior_pending_intent_recovered,
        value.uploaded_anchor_count,
        value.idempotent_duplicate_count,
        value.current_anchor_intent_semantic_sha256,
        value.current_candidate_remote_readback_sha256,
        value.current_receipt_semantic_sha256,
    )


def _result_payload(values: tuple[object, ...]) -> dict[str, object]:
    (
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
    ) = values
    if type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result reason is invalid"
        )
    if type(receipt_observed_at_utc) is not datetime:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result receipt instant is invalid"
        )
    return {
        "anchor_sequence": anchor_sequence,
        "checkpoint_reason": checkpoint_reason.value,
        "confirmed_anchor_count": confirmed_anchor_count,
        "confirmed_anchor_local_transition_ordinal": (confirmed_anchor_local_transition_ordinal),
        "contract_version": (TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_TERMINAL_RESULT_CONTRACT_VERSION),
        "current_anchor_intent_semantic_sha256": current_anchor_intent_semantic_sha256,
        "current_anchor_semantic_sha256": current_anchor_semantic_sha256,
        "current_anchor_sha256": current_anchor_sha256,
        "current_candidate_remote_readback_sha256": (current_candidate_remote_readback_sha256),
        "current_host_head_sha256": current_host_head_sha256,
        "current_receipt_semantic_sha256": current_receipt_semantic_sha256,
        "full_audit_completed": full_audit_completed,
        "idempotent_duplicate_count": idempotent_duplicate_count,
        "local_transition_count": local_transition_count,
        "predecessor_anchor_sha256": predecessor_anchor_sha256,
        "prior_pending_intent_recovered": prior_pending_intent_recovered,
        "receipt_observed_at_utc": _utc_text(receipt_observed_at_utc),
        "request_scheduled_monotonic_ns": request_scheduled_monotonic_ns,
        "request_sequence": request_sequence,
        "status": "exact_current_new_record_clean_stop_completed",
        "uploaded_anchor_count": uploaded_anchor_count,
    }


def _validate_result_values(values: tuple[object, ...]) -> None:
    (
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
    ) = values
    integer_fields = (
        request_sequence,
        anchor_sequence,
        confirmed_anchor_count,
        local_transition_count,
        confirmed_anchor_local_transition_ordinal,
    )
    if any(type(item) is not int or not 0 < item <= _MAXIMUM_INTEGER for item in integer_fields):
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result sequence or count is invalid"
        )
    exact_anchor_sequence = cast(int, anchor_sequence)
    exact_confirmed_anchor_count = cast(int, confirmed_anchor_count)
    exact_local_transition_count = cast(int, local_transition_count)
    exact_terminal_ordinal = cast(int, confirmed_anchor_local_transition_ordinal)
    if (
        type(request_scheduled_monotonic_ns) is not int
        or not 0 <= request_scheduled_monotonic_ns <= _MAXIMUM_INTEGER
        or type(checkpoint_reason) is not TrustedTimeHeadAnchorCheckpointReason
        or checkpoint_reason is not TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
        or exact_anchor_sequence < 3
        or exact_confirmed_anchor_count != exact_anchor_sequence
        or exact_terminal_ordinal != exact_local_transition_count
        or exact_terminal_ordinal < exact_anchor_sequence
    ):
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result chronology is invalid"
        )
    if (
        not all(
            _is_sha256(item)
            for item in (
                predecessor_anchor_sha256,
                current_host_head_sha256,
                current_anchor_sha256,
                current_anchor_semantic_sha256,
                current_anchor_intent_semantic_sha256,
                current_candidate_remote_readback_sha256,
                current_receipt_semantic_sha256,
            )
        )
        or current_candidate_remote_readback_sha256 != current_anchor_sha256
    ):
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result digest binding is invalid"
        )
    if (
        type(receipt_observed_at_utc) is not datetime
        or receipt_observed_at_utc.tzinfo is None
        or receipt_observed_at_utc.utcoffset() is None
        or receipt_observed_at_utc.utcoffset() != UTC.utcoffset(receipt_observed_at_utc)
    ):
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result receipt instant must be UTC"
        )
    if (
        type(full_audit_completed) is not bool
        or type(prior_pending_intent_recovered) is not bool
        or type(uploaded_anchor_count) is not int
        or uploaded_anchor_count not in (0, 1)
        or type(idempotent_duplicate_count) is not int
        or idempotent_duplicate_count not in (0, 1)
        or uploaded_anchor_count + idempotent_duplicate_count != 1
    ):
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result completion facts are invalid"
        )


def _result_semantic_sha256(values: tuple[object, ...]) -> str:
    encoded = canonical_first_enrollment_json_bytes(_result_payload(values))
    return hashlib.sha256(encoded).hexdigest()


_ResultRegistration = tuple[
    "TrustedTimeHeadAnchorCleanStopTerminalResult",
    int,
    tuple[object, ...],
    str,
    object,
    bool,
    bool,
]
_RESULT_REGISTRY: dict[int, _ResultRegistration] = {}


def _validate_registered_result(value: object) -> None:
    try:
        if (
            os.getpid() != _ORIGIN_PID
            or type(value) is not TrustedTimeHeadAnchorCleanStopTerminalResult
        ):
            raise ValueError
        exact = value
        values = _result_values(exact)
        _validate_result_values(values)
        semantic_sha256 = object.__getattribute__(exact, "_semantic_sha256")
        if not _is_sha256(semantic_sha256) or semantic_sha256 != _result_semantic_sha256(values):
            raise ValueError
        with _REGISTRY_LOCK:
            registration = _RESULT_REGISTRY.get(id(exact))
        if (
            registration is None
            or registration[0] is not exact
            or registration[1] != _ORIGIN_PID
            or registration[2] != values
            or registration[3] != semantic_sha256
        ):
            raise ValueError
    except BaseException as error:
        if (
            os.getpid() == _ORIGIN_PID
            and type(value) is TrustedTimeHeadAnchorCleanStopTerminalResult
        ):
            with _REGISTRY_LOCK:
                registration = _RESULT_REGISTRY.get(id(value))
                if registration is not None and registration[0] is value:
                    _RESULT_REGISTRY.pop(id(value), None)
        if isinstance(error, TrustedTimeHeadAnchorCleanStopTerminalResultError):
            raise
        if isinstance(error, Exception):
            raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
                "trusted-time clean-stop terminal result is invalid"
            ) from None
        raise


@dataclass(frozen=True, slots=True, init=False, eq=False)
class TrustedTimeHeadAnchorCleanStopTerminalResult:
    """Sealed evidence that the exact current clean stop wrote one record."""

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
    _semantic_sha256: str = field(init=False, repr=False, compare=False)

    def __init__(self, *_: object, **__: object) -> None:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result is issued internally"
        )

    def __post_init__(self) -> None:
        _validate_registered_result(self)

    @property
    def semantic_sha256(self) -> str:
        _validate_registered_result(self)
        return self._semantic_sha256

    def __copy__(self) -> Never:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be copied"
        )

    def __replace__(self, **_: object) -> Never:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be replaced"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be serialized"
        )

    authority_granted = property(_authority_is_never_granted)
    provider_terminal_authenticated = property(_authority_is_never_granted)
    provider_terminal_currentness_authenticated = property(_authority_is_never_granted)
    no_new_record_authenticated = property(_authority_is_never_granted)
    no_new_record_success = property(_authority_is_never_granted)
    durability_authenticated = property(_authority_is_never_granted)
    durable_stop_outcome_authenticated = property(_authority_is_never_granted)
    stop_outcome_retained = property(_authority_is_never_granted)
    slot_authorized = property(_authority_is_never_granted)
    admission_authorized = property(_authority_is_never_granted)
    signal_authorized = property(_authority_is_never_granted)
    graceful_stop_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    teardown_authorized = property(_authority_is_never_granted)
    effect_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)


def _issue_trusted_time_head_anchor_clean_stop_terminal_result(
    *,
    request_identity: object,
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
) -> TrustedTimeHeadAnchorCleanStopTerminalResult:
    """Issue the exact process-local projection after current receipt confirmation."""

    if os.getpid() != _ORIGIN_PID or request_identity is None:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result issuer is unavailable"
        )
    values: tuple[object, ...] = (
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
    )
    _validate_result_values(values)
    semantic_sha256 = _result_semantic_sha256(values)
    result = object.__new__(TrustedTimeHeadAnchorCleanStopTerminalResult)
    for field_name, field_value in zip(
        (
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
        ),
        values,
        strict=True,
    ):
        object.__setattr__(result, field_name, field_value)
    object.__setattr__(result, "_semantic_sha256", semantic_sha256)
    registration: _ResultRegistration = (
        result,
        _ORIGIN_PID,
        values,
        semantic_sha256,
        request_identity,
        False,
        False,
    )
    with _REGISTRY_LOCK:
        if id(result) in _RESULT_REGISTRY:  # pragma: no cover - live identity is retained
            raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
                "trusted-time clean-stop terminal result identity collided"
            )
        _RESULT_REGISTRY[id(result)] = registration
    try:
        result.__post_init__()
    except BaseException:
        with _REGISTRY_LOCK:
            _RESULT_REGISTRY.pop(id(result), None)
        raise
    return result


def _consume_trusted_time_head_anchor_clean_stop_terminal_result(
    result: object,
    *,
    request_identity: object,
) -> None:
    """Atomically bind one sealed result to its exact in-flight request once."""

    try:
        if (
            os.getpid() != _ORIGIN_PID
            or request_identity is None
            or type(result) is not TrustedTimeHeadAnchorCleanStopTerminalResult
        ):
            raise ValueError
        with _REGISTRY_LOCK:
            registration = _RESULT_REGISTRY.get(id(result))
            if registration is None or registration[0] is not result:
                raise ValueError
            _RESULT_REGISTRY.pop(id(result), None)
            values = _result_values(result)
            _validate_result_values(values)
            semantic_sha256 = object.__getattribute__(result, "_semantic_sha256")
            if (
                not _is_sha256(semantic_sha256)
                or semantic_sha256 != _result_semantic_sha256(values)
                or registration[1] != _ORIGIN_PID
                or registration[2] != values
                or registration[3] != semantic_sha256
                or registration[4] is not request_identity
                or registration[5]
            ):
                raise ValueError
            _RESULT_REGISTRY[id(result)] = (*registration[:5], True, registration[6])
    except TrustedTimeHeadAnchorCleanStopTerminalResultError:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be consumed"
        ) from None


def _consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
    result: object,
    *,
    request_identity: object,
) -> tuple[tuple[object, ...], str]:
    """Atomically export one immutable registered terminal projection once."""

    try:
        if (
            os.getpid() != _ORIGIN_PID
            or type(result) is not TrustedTimeHeadAnchorCleanStopTerminalResult
        ):
            raise ValueError
        with _REGISTRY_LOCK:
            registration = _RESULT_REGISTRY.get(id(result))
            if registration is None or registration[0] is not result:
                raise ValueError
            _RESULT_REGISTRY.pop(id(result), None)
            values = _result_values(result)
            _validate_result_values(values)
            semantic_sha256 = object.__getattribute__(result, "_semantic_sha256")
            if (
                not _is_sha256(semantic_sha256)
                or semantic_sha256 != _result_semantic_sha256(values)
                or registration[1] != _ORIGIN_PID
                or registration[2] != values
                or registration[3] != semantic_sha256
                or request_identity is None
                or registration[4] is not request_identity
                or registration[5] is not True
                or registration[6]
            ):
                raise ValueError
            _RESULT_REGISTRY[id(result)] = (*registration[:6], True)
            return registration[2], registration[3]
    except TrustedTimeHeadAnchorCleanStopTerminalResultError:
        raise
    except Exception:
        raise TrustedTimeHeadAnchorCleanStopTerminalResultError(
            "trusted-time clean-stop terminal result cannot be exported"
        ) from None


__all__ = [
    "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_TERMINAL_RESULT_CONTRACT_VERSION",
    "TrustedTimeHeadAnchorCleanStopTerminalResult",
    "TrustedTimeHeadAnchorCleanStopTerminalResultError",
]
