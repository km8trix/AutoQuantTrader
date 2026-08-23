from __future__ import annotations

import copy
import inspect
import json
import os
import pickle
import select
import signal
import sys
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from types import FrameType
from typing import Any, Protocol, cast

import pytest

from packages.application import trusted_time_head_anchor_clean_stop as clean_stop
from packages.application import (
    trusted_time_head_anchor_clean_stop_supervisor_bridge as bridge,
)
from packages.application import trusted_time_head_anchor_worker as worker_module
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from packages.application.trusted_time_head_anchor_worker import (
    TrustedTimeHeadAnchorAttemptResult,
    TrustedTimeHeadAnchorWorkerCore,
    TrustedTimeHeadAnchorWorkerError,
    TrustedTimeHeadAnchorWorkRequest,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)

BASE = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


class _RegisterRequest(Protocol):
    def __call__(self, request: object, *, core_identity: object) -> None: ...


def _raise_from_function_line(
    function: Any,
    marker: str,
    operation: Callable[[], object],
    exception_type: type[BaseException],
    *,
    occurrence: int = 1,
) -> None:
    source_lines, first_line = inspect.getsourcelines(function)
    matching_lines = [
        first_line + index
        for index, source_line in enumerate(source_lines)
        if marker in source_line
    ]
    target_line = matching_lines[occurrence - 1]

    def trace(frame: FrameType, event: str, _: object) -> Any:
        if event == "line" and frame.f_code is function.__code__ and frame.f_lineno == target_line:
            raise exception_type()
        return trace

    sys.settrace(trace)
    try:
        operation()
    finally:
        sys.settrace(None)


def _operation_request(
    index: int,
) -> bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    return bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest(
        graceful_stop_operation_id=f"00000000-0000-4000-8000-{index:012x}",
        graceful_stop_target_sha256="1" * 64,
        graceful_stop_decision_v1_sha256="2" * 64,
        graceful_stop_decision_artifact_receipt_sha256="3" * 64,
        operator_attestation_envelope_sha256="4" * 64,
        attempt_slot_sha256="5" * 64,
        bridge_required_progress_sha256="6" * 64,
        controller_outcome_sha256="7" * 64,
        durable_shutdown_locator_sha256="8" * 64,
        active_controller_session_sha256="9" * 64,
        persistent_topology_sha256="a" * 64,
        persistent_topology_transcript_sha256="b" * 64,
        supervisor_container_id="c" * 64,
    )


def _work_request_values(
    request: TrustedTimeHeadAnchorWorkRequest,
) -> tuple[object, ...]:
    return (
        request.request_sequence,
        request.checkpoint_reason,
        request.full_audit,
        request.allow_enrollment,
        request.scheduled_monotonic_ns,
    )


def _startup_result(
    request: TrustedTimeHeadAnchorWorkRequest,
) -> TrustedTimeHeadAnchorAttemptResult:
    return TrustedTimeHeadAnchorAttemptResult(
        request_sequence=request.request_sequence,
        checkpoint_reason=request.checkpoint_reason,
        current_host_head_sha256="a" * 64,
        current_anchor_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        completed_at_utc=BASE,
        full_audit_completed=True,
        pending_intent_recovered=False,
        candidate_remote_readback_sha256=None,
        receipt_semantic_sha256=None,
    )


def _complete_startup(core: TrustedTimeHeadAnchorWorkerCore) -> None:
    request = core.take_work(observed_at_monotonic_ns=0)
    assert request is not None
    assert request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.EPOCH_ROTATION
    core.record_success(request, _startup_result(request), observed_at_monotonic_ns=0)


def _terminal_result(
    request: TrustedTimeHeadAnchorWorkRequest,
) -> clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult:
    return clean_stop._issue_trusted_time_head_anchor_clean_stop_terminal_result(
        request_identity=request,
        request_sequence=request.request_sequence,
        request_scheduled_monotonic_ns=request.scheduled_monotonic_ns,
        anchor_sequence=3,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
        confirmed_anchor_count=3,
        local_transition_count=4,
        confirmed_anchor_local_transition_ordinal=4,
        predecessor_anchor_sha256="1" * 64,
        current_host_head_sha256="a" * 64,
        current_anchor_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        receipt_observed_at_utc=BASE,
        full_audit_completed=request.full_audit,
        prior_pending_intent_recovered=False,
        uploaded_anchor_count=1,
        idempotent_duplicate_count=0,
        current_anchor_intent_semantic_sha256="d" * 64,
        current_candidate_remote_readback_sha256="b" * 64,
        current_receipt_semantic_sha256="e" * 64,
    )


def _clean_stop_attempt_result(
    request: TrustedTimeHeadAnchorWorkRequest,
    terminal: clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult,
) -> TrustedTimeHeadAnchorAttemptResult:
    return TrustedTimeHeadAnchorAttemptResult(
        request_sequence=request.request_sequence,
        checkpoint_reason=request.checkpoint_reason,
        current_host_head_sha256="a" * 64,
        current_anchor_sha256="b" * 64,
        current_anchor_semantic_sha256="c" * 64,
        completed_at_utc=BASE,
        full_audit_completed=request.full_audit,
        pending_intent_recovered=False,
        candidate_remote_readback_sha256="b" * 64,
        receipt_semantic_sha256="e" * 64,
        clean_stop_terminal_result=terminal,
    )


def _registered_core(
    index: int,
) -> tuple[
    TrustedTimeHeadAnchorWorkerCore,
    bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
]:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    _complete_startup(core)
    operation_request = _operation_request(index)
    core._request_operation_bound_clean_stop(
        operation_request,
        observed_at_monotonic_ns=1,
    )
    return core, operation_request


def _issued_core(
    index: int,
) -> tuple[
    TrustedTimeHeadAnchorWorkerCore,
    bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    bridge.TrustedTimeHeadAnchorOperationBoundCleanStopResult,
]:
    core, operation_request = _registered_core(index)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    assert work_request.checkpoint_reason is TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
    terminal = _terminal_result(work_request)
    core.record_success(
        work_request,
        _clean_stop_attempt_result(work_request, terminal),
        observed_at_monotonic_ns=1,
    )
    issued = core._operation_bound_clean_stop_terminal_result
    assert issued is not None
    return core, operation_request, issued


def test_request_codec_is_canonical_closed_and_structural_only() -> None:
    request = _operation_request(1)
    encoded = request.encoded
    decoded = bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_request(encoded)

    assert decoded is not request
    assert decoded.encoded == encoded
    assert decoded.request_sha256 == request.request_sha256
    assert (
        decoded.payload()["status"]
        == bridge.TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_SUPERVISOR_BRIDGE_REQUEST_STATUS
    )
    assert decoded.payload()["progress_ordinal"] == 1
    assert all(getattr(decoded, field_name) is False for field_name in bridge._CLOSED_FIELDS)
    for operation in (
        lambda: copy.copy(request),
        lambda: copy.deepcopy(request),
        lambda: pickle.dumps(request),
    ):
        with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
            operation()
    with pytest.raises(TypeError):
        replace(request)


def test_request_decoder_rejects_duplicates_noncanonical_unknown_true_and_bool_ordinal() -> None:
    encoded = _operation_request(2).encoded
    payload = json.loads(encoded)

    invalid_encodings = [
        b" " + encoded,
        encoded.replace(b"{", b'{"status":"foreign",', 1),
    ]
    unknown = dict(payload)
    unknown["unknown"] = False
    invalid_encodings.append(canonical_first_enrollment_json_bytes(unknown))
    opened = dict(payload)
    opened["shutdown_authorized"] = True
    invalid_encodings.append(canonical_first_enrollment_json_bytes(opened))
    bool_ordinal = dict(payload)
    bool_ordinal["progress_ordinal"] = True
    invalid_encodings.append(canonical_first_enrollment_json_bytes(bool_ordinal))

    for invalid in invalid_encodings:
        with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
            bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_request(invalid)


def test_exact_core_flow_returns_one_immutable_canonical_result() -> None:
    core, operation_request, issued = _issued_core(3)

    encoded = core._take_operation_bound_clean_stop_terminal_result_once(operation_request)

    assert type(encoded) is bytes
    decoded = bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(encoded)
    terminal_values = tuple(getattr(decoded, name) for name in bridge._TERMINAL_FIELDS[:-1])
    assert decoded.request_sha256 == operation_request.request_sha256
    assert decoded.request.encoded == operation_request.encoded
    assert decoded.clean_stop_terminal_result_semantic_sha256 == (
        clean_stop._result_semantic_sha256(terminal_values)
    )
    assert decoded.exact_request_work_result_correlated is True
    assert all(getattr(decoded, field_name) is False for field_name in bridge._CLOSED_FIELDS)
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None

    original_encoded = encoded
    object.__setattr__(issued, "predecessor_anchor_sha256", "f" * 64)
    assert encoded == original_encoded
    assert decoded.predecessor_anchor_sha256 == "1" * 64


def test_result_decoder_rejects_substituted_terminal_digest_and_nested_bool_ordinal() -> None:
    core, operation_request, _ = _issued_core(4)
    encoded = core._take_operation_bound_clean_stop_terminal_result_once(operation_request)
    assert encoded is not None
    payload = json.loads(encoded)

    wrong_digest = dict(payload)
    wrong_digest["clean_stop_terminal_result_semantic_sha256"] = "0" * 64
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
            canonical_first_enrollment_json_bytes(wrong_digest)
        )

    nested_bool = dict(payload)
    nested_request = dict(nested_bool["operation_bound_request"])
    nested_request["progress_ordinal"] = True
    nested_bool["operation_bound_request"] = nested_request
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
            canonical_first_enrollment_json_bytes(nested_bool)
        )


def test_generic_clean_stop_never_issues_a_bridge_result() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    _complete_startup(core)
    core.request_clean_stop(observed_at_monotonic_ns=1)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    core.record_success(
        work_request,
        _clean_stop_attempt_result(work_request, terminal),
        observed_at_monotonic_ns=1,
    )

    assert core._operation_bound_clean_stop_terminal_result is None
    assert core._take_operation_bound_clean_stop_terminal_result_once(_operation_request(5)) is None


def test_post_selection_registration_is_burned_and_cannot_be_replayed() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    _complete_startup(core)
    core.request_clean_stop(observed_at_monotonic_ns=1)
    assert core.take_work(observed_at_monotonic_ns=1) is not None
    operation_request = _operation_request(6)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core._request_operation_bound_clean_stop(
            operation_request,
            observed_at_monotonic_ns=1,
        )
    assert core.fatal_error_latched is True

    other = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        other._request_operation_bound_clean_stop(
            operation_request,
            observed_at_monotonic_ns=0,
        )


def test_scalar_equal_request_clone_cannot_register_on_another_core() -> None:
    core, operation_request = _registered_core(7)
    clone = bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
        operation_request.encoded
    )
    other = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        other._request_operation_bound_clean_stop(clone, observed_at_monotonic_ns=0)
    assert other.fatal_error_latched is True

    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    core.record_transient_failure(work_request, observed_at_monotonic_ns=1)


def test_duck_typed_work_binding_burns_before_validation() -> None:
    core, operation_request = _registered_core(8)

    class FakeWorkRequest:
        request_sequence = 2
        checkpoint_reason = TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP
        scheduled_monotonic_ns = 1

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
            operation_request,
            core_identity=core,
            work_request_identity=FakeWorkRequest(),
            work_request_values=(
                2,
                TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
                False,
                False,
                1,
            ),
        )
    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core.take_work(observed_at_monotonic_ns=1)
    assert core.fatal_error_latched is True


def test_bind_rejects_current_thread_hook_relabeling_before_snapshot_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core, operation_request = _registered_core(37)
    real_current_thread = threading.current_thread

    def relabel_then_return_thread() -> threading.Thread:
        work_request = core._in_flight
        assert type(work_request) is TrustedTimeHeadAnchorWorkRequest
        object.__setattr__(work_request, "request_sequence", 99)
        return real_current_thread()

    monkeypatch.setattr(threading, "current_thread", relabel_then_return_thread)
    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core.take_work(observed_at_monotonic_ns=1)

    assert core.fatal_error_latched is True
    assert core._in_flight is None
    assert core._operation_bound_clean_stop_request is None
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
            operation_request,
            core_identity=core,
            work_request_identity=object(),
            work_request_values=(
                2,
                TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
                False,
                False,
                1,
            ),
        )


def test_wrong_core_bind_burns_before_a_correct_retry() -> None:
    core, operation_request = _registered_core(16)
    other = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    work_request = TrustedTimeHeadAnchorWorkRequest(
        request_sequence=2,
        checkpoint_reason=TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
        full_audit=False,
        allow_enrollment=False,
        scheduled_monotonic_ns=1,
    )

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
            operation_request,
            core_identity=other,
            work_request_identity=work_request,
            work_request_values=_work_request_values(work_request),
        )
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            work_request_values=_work_request_values(work_request),
        )


def test_wrong_core_issue_burns_before_a_correct_retry() -> None:
    core, operation_request = _registered_core(17)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        terminal,
        request_identity=work_request,
    )
    other = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=other,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=_clean_stop_attempt_result(work_request, terminal),
        )
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=_clean_stop_attempt_result(work_request, terminal),
        )


def test_issue_after_in_flight_clear_is_burned_as_post_hoc() -> None:
    core, operation_request = _registered_core(18)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        terminal,
        request_identity=work_request,
    )
    core._in_flight = None

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=_clean_stop_attempt_result(work_request, terminal),
        )
    core._in_flight = work_request
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=_clean_stop_attempt_result(work_request, terminal),
        )


def test_issue_uses_immutable_terminal_export_snapshot_across_b_to_a_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core, operation_request = _registered_core(38)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        terminal,
        request_identity=work_request,
    )
    original_host_head = terminal.current_host_head_sha256
    original_semantic_sha256 = terminal.semantic_sha256
    encoded_property = vars(bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest)["encoded"]
    assert isinstance(encoded_property, property)
    original_request_encoded = encoded_property.fget
    assert original_request_encoded is not None
    real_bridge_consume = clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge  # noqa: E501

    def relabel_during_request_encoding(
        value: bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    ) -> bytes:
        encoded = cast(bytes, original_request_encoded(value))
        object.__setattr__(terminal, "current_host_head_sha256", "f" * 64)
        return encoded

    def live_terminal_semantic_sha256(
        value: clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult,
    ) -> str:
        return clean_stop._result_semantic_sha256(clean_stop._result_values(value))

    def restore_then_consume(
        result: object,
        *,
        request_identity: object,
    ) -> tuple[tuple[object, ...], str]:
        object.__setattr__(terminal, "current_host_head_sha256", original_host_head)
        return real_bridge_consume(result, request_identity=request_identity)

    monkeypatch.setattr(
        bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
        "encoded",
        property(relabel_during_request_encoding),
    )
    monkeypatch.setattr(
        clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult,
        "semantic_sha256",
        property(live_terminal_semantic_sha256),
    )
    monkeypatch.setattr(
        bridge,
        "_consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge",
        restore_then_consume,
    )

    issued = bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
        operation_request,
        core_identity=core,
        work_request_identity=work_request,
        terminal_result=terminal,
        attempt_result=attempt,
    )

    assert issued.current_host_head_sha256 == original_host_head
    assert issued.clean_stop_terminal_result_semantic_sha256 == original_semantic_sha256
    core.record_transient_failure(work_request, observed_at_monotonic_ns=1)


@pytest.mark.parametrize(
    ("index", "field_name", "mutated_value"),
    [
        (20, "request_sequence", 99),
        (21, "checkpoint_reason", TrustedTimeHeadAnchorCheckpointReason.PERIODIC),
        (22, "full_audit", True),
        (23, "allow_enrollment", True),
        (24, "scheduled_monotonic_ns", 99),
    ],
)
def test_each_post_bind_work_projection_mutation_burns_issue(
    index: int,
    field_name: str,
    mutated_value: object,
) -> None:
    core, operation_request = _registered_core(index)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        terminal,
        request_identity=work_request,
    )
    object.__setattr__(work_request, field_name, mutated_value)

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=attempt,
        )


def test_matching_mutated_terminal_and_attempt_cannot_replace_bound_work_projection() -> None:
    core, operation_request = _registered_core(25)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    object.__setattr__(work_request, "request_sequence", 77)
    object.__setattr__(work_request, "scheduled_monotonic_ns", 88)
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core.record_success(work_request, attempt, observed_at_monotonic_ns=88)
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None


def test_scalar_equal_work_clone_cannot_replace_the_bound_identity() -> None:
    core, operation_request = _registered_core(26)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    clone = TrustedTimeHeadAnchorWorkRequest(
        request_sequence=work_request.request_sequence,
        checkpoint_reason=work_request.checkpoint_reason,
        full_audit=work_request.full_audit,
        allow_enrollment=work_request.allow_enrollment,
        scheduled_monotonic_ns=work_request.scheduled_monotonic_ns,
    )
    terminal = _terminal_result(clone)
    attempt = _clean_stop_attempt_result(clone, terminal)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        terminal,
        request_identity=clone,
    )
    core._in_flight = clone
    core._operation_bound_clean_stop_work_request = clone

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=clone,
            terminal_result=terminal,
            attempt_result=attempt,
        )


def test_mutated_then_restored_work_projection_cannot_retry_issue() -> None:
    core, operation_request = _registered_core(27)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        terminal,
        request_identity=work_request,
    )
    original_scheduled = work_request.scheduled_monotonic_ns
    object.__setattr__(work_request, "scheduled_monotonic_ns", original_scheduled + 1)

    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=attempt,
        )
    object.__setattr__(work_request, "scheduled_monotonic_ns", original_scheduled)
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._issue_trusted_time_head_anchor_operation_bound_clean_stop_result(
            operation_request,
            core_identity=core,
            work_request_identity=work_request,
            terminal_result=terminal,
            attempt_result=attempt,
        )


@pytest.mark.parametrize(
    ("index", "field_name", "mutated_value"),
    [
        (30, "request_sequence", 99),
        (31, "checkpoint_reason", TrustedTimeHeadAnchorCheckpointReason.PERIODIC),
        (32, "full_audit", True),
        (33, "allow_enrollment", True),
        (34, "scheduled_monotonic_ns", 99),
    ],
)
def test_each_post_issue_work_projection_mutation_burns_take(
    index: int,
    field_name: str,
    mutated_value: object,
) -> None:
    core, operation_request, _ = _issued_core(index)
    work_request = core._operation_bound_clean_stop_work_request
    assert work_request is not None
    object.__setattr__(work_request, field_name, mutated_value)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core._take_operation_bound_clean_stop_terminal_result_once(operation_request)
    assert core.fatal_error_latched is True


def test_completed_generic_stop_cannot_be_backfilled_with_an_operation_request() -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    _complete_startup(core)
    core.request_clean_stop(observed_at_monotonic_ns=1)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    core.record_success(
        work_request,
        _clean_stop_attempt_result(work_request, terminal),
        observed_at_monotonic_ns=1,
    )
    operation_request = _operation_request(19)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core._request_operation_bound_clean_stop(
            operation_request,
            observed_at_monotonic_ns=1,
        )
    assert core.fatal_error_latched is True


def test_wrong_core_and_decoded_result_each_burn_an_issued_association() -> None:
    core, operation_request, issued = _issued_core(9)
    other = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)

    assert (
        bridge._take_trusted_time_head_anchor_operation_bound_clean_stop_result_once(
            operation_request,
            core_identity=other,
            result_identity=issued,
        )
        is None
    )
    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core._take_operation_bound_clean_stop_terminal_result_once(operation_request)

    core, operation_request, issued = _issued_core(10)
    decoded_clone = bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
        issued.encoded
    )
    assert (
        bridge._take_trusted_time_head_anchor_operation_bound_clean_stop_result_once(
            operation_request,
            core_identity=core,
            result_identity=decoded_clone,
        )
        is None
    )
    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core._take_operation_bound_clean_stop_terminal_result_once(operation_request)


def test_coordinated_result_and_internal_seal_mutation_burns_before_take() -> None:
    core, operation_request, issued = _issued_core(11)
    original_predecessor = issued.predecessor_anchor_sha256
    original_semantic = issued.clean_stop_terminal_result_semantic_sha256
    original_sealed = issued._sealed_fields

    terminal_values = [getattr(issued, name) for name in bridge._TERMINAL_FIELDS[:-1]]
    terminal_values[7] = "f" * 64
    mutated_semantic = clean_stop._result_semantic_sha256(tuple(terminal_values))
    mutated_sealed = list(original_sealed)
    mutated_sealed[8] = "f" * 64
    mutated_sealed[20] = mutated_semantic
    object.__setattr__(issued, "predecessor_anchor_sha256", "f" * 64)
    object.__setattr__(
        issued,
        "clean_stop_terminal_result_semantic_sha256",
        mutated_semantic,
    )
    object.__setattr__(issued, "_sealed_fields", tuple(mutated_sealed))
    issued.__post_init__()

    assert (
        bridge._take_trusted_time_head_anchor_operation_bound_clean_stop_result_once(
            operation_request,
            core_identity=core,
            result_identity=issued,
        )
        is None
    )
    object.__setattr__(issued, "predecessor_anchor_sha256", original_predecessor)
    object.__setattr__(
        issued,
        "clean_stop_terminal_result_semantic_sha256",
        original_semantic,
    )
    object.__setattr__(issued, "_sealed_fields", original_sealed)
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._take_trusted_time_head_anchor_operation_bound_clean_stop_result_once(
            operation_request,
            core_identity=core,
            result_identity=issued,
        )


def test_worker_thread_mismatch_burns_before_issue() -> None:
    core, operation_request = _registered_core(12)
    selected: list[TrustedTimeHeadAnchorWorkRequest] = []

    def select_work() -> None:
        work_request = core.take_work(observed_at_monotonic_ns=1)
        assert work_request is not None
        selected.append(work_request)

    worker_thread = threading.Thread(target=select_work)
    worker_thread.start()
    worker_thread.join()
    work_request = selected[0]
    terminal = _terminal_result(work_request)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core.record_success(
            work_request,
            _clean_stop_attempt_result(work_request, terminal),
            observed_at_monotonic_ns=1,
        )
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None


def test_control_thread_mismatch_burns_before_take() -> None:
    core, operation_request, _ = _issued_core(13)
    errors: list[BaseException] = []

    def take_on_foreign_thread() -> None:
        try:
            core._take_operation_bound_clean_stop_terminal_result_once(operation_request)
        except BaseException as error:
            errors.append(error)

    foreign_thread = threading.Thread(target=take_on_foreign_thread)
    foreign_thread.start()
    foreign_thread.join()

    assert len(errors) == 1
    assert type(errors[0]) is TrustedTimeHeadAnchorWorkerError
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None


def test_register_then_keyboard_interrupt_revokes_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core = TrustedTimeHeadAnchorWorkerCore(started_at_monotonic_ns=0)
    operation_request = _operation_request(14)
    real_register = cast(
        _RegisterRequest,
        vars(worker_module)[
            "_register_trusted_time_head_anchor_operation_bound_clean_stop_request"
        ],
    )

    def register_then_interrupt(request: object, *, core_identity: object) -> None:
        real_register(request, core_identity=core_identity)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        worker_module,
        "_register_trusted_time_head_anchor_operation_bound_clean_stop_request",
        register_then_interrupt,
    )
    with pytest.raises(KeyboardInterrupt):
        core._request_operation_bound_clean_stop(operation_request, observed_at_monotonic_ns=0)

    assert core.fatal_error_latched is True
    assert core._operation_bound_clean_stop_request is None
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
            operation_request,
            core_identity=core,
            work_request_identity=object(),
            work_request_values=(
                1,
                TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
                False,
                False,
                0,
            ),
        )


@pytest.mark.parametrize(
    ("index", "marker", "exception_type"),
    [
        (39, "self._next_request_sequence += 1", KeyboardInterrupt),
        (40, "self._next_request_sequence += 1", SystemExit),
        (41, "return request", KeyboardInterrupt),
        (42, "return request", SystemExit),
    ],
)
def test_operation_bound_new_request_async_commit_gaps_burn_and_propagate(
    index: int,
    marker: str,
    exception_type: type[BaseException],
) -> None:
    core, operation_request = _registered_core(index)
    next_sequence = core._next_request_sequence

    with pytest.raises(exception_type):
        _raise_from_function_line(
            TrustedTimeHeadAnchorWorkerCore._new_request,
            marker,
            lambda: core.take_work(observed_at_monotonic_ns=1),
            exception_type,
        )

    assert core._next_request_sequence == next_sequence + 1
    assert core._in_flight is None
    assert core._operation_bound_clean_stop_request is None
    assert core.fatal_error_latched is True
    assert core.take_work(observed_at_monotonic_ns=1) is None
    with pytest.raises(bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError):
        bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
            operation_request,
            core_identity=core,
            work_request_identity=object(),
            work_request_values=(
                next_sequence,
                TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
                False,
                False,
                1,
            ),
        )


@pytest.mark.parametrize(
    ("index", "marker", "exception_type"),
    [
        (
            43,
            "self._operation_bound_clean_stop_terminal_result = operation_bound_result",
            KeyboardInterrupt,
        ),
        (
            44,
            "self._operation_bound_clean_stop_terminal_result = operation_bound_result",
            SystemExit,
        ),
        (45, "self._retry_request = None", KeyboardInterrupt),
        (46, "self._retry_request = None", SystemExit),
    ],
)
def test_operation_bound_success_async_commit_gaps_burn_and_propagate(
    index: int,
    marker: str,
    exception_type: type[BaseException],
) -> None:
    core, operation_request = _registered_core(index)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)

    with pytest.raises(exception_type):
        _raise_from_function_line(
            TrustedTimeHeadAnchorWorkerCore._record_success_transition,
            marker,
            lambda: core.record_success(
                work_request,
                attempt,
                observed_at_monotonic_ns=1,
            ),
            exception_type,
        )

    assert core._in_flight is None
    assert core._operation_bound_clean_stop_request is None
    assert core._operation_bound_clean_stop_terminal_result is None
    assert core.clean_shutdown_completed is False
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            terminal,
            request_identity=work_request,
        )


@pytest.mark.parametrize(
    ("index", "marker", "exception_type"),
    [
        (51, "self._observe_monotonic(", KeyboardInterrupt),
        (52, "self._observe_monotonic(", SystemExit),
        (53, "terminal = result.clean_stop_terminal_result", KeyboardInterrupt),
        (54, "terminal = result.clean_stop_terminal_result", SystemExit),
        (55, "operation_bound_request = (", KeyboardInterrupt),
        (56, "operation_bound_request = (", SystemExit),
    ],
)
def test_operation_bound_success_outer_guard_covers_preconsume_async_gaps(
    index: int,
    marker: str,
    exception_type: type[BaseException],
) -> None:
    core, operation_request = _registered_core(index)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)

    with pytest.raises(exception_type):
        _raise_from_function_line(
            TrustedTimeHeadAnchorWorkerCore._record_success_transition,
            marker,
            lambda: core.record_success(
                work_request,
                attempt,
                observed_at_monotonic_ns=1,
            ),
            exception_type,
        )

    assert core._in_flight is None
    assert core._operation_bound_clean_stop_request is None
    assert core._operation_bound_clean_stop_work_request is None
    assert core._operation_bound_clean_stop_terminal_result is None
    assert core.clean_shutdown_completed is False
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None


def test_operation_bound_success_monotonic_regression_clears_every_association() -> None:
    core, operation_request = _registered_core(57)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)

    with pytest.raises(TrustedTimeHeadAnchorWorkerError):
        core.record_success(work_request, attempt, observed_at_monotonic_ns=0)

    assert core._in_flight is None
    assert core._operation_bound_clean_stop_request is None
    assert core._operation_bound_clean_stop_work_request is None
    assert core._operation_bound_clean_stop_terminal_result is None
    assert core.clean_shutdown_completed is False
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None


@pytest.mark.parametrize(
    ("index", "marker", "exception_type"),
    [
        (47, "if encoded is None or result is None", KeyboardInterrupt),
        (48, "if encoded is None or result is None", SystemExit),
        (49, "return encoded", KeyboardInterrupt),
        (50, "return encoded", SystemExit),
    ],
)
def test_operation_bound_take_async_commit_gaps_burn_and_propagate(
    index: int,
    marker: str,
    exception_type: type[BaseException],
) -> None:
    core, operation_request, _ = _issued_core(index)

    with pytest.raises(exception_type):
        _raise_from_function_line(
            TrustedTimeHeadAnchorWorkerCore._take_operation_bound_clean_stop_terminal_result_once,
            marker,
            lambda: core._take_operation_bound_clean_stop_terminal_result_once(operation_request),
            exception_type,
        )

    assert core._in_flight is None
    assert core._operation_bound_clean_stop_request is None
    assert core._operation_bound_clean_stop_terminal_result is None
    assert core.fatal_error_latched is True
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None


@pytest.mark.parametrize(
    ("index", "exception_type"),
    [(35, KeyboardInterrupt), (36, SystemExit)],
)
def test_terminal_validation_async_error_propagates_and_cleans_core(
    monkeypatch: pytest.MonkeyPatch,
    index: int,
    exception_type: type[BaseException],
) -> None:
    core, operation_request = _registered_core(index)
    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    terminal = _terminal_result(work_request)
    attempt = _clean_stop_attempt_result(work_request, terminal)
    real_result_values = clean_stop._result_values

    def interrupt(_: object) -> tuple[object, ...]:
        raise exception_type()

    monkeypatch.setattr(clean_stop, "_result_values", interrupt)
    with pytest.raises(exception_type):
        core.record_success(work_request, attempt, observed_at_monotonic_ns=1)
    monkeypatch.setattr(clean_stop, "_result_values", real_result_values)

    assert core.fatal_error_latched is True
    assert core._operation_bound_clean_stop_request is None
    assert core._take_operation_bound_clean_stop_terminal_result_once(operation_request) is None
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            terminal,
            request_identity=work_request,
        )
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            terminal,
            request_identity=work_request,
        )


def test_fork_rejects_before_an_inherited_held_registry_lock() -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    core, operation_request = _registered_core(15)
    read_descriptor, write_descriptor = os.pipe()
    bridge._REGISTRY_LOCK.acquire()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        signal.alarm(2)
        try:
            bridge._bind_trusted_time_head_anchor_operation_bound_clean_stop_work_request(
                operation_request,
                core_identity=core,
                work_request_identity=object(),
                work_request_values=(
                    2,
                    TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
                    False,
                    False,
                    1,
                ),
            )
        except bridge.TrustedTimeHeadAnchorCleanStopSupervisorBridgeError:
            os.write(write_descriptor, b"rejected")
        finally:
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    data = b""
    try:
        readable, _, _ = select.select((read_descriptor,), (), (), 3.0)
        if readable:
            data = os.read(read_descriptor, 16)
    finally:
        bridge._REGISTRY_LOCK.release()
        os.close(read_descriptor)
        os.waitpid(child_pid, 0)
    assert data == b"rejected"

    work_request = core.take_work(observed_at_monotonic_ns=1)
    assert work_request is not None
    core.record_transient_failure(work_request, observed_at_monotonic_ns=1)


def test_public_surface_has_no_runtime_effect_or_transport_api() -> None:
    assert set(bridge.__all__) == {
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
    }
