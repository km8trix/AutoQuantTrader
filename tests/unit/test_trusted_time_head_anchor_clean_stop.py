from __future__ import annotations

import copy
import os
import pickle
from dataclasses import fields, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from packages.application import trusted_time_head_anchor_clean_stop as clean_stop
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)

BASE = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _values(*, request_identity: object | None = None) -> dict[str, object]:
    return {
        "request_identity": object() if request_identity is None else request_identity,
        "request_sequence": 7,
        "request_scheduled_monotonic_ns": 123,
        "anchor_sequence": 3,
        "checkpoint_reason": TrustedTimeHeadAnchorCheckpointReason.CLEAN_STOP,
        "confirmed_anchor_count": 3,
        "local_transition_count": 4,
        "confirmed_anchor_local_transition_ordinal": 4,
        "predecessor_anchor_sha256": "1" * 64,
        "current_host_head_sha256": "2" * 64,
        "current_anchor_sha256": "3" * 64,
        "current_anchor_semantic_sha256": "4" * 64,
        "receipt_observed_at_utc": BASE,
        "full_audit_completed": False,
        "prior_pending_intent_recovered": True,
        "uploaded_anchor_count": 1,
        "idempotent_duplicate_count": 0,
        "current_anchor_intent_semantic_sha256": "5" * 64,
        "current_candidate_remote_readback_sha256": "3" * 64,
        "current_receipt_semantic_sha256": "6" * 64,
    }


def _result(
    *,
    request_identity: object | None = None,
) -> clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult:
    return clean_stop._issue_trusted_time_head_anchor_clean_stop_terminal_result(
        **_values(request_identity=request_identity)  # type: ignore[arg-type]
    )


def test_exact_new_record_result_is_sealed_digest_evidence_only() -> None:
    result = _result()

    result.__post_init__()
    assert result.request_sequence == 7
    assert result.request_scheduled_monotonic_ns == 123
    assert result.anchor_sequence == result.confirmed_anchor_count == 3
    assert result.confirmed_anchor_local_transition_ordinal == result.local_transition_count == 4
    assert result.current_candidate_remote_readback_sha256 == result.current_anchor_sha256
    assert result.uploaded_anchor_count + result.idempotent_duplicate_count == 1
    assert len(result.semantic_sha256) == 64
    assert result.semantic_sha256 == _result().semantic_sha256
    for field_name in (
        "authority_granted",
        "provider_terminal_authenticated",
        "provider_terminal_currentness_authenticated",
        "no_new_record_authenticated",
        "no_new_record_success",
        "durability_authenticated",
        "durable_stop_outcome_authenticated",
        "stop_outcome_retained",
        "slot_authorized",
        "admission_authorized",
        "signal_authorized",
        "graceful_stop_authorized",
        "shutdown_authorized",
        "teardown_authorized",
        "effect_authorized",
        "operational_control_authorized",
        "readiness_authorized",
        "arming_authorized",
        "new_exposure_authorized",
        "broker_action_authorized",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "alert_delivery_authorized",
        "exposure_authorized",
        "paper_trading_authorized",
        "live_trading_authorized",
    ):
        assert getattr(result, field_name) is False


@pytest.mark.parametrize(
    ("field_name", "invalid"),
    [
        ("request_sequence", True),
        ("request_scheduled_monotonic_ns", -1),
        ("anchor_sequence", 2),
        ("checkpoint_reason", TrustedTimeHeadAnchorCheckpointReason.PERIODIC),
        ("confirmed_anchor_count", 4),
        ("confirmed_anchor_local_transition_ordinal", 3),
        ("predecessor_anchor_sha256", None),
        ("current_candidate_remote_readback_sha256", "7" * 64),
        ("receipt_observed_at_utc", datetime(2026, 8, 1, 12, 0)),
        ("full_audit_completed", 1),
        ("prior_pending_intent_recovered", 0),
        ("uploaded_anchor_count", 0),
        ("idempotent_duplicate_count", 1),
    ],
)
def test_issuer_rejects_partial_or_non_current_completion_facts(
    field_name: str,
    invalid: object,
) -> None:
    values = _values()
    values[field_name] = invalid

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._issue_trusted_time_head_anchor_clean_stop_terminal_result(
            **values  # type: ignore[arg-type]
        )


def test_direct_construction_copy_replace_pickle_and_forged_clone_are_rejected() -> None:
    result = _result()

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult()
    for operation in (
        lambda: copy.copy(result),
        lambda: copy.deepcopy(result),
        lambda: replace(result),
        lambda: pickle.dumps(result),
    ):
        with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
            operation()

    forged = object.__new__(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResult)
    for result_field in fields(result):
        object.__setattr__(forged, result_field.name, getattr(result, result_field.name))
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        forged.__post_init__()
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        _ = forged.semantic_sha256


def test_object_drift_is_rejected_on_revalidation_and_semantic_access() -> None:
    result = _result()
    object.__setattr__(result, "request_sequence", result.request_sequence + 1)

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        result.__post_init__()
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        _ = result.semantic_sha256


def test_one_shot_consumer_burns_a_wrong_identity_and_accepts_one_fresh_exact_identity() -> None:
    request_identity = object()
    same_scalar_foreign_request = object()
    result = _result(request_identity=request_identity)

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            result,
            request_identity=same_scalar_foreign_request,
        )
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            result,
            request_identity=request_identity,
        )

    fresh = _result(request_identity=request_identity)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        fresh,
        request_identity=request_identity,
    )
    fresh.__post_init__()
    assert len(fresh.semantic_sha256) == 64
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            fresh,
            request_identity=request_identity,
        )


def test_bridge_export_before_worker_consume_burns_the_result() -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            result,
            request_identity=request_identity,
        )


@pytest.mark.parametrize("foreign_identity", [None, object()])
def test_wrong_bridge_export_identity_burns_before_retry(
    foreign_identity: object | None,
) -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        result,
        request_identity=request_identity,
    )

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=foreign_identity,
        )
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )


def test_bridge_export_mutation_burns_even_after_the_value_is_restored() -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        result,
        request_identity=request_identity,
    )
    original_sequence = result.request_sequence
    object.__setattr__(result, "request_sequence", original_sequence + 1)

    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )
    object.__setattr__(result, "request_sequence", original_sequence)
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )


def test_bridge_export_async_interrupt_propagates_after_burn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        result,
        request_identity=request_identity,
    )
    real_result_values = clean_stop._result_values

    def interrupt(_: object) -> tuple[object, ...]:
        raise KeyboardInterrupt

    monkeypatch.setattr(clean_stop, "_result_values", interrupt)
    with pytest.raises(KeyboardInterrupt):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )
    monkeypatch.setattr(clean_stop, "_result_values", real_result_values)
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
def test_registered_validation_async_error_propagates_after_burn(
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    real_result_values = clean_stop._result_values

    def interrupt(_: object) -> tuple[object, ...]:
        raise exception_type()

    monkeypatch.setattr(clean_stop, "_result_values", interrupt)
    with pytest.raises(exception_type):
        result.__post_init__()
    monkeypatch.setattr(clean_stop, "_result_values", real_result_values)
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        result.__post_init__()
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            result,
            request_identity=request_identity,
        )


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
def test_worker_consume_async_error_propagates_after_burn(
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    real_result_values = clean_stop._result_values

    def interrupt(_: object) -> tuple[object, ...]:
        raise exception_type()

    monkeypatch.setattr(clean_stop, "_result_values", interrupt)
    with pytest.raises(exception_type):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            result,
            request_identity=request_identity,
        )
    monkeypatch.setattr(clean_stop, "_result_values", real_result_values)
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
            result,
            request_identity=request_identity,
        )
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )


def test_bridge_export_is_one_shot_and_success_remains_inspectable() -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        result,
        request_identity=request_identity,
    )

    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
        result,
        request_identity=request_identity,
    )
    result.__post_init__()
    assert len(result.semantic_sha256) == 64
    with pytest.raises(clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError):
        clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(
            result,
            request_identity=request_identity,
        )


def test_bridge_export_returns_the_immutable_registered_projection() -> None:
    request_identity = object()
    result = _result(request_identity=request_identity)
    expected_values = clean_stop._result_values(result)
    expected_semantic_sha256 = result.semantic_sha256
    clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result(
        result,
        request_identity=request_identity,
    )

    projection = clean_stop._consume_trusted_time_head_anchor_clean_stop_terminal_result_for_supervisor_bridge(  # noqa: E501
        result,
        request_identity=request_identity,
    )
    object.__setattr__(result, "current_host_head_sha256", "f" * 64)

    assert projection == (expected_values, expected_semantic_sha256)


def test_result_is_invalid_in_a_forked_child() -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    result = _result()
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        rejected = 0
        for operation in (result.__post_init__, lambda: result.semantic_sha256):
            try:
                operation()
            except clean_stop.TrustedTimeHeadAnchorCleanStopTerminalResultError:
                rejected += 1
        try:
            os.write(write_descriptor, b"rejected" if rejected == 2 else b"accepted")
        finally:
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 16) == b"rejected"
    finally:
        os.close(read_descriptor)
        os.waitpid(child_pid, 0)


def test_public_surface_has_no_issuer_consumer_or_effect_contract() -> None:
    assert set(clean_stop.__all__) == {
        "TRUSTED_TIME_HEAD_ANCHOR_CLEAN_STOP_TERMINAL_RESULT_CONTRACT_VERSION",
        "TrustedTimeHeadAnchorCleanStopTerminalResult",
        "TrustedTimeHeadAnchorCleanStopTerminalResultError",
    }
    source = Path(clean_stop.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "signal.",
        "docker",
        "slot_path",
        "outcome_path",
        "no_new_record_disposition",
    ):
        assert forbidden not in source.lower()
