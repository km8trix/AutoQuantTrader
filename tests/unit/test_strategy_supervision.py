from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from packages.domain.market_batch import MarketBatch, MarketWatermark
from packages.domain.models import MarketEvent
from packages.domain.operational_control import OperationalControlState
from packages.domain.replay import replay_market_events
from packages.domain.strategy_supervision import (
    STRATEGY_DECISION_DEADLINE_MICROSECONDS,
    STRATEGY_FAILURE_PROTECTED_LOOPS,
    STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
    StrategyProtocolError,
    StrategyRuntimeBinding,
    StrategySupervisionError,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
    bind_strategy_invocation,
    decode_strategy_response,
    encode_strategy_request,
)

_CONFIGURATION_SHA256 = "a" * 64
_STATE_SHA256 = "b" * 64
_ARTIFACT_SHA256 = "c" * 64
_LAUNCH_SHA256 = "d" * 64


def _batch(*, complete: bool = True) -> MarketBatch:
    event_time = datetime(2026, 7, 27, 14, 30, tzinfo=UTC)
    available_at = event_time + timedelta(seconds=1)
    watermark = MarketWatermark(
        watermark_id="watermark-2026-07-27T14:30:00Z",
        event_time_through=event_time,
        closed_at=event_time + timedelta(seconds=2),
        expected_instrument_ids=("instrument-spy",),
    )
    events: tuple[MarketEvent, ...]
    if complete:
        events = (
            MarketEvent(
                event_id="event-spy-2026-07-27T14:30:00Z",
                instrument_id="instrument-spy",
                symbol="SPY",
                event_time=event_time,
                available_at=available_at,
                close_price=Decimal("632.1500000000"),
                source_sequence=7,
            ),
        )
    else:
        events = ()
    return replay_market_events(events=events, watermarks=(watermark,)).batches[0]


def _runtime(*, launch_sha256: str = _LAUNCH_SHA256) -> StrategyRuntimeBinding:
    return StrategyRuntimeBinding(
        runtime_id="cpython-isolated",
        runtime_version="3.12.11",
        artifact_sha256=_ARTIFACT_SHA256,
        launch_spec_sha256=launch_sha256,
    )


def _invocation(batch: MarketBatch | None = None) -> tuple[MarketBatch, object]:
    selected_batch = batch or _batch()
    invocation = bind_strategy_invocation(
        control_scope_id="paper-account-1",
        environment="paper",
        market_batch=selected_batch,
        strategy_id="equal-weight-etf",
        strategy_version="1.4.0",
        strategy_configuration_sha256=_CONFIGURATION_SHA256,
        input_state_sha256=_STATE_SHA256,
        runtime=_runtime(),
        requested_at=selected_batch.as_of + timedelta(microseconds=1),
    )
    return selected_batch, invocation


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _response_bytes(invocation: object, result: object) -> bytes:
    from packages.domain.strategy_supervision import StrategyInvocation

    assert type(invocation) is StrategyInvocation
    return _json_bytes(
        {
            "invocation_id": invocation.invocation_id,
            "invocation_sha256": invocation.semantic_sha256,
            "protocol_version": STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
            "result": result,
        }
    )


def test_invocation_identity_binds_batch_strategy_configuration_state_and_runtime() -> None:
    batch, invocation_object = _invocation()
    from packages.domain.strategy_supervision import StrategyInvocation

    assert type(invocation_object) is StrategyInvocation
    invocation = invocation_object
    same = replace(invocation)
    changed_state = replace(invocation, input_state_sha256="e" * 64)
    changed_runtime = replace(
        invocation,
        runtime=_runtime(launch_sha256="f" * 64),
    )

    assert same.invocation_id == invocation.invocation_id
    assert same.semantic_sha256 == invocation.semantic_sha256
    assert changed_state.invocation_id != invocation.invocation_id
    assert changed_runtime.invocation_id != invocation.invocation_id

    request = encode_strategy_request(invocation, batch)
    assert request == encode_strategy_request(invocation, batch)
    decoded = json.loads(request)
    assert decoded["market_batch"]["id"] == batch.batch_id
    assert decoded["market_batch"]["semantic_sha256"] == batch.semantic_sha256
    assert decoded["market_batch"]["events"][0]["close_price"] == "63215e-2"
    assert decoded["invocation"]["semantic_sha256"] == invocation.semantic_sha256

    with pytest.raises(FrozenInstanceError):
        invocation.strategy_version = "mutated"  # type: ignore[misc]


def test_invocation_refuses_an_incomplete_market_batch() -> None:
    incomplete = _batch(complete=False)

    with pytest.raises(
        StrategySupervisionError,
        match="watermark-complete",
    ):
        _invocation(incomplete)


def test_response_protocol_accepts_only_exact_identity_and_canonical_json() -> None:
    _, invocation_object = _invocation()
    from packages.domain.strategy_supervision import StrategyInvocation

    assert type(invocation_object) is StrategyInvocation
    invocation = invocation_object
    payload = _response_bytes(
        invocation,
        {"generation": 2, "target": ["DIA", "IWM", "QQQ", "SPY"]},
    )

    response = decode_strategy_response(payload + b"\n", invocation)

    assert response.invocation_id == invocation.invocation_id
    assert response.invocation_sha256 == invocation.semantic_sha256
    assert response.result_json == ('{"generation":2,"target":["DIA","IWM","QQQ","SPY"]}')
    assert response.result_sha256 == hashlib.sha256(response.result_json.encode()).hexdigest()


@pytest.mark.parametrize(
    "payload",
    (
        b"not-json",
        b'{"invocation_id":"duplicate","invocation_id":"again"}',
        b'{"invocation_id": "noncanonical"}',
        b'{"invocation_id":"x","invocation_sha256":"x",'
        b'"protocol_version":"phase5c-strategy-json-v1","result":1.5}',
    ),
)
def test_response_protocol_rejects_malformed_duplicate_or_inexact_json(
    payload: bytes,
) -> None:
    _, invocation = _invocation()

    with pytest.raises(StrategyProtocolError):
        decode_strategy_response(payload, invocation)  # type: ignore[arg-type]


def test_response_protocol_rejects_wrong_invocation_identity() -> None:
    _, invocation = _invocation()
    from packages.domain.strategy_supervision import StrategyInvocation

    assert type(invocation) is StrategyInvocation
    decoded = json.loads(_response_bytes(invocation, {"target": "ok"}))
    decoded["invocation_id"] = "wrong-invocation"

    with pytest.raises(StrategyProtocolError, match="wrong invocation ID"):
        decode_strategy_response(_json_bytes(decoded), invocation)


def _failed_result(
    outcome: StrategySupervisionOutcome,
) -> StrategySupervisionResult:
    _, invocation = _invocation()
    from packages.domain.strategy_supervision import StrategyInvocation

    assert type(invocation) is StrategyInvocation
    started_at = invocation.requested_at
    elapsed = (
        STRATEGY_DECISION_DEADLINE_MICROSECONDS
        if outcome is StrategySupervisionOutcome.TIMEOUT
        else 10
    )
    process_started = outcome is not StrategySupervisionOutcome.RESOURCE_EXCEEDED
    exit_code = (
        7 if outcome is StrategySupervisionOutcome.CRASH else (0 if process_started else None)
    )
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    return StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=outcome,
        started_at=started_at,
        completed_at=started_at + timedelta(microseconds=elapsed),
        elapsed_microseconds=elapsed,
        process_started=process_started,
        exit_code=exit_code,
        stdout_bytes=0,
        stdout_sha256=empty_sha256,
        stderr_bytes=0,
        stderr_sha256=empty_sha256,
        detail_code=f"test_{outcome.value}",
    )


@pytest.mark.parametrize(
    "outcome",
    (
        StrategySupervisionOutcome.TIMEOUT,
        StrategySupervisionOutcome.CRASH,
        StrategySupervisionOutcome.PROTOCOL_ERROR,
        StrategySupervisionOutcome.RESOURCE_EXCEEDED,
    ),
)
def test_every_failure_only_requests_paused_and_preserves_runtime_loops(
    outcome: StrategySupervisionOutcome,
) -> None:
    result = _failed_result(outcome)

    assert result.blocks_new_exposure is True
    assert result.requested_control_state is OperationalControlState.PAUSED
    assert result.protected_runtime_loops == STRATEGY_FAILURE_PROTECTED_LOOPS
    assert result.automatic_resume_authorized is False


def test_later_success_never_requests_running_or_automatic_resume() -> None:
    prior_timeout = _failed_result(StrategySupervisionOutcome.TIMEOUT)
    _, invocation = _invocation()
    from packages.domain.strategy_supervision import StrategyInvocation

    assert type(invocation) is StrategyInvocation
    payload = _response_bytes(invocation, {"target": "ok"})
    response = decode_strategy_response(payload, invocation)
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    success = StrategySupervisionResult(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        outcome=StrategySupervisionOutcome.COMPLETED,
        started_at=invocation.requested_at,
        completed_at=invocation.requested_at + timedelta(microseconds=100),
        elapsed_microseconds=100,
        process_started=True,
        exit_code=0,
        stdout_bytes=len(payload),
        stdout_sha256=payload_sha256,
        stderr_bytes=0,
        stderr_sha256=empty_sha256,
        detail_code="completed",
        response=response,
    )

    assert prior_timeout.requested_control_state is OperationalControlState.PAUSED
    assert success.requested_control_state is None
    assert success.blocks_new_exposure is False
    assert success.automatic_resume_authorized is False
    assert OperationalControlState.RUNNING not in {
        prior_timeout.requested_control_state,
        success.requested_control_state,
    }
