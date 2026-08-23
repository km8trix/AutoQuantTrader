from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from packages.application.supervised_strategy import (
    ConfiguredSupervisedStrategyRunner,
    StrategySubprocessError,
    StrategySubprocessSpec,
    _finish_process,
    run_supervised_strategy,
)
from packages.domain.account_coordinator import AccountFence, _account_fence_receipt
from packages.domain.market_batch import MarketBatch, MarketWatermark
from packages.domain.models import MarketEvent
from packages.domain.operational_control import OperationalControlState
from packages.domain.replay import replay_market_events
from packages.domain.strategy_invocation_lifecycle import (
    STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    StrategyInvocationClaim,
    StrategyInvocationLifecycleConflict,
    StrategyInvocationStartAuthorization,
    _strategy_invocation_start_authorization,
)
from packages.domain.strategy_supervision import (
    MAX_STRATEGY_STDOUT_BYTES,
    STRATEGY_DECISION_DEADLINE_MICROSECONDS,
    STRATEGY_FAILURE_PROTECTED_LOOPS,
    STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS,
    STRATEGY_SUBPROCESS_PROTOCOL_VERSION,
    StrategyInvocation,
    StrategySupervisionOutcome,
    bind_strategy_invocation,
)
from packages.persistence.strategy_invocation_lifecycle import (
    _StrategyInvocationStartAuthorizationUse,
)

_CONFIGURATION_SHA256 = "a" * 64
_STATE_SHA256 = "b" * 64
_ARTIFACT_SHA256 = "c" * 64


def _base_python_executable() -> str:
    candidate = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    assert candidate.is_file()
    assert not candidate.is_symlink()
    return str(candidate)


def _batch() -> MarketBatch:
    event_time = datetime(2026, 7, 27, 14, 30, tzinfo=UTC)
    watermark = MarketWatermark(
        watermark_id="supervised-watermark",
        event_time_through=event_time,
        closed_at=event_time + timedelta(seconds=2),
        expected_instrument_ids=("instrument-spy",),
    )
    event = MarketEvent(
        event_id="supervised-event-spy",
        instrument_id="instrument-spy",
        symbol="SPY",
        event_time=event_time,
        available_at=event_time + timedelta(seconds=1),
        close_price=Decimal("632.15"),
        source_sequence=1,
    )
    return replay_market_events(events=(event,), watermarks=(watermark,)).batches[0]


def _large_batch() -> MarketBatch:
    event_time = datetime(2026, 7, 27, 14, 30, tzinfo=UTC)
    instrument_ids = tuple(f"instrument-{index:05d}" for index in range(5_000))
    watermark = MarketWatermark(
        watermark_id="oversized-supervised-watermark",
        event_time_through=event_time,
        closed_at=event_time + timedelta(seconds=2),
        expected_instrument_ids=instrument_ids,
    )
    events = tuple(
        MarketEvent(
            event_id=f"oversized-event-{index:05d}",
            instrument_id=instrument_id,
            symbol=f"S{index:05d}",
            event_time=event_time,
            available_at=event_time + timedelta(seconds=1),
            close_price=Decimal("1"),
            source_sequence=index,
        )
        for index, instrument_id in enumerate(instrument_ids)
    )
    return replay_market_events(events=events, watermarks=(watermark,)).batches[0]


def _spec(script: str, *, executable: str | None = None) -> StrategySubprocessSpec:
    resolved_executable = _base_python_executable() if executable is None else executable
    return StrategySubprocessSpec(
        argv=(resolved_executable, "-c", script),
        runtime_id="test-cpython",
        runtime_version=f"{sys.version_info.major}.{sys.version_info.minor}",
        artifact_sha256=_ARTIFACT_SHA256,
    )


def _invocation(
    *,
    batch: MarketBatch,
    spec: StrategySubprocessSpec,
) -> StrategyInvocation:
    return bind_strategy_invocation(
        control_scope_id="paper-account-1",
        environment="paper",
        market_batch=batch,
        strategy_id="supervised-test-strategy",
        strategy_version="1.0.0",
        strategy_configuration_sha256=_CONFIGURATION_SHA256,
        input_state_sha256=_STATE_SHA256,
        runtime=spec.runtime_binding,
        requested_at=batch.as_of + timedelta(microseconds=1),
    )


def _sequence_clock(values: tuple[float, ...]) -> Callable[[], float]:
    if not values:
        raise ValueError("test monotonic sequence must not be empty")
    index = 0

    def read() -> float:
        nonlocal index
        value = values[min(index, len(values) - 1)]
        index += 1
        return value

    return read


def _sequence_utc_clock(
    values: tuple[datetime, ...],
) -> Callable[[], datetime]:
    remaining = iter(values)

    def read() -> datetime:
        return next(remaining)

    return read


def _start_authorization(
    *,
    claim: StrategyInvocationClaim,
    fence: AccountFence,
    authorized_at: datetime,
) -> StrategyInvocationStartAuthorization:
    issuer_identity = object()
    capability = object()
    return _strategy_invocation_start_authorization(
        claim,
        fence_receipt=_account_fence_receipt(
            fence=fence,
            validated_at=authorized_at,
            valid_until=claim.fence_receipt.valid_until,
            policy_sha256=claim.fence_receipt.policy_sha256,
            lease_sha256=claim.fence_receipt.lease_sha256,
        ),
        issuer_identity=issuer_identity,
        capability_nonce=capability,
        use=_StrategyInvocationStartAuthorizationUse(
            issuer_identity=issuer_identity,
            capability_nonce=capability,
        ),
    )


def _fresh_start_authorization(
    invocation: StrategyInvocation,
    *,
    claimed_at: datetime | None = None,
) -> tuple[StrategyInvocationStartAuthorization, Callable[[], datetime]]:
    if claimed_at is None:
        claimed_at = invocation.requested_at + timedelta(milliseconds=1)
    fence = AccountFence(
        account_id=invocation.control_scope_id,
        owner_id="supervised-test-worker",
        lease_id="supervised-test-lease",
        fencing_generation=1,
    )
    claim = StrategyInvocationClaim(
        invocation=invocation,
        fence_receipt=_account_fence_receipt(
            fence=fence,
            validated_at=claimed_at,
            valid_until=claimed_at + timedelta(minutes=1),
            policy_sha256="d" * 64,
            lease_sha256="e" * 64,
        ),
        recoverable_at=claimed_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    )
    authorization = _start_authorization(
        claim=claim,
        fence=fence,
        authorized_at=claimed_at,
    )
    current = claimed_at

    def utc_clock() -> datetime:
        nonlocal current
        value = current
        current += timedelta(microseconds=1)
        return value

    return authorization, utc_clock


@dataclass(slots=True)
class _AdvancingClock:
    value: float = 0.0

    def __call__(self) -> float:
        return self.value


@dataclass(slots=True)
class _BlockingThread:
    clock: _AdvancingClock

    def join(self, timeout: float | None = None) -> None:
        if timeout is not None:
            self.clock.value += timeout

    def is_alive(self) -> bool:
        return True


class _ExitedProcess:
    stdin: None = None
    stdout: None = None
    stderr: None = None

    @staticmethod
    def poll() -> int:
        return 0

    @staticmethod
    def wait(timeout: float | None = None) -> int:
        del timeout
        return 0


def test_success_uses_canonical_protocol_and_a_sanitized_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOQUANT_TEST_SECRET", "must-not-reach-child")
    script = """
import json
import os
import sys
request = json.loads(sys.stdin.buffer.read())
response = {
    "invocation_id": request["invocation"]["id"],
    "invocation_sha256": request["invocation"]["semantic_sha256"],
    "protocol_version": request["protocol_version"],
    "result": {
        "batch_id": request["market_batch"]["id"],
        "leaked": os.environ.get("AUTOQUANT_TEST_SECRET"),
    },
}
sys.stdout.write(json.dumps(response, ensure_ascii=True, allow_nan=False,
                            sort_keys=True, separators=(",", ":")))
"""
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.outcome is StrategySupervisionOutcome.COMPLETED
    assert result.response is not None
    assert json.loads(result.response.result_json) == {
        "batch_id": batch.batch_id,
        "leaked": None,
    }
    assert result.requested_control_state is None
    assert result.automatic_resume_authorized is False
    assert result.exit_code == 0


def test_nonzero_child_exit_is_a_crash_that_only_requests_paused() -> None:
    script = "import sys; sys.stdin.buffer.read(); sys.stderr.write('failed'); sys.exit(7)"
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.outcome is StrategySupervisionOutcome.CRASH
    assert result.exit_code == 7
    assert result.requested_control_state is OperationalControlState.PAUSED
    assert result.protected_runtime_loops == STRATEGY_FAILURE_PROTECTED_LOOPS
    assert result.automatic_resume_authorized is False


def test_malformed_child_response_is_a_protocol_error() -> None:
    script = "import sys; sys.stdin.buffer.read(); sys.stdout.write('not-json')"
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.outcome is StrategySupervisionOutcome.PROTOCOL_ERROR
    assert result.exit_code == 0
    assert result.requested_control_state is OperationalControlState.PAUSED
    assert result.response is None


def test_oversized_stdout_kills_only_the_child_and_requests_paused() -> None:
    script = (
        "import os,sys; sys.stdin.buffer.read(); "
        f"os.write(1, b'x' * {MAX_STRATEGY_STDOUT_BYTES + 1})"
    )
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.outcome is StrategySupervisionOutcome.RESOURCE_EXCEEDED
    assert result.stdout_bytes == MAX_STRATEGY_STDOUT_BYTES + 1
    assert result.requested_control_state is OperationalControlState.PAUSED
    assert result.protected_runtime_loops == STRATEGY_FAILURE_PROTECTED_LOOPS


def test_oversized_request_is_rejected_before_process_creation() -> None:
    batch = _large_batch()
    spec = _spec(
        "raise AssertionError('must not execute')",
        executable="/definitely/not/a/real/strategy-runtime",
    )
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.outcome is StrategySupervisionOutcome.RESOURCE_EXCEEDED
    assert result.detail_code == "request_too_large"
    assert result.process_started is False
    assert result.exit_code is None
    assert result.requested_control_state is OperationalControlState.PAUSED


def test_hard_deadline_kills_child_at_equality_without_auto_resume() -> None:
    script = "import sys,time; sys.stdin.buffer.read(); time.sleep(60)"
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    started_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    authorization, _ = _fresh_start_authorization(
        invocation,
        claimed_at=started_at,
    )

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        monotonic_clock=_sequence_clock((100.0, 105.0, 105.0)),
        utc_clock=_sequence_utc_clock((started_at, started_at + timedelta(seconds=5))),
        sleeper=lambda _seconds: None,
    )

    assert result.outcome is StrategySupervisionOutcome.TIMEOUT
    assert result.elapsed_microseconds == STRATEGY_DECISION_DEADLINE_MICROSECONDS
    assert result.warning_threshold_exceeded is True
    assert result.requested_control_state is OperationalControlState.PAUSED
    assert result.automatic_resume_authorized is False
    assert result.process_started is True
    assert result.exit_code is not None


def test_runtime_binding_mismatch_fails_before_child_creation() -> None:
    batch = _batch()
    first_spec = _spec("raise AssertionError('must not execute')")
    invocation = _invocation(batch=batch, spec=first_spec)
    second_spec = _spec("raise AssertionError('different launch')")
    authorization, _ = _fresh_start_authorization(invocation)

    with pytest.raises(ValueError, match="not bound"):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=second_spec,
            start_authorization=authorization,
        )


def test_protocol_version_is_fixed_in_child_request() -> None:
    script = """
import json
import sys
request = json.loads(sys.stdin.buffer.read())
response = {
    "invocation_id": request["invocation"]["id"],
    "invocation_sha256": request["invocation"]["semantic_sha256"],
    "protocol_version": request["protocol_version"],
    "result": request["protocol_version"],
}
sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")))
"""
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.response is not None
    assert json.loads(result.response.result_json) == STRATEGY_SUBPROCESS_PROTOCOL_VERSION


def test_process_cleanup_uses_one_aggregate_three_second_budget() -> None:
    clock = _AdvancingClock()
    threads = tuple(_BlockingThread(clock) for _ in range(3))

    with pytest.raises(
        StrategySubprocessError,
        match="cleanup",
    ):
        _finish_process(
            cast(Any, _ExitedProcess()),
            cast(Any, threads),
            kill=False,
            cleanup_deadline=(STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS / 1_000_000),
            monotonic_clock=clock,
        )

    assert clock.value == STRATEGY_SUBPROCESS_CLEANUP_MICROSECONDS / 1_000_000


def test_process_cleanup_uses_only_the_remaining_absolute_runner_budget() -> None:
    clock = _AdvancingClock(value=7.5)
    threads = (_BlockingThread(clock),)

    with pytest.raises(
        StrategySubprocessError,
        match="cleanup",
    ):
        _finish_process(
            cast(Any, _ExitedProcess()),
            cast(Any, threads),
            kill=False,
            cleanup_deadline=8.0,
            monotonic_clock=clock,
        )

    assert clock.value == 8.0


def test_configured_runner_requires_and_forwards_sealed_authorization() -> None:
    script = """
import json
import sys
request = json.loads(sys.stdin.buffer.read())
response = {
    "invocation_id": request["invocation"]["id"],
    "invocation_sha256": request["invocation"]["semantic_sha256"],
    "protocol_version": request["protocol_version"],
    "result": {"adapter": "configured"},
}
sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")))
"""
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)
    runner = ConfiguredSupervisedStrategyRunner(
        subprocess_spec=spec,
        utc_clock=utc_clock,
    )

    result = runner.run(
        invocation=invocation,
        market_batch=batch,
        start_authorization=authorization,
    )

    assert result.outcome is StrategySupervisionOutcome.COMPLETED
    assert result.response is not None
    assert json.loads(result.response.result_json) == {"adapter": "configured"}


def test_start_authorization_is_one_shot_before_process_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = """
import json
import sys
request = json.loads(sys.stdin.buffer.read())
response = {
    "invocation_id": request["invocation"]["id"],
    "invocation_sha256": request["invocation"]["semantic_sha256"],
    "protocol_version": request["protocol_version"],
    "result": {"adapter": "one-shot"},
}
sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")))
"""
    batch = _batch()
    spec = _spec(script)
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)

    first = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )
    assert first.outcome is StrategySupervisionOutcome.COMPLETED

    popen_called = False

    def fail_if_spawned(*_args: object, **_kwargs: object) -> Any:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("replayed authorization must not reach Popen")

    monkeypatch.setattr(
        "packages.application.supervised_strategy.subprocess.Popen",
        fail_if_spawned,
    )
    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="already consumed",
    ):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=spec,
            start_authorization=authorization,
            utc_clock=utc_clock,
        )

    assert popen_called is False


def test_start_authorization_is_bound_to_the_issuing_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = _batch()
    spec = _spec("raise AssertionError('must not execute')")
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)
    popen_called = False

    def fail_if_spawned(*_args: object, **_kwargs: object) -> Any:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("foreign-process authorization must not reach Popen")

    monkeypatch.setattr(
        "packages.application.supervised_strategy.subprocess.Popen",
        fail_if_spawned,
    )
    monkeypatch.setattr(
        "packages.persistence.strategy_invocation_lifecycle.os.getpid",
        lambda: -1,
    )

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="another repository process",
    ):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=spec,
            start_authorization=authorization,
            utc_clock=utc_clock,
        )

    assert popen_called is False


def test_start_authorization_is_consumed_before_fallible_request_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = _batch()
    spec = _spec("raise AssertionError('must not execute')")
    invocation = _invocation(batch=batch, spec=spec)
    authorization, utc_clock = _fresh_start_authorization(invocation)
    encode_calls = 0

    def interrupted_encoding(
        supplied_invocation: StrategyInvocation,
        supplied_batch: MarketBatch,
    ) -> bytes:
        nonlocal encode_calls
        assert supplied_invocation == invocation
        assert supplied_batch == batch
        encode_calls += 1
        raise RuntimeError("injected request-preparation interruption")

    monkeypatch.setattr(
        "packages.application.supervised_strategy.encode_strategy_request",
        interrupted_encoding,
    )

    with pytest.raises(
        RuntimeError,
        match="request-preparation interruption",
    ):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=spec,
            start_authorization=authorization,
            utc_clock=utc_clock,
        )
    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="already consumed",
    ):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=spec,
            start_authorization=authorization,
            utc_clock=utc_clock,
        )

    assert encode_calls == 1


def test_expired_start_authorization_fails_before_process_creation() -> None:
    batch = _batch()
    spec = _spec(
        "raise AssertionError('must not execute')",
        executable="/definitely/not/a/real/strategy-runtime",
    )
    invocation = _invocation(batch=batch, spec=spec)
    claimed_at = invocation.requested_at + timedelta(microseconds=1)
    fence = AccountFence(
        account_id=invocation.control_scope_id,
        owner_id="supervised-test-worker",
        lease_id="supervised-test-lease",
        fencing_generation=1,
    )
    valid_until = claimed_at + timedelta(minutes=1)
    claim = StrategyInvocationClaim(
        invocation=invocation,
        fence_receipt=_account_fence_receipt(
            fence=fence,
            validated_at=claimed_at,
            valid_until=valid_until,
            policy_sha256="d" * 64,
            lease_sha256="e" * 64,
        ),
        recoverable_at=claimed_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    )
    authorization = _start_authorization(
        claim=claim,
        fence=fence,
        authorized_at=claimed_at + timedelta(microseconds=1),
    )

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="fresh authorization window",
    ):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=spec,
            start_authorization=authorization,
            monotonic_clock=_sequence_clock((1.0,)),
            utc_clock=_sequence_utc_clock((claim.recoverable_at,)),
        )


@pytest.mark.parametrize(
    "expiry_boundary",
    ("start_deadline", "recovery"),
)
def test_encoding_cannot_consume_start_authorization_window(
    monkeypatch: pytest.MonkeyPatch,
    expiry_boundary: str,
) -> None:
    batch = _batch()
    spec = _spec("raise AssertionError('must not execute')")
    invocation = _invocation(batch=batch, spec=spec)
    claimed_at = invocation.requested_at + timedelta(microseconds=1)
    fence = AccountFence(
        account_id=invocation.control_scope_id,
        owner_id="supervised-test-worker",
        lease_id="supervised-test-lease",
        fencing_generation=1,
    )
    valid_until = claimed_at + timedelta(minutes=1)
    claim = StrategyInvocationClaim(
        invocation=invocation,
        fence_receipt=_account_fence_receipt(
            fence=fence,
            validated_at=claimed_at,
            valid_until=valid_until,
            policy_sha256="d" * 64,
            lease_sha256="e" * 64,
        ),
        recoverable_at=claimed_at + STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    )
    authorization = _start_authorization(
        claim=claim,
        fence=fence,
        authorized_at=claimed_at + timedelta(microseconds=1),
    )
    current_utc = authorization.authorized_at
    popen_called = False

    def encode_and_advance(
        supplied_invocation: StrategyInvocation,
        supplied_batch: MarketBatch,
    ) -> bytes:
        nonlocal current_utc
        assert supplied_invocation == invocation
        assert supplied_batch == batch
        current_utc = (
            claim.start_deadline_at if expiry_boundary == "start_deadline" else claim.recoverable_at
        )
        return b"{}"

    def fail_if_spawned(*_args: object, **_kwargs: object) -> Any:
        nonlocal popen_called
        popen_called = True
        raise AssertionError("expired authorization must not reach Popen")

    monkeypatch.setattr(
        "packages.application.supervised_strategy.encode_strategy_request",
        encode_and_advance,
    )
    monkeypatch.setattr(
        "packages.application.supervised_strategy.subprocess.Popen",
        fail_if_spawned,
    )

    with pytest.raises(
        StrategyInvocationLifecycleConflict,
        match="fresh authorization window",
    ):
        run_supervised_strategy(
            invocation=invocation,
            market_batch=batch,
            subprocess_spec=spec,
            start_authorization=authorization,
            monotonic_clock=_sequence_clock((1.0,)),
            utc_clock=lambda: current_utc,
        )

    assert popen_called is False
