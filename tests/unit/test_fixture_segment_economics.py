from __future__ import annotations

import inspect
import json
import os
import subprocess
import time
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from subprocess import Popen as ProcessType
from typing import Any, cast

import pytest

import packages.application.fixture_segment_economics as economic_application
from packages.application.fixture_segment_economics import (
    FIXTURE_ECONOMIC_ENVIRONMENT,
    FixtureEconomicExecutionError,
    _RawProcessObservation,
    _run_fixture_economic_child,
    decode_fixture_economic_response,
    encode_fixture_economic_request,
    execute_fixture_segment_economics,
)
from packages.domain.experiment_governance import GovernedSegmentEvaluationReceipt
from packages.domain.feature_target import CertifiedFeatureTargetReplay
from packages.domain.fixture_segment_economics import (
    FIXTURE_ECONOMIC_STARTING_CASH,
    MAX_FIXTURE_ECONOMIC_REQUEST_BYTES,
    FixtureEconomicProcessEvidence,
    FixtureEconomicProcessOutcome,
    FixtureEconomicSegmentError,
    FixtureEconomicSegmentReceipt,
    bind_fixture_economic_request,
    evaluate_fixture_economic_request,
)
from packages.domain.fixture_segment_worker import (
    FixtureSegmentJobProjection,
    FixtureTranscriptArtifact,
    complete_fixture_segment_job,
)
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _target_certification,
)
from tests.unit.test_fixture_segment_worker import _running


def _completed() -> tuple[
    GovernanceFixture,
    FixtureSegmentJobProjection,
    CertifiedFeatureTargetReplay,
]:
    fixture, governed, feature_certification, running = _running()
    token = running.claim_token
    assert token is not None
    target_certification = _target_certification(feature_certification, fixture.configuration)
    completed_governance = governed.complete_attempt(
        running.job.attempt_id,
        target_certification,
        completed_at=FIRST_ATTEMPT_AT + timedelta(minutes=2),
        actor_id=running.job.governed_actor_id,
    )
    completed_event = completed_governance.latest_event(running.job.attempt_id)
    receipt = completed_event.terminal_evidence
    assert isinstance(receipt, GovernedSegmentEvaluationReceipt)
    target_artifact = FixtureTranscriptArtifact.from_target_certification(
        family=fixture.family,
        attempt=governed.attempts[-1],
        source_evidence=fixture.family.validation_evidence,
        certification=target_certification,
    )
    completed = complete_fixture_segment_job(
        running,
        token,
        target_artifact=target_artifact,
        receipt=receipt,
        governance_completed_event=completed_event,
        completed_at=completed_event.occurred_at,
    )
    return fixture, completed, target_certification


def _failure_observation(outcome: FixtureEconomicProcessOutcome) -> _RawProcessObservation:
    return _RawProcessObservation(
        outcome=outcome,
        process_started=True,
        exit_code=-9,
        elapsed_microseconds=1,
        stdout=b"",
        stderr=b"material-that-must-not-reach-the-error",
        runtime_artifact_sha256="1" * 64,
        launch_spec_sha256="2" * 64,
    )


def test_request_cross_binds_exact_completed_phase3f_governance_root() -> None:
    _fixture, completed, target_certification = _completed()

    request = bind_fixture_economic_request(completed, target_certification)

    assert request.job_id == completed.job.job_id
    assert request.attempt_id == completed.job.attempt_id
    assert request.completion_receipt_sha256 == completed.latest.completion_receipt_sha256
    assert completed.target_artifact is not None
    assert request.target_artifact_sha256 == completed.target_artifact.artifact_sha256
    assert request.target_certification_sha256 == target_certification.semantic_sha256
    assert request.starting_cash == FIXTURE_ECONOMIC_STARTING_CASH
    assert request.target_count == 2


def test_noncompleted_or_substituted_target_evidence_fails_closed() -> None:
    fixture, _governed, feature_certification, running = _running()
    target = _target_certification(feature_certification, fixture.configuration)
    with pytest.raises(FixtureEconomicSegmentError, match="completed authenticated"):
        bind_fixture_economic_request(running, target)

    _completed_fixture, completed, _completed_target = _completed()
    substituted = _target_certification(fixture.train_certification, fixture.configuration)
    with pytest.raises(FixtureEconomicSegmentError, match="completed target transcript"):
        bind_fixture_economic_request(completed, substituted)


def test_closed_model_recomputes_exact_fixture_economics() -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)

    result = evaluate_fixture_economic_request(request)

    assert result.ending_cash == Decimal("99930")
    assert result.ending_market_value == Decimal("0")
    assert result.ending_equity == Decimal("99930")
    assert result.net_pnl == Decimal("-70")
    assert result.gross_traded_notional == Decimal("2050")
    assert result.trade_count == 2
    assert result.filled_target_count == 2
    assert tuple(position.quantity for position in result.positions) == (Decimal("0"),)


def test_request_rejects_universe_drift_and_noncausal_order() -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)
    changed_universe = replace(
        request.rows[-1],
        instruments=(replace(request.rows[-1].instruments[0], instrument_id="different"),),
    )
    with pytest.raises(FixtureEconomicSegmentError, match="instrument universe"):
        replace(request, rows=(*request.rows[:-1], changed_universe))
    changed_symbol = replace(
        request.rows[-1],
        instruments=(replace(request.rows[-1].instruments[0], symbol="ALT"),),
    )
    with pytest.raises(FixtureEconomicSegmentError, match="instrument symbols"):
        replace(request, rows=(*request.rows[:-1], changed_symbol))
    with pytest.raises(FixtureEconomicSegmentError, match="source order"):
        replace(request, rows=(request.rows[-1], request.rows[0]))
    with pytest.raises(FixtureEconomicSegmentError, match="starting cash"):
        replace(request, starting_cash=Decimal("99999"))


def test_plain_protocol_is_canonical_bounded_and_request_bound() -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)

    encoded, payload_sha256 = encode_fixture_economic_request(request)

    assert 0 < len(encoded) <= MAX_FIXTURE_ECONOMIC_REQUEST_BYTES
    assert b" " not in encoded and b"\n" not in encoded
    decoded = json.loads(encoded)
    assert decoded["request_payload_sha256"] == payload_sha256
    assert decoded["request"]["request_semantic_sha256"] == request.semantic_sha256


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_real_child_is_process_session_and_resource_isolated() -> None:
    _fixture, completed, target = _completed()

    receipt = execute_fixture_segment_economics(completed, target)

    assert receipt.result == evaluate_fixture_economic_request(receipt.request)
    assert receipt.process.outcome is FixtureEconomicProcessOutcome.COMPLETED
    assert receipt.process.process_started is True
    assert receipt.process.exit_code == 0
    assert receipt.process.stderr_bytes == 0


def test_public_execution_surface_has_no_command_code_or_environment_input() -> None:
    assert tuple(inspect.signature(execute_fixture_segment_economics).parameters) == (
        "projection",
        "certification",
    )
    assert "_run_fixture_economic_child" not in economic_application.__all__
    child_source = (
        Path(economic_application.__file__)
        .with_name("_fixture_segment_economic_child.py")
        .read_text(encoding="utf-8")
    )
    assert "sys.argv" not in child_source
    assert "subprocess" not in child_source
    assert "socket" not in child_source


def test_launch_uses_fixed_argv_empty_cwd_and_noninherited_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setenv("PHASE3H_MUST_NOT_CROSS", "secret")

    def reject_spawn(argv: tuple[str, ...], **kwargs: object) -> object:
        observed["argv"] = argv
        observed.update(kwargs)
        assert Path(argv[0]).is_absolute()
        assert Path(argv[0]).name.startswith("python")
        assert Path(argv[-1]).name == "_fixture_segment_economic_child.py"
        assert argv[1:4] == ("-I", "-S", "-B")
        assert kwargs["shell"] is False
        assert kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True
        environment = kwargs["env"]
        assert environment == dict(FIXTURE_ECONOMIC_ENVIRONMENT)
        assert isinstance(environment, dict)
        assert "PHASE3H_MUST_NOT_CROSS" not in environment
        working_directory = Path(str(kwargs["cwd"]))
        assert working_directory.is_dir()
        assert tuple(working_directory.iterdir()) == ()
        raise OSError("closed test spawn")

    monkeypatch.setattr(subprocess, "Popen", reject_spawn)
    with pytest.raises(FixtureEconomicExecutionError) as failure:
        _run_fixture_economic_child(b"{}")
    assert failure.value.outcome is FixtureEconomicProcessOutcome.SPAWN_FAILED
    assert observed


def test_each_closed_process_fault_returns_only_a_bounded_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, completed, target = _completed()
    for outcome in (
        FixtureEconomicProcessOutcome.SPAWN_FAILED,
        FixtureEconomicProcessOutcome.TIMEOUT,
        FixtureEconomicProcessOutcome.RESOURCE_EXCEEDED,
        FixtureEconomicProcessOutcome.CRASHED,
    ):
        monkeypatch.setattr(
            economic_application,
            "_run_fixture_economic_child",
            lambda _request, value=outcome: _failure_observation(value),
        )
        with pytest.raises(FixtureEconomicExecutionError) as failure:
            execute_fixture_segment_economics(completed, target)
        assert failure.value.outcome is outcome
        assert "material-that-must-not-reach-the-error" not in str(failure.value)


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_hard_parent_timeout_kills_and_reaps_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)
    encoded, _payload_sha256 = encode_fixture_economic_request(request)
    original_popen = subprocess.Popen
    child_pid: list[int] = []

    def recording_popen(*args: Any, **kwargs: Any) -> ProcessType[bytes]:
        process = cast(ProcessType[bytes], original_popen(*args, **kwargs))
        child_pid.append(process.pid)
        return process

    clock_values = iter((100.0, 104.0, 104.1))
    monkeypatch.setattr(subprocess, "Popen", recording_popen)
    monkeypatch.setattr(
        time,
        "monotonic",
        lambda: next(clock_values, 104.1),
    )

    observation = _run_fixture_economic_child(encoded)

    assert observation.outcome is FixtureEconomicProcessOutcome.TIMEOUT
    assert observation.exit_code is not None
    assert child_pid
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid[0], 0)


def test_protocol_corruption_and_child_stderr_cannot_mint_a_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, completed, target = _completed()
    malformed = _failure_observation(FixtureEconomicProcessOutcome.COMPLETED)
    malformed = replace(malformed, exit_code=0, stdout=b"{}", stderr=b"")
    monkeypatch.setattr(
        economic_application,
        "_run_fixture_economic_child",
        lambda _request: malformed,
    )
    with pytest.raises(FixtureEconomicExecutionError) as failure:
        execute_fixture_segment_economics(completed, target)
    assert failure.value.outcome is FixtureEconomicProcessOutcome.PROTOCOL_ERROR

    noisy = replace(malformed, stdout=b"valid-looking", stderr=b"diagnostic")
    monkeypatch.setattr(economic_application, "_run_fixture_economic_child", lambda _: noisy)
    with pytest.raises(FixtureEconomicExecutionError) as failure:
        execute_fixture_segment_economics(completed, target)
    assert failure.value.outcome is FixtureEconomicProcessOutcome.CRASHED


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_response_rejects_missing_limit_enforcement() -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)
    encoded, payload_sha256 = encode_fixture_economic_request(request)
    observation = _run_fixture_economic_child(encoded)
    assert observation.outcome is FixtureEconomicProcessOutcome.COMPLETED
    response = json.loads(observation.stdout)
    response["isolation"]["limits"]["cpu_seconds"] += 1
    tampered = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()

    with pytest.raises(FixtureEconomicSegmentError, match="resource limits"):
        decode_fixture_economic_response(
            tampered,
            request=request,
            request_payload_sha256=payload_sha256,
        )


def test_independent_parent_recomputation_rejects_economic_substitution() -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)
    expected = evaluate_fixture_economic_request(request)
    substituted = replace(expected, trade_count=expected.trade_count + 1)
    process = FixtureEconomicProcessEvidence._from_supervisor(
        runtime_artifact_sha256="1" * 64,
        launch_spec_sha256="2" * 64,
        request_bytes=1,
        request_payload_sha256="3" * 64,
        stdout_bytes=1,
        stdout_sha256="4" * 64,
        stderr_bytes=0,
        stderr_sha256="5" * 64,
        elapsed_microseconds=1,
    )
    with pytest.raises(FixtureEconomicSegmentError, match="independent parent"):
        FixtureEconomicSegmentReceipt._from_verified_execution(
            request,
            substituted,
            process,
        )


def test_receipt_constructors_are_sealed_and_all_authority_stays_closed() -> None:
    with pytest.raises(TypeError):
        FixtureEconomicProcessEvidence()
    with pytest.raises(TypeError):
        FixtureEconomicSegmentReceipt()

    _fixture, completed, target = _completed()
    if os.name != "posix":
        pytest.skip("Phase 3H fails closed off POSIX")
    receipt = execute_fixture_segment_economics(completed, target)
    assert receipt.counts_as_captured_tape_evidence is False
    assert receipt.promotion_authorized is False
    assert receipt.provider_io_authorized is False
    assert receipt.broker_effect_authorized is False
    assert receipt.trading_authorized is False
    assert receipt.public_view_authorized is False
