from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import subprocess
import sys
import time
import tomllib
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
from packages.domain.experiment_registry import EvaluationSegmentKind
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
    fixture_economic_isolation_profile_sha256,
)
from packages.domain.fixture_segment_worker import (
    FixtureSegmentJobProjection,
    FixtureTranscriptArtifact,
    FixtureTranscriptKind,
    _event,
    complete_fixture_segment_job,
)
from scripts.check_architecture import _phase3h_proof_boundary_violations
from tests.unit.test_experiment_governance import (
    FIRST_ATTEMPT_AT,
    GovernanceFixture,
    _target_certification,
)
from tests.unit.test_fixture_segment_worker import _running

REPOSITORY = Path(__file__).resolve().parents[2]

_SCOPE_POISONED_PACKAGE_EXCEPTION_ESCAPE = (
    "from packages.application.durable_trusted_time_monitor import "
    "DurableTrustedTimeMonitorError\n"
    "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
    "import TrustedTimeHeadAnchorCleanStopSupervisorBridgeError\n"
    "import packages.domain.models\n"
    "def poison_import_provenance() -> None:\n"
    "    import math as packages\n"
    "root_package = packages\n"
    "loader = root_package.application.durable_trusted_time_monitor._port_method(\n"
    "    root_package.application.trusted_time_head_anchor_clean_stop_supervisor_bridge."
    "_BUILTINS, import_name\n"
    ")\n"
    "module = loader(module_name, fromlist=('sentinel',))\n"
    "capability = root_package.application.durable_trusted_time_monitor._port_method(\n"
    "    module, attribute_name\n"
    ")"
)

_SCOPE_POISONED_SCRIPT_FFI_ESCAPE = (
    "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
    "import TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected\n"
    "import scripts.check_architecture\n"
    "def poison_import_provenance() -> None:\n"
    "    import cmath as scripts\n"
    "root_scripts = scripts\n"
    "ctypes_owner = "
    "root_scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication\n"
    "library = ctypes_owner.ctypes.pydll.LoadLibrary(None)"
)


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


def _restore_target_artifact(
    completed: FixtureSegmentJobProjection,
    artifact: FixtureTranscriptArtifact,
) -> FixtureSegmentJobProjection:
    latest = completed.latest
    restored_terminal = _event(
        job_id=latest.job_id,
        sequence=latest.sequence,
        status=latest.status,
        occurred_at=latest.occurred_at,
        actor_id=latest.actor_id,
        attempt_number=latest.attempt_number,
        previous_event_sha256=latest.previous_event_sha256,
        worker_id=latest.worker_id,
        claim_expires_at=latest.claim_expires_at,
        governance_event_sha256=latest.governance_event_sha256,
        feature_artifact_sha256=latest.feature_artifact_sha256,
        target_artifact_sha256=artifact.artifact_sha256,
        completion_receipt_sha256=latest.completion_receipt_sha256,
        terminal_reason_code=latest.terminal_reason_code,
        terminal_reason_sha256=latest.terminal_reason_sha256,
    )
    return FixtureSegmentJobProjection(
        job=completed.job,
        feature_artifact=completed.feature_artifact,
        events=(*completed.events[:-1], restored_terminal),
        target_artifact=artifact,
    )


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


def test_coherent_train_target_restored_as_validation_fails_exact_job_bindings() -> None:
    fixture, completed, _validation_target = _completed()
    train_target = _target_certification(
        fixture.train_certification,
        fixture.configuration,
    )
    train_artifact = FixtureTranscriptArtifact._restore(
        kind=FixtureTranscriptKind.TARGET,
        family_id=completed.job.family_id,
        attempt_id=completed.job.attempt_id,
        segment_kind=completed.job.segment_kind,
        segment_sha256=completed.job.segment_sha256,
        source_evidence_sha256=completed.job.source_evidence_sha256,
        configuration_sha256=completed.job.configuration_sha256,
        certification_sha256=train_target.semantic_sha256,
        parity_receipt_sha256=train_target.receipt.semantic_sha256,
        transcript_sha256=train_target.batch_result.transcript_sha256,
        step_sha256s=tuple(step.semantic_sha256 for step in train_target.batch_result.steps),
        output_ids=tuple(target.target_id for target in train_target.batch_result.targets),
    )
    restored_projection = _restore_target_artifact(completed, train_artifact)

    assert restored_projection.job.segment_kind is EvaluationSegmentKind.VALIDATION
    assert train_artifact.segment_kind is EvaluationSegmentKind.VALIDATION
    assert train_target.feature_certification.semantic_sha256 != (
        restored_projection.job.feature_certification_sha256
    )
    with pytest.raises(FixtureEconomicSegmentError, match="completed target transcript"):
        bind_fixture_economic_request(restored_projection, train_target)


def test_target_artifact_segment_identity_is_bound_to_the_job() -> None:
    _fixture, completed, target = _completed()
    assert completed.target_artifact is not None
    artifact = completed.target_artifact
    substitutions: tuple[dict[str, object], ...] = (
        {"segment_kind": EvaluationSegmentKind.TRAIN},
        {"segment_sha256": "f" * 64},
        {"source_evidence_sha256": "e" * 64},
    )
    for changed in substitutions:
        values: dict[str, object] = {
            "kind": artifact.kind,
            "family_id": artifact.family_id,
            "attempt_id": artifact.attempt_id,
            "segment_kind": artifact.segment_kind,
            "segment_sha256": artifact.segment_sha256,
            "source_evidence_sha256": artifact.source_evidence_sha256,
            "configuration_sha256": artifact.configuration_sha256,
            "certification_sha256": artifact.certification_sha256,
            "parity_receipt_sha256": artifact.parity_receipt_sha256,
            "transcript_sha256": artifact.transcript_sha256,
            "step_sha256s": artifact.step_sha256s,
            "output_ids": artifact.output_ids,
        }
        values.update(changed)
        substituted = FixtureTranscriptArtifact._restore(**values)  # type: ignore[arg-type]
        projection = _restore_target_artifact(completed, substituted)

        with pytest.raises(FixtureEconomicSegmentError, match="completed target transcript"):
            bind_fixture_economic_request(projection, target)


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


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_large_persisted_inputs_produce_exact_e63_derived_economics() -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)
    magnitude = Decimal("1e17")
    large_rows = tuple(
        replace(
            row,
            instruments=tuple(
                replace(
                    item,
                    close_price=magnitude,
                    target_quantity=(magnitude if row.target_id is not None else None),
                )
                for item in row.instruments
            ),
        )
        for row in request.rows
    )
    large_request = replace(request, rows=large_rows)

    expected = evaluate_fixture_economic_request(large_request)
    encoded, payload_sha256 = encode_fixture_economic_request(large_request)
    observation = _run_fixture_economic_child(encoded)

    assert observation.outcome is FixtureEconomicProcessOutcome.COMPLETED
    actual = decode_fixture_economic_response(
        observation.stdout,
        request=large_request,
        request_payload_sha256=payload_sha256,
    )
    assert actual == expected
    assert actual.ending_market_value == Decimal("1e34")
    assert actual.gross_traded_notional == Decimal("1e34")
    assert actual.ending_equity == FIXTURE_ECONOMIC_STARTING_CASH
    assert actual.net_pnl == Decimal(0)


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
    application_source = Path(economic_application.__file__).read_text(encoding="utf-8")
    assert '"-c"' not in application_source
    assert "/proc/self/fd" not in application_source


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_launch_uses_fixed_argv_empty_cwd_and_noninherited_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    inherited_descriptor: list[int] = []
    monkeypatch.setenv("PHASE3H_MUST_NOT_CROSS", "secret")

    def reject_spawn(argv: tuple[str, ...], **kwargs: object) -> object:
        import fcntl

        observed["argv"] = argv
        observed.update(kwargs)
        assert Path(argv[0]).is_absolute()
        assert Path(argv[0]).name.startswith("python")
        assert argv[1:4] == ("-I", "-S", "-B")
        assert "-c" not in argv
        passed = kwargs["pass_fds"]
        assert type(passed) is tuple and len(passed) == 1
        child_descriptor = cast(tuple[int], passed)[0]
        inherited_descriptor.append(child_descriptor)
        assert argv[-1] == f"/dev/fd/{child_descriptor}"
        descriptor_flags = fcntl.fcntl(child_descriptor, fcntl.F_GETFL)
        assert descriptor_flags & os.O_ACCMODE == os.O_RDONLY
        descriptor_metadata = os.fstat(child_descriptor)
        assert descriptor_metadata.st_nlink == 0
        assert descriptor_metadata.st_mode & 0o777 == 0o400
        assert kwargs["shell"] is False
        assert kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True
        environment = kwargs["env"]
        assert environment == dict(FIXTURE_ECONOMIC_ENVIRONMENT)
        assert isinstance(environment, dict)
        assert "PHASE3H_MUST_NOT_CROSS" not in environment
        working_directory = Path(str(kwargs["cwd"]))
        assert working_directory.is_dir()
        assert working_directory.stat().st_mode & 0o777 == 0o700
        assert tuple(working_directory.iterdir()) == ()
        raise OSError("closed test spawn")

    monkeypatch.setattr(subprocess, "Popen", reject_spawn)
    with pytest.raises(FixtureEconomicExecutionError) as failure:
        _run_fixture_economic_child(b"{}")
    assert failure.value.outcome is FixtureEconomicProcessOutcome.SPAWN_FAILED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert observed
    assert inherited_descriptor
    with pytest.raises(OSError):
        os.fstat(inherited_descriptor[0])


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_source_path_swap_after_snapshot_executes_the_recorded_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fixture, completed, target = _completed()
    request = bind_fixture_economic_request(completed, target)
    encoded, _payload_sha256 = encode_fixture_economic_request(request)
    actual_application = Path(economic_application.__file__)
    original_child_bytes = actual_application.with_name(
        "_fixture_segment_economic_child.py"
    ).read_bytes()
    fake_application = tmp_path / "fixture_segment_economics.py"
    fake_child = tmp_path / "_fixture_segment_economic_child.py"
    replacement_child = tmp_path / "replacement-child.py"
    fake_application.write_text("# fixed sibling anchor\n", encoding="utf-8")
    fake_child.write_bytes(original_child_bytes)
    replacement_child.write_text("raise SystemExit(73)\n", encoding="utf-8")
    original_popen = subprocess.Popen
    swapped = False

    def swapping_popen(*args: Any, **kwargs: Any) -> ProcessType[bytes]:
        nonlocal swapped
        replacement_child.replace(fake_child)
        swapped = True
        return cast(ProcessType[bytes], original_popen(*args, **kwargs))

    monkeypatch.setattr(economic_application, "__file__", str(fake_application))
    monkeypatch.setattr(subprocess, "Popen", swapping_popen)

    observation = _run_fixture_economic_child(encoded)

    assert swapped is True
    assert fake_child.read_text(encoding="utf-8") == "raise SystemExit(73)\n"
    assert observation.outcome is FixtureEconomicProcessOutcome.COMPLETED
    assert observation.runtime_artifact_sha256 == hashlib.sha256(original_child_bytes).hexdigest()


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_snapshot_readback_difference_fails_before_process_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read = economic_application._read_descriptor_bytes
    read_count = 0
    process_started = False

    def changed_readback(descriptor: int, maximum: int) -> bytes:
        nonlocal read_count
        read_count += 1
        value = original_read(descriptor, maximum)
        return value if read_count == 1 else value + b"x"

    def record_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal process_started
        process_started = True
        raise AssertionError("snapshot fault must precede Popen")

    monkeypatch.setattr(economic_application, "_read_descriptor_bytes", changed_readback)
    monkeypatch.setattr(subprocess, "Popen", record_spawn)

    with pytest.raises(FixtureEconomicExecutionError) as failure:
        _run_fixture_economic_child(b"{}")

    assert failure.value.outcome is FixtureEconomicProcessOutcome.SPAWN_FAILED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert read_count == 2
    assert process_started is False


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
def test_dev_fd_stat_difference_fails_before_process_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_match = economic_application._same_regular_file_projection
    process_started = False

    def reject_unlinked_projection(
        left: os.stat_result,
        right: os.stat_result,
    ) -> bool:
        if left.st_nlink == 0:
            return False
        return original_match(left, right)

    def record_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal process_started
        process_started = True
        raise AssertionError("descriptor stat fault must precede Popen")

    monkeypatch.setattr(
        economic_application,
        "_same_regular_file_projection",
        reject_unlinked_projection,
    )
    monkeypatch.setattr(subprocess, "Popen", record_spawn)

    with pytest.raises(FixtureEconomicExecutionError) as failure:
        _run_fixture_economic_child(b"{}")

    assert failure.value.outcome is FixtureEconomicProcessOutcome.SPAWN_FAILED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert process_started is False


@pytest.mark.skipif(os.name != "posix", reason="Phase 3H fails closed off POSIX")
@pytest.mark.parametrize("fault", ["platform", "missing-devfd", "descriptor-flags"])
def test_unsupported_snapshot_platform_has_no_reduced_isolation_fallback(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    process_started = False
    if fault == "platform":
        monkeypatch.setattr(sys, "platform", "unsupported-phase3h")
    elif fault == "missing-devfd":
        original_stat = os.stat

        def missing_devfd(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if os.fspath(path) == "/dev/fd":
                raise FileNotFoundError("closed test devfd")
            return original_stat(path, *args, **kwargs)

        monkeypatch.setattr(os, "stat", missing_devfd)
    else:
        monkeypatch.setattr(os, "O_NOFOLLOW", 0)

    def record_spawn(*_args: object, **_kwargs: object) -> object:
        nonlocal process_started
        process_started = True
        raise AssertionError("unsupported isolation must precede Popen")

    monkeypatch.setattr(subprocess, "Popen", record_spawn)

    with pytest.raises(FixtureEconomicExecutionError) as failure:
        _run_fixture_economic_child(b"{}")

    assert failure.value.outcome is FixtureEconomicProcessOutcome.SPAWN_FAILED
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    assert process_started is False


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
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None

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


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("request_bytes", True, "request byte count"),
        ("stdout_bytes", True, "stdout byte count"),
        ("stderr_bytes", False, "stderr byte count"),
        ("exit_code", False, "not successful"),
    ),
)
def test_process_evidence_rejects_bool_as_integer_mutation(
    field_name: str,
    value: object,
    message: str,
) -> None:
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
    object.__setattr__(process, field_name, value)

    with pytest.raises(FixtureEconomicSegmentError, match=message):
        process._validate()


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


def test_object_new_reconstruction_cannot_mint_process_or_receipt_evidence() -> None:
    process = object.__new__(FixtureEconomicProcessEvidence)
    forged_process_values: dict[str, object] = {
        "runtime_artifact_sha256": "1" * 64,
        "launch_spec_sha256": "2" * 64,
        "isolation_profile_sha256": fixture_economic_isolation_profile_sha256(),
        "request_bytes": 1,
        "request_payload_sha256": "3" * 64,
        "stdout_bytes": 1,
        "stdout_sha256": "4" * 64,
        "stderr_bytes": 0,
        "stderr_sha256": "5" * 64,
        "exit_code": 0,
        "elapsed_microseconds": 0,
        "process_started": True,
        "outcome": FixtureEconomicProcessOutcome.COMPLETED,
        "_process_factory_proof": object(),
    }
    for field_name, value in forged_process_values.items():
        object.__setattr__(process, field_name, value)
    with pytest.raises(FixtureEconomicSegmentError, match="not factory-built"):
        process._validate()
    with pytest.raises(FixtureEconomicSegmentError, match="not factory-built"):
        _ = process.semantic_sha256

    receipt = object.__new__(FixtureEconomicSegmentReceipt)
    object.__setattr__(receipt, "request", None)
    object.__setattr__(receipt, "result", None)
    object.__setattr__(receipt, "process", None)
    object.__setattr__(receipt, "receipt_sha256", "f" * 64)
    object.__setattr__(receipt, "_receipt_factory_proof", object())
    with pytest.raises(FixtureEconomicSegmentError, match="not factory-built"):
        receipt._validate()
    with pytest.raises(FixtureEconomicSegmentError, match="not factory-built"):
        _ = receipt.semantic_sha256


@pytest.mark.parametrize(
    "source",
    (
        "from packages.domain.fixture_segment_economics import "
        "FixtureEconomicProcessEvidence as Evidence",
        "from .fixture_segment_economics import FixtureEconomicSegmentReceipt",
        "import packages.domain.fixture_segment_economics as economics",
        "import packages.domain as domain",
        "from packages.application.fixture_segment_economics import "
        "execute_fixture_segment_economics as run",
        "loader = __import__\nloader('packages.domain.fixture_segment_economics')",
        "from importlib import import_module as load\nload('unrelated')",
        "import importlib\nload = importlib.import_module\nload('unrelated')",
        "private_name = '_from_' + 'supervisor'",
        "from packages.domain.fixture_segment_economics import "
        "FixtureEconomicProcessEvidence\n"
        "class Forged(FixtureEconomicProcessEvidence):\n    pass",
        "from packages.domain.fixture_segment_economics import "
        "FixtureEconomicProcessEvidence\n"
        "owner = globals()['Fixture' + 'EconomicProcessEvidence']",
        "namespace = vars()['%(a)s%(b)s' % {'a': '__built', 'b': 'ins__'}]\n"
        "loader = namespace['%(a)s%(b)s' % {'a': '__im', 'b': 'port__'}]\n"
        "owner = loader('packages.domain.fixture_segment_economics', "
        "fromlist=('sentinel',))",
        "import uvicorn.importer as importer\n"
        "loader = getattr(importer, '%s%s' % ('import_from_', 'string'))\n"
        "owner = loader('packages.domain.fixture_segment_economics:"
        "FixtureEconomicProcessEvidence')",
        "scope_owner = lambda: None\n"
        "scope_prefix = '__global'\n"
        "scope_suffix = 's__'\n"
        "scope = getattr(scope_owner, scope_prefix + scope_suffix)\n"
        "builtins_prefix = '__built'\n"
        "builtins_suffix = 'ins__'\n"
        "namespace = scope[builtins_prefix + builtins_suffix]",
        "owner = lambda: None\n"
        "a, b = '__glo', 'bals__'\n"
        "scope = getattr(owner, f'{a}{b}')\n"
        "c, d = '__built', 'ins__'\n"
        "namespace = scope[f'{c}{d}']",
        "scope = getattr(lambda: None, '__gloXbals__'.replace('X', ''))\n"
        "namespace = scope['__builXtins__'.replace('X', '')]",
        "def resolve(module_name, attribute_name):\n"
        "    reflect = getattr\n"
        "    scope = reflect(resolve, '__globals__')\n"
        "    namespace = scope['__builtins__']\n"
        "    loader = namespace['__import__']\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return reflect(module, attribute_name)",
        "def resolve(scope_key, builtins_key, import_key):\n"
        "    scope = getattr(resolve, scope_key)\n"
        "    namespace = scope[builtins_key]\n"
        "    return namespace[import_key]",
        "import string\n"
        "def resolve(module_name, attribute_name):\n"
        "    formatter = string.Formatter()\n"
        "    loader = formatter.get_field(\n"
        "        '0.__globals__[__builtins__][__import__]', (resolve,), {}\n"
        "    )[0]\n"
        "    module = loader(module_name, fromlist=('sentinel',))\n"
        "    return formatter.get_field('0.' + attribute_name, (module,), {})[0]",
        "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "import _BUILTINS\n"
        "from packages.application.durable_trusted_time_monitor import _port_method\n"
        "loader = _port_method(_BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = _port_method(module, attribute_name)",
        "from packages.application import "
        "trusted_time_head_anchor_clean_stop_supervisor_bridge as builtins_owner\n"
        "from packages.application import durable_trusted_time_monitor as resolver_owner\n"
        "builtins_alias = builtins_owner\n"
        "resolver_alias = resolver_owner\n"
        "loader = resolver_alias._port_method(builtins_alias._BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = resolver_alias._port_method(module, attribute_name)",
        "from packages.application import durable_trusted_time_monitor as owner\n"
        "aliases = (owner,)\n"
        "callback(owner)",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import ctypes\n"
        "import _ctypes\n"
        "library = ctypes.pydll.LoadLibrary(None)\n"
        "importer = library['Py' + 'Import_ImportModule']\n"
        "resolver = library['Py' + 'Object_GetAttrString']\n"
        "bridge = _ctypes.PyObj_FromPtr",
        "class Owners:\n"
        "    import packages.application.durable_trusted_time_monitor as resolver\n"
        "    import packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "as builtins\n"
        "loader = Owners.resolver._port_method(Owners.builtins._BUILTINS, import_name)\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = Owners.resolver._port_method(module, attribute_name)",
        "from packages.application.durable_trusted_time_monitor import "
        "DurableTrustedTimeMonitorError\n"
        "from packages.application.trusted_time_head_anchor_clean_stop_supervisor_bridge "
        "import TrustedTimeHeadAnchorCleanStopSupervisorBridgeError\n"
        "import packages.domain.models\n"
        "root_package = packages\n"
        "loader = root_package.application.durable_trusted_time_monitor._port_method(\n"
        "    root_package.application.trusted_time_head_anchor_clean_stop_supervisor_bridge."
        "_BUILTINS, import_name\n"
        ")\n"
        "module = loader(module_name, fromlist=('sentinel',))\n"
        "capability = root_package.application.durable_trusted_time_monitor._port_method(\n"
        "    module, attribute_name\n"
        ")",
        "from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication "
        "import TrustedTimePostEnrollmentCleanStopTerminalReauthenticationRejected\n"
        "import scripts.check_architecture\n"
        "root_scripts = scripts\n"
        "ctypes_owner = "
        "root_scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication\n"
        "library = ctypes_owner.ctypes.pydll.LoadLibrary(None)",
        _SCOPE_POISONED_PACKAGE_EXCEPTION_ESCAPE,
        _SCOPE_POISONED_SCRIPT_FFI_ESCAPE,
        "import ctypes\n"
        "library = ctypes.CDLL(None)\n"
        "importer = library.PyImport_ImportModule\n"
        "resolver = library.PyObject_GetAttrString",
        "from packages.domain.fixture_segment_economics import "
        "FixtureEconomicProcessEvidence\n"
        "forged = object.__new__(FixtureEconomicProcessEvidence)",
        "import runpy\nnamespace = runpy.run_path('unrelated.py')",
        "source = open('unrelated.py').read()\n"
        "namespace = {}\n"
        "exec(compile(source, 'unrelated.py', 'exec'), namespace)",
        "import builtins\ngetattr(builtins, 'e' + 'xec')('pass')",
        "import builtins\ncode = builtins.compile('pass', 'x', 'exec')",
        "import pickle\nowner = pickle.loads(b'x')",
        "import pydoc\nowner = pydoc.locate('unrelated')",
        "import _frozen_importlib_external as machinery\n"
        "loader = machinery.SourceFileLoader('unrelated', 'unrelated.py')",
        "import code\n"
        "import codeop\n"
        "compiled = codeop.compile_command('pass')\n"
        "code.InteractiveInterpreter({}).runcode(compiled)",
        "import pkgutil\nloader = pkgutil.get_loader('unrelated')",
        "from unittest import mock\npatched = mock.patch('unrelated')",
        "import marshal\n"
        "from types import FunctionType\n"
        "function = FunctionType(marshal.loads(b'x'), {})",
        "payload = b'cpackages.domain.fixture_segment_economics\\n'"
        " b'FixtureEconomicProcessEvidence\\n.'",
    ),
)
def test_architecture_guard_rejects_phase3h_proof_reachability(source: str) -> None:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    violations = _phase3h_proof_boundary_violations(
        ast.parse(source),
        policy_enabled=True,
        relative_path=Path("packages/domain/adversarial_phase3h_consumer.py"),
        proof_module="packages.domain.fixture_segment_economics",
        proof_path=Path("packages/domain/fixture_segment_economics.py"),
        execution_module="packages.application.fixture_segment_economics",
        execution_path=Path("packages/application/fixture_segment_economics.py"),
        allowed_proof_imports=frozenset(),
        module_ast_sha256={},
        dynamic_code_exception_module_ast_sha256={
            Path(path): digest
            for path, digest in scan["phase3h_dynamic_code_exception_module_ast_sha256"].items()
        },
    )

    assert violations


def test_architecture_guard_is_disabled_when_phase3h_policy_is_absent() -> None:
    assert not _phase3h_proof_boundary_violations(
        ast.parse("from importlib import import_module"),
        policy_enabled=False,
        relative_path=Path("packages/domain/legacy_fixture.py"),
        proof_module="",
        proof_path=Path(),
        execution_module="",
        execution_path=Path(),
        allowed_proof_imports=frozenset(),
        module_ast_sha256={},
        dynamic_code_exception_module_ast_sha256={},
    )


def test_architecture_guard_allows_benign_compile_attribute_and_exec_text() -> None:
    assert not _phase3h_proof_boundary_violations(
        ast.parse("import re\npattern = re.compile('x')\nlabel = 'exec'"),
        policy_enabled=True,
        relative_path=Path("packages/domain/benign_fixture.py"),
        proof_module="packages.domain.fixture_segment_economics",
        proof_path=Path("packages/domain/fixture_segment_economics.py"),
        execution_module="packages.application.fixture_segment_economics",
        execution_path=Path("packages/application/fixture_segment_economics.py"),
        allowed_proof_imports=frozenset(),
        module_ast_sha256={},
        dynamic_code_exception_module_ast_sha256={},
    )


def test_architecture_guard_accepts_only_exact_phase3h_modules() -> None:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    module_ast_sha256 = {
        Path(path): digest for path, digest in scan["phase3h_isolated_module_ast_sha256"].items()
    }
    proof_path = Path(scan["phase3h_proof_module_path"])
    execution_path = Path(scan["phase3h_execution_module_path"])

    for relative_path in (proof_path, execution_path):
        tree = ast.parse((REPOSITORY / relative_path).read_text(encoding="utf-8"))
        assert not _phase3h_proof_boundary_violations(
            tree,
            policy_enabled=True,
            relative_path=relative_path,
            proof_module=scan["phase3h_proof_module"],
            proof_path=proof_path,
            execution_module=scan["phase3h_execution_module"],
            execution_path=execution_path,
            allowed_proof_imports=frozenset(scan["phase3h_proof_consumer_allowed_imports"]),
            module_ast_sha256=module_ast_sha256,
            dynamic_code_exception_module_ast_sha256={
                Path(path): digest
                for path, digest in scan["phase3h_dynamic_code_exception_module_ast_sha256"].items()
            },
        )


def test_architecture_guard_pins_dynamic_code_exceptions() -> None:
    with (REPOSITORY / "infra/architecture-boundaries.toml").open("rb") as stream:
        scan = tomllib.load(stream)["scan"]
    exceptions = {
        Path(path): digest
        for path, digest in scan["phase3h_dynamic_code_exception_module_ast_sha256"].items()
    }
    arguments = {
        "policy_enabled": True,
        "proof_module": scan["phase3h_proof_module"],
        "proof_path": Path(scan["phase3h_proof_module_path"]),
        "execution_module": scan["phase3h_execution_module"],
        "execution_path": Path(scan["phase3h_execution_module_path"]),
        "allowed_proof_imports": frozenset(scan["phase3h_proof_consumer_allowed_imports"]),
        "module_ast_sha256": {
            Path(path): digest
            for path, digest in scan["phase3h_isolated_module_ast_sha256"].items()
        },
    }

    for relative_path in exceptions:
        tree = ast.parse((REPOSITORY / relative_path).read_text(encoding="utf-8"))
        assert not _phase3h_proof_boundary_violations(
            tree,
            relative_path=relative_path,
            dynamic_code_exception_module_ast_sha256=exceptions,
            **arguments,
        )
        assert _phase3h_proof_boundary_violations(
            tree,
            relative_path=relative_path,
            dynamic_code_exception_module_ast_sha256={relative_path: "0" * 64},
            **arguments,
        )
