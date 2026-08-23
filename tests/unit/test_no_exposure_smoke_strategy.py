from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from packages.application.no_exposure_smoke_strategy import (
    NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256,
    NO_EXPOSURE_SMOKE_MANIFEST,
    NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
    NoExposureSmokeArtifactError,
    load_no_exposure_smoke_artifact,
    verify_no_exposure_smoke_artifact,
    verify_no_exposure_smoke_response,
)
from packages.application.supervised_strategy import (
    STRATEGY_SUBPROCESS_ENVIRONMENT,
    run_supervised_strategy,
)
from packages.domain.account_coordinator import AccountFence, _account_fence_receipt
from packages.domain.market_batch import MarketBatch, MarketWatermark
from packages.domain.models import MarketEvent
from packages.domain.replay import replay_market_events
from packages.domain.strategy_invocation_lifecycle import (
    STRATEGY_INVOCATION_RECOVERY_INTERVAL,
    StrategyInvocationClaim,
    StrategyInvocationStartAuthorization,
    _strategy_invocation_start_authorization,
)
from packages.domain.strategy_supervision import (
    StrategyInvocation,
    StrategyProtocolResponse,
    StrategyRuntimeBinding,
    StrategySupervisionConflict,
    StrategySupervisionOutcome,
    bind_strategy_invocation,
    encode_strategy_request,
)
from packages.persistence.strategy_invocation_lifecycle import (
    _StrategyInvocationStartAuthorizationUse,
)


def _base_python_executable() -> str:
    candidate = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    assert candidate.is_file()
    assert not candidate.is_symlink()
    return str(candidate)


@pytest.fixture(autouse=True)
def _install_base_python_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "executable", _base_python_executable())


def _plain_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _batch() -> MarketBatch:
    event_time = datetime(2026, 7, 28, 14, 30, tzinfo=UTC)
    watermark = MarketWatermark(
        watermark_id="no-exposure-smoke-watermark",
        event_time_through=event_time,
        closed_at=event_time + timedelta(seconds=2),
        expected_instrument_ids=("instrument-spy",),
    )
    event = MarketEvent(
        event_id="no-exposure-smoke-event-spy",
        instrument_id="instrument-spy",
        symbol="SPY",
        event_time=event_time,
        available_at=event_time + timedelta(seconds=1),
        close_price=Decimal("632.15"),
        source_sequence=1,
    )
    return replay_market_events(events=(event,), watermarks=(watermark,)).batches[0]


def _invocation(
    *,
    strategy_id: str | None = None,
    strategy_version: str | None = None,
    strategy_configuration_sha256: str | None = None,
    runtime: StrategyRuntimeBinding | None = None,
) -> tuple[MarketBatch, StrategyInvocation]:
    artifact = load_no_exposure_smoke_artifact()
    batch = _batch()
    invocation = bind_strategy_invocation(
        control_scope_id="no-exposure-smoke-account",
        environment="local-smoke",
        market_batch=batch,
        strategy_id=artifact.strategy_id if strategy_id is None else strategy_id,
        strategy_version=(
            artifact.strategy_version if strategy_version is None else strategy_version
        ),
        strategy_configuration_sha256=(
            artifact.strategy_configuration_sha256
            if strategy_configuration_sha256 is None
            else strategy_configuration_sha256
        ),
        input_state_sha256=hashlib.sha256(b"no-exposure-smoke-empty-state").hexdigest(),
        runtime=artifact.subprocess_spec.runtime_binding if runtime is None else runtime,
        requested_at=batch.as_of + timedelta(microseconds=1),
    )
    return batch, invocation


def _start_authorization(
    invocation: StrategyInvocation,
) -> tuple[StrategyInvocationStartAuthorization, Callable[[], datetime]]:
    claimed_at = invocation.requested_at + timedelta(milliseconds=1)
    fence = AccountFence(
        account_id=invocation.control_scope_id,
        owner_id="no-exposure-smoke-test-worker",
        lease_id="no-exposure-smoke-test-lease",
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
    issuer_identity = object()
    capability_nonce = object()
    authorization = _strategy_invocation_start_authorization(
        claim,
        fence_receipt=_account_fence_receipt(
            fence=fence,
            validated_at=claimed_at,
            valid_until=claim.fence_receipt.valid_until,
            policy_sha256=claim.fence_receipt.policy_sha256,
            lease_sha256=claim.fence_receipt.lease_sha256,
        ),
        issuer_identity=issuer_identity,
        capability_nonce=capability_nonce,
        use=_StrategyInvocationStartAuthorizationUse(
            issuer_identity=issuer_identity,
            capability_nonce=capability_nonce,
        ),
    )
    current = claimed_at

    def utc_clock() -> datetime:
        nonlocal current
        value = current
        current += timedelta(microseconds=1)
        return value

    return authorization, utc_clock


def _copy_artifact(tmp_path: Path) -> Path:
    source_directory = NO_EXPOSURE_SMOKE_MANIFEST.parent
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes((source_directory / "manifest.json").read_bytes())
    (tmp_path / "strategy.py").write_bytes((source_directory / "strategy.py").read_bytes())
    return manifest_path


def test_checked_in_manifest_binds_exact_artifact_and_is_deterministic() -> None:
    first = load_no_exposure_smoke_artifact()
    second = load_no_exposure_smoke_artifact()
    artifact_path = NO_EXPOSURE_SMOKE_MANIFEST.parent / "strategy.py"

    assert first == second
    assert first.strategy_configuration_sha256 == NO_EXPOSURE_SMOKE_CONFIGURATION_SHA256
    assert (
        first.subprocess_spec.artifact_sha256
        == hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    )
    assert first.subprocess_spec.argv[0] == _base_python_executable()
    assert first.subprocess_spec.argv[1:4] == ("-I", "-S", "-c")
    assert Path(first.subprocess_spec.argv[5]) == artifact_path.resolve()
    assert first.subprocess_spec.argv[6] == first.subprocess_spec.artifact_sha256
    assert first.subprocess_spec.runtime_binding == second.subprocess_spec.runtime_binding


def test_artifact_runs_through_strict_supervisor_and_emits_no_exposure() -> None:
    artifact = load_no_exposure_smoke_artifact()
    batch, invocation = _invocation()
    authorization, utc_clock = _start_authorization(invocation)

    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=artifact.subprocess_spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )

    assert result.outcome is StrategySupervisionOutcome.COMPLETED
    assert result.response is not None
    evidence = verify_no_exposure_smoke_response(result.response, invocation, artifact)
    assert evidence.proposed_intent_count == 0
    assert evidence.exposure_authorized is False
    assert json.loads(result.response.result_json) == {
        "contract_version": NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
        "decision": "NO_EXPOSURE",
        "market_batch_id": batch.batch_id,
        "market_batch_sha256": batch.semantic_sha256,
        "proposed_intents": [],
    }
    assert result.requested_control_state is None
    assert result.automatic_resume_authorized is False


def test_manifest_rejects_artifact_byte_tampering_before_launch(tmp_path: Path) -> None:
    manifest_path = _copy_artifact(tmp_path)
    (tmp_path / "strategy.py").write_bytes(
        (tmp_path / "strategy.py").read_bytes() + b"\n# tampered\n"
    )

    with pytest.raises(
        NoExposureSmokeArtifactError,
        match="does not match its manifest digest",
    ):
        verify_no_exposure_smoke_artifact(manifest_path)


def test_child_rechecks_artifact_identity_after_manifest_verification(
    tmp_path: Path,
) -> None:
    manifest_path = _copy_artifact(tmp_path)
    artifact = verify_no_exposure_smoke_artifact(manifest_path)
    batch = _batch()
    invocation = bind_strategy_invocation(
        control_scope_id="no-exposure-smoke-account",
        environment="local-smoke",
        market_batch=batch,
        strategy_id=artifact.strategy_id,
        strategy_version=artifact.strategy_version,
        strategy_configuration_sha256=artifact.strategy_configuration_sha256,
        input_state_sha256=hashlib.sha256(b"empty-state").hexdigest(),
        runtime=artifact.subprocess_spec.runtime_binding,
        requested_at=batch.as_of + timedelta(microseconds=1),
    )
    (tmp_path / "strategy.py").write_bytes(
        b"import json,sys\n"
        b"request=json.loads(sys.stdin.buffer.read())\n"
        b"response={'invocation_id':request['invocation']['id'],"
        b"'invocation_sha256':request['invocation']['semantic_sha256'],"
        b"'protocol_version':request['protocol_version'],'result':"
        b"{'contract_version':'aqt-no-exposure-smoke-result-v1',"
        b"'decision':'NO_EXPOSURE','market_batch_id':request['market_batch']['id'],"
        b"'market_batch_sha256':request['market_batch']['semantic_sha256'],"
        b"'proposed_intents':[]}}\n"
        b"sys.stdout.write(json.dumps(response,sort_keys=True,separators=(',',':')))\n"
    )

    completed = subprocess.run(
        artifact.subprocess_spec.argv,
        input=encode_strategy_request(invocation, batch),
        capture_output=True,
        check=False,
        close_fds=True,
        env=dict(STRATEGY_SUBPROCESS_ENVIRONMENT),
    )

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"no-exposure smoke artifact rejected\n"


def test_result_verifier_rejects_any_nonempty_intent_material() -> None:
    _, invocation = _invocation()
    result_json = _plain_json_bytes(
        {
            "contract_version": NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
            "decision": "NO_EXPOSURE",
            "market_batch_id": invocation.market_batch_id,
            "market_batch_sha256": invocation.market_batch_sha256,
            "proposed_intents": [{"side": "BUY"}],
        }
    ).decode()
    response = StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=invocation.protocol_version,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
    )

    with pytest.raises(
        NoExposureSmokeArtifactError,
        match="exact empty-intent observation",
    ):
        verify_no_exposure_smoke_response(
            response,
            invocation,
            load_no_exposure_smoke_artifact(),
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("strategy_id", "another-strategy"),
        ("strategy_version", "2.0.0"),
        ("strategy_configuration_sha256", "f" * 64),
    ),
)
def test_child_rejects_substituted_strategy_identity(
    field_name: str,
    value: str,
) -> None:
    artifact = load_no_exposure_smoke_artifact()
    batch, invocation = _invocation(**{field_name: value})  # type: ignore[arg-type]

    completed = subprocess.run(
        artifact.subprocess_spec.argv,
        input=encode_strategy_request(invocation, batch),
        capture_output=True,
        check=False,
        close_fds=True,
        env=dict(STRATEGY_SUBPROCESS_ENVIRONMENT),
    )

    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"no-exposure smoke request rejected\n"


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("strategy_id", "another-strategy"),
        ("strategy_version", "2.0.0"),
        ("strategy_configuration_sha256", "f" * 64),
    ),
)
def test_response_verifier_rejects_substituted_strategy_identity(
    field_name: str,
    value: str,
) -> None:
    artifact = load_no_exposure_smoke_artifact()
    _, invocation = _invocation(**{field_name: value})  # type: ignore[arg-type]
    result_json = _plain_json_bytes(
        {
            "contract_version": NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
            "decision": "NO_EXPOSURE",
            "market_batch_id": invocation.market_batch_id,
            "market_batch_sha256": invocation.market_batch_sha256,
            "proposed_intents": [],
        }
    ).decode()
    response = StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=invocation.protocol_version,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
    )

    with pytest.raises(
        StrategySupervisionConflict,
        match="bound to the verified artifact",
    ):
        verify_no_exposure_smoke_response(response, invocation, artifact)


def test_response_verifier_rejects_a_different_runtime_binding() -> None:
    artifact = load_no_exposure_smoke_artifact()
    changed_runtime = replace(
        artifact.subprocess_spec.runtime_binding,
        runtime_version="substituted-runtime",
    )
    _, invocation = _invocation(runtime=changed_runtime)
    result_json = _plain_json_bytes(
        {
            "contract_version": NO_EXPOSURE_SMOKE_RESULT_CONTRACT_VERSION,
            "decision": "NO_EXPOSURE",
            "market_batch_id": invocation.market_batch_id,
            "market_batch_sha256": invocation.market_batch_sha256,
            "proposed_intents": [],
        }
    ).decode()
    response = StrategyProtocolResponse(
        invocation_id=invocation.invocation_id,
        invocation_sha256=invocation.semantic_sha256,
        protocol_version=invocation.protocol_version,
        result_json=result_json,
        result_sha256=hashlib.sha256(result_json.encode()).hexdigest(),
    )

    with pytest.raises(
        StrategySupervisionConflict,
        match="bound to the verified artifact",
    ):
        verify_no_exposure_smoke_response(response, invocation, artifact)


def test_verified_artifact_and_evidence_cannot_be_replaced_into_other_facts() -> None:
    artifact = load_no_exposure_smoke_artifact()
    changed_spec = replace(
        artifact.subprocess_spec,
        runtime_version="substituted-runtime",
    )
    with pytest.raises(
        NoExposureSmokeArtifactError,
        match="verification seal is invalid",
    ):
        replace(artifact, subprocess_spec=changed_spec)

    batch, invocation = _invocation()
    authorization, utc_clock = _start_authorization(invocation)
    result = run_supervised_strategy(
        invocation=invocation,
        market_batch=batch,
        subprocess_spec=artifact.subprocess_spec,
        start_authorization=authorization,
        utc_clock=utc_clock,
    )
    assert result.response is not None
    evidence = verify_no_exposure_smoke_response(result.response, invocation, artifact)
    with pytest.raises(
        NoExposureSmokeArtifactError,
        match="verification seal is invalid",
    ):
        replace(evidence, result_sha256="f" * 64)
    with pytest.raises(
        NoExposureSmokeArtifactError,
        match="cannot contain or authorize exposure",
    ):
        replace(evidence, proposed_intent_count=False)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("strategy_id", "another-strategy"),
        ("protocol_version", "future-protocol"),
        ("entrypoint", "../strategy.py"),
        ("artifact_sha256", "A" * 64),
    ),
)
def test_manifest_rejects_unapproved_identity_fields(
    tmp_path: Path,
    field_name: str,
    value: str,
) -> None:
    manifest_path = _copy_artifact(tmp_path)
    manifest = json.loads(manifest_path.read_bytes())
    manifest[field_name] = value
    manifest_path.write_bytes(_plain_json_bytes(manifest) + b"\n")

    with pytest.raises(NoExposureSmokeArtifactError):
        verify_no_exposure_smoke_artifact(manifest_path)
