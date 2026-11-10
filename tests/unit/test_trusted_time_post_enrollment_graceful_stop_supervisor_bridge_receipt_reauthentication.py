from __future__ import annotations

import copy
import gc
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

import packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation as verifier_adapter
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification,
)
from packages.application import (
    trusted_time_head_anchor_clean_stop_supervisor_bridge as core_bridge,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    build_post_enrollment_graceful_stop_operator_attestation_envelope,
    build_post_enrollment_graceful_stop_operator_attestation_statement,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    build_post_enrollment_graceful_stop_operator_authority,
)
from scripts import (
    trusted_time_post_enrollment_graceful_stop_decision_artifacts as decision_artifacts,
)
from scripts import (
    trusted_time_post_enrollment_graceful_stop_supervisor_bridge as bridge,
)
from scripts import verify_trusted_time_images as image_verifier
from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication import (
    TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    decode_post_enrollment_graceful_stop_decision,
)
from scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts import (
    LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
)
from scripts.trusted_time_post_enrollment_graceful_stop_lifecycle import (
    RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    RetainedTrustedTimePostEnrollmentGracefulStopProgress,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import (
    test_trusted_time_post_enrollment_clean_stop_terminal_reauthentication as reauth_fx,
)
from tests.unit import test_trusted_time_post_enrollment_execution_admission as execution_fx
from tests.unit import (
    test_trusted_time_post_enrollment_graceful_stop_decision_artifacts as decision_fx,
)
from tests.unit import test_trusted_time_post_enrollment_graceful_stop_lifecycle as lifecycle_fx


@dataclass(frozen=True, slots=True)
class _DurableBridgeInputs:
    prepared: decision_fx._PreparedInputs
    receipt: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt
    progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress

    @property
    def candidate_path(self) -> Path:
        return self.prepared.candidate_directory / self.receipt.artifact_location


@dataclass(frozen=True, slots=True)
class _TerminalEvidence:
    issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    postcondition: TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    result: core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopResult


def _registry_sizes() -> tuple[int, int, int, int, int]:
    return (
        len(decision_artifacts._PENDING_LOADED_RECEIPT_REGISTRY),
        len(decision_artifacts._LOADED_RECEIPT_REGISTRY),
        len(bridge._AUTHENTICATED_REQUEST_REGISTRY),
        len(bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID),
        len(bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256),
    )


@pytest.fixture(scope="module")
def durable_bridge_inputs(
    tmp_path_factory: pytest.TempPathFactory,
) -> Any:
    monkeypatch = pytest.MonkeyPatch()

    def valid(candidate: object, payload: object) -> bool:
        return type(candidate) is bytes and candidate == claimed_fx._authenticated_seal(
            cast(dict[str, object], payload)
        )

    monkeypatch.setattr(reader, "_valid_observation_seal", valid)
    monkeypatch.setattr(
        reader,
        "_valid_cursor_seal",
        lambda candidate, payload, _result: valid(candidate, payload),
    )
    monkeypatch.setattr(
        image_verifier,
        "reviewed_input_bindings",
        execution_fx._reviewed_bindings,
    )

    root = tmp_path_factory.mktemp("real-receipt-supervisor-bridge")
    prepared = decision_fx._prepared_inputs(monkeypatch, root)
    receipt = decision_fx._prepare(prepared)
    decision = decode_post_enrollment_graceful_stop_decision(
        (prepared.candidate_directory / receipt.artifact_location).read_bytes()
    )
    authority = build_post_enrollment_graceful_stop_operator_authority(lifecycle_fx.PUBLIC_KEY)
    statement = build_post_enrollment_graceful_stop_operator_attestation_statement(
        authority=authority,
        graceful_stop_decision_v1_sha256=decision.decision_sha256,
        graceful_stop_operation_id=decision.operation_id,
        graceful_stop_target_sha256=decision.target.target_sha256,
    )
    envelope = build_post_enrollment_graceful_stop_operator_attestation_envelope(
        graceful_stop_decision_v1=decision.encoded,
        statement=statement,
        signature_ed25519=lifecycle_fx.SIGNATURE,
    )
    verification = TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification(
        authority_artifact_sha256=authority.authority_sha256,
        public_key_sha256=authority.public_key_sha256,
        graceful_stop_decision_v1_sha256=decision.decision_sha256,
        graceful_stop_operation_id=decision.operation_id,
        graceful_stop_target_sha256=decision.target.target_sha256,
        operator_attestation_statement_sha256=statement.statement_sha256,
        operator_attestation_signature_sha256=hashlib.sha256(lifecycle_fx.SIGNATURE).hexdigest(),
        operator_attestation_envelope_sha256=envelope.envelope_sha256,
        _construction_capability=(verifier_adapter._VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY),
    )
    lifecycle_inputs = lifecycle_fx._Inputs(
        ignored_root=prepared.ignored_root,
        artifact_directory=prepared.artifact_directory,
        decision=decision,
        envelope=envelope,
        verification=verification,
    )
    repository = lifecycle_fx._repository(lifecycle_inputs)
    attempt = lifecycle_fx._reserve(lifecycle_inputs, repository)
    progress = repository._retain_bridge_required_progress(attempt)
    attempt_record = attempt.record
    progress_record = progress.record
    locator = attempt_record.durable_shutdown_locator
    topology = locator.persistent_topology

    class StableRecoveryState:
        status = bridge.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
        outcome = None

        def __init__(self) -> None:
            self.attempt = attempt
            self.progress = progress

        def __post_init__(self) -> None:
            return None

    def decode_attempt(encoded: object) -> object:
        if encoded != attempt.encoded:
            raise ValueError
        return attempt_record

    def decode_progress(encoded: object) -> object:
        if encoded != progress.encoded:
            raise ValueError
        return progress_record

    monkeypatch.setattr(type(attempt), "__post_init__", lambda self: None)
    monkeypatch.setattr(type(progress), "__post_init__", lambda self: None)
    monkeypatch.setattr(type(attempt_record), "__post_init__", lambda self: None)
    monkeypatch.setattr(type(progress_record), "__post_init__", lambda self: None)
    monkeypatch.setattr(
        type(attempt_record),
        "durable_shutdown_locator",
        property(lambda self: locator),
    )
    monkeypatch.setattr(
        type(attempt_record),
        "record_sha256",
        property(lambda self: attempt.artifact_sha256),
    )
    monkeypatch.setattr(
        type(progress_record),
        "record_sha256",
        property(lambda self: progress.artifact_sha256),
    )
    monkeypatch.setattr(type(locator), "__post_init__", lambda self: None)
    monkeypatch.setattr(
        type(locator),
        "persistent_topology",
        property(lambda self: topology),
    )
    monkeypatch.setattr(
        bridge,
        "decode_post_enrollment_graceful_stop_attempt_bytes",
        decode_attempt,
    )
    monkeypatch.setattr(
        bridge,
        "decode_post_enrollment_graceful_stop_progress_bytes",
        decode_progress,
    )
    monkeypatch.setattr(
        bridge,
        "inspect_post_enrollment_graceful_stop_recovery_state",
        lambda **_: StableRecoveryState(),
    )
    evidence = _DurableBridgeInputs(
        prepared=prepared,
        receipt=receipt,
        attempt=attempt,
        progress=progress,
    )
    try:
        yield evidence
    finally:
        monkeypatch.undo()


@pytest.fixture(autouse=True)
def _isolated_one_shot_registries() -> Any:
    assert _registry_sizes() == (0, 0, 0, 0, 0)
    bridge._SEEN_AUTHENTICATED_REQUEST_SHA256S.clear()
    try:
        yield
    finally:
        decision_artifacts._PENDING_LOADED_RECEIPT_REGISTRY.clear()
        decision_artifacts._LOADED_RECEIPT_REGISTRY.clear()
        bridge._AUTHENTICATED_REQUEST_REGISTRY.clear()
        bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.clear()
        bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256.clear()
        bridge._SEEN_AUTHENTICATED_REQUEST_SHA256S.clear()
        bridge._COMPOSITE_REGISTRY.clear()


def _load_pending(
    evidence: _DurableBridgeInputs,
) -> LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    return decision_fx._load_pending_receipt(evidence.prepared, evidence.receipt)


def _build_request(
    evidence: _DurableBridgeInputs,
    loaded: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    return bridge.build_post_enrollment_graceful_stop_supervisor_clean_stop_request(
        loaded_decision_artifact_receipt=loaded,
        start_operator_attested_approval_artifact=evidence.prepared.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(
            evidence.receipt.graceful_stop_decision_v1_sha256
        ),
        retained_attempt=evidence.attempt,
        retained_progress=evidence.progress,
        artifact_directory=evidence.prepared.artifact_directory,
        ignored_root=evidence.prepared.ignored_root,
    )


def _terminal_evidence(
    request: core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
) -> _TerminalEvidence:
    issuer, _, _ = reauth_fx._harness()
    postcondition = issuer.reauthenticate_clean_stop_terminal_once()
    fields: dict[str, object] = {
        "request_sequence": 7,
        "request_scheduled_monotonic_ns": 123,
        "anchor_sequence": postcondition.anchor_sequence,
        "checkpoint_reason": postcondition.checkpoint_reason,
        "confirmed_anchor_count": postcondition.confirmed_anchor_count,
        "local_transition_count": postcondition.local_transition_count,
        "confirmed_anchor_local_transition_ordinal": (
            postcondition.confirmed_anchor_local_transition_ordinal
        ),
        "predecessor_anchor_sha256": postcondition.predecessor_anchor_sha256,
        "current_host_head_sha256": postcondition.current_host_head_sha256,
        "current_anchor_sha256": postcondition.current_anchor_sha256,
        "current_anchor_semantic_sha256": postcondition.current_anchor_semantic_sha256,
        "receipt_observed_at_utc": postcondition.receipt_observed_at_utc,
        "full_audit_completed": False,
        "prior_pending_intent_recovered": True,
        "uploaded_anchor_count": 1,
        "idempotent_duplicate_count": 0,
        "current_anchor_intent_semantic_sha256": (postcondition.anchor_intent_semantic_sha256),
        "current_candidate_remote_readback_sha256": (
            postcondition.candidate_remote_readback_sha256
        ),
        "current_receipt_semantic_sha256": postcondition.receipt_semantic_sha256,
    }
    fields["clean_stop_terminal_result_semantic_sha256"] = core_bridge._result_semantic_sha256(
        tuple(fields[name] for name in core_bridge._TERMINAL_FIELDS[:-1])
    )
    issued = core_bridge._new_result(request_encoded=request.encoded, fields=fields)
    result = core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
        core_bridge.canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes(
            issued
        )
    )
    return _TerminalEvidence(
        issuer=issuer,
        postcondition=postcondition,
        result=result,
    )


def _bind(
    evidence: _DurableBridgeInputs,
    loaded: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    request: core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    terminal: _TerminalEvidence,
) -> bridge.TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation:
    return bridge.bind_post_enrollment_graceful_stop_operation_bound_terminal_observation(
        loaded_decision_artifact_receipt=loaded,
        retained_attempt=evidence.attempt,
        retained_progress=evidence.progress,
        artifact_directory=evidence.prepared.artifact_directory,
        ignored_root=evidence.prepared.ignored_root,
        request=request,
        operation_bound_result=terminal.result,
        terminal_postcondition=terminal.postcondition,
        terminal_reauthentication_issuer=terminal.issuer,
    )


def test_real_loaded_receipt_is_authenticated_consumed_and_bound_without_authority(
    durable_bridge_inputs: _DurableBridgeInputs,
) -> None:
    evidence = durable_bridge_inputs
    loaded = _load_pending(evidence)
    assert _registry_sizes()[:2] == (1, 0)

    request = _build_request(evidence, loaded)

    assert _registry_sizes() == (0, 0, 1, 1, 1)
    assert (
        request.graceful_stop_decision_artifact_receipt_sha256
        == hashlib.sha256(
            bridge.canonical_first_enrollment_json_bytes(evidence.receipt.public_payload)
        ).hexdigest()
    )
    assert (
        decision_artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            artifact_directory=evidence.prepared.artifact_directory,
            ignored_root=evidence.prepared.ignored_root,
        )
        is False
    )

    terminal = _terminal_evidence(request)
    observation = _bind(evidence, loaded, request, terminal)
    payload = observation.payload()

    assert _registry_sizes() == (0, 0, 0, 0, 0)
    assert observation.decision_artifact_receipt_authenticated is True
    assert observation.historical_start_chain_authenticated is True
    assert observation.exact_terminal_projection_cross_bound_unqualified is True
    assert observation.provider_terminal_observed_under_stable_sql_authenticated is True
    assert payload["decision_artifact_receipt_authenticated"] is True
    assert payload["historical_start_chain_authenticated"] is True
    assert all(payload[name] is False for name in bridge._CLOSED_FIELDS)
    assert all(payload[name] is False for name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS)


def test_loaded_receipt_and_request_scalar_replays_are_burned(
    durable_bridge_inputs: _DurableBridgeInputs,
) -> None:
    evidence = durable_bridge_inputs
    loaded = _load_pending(evidence)
    request = _build_request(evidence, loaded)

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _build_request(evidence, loaded)
    assert _registry_sizes() == (0, 0, 1, 1, 1)

    scalar_equal_request = (
        core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
            core_bridge.canonical_trusted_time_head_anchor_operation_bound_clean_stop_request_bytes(
                request
            )
        )
    )
    assert scalar_equal_request is not request
    assert scalar_equal_request.request_sha256 == request.request_sha256
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        bridge.bind_post_enrollment_graceful_stop_operation_bound_terminal_observation(
            loaded_decision_artifact_receipt=loaded,
            retained_attempt=evidence.attempt,
            retained_progress=evidence.progress,
            artifact_directory=evidence.prepared.artifact_directory,
            ignored_root=evidence.prepared.ignored_root,
            request=scalar_equal_request,
            operation_bound_result=cast(Any, object()),
            terminal_postcondition=cast(Any, object()),
            terminal_reauthentication_issuer=cast(Any, object()),
        )
    assert _registry_sizes() == (0, 0, 0, 0, 0)


def test_unregistered_loaded_receipt_copy_cannot_substitute_for_exact_pending_identity(
    durable_bridge_inputs: _DurableBridgeInputs,
) -> None:
    evidence = durable_bridge_inputs
    loaded = _load_pending(evidence)
    with pytest.raises(
        decision_artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ):
        copy.copy(loaded)

    scalar_equal_copy = decision_fx._clone_pending_receipt(loaded)
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _build_request(evidence, scalar_equal_copy)
    assert _registry_sizes() == (1, 0, 0, 0, 0)

    request = _build_request(evidence, loaded)
    terminal = _terminal_evidence(request)
    _bind(evidence, loaded, request, terminal)
    assert _registry_sizes() == (0, 0, 0, 0, 0)


@pytest.mark.parametrize("drift_kind", ["stale-bytes", "replacement-inode"])
def test_source_drift_between_load_and_bridge_authentication_burns_receipt(
    durable_bridge_inputs: _DurableBridgeInputs,
    drift_kind: str,
) -> None:
    evidence = durable_bridge_inputs
    loaded = _load_pending(evidence)
    candidate_path = evidence.candidate_path
    original = candidate_path.read_bytes()
    backup = candidate_path.parent.parent / f"{candidate_path.name}.{drift_kind}.backup"
    try:
        if drift_kind == "stale-bytes":
            candidate_path.write_bytes(original + b" ")
            candidate_path.chmod(0o600)
        else:
            os.replace(candidate_path, backup)
            candidate_path.write_bytes(original)
            candidate_path.chmod(0o600)
        with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
            _build_request(evidence, loaded)
        assert _registry_sizes() == (0, 0, 0, 0, 0)
    finally:
        if drift_kind == "replacement-inode":
            if candidate_path.exists():
                candidate_path.unlink()
            if backup.exists():
                os.replace(backup, candidate_path)
        else:
            candidate_path.write_bytes(original)
            candidate_path.chmod(0o600)


def test_failure_after_real_receipt_consumption_leaves_no_request_registration(
    durable_bridge_inputs: _DurableBridgeInputs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = durable_bridge_inputs
    loaded = _load_pending(evidence)
    monkeypatch.setattr(
        bridge,
        "_request_from_exact_evidence",
        lambda **_: (_ for _ in ()).throw(RuntimeError("injected post-consumption failure")),
    )

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _build_request(evidence, loaded)

    assert _registry_sizes() == (0, 0, 0, 0, 0)
    assert (
        decision_artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            artifact_directory=evidence.prepared.artifact_directory,
            ignored_root=evidence.prepared.ignored_root,
        )
        is False
    )
    del loaded
    gc.collect()
