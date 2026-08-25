from __future__ import annotations

import copy
import gc
import hashlib
import inspect
import os
import pickle
import select
import signal
import threading
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from packages.application import (
    trusted_time_head_anchor_clean_stop_supervisor_bridge as core_bridge,
)
from packages.application.trusted_time_head_anchor import (
    TrustedTimeHeadAnchorCheckpointReason,
)
from scripts import (
    trusted_time_post_enrollment_graceful_stop_decision_artifacts as decision_artifacts,
)
from scripts import trusted_time_post_enrollment_graceful_stop_supervisor_bridge as bridge
from scripts.trusted_time_post_enrollment_clean_stop_terminal_reauthentication import (
    TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer,
)
from scripts.trusted_time_post_enrollment_graceful_stop_decision_artifacts import (
    LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
    TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
)
from scripts.trusted_time_post_enrollment_graceful_stop_lifecycle import (
    RetainedTrustedTimePostEnrollmentGracefulStopAttempt,
    RetainedTrustedTimePostEnrollmentGracefulStopProgress,
    load_retained_post_enrollment_graceful_stop_attempt,
    load_retained_post_enrollment_graceful_stop_progress,
)
from tests.unit import (
    test_trusted_time_post_enrollment_clean_stop_terminal_reauthentication as reauth_fx,
)
from tests.unit import test_trusted_time_post_enrollment_graceful_stop_lifecycle as lifecycle_fx


@dataclass(frozen=True, slots=True)
class _LifecycleEvidence:
    receipt: TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    loaded_receipt: LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    start_operator_attested_approval_artifact: Path
    attempt: RetainedTrustedTimePostEnrollmentGracefulStopAttempt
    progress: RetainedTrustedTimePostEnrollmentGracefulStopProgress
    artifact_directory: Path
    ignored_root: Path
    locator: object
    topology: dict[str, object]


@dataclass(frozen=True, slots=True)
class _TerminalEvidence:
    issuer: TrustedTimePostEnrollmentCleanStopTerminalReauthenticationIssuer
    postcondition: TrustedTimePostEnrollmentCleanStopTerminalPostcondition
    result: core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopResult


def _scalar_equal_clone(value: object) -> object:
    clone = object.__new__(type(value))
    for item in dataclass_fields(value):
        object.__setattr__(clone, item.name, getattr(value, item.name))
    return clone


def _different_digest(value: object) -> str:
    return "0" * 64 if value != "0" * 64 else "1" * 64


@pytest.fixture(scope="module")
def lifecycle_evidence(
    tmp_path_factory: pytest.TempPathFactory,
) -> _LifecycleEvidence:
    tmp_path = tmp_path_factory.mktemp("host-bridge")
    base = lifecycle_fx.base_evidence.__wrapped__()
    inputs = lifecycle_fx._inputs(base, tmp_path, name="lifecycle")
    repository = lifecycle_fx._repository(inputs)
    attempt = lifecycle_fx._reserve(inputs, repository)
    repository._retain_bridge_required_progress(attempt)
    return _load_lifecycle_evidence((inputs.artifact_directory, inputs.ignored_root))


def _load_lifecycle_evidence(roots: tuple[Path, Path]) -> _LifecycleEvidence:
    artifact_directory, ignored_root = roots
    attempt = load_retained_post_enrollment_graceful_stop_attempt(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    progress = load_retained_post_enrollment_graceful_stop_progress(
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
    )
    locator = attempt.record.durable_shutdown_locator
    topology = locator.persistent_topology
    launch = cast(dict[str, object], topology["approved_launch"])
    receipt = TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt(
        artifact_location=decision_artifacts._decision_candidate_file_name(
            attempt.record.graceful_stop_decision_v1_sha256
        ),
        controller_outcome_sha256=attempt.record.controller_outcome_sha256,
        durable_shutdown_locator_sha256=attempt.record.durable_shutdown_locator_sha256,
        graceful_stop_decision_v1_sha256=attempt.record.graceful_stop_decision_v1_sha256,
        graceful_stop_operation_id=attempt.record.graceful_stop_operation_id,
        graceful_stop_target_sha256=attempt.record.graceful_stop_target_sha256,
        start_approval_sha256=attempt.record.start_approval_sha256,
        start_approved_image_provenance_sha256=cast(str, launch["image_admission_sha256"]),
        start_approved_image_provenance_source_revision_sha256="f" * 64,
        start_execution_attempt_slot_sha256=(attempt.record.start_execution_attempt_slot_sha256),
        start_git_revision=cast(str, launch["git_revision"]),
        start_operation_id=attempt.record.start_operation_id,
        start_operator_attestation_envelope_sha256=(
            attempt.record.start_operator_attestation_envelope_sha256
        ),
        start_source_image_id=cast(str, launch["source_image_id"]),
        start_supervisor_image_id=cast(str, launch["supervisor_image_id"]),
        _construction_capability=decision_artifacts._RECEIPT_CONSTRUCTION_CAPABILITY,
    )
    receipt_encoded = bridge.canonical_first_enrollment_json_bytes(receipt.public_payload)
    loaded_receipt = LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt(
        artifact_path=artifact_directory / receipt.artifact_location,
        encoded=b"{}\n",
        directory_identity=(1, 2),
        file_identity=(1, 2, 0o100600, os.geteuid(), 0, 1, 3, 0, 0),
        receipt_encoded=receipt_encoded,
        receipt_sha256=hashlib.sha256(receipt_encoded).hexdigest(),
        _construction_capability=decision_artifacts._LOADED_RECEIPT_CONSTRUCTION_CAPABILITY,
    )
    return _LifecycleEvidence(
        receipt=receipt,
        loaded_receipt=loaded_receipt,
        start_operator_attested_approval_artifact=(artifact_directory / "test-start-approval.json"),
        attempt=attempt,
        progress=progress,
        artifact_directory=artifact_directory,
        ignored_root=ignored_root,
        locator=locator,
        topology=topology,
    )


@pytest.fixture(autouse=True)
def _fast_stable_lifecycle_view(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
) -> Any:
    """Keep adversarial host tests focused after one real durable fixture load."""

    attempt_record = lifecycle_evidence.attempt.record
    progress_record = lifecycle_evidence.progress.record
    receipt_values = {
        name: getattr(lifecycle_evidence.receipt, name)
        for name in bridge._DECISION_RECEIPT_IDENTITY_FIELDS
    }
    receipt_seal = lifecycle_evidence.receipt._sealed_fields
    attempt_record_identity = lifecycle_evidence.attempt.record
    attempt_seal = lifecycle_evidence.attempt._sealed_fields
    progress_record_identity = lifecycle_evidence.progress.record
    progress_seal = lifecycle_evidence.progress._sealed_fields
    loaded_seal = lifecycle_evidence.loaded_receipt._sealed_fields

    bridge._AUTHENTICATED_REQUEST_REGISTRY.clear()
    bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.clear()
    bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256.clear()
    bridge._SEEN_AUTHENTICATED_REQUEST_SHA256S.clear()
    bridge._COMPOSITE_REGISTRY.clear()

    def consume_loaded_receipt(
        loaded: object,
        *,
        consumer_identity: object,
        **_: object,
    ) -> object:
        assert loaded is lifecycle_evidence.loaded_receipt
        receipt_encoded = bridge.canonical_first_enrollment_json_bytes(
            lifecycle_evidence.receipt.public_payload
        )
        candidate = object.__new__(bridge._ConsumedLoadedDecisionArtifactReceiptSnapshot)
        for name, value in {
            "loaded_identity": loaded,
            "consumer_identity": consumer_identity,
            "owner_pid": bridge._ORIGIN_PID,
            "owner_thread": threading.current_thread(),
            "historical_snapshot": (),
            "source_snapshot": (),
            "artifact_directory": os.fspath(lifecycle_evidence.artifact_directory),
            "ignored_root": os.fspath(lifecycle_evidence.ignored_root),
            "receipt_identity_values": tuple(
                getattr(lifecycle_evidence.receipt, name)
                for name in bridge._DECISION_RECEIPT_IDENTITY_FIELDS
            ),
            "receipt_encoded": receipt_encoded,
            "receipt_sha256": hashlib.sha256(receipt_encoded).hexdigest(),
            "_construction_capability": object(),
        }.items():
            object.__setattr__(candidate, name, value)
        return candidate

    def require_consumed(
        value: object,
        *,
        loaded_identity: object,
        consumer_identity: object,
    ) -> object:
        if (
            type(value) is not bridge._ConsumedLoadedDecisionArtifactReceiptSnapshot
            or value.loaded_identity is not loaded_identity
            or value.consumer_identity is not consumer_identity
        ):
            raise ValueError
        return value

    class State:
        status = bridge.TrustedTimePostEnrollmentGracefulStopRecoveryStateStatus.RECOVERY_REQUIRED
        attempt = lifecycle_evidence.attempt
        progress = lifecycle_evidence.progress
        outcome = None

        def __post_init__(self) -> None:
            return None

    def decode_attempt(encoded: object) -> object:
        if encoded != lifecycle_evidence.attempt.encoded:
            raise ValueError
        return attempt_record

    def decode_progress(encoded: object) -> object:
        if encoded != lifecycle_evidence.progress.encoded:
            raise ValueError
        return progress_record

    monkeypatch.setattr(
        type(lifecycle_evidence.attempt),
        "__post_init__",
        lambda self: None,
    )
    monkeypatch.setattr(
        type(lifecycle_evidence.progress),
        "__post_init__",
        lambda self: None,
    )
    monkeypatch.setattr(type(attempt_record), "__post_init__", lambda self: None)
    monkeypatch.setattr(type(progress_record), "__post_init__", lambda self: None)
    monkeypatch.setattr(
        type(attempt_record),
        "durable_shutdown_locator",
        property(lambda self: lifecycle_evidence.locator),
    )
    monkeypatch.setattr(
        type(attempt_record),
        "record_sha256",
        property(lambda self: lifecycle_evidence.attempt.artifact_sha256),
    )
    monkeypatch.setattr(
        type(progress_record),
        "record_sha256",
        property(lambda self: lifecycle_evidence.progress.artifact_sha256),
    )
    monkeypatch.setattr(type(lifecycle_evidence.locator), "__post_init__", lambda self: None)
    monkeypatch.setattr(
        type(lifecycle_evidence.locator),
        "persistent_topology",
        property(lambda self: lifecycle_evidence.topology),
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
        lambda **_: State(),
    )
    monkeypatch.setattr(
        bridge,
        "_authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge",
        consume_loaded_receipt,
    )
    monkeypatch.setattr(
        bridge,
        "_require_consumed_loaded_decision_artifact_receipt_snapshot",
        require_consumed,
    )
    yield
    for name, value in receipt_values.items():
        object.__setattr__(lifecycle_evidence.receipt, name, value)
    object.__setattr__(lifecycle_evidence.receipt, "_sealed_fields", receipt_seal)
    object.__setattr__(lifecycle_evidence.attempt, "record", attempt_record_identity)
    object.__setattr__(lifecycle_evidence.attempt, "_sealed_fields", attempt_seal)
    object.__setattr__(lifecycle_evidence.progress, "record", progress_record_identity)
    object.__setattr__(lifecycle_evidence.progress, "_sealed_fields", progress_seal)
    object.__setattr__(lifecycle_evidence.loaded_receipt, "_sealed_fields", loaded_seal)
    bridge._AUTHENTICATED_REQUEST_REGISTRY.clear()
    bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID.clear()
    bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256.clear()
    bridge._SEEN_AUTHENTICATED_REQUEST_SHA256S.clear()
    bridge._COMPOSITE_REGISTRY.clear()


def _request(
    evidence: _LifecycleEvidence,
) -> core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest:
    return bridge.build_post_enrollment_graceful_stop_supervisor_clean_stop_request(
        loaded_decision_artifact_receipt=evidence.loaded_receipt,
        start_operator_attested_approval_artifact=(
            evidence.start_operator_attested_approval_artifact
        ),
        expected_graceful_stop_decision_v1_sha256=(
            evidence.receipt.graceful_stop_decision_v1_sha256
        ),
        retained_attempt=evidence.attempt,
        retained_progress=evidence.progress,
        artifact_directory=evidence.artifact_directory,
        ignored_root=evidence.ignored_root,
    )


def _consumed_receipt_snapshot(
    evidence: _LifecycleEvidence,
) -> bridge._DecisionReceiptSnapshot:
    bridge_identity = bridge._new_bridge_identity()
    consumed = bridge._authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge(  # noqa: E501
        evidence.loaded_receipt,
        start_operator_attested_approval_artifact=(
            evidence.start_operator_attested_approval_artifact
        ),
        expected_graceful_stop_decision_v1_sha256=(
            evidence.receipt.graceful_stop_decision_v1_sha256
        ),
        artifact_directory=evidence.artifact_directory,
        ignored_root=evidence.ignored_root,
        consumer_identity=bridge_identity,
    )
    return bridge._capture_consumed_receipt_snapshot(
        consumed,
        loaded_identity=evidence.loaded_receipt,
        bridge_identity=bridge_identity,
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
    issued = core_bridge._new_result(
        request_encoded=request.encoded,
        fields=fields,
    )
    encoded = (
        core_bridge.canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes(
            issued
        )
    )
    result = core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(encoded)
    return _TerminalEvidence(issuer=issuer, postcondition=postcondition, result=result)


def _bind(
    evidence: _LifecycleEvidence,
    request: core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest,
    terminal: _TerminalEvidence,
) -> bridge.TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation:
    return bridge.bind_post_enrollment_graceful_stop_operation_bound_terminal_observation(
        loaded_decision_artifact_receipt=evidence.loaded_receipt,
        retained_attempt=evidence.attempt,
        retained_progress=evidence.progress,
        artifact_directory=evidence.artifact_directory,
        ignored_root=evidence.ignored_root,
        request=request,
        operation_bound_result=terminal.result,
        terminal_postcondition=terminal.postcondition,
        terminal_reauthentication_issuer=terminal.issuer,
    )


def test_request_and_terminal_composite_are_exact_inert_projections(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)

    observation = _bind(evidence, request, terminal)

    assert request.attempt_slot_sha256 == evidence.attempt.artifact_sha256
    assert request.bridge_required_progress_sha256 == evidence.progress.artifact_sha256
    assert (
        request.graceful_stop_decision_artifact_receipt_sha256
        == hashlib.sha256(
            bridge.canonical_first_enrollment_json_bytes(evidence.receipt.public_payload)
        ).hexdigest()
    )
    assert observation.operation_bound_request_sha256 == request.request_sha256
    assert observation.operation_bound_result_sha256 == terminal.result.result_sha256
    assert observation.decision_artifact_receipt_authenticated is True
    assert observation.historical_start_chain_authenticated is True
    assert observation.provider_terminal_observed_under_stable_sql_authenticated is True
    assert observation.exact_terminal_projection_cross_bound_unqualified is True
    assert observation.status == bridge.POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS
    assert (
        observation.semantic_sha256
        == hashlib.sha256(
            bridge.canonical_first_enrollment_json_bytes(observation.payload())
        ).hexdigest()
    )
    for field_name in bridge._CLOSED_FIELDS:
        assert getattr(observation, field_name) is False
        assert observation.payload()[field_name] is False
    registration = bridge._COMPOSITE_REGISTRY[id(observation)]
    assert registration.source_identities == (
        evidence.loaded_receipt,
        registration.request_evidence_snapshot.receipt.consumed_identity,
        registration.authenticated_request_registration,
        evidence.attempt,
        evidence.progress,
        request,
        terminal.result,
        terminal.postcondition,
        terminal.issuer,
        registration.bridge_identity,
    )


def test_request_builder_uses_coherent_inspections_and_rejects_live_record_mutation(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    original = bridge.inspect_post_enrollment_graceful_stop_recovery_state
    calls = 0

    def inspect_and_mutate(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        state = original(**cast(Any, kwargs))
        if calls == 1:
            clone = _scalar_equal_clone(evidence.attempt.record)
            object.__setattr__(
                evidence.attempt,
                "record",
                clone,
            )
            object.__setattr__(
                evidence.attempt,
                "_sealed_fields",
                (
                    clone,
                    evidence.attempt.artifact_sha256,
                    evidence.attempt.artifact_path,
                    evidence.attempt.encoded,
                    evidence.attempt.file_identity,
                ),
            )
        return state

    monkeypatch.setattr(
        bridge,
        "inspect_post_enrollment_graceful_stop_recovery_state",
        inspect_and_mutate,
    )
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _request(evidence)
    assert calls == 1


@pytest.mark.parametrize(
    "mutation",
    ["loaded_identity", "consumer_identity", "identity_values", "encoded", "sha256"],
)
def test_request_builder_rejects_consumed_receipt_snapshot_identity_and_value_spoof(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
    mutation: str,
) -> None:
    evidence = lifecycle_evidence
    original = bridge._authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge  # noqa: E501
    calls = 0

    def consume(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        consumed = original(*cast(Any, args), **cast(Any, kwargs))
        if mutation == "loaded_identity":
            object.__setattr__(consumed, "loaded_identity", object())
        elif mutation == "consumer_identity":
            object.__setattr__(consumed, "consumer_identity", object())
        elif mutation == "identity_values":
            values = list(consumed.receipt_identity_values)
            values[bridge._DECISION_RECEIPT_IDENTITY_FIELDS.index("start_git_revision")] = "e" * 40
            object.__setattr__(consumed, "receipt_identity_values", tuple(values))
        elif mutation == "encoded":
            object.__setattr__(consumed, "receipt_encoded", b"{}\n")
        else:
            object.__setattr__(consumed, "receipt_sha256", "0" * 64)
        return consumed

    monkeypatch.setattr(
        bridge,
        "_authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge",
        consume,
    )

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _request(evidence)

    assert calls == 1


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("stop_effect_authorized", True),
        ("historical_evidence_only", False),
        ("contract_version", "evil-v1"),
        ("service", "evil-service"),
        ("status", "evil-status"),
        ("authority_granted", True),
    ],
)
def test_request_builder_rejects_every_receipt_semantic_category_spoof(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
    field_name: str,
    replacement: object,
) -> None:
    evidence = lifecycle_evidence
    assert field_name in bridge.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS
    original = bridge._authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge  # noqa: E501

    def consume(*args: object, **kwargs: object) -> object:
        consumed = original(*cast(Any, args), **cast(Any, kwargs))
        payload = evidence.receipt.public_payload
        payload[field_name] = replacement
        encoded = bridge.canonical_first_enrollment_json_bytes(payload)
        object.__setattr__(consumed, "receipt_encoded", encoded)
        object.__setattr__(
            consumed,
            "receipt_sha256",
            hashlib.sha256(encoded).hexdigest(),
        )
        return consumed

    monkeypatch.setattr(
        bridge,
        "_authenticate_and_consume_loaded_post_enrollment_graceful_stop_decision_artifact_receipt_for_supervisor_bridge",
        consume,
    )

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _request(evidence)


def test_request_snapshot_rejects_values_not_decoded_from_its_receipt_bytes(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    receipt_snapshot = _consumed_receipt_snapshot(evidence)
    snapshot = bridge._capture_request_evidence_snapshot(
        decision_artifact_receipt=receipt_snapshot,
        retained_attempt=evidence.attempt,
        retained_progress=evidence.progress,
    )
    values = list(snapshot.receipt.values)
    values[bridge._DECISION_RECEIPT_IDENTITY_FIELDS.index("start_git_revision")] = "e" * 40
    inconsistent = bridge._RequestEvidenceSnapshot(
        receipt=bridge._DecisionReceiptSnapshot(
            loaded_identity=snapshot.receipt.loaded_identity,
            bridge_identity=snapshot.receipt.bridge_identity,
            consumed_identity=snapshot.receipt.consumed_identity,
            values=tuple(values),
            encoded=snapshot.receipt.encoded,
            receipt_sha256=snapshot.receipt.receipt_sha256,
        ),
        attempt=snapshot.attempt,
        progress=snapshot.progress,
    )

    with pytest.raises(ValueError):
        bridge._request_from_snapshot(inconsistent)


@pytest.mark.parametrize("record_name", ["attempt", "progress"])
def test_request_builder_rejects_scalar_equal_live_record_swap(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
    record_name: str,
) -> None:
    evidence = lifecycle_evidence
    original = bridge.inspect_post_enrollment_graceful_stop_recovery_state

    def inspect_and_swap(**kwargs: object) -> object:
        state = original(**cast(Any, kwargs))
        retained = getattr(evidence, record_name)
        if record_name == "attempt":
            clone = _scalar_equal_clone(retained.record)
            sealed = (
                clone,
                retained.artifact_sha256,
                retained.artifact_path,
                retained.encoded,
                retained.file_identity,
            )
        else:
            clone = _scalar_equal_clone(retained.record)
            sealed = (
                clone,
                retained.artifact_sha256,
                retained.artifact_path,
                retained.encoded,
                retained.file_identity,
                retained.attempt_slot_file_identity,
            )
        object.__setattr__(retained, "record", clone)
        object.__setattr__(retained, "_sealed_fields", sealed)
        return state

    monkeypatch.setattr(
        bridge,
        "inspect_post_enrollment_graceful_stop_recovery_state",
        inspect_and_swap,
    )
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _request(evidence)


def test_request_builder_aba_callback_never_changes_snapshot_derived_request(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    receipt_snapshot = _consumed_receipt_snapshot(evidence)
    expected = bridge._request_from_exact_evidence(
        decision_artifact_receipt=receipt_snapshot,
        retained_attempt=evidence.attempt,
        retained_progress=evidence.progress,
        artifact_directory=evidence.artifact_directory,
        ignored_root=evidence.ignored_root,
    ).encoded
    original = bridge.inspect_post_enrollment_graceful_stop_recovery_state
    calls = 0

    def inspect_with_aba(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        state = original(**cast(Any, kwargs))
        original_revision = evidence.receipt.start_approved_image_provenance_source_revision_sha256
        object.__setattr__(
            evidence.receipt,
            "start_approved_image_provenance_source_revision_sha256",
            "e" * 64,
        )
        object.__setattr__(
            evidence.receipt,
            "_sealed_fields",
            decision_artifacts._receipt_seal_values(evidence.receipt),
        )
        object.__setattr__(
            evidence.receipt,
            "start_approved_image_provenance_source_revision_sha256",
            original_revision,
        )
        object.__setattr__(
            evidence.receipt,
            "_sealed_fields",
            decision_artifacts._receipt_seal_values(evidence.receipt),
        )
        return state

    monkeypatch.setattr(
        bridge,
        "inspect_post_enrollment_graceful_stop_recovery_state",
        inspect_with_aba,
    )
    observed = _request(evidence)

    assert calls == 3
    assert observed.encoded == expected


def test_abandoned_authenticated_request_gc_cleans_every_live_index(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    request_id = id(request)
    request_sha256 = request.request_sha256
    loaded_id = id(evidence.loaded_receipt)

    assert bridge._AUTHENTICATED_REQUEST_REGISTRY[request_id].request_reference() is request
    assert bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID[loaded_id] == request_id
    assert bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256[request_sha256] == request_id

    del request
    gc.collect()

    assert request_id not in bridge._AUTHENTICATED_REQUEST_REGISTRY
    assert loaded_id not in bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID
    assert request_sha256 not in bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256
    assert request_sha256 in bridge._SEEN_AUTHENTICATED_REQUEST_SHA256S


def test_scalar_equal_request_copy_burns_request_and_postcondition(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    copied_request = core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
        request.encoded
    )
    terminal = _terminal_evidence(request)

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, copied_request, terminal)
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, request, terminal)

    assert bridge._AUTHENTICATED_REQUEST_REGISTRY == {}
    assert bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID == {}
    assert bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256 == {}


def test_interrupted_request_pop_is_retried_to_complete_burn(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    original = bridge._remove_authenticated_request_registration_locked
    calls = 0

    def interrupt_once(request_id: int, registration: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt
        original(request_id, cast(Any, registration))

    monkeypatch.setattr(
        bridge,
        "_remove_authenticated_request_registration_locked",
        interrupt_once,
    )

    with pytest.raises(KeyboardInterrupt):
        _bind(evidence, request, terminal)

    assert calls == 2
    assert bridge._AUTHENTICATED_REQUEST_REGISTRY == {}
    assert bridge._AUTHENTICATED_REQUEST_ID_BY_LOADED_ID == {}
    assert bridge._AUTHENTICATED_REQUEST_ID_BY_SHA256 == {}
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, request, terminal)


def test_wrong_thread_request_use_burns_the_one_shot_association(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    observed: list[BaseException | None] = []

    def bind_in_thread() -> None:
        try:
            _bind(evidence, request, terminal)
        except BaseException as error:
            observed.append(error)
        else:
            observed.append(None)

    thread = threading.Thread(target=bind_in_thread)
    thread.start()
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert len(observed) == 1
    assert isinstance(
        observed[0],
        bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected,
    )
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, request, terminal)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork process semantics")
def test_request_registry_held_across_fork_rejects_child_without_deadlock(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    read_fd, write_fd = os.pipe()
    bridge._AUTHENTICATED_REQUEST_REGISTRY_LOCK.acquire()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_fd)
        try:
            _bind(evidence, request, terminal)
        except bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected:
            observed = b"1"
        else:
            observed = b"0"
        os.write(write_fd, observed)
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    try:
        readable, _, _ = select.select([read_fd], [], [], 2.0)
    finally:
        bridge._AUTHENTICATED_REQUEST_REGISTRY_LOCK.release()
    if readable:
        observed = os.read(read_fd, 1)
    else:
        observed = b""
        os.kill(child_pid, signal.SIGKILL)
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)

    assert readable == [read_fd]
    assert status == 0
    assert observed == b"1"
    observation = _bind(evidence, request, terminal)
    assert observation.decision_artifact_receipt_authenticated is True


def test_terminal_projection_mismatch_burns_postcondition_before_correct_retry(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    fields = {name: getattr(terminal.result, name) for name in core_bridge._TERMINAL_FIELDS[:-1]}
    fields["predecessor_anchor_sha256"] = "0" * 64
    fields["clean_stop_terminal_result_semantic_sha256"] = core_bridge._result_semantic_sha256(
        tuple(fields[name] for name in core_bridge._TERMINAL_FIELDS[:-1])
    )
    mismatched = core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
        core_bridge.canonical_trusted_time_head_anchor_operation_bound_clean_stop_result_bytes(
            core_bridge._new_result(request_encoded=request.encoded, fields=fields)
        )
    )

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        bridge.bind_post_enrollment_graceful_stop_operation_bound_terminal_observation(
            loaded_decision_artifact_receipt=evidence.loaded_receipt,
            retained_attempt=evidence.attempt,
            retained_progress=evidence.progress,
            artifact_directory=evidence.artifact_directory,
            ignored_root=evidence.ignored_root,
            request=request,
            operation_bound_result=mismatched,
            terminal_postcondition=terminal.postcondition,
            terminal_reauthentication_issuer=terminal.issuer,
        )
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, request, terminal)


@pytest.mark.parametrize("wire_kind", ["request", "result"])
@pytest.mark.parametrize("spoofed_capture", [1, 2])
def test_binder_rejects_wire_payload_spoof_at_initial_and_issuance_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
    wire_kind: str,
    spoofed_capture: int,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    if wire_kind == "request":
        source: object = request
        request_fields = {name: getattr(request, name) for name in bridge._REQUEST_BINDING_FIELDS}
        request_fields["controller_outcome_sha256"] = "0" * 64
        alternate: object = core_bridge.TrustedTimeHeadAnchorOperationBoundCleanStopRequest(
            **request_fields
        )
    else:
        source = terminal.result
        result_fields = {
            name: getattr(terminal.result, name) for name in core_bridge._TERMINAL_FIELDS[:-1]
        }
        result_fields["predecessor_anchor_sha256"] = "0" * 64
        result_fields["clean_stop_terminal_result_semantic_sha256"] = (
            core_bridge._result_semantic_sha256(
                tuple(result_fields[name] for name in core_bridge._TERMINAL_FIELDS[:-1])
            )
        )
        alternate = core_bridge._new_result(
            request_encoded=request.encoded,
            fields=result_fields,
        )
    source_type = type(source)
    original_payload = source_type.payload
    calls = 0

    def payload(value: object) -> dict[str, object]:
        nonlocal calls
        if value is source:
            calls += 1
            if calls == spoofed_capture:
                return cast(dict[str, object], original_payload(alternate))
        return cast(dict[str, object], original_payload(value))

    monkeypatch.setattr(source_type, "payload", payload)

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, request, terminal)

    assert calls == spoofed_capture + (2 if wire_kind == "request" else 0)


@pytest.mark.parametrize("mutating_read", [1, 2])
def test_binder_rejects_postcondition_mutation_after_registry_snapshot_read(
    monkeypatch: pytest.MonkeyPatch,
    lifecycle_evidence: _LifecycleEvidence,
    mutating_read: int,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    original_values = reauth_fx.reauth_module._postcondition_values
    calls = 0

    def values(
        value: TrustedTimePostEnrollmentCleanStopTerminalPostcondition,
    ) -> tuple[object, ...]:
        nonlocal calls
        captured = original_values(value)
        if value is terminal.postcondition:
            calls += 1
            if calls == mutating_read:
                object.__setattr__(
                    value,
                    "predecessor_anchor_sha256",
                    _different_digest(value.predecessor_anchor_sha256),
                )
        return captured

    monkeypatch.setattr(reauth_fx.reauth_module, "_postcondition_values", values)

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        _bind(evidence, request, terminal)

    assert calls == mutating_read + 2


def test_all_thirteen_terminal_projection_equalities_are_required(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    bridge_identity = bridge._new_bridge_identity()
    postcondition_snapshot = (
        bridge._consume_trusted_time_post_enrollment_clean_stop_terminal_postcondition_once(
            terminal.postcondition,
            issuer=terminal.issuer,
            bridge_identity=bridge_identity,
        )
    )
    result_snapshot = bridge._capture_result_wire_snapshot(terminal.result)
    assert bridge._terminal_projection_matches(result_snapshot, postcondition_snapshot)
    bindings = (
        ("anchor_sequence", "anchor_sequence"),
        ("checkpoint_reason", "checkpoint_reason"),
        ("confirmed_anchor_count", "confirmed_anchor_count"),
        ("local_transition_count", "local_transition_count"),
        (
            "confirmed_anchor_local_transition_ordinal",
            "confirmed_anchor_local_transition_ordinal",
        ),
        ("predecessor_anchor_sha256", "predecessor_anchor_sha256"),
        ("current_host_head_sha256", "current_host_head_sha256"),
        ("current_anchor_sha256", "current_anchor_sha256"),
        ("current_anchor_semantic_sha256", "current_anchor_semantic_sha256"),
        ("current_anchor_intent_semantic_sha256", "anchor_intent_semantic_sha256"),
        (
            "current_candidate_remote_readback_sha256",
            "candidate_remote_readback_sha256",
        ),
        ("current_receipt_semantic_sha256", "receipt_semantic_sha256"),
        ("receipt_observed_at_utc", "receipt_observed_at_utc"),
    )
    assert len(bindings) == 13
    for _, postcondition_name in bindings:
        values = list(postcondition_snapshot.values)
        index = bridge._POSTCONDITION_SNAPSHOT_FIELDS.index(postcondition_name)
        original = values[index]
        if postcondition_name == "checkpoint_reason":
            replacement: object = TrustedTimeHeadAnchorCheckpointReason.PERIODIC
        elif postcondition_name == "receipt_observed_at_utc":
            replacement = original + timedelta(microseconds=1)
        elif type(original) is int:
            replacement = original + 1
        else:
            replacement = "0" * 64 if original != "0" * 64 else "1" * 64
        values[index] = replacement
        changed = bridge._ConsumedPostconditionRegistrySnapshot(
            values=tuple(values),
            semantic_sha256=postcondition_snapshot.semantic_sha256,
            issuer_identity=postcondition_snapshot.issuer_identity,
            bridge_identity=postcondition_snapshot.bridge_identity,
        )
        assert not bridge._terminal_projection_matches(
            result_snapshot,
            changed,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "receipt_inner",
        "attempt_record_swap",
        "progress_record_swap",
        "request_swap",
        "result_swap",
        "postcondition_swap",
        "issuer_swap",
        "bridge_swap",
        "request_snapshot_inner",
        "result_snapshot_inner",
        "postcondition_snapshot_inner",
        "issuer_binding_snapshot",
        "configuration_snapshot",
        "joint_inner",
    ],
)
def test_composite_rejects_nested_seal_rewrites_and_scalar_equal_swaps(
    lifecycle_evidence: _LifecycleEvidence,
    mutation: str,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    observation = _bind(evidence, request, terminal)
    registration = bridge._COMPOSITE_REGISTRY[id(observation)]

    if mutation in {"receipt_inner", "joint_inner"}:
        object.__setattr__(
            registration.request_evidence_snapshot.receipt.consumed_identity,
            "receipt_sha256",
            _different_digest(registration.request_evidence_snapshot.receipt.receipt_sha256),
        )
    if mutation in {"attempt_record_swap", "joint_inner"}:
        clone = _scalar_equal_clone(evidence.attempt.record)
        object.__setattr__(evidence.attempt, "record", clone)
        object.__setattr__(
            evidence.attempt,
            "_sealed_fields",
            (
                clone,
                evidence.attempt.artifact_sha256,
                evidence.attempt.artifact_path,
                evidence.attempt.encoded,
                evidence.attempt.file_identity,
            ),
        )
    if mutation == "progress_record_swap":
        clone = _scalar_equal_clone(evidence.progress.record)
        object.__setattr__(evidence.progress, "record", clone)
        object.__setattr__(
            evidence.progress,
            "_sealed_fields",
            (
                clone,
                evidence.progress.artifact_sha256,
                evidence.progress.artifact_path,
                evidence.progress.encoded,
                evidence.progress.file_identity,
                evidence.progress.attempt_slot_file_identity,
            ),
        )
    if mutation == "request_swap":
        registration.request = (
            core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_request(
                registration.request_wire_snapshot.encoded
            )
        )
    if mutation == "result_swap":
        registration.result = (
            core_bridge.decode_trusted_time_head_anchor_operation_bound_clean_stop_result(
                registration.result_wire_snapshot.encoded
            )
        )
    if mutation == "postcondition_swap":
        replacement = _terminal_evidence(request)
        registration.terminal_postcondition = replacement.postcondition
    if mutation == "issuer_swap":
        replacement_issuer, _, _ = reauth_fx._harness()
        registration.terminal_reauthentication_issuer = replacement_issuer
    if mutation == "bridge_swap":
        registration.bridge_identity = bridge._new_bridge_identity()
    if mutation in {"request_snapshot_inner", "joint_inner"}:
        request_values = list(registration.request_wire_snapshot.values)
        request_values[1] = _different_digest(request_values[1])
        object.__setattr__(
            registration.request_wire_snapshot,
            "values",
            tuple(request_values),
        )
    if mutation in {"result_snapshot_inner", "joint_inner"}:
        object.__setattr__(
            registration.result_wire_snapshot,
            "result_sha256",
            _different_digest(registration.result_wire_snapshot.result_sha256),
        )
    if mutation in {"postcondition_snapshot_inner", "joint_inner"}:
        object.__setattr__(
            registration.postcondition_registry_snapshot,
            "semantic_sha256",
            _different_digest(registration.postcondition_registry_snapshot.semantic_sha256),
        )
    if mutation in {"issuer_binding_snapshot", "joint_inner"}:
        registration.issuer_binding_sha256 = _different_digest(registration.issuer_binding_sha256)
    if mutation in {"configuration_snapshot", "joint_inner"}:
        registration.read_only_configuration_sha256 = _different_digest(
            registration.read_only_configuration_sha256
        )

    for access in (
        lambda: observation.status,
        lambda: observation.semantic_sha256,
        observation.payload,
    ):
        with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
            access()


def test_composite_direct_construction_copy_pickle_and_scalar_drift_are_rejected(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    observation = _bind(evidence, request, terminal)

    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        bridge.TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation()
    for operation in (
        lambda: copy.copy(observation),
        lambda: copy.deepcopy(observation),
        lambda: pickle.dumps(observation),
    ):
        with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
            operation()
    object.__setattr__(observation, "predecessor_anchor_sha256", "0" * 64)
    with pytest.raises(bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected):
        observation.__post_init__()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork process semantics")
def test_composite_registry_held_across_fork_rejects_gc_and_issue_without_deadlock(
    lifecycle_evidence: _LifecycleEvidence,
) -> None:
    evidence = lifecycle_evidence
    request = _request(evidence)
    terminal = _terminal_evidence(request)
    observation = _bind(evidence, request, terminal)
    registration = bridge._COMPOSITE_REGISTRY[id(observation)]
    read_fd, write_fd = os.pipe()
    bridge._COMPOSITE_REGISTRY_LOCK.acquire()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_fd)
        rejected = bytearray()
        try:
            _ = observation.status
        except bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected:
            rejected.extend(b"1")
        else:
            rejected.extend(b"0")
        try:
            bridge._issue_composite(
                loaded_decision_artifact_receipt=evidence.loaded_receipt,
                authenticated_request_registration=(
                    registration.authenticated_request_registration
                ),
                retained_attempt=evidence.attempt,
                retained_progress=evidence.progress,
                request=request,
                result=terminal.result,
                terminal_postcondition=terminal.postcondition,
                terminal_reauthentication_issuer=terminal.issuer,
                bridge_identity=registration.bridge_identity,
                request_wire_snapshot=registration.request_wire_snapshot,
                result_wire_snapshot=registration.result_wire_snapshot,
                postcondition_registry_snapshot=(registration.postcondition_registry_snapshot),
            )
        except bridge.TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected:
            rejected.extend(b"1")
        else:
            rejected.extend(b"0")
        del observation
        gc.collect()
        rejected.extend(b"1")
        os.write(write_fd, bytes(rejected))
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    try:
        readable, _, _ = select.select([read_fd], [], [], 2.0)
    finally:
        bridge._COMPOSITE_REGISTRY_LOCK.release()
    if readable:
        observed = os.read(read_fd, 3)
    else:
        observed = b""
        os.kill(child_pid, signal.SIGKILL)
    os.close(read_fd)
    _, status = os.waitpid(child_pid, 0)

    assert readable == [read_fd]
    assert status == 0
    assert observed == b"111"
    assert observation.status == bridge.POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS


def test_public_surface_has_no_runtime_caller_or_effect_path() -> None:
    assert set(bridge.__all__) == {
        "POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_CONTRACT_VERSION",
        "POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_SERVICE",
        "POST_ENROLLMENT_GRACEFUL_STOP_SUPERVISOR_BRIDGE_STATUS",
        "TrustedTimePostEnrollmentGracefulStopOperationBoundTerminalObservation",
        "TrustedTimePostEnrollmentGracefulStopSupervisorBridgeRejected",
        "bind_post_enrollment_graceful_stop_operation_bound_terminal_observation",
        "build_post_enrollment_graceful_stop_supervisor_clean_stop_request",
    }
    source = inspect.getsource(bridge)
    for forbidden in (
        "subprocess",
        "create_engine",
        "upload_object",
        "docker",
        "signal.",
        "def main(",
        "_take_trusted_time_head_anchor_operation_bound_clean_stop_result_once",
        "_register_trusted_time_head_anchor_operation_bound_clean_stop_request",
    ):
        assert forbidden not in source
