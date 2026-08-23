from __future__ import annotations

import ast
import copy
import dis
import gc
import hashlib
import json
import os
import pickle
import sys
import threading
import weakref
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Never, cast

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from scripts import trusted_time_post_enrollment_controller_outcome as controller_outcome
from scripts import trusted_time_post_enrollment_execution_admission as execution
from scripts import trusted_time_post_enrollment_graceful_stop_decision_artifacts as artifacts
from scripts import verify_trusted_time_images as image_verifier
from scripts.trusted_time_post_enrollment_controller_outcome import (
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
)
from scripts.trusted_time_post_enrollment_execution_admission import (
    POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME,
    LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
    canonical_post_enrollment_graceful_stop_decision_bytes,
    decode_post_enrollment_graceful_stop_decision,
)
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_execution_admission as execution_fx
from tests.unit import test_trusted_time_post_enrollment_graceful_stop as stop_fx
from tests.unit import test_trusted_time_post_enrollment_staged_topology as staged_fx

STOP_OPERATION_ID = "323e4567-e89b-42d3-a456-426614174002"


def _tuple_with_slot(
    value: tuple[object, ...], index: int, replacement: object
) -> tuple[object, ...]:
    return (*value[:index], replacement, *value[index + 1 :])


def _pending_value(
    registration: artifacts._PendingLoadedReceiptRegistration,
    index: int,
) -> object:
    return artifacts._pending_slot(registration, index)


def _registration_value(
    registration: artifacts._LoadedReceiptRegistration,
    index: int,
) -> object:
    return artifacts._registration_slot(registration, index)


def _source_value(snapshot: artifacts._LoadedReceiptSourceSnapshot, index: int) -> object:
    return artifacts._source_slot(snapshot, index)


@pytest.fixture(autouse=True)
def _install_test_observation_validators(monkeypatch: pytest.MonkeyPatch) -> None:
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


@pytest.fixture(autouse=True)
def _require_empty_registry_at_test_entry(request: pytest.FixtureRequest) -> None:
    pending = tuple(artifacts._PENDING_LOADED_RECEIPT_REGISTRY.items())
    active = tuple(artifacts._LOADED_RECEIPT_REGISTRY.items())
    assert not pending and not active, (
        request.node.nodeid,
        tuple(
            (
                candidate_id,
                type(registration).__name__,
                (
                    tuple.__getitem__(registration, 1)()
                    if type(registration) is tuple
                    and len(registration) > 1
                    and isinstance(tuple.__getitem__(registration, 1), weakref.ReferenceType)
                    else "not-an-exact-registration"
                ),
            )
            for candidate_id, registration in (*pending, *active)
        ),
    )


@dataclass(frozen=True, slots=True)
class _PreparedInputs:
    ignored_root: Path
    artifact_directory: Path
    attested_artifact: Path
    loaded: LoadedTrustedTimePostEnrollmentOperatorAttestedExecutionApproval
    outcome: RetainedTrustedTimePostEnrollmentStartControllerOutcome
    attempt_slot_sha256: str
    candidate_directory: Path

    @property
    def locator_sha256(self) -> str:
        value = self.outcome.durable_shutdown_locator_sha256
        assert value is not None
        return value


def _prepared_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> _PreparedInputs:
    (tmp_path / "start").mkdir(mode=0o700)
    (
        _,
        _,
        attested_artifact,
        loaded,
        _,
        attempt_encoded,
    ) = execution_fx._retained_attempt_fixture(tmp_path / "start")
    monkeypatch.setattr(staged_fx, "_approval", lambda: loaded.approval)
    monkeypatch.setattr(
        staged_fx,
        "SOURCE_IMAGE_ID",
        loaded.approval.proposed_launch.source_image_id,
    )
    monkeypatch.setattr(
        staged_fx,
        "SUPERVISOR_IMAGE_ID",
        loaded.approval.proposed_launch.supervisor_image_id,
    )
    (tmp_path / "outcome").mkdir(mode=0o700)
    outcome = stop_fx._confirmed_receipt(monkeypatch, tmp_path / "outcome")
    artifact_directory = outcome.artifact_path.parent
    ignored_root = artifact_directory.parent
    attempt_path = artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    attempt_path.write_bytes(attempt_encoded)
    attempt_path.chmod(0o600)
    provenance_path = artifact_directory / loaded.image_provenance.path.name
    provenance_path.write_bytes(loaded.image_provenance.encoded)
    provenance_path.chmod(0o600)
    monkeypatch.setattr(
        execution,
        "load_post_enrollment_operator_attested_execution_approval",
        lambda **_: loaded,
    )
    authority = execution_fx.build_post_enrollment_operator_authority(
        bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    )
    authority_encoded = execution_fx.canonical_post_enrollment_operator_authority_bytes(authority)
    monkeypatch.setattr(
        execution,
        "_head_reviewed_operator_authority_object",
        lambda _: ("100644", "b" * 40, authority_encoded),
    )
    candidate_directory = tmp_path / "external-stop-decisions"
    candidate_directory.mkdir(mode=0o700)
    return _PreparedInputs(
        ignored_root=ignored_root,
        artifact_directory=artifact_directory,
        attested_artifact=attested_artifact,
        loaded=loaded,
        outcome=outcome,
        attempt_slot_sha256=hashlib.sha256(attempt_encoded).hexdigest(),
        candidate_directory=candidate_directory,
    )


def _prepare(
    inputs: _PreparedInputs, **changes: object
) -> artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    arguments: dict[str, object] = {
        "graceful_stop_operation_id": STOP_OPERATION_ID,
        "start_operator_attested_approval_artifact": inputs.attested_artifact,
        "decision_candidate_directory": inputs.candidate_directory,
        "expected_controller_outcome_sha256": inputs.outcome.outcome_sha256,
        "expected_durable_shutdown_locator_sha256": inputs.locator_sha256,
        "expected_start_execution_attempt_slot_sha256": inputs.attempt_slot_sha256,
        "expected_start_operator_attestation_envelope_sha256": (
            inputs.loaded.operator_attestation_envelope_sha256
        ),
        "expected_start_operation_id": inputs.loaded.approval.operation_id,
        "expected_start_approval_sha256": inputs.loaded.approval.approval_sha256,
        "artifact_directory": inputs.artifact_directory,
        "ignored_root": inputs.ignored_root,
    }
    arguments.update(changes)
    return artifacts.prepare_post_enrollment_graceful_stop_decision_candidate(
        **cast(Any, arguments)
    )


def _load_prepared_receipt(
    inputs: _PreparedInputs,
    receipt: artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    return loaded


def _load_pending_receipt(
    inputs: _PreparedInputs,
    receipt: artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    return artifacts.load_post_enrollment_graceful_stop_decision_artifact_receipt(
        graceful_stop_decision_v1_artifact=(inputs.candidate_directory / receipt.artifact_location),
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )


def _clone_pending_receipt(
    source: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    return artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt(
        artifact_path=source.artifact_path,
        encoded=source.encoded,
        directory_identity=source.directory_identity,
        file_identity=source.file_identity,
        receipt_encoded=source.receipt_encoded,
        receipt_sha256=source.receipt_sha256,
        _construction_capability=artifacts._LOADED_RECEIPT_CONSTRUCTION_CAPABILITY,
    )


def _install_fast_pending_reauthentication(
    monkeypatch: pytest.MonkeyPatch,
    inputs: _PreparedInputs,
    receipt: artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
) -> artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
    real_read = artifacts._read_decision_candidate_binding
    real_load = artifacts._load_historical_start_chain
    captured_binding: list[tuple[Any, Any]] = []
    captured_history: list[tuple[Any, Any]] = []

    def capture_binding(*args: object, **kwargs: object) -> tuple[Any, Any]:
        result = real_read(*cast(Any, args), **cast(Any, kwargs))
        captured_binding.append(result)
        return result

    def capture_history(*args: object, **kwargs: object) -> tuple[Any, Any]:
        result = real_load(*cast(Any, args), **cast(Any, kwargs))
        captured_history.append(result)
        return result

    monkeypatch.setattr(artifacts, "_read_decision_candidate_binding", capture_binding)
    monkeypatch.setattr(artifacts, "_load_historical_start_chain", capture_history)
    pending = _load_pending_receipt(inputs, receipt)
    assert len(captured_binding) == 1
    assert len(captured_history) == 1
    monkeypatch.setattr(
        artifacts,
        "_read_decision_candidate_binding",
        lambda **_: captured_binding[0],
    )
    monkeypatch.setattr(
        artifacts,
        "_load_historical_start_chain",
        lambda **_: captured_history[0],
    )
    monkeypatch.setattr(artifacts, "_revalidate_historical_start_chain", lambda *_args, **_kw: None)
    monkeypatch.setattr(artifacts, "_revalidate_decision_candidate_binding", lambda _binding: None)
    return pending


def _interrupt_instruction(
    target: Any,
    instruction_offset: int,
    action: Any,
    *,
    async_error: type[BaseException],
) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == instruction_offset:
            raise async_error()

    sys.monitoring.use_tool_id(tool_id, "decision-artifact-instruction-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        action()
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)


def _record_instruction_offsets(target: Any, action: Any) -> tuple[int, ...]:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    observed: list[int] = []

    def record(_: object, offset: int) -> None:
        observed.append(offset)

    sys.monitoring.use_tool_id(tool_id, "decision-artifact-instruction-record")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        record,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        action()
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)
    return tuple(observed)


def _act_at_instruction(
    target: Any,
    instruction_offset: int,
    instruction_action: Any,
    action: Any,
) -> Any:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    acted = False

    def act(_: object, offset: int) -> None:
        nonlocal acted
        if offset == instruction_offset and not acted:
            acted = True
            instruction_action()

    sys.monitoring.use_tool_id(tool_id, "decision-artifact-instruction-action-test")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        act,
    )
    sys.monitoring.set_local_events(
        tool_id,
        target.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        return action()
    finally:
        sys.monitoring.set_local_events(tool_id, target.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)


def _open_descriptor_names() -> frozenset[str]:
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.exists():
        descriptor_root = Path("/dev/fd")
    return frozenset(entry.name for entry in descriptor_root.iterdir())


def test_prepare_publishes_exact_inert_content_addressed_decision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)

    receipt = _prepare(inputs)

    artifact_path = inputs.candidate_directory / receipt.artifact_location
    encoded = artifact_path.read_bytes()
    decision = decode_post_enrollment_graceful_stop_decision(encoded)
    assert artifact_path.stat().st_mode & 0o777 == 0o600
    assert artifact_path.stat().st_nlink == 1
    assert receipt.contract_version == artifacts.ARTIFACT_RECEIPT_CONTRACT_VERSION
    assert receipt.service == artifacts.ARTIFACT_WORKFLOW_SERVICE
    assert receipt.status == artifacts.DECISION_CANDIDATE_PREPARED_STATUS
    assert receipt.graceful_stop_decision_v1_sha256 == hashlib.sha256(encoded).hexdigest()
    assert receipt.graceful_stop_operation_id == STOP_OPERATION_ID
    assert receipt.graceful_stop_target_sha256 == decision.target.target_sha256
    assert receipt.start_execution_attempt_slot_sha256 == inputs.attempt_slot_sha256
    assert receipt.start_operator_attestation_envelope_sha256 == (
        inputs.loaded.operator_attestation_envelope_sha256
    )
    assert canonical_post_enrollment_graceful_stop_decision_bytes(decision) == encoded
    assert set(receipt.public_payload) == (
        artifacts.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS
    )
    for field_name in (
        "committed_confirmed_start_outcome_revalidated",
        "decision_candidate_semantically_bound",
        "durable_shutdown_locator_revalidated",
        "external_stop_attestation_required",
        "historical_evidence_only",
        "historical_start_chain_authenticated",
        "later_atomic_stop_admission_revalidation_required",
        "start_execution_attempt_slot_revalidated",
        "start_operator_attestation_envelope_revalidated",
        "verification_only",
    ):
        assert getattr(receipt, field_name) is True
    for field_name in {
        *POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
        "currentness_qualified",
        "freshness_qualified",
        "single_use_qualified",
        "stop_admission_qualified",
        "stop_attempt_slot_reserved",
        "stop_effect_authorized",
        "stop_operator_signature_authenticated",
        "stop_outcome_or_recovery_available",
    }:
        assert getattr(receipt, field_name) is False
        assert receipt.public_payload[field_name] is False
    assert canonical_first_enrollment_json_bytes(receipt.public_payload).endswith(b"\n")


def test_loaded_receipt_reauthenticates_exact_durable_candidate_and_history(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    candidate = inputs.candidate_directory / receipt.artifact_location

    loaded = _load_prepared_receipt(inputs, receipt)

    assert loaded.artifact_path == candidate
    assert loaded.encoded == candidate.read_bytes()
    assert json.loads(loaded.receipt_encoded) == receipt.public_payload
    assert loaded.receipt_sha256 == hashlib.sha256(loaded.receipt_encoded).hexdigest()
    assert loaded.decision_artifact_receipt_authenticated is True
    assert loaded.decision_candidate_retention_revalidated is True
    assert loaded.historical_start_chain_authenticated is True
    assert loaded.verification_only is True
    for field_name in (
        *POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
        "currentness_qualified",
        "freshness_qualified",
        "single_use_qualified",
        "stop_admission_qualified",
        "stop_attempt_slot_reserved",
        "stop_effect_authorized",
        "stop_operator_signature_authenticated",
        "stop_outcome_or_recovery_available",
    ):
        assert getattr(loaded, field_name) is False
    for absent in ("receipt", "decision", "outcome", "attempt", "approval"):
        assert not hasattr(loaded, absent)
    assert (
        artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
        is True
    )
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()
    assert (
        artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
        is False
    )


def test_loaded_receipt_is_inert_until_explicit_fresh_authentication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)

    loaded = _load_pending_receipt(inputs, receipt)

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    assert id(loaded) in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    for field_name in (
        "decision_artifact_receipt_authenticated",
        "decision_candidate_retention_revalidated",
        "historical_start_chain_authenticated",
        "verification_only",
        "currentness_qualified",
        "stop_effect_authorized",
    ):
        with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
            getattr(loaded, field_name)
    for operation in (
        lambda: copy.copy(loaded),
        lambda: copy.deepcopy(loaded),
        lambda: replace(loaded),
        lambda: pickle.dumps(loaded),
    ):
        with pytest.raises(
            (
                TypeError,
                artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
            )
        ):
            operation()

    assert (
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
        is None
    )
    assert loaded.decision_artifact_receipt_authenticated is True
    assert id(loaded) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert id(loaded) in artifacts._LOADED_RECEIPT_REGISTRY
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_loaded_receipt_constructor_never_registers_and_loader_only_pends(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    template = _install_fast_pending_reauthentication(monkeypatch, inputs, receipt)
    template_registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(template)]
    assert (
        artifacts._burn_pending_loaded_receipt_registry_entry(
            id(template),
            registration=template_registration,
        )
        is None
    )
    constructor = (
        artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt.__init__
    )

    def construct() -> None:
        candidate = object.__new__(
            artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
        )
        constructor(
            candidate,
            artifact_path=template.artifact_path,
            encoded=template.encoded,
            directory_identity=template.directory_identity,
            file_identity=template.file_identity,
            receipt_encoded=template.receipt_encoded,
            receipt_sha256=template.receipt_sha256,
            _construction_capability=artifacts._LOADED_RECEIPT_CONSTRUCTION_CAPABILITY,
        )

    constructor_offsets = tuple(dict.fromkeys(_record_instruction_offsets(constructor, construct)))
    assert constructor_offsets
    for async_error in (KeyboardInterrupt, SystemExit):
        for instruction_offset in constructor_offsets:
            with pytest.raises(async_error):
                _interrupt_instruction(
                    constructor,
                    instruction_offset,
                    construct,
                    async_error=async_error,
                )
            assert artifacts._LOADED_RECEIPT_REGISTRY == {}
            assert artifacts._PENDING_LOADED_RECEIPT_REGISTRY == {}

    loader = artifacts.load_post_enrollment_graceful_stop_decision_artifact_receipt
    real_register_pending = artifacts._register_pending_loaded_receipt
    captured_pending: list[
        artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ] = []

    def capture_pending_registration(
        value: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        **kwargs: object,
    ) -> artifacts._PendingLoadedReceiptRegistration:
        registration = real_register_pending(value, **cast(Any, kwargs))
        captured_pending.append(value)
        return registration

    monkeypatch.setattr(
        artifacts,
        "_register_pending_loaded_receipt",
        capture_pending_registration,
    )

    def load_pending() -> None:
        loaded = _load_pending_receipt(inputs, receipt)
        assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
        registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(loaded)]
        assert (
            artifacts._burn_pending_loaded_receipt_registry_entry(
                id(loaded),
                registration=registration,
            )
            is None
        )

    loader_instructions = tuple(dis.get_instructions(loader))
    first_loaded_store = next(
        instruction.offset
        for instruction in loader_instructions
        if instruction.opname == "STORE_FAST" and instruction.argval == "loaded"
    )
    loader_offsets = tuple(
        dict.fromkeys(
            offset
            for offset in _record_instruction_offsets(loader, load_pending)
            if offset >= first_loaded_store
        )
    )
    assert loader_offsets
    return_offset = next(
        instruction.offset
        for instruction in loader_instructions
        if instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
    )
    for async_error in (KeyboardInterrupt, SystemExit):
        for instruction_offset in loader_offsets:
            captured_pending.clear()
            with pytest.raises(async_error):
                _interrupt_instruction(
                    loader,
                    instruction_offset,
                    load_pending,
                    async_error=async_error,
                )
            assert artifacts._LOADED_RECEIPT_REGISTRY == {}
            if instruction_offset == return_offset:
                assert len(captured_pending) == 1
                candidate = captured_pending[0]
                registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(candidate)]
                reference = cast(weakref.ReferenceType[object], _pending_value(registration, 1))
                assert reference() is candidate
                assert (
                    artifacts._burn_pending_loaded_receipt_registry_entry(
                        id(candidate),
                        registration=registration,
                    )
                    is None
                )
            else:
                assert artifacts._PENDING_LOADED_RECEIPT_REGISTRY == {}


def test_loaded_receipt_authentication_sweep_is_absent_or_exactly_live(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    template = _install_fast_pending_reauthentication(monkeypatch, inputs, receipt)
    template_registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(template)]
    assert (
        artifacts._burn_pending_loaded_receipt_registry_entry(
            id(template),
            registration=template_registration,
        )
        is None
    )
    target = artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt

    def authenticate(candidate: object) -> None:
        target(
            candidate,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    def record_success() -> None:
        candidate = _load_pending_receipt(inputs, receipt)
        authenticate(candidate)
        registration = artifacts._LOADED_RECEIPT_REGISTRY[id(candidate)]
        assert candidate.__post_init__() is None
        assert artifacts._revoke_loaded_receipt(candidate, registration) is None

    instructions = tuple(dis.get_instructions(target))
    return_offset = next(
        instruction.offset
        for instruction in instructions
        if instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
    )
    pending_consumed_offset = next(
        instruction.offset
        for instruction in instructions
        if instruction.opname == "STORE_FAST" and instruction.argval == "pending"
    )
    executed_offsets = tuple(
        dict.fromkeys(
            offset
            for offset in _record_instruction_offsets(target, record_success)
            if offset >= pending_consumed_offset
        )
    )
    assert return_offset in executed_offsets

    for async_error in (KeyboardInterrupt, SystemExit):
        for instruction_offset in executed_offsets:
            candidate = _load_pending_receipt(inputs, receipt)
            with pytest.raises(async_error):
                _interrupt_instruction(
                    target,
                    instruction_offset,
                    lambda candidate=candidate: authenticate(candidate),
                    async_error=async_error,
                )
            registration = artifacts._LOADED_RECEIPT_REGISTRY.get(id(candidate))
            assert id(candidate) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
            if instruction_offset == return_offset:
                assert registration is not None
                assert candidate.__post_init__() is None
                assert artifacts._revoke_loaded_receipt(candidate, registration) is None
            else:
                assert registration is None
                with pytest.raises(
                    artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
                ):
                    candidate.__post_init__()


@pytest.mark.parametrize(
    "source_kind",
    [
        "candidate",
        "controller_outcome",
        "controller_slot",
        "controller_commit",
        "controller_locator",
        "attempt",
        "approval_envelope",
        "git_authority",
        "provenance",
    ],
)
def test_loaded_receipt_authentication_rejects_every_post_load_source_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_kind: str,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)

    if source_kind == "candidate":
        loaded.artifact_path.write_bytes(b"{}\n")
    elif source_kind == "controller_outcome":
        inputs.outcome.artifact_path.write_bytes(b"{}\n")
    elif source_kind == "controller_slot":
        (
            inputs.artifact_directory
            / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
        ).write_bytes(b"{}\n")
    elif source_kind == "controller_commit":
        (
            inputs.artifact_directory
            / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
        ).write_bytes(b"{}\n")
    elif source_kind == "controller_locator":
        payload = json.loads(inputs.outcome.artifact_path.read_bytes())
        assert type(payload) is dict
        locator = payload["durable_shutdown_locator"]
        assert type(locator) is dict
        locator["active_controller_session_sha256"] = "f" * 64
        inputs.outcome.artifact_path.write_bytes(canonical_first_enrollment_json_bytes(payload))
    elif source_kind == "attempt":
        (inputs.artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME).write_bytes(
            b"{}\n"
        )
    elif source_kind == "approval_envelope":
        inputs.attested_artifact.write_bytes(b"{}\n")
    elif source_kind == "git_authority":
        monkeypatch.setattr(
            execution,
            "_head_reviewed_operator_authority_object",
            lambda _: ("100644", "b" * 40, b"{}\n"),
        )
    elif source_kind == "provenance":
        (inputs.artifact_directory / inputs.loaded.image_provenance.path.name).write_bytes(b"{}\n")
    else:  # pragma: no cover - the closed parametrization makes this unreachable.
        raise AssertionError

    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    assert id(loaded) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


@pytest.mark.parametrize(
    "field_name",
    [
        "artifact_path",
        "encoded",
        "directory_identity",
        "file_identity",
        "receipt_encoded",
        "receipt_sha256",
        "_sealed_fields",
    ],
)
def test_loaded_receipt_authority_ignores_every_heap_view_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field_name: str,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    original_values = {
        name: getattr(loaded, name)
        for name in (
            "artifact_path",
            "encoded",
            "directory_identity",
            "file_identity",
            "receipt_encoded",
            "receipt_sha256",
            "_sealed_fields",
        )
    }
    replacement_values: dict[str, object] = {
        "artifact_path": loaded.artifact_path.with_name(
            f"{artifacts.DECISION_CANDIDATE_FILE_PREFIX}{'f' * 64}.json"
        ),
        "encoded": loaded.encoded + b" ",
        "directory_identity": (loaded.directory_identity[0] + 1, loaded.directory_identity[1]),
        "file_identity": (
            loaded.file_identity[0],
            loaded.file_identity[1] + 1,
            *loaded.file_identity[2:],
        ),
        "receipt_encoded": loaded.receipt_encoded + b" ",
        "receipt_sha256": "f" * 64,
        "_sealed_fields": (*loaded._sealed_fields, "forged"),
    }
    real_register = artifacts._register_loaded_receipt

    def register_during_relabel(
        value: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        **kwargs: object,
    ) -> artifacts._LoadedReceiptRegistration:
        object.__setattr__(value, field_name, replacement_values[field_name])
        if field_name != "_sealed_fields":
            object.__setattr__(
                value,
                "_sealed_fields",
                artifacts._loaded_receipt_seal_values(value),
            )
        try:
            return real_register(value, **cast(Any, kwargs))
        finally:
            for name, original in original_values.items():
                object.__setattr__(value, name, original)

    monkeypatch.setattr(artifacts, "_register_loaded_receipt", register_during_relabel)

    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert id(loaded) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    registration = artifacts._LOADED_RECEIPT_REGISTRY[id(loaded)]
    source_snapshot = cast(
        artifacts._LoadedReceiptSourceSnapshot,
        _registration_value(registration, 5),
    )
    assert _source_value(source_snapshot, 1) == os.fspath(original_values["artifact_path"])
    assert _source_value(source_snapshot, 2) == original_values["encoded"]
    assert _source_value(source_snapshot, 3) == original_values["directory_identity"]
    assert _source_value(source_snapshot, 4) == original_values["file_identity"]
    assert _source_value(source_snapshot, 20) == original_values["receipt_encoded"]
    assert _source_value(source_snapshot, 21) == original_values["receipt_sha256"]
    assert all(getattr(loaded, name) == value for name, value in original_values.items())
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_loaded_receipt_authentication_never_reads_a_b_a_view_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    loaded_type = artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    field_names = (
        "artifact_path",
        "encoded",
        "directory_identity",
        "file_identity",
        "receipt_encoded",
        "receipt_sha256",
        "_sealed_fields",
    )
    original_descriptors = {name: loaded_type.__dict__[name] for name in field_names}
    original_post_init = loaded_type.__dict__["__post_init__"]
    accessed: list[str] = []
    real_register = artifacts._register_loaded_receipt

    def forbidden_descriptor(name: str) -> property:
        def read(_: object) -> Never:
            accessed.append(name)
            raise AssertionError(f"public heap view read: {name}")

        return property(read)

    def forbidden_post_init(_: object) -> Never:
        accessed.append("__post_init__")
        raise AssertionError("public heap view validation called")

    def register_during_descriptor_b(
        value: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        **kwargs: object,
    ) -> artifacts._LoadedReceiptRegistration:
        for name in field_names:
            type.__setattr__(loaded_type, name, forbidden_descriptor(name))
        type.__setattr__(loaded_type, "__post_init__", forbidden_post_init)
        try:
            return real_register(value, **cast(Any, kwargs))
        finally:
            for name, descriptor in original_descriptors.items():
                type.__setattr__(loaded_type, name, descriptor)
            type.__setattr__(loaded_type, "__post_init__", original_post_init)

    monkeypatch.setattr(
        artifacts,
        "_register_loaded_receipt",
        register_during_descriptor_b,
    )
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=receipt.graceful_stop_decision_v1_sha256,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )

    assert accessed == []
    assert id(loaded) in artifacts._LOADED_RECEIPT_REGISTRY
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )


def test_pending_binding_rejects_full_valid_transplant_and_constructor_clone(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt_a = _prepare(inputs)
    receipt_b = _prepare(
        inputs,
        graceful_stop_operation_id="423e4567-e89b-42d3-a456-426614174003",
    )
    pending_a = _load_pending_receipt(inputs, receipt_a)
    pending_b = _load_pending_receipt(inputs, receipt_b)
    original_a = {
        name: getattr(pending_a, name)
        for name in (
            "artifact_path",
            "encoded",
            "directory_identity",
            "file_identity",
            "receipt_encoded",
            "receipt_sha256",
            "_sealed_fields",
        )
    }
    for name in (
        "artifact_path",
        "encoded",
        "directory_identity",
        "file_identity",
        "receipt_encoded",
        "receipt_sha256",
    ):
        object.__setattr__(pending_a, name, getattr(pending_b, name))
    object.__setattr__(
        pending_a,
        "_sealed_fields",
        artifacts._loaded_receipt_seal_values(pending_a),
    )

    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            pending_a,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt_b.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
    assert id(pending_a) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert id(pending_a) not in artifacts._LOADED_RECEIPT_REGISTRY

    for name, value in original_a.items():
        object.__setattr__(pending_a, name, value)
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            pending_a,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt_a.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    clone = _clone_pending_receipt(pending_b)
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            clone,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt_b.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
    assert id(clone) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert id(clone) not in artifacts._LOADED_RECEIPT_REGISTRY
    assert id(pending_b) in artifacts._PENDING_LOADED_RECEIPT_REGISTRY

    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        pending_b,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt_b.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert pending_b.decision_artifact_receipt_authenticated is True
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        pending_b,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("interrupt_after_pop", [False, True])
def test_pending_registration_async_during_consume_is_one_shot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
    interrupt_after_pop: bool,
) -> None:
    class InterruptingPendingRegistry(dict[int, artifacts._PendingLoadedReceiptRegistration]):
        interrupted = False

        def pop(  # type: ignore[override]
            self,
            key: int,
            default: artifacts._PendingLoadedReceiptRegistration | None = None,
        ) -> artifacts._PendingLoadedReceiptRegistration | None:
            if not self.interrupted:
                self.interrupted = True
                if interrupt_after_pop:
                    super().pop(key, default)
                raise async_error()
            return super().pop(key, default)

    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY.pop(id(loaded))
    registry = InterruptingPendingRegistry({id(loaded): registration})
    monkeypatch.setattr(artifacts, "_PENDING_LOADED_RECEIPT_REGISTRY", registry)

    with pytest.raises(async_error):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    assert registry.interrupted
    assert id(loaded) not in registry
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_pending_registration_store_then_async_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    class StoreThenInterruptPendingRegistry(dict[int, artifacts._PendingLoadedReceiptRegistration]):
        interrupted = False

        def __setitem__(
            self,
            key: int,
            value: artifacts._PendingLoadedReceiptRegistration,
        ) -> None:
            super().__setitem__(key, value)
            if not self.interrupted:
                self.interrupted = True
                raise async_error()

    registry = StoreThenInterruptPendingRegistry()
    monkeypatch.setattr(artifacts, "_PENDING_LOADED_RECEIPT_REGISTRY", registry)
    monkeypatch.setattr(artifacts, "_LOADED_RECEIPT_REGISTRY_BURN_ATTEMPTS", 0)
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)

    with pytest.raises(async_error):
        _load_pending_receipt(inputs, receipt)

    gc.collect()
    assert registry.interrupted
    assert registry == {}
    assert artifacts._LOADED_RECEIPT_REGISTRY == {}


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_pending_registration_weakref_cleanup_retries_async(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(loaded)]
    reference = cast(weakref.ReferenceType[object], _pending_value(registration, 1))
    callback = reference.__callback__
    assert callback is not None
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(callback)
        if instruction.argval == "_discard_lost_registry_reference"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            callback,
            cleanup_offset,
            lambda: callback(reference),
            async_error=async_error,
        )

    assert id(loaded) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_pending_registration_rejects_and_burns_wrong_record_type(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(loaded)] = cast(Any, object())

    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    assert id(loaded) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_pending_registration_rejects_malformed_dead_and_stale_references(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class RetargetingReference:
        def __init__(
            self,
            target: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        ) -> None:
            self.target = target
            self.called = False

        def __call__(
            self,
        ) -> artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt:
            self.called = True
            return self.target

    class ShapedPendingProxy:
        def __init__(
            self,
            delegate: artifacts._PendingLoadedReceiptRegistration,
            target: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        ) -> None:
            self.delegate = delegate
            self.target = target
            self.reference_accessed = False

        @property
        def reference(self) -> Any:
            self.reference_accessed = True
            return lambda: self.target

        def __getattr__(self, name: str) -> object:
            return getattr(self.delegate, name)

    class WeakTarget:
        pass

    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    original = _load_pending_receipt(inputs, receipt)
    registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY.pop(id(original))
    registry = cast(dict[int, object], artifacts._PENDING_LOADED_RECEIPT_REGISTRY)

    callable_target = _clone_pending_receipt(original)
    retargeting_reference = RetargetingReference(callable_target)
    registry[id(callable_target)] = _tuple_with_slot(
        registration,
        1,
        cast(Any, retargeting_reference),
    )
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            callable_target,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )
    assert not retargeting_reference.called
    assert id(callable_target) not in registry
    assert id(callable_target) not in artifacts._LOADED_RECEIPT_REGISTRY

    dead_reference_target = WeakTarget()
    dead_reference = weakref.ref(dead_reference_target)
    del dead_reference_target
    gc.collect()
    assert dead_reference() is None
    dead_target = _clone_pending_receipt(original)
    registry[id(dead_target)] = _tuple_with_slot(
        registration,
        1,
        cast(Any, dead_reference),
    )
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts._consume_pending_loaded_receipt(dead_target)
    assert id(dead_target) not in registry

    stale_reference_target = _clone_pending_receipt(original)
    stale_target = _clone_pending_receipt(original)
    registry[id(stale_target)] = _tuple_with_slot(
        registration,
        1,
        weakref.ref(stale_reference_target),
    )
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts._consume_pending_loaded_receipt(stale_target)
    assert id(stale_target) not in registry

    revoke_target = _clone_pending_receipt(original)
    revoke_proxy = ShapedPendingProxy(registration, revoke_target)
    registry[id(revoke_target)] = revoke_proxy
    assert artifacts._revoke_pending_loaded_receipt_if_registered(revoke_target) is None
    assert not revoke_proxy.reference_accessed
    assert id(revoke_target) not in registry

    callback_target = _clone_pending_receipt(original)
    callback_proxy = ShapedPendingProxy(registration, callback_target)
    registry[id(callback_target)] = callback_proxy
    assert (
        artifacts._burn_pending_loaded_receipt_registry_entry(
            id(callback_target),
            reference=weakref.ref(callback_target),
        )
        is None
    )
    assert not callback_proxy.reference_accessed
    assert id(callback_target) not in registry


def test_pending_registration_wrong_thread_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    observed: list[BaseException] = []
    creator_thread = threading.current_thread()

    class ReboundThreading:
        Thread = threading.Thread

        @staticmethod
        def current_thread() -> threading.Thread:
            return creator_thread

    monkeypatch.setattr(artifacts, "threading", ReboundThreading)

    def authenticate_from_wrong_thread() -> None:
        try:
            artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                loaded,
                start_operator_attested_approval_artifact=inputs.attested_artifact,
                expected_graceful_stop_decision_v1_sha256=(
                    receipt.graceful_stop_decision_v1_sha256
                ),
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )
        except BaseException as error:
            observed.append(error)

    thread = threading.Thread(target=authenticate_from_wrong_thread)
    thread.start()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert len(observed) == 1
    assert isinstance(
        observed[0],
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
    )
    assert id(loaded) not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )


def test_active_registration_ignores_cross_thread_current_thread_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    creator_thread = threading.current_thread()

    class ReboundThreading:
        Thread = threading.Thread

        @staticmethod
        def current_thread() -> threading.Thread:
            return creator_thread

    monkeypatch.setattr(artifacts, "threading", ReboundThreading)
    observed: list[object] = []

    def revalidate_from_wrong_thread() -> None:
        try:
            observed.append(
                artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                    loaded,
                    artifact_directory=inputs.artifact_directory,
                    ignored_root=inputs.ignored_root,
                )
            )
        except BaseException as error:
            observed.append(error)

    thread = threading.Thread(target=revalidate_from_wrong_thread)
    thread.start()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert observed == [False]
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_pending_registration_is_weak_and_non_authorizing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    candidate_id = id(loaded)
    registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[candidate_id]

    reference = cast(weakref.ReferenceType[object], _pending_value(registration, 1))
    source_snapshot = cast(
        artifacts._LoadedReceiptSourceSnapshot,
        _pending_value(registration, 5),
    )
    historical_snapshot = cast(
        artifacts._HistoricalStartFileSnapshot,
        _pending_value(registration, 4),
    )
    attempt_snapshot = artifacts._historical_slot(historical_snapshot, 2)
    assert reference() is loaded
    assert _pending_value(registration, 2) == os.getpid()
    assert _pending_value(registration, 3) is threading.current_thread()
    assert _source_value(source_snapshot, 2) == loaded.encoded
    assert execution._retained_attempt_snapshot_value(attempt_snapshot, 5) == (
        inputs.attempt_slot_sha256
    )
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()

    del loaded
    gc.collect()
    assert reference() is None
    assert candidate_id not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork")
def test_pending_registration_is_never_usable_after_fork(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - assertions are returned through the pipe.
        os.close(read_descriptor)
        try:
            artifacts._LOADED_RECEIPT_ORIGIN_PID = os.getpid()
            try:
                artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                    loaded,
                    start_operator_attested_approval_artifact=inputs.attested_artifact,
                    expected_graceful_stop_decision_v1_sha256=(
                        receipt.graceful_stop_decision_v1_sha256
                    ),
                    artifact_directory=inputs.artifact_directory,
                    ignored_root=inputs.ignored_root,
                )
            except artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError:
                result = b"rejected"
            except BaseException:
                result = b"error"
            else:
                result = b"accepted"
            os.write(write_descriptor, result)
        finally:
            os.close(write_descriptor)
            os._exit(0)

    os.close(write_descriptor)
    try:
        result = os.read(read_descriptor, 16)
    finally:
        os.close(read_descriptor)
    waited_pid, status = os.waitpid(child_pid, 0)
    assert waited_pid == child_pid
    assert os.waitstatus_to_exitcode(status) == 0
    assert result == b"rejected"
    assert id(loaded) in artifacts._PENDING_LOADED_RECEIPT_REGISTRY

    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )


def test_active_registration_rejects_and_burns_every_non_exact_or_stale_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ShapedRegistrationProxy:
        def __init__(
            self,
            delegate: artifacts._LoadedReceiptRegistration,
            target: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        ) -> None:
            self.delegate = delegate
            self.target = target
            self.reference_accessed = False

        @property
        def reference(self) -> Any:
            self.reference_accessed = True
            return lambda: self.target

        def __getattr__(self, name: str) -> object:
            return getattr(self.delegate, name)

    class WeakTarget:
        pass

    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    registration = artifacts._LOADED_RECEIPT_REGISTRY.pop(id(loaded))
    registry = cast(dict[int, object], artifacts._LOADED_RECEIPT_REGISTRY)

    proxy_target = _clone_pending_receipt(loaded)
    proxy = ShapedRegistrationProxy(registration, proxy_target)
    registry[id(proxy_target)] = proxy
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        proxy_target.__post_init__()
    assert not proxy.reference_accessed
    assert id(proxy_target) not in registry

    wrong_type_target = _clone_pending_receipt(loaded)
    registry[id(wrong_type_target)] = object()
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        wrong_type_target.__post_init__()
    assert id(wrong_type_target) not in registry

    dead_reference_target = WeakTarget()
    dead_reference = weakref.ref(dead_reference_target)
    del dead_reference_target
    gc.collect()
    assert dead_reference() is None
    dead_target = _clone_pending_receipt(loaded)
    registry[id(dead_target)] = _tuple_with_slot(
        registration,
        1,
        cast(Any, dead_reference),
    )
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        dead_target.__post_init__()
    assert id(dead_target) not in registry

    stale_reference_target = _clone_pending_receipt(loaded)
    stale_target = _clone_pending_receipt(loaded)
    registry[id(stale_target)] = _tuple_with_slot(
        registration,
        1,
        weakref.ref(stale_reference_target),
    )
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        stale_target.__post_init__()
    assert id(stale_target) not in registry

    callback_target = _clone_pending_receipt(loaded)
    callback_proxy = ShapedRegistrationProxy(registration, callback_target)
    registry[id(callback_target)] = callback_proxy
    assert (
        artifacts._burn_loaded_receipt_registry_entry(
            id(callback_target),
            reference=weakref.ref(callback_target),
        )
        is None
    )
    assert not callback_proxy.reference_accessed
    assert id(callback_target) not in registry


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("interrupt_after_pop", [False, True])
def test_active_registration_invalid_entry_pop_interruption_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
    interrupt_after_pop: bool,
) -> None:
    class InterruptingRegistry(dict[int, object]):
        interrupted = False

        def pop(self, key: int, default: object = None) -> object:
            if not self.interrupted:
                self.interrupted = True
                if interrupt_after_pop:
                    super().pop(key, default)
                raise async_error()
            return super().pop(key, default)

    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    registration = artifacts._LOADED_RECEIPT_REGISTRY.pop(id(loaded))
    registry = InterruptingRegistry({id(loaded): registration})
    registry[id(loaded)] = object()
    monkeypatch.setattr(
        artifacts,
        "_LOADED_RECEIPT_REGISTRY",
        cast(Any, registry),
    )

    with pytest.raises(async_error):
        artifacts._require_loaded_receipt_registration(loaded)

    assert registry.interrupted
    assert id(loaded) not in registry
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_loaded_receipt_registry_lock_acquire_then_async_is_released(
    monkeypatch: pytest.MonkeyPatch,
    async_error: type[BaseException],
) -> None:
    class AcquireThenInterruptRLock:
        def __init__(self) -> None:
            self.lock = threading.RLock()
            self.interrupted = False

        def _recursion_count(self) -> int:
            return cast(int, self.lock._recursion_count())  # type: ignore[attr-defined]

        def acquire(self) -> bool:
            acquired = self.lock.acquire()
            if not self.interrupted:
                self.interrupted = True
                raise async_error()
            return acquired

        def release(self) -> None:
            self.lock.release()

        def __enter__(self) -> AcquireThenInterruptRLock:
            self.acquire()
            return self

        def __exit__(self, *_: object) -> None:
            self.release()

    lock = AcquireThenInterruptRLock()
    monkeypatch.setattr(artifacts, "_LOADED_RECEIPT_REGISTRY_LOCK", lock)

    with pytest.raises(async_error), artifacts._held_loaded_receipt_registry_lock():
        pytest.fail("the interrupted acquisition must not enter the body")

    assert lock._recursion_count() == 0
    with artifacts._held_loaded_receipt_registry_lock():
        assert lock._recursion_count() == 1
    assert lock._recursion_count() == 0


def test_loaded_receipt_registry_lock_opcode_sweep_always_releases() -> None:
    target = artifacts._held_loaded_receipt_registry_lock.__wrapped__
    instructions = tuple(dis.get_instructions(target))

    def normal_exit() -> None:
        with artifacts._held_loaded_receipt_registry_lock():
            assert artifacts._loaded_receipt_registry_lock_depth() == 1

    def failing_exit() -> None:
        with artifacts._held_loaded_receipt_registry_lock():
            raise ValueError

    def caught_failing_exit() -> None:
        with pytest.raises(ValueError):
            failing_exit()

    normal_offsets = _record_instruction_offsets(target, normal_exit)
    failing_offsets = _record_instruction_offsets(target, caught_failing_exit)
    first_guarded_offset = next(
        instruction.offset
        for instruction in instructions
        if instruction.opname == "LOAD_GLOBAL"
        and instruction.argval == "_LOADED_RECEIPT_REGISTRY_LOCK"
    )
    actions = {offset: normal_exit for offset in normal_offsets if offset >= first_guarded_offset}
    actions.update(
        {
            offset: failing_exit
            for offset in failing_offsets
            if offset >= first_guarded_offset and offset not in actions
        }
    )

    for async_error in (KeyboardInterrupt, SystemExit):
        for instruction_offset, action in actions.items():
            with pytest.raises(async_error):
                _interrupt_instruction(
                    target,
                    instruction_offset,
                    action,
                    async_error=async_error,
                )
            assert artifacts._loaded_receipt_registry_lock_depth() == 0
            with artifacts._held_loaded_receipt_registry_lock():
                assert artifacts._loaded_receipt_registry_lock_depth() == 1

    assert actions


@pytest.mark.parametrize("registry_kind", ["pending", "active"])
@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_weakref_loss_during_registry_lock_exit_cannot_leave_dead_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    registry_kind: str,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    holder = [
        _load_pending_receipt(inputs, receipt)
        if registry_kind == "pending"
        else _load_prepared_receipt(inputs, receipt)
    ]
    candidate_id = id(holder[0])
    target = artifacts._held_loaded_receipt_registry_lock.__wrapped__
    instructions = tuple(dis.get_instructions(target))
    yield_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "YIELD_VALUE"
    )

    def normal_lock_exit() -> None:
        with artifacts._held_loaded_receipt_registry_lock():
            pass

    recorded_offsets = _record_instruction_offsets(target, normal_lock_exit)
    post_yield_offset = next(
        instruction.offset
        for instruction in instructions[yield_index + 1 :]
        if instruction.offset in recorded_offsets
    )

    def lose_last_reference_while_lock_is_held() -> None:
        with artifacts._held_loaded_receipt_registry_lock():
            holder.clear()
            gc.collect()

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            post_yield_offset,
            lose_last_reference_while_lock_is_held,
            async_error=async_error,
        )

    assert holder == []
    assert candidate_id not in artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert candidate_id not in artifacts._LOADED_RECEIPT_REGISTRY
    assert artifacts._loaded_receipt_registry_lock_depth() == 0


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_loaded_receipt_registry_burn_retries_async_before_pop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    class InterruptingRegistry(dict[int, artifacts._LoadedReceiptRegistration]):
        interrupt_pop = False
        interrupted = False

        def pop(  # type: ignore[override]
            self,
            key: int,
            default: artifacts._LoadedReceiptRegistration | None = None,
        ) -> artifacts._LoadedReceiptRegistration | None:
            if self.interrupt_pop and not self.interrupted:
                self.interrupted = True
                raise async_error()
            return super().pop(key, default)

    registry = InterruptingRegistry()
    monkeypatch.setattr(artifacts, "_LOADED_RECEIPT_REGISTRY", registry)
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    original_sha256 = loaded.receipt_sha256
    registration = registry[id(loaded)]
    object.__setattr__(loaded, "receipt_sha256", "b" * 64)
    registry.interrupt_pop = True

    with pytest.raises(async_error):
        loaded.__post_init__()

    assert registry.interrupted
    assert registry.get(id(loaded)) is not registration
    assert id(loaded) not in registry
    object.__setattr__(loaded, "receipt_sha256", original_sha256)
    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        loaded.__post_init__()
    assert captured.value.reason_code == "loaded_decision_artifact_receipt_invalid"


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_loaded_receipt_post_init_failure_cleanup_call_entry_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    original_sha256 = loaded.receipt_sha256
    object.__setattr__(loaded, "receipt_sha256", "b" * 64)
    target = loaded.__post_init__.__func__
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.argval == "_burn_loaded_receipt_targets"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            cleanup_offset,
            loaded.__post_init__,
            async_error=async_error,
        )

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    object.__setattr__(loaded, "receipt_sha256", original_sha256)
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_same_loaded_receipt_failure_cleanup_burns_both_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    left = _load_prepared_receipt(inputs, receipt)
    right = _load_prepared_receipt(inputs, receipt)
    right_registration = artifacts._LOADED_RECEIPT_REGISTRY[id(right)]
    artifacts._LOADED_RECEIPT_REGISTRY[id(right)] = cast(
        artifacts._LoadedReceiptRegistration,
        _tuple_with_slot(
            right_registration,
            7,
            (*cast(tuple[object, ...], _registration_value(right_registration, 7)), "different"),
        ),
    )
    target = artifacts._same_loaded_receipt
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.argval == "_burn_loaded_receipt_targets"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            cleanup_offset,
            lambda: target(left, right),
            async_error=async_error,
        )

    assert id(left) not in artifacts._LOADED_RECEIPT_REGISTRY
    assert id(right) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        left.__post_init__()
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        right.__post_init__()


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_loaded_receipt_weakref_cleanup_retries_call_entry_async(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    registration = artifacts._LOADED_RECEIPT_REGISTRY[id(loaded)]
    reference = cast(weakref.ReferenceType[object], _registration_value(registration, 1))
    callback = reference.__callback__
    assert callback is not None
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(callback)
        if instruction.argval == "_discard_lost_registry_reference"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            callback,
            cleanup_offset,
            lambda: callback(reference),
            async_error=async_error,
        )

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_loaded_receipt_registration_store_then_async_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    class StoreThenInterruptRegistry(dict[int, artifacts._LoadedReceiptRegistration]):
        interrupted = False

        def __setitem__(
            self,
            key: int,
            value: artifacts._LoadedReceiptRegistration,
        ) -> None:
            super().__setitem__(key, value)
            if not self.interrupted:
                self.interrupted = True
                raise async_error()

    registry = StoreThenInterruptRegistry()
    monkeypatch.setattr(artifacts, "_LOADED_RECEIPT_REGISTRY", registry)
    monkeypatch.setattr(artifacts, "_LOADED_RECEIPT_REGISTRY_BURN_ATTEMPTS", 0)
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)

    with pytest.raises(async_error):
        _load_prepared_receipt(inputs, receipt)

    gc.collect()
    assert registry.interrupted
    assert registry == {}


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_authenticator_failure_cleanup_call_entry_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    real_revalidate = artifacts._revalidate_historical_start_chain
    real_register = artifacts._register_loaded_receipt
    revalidation_calls = 0
    captured_loaded: list[
        artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    ] = []

    def fail_final_revalidation(*args: object, **kwargs: object) -> None:
        nonlocal revalidation_calls
        revalidation_calls += 1
        real_revalidate(*cast(Any, args), **cast(Any, kwargs))
        if revalidation_calls == 2:
            raise ValueError

    def capture_registration(
        value: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        **kwargs: object,
    ) -> artifacts._LoadedReceiptRegistration:
        registration = real_register(value, **cast(Any, kwargs))
        captured_loaded.append(value)
        return registration

    monkeypatch.setattr(
        artifacts,
        "_revalidate_historical_start_chain",
        fail_final_revalidation,
    )
    monkeypatch.setattr(artifacts, "_register_loaded_receipt", capture_registration)
    target = artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.argval == "_burn_loaded_receipt_targets"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            cleanup_offset,
            lambda: target(
                loaded,
                start_operator_attested_approval_artifact=inputs.attested_artifact,
                expected_graceful_stop_decision_v1_sha256=(
                    receipt.graceful_stop_decision_v1_sha256
                ),
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            ),
            async_error=async_error,
        )

    assert len(captured_loaded) == 1
    assert id(captured_loaded[0]) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        captured_loaded[0].__post_init__()


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_wrong_thread_registration_is_burned_before_post_lock_async(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    real_current_thread = threading.current_thread
    monkeypatch.setattr(
        artifacts.threading,
        "current_thread",
        lambda: cast(threading.Thread, object()),
    )
    target = artifacts._require_loaded_receipt_registration
    instructions = tuple(dis.get_instructions(target))
    cleanup_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.argval == "_burn_loaded_receipt_targets"
    )
    post_with_offset = max(
        instruction.offset
        for instruction in instructions[:cleanup_index]
        if instruction.opname == "POP_TOP"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            post_with_offset,
            lambda: target(loaded),
            async_error=async_error,
        )

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    monkeypatch.setattr(artifacts.threading, "current_thread", real_current_thread)
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_require_registration_failure_cleanup_call_entry_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    class FailFirstGetRegistry(dict[int, artifacts._LoadedReceiptRegistration]):
        failed = False

        def get(  # type: ignore[override]
            self,
            key: int,
            default: artifacts._LoadedReceiptRegistration | None = None,
        ) -> artifacts._LoadedReceiptRegistration | None:
            if not self.failed:
                self.failed = True
                raise ValueError
            return super().get(key, default)

    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    registration = artifacts._LOADED_RECEIPT_REGISTRY.pop(id(loaded))
    registry = FailFirstGetRegistry({id(loaded): registration})
    monkeypatch.setattr(artifacts, "_LOADED_RECEIPT_REGISTRY", registry)
    target = artifacts._require_loaded_receipt_registration
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.argval == "_burn_loaded_receipt_targets"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            cleanup_offset,
            lambda: target(loaded),
            async_error=async_error,
        )

    assert registry.failed
    assert id(loaded) not in registry
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


@pytest.mark.parametrize(
    ("body_error", "cleanup_error", "expected_error"),
    [
        (KeyboardInterrupt, ValueError, KeyboardInterrupt),
        (KeyboardInterrupt, SystemExit, KeyboardInterrupt),
        (ValueError, KeyboardInterrupt, KeyboardInterrupt),
    ],
)
def test_revalidator_preserves_async_priority_after_consuming_registration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    body_error: type[BaseException],
    cleanup_error: type[BaseException],
    expected_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    real_revoke = artifacts._revoke_loaded_receipt

    def fail_candidate_revalidation(_: object) -> None:
        raise body_error()

    def burn_then_fail(
        value: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        registration: artifacts._LoadedReceiptRegistration,
    ) -> BaseException | None:
        observed = real_revoke(value, registration)
        assert observed is None
        return cleanup_error()

    monkeypatch.setattr(
        artifacts,
        "_revalidate_decision_candidate_binding",
        fail_candidate_revalidation,
    )
    monkeypatch.setattr(
        artifacts,
        "_revoke_loaded_receipt",
        burn_then_fail,
    )

    with pytest.raises(expected_error):
        artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
            loaded,
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
def test_revalidator_failure_cleanup_call_entry_is_burned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)

    def fail_candidate_revalidation(_: object) -> None:
        raise ValueError

    monkeypatch.setattr(
        artifacts,
        "_revalidate_decision_candidate_binding",
        fail_candidate_revalidation,
    )
    target = artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt
    cleanup_offset = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.argval == "_burn_loaded_receipt_targets"
    )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            cleanup_offset,
            lambda: target(
                loaded,
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            ),
            async_error=async_error,
        )

    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        loaded.__post_init__()


def test_revalidator_burns_before_reentrant_source_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_prepared_receipt(inputs, receipt)
    real_read = artifacts._read_decision_candidate_binding
    reentrant_results: list[bool] = []

    def reenter_after_burn(**kwargs: object) -> tuple[object, object]:
        assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY
        reentrant_results.append(
            artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                loaded,
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )
        )
        return cast(tuple[object, object], real_read(**cast(Any, kwargs)))

    monkeypatch.setattr(
        artifacts,
        "_read_decision_candidate_binding",
        reenter_after_burn,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert reentrant_results == [False]
    assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_revalidator_consumes_registration_at_every_success_return_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    template = _install_fast_pending_reauthentication(monkeypatch, inputs, receipt)
    template_registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(template)]
    assert (
        artifacts._burn_pending_loaded_receipt_registry_entry(
            id(template),
            registration=template_registration,
        )
        is None
    )
    target = artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt
    instructions = tuple(dis.get_instructions(target))
    consumed_store_offset = max(
        instruction.offset
        for instruction in instructions
        if instruction.opname == "STORE_FAST" and instruction.argval == "registration"
    )

    def revalidate_success() -> None:
        loaded = _load_prepared_receipt(inputs, receipt)
        assert target(
            loaded,
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    executed_offsets = tuple(
        dict.fromkeys(
            offset
            for offset in _record_instruction_offsets(target, revalidate_success)
            if offset >= consumed_store_offset
        )
    )
    assert executed_offsets
    assert any(
        instruction.offset in executed_offsets
        and instruction.opname in {"RETURN_CONST", "RETURN_VALUE"}
        for instruction in instructions
    )

    for async_error in (KeyboardInterrupt, SystemExit):
        for instruction_offset in executed_offsets:
            loaded = _load_prepared_receipt(inputs, receipt)
            with pytest.raises(async_error):
                _interrupt_instruction(
                    target,
                    instruction_offset,
                    lambda loaded=loaded: target(
                        loaded,
                        artifact_directory=inputs.artifact_directory,
                        ignored_root=inputs.ignored_root,
                    ),
                    async_error=async_error,
                )
            assert id(loaded) not in artifacts._LOADED_RECEIPT_REGISTRY


def test_prepare_is_exactly_idempotent_without_inode_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    first = _prepare(inputs)
    artifact_path = inputs.candidate_directory / first.artifact_location
    inode = artifact_path.stat().st_ino

    second = _prepare(inputs)

    assert second.public_payload == first.public_payload
    assert artifact_path.stat().st_ino == inode
    assert tuple(inputs.candidate_directory.iterdir()) == (artifact_path,)


def test_prepare_revalidates_the_entire_historical_chain_four_times(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    original = artifacts._revalidate_historical_start_chain
    calls = 0

    def counted(
        chain: Any,
        historical_snapshot: Any,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        nonlocal calls
        calls += 1
        original(
            chain,
            historical_snapshot,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )

    monkeypatch.setattr(artifacts, "_revalidate_historical_start_chain", counted)

    _prepare(inputs)

    assert calls == 4


def test_prepare_derives_candidate_and_receipt_only_from_immutable_history_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    real_load = artifacts._load_historical_start_chain
    real_build = artifacts._expected_decision_candidate_snapshot
    captured_chain: list[Any] = []
    attacked = False

    def capture_chain(**kwargs: object) -> Any:
        result = real_load(**cast(Any, kwargs))
        captured_chain.append(result[0])
        return result

    def relabel_live_chain_only(snapshot: Any, *, decision_operation_id: str) -> Any:
        nonlocal attacked
        chain = captured_chain[-1]
        changes = ((artifacts._chain_slot(chain, 1), "outcome_sha256", "f" * 64),)
        originals = tuple((value, name, getattr(value, name)) for value, name, _ in changes)
        for value, name, replacement in changes:
            object.__setattr__(value, name, replacement)
        attacked = True
        try:
            return real_build(snapshot, decision_operation_id=decision_operation_id)
        finally:
            for value, name, original in originals:
                object.__setattr__(value, name, original)

    monkeypatch.setattr(artifacts, "_load_historical_start_chain", capture_chain)
    monkeypatch.setattr(
        artifacts,
        "_expected_decision_candidate_snapshot",
        relabel_live_chain_only,
    )

    receipt = _prepare(inputs)

    assert attacked
    candidate = decode_post_enrollment_graceful_stop_decision(
        (inputs.candidate_directory / receipt.artifact_location).read_bytes()
    )
    assert candidate.target.controller_outcome_sha256 == inputs.outcome.outcome_sha256
    assert candidate.target.start_execution_attempt_slot_sha256 == inputs.attempt_slot_sha256
    assert receipt.controller_outcome_sha256 == candidate.target.controller_outcome_sha256
    assert receipt.graceful_stop_target_sha256 == candidate.target.target_sha256
    assert receipt.start_approval_sha256 == inputs.loaded.approval.approval_sha256
    assert receipt.start_operator_attestation_envelope_sha256 == (
        inputs.loaded.operator_attestation_envelope_sha256
    )


def test_authority_records_reject_heap_tuple_descriptor_a_b_a(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    pending = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(loaded)]
    historical = cast(
        artifacts._HistoricalStartFileSnapshot,
        artifacts._pending_slot(pending, 4),
    )
    source = cast(
        artifacts._LoadedReceiptSourceSnapshot,
        artifacts._pending_slot(pending, 5),
    )
    chain, exact_historical = artifacts._load_historical_start_chain(
        start_operator_attested_approval_artifact=os.fspath(inputs.attested_artifact),
        artifact_directory=os.fspath(inputs.artifact_directory),
        ignored_root=os.fspath(inputs.ignored_root),
    )
    assert exact_historical == historical
    expected = artifacts._expected_decision_candidate_snapshot(
        historical,
        decision_operation_id=STOP_OPERATION_ID,
    )
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=receipt.graceful_stop_decision_v1_sha256,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    registration = artifacts._LOADED_RECEIPT_REGISTRY[id(loaded)]

    class LegacyAuthorityTuple(tuple[object, ...]):
        pass

    accessed: list[str] = []

    def descriptor(label: str, slot: int) -> property:
        def get(instance: LegacyAuthorityTuple) -> object:
            accessed.append(label)
            return tuple.__getitem__(instance, slot)

        return property(get)

    records: tuple[tuple[tuple[object, ...], Any], ...] = (
        (cast(tuple[object, ...], chain), artifacts._chain_slot),
        (cast(tuple[object, ...], historical), artifacts._historical_slot),
        (cast(tuple[object, ...], source), artifacts._source_slot),
        (cast(tuple[object, ...], expected), artifacts._expected_slot),
        (cast(tuple[object, ...], pending), artifacts._pending_slot),
        (cast(tuple[object, ...], registration), artifacts._registration_slot),
    )
    for exact, tuple_reader in records:
        forged = LegacyAuthorityTuple(exact)
        for replacement in (descriptor("A", 1), descriptor("B", 2), descriptor("A", 1)):
            type.__setattr__(LegacyAuthorityTuple, "field", replacement)
            with pytest.raises(ValueError):
                tuple_reader(forged, 1)
        type.__delattr__(LegacyAuthorityTuple, "field")

    assert accessed == []
    assert artifacts._revoke_loaded_receipt(loaded, registration) is None


def test_prepublication_revalidation_failure_creates_no_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    original = artifacts._revalidate_historical_start_chain
    calls = 0

    def fail_second(
        chain: Any,
        historical_snapshot: Any,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        nonlocal calls
        calls += 1
        original(
            chain,
            historical_snapshot,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        if calls == 2:
            raise artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError(
                "historical_start_chain_revalidation_failed"
            )

    monkeypatch.setattr(artifacts, "_revalidate_historical_start_chain", fail_second)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(inputs)

    assert captured.value.reason_code == "historical_start_chain_revalidation_failed"
    assert not tuple(inputs.candidate_directory.iterdir())


def test_postpublication_revalidation_failure_retains_ambiguous_file_without_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    original = artifacts._revalidate_historical_start_chain
    calls = 0

    def fail_third(
        chain: Any,
        historical_snapshot: Any,
        *,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> None:
        nonlocal calls
        calls += 1
        original(
            chain,
            historical_snapshot,
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
        )
        if calls == 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(artifacts, "_revalidate_historical_start_chain", fail_third)

    with pytest.raises(KeyboardInterrupt):
        _prepare(inputs)

    retained = tuple(inputs.candidate_directory.iterdir())
    assert len(retained) == 1
    assert retained[0].read_bytes().startswith(b"{")


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("boundary", ["publish_return", "receipt_build"])
def test_prepare_propagates_async_after_exact_candidate_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
    boundary: str,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    target = artifacts._prepare_post_enrollment_graceful_stop_decision_candidate_with_snapshot
    instructions = tuple(dis.get_instructions(target))
    if boundary == "publish_return":
        instruction_offset = next(
            instruction.offset
            for instruction in instructions
            if instruction.opname == "STORE_FAST" and instruction.argval == "published_identity"
        )
    else:
        instruction_offset = next(
            instruction.offset
            for instruction in instructions
            if instruction.opname == "LOAD_GLOBAL"
            and instruction.argval == "_receipt_from_identity_values"
        )

    with pytest.raises(async_error):
        _interrupt_instruction(
            target,
            instruction_offset,
            lambda: _prepare(inputs),
            async_error=async_error,
        )

    retained = tuple(inputs.candidate_directory.iterdir())
    assert len(retained) == 1
    encoded = retained[0].read_bytes()
    assert retained[0].name == artifacts._decision_candidate_file_name(
        hashlib.sha256(encoded).hexdigest()
    )
    assert (
        canonical_post_enrollment_graceful_stop_decision_bytes(
            decode_post_enrollment_graceful_stop_decision(encoded)
        )
        == encoded
    )


def test_output_directory_replacement_after_publish_is_retention_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    held_directory = inputs.candidate_directory.with_name("held-stop-decisions")
    audited_fs = cast(Any, artifacts)._audited_fs
    original = audited_fs._publish_candidate

    def replace_after_publish(*args: object, **kwargs: object) -> tuple[int, ...]:
        identity = cast(tuple[int, ...], original(*args, **kwargs))
        inputs.candidate_directory.rename(held_directory)
        inputs.candidate_directory.mkdir(mode=0o700)
        return identity

    monkeypatch.setattr(audited_fs, "_publish_candidate", replace_after_publish)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(inputs)

    assert captured.value.reason_code == "decision_candidate_retention_unconfirmed"
    assert not tuple(inputs.candidate_directory.iterdir())
    assert len(tuple(held_directory.iterdir())) == 1


def test_output_directory_swap_before_publish_open_creates_no_file_anywhere(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    held_directory = inputs.candidate_directory.with_name("held-stop-decisions")
    audited_fs = cast(Any, artifacts)._audited_fs
    original = audited_fs._publish_candidate
    publish_calls = 0

    def swap_before_publish_open(*args: object, **kwargs: object) -> tuple[int, ...]:
        nonlocal publish_calls
        publish_calls += 1
        inputs.candidate_directory.rename(held_directory)
        inputs.candidate_directory.mkdir(mode=0o700)
        return cast(tuple[int, ...], original(*args, **kwargs))

    monkeypatch.setattr(audited_fs, "_publish_candidate", swap_before_publish_open)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(inputs)

    assert captured.value.reason_code == "decision_candidate_retention_unconfirmed"
    assert publish_calls == 1
    assert not tuple(inputs.candidate_directory.iterdir())
    assert not tuple(held_directory.iterdir())


def test_conflicting_existing_candidate_remains_blocking_and_is_not_unlinked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    artifact_path = inputs.candidate_directory / receipt.artifact_location
    artifact_path.write_bytes(b"conflict\n")
    artifact_path.chmod(0o600)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(inputs)

    assert captured.value.reason_code == "decision_candidate_retention_unconfirmed"
    assert artifact_path.read_bytes() == b"conflict\n"


@pytest.mark.parametrize(
    ("change", "reason_code"),
    [
        (
            {"graceful_stop_operation_id": "not-a-uuid"},
            "graceful_stop_operation_id_invalid",
        ),
        (
            {"expected_start_operation_id": "not-a-uuid"},
            "expected_start_operation_id_invalid",
        ),
        (
            {"expected_controller_outcome_sha256": "A" * 64},
            "expected_controller_outcome_sha256_invalid",
        ),
        (
            {"expected_durable_shutdown_locator_sha256": "A" * 64},
            "expected_durable_shutdown_locator_sha256_invalid",
        ),
        (
            {"expected_start_execution_attempt_slot_sha256": "A" * 64},
            "expected_start_execution_attempt_slot_sha256_invalid",
        ),
        (
            {"expected_start_operator_attestation_envelope_sha256": "A" * 64},
            "expected_start_operator_attestation_envelope_sha256_invalid",
        ),
        (
            {"expected_start_approval_sha256": "A" * 64},
            "expected_start_approval_sha256_invalid",
        ),
    ],
)
def test_malformed_review_assertions_fail_before_any_file_access(
    tmp_path: Path,
    change: dict[str, object],
    reason_code: str,
) -> None:
    arguments: dict[str, object] = {
        "graceful_stop_operation_id": STOP_OPERATION_ID,
        "start_operator_attested_approval_artifact": tmp_path / "absent.json",
        "decision_candidate_directory": tmp_path / "absent-directory",
        "expected_controller_outcome_sha256": "0" * 64,
        "expected_durable_shutdown_locator_sha256": "1" * 64,
        "expected_start_execution_attempt_slot_sha256": "2" * 64,
        "expected_start_operator_attestation_envelope_sha256": "3" * 64,
        "expected_start_operation_id": "223e4567-e89b-42d3-a456-426614174001",
        "expected_start_approval_sha256": "4" * 64,
    }
    arguments.update(change)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        artifacts.prepare_post_enrollment_graceful_stop_decision_candidate(**cast(Any, arguments))

    assert captured.value.reason_code == reason_code


def test_stop_operation_id_must_be_distinct_from_reviewed_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(
            inputs,
            graceful_stop_operation_id=inputs.loaded.approval.operation_id,
        )

    assert captured.value.reason_code == "graceful_stop_operation_id_conflicts_with_start"
    assert not tuple(inputs.candidate_directory.iterdir())


def test_every_review_assertion_is_only_an_exact_equality_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    changes = {
        "expected_controller_outcome_sha256": "a" * 64,
        "expected_durable_shutdown_locator_sha256": "b" * 64,
        "expected_start_execution_attempt_slot_sha256": "c" * 64,
        "expected_start_operator_attestation_envelope_sha256": "d" * 64,
        "expected_start_operation_id": "423e4567-e89b-42d3-a456-426614174003",
        "expected_start_approval_sha256": "e" * 64,
    }

    for name, value in changes.items():
        with pytest.raises(
            artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
        ) as captured:
            _prepare(inputs, **{name: value})
        assert captured.value.reason_code == "historical_start_chain_differs_from_review"

    assert not tuple(inputs.candidate_directory.iterdir())


def test_tampered_attempt_slot_cannot_be_reblessed_by_a_new_expected_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    slot_path = inputs.artifact_directory / POST_ENROLLMENT_EXECUTION_ATTEMPT_SLOT_FILE_NAME
    payload = cast(dict[str, object], json.loads(slot_path.read_bytes()))
    payload["operation_id"] = "423e4567-e89b-42d3-a456-426614174003"
    tampered = canonical_first_enrollment_json_bytes(payload)
    slot_path.write_bytes(tampered)
    slot_path.chmod(0o600)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(
            inputs,
            expected_start_execution_attempt_slot_sha256=(hashlib.sha256(tampered).hexdigest()),
        )

    assert captured.value.reason_code == "historical_start_chain_unavailable"
    assert not tuple(inputs.candidate_directory.iterdir())


@pytest.mark.parametrize("mode", [0o755, 0o750])
def test_candidate_directory_must_be_external_owner_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: int,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    inputs.candidate_directory.chmod(mode)

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        _prepare(inputs)

    assert captured.value.reason_code == "decision_candidate_directory_unavailable"


@pytest.mark.parametrize("async_error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("timing", ["before", "after"])
@pytest.mark.parametrize("owner_name", ["candidate", "artifact", "ignored"])
def test_candidate_directory_cleanup_finishes_every_owner_after_async(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    async_error: type[BaseException],
    timing: str,
    owner_name: str,
) -> None:
    ignored_root = tmp_path / "artifacts"
    artifact_directory = ignored_root / "trusted-time"
    candidate_directory = tmp_path / "decisions"
    artifact_directory.mkdir(parents=True, mode=0o700)
    candidate_directory.mkdir(mode=0o700)
    ignored_root.chmod(0o700)
    real_directory_identity = artifacts._external_directory_identity
    real_open_root = artifacts._open_root_directory
    real_open_child = artifacts._open_child_directory
    real_cleanup = artifacts._cleanup_external_directory_owners
    labels = {
        os.fspath(candidate_directory): "candidate",
        os.fspath(artifact_directory): "artifact",
        os.fspath(ignored_root): "ignored",
    }
    current_label: str | None = None
    captured_owners: list[Any] = []

    def capture_identity(path: str, **kwargs: object) -> tuple[int, int]:
        nonlocal current_label
        current_label = labels[path]
        try:
            return real_directory_identity(path, **cast(Any, kwargs))
        finally:
            current_label = None

    def capture_root() -> Any:
        owner = real_open_root()
        if current_label == owner_name:
            captured_owners.append(owner)
        return owner

    def capture_child(owner: Any, component: str | bytes) -> Any:
        child = real_open_child(owner, component)
        if current_label == owner_name:
            captured_owners.append(child)
        return child

    interrupted = False

    def interrupting_cleanup(owners: tuple[Any | None, ...]) -> BaseException | None:
        nonlocal interrupted
        if current_label == owner_name and not interrupted:
            interrupted = True
            if timing == "after":
                cleanup_error = real_cleanup(owners)
                if cleanup_error is not None:
                    raise cleanup_error
            raise async_error()
        return real_cleanup(owners)

    monkeypatch.setattr(artifacts, "_external_directory_identity", capture_identity)
    monkeypatch.setattr(artifacts, "_open_root_directory", capture_root)
    monkeypatch.setattr(artifacts, "_open_child_directory", capture_child)
    monkeypatch.setattr(
        artifacts,
        "_cleanup_external_directory_owners",
        interrupting_cleanup,
    )
    before = _open_descriptor_names()

    with pytest.raises(async_error):
        artifacts._require_external_candidate_directory(
            os.fspath(candidate_directory),
            artifact_directory=os.fspath(artifact_directory),
            ignored_root=os.fspath(ignored_root),
        )

    assert interrupted
    assert captured_owners
    assert all(owner.closed for owner in captured_owners)
    assert _open_descriptor_names() == before


def test_receipt_rejects_forgery_copy_replace_pickle_and_valid_shaped_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    identity = {name: getattr(receipt, name) for name in artifacts._RECEIPT_IDENTITY_FIELDS}

    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt(
            **cast(Any, identity),
            _construction_capability=object(),
        )
    for operation in (
        lambda: copy.copy(receipt),
        lambda: copy.deepcopy(receipt),
        lambda: replace(receipt),
        lambda: pickle.dumps(receipt),
    ):
        with pytest.raises(
            (
                TypeError,
                artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError,
            )
        ):
            operation()

    valid_shaped_mutations: dict[str, object] = {
        "artifact_location": (f"{artifacts.DECISION_CANDIDATE_FILE_PREFIX}{'0' * 64}.json"),
        "controller_outcome_sha256": "0" * 64,
        "durable_shutdown_locator_sha256": "1" * 64,
        "graceful_stop_decision_v1_sha256": "2" * 64,
        "graceful_stop_operation_id": "523e4567-e89b-42d3-a456-426614174004",
        "graceful_stop_target_sha256": "3" * 64,
        "start_approval_sha256": "4" * 64,
        "start_approved_image_provenance_sha256": "5" * 64,
        "start_approved_image_provenance_source_revision_sha256": "6" * 64,
        "start_execution_attempt_slot_sha256": "7" * 64,
        "start_git_revision": "8" * 40,
        "start_operation_id": "623e4567-e89b-42d3-a456-426614174005",
        "start_operator_attestation_envelope_sha256": "9" * 64,
        "start_source_image_id": "sha256:" + "a" * 64,
        "start_supervisor_image_id": "sha256:" + "b" * 64,
    }
    for field_name, changed_value in valid_shaped_mutations.items():
        exact = _prepare(inputs)
        object.__setattr__(exact, field_name, changed_value)
        for trust_surface in (
            "historical_start_chain_authenticated",
            "currentness_qualified",
            next(iter(POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS)),
            "public_payload",
        ):
            with pytest.raises(
                artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
            ):
                getattr(exact, trust_surface)


def test_cli_has_exact_closed_command_flags_and_canonical_one_line_stdout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    identity_values = cast(tuple[str, ...], artifacts._receipt_seal_values(receipt))
    receipt_encoded = artifacts._canonical_receipt_bytes_from_identity_values(identity_values)
    monkeypatch.setattr(
        artifacts,
        "_prepare_post_enrollment_graceful_stop_decision_candidate_with_snapshot",
        lambda **_: (receipt, identity_values, receipt_encoded),
    )
    monkeypatch.setattr(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt,
        "public_payload",
        property(lambda _: (_ for _ in ()).throw(AssertionError("live payload read"))),
    )
    argv = [
        "prepare-decision",
        "--graceful-stop-operation-id",
        STOP_OPERATION_ID,
        "--start-operator-attested-approval-artifact",
        os.fspath(inputs.attested_artifact),
        "--decision-candidate-directory",
        os.fspath(inputs.candidate_directory),
        "--expected-controller-outcome-sha256",
        inputs.outcome.outcome_sha256,
        "--expected-durable-shutdown-locator-sha256",
        inputs.locator_sha256,
        "--expected-start-execution-attempt-slot-sha256",
        inputs.attempt_slot_sha256,
        "--expected-start-operator-attestation-envelope-sha256",
        inputs.loaded.operator_attestation_envelope_sha256,
        "--expected-start-operation-id",
        inputs.loaded.approval.operation_id,
        "--expected-start-approval-sha256",
        inputs.loaded.approval.approval_sha256,
    ]

    output_offset = max(
        instruction.offset
        for instruction in dis.get_instructions(artifacts.main)
        if instruction.opname == "LOAD_GLOBAL" and instruction.argval == "sys"
    )

    receipt_type = artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt
    original_controller_descriptor = receipt_type.__dict__["controller_outcome_sha256"]
    original_seal_descriptor = receipt_type.__dict__["_sealed_fields"]
    accessed: list[str] = []

    def forbidden_receipt_field(name: str) -> property:
        def read(_: object) -> Never:
            accessed.append(name)
            raise AssertionError(f"public receipt view read: {name}")

        return property(read)

    def relabel_live_receipt_after_snapshot_validation() -> None:
        type.__setattr__(
            receipt_type,
            "controller_outcome_sha256",
            forbidden_receipt_field("controller_outcome_sha256"),
        )
        type.__setattr__(
            receipt_type,
            "_sealed_fields",
            forbidden_receipt_field("_sealed_fields"),
        )

    try:
        assert (
            _act_at_instruction(
                artifacts.main,
                output_offset,
                relabel_live_receipt_after_snapshot_validation,
                lambda: artifacts.main(argv),
            )
            == 0
        )
    finally:
        type.__setattr__(
            receipt_type,
            "controller_outcome_sha256",
            original_controller_descriptor,
        )
        type.__setattr__(receipt_type, "_sealed_fields", original_seal_descriptor)
    assert accessed == []
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.encode("ascii") == receipt_encoded

    assert artifacts.main(["prepare-decision", "--graceful-stop-operation", STOP_OPERATION_ID]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "command_arguments_invalid\n"


def test_isolated_cli_source_attestation_rejects_ordinary_runtime() -> None:
    with pytest.raises(RuntimeError, match="CLI runtime attestation failed"):
        artifacts._require_isolated_cli_source_runtime(
            expected_relative_path=Path(
                "scripts/trusted_time_post_enrollment_graceful_stop_decision_artifacts.py"
            )
        )


def test_internal_authority_paths_never_read_public_receipt_heap_views() -> None:
    source = Path(artifacts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    authority_functions = {
        "_consume_pending_loaded_receipt",
        "_pending_loaded_receipt_matches_live",
        "_register_pending_loaded_receipt",
        "_register_loaded_receipt",
        "_registration_matches_live",
        "_same_loaded_receipt",
        "authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
        "load_post_enrollment_graceful_stop_decision_artifact_receipt",
        "main",
        "revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
    }
    definitions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in authority_functions
    }
    assert definitions.keys() == authority_functions
    forbidden_attributes = {
        "__post_init__",
        "_sealed_fields",
        "artifact_path",
        "directory_identity",
        "encoded",
        "file_identity",
        "public_payload",
        "receipt_encoded",
        "receipt_sha256",
    }
    forbidden_calls = {
        "_loaded_receipt_seal_values",
        "_receipt_from_identity_values",
        "_receipt_seal_values",
    }
    for definition in definitions.values():
        assert {
            node.attr
            for node in ast.walk(definition)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
        }.isdisjoint(forbidden_attributes)
        assert {
            node.func.id
            for node in ast.walk(definition)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }.isdisjoint(forbidden_calls)


def test_internal_authority_profiles_ignore_module_global_relabels(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    forged_globals: dict[str, object] = {
        "ARTIFACT_FILE_SUFFIX": ".forged",
        "ARTIFACT_RECEIPT_CONTRACT_VERSION": "forged-receipt-contract",
        "ARTIFACT_WORKFLOW_SERVICE": "forged-receipt-service",
        "DECISION_CANDIDATE_FILE_PREFIX": "forged-",
        "DECISION_CANDIDATE_PREPARED_STATUS": "forged-receipt-status",
        "POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS": frozenset(("authority_granted",)),
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION": "forged-decision",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION": ("forged-decision-contract"),
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_FIELDS": frozenset(),
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES": 1,
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS": "forged-decision-status",
        "POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN": "forged-replay-domain",
        "POST_ENROLLMENT_GRACEFUL_STOP_SERVICE": "forged-service",
        "POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES": 1,
        "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION": ("forged-target-contract"),
        "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_FIELDS": frozenset(),
        "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS": "forged-target-status",
        "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION": (
            "forged-outcome-contract"
        ),
        "_DECISION_CANDIDATE_INPUT_MODES": frozenset((0o777,)),
        "_FALSE_QUALIFICATION_FIELDS": frozenset(),
        "_MAXIMUM_RECEIPT_BYTES": 1,
        "_TRUE_HISTORICAL_FACT_FIELDS": frozenset(),
    }
    for name, value in forged_globals.items():
        monkeypatch.setattr(artifacts, name, value, raising=False)

    receipt = _prepare(inputs)
    expected_decision_sha256 = receipt.graceful_stop_decision_v1_sha256
    candidate_path = inputs.candidate_directory / receipt.artifact_location
    decision = json.loads(candidate_path.read_bytes())
    target = decision["graceful_stop_target"]
    identity_values = cast(tuple[str, ...], artifacts._receipt_seal_values(receipt))
    receipt_payload = json.loads(
        artifacts._canonical_receipt_bytes_from_identity_values(identity_values)
    )

    assert candidate_path.name == (
        f"trusted-time-post-enrollment-graceful-stop-decision-v1-{expected_decision_sha256}.json"
    )
    assert decision["contract_version"] == ("phase6d-post-enrollment-graceful-stop-decision-v1")
    assert decision["decision"] == "approve_one_post_enrollment_graceful_stop_attempt"
    assert decision["replay_domain"] == (
        "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
        "post-enrollment-graceful-stop/operator-attestation/v1"
    )
    assert decision["service"] == "trusted-time-post-enrollment-graceful-stop"
    assert decision["status"] == "external_attestation_required"
    assert target["contract_version"] == ("phase6d-post-enrollment-graceful-stop-target-v1")
    assert target["service"] == "trusted-time-post-enrollment-graceful-stop"
    assert target["status"] == "graceful_stop_target_unqualified"
    assert all(decision[name] is False for name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS)
    assert all(target[name] is False for name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS)
    assert receipt_payload["contract_version"] == (
        "phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1"
    )
    assert receipt_payload["service"] == (
        "trusted-time-post-enrollment-graceful-stop-decision-artifacts"
    )
    assert receipt_payload["status"] == ("graceful_stop_decision_candidate_prepared_unqualified")

    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=expected_decision_sha256,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )


def test_byte_authority_ignores_selective_91_item_serializer_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[object] = []

    def forged_serializer(value: object) -> bytes:
        calls.append(value)
        if (
            type(value) is tuple
            and len(value) == 2
            and tuple.__getitem__(value, 0) == 0
            and type(tuple.__getitem__(value, 1)) is tuple
            and len(tuple.__getitem__(value, 1)) == 91
        ):
            return b'{"authority_granted":true}\n'
        raise AssertionError("rebound serializer reached byte authority")

    monkeypatch.setattr(
        artifacts,
        "_canonical_immutable_json_bytes",
        forged_serializer,
        raising=False,
    )
    monkeypatch.setattr(
        artifacts,
        "_EXACT_IMMUTABLE_JSON_SERIALIZER",
        forged_serializer,
    )
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    receipt_payload = json.loads(loaded.receipt_encoded)
    assert receipt_payload["authority_granted"] is False
    assert calls == []


def test_byte_authority_ignores_selective_receipt_helper_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    def forged_receipt_bytes(identity_values: tuple[str, ...]) -> bytes:
        calls.append(identity_values)
        return b'{"authority_granted":true}\n'

    monkeypatch.setattr(
        artifacts,
        "_canonical_receipt_bytes_from_identity_values",
        forged_receipt_bytes,
    )
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert json.loads(loaded.receipt_encoded)["authority_granted"] is False
    assert calls == []


def test_path_authority_ignores_selective_candidate_name_helper_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    def forged_candidate_name(decision_sha256: str) -> str:
        calls.append(decision_sha256)
        return "forged.json"

    monkeypatch.setattr(
        artifacts,
        "_decision_candidate_file_name",
        forged_candidate_name,
    )
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    assert receipt.artifact_location == (
        "trusted-time-post-enrollment-graceful-stop-decision-v1-"
        f"{receipt.graceful_stop_decision_v1_sha256}.json"
    )
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert calls == []


def test_byte_authority_ignores_outcome_only_sha256_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    outcome_encoded = inputs.outcome.artifact_path.read_bytes()
    exact_sha256 = hashlib.sha256
    calls: list[bytes] = []

    class ForgedDigest:
        @staticmethod
        def hexdigest() -> str:
            return "0" * 64

    class ReboundHashlib:
        @staticmethod
        def sha256(encoded: bytes) -> object:
            calls.append(encoded)
            return ForgedDigest() if encoded == outcome_encoded else exact_sha256(encoded)

    monkeypatch.setattr(artifacts, "hashlib", ReboundHashlib)
    receipt = _prepare(inputs)
    assert receipt.controller_outcome_sha256 == exact_sha256(outcome_encoded).hexdigest()
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert calls == []


def test_candidate_decoder_has_no_mutable_object_pairs_hook_aba(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ForgingJSONModule:
        calls = 0

        def loads(self, *_args: object, **kwargs: object) -> object:
            self.calls += 1
            hook = kwargs["object_pairs_hook"]
            return hook([("authority_granted", True)])

    forged_json = ForgingJSONModule()
    monkeypatch.setattr(artifacts, "json", forged_json, raising=False)
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert forged_json.calls == 0

    source = Path(artifacts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    decoder = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_decode_immutable_json_object"
    )
    assert not any(
        isinstance(node, (ast.Dict, ast.DictComp, ast.ListComp)) for node in ast.walk(decoder)
    )
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "list"
        for node in ast.walk(decoder)
    )
    assert {
        node.id
        for node in ast.walk(decoder)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }.isdisjoint({"json", "_canonical_immutable_json_bytes", "_immutable_json_object"})


def test_byte_authority_ignores_selective_locator_decoder_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    _, historical = artifacts._load_historical_start_chain(
        start_operator_attested_approval_artifact=os.fspath(inputs.attested_artifact),
        artifact_directory=os.fspath(inputs.artifact_directory),
        ignored_root=os.fspath(inputs.ignored_root),
    )
    outcome_snapshot = cast(
        tuple[object, ...],
        artifacts._historical_slot(historical, 1),
    )
    semantic = cast(
        tuple[object, ...],
        artifacts._controller_snapshot_value(outcome_snapshot, 8),
    )
    locator_encoded = cast(
        bytes,
        artifacts._controller_semantic_value(semantic, 9),
    )
    exact_decoder = artifacts._decode_immutable_json_object
    calls: list[bytes] = []

    def selective_decoder(
        encoded: object,
        *,
        maximum_bytes: int,
    ) -> tuple[object, ...]:
        assert type(encoded) is bytes
        calls.append(encoded)
        if encoded == locator_encoded:
            return (0, (("authority_granted", True),))
        return exact_decoder(encoded, maximum_bytes=maximum_bytes)

    monkeypatch.setattr(
        artifacts,
        "_decode_immutable_json_object",
        selective_decoder,
    )
    receipt = _prepare(inputs)
    loaded = _load_pending_receipt(inputs, receipt)
    artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        start_operator_attested_approval_artifact=inputs.attested_artifact,
        expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert artifacts.revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
        loaded,
        artifact_directory=inputs.artifact_directory,
        ignored_root=inputs.ignored_root,
    )
    assert calls == []


@pytest.mark.parametrize("boundary", ["load", "authenticate"])
def test_registry_root_binding_rejects_path_a_b_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
) -> None:
    actual_root = tmp_path / "actual"
    actual_root.mkdir(mode=0o700)
    inputs = _prepared_inputs(monkeypatch, actual_root)
    receipt = _prepare(inputs)
    labelled_ignored_root = tmp_path / "labelled-ignored"
    labelled_ignored_root.mkdir(mode=0o700)
    labelled_artifact_directory = labelled_ignored_root / "trusted-time"
    labelled_artifact_directory.mkdir(mode=0o700)
    pending = _load_pending_receipt(inputs, receipt) if boundary == "authenticate" else None
    directory_raw = labelled_artifact_directory._raw_paths
    directory_string = os.fspath(labelled_artifact_directory)
    root_raw = labelled_ignored_root._raw_paths
    root_string = os.fspath(labelled_ignored_root)
    real_capture = artifacts._captured_path_string
    switched = False

    def switch_after_root_capture(value: object) -> str:
        nonlocal switched
        result = real_capture(value)
        if not switched and value is labelled_ignored_root:
            switched = True
            object.__setattr__(
                labelled_artifact_directory,
                "_raw_paths",
                [os.fspath(inputs.artifact_directory)],
            )
            object.__setattr__(
                labelled_artifact_directory,
                "_str",
                os.fspath(inputs.artifact_directory),
            )
            object.__setattr__(
                labelled_ignored_root,
                "_raw_paths",
                [os.fspath(inputs.ignored_root)],
            )
            object.__setattr__(
                labelled_ignored_root,
                "_str",
                os.fspath(inputs.ignored_root),
            )
        return result

    monkeypatch.setattr(artifacts, "_captured_path_string", switch_after_root_capture)
    try:
        with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
            if boundary == "authenticate":
                assert pending is not None
                artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                    pending,
                    start_operator_attested_approval_artifact=inputs.attested_artifact,
                    expected_graceful_stop_decision_v1_sha256=(
                        receipt.graceful_stop_decision_v1_sha256
                    ),
                    artifact_directory=labelled_artifact_directory,
                    ignored_root=labelled_ignored_root,
                )
            else:
                artifacts.load_post_enrollment_graceful_stop_decision_artifact_receipt(
                    graceful_stop_decision_v1_artifact=(
                        inputs.candidate_directory / receipt.artifact_location
                    ),
                    start_operator_attested_approval_artifact=inputs.attested_artifact,
                    expected_graceful_stop_decision_v1_sha256=(
                        receipt.graceful_stop_decision_v1_sha256
                    ),
                    artifact_directory=labelled_artifact_directory,
                    ignored_root=labelled_ignored_root,
                )
    finally:
        object.__setattr__(labelled_artifact_directory, "_raw_paths", directory_raw)
        object.__setattr__(labelled_artifact_directory, "_str", directory_string)
        object.__setattr__(labelled_ignored_root, "_raw_paths", root_raw)
        object.__setattr__(labelled_ignored_root, "_str", root_string)

    assert switched
    assert not artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert not artifacts._LOADED_RECEIPT_REGISTRY


def test_candidate_filename_ignores_selective_basename_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    canonical_path = inputs.candidate_directory / receipt.artifact_location
    noncanonical_path = inputs.candidate_directory / "reviewed-candidate.json"
    noncanonical_path.write_bytes(canonical_path.read_bytes())
    noncanonical_path.chmod(0o600)
    exact_os = artifacts.os
    exact_basename = exact_os.path.basename
    calls: list[str] = []

    class ReboundPathModule:
        def basename(self, value: str) -> str:
            calls.append(value)
            if value == os.fspath(noncanonical_path):
                return receipt.artifact_location
            return exact_basename(value)

        def __getattr__(self, name: str) -> object:
            return getattr(exact_os.path, name)

    class ReboundOSModule:
        path = ReboundPathModule()

        def __getattr__(self, name: str) -> object:
            return getattr(exact_os, name)

    monkeypatch.setattr(artifacts, "os", ReboundOSModule())

    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        artifacts.load_post_enrollment_graceful_stop_decision_artifact_receipt(
            graceful_stop_decision_v1_artifact=noncanonical_path,
            start_operator_attested_approval_artifact=inputs.attested_artifact,
            expected_graceful_stop_decision_v1_sha256=(receipt.graceful_stop_decision_v1_sha256),
            artifact_directory=inputs.artifact_directory,
            ignored_root=inputs.ignored_root,
        )

    assert calls == []
    assert not artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert not artifacts._LOADED_RECEIPT_REGISTRY


def test_candidate_directory_rejects_relabelled_repository_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "ignored"
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(parents=True, mode=0o700)
    repository_root = Path(artifacts._audited_fs._REPOSITORY_ROOT_STRING)
    candidate_directory = repository_root / f".adr0112-candidate-{tmp_path.name}"
    candidate_directory.mkdir(mode=0o700)
    monkeypatch.setattr(
        artifacts._audited_fs,
        "_REPOSITORY_ROOT_STRING",
        os.fspath(tmp_path),
    )
    try:
        with pytest.raises(
            artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
        ) as captured:
            artifacts._require_external_candidate_directory(
                os.fspath(candidate_directory),
                artifact_directory=os.fspath(artifact_directory),
                ignored_root=os.fspath(ignored_root),
            )
    finally:
        candidate_directory.rmdir()

    assert captured.value.reason_code == "decision_candidate_directory_unavailable"


def test_candidate_directory_containment_predicate_is_captured(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "ignored"
    artifact_directory = ignored_root / "trusted-time"
    candidate_directory = artifact_directory / "nested-candidate"
    candidate_directory.mkdir(parents=True, mode=0o700)
    calls: list[tuple[str, str]] = []

    def forged_containment(path: str, root: str) -> bool:
        calls.append((path, root))
        return False

    monkeypatch.setattr(
        artifacts,
        "_path_is_same_or_beneath",
        forged_containment,
    )

    with pytest.raises(
        artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
    ) as captured:
        artifacts._require_external_candidate_directory(
            os.fspath(candidate_directory),
            artifact_directory=os.fspath(artifact_directory),
            ignored_root=os.fspath(ignored_root),
        )

    assert captured.value.reason_code == "decision_candidate_directory_unavailable"
    assert calls == []


@pytest.mark.parametrize("boundary", ["candidate_load", "start_load", "start_authenticate"])
def test_public_selection_paths_are_frozen_before_callbacks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    receipt = _prepare(inputs)
    actual_candidate = inputs.candidate_directory / receipt.artifact_location
    alternate_candidate_directory = tmp_path / "alternate-candidates"
    alternate_candidate_directory.mkdir(mode=0o700)
    alternate_candidate = alternate_candidate_directory / receipt.artifact_location
    alternate_candidate.write_bytes(actual_candidate.read_bytes())
    alternate_candidate.chmod(0o600)
    alternate_start = tmp_path / "alternate-start-approval.json"
    alternate_start.write_bytes(inputs.attested_artifact.read_bytes())
    alternate_start.chmod(0o600)
    if boundary == "candidate_load":
        selected = alternate_candidate
        replacement = actual_candidate
    else:
        selected = alternate_start
        replacement = inputs.attested_artifact
    selected_raw = selected._raw_paths
    selected_string = os.fspath(selected)
    real_require_sha256 = artifacts._require_expected_sha256
    switched = False

    def switch_after_capture(value: object, *, field_name: str) -> str:
        nonlocal switched
        if not switched:
            switched = True
            object.__setattr__(selected, "_raw_paths", [os.fspath(replacement)])
            object.__setattr__(selected, "_str", os.fspath(replacement))
        return real_require_sha256(value, field_name=field_name)

    pending = _load_pending_receipt(inputs, receipt) if boundary == "start_authenticate" else None
    monkeypatch.setattr(artifacts, "_require_expected_sha256", switch_after_capture)
    loaded: artifacts.LoadedTrustedTimePostEnrollmentGracefulStopDecisionArtifactReceipt | None = (
        None
    )
    try:
        if boundary == "candidate_load":
            loaded = artifacts.load_post_enrollment_graceful_stop_decision_artifact_receipt(
                graceful_stop_decision_v1_artifact=selected,
                start_operator_attested_approval_artifact=inputs.attested_artifact,
                expected_graceful_stop_decision_v1_sha256=(
                    receipt.graceful_stop_decision_v1_sha256
                ),
                artifact_directory=inputs.artifact_directory,
                ignored_root=inputs.ignored_root,
            )
            registration = artifacts._PENDING_LOADED_RECEIPT_REGISTRY[id(loaded)]
            source = cast(tuple[object, ...], tuple.__getitem__(registration, 5))
            assert artifacts._source_slot(source, 1) == selected_string
        elif boundary == "start_load":
            with pytest.raises(
                artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
            ):
                artifacts.load_post_enrollment_graceful_stop_decision_artifact_receipt(
                    graceful_stop_decision_v1_artifact=actual_candidate,
                    start_operator_attested_approval_artifact=selected,
                    expected_graceful_stop_decision_v1_sha256=(
                        receipt.graceful_stop_decision_v1_sha256
                    ),
                    artifact_directory=inputs.artifact_directory,
                    ignored_root=inputs.ignored_root,
                )
        else:
            assert pending is not None
            with pytest.raises(
                artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
            ):
                artifacts.authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt(
                    pending,
                    start_operator_attested_approval_artifact=selected,
                    expected_graceful_stop_decision_v1_sha256=(
                        receipt.graceful_stop_decision_v1_sha256
                    ),
                    artifact_directory=inputs.artifact_directory,
                    ignored_root=inputs.ignored_root,
                )
    finally:
        object.__setattr__(selected, "_raw_paths", selected_raw)
        object.__setattr__(selected, "_str", selected_string)
    assert switched
    if loaded is not None:
        cleanup_error = artifacts._revoke_pending_loaded_receipt_if_registered(loaded)
        assert cleanup_error is None
    assert not artifacts._PENDING_LOADED_RECEIPT_REGISTRY
    assert not artifacts._LOADED_RECEIPT_REGISTRY


@pytest.mark.parametrize("boundary", ["start", "candidate_directory"])
def test_prepare_selection_paths_are_frozen_before_callbacks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    boundary: str,
) -> None:
    inputs = _prepared_inputs(monkeypatch, tmp_path)
    alternate_candidate_directory = tmp_path / "alternate-candidate-directory"
    alternate_candidate_directory.mkdir(mode=0o700)
    alternate_start = tmp_path / "alternate-start-approval.json"
    alternate_start.write_bytes(inputs.attested_artifact.read_bytes())
    alternate_start.chmod(0o600)
    if boundary == "candidate_directory":
        selected = alternate_candidate_directory
        replacement = inputs.candidate_directory
    else:
        selected = alternate_start
        replacement = inputs.attested_artifact
    selected_raw = selected._raw_paths
    selected_string = os.fspath(selected)
    replacement_before = tuple(inputs.candidate_directory.iterdir())
    real_require_operation_id = artifacts._require_graceful_stop_operation_id
    switched = False

    def switch_after_capture(value: object) -> str:
        nonlocal switched
        if not switched:
            switched = True
            object.__setattr__(selected, "_raw_paths", [os.fspath(replacement)])
            object.__setattr__(selected, "_str", os.fspath(replacement))
        return real_require_operation_id(value)

    monkeypatch.setattr(
        artifacts,
        "_require_graceful_stop_operation_id",
        switch_after_capture,
    )
    try:
        if boundary == "candidate_directory":
            receipt = _prepare(inputs, decision_candidate_directory=selected)
            assert (Path(selected_string) / receipt.artifact_location).is_file()
            assert tuple(inputs.candidate_directory.iterdir()) == replacement_before
        else:
            with pytest.raises(
                artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError
            ):
                _prepare(inputs, start_operator_attested_approval_artifact=selected)
    finally:
        object.__setattr__(selected, "_raw_paths", selected_raw)
        object.__setattr__(selected, "_str", selected_string)
    assert switched


def test_prepare_rejects_historical_snapshot_from_relabelled_invocation_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    actual_root = tmp_path / "actual"
    actual_root.mkdir(mode=0o700)
    inputs = _prepared_inputs(monkeypatch, actual_root)
    labelled_ignored_root = tmp_path / "labelled-ignored"
    labelled_artifact_directory = labelled_ignored_root / "trusted-time"
    labelled_artifact_directory.mkdir(parents=True, mode=0o700)
    labelled_start = tmp_path / "labelled-start-approval.json"
    labelled_start.write_bytes(inputs.attested_artifact.read_bytes())
    labelled_start.chmod(0o600)
    real_load = artifacts._load_historical_start_chain

    def load_from_relabelled_b(**_kwargs: object) -> tuple[Any, Any]:
        return real_load(
            start_operator_attested_approval_artifact=os.fspath(inputs.attested_artifact),
            artifact_directory=os.fspath(inputs.artifact_directory),
            ignored_root=os.fspath(inputs.ignored_root),
        )

    monkeypatch.setattr(artifacts, "_load_historical_start_chain", load_from_relabelled_b)
    before = tuple(inputs.candidate_directory.iterdir())

    with pytest.raises(artifacts.TrustedTimePostEnrollmentGracefulStopDecisionArtifactError):
        _prepare(
            inputs,
            start_operator_attested_approval_artifact=labelled_start,
            artifact_directory=labelled_artifact_directory,
            ignored_root=labelled_ignored_root,
        )

    assert tuple(inputs.candidate_directory.iterdir()) == before


def test_private_path_authority_is_exact_string_only() -> None:
    source = Path(artifacts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {
        "_load_historical_start_chain",
        "_revalidate_historical_start_chain",
        "_require_external_candidate_directory",
        "_read_decision_candidate_binding",
    }
    definitions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in names
    }
    assert definitions.keys() == names
    for definition in definitions.values():
        path_arguments = {
            argument.arg
            for argument in (*definition.args.args, *definition.args.kwonlyargs)
            if argument.arg
            in {
                "artifact_directory",
                "directory",
                "graceful_stop_decision_v1_artifact",
                "ignored_root",
                "start_operator_attested_approval_artifact",
            }
        }
        annotations = {
            argument.arg: argument.annotation
            for argument in (*definition.args.args, *definition.args.kwonlyargs)
            if argument.arg in path_arguments
        }
        assert annotations.keys() == path_arguments
        assert all(
            isinstance(annotation, ast.Name) and annotation.id == "str"
            for annotation in annotations.values()
        )
        assert not any(
            isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "Path"
            for node in ast.walk(definition)
        )

    invocation_consumers = {
        "_prepare_post_enrollment_graceful_stop_decision_candidate_with_snapshot",
        "authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
        "load_post_enrollment_graceful_stop_decision_artifact_receipt",
        "revalidate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt",
    }
    consumer_definitions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in invocation_consumers
    }
    assert consumer_definitions.keys() == invocation_consumers
    for definition in consumer_definitions.values():
        called_names = {
            node.func.id
            for node in ast.walk(definition)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "_load_historical_start_chain" in called_names
        assert "_historical_invocation_binding_matches" in called_names

    dynamic_path_calls = {
        ast.unparse(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and (
            (
                isinstance(node.func.value, ast.Attribute)
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "os"
                and node.func.value.attr == "path"
            )
            or (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in {"fsencode", "fspath"}
            )
        )
    }
    assert dynamic_path_calls == set()
    direct_named_authority_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {
            "_canonical_receipt_bytes_from_identity_values",
            "_decision_candidate_file_name",
            "_decode_immutable_json_object",
            "_path_is_same_or_beneath",
        }
    }
    assert direct_named_authority_calls == set()


def test_registry_runtime_primitives_and_retry_bound_are_captured() -> None:
    source = Path(artifacts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    registry_functions = {
        "_burn_loaded_receipt_registry_entry",
        "_burn_pending_loaded_receipt_registry_entry",
        "_consume_loaded_receipt_registration",
        "_consume_pending_loaded_receipt",
        "_held_loaded_receipt_registry_lock",
        "_pending_loaded_receipt_matches_live",
        "_register_loaded_receipt",
        "_register_pending_loaded_receipt",
        "_registration_matches_live",
        "_require_loaded_receipt_registration",
        "_revoke_loaded_receipt",
        "_revoke_loaded_receipt_if_registered",
        "_revoke_pending_loaded_receipt_if_registered",
    }
    definitions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in registry_functions
    }
    assert definitions.keys() == registry_functions
    for definition in definitions.values():
        body = ast.Module(body=definition.body, type_ignores=[])
        loaded_names = {
            node.id
            for node in ast.walk(body)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        assert "_LOADED_RECEIPT_REGISTRY_BURN_ATTEMPTS" not in loaded_names
        assert "_LOADED_RECEIPT_ORIGIN_PID" not in loaded_names
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and (node.func.value.id, node.func.attr)
            in {
                ("os", "getpid"),
                ("threading", "current_thread"),
                ("weakref", "ref"),
            }
            for node in ast.walk(body)
        )
    for function_name in (
        "_burn_loaded_receipt_registry_entry",
        "_burn_pending_loaded_receipt_registry_entry",
        "_revoke_loaded_receipt_if_registered",
        "_revoke_pending_loaded_receipt_if_registered",
    ):
        definition = definitions[function_name]
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "range"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == 16
            for node in ast.walk(definition)
        )


def test_internal_authority_profiles_do_not_load_rebindable_schema_globals() -> None:
    source = Path(artifacts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    authority_functions = {
        "_build_loaded_receipt_source_snapshot",
        "_canonical_receipt_bytes_from_identity_values",
        "_expected_decision_candidate_snapshot",
        "_require_historical_start_chain",
    }
    definitions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in authority_functions
    }
    assert definitions.keys() == authority_functions
    forbidden_names = {
        "ARTIFACT_FILE_SUFFIX",
        "ARTIFACT_RECEIPT_CONTRACT_VERSION",
        "ARTIFACT_WORKFLOW_SERVICE",
        "DECISION_CANDIDATE_FILE_PREFIX",
        "DECISION_CANDIDATE_PREPARED_STATUS",
        "POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_ARTIFACT_RECEIPT_FIELDS",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_CONTRACT_VERSION",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_FIELDS",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES",
        "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_STATUS",
        "POST_ENROLLMENT_GRACEFUL_STOP_REPLAY_DOMAIN",
        "POST_ENROLLMENT_GRACEFUL_STOP_SERVICE",
        "POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES",
        "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_CONTRACT_VERSION",
        "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_FIELDS",
        "POST_ENROLLMENT_GRACEFUL_STOP_TARGET_STATUS",
        "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION",
        "_DECISION_CANDIDATE_INPUT_MODES",
        "_FALSE_QUALIFICATION_FIELDS",
        "_MAXIMUM_RECEIPT_BYTES",
        "_TRUE_HISTORICAL_FACT_FIELDS",
    }
    for definition in definitions.values():
        assert {
            node.id
            for node in ast.walk(definition)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }.isdisjoint(forbidden_names)


def test_source_has_no_effecting_secret_or_caller_choice_surface() -> None:
    source = Path(artifacts.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    called_names = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))
    }

    assert imported_roots.isdisjoint(
        {
            "boto3",
            "docker",
            "psycopg",
            "requests",
            "secrets",
            "socket",
            "sqlalchemy",
            "subprocess",
        }
    )
    assert called_names.isdisjoint(
        {
            "connect",
            "execve",
            "getenv",
            "input",
            "kill",
            "Popen",
            "remove",
            "run",
            "send_signal",
            "sign",
            "unlink",
            "uuid4",
        }
    )
    assert "os.environ" not in source
    assert "sys.stdin" not in source
    assert "private_key" not in source
    assert "_decode_slot_payload" not in source
    assert "slot_payload" not in source
    assert "NamedTuple" not in source
    assert "_RECEIPT_IDENTITY_FIELD_ORDER" not in source
    assert "._replace(" not in source
    forbidden_imported_authority_metadata = {
        "_ControllerOutcomeSemanticSnapshot",
        "_LoadedOperatorAttestedApprovalSnapshot",
        "_RetainedControllerOutcomeSnapshot",
        "_RetainedOperatorAttestedExecutionAttemptSnapshot",
        "_TrustedTimeImageAdmissionProvenanceSnapshot",
    }
    assert forbidden_imported_authority_metadata.isdisjoint(
        {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
    )
    authority_slot_helpers = {
        "_attempt_snapshot_value",
        "_chain_slot",
        "_controller_semantic_value",
        "_controller_snapshot_value",
        "_expected_slot",
        "_external_binding_value",
        "_historical_slot",
        "_loaded_approval_snapshot_value",
        "_pending_slot",
        "_provenance_value",
        "_registration_slot",
        "_source_slot",
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in authority_slot_helpers
        ):
            assert len(node.args) >= 2
            assert isinstance(node.args[1], ast.Constant)
            assert type(node.args[1].value) is int
    assert "authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt" in (
        artifacts.__all__
    )
