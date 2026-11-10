from __future__ import annotations

import ast
import copy
import hashlib
import json
import pickle
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_graceful_stop as graceful_stop
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
)
from scripts import trusted_time_post_enrollment_controller_outcome as controller_outcome
from scripts import trusted_time_post_enrollment_shutdown_locator as shutdown_locator
from scripts.trusted_time_post_enrollment_active_controller_admission import (
    TrustedTimePostEnrollmentStartActiveControllerAdmission,
)
from tests.unit import test_trusted_time_post_enrollment_active_controller_admission as admission_fx
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_controller_outcome as outcome_fx
from tests.unit import test_trusted_time_post_enrollment_persistent_topology as persistent_fx

STOP_OPERATION_ID = "323e4567-e89b-42d3-a456-426614174002"
START_ATTEMPT_SLOT_SHA256 = "7" * 64
START_ATTESTATION_ENVELOPE_SHA256 = "8" * 64


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


def _confirmed_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
    origin = next(
        candidate
        for candidate in admission_fx._registry_state()[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    capability, _ = outcome_fx._install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
        expected_outcome_kind="success",
    )
    topology = persistent_fx._validate(inputs)
    return controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=outcome_fx._confirmed_evidence(inputs, topology),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )


def _target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> graceful_stop.TrustedTimePostEnrollmentGracefulStopTarget:
    return graceful_stop.build_post_enrollment_graceful_stop_target(
        retained_start_outcome=_confirmed_receipt(monkeypatch, tmp_path),
        start_execution_attempt_slot_sha256=START_ATTEMPT_SLOT_SHA256,
        start_operator_attestation_envelope_sha256=(START_ATTESTATION_ENVELOPE_SHA256),
    )


def _decision(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> graceful_stop.TrustedTimePostEnrollmentGracefulStopDecision:
    return graceful_stop.build_post_enrollment_graceful_stop_decision(
        operation_id=STOP_OPERATION_ID,
        target=_target(monkeypatch, tmp_path),
    )


def _mutated(payload: dict[str, object], path: tuple[str, ...], value: object) -> bytes:
    isolated = json.loads(canonical_first_enrollment_json_bytes(payload))
    cursor = isolated
    for component in path[:-1]:
        cursor = cast(dict[str, object], cursor[component])
    cursor[path[-1]] = value
    return canonical_first_enrollment_json_bytes(isolated)


def test_target_round_trip_freezes_exact_fields_bindings_and_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    receipt = _confirmed_receipt(monkeypatch, tmp_path)
    target = graceful_stop.build_post_enrollment_graceful_stop_target(
        retained_start_outcome=receipt,
        start_execution_attempt_slot_sha256=START_ATTEMPT_SLOT_SHA256,
        start_operator_attestation_envelope_sha256=(START_ATTESTATION_ENVELOPE_SHA256),
    )
    encoded = graceful_stop.canonical_post_enrollment_graceful_stop_target_bytes(target)
    decoded = graceful_stop.decode_post_enrollment_graceful_stop_target(encoded)
    payload = decoded.payload()

    assert decoded == target
    assert set(payload) == graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_TARGET_FIELDS
    assert payload["contract_version"] == ("phase6d-post-enrollment-graceful-stop-target-v1")
    assert payload["service"] == "trusted-time-post-enrollment-graceful-stop"
    assert payload["status"] == "graceful_stop_target_unqualified"
    assert payload["start_operation_id"] == receipt.operation_id
    assert payload["start_approval_sha256"] == receipt.approval_sha256
    assert payload["controller_outcome_contract_version"] == (
        "phase6d-post-enrollment-start-retained-controller-outcome-v2"
    )
    assert payload["controller_outcome_status"] == "post_enrollment_start_confirmed"
    assert payload["controller_outcome_reason"] == "post_enrollment_start_confirmed"
    assert payload["controller_outcome_sha256"] == receipt.outcome_sha256
    assert payload["start_execution_attempt_slot_sha256"] == START_ATTEMPT_SLOT_SHA256
    assert payload["start_operator_attestation_envelope_sha256"] == (
        START_ATTESTATION_ENVELOPE_SHA256
    )
    assert payload["durable_shutdown_locator_sha256"] == (receipt.durable_shutdown_locator_sha256)
    assert (
        payload["durable_shutdown_locator"] == cast(Any, receipt.durable_shutdown_locator).payload()
    )
    assert encoded.endswith(b"\n") and encoded.count(b"\n") == 1
    assert len(encoded) <= graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES
    assert target.encoded == encoded
    assert target.target_sha256 == hashlib.sha256(encoded).hexdigest()


def test_decision_round_trip_freezes_stop_only_domain_without_key_or_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    decision = _decision(monkeypatch, tmp_path)
    encoded = graceful_stop.canonical_post_enrollment_graceful_stop_decision_bytes(decision)
    decoded = graceful_stop.decode_post_enrollment_graceful_stop_decision(encoded)
    payload = decoded.payload()

    assert decoded == decision
    assert set(payload) == graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_FIELDS
    assert payload["contract_version"] == ("phase6d-post-enrollment-graceful-stop-decision-v1")
    assert payload["decision"] == "approve_one_post_enrollment_graceful_stop_attempt"
    assert payload["replay_domain"] == (
        "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
        "post-enrollment-graceful-stop/operator-attestation/v1"
    )
    assert payload["decision"] != POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION
    assert payload["replay_domain"] != POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
    assert payload["status"] == "external_attestation_required"
    assert payload["operation_id"] == STOP_OPERATION_ID
    assert payload["graceful_stop_target"] == decision.target.payload()
    assert payload["graceful_stop_target_sha256"] == decision.target.target_sha256
    assert "key_id" not in payload
    assert "signature" not in payload
    assert encoded.endswith(b"\n") and encoded.count(b"\n") == 1
    assert len(encoded) <= graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES
    assert decision.encoded == encoded
    assert decision.decision_sha256 == hashlib.sha256(encoded).hexdigest()


def test_target_and_decision_close_every_fact_and_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    decision = graceful_stop.build_post_enrollment_graceful_stop_decision(
        operation_id=STOP_OPERATION_ID,
        target=target,
    )

    for projection in (target, decision):
        payload = projection.payload()
        assert all(
            payload[field_name] is False
            for field_name in graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
        )
        assert all(
            getattr(projection, field_name) is False
            for field_name in graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
        )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        (
            "contract_version",
            controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION,
        ),
        (
            "status",
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED,
        ),
        (
            "reason",
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED,
        ),
        ("durable_shutdown_locator", None),
        ("durable_shutdown_locator_sha256", "0" * 64),
        ("commit_file_identity", None),
    ],
)
def test_target_builder_rejects_wrong_or_uncommitted_start_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field_name: str,
    replacement: object,
) -> None:
    receipt = _confirmed_receipt(monkeypatch, tmp_path)
    object.__setattr__(receipt, field_name, replacement)

    with pytest.raises(
        graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected,
        match="target is invalid",
    ):
        graceful_stop.build_post_enrollment_graceful_stop_target(
            retained_start_outcome=receipt,
            start_execution_attempt_slot_sha256=START_ATTEMPT_SLOT_SHA256,
            start_operator_attestation_envelope_sha256=(START_ATTESTATION_ENVELOPE_SHA256),
        )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("start_execution_attempt_slot_sha256", True),
        ("start_execution_attempt_slot_sha256", "A" * 64),
        ("start_operator_attestation_envelope_sha256", "0" * 63),
        ("start_operator_attestation_envelope_sha256", b"0" * 64),
    ],
)
def test_target_builder_rejects_malformed_attempt_or_envelope_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field_name: str,
    replacement: object,
) -> None:
    values: dict[str, object] = {
        "start_execution_attempt_slot_sha256": START_ATTEMPT_SLOT_SHA256,
        "start_operator_attestation_envelope_sha256": (START_ATTESTATION_ENVELOPE_SHA256),
    }
    values[field_name] = replacement
    builder = cast(Callable[..., object], graceful_stop.build_post_enrollment_graceful_stop_target)

    with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
        builder(
            retained_start_outcome=_confirmed_receipt(monkeypatch, tmp_path),
            **values,
        )


def test_target_decoder_rejects_every_chain_or_locator_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    payload = target.payload()
    locator_payload = cast(dict[str, object], payload["durable_shutdown_locator"])
    topology = cast(dict[str, object], locator_payload["persistent_topology"])
    candidates = (
        _mutated(payload, ("controller_outcome_contract_version",), "outcome-v1"),
        _mutated(payload, ("controller_outcome_status",), "recovery_required"),
        _mutated(payload, ("controller_outcome_reason",), "sequence_2_unconfirmed"),
        _mutated(payload, ("controller_outcome_sha256",), "0" * 63),
        _mutated(payload, ("durable_shutdown_locator_sha256",), "0" * 64),
        _mutated(payload, ("start_execution_attempt_slot_sha256",), "A" * 64),
        _mutated(payload, ("start_operator_attestation_envelope_sha256",), True),
        _mutated(payload, ("shutdown_authorized",), True),
        _mutated(
            payload,
            ("durable_shutdown_locator", "persistent_topology", "operation_id"),
            STOP_OPERATION_ID,
        ),
        _mutated(
            payload,
            ("durable_shutdown_locator", "persistent_topology", "approval_sha256"),
            "0" * 64,
        ),
    )
    assert topology["operation_id"] == target.start_operation_id

    for encoded in candidates:
        with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
            graceful_stop.decode_post_enrollment_graceful_stop_target(encoded)


def test_decision_decoder_rejects_scope_target_hash_and_same_uuid_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    decision = _decision(monkeypatch, tmp_path)
    payload = decision.payload()
    candidates = (
        _mutated(payload, ("contract_version",), "decision-v2"),
        _mutated(payload, ("decision",), "approve_all_stops"),
        _mutated(payload, ("replay_domain",), "start-domain"),
        _mutated(payload, ("status",), "approved"),
        _mutated(payload, ("graceful_stop_target_sha256",), "0" * 64),
        _mutated(payload, ("operation_id",), decision.target.start_operation_id),
        _mutated(payload, ("single_use_authenticated",), True),
    )

    for encoded in candidates:
        with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
            graceful_stop.decode_post_enrollment_graceful_stop_decision(encoded)

    with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
        graceful_stop.build_post_enrollment_graceful_stop_decision(
            operation_id=decision.target.start_operation_id,
            target=decision.target,
        )


def test_codecs_reject_duplicate_extra_missing_noncanonical_oversized_and_tree_abuse(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    encoded = target.encoded
    duplicate = encoded.replace(
        b'{"active_controller_authorized":false,',
        b'{"active_controller_authorized":false,"active_controller_authorized":false,',
        1,
    )
    extra = target.payload()
    extra["unexpected"] = False
    missing = target.payload()
    del missing["status"]
    deep: object = False
    for _ in range(graceful_stop._MAXIMUM_JSON_DEPTH + 2):
        deep = [deep]
    deep_payload = target.payload()
    deep_payload["status"] = deep

    candidates = (
        duplicate,
        canonical_first_enrollment_json_bytes(extra),
        canonical_first_enrollment_json_bytes(missing),
        encoded.removesuffix(b"\n"),
        b" " + encoded,
        encoded + b"\n",
        b" " * (graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES + 1),
        canonical_first_enrollment_json_bytes(deep_payload),
    )
    for candidate in candidates:
        with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
            graceful_stop.decode_post_enrollment_graceful_stop_target(candidate)

    for invalid_value in (None, True, "{}\n", bytearray(b"{}\n"), b"[]\n", b"null\n"):
        with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
            graceful_stop.decode_post_enrollment_graceful_stop_decision(invalid_value)


def test_codecs_reject_duplicates_at_locator_topology_target_and_decision_nesting(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    target_encoded = target.encoded
    decision_encoded = graceful_stop.build_post_enrollment_graceful_stop_decision(
        operation_id=STOP_OPERATION_ID,
        target=target,
    ).encoded
    mutations = (
        target_encoded.replace(
            b'"active_controller_session_sha256":',
            b'"active_controller_session_sha256":"duplicate","active_controller_session_sha256":',
            1,
        ),
        target_encoded.replace(
            b'"daemon_identity":{',
            b'"daemon_identity":{"context_name":"duplicate",',
            1,
        ),
        decision_encoded.replace(
            b'"controller_outcome_sha256":',
            b'"controller_outcome_sha256":"duplicate","controller_outcome_sha256":',
            1,
        ),
        decision_encoded.replace(
            b'"graceful_stop_target_sha256":',
            b'"graceful_stop_target_sha256":"duplicate","graceful_stop_target_sha256":',
            1,
        ),
    )

    for candidate in mutations[:2]:
        with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
            graceful_stop.decode_post_enrollment_graceful_stop_target(candidate)
    for candidate in mutations[2:]:
        with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
            graceful_stop.decode_post_enrollment_graceful_stop_decision(candidate)


def test_maximum_astral_locator_survives_target_and_decision_codecs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    locator_payload = json.loads(
        canonical_first_enrollment_json_bytes(target.durable_shutdown_locator.payload())
    )
    topology = cast(dict[str, object], locator_payload["persistent_topology"])
    daemon = cast(dict[str, object], topology["daemon_identity"])
    endpoint_prefix = "unix:///"
    endpoint = endpoint_prefix + chr(0x1F600) * (4_096 - len(endpoint_prefix))
    daemon["endpoint"] = endpoint
    topology_encoded = canonical_first_enrollment_json_bytes(topology)
    locator_payload["persistent_topology_sha256"] = hashlib.sha256(topology_encoded).hexdigest()
    locator = shutdown_locator.decode_post_enrollment_graceful_stop_shutdown_locator(
        canonical_first_enrollment_json_bytes(locator_payload)
    )
    target_payload = target.payload()
    target_payload["durable_shutdown_locator"] = locator.payload()
    target_payload["durable_shutdown_locator_sha256"] = (
        shutdown_locator.post_enrollment_graceful_stop_shutdown_locator_sha256(locator)
    )
    astral_target = graceful_stop.decode_post_enrollment_graceful_stop_target(
        canonical_first_enrollment_json_bytes(target_payload)
    )
    decision_payload = graceful_stop.build_post_enrollment_graceful_stop_decision(
        operation_id=STOP_OPERATION_ID,
        target=target,
    ).payload()
    decision_payload["graceful_stop_target"] = astral_target.payload()
    decision_payload["graceful_stop_target_sha256"] = astral_target.target_sha256
    decision = graceful_stop.decode_post_enrollment_graceful_stop_decision(
        canonical_first_enrollment_json_bytes(decision_payload)
    )

    assert len(endpoint) == 4_096
    assert len(astral_target.encoded) > 16 * 1_024
    assert len(astral_target.encoded) <= (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_TARGET_MAXIMUM_BYTES
    )
    assert len(decision.encoded) > 16 * 1_024
    assert len(decision.encoded) <= (
        graceful_stop.POST_ENROLLMENT_GRACEFUL_STOP_DECISION_MAXIMUM_BYTES
    )
    assert (
        cast(
            dict[str, object],
            decision.target.durable_shutdown_locator.persistent_topology["daemon_identity"],
        )["endpoint"]
        == endpoint
    )


def test_nested_payloads_are_isolated_and_object_tamper_is_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    decision = graceful_stop.build_post_enrollment_graceful_stop_decision(
        operation_id=STOP_OPERATION_ID,
        target=target,
    )
    target_encoded = target.encoded
    decision_encoded = decision.encoded

    target_payload = target.payload()
    cast(dict[str, object], target_payload["durable_shutdown_locator"])["status"] = "mutated"
    decision_payload = decision.payload()
    cast(dict[str, object], decision_payload["graceful_stop_target"])["status"] = "mutated"

    assert target.encoded == target_encoded
    assert decision.encoded == decision_encoded
    object.__setattr__(target, "start_approval_sha256", "0" * 64)
    with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
        target.payload()
    object.__setattr__(decision, "operation_id", "423e4567-e89b-42d3-a456-426614174003")
    with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
        decision.payload()


def test_direct_construction_copy_replace_and_pickle_are_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = _target(monkeypatch, tmp_path)
    decision = graceful_stop.build_post_enrollment_graceful_stop_decision(
        operation_id=STOP_OPERATION_ID,
        target=target,
    )
    with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
        graceful_stop.TrustedTimePostEnrollmentGracefulStopTarget(
            start_operation_id=target.start_operation_id,
            start_approval_sha256=target.start_approval_sha256,
            controller_outcome_contract_version=target.controller_outcome_contract_version,
            controller_outcome_status=target.controller_outcome_status,
            controller_outcome_reason=target.controller_outcome_reason,
            controller_outcome_sha256=target.controller_outcome_sha256,
            start_execution_attempt_slot_sha256=target.start_execution_attempt_slot_sha256,
            start_operator_attestation_envelope_sha256=(
                target.start_operator_attestation_envelope_sha256
            ),
            durable_shutdown_locator_sha256=target.durable_shutdown_locator_sha256,
            durable_shutdown_locator_encoded=(
                shutdown_locator.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(
                    target.durable_shutdown_locator
                )
            ),
            _construction_capability=object(),
        )
    with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
        graceful_stop.TrustedTimePostEnrollmentGracefulStopDecision(
            operation_id=STOP_OPERATION_ID,
            target_encoded=target.encoded,
            _construction_capability=object(),
        )

    for projection in (target, decision):
        for operation in (
            lambda projection=projection: copy.copy(projection),
            lambda projection=projection: copy.deepcopy(projection),
            lambda projection=projection: pickle.dumps(projection),
        ):
            with pytest.raises(graceful_stop.TrustedTimePostEnrollmentGracefulStopRejected):
                operation()
        with pytest.raises(TypeError):
            replace(projection)


def test_module_has_no_effecting_import_or_entrypoint_surface() -> None:
    source = Path(graceful_stop.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = {
        node.names[0].name.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import) and node.names
    } | {
        node.module.partition(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert imported_roots.isdisjoint(
        {
            "asyncio",
            "docker",
            "httpx",
            "os",
            "pathlib",
            "psycopg",
            "requests",
            "socket",
            "sqlalchemy",
            "subprocess",
            "time",
        }
    )
    assert "if __name__" not in source
    assert "def main(" not in source
    assert "key_id" not in source
