from __future__ import annotations

import ast
import dis
import fcntl
import hashlib
import inspect
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.trusted_time_post_enrollment_active_controller_admission as admission_module
import scripts.trusted_time_post_enrollment_controller_outcome as controller_outcome
import scripts.trusted_time_post_enrollment_outcome as recovery_outcome
import scripts.trusted_time_post_enrollment_shutdown_locator as shutdown_locator
import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from scripts.trusted_time_post_enrollment_start import (
    RetainedTrustedTimePostEnrollmentStartClaim,
)
from tests.unit import test_trusted_time_post_enrollment_active_controller_admission as admission_fx
from tests.unit import test_trusted_time_post_enrollment_claimed_fence as claimed_fx
from tests.unit import test_trusted_time_post_enrollment_persistent_topology as persistent_fx


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


def _admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[
    claimed_fx._Context,
    object,
    object,
    admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
    RetainedTrustedTimePostEnrollmentStartClaim,
]:
    context, lease, recovery, action_fence = admission_fx._action_context(
        monkeypatch,
        tmp_path,
    )
    admission = admission_module.prepare_post_enrollment_start_active_controller_admission(
        **admission_fx._admission_kwargs(context, lease, recovery, action_fence)
    )
    retained = action_fence._claimed_fence._handoff.retained_claim
    return context, lease, recovery, admission, retained


def _release_unconfirmed_evidence(
    admission: admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
    *,
    pre_effect_observation_sha256: str = "e" * 64,
) -> controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence:
    return controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ),
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
        ),
        pre_effect_observation_sha256=pre_effect_observation_sha256,
        verifier_binding_sha256="f" * 64,
        read_only_configuration_sha256="0" * 64,
        verification_transcript_sha256=None,
        release_execution_sha256=None,
        runtime_state_sha256=None,
        successor=None,
        persistent_topology=None,
        persistent_topology_transcript_sha256=None,
    )


def _confirmed_evidence(
    inputs: dict[str, object],
    persistent_topology: object,
) -> controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence:
    return controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=cast(
            admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
            inputs["admission"],
        ),
        status=controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED,
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=cast(Any, persistent_topology),
        persistent_topology_transcript_sha256="d" * 64,
    )


def _publish_controller_outcome_payload(
    *,
    artifact_directory: Path,
    payload: dict[str, object],
    contract_version: str,
) -> tuple[str, Path, Path]:
    encoded = canonical_first_enrollment_json_bytes(payload)
    digest = hashlib.sha256(encoded).hexdigest()
    artifact_path = artifact_directory / controller_outcome._outcome_file_name(digest)
    slot_path = (
        artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    )
    commit_path = (
        artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    )
    for path, content in (
        (artifact_path, encoded),
        (
            slot_path,
            controller_outcome._slot_bytes(
                digest,
                contract_version=contract_version,
            ),
        ),
        (
            commit_path,
            controller_outcome._commit_bytes(
                digest,
                contract_version=contract_version,
            ),
        ),
    ):
        path.write_bytes(content)
        path.chmod(0o600)
    return digest, slot_path, commit_path


def _publish_failure_controller_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> claimed_fx._Context:
    context, _, _, admission, _ = _admission(monkeypatch, tmp_path)
    evidence = _release_unconfirmed_evidence(admission)
    _publish_controller_outcome_payload(
        artifact_directory=context.artifact_directory,
        payload=evidence.payload(),
        contract_version=(
            controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
        ),
    )
    return context


def _install_retention(
    monkeypatch: pytest.MonkeyPatch,
    *,
    retained: RetainedTrustedTimePostEnrollmentStartClaim,
    artifact_directory: Path,
    ignored_root: Path,
    expected_outcome_kind: str = "failure",
) -> tuple[object, list[object]]:
    capability = object()
    completed: list[object] = []

    def begin(
        _issuer: object,
        candidate: object,
        choreography_lease: object,
        retained_claim: object,
        *,
        outcome_kind: str,
        artifact_directory: Path,
        ignored_root: Path,
    ) -> reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint:
        assert choreography_lease is not None
        assert candidate is capability
        assert retained_claim is retained
        assert outcome_kind == expected_outcome_kind
        assert artifact_directory == retained.artifact_path.parent
        assert ignored_root == artifact_directory.parent
        return reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint(
            retained_claim=retained,
            outcome_kind=cast(Any, expected_outcome_kind),
            artifact_directory=artifact_directory,
            ignored_root=ignored_root,
            started_monotonic_ns=1,
            action_deadline_monotonic_ns=300_000_000_001,
            deadline_monotonic_ns=(
                300_000_000_001 if expected_outcome_kind == "success" else 305_000_000_001
            ),
            observed_monotonic_ns=2,
        )

    def complete(
        _issuer: object,
        candidate: object,
        checkpoint: object,
        receipt: object,
    ) -> None:
        assert candidate is capability
        assert type(checkpoint) is (
            reader._TrustedTimePostEnrollmentControllerOutcomeRetentionCheckpoint
        )
        completed.append(receipt)

    def abandon(
        _issuer: object,
        candidate: object,
        checkpoint: object,
        receipt: object | None,
    ) -> None:
        assert candidate is capability
        completed.append(("abandoned", checkpoint, receipt))

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_begin_post_effect_controller_outcome_retention",
        begin,
        raising=False,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_complete_post_effect_controller_outcome_retention",
        complete,
        raising=False,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_abandon_post_effect_controller_outcome_retention",
        abandon,
        raising=False,
    )
    return capability, completed


def test_retains_one_truthful_post_effect_failure_in_the_global_outcome_slot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = _release_unconfirmed_evidence(admission)

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert completed == [receipt]
    assert receipt.status is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
    )
    assert receipt.reason is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED
    )
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        receipt,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert json.loads(receipt.encoded) == evidence.payload()
    assert receipt.outcome_sha256 == hashlib.sha256(receipt.encoded).hexdigest()
    assert receipt.artifact_path.read_bytes() == receipt.encoded
    assert receipt.contract_version == (
        controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
    )
    assert receipt.durable_shutdown_locator is None
    assert receipt.durable_shutdown_locator_sha256 is None
    assert receipt.durable_shutdown_locator_available is False
    slot = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    )
    assert slot.read_bytes() == controller_outcome._slot_bytes(receipt.outcome_sha256)


def test_retains_and_reloads_one_fully_bound_confirmed_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
    origin = next(
        candidate
        for candidate in admission_fx._registry_state()[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
        expected_outcome_kind="success",
    )
    persistent_topology = persistent_fx._validate(inputs)
    evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED,
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=persistent_topology,
        persistent_topology_transcript_sha256="d" * 64,
    )

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert completed == [receipt]
    assert loaded == receipt
    payload = json.loads(loaded.encoded)
    assert payload["controller_execution_confirmed"] is True
    assert payload["pre_effect_observation_sha256"] == "a" * 64
    assert payload["persistent_topology_transcript_sha256"] == "d" * 64
    assert payload["success_outcome_retained"] is True
    locator_payload = cast(dict[str, object], payload["durable_shutdown_locator"])
    assert locator_payload["persistent_topology"] == persistent_topology.payload()
    assert loaded.durable_shutdown_locator is not None
    assert loaded.durable_shutdown_locator.payload() == locator_payload
    assert payload["durable_shutdown_locator_sha256"] == (
        shutdown_locator.post_enrollment_graceful_stop_shutdown_locator_sha256(
            loaded.durable_shutdown_locator
        )
    )
    assert loaded.durable_shutdown_locator_sha256 == payload["durable_shutdown_locator_sha256"]
    assert loaded.durable_shutdown_locator_available is True


def test_loads_historical_v1_confirmed_outcome_with_exact_markers_without_locator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    evidence = _confirmed_evidence(inputs, persistent_fx._validate(inputs))
    payload = evidence.payload()
    del payload["durable_shutdown_locator"]
    del payload["durable_shutdown_locator_sha256"]
    payload["contract_version"] = (
        controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
    )
    digest, slot_path, commit_path = _publish_controller_outcome_payload(
        artifact_directory=context.artifact_directory,
        payload=payload,
        contract_version=(
            controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
        ),
    )

    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert loaded.contract_version == (
        controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
    )
    assert loaded.status is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
    )
    assert loaded.durable_shutdown_locator is None
    assert loaded.durable_shutdown_locator_sha256 is None
    assert loaded.durable_shutdown_locator_available is False
    assert slot_path.read_bytes() == controller_outcome._slot_bytes(
        digest,
        contract_version=(
            controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
        ),
    )
    assert commit_path.read_bytes() == controller_outcome._commit_bytes(
        digest,
        contract_version=(
            controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_V1_CONTRACT_VERSION
        ),
    )
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        loaded,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    commit_path.write_bytes(controller_outcome._commit_bytes(digest))
    commit_path.chmod(0o600)
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome.load_retained_post_enrollment_start_controller_outcome(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )


def test_private_controller_outcome_snapshot_is_deeply_immutable_and_forgery_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    _, snapshot = (
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )

    def drift_identity(identity: tuple[int, ...]) -> tuple[int, ...]:
        return (identity[0], identity[1] + 1, *identity[2:])

    semantic = cast(
        tuple[object, ...],
        controller_outcome._snapshot_slot(snapshot, 8),
    )
    forged_semantic = (
        *semantic[:4],
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        *semantic[4 + 1 :],
    )
    replacements: tuple[tuple[int, object], ...] = (
        (
            1,
            cast(
                str,
                controller_outcome._snapshot_slot(
                    snapshot,
                    1,
                ),
            )
            + "-other",
        ),
        (
            2,
            cast(
                str,
                controller_outcome._snapshot_slot(
                    snapshot,
                    2,
                ),
            )
            + "-other",
        ),
        (
            3,
            drift_identity(
                cast(
                    tuple[int, ...],
                    controller_outcome._snapshot_slot(
                        snapshot,
                        3,
                    ),
                )
            ),
        ),
        (4, False),
        (5, ("other.json",)),
        (
            6,
            cast(
                str,
                controller_outcome._snapshot_slot(
                    snapshot,
                    6,
                ),
            )
            + ".other",
        ),
        (
            7,
            cast(
                bytes,
                controller_outcome._snapshot_slot(
                    snapshot,
                    7,
                ),
            )
            + b" ",
        ),
        (8, forged_semantic),
        (
            9,
            drift_identity(
                cast(
                    tuple[int, ...],
                    controller_outcome._snapshot_slot(
                        snapshot,
                        9,
                    ),
                )
            ),
        ),
        (
            10,
            cast(
                bytes,
                controller_outcome._snapshot_slot(
                    snapshot,
                    10,
                ),
            )
            + b" ",
        ),
        (
            11,
            drift_identity(
                cast(
                    tuple[int, ...],
                    controller_outcome._snapshot_slot(
                        snapshot,
                        11,
                    ),
                )
            ),
        ),
        (
            12,
            cast(
                bytes,
                controller_outcome._snapshot_slot(
                    snapshot,
                    12,
                ),
            )
            + b" ",
        ),
        (
            13,
            drift_identity(
                cast(
                    tuple[int, ...],
                    controller_outcome._snapshot_slot(
                        snapshot,
                        13,
                    ),
                )
            ),
        ),
    )
    for index, replacement in replacements:
        forged = (*snapshot[:index], replacement, *snapshot[index + 1 :])
        assert not (
            controller_outcome._revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
                forged,
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
        )

    for forged in (
        ("wrong-controller-outcome-snapshot-tag", *snapshot[1:]),
        snapshot[:-1],
    ):
        assert not (
            controller_outcome._revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
                forged,
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
        )

    assert type(snapshot) is tuple
    assert not hasattr(snapshot, "_fields")

    class HeapTuple(tuple[object, ...]):
        pass

    assert not (
        controller_outcome._revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
            HeapTuple(snapshot),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )


def test_private_controller_outcome_snapshot_uses_literal_tuple_slots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    _, snapshot = (
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )
    expected = controller_outcome._snapshot_outcome_projection(snapshot)

    index_names = tuple(
        name
        for name in vars(controller_outcome)
        if name.startswith(("_SEMANTIC_", "_SNAPSHOT_"))
        and type(getattr(controller_outcome, name)) is int
    )
    assert not index_names

    assert controller_outcome._snapshot_outcome_projection(snapshot) == expected
    assert (
        controller_outcome._revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
            snapshot,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )


def test_private_controller_outcome_snapshot_rejects_post_build_object_relabel(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    loaded, snapshot = (
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )

    object.__setattr__(loaded, "outcome_sha256", "f" * 64)

    assert not controller_outcome._retained_outcome_matches_snapshot(loaded, snapshot)
    assert not controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        loaded,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert (
        controller_outcome._revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
            snapshot,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )


def test_private_controller_outcome_snapshot_does_not_consult_public_view_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)

    def forbidden_public_comparison(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("private snapshot loader consulted the public retained view")

    monkeypatch.setattr(
        controller_outcome,
        "_retained_outcome_matches_snapshot",
        forbidden_public_comparison,
    )

    loaded, snapshot = (
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )

    assert (
        type(loaded) is controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome
    )
    assert controller_outcome._snapshot_outcome_projection(snapshot)


@pytest.mark.parametrize(
    "mutation",
    ["outcome", "slot", "commit", "staging", "inventory", "directory"],
)
def test_private_controller_outcome_snapshot_rejects_every_final_reread_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    real_receipt_from_encoded = controller_outcome._receipt_from_encoded

    def mutate_after_construction(
        *,
        encoded: bytes,
        artifact_path: Path,
        file_identity: tuple[int, ...],
        slot_file_identity: tuple[int, ...],
        commit_file_identity: tuple[int, ...],
    ) -> controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        loaded = real_receipt_from_encoded(
            encoded=encoded,
            artifact_path=artifact_path,
            file_identity=file_identity,
            slot_file_identity=slot_file_identity,
            commit_file_identity=commit_file_identity,
        )
        slot_path = (
            context.artifact_directory
            / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
        )
        commit_path = (
            context.artifact_directory
            / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
        )
        if mutation == "outcome":
            artifact_path.write_bytes(b" " + encoded[1:])
            artifact_path.chmod(0o600)
        elif mutation == "slot":
            slot_path.write_bytes(slot_path.read_bytes() + b" ")
            slot_path.chmod(0o600)
        elif mutation == "commit":
            commit_path.write_bytes(commit_path.read_bytes() + b" ")
            commit_path.chmod(0o600)
        elif mutation == "staging":
            staging_name = ".post-enrollment-start-controller-outcome-commit-staging"
            staging = context.artifact_directory / staging_name
            staging.write_bytes(b"staging")
            staging.chmod(0o600)
        elif mutation == "inventory":
            extra = context.artifact_directory / controller_outcome._outcome_file_name("f" * 64)
            extra.write_bytes(b"{}\n")
            extra.chmod(0o600)
        else:
            drift = context.artifact_directory / "unreviewed-directory-entry"
            drift.write_bytes(b"drift")
            drift.chmod(0o600)
        return loaded

    monkeypatch.setattr(
        controller_outcome,
        "_receipt_from_encoded",
        mutate_after_construction,
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize(
    "boundary",
    ["raw_read", "decode", "post_init", "final_reread", "fresh_reload"],
)
def test_private_controller_outcome_snapshot_preserves_async_interruption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interruption: type[BaseException],
    boundary: str,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    _, snapshot = (
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    )

    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise interruption

    if boundary == "raw_read":
        monkeypatch.setattr(
            controller_outcome,
            "_native_read_retained_outcome",
            interrupt,
        )
    elif boundary == "decode":
        monkeypatch.setattr(
            controller_outcome,
            "_validate_encoded_payload_projection",
            interrupt,
        )
    elif boundary == "post_init":
        monkeypatch.setattr(
            controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome,
            "__post_init__",
            interrupt,
        )
    elif boundary == "final_reread":
        original_read = controller_outcome._native_read_retained_outcome
        read_count = 0

        def interrupt_final_reread(*args: object, **kwargs: object) -> object:
            nonlocal read_count
            read_count += 1
            if read_count == 4:
                raise interruption
            return original_read(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(
            controller_outcome,
            "_native_read_retained_outcome",
            interrupt_final_reread,
        )
    else:
        monkeypatch.setattr(
            controller_outcome,
            "_load_retained_post_enrollment_start_controller_outcome_with_snapshot",
            interrupt,
        )

    with pytest.raises(interruption):
        if boundary == "fresh_reload":
            controller_outcome._revalidate_retained_post_enrollment_start_controller_outcome_snapshot(
                snapshot,
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
        else:
            controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )


def _interrupt_native_snapshot_instruction(
    target: Any,
    instruction_offset: int,
    action: Any,
    *,
    exception_type: type[BaseException],
) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == instruction_offset:
            raise exception_type

    sys.monitoring.use_tool_id(tool_id, "controller-outcome-native-cleanup-interrupt")
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


def _capture_native_snapshot_instruction_offsets(
    target: Any,
    action: Any,
) -> tuple[int, ...]:
    observed: list[int] = []
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def capture(_: object, offset: int) -> None:
        observed.append(offset)

    sys.monitoring.use_tool_id(tool_id, "controller-outcome-native-cleanup-capture")
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        capture,
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


def _native_cleanup_instruction_offsets(target: Any) -> tuple[int, ...]:
    instructions = tuple(dis.get_instructions(target))
    offsets: list[int] = []
    for index, instruction in enumerate(instructions):
        if instruction.argval != "_cleanup_native_owners":
            continue
        for candidate in instructions[index:]:
            offsets.append(candidate.offset)
            if candidate.opname == "STORE_FAST":
                break
    return tuple(dict.fromkeys(offsets))


def test_private_snapshot_native_reachability_has_no_raw_or_live_owner_handoff() -> None:
    for opener in (
        controller_outcome._native_open_root_directory,
        controller_outcome._native_open_child_directory,
        controller_outcome._native_open_child_regular,
    ):
        assert not hasattr(opener, "__code__")
    assert not hasattr(controller_outcome._NativeOwnedFileDescriptor, "fileno")

    source = "\n".join(
        (
            inspect.getsource(
                controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot
            ),
            inspect.getsource(controller_outcome._native_read_retained_outcome),
            inspect.getsource(controller_outcome._native_inventory_snapshot),
            inspect.getsource(controller_outcome._native_entry_is_absent),
        )
    )
    called_names = {
        node.func.id
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert called_names.isdisjoint(
        {
            "_open_owner_only_artifact_directory",
            "_locked_outcome_slot",
            "_read_retained_outcome",
            "_outcome_names",
        }
    )
    for forbidden in (
        ".fileno()",
        "os.open(",
        "os.close(",
        "os.read(",
        "os.fstat(",
        "os.stat(",
        "fcntl.flock(",
    ):
        assert forbidden not in source
    assert "_held_outcome_slot_process_lock" in source
    assert "_native_open_root_directory()" in source
    assert "_native_open_child_directory(" in source
    assert "_native_open_child_regular(" in source


def test_private_snapshot_native_owner_cleanup_opcode_sweeps(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    opened: list[Any] = []

    def capture_open(original: Any) -> Any:
        def open_and_capture(*args: object, **kwargs: object) -> object:
            owner = original(*args, **kwargs)
            opened.append(owner)
            return owner

        return open_and_capture

    monkeypatch.setattr(
        controller_outcome,
        "_native_open_root_directory",
        capture_open(controller_outcome._native_open_root_directory),
    )
    monkeypatch.setattr(
        controller_outcome,
        "_native_open_child_directory",
        capture_open(controller_outcome._native_open_child_directory),
    )
    monkeypatch.setattr(
        controller_outcome,
        "_native_open_child_regular",
        capture_open(controller_outcome._native_open_child_regular),
    )

    def action() -> object:
        loader = (
            controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot
        )
        return loader(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    for target in (
        controller_outcome._native_read_retained_outcome,
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot,
    ):
        executed = frozenset(_capture_native_snapshot_instruction_offsets(target, action))
        offsets = tuple(
            offset for offset in _native_cleanup_instruction_offsets(target) if offset in executed
        )
        assert offsets
        assert opened
        assert all(owner.closed for owner in opened)
        for exception_type in (KeyboardInterrupt, SystemExit):
            for offset in offsets:
                opened.clear()
                with pytest.raises(exception_type):
                    _interrupt_native_snapshot_instruction(
                        target,
                        offset,
                        action,
                        exception_type=exception_type,
                    )
                assert opened
                assert all(owner.closed for owner in opened)
                action()
                assert all(owner.closed for owner in opened)


def test_private_snapshot_native_slot_lock_contention_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    slot = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    )
    with slot.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
        ):
            controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )


@pytest.mark.parametrize(
    "mutation",
    ["outcome_mode", "outcome_hardlink", "slot_symlink", "commit_directory", "directory_mode"],
)
def test_private_snapshot_native_path_type_mode_and_link_attacks_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    context = _publish_failure_controller_outcome(monkeypatch, tmp_path)
    outcome = next(
        context.artifact_directory.glob(
            f"{controller_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"
            f"{controller_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX}"
        )
    )
    slot = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    )
    commit = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    )
    if mutation == "outcome_mode":
        outcome.chmod(0o400)
    elif mutation == "outcome_hardlink":
        alias = context.artifact_directory / "outcome-hardlink"
        alias.hardlink_to(outcome)
    elif mutation == "slot_symlink":
        slot.unlink()
        slot.symlink_to(outcome.name)
    elif mutation == "commit_directory":
        commit.unlink()
        commit.mkdir(mode=0o700)
    else:
        context.artifact_directory.chmod(0o755)

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome._load_retained_post_enrollment_start_controller_outcome_with_snapshot(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )


def test_v2_projection_rejects_a_rehashed_locator_not_bound_to_outer_topology(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    payload = deepcopy(_confirmed_evidence(inputs, persistent_fx._validate(inputs)).payload())
    locator_payload = cast(dict[str, object], payload["durable_shutdown_locator"])
    locator_payload["persistent_topology_transcript_sha256"] = "8" * 64
    payload["durable_shutdown_locator_sha256"] = hashlib.sha256(
        canonical_first_enrollment_json_bytes(locator_payload)
    ).hexdigest()

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome._validate_payload_projection(payload)


@pytest.mark.parametrize(
    "category",
    [
        "outer_authority",
        "outer_closed",
        "service",
        "confirmation",
        "qualification",
        "locator_authority",
        "topology_authority",
    ],
)
def test_encoded_controller_projection_cannot_be_healed_through_a_mutable_validator(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    category: str,
) -> None:
    inputs, _ = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    valid = deepcopy(_confirmed_evidence(inputs, persistent_fx._validate(inputs)).payload())
    invalid = deepcopy(valid)
    locator_payload = cast(dict[str, object], invalid["durable_shutdown_locator"])
    topology_payload = cast(dict[str, object], locator_payload["persistent_topology"])
    if category == "outer_authority":
        invalid["authority_granted"] = True
    elif category == "outer_closed":
        invalid["controller_execution_authorized"] = True
    elif category == "service":
        invalid["service"] = "unreviewed-service"
    elif category == "confirmation":
        invalid["controller_execution_confirmed"] = False
    elif category == "qualification":
        invalid["qualified"] = False
    elif category == "locator_authority":
        locator_payload["shutdown_authorized"] = True
    else:
        topology_payload["authority_granted"] = True
        topology_sha256 = hashlib.sha256(
            canonical_first_enrollment_json_bytes(topology_payload)
        ).hexdigest()
        locator_payload["persistent_topology_sha256"] = topology_sha256
        invalid["persistent_topology_sha256"] = topology_sha256
    invalid["durable_shutdown_locator_sha256"] = hashlib.sha256(
        canonical_first_enrollment_json_bytes(locator_payload)
    ).hexdigest()
    invalid_encoded = canonical_first_enrollment_json_bytes(invalid)
    valid_copy = deepcopy(valid)
    real_mutable_validator = controller_outcome._validate_payload_projection

    def heal_mutable_projection(payload: object) -> object:
        if type(payload) is dict:
            payload.clear()
            payload.update(deepcopy(valid_copy))
        return real_mutable_validator(payload)

    monkeypatch.setattr(
        controller_outcome,
        "_validate_payload_projection",
        heal_mutable_projection,
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome._validate_encoded_payload_projection(invalid_encoded)
    digest = hashlib.sha256(invalid_encoded).hexdigest()
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome._receipt_from_encoded(
            encoded=invalid_encoded,
            artifact_path=Path("/tmp") / controller_outcome._outcome_file_name(digest),
            file_identity=(0,) * 9,
            slot_file_identity=(0,) * 9,
            commit_file_identity=(0,) * 9,
        )


@pytest.mark.parametrize(
    ("reason", "baseline_updates", "one_sided_update"),
    [
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED,
            {},
            {"runtime_state_sha256": "1" * 64},
        ),
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED,
            {},
            {"successor_candidate_sha256": "2" * 64},
        ),
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED,
            {
                "reason": (
                    controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED.value
                ),
                "release_confirmed": True,
                "release_execution_sha256": "3" * 64,
            },
            {"successor_candidate_sha256": "4" * 64},
        ),
    ],
    ids=["release-runtime-only", "release-successor-only", "sequence-successor-only"],
)
def test_encoded_controller_projection_rejects_one_sided_sequence_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reason: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason,
    baseline_updates: dict[str, object],
    one_sided_update: dict[str, object],
) -> None:
    _, _, _, admission, _ = _admission(monkeypatch, tmp_path)
    payload = _release_unconfirmed_evidence(admission).payload()
    payload.update(baseline_updates)
    payload.update(one_sided_update)
    assert payload["reason"] == reason.value
    encoded = canonical_first_enrollment_json_bytes(payload)

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome._validate_encoded_payload_projection(encoded)


def test_astral_maximum_daemon_endpoint_survives_v2_persist_and_load(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
    origin = next(
        candidate
        for candidate in admission_fx._registry_state()[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    persistent_topology = persistent_fx._validate(inputs)
    endpoint_prefix = "unix:///"
    endpoint = endpoint_prefix + chr(0x1F600) * (4_096 - len(endpoint_prefix))
    assert len(endpoint) == 4_096
    monkeypatch.setattr(type(persistent_topology), "__post_init__", lambda _self: None)
    persistent_topology = replace(persistent_topology, daemon_endpoint=endpoint)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
        expected_outcome_kind="success",
    )

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=_confirmed_evidence(inputs, persistent_topology),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert len(receipt.encoded) > 32 * 1_024
    assert len(receipt.encoded) < recovery_outcome.MAXIMUM_POST_ENROLLMENT_START_OUTCOME_BYTES
    assert loaded == receipt
    assert loaded.durable_shutdown_locator_available is True
    assert loaded.durable_shutdown_locator is not None
    daemon_identity = cast(
        dict[str, object],
        loaded.durable_shutdown_locator.persistent_topology["daemon_identity"],
    )
    assert daemon_identity["endpoint"] == endpoint
    locator_encoded = (
        shutdown_locator.canonical_post_enrollment_graceful_stop_shutdown_locator_bytes(
            loaded.durable_shutdown_locator
        )
    )
    assert len(locator_encoded) > 16 * 1_024
    assert len(locator_encoded) < (
        shutdown_locator.POST_ENROLLMENT_GRACEFUL_STOP_SHUTDOWN_LOCATOR_MAXIMUM_BYTES
    )


def test_post_effect_failure_payload_is_progress_truthful_and_non_authorizing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, _, _, admission, _ = _admission(monkeypatch, tmp_path)
    evidence = _release_unconfirmed_evidence(admission)
    payload = evidence.payload()

    assert payload["release_attempted"] is True
    assert payload["release_confirmed"] is False
    assert payload["sequence_2_confirmed"] is False
    assert payload["topology_qualified"] is False
    assert payload["success_outcome_retained"] is False
    assert payload["controller_execution_confirmed"] is False
    for field in controller_outcome._CLOSED_FIELDS:
        assert payload[field] is False


def test_success_retention_failure_preserves_only_completed_runtime_facts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, _ = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ),
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=persistent_fx._validate(inputs),
        persistent_topology_transcript_sha256="d" * 64,
    )

    payload = evidence.payload()

    assert payload["release_confirmed"] is True
    assert payload["sequence_2_confirmed"] is True
    assert payload["runtime_start_confirmed"] is True
    assert payload["topology_qualified"] is True
    assert payload["persistent_start_confirmed"] is True
    assert payload["controller_execution_confirmed"] is False
    assert payload["success_outcome_retained"] is False
    assert payload["qualified"] is False
    assert payload["durable_shutdown_locator"] is not None
    assert payload["durable_shutdown_locator_sha256"] is not None


def test_retains_and_reloads_success_outcome_unconfirmed_as_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
    admission = cast(
        admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
        inputs["admission"],
    )
    retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
    origin = next(
        candidate
        for candidate in admission_fx._registry_state()[1].values()
        if cast(tuple[object, ...], candidate)[0] is admission
    )
    lease = cast(tuple[object, ...], origin)[2]
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
        admission=admission,
        status=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
        ),
        reason=(
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
        ),
        pre_effect_observation_sha256="a" * 64,
        verifier_binding_sha256="e" * 64,
        read_only_configuration_sha256="f" * 64,
        verification_transcript_sha256="9" * 64,
        release_execution_sha256="b" * 64,
        runtime_state_sha256="c" * 64,
        successor=cast(Any, inputs["successor"]),
        persistent_topology=persistent_fx._validate(inputs),
        persistent_topology_transcript_sha256="d" * 64,
    )

    receipt = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert completed == [receipt]
    assert loaded == receipt
    assert loaded.reason is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SUCCESS_OUTCOME_UNCONFIRMED
    )
    payload = json.loads(loaded.encoded)
    assert payload["sequence_2_confirmed"] is True
    assert payload["topology_qualified"] is True
    assert payload["controller_execution_confirmed"] is False
    assert payload["verification_transcript_sha256"] == "9" * 64
    assert loaded.durable_shutdown_locator is not None
    assert loaded.durable_shutdown_locator_sha256 == payload["durable_shutdown_locator_sha256"]
    assert loaded.durable_shutdown_locator_available is True


@pytest.mark.parametrize(
    ("reason", "release_sha256", "runtime_sha256"),
    [
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.RELEASE_OUTCOME_UNCONFIRMED,
            "1" * 64,
            None,
        ),
        (
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.SEQUENCE_TWO_UNCONFIRMED,
            None,
            None,
        ),
    ],
)
def test_rejects_progress_inconsistent_failure_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reason: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason,
    release_sha256: str | None,
    runtime_sha256: str | None,
) -> None:
    _, _, _, admission, _ = _admission(monkeypatch, tmp_path)

    with pytest.raises(controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRejected):
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
            admission=admission,
            status=(
                controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
            ),
            reason=reason,
            pre_effect_observation_sha256="e" * 64,
            verifier_binding_sha256="f" * 64,
            read_only_configuration_sha256="0" * 64,
            verification_transcript_sha256=None,
            release_execution_sha256=release_sha256,
            runtime_state_sha256=runtime_sha256,
            successor=None,
            persistent_topology=None,
            persistent_topology_transcript_sha256=None,
        )


def test_global_outcome_slot_rejects_a_second_controller_disposition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = _release_unconfirmed_evidence(admission)
    first = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=evidence,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert first.artifact_path.exists()

    second_capability, abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=second_capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert len(abandoned) == 1
    assert cast(tuple[object, object, object], abandoned[0])[0] == "abandoned"


def test_fixed_slot_linearizes_two_concurrent_distinct_controller_dispositions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, _, _, admission, retained = _admission(monkeypatch, tmp_path)
    evidence = (
        _release_unconfirmed_evidence(
            admission,
            pre_effect_observation_sha256="a" * 64,
        ),
        _release_unconfirmed_evidence(
            admission,
            pre_effect_observation_sha256="b" * 64,
        ),
    )
    original_outcome_names = controller_outcome._outcome_names
    first_inventory = threading.local()
    both_checked_empty = threading.Barrier(2)

    def synchronized_empty_inventory(directory_descriptor: int) -> frozenset[str]:
        observed = original_outcome_names(directory_descriptor)
        if not getattr(first_inventory, "completed", False):
            first_inventory.completed = True
            assert observed == frozenset()
            both_checked_empty.wait(timeout=5)
        return observed

    monkeypatch.setattr(
        controller_outcome,
        "_outcome_names",
        synchronized_empty_inventory,
    )

    def retain(
        candidate: controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence,
    ) -> object:
        try:
            return controller_outcome._persist(
                candidate,
                retained_claim=retained,
                artifact_directory=context.artifact_directory,
                ignored_root=context.ignored_root,
            )
        except BaseException as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(retain, evidence))
    monkeypatch.setattr(controller_outcome, "_outcome_names", original_outcome_names)

    receipts = tuple(
        result
        for result in results
        if type(result)
        is controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome
    )
    failures = tuple(
        result
        for result in results
        if type(result)
        is controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained
    )
    assert len(receipts) == 1
    assert len(failures) == 1
    outcome_names = frozenset(
        candidate.name
        for candidate in context.artifact_directory.iterdir()
        if candidate.name.startswith(controller_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX)
        and candidate.name.endswith(controller_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_SUFFIX)
    )
    assert outcome_names == frozenset({cast(Any, receipts[0]).artifact_path.name})
    assert controller_outcome._revalidate_prepared_controller_outcome(
        cast(Any, receipts[0]),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )


def test_failed_publication_leaves_one_unreadable_reservation_and_blocks_retry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    evidence = _release_unconfirmed_evidence(admission)
    monkeypatch.setattr(
        controller_outcome.os,
        "link",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("link failed")),
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    staging = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_STAGING_FILE_NAME
    )
    assert staging.is_file()
    assert (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_SLOT_FILE_NAME
    ).is_file()
    assert len(abandoned) == 1

    second_capability, second_abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeAlreadyRetained
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=second_capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert len(second_abandoned) == 1


@pytest.mark.parametrize(
    ("transitioned", "expected_error"),
    [
        (
            True,
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed,
        ),
        (
            False,
            controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeCapabilityUnavailable,
        ),
    ],
)
def test_begin_call_store_ambiguity_falls_back_only_when_transition_never_committed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transitioned: bool,
    expected_error: type[BaseException],
) -> None:
    context, lease, _, admission, _ = _admission(monkeypatch, tmp_path)
    capability = object()
    abandoned: list[tuple[object, object | None]] = []
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_begin_post_effect_controller_outcome_retention",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_post_effect_outcome_retention_was_transitioned",
        lambda _issuer, candidate: candidate is capability and transitioned,
    )
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_abandon_post_effect_controller_outcome_retention",
        lambda _issuer, candidate, checkpoint, receipt=None: abandoned.append(
            (candidate, checkpoint)
        ),
    )

    with pytest.raises(expected_error):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert abandoned == [(capability, None)]


def test_retained_projection_can_be_loaded_without_reconstructing_process_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    original = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=_release_unconfirmed_evidence(admission),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    loaded = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )

    assert loaded == original
    assert loaded._evidence is None
    assert loaded.status is (
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.RECOVERY_REQUIRED
    )


def test_revalidator_rejects_same_bytes_commit_marker_inode_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, _ = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    original = controller_outcome.retain_post_enrollment_start_controller_outcome(
        topology_issuer=context.topology_issuer,
        choreography_lease=lease,
        post_effect_outcome_capability=capability,
        evidence=_release_unconfirmed_evidence(admission),
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    marker = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    )
    encoded = marker.read_bytes()
    original_identity = original.commit_file_identity
    marker.unlink()
    marker.write_bytes(encoded)
    marker.chmod(0o600)

    assert not controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        original,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    reconstructed = controller_outcome.load_retained_post_enrollment_start_controller_outcome(
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert reconstructed.commit_file_identity != original_identity
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        reconstructed,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )


def test_registry_completion_failure_never_publishes_a_committed_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, abandoned = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    prepared: list[controller_outcome.RetainedTrustedTimePostEnrollmentStartControllerOutcome] = []
    real_persist = controller_outcome._persist

    def capture_prepared(*args: object, **kwargs: object) -> object:
        receipt = real_persist(*args, **kwargs)  # type: ignore[arg-type]
        prepared.append(receipt)
        return receipt

    monkeypatch.setattr(controller_outcome, "_persist", capture_prepared)
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_complete_post_effect_controller_outcome_retention",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("injected completion")),
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert len(prepared) == 1
    assert prepared[0].commit_file_identity is None
    assert not controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        prepared[0],
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome.load_retained_post_enrollment_start_controller_outcome(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    assert not (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    ).exists()
    assert len(abandoned) == 1


def test_final_commit_directory_fsync_failure_remains_publicly_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    real_fsync = controller_outcome.os.fsync
    artifact_directory_identity = context.artifact_directory.stat()
    directory_fsync_count = 0

    def fail_final_commit_directory_fsync(descriptor: int) -> None:
        nonlocal directory_fsync_count
        metadata = controller_outcome.os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == (
            artifact_directory_identity.st_dev,
            artifact_directory_identity.st_ino,
        ):
            directory_fsync_count += 1
            if directory_fsync_count == 5:
                raise OSError("injected final commit directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(controller_outcome.os, "fsync", fail_final_commit_directory_fsync)
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome.retain_post_enrollment_start_controller_outcome(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=_release_unconfirmed_evidence(admission),
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    final_marker = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_FILE_NAME
    )
    staging_marker = (
        context.artifact_directory
        / controller_outcome._POST_ENROLLMENT_START_CONTROLLER_OUTCOME_COMMIT_STAGING_FILE_NAME
    )
    assert directory_fsync_count >= 5
    assert final_marker.is_file()
    assert staging_marker.is_file()
    assert final_marker.stat().st_ino == staging_marker.stat().st_ino
    assert final_marker.stat().st_nlink == 2
    assert len(completed) == 2
    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidenceUnavailable
    ):
        controller_outcome.load_retained_post_enrollment_start_controller_outcome(
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )


@pytest.mark.parametrize("outcome_kind", ["success", "failure"])
def test_async_interruption_after_durable_commit_returns_exact_confirmed_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    outcome_kind: str,
) -> None:
    if outcome_kind == "success":
        inputs, context = persistent_fx._valid_inputs(monkeypatch, tmp_path)
        admission = cast(
            admission_module.TrustedTimePostEnrollmentStartActiveControllerAdmission,
            inputs["admission"],
        )
        retained = cast(Any, admission)._action_fence._claimed_fence._handoff.retained_claim
        origin = next(
            candidate
            for candidate in admission_fx._registry_state()[1].values()
            if cast(tuple[object, ...], candidate)[0] is admission
        )
        lease = cast(tuple[object, ...], origin)[2]
        evidence = controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeEvidence(
            admission=admission,
            status=controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED,
            reason=controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeReason.POST_ENROLLMENT_START_CONFIRMED,
            pre_effect_observation_sha256="a" * 64,
            verifier_binding_sha256="e" * 64,
            read_only_configuration_sha256="f" * 64,
            verification_transcript_sha256="9" * 64,
            release_execution_sha256="b" * 64,
            runtime_state_sha256="c" * 64,
            successor=cast(Any, inputs["successor"]),
            persistent_topology=persistent_fx._validate(inputs),
            persistent_topology_transcript_sha256="d" * 64,
        )
    else:
        context, lease, _, admission, retained = _admission(monkeypatch, tmp_path)
        evidence = _release_unconfirmed_evidence(admission)
    capability, completed = _install_retention(
        monkeypatch,
        retained=retained,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
        expected_outcome_kind=outcome_kind,
    )
    retain = controller_outcome.retain_post_enrollment_start_controller_outcome
    instructions = list(dis.get_instructions(retain))
    load_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "LOAD_GLOBAL"
        and instruction.argval == "_commit_prepared_controller_outcome"
    )
    call_index = next(
        index
        for index in range(load_index + 1, len(instructions))
        if instructions[index].opname == "CALL"
    )
    assert instructions[call_index + 1].opname == "POP_TOP"
    target_offset = instructions[call_index + 1].offset
    interrupted = False
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )
    sys.monitoring.use_tool_id(tool_id, "trusted-time-controller-commit-return-test")

    def interrupt_after_commit(code: object, instruction_offset: int) -> None:
        nonlocal interrupted
        if not interrupted and code is retain.__code__ and instruction_offset == target_offset:
            interrupted = True
            raise KeyboardInterrupt

    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt_after_commit,
    )
    sys.monitoring.set_local_events(
        tool_id,
        retain.__code__,
        sys.monitoring.events.INSTRUCTION,
    )
    try:
        receipt = retain(
            topology_issuer=context.topology_issuer,
            choreography_lease=lease,
            post_effect_outcome_capability=capability,
            evidence=evidence,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    finally:
        sys.monitoring.set_local_events(tool_id, retain.__code__, 0)
        sys.monitoring.register_callback(tool_id, sys.monitoring.events.INSTRUCTION, None)
        sys.monitoring.free_tool_id(tool_id)

    assert interrupted is True
    assert completed == [receipt]
    assert receipt.commit_file_identity is not None
    assert controller_outcome.revalidate_retained_post_enrollment_start_controller_outcome(
        receipt,
        artifact_directory=context.artifact_directory,
        ignored_root=context.ignored_root,
    )
    assert receipt.contract_version == (
        controller_outcome.POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION
    )
    if outcome_kind == "success":
        assert receipt.durable_shutdown_locator_available is True
        assert receipt.durable_shutdown_locator is not None
        assert receipt.durable_shutdown_locator_sha256 == (
            shutdown_locator.post_enrollment_graceful_stop_shutdown_locator_sha256(
                receipt.durable_shutdown_locator
            )
        )
    else:
        assert receipt.durable_shutdown_locator_available is False
        assert receipt.durable_shutdown_locator is None
        assert receipt.durable_shutdown_locator_sha256 is None


def test_partial_controller_publication_atomically_blocks_legacy_recovery_writer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context, _, _, admission, retained = _admission(monkeypatch, tmp_path)
    monkeypatch.setattr(
        controller_outcome.os,
        "link",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("injected publication")),
    )

    with pytest.raises(
        controller_outcome.TrustedTimePostEnrollmentStartControllerOutcomeRetentionUnconfirmed
    ):
        controller_outcome._persist(
            _release_unconfirmed_evidence(admission),
            retained_claim=retained,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )
    with pytest.raises(recovery_outcome.TrustedTimePostEnrollmentStartOutcomeAlreadyRetained):
        recovery_outcome._persist_outcome(
            retained_claim=retained,
            artifact_directory=context.artifact_directory,
            ignored_root=context.ignored_root,
        )

    assert (
        context.artifact_directory / recovery_outcome.POST_ENROLLMENT_START_OUTCOME_SLOT_FILE_NAME
    ).is_file()
    assert not tuple(
        context.artifact_directory.glob(
            f"{recovery_outcome.POST_ENROLLMENT_START_OUTCOME_FILE_PREFIX}*"
        )
    )


def test_controller_outcome_module_has_no_cli_or_effecting_import_surface() -> None:
    source = Path(cast(str, controller_outcome.__file__)).read_text(encoding="utf-8")
    assert "def main(" not in source
    assert "if __name__" not in source
    assert "subprocess" not in source
    assert "docker" not in source.lower()
    assert "sqlalchemy" not in source
    assert "alpaca" not in source.lower()
    assert "etrade" not in source.lower()
    assert "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION" in (
        controller_outcome.__all__
    )
