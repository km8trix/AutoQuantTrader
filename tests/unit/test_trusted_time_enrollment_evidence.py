from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION,
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION,
    FIRST_ENROLLMENT_HOST_SERVICE,
    FIRST_ENROLLMENT_IDENTITY_FIELDS,
    FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION,
    FIRST_ENROLLMENT_OUTCOME_GATES,
    FIRST_ENROLLMENT_RUNTIME_SERVICE,
    POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION,
    TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
    TrustedTimeEnrollmentEvidenceError,
    TrustedTimeImmutableLaunchEvidence,
    build_post_enrollment_start_review,
    canonical_first_enrollment_json_bytes,
    decode_confirmed_first_enrollment,
)
from scripts.trusted_time_post_enrollment_evidence import (
    TrustedTimeRetainedEnrollmentEvidenceError,
    load_confirmed_first_enrollment_evidence,
)

OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000"
SECRET_CANARY = "post-enrollment-secret-canary"


def _approval_payload() -> dict[str, object]:
    return {
        "anchor_authority_sha256": "3" * 64,
        "anchor_project_identity_sha256": "6" * 64,
        "approved_git_revision": "a" * 40,
        "approved_image_admission_sha256": "b" * 64,
        "approved_source_image_id": "sha256:" + "1" * 64,
        "approved_supervisor_image_id": "sha256:" + "2" * 64,
        "bucket_identity_sha256": "c" * 64,
        "contract_version": FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION,
        "deployment_identity_sha256": "4" * 64,
        "host_identity_sha256": "a" * 64,
        "operation_id": OPERATION_ID,
        "operation_mode": "new",
        "prior_new_claim_sha256": None,
        "prior_new_operation_id": None,
        "principal_identity_sha256": "b" * 64,
        "runtime_database_identity_sha256": "5" * 64,
        "signing_public_key_sha256": "8" * 64,
        "source_authority_sha256": "7" * 64,
        "unenrolled_admission_sha256": "9" * 64,
    }


def _claim_payload(approval: dict[str, object] | None = None) -> dict[str, object]:
    approval = _approval_payload() if approval is None else approval
    payload = dict(approval)
    payload.update({field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS})
    payload.update(
        {
            "approval_sha256": hashlib.sha256(
                canonical_first_enrollment_json_bytes(approval)
            ).hexdigest(),
            "authority_granted": False,
            "claim_contract_version": FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION,
            "service": FIRST_ENROLLMENT_HOST_SERVICE,
            "status": "claimed",
        }
    )
    return payload


def _terminal_payload(approval: dict[str, object] | None = None) -> dict[str, object]:
    approval = _approval_payload() if approval is None else approval
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update(
        {field_name: approval[field_name] for field_name in FIRST_ENROLLMENT_IDENTITY_FIELDS}
    )
    payload.update(
        {
            "anchor_intent_semantic_sha256": "0" * 64,
            "anchor_sequence": 1,
            "candidate_remote_readback_sha256": "d" * 64,
            "checkpoint_reason": "enrollment",
            "completion_disposition": "new_intent_completed",
            "contract_version": TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION,
            "current_anchor_semantic_sha256": "e" * 64,
            "current_anchor_sha256": "d" * 64,
            "current_host_head_sha256": "f" * 64,
            "database_secret_disclosed": False,
            "full_audit_completed": True,
            "idempotent_duplicate_count": 0,
            "operation_mode": "new",
            "pending_intent_recovered": False,
            "reason": "first_enrollment_confirmed",
            "receipt_semantic_sha256": "9" * 64,
            "remote_namespace_sha256": "8" * 64,
            "service": FIRST_ENROLLMENT_RUNTIME_SERVICE,
            "status": "confirmed",
            "uploaded_anchor_count": 1,
        }
    )
    return payload


def _outcome_payload(
    *,
    approval: dict[str, object] | None = None,
    claim_encoded: bytes,
) -> dict[str, object]:
    approval = _approval_payload() if approval is None else approval
    payload: dict[str, object] = {
        field_name: False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS
    }
    payload.update(
        {
            "approval": dict(approval),
            "approval_sha256": hashlib.sha256(
                canonical_first_enrollment_json_bytes(approval)
            ).hexdigest(),
            "authority_granted": False,
            "claim_sha256": hashlib.sha256(claim_encoded).hexdigest(),
            "contract_version": FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION,
            "database_secret_disclosed": False,
            "gates": {gate_name: True for gate_name in FIRST_ENROLLMENT_OUTCOME_GATES},
            "reason": "first_enrollment_confirmed",
            "runtime_terminal": _terminal_payload(approval),
            "service": FIRST_ENROLLMENT_HOST_SERVICE,
            "status": "confirmed",
        }
    )
    return payload


def _encoded_evidence() -> tuple[bytes, bytes]:
    claim = canonical_first_enrollment_json_bytes(_claim_payload())
    outcome = canonical_first_enrollment_json_bytes(_outcome_payload(claim_encoded=claim))
    return claim, outcome


def _decode(claim: bytes, outcome: bytes):  # type: ignore[no-untyped-def]
    return decode_confirmed_first_enrollment(
        claim_encoded=claim,
        outcome_encoded=outcome,
        expected_operation_id=OPERATION_ID,
        expected_claim_sha256=hashlib.sha256(claim).hexdigest(),
        expected_outcome_sha256=hashlib.sha256(outcome).hexdigest(),
    )


def _reencode(payload: dict[str, object]) -> bytes:
    return canonical_first_enrollment_json_bytes(payload)


def test_exact_new_claim_and_confirmed_outcome_decode_to_closed_typed_evidence() -> None:
    claim, outcome = _encoded_evidence()

    evidence = _decode(claim, outcome)

    assert evidence.operation_id == OPERATION_ID
    assert evidence.claim_sha256 == hashlib.sha256(claim).hexdigest()
    assert evidence.outcome_sha256 == hashlib.sha256(outcome).hexdigest()
    assert evidence.enrollment_launch.git_revision == "a" * 40
    assert evidence.sequence_one.payload()["anchor_sequence"] == 1
    assert evidence.sequence_one.remote_namespace_sha256 == "8" * 64
    assert len(evidence.evidence_sha256) == 64
    assert set(evidence.identities.payload()) == FIRST_ENROLLMENT_IDENTITY_FIELDS
    assert SECRET_CANARY.encode() not in canonical_first_enrollment_json_bytes(evidence.payload())


def test_literal_v1_wire_hashes_and_contract_names_remain_backward_compatible() -> None:
    claim, outcome = _encoded_evidence()

    assert TRUSTED_TIME_FIRST_ENROLLMENT_CONTRACT_VERSION == (
        "phase6d-one-shot-trusted-time-first-enrollment-v1"
    )
    assert FIRST_ENROLLMENT_APPROVAL_CONTRACT_VERSION == (
        "phase6d-first-enrollment-exact-operation-approval-v2"
    )
    assert FIRST_ENROLLMENT_CLAIM_CONTRACT_VERSION == (
        "phase6d-first-enrollment-single-use-claim-v2"
    )
    assert FIRST_ENROLLMENT_OUTCOME_CONTRACT_VERSION == ("phase6d-first-enrollment-host-outcome-v1")
    assert FIRST_ENROLLMENT_HOST_SERVICE == "trusted-time-first-enrollment-host-launcher"
    assert FIRST_ENROLLMENT_RUNTIME_SERVICE == "trusted-time-first-enrollment"
    assert hashlib.sha256(claim).hexdigest() == (
        "2fd08f5fe4a503567e97fce9b45a289c84be062b3246014b91d4e73ceff24131"
    )
    assert hashlib.sha256(outcome).hexdigest() == (
        "d2c1bc3678904c688bd423f9c606f19e6064745f38fdb6c15b57b56be26f3334"
    )
    assert _decode(claim, outcome).operation_id == OPERATION_ID


def test_sequence_one_evidence_rejects_adversarial_string_subclass() -> None:
    class _ForgedDisposition(str):
        def __eq__(self, _: object) -> bool:
            return True

        def __ne__(self, _: object) -> bool:
            return False

    claim, outcome = _encoded_evidence()
    confirmed = _decode(claim, outcome)

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        replace(
            confirmed.sequence_one,
            completion_disposition=_ForgedDisposition("forged"),
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra_field=False),
        lambda value: value.update(claim_contract_version="wrong"),
        lambda value: value.update(approval_sha256="0" * 64),
        lambda value: value.update(authority_granted=True),
        lambda value: value.update(readiness_authorized=True),
        lambda value: value.update(operation_mode="recover_pending"),
        lambda value: value.update(prior_new_claim_sha256="0" * 64),
        lambda value: value.update(approved_source_image_id=value["approved_supervisor_image_id"]),
    ],
)
def test_claim_rejects_every_authority_contract_and_approval_ambiguity(mutate: object) -> None:
    claim_payload = _claim_payload()
    mutate(claim_payload)  # type: ignore[operator]
    claim = _reencode(claim_payload)
    original_claim, original_outcome = _encoded_evidence()
    assert original_claim != claim

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        _decode(claim, original_outcome)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra_field=False),
        lambda value: value.update(contract_version="wrong"),
        lambda value: value.update(approval_sha256="0" * 64),
        lambda value: value.update(claim_sha256="0" * 64),
        lambda value: value.update(authority_granted=True),
        lambda value: value.update(database_secret_disclosed=True),
        lambda value: value.update(status="fatal"),
        lambda value: value.update(reason="first_enrollment_recovery_required"),
        lambda value: value.update(readiness_authorized=True),
        lambda value: value["gates"].update(topology_removed=False),
        lambda value: value["gates"].update(extra_gate=True),
        lambda value: value["approval"].update(anchor_authority_sha256="0" * 64),
        lambda value: value["runtime_terminal"].update(anchor_authority_sha256="0" * 64),
        lambda value: value["runtime_terminal"].update(anchor_sequence=True),
        lambda value: value["runtime_terminal"].update(anchor_sequence=2),
        lambda value: value["runtime_terminal"].update(checkpoint_reason="periodic"),
        lambda value: value["runtime_terminal"].update(
            completion_disposition="pending_intent_recovered"
        ),
        lambda value: value["runtime_terminal"].update(full_audit_completed=False),
        lambda value: value["runtime_terminal"].update(pending_intent_recovered=True),
        lambda value: value["runtime_terminal"].update(uploaded_anchor_count=2),
        lambda value: value["runtime_terminal"].update(uploaded_anchor_count=True),
        lambda value: value["runtime_terminal"].update(idempotent_duplicate_count=True),
        lambda value: value["runtime_terminal"].update(database_secret_disclosed=True),
        lambda value: value["runtime_terminal"].update(readiness_authorized=True),
        lambda value: value["runtime_terminal"].update(remote_namespace_sha256=None),
        lambda value: value["runtime_terminal"].update(candidate_remote_readback_sha256="1" * 64),
    ],
)
def test_outcome_rejects_nonconfirmed_mismatched_or_authorizing_evidence(mutate: object) -> None:
    claim, _ = _encoded_evidence()
    outcome_payload = _outcome_payload(claim_encoded=claim)
    mutate(outcome_payload)  # type: ignore[operator]
    outcome = _reencode(outcome_payload)

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        _decode(claim, outcome)


@pytest.mark.parametrize("kind", ["claim", "outcome"])
def test_duplicate_json_keys_are_rejected_at_every_artifact_boundary(kind: str) -> None:
    claim, outcome = _encoded_evidence()
    if kind == "claim":
        claim = b'{"alert_delivery_authorized":false,' + claim[1:]
    else:
        outcome = b'{"alert_delivery_authorized":false,' + outcome[1:]

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        _decode(claim, outcome)


@pytest.mark.parametrize(
    "transform",
    [
        lambda value: value.rstrip(b"\n"),
        lambda value: value.replace(b":false", b": false", 1),
        lambda value: value + b"\n",
    ],
)
def test_noncanonical_claim_bytes_are_rejected(transform: object) -> None:
    claim, outcome = _encoded_evidence()
    changed = transform(claim)  # type: ignore[operator]

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        _decode(changed, outcome)


@pytest.mark.parametrize(
    "transform",
    [
        lambda value: value.rstrip(b"\n"),
        lambda value: value.replace(b":false", b": false", 1),
        lambda value: value + b"\n",
    ],
)
def test_noncanonical_outcome_bytes_are_rejected(transform: object) -> None:
    claim, outcome = _encoded_evidence()
    changed = transform(outcome)  # type: ignore[operator]

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        _decode(claim, changed)


def test_expected_public_bindings_are_checked_before_any_semantic_success() -> None:
    claim, outcome = _encoded_evidence()
    kwargs = {
        "claim_encoded": claim,
        "outcome_encoded": outcome,
        "expected_operation_id": OPERATION_ID,
        "expected_claim_sha256": hashlib.sha256(claim).hexdigest(),
        "expected_outcome_sha256": hashlib.sha256(outcome).hexdigest(),
    }
    for field_name, changed in (
        ("expected_operation_id", "223e4567-e89b-42d3-a456-426614174001"),
        ("expected_claim_sha256", "0" * 64),
        ("expected_outcome_sha256", "0" * 64),
    ):
        changed_kwargs = dict(kwargs)
        changed_kwargs[field_name] = changed
        with pytest.raises(TrustedTimeEnrollmentEvidenceError):
            decode_confirmed_first_enrollment(**changed_kwargs)  # type: ignore[arg-type]


def test_errors_never_echo_rejected_evidence_values() -> None:
    claim_payload = _claim_payload()
    claim_payload["operation_id"] = SECRET_CANARY
    claim = _reencode(claim_payload)
    _, outcome = _encoded_evidence()

    with pytest.raises(TrustedTimeEnrollmentEvidenceError) as captured:
        _decode(claim, outcome)

    assert SECRET_CANARY not in str(captured.value)


def test_review_projection_separates_historical_enrollment_from_new_target() -> None:
    claim, outcome = _encoded_evidence()
    confirmed = _decode(claim, outcome)
    proposed = TrustedTimeImmutableLaunchEvidence(
        git_revision="f" * 40,
        image_admission_sha256="e" * 64,
        source_image_id="sha256:" + "4" * 64,
        supervisor_image_id="sha256:" + "5" * 64,
    )

    review = build_post_enrollment_start_review(
        confirmed_enrollment=confirmed,
        proposed_launch=proposed,
    )
    payload = review.payload()

    assert payload["contract_version"] == POST_ENROLLMENT_START_REVIEW_CONTRACT_VERSION
    assert payload["status"] == "review_required"
    assert payload["persistent_start_authorized"] is False
    assert payload["sequence_2_authorized"] is False
    assert payload["shutdown_authorized"] is False
    assert all(payload[field_name] is False for field_name in FIRST_ENROLLMENT_AUTHORITY_FIELDS)
    assert payload["confirmed_enrollment"]["enrollment_launch"] != payload["proposed_launch"]  # type: ignore[index]
    assert len(review.projection_sha256) == 64


def test_review_projection_rejects_historical_enrollment_as_proposed_target() -> None:
    claim, outcome = _encoded_evidence()
    confirmed = _decode(claim, outcome)

    with pytest.raises(
        TrustedTimeEnrollmentEvidenceError,
        match="post-enrollment start review is invalid",
    ):
        build_post_enrollment_start_review(
            confirmed_enrollment=confirmed,
            proposed_launch=confirmed.enrollment_launch,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "git_revision",
        "image_admission_sha256",
        "source_image_id",
        "supervisor_image_id",
    ],
)
def test_review_projection_requires_every_proposed_launch_component_to_be_new(
    field_name: str,
) -> None:
    claim, outcome = _encoded_evidence()
    confirmed = _decode(claim, outcome)
    proposed = TrustedTimeImmutableLaunchEvidence(
        git_revision="f" * 40,
        image_admission_sha256="e" * 64,
        source_image_id="sha256:" + "4" * 64,
        supervisor_image_id="sha256:" + "5" * 64,
    )
    proposed = replace(
        proposed,
        **{field_name: getattr(confirmed.enrollment_launch, field_name)},
    )

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        build_post_enrollment_start_review(
            confirmed_enrollment=confirmed,
            proposed_launch=proposed,
        )


def _write_retained_pair(directory: Path) -> tuple[bytes, bytes, str, str]:
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)
    claim, outcome = _encoded_evidence()
    claim_sha256 = hashlib.sha256(claim).hexdigest()
    outcome_sha256 = hashlib.sha256(outcome).hexdigest()
    claim_path = directory / f"trusted-time-first-enrollment-claim-{OPERATION_ID}.json"
    outcome_path = directory / f"trusted-time-first-enrollment-outcome-{outcome_sha256}.json"
    claim_path.write_bytes(claim)
    outcome_path.write_bytes(outcome)
    claim_path.chmod(0o600)
    outcome_path.chmod(0o600)
    return claim, outcome, claim_sha256, outcome_sha256


def test_owner_only_loader_requires_one_exact_pair_and_allows_unrelated_artifacts(
    tmp_path: Path,
) -> None:
    artifact_directory = tmp_path / "trusted-time"
    _, _, claim_sha256, outcome_sha256 = _write_retained_pair(artifact_directory)
    unrelated = artifact_directory / "trusted-time-unenrolled-launch-admission-example.json"
    unrelated.write_bytes(b"unrelated\n")
    unrelated.chmod(0o600)

    evidence = load_confirmed_first_enrollment_evidence(
        operation_id=OPERATION_ID,
        claim_sha256=claim_sha256,
        outcome_sha256=outcome_sha256,
        artifact_directory=artifact_directory,
    )

    assert evidence.operation_id == OPERATION_ID
    assert evidence.claim_sha256 == claim_sha256
    assert evidence.outcome_sha256 == outcome_sha256


@pytest.mark.parametrize("extra_kind", ["claim", "outcome"])
def test_owner_only_loader_rejects_ambiguous_enrollment_inventory(
    tmp_path: Path,
    extra_kind: str,
) -> None:
    artifact_directory = tmp_path / "trusted-time"
    _, _, claim_sha256, outcome_sha256 = _write_retained_pair(artifact_directory)
    extra_name = (
        "trusted-time-first-enrollment-claim-223e4567-e89b-42d3-a456-426614174001.json"
        if extra_kind == "claim"
        else f"trusted-time-first-enrollment-outcome-{'0' * 64}.json"
    )
    extra = artifact_directory / extra_name
    extra.write_bytes(b"{}\n")
    extra.chmod(0o600)

    with pytest.raises(
        TrustedTimeRetainedEnrollmentEvidenceError,
        match="inventory is ambiguous",
    ):
        load_confirmed_first_enrollment_evidence(
            operation_id=OPERATION_ID,
            claim_sha256=claim_sha256,
            outcome_sha256=outcome_sha256,
            artifact_directory=artifact_directory,
        )


def test_owner_only_loader_bounds_inventory_before_materializing_all_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_directory = tmp_path / "trusted-time"
    _, _, claim_sha256, outcome_sha256 = _write_retained_pair(artifact_directory)
    observed_entries = 0

    class _Entry:
        name = "unrelated"

    class _Iterator:
        def __enter__(self) -> _Iterator:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def __iter__(self) -> _Iterator:
            return self

        def __next__(self) -> _Entry:
            nonlocal observed_entries
            observed_entries += 1
            if observed_entries > 4_098:
                raise AssertionError("inventory iteration was not bounded")
            return _Entry()

    monkeypatch.setattr(os, "scandir", lambda _: _Iterator())

    with pytest.raises(
        TrustedTimeRetainedEnrollmentEvidenceError,
        match="inventory is invalid",
    ):
        load_confirmed_first_enrollment_evidence(
            operation_id=OPERATION_ID,
            claim_sha256=claim_sha256,
            outcome_sha256=outcome_sha256,
            artifact_directory=artifact_directory,
        )

    assert observed_entries == 4_097


@pytest.mark.parametrize("mode", [0o400, 0o640])
def test_owner_only_loader_requires_exact_0600_artifacts(tmp_path: Path, mode: int) -> None:
    artifact_directory = tmp_path / "trusted-time"
    _, _, claim_sha256, outcome_sha256 = _write_retained_pair(artifact_directory)
    claim_path = artifact_directory / f"trusted-time-first-enrollment-claim-{OPERATION_ID}.json"
    claim_path.chmod(mode)

    with pytest.raises(TrustedTimeRetainedEnrollmentEvidenceError):
        load_confirmed_first_enrollment_evidence(
            operation_id=OPERATION_ID,
            claim_sha256=claim_sha256,
            outcome_sha256=outcome_sha256,
            artifact_directory=artifact_directory,
        )


def test_owner_only_loader_rejects_hard_linked_or_symlinked_claims(tmp_path: Path) -> None:
    for kind in ("hardlink", "symlink"):
        artifact_directory = tmp_path / kind / "trusted-time"
        _, _, claim_sha256, outcome_sha256 = _write_retained_pair(artifact_directory)
        claim_path = artifact_directory / f"trusted-time-first-enrollment-claim-{OPERATION_ID}.json"
        if kind == "hardlink":
            os.link(claim_path, artifact_directory / "unrelated-alias.json")
        else:
            original = artifact_directory / "claim-source.json"
            claim_path.rename(original)
            claim_path.symlink_to(original)

        with pytest.raises(TrustedTimeRetainedEnrollmentEvidenceError):
            load_confirmed_first_enrollment_evidence(
                operation_id=OPERATION_ID,
                claim_sha256=claim_sha256,
                outcome_sha256=outcome_sha256,
                artifact_directory=artifact_directory,
            )


def test_owner_only_loader_rejects_noncanonical_or_non_owner_only_directory(
    tmp_path: Path,
) -> None:
    artifact_directory = tmp_path / "trusted-time"
    _, _, claim_sha256, outcome_sha256 = _write_retained_pair(artifact_directory)
    artifact_directory.chmod(0o755)

    with pytest.raises(TrustedTimeRetainedEnrollmentEvidenceError):
        load_confirmed_first_enrollment_evidence(
            operation_id=OPERATION_ID,
            claim_sha256=claim_sha256,
            outcome_sha256=outcome_sha256,
            artifact_directory=artifact_directory,
        )
    with pytest.raises(TrustedTimeRetainedEnrollmentEvidenceError):
        load_confirmed_first_enrollment_evidence(
            operation_id=OPERATION_ID,
            claim_sha256=claim_sha256,
            outcome_sha256=outcome_sha256,
            artifact_directory=Path("relative/trusted-time"),
        )


def test_mutating_copies_cannot_change_already_decoded_evidence() -> None:
    claim, outcome = _encoded_evidence()
    outcome_payload = json.loads(outcome)
    mutable_copy = copy.deepcopy(outcome_payload)
    evidence = _decode(claim, outcome)

    mutable_copy["runtime_terminal"]["anchor_sequence"] = 2

    assert evidence.sequence_one.payload()["anchor_sequence"] == 1
    assert evidence.sequence_one.remote_namespace_sha256 == "8" * 64


def test_launch_evidence_rejects_equal_image_ids_and_nonexact_types() -> None:
    valid = TrustedTimeImmutableLaunchEvidence(
        git_revision="a" * 40,
        image_admission_sha256="b" * 64,
        source_image_id="sha256:" + "1" * 64,
        supervisor_image_id="sha256:" + "2" * 64,
    )

    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        replace(valid, supervisor_image_id=valid.source_image_id)
    with pytest.raises(TrustedTimeEnrollmentEvidenceError):
        replace(valid, git_revision=True)  # type: ignore[arg-type]
