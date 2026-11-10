from __future__ import annotations

import ast
import copy
import dis
import hashlib
import json
import os
import pickle
import stat
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, Never

import pytest

from packages.adapters.trusted_time.ed25519_operator_attestation import (
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    Ed25519PostEnrollmentOperatorAttestationVerifier,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
    EXECUTION_APPROVAL_V2_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
    build_post_enrollment_operator_attestation_statement,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
    canonical_post_enrollment_operator_attestation_statement_bytes,
    decode_post_enrollment_operator_attestation_envelope,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
)
from scripts import trusted_time_post_enrollment_operator_attestation_artifacts as workflow
from scripts.trusted_time_post_enrollment_operator_attestation_artifacts import (
    ARTIFACT_RECEIPT_CONTRACT_VERSION,
    ARTIFACT_WORKFLOW_SERVICE,
    ENVELOPE_CANDIDATE_VERIFIED_STATUS,
    EXECUTION_APPROVAL_V2_VALIDATION_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS,
    STATEMENT_CANDIDATE_PREPARED_STATUS,
    TrustedTimePostEnrollmentOperatorAttestationArtifactError,
    TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt,
    TrustedTimePostEnrollmentOperatorAttestationStatementReceipt,
    main,
    prepare_post_enrollment_operator_attestation_statement_candidate,
    verify_and_retain_post_enrollment_operator_attestation_envelope_candidate,
)

# Public-only fixture derived from RFC 8032 test key 2.  Neither a private seed
# nor a signer/private-key API is present in this workflow test.
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
SIGNATURE = bytes.fromhex(
    "25dbf98a3808469b89e27dbff180780d08cb90ca846619a7f971c9e668ae38be"
    "317522b7fe2e9f29ad9fa5489f68337eb97e2bf6e6f660f6002f7edeaf2f780c"
)
EXECUTION_APPROVAL_V2 = (
    b'{"contract_version":"phase6d-post-enrollment-start-execution-approval-v2",'
    b'"service":"trusted-time-post-enrollment-start-execution-approval",'
    b'"status":"execution_approval_artifact"}\n'
)


def _owner_only_directory(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def _owner_only_file(path: Path, encoded: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(encoded)
    path.chmod(mode)
    return path


class _Artifacts:
    def __init__(self, tmp_path: Path, *, execution_approval_v2: bytes = EXECUTION_APPROVAL_V2):
        self.authority = build_post_enrollment_operator_authority(PUBLIC_KEY)
        self.authority_encoded = canonical_post_enrollment_operator_authority_bytes(self.authority)
        self.authority_sha256 = hashlib.sha256(self.authority_encoded).hexdigest()
        self.public_key_sha256 = hashlib.sha256(PUBLIC_KEY).hexdigest()
        self.execution_approval_v2 = execution_approval_v2
        self.execution_approval_v2_sha256 = hashlib.sha256(execution_approval_v2).hexdigest()
        authority_directory = _owner_only_directory(tmp_path / "authority")
        approval_directory = _owner_only_directory(tmp_path / "approval")
        self.statement_directory = _owner_only_directory(tmp_path / "statements")
        self.signature_directory = _owner_only_directory(tmp_path / "signature")
        self.envelope_directory = _owner_only_directory(tmp_path / "envelopes")
        self.authority_artifact = _owner_only_file(
            authority_directory
            / (f"{workflow.AUTHORITY_CANDIDATE_FILE_PREFIX}{self.authority_sha256}.json"),
            self.authority_encoded,
        )
        self.execution_approval_v2_artifact = _owner_only_file(
            approval_directory
            / (
                f"{workflow.EXECUTION_APPROVAL_V2_FILE_PREFIX}"
                f"{self.execution_approval_v2_sha256}.json"
            ),
            execution_approval_v2,
        )
        self.detached_signature_file = _owner_only_file(
            self.signature_directory / "operator-signature.ed25519",
            SIGNATURE,
        )
        self.signature_sha256 = hashlib.sha256(SIGNATURE).hexdigest()

    def prepare_kwargs(self) -> dict[str, object]:
        return {
            "authority_artifact": self.authority_artifact,
            "execution_approval_v2_artifact": self.execution_approval_v2_artifact,
            "statement_candidate_directory": self.statement_directory,
            "expected_authority_sha256": self.authority_sha256,
            "expected_public_key_sha256": self.public_key_sha256,
            "expected_execution_approval_v2_sha256": self.execution_approval_v2_sha256,
        }

    def prepare(self) -> TrustedTimePostEnrollmentOperatorAttestationStatementReceipt:
        return prepare_post_enrollment_operator_attestation_statement_candidate(
            **self.prepare_kwargs()  # type: ignore[arg-type]
        )

    def verify_kwargs(self) -> dict[str, object]:
        prepared = self.prepare()
        return {
            "authority_artifact": self.authority_artifact,
            "execution_approval_v2_artifact": self.execution_approval_v2_artifact,
            "statement_artifact": self.statement_directory / prepared.artifact_location,
            "detached_signature_file": self.detached_signature_file,
            "envelope_candidate_directory": self.envelope_directory,
            "expected_authority_sha256": self.authority_sha256,
            "expected_public_key_sha256": self.public_key_sha256,
            "expected_execution_approval_v2_sha256": self.execution_approval_v2_sha256,
            "expected_statement_sha256": (prepared.operator_attestation_statement_sha256),
            "expected_signature_sha256": self.signature_sha256,
        }


def _prepared(
    tmp_path: Path,
) -> tuple[
    _Artifacts,
    TrustedTimePostEnrollmentOperatorAttestationStatementReceipt,
    Path,
]:
    artifacts = _Artifacts(tmp_path)
    receipt = artifacts.prepare()
    return artifacts, receipt, artifacts.statement_directory / receipt.artifact_location


def _assert_closed_receipt(payload: dict[str, object]) -> None:
    for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS:
        assert payload[field_name] is False
    assert payload["authority_material_source"] == (
        "explicit_external_adr0100_content_addressed_candidate"
    )
    assert payload["installed_authority_used"] is False
    assert payload["execution_approval_v2_semantically_qualified"] is False
    assert payload["freshness_qualified"] is False
    assert payload["single_use_qualified"] is False
    assert payload["later_atomic_cutover_revalidation_required"] is True
    assert payload["structural_receipt_only"] is True
    assert payload["verification_only"] is True


def test_prepare_retains_exact_content_addressed_statement_and_sealed_receipt(
    tmp_path: Path,
) -> None:
    artifacts, receipt, statement_path = _prepared(tmp_path)
    expected_statement = build_post_enrollment_operator_attestation_statement(
        authority=artifacts.authority,
        execution_approval_v2_sha256=artifacts.execution_approval_v2_sha256,
    )
    expected_encoded = canonical_post_enrollment_operator_attestation_statement_bytes(
        expected_statement
    )
    payload = receipt.public_payload

    assert statement_path.read_bytes() == expected_encoded
    assert stat.S_IMODE(statement_path.stat().st_mode) == 0o600
    assert receipt.status == STATEMENT_CANDIDATE_PREPARED_STATUS
    assert receipt.authority_artifact_sha256 == artifacts.authority_sha256
    assert receipt.public_key_sha256 == artifacts.public_key_sha256
    assert receipt.execution_approval_v2_sha256 == artifacts.execution_approval_v2_sha256
    assert (
        receipt.operator_attestation_statement_sha256
        == hashlib.sha256(expected_encoded).hexdigest()
    )
    assert receipt.artifact_location == (
        f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}"
        f"{receipt.operator_attestation_statement_sha256}.json"
    )
    assert set(payload) == POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS
    assert payload["contract_version"] == ARTIFACT_RECEIPT_CONTRACT_VERSION
    assert payload["service"] == ARTIFACT_WORKFLOW_SERVICE
    assert payload["status"] == STATEMENT_CANDIDATE_PREPARED_STATUS
    assert payload["execution_approval_v2_validation"] == (EXECUTION_APPROVAL_V2_VALIDATION_STATUS)
    _assert_closed_receipt(payload)


def test_verify_authenticates_exact_signature_and_retains_public_v3_candidate(
    tmp_path: Path,
) -> None:
    artifacts = _Artifacts(tmp_path)
    arguments = artifacts.verify_kwargs()

    receipt = verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
        **arguments  # type: ignore[arg-type]
    )

    envelope_path = artifacts.envelope_directory / receipt.artifact_location
    encoded = envelope_path.read_bytes()
    envelope = decode_post_enrollment_operator_attestation_envelope(encoded)
    result = Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(
        artifacts.authority
    ).verify(envelope)
    payload = receipt.public_payload
    assert canonical_post_enrollment_operator_attestation_envelope_bytes(envelope) == encoded
    assert stat.S_IMODE(envelope_path.stat().st_mode) == 0o600
    assert receipt.status == ENVELOPE_CANDIDATE_VERIFIED_STATUS
    assert receipt.detached_signature_sha256 == artifacts.signature_sha256
    assert receipt.operator_attestation_envelope_sha256 == hashlib.sha256(encoded).hexdigest()
    assert receipt.artifact_location == (
        f"{workflow.ENVELOPE_CANDIDATE_FILE_PREFIX}"
        f"{receipt.operator_attestation_envelope_sha256}.json"
    )
    assert result.operator_attestation_envelope_sha256 == (
        receipt.operator_attestation_envelope_sha256
    )
    assert set(payload) == POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_RECEIPT_FIELDS
    assert payload["status"] == ENVELOPE_CANDIDATE_VERIFIED_STATUS
    _assert_closed_receipt(payload)


def test_both_publications_are_exactly_idempotent_without_inode_replacement(
    tmp_path: Path,
) -> None:
    artifacts = _Artifacts(tmp_path)
    first_statement = artifacts.prepare()
    statement_path = artifacts.statement_directory / first_statement.artifact_location
    statement_inode = statement_path.stat().st_ino
    second_statement = artifacts.prepare()
    assert second_statement.public_payload == first_statement.public_payload
    assert statement_path.stat().st_ino == statement_inode

    verify_arguments = artifacts.verify_kwargs()
    first_envelope = verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
        **verify_arguments  # type: ignore[arg-type]
    )
    envelope_path = artifacts.envelope_directory / first_envelope.artifact_location
    envelope_inode = envelope_path.stat().st_ino
    second_envelope = verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
        **verify_arguments  # type: ignore[arg-type]
    )
    assert second_envelope.public_payload == first_envelope.public_payload
    assert envelope_path.stat().st_ino == envelope_inode


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    [
        ("expected_authority_sha256", "expected_authority_sha256_invalid"),
        ("expected_public_key_sha256", "expected_public_key_sha256_invalid"),
        (
            "expected_execution_approval_v2_sha256",
            "expected_execution_approval_v2_sha256_invalid",
        ),
    ],
)
@pytest.mark.parametrize("invalid", [None, b"0" * 64, "A" * 64, "0" * 63, "0" * 65])
def test_prepare_rejects_every_malformed_expected_digest(
    tmp_path: Path,
    field_name: str,
    reason_code: str,
    invalid: object,
) -> None:
    arguments = _Artifacts(tmp_path).prepare_kwargs()
    arguments[field_name] = invalid

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        prepare_post_enrollment_operator_attestation_statement_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    [
        ("expected_statement_sha256", "expected_statement_sha256_invalid"),
        ("expected_signature_sha256", "expected_signature_sha256_invalid"),
    ],
)
def test_verify_rejects_malformed_phase_two_expected_digests(
    tmp_path: Path,
    field_name: str,
    reason_code: str,
) -> None:
    arguments = _Artifacts(tmp_path).verify_kwargs()
    arguments[field_name] = "F" * 64

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == reason_code


@pytest.mark.parametrize(
    ("field_name", "reason_code"),
    [
        ("expected_authority_sha256", "authority_artifact_differs_from_review"),
        ("expected_public_key_sha256", "public_key_differs_from_review"),
        (
            "expected_execution_approval_v2_sha256",
            "execution_approval_v2_artifact_differs_from_review",
        ),
    ],
)
def test_prepare_rejects_well_formed_but_wrong_reviewed_identity(
    tmp_path: Path,
    field_name: str,
    reason_code: str,
) -> None:
    arguments = _Artifacts(tmp_path).prepare_kwargs()
    arguments[field_name] = "0" * 64

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        prepare_post_enrollment_operator_attestation_statement_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == reason_code


def test_verify_rejects_wrong_reviewed_statement_and_signature_identities(
    tmp_path: Path,
) -> None:
    artifacts = _Artifacts(tmp_path)
    for field_name, reason_code in (
        ("expected_statement_sha256", "statement_artifact_differs_from_review"),
        ("expected_signature_sha256", "detached_signature_differs_from_review"),
    ):
        arguments = artifacts.verify_kwargs()
        arguments[field_name] = "0" * 64
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
            verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
                **arguments  # type: ignore[arg-type]
            )
        assert captured.value.reason_code == reason_code


def _replace_v2(artifacts: _Artifacts, encoded: bytes, *, file_name: str | None = None) -> None:
    digest = hashlib.sha256(encoded).hexdigest()
    path = artifacts.execution_approval_v2_artifact.parent / (
        file_name
        if file_name is not None
        else f"{workflow.EXECUTION_APPROVAL_V2_FILE_PREFIX}{digest}.json"
    )
    _owner_only_file(path, encoded)
    artifacts.execution_approval_v2 = encoded
    artifacts.execution_approval_v2_sha256 = digest
    artifacts.execution_approval_v2_artifact = path


@pytest.mark.parametrize(
    "encoded",
    [
        EXECUTION_APPROVAL_V2.rstrip(b"\n"),
        b" " + EXECUTION_APPROVAL_V2,
        (
            b'{"contract_version":"phase6d-post-enrollment-start-execution-approval-v2",'
            b'"contract_version":"phase6d-post-enrollment-start-execution-approval-v2",'
            b'"service":"trusted-time-post-enrollment-start-execution-approval",'
            b'"status":"execution_approval_artifact"}\n'
        ),
        canonical_first_enrollment_json_bytes([]),
        canonical_first_enrollment_json_bytes(
            {
                "contract_version": "wrong",
                "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
                "status": EXECUTION_APPROVAL_V2_STATUS,
            }
        ),
        canonical_first_enrollment_json_bytes(
            {
                "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
                "service": "wrong",
                "status": EXECUTION_APPROVAL_V2_STATUS,
            }
        ),
        canonical_first_enrollment_json_bytes(
            {
                "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
                "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
                "status": "wrong",
            }
        ),
        (
            b'{"contract_version":"phase6d-post-enrollment-start-execution-approval-v2",'
            b'"opaque":NaN,"service":"trusted-time-post-enrollment-start-execution-approval",'
            b'"status":"execution_approval_artifact"}\n'
        ),
        b"\xff\n",
    ],
)
def test_prepare_rejects_noncanonical_duplicate_or_wrong_identity_v2(
    tmp_path: Path,
    encoded: bytes,
) -> None:
    artifacts = _Artifacts(tmp_path)
    _replace_v2(artifacts, encoded)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == "execution_approval_v2_artifact_invalid"
    assert not any(artifacts.statement_directory.iterdir())


def test_prepare_accepts_opaque_structural_v2_but_receipt_is_explicitly_unqualified(
    tmp_path: Path,
) -> None:
    encoded = canonical_first_enrollment_json_bytes(
        {
            "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
            "opaque_unvalidated_semantics": {
                "authority_granted": True,
                "unknown": [None, 7, "content"],
            },
            "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
            "status": EXECUTION_APPROVAL_V2_STATUS,
        }
    )
    artifacts = _Artifacts(tmp_path, execution_approval_v2=encoded)

    receipt = artifacts.prepare()

    assert receipt.public_payload["execution_approval_v2_validation"] == (
        "canonical_top_level_identity_only_semantics_unqualified"
    )
    assert receipt.public_payload["execution_approval_v2_semantically_qualified"] is False
    assert receipt.public_payload["authority_granted"] is False


def test_prepare_rejects_oversized_v2_before_publication(tmp_path: Path) -> None:
    artifacts = _Artifacts(tmp_path)
    encoded = b"{" + b" " * 65_536
    _replace_v2(artifacts, encoded)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == "execution_approval_v2_artifact_unavailable"
    assert not any(artifacts.statement_directory.iterdir())


@pytest.mark.parametrize("artifact_name", ["authority", "execution_approval_v2"])
def test_prepare_rejects_non_content_addressed_input_name(
    tmp_path: Path,
    artifact_name: str,
) -> None:
    artifacts = _Artifacts(tmp_path)
    attribute = f"{artifact_name}_artifact"
    source = getattr(artifacts, attribute)
    renamed = source.with_name(f"reviewed-{artifact_name}.json")
    source.rename(renamed)
    setattr(artifacts, attribute, renamed)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == (
        "authority_artifact_differs_from_review"
        if artifact_name == "authority"
        else "execution_approval_v2_artifact_differs_from_review"
    )


def test_prepare_rejects_invalid_canonical_authority_candidate(tmp_path: Path) -> None:
    artifacts = _Artifacts(tmp_path)
    encoded = b"{}\n"
    digest = hashlib.sha256(encoded).hexdigest()
    path = artifacts.authority_artifact.parent / (
        f"{workflow.AUTHORITY_CANDIDATE_FILE_PREFIX}{digest}.json"
    )
    _owner_only_file(path, encoded)
    artifacts.authority_artifact = path
    artifacts.authority_sha256 = digest

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == "authority_artifact_invalid"


@pytest.mark.parametrize("size", [0, 1, 63, 65, 1024])
def test_verify_requires_exact_raw_64_byte_signature(tmp_path: Path, size: int) -> None:
    artifacts = _Artifacts(tmp_path)
    arguments = artifacts.verify_kwargs()
    signature = b"s" * size
    artifacts.detached_signature_file.write_bytes(signature)
    artifacts.detached_signature_file.chmod(0o600)
    arguments["expected_signature_sha256"] = hashlib.sha256(signature).hexdigest()

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == "detached_signature_unavailable"
    assert not any(artifacts.envelope_directory.iterdir())


def test_verify_rejects_cryptographically_invalid_exact_64_byte_signature(
    tmp_path: Path,
) -> None:
    artifacts = _Artifacts(tmp_path)
    arguments = artifacts.verify_kwargs()
    invalid_signature = bytes(range(64))
    artifacts.detached_signature_file.write_bytes(invalid_signature)
    artifacts.detached_signature_file.chmod(0o600)
    arguments["expected_signature_sha256"] = hashlib.sha256(invalid_signature).hexdigest()

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == "operator_attestation_signature_verification_failed"
    assert not any(artifacts.envelope_directory.iterdir())


@pytest.mark.parametrize("canonical", [False, True])
def test_verify_rejects_statement_not_exactly_rebuilt_from_authority_and_v2(
    tmp_path: Path,
    canonical: bool,
) -> None:
    artifacts, receipt, statement_path = _prepared(tmp_path)
    if canonical:
        payload = json.loads(statement_path.read_text(encoding="ascii"))
        payload["public_key_sha256"] = "0" * 64
        encoded = canonical_first_enrollment_json_bytes(payload)
        reason_code = "statement_artifact_differs_from_review"
    else:
        encoded = statement_path.read_bytes().rstrip(b"\n")
        reason_code = "statement_artifact_invalid"
    digest = hashlib.sha256(encoded).hexdigest()
    changed = statement_path.with_name(f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{digest}.json")
    _owner_only_file(changed, encoded)
    arguments = {
        "authority_artifact": artifacts.authority_artifact,
        "execution_approval_v2_artifact": artifacts.execution_approval_v2_artifact,
        "statement_artifact": changed,
        "detached_signature_file": artifacts.detached_signature_file,
        "envelope_candidate_directory": artifacts.envelope_directory,
        "expected_authority_sha256": artifacts.authority_sha256,
        "expected_public_key_sha256": artifacts.public_key_sha256,
        "expected_execution_approval_v2_sha256": artifacts.execution_approval_v2_sha256,
        "expected_statement_sha256": digest,
        "expected_signature_sha256": artifacts.signature_sha256,
    }

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert receipt.operator_attestation_statement_sha256 != digest
    assert captured.value.reason_code == reason_code
    assert not any(artifacts.envelope_directory.iterdir())


@pytest.mark.parametrize("input_name", ["authority_artifact", "execution_approval_v2_artifact"])
@pytest.mark.parametrize("mode", [0o000, 0o440, 0o644])
def test_prepare_rejects_input_not_exact_owner_only_mode(
    tmp_path: Path,
    input_name: str,
    mode: int,
) -> None:
    artifacts = _Artifacts(tmp_path)
    getattr(artifacts, input_name).chmod(mode)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == f"{input_name}_unavailable"


@pytest.mark.parametrize("input_name", ["statement_artifact", "detached_signature_file"])
def test_verify_rejects_phase_two_input_not_owner_only(
    tmp_path: Path,
    input_name: str,
) -> None:
    artifacts = _Artifacts(tmp_path)
    arguments = artifacts.verify_kwargs()
    path = arguments[input_name]
    assert isinstance(path, Path)
    path.chmod(0o644)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
            **arguments  # type: ignore[arg-type]
        )

    phase = "statement_artifact" if input_name == "statement_artifact" else "detached_signature"
    assert captured.value.reason_code == f"{phase}_unavailable"


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_prepare_rejects_linked_input_artifacts(tmp_path: Path, kind: str) -> None:
    artifacts = _Artifacts(tmp_path)
    original = artifacts.authority_artifact.with_name("authority-original.json")
    artifacts.authority_artifact.rename(original)
    if kind == "symlink":
        artifacts.authority_artifact.symlink_to(original)
    else:
        os.link(original, artifacts.authority_artifact)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == "authority_artifact_unavailable"


@pytest.mark.parametrize("path_value", [Path("relative.json"), "absolute-string.json", None])
def test_prepare_rejects_non_absolute_or_mistyped_path(
    tmp_path: Path,
    path_value: object,
) -> None:
    arguments = _Artifacts(tmp_path).prepare_kwargs()
    arguments["authority_artifact"] = path_value

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        prepare_post_enrollment_operator_attestation_statement_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == "authority_artifact_path_invalid"


@pytest.mark.parametrize("directory_name", ["authority", "approval", "statements"])
def test_prepare_rejects_non_owner_only_external_directory(
    tmp_path: Path,
    directory_name: str,
) -> None:
    artifacts = _Artifacts(tmp_path)
    path = {
        "authority": artifacts.authority_artifact.parent,
        "approval": artifacts.execution_approval_v2_artifact.parent,
        "statements": artifacts.statement_directory,
    }[directory_name]
    path.chmod(0o755)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code in {
        "authority_artifact_unavailable",
        "execution_approval_v2_artifact_unavailable",
        "statement_candidate_directory_unavailable",
    }


def test_prepare_rejects_external_path_that_traverses_repository(tmp_path: Path) -> None:
    arguments = _Artifacts(tmp_path).prepare_kwargs()
    arguments["authority_artifact"] = Path(__file__).resolve()

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        prepare_post_enrollment_operator_attestation_statement_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == "authority_artifact_unavailable"


@pytest.mark.parametrize("phase", ["authority_artifact", "execution_approval_v2_artifact"])
def test_prepare_revalidates_every_input_before_creating_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    artifacts = _Artifacts(tmp_path)
    original = workflow._revalidate_external_binding
    replaced = False

    def replace_at_revalidation(binding: workflow._ExternalFileBinding) -> None:
        nonlocal replaced
        if workflow._external_file_phase(binding) == phase and not replaced:
            replaced = True
            binding_path = Path(workflow._external_file_path(binding))
            old_path = binding_path.with_name(f"old-{binding_path.name}")
            binding_path.rename(old_path)
            _owner_only_file(binding_path, workflow._external_file_encoded(binding))
        original(binding)

    monkeypatch.setattr(workflow, "_revalidate_external_binding", replace_at_revalidation)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()

    assert captured.value.reason_code == f"{phase}_path_revalidation_failed"
    assert not any(artifacts.statement_directory.iterdir())


@pytest.mark.parametrize(
    "phase",
    [
        "authority_artifact",
        "execution_approval_v2_artifact",
        "statement_artifact",
        "detached_signature",
    ],
)
def test_verify_revalidates_every_input_before_creating_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    artifacts = _Artifacts(tmp_path)
    arguments = artifacts.verify_kwargs()
    original = workflow._revalidate_external_binding
    replaced = False

    def replace_at_revalidation(binding: workflow._ExternalFileBinding) -> None:
        nonlocal replaced
        if workflow._external_file_phase(binding) == phase and not replaced:
            replaced = True
            binding_path = Path(workflow._external_file_path(binding))
            old_path = binding_path.with_name(f"old-{binding_path.name}")
            binding_path.rename(old_path)
            _owner_only_file(binding_path, workflow._external_file_encoded(binding))
        original(binding)

    monkeypatch.setattr(workflow, "_revalidate_external_binding", replace_at_revalidation)

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
            **arguments  # type: ignore[arg-type]
        )

    assert captured.value.reason_code == f"{phase}_path_revalidation_failed"
    assert not any(artifacts.envelope_directory.iterdir())


@pytest.mark.parametrize("operation", ["prepare", "verify"])
def test_output_directory_replacement_after_retention_is_ambiguous_and_has_no_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    artifacts = _Artifacts(tmp_path)
    arguments = artifacts.prepare_kwargs() if operation == "prepare" else artifacts.verify_kwargs()
    target_directory = (
        artifacts.statement_directory if operation == "prepare" else artifacts.envelope_directory
    )
    held_directory = target_directory.with_name(f"held-{target_directory.name}")
    original = workflow._retain_exact_file

    def replace_directory_after_retention(*args: object, **kwargs: object) -> tuple[int, ...]:
        identity = original(*args, **kwargs)  # type: ignore[arg-type]
        target_directory.rename(held_directory)
        _owner_only_directory(target_directory)
        return identity

    monkeypatch.setattr(workflow, "_retain_exact_file", replace_directory_after_retention)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        if operation == "prepare":
            prepare_post_enrollment_operator_attestation_statement_candidate(
                **arguments  # type: ignore[arg-type]
            )
        else:
            verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
                **arguments  # type: ignore[arg-type]
            )

    expected_phase = "statement_candidate" if operation == "prepare" else "envelope_candidate"
    assert captured.value.reason_code == f"{expected_phase}_retention_unconfirmed"
    assert not any(target_directory.iterdir())
    assert len(tuple(held_directory.iterdir())) == 1


def test_conflicting_or_wrong_mode_existing_statement_candidate_fails_closed(
    tmp_path: Path,
) -> None:
    artifacts, receipt, candidate = _prepared(tmp_path)
    candidate.write_bytes(b"conflict\n")
    candidate.chmod(0o600)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()
    assert captured.value.reason_code == "statement_candidate_retention_unconfirmed"

    candidate.write_bytes(
        canonical_post_enrollment_operator_attestation_statement_bytes(
            build_post_enrollment_operator_attestation_statement(
                authority=artifacts.authority,
                execution_approval_v2_sha256=artifacts.execution_approval_v2_sha256,
            )
        )
    )
    candidate.chmod(0o400)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()
    assert receipt.artifact_location == candidate.name
    assert captured.value.reason_code == "statement_candidate_retention_unconfirmed"


def test_partial_publication_remains_blocking_and_never_yields_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _Artifacts(tmp_path)
    real_write_all = workflow._write_all

    def partial_then_interrupt(
        owner: workflow._OwnedFileDescriptor,
        payload: bytes,
    ) -> None:
        real_write_all(owner, payload[:1])
        raise KeyboardInterrupt

    monkeypatch.setattr(workflow, "_write_all", partial_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        artifacts.prepare()
    partial = tuple(artifacts.statement_directory.iterdir())
    assert len(partial) == 1
    assert partial[0].read_bytes() == b"{"

    monkeypatch.setattr(workflow, "_write_all", real_write_all)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError) as captured:
        artifacts.prepare()
    assert captured.value.reason_code == "statement_candidate_retention_unconfirmed"


def test_receipts_reject_direct_forgery_copy_replace_pickle_and_mutation(
    tmp_path: Path,
) -> None:
    artifacts = _Artifacts(tmp_path)
    statement_receipt = artifacts.prepare()
    envelope_receipt = verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
        **artifacts.verify_kwargs()  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError):
        TrustedTimePostEnrollmentOperatorAttestationStatementReceipt(
            authority_artifact_sha256="0" * 64,
            public_key_sha256="1" * 64,
            execution_approval_v2_sha256="2" * 64,
            operator_attestation_statement_sha256="3" * 64,
            artifact_location=(f"{workflow.STATEMENT_CANDIDATE_FILE_PREFIX}{'3' * 64}.json"),
        )  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        TrustedTimePostEnrollmentOperatorAttestationEnvelopeReceipt(
            authority_artifact_sha256="0" * 64,
            public_key_sha256="1" * 64,
            execution_approval_v2_sha256="2" * 64,
            operator_attestation_statement_sha256="3" * 64,
            detached_signature_sha256="4" * 64,
            operator_attestation_envelope_sha256="5" * 64,
            artifact_location=(f"{workflow.ENVELOPE_CANDIDATE_FILE_PREFIX}{'5' * 64}.json"),
        )  # type: ignore[call-arg]
    with pytest.raises((TypeError, TrustedTimePostEnrollmentOperatorAttestationArtifactError)):
        replace(statement_receipt, authority_artifact_sha256="0" * 64)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError):
        copy.copy(statement_receipt)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError):
        copy.deepcopy(envelope_receipt)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationArtifactError):
        pickle.dumps(statement_receipt)
    with pytest.raises(FrozenInstanceError):
        statement_receipt.public_key_sha256 = "0" * 64  # type: ignore[misc]

    object.__setattr__(envelope_receipt, "detached_signature_sha256", "0" * 64)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationArtifactError,
        match="artifact_receipt_invalid",
    ):
        _ = envelope_receipt.public_payload


def test_receipt_signature_authentication_is_exact_and_machine_readable(tmp_path: Path) -> None:
    artifacts = _Artifacts(tmp_path)
    statement = artifacts.prepare()
    envelope = verify_and_retain_post_enrollment_operator_attestation_envelope_candidate(
        **artifacts.verify_kwargs()  # type: ignore[arg-type]
    )

    assert statement.public_payload["operator_signature_authentication"] == "not_authenticated"
    assert envelope.public_payload["operator_signature_authentication"] == (
        "authenticated_unqualified"
    )
    for receipt in (statement, envelope):
        for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS:
            assert getattr(receipt, field_name) is False


def test_cli_prepare_emits_one_canonical_public_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifacts = _Artifacts(tmp_path)
    result = main(
        [
            "prepare-statement",
            "--authority-artifact",
            os.fspath(artifacts.authority_artifact),
            "--execution-approval-v2-artifact",
            os.fspath(artifacts.execution_approval_v2_artifact),
            "--expected-authority-sha256",
            artifacts.authority_sha256,
            "--expected-public-key-sha256",
            artifacts.public_key_sha256,
            "--expected-execution-approval-v2-sha256",
            artifacts.execution_approval_v2_sha256,
            "--statement-candidate-directory",
            os.fspath(artifacts.statement_directory),
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert result == 0
    assert captured.err == ""
    assert captured.out.encode("ascii") == canonical_first_enrollment_json_bytes(payload)
    assert set(payload) == POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_RECEIPT_FIELDS


def test_cli_has_closed_commands_exact_flags_and_no_abbreviations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifacts = _Artifacts(tmp_path)
    result = main(
        [
            "prepare-statement",
            "--authority-art",
            os.fspath(artifacts.authority_artifact),
        ]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == "command_arguments_invalid\n"


def test_isolated_cli_source_attestation_rejects_ordinary_runtime() -> None:
    with pytest.raises(RuntimeError, match="CLI runtime attestation failed"):
        workflow._require_isolated_cli_source_runtime(
            expected_relative_path=Path(
                "scripts/trusted_time_post_enrollment_operator_attestation_artifacts.py"
            )
        )


def test_source_contains_no_effecting_or_secret_surface() -> None:
    source_path = Path(workflow.__file__)
    source = source_path.read_text(encoding="utf-8")
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
            "Popen",
            "run",
            "sign",
        }
    )
    assert "os.environ" not in source
    assert "sys.stdin" not in source
    assert "trusted_time_post_enrollment_execution_admission" not in source
    assert "trusted_time_post_enrollment_host_orchestrator" not in source


def _interrupt_instruction(
    target: Any,
    instruction_offset: int,
    action: Any,
    *,
    exception_type: type[BaseException] = KeyboardInterrupt,
) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def interrupt(_: object, offset: int) -> None:
        if offset == instruction_offset:
            raise exception_type

    sys.monitoring.use_tool_id(tool_id, "operator-attestation-artifact-instruction-test")
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


def _cleanup_call_instruction_offsets(target: Any) -> tuple[int, ...]:
    instructions = tuple(dis.get_instructions(target))
    offsets: list[int] = []
    for index, instruction in enumerate(instructions):
        if instruction.argval != "_cleanup_owned_descriptors":
            continue
        for candidate in instructions[index:]:
            offsets.append(candidate.offset)
            if candidate.opname == "STORE_FAST":
                break
    return tuple(dict.fromkeys(offsets))


def _capture_executed_instruction_offsets(
    target: Any,
    action: Any,
    observed: list[int],
) -> None:
    tool_id = next(
        candidate
        for candidate in range(sys.monitoring.OPTIMIZER_ID + 1)
        if sys.monitoring.get_tool(candidate) is None
    )

    def capture(_: object, offset: int) -> None:
        observed.append(offset)

    sys.monitoring.use_tool_id(tool_id, "operator-attestation-artifact-opcode-capture")
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


class _SyntheticOwnedDescriptor:
    def __init__(self) -> None:
        self.closed = False
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True


def _synthetic_stat(*, directory: bool, size: int = 0) -> tuple[int, ...]:
    mode = (stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | 0o600)
    return (17, 23, mode, os.geteuid(), os.getegid(), 1, size, 1, 1)


def _assert_executed_cleanup_opcode_sweep(
    target: Any,
    action: Any,
    opened: list[_SyntheticOwnedDescriptor],
    *,
    owner_required: bool = True,
) -> None:
    executed: list[int] = []
    action()
    _capture_executed_instruction_offsets(target, action, executed)
    offsets = tuple(
        offset for offset in _cleanup_call_instruction_offsets(target) if offset in executed
    )
    assert offsets
    for exception_type in (KeyboardInterrupt, SystemExit):
        for offset in offsets:
            opened.clear()
            with pytest.raises(exception_type):
                _interrupt_instruction(
                    target,
                    offset,
                    action,
                    exception_type=exception_type,
                )
            if owner_required:
                assert opened
            assert all(owner.closed for owner in opened)


def test_publisher_uses_only_direct_native_owner_creation_without_descriptor_escape() -> None:
    for opener in (
        workflow._open_root_directory,
        workflow._open_child_directory,
        workflow._open_child_regular,
        workflow._create_child_regular_exclusive,
    ):
        assert not hasattr(opener, "__code__")
    assert not hasattr(workflow._OwnedFileDescriptor, "fileno")
    assert not hasattr(workflow._OwnedFileDescriptor, "detach")

    source = Path(workflow.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "_open_owned_descriptor",
        "_open_directory_chain",
        "_open_external_owner_only_directory",
        "_open_relative_file",
        ".fileno()",
        "os.open(",
        "os.close(",
        "os.read(",
        "os.write(",
        "os.fstat(",
        "fcntl.flock(",
    ):
        assert forbidden not in source


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
def test_publisher_cleanup_entry_and_call_opcodes_close_owner_before_async_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exception_type: type[BaseException],
) -> None:
    candidate_directory = _owner_only_directory(tmp_path / "cleanup-publisher")
    opened: list[_SyntheticOwnedDescriptor] = []
    directory_metadata = _synthetic_stat(directory=True)

    def capture_open(*_: object) -> _SyntheticOwnedDescriptor:
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    def reject_retention(*_: object, **__: object) -> tuple[int, ...]:
        raise OSError("forced retention failure")

    monkeypatch.setattr(workflow, "_repository_identity", lambda: (91, 92))
    monkeypatch.setattr(workflow, "_open_root_directory", capture_open)
    monkeypatch.setattr(workflow, "_open_child_directory", capture_open)
    monkeypatch.setattr(workflow, "_fstat", lambda _: directory_metadata)
    monkeypatch.setattr(workflow, "_retain_exact_file", reject_retention)
    executed: list[int] = []
    with pytest.raises(workflow.TrustedTimePostEnrollmentOperatorAttestationArtifactError):
        _capture_executed_instruction_offsets(
            workflow._publish_candidate,
            lambda: workflow._publish_candidate(
                directory=candidate_directory,
                file_name=f"candidate-{'a' * 64}.json",
                encoded=b"{}\n",
                maximum_bytes=64,
                phase="candidate",
            ),
            executed,
        )
    assert opened
    assert all(owner.closed for owner in opened)
    offsets = tuple(
        offset
        for offset in _cleanup_call_instruction_offsets(workflow._publish_candidate)
        if offset in executed
    )
    assert offsets

    for offset in offsets:
        opened.clear()
        with pytest.raises(exception_type):
            _interrupt_instruction(
                workflow._publish_candidate,
                offset,
                lambda: workflow._publish_candidate(
                    directory=candidate_directory,
                    file_name=f"candidate-{'a' * 64}.json",
                    encoded=b"{}\n",
                    maximum_bytes=64,
                    phase="candidate",
                ),
                exception_type=exception_type,
            )
        assert opened
        assert all(owner.closed for owner in opened)


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
def test_cleanup_all_retries_each_owner_and_preserves_async_priority(
    exception_type: type[BaseException],
) -> None:
    class InterruptingOwner:
        def __init__(self) -> None:
            self.closed = False
            self.calls = 0

        def close(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise exception_type
            self.closed = True

    owners = (InterruptingOwner(), InterruptingOwner(), InterruptingOwner())
    cleanup_error = workflow._cleanup_owned_descriptors(owners)  # type: ignore[arg-type]

    assert type(cleanup_error) is exception_type
    assert all(owner.closed for owner in owners)
    assert all(owner.calls == 2 for owner in owners)


def test_repository_identity_cleanup_opcode_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[_SyntheticOwnedDescriptor] = []

    def open_owner(*_: object) -> _SyntheticOwnedDescriptor:
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    monkeypatch.setattr(workflow, "_open_root_directory", open_owner)
    monkeypatch.setattr(workflow, "_open_child_directory", open_owner)
    monkeypatch.setattr(workflow, "_fstat", lambda _: _synthetic_stat(directory=True))
    _assert_executed_cleanup_opcode_sweep(
        workflow._repository_identity,
        workflow._repository_identity,
        opened,
    )


def test_relative_read_cleanup_opcode_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[_SyntheticOwnedDescriptor] = []
    directory_owner = _SyntheticOwnedDescriptor()
    directory_metadata = _synthetic_stat(directory=True)
    file_metadata = _synthetic_stat(directory=False, size=1)

    def open_relative(*_: object) -> _SyntheticOwnedDescriptor:
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    def action() -> tuple[bytes, tuple[int, ...]]:
        return workflow._read_relative_file(
            directory_owner,  # type: ignore[arg-type]
            file_name="candidate.json",
            allowed_modes=frozenset({0o600}),
            minimum_bytes=1,
            maximum_bytes=8,
        )

    monkeypatch.setattr(workflow, "_open_child_regular", open_relative)
    monkeypatch.setattr(
        workflow,
        "_fstat",
        lambda owner: directory_metadata if owner is directory_owner else file_metadata,
    )
    monkeypatch.setattr(
        workflow,
        "_read_snapshot",
        lambda *_, **__: (b"x", file_metadata, file_metadata),
    )
    monkeypatch.setattr(workflow, "_statat", lambda *_, **__: file_metadata)
    _assert_executed_cleanup_opcode_sweep(
        workflow._read_relative_file,
        action,
        opened,
    )


def test_external_binding_read_and_revalidation_cleanup_opcode_sweeps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[_SyntheticOwnedDescriptor] = []
    directory_metadata = _synthetic_stat(directory=True)
    file_identity = _synthetic_stat(directory=False, size=1)
    artifact = tmp_path / "candidate.json"

    def open_external(*_: object) -> _SyntheticOwnedDescriptor:
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    monkeypatch.setattr(workflow, "_repository_identity", lambda: (91, 92))
    monkeypatch.setattr(workflow, "_open_root_directory", open_external)
    monkeypatch.setattr(workflow, "_open_child_directory", open_external)
    monkeypatch.setattr(workflow, "_fstat", lambda _: directory_metadata)
    monkeypatch.setattr(
        workflow,
        "_read_relative_file",
        lambda *_, **__: (b"x", file_identity),
    )

    def read_action() -> workflow._ExternalFileBinding:
        return workflow._read_external_binding(
            artifact,
            allowed_modes=frozenset({0o600}),
            minimum_bytes=1,
            maximum_bytes=8,
            phase="candidate",
        )

    binding = read_action()
    _assert_executed_cleanup_opcode_sweep(
        workflow._read_external_binding,
        read_action,
        opened,
    )
    _assert_executed_cleanup_opcode_sweep(
        workflow._revalidate_external_binding,
        lambda: workflow._revalidate_external_binding(binding),
        opened,
    )


def test_durable_confirmation_cleanup_opcode_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[_SyntheticOwnedDescriptor] = []
    directory_owner = _SyntheticOwnedDescriptor()
    encoded = b"x"
    directory_metadata = _synthetic_stat(directory=True)
    file_metadata = _synthetic_stat(directory=False, size=len(encoded))

    def open_relative(*_: object) -> _SyntheticOwnedDescriptor:
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    def action() -> tuple[int, ...]:
        return workflow._confirm_durable_exact_file(
            directory_owner,  # type: ignore[arg-type]
            file_name="candidate.json",
            encoded=encoded,
            required_mode=0o600,
        )

    monkeypatch.setattr(workflow, "_open_child_regular", open_relative)
    monkeypatch.setattr(
        workflow,
        "_fstat",
        lambda owner: directory_metadata if owner is directory_owner else file_metadata,
    )
    monkeypatch.setattr(
        workflow,
        "_read_snapshot",
        lambda *_, **__: (encoded, file_metadata, file_metadata),
    )
    monkeypatch.setattr(workflow, "_statat", lambda *_, **__: file_metadata)
    monkeypatch.setattr(workflow, "_fsync", lambda _: None)
    monkeypatch.setattr(workflow, "_flock", lambda *_, **__: None)
    _assert_executed_cleanup_opcode_sweep(
        workflow._confirm_durable_exact_file,
        action,
        opened,
    )


@pytest.mark.parametrize("existing", [False, True])
def test_retention_cleanup_opcode_sweep_for_create_and_existing_branches(
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
) -> None:
    opened: list[_SyntheticOwnedDescriptor] = []
    directory_owner = _SyntheticOwnedDescriptor()
    encoded = b"x"
    file_identity = _synthetic_stat(directory=False, size=1)

    def open_relative(*_: object, **__: object) -> _SyntheticOwnedDescriptor:
        if existing:
            raise FileExistsError
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    monkeypatch.setattr(workflow, "_create_child_regular_exclusive", open_relative)
    monkeypatch.setattr(
        workflow,
        "_read_relative_file",
        lambda *_, **__: (encoded, file_identity),
    )
    monkeypatch.setattr(
        workflow,
        "_confirm_durable_exact_file",
        lambda *_, **__: file_identity,
    )
    monkeypatch.setattr(workflow, "_write_all", lambda *_, **__: None)
    monkeypatch.setattr(workflow, "_ftruncate", lambda *_, **__: None)
    monkeypatch.setattr(workflow, "_fchmod_0600", lambda *_, **__: None)
    monkeypatch.setattr(workflow, "_fsync", lambda *_, **__: None)
    monkeypatch.setattr(workflow, "_flock", lambda *_, **__: None)

    def action() -> tuple[int, ...]:
        return workflow._retain_exact_file(
            directory_owner,  # type: ignore[arg-type]
            file_name="candidate.json",
            encoded=encoded,
            maximum_bytes=8,
            phase="candidate",
        )

    _assert_executed_cleanup_opcode_sweep(
        workflow._retain_exact_file,
        action,
        opened,
        owner_required=not existing,
    )


def test_published_file_revalidation_cleanup_opcode_sweep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[_SyntheticOwnedDescriptor] = []
    directory_metadata = _synthetic_stat(directory=True)
    file_identity = _synthetic_stat(directory=False, size=1)

    def open_external(*_: object) -> _SyntheticOwnedDescriptor:
        owner = _SyntheticOwnedDescriptor()
        opened.append(owner)
        return owner

    monkeypatch.setattr(workflow, "_repository_identity", lambda: (91, 92))
    monkeypatch.setattr(workflow, "_open_root_directory", open_external)
    monkeypatch.setattr(workflow, "_open_child_directory", open_external)
    monkeypatch.setattr(workflow, "_fstat", lambda _: directory_metadata)
    monkeypatch.setattr(
        workflow,
        "_confirm_durable_exact_file",
        lambda *_, **__: file_identity,
    )

    def action() -> tuple[int, ...]:
        return workflow._revalidate_external_published_file(
            directory_path=os.fspath(tmp_path),
            expected_directory_identity=(
                directory_metadata[0],
                directory_metadata[1],
            ),
            file_name="candidate.json",
            encoded=b"x",
            phase="candidate",
        )

    _assert_executed_cleanup_opcode_sweep(
        workflow._revalidate_external_published_file,
        action,
        opened,
    )


@pytest.mark.parametrize(
    ("body_exception", "cleanup_exception", "expected_exception"),
    [
        (KeyboardInterrupt, OSError, KeyboardInterrupt),
        (OSError, KeyboardInterrupt, KeyboardInterrupt),
        (KeyboardInterrupt, SystemExit, KeyboardInterrupt),
    ],
)
def test_binding_cleanup_preserves_body_and_cleanup_async_priority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body_exception: type[BaseException],
    cleanup_exception: type[BaseException],
    expected_exception: type[BaseException],
) -> None:
    class InterruptingOwner(_SyntheticOwnedDescriptor):
        def close(self) -> None:
            self.close_calls += 1
            if self.close_calls == 1:
                raise cleanup_exception
            self.closed = True

    owners: list[InterruptingOwner] = []

    def open_owner(*_: object) -> InterruptingOwner:
        owner = InterruptingOwner()
        owners.append(owner)
        return owner

    monkeypatch.setattr(workflow, "_repository_identity", lambda: (91, 92))
    monkeypatch.setattr(workflow, "_absolute_path_components", lambda _: ())
    monkeypatch.setattr(workflow, "_open_root_directory", open_owner)
    monkeypatch.setattr(workflow, "_open_child_directory", open_owner)
    monkeypatch.setattr(workflow, "_fstat", lambda _: _synthetic_stat(directory=True))

    def fail_read(*_: object, **__: object) -> Never:
        raise body_exception

    monkeypatch.setattr(workflow, "_read_relative_file", fail_read)
    with pytest.raises(expected_exception):
        workflow._read_external_binding(
            tmp_path / "candidate.json",
            allowed_modes=frozenset({0o600}),
            minimum_bytes=1,
            maximum_bytes=8,
            phase="candidate",
        )
    assert owners
    assert all(owner.closed for owner in owners)
    assert all(owner.close_calls == 2 for owner in owners)


def test_publication_return_store_interruption_has_no_receipt_and_recovers_idempotently(
    tmp_path: Path,
) -> None:
    artifacts = _Artifacts(tmp_path)
    target = prepare_post_enrollment_operator_attestation_statement_candidate
    store = next(
        instruction.offset
        for instruction in dis.get_instructions(target)
        if instruction.opname == "STORE_FAST" and instruction.argval == "_publication_identity"
    )

    with pytest.raises(KeyboardInterrupt):
        _interrupt_instruction(
            target,
            store,
            lambda: target(**artifacts.prepare_kwargs()),  # type: ignore[arg-type]
        )

    candidates = tuple(artifacts.statement_directory.iterdir())
    assert len(candidates) == 1
    candidate_inode = candidates[0].stat().st_ino
    receipt = artifacts.prepare()
    assert candidates[0].name == receipt.artifact_location
    assert candidates[0].stat().st_ino == candidate_inode


def test_native_owner_capabilities_pin_close_on_exec_and_nofollow() -> None:
    from packages.adapters.trusted_time import _owned_file_descriptor as owned_fd

    capabilities = owned_fd._native_owned_file_descriptor_capabilities()
    assert "o-cloexec-and-nofollow-mandatory" in capabilities
    assert "no-python-visible-descriptor" in capabilities
