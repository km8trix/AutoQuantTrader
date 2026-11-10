from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import pickle
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any, cast

import pytest

import packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation as adapter
from packages.adapters.trusted_time.ed25519_graceful_stop_operator_attestation import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
    Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
)
from packages.domain import (
    trusted_time_post_enrollment_graceful_stop_operator_authority as authority_domain,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement,
    build_post_enrollment_graceful_stop_operator_attestation_envelope,
    build_post_enrollment_graceful_stop_operator_attestation_statement,
    canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes,
    canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    build_post_enrollment_graceful_stop_operator_authority,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    build_post_enrollment_operator_attestation_envelope,
    build_post_enrollment_operator_attestation_statement,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    build_post_enrollment_operator_authority,
)
from scripts.trusted_time_post_enrollment_graceful_stop import (
    POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS,
)

# Public-only fixture derived from RFC 8032 test key 2.  No private material or
# signing API is present in this test module.
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
OTHER_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
IDENTITY_PUBLIC_KEY = b"\x01" + b"\x00" * 31
IDENTITY_FORGED_SIGNATURE = IDENTITY_PUBLIC_KEY + b"\x00" * 32
MIXED_SUBGROUP_PUBLIC_KEY = bytes.fromhex(
    "b0bfe83c17bc76a56d48f558b2e481436367d330d13b69733f32aa0ed50b99f3"
)
STOP_OPERATION_ID = "fa3f23cc-a7c1-4a5c-b915-3c2ad1d9e723"
TARGET_SHA256 = "1" * 64
DECISION_V1 = (
    b'{"contract_version":"phase6d-post-enrollment-graceful-stop-decision-v1",'
    b'"graceful_stop_target_sha256":"111111111111111111111111111111111111111111111111'
    b'1111111111111111","operation_id":"fa3f23cc-a7c1-4a5c-b915-3c2ad1d9e723",'
    b'"service":"trusted-time-post-enrollment-graceful-stop",'
    b'"status":"external_attestation_required"}\n'
)
EXPECTED_STATEMENT = (
    b'{"algorithm":"Ed25519","authority_artifact_sha256":"b0b6935d8b9573e55d68f7eb'
    b'9fb639f71127e34d30110ee06c3613acbdc31db8","authority_contract_version":"phase6d-'
    b'post-enrollment-graceful-stop-operator-attestation-authority-v1","contract_version"'
    b':"phase6d-post-enrollment-graceful-stop-operator-attestation-statement-v1","decision"'
    b':"approve_one_post_enrollment_graceful_stop_attempt","graceful_stop_decision_contract_'
    b'version":"phase6d-post-enrollment-graceful-stop-decision-v1","graceful_stop_decision_'
    b'v1_sha256":"a0ad511546ed105ff410cdd19ab739e8d3e3c346e82a08e1c6c61ade1dd6696c"'
    b',"graceful_stop_operation_id":"fa3f23cc-a7c1-4a5c-b915-3c2ad1d9e723","graceful_'
    b'stop_target_sha256":"1111111111111111111111111111111111111111111111111111111111111111"'
    b',"key_id":"aqt-post-enrollment-graceful-stop-operator-ed25519-v1","public_key_sha256"'
    b':"39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f","replay_'
    b'domain":"github.com/km8trix/AutoQuantTrader/production/trusted-time/post-enrollment-'
    b'graceful-stop/operator-attestation/v1","service":"trusted-time-post-enrollment-'
    b'graceful-stop-operator-attestation","status":"exact_one_attempt_graceful_stop_'
    b'decision_statement"}\n'
)
SIGNATURE = bytes.fromhex(
    "9b85173bec29e2ff23dd382fe0741cb8a113c179b5ccddac181395db94b3d96f4"
    "1b012c56f6ee36e87131add43f6c4efca30a660951ceba968c542afc03ff90b"
)
START_EXECUTION_APPROVAL_V2 = (
    b'{"contract_version":"phase6d-post-enrollment-start-execution-approval-v2",'
    b'"service":"trusted-time-post-enrollment-start-execution-approval",'
    b'"status":"execution_approval_artifact"}\n'
)

_RESULT_IDENTITY_FIELDS = frozenset(
    {
        "authority_artifact_sha256",
        "contract_version",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "operator_attestation_envelope_sha256",
        "operator_attestation_signature_sha256",
        "operator_attestation_statement_sha256",
        "public_key_sha256",
        "service",
        "status",
        "verification_only",
    }
)


def _authority(
    public_key: bytes = PUBLIC_KEY,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
    return build_post_enrollment_graceful_stop_operator_authority(public_key)


def _statement(
    *,
    authority: TrustedTimePostEnrollmentGracefulStopOperatorAuthority | None = None,
    decision_v1: bytes = DECISION_V1,
    operation_id: str = STOP_OPERATION_ID,
    target_sha256: str = TARGET_SHA256,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
    return build_post_enrollment_graceful_stop_operator_attestation_statement(
        authority=_authority() if authority is None else authority,
        graceful_stop_decision_v1_sha256=hashlib.sha256(decision_v1).hexdigest(),
        graceful_stop_operation_id=operation_id,
        graceful_stop_target_sha256=target_sha256,
    )


def _envelope(
    *,
    authority: TrustedTimePostEnrollmentGracefulStopOperatorAuthority | None = None,
    decision_v1: bytes = DECISION_V1,
    signature: bytes = SIGNATURE,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
    return build_post_enrollment_graceful_stop_operator_attestation_envelope(
        graceful_stop_decision_v1=decision_v1,
        statement=_statement(authority=authority, decision_v1=decision_v1),
        signature_ed25519=signature,
    )


def _verifier(
    authority: TrustedTimePostEnrollmentGracefulStopOperatorAuthority | None = None,
) -> Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier:
    return Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.from_authority(
        _authority() if authority is None else authority
    )


def test_fixed_public_only_vector_verifies_exact_lf_statement() -> None:
    statement = _statement()
    envelope = _envelope()

    assert (
        canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
        == EXPECTED_STATEMENT
    )
    assert EXPECTED_STATEMENT.endswith(b"\n")
    assert EXPECTED_STATEMENT.count(b"\n") == 1

    result = _verifier().verify(envelope)

    assert result.authority_artifact_sha256 == _authority().authority_sha256
    assert result.public_key_sha256 == hashlib.sha256(PUBLIC_KEY).hexdigest()
    assert result.graceful_stop_decision_v1_sha256 == hashlib.sha256(DECISION_V1).hexdigest()
    assert result.graceful_stop_operation_id == STOP_OPERATION_ID
    assert result.graceful_stop_target_sha256 == TARGET_SHA256
    assert (
        result.operator_attestation_statement_sha256
        == hashlib.sha256(EXPECTED_STATEMENT).hexdigest()
    )
    assert result.operator_attestation_signature_sha256 == hashlib.sha256(SIGNATURE).hexdigest()
    assert result.operator_attestation_envelope_sha256 == envelope.envelope_sha256


def test_result_is_frozen_verification_only_and_full_adr0104_surface_is_false() -> None:
    result = _verifier().verify(_envelope())
    payload = result.payload()

    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS == (
        POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS
    )
    assert result.status == "graceful_stop_operator_signature_authenticated_unqualified"
    assert result.status == (POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS)
    assert result.verification_only is True
    assert payload["contract_version"] == (
        "phase6d-post-enrollment-graceful-stop-operator-attestation-verification-v1"
    )
    assert payload["contract_version"] == (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
    )
    assert payload["service"] == (
        "trusted-time-post-enrollment-graceful-stop-operator-attestation-verification"
    )
    assert payload["service"] == (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
    )
    assert set(payload) == (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        | _RESULT_IDENTITY_FIELDS
    )
    for field_name in POST_ENROLLMENT_GRACEFUL_STOP_AUTHORITY_FIELDS:
        assert payload[field_name] is False
        assert getattr(result, field_name) is False
    with pytest.raises(FrozenInstanceError):
        result.authority_artifact_sha256 = "0" * 64  # type: ignore[misc]


def test_result_rejects_direct_construction_copy_replace_pickle_and_mutation() -> None:
    values = {
        "authority_artifact_sha256": "1" * 64,
        "public_key_sha256": "2" * 64,
        "graceful_stop_decision_v1_sha256": "3" * 64,
        "graceful_stop_operation_id": STOP_OPERATION_ID,
        "graceful_stop_target_sha256": "4" * 64,
        "operator_attestation_statement_sha256": "5" * 64,
        "operator_attestation_signature_sha256": "6" * 64,
        "operator_attestation_envelope_sha256": "7" * 64,
    }
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification(
            **values,
            _construction_capability=object(),
        )

    result = _verifier().verify(_envelope())
    assert not hasattr(result, "_construction_capability")
    for operation in (
        lambda: copy.copy(result),
        lambda: copy.deepcopy(result),
        lambda: pickle.dumps(result),
    ):
        with pytest.raises(
            TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError
        ):
            operation()
    with pytest.raises(TypeError):
        replace(result, graceful_stop_target_sha256="0" * 64)

    object.__setattr__(result, "graceful_stop_target_sha256", "0" * 64)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        result.payload()


@pytest.mark.parametrize(
    "field_name,value",
    [
        ("authority_artifact_sha256", True),
        ("public_key_sha256", "x" * 64),
        ("graceful_stop_decision_v1_sha256", "0" * 63),
        ("graceful_stop_operation_id", "00000000-0000-0000-0000-000000000000"),
        ("graceful_stop_target_sha256", None),
        ("operator_attestation_statement_sha256", object()),
        ("operator_attestation_signature_sha256", "F" * 64),
        ("operator_attestation_envelope_sha256", 0),
    ],
)
def test_result_rejects_invalid_identity_construction(field_name: str, value: object) -> None:
    values: dict[str, object] = {
        "authority_artifact_sha256": "1" * 64,
        "public_key_sha256": "2" * 64,
        "graceful_stop_decision_v1_sha256": "3" * 64,
        "graceful_stop_operation_id": STOP_OPERATION_ID,
        "graceful_stop_target_sha256": "4" * 64,
        "operator_attestation_statement_sha256": "5" * 64,
        "operator_attestation_signature_sha256": "6" * 64,
        "operator_attestation_envelope_sha256": "7" * 64,
    }
    values[field_name] = value
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification(
            **cast(Any, values),
            _construction_capability=adapter._VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY,
        )


@pytest.mark.parametrize("envelope", [None, True, object(), {}, DECISION_V1])
def test_verifier_rejects_fake_and_wrong_type_envelopes(envelope: object) -> None:
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="envelope is invalid",
    ):
        _verifier().verify(envelope)


def test_verifier_rejects_start_protocol_authority_and_envelope() -> None:
    start_authority = build_post_enrollment_operator_authority(PUBLIC_KEY)
    start_statement = build_post_enrollment_operator_attestation_statement(
        authority=start_authority,
        execution_approval_v2_sha256=hashlib.sha256(START_EXECUTION_APPROVAL_V2).hexdigest(),
    )
    start_envelope = build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=START_EXECUTION_APPROVAL_V2,
        statement=start_statement,
        signature_ed25519=SIGNATURE,
    )

    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.from_authority(start_authority)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="envelope is invalid",
    ):
        _verifier().verify(start_envelope)


def test_constructor_rejects_subclasses_and_has_no_default_path() -> None:
    class AuthoritySubclass(TrustedTimePostEnrollmentGracefulStopOperatorAuthority):
        pass

    class EnvelopeSubclass(TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope):
        pass

    class VerifierSubclass(Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier):
        pass

    authority_subclass = AuthoritySubclass(public_key_bytes=PUBLIC_KEY)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.from_authority(
            authority_subclass
        )
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        VerifierSubclass.from_authority(_authority())

    envelope_subclass = object.__new__(EnvelopeSubclass)
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="envelope is invalid",
    ):
        _verifier().verify(envelope_subclass)

    from_authority_signature = inspect.signature(
        Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.from_authority
    )
    verify_signature = inspect.signature(
        Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier.verify
    )
    assert from_authority_signature.parameters["authority"].default is inspect.Parameter.empty
    assert verify_signature.parameters["envelope"].default is inspect.Parameter.empty
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError):
        Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier(
            _authority_encoded=_authority().encoded,
            _construction_capability=object(),
        )


def test_verifier_and_result_reject_copy_replace_pickle_and_tampered_authority() -> None:
    verifier = _verifier()
    for operation in (
        lambda: copy.copy(verifier),
        lambda: copy.deepcopy(verifier),
        lambda: pickle.dumps(verifier),
    ):
        with pytest.raises(
            TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError
        ):
            operation()
    with pytest.raises(TypeError):
        replace(verifier, _authority_encoded=_authority().encoded)

    object.__setattr__(verifier, "_authority_encoded", verifier._authority_encoded + b"\n")
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="verification failed",
    ):
        verifier.verify(_envelope())


def test_wrong_authority_decision_and_signature_fail_closed() -> None:
    different_decision = canonical_first_enrollment_json_bytes(
        {
            "contract_version": "phase6d-post-enrollment-graceful-stop-decision-v1",
            "graceful_stop_target_sha256": TARGET_SHA256,
            "operation_id": STOP_OPERATION_ID,
            "service": "trusted-time-post-enrollment-graceful-stop",
            "status": "external_attestation_required",
            "unexpected": "different-byte-level-artifact",
        }
    )
    tampered_signature = bytes([SIGNATURE[0] ^ 1]) + SIGNATURE[1:]

    for verifier, envelope in (
        (_verifier(_authority(OTHER_PUBLIC_KEY)), _envelope()),
        (_verifier(), _envelope(decision_v1=different_decision)),
        (_verifier(), _envelope(signature=tampered_signature)),
    ):
        with pytest.raises(
            TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
            match="verification failed",
        ):
            verifier.verify(envelope)


def test_verification_uses_one_canonical_input_then_only_fresh_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _envelope()
    expected_envelope_sha256 = envelope.envelope_sha256
    real_canonicalize = canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes
    calls = 0

    def canonicalize_then_mutate(candidate: object) -> bytes:
        nonlocal calls
        calls += 1
        encoded = real_canonicalize(candidate)
        assert candidate is envelope
        object.__setattr__(
            envelope, "_signature_ed25519", bytes([SIGNATURE[0] ^ 1]) + SIGNATURE[1:]
        )
        object.__setattr__(envelope, "_graceful_stop_decision_v1_encoded", DECISION_V1 + b"\n")
        object.__setattr__(envelope, "_statement_encoded", EXPECTED_STATEMENT + b"\n")
        return encoded

    monkeypatch.setattr(
        adapter,
        "canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes",
        canonicalize_then_mutate,
    )

    result = _verifier().verify(envelope)

    assert calls == 1
    assert result.operator_attestation_envelope_sha256 == expected_envelope_sha256
    assert result.operator_attestation_signature_sha256 == hashlib.sha256(SIGNATURE).hexdigest()


@pytest.mark.parametrize(
    "public_key",
    [
        b"\x00" * 32,
        IDENTITY_PUBLIC_KEY,
        b"\xec" + b"\xff" * 30 + b"\x7f",
        b"\x01" + b"\x00" * 30 + b"\x80",
        b"\xff" * 32,
        MIXED_SUBGROUP_PUBLIC_KEY,
    ],
)
def test_non_prime_order_noncanonical_and_off_curve_keys_fail_closed(
    public_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        authority_domain,
        "require_strict_post_enrollment_operator_public_key",
        lambda value: cast(bytes, value),
    )
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        _verifier(_authority(public_key))


def test_identity_key_universal_forgery_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        authority_domain,
        "require_strict_post_enrollment_operator_public_key",
        lambda value: cast(bytes, value),
    )
    authority = _authority(IDENTITY_PUBLIC_KEY)
    forged_envelope = _envelope(
        authority=authority,
        signature=IDENTITY_FORGED_SIGNATURE,
    )

    assert len(IDENTITY_FORGED_SIGNATURE) == 64
    with pytest.raises(
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        _verifier(authority).verify(forged_envelope)


def test_mutated_decoded_envelope_is_revalidated_and_sanitized() -> None:
    mutations = (
        ("_signature_ed25519", b"short"),
        ("_graceful_stop_decision_v1_encoded", DECISION_V1 + b"\n"),
        ("_statement_encoded", EXPECTED_STATEMENT + b"\n"),
        ("_sealed_fields", ()),
    )
    for field_name, value in mutations:
        envelope = _envelope()
        object.__setattr__(envelope, field_name, value)
        with pytest.raises(
            TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError,
            match="verification failed",
        ):
            _verifier().verify(envelope)


def test_production_module_is_public_only_inert_and_has_no_default_key() -> None:
    module_path = Path(adapter.__file__)
    source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    allowed_modules = {
        "__future__",
        "dataclasses",
        "hashlib",
        "typing",
        "uuid",
        "cryptography.exceptions",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        "packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation",
        "packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority",
    }

    assert imported_modules <= allowed_modules
    assert "Ed25519PrivateKey" not in source
    assert "private_key" not in source
    assert "sign(" not in source
    assert not any(type(value) is bytes and len(value) == 32 for value in vars(adapter).values())
    assert not any("default" in name.lower() for name in vars(adapter))
