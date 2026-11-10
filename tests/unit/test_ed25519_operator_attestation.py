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

import packages.adapters.trusted_time.ed25519_operator_attestation as adapter
import packages.domain.trusted_time_post_enrollment_operator_authority as authority_domain
from packages.adapters.trusted_time.ed25519_operator_attestation import (
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS,
    Ed25519PostEnrollmentOperatorAttestationVerifier,
    TrustedTimePostEnrollmentOperatorAttestationVerification,
    TrustedTimePostEnrollmentOperatorAttestationVerificationError,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    TrustedTimePostEnrollmentOperatorAttestationEnvelope,
    TrustedTimePostEnrollmentOperatorAttestationStatement,
    build_post_enrollment_operator_attestation_envelope,
    build_post_enrollment_operator_attestation_statement,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
    canonical_post_enrollment_operator_attestation_statement_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    TrustedTimePostEnrollmentOperatorAuthority,
    build_post_enrollment_operator_authority,
)

# Public-only fixture derived from RFC 8032 test key 2.  Neither its private seed
# nor any signer/private-key API is present in this repository test.
PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
OTHER_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
IDENTITY_PUBLIC_KEY = b"\x01" + b"\x00" * 31
IDENTITY_FORGED_SIGNATURE = IDENTITY_PUBLIC_KEY + b"\x00" * 32
MIXED_SUBGROUP_PUBLIC_KEY = bytes.fromhex(
    "b0bfe83c17bc76a56d48f558b2e481436367d330d13b69733f32aa0ed50b99f3"
)
EXECUTION_APPROVAL_V2 = (
    b'{"contract_version":"phase6d-post-enrollment-start-execution-approval-v2",'
    b'"service":"trusted-time-post-enrollment-start-execution-approval",'
    b'"status":"execution_approval_artifact"}\n'
)
EXPECTED_STATEMENT = (
    b'{"algorithm":"Ed25519","authority_artifact_sha256":"e85bb071696c484a08c93284d'
    b'd7d67e3e52d83734ef732c3a33722e5dc6d673e","authority_contract_version":"phase6d-'
    b'post-enrollment-operator-attestation-authority-v1","contract_version":"phase6d-post-'
    b'enrollment-start-operator-attestation-statement-v1","decision":"approve_one_post_'
    b'enrollment_start_attempt","execution_approval_contract_version":"phase6d-post-'
    b'enrollment-start-execution-approval-v2","execution_approval_v2_sha256":"8373db0ac922'
    b'06ac8321dc5c111eead3047c411d05a893183bd1901d806ba2f4","key_id":"aqt-post-'
    b'enrollment-start-operator-ed25519-v1","public_key_sha256":"39f713d0a644253f04529421'
    b'b9f51b9b08979d08295959c4f3990ee617f5139f","replay_domain":"github.com/km8trix/'
    b'AutoQuantTrader/production/trusted-time/post-enrollment-start/operator-attestation/v1",'
    b'"service":"trusted-time-post-enrollment-start-operator-attestation","status":"exact_'
    b'one_attempt_execution_approval_statement"}\n'
)
SIGNATURE = bytes.fromhex(
    "25dbf98a3808469b89e27dbff180780d08cb90ca846619a7f971c9e668ae38be"
    "317522b7fe2e9f29ad9fa5489f68337eb97e2bf6e6f660f6002f7edeaf2f780c"
)

_RESULT_IDENTITY_FIELDS = frozenset(
    {
        "authority_artifact_sha256",
        "contract_version",
        "execution_approval_v2_sha256",
        "operator_attestation_envelope_sha256",
        "operator_attestation_statement_sha256",
        "public_key_sha256",
        "service",
        "status",
        "verification_only",
    }
)


def _authority(
    public_key: bytes = PUBLIC_KEY,
) -> TrustedTimePostEnrollmentOperatorAuthority:
    return build_post_enrollment_operator_authority(public_key)


def _statement(
    *,
    authority: TrustedTimePostEnrollmentOperatorAuthority | None = None,
    execution_approval_v2: bytes = EXECUTION_APPROVAL_V2,
) -> TrustedTimePostEnrollmentOperatorAttestationStatement:
    exact_authority = _authority() if authority is None else authority
    return build_post_enrollment_operator_attestation_statement(
        authority=exact_authority,
        execution_approval_v2_sha256=hashlib.sha256(execution_approval_v2).hexdigest(),
    )


def _envelope(
    *,
    authority: TrustedTimePostEnrollmentOperatorAuthority | None = None,
    execution_approval_v2: bytes = EXECUTION_APPROVAL_V2,
    signature: bytes = SIGNATURE,
) -> TrustedTimePostEnrollmentOperatorAttestationEnvelope:
    return build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=execution_approval_v2,
        statement=_statement(
            authority=authority,
            execution_approval_v2=execution_approval_v2,
        ),
        signature_ed25519=signature,
    )


def _verifier(
    authority: TrustedTimePostEnrollmentOperatorAuthority | None = None,
) -> Ed25519PostEnrollmentOperatorAttestationVerifier:
    return Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(
        _authority() if authority is None else authority
    )


def test_fixed_public_only_vector_verifies_exact_newline_terminated_statement() -> None:
    statement = _statement()
    envelope = _envelope()

    assert canonical_post_enrollment_operator_attestation_statement_bytes(statement) == (
        EXPECTED_STATEMENT
    )
    assert EXPECTED_STATEMENT.endswith(b"\n")
    assert EXPECTED_STATEMENT.count(b"\n") == 1

    result = _verifier().verify(envelope)

    assert result.authority_artifact_sha256 == _authority().authority_sha256
    assert result.public_key_sha256 == hashlib.sha256(PUBLIC_KEY).hexdigest()
    assert result.execution_approval_v2_sha256 == hashlib.sha256(EXECUTION_APPROVAL_V2).hexdigest()
    assert (
        result.operator_attestation_statement_sha256
        == hashlib.sha256(EXPECTED_STATEMENT).hexdigest()
    )
    assert result.operator_attestation_envelope_sha256 == envelope.envelope_sha256


def test_result_is_frozen_unqualified_and_every_operational_authority_is_false() -> None:
    result = _verifier().verify(_envelope())
    payload = result.payload()

    assert result.status == "operator_signature_authenticated_unqualified"
    assert result.status == POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS
    assert result.verification_only is True
    assert payload["contract_version"] == (
        "phase6d-post-enrollment-operator-attestation-verification-v1"
    )
    assert payload["contract_version"] == (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
    )
    assert payload["service"] == ("trusted-time-post-enrollment-operator-attestation-verification")
    assert payload["service"] == POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
    assert set(payload) == (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS | _RESULT_IDENTITY_FIELDS
    )
    for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS:
        assert payload[field_name] is False
        assert getattr(result, field_name) is False
    with pytest.raises(FrozenInstanceError):
        result.authority_artifact_sha256 = "0" * 64  # type: ignore[misc]


def test_result_rejects_direct_valid_forgery_copy_deepcopy_replace_and_pickle() -> None:
    valid_digests = {
        "authority_artifact_sha256": "1" * 64,
        "public_key_sha256": "2" * 64,
        "execution_approval_v2_sha256": "3" * 64,
        "operator_attestation_statement_sha256": "4" * 64,
        "operator_attestation_envelope_sha256": "5" * 64,
    }
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        TrustedTimePostEnrollmentOperatorAttestationVerification(
            **valid_digests,
            _construction_capability=object(),
        )

    result = _verifier().verify(_envelope())
    assert not hasattr(result, "_construction_capability")
    for operation in (
        lambda: copy.copy(result),
        lambda: copy.deepcopy(result),
        lambda: pickle.dumps(result),
    ):
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationVerificationError):
            operation()
    with pytest.raises(TypeError):
        replace(result, execution_approval_v2_sha256="0" * 64)


@pytest.mark.parametrize(
    "digest_field",
    [
        "authority_artifact_sha256",
        "public_key_sha256",
        "execution_approval_v2_sha256",
        "operator_attestation_statement_sha256",
        "operator_attestation_envelope_sha256",
    ],
)
def test_result_rejects_valid_shaped_post_construction_digest_mutation(
    digest_field: str,
) -> None:
    result = _verifier().verify(_envelope())
    object.__setattr__(result, digest_field, "0" * 64)

    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        result.payload()


@pytest.mark.parametrize(
    "envelope",
    [None, True, object(), {}, EXECUTION_APPROVAL_V2],
)
def test_verifier_rejects_fake_and_wrong_type_envelopes(envelope: object) -> None:
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="envelope is invalid",
    ):
        _verifier().verify(envelope)


def test_verifier_rejects_envelope_subclasses() -> None:
    class EnvelopeSubclass(TrustedTimePostEnrollmentOperatorAttestationEnvelope):
        pass

    exact = _envelope()
    subclass = EnvelopeSubclass(
        execution_approval_v2=exact.execution_approval_v2,
        statement=exact.statement,
        signature_ed25519=exact.signature_ed25519,
    )

    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="envelope is invalid",
    ):
        _verifier().verify(subclass)


@pytest.mark.parametrize("authority", [None, True, object(), {}, PUBLIC_KEY])
def test_constructor_rejects_fake_and_wrong_type_authorities(authority: object) -> None:
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority)


def test_constructor_rejects_authority_and_verifier_subclasses() -> None:
    class AuthoritySubclass(TrustedTimePostEnrollmentOperatorAuthority):
        pass

    class VerifierSubclass(Ed25519PostEnrollmentOperatorAttestationVerifier):
        pass

    authority_subclass = AuthoritySubclass(public_key_bytes=PUBLIC_KEY)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority_subclass)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        VerifierSubclass.from_authority(_authority())


def test_constructor_has_no_default_or_fake_construction_path() -> None:
    from_authority_signature = inspect.signature(
        Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority
    )
    verify_signature = inspect.signature(Ed25519PostEnrollmentOperatorAttestationVerifier.verify)

    assert from_authority_signature.parameters["authority"].default is inspect.Parameter.empty
    assert verify_signature.parameters["envelope"].default is inspect.Parameter.empty
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationVerificationError):
        Ed25519PostEnrollmentOperatorAttestationVerifier(
            _authority_encoded=_authority().encoded,
            _construction_capability=object(),
        )


def test_constructor_and_verify_revalidate_tampered_authority_bytes() -> None:
    authority = _authority()
    object.__setattr__(authority, "public_key_bytes", b"short")
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority)

    verifier = _verifier()
    object.__setattr__(verifier, "_authority_encoded", verifier._authority_encoded + b"\n")
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification failed",
    ):
        verifier.verify(_envelope())


def test_wrong_authority_key_and_every_statement_authority_binding_fail_closed() -> None:
    correct_statement = _statement()
    wrong_authority = _authority(OTHER_PUBLIC_KEY)
    wrong_authority_envelope = build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=EXECUTION_APPROVAL_V2,
        statement=TrustedTimePostEnrollmentOperatorAttestationStatement(
            authority_artifact_sha256=wrong_authority.authority_sha256,
            public_key_sha256=correct_statement.public_key_sha256,
            execution_approval_v2_sha256=correct_statement.execution_approval_v2_sha256,
        ),
        signature_ed25519=SIGNATURE,
    )
    wrong_key_envelope = build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=EXECUTION_APPROVAL_V2,
        statement=TrustedTimePostEnrollmentOperatorAttestationStatement(
            authority_artifact_sha256=correct_statement.authority_artifact_sha256,
            public_key_sha256=wrong_authority.public_key_sha256,
            execution_approval_v2_sha256=correct_statement.execution_approval_v2_sha256,
        ),
        signature_ed25519=SIGNATURE,
    )

    for verifier, envelope in (
        (_verifier(wrong_authority), _envelope()),
        (_verifier(), wrong_authority_envelope),
        (_verifier(), wrong_key_envelope),
    ):
        with pytest.raises(
            TrustedTimePostEnrollmentOperatorAttestationVerificationError,
            match="verification failed",
        ):
            verifier.verify(envelope)


def test_wrong_v2_bytes_and_statement_signature_fail_closed() -> None:
    different_v2 = canonical_first_enrollment_json_bytes(
        {
            "contract_version": "phase6d-post-enrollment-start-execution-approval-v2",
            "operation_id": "different-byte-level-artifact",
            "service": "trusted-time-post-enrollment-start-execution-approval",
            "status": "execution_approval_artifact",
        }
    )
    tampered_signature = bytes([SIGNATURE[0] ^ 1]) + SIGNATURE[1:]

    for envelope in (
        _envelope(execution_approval_v2=different_v2),
        _envelope(signature=tampered_signature),
    ):
        with pytest.raises(
            TrustedTimePostEnrollmentOperatorAttestationVerificationError,
            match="verification failed",
        ):
            _verifier().verify(envelope)


def test_verification_uses_only_one_fresh_decoded_envelope_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _envelope()
    expected_envelope_sha256 = envelope.envelope_sha256
    real_canonicalize = canonical_post_enrollment_operator_attestation_envelope_bytes
    calls = 0

    def canonicalize_then_mutate(candidate: object) -> bytes:
        nonlocal calls
        calls += 1
        encoded = real_canonicalize(candidate)
        assert candidate is envelope
        object.__setattr__(envelope.statement, "authority_artifact_sha256", "0" * 64)
        object.__setattr__(
            envelope,
            "signature_ed25519",
            bytes([SIGNATURE[0] ^ 1]) + SIGNATURE[1:],
        )
        object.__setattr__(envelope, "execution_approval_v2", EXECUTION_APPROVAL_V2 + b"\n")
        return encoded

    monkeypatch.setattr(
        adapter,
        "canonical_post_enrollment_operator_attestation_envelope_bytes",
        canonicalize_then_mutate,
    )

    result = _verifier().verify(envelope)

    assert calls == 1
    assert result.operator_attestation_envelope_sha256 == expected_envelope_sha256
    assert result.execution_approval_v2_sha256 == hashlib.sha256(EXECUTION_APPROVAL_V2).hexdigest()


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
def test_non_prime_order_noncanonical_and_off_curve_public_keys_fail_closed(
    public_key: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def bypass_domain_curve_validation(value: object) -> bytes:
        return cast(bytes, value)

    monkeypatch.setattr(
        authority_domain,
        "require_strict_post_enrollment_operator_public_key",
        bypass_domain_curve_validation,
    )
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        _verifier(_authority(public_key))


def test_identity_public_key_universal_signature_forgery_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def bypass_domain_curve_validation(value: object) -> bytes:
        return cast(bytes, value)

    monkeypatch.setattr(
        authority_domain,
        "require_strict_post_enrollment_operator_public_key",
        bypass_domain_curve_validation,
    )
    authority = _authority(IDENTITY_PUBLIC_KEY)
    forged_envelope = _envelope(
        authority=authority,
        signature=IDENTITY_FORGED_SIGNATURE,
    )

    assert len(IDENTITY_FORGED_SIGNATURE) == 64
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority(authority)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="authority is invalid",
    ):
        _verifier(authority).verify(forged_envelope)


def test_mutated_decoded_envelope_and_statement_are_revalidated() -> None:
    envelope = _envelope()
    object.__setattr__(envelope.statement, "authority_artifact_sha256", "0" * 64)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification failed",
    ):
        _verifier().verify(envelope)

    envelope = _envelope()
    object.__setattr__(envelope, "signature_ed25519", b"short")
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification failed",
    ):
        _verifier().verify(envelope)

    envelope = _envelope()
    object.__setattr__(envelope, "execution_approval_v2", EXECUTION_APPROVAL_V2 + b"\n")
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification failed",
    ):
        _verifier().verify(envelope)


@pytest.mark.parametrize(
    "digest_field",
    [
        "authority_artifact_sha256",
        "public_key_sha256",
        "execution_approval_v2_sha256",
        "operator_attestation_statement_sha256",
        "operator_attestation_envelope_sha256",
    ],
)
def test_result_rejects_invalid_digest_and_subclass_construction(digest_field: str) -> None:
    values: dict[str, object] = {
        "authority_artifact_sha256": "1" * 64,
        "public_key_sha256": "2" * 64,
        "execution_approval_v2_sha256": "3" * 64,
        "operator_attestation_statement_sha256": "4" * 64,
        "operator_attestation_envelope_sha256": "5" * 64,
    }
    values[digest_field] = cast(Any, True)
    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        TrustedTimePostEnrollmentOperatorAttestationVerification(
            **cast(Any, values),
            _construction_capability=object(),
        )

    class VerificationSubclass(TrustedTimePostEnrollmentOperatorAttestationVerification):
        pass

    with pytest.raises(
        TrustedTimePostEnrollmentOperatorAttestationVerificationError,
        match="verification is invalid",
    ):
        VerificationSubclass(
            authority_artifact_sha256="1" * 64,
            public_key_sha256="2" * 64,
            execution_approval_v2_sha256="3" * 64,
            operator_attestation_statement_sha256="4" * 64,
            operator_attestation_envelope_sha256="5" * 64,
            _construction_capability=object(),
        )


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
        "cryptography.exceptions",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        "packages.domain.trusted_time_post_enrollment_operator_attestation",
        "packages.domain.trusted_time_post_enrollment_operator_authority",
    }

    assert imported_modules <= allowed_modules
    assert "Ed25519PrivateKey" not in source
    assert "private_key" not in source
    assert "sign(" not in source
    assert not any(type(value) is bytes and len(value) == 32 for value in vars(adapter).values())
    assert not any("default" in name.lower() for name in vars(adapter))
