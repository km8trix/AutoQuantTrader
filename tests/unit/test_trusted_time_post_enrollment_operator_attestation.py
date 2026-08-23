from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from typing import Any, cast

import pytest

import packages.domain.trusted_time_post_enrollment_operator_attestation as attestation_module
from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
    EXECUTION_APPROVAL_V2_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS,
    TrustedTimePostEnrollmentOperatorAttestationEnvelope,
    TrustedTimePostEnrollmentOperatorAttestationError,
    TrustedTimePostEnrollmentOperatorAttestationStatement,
    build_post_enrollment_operator_attestation_envelope,
    build_post_enrollment_operator_attestation_statement,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
    canonical_post_enrollment_operator_attestation_statement_bytes,
    decode_post_enrollment_operator_attestation_envelope,
    decode_post_enrollment_operator_attestation_statement,
    post_enrollment_operator_attestation_envelope_sha256,
    post_enrollment_operator_attestation_statement_sha256,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    TrustedTimePostEnrollmentOperatorAuthority,
    build_post_enrollment_operator_authority,
)

PUBLIC_KEY_BYTES = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
SIGNATURE_BYTES = bytes(range(64))
AUTHORITY_ARTIFACT_SHA256 = "e85bb071696c484a08c93284dd7d67e3e52d83734ef732c3a33722e5dc6d673e"
PUBLIC_KEY_SHA256 = "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f"
EXECUTION_APPROVAL_V2_SHA256 = "bd4d326f98cd356da151138ab868995b48a87a037c0f5e51a21111098603687b"
STATEMENT_SHA256 = "52d236fa861a42804e71d4d29fd76699d78d4f6b823c6d2d4e4e36c6bc6a8b9d"
ENVELOPE_SHA256 = "4ea5d1e5b24398064a9f6d5cffe66ca5886b425a404793c44b9546c5c01b04a0"

EXECUTION_APPROVAL_V2_BYTES = (
    b'{"approval":{"opaque":true},"contract_version":'
    b'"phase6d-post-enrollment-start-execution-approval-v2",'
    b'"service":"trusted-time-post-enrollment-start-execution-approval",'
    b'"status":"execution_approval_artifact"}\n'
)
EXPECTED_STATEMENT_BYTES = (
    b'{"algorithm":"Ed25519","authority_artifact_sha256":'
    b'"e85bb071696c484a08c93284dd7d67e3e52d83734ef732c3a33722e5dc6d673e",'
    b'"authority_contract_version":'
    b'"phase6d-post-enrollment-operator-attestation-authority-v1",'
    b'"contract_version":'
    b'"phase6d-post-enrollment-start-operator-attestation-statement-v1",'
    b'"decision":"approve_one_post_enrollment_start_attempt",'
    b'"execution_approval_contract_version":'
    b'"phase6d-post-enrollment-start-execution-approval-v2",'
    b'"execution_approval_v2_sha256":'
    b'"bd4d326f98cd356da151138ab868995b48a87a037c0f5e51a21111098603687b",'
    b'"key_id":"aqt-post-enrollment-start-operator-ed25519-v1",'
    b'"public_key_sha256":'
    b'"39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f",'
    b'"replay_domain":"github.com/km8trix/AutoQuantTrader/production/trusted-time/'
    b'post-enrollment-start/operator-attestation/v1",'
    b'"service":"trusted-time-post-enrollment-start-operator-attestation",'
    b'"status":"exact_one_attempt_execution_approval_statement"}\n'
)


def _authority() -> TrustedTimePostEnrollmentOperatorAuthority:
    return build_post_enrollment_operator_authority(PUBLIC_KEY_BYTES)


def _v2_payload() -> dict[str, object]:
    return {
        "approval": {"opaque": True},
        "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
        "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
        "status": EXECUTION_APPROVAL_V2_STATUS,
    }


def _statement() -> TrustedTimePostEnrollmentOperatorAttestationStatement:
    return build_post_enrollment_operator_attestation_statement(
        authority=_authority(),
        execution_approval_v2_sha256=hashlib.sha256(EXECUTION_APPROVAL_V2_BYTES).hexdigest(),
    )


def _envelope() -> TrustedTimePostEnrollmentOperatorAttestationEnvelope:
    return build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=EXECUTION_APPROVAL_V2_BYTES,
        statement=_statement(),
        signature_ed25519=SIGNATURE_BYTES,
    )


def _encoded(payload: object) -> bytes:
    return canonical_first_enrollment_json_bytes(payload)


def _statement_payload() -> dict[str, object]:
    return _statement().payload()


def _envelope_payload() -> dict[str, object]:
    return _envelope().payload()


def test_statement_has_exact_frozen_fields_bytes_and_digests() -> None:
    statement = _statement()

    assert _authority().authority_sha256 == AUTHORITY_ARTIFACT_SHA256
    assert _authority().public_key_sha256 == PUBLIC_KEY_SHA256
    assert hashlib.sha256(EXECUTION_APPROVAL_V2_BYTES).hexdigest() == EXECUTION_APPROVAL_V2_SHA256
    assert statement.payload() == {
        "algorithm": "Ed25519",
        "authority_artifact_sha256": AUTHORITY_ARTIFACT_SHA256,
        "authority_contract_version": ("phase6d-post-enrollment-operator-attestation-authority-v1"),
        "contract_version": ("phase6d-post-enrollment-start-operator-attestation-statement-v1"),
        "decision": "approve_one_post_enrollment_start_attempt",
        "execution_approval_contract_version": (
            "phase6d-post-enrollment-start-execution-approval-v2"
        ),
        "execution_approval_v2_sha256": EXECUTION_APPROVAL_V2_SHA256,
        "key_id": "aqt-post-enrollment-start-operator-ed25519-v1",
        "public_key_sha256": PUBLIC_KEY_SHA256,
        "replay_domain": (
            "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
            "post-enrollment-start/operator-attestation/v1"
        ),
        "service": "trusted-time-post-enrollment-start-operator-attestation",
        "status": "exact_one_attempt_execution_approval_statement",
    }
    assert set(statement.payload()) == POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS
    assert statement.encoded == EXPECTED_STATEMENT_BYTES
    assert statement.encoded.endswith(b"\n")
    assert statement.encoded.count(b"\n") == 1
    assert statement.statement_sha256 == STATEMENT_SHA256
    assert (
        canonical_post_enrollment_operator_attestation_statement_bytes(statement)
        == EXPECTED_STATEMENT_BYTES
    )
    assert post_enrollment_operator_attestation_statement_sha256(statement) == STATEMENT_SHA256


def test_statement_constants_are_the_exact_protocol_identity() -> None:
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-operator-attestation-statement-v1"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE
        == "trusted-time-post-enrollment-start-operator-attestation"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS
        == "exact_one_attempt_execution_approval_statement"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION == "approve_one_post_enrollment_start_attempt"
    )
    assert (
        EXECUTION_APPROVAL_V2_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-approval-v2"
    )
    assert EXECUTION_APPROVAL_V2_STATUS == "execution_approval_artifact"
    assert POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES == 4_096
    assert POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES == 65_536


def test_statement_round_trip_preserves_exact_signed_bytes() -> None:
    decoded = decode_post_enrollment_operator_attestation_statement(EXPECTED_STATEMENT_BYTES)

    assert decoded == _statement()
    assert decoded.encoded == EXPECTED_STATEMENT_BYTES
    assert decoded.statement_sha256 == STATEMENT_SHA256


def test_statement_builder_derives_only_the_explicit_authority_identity() -> None:
    authority = _authority()
    statement = build_post_enrollment_operator_attestation_statement(
        authority=authority,
        execution_approval_v2_sha256="a" * 64,
    )

    assert statement.authority_artifact_sha256 == authority.authority_sha256
    assert statement.public_key_sha256 == authority.public_key_sha256
    assert statement.execution_approval_v2_sha256 == "a" * 64


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("algorithm", "ed25519"),
        ("authority_contract_version", "authority-v2"),
        ("contract_version", "statement-v2"),
        ("decision", "approve_all_attempts"),
        ("execution_approval_contract_version", "execution-approval-v1"),
        ("key_id", "aqt-trusted-time-anchor-ed25519-v1"),
        ("replay_domain", "github.com/km8trix/AutoQuantTrader/test"),
        ("service", "trusted-time-post-enrollment-start"),
        ("status", "approved"),
    ],
)
def test_statement_decoder_rejects_every_fixed_scope_mutation(
    field_name: str,
    replacement: str,
) -> None:
    payload = _statement_payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_statement(_encoded(payload))


@pytest.mark.parametrize(
    "field_name",
    [
        "authority_artifact_sha256",
        "public_key_sha256",
        "execution_approval_v2_sha256",
    ],
)
@pytest.mark.parametrize("replacement", [True, "0" * 63, "0" * 65, "A" * 64, "g" * 64])
def test_statement_rejects_every_malformed_dynamic_digest(
    field_name: str,
    replacement: object,
) -> None:
    payload = _statement_payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_statement(_encoded(payload))


@pytest.mark.parametrize(
    "field_name", sorted(POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS)
)
def test_statement_decoder_rejects_wrong_type_for_every_field(field_name: str) -> None:
    payload = _statement_payload()
    payload[field_name] = True

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_statement(_encoded(payload))


def test_statement_decoder_rejects_duplicate_extra_and_missing_fields() -> None:
    duplicate = EXPECTED_STATEMENT_BYTES.replace(
        b'{"algorithm":"Ed25519",',
        b'{"algorithm":"Ed25519","algorithm":"Ed25519",',
        1,
    )
    extra = _statement_payload()
    extra["unexpected"] = False
    missing = _statement_payload()
    del missing["status"]

    for candidate in (duplicate, _encoded(extra), _encoded(missing)):
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            decode_post_enrollment_operator_attestation_statement(candidate)


def test_statement_decoder_rejects_noncanonical_and_oversized_json() -> None:
    payload = _statement_payload()
    candidates = (
        EXPECTED_STATEMENT_BYTES.removesuffix(b"\n"),
        EXPECTED_STATEMENT_BYTES + b"\n",
        b" " + EXPECTED_STATEMENT_BYTES,
        json.dumps(payload, sort_keys=True).encode("ascii") + b"\n",
        json.dumps(payload, indent=2, sort_keys=True).encode("ascii") + b"\n",
        b" " * (POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES + 1),
    )

    for candidate in candidates:
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            decode_post_enrollment_operator_attestation_statement(candidate)


@pytest.mark.parametrize(
    "encoded",
    [
        None,
        True,
        "{}\n",
        bytearray(b"{}\n"),
        memoryview(b"{}\n"),
        b"",
        b"{}\n",
        b"[]\n",
        b"null\n",
        b'{"value":NaN}\n',
        b"\xff\n",
    ],
)
def test_statement_decoder_rejects_malformed_container_types_and_json(encoded: object) -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_statement(encoded)


@pytest.mark.parametrize("digest", [None, True, b"0" * 64, "", "0" * 63, "A" * 64])
def test_statement_builder_and_value_object_reject_malformed_inputs(digest: object) -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_statement(
            authority=_authority(),
            execution_approval_v2_sha256=cast(Any, digest),
        )
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        TrustedTimePostEnrollmentOperatorAttestationStatement(
            authority_artifact_sha256=cast(Any, digest),
            public_key_sha256=PUBLIC_KEY_SHA256,
            execution_approval_v2_sha256=EXECUTION_APPROVAL_V2_SHA256,
        )


def test_statement_builder_rejects_wrong_subclass_and_mutated_authority() -> None:
    class AuthoritySubclass(TrustedTimePostEnrollmentOperatorAuthority):
        pass

    subclass = AuthoritySubclass(public_key_bytes=PUBLIC_KEY_BYTES)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_statement(
            authority=cast(Any, subclass),
            execution_approval_v2_sha256=EXECUTION_APPROVAL_V2_SHA256,
        )

    authority = _authority()
    object.__setattr__(authority, "public_key_bytes", b"short")
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_statement(
            authority=authority,
            execution_approval_v2_sha256=EXECUTION_APPROVAL_V2_SHA256,
        )


def test_envelope_has_exact_frozen_fields_bytes_and_digests() -> None:
    envelope = _envelope()
    payload = envelope.payload()

    assert payload == {
        "contract_version": "phase6d-post-enrollment-start-execution-approval-v3",
        "execution_approval_v2_base64": base64.b64encode(EXECUTION_APPROVAL_V2_BYTES).decode(
            "ascii"
        ),
        "execution_approval_v2_sha256": EXECUTION_APPROVAL_V2_SHA256,
        "operator_attestation_statement": _statement().payload(),
        "operator_attestation_statement_sha256": STATEMENT_SHA256,
        "service": "trusted-time-post-enrollment-start-execution-approval",
        "signature_algorithm": "Ed25519",
        "signature_base64": base64.b64encode(SIGNATURE_BYTES).decode("ascii"),
        "status": "operator_attested_execution_approval_envelope",
    }
    assert set(payload) == POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS
    expected_bytes = canonical_first_enrollment_json_bytes(payload)
    assert envelope.encoded == expected_bytes
    assert envelope.encoded.endswith(b"\n")
    assert envelope.encoded.count(b"\n") == 1
    assert envelope.envelope_sha256 == ENVELOPE_SHA256
    assert canonical_post_enrollment_operator_attestation_envelope_bytes(envelope) == expected_bytes
    assert post_enrollment_operator_attestation_envelope_sha256(envelope) == ENVELOPE_SHA256


def test_envelope_constants_are_the_exact_protocol_identity() -> None:
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION
        == "phase6d-post-enrollment-start-execution-approval-v3"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE
        == "trusted-time-post-enrollment-start-execution-approval"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS
        == "operator_attested_execution_approval_envelope"
    )
    assert (
        POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_FIELDS
        == POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS
    )
    assert POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES == 131_072


def test_envelope_round_trip_preserves_every_exact_byte_relationship() -> None:
    original = _envelope()
    decoded = decode_post_enrollment_operator_attestation_envelope(original.encoded)

    assert decoded == original
    assert decoded.execution_approval_v2 is not original.execution_approval_v2
    assert decoded.execution_approval_v2 == EXECUTION_APPROVAL_V2_BYTES
    assert decoded.statement.encoded == EXPECTED_STATEMENT_BYTES
    assert decoded.signature_ed25519 == SIGNATURE_BYTES
    assert decoded.encoded == original.encoded
    assert decoded.envelope_sha256 == ENVELOPE_SHA256


def test_envelope_accepts_only_structural_v2_identity_without_semantic_decoding() -> None:
    opaque_v2 = _encoded(
        {
            "approval": "deliberately-not-a-semantic-v2-approval-object",
            "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
            "extra_top_level_field": [None, False, 7],
            "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
            "status": EXECUTION_APPROVAL_V2_STATUS,
        }
    )
    statement = build_post_enrollment_operator_attestation_statement(
        authority=_authority(),
        execution_approval_v2_sha256=hashlib.sha256(opaque_v2).hexdigest(),
    )

    envelope = build_post_enrollment_operator_attestation_envelope(
        execution_approval_v2=opaque_v2,
        statement=statement,
        signature_ed25519=SIGNATURE_BYTES,
    )

    assert decode_post_enrollment_operator_attestation_envelope(envelope.encoded) == envelope


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("contract_version", "phase6d-post-enrollment-start-execution-approval-v2"),
        ("service", "trusted-time-post-enrollment-start"),
        ("signature_algorithm", "Ed25519ph"),
        ("status", "execution_approval_artifact"),
    ],
)
def test_envelope_decoder_rejects_every_fixed_scope_mutation(
    field_name: str,
    replacement: str,
) -> None:
    payload = _envelope_payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


@pytest.mark.parametrize(
    "field_name", sorted(POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS)
)
def test_envelope_decoder_rejects_wrong_type_for_every_field(field_name: str) -> None:
    payload = _envelope_payload()
    payload[field_name] = True

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


def test_envelope_decoder_rejects_duplicate_extra_and_missing_fields() -> None:
    canonical = _envelope().encoded
    duplicate = canonical.replace(
        b'{"contract_version":',
        b'{"contract_version":"phase6d-post-enrollment-start-execution-approval-v3",'
        b'"contract_version":',
        1,
    )
    nested_duplicate = canonical.replace(
        b'{"algorithm":"Ed25519",',
        b'{"algorithm":"Ed25519","algorithm":"Ed25519",',
        1,
    )
    extra = _envelope_payload()
    extra["unexpected"] = False
    missing = _envelope_payload()
    del missing["status"]

    for candidate in (duplicate, nested_duplicate, _encoded(extra), _encoded(missing)):
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            decode_post_enrollment_operator_attestation_envelope(candidate)


def test_envelope_decoder_rejects_noncanonical_and_oversized_json() -> None:
    canonical = _envelope().encoded
    payload = _envelope_payload()
    candidates = (
        canonical.removesuffix(b"\n"),
        canonical + b"\n",
        b" " + canonical,
        json.dumps(payload, sort_keys=True).encode("ascii") + b"\n",
        json.dumps(payload, indent=2, sort_keys=True).encode("ascii") + b"\n",
        b" " * (POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES + 1),
    )

    for candidate in candidates:
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            decode_post_enrollment_operator_attestation_envelope(candidate)


@pytest.mark.parametrize(
    "encoded",
    [
        None,
        True,
        "{}\n",
        bytearray(b"{}\n"),
        memoryview(b"{}\n"),
        b"",
        b"{}\n",
        b"[]\n",
        b"null\n",
        b'{"value":Infinity}\n',
        b"\xff\n",
        EXECUTION_APPROVAL_V2_BYTES,
    ],
)
def test_envelope_decoder_rejects_malformed_container_json_and_unsigned_v2(
    encoded: object,
) -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(encoded)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("execution_approval_v2_sha256", "0" * 64),
        ("execution_approval_v2_sha256", "A" * 64),
        ("operator_attestation_statement_sha256", "0" * 64),
        ("operator_attestation_statement_sha256", "g" * 64),
    ],
)
def test_envelope_decoder_rejects_malformed_or_mismatched_digest_bindings(
    field_name: str,
    replacement: str,
) -> None:
    payload = _envelope_payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


def test_envelope_decoder_rejects_any_v2_change_without_all_exact_bindings() -> None:
    changed_v2 = _encoded(
        {
            **_v2_payload(),
            "approval": {"opaque": False},
        }
    )
    payload = _envelope_payload()
    payload["execution_approval_v2_base64"] = base64.b64encode(changed_v2).decode("ascii")

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))

    changed_sha256 = hashlib.sha256(changed_v2).hexdigest()
    payload["execution_approval_v2_sha256"] = changed_sha256
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


def test_envelope_decoder_rejects_any_nested_statement_change_without_its_digest() -> None:
    payload = _envelope_payload()
    nested = cast(dict[str, object], payload["operator_attestation_statement"])
    nested["authority_artifact_sha256"] = "0" * 64

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


@pytest.mark.parametrize(
    "base64_value",
    [
        "not-base64!",
        " Zm9v",
        "Zm9v\n",
        "Zm9v=",
        "Zm9v===",
    ],
)
def test_envelope_decoder_rejects_noncanonical_v2_base64(base64_value: str) -> None:
    payload = _envelope_payload()
    payload["execution_approval_v2_base64"] = base64_value

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


@pytest.mark.parametrize(
    "signature_base64",
    [
        "not-base64!",
        base64.b64encode(SIGNATURE_BYTES).decode("ascii").removesuffix("="),
        base64.b64encode(SIGNATURE_BYTES).decode("ascii").replace("+", "-"),
        base64.b64encode(SIGNATURE_BYTES).decode("ascii") + "\n",
        base64.b64encode(SIGNATURE_BYTES[:-1]).decode("ascii"),
        base64.b64encode(SIGNATURE_BYTES + b"x").decode("ascii"),
    ],
)
def test_envelope_decoder_rejects_noncanonical_or_wrong_length_signature_base64(
    signature_base64: str,
) -> None:
    payload = _envelope_payload()
    payload["signature_base64"] = signature_base64

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        decode_post_enrollment_operator_attestation_envelope(_encoded(payload))


def test_envelope_codec_preserves_but_does_not_authenticate_a_64_byte_signature_change() -> None:
    changed_signature = bytes([SIGNATURE_BYTES[0] ^ 1, *SIGNATURE_BYTES[1:]])
    payload = _envelope_payload()
    payload["signature_base64"] = base64.b64encode(changed_signature).decode("ascii")

    decoded = decode_post_enrollment_operator_attestation_envelope(_encoded(payload))

    assert decoded.signature_ed25519 == changed_signature
    assert decoded.statement == _statement()


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("contract_version", "phase6d-post-enrollment-start-execution-approval-v1"),
        ("service", "trusted-time-post-enrollment-start"),
        ("status", "approved"),
        ("contract_version", True),
        ("service", None),
        ("status", 1),
    ],
)
def test_envelope_rejects_wrong_v2_top_level_identity(
    field_name: str,
    replacement: object,
) -> None:
    payload = _v2_payload()
    payload[field_name] = replacement
    v2 = _encoded(payload)
    statement = build_post_enrollment_operator_attestation_statement(
        authority=_authority(),
        execution_approval_v2_sha256=hashlib.sha256(v2).hexdigest(),
    )

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_envelope(
            execution_approval_v2=v2,
            statement=statement,
            signature_ed25519=SIGNATURE_BYTES,
        )


@pytest.mark.parametrize(
    "v2",
    [
        b"",
        b"{}\n",
        b"[]\n",
        b"null\n",
        EXECUTION_APPROVAL_V2_BYTES.removesuffix(b"\n"),
        EXECUTION_APPROVAL_V2_BYTES + b"\n",
        b" " + EXECUTION_APPROVAL_V2_BYTES,
        EXECUTION_APPROVAL_V2_BYTES.replace(b'{"approval":', b'{"approval":null,"approval":', 1),
    ],
)
def test_envelope_rejects_malformed_noncanonical_or_duplicate_v2(v2: bytes) -> None:
    statement = build_post_enrollment_operator_attestation_statement(
        authority=_authority(),
        execution_approval_v2_sha256=hashlib.sha256(v2).hexdigest(),
    )

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_envelope(
            execution_approval_v2=v2,
            statement=statement,
            signature_ed25519=SIGNATURE_BYTES,
        )


def test_envelope_rejects_v2_over_the_exact_byte_limit() -> None:
    oversized_v2 = _encoded(
        {
            **_v2_payload(),
            "padding": "x"
            * POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES,
        }
    )
    statement = build_post_enrollment_operator_attestation_statement(
        authority=_authority(),
        execution_approval_v2_sha256=hashlib.sha256(oversized_v2).hexdigest(),
    )

    assert (
        len(oversized_v2) > POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES
    )
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_envelope(
            execution_approval_v2=oversized_v2,
            statement=statement,
            signature_ed25519=SIGNATURE_BYTES,
        )


@pytest.mark.parametrize(
    ("execution_approval_v2", "statement", "signature"),
    [
        (bytearray(EXECUTION_APPROVAL_V2_BYTES), None, SIGNATURE_BYTES),
        (memoryview(EXECUTION_APPROVAL_V2_BYTES), None, SIGNATURE_BYTES),
        (EXECUTION_APPROVAL_V2_BYTES, object(), SIGNATURE_BYTES),
        (EXECUTION_APPROVAL_V2_BYTES, None, bytearray(SIGNATURE_BYTES)),
        (EXECUTION_APPROVAL_V2_BYTES, None, memoryview(SIGNATURE_BYTES)),
        (EXECUTION_APPROVAL_V2_BYTES, None, SIGNATURE_BYTES[:-1]),
        (EXECUTION_APPROVAL_V2_BYTES, None, SIGNATURE_BYTES + b"x"),
    ],
)
def test_envelope_builder_and_value_object_reject_wrong_member_types_and_lengths(
    execution_approval_v2: object,
    statement: object,
    signature: object,
) -> None:
    exact_statement: object = _statement() if statement is None else statement
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_envelope(
            execution_approval_v2=cast(Any, execution_approval_v2),
            statement=cast(Any, exact_statement),
            signature_ed25519=cast(Any, signature),
        )
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        TrustedTimePostEnrollmentOperatorAttestationEnvelope(
            execution_approval_v2=cast(Any, execution_approval_v2),
            statement=cast(Any, exact_statement),
            signature_ed25519=cast(Any, signature),
        )


def test_envelope_builder_rejects_a_v2_digest_that_differs_from_the_statement() -> None:
    statement = build_post_enrollment_operator_attestation_statement(
        authority=_authority(),
        execution_approval_v2_sha256="0" * 64,
    )

    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        build_post_enrollment_operator_attestation_envelope(
            execution_approval_v2=EXECUTION_APPROVAL_V2_BYTES,
            statement=statement,
            signature_ed25519=SIGNATURE_BYTES,
        )


def test_canonical_helpers_reject_wrong_subclass_and_mutated_objects() -> None:
    class StatementSubclass(TrustedTimePostEnrollmentOperatorAttestationStatement):
        pass

    class EnvelopeSubclass(TrustedTimePostEnrollmentOperatorAttestationEnvelope):
        pass

    statement_subclass = StatementSubclass(
        authority_artifact_sha256=AUTHORITY_ARTIFACT_SHA256,
        public_key_sha256=PUBLIC_KEY_SHA256,
        execution_approval_v2_sha256=EXECUTION_APPROVAL_V2_SHA256,
    )
    envelope_subclass = EnvelopeSubclass(
        execution_approval_v2=EXECUTION_APPROVAL_V2_BYTES,
        statement=_statement(),
        signature_ed25519=SIGNATURE_BYTES,
    )
    for statement_helper in (
        canonical_post_enrollment_operator_attestation_statement_bytes,
        post_enrollment_operator_attestation_statement_sha256,
    ):
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            statement_helper(statement_subclass)
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            statement_helper(object())
    for envelope_helper in (
        canonical_post_enrollment_operator_attestation_envelope_bytes,
        post_enrollment_operator_attestation_envelope_sha256,
    ):
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            envelope_helper(envelope_subclass)
        with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
            envelope_helper(object())

    statement = _statement()
    object.__setattr__(statement, "execution_approval_v2_sha256", "invalid")
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        canonical_post_enrollment_operator_attestation_statement_bytes(statement)

    envelope = _envelope()
    object.__setattr__(envelope, "signature_ed25519", b"short")
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError, match="invalid"):
        canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)


def test_codec_is_inert_and_grants_no_authority() -> None:
    statement_payload = _statement_payload()
    envelope_payload = _envelope_payload()
    combined_fields = set(statement_payload) | set(envelope_payload)
    public_api = set(attestation_module.__all__)

    assert combined_fields.isdisjoint(FIRST_ENROLLMENT_AUTHORITY_FIELDS)
    assert not any(field_name.endswith("_authorized") for field_name in combined_fields)
    assert "authority_granted" not in combined_fields
    assert "verification_only" not in combined_fields
    assert not any("signer" in name.lower() or "private" in name.lower() for name in public_api)
    assert not any("loader" in name.lower() or "execute" in name.lower() for name in public_api)


@pytest.mark.parametrize(
    "decoder",
    [
        decode_post_enrollment_operator_attestation_statement,
        decode_post_enrollment_operator_attestation_envelope,
    ],
)
def test_decoders_collapse_internal_failures_to_one_domain_error(
    decoder: Callable[[object], object],
) -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAttestationError) as raised:
        decoder(object())

    assert str(raised.value) == "trusted-time post-enrollment operator attestation is invalid"
