from __future__ import annotations

import ast
import base64
import copy
import hashlib
import pickle
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from packages.domain import (
    trusted_time_post_enrollment_graceful_stop_operator_attestation as stop_attestation,
)
from packages.domain.trusted_time_enrollment_evidence import (
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_SERVICE,
    POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_STATUS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_FIELDS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationError,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement,
    build_post_enrollment_graceful_stop_operator_attestation_envelope,
    build_post_enrollment_graceful_stop_operator_attestation_statement,
    canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes,
    canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes,
    decode_post_enrollment_graceful_stop_operator_attestation_envelope,
    decode_post_enrollment_graceful_stop_operator_attestation_statement,
    post_enrollment_graceful_stop_operator_attestation_envelope_sha256,
    post_enrollment_graceful_stop_operator_attestation_statement_sha256,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    build_post_enrollment_graceful_stop_operator_authority,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    build_post_enrollment_operator_authority,
)

PUBLIC_KEY_BYTES = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
SIGNATURE_BYTES = bytes(range(64))
OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001"
TARGET_SHA256 = "a" * 64
AUTHORITY_SHA256 = "b0b6935d8b9573e55d68f7eb9fb639f71127e34d30110ee06c3613acbdc31db8"
PUBLIC_KEY_SHA256 = "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f"
DECISION_SHA256 = "096b72151828967cc2c63102e1220b77f89b5781373a38b61de41aa52af99b74"
STATEMENT_SHA256 = "71c1e32e410b91441cb5258e954760452a1477a54262526fa8830f41738bf09e"
ENVELOPE_SHA256 = "1f92c26c002137cbc93c41880c16d5db7d807f40e66f767da4adf941d5ffe0c4"


def _authority() -> TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
    return build_post_enrollment_graceful_stop_operator_authority(PUBLIC_KEY_BYTES)


def _decision_payload(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract_version": POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION,
        "graceful_stop_target_sha256": TARGET_SHA256,
        "opaque_unqualified_projection": {"current": False, "sequence": [1, 2, 3]},
        "operation_id": OPERATION_ID,
        "service": POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_SERVICE,
        "status": POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_STATUS,
    }
    payload.update(changes)
    return payload


def _decision_bytes(**changes: object) -> bytes:
    return canonical_first_enrollment_json_bytes(_decision_payload(**changes))


def _statement(
    *,
    decision_bytes: bytes | None = None,
    operation_id: str = OPERATION_ID,
    target_sha256: str = TARGET_SHA256,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
    encoded = decision_bytes if decision_bytes is not None else _decision_bytes()
    return build_post_enrollment_graceful_stop_operator_attestation_statement(
        authority=_authority(),
        graceful_stop_decision_v1_sha256=hashlib.sha256(encoded).hexdigest(),
        graceful_stop_operation_id=operation_id,
        graceful_stop_target_sha256=target_sha256,
    )


def _envelope(
    *,
    decision_bytes: bytes | None = None,
    statement: TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement | None = None,
    signature: bytes = SIGNATURE_BYTES,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
    encoded = decision_bytes if decision_bytes is not None else _decision_bytes()
    exact_statement = statement if statement is not None else _statement(decision_bytes=encoded)
    return build_post_enrollment_graceful_stop_operator_attestation_envelope(
        graceful_stop_decision_v1=encoded,
        statement=exact_statement,
        signature_ed25519=signature,
    )


def _canonical(payload: object) -> bytes:
    return canonical_first_enrollment_json_bytes(payload)


def test_statement_freezes_exact_stop_protocol_and_digest_bindings() -> None:
    authority = _authority()
    decision = _decision_bytes()
    statement = _statement(decision_bytes=decision)
    expected = {
        "algorithm": "Ed25519",
        "authority_artifact_sha256": authority.authority_sha256,
        "authority_contract_version": (
            "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-v1"
        ),
        "contract_version": (
            "phase6d-post-enrollment-graceful-stop-operator-attestation-statement-v1"
        ),
        "decision": "approve_one_post_enrollment_graceful_stop_attempt",
        "graceful_stop_decision_contract_version": (
            "phase6d-post-enrollment-graceful-stop-decision-v1"
        ),
        "graceful_stop_decision_v1_sha256": hashlib.sha256(decision).hexdigest(),
        "graceful_stop_operation_id": OPERATION_ID,
        "graceful_stop_target_sha256": TARGET_SHA256,
        "key_id": "aqt-post-enrollment-graceful-stop-operator-ed25519-v1",
        "public_key_sha256": authority.public_key_sha256,
        "replay_domain": (
            "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
            "post-enrollment-graceful-stop/operator-attestation/v1"
        ),
        "service": "trusted-time-post-enrollment-graceful-stop-operator-attestation",
        "status": "exact_one_attempt_graceful_stop_decision_statement",
    }

    assert statement.payload() == expected
    assert authority.authority_sha256 == AUTHORITY_SHA256
    assert authority.public_key_sha256 == PUBLIC_KEY_SHA256
    assert hashlib.sha256(decision).hexdigest() == DECISION_SHA256
    assert set(expected) == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS
    assert statement.encoded == _canonical(expected)
    assert statement.encoded.endswith(b"\n")
    assert statement.encoded.count(b"\n") == 1
    assert statement.statement_sha256 == hashlib.sha256(statement.encoded).hexdigest()
    assert statement.statement_sha256 == STATEMENT_SHA256
    assert (
        canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
        == statement.encoded
    )
    assert (
        post_enrollment_graceful_stop_operator_attestation_statement_sha256(statement)
        == statement.statement_sha256
    )


def test_constants_are_distinct_from_start_and_match_the_frozen_stop_decision() -> None:
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-operator-attestation-statement-v1"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE == (
        "trusted-time-post-enrollment-graceful-stop-operator-attestation"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS == (
        "exact_one_attempt_graceful_stop_decision_statement"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION == (
        "approve_one_post_enrollment_graceful_stop_attempt"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN.endswith(
        "/post-enrollment-graceful-stop/operator-attestation/v1"
    )
    assert "/post-enrollment-start/" not in (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID != (
        "aqt-post-enrollment-start-operator-ed25519-v1"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-v1"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION == (
        "phase6d-post-enrollment-graceful-stop-decision-v2"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE == (
        "trusted-time-post-enrollment-graceful-stop"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS == (
        "operator_attested_graceful_stop_decision_envelope"
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES == 4_096
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES == (
        128 * 1_024
    )
    assert POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES == 256 * 1_024


def test_statement_round_trip_is_exact_and_payloads_are_isolated() -> None:
    statement = _statement()
    decoded = decode_post_enrollment_graceful_stop_operator_attestation_statement(statement.encoded)
    first = statement.payload()
    first["status"] = "mutated"

    assert decoded == statement
    assert decoded is not statement
    assert decoded.encoded == statement.encoded
    assert statement.payload()["status"] == (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS
    )


def test_statement_builder_rejects_start_authority_and_mutated_stop_authority() -> None:
    start_authority = build_post_enrollment_operator_authority(PUBLIC_KEY_BYTES)
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        build_post_enrollment_graceful_stop_operator_attestation_statement(
            authority=cast(Any, start_authority),
            graceful_stop_decision_v1_sha256="1" * 64,
            graceful_stop_operation_id=OPERATION_ID,
            graceful_stop_target_sha256=TARGET_SHA256,
        )

    stop_authority = _authority()
    object.__setattr__(stop_authority, "public_key_bytes", b"short")
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        build_post_enrollment_graceful_stop_operator_attestation_statement(
            authority=stop_authority,
            graceful_stop_decision_v1_sha256="1" * 64,
            graceful_stop_operation_id=OPERATION_ID,
            graceful_stop_target_sha256=TARGET_SHA256,
        )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("algorithm", "ed25519"),
        ("authority_contract_version", "phase6d-post-enrollment-operator-attestation-authority-v1"),
        ("contract_version", "statement-v2"),
        ("decision", "approve_one_post_enrollment_start_attempt"),
        ("graceful_stop_decision_contract_version", "decision-v2"),
        ("key_id", "aqt-post-enrollment-start-operator-ed25519-v1"),
        (
            "replay_domain",
            "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
            "post-enrollment-start/operator-attestation/v1",
        ),
        ("service", "trusted-time-post-enrollment-start-operator-attestation"),
        ("status", "approved"),
    ],
)
def test_statement_rejects_fixed_scope_and_cross_protocol_mutations(
    field_name: str,
    replacement: str,
) -> None:
    payload = _statement().payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_statement(_canonical(payload))


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("authority_artifact_sha256", True),
        ("authority_artifact_sha256", "A" * 64),
        ("public_key_sha256", "0" * 63),
        ("graceful_stop_decision_v1_sha256", "g" * 64),
        ("graceful_stop_target_sha256", ["0" * 64]),
        ("graceful_stop_operation_id", "123e4567-e89b-12d3-a456-426614174000"),
        ("graceful_stop_operation_id", "223E4567-E89B-42D3-A456-426614174001"),
    ],
)
def test_statement_rejects_bad_hashes_and_noncanonical_uuid4(
    field_name: str,
    replacement: object,
) -> None:
    payload = _statement().payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_statement(_canonical(payload))


def test_statement_rejects_duplicate_extra_missing_noncanonical_and_size() -> None:
    encoded = _statement().encoded
    duplicate = encoded.replace(
        b'{"algorithm":"Ed25519",',
        b'{"algorithm":"Ed25519","algorithm":"Ed25519",',
        1,
    )
    extra = _statement().payload()
    extra["unexpected"] = False
    missing = _statement().payload()
    del missing["status"]
    candidates = (
        duplicate,
        _canonical(extra),
        _canonical(missing),
        encoded.removesuffix(b"\n"),
        b" " + encoded,
        encoded + b"\n",
        b" " * (POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES + 1),
    )
    for candidate in candidates:
        with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
            decode_post_enrollment_graceful_stop_operator_attestation_statement(candidate)


@pytest.mark.parametrize(
    "value",
    [None, True, "{}\n", bytearray(b"{}\n"), b"", b"{}\n", b"[]\n", b"null\n", b"\xff\n"],
)
def test_statement_decoder_and_builder_reject_wrong_container_types(value: object) -> None:
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_statement(value)
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        build_post_enrollment_graceful_stop_operator_attestation_statement(
            authority=_authority(),
            graceful_stop_decision_v1_sha256=cast(Any, value),
            graceful_stop_operation_id=OPERATION_ID,
            graceful_stop_target_sha256=TARGET_SHA256,
        )


def test_envelope_freezes_exact_fields_bytes_and_digests() -> None:
    envelope = _envelope()
    payload = envelope.payload()

    assert set(payload) == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS
    assert (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_FIELDS
        == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS
    )
    assert payload == {
        "contract_version": "phase6d-post-enrollment-graceful-stop-decision-v2",
        "graceful_stop_decision_v1_base64": base64.b64encode(_decision_bytes()).decode("ascii"),
        "graceful_stop_decision_v1_sha256": hashlib.sha256(_decision_bytes()).hexdigest(),
        "operator_attestation_statement": _statement().payload(),
        "operator_attestation_statement_sha256": _statement().statement_sha256,
        "service": "trusted-time-post-enrollment-graceful-stop",
        "signature_algorithm": "Ed25519",
        "signature_base64": base64.b64encode(SIGNATURE_BYTES).decode("ascii"),
        "status": "operator_attested_graceful_stop_decision_envelope",
    }
    assert envelope.encoded == _canonical(payload)
    assert envelope.envelope_sha256 == hashlib.sha256(envelope.encoded).hexdigest()
    assert envelope.envelope_sha256 == ENVELOPE_SHA256
    assert (
        canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(envelope)
        == envelope.encoded
    )
    assert (
        post_enrollment_graceful_stop_operator_attestation_envelope_sha256(envelope)
        == envelope.envelope_sha256
    )


def test_envelope_round_trip_preserves_exact_bytes_with_snapshot_isolation() -> None:
    original = _envelope()
    decoded = decode_post_enrollment_graceful_stop_operator_attestation_envelope(original.encoded)
    payload = decoded.payload()
    cast(dict[str, object], payload["operator_attestation_statement"])["status"] = "mutated"
    payload["signature_base64"] = "mutated"

    assert decoded == original
    assert decoded is not original
    assert decoded.graceful_stop_decision_v1 == _decision_bytes()
    assert decoded.statement == _statement()
    assert decoded.statement is not decoded.statement
    assert decoded.signature_ed25519 == SIGNATURE_BYTES
    assert decoded.encoded == original.encoded
    assert decoded.payload()["signature_base64"] != "mutated"
    assert (
        cast(dict[str, object], decoded.payload()["operator_attestation_statement"])["status"]
        == POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS
    )


def test_envelope_accepts_only_canonical_top_level_v1_identity_without_script_semantics() -> None:
    opaque = _decision_bytes(
        opaque_unqualified_projection={"not": "a real graceful-stop decision"},
        unrelated_extension=[None, False, 7],
    )
    envelope = _envelope(decision_bytes=opaque)

    assert decode_post_enrollment_graceful_stop_operator_attestation_envelope(envelope.encoded) == (
        envelope
    )


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("contract_version", "phase6d-post-enrollment-graceful-stop-decision-v1"),
        ("service", "trusted-time-post-enrollment-start-execution-approval"),
        ("signature_algorithm", "Ed25519ph"),
        ("status", "external_attestation_required"),
    ],
)
def test_envelope_rejects_fixed_scope_mutations(field_name: str, replacement: str) -> None:
    payload = _envelope().payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_envelope(_canonical(payload))


def test_envelope_rejects_duplicate_extra_missing_noncanonical_and_size() -> None:
    encoded = _envelope().encoded
    duplicate = encoded.replace(
        b'{"contract_version":',
        b'{"contract_version":"phase6d-post-enrollment-graceful-stop-decision-v2",'
        b'"contract_version":',
        1,
    )
    nested_duplicate = encoded.replace(
        b'{"algorithm":"Ed25519",',
        b'{"algorithm":"Ed25519","algorithm":"Ed25519",',
        1,
    )
    extra = _envelope().payload()
    extra["unexpected"] = False
    missing = _envelope().payload()
    del missing["status"]
    candidates = (
        duplicate,
        nested_duplicate,
        _canonical(extra),
        _canonical(missing),
        encoded.removesuffix(b"\n"),
        b" " + encoded,
        encoded + b"\n",
        b" " * (POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES + 1),
    )
    for candidate in candidates:
        with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
            decode_post_enrollment_graceful_stop_operator_attestation_envelope(candidate)


@pytest.mark.parametrize(
    "base64_value",
    ["not-base64!", " Zm9v", "Zm9v\n", "Zm9v=", "Zm9v===", "e30"],
)
def test_envelope_rejects_noncanonical_decision_base64(base64_value: str) -> None:
    payload = _envelope().payload()
    payload["graceful_stop_decision_v1_base64"] = base64_value

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_envelope(_canonical(payload))


@pytest.mark.parametrize(
    "signature",
    [b"", SIGNATURE_BYTES[:-1], SIGNATURE_BYTES + b"x", bytearray(SIGNATURE_BYTES)],
)
def test_envelope_builder_rejects_non_bytes_or_wrong_signature_length(signature: object) -> None:
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        build_post_enrollment_graceful_stop_operator_attestation_envelope(
            graceful_stop_decision_v1=_decision_bytes(),
            statement=_statement(),
            signature_ed25519=cast(Any, signature),
        )


@pytest.mark.parametrize(
    "signature_base64",
    [
        "not-base64!",
        base64.b64encode(SIGNATURE_BYTES).decode("ascii").removesuffix("="),
        base64.b64encode(SIGNATURE_BYTES).decode("ascii") + "\n",
        base64.b64encode(SIGNATURE_BYTES[:-1]).decode("ascii"),
        base64.b64encode(SIGNATURE_BYTES + b"x").decode("ascii"),
    ],
)
def test_envelope_decoder_rejects_noncanonical_or_wrong_length_signature(
    signature_base64: str,
) -> None:
    payload = _envelope().payload()
    payload["signature_base64"] = signature_base64

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_envelope(_canonical(payload))


def test_envelope_rejects_decision_digest_operation_and_target_drift() -> None:
    changed_operation = "323e4567-e89b-42d3-a456-426614174002"
    changed_target = "b" * 64
    cases = (
        (
            _decision_bytes(operation_id=changed_operation),
            _statement(
                decision_bytes=_decision_bytes(operation_id=changed_operation),
                operation_id=OPERATION_ID,
            ),
        ),
        (
            _decision_bytes(graceful_stop_target_sha256=changed_target),
            _statement(
                decision_bytes=_decision_bytes(graceful_stop_target_sha256=changed_target),
                target_sha256=TARGET_SHA256,
            ),
        ),
    )
    for decision, statement in cases:
        with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
            _envelope(decision_bytes=decision, statement=statement)

    payload = _envelope().payload()
    changed_decision = _decision_bytes(opaque_unqualified_projection={"drift": True})
    payload["graceful_stop_decision_v1_base64"] = base64.b64encode(changed_decision).decode("ascii")
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        decode_post_enrollment_graceful_stop_operator_attestation_envelope(_canonical(payload))


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("contract_version", "wrong"),
        ("service", "wrong"),
        ("status", "wrong"),
        ("operation_id", "123e4567-e89b-12d3-a456-426614174000"),
        ("graceful_stop_target_sha256", "A" * 64),
    ],
)
def test_envelope_rejects_invalid_inner_decision_identity(
    field_name: str,
    replacement: object,
) -> None:
    decision = _decision_bytes(**{field_name: replacement})
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        _envelope(decision_bytes=decision, statement=_statement(decision_bytes=decision))


def test_maximum_inner_decision_round_trips_and_overflow_fails() -> None:
    base = _decision_bytes(opaque_unqualified_projection="")
    maximum_opaque_length = (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES - len(base)
    )
    maximum = _decision_bytes(opaque_unqualified_projection="x" * maximum_opaque_length)
    assert len(maximum) == (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES
    )

    envelope = _envelope(decision_bytes=maximum)
    assert len(envelope.encoded) < (
        POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES
    )
    assert decode_post_enrollment_graceful_stop_operator_attestation_envelope(envelope.encoded) == (
        envelope
    )

    overflow = maximum.replace(
        b'"opaque_unqualified_projection":"', b'"opaque_unqualified_projection":"x', 1
    )
    assert len(overflow) == len(maximum) + 1
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        _envelope(decision_bytes=overflow, statement=_statement(decision_bytes=maximum))


def test_seals_reject_mutation_copy_pickle_replace_and_direct_construction() -> None:
    statement = _statement()
    envelope = _envelope()
    object.__setattr__(statement, "graceful_stop_target_sha256", "b" * 64)
    object.__setattr__(envelope, "_signature_ed25519", b"z" * 64)

    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        statement.payload()
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        envelope.payload()

    fresh_statement = _statement()
    fresh_envelope = _envelope()
    for projection in (fresh_statement, fresh_envelope):
        for operation in (
            lambda projection=projection: copy.copy(projection),
            lambda projection=projection: copy.deepcopy(projection),
            lambda projection=projection: pickle.dumps(projection),
        ):
            with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
                operation()
        with pytest.raises(TypeError):
            replace(projection)

    statement_constructor = cast(
        Callable[..., object],
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement,
    )
    envelope_constructor = cast(
        Callable[..., object],
        TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    )
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        statement_constructor(
            authority_artifact_sha256="1" * 64,
            public_key_sha256="2" * 64,
            graceful_stop_decision_v1_sha256="3" * 64,
            graceful_stop_operation_id=OPERATION_ID,
            graceful_stop_target_sha256=TARGET_SHA256,
            _construction_capability=object(),
        )
    with pytest.raises(TrustedTimePostEnrollmentGracefulStopOperatorAttestationError):
        envelope_constructor(
            graceful_stop_decision_v1_encoded=_decision_bytes(),
            statement_encoded=_statement().encoded,
            signature_ed25519=SIGNATURE_BYTES,
            _construction_capability=object(),
        )


def test_module_has_no_script_signer_private_key_or_effect_surface() -> None:
    source_path = Path(stop_attestation.__file__)
    source = source_path.read_text(encoding="utf-8")
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

    assert "scripts" not in imported_roots
    assert imported_roots.isdisjoint(
        {"asyncio", "docker", "httpx", "os", "requests", "socket", "subprocess"}
    )
    assert "Ed25519PrivateKey" not in source
    assert "private_bytes" not in source
    assert "from_private_bytes" not in source
    assert ".sign(" not in source
    assert "generate(" not in source
    assert "__main__" not in source
    assert "argparse" not in source
