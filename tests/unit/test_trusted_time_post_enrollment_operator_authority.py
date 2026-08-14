from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, cast

import pytest

from packages.domain.trusted_time_enrollment_evidence import (
    FIRST_ENROLLMENT_AUTHORITY_FIELDS,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS,
    TrustedTimePostEnrollmentOperatorAuthority,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    build_post_enrollment_operator_authority,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
    post_enrollment_operator_authority_artifact_sha256,
)

PUBLIC_KEY_BYTES = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
PUBLIC_KEY_BASE64 = "PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="
PUBLIC_KEY_SHA256 = hashlib.sha256(PUBLIC_KEY_BYTES).hexdigest()


def _authority() -> TrustedTimePostEnrollmentOperatorAuthority:
    return build_post_enrollment_operator_authority(PUBLIC_KEY_BYTES)


def _payload() -> dict[str, object]:
    return _authority().payload()


def _encoded(payload: object) -> bytes:
    return canonical_first_enrollment_json_bytes(payload)


def test_public_material_has_the_exact_fixed_v1_scope_and_key_identity() -> None:
    authority = _authority()

    assert authority.public_key_bytes == PUBLIC_KEY_BYTES
    assert authority.public_key_base64 == PUBLIC_KEY_BASE64
    assert authority.public_key_sha256 == PUBLIC_KEY_SHA256
    assert authority.payload() == {
        "algorithm": "Ed25519",
        "contract_version": "phase6d-post-enrollment-operator-attestation-authority-v1",
        "key_id": "aqt-post-enrollment-start-operator-ed25519-v1",
        "public_key_base64": PUBLIC_KEY_BASE64,
        "public_key_sha256": PUBLIC_KEY_SHA256,
        "replay_domain": (
            "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
            "post-enrollment-start/operator-attestation/v1"
        ),
        "service": "trusted-time-post-enrollment-operator-attestation-authority",
        "status": "public_operator_authority_material",
    }
    assert set(authority.payload()) == POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS
    assert authority.payload()["algorithm"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM
    assert (
        authority.payload()["contract_version"]
        == POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION
    )
    assert authority.payload()["key_id"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID
    assert authority.payload()["replay_domain"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN
    assert authority.payload()["service"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE
    assert authority.payload()["status"] == POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS


def test_manifest_is_structurally_verification_only_and_grants_no_authority() -> None:
    payload = _payload()
    encoded = _encoded(payload)

    assert set(payload).isdisjoint(FIRST_ENROLLMENT_AUTHORITY_FIELDS)
    assert not any(field_name.endswith("_authorized") for field_name in payload)
    assert "authority_granted" not in payload
    assert "verification_only" not in payload
    assert b"private" not in encoded
    assert b"signer" not in encoded
    assert b"secret" not in encoded
    assert b"head-anchor" not in encoded


def test_canonical_round_trip_and_artifact_sha_are_exact() -> None:
    authority = _authority()
    expected_encoded = canonical_first_enrollment_json_bytes(authority.payload())

    assert authority.encoded == expected_encoded
    assert canonical_post_enrollment_operator_authority_bytes(authority) == expected_encoded
    assert expected_encoded.endswith(b"\n")
    assert expected_encoded.count(b"\n") == 1
    assert decode_post_enrollment_operator_authority(expected_encoded) == authority
    expected_sha256 = hashlib.sha256(expected_encoded).hexdigest()
    assert authority.authority_sha256 == expected_sha256
    assert post_enrollment_operator_authority_artifact_sha256(authority) == expected_sha256


@pytest.mark.parametrize(
    "public_key_bytes",
    [
        None,
        True,
        "not-bytes",
        bytearray(PUBLIC_KEY_BYTES),
        memoryview(PUBLIC_KEY_BYTES),
        b"",
        PUBLIC_KEY_BYTES[:-1],
        PUBLIC_KEY_BYTES + b"x",
    ],
)
def test_builder_and_value_object_reject_malformed_raw_public_keys(
    public_key_bytes: object,
) -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        build_post_enrollment_operator_authority(public_key_bytes)
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        TrustedTimePostEnrollmentOperatorAuthority(public_key_bytes=cast(Any, public_key_bytes))


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
        b" " * (POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES + 1),
    ],
)
def test_decoder_rejects_malformed_container_types_and_json(encoded: object) -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        decode_post_enrollment_operator_authority(encoded)


def test_decoder_rejects_duplicate_extra_and_missing_fields() -> None:
    encoded = _authority().encoded
    duplicate = encoded.replace(
        b'{"algorithm":"Ed25519",',
        b'{"algorithm":"Ed25519","algorithm":"Ed25519",',
        1,
    )
    extra = _payload()
    extra["unexpected"] = False
    missing = _payload()
    del missing["status"]

    for candidate in (duplicate, _encoded(extra), _encoded(missing)):
        with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
            decode_post_enrollment_operator_authority(candidate)


def test_decoder_rejects_every_noncanonical_json_representation() -> None:
    canonical = _authority().encoded
    payload = _payload()
    candidates = (
        canonical.removesuffix(b"\n"),
        canonical + b"\n",
        json.dumps(payload, sort_keys=True).encode("ascii") + b"\n",
        json.dumps(payload, indent=2, sort_keys=True).encode("ascii") + b"\n",
        b" " + canonical,
    )

    for candidate in candidates:
        with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
            decode_post_enrollment_operator_authority(candidate)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    [
        ("algorithm", "ed25519"),
        ("contract_version", "phase6d-post-enrollment-operator-attestation-authority-v2"),
        ("key_id", "aqt-trusted-time-anchor-ed25519-v1"),
        ("replay_domain", "github.com/km8trix/AutoQuantTrader/test"),
        ("service", "trusted-time-post-enrollment-start"),
        ("status", "installed"),
    ],
)
def test_decoder_rejects_every_fixed_scope_mutation(field_name: str, replacement: str) -> None:
    payload = _payload()
    payload[field_name] = replacement

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        decode_post_enrollment_operator_authority(_encoded(payload))


@pytest.mark.parametrize("field_name", sorted(POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS))
def test_decoder_rejects_wrong_type_for_every_field(field_name: str) -> None:
    payload = _payload()
    payload[field_name] = True

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        decode_post_enrollment_operator_authority(_encoded(payload))


@pytest.mark.parametrize(
    "public_key_base64",
    [
        "not-base64!",
        PUBLIC_KEY_BASE64.removesuffix("="),
        PUBLIC_KEY_BASE64.replace("+", "-"),
        PUBLIC_KEY_BASE64.replace("+", "\n+"),
        base64.b64encode(PUBLIC_KEY_BYTES[:-1]).decode("ascii"),
        base64.b64encode(PUBLIC_KEY_BYTES + b"x").decode("ascii"),
    ],
)
def test_decoder_rejects_noncanonical_or_wrong_length_base64(public_key_base64: str) -> None:
    payload = _payload()
    payload["public_key_base64"] = public_key_base64

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        decode_post_enrollment_operator_authority(_encoded(payload))


@pytest.mark.parametrize(
    "public_key_sha256",
    [
        "0" * 63,
        "0" * 65,
        "A" * 64,
        "g" * 64,
        "0" * 64,
        hashlib.sha256(b"different-public-key").hexdigest(),
    ],
)
def test_decoder_rejects_malformed_or_mismatched_public_key_digest(
    public_key_sha256: str,
) -> None:
    payload = _payload()
    payload["public_key_sha256"] = public_key_sha256

    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        decode_post_enrollment_operator_authority(_encoded(payload))


def test_canonical_helpers_revalidate_exact_object_type_and_key_shape() -> None:
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        canonical_post_enrollment_operator_authority_bytes(object())
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        post_enrollment_operator_authority_artifact_sha256(object())

    authority = _authority()
    object.__setattr__(authority, "public_key_bytes", b"short")
    with pytest.raises(TrustedTimePostEnrollmentOperatorAuthorityError, match="invalid"):
        canonical_post_enrollment_operator_authority_bytes(authority)
