"""Canonical public-key material for graceful-stop operator attestations.

This pure domain contract contains one raw Ed25519 public key and its distinct
graceful-stop identity.  It contains no private key, signer, filesystem, clock,
runtime, shutdown, teardown, retry, operational-control, or trading authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Never, cast

from packages.domain.trusted_time_enrollment_evidence import (
    TrustedTimeEnrollmentEvidenceError,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    TrustedTimePostEnrollmentOperatorAuthorityError,
    require_strict_post_enrollment_operator_public_key,
)

POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-operator-attestation-authority-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-operator-attestation-authority"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_STATUS = (
    "public_graceful_stop_operator_authority_material"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM = "Ed25519"
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID = (
    "aqt-post-enrollment-graceful-stop-operator-ed25519-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN = (
    "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
    "post-enrollment-graceful-stop/operator-attestation/v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES = 4_096
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_FIELDS = frozenset(
    {
        "algorithm",
        "contract_version",
        "key_id",
        "public_key_base64",
        "public_key_sha256",
        "replay_domain",
        "service",
        "status",
    }
)

_RAW_ED25519_PUBLIC_KEY_BYTES = 32
_ERROR_MESSAGE = "trusted-time post-enrollment graceful-stop operator authority is invalid"


class TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError(ValueError):
    """The public graceful-stop operator authority material is malformed."""


class _InvalidAuthority(ValueError):
    pass


def _invalid() -> Never:
    raise _InvalidAuthority


def _require_strict_public_key(public_key_bytes: object) -> bytes:
    """Apply the shared strict Ed25519 point rule with this contract's error."""

    try:
        return require_strict_post_enrollment_operator_public_key(public_key_bytes)
    except TrustedTimePostEnrollmentOperatorAuthorityError:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError(_ERROR_MESSAGE) from None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _decode_canonical_object(encoded: object) -> dict[str, object]:
    if (
        type(encoded) is not bytes
        or not encoded
        or len(encoded) > POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES
    ):
        _invalid()
    encoded_bytes = encoded
    try:
        payload = json.loads(
            encoded_bytes.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _invalid(),
        )
    except (
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
        _InvalidAuthority,
    ):
        _invalid()
    if type(payload) is not dict:
        _invalid()
    try:
        canonical = canonical_first_enrollment_json_bytes(payload)
    except TrustedTimeEnrollmentEvidenceError:
        _invalid()
    if canonical != encoded_bytes:
        _invalid()
    return cast(dict[str, object], payload)


def _raw_public_key_from_payload(payload: dict[str, object]) -> bytes:
    public_key_base64 = payload.get("public_key_base64")
    public_key_sha256 = payload.get("public_key_sha256")
    if type(public_key_base64) is not str or type(public_key_sha256) is not str:
        _invalid()
    try:
        public_key_bytes = base64.b64decode(public_key_base64, validate=True)
    except (binascii.Error, ValueError):
        _invalid()
    if (
        len(public_key_bytes) != _RAW_ED25519_PUBLIC_KEY_BYTES
        or base64.b64encode(public_key_bytes).decode("ascii") != public_key_base64
        or len(public_key_sha256) != 64
        or any(character not in "0123456789abcdef" for character in public_key_sha256)
        or hashlib.sha256(public_key_bytes).hexdigest() != public_key_sha256
    ):
        _invalid()
    return _require_strict_public_key(public_key_bytes)


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
    """One verification-only Ed25519 public key for the stop replay domain."""

    public_key_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_strict_public_key(self.public_key_bytes)

    @property
    def public_key_base64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    @property
    def public_key_sha256(self) -> str:
        return hashlib.sha256(self.public_key_bytes).hexdigest()

    def payload(self) -> dict[str, object]:
        return {
            "algorithm": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
            "contract_version": (POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION),
            "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
            "public_key_base64": self.public_key_base64,
            "public_key_sha256": self.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE,
            "status": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_STATUS,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_operator_authority_bytes(self)

    @property
    def authority_sha256(self) -> str:
        return post_enrollment_graceful_stop_operator_authority_artifact_sha256(self)


def build_post_enrollment_graceful_stop_operator_authority(
    public_key_bytes: object,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
    """Build final public material from exactly one raw 32-byte Ed25519 key."""

    if type(public_key_bytes) is not bytes:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError(_ERROR_MESSAGE)
    return TrustedTimePostEnrollmentGracefulStopOperatorAuthority(public_key_bytes=public_key_bytes)


def canonical_post_enrollment_graceful_stop_operator_authority_bytes(
    authority: object,
) -> bytes:
    """Return exact newline-terminated bytes for source review and installation."""

    if type(authority) is not TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError(_ERROR_MESSAGE)
    try:
        authority.__post_init__()
        return canonical_first_enrollment_json_bytes(authority.payload())
    except (
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError(_ERROR_MESSAGE) from None


def post_enrollment_graceful_stop_operator_authority_artifact_sha256(
    authority: object,
) -> str:
    """Return the SHA-256 identity of the exact canonical authority artifact."""

    return hashlib.sha256(
        canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority)
    ).hexdigest()


def decode_post_enrollment_graceful_stop_operator_authority(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
    """Decode only the exact canonical public graceful-stop authority manifest."""

    try:
        payload = _decode_canonical_object(encoded)
        if set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_FIELDS:
            _invalid()
        exact_strings = {
            "algorithm": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
            "contract_version": (POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION),
            "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
            "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE,
            "status": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_STATUS,
        }
        if any(
            type(payload.get(field_name)) is not str or payload.get(field_name) != expected
            for field_name, expected in exact_strings.items()
        ):
            _invalid()
        public_key_bytes = _raw_public_key_from_payload(payload)
        authority = TrustedTimePostEnrollmentGracefulStopOperatorAuthority(
            public_key_bytes=public_key_bytes
        )
        if authority.payload() != payload:
            _invalid()
        return authority
    except (
        KeyError,
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
        _InvalidAuthority,
    ):
        raise TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError(_ERROR_MESSAGE) from None


__all__ = [
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_STATUS",
    "TrustedTimePostEnrollmentGracefulStopOperatorAuthority",
    "TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError",
    "build_post_enrollment_graceful_stop_operator_authority",
    "canonical_post_enrollment_graceful_stop_operator_authority_bytes",
    "decode_post_enrollment_graceful_stop_operator_authority",
    "post_enrollment_graceful_stop_operator_authority_artifact_sha256",
]
