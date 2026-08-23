"""Canonical public-key material for post-enrollment operator attestations.

This pure domain contract contains one raw Ed25519 public key and its identity.
It contains no private key, signer, filesystem, clock, execution, runtime, or
trading authority.  Installation and rotation require separate source review.
The dedicated key must not reuse the trusted-time head-anchor key.
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

POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION = (
    "phase6d-post-enrollment-operator-attestation-authority-v1"
)
POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE = (
    "trusted-time-post-enrollment-operator-attestation-authority"
)
POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS = "public_operator_authority_material"
POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM = "Ed25519"
POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID = "aqt-post-enrollment-start-operator-ed25519-v1"
POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN = (
    "github.com/km8trix/AutoQuantTrader/production/trusted-time/"
    "post-enrollment-start/operator-attestation/v1"
)
POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES = 4_096
POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS = frozenset(
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
_ED25519_FIELD_PRIME = 2**255 - 19
_ED25519_SUBGROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (
    -121665 * pow(121666, _ED25519_FIELD_PRIME - 2, _ED25519_FIELD_PRIME)
) % _ED25519_FIELD_PRIME
_ED25519_SQRT_MINUS_ONE = pow(
    2,
    (_ED25519_FIELD_PRIME - 1) // 4,
    _ED25519_FIELD_PRIME,
)

_EdwardsExtendedPoint = tuple[int, int, int, int]


class TrustedTimePostEnrollmentOperatorAuthorityError(ValueError):
    """The public operator-attestation authority material is malformed."""


class _InvalidAuthority(ValueError):
    pass


def _invalid() -> Never:
    raise _InvalidAuthority


def _decode_canonical_ed25519_point(encoded: bytes) -> tuple[int, int] | None:
    """Decode one canonical compressed Edwards25519 point, if it exists."""

    encoded_integer = int.from_bytes(encoded, "little")
    x_sign = encoded_integer >> 255
    y = encoded_integer & ((1 << 255) - 1)
    if y >= _ED25519_FIELD_PRIME:
        return None

    y_squared = y * y % _ED25519_FIELD_PRIME
    denominator = (_ED25519_D * y_squared + 1) % _ED25519_FIELD_PRIME
    if denominator == 0:
        return None
    x_squared = (
        (y_squared - 1)
        * pow(
            denominator,
            _ED25519_FIELD_PRIME - 2,
            _ED25519_FIELD_PRIME,
        )
        % _ED25519_FIELD_PRIME
    )
    x = pow(
        x_squared,
        (_ED25519_FIELD_PRIME + 3) // 8,
        _ED25519_FIELD_PRIME,
    )
    if x * x % _ED25519_FIELD_PRIME != x_squared:
        x = x * _ED25519_SQRT_MINUS_ONE % _ED25519_FIELD_PRIME
    if x * x % _ED25519_FIELD_PRIME != x_squared:
        return None
    if x & 1 != x_sign:
        x = (-x) % _ED25519_FIELD_PRIME
    if x == 0 and x_sign != 0:
        return None
    return x, y


def _add_edwards_extended_points(
    left: _EdwardsExtendedPoint,
    right: _EdwardsExtendedPoint,
) -> _EdwardsExtendedPoint:
    """Use the complete a=-1 extended-coordinate Edwards addition law."""

    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_FIELD_PRIME
    b = (y1 + x1) * (y2 + x2) % _ED25519_FIELD_PRIME
    c = 2 * _ED25519_D * t1 * t2 % _ED25519_FIELD_PRIME
    d = 2 * z1 * z2 % _ED25519_FIELD_PRIME
    e = (b - a) % _ED25519_FIELD_PRIME
    f = (d - c) % _ED25519_FIELD_PRIME
    g = (d + c) % _ED25519_FIELD_PRIME
    h = (b + a) % _ED25519_FIELD_PRIME
    return (
        e * f % _ED25519_FIELD_PRIME,
        g * h % _ED25519_FIELD_PRIME,
        f * g % _ED25519_FIELD_PRIME,
        e * h % _ED25519_FIELD_PRIME,
    )


def _multiply_edwards_point(
    scalar: int,
    point: _EdwardsExtendedPoint,
) -> _EdwardsExtendedPoint:
    result: _EdwardsExtendedPoint = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _add_edwards_extended_points(result, addend)
        addend = _add_edwards_extended_points(addend, addend)
        scalar >>= 1
    return result


def _is_edwards_identity(point: _EdwardsExtendedPoint) -> bool:
    x, y, z, _ = point
    return z != 0 and x == 0 and (y - z) % _ED25519_FIELD_PRIME == 0


def require_strict_post_enrollment_operator_public_key(public_key_bytes: object) -> bytes:
    """Require one canonical nonidentity point in the prime-order Ed25519 subgroup.

    The key is public, so this validation need not be fixed-time.  Full subgroup
    membership is required rather than a blacklist of known low-order encodings.
    """

    if (
        type(public_key_bytes) is not bytes
        or len(public_key_bytes) != _RAW_ED25519_PUBLIC_KEY_BYTES
    ):
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        )
    affine = _decode_canonical_ed25519_point(public_key_bytes)
    if affine is None or affine == (0, 1):
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        )
    x, y = affine
    extended: _EdwardsExtendedPoint = (x, y, 1, x * y % _ED25519_FIELD_PRIME)
    if not _is_edwards_identity(_multiply_edwards_point(_ED25519_SUBGROUP_ORDER, extended)):
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        )
    return public_key_bytes


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
        or len(encoded) > POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES
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
    return require_strict_post_enrollment_operator_public_key(public_key_bytes)


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentOperatorAuthority:
    """One verification-only Ed25519 public key for the fixed replay domain."""

    public_key_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        require_strict_post_enrollment_operator_public_key(self.public_key_bytes)

    @property
    def public_key_base64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    @property
    def public_key_sha256(self) -> str:
        return hashlib.sha256(self.public_key_bytes).hexdigest()

    def payload(self) -> dict[str, object]:
        return {
            "algorithm": POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
            "contract_version": POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
            "public_key_base64": self.public_key_base64,
            "public_key_sha256": self.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
            "status": POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_operator_authority_bytes(self)

    @property
    def authority_sha256(self) -> str:
        return post_enrollment_operator_authority_artifact_sha256(self)


def build_post_enrollment_operator_authority(
    public_key_bytes: object,
) -> TrustedTimePostEnrollmentOperatorAuthority:
    """Build final public material from exactly one raw 32-byte Ed25519 key."""

    if type(public_key_bytes) is not bytes:
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        )
    return TrustedTimePostEnrollmentOperatorAuthority(public_key_bytes=public_key_bytes)


def canonical_post_enrollment_operator_authority_bytes(authority: object) -> bytes:
    """Return exact newline-terminated bytes for source review and installation."""

    if type(authority) is not TrustedTimePostEnrollmentOperatorAuthority:
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        )
    try:
        authority.__post_init__()
        return canonical_first_enrollment_json_bytes(authority.payload())
    except (
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentOperatorAuthorityError,
    ):
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        ) from None


def post_enrollment_operator_authority_artifact_sha256(authority: object) -> str:
    """Return the SHA-256 identity of the exact canonical authority artifact."""

    return hashlib.sha256(canonical_post_enrollment_operator_authority_bytes(authority)).hexdigest()


def decode_post_enrollment_operator_authority(
    encoded: object,
) -> TrustedTimePostEnrollmentOperatorAuthority:
    """Decode only the exact canonical public operator-authority manifest."""

    try:
        payload = _decode_canonical_object(encoded)
        if set(payload) != POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS:
            _invalid()
        exact_strings = {
            "algorithm": POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
            "contract_version": POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
            "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE,
            "status": POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS,
        }
        if any(
            type(payload.get(field_name)) is not str or payload.get(field_name) != expected
            for field_name, expected in exact_strings.items()
        ):
            _invalid()
        public_key_bytes = _raw_public_key_from_payload(payload)
        authority = TrustedTimePostEnrollmentOperatorAuthority(public_key_bytes=public_key_bytes)
        if authority.payload() != payload:
            _invalid()
        return authority
    except (
        KeyError,
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentOperatorAuthorityError,
        _InvalidAuthority,
    ):
        raise TrustedTimePostEnrollmentOperatorAuthorityError(
            "trusted-time post-enrollment operator authority is invalid"
        ) from None


__all__ = [
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_FIELDS",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_MAXIMUM_ARTIFACT_BYTES",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_SERVICE",
    "POST_ENROLLMENT_OPERATOR_AUTHORITY_STATUS",
    "TrustedTimePostEnrollmentOperatorAuthority",
    "TrustedTimePostEnrollmentOperatorAuthorityError",
    "build_post_enrollment_operator_authority",
    "canonical_post_enrollment_operator_authority_bytes",
    "decode_post_enrollment_operator_authority",
    "post_enrollment_operator_authority_artifact_sha256",
    "require_strict_post_enrollment_operator_public_key",
]
