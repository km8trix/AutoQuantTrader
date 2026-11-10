"""Public-key-only verification for inert post-enrollment operator attestations.

The verifier accepts one explicit, already-decoded authority and one explicit,
already-decoded envelope.  It owns no loader, default key, signer, private key,
filesystem, clock, runtime, admission, controller, or trading authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Never, SupportsIndex

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.domain.trusted_time_post_enrollment_operator_attestation import (
    TrustedTimePostEnrollmentOperatorAttestationEnvelope,
    TrustedTimePostEnrollmentOperatorAttestationError,
    canonical_post_enrollment_operator_attestation_envelope_bytes,
    canonical_post_enrollment_operator_attestation_statement_bytes,
    decode_post_enrollment_operator_attestation_envelope,
    post_enrollment_operator_attestation_envelope_sha256,
    post_enrollment_operator_attestation_statement_sha256,
)
from packages.domain.trusted_time_post_enrollment_operator_authority import (
    TrustedTimePostEnrollmentOperatorAuthority,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    canonical_post_enrollment_operator_authority_bytes,
    decode_post_enrollment_operator_authority,
    post_enrollment_operator_authority_artifact_sha256,
)

POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-operator-attestation-verification-v1"
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE = (
    "trusted-time-post-enrollment-operator-attestation-verification"
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS = (
    "operator_signature_authenticated_unqualified"
)

POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS = frozenset(
    {
        "active_controller_authorized",
        "alert_delivery_authorized",
        "arming_authorized",
        "authority_granted",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "claim_retention_authorized",
        "controller_execution_authorized",
        "database_secret_disclosed",
        "execution_admission_authorized",
        "execution_attempt_reservation_authorized",
        "exposure_authorized",
        "live_trading_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "outcome_retention_authorized",
        "paper_trading_authorized",
        "persistent_start_authorized",
        "readiness_authorized",
        "rearm_authorized",
        "release_authorized",
        "retry_authorized",
        "runtime_start_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "source_start_authorized",
        "success_outcome_retention_authorized",
        "supervisor_start_authorized",
        "topology_mutation_authorized",
    }
)

_VERIFIER_CONSTRUCTION_CAPABILITY = object()
_VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY = object()

_ED25519_FIELD_PRIME = 2**255 - 19
_ED25519_SUBGROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
_ED25519_CURVE_D = (-121665 * pow(121666, _ED25519_FIELD_PRIME - 2, _ED25519_FIELD_PRIME)) % (
    _ED25519_FIELD_PRIME
)
_ED25519_SQRT_MINUS_ONE = pow(2, (_ED25519_FIELD_PRIME - 1) // 4, _ED25519_FIELD_PRIME)
_ED25519_IDENTITY = (0, 1, 1, 0)


class TrustedTimePostEnrollmentOperatorAttestationVerificationError(ValueError):
    """The exact authority, envelope, bindings, or signature failed closed."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _authority_is_never_granted(_: object) -> bool:
    return False


def _ed25519_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Add two extended-coordinate points on the complete Edwards curve."""

    left_x, left_y, left_z, left_t = left
    right_x, right_y, right_z, right_t = right
    field_prime = _ED25519_FIELD_PRIME
    a = ((left_y - left_x) * (right_y - right_x)) % field_prime
    b = ((left_y + left_x) * (right_y + right_x)) % field_prime
    c = (2 * _ED25519_CURVE_D * left_t * right_t) % field_prime
    d = (2 * left_z * right_z) % field_prime
    e = (b - a) % field_prime
    f = (d - c) % field_prime
    g = (d + c) % field_prime
    h = (b + a) % field_prime
    return (
        (e * f) % field_prime,
        (g * h) % field_prime,
        (f * g) % field_prime,
        (e * h) % field_prime,
    )


def _ed25519_multiply(
    scalar: int,
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    result = _ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_add(addend, addend)
        scalar >>= 1
    return result


def _ed25519_is_identity(point: tuple[int, int, int, int]) -> bool:
    x, y, z, _ = point
    return (
        z % _ED25519_FIELD_PRIME != 0
        and x % _ED25519_FIELD_PRIME == 0
        and (y - z) % _ED25519_FIELD_PRIME == 0
    )


def _require_prime_order_ed25519_public_key(public_key_bytes: object) -> bytes:
    """Reject noncanonical, off-curve, torsion, and mixed-subgroup encodings."""

    if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
        raise ValueError
    encoded = int.from_bytes(public_key_bytes, byteorder="little")
    x_sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= _ED25519_FIELD_PRIME:
        raise ValueError
    y_squared = (y * y) % _ED25519_FIELD_PRIME
    numerator = (y_squared - 1) % _ED25519_FIELD_PRIME
    denominator = (_ED25519_CURVE_D * y_squared + 1) % _ED25519_FIELD_PRIME
    if denominator == 0:
        raise ValueError
    x_squared = (
        numerator * pow(denominator, _ED25519_FIELD_PRIME - 2, _ED25519_FIELD_PRIME)
    ) % _ED25519_FIELD_PRIME
    x = pow(x_squared, (_ED25519_FIELD_PRIME + 3) // 8, _ED25519_FIELD_PRIME)
    if (x * x - x_squared) % _ED25519_FIELD_PRIME != 0:
        x = (x * _ED25519_SQRT_MINUS_ONE) % _ED25519_FIELD_PRIME
    if (x * x - x_squared) % _ED25519_FIELD_PRIME != 0 or (x == 0 and x_sign != 0):
        raise ValueError
    if x & 1 != x_sign:
        x = _ED25519_FIELD_PRIME - x
    point = (x, y, 1, (x * y) % _ED25519_FIELD_PRIME)
    if _ed25519_is_identity(point) or not _ed25519_is_identity(
        _ed25519_multiply(_ED25519_SUBGROUP_ORDER, point)
    ):
        raise ValueError
    return public_key_bytes


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentOperatorAttestationVerification:
    """Authenticated byte identities that deliberately authorize no operation."""

    authority_artifact_sha256: str
    public_key_sha256: str
    execution_approval_v2_sha256: str
    operator_attestation_statement_sha256: str
    operator_attestation_envelope_sha256: str
    _sealed_digest_tuple: tuple[str, str, str, str, str] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        execution_approval_v2_sha256: str,
        operator_attestation_statement_sha256: str,
        operator_attestation_envelope_sha256: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentOperatorAttestationVerification
            or _construction_capability is not _VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation verification is invalid"
            )
        digest_tuple = (
            authority_artifact_sha256,
            public_key_sha256,
            execution_approval_v2_sha256,
            operator_attestation_statement_sha256,
            operator_attestation_envelope_sha256,
        )
        if not all(_is_sha256(value) for value in digest_tuple):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation verification is invalid"
            )
        object.__setattr__(self, "authority_artifact_sha256", authority_artifact_sha256)
        object.__setattr__(self, "public_key_sha256", public_key_sha256)
        object.__setattr__(self, "execution_approval_v2_sha256", execution_approval_v2_sha256)
        object.__setattr__(
            self,
            "operator_attestation_statement_sha256",
            operator_attestation_statement_sha256,
        )
        object.__setattr__(
            self,
            "operator_attestation_envelope_sha256",
            operator_attestation_envelope_sha256,
        )
        object.__setattr__(self, "_sealed_digest_tuple", digest_tuple)
        self.__post_init__()

    def __post_init__(self) -> None:
        digest_tuple = (
            self.authority_artifact_sha256,
            self.public_key_sha256,
            self.execution_approval_v2_sha256,
            self.operator_attestation_statement_sha256,
            self.operator_attestation_envelope_sha256,
        )
        if type(self) is not TrustedTimePostEnrollmentOperatorAttestationVerification or (
            digest_tuple != getattr(self, "_sealed_digest_tuple", None)
            or not all(_is_sha256(value) for value in digest_tuple)
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation verification is invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS

    @property
    def verification_only(self) -> bool:
        self.__post_init__()
        return True

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload: dict[str, object] = {
            field_name: False
            for field_name in POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
        }
        payload.update(
            {
                "authority_artifact_sha256": self.authority_artifact_sha256,
                "contract_version": (
                    POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
                ),
                "execution_approval_v2_sha256": self.execution_approval_v2_sha256,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
                "operator_attestation_statement_sha256": (
                    self.operator_attestation_statement_sha256
                ),
                "public_key_sha256": self.public_key_sha256,
                "service": POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE,
                "status": self.status,
                "verification_only": self.verification_only,
            }
        )
        return payload

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
            "trusted-time post-enrollment operator-attestation verification cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
            "trusted-time post-enrollment operator-attestation verification cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
            "trusted-time post-enrollment operator-attestation verification cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
            "trusted-time post-enrollment operator-attestation verification cannot be serialized"
        )

    active_controller_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    controller_execution_authorized = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    execution_admission_authorized = property(_authority_is_never_granted)
    execution_attempt_reservation_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    outcome_retention_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    retry_authorized = property(_authority_is_never_granted)
    runtime_start_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    success_outcome_retention_authorized = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True)
class Ed25519PostEnrollmentOperatorAttestationVerifier:
    """Sealed verifier for one exact canonical public-authority artifact."""

    _authority_encoded: bytes = field(repr=False, compare=False)
    _construction_capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not Ed25519PostEnrollmentOperatorAttestationVerifier
            or self._construction_capability is not _VERIFIER_CONSTRUCTION_CAPABILITY
            or type(self._authority_encoded) is not bytes
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation authority is invalid"
            )
        self._validated_authority()

    @classmethod
    def from_authority(
        cls,
        authority: object,
    ) -> Ed25519PostEnrollmentOperatorAttestationVerifier:
        """Seal one exact decoded authority into a verification-only object."""

        if (
            cls is not Ed25519PostEnrollmentOperatorAttestationVerifier
            or type(authority) is not TrustedTimePostEnrollmentOperatorAuthority
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation authority is invalid"
            )
        try:
            authority_encoded = canonical_post_enrollment_operator_authority_bytes(authority)
            verifier = cls(
                _authority_encoded=authority_encoded,
                _construction_capability=_VERIFIER_CONSTRUCTION_CAPABILITY,
            )
        except Exception:
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation authority is invalid"
            ) from None
        return verifier

    def _validated_authority(self) -> TrustedTimePostEnrollmentOperatorAuthority:
        try:
            authority = decode_post_enrollment_operator_authority(self._authority_encoded)
            if (
                canonical_post_enrollment_operator_authority_bytes(authority)
                != self._authority_encoded
                or post_enrollment_operator_authority_artifact_sha256(authority)
                != hashlib.sha256(self._authority_encoded).hexdigest()
                or hashlib.sha256(authority.public_key_bytes).hexdigest()
                != authority.public_key_sha256
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(
                _require_prime_order_ed25519_public_key(authority.public_key_bytes)
            )
        except Exception:
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation authority is invalid"
            ) from None
        return authority

    def verify(
        self,
        envelope: object,
    ) -> TrustedTimePostEnrollmentOperatorAttestationVerification:
        """Authenticate exact canonical statement bytes and return no authority."""

        if (
            type(self) is not Ed25519PostEnrollmentOperatorAttestationVerifier
            or type(envelope) is not TrustedTimePostEnrollmentOperatorAttestationEnvelope
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation envelope is invalid"
            )
        try:
            self.__post_init__()
            authority = self._validated_authority()
            envelope_encoded = canonical_post_enrollment_operator_attestation_envelope_bytes(
                envelope
            )
            snapshot = decode_post_enrollment_operator_attestation_envelope(envelope_encoded)
            statement_encoded = canonical_post_enrollment_operator_attestation_statement_bytes(
                snapshot.statement
            )
            authority_artifact_sha256 = post_enrollment_operator_authority_artifact_sha256(
                authority
            )
            execution_approval_v2_sha256 = hashlib.sha256(
                snapshot.execution_approval_v2
            ).hexdigest()
            statement_sha256 = post_enrollment_operator_attestation_statement_sha256(
                snapshot.statement
            )
            envelope_sha256 = hashlib.sha256(envelope_encoded).hexdigest()
            if (
                hashlib.sha256(statement_encoded).hexdigest() != statement_sha256
                or post_enrollment_operator_attestation_envelope_sha256(snapshot) != envelope_sha256
                or snapshot.statement.authority_artifact_sha256 != authority_artifact_sha256
                or snapshot.statement.public_key_sha256 != authority.public_key_sha256
                or snapshot.statement.execution_approval_v2_sha256 != execution_approval_v2_sha256
                or snapshot.execution_approval_v2_sha256 != execution_approval_v2_sha256
                or snapshot.statement.statement_sha256 != statement_sha256
                or snapshot.envelope_sha256 != envelope_sha256
            ):
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(
                _require_prime_order_ed25519_public_key(authority.public_key_bytes)
            )
            public_key.verify(snapshot.signature_ed25519, statement_encoded)
        except (
            InvalidSignature,
            TypeError,
            ValueError,
            TrustedTimePostEnrollmentOperatorAuthorityError,
            TrustedTimePostEnrollmentOperatorAttestationError,
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation verification failed"
            ) from None
        except Exception:
            raise TrustedTimePostEnrollmentOperatorAttestationVerificationError(
                "trusted-time post-enrollment operator-attestation verification failed"
            ) from None
        return TrustedTimePostEnrollmentOperatorAttestationVerification(
            authority_artifact_sha256=authority_artifact_sha256,
            public_key_sha256=authority.public_key_sha256,
            execution_approval_v2_sha256=execution_approval_v2_sha256,
            operator_attestation_statement_sha256=statement_sha256,
            operator_attestation_envelope_sha256=envelope_sha256,
            _construction_capability=_VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY,
        )


__all__ = [
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_SERVICE",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_VERIFICATION_STATUS",
    "Ed25519PostEnrollmentOperatorAttestationVerifier",
    "TrustedTimePostEnrollmentOperatorAttestationVerification",
    "TrustedTimePostEnrollmentOperatorAttestationVerificationError",
]
