"""Public-key-only verification for inert graceful-stop operator attestations.

The verifier accepts one explicit stop-specific authority and one explicit
stop-specific envelope.  It owns no loader, default key, signer, private key,
filesystem, clock, runtime, shutdown, teardown, retry, operational-control, or
trading authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Never, SupportsIndex
from uuid import RFC_4122, UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_attestation import (
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope,
    TrustedTimePostEnrollmentGracefulStopOperatorAttestationError,
    canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes,
    canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes,
    decode_post_enrollment_graceful_stop_operator_attestation_envelope,
    post_enrollment_graceful_stop_operator_attestation_envelope_sha256,
    post_enrollment_graceful_stop_operator_attestation_statement_sha256,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
    canonical_post_enrollment_graceful_stop_operator_authority_bytes,
    decode_post_enrollment_graceful_stop_operator_authority,
    post_enrollment_graceful_stop_operator_authority_artifact_sha256,
)

POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-operator-attestation-verification-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-operator-attestation-verification"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS = (
    "graceful_stop_operator_signature_authenticated_unqualified"
)

# This is the exact ADR-0104 graceful-stop authority/fact surface.  Signature
# verification authenticates byte identities only, so none of these names is
# opened by this adapter.
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS = frozenset(
    {
        "active_controller_authorized",
        "alert_delivery_authorized",
        "arming_authorized",
        "authority_granted",
        "automatic_rearm_authorized",
        "automatic_resume_authorized",
        "broker_action_authorized",
        "claim_retention_authorized",
        "clean_stop_authorized",
        "clean_stop_outcome_retention_authorized",
        "confirmed_start_outcome_authenticated",
        "container_removal_authorized",
        "controller_execution_authorized",
        "current_topology_authenticated",
        "database_secret_disclosed",
        "decision_authenticated",
        "execution_admission_authorized",
        "execution_attempt_reservation_authorized",
        "exposure_authorized",
        "freshness_authenticated",
        "graceful_stop_authorized",
        "live_trading_authorized",
        "network_removal_authorized",
        "new_exposure_authorized",
        "operational_control_authorized",
        "operator_attestation_authenticated",
        "outcome_retention_authorized",
        "paper_trading_authorized",
        "persistent_start_authorized",
        "persistent_topology_authenticated",
        "qualified",
        "readiness_authorized",
        "rearm_authorized",
        "release_authorized",
        "retry_authorized",
        "runtime_start_authorized",
        "sequence_2_authorized",
        "shutdown_authorized",
        "shutdown_locator_authenticated",
        "shutdown_outcome_retention_authorized",
        "single_use_authenticated",
        "source_start_authorized",
        "source_stop_authorized",
        "start_execution_attempt_authenticated",
        "stop_attempt_reservation_authorized",
        "stop_decision_authenticated",
        "stop_execution_authorized",
        "success_outcome_retention_authorized",
        "supervisor_signal_authorized",
        "supervisor_start_authorized",
        "supervisor_stop_authorized",
        "target_authenticated",
        "teardown_authorized",
        "topology_mutation_authorized",
        "volume_removal_authorized",
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


class TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(ValueError):
    """The exact stop authority, envelope, bindings, or signature failed closed."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_uuid4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.version == 4 and parsed.variant == RFC_4122 and str(parsed) == value


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


def _verification_seal_values(value: object) -> tuple[object, ...]:
    candidate = value
    return (
        getattr(candidate, "authority_artifact_sha256", None),
        getattr(candidate, "public_key_sha256", None),
        getattr(candidate, "graceful_stop_decision_v1_sha256", None),
        getattr(candidate, "graceful_stop_operation_id", None),
        getattr(candidate, "graceful_stop_target_sha256", None),
        getattr(candidate, "operator_attestation_statement_sha256", None),
        getattr(candidate, "operator_attestation_signature_sha256", None),
        getattr(candidate, "operator_attestation_envelope_sha256", None),
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification:
    """Authenticated stop byte identities that authorize no operation."""

    authority_artifact_sha256: str
    public_key_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    operator_attestation_statement_sha256: str
    operator_attestation_signature_sha256: str
    operator_attestation_envelope_sha256: str
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        operator_attestation_statement_sha256: str,
        operator_attestation_signature_sha256: str,
        operator_attestation_envelope_sha256: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification
            or _construction_capability is not _VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation verification "
                "is invalid"
            )
        object.__setattr__(self, "authority_artifact_sha256", authority_artifact_sha256)
        object.__setattr__(self, "public_key_sha256", public_key_sha256)
        object.__setattr__(
            self,
            "graceful_stop_decision_v1_sha256",
            graceful_stop_decision_v1_sha256,
        )
        object.__setattr__(self, "graceful_stop_operation_id", graceful_stop_operation_id)
        object.__setattr__(self, "graceful_stop_target_sha256", graceful_stop_target_sha256)
        object.__setattr__(
            self,
            "operator_attestation_statement_sha256",
            operator_attestation_statement_sha256,
        )
        object.__setattr__(
            self,
            "operator_attestation_signature_sha256",
            operator_attestation_signature_sha256,
        )
        object.__setattr__(
            self,
            "operator_attestation_envelope_sha256",
            operator_attestation_envelope_sha256,
        )
        object.__setattr__(self, "_sealed_fields", _verification_seal_values(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        digest_values = (
            self.authority_artifact_sha256,
            self.public_key_sha256,
            self.graceful_stop_decision_v1_sha256,
            self.graceful_stop_target_sha256,
            self.operator_attestation_statement_sha256,
            self.operator_attestation_signature_sha256,
            self.operator_attestation_envelope_sha256,
        )
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification
            or not all(_is_sha256(value) for value in digest_values)
            or not _is_uuid4(self.graceful_stop_operation_id)
            or _verification_seal_values(self) != getattr(self, "_sealed_fields", None)
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation verification "
                "is invalid"
            )

    @property
    def status(self) -> str:
        self.__post_init__()
        return POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS

    @property
    def verification_only(self) -> bool:
        self.__post_init__()
        return True

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        payload: dict[str, object] = {
            field_name: False
            for field_name in (
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS
            )
        }
        payload.update(
            {
                "authority_artifact_sha256": self.authority_artifact_sha256,
                "contract_version": (
                    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION
                ),
                "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
                "graceful_stop_operation_id": self.graceful_stop_operation_id,
                "graceful_stop_target_sha256": self.graceful_stop_target_sha256,
                "operator_attestation_envelope_sha256": (self.operator_attestation_envelope_sha256),
                "operator_attestation_signature_sha256": (
                    self.operator_attestation_signature_sha256
                ),
                "operator_attestation_statement_sha256": (
                    self.operator_attestation_statement_sha256
                ),
                "public_key_sha256": self.public_key_sha256,
                "service": (
                    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE
                ),
                "status": self.status,
                "verification_only": self.verification_only,
            }
        )
        return payload

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verification "
            "cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verification "
            "cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verification "
            "cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verification "
            "cannot be serialized"
        )

    active_controller_authorized = property(_authority_is_never_granted)
    alert_delivery_authorized = property(_authority_is_never_granted)
    arming_authorized = property(_authority_is_never_granted)
    authority_granted = property(_authority_is_never_granted)
    automatic_rearm_authorized = property(_authority_is_never_granted)
    automatic_resume_authorized = property(_authority_is_never_granted)
    broker_action_authorized = property(_authority_is_never_granted)
    claim_retention_authorized = property(_authority_is_never_granted)
    clean_stop_authorized = property(_authority_is_never_granted)
    clean_stop_outcome_retention_authorized = property(_authority_is_never_granted)
    confirmed_start_outcome_authenticated = property(_authority_is_never_granted)
    container_removal_authorized = property(_authority_is_never_granted)
    controller_execution_authorized = property(_authority_is_never_granted)
    current_topology_authenticated = property(_authority_is_never_granted)
    database_secret_disclosed = property(_authority_is_never_granted)
    decision_authenticated = property(_authority_is_never_granted)
    execution_admission_authorized = property(_authority_is_never_granted)
    execution_attempt_reservation_authorized = property(_authority_is_never_granted)
    exposure_authorized = property(_authority_is_never_granted)
    freshness_authenticated = property(_authority_is_never_granted)
    graceful_stop_authorized = property(_authority_is_never_granted)
    live_trading_authorized = property(_authority_is_never_granted)
    network_removal_authorized = property(_authority_is_never_granted)
    new_exposure_authorized = property(_authority_is_never_granted)
    operational_control_authorized = property(_authority_is_never_granted)
    operator_attestation_authenticated = property(_authority_is_never_granted)
    outcome_retention_authorized = property(_authority_is_never_granted)
    paper_trading_authorized = property(_authority_is_never_granted)
    persistent_start_authorized = property(_authority_is_never_granted)
    persistent_topology_authenticated = property(_authority_is_never_granted)
    qualified = property(_authority_is_never_granted)
    readiness_authorized = property(_authority_is_never_granted)
    rearm_authorized = property(_authority_is_never_granted)
    release_authorized = property(_authority_is_never_granted)
    retry_authorized = property(_authority_is_never_granted)
    runtime_start_authorized = property(_authority_is_never_granted)
    sequence_2_authorized = property(_authority_is_never_granted)
    shutdown_authorized = property(_authority_is_never_granted)
    shutdown_locator_authenticated = property(_authority_is_never_granted)
    shutdown_outcome_retention_authorized = property(_authority_is_never_granted)
    single_use_authenticated = property(_authority_is_never_granted)
    source_start_authorized = property(_authority_is_never_granted)
    source_stop_authorized = property(_authority_is_never_granted)
    start_execution_attempt_authenticated = property(_authority_is_never_granted)
    stop_attempt_reservation_authorized = property(_authority_is_never_granted)
    stop_decision_authenticated = property(_authority_is_never_granted)
    stop_execution_authorized = property(_authority_is_never_granted)
    success_outcome_retention_authorized = property(_authority_is_never_granted)
    supervisor_signal_authorized = property(_authority_is_never_granted)
    supervisor_start_authorized = property(_authority_is_never_granted)
    supervisor_stop_authorized = property(_authority_is_never_granted)
    target_authenticated = property(_authority_is_never_granted)
    teardown_authorized = property(_authority_is_never_granted)
    topology_mutation_authorized = property(_authority_is_never_granted)
    volume_removal_authorized = property(_authority_is_never_granted)


@dataclass(frozen=True, slots=True, init=False)
class Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier:
    """Sealed verifier for one exact canonical stop-authority artifact."""

    _authority_encoded: bytes = field(repr=False, compare=False)
    _sealed_authority_sha256: str = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        _authority_encoded: bytes,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier
            or _construction_capability is not _VERIFIER_CONSTRUCTION_CAPABILITY
            or type(_authority_encoded) is not bytes
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation authority "
                "is invalid"
            )
        object.__setattr__(self, "_authority_encoded", _authority_encoded)
        object.__setattr__(
            self,
            "_sealed_authority_sha256",
            hashlib.sha256(_authority_encoded).hexdigest(),
        )
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            type(self) is not Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier
            or type(self._authority_encoded) is not bytes
            or not _is_sha256(getattr(self, "_sealed_authority_sha256", None))
            or hashlib.sha256(self._authority_encoded).hexdigest() != self._sealed_authority_sha256
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation authority "
                "is invalid"
            )
        self._validated_authority()

    @classmethod
    def from_authority(
        cls,
        authority: object,
    ) -> Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier:
        """Seal one exact decoded graceful-stop authority into a verifier."""

        if (
            cls is not Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier
            or type(authority) is not TrustedTimePostEnrollmentGracefulStopOperatorAuthority
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation authority "
                "is invalid"
            )
        try:
            authority_encoded = canonical_post_enrollment_graceful_stop_operator_authority_bytes(
                authority
            )
            return cls(
                _authority_encoded=authority_encoded,
                _construction_capability=_VERIFIER_CONSTRUCTION_CAPABILITY,
            )
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation authority "
                "is invalid"
            ) from None

    def _validated_authority(
        self,
    ) -> TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
        try:
            authority = decode_post_enrollment_graceful_stop_operator_authority(
                self._authority_encoded
            )
            if (
                canonical_post_enrollment_graceful_stop_operator_authority_bytes(authority)
                != self._authority_encoded
                or post_enrollment_graceful_stop_operator_authority_artifact_sha256(authority)
                != hashlib.sha256(self._authority_encoded).hexdigest()
                or hashlib.sha256(authority.public_key_bytes).hexdigest()
                != authority.public_key_sha256
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(
                _require_prime_order_ed25519_public_key(authority.public_key_bytes)
            )
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation authority "
                "is invalid"
            ) from None
        return authority

    def verify(
        self,
        envelope: object,
    ) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification:
        """Authenticate exact LF-terminated statement bytes and grant no authority."""

        if (
            type(self) is not Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier
            or type(envelope)
            is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation envelope "
                "is invalid"
            )
        try:
            self.__post_init__()
            authority = self._validated_authority()
            envelope_encoded = (
                canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(
                    envelope
                )
            )
            snapshot = decode_post_enrollment_graceful_stop_operator_attestation_envelope(
                envelope_encoded
            )
            statement = snapshot.statement
            statement_encoded = (
                canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(
                    statement
                )
            )
            decision_v1 = snapshot.graceful_stop_decision_v1
            signature = snapshot.signature_ed25519
            authority_sha256 = post_enrollment_graceful_stop_operator_authority_artifact_sha256(
                authority
            )
            decision_sha256 = hashlib.sha256(decision_v1).hexdigest()
            statement_sha256 = post_enrollment_graceful_stop_operator_attestation_statement_sha256(
                statement
            )
            signature_sha256 = hashlib.sha256(signature).hexdigest()
            envelope_sha256 = hashlib.sha256(envelope_encoded).hexdigest()
            if (
                not statement_encoded.endswith(b"\n")
                or statement_encoded.count(b"\n") != 1
                or hashlib.sha256(statement_encoded).hexdigest() != statement_sha256
                or snapshot.graceful_stop_decision_v1_sha256 != decision_sha256
                or statement.graceful_stop_decision_v1_sha256 != decision_sha256
                or statement.authority_artifact_sha256 != authority_sha256
                or statement.public_key_sha256 != authority.public_key_sha256
                or statement.statement_sha256 != statement_sha256
                or post_enrollment_graceful_stop_operator_attestation_envelope_sha256(snapshot)
                != envelope_sha256
                or snapshot.envelope_sha256 != envelope_sha256
            ):
                raise ValueError
            public_key = Ed25519PublicKey.from_public_bytes(
                _require_prime_order_ed25519_public_key(authority.public_key_bytes)
            )
            public_key.verify(signature, statement_encoded)
        except (
            InvalidSignature,
            TypeError,
            ValueError,
            TrustedTimePostEnrollmentGracefulStopOperatorAuthorityError,
            TrustedTimePostEnrollmentGracefulStopOperatorAttestationError,
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation verification "
                "failed"
            ) from None
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
                "trusted-time post-enrollment graceful-stop operator-attestation verification "
                "failed"
            ) from None
        return TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification(
            authority_artifact_sha256=authority_sha256,
            public_key_sha256=authority.public_key_sha256,
            graceful_stop_decision_v1_sha256=decision_sha256,
            graceful_stop_operation_id=statement.graceful_stop_operation_id,
            graceful_stop_target_sha256=statement.graceful_stop_target_sha256,
            operator_attestation_statement_sha256=statement_sha256,
            operator_attestation_signature_sha256=signature_sha256,
            operator_attestation_envelope_sha256=envelope_sha256,
            _construction_capability=_VERIFICATION_RESULT_CONSTRUCTION_CAPABILITY,
        )

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verifier cannot "
            "be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verifier cannot "
            "be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verifier cannot "
            "be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError(
            "trusted-time post-enrollment graceful-stop operator-attestation verifier cannot "
            "be serialized"
        )


__all__ = [
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_AUTHORITY_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_VERIFICATION_STATUS",
    "Ed25519PostEnrollmentGracefulStopOperatorAttestationVerifier",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerification",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationVerificationError",
]
