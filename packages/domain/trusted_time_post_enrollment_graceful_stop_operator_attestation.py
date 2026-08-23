"""Canonical inert bytes for one externally signed graceful-stop decision.

This dependency-pure codec preserves exact canonical graceful-stop decision-v1
bytes and binds their operation and target identities to a stop-specific
operator statement.  It has no signer, private key, verifier, filesystem,
clock, admission, shutdown, or runtime surface.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Never, SupportsIndex, cast
from uuid import RFC_4122, UUID

from packages.domain.trusted_time_enrollment_evidence import (
    TrustedTimeEnrollmentEvidenceError,
    canonical_first_enrollment_json_bytes,
)
from packages.domain.trusted_time_post_enrollment_graceful_stop_operator_authority import (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    canonical_post_enrollment_graceful_stop_operator_authority_bytes,
    post_enrollment_graceful_stop_operator_authority_artifact_sha256,
)

POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-operator-attestation-statement-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop-operator-attestation"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS = (
    "exact_one_attempt_graceful_stop_decision_statement"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION = (
    "approve_one_post_enrollment_graceful_stop_attempt"
)
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-decision-v1"
)
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_SERVICE = "trusted-time-post-enrollment-graceful-stop"
POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_STATUS = "external_attestation_required"
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION = (
    "phase6d-post-enrollment-graceful-stop-decision-v2"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE = (
    "trusted-time-post-enrollment-graceful-stop"
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS = (
    "operator_attested_graceful_stop_decision_envelope"
)

POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES = 4_096
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES = 128 * 1_024
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES = 256 * 1_024

POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS = frozenset(
    {
        "algorithm",
        "authority_artifact_sha256",
        "authority_contract_version",
        "contract_version",
        "decision",
        "graceful_stop_decision_contract_version",
        "graceful_stop_decision_v1_sha256",
        "graceful_stop_operation_id",
        "graceful_stop_target_sha256",
        "key_id",
        "public_key_sha256",
        "replay_domain",
        "service",
        "status",
    }
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS = frozenset(
    {
        "contract_version",
        "graceful_stop_decision_v1_base64",
        "graceful_stop_decision_v1_sha256",
        "operator_attestation_statement",
        "operator_attestation_statement_sha256",
        "service",
        "signature_algorithm",
        "signature_base64",
        "status",
    }
)
POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_FIELDS = (
    POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS
)

_RAW_ED25519_SIGNATURE_BYTES = 64
_STATEMENT_CONSTRUCTION_CAPABILITY = object()
_ENVELOPE_CONSTRUCTION_CAPABILITY = object()


class TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(ValueError):
    """The stop operator-attestation statement or envelope is malformed."""


class _InvalidAttestation(ValueError):
    pass


def _invalid() -> Never:
    raise _InvalidAttestation


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


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _decode_canonical_object(encoded: object, *, maximum_bytes: int) -> dict[str, object]:
    if type(encoded) is not bytes or not encoded or len(encoded) > maximum_bytes:
        _invalid()
    encoded_bytes = encoded
    try:
        payload = json.loads(
            encoded_bytes.decode("ascii", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda _: _invalid(),
        )
    except (TypeError, UnicodeError, ValueError, RecursionError, _InvalidAttestation):
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


def _validate_graceful_stop_decision_v1(encoded: object) -> tuple[bytes, str, str]:
    payload = _decode_canonical_object(
        encoded,
        maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES,
    )
    if (
        payload.get("contract_version")
        != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION
        or payload.get("service") != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_SERVICE
        or payload.get("status") != POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_STATUS
        or not _is_uuid4(payload.get("operation_id"))
        or not _is_sha256(payload.get("graceful_stop_target_sha256"))
    ):
        _invalid()
    return (
        cast(bytes, encoded),
        cast(str, payload["operation_id"]),
        cast(str, payload["graceful_stop_target_sha256"]),
    )


def _statement_seal_values(value: Any) -> tuple[object, ...]:
    return (
        value.authority_artifact_sha256,
        value.public_key_sha256,
        value.graceful_stop_decision_v1_sha256,
        value.graceful_stop_operation_id,
        value.graceful_stop_target_sha256,
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
    """The exact canonical stop-specific bytes signed by external custody."""

    authority_artifact_sha256: str
    public_key_sha256: str
    graceful_stop_decision_v1_sha256: str
    graceful_stop_operation_id: str
    graceful_stop_target_sha256: str
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        authority_artifact_sha256: str,
        public_key_sha256: str,
        graceful_stop_decision_v1_sha256: str,
        graceful_stop_operation_id: str,
        graceful_stop_target_sha256: str,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement
            or _construction_capability is not _STATEMENT_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
                "trusted-time post-enrollment graceful-stop operator attestation is invalid"
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
        object.__setattr__(self, "_sealed_fields", _statement_seal_values(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement
            or not all(
                _is_sha256(value)
                for value in (
                    self.authority_artifact_sha256,
                    self.public_key_sha256,
                    self.graceful_stop_decision_v1_sha256,
                    self.graceful_stop_target_sha256,
                )
            )
            or not _is_uuid4(self.graceful_stop_operation_id)
            or _statement_seal_values(self) != getattr(self, "_sealed_fields", None)
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
                "trusted-time post-enrollment graceful-stop operator attestation is invalid"
            )

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "algorithm": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
            "authority_artifact_sha256": self.authority_artifact_sha256,
            "authority_contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION
            ),
            "contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
            ),
            "decision": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION,
            "graceful_stop_decision_contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION
            ),
            "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
            "graceful_stop_operation_id": self.graceful_stop_operation_id,
            "graceful_stop_target_sha256": self.graceful_stop_target_sha256,
            "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
            "public_key_sha256": self.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
            "status": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(self)

    @property
    def statement_sha256(self) -> str:
        return post_enrollment_graceful_stop_operator_attestation_statement_sha256(self)

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be serialized"
        )


def _new_statement(
    *,
    authority_artifact_sha256: str,
    public_key_sha256: str,
    graceful_stop_decision_v1_sha256: str,
    graceful_stop_operation_id: str,
    graceful_stop_target_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
    return TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement(
        authority_artifact_sha256=authority_artifact_sha256,
        public_key_sha256=public_key_sha256,
        graceful_stop_decision_v1_sha256=graceful_stop_decision_v1_sha256,
        graceful_stop_operation_id=graceful_stop_operation_id,
        graceful_stop_target_sha256=graceful_stop_target_sha256,
        _construction_capability=_STATEMENT_CONSTRUCTION_CAPABILITY,
    )


def build_post_enrollment_graceful_stop_operator_attestation_statement(
    *,
    authority: TrustedTimePostEnrollmentGracefulStopOperatorAuthority,
    graceful_stop_decision_v1_sha256: str,
    graceful_stop_operation_id: str,
    graceful_stop_target_sha256: str,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
    """Bind one exact stop authority and decision identity into signed bytes."""

    try:
        if type(authority) is not TrustedTimePostEnrollmentGracefulStopOperatorAuthority:
            _invalid()
        authority_encoded = canonical_post_enrollment_graceful_stop_operator_authority_bytes(
            authority
        )
        if not _is_sha256(graceful_stop_decision_v1_sha256):
            _invalid()
        result = _new_statement(
            authority_artifact_sha256=(
                post_enrollment_graceful_stop_operator_authority_artifact_sha256(authority)
            ),
            public_key_sha256=authority.public_key_sha256,
            graceful_stop_decision_v1_sha256=graceful_stop_decision_v1_sha256,
            graceful_stop_operation_id=graceful_stop_operation_id,
            graceful_stop_target_sha256=graceful_stop_target_sha256,
        )
        if hashlib.sha256(authority_encoded).hexdigest() != result.authority_artifact_sha256:
            _invalid()
        canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(result)
        return result
    except TrustedTimePostEnrollmentGracefulStopOperatorAttestationError:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation is invalid"
        ) from None


def canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(
    statement: object,
) -> bytes:
    """Return exact bounded canonical statement bytes."""

    try:
        if type(statement) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
            _invalid()
        statement.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(statement.payload())
        if (
            not encoded
            or len(encoded)
            > POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES
        ):
            _invalid()
        return encoded
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation is invalid"
        ) from None


def post_enrollment_graceful_stop_operator_attestation_statement_sha256(
    statement: object,
) -> str:
    """Return the exact canonical statement identity."""

    return hashlib.sha256(
        canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
    ).hexdigest()


def decode_post_enrollment_graceful_stop_operator_attestation_statement(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
    """Strictly decode one exact stop-specific statement."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=(
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES
            ),
        )
        if set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS:
            _invalid()
        exact_strings = {
            "algorithm": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
            "authority_contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_CONTRACT_VERSION
            ),
            "contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION
            ),
            "decision": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION,
            "graceful_stop_decision_contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION
            ),
            "key_id": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_KEY_ID,
            "replay_domain": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
            "status": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS,
        }
        if any(payload.get(name) != expected for name, expected in exact_strings.items()):
            _invalid()
        result = _new_statement(
            authority_artifact_sha256=cast(str, payload.get("authority_artifact_sha256")),
            public_key_sha256=cast(str, payload.get("public_key_sha256")),
            graceful_stop_decision_v1_sha256=cast(
                str,
                payload.get("graceful_stop_decision_v1_sha256"),
            ),
            graceful_stop_operation_id=cast(str, payload.get("graceful_stop_operation_id")),
            graceful_stop_target_sha256=cast(
                str,
                payload.get("graceful_stop_target_sha256"),
            ),
        )
        if result.payload() != payload:
            _invalid()
        return result
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation is invalid"
        ) from None


def _canonical_base64_bytes(value: object, *, exact_length: int | None = None) -> bytes:
    if type(value) is not str:
        _invalid()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _invalid()
    if base64.b64encode(decoded).decode("ascii") != value or (
        exact_length is not None and len(decoded) != exact_length
    ):
        _invalid()
    return decoded


def _envelope_seal_values(value: Any) -> tuple[object, ...]:
    return (
        value._graceful_stop_decision_v1_encoded,
        value._statement_encoded,
        value._signature_ed25519,
    )


@dataclass(frozen=True, slots=True, init=False)
class TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
    """An inert v2 envelope preserving exact decision, statement, and signature bytes."""

    _graceful_stop_decision_v1_encoded: bytes = field(repr=False)
    _statement_encoded: bytes = field(repr=False)
    _signature_ed25519: bytes = field(repr=False)
    _sealed_fields: tuple[object, ...] = field(init=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        graceful_stop_decision_v1_encoded: bytes,
        statement_encoded: bytes,
        signature_ed25519: bytes,
        _construction_capability: object,
    ) -> None:
        if (
            type(self) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope
            or _construction_capability is not _ENVELOPE_CONSTRUCTION_CAPABILITY
        ):
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
                "trusted-time post-enrollment graceful-stop operator attestation is invalid"
            )
        object.__setattr__(
            self,
            "_graceful_stop_decision_v1_encoded",
            graceful_stop_decision_v1_encoded,
        )
        object.__setattr__(self, "_statement_encoded", statement_encoded)
        object.__setattr__(self, "_signature_ed25519", signature_ed25519)
        object.__setattr__(self, "_sealed_fields", _envelope_seal_values(self))
        self.__post_init__()

    def __post_init__(self) -> None:
        try:
            if type(self) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
                _invalid()
            decision_encoded, operation_id, target_sha256 = _validate_graceful_stop_decision_v1(
                self._graceful_stop_decision_v1_encoded
            )
            statement = decode_post_enrollment_graceful_stop_operator_attestation_statement(
                self._statement_encoded
            )
            if (
                type(self._signature_ed25519) is not bytes
                or len(self._signature_ed25519) != _RAW_ED25519_SIGNATURE_BYTES
                or hashlib.sha256(decision_encoded).hexdigest()
                != statement.graceful_stop_decision_v1_sha256
                or operation_id != statement.graceful_stop_operation_id
                or target_sha256 != statement.graceful_stop_target_sha256
                or _envelope_seal_values(self) != getattr(self, "_sealed_fields", None)
            ):
                _invalid()
        except TrustedTimePostEnrollmentGracefulStopOperatorAttestationError:
            raise
        except Exception:
            raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
                "trusted-time post-enrollment graceful-stop operator attestation is invalid"
            ) from None

    @property
    def graceful_stop_decision_v1(self) -> bytes:
        self.__post_init__()
        return bytes(memoryview(self._graceful_stop_decision_v1_encoded))

    @property
    def statement(self) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
        self.__post_init__()
        return decode_post_enrollment_graceful_stop_operator_attestation_statement(
            self._statement_encoded
        )

    @property
    def signature_ed25519(self) -> bytes:
        self.__post_init__()
        return bytes(memoryview(self._signature_ed25519))

    @property
    def graceful_stop_decision_v1_base64(self) -> str:
        return base64.b64encode(self.graceful_stop_decision_v1).decode("ascii")

    @property
    def graceful_stop_decision_v1_sha256(self) -> str:
        return hashlib.sha256(self.graceful_stop_decision_v1).hexdigest()

    @property
    def signature_base64(self) -> str:
        return base64.b64encode(self.signature_ed25519).decode("ascii")

    def payload(self) -> dict[str, object]:
        self.__post_init__()
        statement = self.statement
        return {
            "contract_version": (
                POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION
            ),
            "graceful_stop_decision_v1_base64": self.graceful_stop_decision_v1_base64,
            "graceful_stop_decision_v1_sha256": self.graceful_stop_decision_v1_sha256,
            "operator_attestation_statement": statement.payload(),
            "operator_attestation_statement_sha256": statement.statement_sha256,
            "service": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE,
            "signature_algorithm": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM,
            "signature_base64": self.signature_base64,
            "status": POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(self)

    @property
    def envelope_sha256(self) -> str:
        return post_enrollment_graceful_stop_operator_attestation_envelope_sha256(self)

    def __copy__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be copied"
        )

    def __deepcopy__(self, _: object) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be copied"
        )

    def __reduce__(self) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be serialized"
        )

    def __reduce_ex__(self, _: SupportsIndex) -> Never:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation cannot be serialized"
        )


def _new_envelope(
    *,
    graceful_stop_decision_v1: bytes,
    statement: TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement,
    signature_ed25519: bytes,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
    return TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope(
        graceful_stop_decision_v1_encoded=graceful_stop_decision_v1,
        statement_encoded=(
            canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes(statement)
        ),
        signature_ed25519=signature_ed25519,
        _construction_capability=_ENVELOPE_CONSTRUCTION_CAPABILITY,
    )


def build_post_enrollment_graceful_stop_operator_attestation_envelope(
    *,
    graceful_stop_decision_v1: bytes,
    statement: TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement,
    signature_ed25519: bytes,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
    """Preserve exact decision, statement, and detached signature bytes."""

    try:
        if type(statement) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement:
            _invalid()
        statement.__post_init__()
        result = _new_envelope(
            graceful_stop_decision_v1=graceful_stop_decision_v1,
            statement=statement,
            signature_ed25519=signature_ed25519,
        )
        canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(result)
        return result
    except TrustedTimePostEnrollmentGracefulStopOperatorAttestationError:
        raise
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation is invalid"
        ) from None


def canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(
    envelope: object,
) -> bytes:
    """Return exact bounded canonical envelope bytes."""

    try:
        if type(envelope) is not TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
            _invalid()
        envelope.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(envelope.payload())
        if (
            not encoded
            or len(encoded)
            > POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES
        ):
            _invalid()
        return encoded
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation is invalid"
        ) from None


def post_enrollment_graceful_stop_operator_attestation_envelope_sha256(
    envelope: object,
) -> str:
    """Return the exact canonical envelope identity."""

    return hashlib.sha256(
        canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes(envelope)
    ).hexdigest()


def decode_post_enrollment_graceful_stop_operator_attestation_envelope(
    encoded: object,
) -> TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope:
    """Strictly decode one inert stop-specific operator-attested envelope."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
        )
        if (
            set(payload) != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS
            or payload.get("contract_version")
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION
            or payload.get("service")
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE
            or payload.get("signature_algorithm")
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_AUTHORITY_ALGORITHM
            or payload.get("status")
            != POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS
        ):
            _invalid()
        decision_encoded = _canonical_base64_bytes(payload.get("graceful_stop_decision_v1_base64"))
        _validate_graceful_stop_decision_v1(decision_encoded)
        signature = _canonical_base64_bytes(
            payload.get("signature_base64"),
            exact_length=_RAW_ED25519_SIGNATURE_BYTES,
        )
        if not _is_sha256(payload.get("graceful_stop_decision_v1_sha256")) or not _is_sha256(
            payload.get("operator_attestation_statement_sha256")
        ):
            _invalid()
        nested = payload.get("operator_attestation_statement")
        if type(nested) is not dict:
            _invalid()
        statement_encoded = canonical_first_enrollment_json_bytes(nested)
        statement = decode_post_enrollment_graceful_stop_operator_attestation_statement(
            statement_encoded
        )
        if (
            hashlib.sha256(decision_encoded).hexdigest()
            != payload["graceful_stop_decision_v1_sha256"]
            or statement.graceful_stop_decision_v1_sha256
            != payload["graceful_stop_decision_v1_sha256"]
            or statement.statement_sha256 != payload["operator_attestation_statement_sha256"]
        ):
            _invalid()
        envelope = _new_envelope(
            graceful_stop_decision_v1=decision_encoded,
            statement=statement,
            signature_ed25519=signature,
        )
        if envelope.payload() != payload:
            _invalid()
        return envelope
    except Exception:
        raise TrustedTimePostEnrollmentGracefulStopOperatorAttestationError(
            "trusted-time post-enrollment graceful-stop operator attestation is invalid"
        ) from None


__all__ = [
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_DECISION_V1_STATUS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_DECISION",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_ENVELOPE_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_DECISION_V1_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTATION_STATEMENT_STATUS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_CONTRACT_VERSION",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_FIELDS",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_SERVICE",
    "POST_ENROLLMENT_GRACEFUL_STOP_OPERATOR_ATTESTED_DECISION_STATUS",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationEnvelope",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationError",
    "TrustedTimePostEnrollmentGracefulStopOperatorAttestationStatement",
    "build_post_enrollment_graceful_stop_operator_attestation_envelope",
    "build_post_enrollment_graceful_stop_operator_attestation_statement",
    "canonical_post_enrollment_graceful_stop_operator_attestation_envelope_bytes",
    "canonical_post_enrollment_graceful_stop_operator_attestation_statement_bytes",
    "decode_post_enrollment_graceful_stop_operator_attestation_envelope",
    "decode_post_enrollment_graceful_stop_operator_attestation_statement",
    "post_enrollment_graceful_stop_operator_attestation_envelope_sha256",
    "post_enrollment_graceful_stop_operator_attestation_statement_sha256",
]
