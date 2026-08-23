"""Canonical inert bytes for one externally signed operator attestation.

This pure domain module preserves an exact v2 execution-approval artifact and
binds it to one fixed operator decision.  It has no signer, private key,
authority loader, filesystem, clock, runtime, admission, or execution surface.
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
    POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
    POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
    TrustedTimePostEnrollmentOperatorAuthority,
    TrustedTimePostEnrollmentOperatorAuthorityError,
    post_enrollment_operator_authority_artifact_sha256,
)

POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-operator-attestation-statement-v1"
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE = (
    "trusted-time-post-enrollment-start-operator-attestation"
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS = (
    "exact_one_attempt_execution_approval_statement"
)
POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION = "approve_one_post_enrollment_start_attempt"
POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-execution-approval-v3"
)
POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE = (
    "trusted-time-post-enrollment-start-execution-approval"
)
POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS = (
    "operator_attested_execution_approval_envelope"
)
EXECUTION_APPROVAL_V2_CONTRACT_VERSION = "phase6d-post-enrollment-start-execution-approval-v2"
EXECUTION_APPROVAL_V2_STATUS = "execution_approval_artifact"

POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES = 4_096
POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES = 65_536
POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES = 131_072

POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS = frozenset(
    {
        "algorithm",
        "authority_artifact_sha256",
        "authority_contract_version",
        "contract_version",
        "decision",
        "execution_approval_contract_version",
        "execution_approval_v2_sha256",
        "key_id",
        "public_key_sha256",
        "replay_domain",
        "service",
        "status",
    }
)
POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS = frozenset(
    {
        "contract_version",
        "execution_approval_v2_base64",
        "execution_approval_v2_sha256",
        "operator_attestation_statement",
        "operator_attestation_statement_sha256",
        "service",
        "signature_algorithm",
        "signature_base64",
        "status",
    }
)
# Descriptive alias retained for callers that reason about the container shape
# rather than its dormant v3 contract name.
POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_FIELDS = (
    POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS
)

_RAW_ED25519_SIGNATURE_BYTES = 64


class TrustedTimePostEnrollmentOperatorAttestationError(ValueError):
    """The operator-attestation statement or envelope is malformed."""


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


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentOperatorAttestationStatement:
    """The exact canonical bytes signed externally with the dedicated key."""

    authority_artifact_sha256: str
    public_key_sha256: str
    execution_approval_v2_sha256: str

    def __post_init__(self) -> None:
        if any(
            not _is_sha256(value)
            for value in (
                self.authority_artifact_sha256,
                self.public_key_sha256,
                self.execution_approval_v2_sha256,
            )
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationError(
                "trusted-time post-enrollment operator attestation is invalid"
            )

    def payload(self) -> dict[str, object]:
        return {
            "algorithm": POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
            "authority_artifact_sha256": self.authority_artifact_sha256,
            "authority_contract_version": POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "contract_version": POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
            "decision": POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
            "execution_approval_contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
            "execution_approval_v2_sha256": self.execution_approval_v2_sha256,
            "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
            "public_key_sha256": self.public_key_sha256,
            "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
            "status": POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_operator_attestation_statement_bytes(self)

    @property
    def statement_sha256(self) -> str:
        return post_enrollment_operator_attestation_statement_sha256(self)


@dataclass(frozen=True, slots=True)
class TrustedTimePostEnrollmentOperatorAttestationEnvelope:
    """A dormant v3 envelope retaining exact v2, statement, and signature bytes."""

    execution_approval_v2: bytes = field(repr=False)
    statement: TrustedTimePostEnrollmentOperatorAttestationStatement
    signature_ed25519: bytes = field(repr=False)

    def __post_init__(self) -> None:
        try:
            _validate_execution_approval_v2(self.execution_approval_v2)
            if type(self.statement) is not TrustedTimePostEnrollmentOperatorAttestationStatement:
                _invalid()
            self.statement.__post_init__()
            if (
                type(self.signature_ed25519) is not bytes
                or len(self.signature_ed25519) != _RAW_ED25519_SIGNATURE_BYTES
                or hashlib.sha256(self.execution_approval_v2).hexdigest()
                != self.statement.execution_approval_v2_sha256
            ):
                _invalid()
        except (
            TypeError,
            ValueError,
            TrustedTimePostEnrollmentOperatorAttestationError,
            _InvalidAttestation,
        ):
            raise TrustedTimePostEnrollmentOperatorAttestationError(
                "trusted-time post-enrollment operator attestation is invalid"
            ) from None

    @property
    def execution_approval_v2_base64(self) -> str:
        return base64.b64encode(self.execution_approval_v2).decode("ascii")

    @property
    def execution_approval_v2_sha256(self) -> str:
        return hashlib.sha256(self.execution_approval_v2).hexdigest()

    @property
    def signature_base64(self) -> str:
        return base64.b64encode(self.signature_ed25519).decode("ascii")

    def payload(self) -> dict[str, object]:
        return {
            "contract_version": (
                POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION
            ),
            "execution_approval_v2_base64": self.execution_approval_v2_base64,
            "execution_approval_v2_sha256": self.execution_approval_v2_sha256,
            "operator_attestation_statement": self.statement.payload(),
            "operator_attestation_statement_sha256": self.statement.statement_sha256,
            "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
            "signature_algorithm": POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
            "signature_base64": self.signature_base64,
            "status": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_post_enrollment_operator_attestation_envelope_bytes(self)

    @property
    def envelope_sha256(self) -> str:
        return post_enrollment_operator_attestation_envelope_sha256(self)


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


def _validate_execution_approval_v2(encoded: object) -> bytes:
    payload = _decode_canonical_object(
        encoded,
        maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES,
    )
    exact_strings = {
        "contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
        "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
        "status": EXECUTION_APPROVAL_V2_STATUS,
    }
    if any(
        type(payload.get(field_name)) is not str or payload.get(field_name) != expected
        for field_name, expected in exact_strings.items()
    ):
        _invalid()
    return cast(bytes, encoded)


def build_post_enrollment_operator_attestation_statement(
    *,
    authority: TrustedTimePostEnrollmentOperatorAuthority,
    execution_approval_v2_sha256: str,
) -> TrustedTimePostEnrollmentOperatorAttestationStatement:
    """Bind one v2 digest to one explicit, already-decoded public authority."""

    try:
        if type(authority) is not TrustedTimePostEnrollmentOperatorAuthority:
            _invalid()
        authority.__post_init__()
        statement = TrustedTimePostEnrollmentOperatorAttestationStatement(
            authority_artifact_sha256=(
                post_enrollment_operator_authority_artifact_sha256(authority)
            ),
            public_key_sha256=authority.public_key_sha256,
            execution_approval_v2_sha256=execution_approval_v2_sha256,
        )
        statement.__post_init__()
        return statement
    except (
        TypeError,
        ValueError,
        TrustedTimePostEnrollmentOperatorAuthorityError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        _InvalidAttestation,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationError(
            "trusted-time post-enrollment operator attestation is invalid"
        ) from None


def canonical_post_enrollment_operator_attestation_statement_bytes(statement: object) -> bytes:
    """Return exact newline-terminated bytes to be signed with plain Ed25519."""

    try:
        if type(statement) is not TrustedTimePostEnrollmentOperatorAttestationStatement:
            _invalid()
        statement.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(statement.payload())
        if len(encoded) > POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES:
            _invalid()
        return encoded
    except (
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        _InvalidAttestation,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationError(
            "trusted-time post-enrollment operator attestation is invalid"
        ) from None


def post_enrollment_operator_attestation_statement_sha256(statement: object) -> str:
    """Return the evidence identity of the exact signed statement bytes."""

    return hashlib.sha256(
        canonical_post_enrollment_operator_attestation_statement_bytes(statement)
    ).hexdigest()


def decode_post_enrollment_operator_attestation_statement(
    encoded: object,
) -> TrustedTimePostEnrollmentOperatorAttestationStatement:
    """Decode only the exact canonical fixed-scope statement."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES,
        )
        if set(payload) != POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS:
            _invalid()
        exact_strings = {
            "algorithm": POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
            "authority_contract_version": POST_ENROLLMENT_OPERATOR_AUTHORITY_CONTRACT_VERSION,
            "contract_version": POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION,
            "decision": POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION,
            "execution_approval_contract_version": EXECUTION_APPROVAL_V2_CONTRACT_VERSION,
            "key_id": POST_ENROLLMENT_OPERATOR_AUTHORITY_KEY_ID,
            "replay_domain": POST_ENROLLMENT_OPERATOR_AUTHORITY_REPLAY_DOMAIN,
            "service": POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE,
            "status": POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS,
        }
        if any(
            type(payload.get(field_name)) is not str or payload.get(field_name) != expected
            for field_name, expected in exact_strings.items()
        ):
            _invalid()
        for field_name in (
            "authority_artifact_sha256",
            "public_key_sha256",
            "execution_approval_v2_sha256",
        ):
            if not _is_sha256(payload.get(field_name)):
                _invalid()
        statement = TrustedTimePostEnrollmentOperatorAttestationStatement(
            authority_artifact_sha256=cast(str, payload["authority_artifact_sha256"]),
            public_key_sha256=cast(str, payload["public_key_sha256"]),
            execution_approval_v2_sha256=cast(str, payload["execution_approval_v2_sha256"]),
        )
        if statement.payload() != payload:
            _invalid()
        return statement
    except (
        KeyError,
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        _InvalidAttestation,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationError(
            "trusted-time post-enrollment operator attestation is invalid"
        ) from None


def build_post_enrollment_operator_attestation_envelope(
    *,
    execution_approval_v2: bytes,
    statement: TrustedTimePostEnrollmentOperatorAttestationStatement,
    signature_ed25519: bytes,
) -> TrustedTimePostEnrollmentOperatorAttestationEnvelope:
    """Build a non-authorizing v3 envelope from exact externally produced bytes."""

    return TrustedTimePostEnrollmentOperatorAttestationEnvelope(
        execution_approval_v2=execution_approval_v2,
        statement=statement,
        signature_ed25519=signature_ed25519,
    )


def canonical_post_enrollment_operator_attestation_envelope_bytes(envelope: object) -> bytes:
    """Return the exact canonical newline-terminated v3 envelope bytes."""

    try:
        if type(envelope) is not TrustedTimePostEnrollmentOperatorAttestationEnvelope:
            _invalid()
        envelope.__post_init__()
        encoded = canonical_first_enrollment_json_bytes(envelope.payload())
        if len(encoded) > POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES:
            _invalid()
        return encoded
    except (
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        _InvalidAttestation,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationError(
            "trusted-time post-enrollment operator attestation is invalid"
        ) from None


def post_enrollment_operator_attestation_envelope_sha256(envelope: object) -> str:
    """Return the evidence identity of the exact canonical v3 envelope."""

    return hashlib.sha256(
        canonical_post_enrollment_operator_attestation_envelope_bytes(envelope)
    ).hexdigest()


def _canonical_base64_bytes(value: object, *, exact_length: int | None = None) -> bytes:
    if type(value) is not str:
        _invalid()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _invalid()
    if (exact_length is not None and len(decoded) != exact_length) or base64.b64encode(
        decoded
    ).decode("ascii") != value:
        _invalid()
    return decoded


def decode_post_enrollment_operator_attestation_envelope(
    encoded: object,
) -> TrustedTimePostEnrollmentOperatorAttestationEnvelope:
    """Decode and cross-bind one exact canonical v3 envelope without qualifying v2."""

    try:
        payload = _decode_canonical_object(
            encoded,
            maximum_bytes=POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES,
        )
        if set(payload) != POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS:
            _invalid()
        exact_strings = {
            "contract_version": (
                POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION
            ),
            "service": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE,
            "signature_algorithm": POST_ENROLLMENT_OPERATOR_AUTHORITY_ALGORITHM,
            "status": POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS,
        }
        if any(
            type(payload.get(field_name)) is not str or payload.get(field_name) != expected
            for field_name, expected in exact_strings.items()
        ):
            _invalid()
        execution_approval_v2 = _canonical_base64_bytes(payload.get("execution_approval_v2_base64"))
        _validate_execution_approval_v2(execution_approval_v2)
        signature = _canonical_base64_bytes(
            payload.get("signature_base64"), exact_length=_RAW_ED25519_SIGNATURE_BYTES
        )
        if not _is_sha256(payload.get("execution_approval_v2_sha256")) or not _is_sha256(
            payload.get("operator_attestation_statement_sha256")
        ):
            _invalid()
        nested = payload.get("operator_attestation_statement")
        if type(nested) is not dict:
            _invalid()
        statement_bytes = canonical_first_enrollment_json_bytes(nested)
        statement = decode_post_enrollment_operator_attestation_statement(statement_bytes)
        if (
            hashlib.sha256(execution_approval_v2).hexdigest()
            != payload["execution_approval_v2_sha256"]
            or statement.execution_approval_v2_sha256 != payload["execution_approval_v2_sha256"]
            or statement.statement_sha256 != payload["operator_attestation_statement_sha256"]
        ):
            _invalid()
        envelope = TrustedTimePostEnrollmentOperatorAttestationEnvelope(
            execution_approval_v2=execution_approval_v2,
            statement=statement,
            signature_ed25519=signature,
        )
        if envelope.payload() != payload:
            _invalid()
        return envelope
    except (
        KeyError,
        TypeError,
        ValueError,
        TrustedTimeEnrollmentEvidenceError,
        TrustedTimePostEnrollmentOperatorAttestationError,
        _InvalidAttestation,
    ):
        raise TrustedTimePostEnrollmentOperatorAttestationError(
            "trusted-time post-enrollment operator attestation is invalid"
        ) from None


__all__ = [
    "EXECUTION_APPROVAL_V2_CONTRACT_VERSION",
    "EXECUTION_APPROVAL_V2_STATUS",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_DECISION",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_ENVELOPE_FIELDS",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_ENVELOPE_BYTES",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_EXECUTION_APPROVAL_V2_BYTES",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_MAXIMUM_STATEMENT_BYTES",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_CONTRACT_VERSION",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_FIELDS",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_SERVICE",
    "POST_ENROLLMENT_OPERATOR_ATTESTATION_STATEMENT_STATUS",
    "POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_CONTRACT_VERSION",
    "POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_FIELDS",
    "POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_SERVICE",
    "POST_ENROLLMENT_OPERATOR_ATTESTED_EXECUTION_APPROVAL_STATUS",
    "TrustedTimePostEnrollmentOperatorAttestationEnvelope",
    "TrustedTimePostEnrollmentOperatorAttestationError",
    "TrustedTimePostEnrollmentOperatorAttestationStatement",
    "build_post_enrollment_operator_attestation_envelope",
    "build_post_enrollment_operator_attestation_statement",
    "canonical_post_enrollment_operator_attestation_envelope_bytes",
    "canonical_post_enrollment_operator_attestation_statement_bytes",
    "decode_post_enrollment_operator_attestation_envelope",
    "decode_post_enrollment_operator_attestation_statement",
    "post_enrollment_operator_attestation_envelope_sha256",
    "post_enrollment_operator_attestation_statement_sha256",
]
